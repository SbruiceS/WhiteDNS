#include "whitedns/core/ThreatEngine.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/IanaDns.h"
#include "whitedns/core/DnssecPath.h"
#include "whitedns/core/PoisonClassifier.h"
#include "whitedns/core/ResolverEngine.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>

#ifdef WHITEDNS_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace whitedns {
namespace core {
namespace {

enum Eval : int {
    E_NONE = 0,
    E_COMPARE,
    E_DNSSEC,
    E_UNSIGNED,
    E_SPF,
    E_DMARC,
    E_MX,
    E_WILD,
    E_NX,
    E_PRIV,
    E_TTL,
    E_TXT,
    E_AXFR,
    E_CAA,
    E_INTERNAL
};

ThreatRule R(const char* id, const char* name, const char* cat, const char* rfc, const char* vendor,
             const char* sev, const char* fp, const char* rec, int ev) {
    return ThreatRule{id, name, cat, rfc, vendor, sev, fp, rec, ev};
}

const ThreatRule kRules[] = {
    R("WDNS-POISON-001", "Resolver answer inconsistency", "spoofing_poisoning", "RFC1034/4033", "Cisco SAFE DNS", "medium", "anycast, GeoDNS, CDN", "Compare AA + DNSSEC before calling poison", E_COMPARE),
    R("WDNS-POISON-002", "Authoritative vs recursive mismatch", "spoofing_poisoning", "RFC1035", "ITU-T X.805", "medium", "forwarder policy", "Query apex NS with AA", E_NONE),
    R("WDNS-POISON-003", "Unexpected CNAME redirection", "spoofing_poisoning", "RFC1035", "Cisco", "low", "CDN CNAME", "Check CNAME target ownership", E_NONE),
    R("WDNS-POISON-004", "Unexpected NS in answer", "spoofing_poisoning", "RFC2181", "Nokia SR OS DNS", "medium", "delegation change", "Diff NS vs parent glue", E_NONE),
    R("WDNS-POISON-005", "Unexpected MX change class", "spoofing_poisoning", "RFC5321", "Cisco ESA", "medium", "mail vendor cutover", "Confirm MX with registrar", E_MX),
    R("WDNS-POISON-006", "TTL collapse indicator", "spoofing_poisoning", "RFC2181", "ITU-T E.164/DNS", "low", "fast-flux-like CDN", "Track TTL over time", E_TTL),
    R("WDNS-POISON-007", "Negative-response inconsistency", "spoofing_poisoning", "RFC2308", "RFC", "medium", "split horizon", "Compare NX across resolvers", E_NX),
    R("WDNS-POISON-008", "TXID uniqueness not observable remotely", "spoofing_poisoning", "RFC5452", "Cisco", "info", "n/a", "Requires packet capture — INCONCLUSIVE remotely", E_NONE),
    R("WDNS-POISON-009", "Source-port randomization not observable remotely", "spoofing_poisoning", "RFC5452", "Cisco", "info", "n/a", "Requires local stub telemetry", E_NONE),
    R("WDNS-POISON-010", "On-path answer injection", "spoofing_poisoning", "RFC4033", "ITU X.800", "high", "anycast", "Need DNSSEC bogus + capture", E_NONE),
    R("WDNS-POISON-011", "Off-path poisoning indicator", "spoofing_poisoning", "RFC5452", "RFC", "high", "none remotely", "INCONCLUSIVE without birthday-attack telemetry", E_NONE),
    R("WDNS-POISON-012", "Rogue resolver behavior", "spoofing_poisoning", "RFC1034", "Cisco Umbrella", "medium", "parental filter", "Compare to 8.8.8.8/1.1.1.1/9.9.9.9", E_COMPARE),
    R("WDNS-POISON-013", "Local hosts-file class (not remote)", "spoofing_poisoning", "OS", "Dell endpoint", "info", "n/a", "Workstation forensic only", E_NONE),
    R("WDNS-POISON-014", "Unexpected TXT injection", "spoofing_poisoning", "RFC1035", "Cisco", "low", "vendor verification TXT", "Inventory TXT vs baseline", E_TXT),
    R("WDNS-POISON-015", "Temporal answer flip", "spoofing_poisoning", "RFC1034", "HP Aruba", "medium", "failover", "Needs history store", E_NONE),
    R("WDNS-POISON-016", "Promotion gate (no confirm without 3 signals)", "spoofing_poisoning", "RFC4033", "SANS", "info", "n/a", "DNSSEC + multi-resolver + AA required", E_COMPARE),

    R("WDNS-DNSSEC-001", "DNSSEC unsigned zone", "dnssec", "RFC4035", "ITU", "low", "operator choice", "Enable DNSSEC if policy requires", E_UNSIGNED),
    R("WDNS-DNSSEC-002", "DS present DNSKEY missing", "dnssec", "RFC4034", "RFC", "high", "propagation", "Check child DNSKEY", E_DNSSEC),
    R("WDNS-DNSSEC-003", "DS/DNSKEY digest match", "dnssec", "RFC4034", "RFC", "info", "n/a", "Keep KSK/ZSK hygiene", E_DNSSEC),
    R("WDNS-DNSSEC-004", "Broken chain of trust", "dnssec", "RFC4035", "Cisco", "high", "rollover", "Validate from trust anchor", E_DNSSEC),
    R("WDNS-DNSSEC-005", "Missing DS at parent", "dnssec", "RFC4034", "RFC", "medium", "unsigned by design", "Publish DS if signing", E_UNSIGNED),
    R("WDNS-DNSSEC-006", "RRSIG present inventory", "dnssec", "RFC4034", "RFC", "info", "n/a", "Full RRSet verify still separate", E_DNSSEC),
    R("WDNS-DNSSEC-007", "Expired RRSIG (needs inception/expire parse)", "dnssec", "RFC4034", "RFC", "high", "clock skew", "INCONCLUSIVE until expire field decoded", E_NONE),
    R("WDNS-DNSSEC-008", "Not-yet-valid RRSIG", "dnssec", "RFC4034", "RFC", "medium", "pre-publish", "INCONCLUSIVE remotely without times", E_NONE),
    R("WDNS-DNSSEC-009", "Deprecated algorithm", "dnssec", "RFC8624", "ITU", "medium", "legacy", "Move off RSAMD5/DSA", E_NONE),
    R("WDNS-DNSSEC-010", "Unexpected algorithm", "dnssec", "RFC8624", "RFC", "low", "algorithm rollover", "Pin allowed algs in policy", E_NONE),
    R("WDNS-DNSSEC-011", "Key-tag inconsistency", "dnssec", "RFC4034", "RFC", "medium", "multi-key", "Match DS key tag to DNSKEY", E_DNSSEC),
    R("WDNS-DNSSEC-012", "NSEC vs NSEC3 mix", "dnssec", "RFC5155", "RFC", "low", "migration", "One denial style per zone", E_DNSSEC),
    R("WDNS-DNSSEC-013", "NSEC3 authenticated-denial observation", "dnssec", "RFC5155", "RFC", "info", "n/a", "Not a full proof walk", E_DNSSEC),
    R("WDNS-DNSSEC-014", "Bogus validation (resolver AD=0 with DS)", "dnssec", "RFC4035", "Cisco", "medium", "CD bit / path", "Check AD on validating resolver", E_DNSSEC),
    R("WDNS-DNSSEC-015", "Insecure delegation", "dnssec", "RFC4035", "RFC", "medium", "child unsigned", "Parent DS missing", E_UNSIGNED),
    R("WDNS-DNSSEC-016", "Downgrade indicator", "dnssec", "RFC4035", "ITU X.805", "high", "resolver config", "Compare DO-bit answers", E_NONE),
    R("WDNS-DNSSEC-017", "Signature replay", "dnssec", "RFC4034", "RFC", "high", "long validity", "Needs timestamp series", E_NONE),
    R("WDNS-DNSSEC-018", "Trust-anchor inconsistency", "dnssec", "RFC5011", "RFC", "high", "local TA file", "Not observable remotely", E_NONE),

    R("WDNS-CACHE-001", "Open recursive resolver (remote RA)", "resolver_cache", "RFC5358", "Cisco", "medium", "intended recursor", "Disable recursion on auth NS", E_NONE),
    R("WDNS-CACHE-002", "Resolver disagreement", "resolver_cache", "RFC1034", "Cisco Umbrella", "low", "anycast", "See poison classifier", E_COMPARE),
    R("WDNS-CACHE-003", "Negative-cache anomaly", "resolver_cache", "RFC2308", "RFC", "low", "SOA minimum", "Needs TTL of NX", E_NX),
    R("WDNS-CACHE-004", "Stale-data serving", "resolver_cache", "RFC8767", "RFC", "info", "serve-stale", "INCONCLUSIVE remotely", E_NONE),
    R("WDNS-CACHE-005", "Resolver fingerprint change", "resolver_cache", "n/a", "Nokia", "info", "anycast POP", "Needs CHAOS TXT version.bind", E_NONE),
    R("WDNS-CACHE-006", "Policy rewrite (NXDOMAIN hijack class)", "resolver_cache", "RFC8020", "Cisco", "medium", "ISP search-assist", "Compare public resolvers", E_NX),
    R("WDNS-CACHE-007", "TTL anomaly vs SOA minimum", "resolver_cache", "RFC2181", "RFC", "low", "CDN", "Baseline TTLs", E_TTL),
    R("WDNS-CACHE-008", "Cache inconsistency across vantage", "resolver_cache", "RFC1034", "HP", "low", "geo", "Multi-resolver compare", E_COMPARE),
    R("WDNS-CACHE-009", "Unexpected RA on auth-looking NS", "resolver_cache", "RFC1035", "ITU", "medium", "combined role", "Probe NS host directly", E_NONE),
    R("WDNS-CACHE-010", "Resolver unavailable", "resolver_cache", "n/a", "Dell", "info", "outage", "WDNS-E004", E_NONE),

    R("WDNS-DELEG-001", "NS set inventory", "delegation", "RFC1035/2182", "Cisco", "info", "n/a", "Require ≥2 diverse NS", E_NONE),
    R("WDNS-DELEG-002", "Lame delegation (no AA SOA on NS)", "delegation", "RFC1034", "SANS ISC", "medium", "hidden master", "Query each NS for SOA+AA", E_NONE),
    R("WDNS-DELEG-003", "Glue mismatch", "delegation", "RFC1034", "RFC", "medium", "anycast glue", "Compare parent additional vs child A", E_NONE),
    R("WDNS-DELEG-004", "Cyclic CNAME", "delegation", "RFC1035", "RFC", "medium", "misconfig", "Walk CNAME chain cap 10", E_NONE),
    R("WDNS-DELEG-005", "Unexpected TLD parent", "delegation", "RFC1034", "IANA", "info", "n/a", "Check public suffix", E_NONE),
    R("WDNS-DELEG-006", "NS disappearance class", "delegation", "RFC2182", "Cisco", "medium", "planned shrink", "Needs history", E_NONE),
    R("WDNS-DELEG-007", "NS IP rotation", "delegation", "RFC2182", "Nokia", "low", "anycast", "Needs history", E_NONE),
    R("WDNS-DELEG-008", "Auth-server disagreement", "delegation", "RFC2181", "RFC", "medium", "multi-view", "Query each NS", E_NONE),
    R("WDNS-DELEG-009", "Delegation inconsistency parent/child", "delegation", "RFC1034", "IANA", "medium", "propagation", "Ask parent + child", E_NONE),
    R("WDNS-DELEG-010", "Single-NS weakness", "delegation", "RFC2182", "ITU", "medium", "budget", "Add second NS in other net", E_NONE),
    R("WDNS-DELEG-011", "Out-of-bailiwick NS without glue", "delegation", "RFC1034", "RFC", "low", "normal", "Ensure parent glue if needed", E_NONE),

    R("WDNS-HIJACK-001", "Sudden infrastructure replacement", "hijacking", "n/a", "Cisco", "high", "migration", "Correlate NS+A+MX+DNSSEC", E_NONE),
    R("WDNS-HIJACK-002", "Unexpected DNS provider change", "hijacking", "n/a", "ITU", "high", "planned move", "Needs NS history", E_NONE),
    R("WDNS-HIJACK-003", "Nameserver takeover indicator", "hijacking", "n/a", "SANS", "high", "shared NS", "Do not infer from shared NS alone", E_NONE),
    R("WDNS-HIJACK-004", "Registrar-data unavailable", "hijacking", "RDAP", "IANA", "info", "privacy WHOIS", "INCONCLUSIVE without RDAP", E_NONE),
    R("WDNS-HIJACK-005", "Ownership-control anomaly", "hijacking", "n/a", "Cisco", "medium", "brand protection", "Needs registrar feed", E_NONE),
    R("WDNS-HIJACK-006", "Do not claim registrar compromise", "hijacking", "n/a", "SANS", "info", "n/a", "Evidence gate", E_NONE),

    R("WDNS-XFER-001", "AXFR attempt classification", "zone_transfer", "RFC5936", "Cisco", "medium", "hidden AXFR ACL", "Expect REFUSED on public NS", E_AXFR),
    R("WDNS-XFER-002", "IXFR not probed by default", "zone_transfer", "RFC1995", "RFC", "info", "n/a", "Safe profile skips IXFR", E_NONE),
    R("WDNS-XFER-003", "Timeout on AXFR", "zone_transfer", "RFC5936", "Dell", "info", "firewall drop", "Class TIMEOUT", E_AXFR),
    R("WDNS-XFER-004", "Authorized success inventory", "zone_transfer", "RFC5936", "Cisco", "high", "intended hidden xfer", "Only on owned NS", E_AXFR),
    R("WDNS-XFER-005", "NOTAUTH/REFUSED is healthy public posture", "zone_transfer", "RFC5936", "RFC", "info", "n/a", "Keep AXFR off public", E_AXFR),

    R("WDNS-UPDATE-001", "Dynamic update not attempted", "dynamic_update", "RFC2136", "RFC", "info", "n/a", "Do not send unauthorized UPDATE", E_NONE),
    R("WDNS-UPDATE-002", "Unexpected record churn", "dynamic_update", "RFC2136", "HP", "low", "DHCP DNS", "Needs history", E_NONE),
    R("WDNS-UPDATE-003", "Update ACL unknown remotely", "dynamic_update", "RFC2136", "Cisco", "info", "n/a", "INCONCLUSIVE", E_NONE),
    R("WDNS-UPDATE-004", "Suspicious source metadata", "dynamic_update", "RFC2136", "Nokia", "info", "n/a", "Requires server logs", E_NONE),

    R("WDNS-AMPLIFY-001", "Large response size class", "amplification", "RFC5358", "ITU", "medium", "ANY disabled", "Measure rdata bytes", E_NONE),
    R("WDNS-AMPLIFY-002", "ANY/AXFR as amp vectors", "amplification", "RFC8482", "Cisco", "medium", "minimal ANY", "RFC8482 minimal ANY", E_AXFR),
    R("WDNS-AMPLIFY-003", "No traffic-generation engine", "amplification", "RFC5358", "SANS", "info", "n/a", "Detect only, do not flood", E_NONE),
    R("WDNS-AMPLIFY-004", "Request/response ratio needs pcap", "amplification", "RFC5358", "Cisco", "info", "n/a", "INCONCLUSIVE without telemetry", E_NONE),
    R("WDNS-AMPLIFY-005", "Open resolver abuse class", "amplification", "RFC5358", "ITU", "medium", "intended recursor", "See CACHE-001", E_NONE),
    R("WDNS-AMPLIFY-006", "EDNS buffer abuse", "amplification", "RFC6891", "RFC", "low", "large UDP", "Cap EDNS payload", E_NONE),

    R("WDNS-FLOOD-001", "Query-rate spike needs baseline", "flooding", "n/a", "Cisco", "info", "flash crowd", "INCONCLUSIVE one-shot", E_NONE),
    R("WDNS-FLOOD-002", "NXDOMAIN flood", "flooding", "RFC8020", "Cisco", "info", "scanner", "Needs rate series", E_NONE),
    R("WDNS-FLOOD-003", "Random-label flood", "flooding", "n/a", "Nokia", "info", "enum", "See NX probe only", E_NX),
    R("WDNS-FLOOD-004", "DoH exhaustion", "flooding", "RFC8484", "Cisco", "info", "n/a", "Needs DoH logs", E_NONE),
    R("WDNS-FLOOD-005", "DoT exhaustion", "flooding", "RFC7858", "Nokia", "info", "n/a", "Needs DoT logs", E_NONE),
    R("WDNS-FLOOD-006", "UDP flood", "flooding", "n/a", "ITU", "info", "n/a", "INCONCLUSIVE", E_NONE),
    R("WDNS-FLOOD-007", "TCP exhaustion", "flooding", "RFC7766", "RFC", "info", "n/a", "INCONCLUSIVE", E_NONE),
    R("WDNS-FLOOD-008", "High-cardinality names", "flooding", "n/a", "HP", "info", "SaaS", "Needs unique-qname count", E_NONE),

    R("WDNS-TUNNEL-001", "Long label indicator", "tunneling", "RFC1035", "SANS", "low", "DKIM", "Entropy+volume required", E_TXT),
    R("WDNS-TUNNEL-002", "High-entropy label", "tunneling", "n/a", "Cisco", "low", "DGA-like SaaS", "Never entropy alone", E_NONE),
    R("WDNS-TUNNEL-003", "Excessive TXT usage", "tunneling", "RFC1035", "SANS", "low", "SPF flatten", "Count TXT vs baseline", E_TXT),
    R("WDNS-TUNNEL-004", "Unique-label ratio", "tunneling", "n/a", "ITU", "low", "enum", "Needs stream", E_NONE),
    R("WDNS-TUNNEL-005", "Periodicity", "tunneling", "n/a", "Cisco", "low", "healthcheck", "Needs time series", E_NONE),
    R("WDNS-TUNNEL-006", "Encoding-like charset", "tunneling", "n/a", "RFC", "low", "hex hostnames", "Indicator only", E_NONE),
    R("WDNS-TUNNEL-007", "Request/response size ratio", "tunneling", "n/a", "Nokia", "low", "TXT SPF", "Needs pcap", E_NONE),
    R("WDNS-TUNNEL-008", "Covert-channel research flag", "tunneling", "n/a", "SANS", "info", "n/a", "Experimental", E_NONE),

    R("WDNS-C2-001", "Beaconing needs timing", "c2", "n/a", "Cisco", "info", "cron DNS", "No malware name from DNS alone", E_NONE),
    R("WDNS-C2-002", "Algorithmic subdomain", "c2", "n/a", "SANS", "low", "DGA product", "Feature dump only", E_NONE),
    R("WDNS-C2-003", "TXT as channel", "c2", "RFC1035", "Cisco", "low", "ACME", "Correlate volume", E_TXT),
    R("WDNS-C2-004", "Low-and-slow", "c2", "n/a", "ITU", "info", "keepalive", "INCONCLUSIVE", E_NONE),
    R("WDNS-C2-005", "No family attribution", "c2", "n/a", "SANS", "info", "n/a", "Never name malware from DNS only", E_NONE),

    R("WDNS-EXFIL-001", "Chunked labels", "exfiltration", "n/a", "SANS", "low", "DKIM selectors", "Indicator", E_NONE),
    R("WDNS-EXFIL-002", "Base32-like", "exfiltration", "n/a", "Cisco", "low", "tokens", "Indicator", E_NONE),
    R("WDNS-EXFIL-003", "Base64-like", "exfiltration", "n/a", "Cisco", "low", "TXT keys", "Indicator", E_TXT),
    R("WDNS-EXFIL-004", "Hex labels", "exfiltration", "n/a", "RFC", "low", "IPv6-ARPA", "Indicator", E_NONE),
    R("WDNS-EXFIL-005", "Volume+entropy gate", "exfiltration", "n/a", "ITU", "medium", "backup TXT", "Need both signals", E_NONE),

    R("WDNS-TAKE-001", "Dangling CNAME class", "takeover", "RFC1034", "Cisco", "medium", "pending cutover", "Need provider fingerprint + NX", E_NONE),
    R("WDNS-TAKE-002", "Dangling A", "takeover", "RFC1035", "HP", "low", "anycast leftover", "Multi-signal", E_NONE),
    R("WDNS-TAKE-003", "SaaS target NX", "takeover", "n/a", "Cisco", "medium", "typo provider", "Do not probe vendor abuse", E_NONE),
    R("WDNS-TAKE-004", "Orphan SRV", "takeover", "RFC2782", "RFC", "low", "retired service", "Check SRV target A", E_NONE),
    R("WDNS-TAKE-005", "High confidence needs two signals", "takeover", "n/a", "SANS", "info", "n/a", "CNAME + provider NX", E_NONE),

    R("WDNS-REBIND-001", "Public then RFC1918 A", "rebinding", "RFC1918", "Cisco", "medium", "split horizon", "Do not hit internal ports", E_PRIV),
    R("WDNS-REBIND-002", "Loopback in public name", "rebinding", "RFC6890", "RFC", "high", "captive portal", "Treat as FINDING if public zone", E_PRIV),
    R("WDNS-REBIND-003", "Link-local 169.254", "rebinding", "RFC3927", "ITU", "medium", "misconfig", "Same", E_PRIV),
    R("WDNS-REBIND-004", "TTL+sequence needs history", "rebinding", "RFC1035", "HP", "info", "n/a", "INCONCLUSIVE one-shot", E_NONE),

    R("WDNS-FLUX-001", "Sub-minute A TTL", "fast_flux", "RFC1035", "SANS", "low", "CDN", "Not malicious alone", E_TTL),
    R("WDNS-FLUX-002", "High A diversity across resolvers", "fast_flux", "n/a", "Cisco", "low", "anycast", "See poison compare", E_COMPARE),
    R("WDNS-FLUX-003", "NS churn", "fast_flux", "n/a", "SANS", "low", "provider anycast", "Needs history", E_NONE),
    R("WDNS-FLUX-004", "Geo diversity unknown without ASN", "fast_flux", "n/a", "Nokia", "info", "n/a", "INCONCLUSIVE", E_NONE),
    R("WDNS-FLUX-005", "Do not label infra malicious from flux-like TTL", "fast_flux", "n/a", "SANS", "info", "CDN", "Downgrade confidence", E_TTL),

    R("WDNS-DGA-001", "Label entropy feature", "dga", "n/a", "research", "info", "brand tokens", "Expose features, no family name", E_NONE),
    R("WDNS-DGA-002", "Vowel ratio feature", "dga", "n/a", "research", "info", "n/a", "Feature only", E_NONE),
    R("WDNS-DGA-003", "Numeric ratio", "dga", "n/a", "research", "info", "n/a", "Feature only", E_NONE),
    R("WDNS-DGA-004", "NXDOMAIN rate", "dga", "n/a", "Cisco", "low", "typos", "Needs stream", E_NX),
    R("WDNS-DGA-005", "ML optional never proof", "dga", "n/a", "ITU", "info", "n/a", "No crypto proof from ML", E_NONE),

    R("WDNS-INFRA-001", "Shared NS correlation", "malicious_infra", "n/a", "Cisco", "info", "SaaS NS", "Do not infer malice", E_NONE),
    R("WDNS-INFRA-002", "Shared IP", "malicious_infra", "n/a", "HP", "info", "shared hosting", "Graph only", E_NONE),
    R("WDNS-INFRA-003", "ASN unknown in this build", "malicious_infra", "n/a", "Nokia", "info", "n/a", "INCONCLUSIVE", E_NONE),
    R("WDNS-INFRA-004", "Relationship graph stub", "malicious_infra", "n/a", "ITU", "info", "n/a", "NS+A+MX edges", E_NONE),

    R("WDNS-WILD-001", "A wildcard", "wildcard", "RFC4592", "RFC", "low", "catch-all product", "Probe random label", E_WILD),
    R("WDNS-WILD-002", "AAAA wildcard", "wildcard", "RFC4592", "RFC", "low", "same", "Same probe", E_WILD),
    R("WDNS-WILD-003", "MX wildcard", "wildcard", "RFC4592", "RFC", "medium", "rare legit", "Unusual — FINDING if present", E_NONE),
    R("WDNS-WILD-004", "TXT wildcard", "wildcard", "RFC4592", "SANS", "medium", "rare", "Unusual", E_NONE),

    R("WDNS-EMAIL-001", "SPF presence", "email_dns", "RFC7208", "Cisco ESA", "medium", "no mail", "Publish SPF if mail used", E_SPF),
    R("WDNS-EMAIL-002", "Multiple SPF records", "email_dns", "RFC7208", "RFC", "medium", "misconfig", "One SPF TXT only", E_SPF),
    R("WDNS-EMAIL-003", "Overly broad +all/- missing", "email_dns", "RFC7208", "Cisco", "medium", "transition", "Prefer -all", E_SPF),
    R("WDNS-EMAIL-004", "DMARC presence", "email_dns", "RFC7489", "Cisco", "medium", "no mail", "Publish _dmarc", E_DMARC),
    R("WDNS-EMAIL-005", "Weak DMARC p=none", "email_dns", "RFC7489", "Cisco", "low", "monitor mode", "Move to quarantine/reject", E_DMARC),
    R("WDNS-EMAIL-006", "MX presence", "email_dns", "RFC5321", "RFC", "info", "no mail", "OK if no mail", E_MX),
    R("WDNS-EMAIL-007", "CAA presence", "email_dns", "RFC8659", "ITU", "low", "public CA any", "Publish CAA", E_CAA),
    R("WDNS-EMAIL-008", "MTA-STS/TLS-RPT not queried in safe profile", "email_dns", "RFC8461", "RFC", "info", "n/a", "Optional deep profile", E_NONE),

    R("WDNS-RECON-001", "NS enumeration", "reconnaissance", "RFC1035", "Cisco", "info", "public NS", "Expected public data", E_NONE),
    R("WDNS-RECON-002", "MX discovery", "reconnaissance", "RFC1035", "Cisco", "info", "public MX", "Expected", E_MX),
    R("WDNS-RECON-003", "TXT discovery", "reconnaissance", "RFC1035", "SANS", "info", "vendor TXT", "Review secrets in TXT", E_TXT),
    R("WDNS-RECON-004", "SRV discovery", "reconnaissance", "RFC2782", "RFC", "info", "no SRV", "Optional", E_NONE),
    R("WDNS-RECON-005", "Subdomain enum is separate command", "reconnaissance", "n/a", "SANS", "info", "n/a", "Use enum under scope", E_NONE),
    R("WDNS-RECON-006", "Reverse DNS not default", "reconnaissance", "RFC1035", "IANA", "info", "n/a", "Optional deep", E_NONE),

    R("WDNS-PRIV-001", "Private A on public name", "privacy_leak", "RFC1918", "ITU X.805", "medium", "split horizon leak", "Remove RFC1918 from public view", E_PRIV),
    R("WDNS-PRIV-002", "Internal hostname pattern", "privacy_leak", "n/a", "Cisco", "low", "brand .internal public", "Policy warn, do not block covert resolver", E_INTERNAL),
    R("WDNS-PRIV-003", "Staging/test label", "privacy_leak", "n/a", "HP", "low", "public staging", "Review exposure", E_INTERNAL),
    R("WDNS-PRIV-004", "Sensitive TXT metadata", "privacy_leak", "RFC1035", "Dell", "low", "verification tokens", "Tokens are public by design", E_TXT),
    R("WDNS-PRIV-005", "Dev naming convention", "privacy_leak", "n/a", "Nokia", "low", "dev.product.com", "Policy", E_INTERNAL),
    R("WDNS-PRIV-006", "ODoH residual: target sees QNAME", "privacy_leak", "RFC9230", "RFC", "info", "design", "See odoh-leak", E_NONE),

    R("WDNS-BEHAVE-001", "No historical baseline in this snapshot", "behavioral", "n/a", "ITU", "info", "n/a", "Store JSONL for mean/p95", E_NONE),
    R("WDNS-BEHAVE-002", "Change-rate unknown", "behavioral", "n/a", "Cisco", "info", "n/a", "Needs store", E_NONE),
    R("WDNS-BEHAVE-003", "Cardinality unknown", "behavioral", "n/a", "HP", "info", "n/a", "Needs store", E_NONE),
    R("WDNS-BEHAVE-004", "Entropy of apex label only", "behavioral", "n/a", "research", "info", "brand", "Feature", E_NONE),

    R("WDNS-PROTO-001", "FORMERR/malformed", "protocol_abuse", "RFC1035", "RFC", "medium", "broken middlebox", "WDNS-E002", E_NONE),
    R("WDNS-PROTO-002", "TC then TCP fallback", "protocol_abuse", "RFC7766", "RFC", "info", "large answer", "Normal", E_NONE),
    R("WDNS-PROTO-003", "EDNS presence", "protocol_abuse", "RFC6891", "RFC", "info", "n/a", "Expected", E_NONE),
    R("WDNS-PROTO-004", "Opcode not QUERY", "protocol_abuse", "RFC2136", "RFC", "info", "n/a", "Not sent by this client", E_NONE),
    R("WDNS-PROTO-005", "RCODE health", "protocol_abuse", "IANA rcode", "IANA", "info", "n/a", "Surface SERVFAIL", E_NX),

    R("WDNS-PARSE-001", "Hostile input bounds", "parser", "RFC1035", "RFC", "info", "n/a", "Label≤63 name≤255 jumps≤20", E_NONE),
    R("WDNS-PARSE-002", "Compression-bomb guard", "parser", "RFC1035", "RFC", "info", "n/a", "Jump cap", E_NONE),
    R("WDNS-PARSE-003", "TXT never passed to shell", "parser", "n/a", "Dell", "info", "n/a", "No command injection", E_NONE),
};

} // namespace

const std::vector<ThreatRule>& threat_catalog() {
    static std::vector<ThreatRule> v(std::begin(kRules), std::end(kRules));
    return v;
}

const ThreatRule* find_threat_rule(const std::string& id) {
    for (const auto& r : threat_catalog())
        if (r.id == id) return &r;
    return nullptr;
}

void print_threat_catalog() {
    std::cout << "WhiteDNS threat taxonomy  v1.0.0  rules=" << threat_catalog().size() << "\n";
    for (const auto& r : threat_catalog())
        std::cout << r.id << "  [" << r.category << "]  " << r.name << "\n";
}

void print_threat_categories() {
    std::map<std::string, int> c;
    for (const auto& r : threat_catalog()) c[r.category]++;
    std::cout << "WhiteDNS threat categories (" << c.size() << ")\n";
    for (const auto& kv : c) std::cout << "  " << kv.first << "  " << kv.second << "\n";
}

void print_threat_info(const std::string& id) {
    auto* r = find_threat_rule(id);
    if (!r) {
        std::cout << "unknown rule " << id << "\n";
        return;
    }
    std::cout << r->id << "\n  name: " << r->name << "\n  category: " << r->category
              << "\n  rfc: " << r->rfc << "\n  ref: " << r->vendor
              << "\n  severity: " << r->severity << "\n  false_positives: " << r->fp
              << "\n  recommendation: " << r->recommend
              << "\n  remote_eval: " << (r->eval ? "yes" : "catalog/inconclusive") << "\n";
}

void print_threat_explain(const std::string& id) {
    print_threat_info(id);
    auto* r = find_threat_rule(id);
    if (!r) return;
    std::cout << "  why: rule fires only from collected DNS observations, never from a guess.\n";
    std::cout << "  alternatives: " << r->fp << "\n";
    std::cout << "  confidence stays low unless evidence_strength is cryptographically_verified.\n";
}

bool validate_threat_rules() {
    std::set<std::string> ids;
    for (const auto& r : threat_catalog()) {
        if (!ids.insert(r.id).second) return false;
        if (std::string(r.id).rfind("WDNS-", 0) != 0) return false;
    }
    return ids.size() >= 100;
}

static std::string sha256_hex(const std::string& s) {
#ifdef WHITEDNS_HAVE_OPENSSL
    unsigned char out[32];
    unsigned int len = 0;
    if (EVP_Digest(s.data(), s.size(), out, &len, EVP_sha256(), nullptr) != 1) return "";
    static const char* hexd = "0123456789abcdef";
    std::string h;
    h.resize(len * 2);
    for (unsigned i = 0; i < len; ++i) {
        h[2 * i] = hexd[out[i] >> 4];
        h[2 * i + 1] = hexd[out[i] & 0xf];
    }
    return h;
#else
    return "no-openssl";
#endif
}

ThreatDetectReport run_threat_detect(const std::string& qname) {
    ThreatDetectReport report;
    report.qname = qname;
    report.rules = static_cast<int>(threat_catalog().size());
    ResolverEngine engine;
    auto a = engine.query(qname, DNS_TYPE_A, "8.8.8.8");
    auto txt = engine.query(qname, DNS_TYPE_TXT, "8.8.8.8");
    auto mx = engine.query(qname, DNS_TYPE_MX, "8.8.8.8");
    auto caa = engine.query(qname, DNS_TYPE_CAA, "8.8.8.8");
    auto dmarc = engine.query("_dmarc." + qname, DNS_TYPE_TXT, "8.8.8.8");
    auto wild = engine.query("whitedns-wild-tax." + qname, DNS_TYPE_A, "8.8.8.8");
    auto nx = engine.query("whitedns-nx-tax." + qname, DNS_TYPE_A, "8.8.8.8");
    auto poison = run_poison_classifier(qname, {});
    auto path = run_dnssec_path(qname, "8.8.8.8");

    std::set<std::string> as;
    uint32_t min_ttl = 0;
    bool any_a = false, priv = false;
    for (const auto& r : a.message.answers) {
        if (r.type != DNS_TYPE_A) continue;
        as.insert(r.value);
        any_a = true;
        if (min_ttl == 0 || r.ttl < min_ttl) min_ttl = r.ttl;
        if (r.value.rfind("10.", 0) == 0 || r.value.rfind("192.168.", 0) == 0 || r.value.rfind("127.", 0) == 0)
            priv = true;
    }
    int spf_n = 0;
    bool spf_all_plus = false;
    std::string txt_blob;
    for (const auto& r : txt.message.answers) {
        txt_blob += r.value + " ";
        if (r.value.rfind("v=spf1", 0) == 0) {
            spf_n++;
            if (r.value.find("+all") != std::string::npos ||
                (r.value.find(" -all") == std::string::npos && r.value.find(" ~all") == std::string::npos))
                spf_all_plus = true;
        }
    }
    bool has_mx = false;
    for (const auto& r : mx.message.answers)
        if (r.type == DNS_TYPE_MX) has_mx = true;
    bool has_caa = false;
    for (const auto& r : caa.message.answers)
        if (r.type == DNS_TYPE_CAA) has_caa = true;
    std::string dmarc_v;
    for (const auto& r : dmarc.message.answers)
        if (r.value.rfind("v=DMARC1", 0) == 0) dmarc_v = r.value;
    bool wild_hit = wild.message.flags.rcode == 0 && !wild.message.answers.empty();
    bool nx_ok = nx.message.flags.rcode == 3;
    std::string qlow = qname;
    std::transform(qlow.begin(), qlow.end(), qlow.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    bool internal = qlow.find(".internal") != std::string::npos || qlow.find("staging.") == 0 ||
                    qlow.find("dev.") == 0 || qlow.find("test.") == 0;

    auto add = [&](const ThreatRule& rule, const char* kind, const char* conf, const char* str, const std::string& d) {
        ThreatFinding f;
        f.rule_id = rule.id;
        f.kind = kind;
        f.confidence = conf;
        f.evidence_strength = str;
        f.detail = d;
        report.findings.push_back(f);
        report.evaluated++;
    };

    for (const auto& rule : threat_catalog()) {
        if (rule.eval == E_NONE) {
            report.inconclusive++;
            continue;
        }
        switch (rule.eval) {
            case E_COMPARE:
                if (poison.sets_agree)
                    add(rule, "OBSERVATION", "medium", "moderate", poison.a_sets.empty() ? "agree" : poison.a_sets.front());
                else
                    add(rule, "ANOMALY", "low", "weak", "resolver A sets differ — anycast/GeoDNS first");
                break;
            case E_DNSSEC:
                if (path.ds_matches_key)
                    add(rule, "OBSERVATION", "high", "cryptographically_verified", path.chain_message);
                else if (path.ds_present || path.dnskey_present)
                    add(rule, "ANOMALY", "medium", "moderate", path.chain_message);
                else
                    add(rule, "OBSERVATION", "low", "weak", "no DS/DNSKEY on path");
                break;
            case E_UNSIGNED:
                if (!path.ds_present && !path.dnskey_present)
                    add(rule, "FINDING", "medium", "moderate", "unsigned on this recursive path");
                else
                    add(rule, "OBSERVATION", "high", "moderate", "DNSSEC material present");
                break;
            case E_SPF:
                if (spf_n == 0)
                    add(rule, "FINDING", "medium", "moderate", "no v=spf1");
                else if (spf_n > 1)
                    add(rule, "FINDING", "medium", "moderate", "multiple SPF TXT");
                else if (spf_all_plus)
                    add(rule, "FINDING", "low", "moderate", "SPF not terminating -all/~all");
                else
                    add(rule, "OBSERVATION", "high", "moderate", "single SPF present");
                break;
            case E_DMARC:
                if (dmarc_v.empty())
                    add(rule, "FINDING", "medium", "moderate", "no _dmarc");
                else if (dmarc_v.find("p=none") != std::string::npos)
                    add(rule, "FINDING", "low", "moderate", dmarc_v);
                else
                    add(rule, "OBSERVATION", "high", "moderate", dmarc_v);
                break;
            case E_MX:
                add(rule, has_mx ? "OBSERVATION" : "OBSERVATION", "medium", "moderate",
                    has_mx ? "MX present" : "no MX (ok if no mail)");
                break;
            case E_WILD:
                add(rule, wild_hit ? "ANOMALY" : "OBSERVATION", wild_hit ? "medium" : "high", "moderate",
                    wild_hit ? "random label answered — wildcard or catch-all" : "random label not answered as A");
                break;
            case E_NX:
                add(rule, nx_ok ? "OBSERVATION" : "ANOMALY", "medium", "moderate",
                    std::string("nx rcode=") + iana_rcode_name(nx.message.flags.rcode));
                break;
            case E_PRIV:
                add(rule, priv ? "FINDING" : "OBSERVATION", priv ? "high" : "high", "moderate",
                    priv ? "RFC1918/loopback in public A" : "public A only");
                break;
            case E_TTL:
                add(rule, (any_a && min_ttl < 60) ? "ANOMALY" : "OBSERVATION", "low", "weak",
                    any_a ? ("min A ttl=" + std::to_string(min_ttl) + "s") : "no A");
                break;
            case E_TXT:
                add(rule, txt_blob.size() > 400 ? "ANOMALY" : "OBSERVATION", "low", "weak",
                    "txt_bytes=" + std::to_string(txt_blob.size()));
                break;
            case E_AXFR: {
                auto ns = engine.query(qname, DNS_TYPE_NS, "8.8.8.8");
                add(rule, "OBSERVATION", "low", "weak",
                    "AXFR not sent to third-party NS (safe profile). Public posture expected REFUSED.");
                (void)ns;
                break;
            }
            case E_CAA:
                add(rule, has_caa ? "OBSERVATION" : "FINDING", "low", "moderate",
                    has_caa ? "CAA present" : "no CAA");
                break;
            case E_INTERNAL:
                add(rule, internal ? "FINDING" : "OBSERVATION", "low", "weak",
                    internal ? "name matches staging/dev/test/internal policy" : "no internal-pattern on apex");
                break;
            default:
                report.inconclusive++;
                break;
        }
    }
    std::ostringstream ev;
    ev << qname << "|" << poison.verdict << "|" << path.klass << "|" << as.size();
    report.evidence_sha256 = sha256_hex(ev.str());
    return report;
}

void print_threat_detect(const ThreatDetectReport& report) {
    std::cout << "WhiteDNS detect  target=" << report.qname << "\n";
    std::cout << "taxonomy_version=1.0  rules=" << report.rules
              << " evaluated=" << report.evaluated
              << " catalog_inconclusive=" << report.inconclusive << "\n";
    std::cout << "evidence_sha256=" << report.evidence_sha256 << "\n";
    std::cout << "Concepts: OBSERVATION ≠ ANOMALY ≠ FINDING ≠ CONFIRMED ATTACK\n";
    std::cout << "------------------------------------------------------------\n";
    for (const auto& f : report.findings) {
        std::cout << "[" << f.kind << "] " << f.rule_id << "  conf=" << f.confidence
                  << "  ev=" << f.evidence_strength << "\n";
        std::cout << "        " << f.detail << "\n";
    }
}

} // namespace core
} // namespace whitedns
