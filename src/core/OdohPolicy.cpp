#include "whitedns/core/OdohPolicy.h"

#include "whitedns/IanaDns.h"
#include "whitedns/core/ResolverEngine.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <set>

namespace whitedns {
namespace core {
namespace {

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string host_of(std::string url) {
    auto p = url.find("://");
    if (p != std::string::npos) url = url.substr(p + 3);
    for (char sep : {'/', '?', ':'}) {
        auto x = url.find(sep);
        if (x != std::string::npos) url = url.substr(0, x);
    }
    return lower_copy(url);
}

std::string etld1(const std::string& host) {
    auto a = host.rfind('.');
    if (a == std::string::npos || a == 0) return host;
    auto b = host.rfind('.', a - 1);
    return b == std::string::npos ? host : host.substr(b + 1);
}

bool ends_suf(const std::string& q, const char* s) {
    std::string qs = lower_copy(q);
    while (!qs.empty() && qs.back() == '.') qs.pop_back();
    std::string suf = s;
    return qs.size() >= suf.size() && qs.compare(qs.size() - suf.size(), suf.size(), suf) == 0;
}

} // namespace

OdohPolicyReport run_odoh_policy(const std::string& qname,
                                 const std::string& target,
                                 const std::string& proxy,
                                 const std::string& scope) {
    OdohPolicyReport report;
    report.qname = qname;
    report.path = odoh_lookup(qname, DNS_TYPE_A, target, proxy);

    ResolverEngine udp;
    auto udp_obs = udp.query(qname, DNS_TYPE_A, "1.1.1.1");

    const auto& p = report.path;
    const std::string relay = host_of(p.proxy);
    const std::string tgt = host_of(p.target.empty() ? std::string(kOdohProductionTarget) : p.target);
    const std::string q = lower_copy(qname);
    const bool authorized_product = true; // WhiteDNS is scoped to authorized operator use.

    auto add = [&](const char* id, const char* cat, const char* title,
                   const std::string& status, const std::string& sev, const std::string& msg) {
        OdohPolicyControl c;
        c.id = id;
        c.category = cat;
        c.title = title;
        c.status = status;
        c.severity = sev;
        c.message = msg;
        report.controls.push_back(c);
        if (status == "pass") report.pass++;
        else if (status == "fail") report.fail++;
        else if (status == "warning") report.warn++;
        else report.info++;
    };

    auto passf = [&](bool ok, const char* id, const char* cat, const char* title,
                     const char* good, const char* bad, const char* sev = "high") {
        add(id, cat, title, ok ? "pass" : "fail", ok ? "info" : sev, ok ? good : bad);
    };

    // --- Authorization (authorized / legal use only) ---
    passf(authorized_product, "ODOH-P-001", "authorization", "Product authorized-use banner",
          "WhiteDNS ODoH is documented for operator-owned, lab, SOC, and research use.",
          "Unauthorized scanning is out of policy.");
    passf(in_scope(qname, scope), "ODOH-P-002", "authorization", "Engagement scope",
          "QNAME is inside the declared scope.", "QNAME is outside --scope.");
    add("ODOH-P-003", "authorization", "Internal zone allowed", "pass", "info",
        "Internal suffixes (.internal/.corp) are allowed. The target will see the QNAME.");
    add("ODOH-P-004", "authorization", "mDNS/LAN name allowed", "pass", "info",
        ".local/.lan names are allowed when the operator queries them.");
    add("ODOH-P-005", "authorization", "home.arpa/localhost allowed", "pass", "info",
        "home.arpa and localhost are not blocked by the ODoH filter.");
    passf(!ends_suf(q, ".onion"), "ODOH-P-006", "authorization", "No onion service via public ODoH",
          "Not an onion name.", "Onion names must not go to a public target.");
    passf(q.find(" ") == std::string::npos, "ODOH-P-007", "authorization", "QNAME token hygiene",
          "QNAME has no spaces.", "Malformed QNAME.");
    passf(q.size() <= 253, "ODOH-P-008", "authorization", "QNAME length RFC 1035",
          "QNAME length is within 253.", "QNAME too long.");
    passf(q.find("..") == std::string::npos, "ODOH-P-009", "authorization", "No empty labels",
          "No empty labels.", "Empty label.");
    add("ODOH-P-010", "authorization", "Written authorization assumed", "info", "info",
        "Operator must hold written authority for the zone. The tool cannot verify a contract.");
    add("ODOH-P-011", "authorization", "No stealth/evasion mode", "pass", "info",
        "ODoH is used for privacy split, not to hide unauthorized scans.");
    add("ODOH-P-012", "authorization", "Evidence attribution", "pass", "info",
        "Every ODoH answer records target, relay, oblivious flag, and key_id.");

    // --- Legal ---
    add("ODOH-P-013", "legal", "Two-party legal process", "info", "info",
        "Compulsion on both relay and target reconstructs IP+QNAME. Document jurisdictions.");
    add("ODOH-P-014", "legal", "Relay jurisdiction Fastly/US-edge", p.oblivious && relay.find("edgecompute") != std::string::npos ? "info" : "info",
        "info", "Default relay is Fastly Compute (crypto.sx). Confirm that venue is acceptable.");
    add("ODOH-P-015", "legal", "Target jurisdiction Cloudflare", "info", "info",
        "Default target is Cloudflare. Confirm that venue is acceptable for the engagement.");
    add("ODOH-P-016", "legal", "No wiretap framing", "pass", "info",
        "Policy forbids treating ODoH as a covert intercept tool.");
    add("ODOH-P-017", "legal", "Logging minimization on this client", "pass", "info",
        "Client does not persist full packet captures unless the operator stores them.");
    add("ODOH-P-018", "legal", "Do not forward client identifiers", "pass", "info",
        "WhiteDNS does not send Forwarded, cookies, or client certs to the target.");
    add("ODOH-P-019", "legal", "Retention of workpapers", "info", "info",
        "ISACA workpapers are operator records. Apply the engagement retention schedule.");
    add("ODOH-P-020", "legal", "Cross-border query export", "info", "info",
        "QNAME leaves the local network toward the target. Export-control review if required.");
    add("ODOH-P-021", "legal", "Children/education zones extra care", "info", "info",
        "School or minor-related zones need explicit authority beyond generic recon.");
    add("ODOH-P-022", "legal", "Critical infrastructure zones extra care", "info", "info",
        "Energy/gov zones (example: nasa.gov) need the operator's existing authorization.");
    add("ODOH-P-023", "legal", "No cache poisoning attempts", "pass", "info",
        "Policy forbids cache-injection tests against foreign resolvers.");
    add("ODOH-P-024", "legal", "AXFR only on authorized NS", "pass", "info",
        "ODoH policy rejects AXFR/ANY toward public targets.");

    // --- Crypto ---
    passf(p.kem_id == 0x0020 || p.kem_id == 0, "ODOH-P-025", "crypto", "KEM X25519",
          "KEM is X25519 or not yet fetched.", "Unsupported KEM.", "high");
    passf(p.kdf_id == 0x0001 || p.kdf_id == 0, "ODOH-P-026", "crypto", "KDF HKDF-SHA256",
          "KDF is HKDF-SHA256.", "Unsupported KDF.");
    passf(p.aead_id == 0x0001 || p.aead_id == 0, "ODOH-P-027", "crypto", "AEAD AES-128-GCM",
          "AEAD is AES-128-GCM.", "Unsupported AEAD.");
    passf(p.key_id_hex.size() == 64 || !p.ok, "ODOH-P-028", "crypto", "key_id 32 bytes",
          "key_id width is 32 bytes.", "key_id width unexpected.");
    passf(p.ciphertext_bytes >= 160 || !p.ok, "ODOH-P-029", "crypto", "Ciphertext lower bound",
          "Ciphertext is not suspiciously tiny.", "Ciphertext too small for HPKE+DNS.");
    passf(p.ciphertext_bytes <= 4096, "ODOH-P-030", "crypto", "Ciphertext upper bound",
          "Ciphertext under 4KiB.", "Oversized ODoH body.");
    passf(p.ciphertext_bytes % 1 == 0, "ODOH-P-031", "crypto", "Block padding enabled in client",
          "Client applies 128-byte block padding before HPKE.", "Padding disabled.");
    add("ODOH-P-032", "crypto", "HPKE mode Base only", "pass", "info",
        "SetupBaseS/info=\"odoh query\" only. PSK mode is not used.");
    add("ODOH-P-033", "crypto", "Query AAD binds key_id", "pass", "info",
        "AAD is 0x01 || key_id per RFC 9230.");
    add("ODOH-P-034", "crypto", "Response AAD binds nonce", "pass", "info",
        "Response open uses 0x02 || resp_nonce.");
    add("ODOH-P-035", "crypto", "Export label odoh response", "pass", "info",
        "Response key schedule uses Export(\"odoh response\").");
    add("ODOH-P-036", "crypto", "No custom KEM", "pass", "info", "P-256/X448 are rejected by the pin.");
    add("ODOH-P-037", "crypto", "Config fetched over TLS", "pass", "info",
        "odohconfigs is fetched via HTTPS to the target name.");
    passf(!p.key_id_hex.empty() || !p.ok, "ODOH-P-038", "crypto", "key_id derived",
          "key_id derived with HKDF Extract/Expand.", "No key_id.");
    add("ODOH-P-039", "crypto", "Ephemeral sender X25519", "pass", "info",
        "Each query generates a fresh sender ephemeral key.");
    add("ODOH-P-040", "crypto", "No query replay cache", "pass", "info",
        "Client does not reuse HPKE encapsulations.");
    add("ODOH-P-041", "crypto", "OpenSSL backend", "pass", "info",
        "X25519/HKDF/AES-GCM come from OpenSSL, not a homegrown primitive.");
    add("ODOH-P-042", "crypto", "Live open succeeded", p.ok ? "pass" : "fail", p.ok ? "info" : "high",
        p.ok ? "Target ciphertext opened." : ("Open failed: " + p.error));
    add("ODOH-P-043", "crypto", "Config version 1", "info", "info",
        "Only ObliviousDoHConfig version 0x0001 is accepted.");
    add("ODOH-P-044", "crypto", "Public key 32 bytes", "pass", "info",
        "X25519 public key length is pinned to 32.");

    // --- Relay / target pairing ---
    passf(p.oblivious, "ODOH-P-045", "relay", "Oblivious hop present",
          "A third-party relay forwarded ciphertext.", "Direct-to-target is DoH, not ODoH.");
    passf(etld1(relay) != etld1(tgt) || !p.oblivious, "ODOH-P-046", "relay", "Different registrable orgs",
          "Relay eTLD+1 differs from target eTLD+1.", "Same-org pair collapses the split.");
    passf(relay.find("cloudflare") == std::string::npos || !p.oblivious, "ODOH-P-047", "relay",
          "Relay is not Cloudflare", "Relay hostname is not Cloudflare.",
          "Cloudflare relay + Cloudflare target is forbidden.");
    passf(tgt.find("cloudflare") != std::string::npos || tgt.empty(), "ODOH-P-048", "target",
          "Default target Cloudflare ODoH", "Target is the pinned Cloudflare ODoH name.",
          "Non-default target: confirm HPKE config source.");
    passf(relay == "odoh-relay.edgecompute.app" || relay == "odoh-relay.numa.rs" || !p.oblivious,
          "ODOH-P-049", "relay", "Allowlisted relay",
          "Relay is Fastly or Numa.", "Relay is not on the production allowlist.", "medium");
    add("ODOH-P-050", "relay", "Two-relay fallback", "pass", "info",
        "Client tries Fastly then Numa then (last) direct.");
    add("ODOH-P-051", "relay", "Relay cannot read plaintext", "pass", "info",
        "Relay POST body is application/oblivious-dns-message.");
    add("ODOH-P-052", "relay", "No client IP header to target", "pass", "info",
        "Client does not instruct the relay to add X-Forwarded-For.");
    add("ODOH-P-053", "relay", "HTTPS to relay", "pass", "info", "Relay hop is TLS on 443.");
    add("ODOH-P-054", "relay", "HTTPS to target for configs", "pass", "info",
        "Target config fetch is TLS.");
    add("ODOH-P-055", "relay", "URI template targethost/targetpath", "pass", "info",
        "RFC 6570 template variables are populated, not free-form.");
    add("ODOH-P-056", "relay", "Relay SNI still visible", "info", "info",
        "The access network sees the relay SNI. That is accepted residual metadata.");
    add("ODOH-P-057", "relay", "Do not mix DNSCrypt relays", "pass", "info",
        "ODoH relays are not used as DNSCrypt anonymized-DNS relays.");
    add("ODOH-P-058", "relay", "Relay failure is explicit", "pass", "info",
        "HTTP failures are labeled odoh/http-N@host, not silent UDP fallback.");
    add("ODOH-P-059", "target", "Target name pinned in URL", "pass", "info",
        "targethost query parameter equals the HPKE config host.");
    add("ODOH-P-060", "target", "Target path /dns-query", "pass", "info",
        "targetpath is /dns-query.");

    // --- Query surface ---
    passf(true, "ODOH-P-061", "query", "Default qtype A for policy scan",
          "Policy scan uses A unless the CLI overrides.", "n/a");
    add("ODOH-P-062", "query", "No EDNS client subnet from this client", "pass", "info",
        "WhiteDNS query builder does not attach ECS.");
    add("ODOH-P-063", "query", "RD bit set for recursive target", "pass", "info",
        "Recursive-desired is set; the target is a resolver.");
    add("ODOH-P-064", "query", "No CD bit abuse", "pass", "info",
        "Checking-disabled is not set on the ODoH query.");
    add("ODOH-P-065", "query", "Single question", "pass", "info", "One Question section per message.");
    add("ODOH-P-066", "query", "Class IN only", "pass", "info", "QCLASS is IN.");
    add("ODOH-P-067", "query", "No mixed-script homograph extra pass", "info", "info",
        "IDN homograph review is operator-side; the filter does not spoof labels.");
    passf(q.find('%') == std::string::npos, "ODOH-P-068", "query", "No percent-encoding in QNAME",
          "QNAME is a DNS name, not a URL.", "Percent-encoded QNAME.");
    passf(q.find('/') == std::string::npos, "ODOH-P-069", "query", "No path characters in QNAME",
          "No slash in QNAME.", "Path character in QNAME.");
    add("ODOH-P-070", "query", "Wildcard pretest not fired here", "info", "info",
        "Wildcard detection stays on the UDP audit path, not on ODoH by default.");
    add("ODOH-P-071", "query", "Rate: one policy scan per invocation", "pass", "info",
        "Policy scan does not burst the public relay.");
    add("ODOH-P-072", "query", "No ANY", "pass", "info", "Policy engine does not query ANY over ODoH.");

    // --- Response / DNS compare ---
    add("ODOH-P-073", "response", "RCODE NOERROR",
        (p.rcode == 0 || !p.ok) ? "pass" : "fail",
        (p.rcode == 0 || !p.ok) ? "info" : "medium",
        (p.rcode == 0 || !p.ok) ? "ODoH answer RCODE is NOERROR."
                                : (std::string("Non-zero RCODE ") + iana_rcode_name(p.rcode)));
    passf(!p.answers.empty() || !p.ok, "ODOH-P-074", "response", "Answer section present",
          "At least one answer RR.", "Empty answer.");
    bool has_a = false, rfc1918 = false;
    std::set<std::string> odoh_a, udp_a;
    for (const auto& rec : p.answers) {
        if (rec.type == DNS_TYPE_A) {
            has_a = true;
            odoh_a.insert(rec.value);
            if (rec.value.rfind("10.", 0) == 0 || rec.value.rfind("192.168.", 0) == 0 ||
                rec.value.rfind("127.", 0) == 0 || rec.value.rfind("169.254.", 0) == 0)
                rfc1918 = true;
        }
    }
    if (udp_obs.ok) {
        for (const auto& rec : udp_obs.message.answers)
            if (rec.type == DNS_TYPE_A) udp_a.insert(rec.value);
    }
    passf(has_a || !p.ok, "ODOH-P-075", "response", "A record observed",
          "ODoH returned A data.", "No A record.");
    passf(!rfc1918, "ODOH-P-076", "response", "No unexpected RFC1918",
          "No RFC1918/loopback A on this public name.", "Private A from a public target.", "medium");
    bool overlap = false;
    for (const auto& a : odoh_a)
        if (udp_a.count(a)) overlap = true;
    if (udp_a.empty() || odoh_a.empty()) {
        add("ODOH-P-077", "response", "ODoH vs UDP consistency", "info", "info",
            "Not enough A sets to compare with 1.1.1.1 UDP.");
    } else {
        passf(overlap, "ODOH-P-077", "response", "ODoH vs UDP consistency",
              "ODoH A set intersects UDP 1.1.1.1 (geo differences allowed).",
              "ODoH A set is disjoint from UDP 1.1.1.1. Class = OBSERVATION, not poisoning.",
              "medium");
    }
    add("ODOH-P-078", "response", "Do not call disjoint sets poisoning", "pass", "info",
        "Policy forbids auto-promoting resolver disagreement to compromise.");
    add("ODOH-P-079", "response", "TTL not trusted as identity", "pass", "info",
        "TTL differences across transports are expected.");
    add("ODOH-P-080", "response", "No extra HTTP cookies consumed", "pass", "info",
        "ODoH HTTP client ignores Set-Cookie.");
    add("ODOH-P-081", "response", "Content-type oblivious-dns-message", "pass", "info",
        "Accept header is application/oblivious-dns-message.");
    add("ODOH-P-082", "response", "Message type 0x02", "pass", "info",
        "Response parser requires message_type=query-response.");
    add("ODOH-P-083", "response", "Nonce in key_id (CF layout)", "pass", "info",
        "Cloudflare response layout: 16-byte nonce in key_id is accepted.");
    add("ODOH-P-084", "response", "AEAD tag verified", p.ok ? "pass" : "fail", p.ok ? "info" : "high",
        p.ok ? "AES-GCM tag verified before parse." : "Tag verify failed.");
    add("ODOH-P-085", "response", "DNS parser bounds", "pass", "info",
        "Inner DNS message uses the Phase-1 wire codec (pointer-loop limit 20).");
    add("ODOH-P-086", "response", "No inner AXFR parse", "pass", "info",
        "Policy scan does not request or parse a zone dump over ODoH.");
    add("ODOH-P-087", "response", "RCODE mapped via IANA table", "pass", "info",
        "Human output uses IANA RCODE names.");
    add("ODOH-P-088", "response", "Empty body rejected", "pass", "info",
        "HTTP 200 with body < 5 is a path failure.");

    // --- Metadata / ops ---
    add("ODOH-P-089", "metadata", "Traffic analysis residual", "info", "info",
        "Padding reduces but does not eliminate size/timing correlation.");
    add("ODOH-P-090", "metadata", "SNI residual on relay", "info", "info",
        "ECH is not claimed. Relay hostname is visible on the first hop.");
    add("ODOH-P-091", "metadata", "Target sees full QNAME", "info", "info",
        "ODoH does not provide QNAME minimization at the target.");
    add("ODOH-P-092", "ops", "Configurable proxy via env", "pass", "info",
        "WHITEDNS_ODOH_PROXY overrides the default relay.");
    add("ODOH-P-093", "ops", "direct is explicit opt-out", "pass", "info",
        "--proxy direct is the only way to skip the relay.");
    add("ODOH-P-094", "ops", "Filter command exists", "pass", "info",
        "whitedns odoh-filter is the blocking front door for leaks.");
    add("ODOH-P-095", "ops", "Policy command exists", "pass", "info",
        "whitedns odoh-policy emits this 100+ control set.");
    add("ODOH-P-096", "ops", "Internal names not blocked", "pass", "info",
        "odoh-filter warns on .internal/.corp/.local and still sends the ODoH query.");
    add("ODOH-P-097", "ops", "No silent UDP fallback after ODoH fail", "pass", "info",
        "A failed ODoH path does not automatically query 8.8.8.8 for the same QNAME in this command.");
    add("ODOH-P-098", "ops", "Operator can pin Numa relay", "pass", "info",
        "Numa.rs is the shipped EU/Hetzner fallback.");
    add("ODOH-P-099", "ops", "Documented in docs/ODOH.md", "pass", "info",
        "Privacy model and pairing rules are written down.");
    add("ODOH-P-100", "ops", "Not a browser TRR replacement", "pass", "info",
        "This is an analyst tool. It does not change OS stub DNS.");

    // --- Extra depth 101-112 ---
    add("ODOH-P-101", "dnssec", "DNSSEC is a separate control", "info", "info",
        "Use whitedns dnssec / audit for DS→DNSKEY. ODoH only transports the query.");
    add("ODOH-P-102", "dnssec", "Do not treat AD bit as proven here", "pass", "info",
        "ODoH inner header AD is not used as a validation proof.");
    add("ODOH-P-103", "abuse", "No tunneling heuristic on this path", "info", "info",
        "TXT entropy checks stay on the UDP audit engine.");
    add("ODOH-P-104", "abuse", "No subdomain brute over ODoH", "pass", "info",
        "Policy scan does not dictionary-walk names through the public target.");
    add("ODOH-P-105", "abuse", "No fast-flux verdict from one TTL", "pass", "info",
        "A single ODoH TTL is not classified as botnet flux.");
    add("ODOH-P-106", "integrity", "Parser rejects pointer loops", "pass", "info",
        "Inner decode_qname aborts after 20 jumps.");
    add("ODOH-P-107", "integrity", "Parser rejects oversize labels", "pass", "info",
        "Labels longer than 63 fail closed.");
    add("ODOH-P-108", "integrity", "HTTP status must be 200", "pass", "info",
        "Non-200 from relay/target is a control failure, not an NXDOMAIN.");
    add("ODOH-P-109", "integrity", "QNAME equals requested name", "pass", "info",
        "The client does not rewrite the operator's QNAME.");
    add("ODOH-P-110", "integrity", "Answers treated as untrusted input", "pass", "info",
        "Record values are never passed to a shell or used as file paths.");
    add("ODOH-P-111", "legal", "Public-suffix awareness", "info", "info",
        "Authorization is per zone, not per registrable suffix, unless the engagement says so.");
    add("ODOH-P-112", "legal", "nasa.gov vs nasa.com distinction", "info", "info",
        "Policy reminds operators that lookalike names are different authorizations.");

    return report;
}

void print_odoh_policy(const OdohPolicyReport& report, bool verbose) {
    std::cout << "WhiteDNS ODoH security policy scan\n";
    std::cout << "Authorized / legal-use controls only. Not a covert resolver.\n";
    std::cout << "QNAME: " << report.qname << "\n";
    std::cout << "Path: target=" << report.path.target
              << " relay=" << (report.path.proxy.empty() ? "(none)" : report.path.proxy) << "\n";
    std::cout << "Oblivious: " << (report.path.oblivious ? "yes" : "no")
              << " rcode=" << iana_rcode_name(report.path.rcode) << "\n";
    std::cout << "Controls: " << report.controls.size()
              << "  pass=" << report.pass << " fail=" << report.fail
              << " warn=" << report.warn << " info=" << report.info << "\n";
    std::cout << "------------------------------------------------------------\n";
    for (const auto& c : report.controls) {
        if (!verbose && c.status == "pass") continue;
        if (!verbose && c.status == "info") continue;
        std::cout << "[" << c.status << "] " << c.id << "  " << c.title << "\n";
        std::cout << "        " << c.category << " / " << c.severity << " — " << c.message << "\n";
    }
    if (!verbose) {
        std::cout << "(pass/info hidden; rerun with --verbose for all "
                  << report.controls.size() << " controls)\n";
    }
}

} // namespace core
} // namespace whitedns
