#include "whitedns/FrameworkAudit.h"

#include "whitedns/DnsClient.h"
#include "whitedns/Dnssec.h"
#include "whitedns/IanaDns.h"
#include "whitedns/core/DohClient.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <iostream>
#include <map>
#include <set>
#include <sstream>

namespace whitedns {
namespace {

FrameworkFinding make_finding(const std::string& id,
                              const std::string& title,
                              const std::string& status,
                              const std::string& severity,
                              const std::string& message,
                              const std::string& sans,
                              const std::string& mitre,
                              const std::string& tactic,
                              const std::string& rfc,
                              const std::string& isaca,
                              const std::string& change = "") {
    FrameworkFinding f;
    f.finding_id = id;
    f.title = title;
    f.status = status;
    f.severity = severity;
    f.message = message;
    f.sans_class = sans;
    f.mitre_id = mitre;
    f.mitre_tactic = tactic;
    f.rfc_ref = rfc;
    f.iana_ref = "IANA DNS Parameters RR TYPE / RCODE registries";
    f.isaca_control = isaca;
    f.change_required = change;
    f.evidence = Json::Value(Json::objectValue);
    return f;
}

std::vector<const DnsResponse*> of_type(const std::vector<DnsResponse>& queries, uint16_t type) {
    std::vector<const DnsResponse*> out;
    for (const auto& q : queries) {
        if (q.query_type == type) out.push_back(&q);
    }
    return out;
}

std::set<std::string> values(const std::vector<DnsResponse>& queries, uint16_t type) {
    std::set<std::string> out;
    for (const auto& q : queries) {
        if (q.error) continue;
        auto take = [&](const std::vector<DnsRecord>& recs) {
            for (const auto& rec : recs) {
                if (rec.type == type) out.insert(rec.value);
            }
        };
        if (q.query_type == type || type == DNS_TYPE_DS || type == DNS_TYPE_DNSKEY || type == DNS_TYPE_RRSIG) {
            take(q.answers);
            take(q.authority);
        }
    }
    return out;
}

std::string ipv4_slash16(const std::string& ip) {
    auto pos = ip.find('.');
    if (pos == std::string::npos) return {};
    auto pos2 = ip.find('.', pos + 1);
    if (pos2 == std::string::npos) return {};
    return ip.substr(0, pos2);
}

bool ends_with_domain(const std::string& host, const std::string& domain) {
    std::string h = host;
    if (!h.empty() && h.back() == '.') h.pop_back();
    std::string d = domain;
    if (!d.empty() && d.back() == '.') d.pop_back();
    if (h.size() < d.size()) return false;
    if (h == d) return true;
    return h.size() > d.size() && h.compare(h.size() - d.size(), d.size(), d) == 0 && h[h.size() - d.size() - 1] == '.';
}

double shannon_entropy(const std::string& text) {
    if (text.empty()) return 0.0;
    int freq[256] = {};
    for (unsigned char c : text) freq[c]++;
    double ent = 0.0;
    const double n = static_cast<double>(text.size());
    for (int f : freq) {
        if (!f) continue;
        double p = static_cast<double>(f) / n;
        ent -= p * std::log2(p);
    }
    return ent;
}

std::string provider_label(const std::string& ns) {
    std::string s = ns;
    if (!s.empty() && s.back() == '.') s.pop_back();
    auto pos = s.find_last_of('.');
    if (pos == std::string::npos || pos == 0) return s;
    auto prev = s.find_last_of('.', pos - 1);
    if (prev == std::string::npos) return s.substr(pos + 1);
    return s.substr(prev + 1);
}

bool looks_spf(const std::string& txt) {
    return txt.find("v=spf1") != std::string::npos;
}

bool looks_dmarc(const std::string& txt) {
    return txt.find("v=DMARC1") != std::string::npos;
}

int severity_points(const std::string& severity, const std::string& status) {
    if (status == "pass" || status == "info") return 0;
    if (severity == "critical") return 40;
    if (severity == "high") return 25;
    if (severity == "medium") return 15;
    if (severity == "low") return 8;
    return 5;
}

} // namespace

FrameworkAuditReport run_framework_audit(const std::string& domain,
                                         const std::vector<std::string>& resolvers) {
    FrameworkAuditReport report;
    report.domain = domain;

    std::vector<std::string> servers = resolvers.empty()
        ? std::vector<std::string>{"8.8.8.8", "1.1.1.1"}
        : resolvers;

    const uint16_t types[] = {
        DNS_TYPE_SOA, DNS_TYPE_NS, DNS_TYPE_A, DNS_TYPE_AAAA,
        DNS_TYPE_MX, DNS_TYPE_TXT, DNS_TYPE_CNAME, DNS_TYPE_CAA,
        DNS_TYPE_DNSKEY, DNS_TYPE_DS, DNS_TYPE_RRSIG
    };

    DnsClient client;
    for (const auto& server : servers) {
        for (uint16_t type : types) {
            report.queries.push_back(client.query(domain, server, type, type == DNS_TYPE_DNSKEY || type == DNS_TYPE_RRSIG || type == DNS_TYPE_DS));
        }
    }

    // RFC 1035 SOA — zone authority / fault finding
    auto soa = values(report.queries, DNS_TYPE_SOA);
    {
        auto f = make_finding(
            "RFC-SOA-001", "SOA authority record",
            soa.empty() ? "fail" : "pass",
            soa.empty() ? "high" : "info",
            soa.empty()
                ? "No SOA answer. Zone authority metadata is missing from this resolver path (RFC 1035)."
                : "SOA present. Serial and primary nameserver metadata can be used for change and lame-delegation fault finding.",
            "SANS: zone integrity / unauthorized DNS change monitoring",
            "T1584.002", "Resource Development",
            "RFC1035 §3.3.13",
            "ISACA COBIT BAI10 Change Management; MEA01 Performance Monitoring",
            soa.empty() ? "Publish a valid SOA at the zone apex and confirm every resolver path can see it." : "No zone-authority change required. Monitor SOA serial for unexpected jumps.");
        Json::Value ev(Json::arrayValue);
        for (const auto& v : soa) ev.append(v);
        f.evidence["soa"] = ev;
        report.findings.push_back(f);
    }

    // RFC 1035 / RFC 2182 NS diversity
    auto ns = values(report.queries, DNS_TYPE_NS);
    {
        std::set<std::string> providers;
        for (const auto& n : ns) providers.insert(provider_label(n));
        bool in_bailiwick = !ns.empty();
        for (const auto& n : ns) {
            if (!ends_with_domain(n, domain)) in_bailiwick = false;
        }
        std::string status = "pass";
        std::string sev = "info";
        std::string msg = "Authoritative NS set meets basic resilience expectations.";
        std::string change = "No NS architecture change required.";
        if (ns.size() < 2) {
            status = "fail";
            sev = "high";
            msg = "Fewer than two NS records. RFC 2182 recommends geographically and topologically diverse secondaries.";
            change = "Add at least one independent secondary nameserver on a different network and provider.";
        } else if (providers.size() < 2 && !in_bailiwick) {
            status = "warning";
            sev = "medium";
            msg = "Multiple NS records exist but they appear to share one third-party provider label.";
            change = "Add a secondary on a different DNS operator so a single vendor outage cannot hide the zone.";
        } else if (providers.size() < 2 && in_bailiwick) {
            status = "pass";
            sev = "info";
            msg = "NS hosts are in-bailiwick first-party names (" + std::to_string(ns.size()) +
                  " unique servers). Shared parent label is expected for self-hosted anycast sets such as ns1-ns4.google.com.";
            change = "No vendor-diversity change required solely because the NS names share the zone. Confirm the servers are anycast/multi-site internally.";
        }
        auto f = make_finding(
            "IANA-NS-002", "Name server architecture",
            status, sev, msg,
            "SANS ISC: distinct / diverse authoritative servers",
            "T1583.002", "Resource Development",
            "RFC1035 NS; RFC2182 selection and operation of secondary DNS servers",
            "ISACA COBIT DSS01 Operations; DSS04 Continuity",
            change);
        Json::Value ev(Json::arrayValue);
        for (const auto& v : ns) ev.append(v);
        f.evidence["ns"] = ev;
        f.evidence["provider_labels"] = static_cast<int>(providers.size());
        report.findings.push_back(f);
    }

    // Addressing + dual-stack fault
    auto a = values(report.queries, DNS_TYPE_A);
    auto aaaa = values(report.queries, DNS_TYPE_AAAA);
    {
        std::string status = "pass";
        std::string sev = "info";
        std::string msg = "Address records are present.";
        if (a.empty() && aaaa.empty()) {
            status = "warning";
            sev = "medium";
            msg = "No A or AAAA at apex. This can be valid for alias-only or MX-only zones, but it is a common misconfiguration fault.";
        } else if (a.empty()) {
            status = "info";
            msg = "IPv6-only apex (AAAA without A).";
        } else if (aaaa.empty()) {
            status = "info";
            msg = "IPv4-only apex. Dual-stack is not required by RFC 3596 but is an availability consideration.";
        }
        auto f = make_finding(
            "RFC-ADDR-003", "A / AAAA addressing",
            status, sev, msg,
            "SANS: resolution integrity and availability",
            "T1590.002", "Reconnaissance",
            "RFC1035 A; RFC3596 AAAA",
            "ISACA COBIT DSS05 Managed Security Services");
        Json::Value ev4(Json::arrayValue);
        Json::Value ev6(Json::arrayValue);
        for (const auto& v : a) ev4.append(v);
        for (const auto& v : aaaa) ev6.append(v);
        f.evidence["a"] = ev4;
        f.evidence["aaaa"] = ev6;
        report.findings.push_back(f);
    }

    // Mail exchange faults
    auto mx = values(report.queries, DNS_TYPE_MX);
    {
        std::string status = mx.empty() ? "info" : "pass";
        std::string sev = "info";
        std::string msg = mx.empty()
            ? "No MX records. Acceptable if the domain does not receive mail; otherwise mail delivery will fail (RFC 5321 / RFC 1035)."
            : "MX records are published.";
        auto f = make_finding(
            "RFC-MX-004", "Mail exchanger set",
            status, sev, msg,
            "SANS: infrastructure enumeration and hijack surface",
            "T1590.002", "Reconnaissance",
            "RFC1035 MX; RFC7505 null MX",
            "ISACA COBIT DSS05; APO12 Risk");
        Json::Value ev(Json::arrayValue);
        for (const auto& v : mx) ev.append(v);
        f.evidence["mx"] = ev;
        report.findings.push_back(f);
    }

    // SPF / DMARC (email authentication as DNS policy)
    auto txt = values(report.queries, DNS_TYPE_TXT);
    DnsResponse dmarc_resp = client.query("_dmarc." + domain, servers.front(), DNS_TYPE_TXT);
    report.queries.push_back(dmarc_resp);
    bool has_spf = false;
    bool long_txt = false;
    double max_ent = 0.0;
    for (const auto& t : txt) {
        if (looks_spf(t)) has_spf = true;
        if (t.size() > 200) long_txt = true;
        max_ent = std::max(max_ent, shannon_entropy(t));
    }
    bool has_dmarc = false;
    for (const auto& rec : dmarc_resp.answers) {
        if (looks_dmarc(rec.value)) has_dmarc = true;
    }
    {
        std::string status = (has_spf && has_dmarc) ? "pass" : "warning";
        std::string sev = (has_spf && has_dmarc) ? "info" : "medium";
        auto f = make_finding(
            "RFC-MAILAUTH-005", "SPF and DMARC policy in DNS",
            status, sev,
            has_spf && has_dmarc
                ? "SPF and DMARC policy records are present."
                : "Missing SPF and/or DMARC. This is an email-spoofing and brand-abuse control gap, not a protocol crash.",
            "SANS: DNS as a security control plane (policy records)",
            "T1586", "Resource Development",
            "RFC7208 SPF; RFC7489 DMARC",
            "ISACA COBIT DSS05.02 Manage network and connectivity security; APO13 Security");
        f.evidence["spf"] = has_spf;
        f.evidence["dmarc"] = has_dmarc;
        report.findings.push_back(f);
    }

    // Tunneling heuristic — detection only
    {
        std::string status = "pass";
        std::string sev = "info";
        std::string msg = "TXT set does not show obvious high-entropy tunneling payload at the apex.";
        if (long_txt && max_ent >= 4.5) {
            status = "warning";
            sev = "medium";
            msg = "Long high-entropy TXT data at apex. Treat as a T1071.004 review item (possible tunneling/payload abuse), not proof of compromise.";
        }
        auto f = make_finding(
            "MITRE-T1071-006", "DNS application-layer abuse heuristic",
            status, sev, msg,
            "SANS: DNS tunneling / covert channel review",
            "T1071.004", "Command and Control",
            "RFC1035 TXT; RFC6891 EDNS0 size considerations",
            "ISACA COBIT DSS05.07 Monitor security; MEA01");
        f.evidence["max_txt_entropy"] = std::to_string(max_ent);
        f.evidence["long_txt"] = long_txt;
        report.findings.push_back(f);
    }

    // Resolver disagreement — cache poisoning / hijack signal
    {
        std::map<std::string, std::set<std::string>> by_server;
        for (const auto& q : report.queries) {
            if (q.query_type != DNS_TYPE_A || q.error) continue;
            for (const auto& rec : q.answers) {
                if (rec.type == DNS_TYPE_A) by_server[q.server].insert(rec.value);
            }
        }
        bool exact_disagree = false;
        std::set<std::string> first;
        bool have_first = false;
        std::set<std::string> prefixes;
        bool prefix_overlap = true;
        for (const auto& item : by_server) {
            if (!have_first) {
                first = item.second;
                have_first = true;
                for (const auto& ip : item.second) prefixes.insert(ipv4_slash16(ip));
            } else if (item.second != first) {
                exact_disagree = true;
                bool share = false;
                for (const auto& ip : item.second) {
                    if (prefixes.count(ipv4_slash16(ip))) share = true;
                }
                if (!share) prefix_overlap = false;
            }
        }
        bool poison_signal = exact_disagree && !prefix_overlap;
        auto f = make_finding(
            "SANS-POISON-007", "Multi-resolver A-record consistency",
            poison_signal ? "warning" : "pass",
            poison_signal ? "high" : "info",
            poison_signal
                ? "Resolvers returned A sets with no shared /16. Investigate cache poisoning or hijack."
                : (exact_disagree
                    ? "Resolvers returned different A sets that still share IPv4 /16 space. Treat as geo-DNS/anycast, not poisoning."
                    : "Compared resolvers returned a consistent A set for this vantage point."),
            "SANS: cache poisoning and DNS hijacking",
            "T1557", "Credential Access / Collection (adversary-in-the-middle class)",
            "RFC5452 measures against cache poisoning; RFC1034 resolution",
            "ISACA COBIT DSS05; MEA02 Internal control monitoring",
            poison_signal
                ? "Compare answers from a third resolver and from an authoritative NS. If only public resolvers disagree across ASNs, treat as incident."
                : "No poisoning change required. Continue multi-resolver monitoring.");
        f.evidence["resolver_count"] = static_cast<int>(by_server.size());
        f.evidence["exact_disagreement"] = exact_disagree;
        f.evidence["poison_signal"] = poison_signal;
        report.findings.push_back(f);
    }

    // Fast-flux TTL heuristic
    {
        std::vector<uint32_t> ttls;
        for (const auto& q : report.queries) {
            if (q.query_type != DNS_TYPE_A && q.query_type != DNS_TYPE_AAAA) continue;
            for (const auto& rec : q.answers) {
                if (rec.type == DNS_TYPE_A || rec.type == DNS_TYPE_AAAA) ttls.push_back(rec.ttl);
            }
        }
        bool low = !ttls.empty() && std::all_of(ttls.begin(), ttls.end(), [](uint32_t t) { return t > 0 && t < 60; });
        auto f = make_finding(
            "SANS-FLUX-008", "Address TTL fast-flux signal",
            low ? "warning" : "pass",
            low ? "medium" : "info",
            low
                ? "All observed address TTLs are under 60 seconds. Fast-flux botnets use this pattern; CDNs can as well."
                : "Address TTLs are not uniformly sub-minute.",
            "SANS: fast-flux detection",
            "T1568.001", "Command and Control",
            "RFC1035 TTL; RFC2181 TTL consistency",
            "ISACA COBIT DSS05; APO12");
        f.evidence["sample_ttl_count"] = static_cast<int>(ttls.size());
        report.findings.push_back(f);
    }

    // Cryptographic DNSSEC chain: DS digest must match a child DNSKEY (RFC 4034).
    {
        std::vector<DnsRecord> ds_recs, key_recs, sig_recs;
        auto harvest = [&]() {
            ds_recs.clear();
            key_recs.clear();
            sig_recs.clear();
            for (const auto& q : report.queries) {
                auto take = [&](const std::vector<DnsRecord>& recs) {
                    for (const auto& rec : recs) {
                        if (rec.type == DNS_TYPE_DS && !rec.rdata.empty()) ds_recs.push_back(rec);
                        if (rec.type == DNS_TYPE_DNSKEY && !rec.rdata.empty()) key_recs.push_back(rec);
                        if (rec.type == DNS_TYPE_RRSIG) sig_recs.push_back(rec);
                    }
                };
                take(q.answers);
                take(q.authority);
            }
        };
        harvest();
        if (ds_recs.empty() || key_recs.empty()) {
            auto inject = [&](uint16_t type) {
                auto doh = core::doh_lookup(domain, type);
                DnsResponse syn;
                syn.domain = domain;
                syn.server = doh.endpoint.empty() ? "doh" : doh.endpoint;
                syn.query_type = type;
                syn.query_type_name = dns_type_to_string(type);
                syn.error = !doh.ok;
                syn.error_message = doh.error;
                syn.rcode = doh.status < 0 ? 2 : static_cast<uint16_t>(doh.status);
                syn.answers = doh.records;
                syn.answer_count = static_cast<uint16_t>(doh.records.size());
                report.queries.push_back(syn);
            };
            if (ds_recs.empty()) inject(DNS_TYPE_DS);
            if (key_recs.empty()) inject(DNS_TYPE_DNSKEY);
            harvest();
        }
        DnssecChainResult chain = validate_ds_dnskey_chain(domain, ds_recs, key_recs, sig_recs);
        std::string status = chain.ds_matches_key ? "pass" : (chain.ds_present || chain.dnskey_present ? "warning" : "warning");
        std::string sev = chain.ds_matches_key ? "info" : "medium";
        auto f = make_finding(
            "SANS-DNSSEC-009", "DNSSEC cryptographic parent chain",
            status, sev, chain.message,
            "SANS Ed Skoudis: deploy DNSSEC signing and validation together",
            "T1557", "Adversary-in-the-middle class",
            "RFC4033/4034/4035",
            "ISACA COBIT DSS05.02; NIST-aligned SC-20/SC-21 via COBIT DSS05",
            chain.ds_matches_key
                ? "Keep DS at the parent in sync with the KSK. Enable validating resolvers in production."
                : "Publish DS at the parent that hashes the current KSK, or repair DNSKEY publication. Presence-only DNSSEC is not enough.");
        f.evidence = chain.evidence;
        f.evidence["ds_present"] = chain.ds_present;
        f.evidence["dnskey_present"] = chain.dnskey_present;
        f.evidence["cryptographic_ds_match"] = chain.ds_matches_key;
        f.evidence["ds_count"] = chain.ds_records;
        f.evidence["dnskey_count"] = chain.dnskey_records;
        report.findings.push_back(f);
    }

    // Lame delegation: SOA/AA from each listed NS
    {
        int lame = 0;
        int tested = 0;
        Json::Value rows(Json::arrayValue);
        for (const auto& nshost : ns) {
            std::string host = nshost;
            if (!host.empty() && host.back() == '.') host.pop_back();
            DnsResponse soa = client.query(domain, host, DNS_TYPE_SOA);
            report.queries.push_back(soa);
            tested++;
            bool ok = !soa.error && soa.rcode == 0 && soa.authoritative && !soa.answers.empty();
            if (!ok) lame++;
            Json::Value row(Json::objectValue);
            row["ns"] = host;
            row["error"] = soa.error_message;
            row["rcode"] = iana_rcode_name(soa.rcode);
            row["aa"] = soa.authoritative;
            row["answers"] = static_cast<int>(soa.answers.size());
            row["lame"] = !ok;
            rows.append(row);
        }
        auto f = make_finding(
            "RFC-LAME-015", "Lame delegation",
            (tested == 0) ? "warning" : (lame ? "fail" : "pass"),
            lame ? "high" : "info",
            tested == 0
                ? "No NS hosts to probe for lame delegation."
                : (lame
                    ? std::to_string(lame) + " of " + std::to_string(tested) + " nameservers failed SOA+AA. Those NS are lame or unreachable from this vantage point."
                    : "Every listed NS answered SOA with AA set."),
            "SANS ISC: authoritative server health",
            "T1498", "Impact",
            "RFC1034 lame delegation; RFC2182",
            "ISACA COBIT DSS01 Operations; DSS04 Continuity",
            lame ? "Fix or remove lame NS. Each listed NS must answer authoritatively for the zone." : "No lame-delegation change required.");
        f.evidence["servers"] = rows;
        report.findings.push_back(f);
    }

    // Glue for in-bailiwick NS
    {
        int missing = 0;
        Json::Value rows(Json::arrayValue);
        for (const auto& nshost : ns) {
            bool inb = ends_with_domain(nshost, domain);
            if (!inb) continue;
            std::string host = nshost;
            if (!host.empty() && host.back() == '.') host.pop_back();
            DnsResponse a4 = client.query(host, servers.front(), DNS_TYPE_A);
            DnsResponse a6 = client.query(host, servers.front(), DNS_TYPE_AAAA);
            report.queries.push_back(a4);
            report.queries.push_back(a6);
            bool has = false;
            for (const auto& rec : a4.answers) if (rec.type == DNS_TYPE_A) has = true;
            for (const auto& rec : a6.answers) if (rec.type == DNS_TYPE_AAAA) has = true;
            if (!has) missing++;
            Json::Value row(Json::objectValue);
            row["ns"] = host;
            row["in_bailiwick"] = true;
            row["resolved"] = has;
            rows.append(row);
        }
        auto f = make_finding(
            "RFC-GLUE-016", "In-bailiwick NS glue / address",
            missing ? "warning" : "pass",
            missing ? "medium" : "info",
            rows.empty()
                ? "No in-bailiwick NS names, so child-side glue is not required at this apex."
                : (missing
                    ? "One or more in-bailiwick NS names have no A/AAAA from this resolver path."
                    : "In-bailiwick NS names resolve to A and/or AAAA."),
            "SANS: delegation integrity",
            "T1590.002", "Reconnaissance",
            "RFC1034 glue; RFC4472 IPv6 glue",
            "ISACA COBIT DSS01; BAI10",
            missing ? "Publish A/AAAA (and parent glue) for every in-bailiwick NS host." : "Keep NS glue in sync when addresses change.");
        f.evidence["ns"] = rows;
        report.findings.push_back(f);
    }

    // Dangling CNAME
    {
        DnsResponse www = client.query("www." + domain, servers.front(), DNS_TYPE_CNAME);
        DnsResponse apex_c = client.query(domain, servers.front(), DNS_TYPE_CNAME);
        report.queries.push_back(www);
        report.queries.push_back(apex_c);
        std::vector<std::string> dangling;
        Json::Value rows(Json::arrayValue);
        auto follow = [&](const DnsResponse& cname_q, const std::string& owner) {
            for (const auto& rec : cname_q.answers) {
                if (rec.type != DNS_TYPE_CNAME) continue;
                std::string target = rec.value;
                if (!target.empty() && target.back() == '.') target.pop_back();
                DnsResponse dest = client.query(target, servers.front(), DNS_TYPE_A);
                report.queries.push_back(dest);
                bool ok = !dest.error && dest.rcode != 3 && !dest.answers.empty();
                if (!ok) dangling.push_back(owner + " -> " + target);
                Json::Value row(Json::objectValue);
                row["owner"] = owner;
                row["target"] = target;
                row["target_rcode"] = iana_rcode_name(dest.rcode);
                row["dangling"] = !ok;
                rows.append(row);
            }
        };
        follow(apex_c, domain);
        follow(www, "www." + domain);
        auto f = make_finding(
            "RFC-CNAME-017", "Dangling CNAME",
            dangling.empty() ? "pass" : "warning",
            dangling.empty() ? "info" : "medium",
            dangling.empty()
                ? "No dangling CNAME on apex or www from this vantage point."
                : "CNAME target does not resolve. This is a takeover and availability fault.",
            "SANS: stale DNS / dangling records",
            "T1584.001", "Resource Development",
            "RFC1034 CNAME; RFC1912 data hygiene",
            "ISACA COBIT BAI09 assets; BAI10 change",
            dangling.empty() ? "Re-check CNAMEs when a SaaS or CDN target is retired." : "Remove or retarget the dangling CNAME before the name can be claimed.");
        f.evidence["cnames"] = rows;
        report.findings.push_back(f);
    }

    // CAA
    auto caa = values(report.queries, DNS_TYPE_CAA);
    {
        auto f = make_finding(
            "RFC-CAA-010", "CAA certificate issuance policy",
            caa.empty() ? "warning" : "pass",
            caa.empty() ? "low" : "info",
            caa.empty()
                ? "No CAA records. Issuers are not constrained by RFC 8659 policy at this name."
                : "CAA policy is published.",
            "SANS: monitor certificates associated with the organization",
            "T1588.004", "Resource Development",
            "RFC8659",
            "ISACA COBIT DSS05; BAI10");
        Json::Value ev(Json::arrayValue);
        for (const auto& v : caa) ev.append(v);
        f.evidence["caa"] = ev;
        report.findings.push_back(f);
    }

    // Transport / SERVFAIL / REFUSED fault finding
    {
        int servfail = 0;
        int formerr = 0;
        int refused = 0;
        int ok = 0;
        for (const auto& q : report.queries) {
            if (q.error) continue;
            if (q.rcode == 0) ok++;
            else if (q.rcode == 1) formerr++;
            else if (q.rcode == 2) servfail++;
            else if (q.rcode == 5) refused++;
        }
        std::string status = (servfail > 3 || formerr > 0) ? "warning" : "pass";
        auto f = make_finding(
            "IANA-RCODE-011", "IANA RCODE health",
            status,
            status == "warning" ? "medium" : "info",
            status == "warning"
                ? "Repeated SERVFAIL or FORMERR across queries. Investigate lame delegation, broken DNSSEC, or resolver faults."
                : "Most answers used IANA RCODE NOERROR. Other RCODEs were within expected query mix.",
            "SANS ISC: monitor domains and resolver health",
            "T1498", "Impact (availability)",
            "RFC1035 RCODE; RFC6895 IANA considerations",
            "ISACA COBIT DSS01; DSS04; MEA01");
        f.evidence["noerror"] = ok;
        f.evidence["servfail"] = servfail;
        f.evidence["formerr"] = formerr;
        f.evidence["refused"] = refused;
        report.findings.push_back(f);
    }

    // Existing analyzer hooks reused as mapped controls
    CheckResult nx = check_nxdomain_redirect(client, servers.front(), domain);
    {
        auto f = make_finding(
            "SANS-NX-012", "NXDOMAIN integrity",
            nx.status, nx.status == "pass" ? "info" : "medium", nx.message,
            "SANS: NXDOMAIN flood / redirection and resolver integrity",
            "T1565", "Impact",
            "RFC1035 NXDOMAIN; RFC8020 NXDOMAIN convention",
            "ISACA COBIT DSS05; MEA01");
        f.evidence["analyzer"] = nx.name;
        report.findings.push_back(f);
    }

    CheckResult wild = check_wildcard_dns(client, servers.front(), domain);
    {
        auto f = make_finding(
            "SANS-WILD-013", "Wildcard coverage",
            wild.status, wild.status == "pass" ? "info" : "low", wild.message,
            "SANS: wildcard and catch-all resolution surface",
            "T1584.001", "Resource Development",
            "RFC4592 wildcards",
            "ISACA COBIT DSS05");
        report.findings.push_back(f);
    }

    {
        std::string axfr_target = ns.empty() ? servers.front() : *ns.begin();
        if (!axfr_target.empty() && axfr_target.back() == '.') axfr_target.pop_back();
        DnsResponse axfr = client.query(domain, axfr_target, DNS_TYPE_AXFR);
        report.queries.push_back(axfr);
        bool leaked = !axfr.error && axfr.rcode == 0 && !axfr.answers.empty();
        bool refused = axfr.rcode == 5 || axfr.rcode == 9 || axfr.rcode == 4;
        std::string status = leaked ? "fail" : "pass";
        std::string sev = leaked ? "high" : "info";
        std::string msg;
        if (axfr.error) {
            status = "pass";
            msg = "AXFR to " + axfr_target + " did not return a zone stream (" + axfr.error_message + "). Treat as not exposed from this vantage point.";
        } else if (leaked) {
            msg = "AXFR against " + axfr_target + " returned zone data. Restrict transfers to authorized secondaries (RFC 5936).";
        } else if (refused) {
            msg = "AXFR against " + axfr_target + " was refused (IANA RCODE " + iana_rcode_name(axfr.rcode) + ").";
        } else {
            msg = "AXFR against " + axfr_target + " did not leak a zone (RCODE " + iana_rcode_name(axfr.rcode) + ").";
        }
        auto f = make_finding(
            "RFC-AXFR-014", "AXFR exposure",
            status, sev, msg,
            "SANS: zone transfer leakage / reconnaissance",
            "T1590.002", "Reconnaissance",
            "RFC5936 AXFR",
            "ISACA COBIT DSS05.02 least functionality of name service",
            leaked ? "Disable public AXFR. Allow transfers only to listed secondaries with TSIG or ACL." : "Keep AXFR locked down. Re-test after nameserver changes.");
        f.evidence["target"] = axfr_target;
        f.evidence["rcode"] = iana_rcode_name(axfr.rcode);
        f.evidence["error"] = axfr.error_message;
        report.findings.push_back(f);
    }

    int score = 0;
    for (const auto& f : report.findings) score += severity_points(f.severity, f.status);
    report.fault_score = std::min(score, 100);
    if (report.fault_score >= 60) report.posture = "exposed";
    else if (report.fault_score >= 30) report.posture = "degraded";
    else report.posture = "resilient";
    return report;
}

Json::Value framework_audit_to_json(const FrameworkAuditReport& report) {
    Json::Value root(Json::objectValue);
    root["tool"] = "WhiteDNS";
    root["schema"] = report.schema;
    root["domain"] = report.domain;
    root["fault_score"] = report.fault_score;
    root["posture"] = report.posture;
    root["frameworks"]["sans"] = "SANS Institute DNS attack classes and ISC operational checklists";
    root["frameworks"]["mitre_attack"] = "MITRE ATT&CK Enterprise DNS-related techniques";
    root["frameworks"]["rfc"] = "RFC 1034/1035 plus record-specific RFCs";
    root["frameworks"]["iana"] = "IANA DNS Parameters";
    root["frameworks"]["isaca"] = "COBIT 2019 DSS05/APO12/BAI10/MEA01 mapped control language";

    Json::Value findings(Json::arrayValue);
    for (const auto& f : report.findings) {
        Json::Value item(Json::objectValue);
        item["id"] = f.finding_id;
        item["title"] = f.title;
        item["status"] = f.status;
        item["severity"] = f.severity;
        item["message"] = f.message;
        item["sans_class"] = f.sans_class;
        item["mitre"]["id"] = f.mitre_id;
        item["mitre"]["tactic"] = f.mitre_tactic;
        item["rfc"] = f.rfc_ref;
        item["iana"] = f.iana_ref;
        item["isaca"] = f.isaca_control;
        item["change_required"] = f.change_required;
        item["evidence"] = f.evidence;
        findings.append(item);
    }
    root["findings"] = findings;

    Json::Value queries(Json::arrayValue);
    for (const auto& q : report.queries) {
        Json::Value item = dns_response_to_json(q);
        item["rcode_name"] = iana_rcode_name(q.rcode);
        item["rfc"] = rfc_for_rrtype(q.query_type);
        item["architecture_role"] = architecture_role(q.query_type);
        queries.append(item);
    }
    root["queries"] = queries;
    return root;
}

Json::Value framework_workpaper_to_json(const FrameworkAuditReport& report) {
    Json::Value root(Json::objectValue);
    root["schema"] = "whitedns.isaca.workpaper.v1";
    root["tool"] = "WhiteDNS";
    root["standard"] = "ISACA COBIT 2019";
    root["engagement"]["subject"] = report.domain;
    root["engagement"]["posture"] = report.posture;
    root["engagement"]["fault_score"] = report.fault_score;
    root["engagement"]["procedure"] = "Independent DNS control test using RFC/IANA observations mapped to COBIT management objectives.";

    struct Bucket {
        const char* id;
        const char* title;
        const char* procedure;
    };
    const Bucket buckets[] = {
        {"DSS05.02", "Manage network and connectivity security", "Inspect DNSSEC chain, resolver disagreement, NXDOMAIN integrity, and AXFR exposure."},
        {"DSS01.03", "Monitor IT infrastructure", "Query each NS for SOA+AA (lame delegation) and IANA RCODE health."},
        {"DSS04.03", "Continuity of essential services", "Test NS architecture, glue, and dual-stack addressing."},
        {"BAI10.02", "Manage configuration changes", "Record SOA serial, CAA, and CNAME targets as configuration evidence."},
        {"BAI09.01", "Manage assets", "Identify dangling CNAME and stale delegation records."},
        {"APO12.02", "Risk analysis", "Map residual DNS risk to MITRE ATT&CK and SANS classes."},
        {"MEA01.03", "Monitor, evaluate and assess performance", "Export scored findings and change-required statements."},
    };

    auto conclusion = [](const std::vector<std::string>& statuses) {
        bool fail = false, warn = false;
        for (const auto& s : statuses) {
            if (s == "fail") fail = true;
            if (s == "warning") warn = true;
        }
        if (fail) return "ineffective";
        if (warn) return "partially effective";
        return "effective";
    };

    Json::Value controls(Json::arrayValue);
    for (const auto& b : buckets) {
        Json::Value control(Json::objectValue);
        control["control_id"] = b.id;
        control["title"] = b.title;
        control["test_procedure"] = b.procedure;
        Json::Value tests(Json::arrayValue);
        std::vector<std::string> statuses;
        for (const auto& f : report.findings) {
            if (f.isaca_control.find(b.id) == std::string::npos &&
                !(std::string(b.id).rfind("DSS05", 0) == 0 && f.isaca_control.find("DSS05") != std::string::npos) &&
                !(std::string(b.id).rfind("DSS01", 0) == 0 && f.isaca_control.find("DSS01") != std::string::npos) &&
                !(std::string(b.id).rfind("DSS04", 0) == 0 && f.isaca_control.find("DSS04") != std::string::npos) &&
                !(std::string(b.id).rfind("BAI10", 0) == 0 && f.isaca_control.find("BAI10") != std::string::npos) &&
                !(std::string(b.id).rfind("BAI09", 0) == 0 && f.isaca_control.find("BAI09") != std::string::npos) &&
                !(std::string(b.id).rfind("APO12", 0) == 0 && f.isaca_control.find("APO12") != std::string::npos) &&
                !(std::string(b.id).rfind("MEA01", 0) == 0 && f.isaca_control.find("MEA01") != std::string::npos)) {
                continue;
            }
            Json::Value test(Json::objectValue);
            test["finding_id"] = f.finding_id;
            test["title"] = f.title;
            test["result"] = f.status;
            test["severity"] = f.severity;
            test["observation"] = f.message;
            test["corrective_action"] = f.change_required;
            test["rfc"] = f.rfc_ref;
            test["mitre"] = f.mitre_id;
            tests.append(test);
            statuses.push_back(f.status);
        }
        control["tests"] = tests;
        control["conclusion"] = conclusion(statuses);
        controls.append(control);
    }
    root["controls"] = controls;
    root["source_audit"] = framework_audit_to_json(report);
    return root;
}

void print_framework_audit(const FrameworkAuditReport& report) {
    std::cout << "WhiteDNS framework audit\n";
    std::cout << "Target: " << report.domain << "\n";
    std::cout << "Posture: " << report.posture << "  Fault score: " << report.fault_score << "/100\n";
    std::cout << "Sources: SANS | MITRE ATT&CK | RFC | IANA | ISACA COBIT\n";
    std::cout << "------------------------------------------------------------\n";
    for (const auto& f : report.findings) {
        std::cout << "[" << f.status << "] " << f.finding_id << "  " << f.title << "\n";
        std::cout << "        " << f.message << "\n";
        std::cout << "        SANS: " << f.sans_class << "\n";
        std::cout << "        MITRE: " << f.mitre_id << " (" << f.mitre_tactic << ")\n";
        std::cout << "        RFC: " << f.rfc_ref << "\n";
        std::cout << "        ISACA: " << f.isaca_control << "\n";
        if (!f.change_required.empty()) {
            std::cout << "        CHANGE: " << f.change_required << "\n";
        }
    }
}

} // namespace whitedns
