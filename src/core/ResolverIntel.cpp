#include "whitedns/core/ResolverIntel.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/IanaDns.h"
#include "whitedns/core/ResolverEngine.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>

namespace whitedns {
namespace core {
namespace {

std::string join_vals(const Observation& obs) {
    std::ostringstream o;
    bool first = true;
    for (const auto& r : obs.message.answers) {
        if (r.value.empty()) continue;
        if (!first) o << " | ";
        first = false;
        o << r.value;
    }
    if (first) {
        for (const auto& r : obs.message.authority) {
            if (r.value.empty()) continue;
            if (!first) o << " | ";
            first = false;
            o << r.type_name << " " << r.value;
        }
    }
    return first ? "(none)" : o.str();
}

bool has_prefix(const std::string& s, const char* p) {
    return s.size() >= std::char_traits<char>::length(p) && s.compare(0, std::char_traits<char>::length(p), p) == 0;
}

} // namespace

ResolverIntelReport run_resolver_intel(const std::string& qname, const std::string& resolver) {
    ResolverIntelReport report;
    report.qname = qname;
    report.resolver = resolver.empty() ? "1.1.1.1" : resolver;
    ResolverEngine engine;

    auto q = [&](uint16_t t) { return engine.query(qname, t, report.resolver); };
    auto add = [&](const char* model, const char* rfc, const char* sans, const char* fact, const std::string& value) {
        IntelFact f;
        f.model = model;
        f.rfc = rfc;
        f.sans = sans;
        f.fact = fact;
        f.value = value;
        report.facts.push_back(f);
    };

    auto soa = q(DNS_TYPE_SOA);
    auto ns = q(DNS_TYPE_NS);
    auto a = q(DNS_TYPE_A);
    auto aaaa = q(DNS_TYPE_AAAA);
    auto mx = q(DNS_TYPE_MX);
    auto txt = q(DNS_TYPE_TXT);
    auto caa = q(DNS_TYPE_CAA);
    auto ds = q(DNS_TYPE_DS);
    auto dnskey = q(DNS_TYPE_DNSKEY);
    auto rrsig = q(DNS_TYPE_RRSIG);
    auto srv_sip = engine.query("_sip._tcp." + qname, DNS_TYPE_SRV, report.resolver);
    auto dmarc = engine.query("_dmarc." + qname, DNS_TYPE_TXT, report.resolver);
    auto nxd = engine.query("whitedns-nx-intel." + qname, DNS_TYPE_A, report.resolver);

    add("ZoneAuthority", "RFC1035 §3.3.13", "SANS zone integrity / change monitoring",
        "SOA (primary + mailbox + serial if present)", join_vals(soa));
    add("NameServers", "RFC1035 §3.3.11 / RFC2182", "SANS ISC: diverse authoritative servers",
        "NS set", join_vals(ns));
    add("AddressV4", "RFC1035 A", "SANS infrastructure enumeration",
        "A records", join_vals(a));
    add("AddressV6", "RFC3596", "SANS dual-stack exposure",
        "AAAA records",
        aaaa.message.answers.empty()
            ? (std::string("NODATA ") + iana_rcode_name(aaaa.message.flags.rcode))
            : join_vals(aaaa));
    add("MailExchangers", "RFC1035 MX / RFC5321", "SANS mail hijack surface",
        "MX preference + host", join_vals(mx));

    std::string spf = "(none)", other_txt;
    for (const auto& r : txt.message.answers) {
        if (has_prefix(r.value, "v=spf1")) {
            if (spf == "(none)") spf = r.value;
            else spf += " | " + r.value;
        } else if (!r.value.empty()) {
            if (!other_txt.empty()) other_txt += " | ";
            other_txt += r.value.size() > 80 ? r.value.substr(0, 80) + "…" : r.value;
        }
    }
    add("SpfPolicy", "RFC7208", "SANS DNS as policy plane", "SPF TXT", spf);
    add("TxtOther", "RFC1035 TXT", "SANS tunneling / vendor metadata review",
        "Non-SPF TXT (truncated)", other_txt.empty() ? "(none)" : other_txt);
    add("DmarcPolicy", "RFC7489", "SANS email authentication",
        "_dmarc TXT", join_vals(dmarc));
    add("CaaPolicy", "RFC8659", "SANS certificate issuance control",
        "CAA", join_vals(caa));
    add("DnssecParent", "RFC4034 DS", "SANS: presence ≠ validation",
        "Parent DS", join_vals(ds));
    add("DnssecChild", "RFC4034 DNSKEY/RRSIG", "SANS DNSSEC deployment",
        "DNSKEY / RRSIG counts",
        "DNSKEY=" + std::to_string(dnskey.message.answers.size()) +
            " RRSIG=" + std::to_string(rrsig.message.answers.size()) +
            " rcode_key=" + iana_rcode_name(dnskey.message.flags.rcode));
    add("ServiceDiscovery", "RFC2782", "SANS service mapping",
        "_sip._tcp SRV", join_vals(srv_sip));
    add("NxIntegrity", "RFC2308 / RFC8020", "SANS NXDOMAIN abuse",
        "Random label A",
        std::string("rcode=") + iana_rcode_name(nxd.message.flags.rcode) + " aa=" +
            (nxd.message.flags.aa ? "1" : "0"));
    add("HeaderFlags", "RFC1035 header", "SANS resolver honesty",
        "A-query flags",
        std::string("rcode=") + iana_rcode_name(a.message.flags.rcode) +
            " aa=" + (a.message.flags.aa ? "1" : "0") +
            " ra=" + (a.message.flags.ra ? "1" : "0") +
            " ad=" + (a.message.flags.ad ? "1" : "0") +
            " rtt=" + std::to_string(a.rtt.count()) + "ms");
    add("TtlSurface", "RFC1035 TTL / RFC2181", "SANS fast-flux signal",
        "Lowest A TTL", [&] {
            uint32_t t = 0;
            bool any = false;
            for (const auto& r : a.message.answers)
                if (r.type == DNS_TYPE_A) {
                    if (!any || r.ttl < t) t = r.ttl;
                    any = true;
                }
            if (!any) return std::string("(no A)");
            std::ostringstream o;
            o << t << "s" << (t < 60 ? " (sub-minute — flux observation, not proof)" : "");
            return o.str();
        }());
    add("CacheClass", "RFC1034 iterative vs recursive", "SANS cache poisoning class",
        "This path is recursive configured",
        "resolver=" + report.resolver + " RA=" + (a.message.flags.ra ? "yes" : "no") +
            " — disagreement with another resolver is OBSERVATION, not poisoning");

    report.models = 16;
    return report;
}

void print_resolver_intel(const ResolverIntelReport& report) {
    std::cout << "WhiteDNS advanced resolver engine — RFC / SANS intel\n";
    std::cout << "QNAME: " << report.qname << "  resolver: " << report.resolver
              << "  models: " << report.models << "\n";
    std::cout << "------------------------------------------------------------\n";
    for (const auto& f : report.facts) {
        std::cout << "[" << f.model << "]\n";
        std::cout << "  RFC:  " << f.rfc << "\n";
        std::cout << "  SANS: " << f.sans << "\n";
        std::cout << "  " << f.fact << ": " << f.value << "\n";
    }
}

} // namespace core
} // namespace whitedns
