#include "whitedns/core/DnssecPath.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/Dnssec.h"
#include "whitedns/IanaDns.h"
#include "whitedns/core/ResolverEngine.h"

#include <iostream>
#include <set>

namespace whitedns {
namespace core {

namespace {

std::string rrsig_cover(const DnsRecord& rec) {
    if (rec.rdata.size() < 2) return rec.value.empty() ? "RRSIG" : rec.value;
    uint16_t covered = static_cast<uint16_t>((rec.rdata[0] << 8) | rec.rdata[1]);
    uint8_t algo = rec.rdata.size() > 2 ? rec.rdata[2] : 0;
    uint16_t tag = 0;
    if (rec.rdata.size() >= 18) tag = static_cast<uint16_t>((rec.rdata[16] << 8) | rec.rdata[17]);
    return std::string(dns_type_to_string(covered)) + " algo=" + std::to_string(algo) +
           " keytag=" + std::to_string(tag);
}

void collect(const Observation& obs, uint16_t type, std::vector<DnsRecord>& out) {
    for (const auto& r : obs.message.answers)
        if (r.type == type) out.push_back(r);
    for (const auto& r : obs.message.authority)
        if (r.type == type) out.push_back(r);
    for (const auto& r : obs.message.additional)
        if (r.type == type) out.push_back(r);
}

} // namespace

DnssecPathReport run_dnssec_path(const std::string& qname, const std::string& resolver) {
    DnssecPathReport report;
    report.qname = qname;
    ResolverEngine engine;
    const std::string res = resolver.empty() ? "8.8.8.8" : resolver;

    auto ds_o = engine.query(qname, DNS_TYPE_DS, res, TransportKind::Udp, true);
    auto key_o = engine.query(qname, DNS_TYPE_DNSKEY, res, TransportKind::Udp, true);
    auto sig_o = engine.query(qname, DNS_TYPE_RRSIG, res, TransportKind::Udp, true);
    auto nsec_o = engine.query(qname, DNS_TYPE_NSEC, res, TransportKind::Udp, true);
    auto n3_o = engine.query(qname, DNS_TYPE_NSEC3, res, TransportKind::Udp, true);
    auto a_o = engine.query(qname, DNS_TYPE_A, res, TransportKind::Udp, true);
    auto nx_o = engine.query("whitedns-p3-nx." + qname, DNS_TYPE_A, res, TransportKind::Udp, true);

    std::vector<DnsRecord> ds, keys, sigs, nsec, n3;
    collect(ds_o, DNS_TYPE_DS, ds);
    collect(key_o, DNS_TYPE_DNSKEY, keys);
    collect(sig_o, DNS_TYPE_RRSIG, sigs);
    collect(a_o, DNS_TYPE_RRSIG, sigs);
    collect(key_o, DNS_TYPE_RRSIG, sigs);
    collect(nsec_o, DNS_TYPE_NSEC, nsec);
    collect(nx_o, DNS_TYPE_NSEC, nsec);
    collect(n3_o, DNS_TYPE_NSEC3, n3);
    collect(nx_o, DNS_TYPE_NSEC3, n3);

    report.ds_count = static_cast<int>(ds.size());
    report.dnskey_count = static_cast<int>(keys.size());
    report.rrsig_count = static_cast<int>(sigs.size());
    report.ds_present = !ds.empty();
    report.dnskey_present = !keys.empty();
    report.rrsig_present = !sigs.empty();
    report.nsec_present = !nsec.empty();
    report.nsec3_present = !n3.empty();
    report.nx_has_nsec = nx_o.message.flags.rcode == 3 && (!nsec.empty() || !n3.empty());

    std::set<std::string> covers;
    for (const auto& s : sigs) covers.insert(rrsig_cover(s));
    for (const auto& c : covers) report.rrsig_covers.push_back(c);

    auto chain = validate_ds_dnskey_chain(qname, ds, keys, sigs);
    report.ds_matches_key = chain.ds_matches_key;
    report.chain_message = chain.message.empty() ? "(no DS/DNSKEY pair to hash)" : chain.message;

    if (chain.ds_matches_key) {
        report.klass = "CONFIRMED_BY_VALIDATION";
        report.notes = "DS digest matches a child DNSKEY (RFC 4034). RRSIG RRSet crypto verify of every type is still Phase-3 partial.";
    } else if (report.ds_present || report.dnskey_present || report.rrsig_present) {
        report.klass = "OBSERVATION";
        report.notes = "SANS: presence is not validation. DS/DNSKEY/RRSIG seen but digest did not confirm.";
    } else {
        report.klass = "OBSERVATION";
        report.notes = "No DS/DNSKEY/RRSIG on this resolver path. Zone may be unsigned (example: many enterprise apexes).";
    }
    if (report.nx_has_nsec) {
        report.notes += " NXDOMAIN carried NSEC/NSEC3 in authority (authenticated-denial observation, not a full proof walk).";
    }
    return report;
}

void print_dnssec_path(const DnssecPathReport& report) {
    std::cout << "WhiteDNS DNSSEC path (RFC 4033–4035 / 5155)\n";
    std::cout << "QNAME: " << report.qname << "\n";
    std::cout << "Class: " << report.klass << "\n";
    std::cout << "DS=" << (report.ds_present ? "yes" : "no") << "(" << report.ds_count << ")  "
              << "DNSKEY=" << (report.dnskey_present ? "yes" : "no") << "(" << report.dnskey_count << ")  "
              << "RRSIG=" << (report.rrsig_present ? "yes" : "no") << "(" << report.rrsig_count << ")\n";
    std::cout << "NSEC=" << (report.nsec_present ? "yes" : "no")
              << "  NSEC3=" << (report.nsec3_present ? "yes" : "no")
              << "  NX+NSEC=" << (report.nx_has_nsec ? "yes" : "no") << "\n";
    std::cout << "DS→DNSKEY: " << (report.ds_matches_key ? "MATCH" : "no-match") << "\n";
    std::cout << "  " << report.chain_message << "\n";
    if (!report.rrsig_covers.empty()) {
        std::cout << "RRSIG covers:\n";
        for (const auto& c : report.rrsig_covers) std::cout << "  " << c << "\n";
    }
    std::cout << "Note: " << report.notes << "\n";
}

} // namespace core
} // namespace whitedns
