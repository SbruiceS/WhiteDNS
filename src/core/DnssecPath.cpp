#include "whitedns/core/DnssecPath.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/Dnssec.h"
#include "whitedns/IanaDns.h"
#include "whitedns/core/ResolverEngine.h"

#include <ctime>
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

    std::set<int> tags;
    for (const auto& k : keys) {
        if (k.rdata.size() < 4) continue;
        uint32_t ac = 0;
        for (size_t i = 0; i < k.rdata.size(); ++i) ac += (i & 1) ? k.rdata[i] : (k.rdata[i] << 8);
        tags.insert(static_cast<int>(ac & 0xffff));
    }
    std::time_t now = std::time(nullptr);
    for (const auto& s : sigs) {
        if (s.rdata.size() < 18) continue;
        uint32_t exp = (s.rdata[4] << 24) | (s.rdata[5] << 16) | (s.rdata[6] << 8) | s.rdata[7];
        uint32_t inc = (s.rdata[8] << 24) | (s.rdata[9] << 16) | (s.rdata[10] << 8) | s.rdata[11];
        uint16_t tag = static_cast<uint16_t>((s.rdata[16] << 8) | s.rdata[17]);
        if (static_cast<std::time_t>(inc) <= now && now <= static_cast<std::time_t>(exp)) report.rrsig_in_window++;
        else report.rrsig_expired++;
        if (tags.count(tag)) report.rrsig_keytag_hit++;
    }

    if (chain.ds_matches_key && report.rrsig_in_window > 0 && report.rrsig_keytag_hit > 0) {
        report.klass = "CONFIRMED_BY_VALIDATION";
        report.notes = "DS digest matches a DNSKEY. At least one RRSIG is inside its inception/expiration window and its key tag is on a fetched DNSKEY. RRSet signature bytes are not verified in this build.";
    } else if (chain.ds_matches_key) {
        report.klass = "OBSERVATION";
        report.notes = "DS digest matches. RRSIG window or key tag did not confirm.";
    } else if (report.ds_present || report.dnskey_present || report.rrsig_present) {
        report.klass = "OBSERVATION";
        report.notes = "Presence is not validation. DS digest did not confirm.";
    } else {
        report.klass = "OBSERVATION";
        report.notes = "No DS, DNSKEY, or RRSIG on this resolver path.";
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
    std::cout << "RRSIG window=" << report.rrsig_in_window << " expired=" << report.rrsig_expired
              << " keytag_hit=" << report.rrsig_keytag_hit << "\n";
    std::cout << "  " << report.chain_message << "\n";
    if (!report.rrsig_covers.empty()) {
        std::cout << "RRSIG covers:\n";
        for (const auto& c : report.rrsig_covers) std::cout << "  " << c << "\n";
    }
    std::cout << "Note: " << report.notes << "\n";
}

} // namespace core
} // namespace whitedns
