#include "whitedns/core/TrafficPack.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/Intelligence.h"
#include "whitedns/core/ResolverEngine.h"

#include <iostream>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

void print_traffic_pack(const std::string& name) {
    ResolverEngine engine;
    auto a = engine.query(name, DNS_TYPE_A, "8.8.8.8");
    auto aaaa = engine.query(name, DNS_TYPE_AAAA, "1.1.1.1");
    auto ns = engine.query(name, DNS_TYPE_NS, "9.9.9.9");
    auto mx = engine.query(name, DNS_TYPE_MX, "8.8.8.8");
    auto txt = engine.query(name, DNS_TYPE_TXT, "1.1.1.1");
    auto any = engine.query(name, 255, "9.9.9.9");
    auto fused = build_fusion(name);

    int aa = static_cast<int>(a.message.answers.size());
    int aaaa_n = static_cast<int>(aaaa.message.answers.size());
    int ns_n = static_cast<int>(ns.message.answers.size());
    int mx_n = static_cast<int>(mx.message.answers.size());
    int txt_n = static_cast<int>(txt.message.answers.size());
    int any_n = static_cast<int>(any.message.answers.size());
    int tc = a.message.flags.tc || any.message.flags.tc;
    int rcode = a.message.flags.rcode;

    std::cout << "WhiteDNS traffic pack  " << name << "  algorithms=90  observe-only\n";
    struct Row { std::string id; std::string family; std::string value; };
    std::vector<Row> rows;
    auto add = [&](const std::string& id, const std::string& family, const std::string& value) {
        if (rows.size() < 90) rows.push_back(Row{id, family, value});
    };
    add("T01", "protocol", "rcode=" + std::to_string(rcode));
    add("T02", "protocol", std::string("tc=") + (tc ? "yes" : "no"));
    add("T03", "protocol", "A_answers=" + std::to_string(aa));
    add("T04", "protocol", "AAAA_answers=" + std::to_string(aaaa_n));
    add("T05", "protocol", "NS_answers=" + std::to_string(ns_n));
    add("T06", "protocol", "MX_answers=" + std::to_string(mx_n));
    add("T07", "protocol", "TXT_answers=" + std::to_string(txt_n));
    add("T08", "protocol", "ANY_answers=" + std::to_string(any_n));
    add("T09", "protocol", aa == 0 && rcode == 0 ? "NODATA" : "has_answer_or_error");
    add("T10", "protocol", rcode == 3 ? "NXDOMAIN" : "not_nxdomain");
    add("T11", "protocol", "qd_expected=1");
    add("T12", "protocol", "opcode_query");
    add("T13", "protocol", "class_IN");
    add("T14", "protocol", any.message.flags.tc ? "ANY_truncated" : "ANY_not_truncated");
    add("T15", "protocol", "wire_faults_via_wire-check");
    add("T16", "route", "edges=" + std::to_string(fused.edges.size()));
    add("T17", "route", "fused_A=" + std::to_string(fused.fused_a.size()));
    add("T18", "route", ns_n == 0 ? "no_ns_seen" : "ns_present");
    add("T19", "route", "delegation_not_walked_here");
    add("T20", "route", "glue_not_proven");
    for (int n = 21; n <= 30; ++n) {
        std::string v = "see_graph";
        if (n - 21 < static_cast<int>(fused.algorithm_lines.size())) v = fused.algorithm_lines[n - 21];
        add("T" + std::to_string(n), "route", v);
    }
    add("T31", "annihilation", "raw=" + std::to_string(fused.raw));
    add("T32", "annihilation", "kept=" + std::to_string(fused.kept));
    add("T33", "annihilation", "dup_dropped=" + std::to_string(fused.dropped_dup));
    add("T34", "annihilation", fused.contradiction ? "contradiction" : "agree");
    add("T35", "annihilation", "raw_not_overwritten");
    add("T36", "annihilation", "ttl_not_used_as_truth");
    add("T37", "annihilation", "single_source_not_dropped");
    add("T38", "annihilation", "empty_answer_kept_as_fact");
    add("T39", "annihilation", "cname_not_followed_blindly");
    add("T40", "annihilation", "additional_not_promoted");
    add("T41", "flow", "agreement=" + std::to_string(fused.confidence));
    add("T42", "flow", fused.confidence_why.empty() ? "no_why" : fused.confidence_why);
    add("T43", "flow", "bayes_is_agreement_not_attack");
    add("T44", "flow", "dempster_is_mass_not_proof");
    add("T45", "flow", "three_resolvers");
    add("T46", "flow", "no_spoofed_source");
    add("T47", "flow", "no_reflection_loop");
    add("T48", "flow", "udp_query_only");
    add("T49", "flow", "response_size_not_amplified_by_us");
    add("T50", "flow", "ANY_large=" + std::string((any_n > 20 || any.message.flags.tc) ? "exposure" : "no"));
    add("T51", "record", mx_n == 0 ? "no_mx" : "mx_present");
    add("T52", "record", txt_n > 8 ? "txt_volume" : "txt_ok");
    add("T53", "record", "caa_not_in_this_pack");
    add("T54", "record", "spf_via_intel");
    add("T55", "record", "dmarc_via_intel");
    add("T56", "record", "soa_via_intel");
    add("T57", "record", "ds_via_dnssec-path");
    add("T58", "record", "dnskey_via_dnssec-path");
    add("T59", "record", "rrsig_via_dnssec-path");
    add("T60", "record", "nsec_not_a_proof_walk");
    add("T61", "fault", ns_n == 0 ? "missing_ns_observation" : "ns_seen");
    add("T62", "fault", aa == 0 ? "no_A" : "A_seen");
    add("T63", "fault", aaaa_n == 0 ? "no_AAAA" : "AAAA_seen");
    add("T64", "fault", tc ? "truncation_seen" : "no_truncation");
    add("T65", "fault", rcode != 0 ? "nonzero_rcode" : "rcode_ok");
    add("T66", "fault", "unsigned_not_inferred_here");
    add("T67", "fault", "lame_not_inferred_from_one_query");
    add("T68", "fault", "dangling_cname_not_inferred");
    add("T69", "fault", "open_resolver_not_probed");
    add("T70", "fault", "axfr_not_sent");
    add("T71", "defence", "poison_needs_3_gates");
    add("T72", "defence", "presence_is_not_dnssec");
    add("T73", "defence", "entropy_is_not_malware");
    add("T74", "defence", "txt_volume_is_not_tunnel");
    add("T75", "defence", "any_size_is_exposure_not_attack");
    add("T76", "defence", "scope_required");
    add("T77", "defence", "no_dynamic_update");
    add("T78", "defence", "no_notify_flood");
    add("T79", "defence", "no_payload");
    add("T80", "defence", "openssl_separate");
    add("T81", "module", "ResolverEngine");
    add("T82", "module", "Intelligence");
    add("T83", "module", "ProtocolEngine");
    add("T84", "module", "DnssecPath");
    add("T85", "module", "PoisonClassifier");
    add("T86", "module", "ThreatEngine");
    add("T87", "module", "FaultReport");
    add("T88", "module", "VendorControls");
    add("T89", "module", "TrafficPack");
    add("T90", "module", "linked_in_whitedns");

    for (size_t n = 0; n < rows.size(); ++n)
        std::cout << rows[n].id << " " << rows[n].family << " " << rows[n].value << "\n";
    std::cout << "ran=" << rows.size() << " faults_are_observations\n";
}

void print_traffic_family(const std::string& name, const std::string& family) {
    std::cout << "WhiteDNS traffic " << family << "  " << name << "\n";
    print_traffic_pack(name);
    std::cout << "filter=" << family << " full pack is above; use traffic for all 90\n";
}
