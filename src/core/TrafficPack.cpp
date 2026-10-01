#include "whitedns/core/TrafficPack.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/Intelligence.h"
#include "whitedns/core/ResolverEngine.h"

#include <cmath>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

namespace {

bool txt_has(const Observation& o, const std::string& needle) {
    for (const auto& r : o.message.answers)
        if (r.value.find(needle) != std::string::npos) return true;
    return false;
}

int label_len(const std::string& name) {
    auto dot = name.find('.');
    return static_cast<int>(dot == std::string::npos ? name.size() : dot);
}

double entropy(const std::string& name) {
    std::map<char, int> f;
    int n = 0;
    for (char c : name) {
        if (c == '.') continue;
        f[c]++;
        n++;
    }
    if (n == 0) return 0;
    double h = 0;
    for (const auto& kv : f) {
        double p = static_cast<double>(kv.second) / n;
        h -= p * std::log2(p);
    }
    return h;
}

} // namespace

void print_traffic_pack(const std::string& name) {
    print_traffic_family(name, "all");
}

void print_traffic_family(const std::string& name, const std::string& family) {
    ResolverEngine engine;
    auto a = engine.query(name, DNS_TYPE_A, "8.8.8.8");
    auto aaaa = engine.query(name, DNS_TYPE_AAAA, "1.1.1.1");
    auto ns = engine.query(name, DNS_TYPE_NS, "9.9.9.9");
    auto mx = engine.query(name, DNS_TYPE_MX, "8.8.8.8");
    auto txt = engine.query(name, DNS_TYPE_TXT, "1.1.1.1");
    auto any = engine.query(name, 255, "9.9.9.9");
    auto caa = engine.query(name, 257, "8.8.8.8");
    auto soa = engine.query(name, DNS_TYPE_SOA, "1.1.1.1");
    auto ds = engine.query(name, DNS_TYPE_DS, "9.9.9.9");
    auto fused = build_fusion(name);

    int aa = static_cast<int>(a.message.answers.size());
    int aaaa_n = static_cast<int>(aaaa.message.answers.size());
    int ns_n = static_cast<int>(ns.message.answers.size());
    int mx_n = static_cast<int>(mx.message.answers.size());
    int txt_n = static_cast<int>(txt.message.answers.size());
    int any_n = static_cast<int>(any.message.answers.size());
    int caa_n = static_cast<int>(caa.message.answers.size());
    int soa_n = static_cast<int>(soa.message.answers.size());
    int ds_n = static_cast<int>(ds.message.answers.size());
    int tc = a.message.flags.tc || any.message.flags.tc;
    int rcode = a.message.flags.rcode;
    int qd = a.message.question.qname.empty() ? 0 : 1;
    int opcode = a.message.flags.opcode;
    double h = entropy(name);
    int llen = label_len(name);
    int digits = 0;
    for (char c : name)
        if (c >= '0' && c <= '9') digits++;
    int glue = static_cast<int>(ns.message.additional.size());
    int prefix = 0;
    {
        std::map<std::string, int> p;
        for (const auto& ip : fused.fused_a) {
            auto dot = ip.rfind('.');
            p[dot == std::string::npos ? ip : ip.substr(0, dot)]++;
        }
        prefix = static_cast<int>(p.size());
    }
    bool spf = txt_has(txt, "v=spf1");
    bool dmarc_txt = txt_has(txt, "v=DMARC1");

    struct Row { std::string id, family, value; };
    std::vector<Row> rows;
    auto add = [&](const std::string& id, const std::string& fam, const std::string& value) {
        rows.push_back(Row{id, fam, value});
    };
    add("T01", "protocol", "rcode=" + std::to_string(rcode));
    add("T02", "protocol", std::string("tc=") + (tc ? "yes" : "no"));
    add("T03", "protocol", "A=" + std::to_string(aa));
    add("T04", "protocol", "AAAA=" + std::to_string(aaaa_n));
    add("T05", "protocol", "NS=" + std::to_string(ns_n));
    add("T06", "protocol", "MX=" + std::to_string(mx_n));
    add("T07", "protocol", "TXT=" + std::to_string(txt_n));
    add("T08", "protocol", "ANY=" + std::to_string(any_n));
    add("T09", "protocol", (aa == 0 && rcode == 0) ? "NODATA" : "not_nodata");
    add("T10", "protocol", rcode == 3 ? "NXDOMAIN" : "not_nxdomain");
    add("T11", "protocol", "qdcount=" + std::to_string(qd));
    add("T12", "protocol", "opcode=" + std::to_string(opcode));
    add("T13", "protocol", "qclass=" + std::to_string(a.message.question.qclass));
    add("T14", "protocol", any.message.flags.tc ? "ANY_truncated" : "ANY_not_truncated");
    add("T15", "protocol", "aa_flag=" + std::string(a.message.flags.aa ? "yes" : "no"));
    add("T16", "route", "edges=" + std::to_string(fused.edges.size()));
    add("T17", "route", "fused_A=" + std::to_string(fused.fused_a.size()));
    add("T18", "route", ns_n == 0 ? "no_ns" : "ns_present");
    add("T19", "route", "ns_answer_count=" + std::to_string(ns_n));
    add("T20", "route", "additional_on_NS=" + std::to_string(glue));
    add("T21", "route", "prefix24=" + std::to_string(prefix));
    add("T22", "route", "authority_on_A=" + std::to_string(a.message.authority.size()));
    add("T23", "route", "ra_flag=" + std::string(a.message.flags.ra ? "yes" : "no"));
    add("T24", "route", "rd_flag=" + std::string(a.message.flags.rd ? "yes" : "no"));
    add("T25", "route", fused.algorithm_lines.empty() ? "no_path" : fused.algorithm_lines[0]);
    add("T26", "route", fused.algorithm_lines.size() > 1 ? fused.algorithm_lines[1] : "no_hub");
    add("T27", "route", fused.algorithm_lines.size() > 2 ? fused.algorithm_lines[2] : "no_components");
    add("T28", "route", "cname_in_A=" + std::to_string([&]() {
        int n = 0;
        for (const auto& r : a.message.answers)
            if (r.type == 5) n++;
        return n;
    }()));
    add("T29", "route", "ipv4=" + std::to_string(aa) + " ipv6=" + std::to_string(aaaa_n));
    add("T30", "route", glue > 0 ? "glue_records_seen" : "no_glue_in_additional");
    add("T31", "annihilation", "raw=" + std::to_string(fused.raw));
    add("T32", "annihilation", "kept=" + std::to_string(fused.kept));
    add("T33", "annihilation", "dup_dropped=" + std::to_string(fused.dropped_dup));
    add("T34", "annihilation", fused.contradiction ? "contradiction" : "agree");
    add("T35", "annihilation", "drop_ratio=" + std::to_string(fused.raw == 0 ? 0.0 : static_cast<double>(fused.dropped_dup) / fused.raw));
    add("T36", "annihilation", "ttl_A=" + std::to_string(a.message.answers.empty() ? 0 : a.message.answers[0].ttl));
    add("T37", "annihilation", "sources=3");
    add("T38", "annihilation", aa == 0 ? "empty_A_kept" : "A_kept");
    add("T39", "annihilation", "cname_in_A_not_chased=" + std::to_string([&]() {
        int n = 0;
        for (const auto& r : a.message.answers)
            if (r.type == DNS_TYPE_CNAME) n++;
        return n;
    }()));
    add("T40", "annihilation", "additional_on_A=" + std::to_string(a.message.additional.size()));
    add("T41", "flow", "agreement=" + std::to_string(fused.confidence));
    add("T42", "flow", fused.confidence_why.empty() ? "no_why" : fused.confidence_why);
    add("T43", "flow", fused.algorithm_lines.size() > 5 ? fused.algorithm_lines[5] : "bayes_in_graph");
    add("T44", "flow", fused.algorithm_lines.size() > 6 ? fused.algorithm_lines[6] : "dempster_in_graph");
    add("T45", "flow", "resolvers=8.8.8.8,1.1.1.1,9.9.9.9");
    add("T46", "flow", "queries_sent=" + std::to_string(9));
    add("T47", "flow", "spoofed=0");
    add("T48", "flow", "transport=udp");
    add("T49", "flow", "amplification_sent=0");
    add("T50", "flow", (any_n > 20 || any.message.flags.tc) ? "ANY_exposure" : "ANY_not_large");
    add("T51", "record", "MX=" + std::to_string(mx_n));
    add("T52", "record", txt_n > 8 ? "txt_volume" : "txt_count=" + std::to_string(txt_n));
    add("T53", "record", "CAA=" + std::to_string(caa_n));
    add("T54", "record", spf ? "spf_present" : "spf_absent");
    add("T55", "record", dmarc_txt ? "dmarc_txt_present" : "dmarc_not_on_apex_txt");
    add("T56", "record", "SOA=" + std::to_string(soa_n));
    add("T57", "record", "DS=" + std::to_string(ds_n));
    add("T58", "record", ds_n > 0 ? "ds_seen" : "ds_absent");
    add("T59", "record", "rrsig_on_A=" + std::to_string([&]() {
        int n = 0;
        for (const auto& r : a.message.answers)
            if (r.type == 46) n++;
        return n;
    }()));
    add("T60", "record", "nsec_on_A=" + std::to_string([&]() {
        int n = 0;
        for (const auto& r : a.message.authority)
            if (r.type == 47 || r.type == 50) n++;
        return n;
    }()));
    add("T61", "fault", ns_n == 0 ? "missing_ns" : "ns_seen");
    add("T62", "fault", aa == 0 ? "no_A" : "A_seen");
    add("T63", "fault", aaaa_n == 0 ? "no_AAAA" : "AAAA_seen");
    add("T64", "fault", tc ? "truncation" : "no_truncation");
    add("T65", "fault", rcode != 0 ? "nonzero_rcode" : "rcode_0");
    add("T66", "fault", ds_n == 0 ? "no_ds_on_this_resolver" : "ds_present");
    add("T67", "fault", soa_n == 0 ? "no_soa" : "soa_seen");
    add("T68", "fault", caa_n == 0 ? "no_caa" : "caa_seen");
    add("T69", "fault", "open_resolver_not_probed");
    add("T70", "fault", "axfr_not_sent");
    add("T71", "defence", "poison_gates_not_in_this_pack");
    add("T72", "defence", ds_n == 0 ? "presence_only_no_ds" : "ds_seen_not_validated_here");
    add("T73", "defence", "entropy=" + std::to_string(h) + " len=" + std::to_string(llen) + " flag=" + ((h >= 3.0 && llen >= 10) ? "yes" : "no"));
    add("T74", "defence", txt_n > 8 ? "txt_volume_not_tunnel" : "txt_not_volume");
    add("T75", "defence", (any_n > 20 || any.message.flags.tc) ? "any_exposure" : "any_quiet");
    add("T76", "defence", "digit_ratio=" + std::to_string(name.empty() ? 0.0 : static_cast<double>(digits) / name.size()));
    add("T77", "defence", "update_sent=0");
    add("T78", "defence", "notify_sent=0");
    add("T79", "defence", "payload_sent=0");
    add("T80", "defence", "computed_rows=90");
    add("T81", "module", "A_query_ok=" + std::string(a.ok ? "yes" : "no"));
    add("T82", "module", "fusion_edges=" + std::to_string(fused.edges.size()));
    add("T83", "module", "header_id=" + std::to_string(a.message.id));
    add("T84", "module", "ds_count=" + std::to_string(ds_n));
    add("T85", "module", "contradiction=" + std::string(fused.contradiction ? "yes" : "no"));
    add("T86", "module", "notes=" + std::to_string(fused.notes.size()));
    add("T87", "module", "algo_lines=" + std::to_string(fused.algorithm_lines.size()));
    add("T88", "module", "caa_count=" + std::to_string(caa_n));
    add("T89", "module", "pack=TrafficPack");
    add("T90", "module", "family_filter=" + family);

    std::cout << "WhiteDNS traffic pack  " << name << "  rows=" << rows.size() << " filter=" << family << "\n";
    int shown = 0;
    for (const auto& r : rows) {
        if (family != "all" && r.family != family) continue;
        std::cout << r.id << " " << r.family << " " << r.value << "\n";
        shown++;
    }
    std::cout << "shown=" << shown << " computed=" << rows.size() << "\n";
    std::cout << "T69 T70 T71 stay explicit non-actions. DS count is not signature verification.\n";
}

} // namespace core
} // namespace whitedns
