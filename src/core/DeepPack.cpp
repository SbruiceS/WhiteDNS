#include "whitedns/core/DeepPack.h"

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

int count_type(const std::vector<DnsRecord>& rows, uint16_t type) {
    int n = 0;
    for (const auto& r : rows)
        if (r.type == type) n++;
    return n;
}

double entropy_of(const std::string& s) {
    std::map<char, int> f;
    for (char c : s) f[c]++;
    if (s.empty()) return 0;
    double h = 0;
    for (const auto& kv : f) {
        double p = static_cast<double>(kv.second) / static_cast<double>(s.size());
        h -= p * std::log2(p);
    }
    return h;
}

} // namespace

void print_deep_pack(const std::string& name) {
    ResolverEngine engine;
    auto a = engine.query(name, DNS_TYPE_A, "8.8.8.8");
    auto aaaa = engine.query(name, DNS_TYPE_AAAA, "1.1.1.1");
    auto ns = engine.query(name, DNS_TYPE_NS, "9.9.9.9");
    auto txt = engine.query(name, DNS_TYPE_TXT, "8.8.8.8");
    auto mx = engine.query(name, DNS_TYPE_MX, "1.1.1.1");
    auto fused = build_fusion(name);

    std::string label = name;
    auto dot = label.find('.');
    if (dot != std::string::npos) label = label.substr(0, dot);
    int hyphens = 0, digits = 0, vowels = 0, upper = 0, longest = 0, run = 0;
    for (char c : label) {
        if (c == '-') {
            hyphens++;
            run = 0;
        } else if (c >= '0' && c <= '9') {
            digits++;
            run++;
        } else {
            run = 0;
            char low = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
            if (c >= 'A' && c <= 'Z') upper++;
            if (low == 'a' || low == 'e' || low == 'i' || low == 'o' || low == 'u') vowels++;
        }
        if (run > longest) longest = run;
    }
    int labels = 1;
    for (char c : name)
        if (c == '.') labels++;
    int ttl_min = 0, ttl_max = 0, ttl_n = 0;
    long ttl_sum = 0;
    for (const auto& r : a.message.answers) {
        if (ttl_n == 0 || static_cast<int>(r.ttl) < ttl_min) ttl_min = static_cast<int>(r.ttl);
        if (static_cast<int>(r.ttl) > ttl_max) ttl_max = static_cast<int>(r.ttl);
        ttl_sum += r.ttl;
        ttl_n++;
    }
    int types = 0;
    {
        std::map<uint16_t, int> seen;
        for (const auto& r : a.message.answers) seen[r.type]++;
        for (const auto& r : a.message.authority) seen[r.type]++;
        types = static_cast<int>(seen.size());
    }
    double h = entropy_of(label);
    int a_n = static_cast<int>(a.message.answers.size());
    int ns_n = static_cast<int>(ns.message.answers.size());
    int txt_n = static_cast<int>(txt.message.answers.size());
    int mx_n = static_cast<int>(mx.message.answers.size());
    int aaaa_n = static_cast<int>(aaaa.message.answers.size());

    struct Row { std::string id, value; };
    std::vector<Row> rows;
    auto add = [&](const std::string& id, const std::string& value) { rows.push_back(Row{id, value}); };
    add("H01", "label_len=" + std::to_string(label.size()));
    add("H02", "label_entropy=" + std::to_string(h));
    add("H03", "digit_run=" + std::to_string(longest));
    add("H04", "hyphen=" + std::to_string(hyphens));
    add("H05", "vowels=" + std::to_string(vowels));
    add("H06", "upper=" + std::to_string(upper));
    add("H07", "labels=" + std::to_string(labels));
    add("H08", "digit_ratio=" + std::to_string(label.empty() ? 0.0 : static_cast<double>(digits) / label.size()));
    add("H09", "lexical_flag=" + std::string(h >= 3.0 && label.size() >= 10 ? "yes" : "no"));
    add("H10", "name_len=" + std::to_string(name.size()));
    add("H11", "A=" + std::to_string(a_n));
    add("H12", "AAAA=" + std::to_string(aaaa_n));
    add("H13", "NS=" + std::to_string(ns_n));
    add("H14", "MX=" + std::to_string(mx_n));
    add("H15", "TXT=" + std::to_string(txt_n));
    add("H16", "A_rcode=" + std::to_string(a.message.flags.rcode));
    add("H17", "A_tc=" + std::string(a.message.flags.tc ? "yes" : "no"));
    add("H18", "A_aa=" + std::string(a.message.flags.aa ? "yes" : "no"));
    add("H19", "A_ra=" + std::string(a.message.flags.ra ? "yes" : "no"));
    add("H20", "A_ad=" + std::string(a.message.flags.ad ? "yes" : "no"));
    add("H21", "edns=" + std::string(a.message.has_edns ? "yes" : "no"));
    add("H22", "edns_payload=" + std::to_string(a.message.edns_udp_payload));
    add("H23", "dnssec_ok_flag=" + std::string(a.message.dnssec_ok ? "yes" : "no"));
    add("H24", "authority=" + std::to_string(a.message.authority.size()));
    add("H25", "additional=" + std::to_string(a.message.additional.size()));
    add("H26", "type_diversity=" + std::to_string(types));
    add("H27", "cname=" + std::to_string(count_type(a.message.answers, DNS_TYPE_CNAME)));
    add("H28", "rrsig_A=" + std::to_string(count_type(a.message.answers, DNS_TYPE_RRSIG)));
    add("H29", "ttl_min=" + std::to_string(ttl_min));
    add("H30", "ttl_max=" + std::to_string(ttl_max));
    add("H31", "ttl_mean=" + std::to_string(ttl_n ? ttl_sum / ttl_n : 0));
    add("H32", "ttl_span=" + std::to_string(ttl_max - ttl_min));
    add("H33", "rtt_ms=" + std::to_string(a.rtt.count()));
    add("H34", "aaaa_rtt_ms=" + std::to_string(aaaa.rtt.count()));
    add("H35", "ns_rtt_ms=" + std::to_string(ns.rtt.count()));
    add("H36", "query_ok=" + std::string(a.ok ? "yes" : "no"));
    add("H37", "parse_error=" + (a.message.parse_error.empty() ? std::string("none") : a.message.parse_error));
    add("H38", "fused_A=" + std::to_string(fused.fused_a.size()));
    add("H39", "raw=" + std::to_string(fused.raw));
    add("H40", "kept=" + std::to_string(fused.kept));
    add("H41", "dup_dropped=" + std::to_string(fused.dropped_dup));
    add("H42", "contradiction=" + std::string(fused.contradiction ? "yes" : "no"));
    add("H43", "agreement=" + std::to_string(fused.confidence));
    add("H44", "edges=" + std::to_string(fused.edges.size()));
    add("H45", "ns_additional=" + std::to_string(ns.message.additional.size()));
    add("H46", "mx_additional=" + std::to_string(mx.message.additional.size()));
    add("H47", "txt_bytes=" + std::to_string([&]() {
        int n = 0;
        for (const auto& r : txt.message.answers) n += static_cast<int>(r.value.size());
        return n;
    }()));
    add("H48", "algo_lines=" + std::to_string(fused.algorithm_lines.size()));
    add("H49", "notes=" + std::to_string(fused.notes.size()));
    add("H50", "id=" + std::to_string(a.message.id));

    std::cout << "WhiteDNS deep pack  " << name << "  rows=" << rows.size() << "\n";
    std::cout << "observe only. scores are not attack probabilities.\n";
    for (const auto& r : rows) std::cout << r.id << " " << r.value << "\n";
    std::cout << "computed=" << rows.size() << "\n";
}

} // namespace core
} // namespace whitedns
