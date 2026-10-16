#include "whitedns/core/ScaleIntel.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/Intelligence.h"
#include "whitedns/core/PoisonClassifier.h"
#include "whitedns/core/ResolverEngine.h"
#include "whitedns/core/DnsMath.h"

#include <cmath>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

namespace {

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

int count_type(const std::vector<DnsRecord>& rows, uint16_t type) {
    int n = 0;
    for (const auto& r : rows)
        if (r.type == type) n++;
    return n;
}

void print_graph_lines(const FusionState& s) {
    std::map<std::string, int> degree;
    std::map<std::string, std::vector<std::string>> adj;
    for (const auto& e : s.edges) {
        degree[e.from]++;
        degree[e.to]++;
        adj[e.from].push_back(e.to);
    }
    std::cout << "graph nodes=" << degree.size() << " edges=" << s.edges.size() << "\n";
    std::string root = s.qname;
    std::queue<std::pair<std::string, int>> q;
    std::set<std::string> seen;
    if (!root.empty()) {
        q.push({root, 0});
        seen.insert(root);
    }
    int shown = 0;
    while (!q.empty() && shown < 12) {
        auto cur = q.front();
        q.pop();
        std::cout << "  " << std::string(static_cast<size_t>(cur.second) * 2, ' ') << cur.first
                  << " deg=" << degree[cur.first] << "\n";
        shown++;
        for (const auto& n : adj[cur.first]) {
            if (seen.insert(n).second) q.push({n, cur.second + 1});
        }
    }
    if (static_cast<int>(degree.size()) > shown) std::cout << "  ... " << (degree.size() - shown) << " more\n";
}

} // namespace

void print_scale_intel(const std::string& name, bool as_json) {
    ResolverEngine engine;
    auto a = engine.query(name, DNS_TYPE_A, "8.8.8.8");
    auto aaaa = engine.query(name, DNS_TYPE_AAAA, "1.1.1.1");
    auto ns = engine.query(name, DNS_TYPE_NS, "9.9.9.9");
    auto mx = engine.query(name, DNS_TYPE_MX, "8.8.8.8");
    auto txt = engine.query(name, DNS_TYPE_TXT, "1.1.1.1");
    auto fused = build_fusion(name);
    auto poison = run_poison_classifier(name, {"8.8.8.8", "1.1.1.1", "9.9.9.9"});

    std::string label = name;
    auto dot = label.find('.');
    if (dot != std::string::npos) label = label.substr(0, dot);
    int digits = 0, hyphens = 0, vowels = 0;
    for (char c : label) {
        if (c == '-') hyphens++;
        else if (c >= '0' && c <= '9') digits++;
        else {
            char low = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
            if (low == 'a' || low == 'e' || low == 'i' || low == 'o' || low == 'u') vowels++;
        }
    }
    int labels = 1;
    for (char c : name)
        if (c == '.') labels++;
    int ttl_min = 0, ttl_max = 0, ttl_n = 0;
    for (const auto& r : a.message.answers) {
        if (ttl_n == 0 || static_cast<int>(r.ttl) < ttl_min) ttl_min = static_cast<int>(r.ttl);
        if (static_cast<int>(r.ttl) > ttl_max) ttl_max = static_cast<int>(r.ttl);
        ttl_n++;
    }
    double h = entropy_of(label);
    int a_n = static_cast<int>(a.message.answers.size());
    int degree = 0;
    for (const auto& e : fused.edges)
        if (e.from == name || e.to == name) degree++;

    struct Row { std::string id, value; };
    std::vector<Row> rows;
    auto add = [&](const std::string& id, const std::string& value) { rows.push_back({id, value}); };
    add("S01", "entropy=" + std::to_string(h));
    add("S02", "label_len=" + std::to_string(label.size()));
    add("S03", "digit_ratio=" + std::to_string(label.empty() ? 0.0 : static_cast<double>(digits) / label.size()));
    add("S04", "hyphen=" + std::to_string(hyphens));
    add("S05", "vowel_ratio=" + std::to_string(label.empty() ? 0.0 : static_cast<double>(vowels) / label.size()));
    add("S06", "labels=" + std::to_string(labels));
    add("S07", "lexical_flag=" + std::string(h >= 3.0 && label.size() >= 10 ? "yes" : "no"));
    add("S08", "A=" + std::to_string(a_n));
    add("S09", "AAAA=" + std::to_string(aaaa.message.answers.size()));
    add("S10", "NS=" + std::to_string(ns.message.answers.size()));
    add("S11", "MX=" + std::to_string(mx.message.answers.size()));
    add("S12", "TXT=" + std::to_string(txt.message.answers.size()));
    add("S13", "ttl_span=" + std::to_string(ttl_max - ttl_min));
    add("S14", "edns=" + std::string(a.message.has_edns ? "yes" : "no"));
    add("S15", "dnssec_ok=" + std::string(a.message.dnssec_ok ? "yes" : "no"));
    add("S16", "ad=" + std::string(a.message.flags.ad ? "yes" : "no"));
    add("S17", "aa=" + std::string(a.message.flags.aa ? "yes" : "no"));
    add("S18", "tc=" + std::string(a.message.flags.tc ? "yes" : "no"));
    add("S19", "rrsig=" + std::to_string(count_type(a.message.answers, DNS_TYPE_RRSIG)));
    add("S20", "cname=" + std::to_string(count_type(a.message.answers, DNS_TYPE_CNAME)));
    add("S21", "contradiction=" + std::string(fused.contradiction ? "yes" : "no"));
    add("S22", "agreement=" + std::to_string(fused.confidence));
    add("S23", "raw=" + std::to_string(fused.raw));
    add("S24", "dup_dropped=" + std::to_string(fused.dropped_dup));
    add("S25", "edges=" + std::to_string(fused.edges.size()));
    add("S26", "qname_degree=" + std::to_string(degree));
    add("S27", "poison_verdict=" + poison.verdict);
    add("S28", "gates=" + std::to_string(poison.gate_dnssec) + "/" + std::to_string(poison.gate_resolver) + "/" + std::to_string(poison.gate_aa));
    add("S29", "rtt_ms=" + std::to_string(a.rtt.count()));
    std::vector<double> rtts{static_cast<double>(a.rtt.count())};
    for (int i = 0; i < 3; ++i) {
        auto extra = engine.query(name, DNS_TYPE_A, "1.1.1.1");
        rtts.push_back(static_cast<double>(extra.rtt.count()));
    }
    auto scored = score_name(name, rtts);
    add("S30", "fused_A=" + std::to_string(fused.fused_a.size()) +
               " kalman_rtt_ms=" + std::to_string(scored.smoothed_rtt_ms) +
               " residual_sq=" + std::to_string(scored.residual_sq) +
               " confidence=" + std::to_string(scored.confidence));

    if (as_json) {
        std::cout << "{\n  \"name\": \"" << name << "\",\n  \"features\": [\n";
        for (size_t i = 0; i < rows.size(); ++i) {
            std::cout << "    {\"id\":\"" << rows[i].id << "\",\"value\":\"" << rows[i].value << "\"}"
                      << (i + 1 == rows.size() ? "\n" : ",\n");
        }
        std::cout << "  ],\n  \"edges\": [\n";
        for (size_t i = 0; i < fused.edges.size() && i < 40; ++i) {
            const auto& e = fused.edges[i];
            std::cout << "    {\"from\":\"" << e.from << "\",\"rel\":\"" << e.rel << "\",\"to\":\"" << e.to << "\"}"
                      << (i + 1 == fused.edges.size() || i == 39 ? "\n" : ",\n");
        }
        std::cout << "  ]\n}\n";
        return;
    }

    std::cout << "WhiteDNS scale  " << name << "  features=" << rows.size() << "\n";
    std::cout << "continuous snapshot. scores are observations, not attack probabilities.\n";
    for (const auto& r : rows) std::cout << r.id << " " << r.value << "\n";
    print_graph_lines(fused);
}

} // namespace core
} // namespace whitedns
