#include "whitedns/core/PoisonClassifier.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/IanaDns.h"
#include "whitedns/core/DnssecPath.h"
#include "whitedns/core/ResolverEngine.h"

#include <algorithm>
#include <iostream>
#include <set>
#include <sstream>

namespace whitedns {
namespace core {

PoisonReport run_poison_classifier(const std::string& qname, const std::vector<std::string>& resolvers_in) {
    PoisonReport report;
    report.qname = qname;
    report.resolvers = resolvers_in;
    if (report.resolvers.empty()) report.resolvers = {"8.8.8.8", "1.1.1.1", "9.9.9.9"};

    ResolverEngine engine;
    std::vector<std::set<std::string>> sets;
    for (const auto& r : report.resolvers) {
        auto obs = engine.query(qname, DNS_TYPE_A, r);
        std::set<std::string> s;
        std::ostringstream line;
        line << "@" << r << " rtt=" << obs.rtt.count() << "ms rcode="
             << iana_rcode_name(obs.message.flags.rcode) << " A=";
        bool first = true;
        for (const auto& rec : obs.message.answers) {
            if (rec.type != DNS_TYPE_A) continue;
            s.insert(rec.value);
            if (!first) line << ",";
            first = false;
            line << rec.value;
        }
        if (first) line << "(none)";
        report.a_sets.push_back(line.str());
        sets.push_back(std::move(s));
    }

    auto add = [&](const char* id, const char* klass, const char* title, const std::string& detail) {
        PoisonFinding f;
        f.id = id;
        f.klass = klass;
        f.title = title;
        f.detail = detail;
        report.findings.push_back(f);
    };

    bool any_empty = false;
    bool any_overlap = false;
    for (size_t i = 0; i < sets.size(); ++i) {
        if (sets[i].empty()) any_empty = true;
        for (size_t j = i + 1; j < sets.size(); ++j) {
            for (const auto& ip : sets[i])
                if (sets[j].count(ip)) any_overlap = true;
            if (sets[i] != sets[j]) report.sets_agree = false;
        }
    }
    if (sets.size() == 1) report.sets_agree = true;

    auto path = run_dnssec_path(qname, report.resolvers.front());
    report.dnssec_match = path.ds_matches_key;

    if (report.sets_agree) {
        add("POISON-01", "OBSERVATION", "Multi-resolver A sets",
            "Resolvers returned the same A set (or a single resolver was used).");
        report.verdict = "none";
    } else if (any_overlap) {
        add("POISON-01", "OBSERVATION", "Multi-resolver A sets",
            "Sets differ but intersect. Typical anycast. Not poisoning.");
        report.verdict = "observe";
    } else {
        add("POISON-01", "ANOMALY", "Multi-resolver A sets",
            "Disjoint A sets. Anycast or split view is still the default explanation.");
        report.verdict = "anomaly";
    }

    add("POISON-02", report.dnssec_match ? "CONFIRMED_BY_VALIDATION" : "OBSERVATION",
        "DNSSEC parent chain",
        report.dnssec_match ? "DS digest matches a child DNSKEY."
                            : "No DS→DNSKEY match. Gate 1 (DNSSEC contradiction) stays closed.");

    report.gate_dnssec = path.ds_present && !path.ds_matches_key;

    auto ns_obs = engine.query(qname, DNS_TYPE_NS, report.resolvers.front());
    std::vector<std::string> nshosts;
    for (const auto& rec : ns_obs.message.answers)
        if (rec.type == DNS_TYPE_NS && !rec.value.empty()) nshosts.push_back(rec.value);
    std::vector<std::set<std::string>> aa_ip_sets;
    std::set<std::string> aa_union;
    int aa_ok = 0;
    for (const auto& host : nshosts) {
        auto nip = engine.query(host, DNS_TYPE_A, report.resolvers.front());
        std::string ip;
        for (const auto& rec : nip.message.answers)
            if (rec.type == DNS_TYPE_A) {
                ip = rec.value;
                break;
            }
        if (ip.empty()) {
            report.aa_sets.push_back("NS " + host + " (no A)");
            continue;
        }
        auto auth = engine.query(qname, DNS_TYPE_A, ip);
        std::set<std::string> s;
        std::ostringstream line;
        line << "AA @" << host << " " << ip << " aa=" << (auth.message.flags.aa ? "1" : "0")
             << " rcode=" << iana_rcode_name(auth.message.flags.rcode) << " A=";
        bool first = true;
        for (const auto& rec : auth.message.answers) {
            if (rec.type != DNS_TYPE_A) continue;
            s.insert(rec.value);
            if (!first) line << ",";
            first = false;
            line << rec.value;
        }
        if (first) line << "(none)";
        report.aa_sets.push_back(line.str());
        if (auth.message.flags.aa && !s.empty()) {
            aa_ok++;
            aa_union.insert(s.begin(), s.end());
            aa_ip_sets.push_back(s);
        }
    }
    bool aa_internal_disagree = false;
    for (size_t i = 0; i < aa_ip_sets.size(); ++i)
        for (size_t j = i + 1; j < aa_ip_sets.size(); ++j)
            if (aa_ip_sets[i] != aa_ip_sets[j]) aa_internal_disagree = true;
    bool rec_vs_aa = false;
    if (!aa_union.empty()) {
        for (const auto& rs : sets) {
            if (rs.empty()) continue;
            bool hit = false;
            for (const auto& ip : rs)
                if (aa_union.count(ip)) hit = true;
            if (!hit) rec_vs_aa = true;
        }
    }
    report.gate_aa = aa_internal_disagree || rec_vs_aa;
    report.gate_resolver = !report.sets_agree && !any_overlap;

    if (aa_ok == 0)
        add("POISON-03", "INCONCLUSIVE", "Authoritative AA",
            "No AA A-set from apex NS. Gate 3 stays open/unknown.");
    else if (report.gate_aa)
        add("POISON-03", "ANOMALY", "Authoritative AA",
            "AA sets disagree with each other or are disjoint from recursive answers.");
    else
        add("POISON-03", "OBSERVATION", "Authoritative AA",
            "AA from " + std::to_string(aa_ok) + " NS; recursive answers overlap AA.");

    if (any_empty) {
        add("POISON-04", "ANOMALY", "Empty A from at least one resolver",
            "NODATA/error on one path. Check RCODE before calling it hijack.");
        if (report.verdict == "none") report.verdict = "anomaly";
    }

    const bool all_gates = report.gate_dnssec && report.gate_resolver && report.gate_aa;
    add("POISON-05", all_gates ? "CONFIRMED_BY_VALIDATION" : "OBSERVATION",
        "Promotion gate",
        std::string("dnssec_contradiction=") + (report.gate_dnssec ? "yes" : "no") +
            " resolver_disjoint=" + (report.gate_resolver ? "yes" : "no") +
            " aa_disagree=" + (report.gate_aa ? "yes" : "no") +
            (all_gates ? " → CONFIRMED" : " → not confirmed"));

    if (all_gates) report.verdict = "confirmed";
    else if (report.verdict == "anomaly")
        report.verdict = "not-confirmed";
    return report;
}

void print_poison_classifier(const PoisonReport& report) {
    std::cout << "WhiteDNS poison classifier\n";
    std::cout << "QNAME: " << report.qname << "  verdict: " << report.verdict << "\n";
    for (const auto& line : report.a_sets) std::cout << "  " << line << "\n";
    for (const auto& line : report.aa_sets) std::cout << "  " << line << "\n";
    std::cout << "gates: dnssec=" << (report.gate_dnssec ? "1" : "0")
              << " resolver=" << (report.gate_resolver ? "1" : "0")
              << " aa=" << (report.gate_aa ? "1" : "0") << "\n";
    std::cout << "------------------------------------------------------------\n";
    for (const auto& f : report.findings) {
        std::cout << "[" << f.klass << "] " << f.id << "  " << f.title << "\n";
        std::cout << "        " << f.detail << "\n";
    }
}

} // namespace core
} // namespace whitedns
