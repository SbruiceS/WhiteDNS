#include "whitedns/core/FaultReport.h"

#include "whitedns/core/DnssecPath.h"
#include "whitedns/core/PoisonClassifier.h"
#include "whitedns/core/ResolverIntel.h"
#include "whitedns/core/ThreatEngine.h"

#include <iostream>

namespace whitedns {
namespace core {

void run_print_faults(const std::string& qname) {
    std::cout << "WhiteDNS faults (defensive only — no vendor attack engine)\n";
    std::cout << "QNAME: " << qname << "\n";
    std::cout << "A finding is not a confirmed attack. See poison gates.\n";
    std::cout << "============================================================\n";

    auto poison = run_poison_classifier(qname, {});
    std::cout << "POISON verdict=" << poison.verdict
              << "  gates dnssec=" << (poison.gate_dnssec ? "1" : "0")
              << " resolver=" << (poison.gate_resolver ? "1" : "0")
              << " aa=" << (poison.gate_aa ? "1" : "0") << "\n";
    for (const auto& line : poison.a_sets) std::cout << "  " << line << "\n";
    for (const auto& line : poison.aa_sets) std::cout << "  " << line << "\n";
    if (poison.verdict == "confirmed")
        std::cout << "  CONFIRMED only because all three gates fired.\n";
    else
        std::cout << "  Not a confirmed poison event.\n";

    auto path = run_dnssec_path(qname, "8.8.8.8");
    std::cout << "DNSSEC class=" << path.klass
              << " DS→DNSKEY=" << (path.ds_matches_key ? "MATCH" : "no-match")
              << " DS=" << path.ds_count << " DNSKEY=" << path.dnskey_count
              << " RRSIG=" << path.rrsig_count << "\n";

    auto detect = run_threat_detect(qname);
    int faults = 0;
    std::cout << "------------------------------------------------------------\n";
    std::cout << "Security issues / faults from taxonomy (FINDING + ANOMALY only)\n";
    for (const auto& f : detect.findings) {
        if (f.kind != "FINDING" && f.kind != "ANOMALY") continue;
        faults++;
        std::cout << "[" << f.kind << "] " << f.rule_id << "  conf=" << f.confidence << "\n";
        std::cout << "        " << f.detail << "\n";
        auto* rule = find_threat_rule(f.rule_id);
        if (rule) std::cout << "        do: " << rule->recommend << "  fp: " << rule->fp << "\n";
    }
    if (faults == 0) std::cout << "(no FINDING/ANOMALY on this snapshot)\n";
    std::cout << "------------------------------------------------------------\n";
    std::cout << "issues=" << faults << "  evidence=" << detect.evidence_sha256 << "\n";
}

} // namespace core
} // namespace whitedns
