#ifndef WHITEDNS_CORE_POISON_CLASSIFIER_H
#define WHITEDNS_CORE_POISON_CLASSIFIER_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct PoisonFinding {
    std::string id;
    std::string klass; // OBSERVATION, ANOMALY, SUSPICIOUS, STRONG_INDICATOR, CONFIRMED_BY_VALIDATION
    std::string title;
    std::string detail;
};

struct PoisonReport {
    std::string qname;
    std::string verdict; // none, observe, anomaly, not-confirmed
    std::vector<std::string> resolvers;
    std::vector<std::string> a_sets;
    bool sets_agree = true;
    bool dnssec_match = false;
    bool gate_resolver = false;
    bool gate_dnssec = false;
    bool gate_aa = false;
    std::vector<std::string> aa_sets;
    std::vector<PoisonFinding> findings;
};

PoisonReport run_poison_classifier(const std::string& qname, const std::vector<std::string>& resolvers);
void print_poison_classifier(const PoisonReport& report);

} // namespace core
} // namespace whitedns

#endif
