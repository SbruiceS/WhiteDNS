#ifndef WHITEDNS_CORE_THREAT_ENGINE_H
#define WHITEDNS_CORE_THREAT_ENGINE_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct ThreatRule {
    const char* id;
    const char* name;
    const char* category;
    const char* rfc;
    const char* vendor; // ITU / Cisco / Nokia / RFC
    const char* severity;
    const char* fp;
    const char* recommend;
    int eval; // 0 catalog-only, else evaluator id
};

struct ThreatFinding {
    std::string rule_id;
    std::string kind; // OBSERVATION, ANOMALY, FINDING, INCONCLUSIVE
    std::string confidence;
    std::string evidence_strength;
    std::string detail;
};

struct ThreatDetectReport {
    std::string qname;
    std::string evidence_sha256;
    int rules = 0;
    int evaluated = 0;
    int inconclusive = 0;
    std::vector<ThreatFinding> findings;
};

const std::vector<ThreatRule>& threat_catalog();
const ThreatRule* find_threat_rule(const std::string& id);
void print_threat_catalog();
void print_threat_categories();
void print_threat_info(const std::string& id);
ThreatDetectReport run_threat_detect(const std::string& qname);
void print_threat_detect(const ThreatDetectReport& report);
void print_threat_explain(const std::string& id);
bool validate_threat_rules();

} // namespace core
} // namespace whitedns

#endif
