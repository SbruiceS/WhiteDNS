#ifndef WHITEDNS_CORE_ODOH_FILTER_H
#define WHITEDNS_CORE_ODOH_FILTER_H

#include "whitedns/core/Odoh.h"

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct OdohFilterFinding {
    std::string id;
    std::string title;
    std::string status;     // pass, warning, fail, info
    std::string severity;   // info, low, medium, high, critical
    std::string klass;      // OBSERVATION, ANOMALY, SUSPICIOUS, POLICY
    std::string message;
    std::string change;
};

struct OdohFilterReport {
    std::string qname;
    uint16_t qtype = 0;
    OdohResult path;
    int score = 0;
    std::string posture; // hardened, acceptable, leaky, blocked
    bool allow = true;
    std::vector<OdohFilterFinding> findings;
};

OdohFilterReport run_odoh_filter(const std::string& qname,
                                 uint16_t qtype,
                                 const std::string& target,
                                 const std::string& proxy,
                                 const std::string& scope);

void print_odoh_filter(const OdohFilterReport& report);

} // namespace core
} // namespace whitedns

#endif
