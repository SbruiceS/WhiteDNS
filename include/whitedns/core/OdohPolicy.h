#ifndef WHITEDNS_CORE_ODOH_POLICY_H
#define WHITEDNS_CORE_ODOH_POLICY_H

#include "whitedns/core/OdohFilter.h"

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct OdohPolicyControl {
    std::string id;
    std::string category;
    std::string title;
    std::string status;
    std::string severity;
    std::string message;
};

struct OdohPolicyReport {
    std::string qname;
    OdohResult path;
    int pass = 0;
    int fail = 0;
    int warn = 0;
    int info = 0;
    std::vector<OdohPolicyControl> controls;
};

OdohPolicyReport run_odoh_policy(const std::string& qname,
                                 const std::string& target,
                                 const std::string& proxy,
                                 const std::string& scope);

void print_odoh_policy(const OdohPolicyReport& report, bool verbose);

} // namespace core
} // namespace whitedns

#endif
