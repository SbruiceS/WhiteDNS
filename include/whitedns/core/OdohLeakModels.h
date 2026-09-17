#ifndef WHITEDNS_CORE_ODOH_LEAK_MODELS_H
#define WHITEDNS_CORE_ODOH_LEAK_MODELS_H

#include "whitedns/core/Odoh.h"

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct LeakFinding {
    std::string model;
    std::string id;
    std::string status;   // sealed, residual, leak, info
    std::string title;
    std::string detail;
};

struct OdohLeakReport {
    std::string qname;
    OdohResult a;
    OdohResult aaaa;
    OdohResult ns;
    int sealed = 0;
    int residual = 0;
    int leak = 0;
    int info = 0;
    std::vector<LeakFinding> findings;
};

OdohLeakReport run_odoh_leak_models(const std::string& qname,
                                    const std::string& target,
                                    const std::string& proxy);

void print_odoh_leak_models(const OdohLeakReport& report);

} // namespace core
} // namespace whitedns

#endif
