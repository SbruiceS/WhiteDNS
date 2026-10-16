#ifndef WHITEDNS_CORE_QUERYCONTROL_H
#define WHITEDNS_CORE_QUERYCONTROL_H

#include <string>

namespace whitedns {
namespace core {

struct ControlReport {
    std::string qname;
    std::string transport;
    int samples = 0;
    double target_ms = 0;
    double mean_ms = 0;
    double util = 0;
    int rate = 0;
    std::string note;
};

ControlReport run_query_control(const std::string& qname, const std::string& transport);
void print_query_control(const ControlReport& r);

} // namespace core
} // namespace whitedns

#endif
