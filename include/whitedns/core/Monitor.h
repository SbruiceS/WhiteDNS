#ifndef WHITEDNS_CORE_MONITOR_H
#define WHITEDNS_CORE_MONITOR_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

void run_monitor(const std::string& qname, int samples, int interval_s,
                 const std::vector<std::string>& resolvers);
void print_packages();

} // namespace core
} // namespace whitedns

#endif
