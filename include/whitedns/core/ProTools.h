#ifndef WHITEDNS_CORE_PROTOOLS_H
#define WHITEDNS_CORE_PROTOOLS_H

#include <string>

namespace whitedns {
namespace core {

void run_ptr(const std::string& qname);
void run_mx(const std::string& qname);
void run_latency(const std::string& qname);

} // namespace core
} // namespace whitedns

#endif
