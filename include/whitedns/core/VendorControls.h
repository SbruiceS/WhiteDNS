#ifndef WHITEDNS_CORE_VENDOR_CONTROLS_H
#define WHITEDNS_CORE_VENDOR_CONTROLS_H

#include <string>

namespace whitedns {
namespace core {

// Defensive control catalog only. Does not generate attack traffic.
void run_print_vendor_controls(const std::string& qname);

} // namespace core
} // namespace whitedns

#endif
