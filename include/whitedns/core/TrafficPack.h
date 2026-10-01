#ifndef WHITEDNS_CORE_TRAFFIC_PACK_H
#define WHITEDNS_CORE_TRAFFIC_PACK_H

#include <string>

namespace whitedns {
namespace core {

void print_traffic_pack(const std::string& name);
void print_traffic_family(const std::string& name, const std::string& family);

} // namespace core
} // namespace whitedns

#endif
