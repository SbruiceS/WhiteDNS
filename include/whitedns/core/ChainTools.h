#ifndef WHITEDNS_CORE_CHAINTOOLS_H
#define WHITEDNS_CORE_CHAINTOOLS_H

#include <string>

namespace whitedns {
namespace core {

void print_ct(const std::string& name);
void print_cname_chain(const std::string& name, const std::string& resolver);

} // namespace core
} // namespace whitedns

#endif
