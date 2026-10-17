#ifndef WHITEDNS_CORE_AGCODE_H
#define WHITEDNS_CORE_AGCODE_H

#include <vector>
#include <cstdint>

namespace whitedns {
namespace core {

// Research AG-code syndrome over GF(2). Not used in DNS wire encoding.
// Syndrome of a received word against a parity-check matrix.
std::vector<int> syndrome_gf2(const std::vector<std::vector<int>>& H, const std::vector<int>& received);

} // namespace core
} // namespace whitedns

#endif
