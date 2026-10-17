#ifndef WHITEDNS_CORE_AGCODE_H
#define WHITEDNS_CORE_AGCODE_H

#include <vector>
#include <cstdint>

namespace whitedns {
namespace core {

// Research AG-code syndrome over GF(2). Not used in DNS wire encoding.
// Syndrome of a received word against a parity-check matrix.
std::vector<int> syndrome_gf2(const std::vector<std::vector<int>>& H, const std::vector<int>& received);
// Nearest-codeword decode for a small Hamming-like code. Returns corrected word or empty on failure.
std::vector<int> decode_nearest(const std::vector<std::vector<int>>& codewords, const std::vector<int>& received);

} // namespace core
} // namespace whitedns

#endif
