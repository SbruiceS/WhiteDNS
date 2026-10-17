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
// Evaluation code over y^2 = x^3 + 1 on small field. Research only.
struct AgEval {
    int field = 7;
    int genus = 1;
    std::vector<int> evaluate(const std::vector<int>& poly, const std::vector<int>& points) const;
    // Riemann-Roch: l(D) >= deg(D) - g + 1 for deg(D) > 2g-2.
    int riemann_roch_dim(int deg) const;
    // Decode by nearest codeword in the evaluation of polynomials up to degree d.
    std::vector<int> decode(const std::vector<int>& received, const std::vector<int>& points, int max_deg) const;
};

} // namespace core
} // namespace whitedns

#endif
