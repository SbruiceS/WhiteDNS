#include "whitedns/core/AgCode.h"

#include <cstddef>
#include <vector>

namespace whitedns {
namespace core {

std::vector<int> syndrome_gf2(const std::vector<std::vector<int>>& H, const std::vector<int>& received) {
    std::vector<int> s;
    if (H.empty() || received.empty()) return s;
    for (const auto& row : H) {
        int acc = 0;
        std::size_t n = std::min(row.size(), received.size());
        for (std::size_t i = 0; i < n; ++i) acc ^= (row[i] & received[i] & 1);
        s.push_back(acc);
    }
    return s;
}

std::vector<int> decode_nearest(const std::vector<std::vector<int>>& codewords, const std::vector<int>& received) {
    if (codewords.empty() || received.empty()) return {};
    int best_d = 1000000;
    std::vector<int> best;
    for (const auto& cw : codewords) {
        if (cw.size() != received.size()) continue;
        int d = 0;
        for (std::size_t i = 0; i < cw.size(); ++i) if ((cw[i] & 1) != (received[i] & 1)) d++;
        if (d < best_d) { best_d = d; best = cw; }
    }
    return best;
}

std::vector<int> AgEval::evaluate(const std::vector<int>& poly, const std::vector<int>& points) const {
    std::vector<int> out;
    for (int x : points) {
        int acc = 0, xp = 1;
        for (int c : poly) {
            acc = (acc + c * xp) % field;
            xp = (xp * x) % field;
        }
        out.push_back(acc);
    }
    return out;
}

int AgEval::riemann_roch_dim(int deg) const {
    if (deg < 0) return 0;
    int bound = deg - genus + 1;
    return bound > 0 ? bound : 0;
}

std::vector<int> AgEval::decode(const std::vector<int>& received, const std::vector<int>& points, int max_deg) const {
    if (received.size() != points.size() || received.empty()) return {};
    int best_d = 1000000;
    std::vector<int> best;
    int coeffs = max_deg + 1;
    int span = 1;
    for (int i = 0; i < coeffs; ++i) span *= field;
    for (int mask = 0; mask < span && mask < 2000; ++mask) {
        std::vector<int> poly(coeffs);
        int m = mask;
        for (int i = 0; i < coeffs; ++i) { poly[i] = m % field; m /= field; }
        auto cw = evaluate(poly, points);
        int d = 0;
        for (size_t i = 0; i < cw.size(); ++i) if (cw[i] != received[i]) d++;
        if (d < best_d) { best_d = d; best = cw; }
    }
    return best;
}

} // namespace core
} // namespace whitedns
