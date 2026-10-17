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

} // namespace core
} // namespace whitedns
