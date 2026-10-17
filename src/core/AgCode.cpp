#include "whitedns/core/AgCode.h"

#include <cstddef>

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

} // namespace core
} // namespace whitedns