#include "whitedns/core/Topology.h"

#include <iostream>
#include <set>
#include <map>

namespace whitedns {
namespace core {

TopologyReport compute_topology(const std::vector<SimplexEdge>& edges) {
    TopologyReport r;
    std::set<std::string> verts;
    std::set<std::pair<std::string, std::string>> eset;
    for (const auto& e : edges) {
        if (e.a.empty() || e.b.empty() || e.a == e.b) continue;
        verts.insert(e.a);
        verts.insert(e.b);
        auto a = e.a < e.b ? e.a : e.b;
        auto b = e.a < e.b ? e.b : e.a;
        eset.insert({a, b});
    }
    r.vertices = static_cast<int>(verts.size());
    r.edges = static_cast<int>(eset.size());

    // Count triangles: three vertices all pairwise connected.
    std::vector<std::string> v(verts.begin(), verts.end());
    int tri = 0;
    for (size_t i = 0; i < v.size(); ++i)
        for (size_t j = i + 1; j < v.size(); ++j)
            for (size_t k = j + 1; k < v.size(); ++k) {
                auto has = [&](const std::string& x, const std::string& y) {
                    auto a = x < y ? x : y;
                    auto b = x < y ? y : x;
                    return eset.count({a, b}) > 0;
                };
                if (has(v[i], v[j]) && has(v[j], v[k]) && has(v[i], v[k])) tri++;
            }
    r.triangles = tri;

    // Betti-0 via union-find.
    std::map<std::string, std::string> parent;
    for (const auto& x : verts) parent[x] = x;
    auto find = [&](auto self, const std::string& x) -> std::string {
        if (parent[x] == x) return x;
        return parent[x] = self(self, parent[x]);
    };
    for (const auto& e : eset) {
        auto ra = find(find, e.first);
        auto rb = find(find, e.second);
        if (ra != rb) parent[ra] = rb;
    }
    std::set<std::string> roots;
    for (const auto& x : verts) roots.insert(find(find, x));
    r.betti0 = static_cast<int>(roots.size());

    // Betti-1 of the flag complex: cycle rank of the 1-skeleton minus filled triangles.
    // For a connected graph, cycle rank = E - V + components. Each filled triangle kills one cycle.
    int cycle_rank = r.edges - r.vertices + r.betti0;
    if (cycle_rank < 0) cycle_rank = 0;
    r.betti1 = cycle_rank - r.triangles;
    if (r.betti1 < 0) r.betti1 = 0;

    // Euler: chi = V - E + F, F = triangles in the flag complex.
    r.euler = r.vertices - r.edges + r.triangles;
    r.note = "flag complex; beta0=components; beta1=cycle_rank-triangles; euler=V-E+F; research indicator";
    return r;
}

void print_topology(const TopologyReport& r) {
    std::cout << "topology  vertices=" << r.vertices
              << " edges=" << r.edges
              << " triangles=" << r.triangles
              << " beta0=" << r.betti0
              << " beta1=" << r.betti1
              << " euler=" << r.euler << "\n";
    std::cout << r.note << "\n";
}

} // namespace core
} // namespace whitedns
