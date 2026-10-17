#ifndef WHITEDNS_CORE_TOPOLOGY_H
#define WHITEDNS_CORE_TOPOLOGY_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct SimplexEdge { std::string a, b; };

struct PersistenceInterval {
    double birth = 0;
    double death = 0;  // -1 if infinite
};

struct TopologyReport {
    int vertices = 0;
    int edges = 0;
    int triangles = 0;
    int betti0 = 0;
    int betti1 = 0;
    int euler = 0;
    std::vector<PersistenceInterval> persistence0;  // component birth/death
    std::string note;
};

// 0-dimensional persistence on a filtration by edge weight.
std::vector<PersistenceInterval> persistence_components(const std::vector<SimplexEdge>& edges, const std::vector<double>& weights);

// Flag complex on the undirected graph: a triangle is a 2-simplex when all three edges exist.
TopologyReport compute_topology(const std::vector<SimplexEdge>& edges);
void print_topology(const TopologyReport& r);

} // namespace core
} // namespace whitedns

#endif
