#ifndef WHITEDNS_CORE_TOPOLOGY_H
#define WHITEDNS_CORE_TOPOLOGY_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct SimplexEdge { std::string a, b; };

struct TopologyReport {
    int vertices = 0;
    int edges = 0;
    int triangles = 0;
    int betti0 = 0;          // connected components
    int euler = 0;           // V - E + F (triangles as 2-simplices when present)
    std::string note;
};

// Flag complex on the undirected graph: a triangle is a 2-simplex when all three edges exist.
TopologyReport compute_topology(const std::vector<SimplexEdge>& edges);
void print_topology(const TopologyReport& r);

} // namespace core
} // namespace whitedns

#endif
