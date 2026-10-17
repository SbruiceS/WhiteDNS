#include "whitedns/core/GraphIntel.h"
#include "whitedns/core/Topology.h"

#include <cassert>
#include <iostream>

int main() {
    using namespace whitedns::core;

    // Graph: two components. A-B, C alone via no edge... C-D.
    std::vector<Edge> edges = {{"a","b"}, {"c","d"}};
    assert(connected_components(edges) == 2);

    // Triangle.
    std::vector<SimplexEdge> tri = {{"a","b"}, {"b","c"}, {"a","c"}};
    auto t = compute_topology(tri);
    assert(t.vertices == 3);
    assert(t.edges == 3);
    assert(t.triangles == 1);
    assert(t.betti0 == 1);
    assert(t.euler == 3 - 3 + 1);  // 1

    // Single edge.
    std::vector<SimplexEdge> one = {{"x","y"}};
    auto t2 = compute_topology(one);
    assert(t2.vertices == 2);
    assert(t2.edges == 1);
    assert(t2.triangles == 0);
    assert(t2.betti0 == 1);
    assert(t2.euler == 2 - 1 + 0);  // 1

    // Empty.
    auto t0 = compute_topology({});
    assert(t0.vertices == 0);
    assert(t0.betti0 == 0);
    assert(t0.euler == 0);

    std::cout << "graph+topology tests passed\n";
    return 0;
}
