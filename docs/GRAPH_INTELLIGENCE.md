# Graph intelligence

`whitedns graphintel <name>` runs connected components and PageRank on a small observation graph.

`whitedns topology <name>` builds a flag complex and reports:

- vertices, edges, triangles
- beta0 (connected components)
- Euler characteristic chi = V - E + F

These are research indicators. A high centrality or a non-zero Betti number is not a finding of compromise.

Tests: `tests/test_graph_topology.cpp` checks a two-component graph, a triangle (euler=1), a single edge (euler=1), and the empty complex.
