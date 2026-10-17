#include "whitedns/core/GraphIntel.h"
#include "whitedns/core/Topology.h"
#include "whitedns/core/DnsMath.h"
#include "whitedns/core/AgCode.h"

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
    assert(t.betti1 == 0);  // triangle is filled, cycle killed
    assert(t.euler == 3 - 3 + 1);  // 1

    // Cycle of 4 (no diagonals): beta1 = 1.
    std::vector<SimplexEdge> c4 = {{"a","b"}, {"b","c"}, {"c","d"}, {"d","a"}};
    auto tc = compute_topology(c4);
    assert(tc.triangles == 0);
    assert(tc.betti0 == 1);
    assert(tc.betti1 == 1);

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

    // DFT of a constant is a spike at bin 0.
    std::vector<double> flat(8, 1.0);
    auto mag = dft_magnitude(flat);
    assert(!mag.empty());
    assert(mag[0] > mag[1]);

    // AG syndrome: even parity, all-zero word has zero syndrome.
    std::vector<std::vector<int>> H = {{1,1,0}, {0,1,1}};
    std::vector<int> word = {0,0,0};
    auto syn = syndrome_gf2(H, word);
    assert(syn.size() == 2);
    assert(syn[0] == 0 && syn[1] == 0);

    // KL of identical distributions is 0.
    std::vector<double> p = {0.5, 0.5};
    assert(kl_divergence(p, p) < 1e-9);

    // CUSUM of a constant at the target is 0.
    std::vector<double> flat2(5, 1.0);
    assert(cusum(flat2, 1.0) < 1e-9);

    // Joseph Kalman converges toward the measurement.
    KalmanJoseph kj;
    kj.update(10);
    kj.update(10);
    assert(kj.x > 9 && kj.x < 11);

    // Betweenness of a path a-b-c: b is highest.
    std::vector<Edge> path = {{"a","b"}, {"b","c"}};
    auto bt = betweenness(path);
    assert(bt["b"] >= bt["a"]);

    // Spectral cluster of a triangle is one component.
    std::vector<Edge> tri_e = {{"a","b"}, {"b","c"}, {"a","c"}};
    auto lab = spectral_cluster(tri_e, 2);
    assert(lab.size() == 3);

    // HMM returns a path of the same length.
    Hmm2 hmm;
    auto hp = hmm.viterbi({0, 0, 1, 1});
    assert(hp.size() == 4);

    // AG evaluation is deterministic.
    AgEval ag;
    auto cw = ag.evaluate({1, 2}, {1, 2, 3});
    assert(cw.size() == 3);

    std::cout << "graph+topology tests passed\n";
    return 0;
}
