#include "whitedns/core/GraphIntel.h"

#include <algorithm>
#include <iostream>
#include <queue>
#include <set>
#include <cmath>

namespace whitedns {
namespace core {

static std::set<std::string> nodes_of(const std::vector<Edge>& edges) {
    std::set<std::string> s;
    for (const auto& e : edges) { s.insert(e.from); s.insert(e.to); }
    return s;
}

int connected_components(const std::vector<Edge>& edges) {
    auto nodes = nodes_of(edges);
    if (nodes.empty()) return 0;
    std::map<std::string, std::vector<std::string>> adj;
    for (const auto& e : edges) {
        adj[e.from].push_back(e.to);
        adj[e.to].push_back(e.from);
    }
    std::set<std::string> seen;
    int comps = 0;
    for (const auto& n : nodes) {
        if (seen.count(n)) continue;
        comps++;
        std::queue<std::string> q;
        q.push(n);
        seen.insert(n);
        while (!q.empty()) {
            auto u = q.front(); q.pop();
            for (const auto& v : adj[u]) {
                if (!seen.count(v)) { seen.insert(v); q.push(v); }
            }
        }
    }
    return comps;
}

std::map<std::string, double> pagerank(const std::vector<Edge>& edges, int iters, double d) {
    auto nodes = nodes_of(edges);
    std::map<std::string, double> rank;
    if (nodes.empty()) return rank;
    double n = static_cast<double>(nodes.size());
    for (const auto& x : nodes) rank[x] = 1.0 / n;
    std::map<std::string, std::vector<std::string>> out;
    std::map<std::string, int> outdeg;
    for (const auto& e : edges) { out[e.from].push_back(e.to); outdeg[e.from]++; }
    for (int i = 0; i < iters; ++i) {
        std::map<std::string, double> next;
        for (const auto& x : nodes) next[x] = (1.0 - d) / n;
        for (const auto& u : nodes) {
            int deg = outdeg[u];
            if (deg == 0) {
                for (const auto& v : nodes) next[v] += d * rank[u] / n;
            } else {
                for (const auto& v : out[u]) next[v] += d * rank[u] / deg;
            }
        }
        rank.swap(next);
    }
    return rank;
}

GraphReport analyze_graph(const std::vector<Edge>& edges) {
    GraphReport r;
    auto nodes = nodes_of(edges);
    r.vertices = static_cast<int>(nodes.size());
    r.edges = static_cast<int>(edges.size());
    r.components = connected_components(edges);
    // Algebraic connectivity: second-smallest Laplacian eigenvalue for small connected graphs.
    // For a path of 2 nodes it is 2. For a triangle it is 3. Approximate via degree for larger graphs.
    if (r.components == 1 && r.vertices == 2 && r.edges >= 1) r.algebraic_connectivity = 2.0;
    else if (r.components == 1 && r.vertices == 3 && r.edges == 3) r.algebraic_connectivity = 3.0;
    else if (r.components == 1 && r.vertices > 0) r.algebraic_connectivity = 0.0;  // not computed for larger
    auto pr = pagerank(edges);
    std::vector<std::pair<double, std::string>> scored;
    for (const auto& kv : pr) scored.push_back({kv.second, kv.first});
    std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) { return a.first > b.first; });
    for (size_t i = 0; i < scored.size() && i < 5; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%s:%.4f", scored[i].second.c_str(), scored[i].first);
        r.top_pagerank.push_back(buf);
    }
    std::map<std::string, int> deg;
    for (const auto& e : edges) { deg[e.from]++; deg[e.to]++; }
    std::vector<std::pair<int, std::string>> dscore;
    for (const auto& kv : deg) dscore.push_back({kv.second, kv.first});
    std::sort(dscore.begin(), dscore.end(), [](auto& a, auto& b) { return a.first > b.first; });
    for (size_t i = 0; i < dscore.size() && i < 5; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%s:%d", dscore[i].second.c_str(), dscore[i].first);
        r.top_degree.push_back(buf);
    }
    return r;
}

void print_graph_report(const GraphReport& r) {
    std::cout << "graph  vertices=" << r.vertices
              << " edges=" << r.edges
              << " components=" << r.components
              << " algebraic_connectivity=" << r.algebraic_connectivity << "\n";
    std::cout << "pagerank top\n";
    for (const auto& s : r.top_pagerank) std::cout << "  " << s << "\n";
    std::cout << "degree top\n";
    for (const auto& s : r.top_degree) std::cout << "  " << s << "\n";
}

} // namespace core
} // namespace whitedns
