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
    auto pr = pagerank(edges);
    std::vector<std::pair<double, std::string>> scored;
    for (const auto& kv : pr) scored.push_back({kv.second, kv.first});
    std::sort(scored.begin(), scored.end(), [](auto& a, auto& b) { return a.first > b.first; });
    for (size_t i = 0; i < scored.size() && i < 5; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%s:%.4f", scored[i].second.c_str(), scored[i].first);
        r.top_pagerank.push_back(buf);
    }
    return r;
}

void print_graph_report(const GraphReport& r) {
    std::cout << "graph  vertices=" << r.vertices
              << " edges=" << r.edges
              << " components=" << r.components << "\n";
    std::cout << "pagerank top\n";
    for (const auto& s : r.top_pagerank) std::cout << "  " << s << "\n";
}

} // namespace core
} // namespace whitedns
