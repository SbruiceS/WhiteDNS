#ifndef WHITEDNS_CORE_GRAPHINTEL_H
#define WHITEDNS_CORE_GRAPHINTEL_H

#include <string>
#include <vector>
#include <map>

namespace whitedns {
namespace core {

struct Edge {
    std::string from;
    std::string to;
};

struct GraphReport {
    int vertices = 0;
    int edges = 0;
    int components = 0;
    std::vector<std::string> top_pagerank;  // name:score
    std::vector<std::string> top_degree;    // name:degree
};

// Undirected view for components. Directed for PageRank.
int connected_components(const std::vector<Edge>& edges);
std::map<std::string, double> pagerank(const std::vector<Edge>& edges, int iters = 20, double d = 0.85);
GraphReport analyze_graph(const std::vector<Edge>& edges);
void print_graph_report(const GraphReport& r);

} // namespace core
} // namespace whitedns

#endif
