#ifndef WHITEDNS_CORE_INTELLIGENCE_H
#define WHITEDNS_CORE_INTELLIGENCE_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct IntelEdge {
    std::string from;
    std::string rel;
    std::string to;
    std::string provenance;
};

struct FusionState {
    std::string qname;
    int raw = 0;
    int kept = 0;
    int dropped_dup = 0;
    std::vector<std::string> fused_a;
    bool contradiction = false;
    double confidence = 0;
    std::string confidence_why;
    std::vector<IntelEdge> edges;
    std::vector<std::string> notes;
    std::vector<std::string> algorithm_lines;
};

FusionState build_fusion(const std::string& qname);
void print_graph(const FusionState& s);
void print_security(const FusionState& s);
void print_report(const FusionState& s);
void print_doctor();
void print_dga(const std::string& name);
void print_summary(const std::string& name);
void print_traffic(const std::string& name);

} // namespace core
} // namespace whitedns

#endif
