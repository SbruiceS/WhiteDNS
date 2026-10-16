#ifndef WHITEDNS_CORE_FILTERENGINE_H
#define WHITEDNS_CORE_FILTERENGINE_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct FilterHit {
    std::string type;
    std::string value;
    int resolvers = 0;
    double score = 0;
};

struct FilterReport {
    std::string qname;
    int queries = 0;
    int kept = 0;
    int dropped = 0;
    int peak_items = 0;
    std::vector<FilterHit> hits;
    std::string note;
};

FilterReport run_filter(const std::string& qname,
                        const std::vector<std::string>& resolvers,
                        const std::vector<uint16_t>& types,
                        const std::string& pattern);
void print_filter(const FilterReport& r);

} // namespace core
} // namespace whitedns

#endif
