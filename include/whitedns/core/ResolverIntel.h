#ifndef WHITEDNS_CORE_RESOLVER_INTEL_H
#define WHITEDNS_CORE_RESOLVER_INTEL_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct IntelFact {
    std::string model;
    std::string rfc;
    std::string sans;
    std::string fact;
    std::string value;
};

struct ResolverIntelReport {
    std::string qname;
    std::string resolver;
    int models = 0;
    std::vector<IntelFact> facts;
};

ResolverIntelReport run_resolver_intel(const std::string& qname, const std::string& resolver);
void print_resolver_intel(const ResolverIntelReport& report);

} // namespace core
} // namespace whitedns

#endif
