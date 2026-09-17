#ifndef WHITEDNS_CORE_DOH_CLIENT_H
#define WHITEDNS_CORE_DOH_CLIENT_H

#include "whitedns/DnsTypes.h"

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct DohQueryResult {
    bool ok = false;
    std::string endpoint;
    std::string error;
    int status = -1;
    std::vector<DnsRecord> records;
};

// HTTPS DNS-JSON fallback when UDP resolvers strip or hide DS/DNSKEY.
DohQueryResult doh_lookup(const std::string& qname, uint16_t qtype);

} // namespace core
} // namespace whitedns

#endif
