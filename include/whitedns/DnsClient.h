#ifndef WHITEDNS_DNS_CLIENT_H
#define WHITEDNS_DNS_CLIENT_H

#include "whitedns/DnsTypes.h"

#include <chrono>
#include <string>

namespace whitedns {

class DnsClient {
public:
    explicit DnsClient(std::chrono::milliseconds timeout = std::chrono::milliseconds(2500));

    DnsResponse query(const std::string& domain,
                      const std::string& server,
                      uint16_t query_type,
                      bool request_dnssec = false) const;

private:
    std::chrono::milliseconds timeout_;
};

} // namespace whitedns

#endif // WHITEDNS_DNS_CLIENT_H
