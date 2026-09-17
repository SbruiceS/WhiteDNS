#ifndef WHITEDNS_CORE_RESOLVER_ENGINE_H
#define WHITEDNS_CORE_RESOLVER_ENGINE_H

#include "whitedns/core/Transport.h"
#include "whitedns/core/Wire.h"

#include <chrono>
#include <map>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct Observation {
    std::string qname;
    uint16_t qtype = 0;
    std::string resolver;
    std::string transport;
    Message message;
    std::chrono::milliseconds rtt{0};
    bool ok = false;
    std::string error;
    std::int64_t unix_ms = 0;
};

class ResolverEngine {
public:
    explicit ResolverEngine(std::chrono::milliseconds timeout = std::chrono::milliseconds(2500));

    Observation query(const std::string& qname,
                      uint16_t qtype,
                      const std::string& resolver,
                      TransportKind transport = TransportKind::Udp,
                      bool dnssec_ok = false);

    std::vector<Observation> compare(const std::string& qname,
                                     uint16_t qtype,
                                     const std::vector<std::string>& resolvers,
                                     bool dnssec_ok = false);

    struct CacheStats {
        int hits = 0;
        int misses = 0;
        int stores = 0;
    };

    struct ResolverBaseline {
        std::string resolver;
        int samples = 0;
        int ok = 0;
        long min_ms = 0;
        long max_ms = 0;
        long avg_ms = 0;
        std::vector<std::string> answers;
        bool cache_hit_second = false;
    };

    std::vector<ResolverBaseline> baseline(const std::string& qname,
                                           uint16_t qtype,
                                           const std::vector<std::string>& resolvers);

    CacheStats cache_stats() const { return cache_stats_; }
    void clear_cache();

private:
    std::string cache_key(const std::string& qname, uint16_t qtype, const std::string& resolver) const;
    Observation query_uncached(const std::string& qname, uint16_t qtype, const std::string& resolver,
                               TransportKind transport, bool dnssec_ok);

    std::chrono::milliseconds timeout_;
    UdpTransport udp_;
    TcpTransport tcp_;
    struct CacheEnt {
        Observation obs;
        std::int64_t expire_unix_ms = 0;
    };
    std::map<std::string, CacheEnt> cache_;
    CacheStats cache_stats_;
};

bool in_scope(const std::string& qname, const std::string& scope_suffix);

} // namespace core
} // namespace whitedns

#endif
