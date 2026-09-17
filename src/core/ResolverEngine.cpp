#include "whitedns/core/ResolverEngine.h"

#include <algorithm>
#include <cctype>
#include <chrono>

namespace whitedns {
namespace core {

ResolverEngine::ResolverEngine(std::chrono::milliseconds timeout) : timeout_(timeout) {}

std::string ResolverEngine::cache_key(const std::string& qname, uint16_t qtype, const std::string& resolver) const {
    return qname + "|" + std::to_string(qtype) + "|" + resolver;
}

void ResolverEngine::clear_cache() {
    cache_.clear();
    cache_stats_ = {};
}

Observation ResolverEngine::query(const std::string& qname,
                                  uint16_t qtype,
                                  const std::string& resolver,
                                  TransportKind transport,
                                  bool dnssec_ok) {
    const std::string res = resolver.empty() ? "8.8.8.8" : resolver;
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    auto key = cache_key(qname, qtype, res);
    auto it = cache_.find(key);
    if (it != cache_.end() && it->second.expire_unix_ms > now) {
        cache_stats_.hits++;
        auto hit = it->second.obs;
        hit.transport = hit.transport + "+cache";
        hit.rtt = std::chrono::milliseconds(0);
        return hit;
    }
    cache_stats_.misses++;
    auto obs = query_uncached(qname, qtype, res, transport, dnssec_ok);
    uint32_t ttl = 30;
    for (const auto& rec : obs.message.answers)
        if (rec.ttl > 0 && (ttl == 30 || rec.ttl < ttl)) ttl = rec.ttl;
    if (obs.ok) {
        CacheEnt ent;
        ent.obs = obs;
        ent.expire_unix_ms = now + static_cast<std::int64_t>(ttl) * 1000;
        cache_[key] = ent;
        cache_stats_.stores++;
    }
    return obs;
}

Observation ResolverEngine::query_uncached(const std::string& qname,
                                           uint16_t qtype,
                                           const std::string& resolver,
                                           TransportKind transport,
                                           bool dnssec_ok) {
    Observation obs;
    obs.qname = qname;
    obs.qtype = qtype;
    obs.resolver = resolver.empty() ? "8.8.8.8" : resolver;
    obs.transport = transport_name(transport);
    obs.unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();

    auto packet = build_query_message(qname, qtype, static_cast<uint16_t>(obs.unix_ms & 0xffff), true, dnssec_ok);
    TransportResult raw;
    if (transport == TransportKind::Tcp) raw = tcp_.query(obs.resolver, 53, packet, timeout_);
    else raw = udp_.query(obs.resolver, 53, packet, timeout_);

    obs.rtt = raw.rtt;
    if (!raw.ok) {
        obs.error = raw.error;
        return obs;
    }
    obs.message = parse_message(raw.bytes);
    if (obs.message.flags.tc && transport == TransportKind::Udp) {
        raw = tcp_.query(obs.resolver, 53, packet, timeout_);
        obs.transport = "tcp-fallback";
        obs.rtt = raw.rtt;
        if (raw.ok) obs.message = parse_message(raw.bytes);
    }
    obs.ok = raw.ok && obs.message.parse_error.empty();
    if (!obs.message.parse_error.empty()) obs.error = obs.message.parse_error;
    return obs;
}

std::vector<ResolverEngine::ResolverBaseline> ResolverEngine::baseline(const std::string& qname,
                                                                        uint16_t qtype,
                                                                        const std::vector<std::string>& resolvers) {
    std::vector<ResolverBaseline> out;
    for (const auto& r : resolvers) {
        ResolverBaseline b;
        b.resolver = r;
        long sum = 0;
        for (int i = 0; i < 2; ++i) {
            auto obs = query(qname, qtype, r, TransportKind::Udp, false);
            b.samples++;
            if (!obs.ok) continue;
            b.ok++;
            long ms = obs.rtt.count();
            if (b.ok == 1) {
                b.min_ms = b.max_ms = ms;
            } else {
                if (ms < b.min_ms) b.min_ms = ms;
                if (ms > b.max_ms) b.max_ms = ms;
            }
            sum += ms;
            if (i == 0) {
                for (const auto& rec : obs.message.answers)
                    if (!rec.value.empty()) b.answers.push_back(rec.type_name + " " + rec.value);
            }
            if (i == 1 && obs.transport.find("cache") != std::string::npos) b.cache_hit_second = true;
        }
        if (b.ok) b.avg_ms = sum / b.ok;
        out.push_back(b);
    }
    return out;
}

std::vector<Observation> ResolverEngine::compare(const std::string& qname,
                                                 uint16_t qtype,
                                                 const std::vector<std::string>& resolvers,
                                                 bool dnssec_ok) {
    std::vector<Observation> out;
    for (const auto& r : resolvers) out.push_back(query(qname, qtype, r, TransportKind::Udp, dnssec_ok));
    return out;
}

bool in_scope(const std::string& qname, const std::string& scope_suffix) {
    if (scope_suffix.empty() || scope_suffix == "*") return true;
    std::string q = qname;
    std::string s = scope_suffix;
    auto lower = [](std::string& v) {
        std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    };
    lower(q);
    lower(s);
    while (!q.empty() && q.back() == '.') q.pop_back();
    while (!s.empty() && s.back() == '.') s.pop_back();
    if (s.size() >= 2 && s[0] == '*' && s[1] == '.') s = s.substr(2);
    if (q == s) return true;
    if (q.size() > s.size() && q.compare(q.size() - s.size(), s.size(), s) == 0 && q[q.size() - s.size() - 1] == '.')
        return true;
    return false;
}

} // namespace core
} // namespace whitedns
