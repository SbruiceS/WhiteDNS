#include "whitedns/core/FilterEngine.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/ResolverEngine.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <map>
#include <string>

namespace whitedns {
namespace core {

namespace {

const char* type_name(uint16_t t) {
    switch (t) {
    case DNS_TYPE_A: return "A";
    case DNS_TYPE_AAAA: return "AAAA";
    case DNS_TYPE_NS: return "NS";
    case DNS_TYPE_MX: return "MX";
    case DNS_TYPE_TXT: return "TXT";
    case DNS_TYPE_SOA: return "SOA";
    case DNS_TYPE_CNAME: return "CNAME";
    default: return "TYPE";
    }
}

bool match_pat(const std::string& value, const std::string& pattern) {
    if (pattern.empty()) return true;
    return value.find(pattern) != std::string::npos;
}

} // namespace

FilterReport run_filter(const std::string& qname,
                        const std::vector<std::string>& resolvers,
                        const std::vector<uint16_t>& types,
                        const std::string& pattern) {
    FilterReport r;
    r.qname = qname;
    ResolverEngine engine;
    // key = type|value. value is agreement count. Cap at 4096 keys.
    std::map<std::string, int> agree;
    const int cap = 4096;
    for (const auto& res : resolvers) {
        for (uint16_t t : types) {
            auto o = engine.query(qname, t, res);
            r.queries++;
            for (const auto& rec : o.message.answers) {
                if (!match_pat(rec.value, pattern)) { r.dropped++; continue; }
                std::string key = std::string(type_name(t)) + "|" + rec.value;
                if (agree.size() >= static_cast<size_t>(cap) && !agree.count(key)) {
                    r.dropped++;
                    continue;
                }
                agree[key]++;
            }
            r.peak_items = std::max(r.peak_items, static_cast<int>(agree.size()));
        }
    }
    int nres = std::max(1, static_cast<int>(resolvers.size()));
    for (const auto& kv : agree) {
        auto bar = kv.first.find('|');
        FilterHit h;
        h.type = kv.first.substr(0, bar);
        h.value = kv.first.substr(bar + 1);
        h.resolvers = kv.second;
        // Score: agreement ratio times a small entropy penalty on long values.
        double ratio = static_cast<double>(kv.second) / nres;
        double len = static_cast<double>(h.value.size());
        h.score = ratio / (1.0 + std::log1p(len / 32.0));
        r.hits.push_back(h);
    }
    std::sort(r.hits.begin(), r.hits.end(), [](const FilterHit& a, const FilterHit& b) {
        return a.score > b.score;
    });
    if (r.hits.size() > 50) r.hits.resize(50);
    r.kept = static_cast<int>(r.hits.size());
    r.note = "cap=4096 keys. score = agreement / (1+ln(1+len/32)). top 50 shown. not a 400 MB store.";
    return r;
}

void print_filter(const FilterReport& r) {
    std::cout << "WhiteDNS filter  " << r.qname << "\n";
    std::cout << "queries=" << r.queries << " kept=" << r.kept
              << " dropped=" << r.dropped << " peak_items=" << r.peak_items << "\n";
    for (const auto& h : r.hits)
        std::cout << "  " << h.type << " " << h.value
                  << " resolvers=" << h.resolvers << " score=" << h.score << "\n";
    std::cout << r.note << "\n";
}

} // namespace core
} // namespace whitedns
