#include "whitedns/core/ProTools.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/CliDraw.h"
#include "whitedns/core/ResolverEngine.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <vector>

namespace whitedns {
namespace core {

namespace {

std::string reverse_ptr(const std::string& ip) {
    // IPv4 only for the PTR form.
    std::vector<std::string> o;
    std::stringstream ss(ip);
    std::string part;
    while (std::getline(ss, part, '.')) o.push_back(part);
    if (o.size() != 4) return {};
    return o[3] + "." + o[2] + "." + o[1] + "." + o[0] + ".in-addr.arpa";
}

} // namespace

void run_ptr(const std::string& qname) {
    draw_banner("WhiteDNS ptr", qname);
    ResolverEngine engine;
    auto a = engine.query(qname, DNS_TYPE_A, "8.8.8.8");
    if (a.message.answers.empty()) {
        std::cout << "  no A records\n";
        return;
    }
    for (const auto& rec : a.message.answers) {
        std::string zone = reverse_ptr(rec.value);
        if (zone.empty()) continue;
        auto ptr = engine.query(zone, DNS_TYPE_PTR, "8.8.8.8");
        std::cout << "  " << rec.value << "  ->  ";
        if (ptr.message.answers.empty()) std::cout << "no PTR\n";
        else {
            for (const auto& p : ptr.message.answers) std::cout << p.value << " ";
            std::cout << "\n";
        }
    }
    draw_rule();
    std::cout << "  reverse form is in-addr.arpa. missing PTR is an observation, not a fault.\n";
}

void run_mx(const std::string& qname) {
    draw_banner("WhiteDNS mx", qname);
    ResolverEngine engine;
    auto mx = engine.query(qname, DNS_TYPE_MX, "8.8.8.8");
    if (mx.message.answers.empty()) {
        std::cout << "  no MX\n";
        return;
    }
    int maxp = 1;
    for (const auto& rec : mx.message.answers) maxp = std::max(maxp, static_cast<int>(rec.ttl));
    for (const auto& rec : mx.message.answers)
        draw_bar(rec.value, static_cast<double>(rec.ttl), static_cast<double>(maxp));
    draw_rule();
    std::cout << "  bar is TTL, not preference. lower preference is preferred by SMTP.\n";
}

void run_latency(const std::string& qname) {
    draw_banner("WhiteDNS latency", qname);
    ResolverEngine engine;
    const char* resolvers[] = {"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"};
    std::vector<std::pair<std::string, double>> rows;
    double mx = 1;
    for (const char* res : resolvers) {
        auto o = engine.query(qname, DNS_TYPE_A, res);
        double ms = static_cast<double>(o.rtt.count());
        rows.push_back({res, ms});
        mx = std::max(mx, ms);
    }
    for (const auto& row : rows) draw_bar(row.first, row.second, mx);
    draw_rule();
    std::cout << "  bar is RTT in ms. longer is slower. anycast can differ by path.\n";
}

} // namespace core
} // namespace whitedns
