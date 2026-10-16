#include "whitedns/core/ChainTools.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/ResolverEngine.h"

#include <cstdio>
#include <iostream>
#include <set>
#include <sstream>
#include <string>

namespace whitedns {
namespace core {

namespace {

std::string curl_get(const std::string& url) {
    std::string cmd = "curl -fsS -A \"WhiteDNS/2.0\" --max-time 25 --max-filesize 4000000 \"" + url + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::string body;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) {
        body.append(buf);
        if (body.size() > 4000000) break;
    }
    pclose(pipe);
    return body;
}

std::string json_string_at(const std::string& body, size_t from, const std::string& key) {
    auto p = body.find("\"" + key + "\"", from);
    if (p == std::string::npos) return {};
    auto q1 = body.find('"', body.find(':', p) + 1);
    if (q1 == std::string::npos) return {};
    auto q2 = body.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    return body.substr(q1 + 1, q2 - q1 - 1);
}

} // namespace

void print_ct(const std::string& name) {
    std::cout << "WhiteDNS ct  " << name << "\n";
    std::cout << "source=crt.sh. names are observations from certificates, not a finding.\n";
    std::string url = "https://crt.sh/?q=%25." + name + "&output=json";
    std::string body = curl_get(url);
    if (body.empty()) {
        std::cout << "ct fetch=fail\n";
        return;
    }
    std::set<std::string> names;
    size_t cursor = 0;
    while (true) {
        auto at = body.find("\"name_value\"", cursor);
        if (at == std::string::npos) break;
        std::string raw = json_string_at(body, at, "name_value");
        std::stringstream ss(raw);
        std::string line;
        while (std::getline(ss, line, '\\')) {
            if (line == "n" || line.empty()) continue;
            if (line.size() > 1 && line[0] == 'n') line = line.substr(1);
            if (!line.empty() && line[0] != '*') names.insert(line);
        }
        cursor = at + 12;
    }
    std::cout << "certs_bytes=" << body.size() << " names=" << names.size() << "\n";
    int shown = 0;
    for (const auto& n : names) {
        if (shown++ >= 40) break;
        std::cout << "  " << n << "\n";
    }
    if (names.size() > 40) std::cout << "  ... " << (names.size() - 40) << " more\n";
}

void print_cname_chain(const std::string& name, const std::string& resolver) {
    std::cout << "WhiteDNS cname  " << name << "\n";
    ResolverEngine engine;
    std::string current = name;
    std::set<std::string> seen;
    for (int hop = 0; hop < 8; ++hop) {
        if (!seen.insert(current).second) {
            std::cout << "  hop " << hop << " loop " << current << "\n";
            return;
        }
        auto obs = engine.query(current, DNS_TYPE_CNAME, resolver);
        std::string next;
        for (const auto& rec : obs.message.answers) {
            if (rec.type == DNS_TYPE_CNAME && !rec.value.empty()) {
                next = rec.value;
                break;
            }
        }
        if (next.empty()) {
            auto a = engine.query(current, DNS_TYPE_A, resolver);
            std::cout << "  hop " << hop << " " << current << " terminal";
            for (const auto& rec : a.message.answers)
                if (rec.type == DNS_TYPE_A) std::cout << " A=" << rec.value;
            std::cout << "\n";
            return;
        }
        std::cout << "  hop " << hop << " " << current << " CNAME " << next << "\n";
        if (!next.empty() && next.back() == '.') next.pop_back();
        current = next;
    }
    std::cout << "  hop limit\n";
}

} // namespace core
} // namespace whitedns
