#include "whitedns/core/ThreatFeeds.h"

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

namespace {

std::string lower_copy(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return s;
}

std::string fetch(const std::string& url) {
    std::string cmd = "curl -fsS --max-time 20 --max-filesize 8000000 \"" + url + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::string body;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) {
        body.append(buf);
        if (body.size() > 8000000) break;
    }
    pclose(pipe);
    return body;
}

bool listed(const std::string& body, const std::string& name) {
    std::string needle = lower_copy(name);
    std::istringstream in(body);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = lower_copy(line.substr(start));
        auto sp = line.find_first_of(" \t");
        std::string host = sp == std::string::npos ? line : line.substr(sp + 1);
        host.erase(0, host.find_first_not_of(" \t"));
        auto cut = host.find_first_of(" \t/");
        if (cut != std::string::npos) host = host.substr(0, cut);
        if (host == needle || host.size() > needle.size() + 1 &&
                                  host.compare(host.size() - needle.size() - 1, needle.size() + 1, "." + needle) == 0)
            return true;
    }
    return false;
}

} // namespace

void print_threat_feeds(const std::string& name) {
    struct Feed { const char* id; const char* url; };
    Feed feeds[] = {
        {"urlhaus-host", "https://urlhaus.abuse.ch/downloads/hostfile/"},
        {"urlhaus-text", "https://urlhaus.abuse.ch/downloads/text/"}
    };
    std::cout << "WhiteDNS feeds  " << name << "\n";
    std::cout << "pull on demand. match is an observation, not a conviction.\n";
    int hits = 0;
    int fetched = 0;
    for (const auto& f : feeds) {
        std::string body = fetch(f.url);
        if (body.empty()) {
            std::cout << f.id << " fetch=fail\n";
            continue;
        }
        fetched++;
        bool hit = listed(body, name);
        if (hit) hits++;
        std::cout << f.id << " bytes=" << body.size() << " hit=" << (hit ? "yes" : "no") << "\n";
    }
    std::cout << "fetched=" << fetched << " hits=" << hits << "\n";
}

} // namespace core
} // namespace whitedns
