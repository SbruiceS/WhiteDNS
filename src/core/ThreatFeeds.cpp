#include "whitedns/core/ThreatFeeds.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#define whitedns_popen _popen
#define whitedns_pclose _pclose
#else
#define whitedns_popen popen
#define whitedns_pclose pclose
#endif

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
    FILE* pipe = whitedns_popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::string body;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) {
        body.append(buf);
        if (body.size() > 8000000) break;
    }
    whitedns_pclose(pipe);
    return body;
}

// 0 none, 1 exact, 2 query is under a listed name, 3 a listed name is under the query
int match_kind(const std::string& body, const std::string& name) {
    std::string needle = lower_copy(name);
    std::istringstream in(body);
    std::string line;
    int best = 0;
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
        if (host.empty()) continue;
        if (host == needle) return 1;
        if (needle.size() > host.size() + 1 &&
            needle.compare(needle.size() - host.size() - 1, host.size() + 1, "." + host) == 0)
            best = std::max(best, 2);
        if (host.size() > needle.size() + 1 &&
            host.compare(host.size() - needle.size() - 1, needle.size() + 1, "." + needle) == 0)
            best = std::max(best, 3);
    }
    return best;
}

const char* kind_name(int k) {
    if (k == 1) return "exact";
    if (k == 2) return "parent";
    if (k == 3) return "child";
    return "no";
}

std::string read_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::stringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

} // namespace

void print_threat_feeds(const std::string& name, const std::string& local_urlhaus) {
    std::cout << "WhiteDNS feeds  " << name << "\n";
    std::cout << "match is an observation, not a conviction.\n";
    int hits = 0;
    int fetched = 0;
    if (!local_urlhaus.empty()) {
        std::string body = read_file(local_urlhaus);
        if (body.empty()) {
            std::cout << "urlhaus-local path=" << local_urlhaus << " read=fail\n";
        } else {
            fetched++;
            int kind = match_kind(body, name);
            if (kind) hits++;
            std::cout << "urlhaus-local path=" << local_urlhaus
                      << " bytes=" << body.size()
                      << " hit=" << (kind ? "yes" : "no")
                      << " match=" << kind_name(kind) << "\n";
        }
        std::cout << "fetched=" << fetched << " hits=" << hits << "\n";
        return;
    }
    struct Feed { const char* id; const char* url; };
    Feed feeds[] = {
        {"urlhaus-host", "https://urlhaus.abuse.ch/downloads/hostfile/"},
        {"urlhaus-text", "https://urlhaus.abuse.ch/downloads/text/"}
    };
    std::cout << "source=remote\n";
    for (const auto& f : feeds) {
        std::string body = fetch(f.url);
        if (body.empty()) {
            std::cout << f.id << " fetch=fail\n";
            continue;
        }
        fetched++;
        int kind = match_kind(body, name);
        if (kind) hits++;
        std::cout << f.id << " bytes=" << body.size()
                  << " hit=" << (kind ? "yes" : "no")
                  << " match=" << kind_name(kind) << "\n";
    }
    std::cout << "fetched=" << fetched << " hits=" << hits << "\n";
}

int feed_match(const std::string& name, const std::string& local_urlhaus) {
    if (local_urlhaus.empty()) return 0;
    std::string body = read_file(local_urlhaus);
    if (body.empty()) return -1;
    return match_kind(body, name);
}

} // namespace core
} // namespace whitedns
