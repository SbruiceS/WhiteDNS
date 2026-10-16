#include "whitedns/core/Monitor.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/CliDraw.h"
#include "whitedns/core/ResolverEngine.h"

#include <ctime>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

namespace whitedns {
namespace core {

namespace {

std::string home() {
    if (const char* h = std::getenv("HOME")) return h;
    return ".";
}

std::string snapshot(const std::string& qname, const std::vector<std::string>& resolvers) {
    ResolverEngine engine;
    std::ostringstream out;
    const uint16_t types[] = {DNS_TYPE_A, DNS_TYPE_NS, DNS_TYPE_MX};
    const char* names[] = {"A", "NS", "MX"};
    for (size_t ti = 0; ti < 3; ++ti) {
        std::map<std::string, std::set<std::string>> by_res;
        for (const auto& res : resolvers) {
            auto o = engine.query(qname, types[ti], res);
            for (const auto& r : o.message.answers) by_res[res].insert(r.value);
        }
        out << names[ti];
        for (const auto& kv : by_res) {
            out << " " << kv.first << "=[";
            bool first = true;
            for (const auto& v : kv.second) {
                if (!first) out << ",";
                out << v;
                first = false;
            }
            out << "]";
        }
        out << "\n";
    }
    return out.str();
}

void respond(const std::string& qname, int sample, const std::string& detail) {
    std::string adir = home() + "/.whitedns/alerts";
    std::system(("mkdir -p \"" + adir + "\"").c_str());
    std::ofstream out(adir + "/" + qname + ".alert");
    auto t = std::time(nullptr);
    out << "time=" << t << " sample=" << sample << "\n" << detail << "\n";
    std::cout << "    response log " << adir << "/" << qname << ".alert\n";
    std::cout << "    action dnssec-path " << qname << "\n";
    std::cout << "    action compare resolvers with -S\n";
    std::cout << "    action check NS and SOA before any change\n";
}

} // namespace

void run_monitor(const std::string& qname, int samples, int interval_s,
                 const std::vector<std::string>& resolvers) {
    if (samples < 1) samples = 1;
    if (samples > 12) samples = 12;
    if (interval_s < 1) interval_s = 1;
    std::vector<std::string> res = resolvers;
    if (res.empty()) res = {"8.8.8.8", "1.1.1.1", "9.9.9.9"};
    draw_banner("WhiteDNS monitor", qname);
    std::cout << "  samples=" << samples << "  interval_s=" << interval_s
              << "  resolvers=" << res.size() << "\n";
    std::string dir = home() + "/.whitedns/monitor";
    std::system(("mkdir -p \"" + dir + "\"").c_str());
    std::string prev;
    int alerts = 0;
    for (int i = 1; i <= samples; ++i) {
        std::string now = snapshot(qname, res);
        std::cout << "  sample " << i << "\n";
        std::istringstream cur(now);
        std::string line;
        std::set<std::string> cur_set, prev_set;
        while (std::getline(cur, line)) if (!line.empty()) cur_set.insert(line);
        std::istringstream olds(prev);
        while (std::getline(olds, line)) if (!line.empty()) prev_set.insert(line);
        if (i == 1) std::cout << "    baseline stored\n";
        else if (cur_set == prev_set) std::cout << "    unchanged\n";
        else {
            alerts++;
            std::cout << "    ALERT change\n";
            std::string detail;
            for (const auto& s : cur_set)
                if (!prev_set.count(s)) { std::cout << "    + " << s << "\n"; detail += "+ " + s + "\n"; }
            for (const auto& s : prev_set)
                if (!cur_set.count(s)) { std::cout << "    - " << s << "\n"; detail += "- " + s + "\n"; }
            respond(qname, i, detail);
        }
        // Cross-resolver disagreement on the same sample is also an alert.
        for (const auto& s : cur_set) {
            if (s.find("A ") == 0 && s.find("] [") != std::string::npos) {
                std::cout << "    note multi-resolver A present\n";
                break;
            }
        }
        std::ofstream out(dir + "/" + qname + ".txt");
        out << now;
        prev = now;
        if (i < samples) std::this_thread::sleep_for(std::chrono::seconds(interval_s));
    }
    draw_rule();
    std::cout << "  alerts=" << alerts << "  store " << dir << "/" << qname << ".txt\n";
    std::cout << "  ALERT is a change or a split across resolvers. response is log and check, not an action on the network.\n";
}

void print_packages() {
    draw_banner("WhiteDNS network packages", "modules already wired");
    const char* rows[][2] = {
        {"transport", "udp tcp doh dot odoh"},
        {"resolve", "lookup records resolve compare trace"},
        {"validate", "dnssec-path intel wire-check"},
        {"detect", "poison detect faults feeds controls"},
        {"intel", "rdap asn ct cname ptr mx"},
        {"observe", "filter latency qctrl axfr stat"},
        {"monitor", "monitor history --diff"},
    };
    for (auto& row : rows)
        std::cout << "  " << row[0] << "  " << row[1] << "\n";
    draw_rule();
}

} // namespace core
} // namespace whitedns
