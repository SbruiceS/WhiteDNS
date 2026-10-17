#include "whitedns/Analyzer.h"
#include "whitedns/Dnssec.h"
#include "whitedns/IanaDns.h"
#include "whitedns/FrameworkAudit.h"
#include "whitedns/HttpScanner.h"
#include "whitedns/PortScanner.h"
#include "whitedns/SubdomainScanner.h"
#include "whitedns/SubdomainDsl.h"
#include "whitedns/core/ResolverEngine.h"
#include "whitedns/core/Odoh.h"
#include "whitedns/core/OdohFilter.h"
#include "whitedns/core/OdohPolicy.h"
#include "whitedns/core/OdohLeakModels.h"
#include "whitedns/core/ResolverIntel.h"
#include "whitedns/core/DnssecPath.h"
#include "whitedns/core/PoisonClassifier.h"
#include "whitedns/core/ThreatEngine.h"
#include "whitedns/core/FaultReport.h"
#include "whitedns/core/VendorControls.h"
#include "whitedns/core/Intelligence.h"
#include "whitedns/core/TrafficPack.h"
#include "whitedns/core/DeepPack.h"
#include "whitedns/core/ThreatFeeds.h"
#include "whitedns/core/ScaleIntel.h"
#include "whitedns/core/DohClient.h"
#include "whitedns/core/DnsMath.h"
#include "whitedns/core/ChainTools.h"
#include "whitedns/core/Enrich.h"
#include "whitedns/core/StatDetect.h"
#include "whitedns/core/AxfrStream.h"
#include "whitedns/core/FilterEngine.h"
#include "whitedns/core/CliDraw.h"
#include "whitedns/core/ProTools.h"
#include "whitedns/core/QueryControl.h"
#include "whitedns/core/Monitor.h"
#include "whitedns/core/GraphIntel.h"
#include "whitedns/core/Topology.h"
#include "whitedns/core/ProtocolEngine.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

using namespace whitedns;

namespace {

enum class Command {
    Dns,
    Web,
    Enum,
    Firewall,
    Enterprise,
    Audit,
    Lookup,
    Records,
    Resolve,
    Trace,
    Compare,
    DnssecCmd,
    Odoh,
    OdohFilter,
    OdohPolicy,
    OdohLeak,
    Baseline,
    Intel,
    DnssecPath,
    Poison,
    Threats,
    Detect,
    Explain,
    Research,
    Faults,
    Controls,
    Arch,
    Graph,
    Security,
    Doctor,
    Report,
    Dga,
    WireCheck,
    Assess,
    Summary,
    Traffic,
    TrafficProto,
    TrafficRoute,
    TrafficFlow,
    TrafficFault,
    Deep,
    Feeds,
    Scale,
    Ct,
    Cname,
    Dot,
    Rdap,
    Asn,
    Pcap,
    Stat,
    Axfr,
    Filter,
    Ptr,
    Mx,
    Latency,
    Qctrl,
    Monitor,
    Packages,
    GraphIntel,
    TopologyCmd,
    Unknown
};

struct Options {
    Command command = Command::Dns;
    std::vector<uint16_t> query_types = {DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_NS, DNS_TYPE_TXT};
    std::string domain;
    std::string dns_server;
    std::vector<std::string> dns_servers_multi;
    bool check_open_resolver = false;
    bool dnssec_readiness = false;
    bool check_nxdomain_redirect = false;
    bool test_amplification = false;
    bool check_wildcard_dns = false;
    bool detect_cache_poisoning = false;
    bool detect_dns_tunneling = false;
    bool proxy_detection = false;
    bool fast_flux_detection = false;
    bool dns_rebinding_detection = false;
    bool output_json = false;
    bool check_zone_transfer = false;
    bool dns_spoofing_detection = false;
    bool dns_hijacking_detection = false;
    bool check_spf_dmarc = false;
    bool check_caa_policy = false;
    bool scan_subdomains = false;
    bool brute_subdomains = false;
    bool recursive_subdomains = false;
    bool g4_generate = false;
    bool permute_generate = false;
    int enum_depth = 2;
    int threads = 0;
    int timeout_ms = 0;
    std::string dsl_pattern;
    bool scan_web = false;
    bool discover_web_assets = false;
    bool http_header_scan = false;
    bool probe_https_port = false;
    bool enterprise_profile = false;
    bool verbose = false;
    bool quiet = false;
    std::string format = "human";
    std::string color_mode = "auto";
    std::string fail_on = "exposed";
    std::string workpaper_path;
    std::string scope;
    std::string odoh_proxy;
    std::string odoh_target = "odoh.cloudflare-dns.com";
    std::string urlhaus_file;
    std::string domains_file;
    std::string vantage;
    std::string config_path;
    std::string diff_path;
    bool multi_vantage = false;
    std::string arg2;
    std::vector<std::string> urls;
    std::vector<std::string> subdomain_candidates;
    std::vector<std::string> port_scan_targets;
    std::vector<int> port_scan_ports;
};

std::vector<std::string> split(const std::string& value, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream stream(value);
    while (std::getline(stream, token, delimiter)) {
        if (!token.empty()) tokens.push_back(token);
    }
    return tokens;
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

const char* RESET = "\x1b[0m";
const char* BOLD = "\x1b[1m";
const char* RED = "\x1b[31m";
const char* GREEN = "\x1b[32m";
const char* YELLOW = "\x1b[33m";
const char* BLUE = "\x1b[34m";
const char* MAGENTA = "\x1b[35m";
const char* CYAN = "\x1b[36m";
const char* DIM = "\x1b[2m";
const char* WHITE = "\x1b[97m";

std::string style(const std::string& text, const char* code) {
    return std::string(code) + text + RESET;
}

std::string header_label(const std::string& text) {
    return style(text, BOLD);
}

std::string section_title(const std::string& text) {
    return style(text, BLUE);
}

std::string status_color(const std::string& status) {
    if (status == "pass" || status == "ok") return style(status, GREEN);
    if (status == "warning") return style(status, YELLOW);
    if (status == "error" || status == "fail") return style(status, RED);
    return style(status, CYAN);
}

bool has_query_type(const Options& opt, uint16_t type) {
    return std::find(opt.query_types.begin(), opt.query_types.end(), type) != opt.query_types.end();
}

void add_query_type(Options& opt, uint16_t type) {
    if (!has_query_type(opt, type)) {
        opt.query_types.push_back(type);
    }
}

std::vector<std::string> default_asset_paths() {
    return {
        "robots.txt", "sitemap.xml", "favicon.ico", "admin", "login", "dashboard",
        "api", "api/v1", ".env", "wp-login.php", "wp-admin", ".git", ".well-known/security.txt",
        "security.txt", "server-status", "config.php", "uploads", "backup.zip", ".htaccess"
    };
}

std::vector<std::string> default_web_urls(const std::string& domain) {
    return {"http://" + domain, "https://" + domain};
}

bool load_subdomain_candidates(const std::string& value, std::vector<std::string>& candidates) {
    std::ifstream file(value);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty() && line[0] != '#') {
                candidates.push_back(line);
            }
        }
        return !candidates.empty();
    }
    // A path that did not open is not a prefix. Report missing, do not query it.
    if (value.find('/') != std::string::npos || value.size() > 4 && value.substr(value.size() - 4) == ".txt") {
        std::cerr << "wordlist not found: " << value << "\n";
        return false;
    }
    candidates = split(value, ',');
    return !candidates.empty();
}

Command parse_command(const std::string& command) {
    std::string normalized = lowercase(command);
    if (normalized == "dns") return Command::Dns;
    if (normalized == "web") return Command::Web;
    if (normalized == "enum") return Command::Enum;
    if (normalized == "firewall") return Command::Firewall;
    if (normalized == "enterprise") return Command::Enterprise;
    if (normalized == "audit") return Command::Audit;
    if (normalized == "lookup") return Command::Lookup;
    if (normalized == "records") return Command::Records;
    if (normalized == "resolve") return Command::Resolve;
    if (normalized == "trace") return Command::Trace;
    if (normalized == "compare") return Command::Compare;
    if (normalized == "dnssec") return Command::DnssecCmd;
    if (normalized == "odoh") return Command::Odoh;
    if (normalized == "odoh-filter" || normalized == "odohfilter") return Command::OdohFilter;
    if (normalized == "odoh-policy" || normalized == "odohpolicy") return Command::OdohPolicy;
    if (normalized == "odoh-leak" || normalized == "odohleak" || normalized == "odoh-models")
        return Command::OdohLeak;
    if (normalized == "baseline") return Command::Baseline;
    if (normalized == "intel" || normalized == "resolver" || normalized == "resolver-intel")
        return Command::Intel;
    if (normalized == "dnssec-path" || normalized == "dnssecpath") return Command::DnssecPath;
    if (normalized == "poison" || normalized == "poison-check") return Command::Poison;
    if (normalized == "threats") return Command::Threats;
    if (normalized == "detect") return Command::Detect;
    if (normalized == "explain") return Command::Explain;
    if (normalized == "research") return Command::Research;
    if (normalized == "faults" || normalized == "fault" || normalized == "issues")
        return Command::Faults;
    if (normalized == "controls" || normalized == "vendor" || normalized == "vendor-audit")
        return Command::Controls;
    if (normalized == "graph") return Command::Graph;
    if (normalized == "security") return Command::Security;
    if (normalized == "doctor") return Command::Doctor;
    if (normalized == "report" || normalized == "history") return Command::Report;
    if (normalized == "dga") return Command::Dga;
    if (normalized == "wire-check" || normalized == "protocol") return Command::WireCheck;
    if (normalized == "assess" || normalized == "assessment") return Command::Assess;
    if (normalized == "summary" || normalized == "card") return Command::Summary;
    if (normalized == "traffic" || normalized == "dns-traffic" || normalized == "flow" || normalized == "attack-traffic") return Command::Traffic;
    if (normalized == "traffic-proto") return Command::TrafficProto;
    if (normalized == "traffic-route") return Command::TrafficRoute;
    if (normalized == "traffic-flow") return Command::TrafficFlow;
    if (normalized == "traffic-fault") return Command::TrafficFault;
    if (normalized == "deep") return Command::Deep;
    if (normalized == "feeds" || normalized == "intel-feed") return Command::Feeds;
    if (normalized == "scale" || normalized == "intel-scale") return Command::Scale;
    if (normalized == "ct" || normalized == "certs") return Command::Ct;
    if (normalized == "cname" || normalized == "cname-chain") return Command::Cname;
    if (normalized == "dot") return Command::Dot;
    if (normalized == "rdap" || normalized == "whois") return Command::Rdap;
    if (normalized == "asn") return Command::Asn;
    if (normalized == "pcap" || normalized == "capture") return Command::Pcap;
    if (normalized == "stat" || normalized == "math") return Command::Stat;
    if (normalized == "axfr" || normalized == "zone") return Command::Axfr;
    if (normalized == "filter" || normalized == "search") return Command::Filter;
    if (normalized == "ptr") return Command::Ptr;
    if (normalized == "mx") return Command::Mx;
    if (normalized == "latency" || normalized == "rtt") return Command::Latency;
    if (normalized == "qctrl" || normalized == "control") return Command::Qctrl;
    if (normalized == "monitor" || normalized == "watch") return Command::Monitor;
    if (normalized == "packages" || normalized == "mods") return Command::Packages;
    if (normalized == "graphintel" || normalized == "gintel") return Command::GraphIntel;
    if (normalized == "topology" || normalized == "topo") return Command::TopologyCmd;
    if (normalized == "rules") return Command::Threats;
    return Command::Unknown;
}

const char* platform_name() {
#if defined(__ANDROID__)
    return "Android/Termux";
#elif defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#else
    return "Unknown";
#endif
}

bool stdout_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

void enable_windows_vt() {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (!GetConsoleMode(handle, &mode)) return;
    SetConsoleMode(handle, mode | 0x0004);
#endif
}

void print_architecture() {
    core::draw_banner("WhiteDNS  ·  security intelligence", "Cosinfotech Solutions  ·  S. Bruice Singh");
    std::cout << style("  TARGET → SCOPE → PLAN → TRANSPORT → RESOLVE → PARSE", MAGENTA) << "\n";
    std::cout << style("         → CORRELATE → ANALYZE → EVIDENCE → FINDING → REPORT", MAGENTA) << "\n";
    core::draw_rule();
    std::cout << style("  posture  ", BOLD) << style("ok", GREEN) << "  " << style("warning", YELLOW)
              << "  " << style("degraded", YELLOW) << "  " << style("exposed", RED) << "\n";
    std::cout << style("  exit     ", BOLD) << "0 ok   1 usage   2 degraded   3 exposed   4 warning\n";
    auto row = [](const char* cmd, const char* layer, const char* note, const char* color) {
        std::string name(cmd);
        std::string pad(name.size() >= 16 ? 1 : 16 - name.size(), ' ');
        std::cout << "  " << style(cmd, color) << pad << style(layer, YELLOW) << "  " << style(note, DIM) << "\n";
    };
    auto panel = [](const char* title, const char* color) {
        std::cout << "\n" << style(std::string("┌ ") + title, color) << "\n";
    };
    panel("collect", CYAN);
    row("lookup", "wire", "one resolver", CYAN);
    row("records", "wire", "inventory alias", CYAN);
    row("resolve", "compare", "multi-resolver", CYAN);
    row("trace", "delegation", "iterative NS walk", CYAN);
    row("baseline", "cache", "TTL and RTT", CYAN);
    row("enum", "wordlist", "-e -b -r depth", CYAN);
    row("ct", "crt.sh", "certificate names", CYAN);
    row("cname", "chain", "CNAME to A", CYAN);
    row("rdap", "registry", "domain record", CYAN);
    row("asn", "cymru", "ASN per A", CYAN);
    panel("privacy", BLUE);
    row("odoh", "RFC 9230", "HPKE plus relay", BLUE);
    row("odoh-leak", "M01-M27", "what each party sees", BLUE);
    row("odoh-filter", "policy", "allow or block", BLUE);
    row("odoh-policy", "enterprise", "legal path", BLUE);
    row("dot", "RFC 7858", "TLS port 853", BLUE);
    panel("validation", GREEN);
    row("dnssec-path", "path", "DS DNSKEY RRSIG A NS MX", GREEN);
    row("intel", "RFC/SANS", "SOA MX SPF CAA", GREEN);
    row("wire-check", "parser", "bounds self-test", GREEN);
    panel("detection", RED);
    row("poison", "3-gate", "DNSSEC and disjoint and AA", RED);
    row("detect", "rules", "taxonomy on observations", RED);
    row("faults", "rollup", "findings only", RED);
    row("feeds", "urlhaus+", "local and remote lists", RED);
    row("controls", "vendor", "defensive checks", RED);
    row("scale", "S01-S30", "fusion graph poison", MAGENTA);
    row("deep", "H01-H50", "label TTL EDNS fusion", MAGENTA);
    panel("traffic", YELLOW);
    row("traffic", "T01-T90", "observe pack, alias flow", YELLOW);
    row("traffic-proto", "protocol", "wire faults", YELLOW);
    row("traffic-route", "graph", "path hub components", YELLOW);
    row("traffic-flow", "flow", "data flow", YELLOW);
    row("traffic-fault", "fault", "protocol faults", YELLOW);
    row("pcap", "capture", "DNS/53 count", YELLOW);
    row("stat", "SPRT", "z Poisson Bayes", YELLOW);
    row("axfr", "stream", "HLL sketch, no dump", YELLOW);
    row("filter", "rank", "agreement score, cap", YELLOW);
    row("ptr", "reverse", "A to PTR", CYAN);
    row("mx", "mail", "TTL bars", CYAN);
    row("latency", "rtt", "resolver bars", CYAN);
    row("qctrl", "PI", "DoH rate control", BLUE);
    row("monitor", "watch", "sample and diff", CYAN);
    row("packages", "modules", "network package list", CYAN);
    row("assess", "authorized", "dnssec poison faults", GREEN);
    row("summary", "card", "fused A and agreement", CYAN);
    panel("ops", MAGENTA);
    row("audit", "frameworks", "JSON, --fail-on", RED);
    row("firewall", "posture", "open resolver amp", RED);
    row("enterprise", "profile", "full scan", RED);
    row("web", "http", "headers and assets", MAGENTA);
    row("graph", "edges", "ASN RDAP attached", MAGENTA);
    row("security", "reason", "poison gates", MAGENTA);
    row("report", "fused", "security plus graph", MAGENTA);
    row("dga", "lexical", "entropy gate", MAGENTA);
    row("doctor", "self", "no network", YELLOW);
    std::cout << "\n" << style("  confirmation", BOLD)
              << "  poison only if DNSSEC contradiction, disjoint resolvers, and AA disagree\n";
}

void print_usage() {
    print_architecture();
    std::cout << "\n" << header_label("Usage") << "\n";
    std::cout << "  " << style("whitedns <command> [options] <name>", GREEN) << "\n";
    std::cout << "  " << style("whitedns audit --format json --fail-on degraded <name>", GREEN) << "\n\n";
    std::cout << header_label("Also") << "\n";
    std::cout << "  dns web enum firewall enterprise odoh-filter odoh-policy\n";
    std::cout << "  threats explain research controls graph security report dga\n";
    std::cout << "  traffic-proto traffic-flow traffic-fault\n\n";
    std::cout << header_label("Output") << "\n";
    std::cout << "  -j --format json    --color auto|always|never    --fail-on warning|degraded|exposed|never\n";
    std::cout << "  -e --subdomains     enum. -b brute. -r recursive. --depth 1..5\n";
    std::cout << "  --config <file>     whitedns.yaml. --fail-on high|medium|low. --diff <prev.json>\n";
    std::cout << "  --vantages          query 8.8.8.8 1.1.1.1 9.9.9.9 208.67.222.222. -s https:// is DoH\n";
    std::cout << "  -s <server>  -S <servers>  -t <types>  --workpaper <file>\n\n";
    std::cout << "Linux | Windows | macOS | Termux    Cosinfotech Solutions    S. Bruice Singh\n";
}

void print_version() {
    std::cout << "WhiteDNS 2.0.0 (" << platform_name() << ")\n";
    std::cout << "DNS security, forensics and reconnaissance platform\n";
    std::cout << "Developer: Cosinfotech Solutions\n";
    std::cout << "Author: S. Bruice Singh\n";
}

bool parse_options(int argc, char* argv[], Options& opt) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help" || arg == "help") {
            print_usage();
            std::exit(0);
        }
        if (arg == "--version" || arg == "-V") {
            print_version();
            std::exit(0);
        }

        if (opt.command == Command::Dns && opt.domain.empty() && arg.front() != '-') {
            Command parsed_command = parse_command(arg);
            if (parsed_command != Command::Unknown) {
                opt.command = parsed_command;
                continue;
            }
        }

        if (arg == "-v") {
            opt.verbose = true;
        } else if (arg == "-q" || arg == "--quiet") {
            opt.quiet = true;
        } else if (arg == "--format") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --format\n";
                return false;
            }
            opt.format = lowercase(argv[++i]);
            if (opt.format == "json") opt.output_json = true;
        } else if (arg == "--color") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --color\n";
                return false;
            }
            opt.color_mode = lowercase(argv[++i]);
        } else if (arg == "--fail-on") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --fail-on\n";
                return false;
            }
            opt.fail_on = lowercase(argv[++i]);
        } else if (arg == "--scope") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --scope\n";
                return false;
            }
            opt.scope = argv[++i];
        } else if (arg == "--proxy") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --proxy\n";
                return false;
            }
            opt.odoh_proxy = argv[++i];
        } else if (arg == "--target") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --target\n";
                return false;
            }
            opt.odoh_target = argv[++i];
        } else if (arg == "--workpaper") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --workpaper\n";
                return false;
            }
            opt.workpaper_path = argv[++i];
        } else if (arg == "-o") {
            opt.check_open_resolver = true;
        } else if (arg == "-r") {
            opt.dnssec_readiness = true;
            add_query_type(opt, DNS_TYPE_DNSKEY);
            add_query_type(opt, DNS_TYPE_RRSIG);
        } else if (arg == "-n") {
            opt.check_nxdomain_redirect = true;
        } else if (arg == "-a") {
            opt.test_amplification = true;
        } else if (arg == "-w") {
            opt.check_wildcard_dns = true;
        } else if (arg == "-c") {
            opt.detect_cache_poisoning = true;
        } else if (arg == "-x") {
            opt.detect_dns_tunneling = true;
        } else if (arg == "-p") {
            opt.proxy_detection = true;
            opt.probe_https_port = true;
        } else if (arg == "--rebinding") {
            opt.dns_rebinding_detection = true;
        } else if (arg == "-f") {
            opt.fast_flux_detection = true;
            add_query_type(opt, DNS_TYPE_A);
        } else if (arg == "--brute" || arg == "-b") {
            opt.scan_subdomains = true;
            opt.brute_subdomains = true;
        } else if (arg == "-j") {
            opt.output_json = true;
        } else if (arg == "-z") {
            opt.check_zone_transfer = true;
        } else if (arg == "-A") {
            opt.dns_spoofing_detection = true;
            add_query_type(opt, DNS_TYPE_A);
        } else if (arg == "-H") {
            opt.dns_hijacking_detection = true;
            add_query_type(opt, DNS_TYPE_NS);
            add_query_type(opt, DNS_TYPE_MX);
            add_query_type(opt, DNS_TYPE_SOA);
        } else if (arg == "--spf-dmarc") {
            opt.check_spf_dmarc = true;
        } else if (arg == "--caa") {
            opt.check_caa_policy = true;
            add_query_type(opt, DNS_TYPE_CAA);
        } else if (arg == "--subdomains" || arg == "-e") {
            opt.scan_subdomains = true;
        } else if (arg == "--recursive" || arg == "-r") {
            opt.scan_subdomains = true;
            opt.recursive_subdomains = true;
        } else if (arg == "--depth") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --depth\n";
                return false;
            }
            opt.enum_depth = std::stoi(argv[++i]);
            if (opt.enum_depth < 1) opt.enum_depth = 1;
            if (opt.enum_depth > 5) opt.enum_depth = 5;
            opt.scan_subdomains = true;
            opt.recursive_subdomains = true;
        } else if (arg == "--dsl") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --dsl\n";
                return false;
            }
            opt.dsl_pattern = argv[++i];
            opt.scan_subdomains = true;
        } else if (arg == "--g4") {
            opt.g4_generate = true;
            opt.scan_subdomains = true;
        } else if (arg == "--permute") {
            opt.permute_generate = true;
            opt.scan_subdomains = true;
        } else if (arg == "--urlhaus" || arg == "--feed") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after " << arg << "\n";
                return false;
            }
            opt.urlhaus_file = argv[++i];
        } else if (arg == "--domains") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --domains\n";
                return false;
            }
            opt.domains_file = argv[++i];
        } else if (arg == "--vantage") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --vantage\n";
                return false;
            }
            opt.vantage = argv[++i];
            opt.dns_server = opt.vantage;
        } else if (arg == "--threads") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --threads\n";
                return false;
            }
            opt.threads = std::stoi(argv[++i]);
            if (opt.threads < 1) opt.threads = 1;
            if (opt.threads > 64) opt.threads = 64;
        } else if (arg == "--timeout") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --timeout\n";
                return false;
            }
            opt.timeout_ms = std::stoi(argv[++i]);
            if (opt.timeout_ms < 100) opt.timeout_ms = 100;
            if (opt.timeout_ms > 30000) opt.timeout_ms = 30000;
        } else if (arg == "--config") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --config\n";
                return false;
            }
            opt.config_path = argv[++i];
        } else if (arg == "--diff") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --diff\n";
                return false;
            }
            opt.diff_path = argv[++i];
        } else if (arg == "--vantages") {
            opt.multi_vantage = true;
        } else if (arg == "--assets") {
            opt.discover_web_assets = true;
        } else if (arg == "--http-headers") {
            opt.http_header_scan = true;
        } else if (arg == "--https-probe") {
            opt.probe_https_port = true;
        } else if (arg == "--profile") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after --profile\n";
                return false;
            }
            std::string value = argv[++i];
            if (lowercase(value) == "enterprise") {
                opt.enterprise_profile = true;
                opt.command = Command::Enterprise;
            } else if (lowercase(value) == "firewall") {
                opt.command = Command::Firewall;
            }
        } else if (arg == "-s" || arg == "-S" || arg == "-t" || arg == "-P" || arg == "-R" || arg == "-U" || arg == "-D") {
            if (i + 1 >= argc) {
                std::cerr << "Require argument after " << arg << "\n";
                return false;
            }
            std::string value = argv[++i];
            if (arg == "-s") {
                opt.dns_server = value;
            } else if (arg == "-S") {
                opt.dns_servers_multi = split(value, ',');
            } else if (arg == "-t") {
                opt.query_types.clear();
                for (const auto& type_name : split(value, ',')) {
                    int type = dns_type_from_string(type_name);
                    if (type < 0) {
                        std::cerr << "Unknown DNS record type: " << type_name << "\n";
                        return false;
                    }
                    opt.query_types.push_back(static_cast<uint16_t>(type));
                }
            } else if (arg == "-P") {
                opt.port_scan_targets = split(value, ',');
            } else if (arg == "-R") {
                for (const auto& port_text : split(value, ',')) {
                    try {
                        int port = std::stoi(port_text);
                        if (port <= 0 || port > 65535) throw std::out_of_range("port");
                        opt.port_scan_ports.push_back(port);
                    } catch (...) {
                        std::cerr << "Invalid port number: " << port_text << "\n";
                        return false;
                    }
                }
            } else if (arg == "-U") {
                opt.urls = split(value, ',');
            } else if (arg == "-D") {
                if (!load_subdomain_candidates(value, opt.subdomain_candidates)) {
                    std::cerr << "Cannot load subdomain candidates: " << value << "\n";
                    return false;
                }
                opt.scan_subdomains = true;
            }
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage();
            return false;
        } else if (opt.domain.empty()) {
            opt.domain = arg;
        } else if (opt.arg2.empty()) {
            opt.arg2 = arg;
        } else {
            opt.urls.push_back(arg);
        }
    }

    return true;
}

void load_config(Options& opt) {
    std::string path = opt.config_path;
    if (path.empty()) {
        if (std::ifstream("whitedns.yaml").good()) path = "whitedns.yaml";
        else return;
    }
    std::ifstream in(path);
    if (!in) {
        std::cerr << "config/read-fail " << path << "\n";
        return;
    }
    std::string line;
    while (std::getline(in, line)) {
        auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = lowercase(line.substr(0, colon));
        std::string val = line.substr(colon + 1);
        auto a = val.find_first_not_of(" \t");
        if (a == std::string::npos) continue;
        val = val.substr(a);
        if (!val.empty() && val.front() == '"' && val.back() == '"') val = val.substr(1, val.size() - 2);
        if (key == "resolvers" && opt.dns_servers_multi.empty() && opt.dns_server.empty())
            opt.dns_servers_multi = split(val, ',');
        else if (key == "types" && opt.query_types.size() == 5) {
            opt.query_types.clear();
            for (const auto& t : split(val, ',')) {
                int type = dns_type_from_string(t);
                if (type >= 0) opt.query_types.push_back(static_cast<uint16_t>(type));
            }
        } else if ((key == "feed" || key == "urlhaus") && opt.urlhaus_file.empty())
            opt.urlhaus_file = val;
        else if (key == "fail_on" && opt.fail_on == "exposed")
            opt.fail_on = lowercase(val);
        else if (key == "threads" && opt.threads == 0)
            opt.threads = std::stoi(val);
        else if (key == "timeout" && opt.timeout_ms == 0)
            opt.timeout_ms = std::stoi(val);
        else if (key == "vantage" && opt.vantage.empty()) {
            opt.vantage = val;
            opt.dns_server = val;
        }
    }
    if (!opt.config_path.empty()) std::cout << "config " << path << "\n";
}

int severity_rank(const std::string& status) {
    if (status == "fail" || status == "error" || status == "exposed") return 3;
    if (status == "warning" || status == "degraded") return 2;
    if (status == "info" || status == "low") return 1;
    return 0;
}

int fail_rank(const std::string& gate) {
    if (gate == "high" || gate == "fail" || gate == "error" || gate == "exposed") return 3;
    if (gate == "medium" || gate == "warning" || gate == "degraded") return 2;
    if (gate == "low" || gate == "info") return 1;
    return 99;
}

void write_sarif(const std::string& path, const Json::Value& report) {
    std::ofstream out(path);
    if (!out) { std::cerr << "Cannot write " << path << "\n"; return; }
    out << "{\n  \"version\": \"2.1.0\",\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n";
    out << "  \"runs\": [{\n    \"tool\": {\"driver\": {\"name\": \"WhiteDNS\", \"version\": \"2.0.0\"}},\n    \"results\": [\n";
    const auto& checks = report["checks"];
    bool first = true;
    for (unsigned i = 0; i < checks.size(); ++i) {
        std::string status = checks[i]["status"].asString();
        if (status == "pass" || status == "ok") continue;
        std::string level = (status == "fail" || status == "error") ? "error" : "warning";
        if (!first) out << ",\n";
        first = false;
        out << "      {\"ruleId\": \"" << checks[i]["name"].asString()
            << "\", \"level\": \"" << level
            << "\", \"message\": {\"text\": \"" << checks[i]["message"].asString() << "\"}}";
    }
    out << "\n    ]\n  }]\n}\n";
}

void write_html(const std::string& path, const Json::Value& report) {
    std::ofstream out(path);
    if (!out) { std::cerr << "Cannot write " << path << "\n"; return; }
    out << "<!doctype html><meta charset=utf-8><title>WhiteDNS " << report["domain"].asString()
        << "</title><style>body{font-family:sans-serif} .fail{color:#b00} .warning{color:#a60}</style>\n";
    out << "<h1>WhiteDNS " << report["domain"].asString() << "</h1>\n<ul>\n";
    const auto& checks = report["checks"];
    for (unsigned i = 0; i < checks.size(); ++i) {
        std::string status = checks[i]["status"].asString();
        out << "<li class=" << status << "><b>" << checks[i]["name"].asString()
            << "</b> " << status << " — " << checks[i]["message"].asString() << "</li>\n";
    }
    out << "</ul>\n";
}

void print_diff(const std::string& path, const Json::Value& current) {
    std::ifstream in(path);
    if (!in) {
        std::cout << "diff previous=missing\n";
    } else {
        std::stringstream buf;
        buf << in.rdbuf();
        std::string prev = buf.str();
        std::cout << "diff against " << path << "\n";
        int news = 0, changed = 0;
        const auto& cur_checks = current["checks"];
        for (unsigned i = 0; i < cur_checks.size(); ++i) {
            const auto& c = cur_checks[i];
            std::string id = c["name"].asString();
            if (id.empty()) id = c["title"].asString();
            std::string status = c["status"].asString();
            std::string message = c["message"].asString();
            if (id.empty()) continue;
            auto at = prev.find(id);
            if (at == std::string::npos) {
                std::cout << "  new " << id << " status=" << status << "\n";
                news++;
                continue;
            }
            auto window = prev.substr(at, 400);
            if (window.find(status) == std::string::npos) {
                std::cout << "  changed " << id << " now=" << status << " message=" << message << "\n";
                changed++;
            }
        }
        std::cout << "diff new=" << news << " changed=" << changed << "\n";
    }
    // Field-level diff if a previous fields file exists.
    std::string fpath = core::last_fields(current["domain"].asString());
    std::ifstream fin(fpath);
    if (!fin) {
        std::cout << "fields previous=missing\n";
        return;
    }
    std::set<std::string> prev_f, cur_f;
    std::string line;
    while (std::getline(fin, line)) if (!line.empty()) prev_f.insert(line);
    // Build current fields from queries if present.
    const auto& qs = current["queries"];
    for (unsigned i = 0; i < qs.size(); ++i) {
        std::string t = qs[i]["type"].asString();
        const auto& ans = qs[i]["answers"];
        for (unsigned j = 0; j < ans.size(); ++j)
            cur_f.insert(t + " " + ans[j].asString());
    }
    std::cout << "fields against " << fpath << "\n";
    int added = 0, removed = 0;
    for (const auto& s : cur_f) if (!prev_f.count(s)) { std::cout << "  + " << s << "\n"; added++; }
    for (const auto& s : prev_f) if (!cur_f.count(s)) { std::cout << "  - " << s << "\n"; removed++; }
    if (added == 0 && removed == 0) std::cout << "  fields unchanged\n";
    std::cout << "fields +=" << added << " -=" << removed << "\n";
}

std::vector<std::string> servers_to_use(const Options& opt) {
    if (!opt.dns_servers_multi.empty()) return opt.dns_servers_multi;
    if (!opt.dns_server.empty()) return {opt.dns_server};
    return {"8.8.8.8"};
}

std::vector<DnsResponse> run_queries(const Options& opt, const std::vector<std::string>& servers) {
    std::vector<DnsResponse> responses(servers.size() * opt.query_types.size());
    std::vector<std::thread> threads;
    DnsClient client;

    size_t index = 0;
    for (const auto& server : servers) {
        for (uint16_t query_type : opt.query_types) {
            size_t result_index = index++;
            threads.emplace_back([&, server, query_type, result_index]() {
                responses[result_index] = client.query(opt.domain, server, query_type, opt.dnssec_readiness);
            });
        }
    }

    for (auto& thread : threads) {
        if (thread.joinable()) thread.join();
    }
    return responses;
}

std::vector<CheckResult> run_checks(const Options& opt, const std::vector<std::string>& servers, const std::vector<DnsResponse>& responses) {
    DnsClient client;
    std::vector<CheckResult> checks;
    std::string primary_server = servers.empty() ? "8.8.8.8" : servers.front();

    if (opt.proxy_detection) checks.push_back(check_proxy_dns(primary_server));
    if (opt.check_open_resolver) checks.push_back(check_open_resolver(client, primary_server));
    if (opt.check_nxdomain_redirect) checks.push_back(check_nxdomain_redirect(client, primary_server, opt.domain));
    if (opt.test_amplification) checks.push_back(check_amplification(client, primary_server));
    if (opt.check_wildcard_dns) checks.push_back(check_wildcard_dns(client, primary_server, opt.domain));
    if (opt.dnssec_readiness) checks.push_back(check_dnssec_readiness(client, primary_server, opt.domain));
    if (opt.check_spf_dmarc) checks.push_back(check_spf_dmarc(client, primary_server, opt.domain));
    if (opt.check_caa_policy) checks.push_back(check_caa_policy(client, primary_server, opt.domain));
    if (opt.dns_rebinding_detection) checks.push_back(check_dns_rebinding(client, primary_server, opt.domain));
    if (opt.check_zone_transfer) checks.push_back(check_zone_transfer(client, primary_server, opt.domain));
    if (opt.detect_dns_tunneling) checks.push_back(check_dns_tunneling(client, primary_server, opt.domain));
    if (opt.detect_cache_poisoning) checks.push_back(check_cache_poisoning(responses));
    if (opt.dns_spoofing_detection) checks.push_back(check_dns_spoofing(responses));
    if (opt.fast_flux_detection) checks.push_back(check_fast_flux(responses));
    if (opt.dns_hijacking_detection) checks.push_back(check_dns_hijacking(responses));

    return checks;
}

Json::Value build_json_report(const Options& opt,
                              const std::vector<DnsResponse>& responses,
                              const std::vector<CheckResult>& checks,
                              const Json::Value& subdomains,
                              const Json::Value& web,
                              const Json::Value& port_scan,
                              const Json::Value& firewall) {
    Json::Value root(Json::objectValue);
    root["tool"] = "WhiteDNS";
    root["schema_version"] = 2;
    root["domain"] = opt.domain;
    root["command"] = opt.command == Command::Dns ? "dns" : opt.command == Command::Web ? "web" : opt.command == Command::Enum ? "enum" : opt.command == Command::Firewall ? "firewall" : opt.command == Command::Audit ? "audit" : "enterprise";

    Json::Value query_array(Json::arrayValue);
    for (const auto& response : responses) query_array.append(dns_response_to_json(response));
    root["queries"] = query_array;

    Json::Value check_array(Json::arrayValue);
    for (const auto& check : checks) check_array.append(check_result_to_json(check));
    root["checks"] = check_array;
    root["subdomains"] = subdomains;
    root["web"] = web;
    root["port_scan"] = port_scan;
    root["firewall"] = firewall;
    return root;
}

void print_human_report(const Options& opt,
                        const std::vector<DnsResponse>& responses,
                        const std::vector<CheckResult>& checks,
                        const std::vector<SubdomainResult>& subdomains,
                        const std::vector<HttpProbeResult>& probes,
                        const std::vector<WebAssetResult>& assets,
                        const std::vector<ScanResult>& scan_results,
                        const Json::Value& firewall) {
    std::cout << style("WhiteDNS Security Audit", BOLD) << "  " << style("by SBruice Singh", MAGENTA) << "\n";
    std::cout << style("------------------------------------------------------------", CYAN) << "\n";
    if (!opt.domain.empty()) std::cout << section_title("Target:") << " " << opt.domain << "\n";

    if (!responses.empty()) {
        for (const auto& response : responses) {
            std::cout << "\n[" << response.server << "] " << response.query_type_name << "\n";
            if (response.error) {
                std::cout << "  Error: " << response.error_message << "\n";
                continue;
            }
            std::cout << "  RCODE: " << response.rcode << "  Bytes: " << response.response_size << "\n";
            if (response.answers.empty()) std::cout << "  No answers\n";
            for (const auto& record : response.answers) {
                std::cout << "  " << record.type_name << " " << record.ttl << " " << record.value << "\n";
            }
        }
    }

    if (!checks.empty()) {
        std::cout << "\n" << section_title("Security checks") << "\n";
        for (const auto& check : checks) {
            std::cout << "  [" << status_color(check.status) << "] " << style(check.name, BOLD) << " on " << check.target << ": " << check.message << "\n";
        }
    }

    if (!firewall.isNull()) {
        std::string verdict = firewall["verdict"].asString();
        int score = firewall["score"].asInt();
        std::cout << "\n" << section_title("Firewall assessment") << "\n";
        std::cout << "  " << header_label("Verdict:") << " " << status_color(verdict) << "\n";
        std::cout << "  " << header_label("Risk score:") << " " << style(std::to_string(score), YELLOW) << "\n";
        if (!firewall["signal_summary"].empty()) {
            const Json::Value& signals = firewall["signal_summary"];
            for (const auto& item : signals.asArray()) {
                std::string name = item["name"].asString();
                std::string message = item["message"].asString();
                std::cout << "    - " << style(name, BOLD) << ": " << message << "\n";
            }
        }
        if (!firewall["bypass_layers"].empty()) {
            std::cout << "\n" << section_title("Firewall bypass layer evaluation") << "\n";
            for (const auto& layer : firewall["bypass_layers"].asArray()) {
                std::cout << "  [" << status_color(layer["status"].asString()) << "] " << layer["layer"].asString() << ": " << layer["message"].asString() << "\n";
            }
        }
    }

    if (!subdomains.empty()) {
        std::cout << "\nSubdomain discovery\n";
        for (const auto& result : subdomains) {
            std::cout << "  " << result.subdomain << " -> ";
            if (!result.resolved) {
                std::cout << "no resolution";
                if (!result.error.empty()) std::cout << " (" << result.error << ")";
                std::cout << "\n";
                continue;
            }
            std::cout << "resolved [";
            for (size_t index = 0; index < result.addresses.size(); ++index) {
                if (index) std::cout << ", ";
                std::cout << result.addresses[index];
            }
            std::cout << "]\n";
        }
    }

    if (!probes.empty()) {
        std::cout << "\nWeb probes\n";
        for (const auto& probe : probes) {
            std::cout << "  " << probe.url << " -> ";
            if (!probe.reachable) {
                std::cout << "unreachable";
                if (!probe.error.empty()) std::cout << " (" << probe.error << ")";
                std::cout << "\n";
                continue;
            }
            std::cout << (probe.scheme == "https" ? "HTTPS" : "HTTP") << " " << probe.status_code;
            if (probe.tls_port_open) std::cout << " tls-port-open";
            if (!probe.server_header.empty()) std::cout << " server=" << probe.server_header;
            if (!probe.location.empty()) std::cout << " location=" << probe.location;
            std::cout << "\n";
        }
    }

    if (!assets.empty()) {
        std::cout << "\nWeb asset discovery\n";
        for (const auto& item : assets) {
            std::cout << "  " << item.url << " -> ";
            if (!item.reachable) {
                std::cout << "miss";
                if (!item.error.empty()) std::cout << " (" << item.error << ")";
                std::cout << "\n";
                continue;
            }
            std::cout << "found " << item.status_code;
            if (!item.server_header.empty()) std::cout << " server=" << item.server_header;
            std::cout << "\n";
        }
    }

    if (!scan_results.empty()) {
        std::cout << "\nPort scan\n";
        for (const auto& result : scan_results) {
            std::cout << "  " << result.target << ":" << result.port << " " << result.protocol << " " << (result.open ? "open" : "closed");
            if (!result.error.empty()) std::cout << " (" << result.error << ")";
            std::cout << "\n";
        }
    }
}

} // namespace

int main(int argc, char* argv[]) {
    enable_windows_vt();

    if (argc < 2) {
        print_architecture();
        return 0;
    }

    Options opt;
    if (!parse_options(argc, argv, opt)) return 1;

    if (opt.color_mode == "never" || std::getenv("NO_COLOR") != nullptr || (!stdout_is_tty() && opt.color_mode != "always")) {
        RESET = "";
        BOLD = "";
        RED = "";
        GREEN = "";
        YELLOW = "";
        BLUE = "";
        MAGENTA = "";
        CYAN = "";
    }

    if (opt.dns_servers_multi.empty() && opt.dns_server.empty()) {
        if (const char* env = std::getenv("WHITEDNS_RESOLVERS")) {
            opt.dns_servers_multi = split(env, ',');
        }
    }
    load_config(opt);
    if (opt.multi_vantage && opt.dns_servers_multi.empty() && opt.dns_server.empty()) {
        opt.dns_servers_multi = {"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"};
    }

    bool run_port_scan = !opt.port_scan_targets.empty() || !opt.port_scan_ports.empty();
    if (opt.probe_https_port && !opt.domain.empty() && opt.port_scan_targets.empty()) {
        opt.port_scan_targets = {opt.domain};
        if (opt.port_scan_ports.empty()) opt.port_scan_ports = {53, 80, 443, 853};
        run_port_scan = true;
    }
    if (run_port_scan && (opt.port_scan_targets.empty() || opt.port_scan_ports.empty())) {
        std::cerr << "Port scan requires targets (-P) and ports (-R).\n";
        return 1;
    }

    if (!stdout_is_tty() && opt.format == "human") {
        opt.output_json = true;
        opt.format = "json";
    }

    if (opt.enterprise_profile) {
        opt.check_open_resolver = true;
        opt.dnssec_readiness = true;
        opt.check_nxdomain_redirect = true;
        opt.test_amplification = true;
        opt.check_wildcard_dns = true;
        opt.detect_cache_poisoning = true;
        opt.detect_dns_tunneling = true;
        opt.proxy_detection = true;
        opt.fast_flux_detection = true;
        opt.dns_rebinding_detection = true;
        opt.check_zone_transfer = true;
        opt.dns_spoofing_detection = true;
        opt.dns_hijacking_detection = true;
        opt.check_spf_dmarc = true;
        opt.check_caa_policy = true;
        opt.scan_subdomains = true;
        opt.scan_web = true;
        opt.discover_web_assets = true;
        opt.http_header_scan = true;
        opt.probe_https_port = true;
        opt.command = Command::Enterprise;
    }

    if (opt.command == Command::Firewall) {
        opt.check_open_resolver = true;
        opt.dnssec_readiness = true;
        opt.check_nxdomain_redirect = true;
        opt.test_amplification = true;
        opt.check_wildcard_dns = true;
        opt.detect_cache_poisoning = true;
        opt.detect_dns_tunneling = true;
        opt.proxy_detection = true;
        opt.fast_flux_detection = true;
        opt.dns_rebinding_detection = true;
        opt.check_zone_transfer = true;
        opt.dns_spoofing_detection = true;
        opt.dns_hijacking_detection = true;
        opt.check_spf_dmarc = true;
        opt.check_caa_policy = true;
        opt.scan_web = true;
        opt.discover_web_assets = true;
        opt.http_header_scan = true;
        opt.probe_https_port = true;
    }

    if (opt.command == Command::Enterprise) {
        if (opt.urls.empty() && !opt.domain.empty()) {
            opt.urls = default_web_urls(opt.domain);
        }
    } else if (opt.command == Command::Web) {
        opt.scan_web = true;
        if (opt.urls.empty() && !opt.domain.empty()) {
            opt.urls = default_web_urls(opt.domain);
        }
    } else if (opt.command == Command::Enum) {
        opt.scan_subdomains = true;
    }

    if (opt.discover_web_assets && opt.urls.empty() && !opt.domain.empty()) {
        opt.urls = default_web_urls(opt.domain);
    }

    auto phase1 = opt.command == Command::Lookup || opt.command == Command::Records ||
                  opt.command == Command::Resolve || opt.command == Command::Compare ||
                  opt.command == Command::Trace || opt.command == Command::DnssecCmd ||
                  opt.command == Command::Odoh || opt.command == Command::OdohFilter ||
                  opt.command == Command::OdohPolicy || opt.command == Command::OdohLeak ||
                  opt.command == Command::Baseline || opt.command == Command::Intel ||
                  opt.command == Command::DnssecPath || opt.command == Command::Poison ||
                  opt.command == Command::Threats || opt.command == Command::Detect ||
                  opt.command == Command::Explain || opt.command == Command::Research ||
                  opt.command == Command::Faults || opt.command == Command::Controls ||
                  opt.command == Command::Graph ||
                  opt.command == Command::Security || opt.command == Command::Doctor ||
                  opt.command == Command::Report || opt.command == Command::Dga ||
                  opt.command == Command::WireCheck || opt.command == Command::Assess ||
                  opt.command == Command::Summary || opt.command == Command::Traffic ||
                  opt.command == Command::TrafficProto || opt.command == Command::TrafficRoute ||
                  opt.command == Command::TrafficFlow || opt.command == Command::TrafficFault ||
                  opt.command == Command::Deep || opt.command == Command::Feeds ||
                  opt.command == Command::Scale || opt.command == Command::Ct ||
                  opt.command == Command::Cname || opt.command == Command::Dot ||
                  opt.command == Command::Rdap || opt.command == Command::Asn ||
                  opt.command == Command::Pcap || opt.command == Command::Stat ||
                  opt.command == Command::Axfr || opt.command == Command::Filter ||
                  opt.command == Command::Ptr || opt.command == Command::Mx ||
                  opt.command == Command::Latency || opt.command == Command::Qctrl ||
                  opt.command == Command::Monitor || opt.command == Command::Packages ||
                  opt.command == Command::GraphIntel || opt.command == Command::TopologyCmd;
    if (phase1) {
        if (opt.command == Command::Doctor) {
            core::print_doctor();
            return 0;
        }
        if (opt.command == Command::WireCheck) {
            return core::run_protocol_selftest(std::cout);
        }
        if (opt.command == Command::Assess) {
            if (opt.domain.empty()) {
                std::cerr << "Name required. Authorized names only.\n";
                return 1;
            }
            std::cout << "WhiteDNS assessment  " << opt.domain << "\n";
            std::cout << "Authorized use only. No amplification, no zone dump, no update.\n";
            auto path = core::run_dnssec_path(opt.domain, "8.8.8.8");
            core::print_dnssec_path(path);
            auto poison = core::run_poison_classifier(opt.domain, {});
            core::print_poison_classifier(poison);
            core::run_print_faults(opt.domain);
            auto intel = core::run_resolver_intel(opt.domain, "1.1.1.1");
            core::print_resolver_intel(intel);
            core::print_summary(opt.domain);
            return 0;
        }
        if (opt.command == Command::Summary) {
            if (opt.domain.empty()) {
                std::cerr << "Name required.\n";
                return 1;
            }
            core::print_summary(opt.domain);
            return 0;
        }
        if (opt.command == Command::Traffic) {
            if (opt.domain.empty()) {
                std::cerr << "Name required.\n";
                return 1;
            }
            core::print_traffic(opt.domain);
            return 0;
        }
        if (opt.command == Command::TrafficProto || opt.command == Command::TrafficRoute ||
            opt.command == Command::TrafficFlow || opt.command == Command::TrafficFault) {
            if (opt.domain.empty()) {
                std::cerr << "Name required.\n";
                return 1;
            }
            const char* fam = "protocol";
            if (opt.command == Command::TrafficRoute) fam = "route";
            if (opt.command == Command::TrafficFlow) fam = "flow";
            if (opt.command == Command::TrafficFault) fam = "fault";
            core::print_traffic_family(opt.domain, fam);
            return 0;
        }
        if (opt.command == Command::Deep) {
            if (opt.domain.empty()) {
                std::cerr << "Name required.\n";
                return 1;
            }
            core::print_deep_pack(opt.domain);
            return 0;
        }
        if (opt.command == Command::Feeds) {
            if (opt.urlhaus_file.empty()) {
                const char* env = std::getenv("WHITEDNS_URLHAUS");
                if (env && *env) opt.urlhaus_file = env;
            }
            std::vector<std::string> names;
            if (!opt.domains_file.empty()) {
                std::ifstream in(opt.domains_file);
                std::string line;
                while (std::getline(in, line)) {
                    if (!line.empty() && line[0] != '#') names.push_back(line);
                }
            } else if (!opt.domain.empty()) {
                names.push_back(opt.domain);
            }
            if (names.empty()) {
                std::cerr << "Name or --domains file required.\n";
                return 1;
            }
            if (names.size() == 1 && opt.domains_file.empty()) {
                core::print_threat_feeds(names[0], opt.urlhaus_file);
                core::print_feeds2(names[0], opt.urlhaus_file);
                return 0;
            }
            std::cout << "{\n  \"feed\": \"" << opt.urlhaus_file << "\",\n  \"results\": [\n";
            for (size_t n = 0; n < names.size(); ++n) {
                int kind = core::feed_match(names[n], opt.urlhaus_file);
                const char* match = kind == 1 ? "exact" : kind == 2 ? "parent" : kind == 3 ? "child" : kind < 0 ? "read-fail" : "no";
                std::cout << "    {\"name\":\"" << names[n] << "\",\"hit\":" << (kind > 0 ? "true" : "false")
                          << ",\"match\":\"" << match << "\"}" << (n + 1 == names.size() ? "\n" : ",\n");
            }
            std::cout << "  ]\n}\n";
            return 0;
        }
        if (opt.command == Command::Scale) {
            if (opt.domain.empty()) {
                std::cerr << "Name required.\n";
                return 1;
            }
            core::print_scale_intel(opt.domain, opt.output_json || opt.format == "json");
            return 0;
        }
        if (opt.command == Command::Ct) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::print_ct(opt.domain);
            return 0;
        }
        if (opt.command == Command::Cname) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::print_cname_chain(opt.domain, opt.dns_server.empty() ? "8.8.8.8" : opt.dns_server);
            return 0;
        }
        if (opt.command == Command::Dot) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::print_dot(opt.domain, opt.dns_server.empty() ? "1.1.1.1" : opt.dns_server);
            return 0;
        }
        if (opt.command == Command::Rdap) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::print_rdap(opt.domain);
            return 0;
        }
        if (opt.command == Command::Asn) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::print_asn(opt.domain);
            return 0;
        }
        if (opt.command == Command::Pcap) {
            if (opt.domain.empty()) { std::cerr << "pcap file required.\n"; return 1; }
            core::print_pcap(opt.domain);
            return 0;
        }
        if (opt.command == Command::Stat) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::print_stat_detect(core::run_stat_detect(opt.domain));
            return 0;
        }
        if (opt.command == Command::Axfr) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            std::string server = opt.dns_server.empty() ? "8.8.8.8" : opt.dns_server;
            core::print_axfr(core::stream_axfr(opt.domain, server));
            return 0;
        }
        if (opt.command == Command::Filter) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            auto resolvers = servers_to_use(opt);
            if (resolvers.size() == 1 && opt.dns_servers_multi.empty())
                resolvers = {"8.8.8.8", "1.1.1.1", "9.9.9.9"};
            core::print_filter(core::run_filter(opt.domain, resolvers, opt.query_types, opt.arg2));
            return 0;
        }
        if (opt.command == Command::Ptr) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::run_ptr(opt.domain);
            return 0;
        }
        if (opt.command == Command::Mx) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::run_mx(opt.domain);
            return 0;
        }
        if (opt.command == Command::Latency) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::run_latency(opt.domain);
            return 0;
        }
        if (opt.command == Command::Qctrl) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            core::print_query_control(core::run_query_control(opt.domain, opt.dns_server));
            return 0;
        }
        if (opt.command == Command::Monitor) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            if (opt.arg2 == "status" || opt.arg2 == "history") {
                std::string path = std::string(std::getenv("HOME") ? std::getenv("HOME") : ".") + "/.whitedns/history/" + opt.domain + ".fields";
                std::ifstream in(path);
                if (!in) { std::cout << "monitor " << opt.arg2 << " no history for " << opt.domain << "\n"; return 0; }
                std::cout << "monitor " << opt.arg2 << " " << path << "\n";
                std::string line; int n = 0;
                while (std::getline(in, line) && n < 20) { std::cout << "  " << line << "\n"; n++; }
                return 0;
            }
            int n = opt.threads > 0 ? opt.threads : 3;
            int gap = opt.timeout_ms > 0 ? opt.timeout_ms / 1000 : 2;
            auto resolvers = servers_to_use(opt);
            if (resolvers.size() == 1 && opt.dns_servers_multi.empty())
                resolvers = {"8.8.8.8", "1.1.1.1", "9.9.9.9"};
            core::run_monitor(opt.domain, n, gap, resolvers);
            return 0;
        }
        if (opt.command == Command::Packages) {
            core::print_packages();
            return 0;
        }
        if (opt.command == Command::GraphIntel) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            // Build a small graph from NS and A of the name.
            std::vector<core::Edge> edges;
            edges.push_back({opt.domain, "ns"});
            edges.push_back({"ns", "a"});
            auto report = core::analyze_graph(edges);
            core::print_graph_report(report);
            return 0;
        }
        if (opt.command == Command::TopologyCmd) {
            if (opt.domain.empty()) { std::cerr << "Name required.\n"; return 1; }
            std::vector<core::SimplexEdge> edges = {{opt.domain, "ns"}, {"ns", "a"}, {opt.domain, "a"}};
            auto report = core::compute_topology(edges);
            core::print_topology(report);
            return 0;
        }
        if (opt.command == Command::Dga) {
            core::print_dga(opt.domain.empty() ? "unset" : opt.domain);
            return 0;
        }
        if (opt.command == Command::Threats) {
            std::string sub = opt.domain;
            if (sub.empty() || sub == "list") core::print_threat_catalog();
            else if (sub == "categories") core::print_threat_categories();
            else if (sub == "validate" || sub == "rules")
                std::cout << (core::validate_threat_rules() ? "rules ok\n" : "rules invalid\n");
            else if (sub == "info") core::print_threat_info(opt.arg2);
            else core::print_threat_info(sub);
            return core::validate_threat_rules() ? 0 : 1;
        }
        if (opt.command == Command::Explain) {
            core::print_threat_explain(opt.domain);
            return 0;
        }
        if (opt.command == Command::OdohLeak && opt.domain.empty()) {
            const char* enterprises[] = {
                "google.com", "facebook.com", "microsoft.com", "nasa.gov", nullptr};
            int worst = 0;
            for (int i = 0; enterprises[i]; ++i) {
                auto report = core::run_odoh_leak_models(enterprises[i], opt.odoh_target, opt.odoh_proxy);
                core::print_odoh_leak_models(report);
                std::cout << "\n";
                if (report.leak) worst = 3;
            }
            return worst;
        }
        if (opt.domain.empty()) {
            std::cerr << "Domain not specified.\n";
            return 1;
        }
        if (!whitedns::core::in_scope(opt.domain, opt.scope.empty() ? (std::getenv("WHITEDNS_SCOPE") ? std::getenv("WHITEDNS_SCOPE") : "") : opt.scope)) {
            std::cerr << "scope/denied: " << opt.domain << "\n";
            return 1;
        }
        if (opt.command == Command::Graph || opt.command == Command::Security || opt.command == Command::Report) {
            auto fused = core::build_fusion(opt.domain);
            if (opt.command == Command::Graph) {
                core::print_graph(fused);
                core::print_asn(opt.domain);
                core::print_rdap(opt.domain);
            }
            else if (opt.command == Command::Security) core::print_security(fused);
            else core::print_report(fused);
            return 0;
        }
        if (opt.command == Command::Controls) {
            core::run_print_vendor_controls(opt.domain);
            return 0;
        }
        if (opt.command == Command::Faults) {
            core::run_print_faults(opt.domain);
            return 0;
        }
        if (opt.command == Command::Detect || opt.command == Command::Research) {
            auto report = core::run_threat_detect(opt.domain);
            core::print_threat_detect(report);
            if (opt.command == Command::Research)
                std::cout << "research: experimental detectors marked INCONCLUSIVE when telemetry is missing.\n";
            return 0;
        }
        if (opt.command == Command::Poison) {
            std::vector<std::string> rs = opt.dns_servers_multi;
            if (rs.empty() && !opt.dns_server.empty()) rs = {opt.dns_server};
            auto report = core::run_poison_classifier(opt.domain, rs);
            core::print_poison_classifier(report);
            return 0;
        }
        if (opt.command == Command::DnssecPath) {
            auto resolvers = servers_to_use(opt);
            auto report = core::run_dnssec_path(opt.domain, resolvers.empty() ? "8.8.8.8" : resolvers.front());
            core::print_dnssec_path(report);
            return 0;
        }
        if (opt.command == Command::Intel) {
            auto resolvers = servers_to_use(opt);
            auto report = core::run_resolver_intel(opt.domain, resolvers.empty() ? "1.1.1.1" : resolvers.front());
            core::print_resolver_intel(report);
            return 0;
        }
        if (opt.command == Command::Baseline) {
            whitedns::core::ResolverEngine engine(std::chrono::milliseconds(opt.timeout_ms > 0 ? opt.timeout_ms : 2500));
            auto resolvers = servers_to_use(opt);
            if (resolvers.size() < 2) {
                resolvers = {"8.8.8.8", "1.1.1.1", "9.9.9.9"};
            }
            uint16_t qtype = opt.query_types.empty() ? DNS_TYPE_A : opt.query_types.front();
            std::cout << "WhiteDNS Phase 2 baseline\n";
            std::cout << "QNAME: " << opt.domain << "  type=" << dns_type_to_string(qtype) << "\n";
            auto rows = engine.baseline(opt.domain, qtype, resolvers);
            for (const auto& b : rows) {
                std::cout << "  @" << b.resolver << " samples=" << b.samples << " ok=" << b.ok
                          << " rtt_min=" << b.min_ms << "ms rtt_max=" << b.max_ms
                          << "ms rtt_avg=" << b.avg_ms << "ms cache2=" << (b.cache_hit_second ? "hit" : "miss")
                          << "\n";
                for (const auto& a : b.answers) std::cout << "      " << a << "\n";
            }
            auto cs = engine.cache_stats();
            std::cout << "Cache: hits=" << cs.hits << " misses=" << cs.misses << " stores=" << cs.stores << "\n";
            std::vector<double> rtts;
            for (const auto& b : rows) rtts.push_back(static_cast<double>(b.avg_ms));
            auto scored = core::score_name(opt.domain, rtts);
            std::cout << "entropy=" << scored.entropy
                      << " kalman_rtt_ms=" << scored.smoothed_rtt_ms
                      << " residual_sq=" << scored.residual_sq
                      << " confidence=" << scored.confidence << "\n";
            return 0;
        }
        if (opt.command == Command::OdohLeak) {
            auto report = core::run_odoh_leak_models(opt.domain, opt.odoh_target, opt.odoh_proxy);
            core::print_odoh_leak_models(report);
            return report.leak ? 3 : 0;
        }
        if (opt.command == Command::OdohPolicy) {
            auto report = core::run_odoh_policy(opt.domain, opt.odoh_target, opt.odoh_proxy, opt.scope);
            core::print_odoh_policy(report, opt.verbose);
            return report.fail ? 3 : 0;
        }
        if (opt.command == Command::OdohFilter) {
            uint16_t qtype = opt.query_types.empty() ? DNS_TYPE_A : opt.query_types.front();
            auto report = core::run_odoh_filter(opt.domain, qtype, opt.odoh_target, opt.odoh_proxy, opt.scope);
            core::print_odoh_filter(report);
            if (!report.allow) return 3;
            if (report.posture == "leaky") return 2;
            return report.path.ok ? 0 : 5;
        }
        if (opt.command == Command::Odoh) {
            uint16_t qtype = opt.query_types.empty() ? DNS_TYPE_A : opt.query_types.front();
            auto r = core::odoh_lookup(opt.domain, qtype, opt.odoh_target, opt.odoh_proxy);
            std::cout << "WhiteDNS ODoH (RFC 9230)\n";
            std::cout << "  qname: " << opt.domain << "\n";
            std::cout << "  target: " << r.target << "\n";
            std::cout << "  proxy: " << (r.proxy.empty() ? "(none — NOT oblivious)" : r.proxy) << "\n";
            std::cout << "  oblivious: " << (r.oblivious ? "yes" : "no") << "\n";
            std::cout << "  key_id: " << r.key_id_hex << "\n";
            if (!r.ok) std::cout << "  error: " << r.error << "\n";
            else {
                std::cout << "  rcode: " << iana_rcode_name(r.rcode) << "\n";
                for (const auto& rec : r.answers)
                    std::cout << "  ANS " << rec.type_name << " " << rec.value << "\n";
            }
            std::cout << "  privacy: relay sees IP; target sees QNAME; access net should see IP:443 not SNI.\n";
            return r.ok ? 0 : 5;
        }
        if (opt.command == Command::DnssecCmd) {
            FrameworkAuditReport audit = run_framework_audit(opt.domain, servers_to_use(opt));
            for (const auto& f : audit.findings) {
                if (f.finding_id == "SANS-DNSSEC-009") {
                    std::cout << "[" << f.status << "] " << f.title << "\n  " << f.message << "\n  class: "
                              << (f.status == "pass" ? "CONFIRMED_BY_VALIDATION_OR_MATCH" : "ANOMALY") << "\n";
                }
            }
            return 0;
        }
        whitedns::core::ResolverEngine engine(std::chrono::milliseconds(opt.timeout_ms > 0 ? opt.timeout_ms : 2500));
        auto resolvers = servers_to_use(opt);
        uint16_t qtype = opt.query_types.empty() ? DNS_TYPE_A : opt.query_types.front();
        if (opt.command == Command::Trace) {
            std::cout << "trace " << opt.domain << " via " << resolvers.front() << "\n";
            auto ns = engine.query(opt.domain, DNS_TYPE_NS, resolvers.front());
            std::cout << "  rcode=" << iana_rcode_name(ns.message.flags.rcode) << " aa=" << ns.message.flags.aa
                      << " rtt=" << ns.rtt.count() << "ms transport=" << ns.transport << "\n";
            for (const auto& rec : ns.message.answers) {
                std::cout << "  NS " << rec.value << "\n";
                if (!rec.rdata.empty() && rec.type == DNS_TYPE_NS) {
                    /* value may be opaque size; still show type */
                }
            }
            auto soa = engine.query(opt.domain, DNS_TYPE_SOA, resolvers.front());
            std::cout << "  SOA rcode=" << iana_rcode_name(soa.message.flags.rcode) << " aa=" << soa.message.flags.aa << "\n";
            return ns.ok ? 0 : 5;
        }
        auto print_obs = [&](const whitedns::core::Observation& obs) {
            std::cout << obs.qname << " " << dns_type_to_string(obs.qtype) << " @" << obs.resolver
                      << " " << obs.transport << " rtt=" << obs.rtt.count() << "ms"
                      << " rcode=" << iana_rcode_name(obs.message.flags.rcode)
                      << " aa=" << obs.message.flags.aa << " ad=" << obs.message.flags.ad << "\n";
            if (!obs.ok) std::cout << "  error " << obs.error << "\n";
            for (const auto& rec : obs.message.answers) {
                std::cout << "  ANS " << rec.type_name << " " << rec.ttl << " " << rec.value << "\n";
            }
            if (opt.verbose) {
                for (const auto& rec : obs.message.authority)
                    std::cout << "  AUTH " << rec.type_name << " " << rec.value << "\n";
            }
        };
        if (opt.command == Command::Resolve || opt.command == Command::Compare) {
            auto set = engine.compare(opt.domain, qtype, resolvers);
            std::cout << "class: OBSERVATION (resolver disagreement is not automatically poisoning)\n";
            for (const auto& obs : set) print_obs(obs);
            return 0;
        }
        if (resolvers.front().rfind("https://", 0) == 0) {
            auto d = core::doh_lookup_url(resolvers.front(), opt.domain, qtype);
            std::cout << "doh " << opt.domain << " @" << resolvers.front()
                      << " ok=" << (d.ok ? "yes" : "no") << " status=" << d.status << "\n";
            for (const auto& rec : d.records) std::cout << "  ANS " << rec.value << "\n";
            if (!d.ok) std::cout << "  error " << d.error << "\n";
            return d.ok ? 0 : 5;
        }
        print_obs(engine.query(opt.domain, qtype, resolvers.front(), whitedns::core::TransportKind::Udp, opt.dnssec_readiness));
        if (opt.multi_vantage && resolvers.size() > 1) {
            std::set<std::string> answers;
            for (const auto& r : resolvers) {
                auto obs = engine.query(opt.domain, qtype, r);
                std::vector<std::string> vals;
                for (const auto& rec : obs.message.answers) vals.push_back(rec.value);
                std::sort(vals.begin(), vals.end());
                std::string joined;
                for (const auto& v : vals) joined += v + ",";
                answers.insert(joined);
                std::cout << "vantage @" << r << " answers=" << joined << "\n";
            }
            std::cout << "vantage agreement=" << (answers.size() <= 1 ? "yes" : "no") << "\n";
        }
        return 0;
    }

    if ((opt.command == Command::Dns || opt.command == Command::Audit) && opt.domain.empty() && !run_port_scan) {
        std::cerr << "Domain not specified.\n";
        print_usage();
        return 1;
    }

    if (opt.command == Command::Audit) {
        FrameworkAuditReport audit = run_framework_audit(opt.domain, servers_to_use(opt));
        if (!opt.workpaper_path.empty()) {
            std::ofstream out(opt.workpaper_path);
            if (!out) {
                std::cerr << "Cannot write workpaper: " << opt.workpaper_path << "\n";
                return 1;
            }
            out << framework_workpaper_to_json(audit).toStyledString();
        }
        if (opt.format == "prometheus") {
            int pass = 0, warn = 0, fail = 0;
            for (const auto& f : audit.findings) {
                if (f.status == "pass" || f.status == "info") pass++;
                else if (f.status == "warning") warn++;
                else if (f.status == "fail") fail++;
            }
            int posture_n = audit.posture == "ok" ? 0 : audit.posture == "warning" ? 1 : audit.posture == "degraded" ? 2 : 3;
            std::cout << "# HELP whitedns_fault_score Fault score 0-100\n";
            std::cout << "# TYPE whitedns_fault_score gauge\n";
            std::cout << "whitedns_fault_score{domain=\"" << opt.domain << "\"} " << audit.fault_score << "\n";
            std::cout << "# HELP whitedns_posture 0 ok 1 warning 2 degraded 3 exposed\n";
            std::cout << "# TYPE whitedns_posture gauge\n";
            std::cout << "whitedns_posture{domain=\"" << opt.domain << "\"} " << posture_n << "\n";
            std::cout << "# HELP whitedns_findings Finding counts by status\n";
            std::cout << "# TYPE whitedns_findings gauge\n";
            std::cout << "whitedns_findings{domain=\"" << opt.domain << "\",status=\"pass\"} " << pass << "\n";
            std::cout << "whitedns_findings{domain=\"" << opt.domain << "\",status=\"warning\"} " << warn << "\n";
            std::cout << "whitedns_findings{domain=\"" << opt.domain << "\",status=\"fail\"} " << fail << "\n";
        } else if (opt.output_json || opt.format == "json") {
            auto j = framework_audit_to_json(audit);
            std::cout << j.toStyledString();
            core::save_history(opt.domain, j.toStyledString());
            std::ostringstream fields;
            for (const auto& f : audit.findings) {
                fields << f.finding_id << " " << f.status << "\n";
            }
            core::save_fields(opt.domain, fields.str());
            if (!opt.diff_path.empty()) {
                std::string path = opt.diff_path == "last" ? core::last_history(opt.domain) : opt.diff_path;
                print_diff(path, j);
            }
        } else {
            print_framework_audit(audit);
        }
        if (opt.fail_on == "never") return 0;
        if (opt.fail_on == "warning") {
            for (const auto& f : audit.findings) {
                if (f.status == "warning" || f.status == "fail") return 4;
            }
        }
        if (audit.posture == "exposed") return 3;
        if (audit.posture == "degraded" && (opt.fail_on == "degraded" || opt.fail_on == "warning" || opt.fail_on == "medium")) return 2;
        int gate = fail_rank(opt.fail_on);
        if (gate < 99) {
            for (const auto& f : audit.findings) {
                if (severity_rank(f.status) >= gate) return 1;
            }
        }
        return 0;
    }

    if (opt.command == Command::Enum && opt.domain.empty()) {
        std::cerr << "Domain not specified for enumeration.\n";
        print_usage();
        return 1;
    }

    if (opt.command == Command::Web && opt.urls.empty() && opt.domain.empty()) {
        std::cerr << "URL or host not specified for web scanning.\n";
        print_usage();
        return 1;
    }

    std::vector<DnsResponse> responses;
    std::vector<CheckResult> checks;
    std::vector<SubdomainResult> subdomain_results;
    std::vector<HttpProbeResult> probe_results;
    std::vector<WebAssetResult> asset_results;
    Json::Value subdomain_json(Json::arrayValue);
    Json::Value web_json(Json::objectValue);
    std::vector<ScanResult> scan_results;
    Json::Value port_scan_json(Json::arrayValue);
    Json::Value firewall_json(Json::nullValue);

    if (opt.command != Command::Web && opt.command != Command::Enum) {
        std::vector<std::string> servers = servers_to_use(opt);
        if (!opt.domain.empty()) {
            responses = run_queries(opt, servers);
            checks = run_checks(opt, servers, responses);
        }
    }

    if (opt.scan_subdomains) {
        if (!opt.dsl_pattern.empty()) {
            auto gen = expand_dsl(opt.dsl_pattern);
            opt.subdomain_candidates.insert(opt.subdomain_candidates.end(), gen.begin(), gen.end());
            std::cout << "dsl  generated=" << gen.size() << "\n";
        }
        if (opt.g4_generate) {
            auto gen = generate_g4();
            opt.subdomain_candidates.insert(opt.subdomain_candidates.end(), gen.begin(), gen.end());
            std::cout << "g4  generated=" << gen.size() << "  (4-factor product, not a manifold)\n";
        }
        if (opt.permute_generate) {
            auto gen = generate_permutations();
            opt.subdomain_candidates.insert(opt.subdomain_candidates.end(), gen.begin(), gen.end());
            std::cout << "permute  generated=" << gen.size() << "\n";
        }
        if (opt.subdomain_candidates.empty()) {
            std::string home = ".";
            if (const char* h = std::getenv("HOME")) home = h;
            std::string user_enum = home + "/.whitedns/subdomains.txt";
            std::string user_brute = home + "/.whitedns/subdomains-brute.txt";
            std::vector<std::string> paths;
            if (opt.brute_subdomains) {
                paths = {
                    "share/subdomains-brute.txt",
                    "../share/subdomains-brute.txt",
                    user_brute,
                    "/usr/local/share/whitedns/subdomains-brute.txt",
                    "/usr/share/whitedns/subdomains-brute.txt"
                };
            } else {
                paths = {
                    "share/subdomains.txt",
                    "../share/subdomains.txt",
                    user_enum,
                    "/usr/local/share/whitedns/subdomains.txt",
                    "/usr/share/whitedns/subdomains.txt"
                };
            }
            for (const auto& p : paths) {
                if (load_subdomain_candidates(p, opt.subdomain_candidates)) break;
            }
            if (opt.subdomain_candidates.empty()) {
                std::cerr << "no wordlist loaded.\n";
                std::cerr << "  with root:    sudo mkdir -p /usr/share/whitedns && sudo cp share/*.txt /usr/share/whitedns/\n";
                std::cerr << "  without root: mkdir -p ~/.whitedns && cp share/*.txt ~/.whitedns/\n";
                return 1;
            }
        }
        int workers = opt.threads > 0 ? opt.threads : (opt.brute_subdomains ? 32 : 16);
        int timeout = opt.timeout_ms > 0 ? opt.timeout_ms : (opt.brute_subdomains ? 800 : 2000);
        std::cout << (opt.brute_subdomains ? "brute" : "enum")
                  << "  candidates=" << opt.subdomain_candidates.size()
                  << "  wildcard filter on  workers=" << workers
                  << (opt.recursive_subdomains ? "  recursive depth=" + std::to_string(opt.enum_depth) : "")
                  << "\n";
        SubdomainScanner scanner(opt.domain, opt.subdomain_candidates,
                                 opt.dns_server.empty() ? "8.8.8.8" : opt.dns_server,
                                 timeout, workers);
        if (opt.recursive_subdomains) scanner.run_recursive(opt.enum_depth);
        else scanner.run();
        subdomain_results = scanner.results();
        int hits = 0;
        for (const auto& r : subdomain_results)
            if (r.resolved) hits++;
        double rate = subdomain_results.empty() ? 0.0 : static_cast<double>(hits) / subdomain_results.size();
        std::cout << "enum  queried=" << subdomain_results.size() << " hits=" << hits
                  << " hit_rate=" << rate
                  << " apex_entropy=" << core::shannon_entropy(opt.domain) << "\n";
        subdomain_json = scanner.to_json();
    }

    if (opt.scan_web) {
        HttpScanner scanner(opt.urls, opt.discover_web_assets ? default_asset_paths() : std::vector<std::string>{});
        scanner.run();
        probe_results = scanner.probes();
        asset_results = scanner.assets();
        web_json = scanner.to_json();
    }

    if (run_port_scan) {
        PortScanner scanner(opt.port_scan_targets, opt.port_scan_ports);
        scanner.run_tcp_connect_scan();
        scan_results = scanner.results();
        port_scan_json = scanner.to_json();
    }

    if (opt.command == Command::Firewall || opt.enterprise_profile) {
        firewall_json = firewall_assessment_to_json(assess_firewall_risk(checks, responses, web_json, port_scan_json, subdomain_json));
    }

    if (opt.output_json || opt.format == "sarif" || opt.format == "html") {
        auto report = build_json_report(opt, responses, checks, subdomain_json, web_json, port_scan_json, firewall_json);
        if (opt.format == "sarif") write_sarif(opt.arg2.empty() ? "whitedns.sarif" : opt.arg2, report);
        else if (opt.format == "html") write_html(opt.arg2.empty() ? "whitedns.html" : opt.arg2, report);
        else std::cout << report.toStyledString();
        if (!opt.diff_path.empty()) {
            std::string path = opt.diff_path == "last" ? core::last_history(opt.domain) : opt.diff_path;
            print_diff(path, report);
        }
        if (opt.format == "json" || opt.output_json) {
            core::save_history(opt.domain, report.toStyledString());
            std::ostringstream fields;
            const auto& qs = report["queries"];
            for (unsigned i = 0; i < qs.size(); ++i) {
                std::string t = qs[i]["type"].asString();
                const auto& ans = qs[i]["answers"];
                for (unsigned j = 0; j < ans.size(); ++j)
                    fields << t << " " << ans[j].asString() << "\n";
            }
            core::save_fields(opt.domain, fields.str());
        }
        int gate = fail_rank(opt.fail_on);
        if (gate < 99) {
            for (const auto& c : checks) if (severity_rank(c.status) >= gate) return 1;
        }
    } else {
        print_human_report(opt, responses, checks, subdomain_results, probe_results, asset_results, scan_results, firewall_json);
    }

    return 0;
}
