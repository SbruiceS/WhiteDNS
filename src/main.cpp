#include "whitedns/Analyzer.h"
#include "whitedns/Dnssec.h"
#include "whitedns/IanaDns.h"
#include "whitedns/FrameworkAudit.h"
#include "whitedns/HttpScanner.h"
#include "whitedns/PortScanner.h"
#include "whitedns/SubdomainScanner.h"
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

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
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

void print_version() {
    std::cout << "WhiteDNS 2.0.0 (" << platform_name() << ")\n";
    std::cout << "DNS security, forensics and reconnaissance platform\n";
    std::cout << "Developer: Cosinfotech Solutions\n";
    std::cout << "Author: S. Bruice Singh\n";
}

void print_usage() {
    std::cout << style("WhiteDNS", BOLD) << "  " << style("1.1.0", CYAN) << "  [" << platform_name() << "]\n";
    std::cout << style("Cross-platform DNS security and fault-finding CLI", CYAN) << "\n";
    std::cout << "Linux | Windows | macOS | Termux   Author: SBruice Singh\n";
    std::cout << style("============================================================", YELLOW) << "\n\n";
    std::cout << header_label("Usage:") << "\n";
    std::cout << "  " << style("whitedns <command> [options] <domain|url>", GREEN) << "\n";
    std::cout << "  " << style("whitedns help [command]", GREEN) << "\n\n";
    std::cout << header_label("Commands:") << "\n";
    std::cout << "  dns           Perform DNS security and resolver comparison checks\n";
    std::cout << "  web           Probe HTTP and HTTPS endpoints, headers, and asset paths\n";
    std::cout << "  enum          Run subdomain enumeration against a target domain\n";
    std::cout << "  firewall      Run a firewall risk assessment using DNS and web signals\n";
    std::cout << "  enterprise    Run a comprehensive enterprise scan profile\n";
    std::cout << "  audit         SANS / MITRE ATT&CK / RFC / IANA / ISACA framework audit\n";
    std::cout << "  lookup        Phase-1 resolver engine query (UDP/TCP, EDNS)\n";
    std::cout << "  records       Same as lookup; print record inventory\n";
    std::cout << "  resolve       Multi-resolver compare (not auto-classified as poisoning)\n";
    std::cout << "  compare       Alias of resolve\n";
    std::cout << "  trace         Iterative NS walk using the Phase-1 engine\n";
    std::cout << "  dnssec        Cryptographic DS→DNSKEY audit slice\n";
    std::cout << "  odoh          RFC 9230 Oblivious DoH (HPKE + production relay)\n";
    std::cout << "  odoh-filter   Deep ODoH policy: collusion, leak, suite, padding\n";
    std::cout << "  odoh-policy   112-control authorized-use ODoH security policy scan\n";
    std::cout << "  odoh-leak     27 leakage models (enterprise: google/facebook/microsoft/nasa)\n";
    std::cout << "  baseline      Comparative resolvers, TTL cache, RTT baselines\n";
    std::cout << "  intel         RFC/SANS resolver models — extract zone/mail/DNSSEC facts\n";
    std::cout << "  dnssec-path   DS→DNSKEY + RRSIG/NSEC/NSEC3 inventory\n";
    std::cout << "  poison        Multi-resolver A + DNSSEC; disagreement is not poisoning\n";
    std::cout << "  threats       list | categories | info <ID> | validate\n";
    std::cout << "  detect        Run taxonomy evaluators on a zone\n";
    std::cout << "  explain       Explain a rule ID\n";
    std::cout << "  research      Raw observations + experimental detectors\n";
    std::cout << "  faults        Aggregate FINDING/ANOMALY + poison gates (defensive)\n";
    std::cout << "  controls      Cisco/ITU/Nokia/HP/Dell defensive control gaps\n\n";
    std::cout << "Developer: Cosinfotech Solutions    Author: S. Bruice Singh\n\n";
    std::cout << "Global options:\n";
    std::cout << "  -h, --help      Show help\n";
    std::cout << "  --version       Show version and platform\n";
    std::cout << "  -v              Verbose output\n";
    std::cout << "  -q, --quiet     Findings only (human mode)\n";
    std::cout << "  -j              JSON output (same as --format json)\n";
    std::cout << "  --format <fmt>  human | json\n";
    std::cout << "  --color <mode>  auto | always | never  (NO_COLOR supported)\n";
    std::cout << "  --fail-on <lvl> warning | degraded | exposed | never\n";
    std::cout << "  --workpaper <file>  Write ISACA COBIT JSON workpaper\n";
    std::cout << "  --profile <name>  Scan profile: standard, enterprise\n";
    std::cout << "  -s <server>     DNS server hostname/IP. Default: 8.8.8.8\n";
    std::cout << "  -S <servers>    Compare comma-separated DNS servers\n";
    std::cout << "  -t <types>      Record types: A,AAAA,NS,MX,TXT,SOA,DNSKEY,RRSIG,CAA,ANY\n";
    std::cout << "  -P <targets>    Comma-separated port scan targets\n";
    std::cout << "  -R <ports>      Comma-separated TCP ports\n\n";
    std::cout << "DNS options:\n";
    std::cout << "  -r              DNSSEC readiness\n";
    std::cout << "  -o              Open resolver check\n";
    std::cout << "  -n              NXDOMAIN redirect detection\n";
    std::cout << "  -a              Amplification signal\n";
    std::cout << "  -w              Wildcard DNS\n";
    std::cout << "  -x              Suspicious TXT tunneling patterns\n";
    std::cout << "  -b              DNS rebinding signal\n";
    std::cout << "  -z              AXFR zone transfer exposure\n";
    std::cout << "  -c              Cache poisoning signal\n";
    std::cout << "  -f              Fast-flux signal\n";
    std::cout << "  -A              DNS spoofing signal\n";
    std::cout << "  -H              DNS hijacking signal\n";
    std::cout << "  --spf-dmarc     SPF/DMARC policy check\n";
    std::cout << "  --caa           CAA policy check\n\n";
    std::cout << "Enumeration options:\n";
    std::cout << "  -D <list|file>  Comma-separated subdomain candidates or wordlist file\n";
    std::cout << "  --subdomains    Enable built-in subdomain discovery\n\n";
    std::cout << "Web options:\n";
    std::cout << "  -U <urls>      Comma-separated URLs or hosts to scan\n";
    std::cout << "  --assets        Discover common web asset paths\n";
    std::cout << "  --http-headers  Collect HTTP headers\n";
    std::cout << "  --https-probe  Probe HTTPS connectivity\n\n";
    std::cout << "Examples:\n";
    std::cout << "  whitedns dns -j -r -n -w -x -t A,AAAA,NS,MX,TXT google.com\n";
    std::cout << "  whitedns web -U https://google.com --assets --http-headers\n";
    std::cout << "  whitedns enum -D subdomains.txt example.com\n";
    std::cout << "  whitedns enterprise google.com\n";
    std::cout << "  whitedns audit --format json --fail-on degraded google.com\n";
    std::cout << "  WHITEDNS_RESOLVERS=8.8.8.8,1.1.1.1 whitedns audit google.com\n\n";
    std::cout << "Termux: pkg install clang cmake; cmake -B build && cmake --build build\n";
    std::cout << "Windows: cmake -B build && cmake --build build --config Release\n";
    std::cout << "macOS/Linux: cmake -B build && cmake --build build\n";
    std::cout << "Exit codes: 0 ok, 1 usage, 2 degraded, 3 exposed, 4 warning-threshold\n";
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
        } else if (arg == "-f") {
            opt.fast_flux_detection = true;
            add_query_type(opt, DNS_TYPE_A);
        } else if (arg == "-b") {
            opt.dns_rebinding_detection = true;
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
        } else if (arg == "--subdomains") {
            opt.scan_subdomains = true;
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
        print_usage();
        return 1;
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

    bool run_port_scan = !opt.port_scan_targets.empty() || !opt.port_scan_ports.empty();
    if (run_port_scan && (opt.port_scan_targets.empty() || opt.port_scan_ports.empty())) {
        std::cerr << "Port scan requires targets (-P) and ports (-R).\n";
        return 1;
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
                  opt.command == Command::Faults || opt.command == Command::Controls;
    if (phase1) {
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
            whitedns::core::ResolverEngine engine;
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
        whitedns::core::ResolverEngine engine;
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
        print_obs(engine.query(opt.domain, qtype, resolvers.front(), whitedns::core::TransportKind::Udp, opt.dnssec_readiness));
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
        if (opt.output_json || opt.format == "json") {
            std::cout << framework_audit_to_json(audit).toStyledString();
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
        if (audit.posture == "degraded" && (opt.fail_on == "degraded" || opt.fail_on == "warning")) return 2;
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
        SubdomainScanner scanner(opt.domain, opt.subdomain_candidates, opt.dns_server.empty() ? "8.8.8.8" : opt.dns_server);
        scanner.run();
        subdomain_results = scanner.results();
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

    if (opt.output_json) {
        std::cout << build_json_report(opt, responses, checks, subdomain_json, web_json, port_scan_json, firewall_json).toStyledString();
    } else {
        print_human_report(opt, responses, checks, subdomain_results, probe_results, asset_results, scan_results, firewall_json);
    }

    return 0;
}
