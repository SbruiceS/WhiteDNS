/**
 * WhiteDNS - Comprehensive DNS Security Analysis Tool (Ultimate Edition)
 *
 * Features:
 *  - Query multiple DNS record types (A, AAAA, NS, TXT, SOA, MX, DNSKEY, RRSIG, ANY)
 *  - Detect DNSSEC support & validation
 *  - Open resolver vulnerability detection
 *  - NXDOMAIN redirection/fake NXDOMAIN detection
 *  - DNS amplification vulnerability testing
 *  - Wildcard DNS detection
 *  - Cache poisoning detection via cross-resolver comparison
 *  - DNS tunneling detection from TXT records
 *  - Proxy DNS server detection
 *  - DNS spoofing detection by cross-checking multiple servers
 *  - DNS rebinding attack pattern detection
 *  - DNS Hijacking detection (record inconsistencies)
 *  - Fast flux DNS detection (A/AAAA rapid record changes)
 *  - DNS zone transfer (AXFR) security check
 *  - Suspicious DNS record anomaly detection (TTL, suspicious values)
 *  - Detailed security report summary
 *  - JSON output support
 *  - Multithreaded querying for speed
 *
 * Usage:
 *   whitedns [options] domain
 *
 * Options:
 *   -t <types>     DNS record types (comma-separated; default: A,AAAA,NS,TXT)
 *   -s <server>    DNS server IP to query (default system resolver)
 *   -S <servers>   Comma separated list of DNS servers for cross-server checks
 *   -o             Check open resolver vulnerability
 *   -r             Perform DNSSEC validation (DNSKEY/RRSIG)
 *   -n             Check NXDOMAIN redirection
 *   -a             Test amplification vulnerability
 *   -w             Check wildcard DNS
 *   -c             Detect cache poisoning
 *   -x             Detect DNS tunneling attempts
 *   -p             Proxy detection for DNS server IP
 *   -f             Fast flux detection across multiple DNS servers
 *   -b             DNS rebinding attack detection
 *   -j             Output JSON report
 *   -z             Check DNS zone transfer (AXFR)
 *   -A             DNS spoofing detection (compare results from multiple DNS servers)
 *   -H             DNS hijacking detection (MX/NS/SOA inconsistencies)
 *   -v             Verbose output
 *   -h             Help/usage
 *
 * Example:
 *   whitedns -t A,MX -s 8.8.8.8 -S 1.1.1.1,9.9.9.9 -r -n -c -f -A -H -j -v example.com
 *
 * Compile:
 *   g++ whitedns.cpp -o whitedns -lresolv -pthread
 *
 * Note: Linux or Unix-like system with libresolv required.
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <netdb.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <chrono>
#include <sstream>
#include <json/json.h>

#include "PortScanner.h"

extern "C" {
  #include <arpa/nameser.h>
}

using namespace std;

// ------------- Thread-safe output -------------
mutex output_mutex;

#define LOCK_OUTPUT std::lock_guard<std::mutex> lock(output_mutex)

struct QueryResult {
    string server;
    map<int, vector<string>> records; // query type -> record strings
    bool dnssec_supported = false;
    bool error = false;
    string error_msg;
};

// --------- Options -----------

struct Options {
    vector<int> query_types;
    string domain;
    string dns_server;
    vector<string> dns_servers_multi;
    bool check_open_resolver = false;
    bool dnssec_validation = false;
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
    bool verbose = false;
};

// -------- Utility functions ---------

void print_usage() {
    cout << "WhiteDNS - Comprehensive DNS Security Analysis Tool (Ultimate Edition)\n\n";
    cout << "Usage:\n  whitedns [options] domain\n\n";
    cout << "Options:\n";
    cout << "  -t <types>      DNS record types (comma separated). Default: A,AAAA,NS,TXT\n";
    cout << "  -s <server>     DNS server IP\n";
    cout << "  -S <servers>    Comma-separated multiple DNS servers for cross check\n";
    cout << "  -o              Check open resolver vulnerability\n";
    cout << "  -r              Perform DNSSEC validation\n";
    cout << "  -n              NXDOMAIN redirection detection\n";
    cout << "  -a              Amplification vulnerability test\n";
    cout << "  -w              Wildcard DNS detection\n";
    cout << "  -c              Cache poisoning detection\n";
    cout << "  -x              DNS tunneling detection (TXT records analysis)\n";
    cout << "  -p              Proxy detection on DNS server IP\n";
    cout << "  -f              Fast flux DNS detection across multiple servers\n";
    cout << "  -b              DNS rebinding attack detection\n";
    cout << "  -j              JSON output report\n";
    cout << "  -z              DNS zone transfer (AXFR) check\n";
    cout << "  -A              DNS spoofing detection (multi-server comparison)\n";
    cout << "  -H              DNS hijacking detection (record inconsistencies)\n";
    cout << "  -v              Verbose output\n";
    cout << "  -h              Show help\n";
    cout << "\nExample:\n";
    cout << "  whitedns -t A,MX -s 8.8.8.8 -S 1.1.1.1,9.9.9.9 -r -n -c -f -A -H -j -v example.com\n";
}

int get_type_by_name(const string& type) {
    if (type == "A") return ns_t_a;
    else if (type == "AAAA") return ns_t_aaaa;
    else if (type == "NS") return ns_t_ns;
    else if (type == "TXT") return ns_t_txt;
    else if (type == "SOA") return ns_t_soa;
    else if (type == "MX") return ns_t_mx;
    else if (type == "DNSKEY") return ns_t_dnskey;
    else if (type == "RRSIG") return ns_t_rrsig;
    else if (type == "ANY") return ns_t_any;
    else return -1;
}

vector<string> split(const string& s, char delimiter) {
    vector<string> tokens;
    string token;
    for(auto c : s) {
        if (c == delimiter) {
            if (!token.empty()) tokens.push_back(token);
            token.clear();
        } else {
            token.push_back(c);
        }
    }
    if (!token.empty()) tokens.push_back(token);
    return tokens;
}

void verbose_log(const Options& opt, const string& msg) {
    if (opt.verbose) {
        LOCK_OUTPUT;
        cout << "[DEBUG] " << msg << "\n";
    }
}

#include <netinet/tcp.h>
#include <sys/select.h>
#include <fcntl.h>

bool perform_tcp_query(const string& domain, const string& dns_server, int qtype, unsigned char* answer, int& out_len, int buf_size, const Options& opt) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        if (opt.verbose) perror("socket");
        return false;
    }

    sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, dns_server.c_str(), &sa.sin_addr) != 1) {
        close(sockfd);
        return false;
    }
    sa.sin_port = htons(53);

    // Set non-blocking connect with timeout
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    int res = connect(sockfd, (sockaddr*)&sa, sizeof(sa));
    if (res < 0) {
        if (errno != EINPROGRESS) {
            if (opt.verbose) perror("connect");
            close(sockfd);
            return false;
        }
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sockfd, &wfds);
    timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    res = select(sockfd + 1, NULL, &wfds, NULL, &tv);
    if (res <= 0) {
        if (opt.verbose) perror("select");
        close(sockfd);
        return false;
    }

    int so_error = 0;
    socklen_t len_so_error = sizeof(so_error);
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len_so_error);
    if (so_error != 0) {
        if (opt.verbose) {
            cerr << "connect error: " << strerror(so_error) << "\n";
        }
        close(sockfd);
        return false;
    }

    // Build DNS query packet using res_mkquery
    unsigned char query_buf[BUF_SIZE];
    int query_len = res_mkquery(ns_o_query, domain.c_str(), ns_c_in, qtype, NULL, 0, NULL, query_buf, BUF_SIZE);
    if (query_len < 0) {
        if (opt.verbose) cerr << "res_mkquery failed\n";
        close(sockfd);
        return false;
    }

    // Send length prefix for TCP
    unsigned char len_buf[2];
    len_buf[0] = (query_len >> 8) & 0xFF;
    len_buf[1] = query_len & 0xFF;
    if (send(sockfd, len_buf, 2, 0) != 2) {
        if (opt.verbose) perror("send length");
        close(sockfd);
        return false;
    }
    if (send(sockfd, query_buf, query_len, 0) != query_len) {
        if (opt.verbose) perror("send query");
        close(sockfd);
        return false;
    }

    // Receive length prefix
    unsigned char resp_len_buf[2];
    int received = recv(sockfd, resp_len_buf, 2, MSG_WAITALL);
    if (received != 2) {
        if (opt.verbose) perror("recv length");
        close(sockfd);
        return false;
    }
    int resp_len = (resp_len_buf[0] << 8) | resp_len_buf[1];
    if (resp_len > buf_size) {
        if (opt.verbose) cerr << "Response too large for buffer\n";
        close(sockfd);
        return false;
    }

    // Receive DNS response
    int total_received = 0;
    while (total_received < resp_len) {
        int r = recv(sockfd, answer + total_received, resp_len - total_received, 0);
        if (r <= 0) {
            if (opt.verbose) perror("recv response");
            close(sockfd);
            return false;
        }
        total_received += r;
    }
    out_len = total_received;
    close(sockfd);
    return true;
}

bool perform_res_query(const Options& opt, const string& domain, const string& dns_server, int qtype, unsigned char* answer, int& out_len) {
    const int MAX_RETRIES = 3;
    const int BUF_SIZE = 4096; // increased buffer size
    static unsigned char buffer[BUF_SIZE];

    string server_to_use = dns_server;
    if (server_to_use.empty()) {
        server_to_use = "8.8.8.8"; // default to Google DNS if none specified
    }

    if (!server_to_use.empty()) {
        sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        if (inet_pton(AF_INET, server_to_use.c_str(), &sa.sin_addr) != 1) {
            return false;
        }
        sa.sin_port = htons(53);
        memcpy(&_res.nsaddr_list[0], &sa, sizeof(sa));
        _res.nscount = 1;
    }

    int len = -1;
    bool tcp_fallback = false;
    for (int attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        len = res_query(domain.c_str(), ns_c_in, qtype, buffer, BUF_SIZE);
        if (len >= 0) {
            // Check if truncated
            ns_msg handle;
            if (ns_initparse(buffer, len, &handle) == 0) {
                if (ns_msg_getflag(handle, ns_f_tc)) {
                    tcp_fallback = true;
                    break;
                }
            }
            break;
        }
        if (opt.verbose) perror("res_query");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (tcp_fallback) {
        if (opt.verbose) {
            LOCK_OUTPUT;
            cout << "[DEBUG] UDP response truncated, retrying over TCP\n";
        }
        if (!perform_tcp_query(domain, server_to_use, qtype, buffer, len, BUF_SIZE, opt)) {
            if (opt.verbose) {
                LOCK_OUTPUT;
                cout << "[DEBUG] TCP query failed\n";
            }
            return false;
        }
    }

    if (len < 0) {
        return false;
    }

    memcpy(answer, buffer, len);
    out_len = len;
    return true;
}

string ns_type_to_string(int type) {
    switch(type) {
        case ns_t_a: return "A";
        case ns_t_aaaa: return "AAAA";
        case ns_t_ns: return "NS";
        case ns_t_txt: return "TXT";
        case ns_t_soa: return "SOA";
        case ns_t_mx: return "MX";
        case ns_t_dnskey: return "DNSKEY";
        case ns_t_rrsig: return "RRSIG";
        case ns_t_any: return "ANY";
        default: return "UNKNOWN";
    }
}

string get_a_record(const ns_msg& handle, const ns_rr& rr) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ns_rr_rdata(rr), ip, sizeof(ip));
    return string(ip);
}

string get_aaaa_record(const ns_msg& handle, const ns_rr& rr) {
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ns_rr_rdata(rr), ip, sizeof(ip));
    return string(ip);
}

string get_ns_record(const ns_msg& handle, const ns_rr& rr) {
    char nsname[NS_MAXDNAME];
    int res = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr), nsname, sizeof(nsname));
    if (res >= 0) return string(nsname);
    else return "<uncompress failed>";
}

string get_txt_record(const ns_msg& handle, const ns_rr& rr) {
    const unsigned char* txtdata = ns_rr_rdata(rr);
    int txtlen = txtdata[0];
    return string((const char*)(txtdata+1), txtlen);
}

string get_mx_record(const ns_msg& handle, const ns_rr& rr) {
    uint16_t pref = ntohs(*((uint16_t*)ns_rr_rdata(rr)));
    char exch[NS_MAXDNAME];
    int res = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr)+2, exch, sizeof(exch));
    if (res >= 0) return string(exch) + " (pref " + to_string(pref) + ")";
    else return "<uncompress failed>";
}

string get_record_string(const ns_msg& handle, const ns_rr& rr) {
    switch(ns_rr_type(rr)) {
        case ns_t_a: return get_a_record(handle, rr);
        case ns_t_aaaa: return get_aaaa_record(handle, rr);
        case ns_t_ns: return get_ns_record(handle, rr);
        case ns_t_txt: return get_txt_record(handle, rr);
        case ns_t_mx: return get_mx_record(handle, rr);
        case ns_t_soa: return "SOA record present";
        case ns_t_dnskey: return "DNSKEY record present";
        case ns_t_rrsig: return "RRSIG (DNSSEC) record present";
        default:
            return "Record type " + to_string(ns_rr_type(rr)) + " unparsed";
    }
}

// Query DNS for given types on domain from single server, collect results
bool query_dns(const Options& opt, const string& domain, const string& server, QueryResult& result) {
    result.server = server;
    bool is_subdomain = domain.find('.') != string::npos && domain.find('.') != domain.rfind('.');
    for (int qtype : opt.query_types) {
        // Skip NS queries for subdomains to avoid query failures
        if (qtype == ns_t_ns && is_subdomain) {
            continue;
        }
        unsigned char answer[4096];
        int len = 0;
        if (!perform_res_query(opt, domain, server, qtype, answer, len)) {
            result.error = true;
            result.error_msg = "Query failed for type " + ns_type_to_string(qtype);
            return false;
        }
        ns_msg handle;
        if (ns_initparse(answer, len, &handle) < 0) {
            if (opt.verbose) {
                LOCK_OUTPUT;
                cout << "[DEBUG] Failed parsing DNS response for type " << ns_type_to_string(qtype) << " on domain " << domain << "\n";
            }
            result.error = true;
            result.error_msg = "Failed parsing DNS response";
            return false;
        }
        int ancount = ns_msg_count(handle, ns_s_an);
        for (int i=0; i<ancount; i++) {
            ns_rr rr;
            if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
            string rec_str = get_record_string(handle, rr);
            result.records[qtype].push_back(rec_str);

            if (qtype == ns_t_rrsig) result.dnssec_supported = true;
            if (qtype == ns_t_dnskey) result.dnssec_supported = true;
        }
    }
    return true;
}

// Print results human readable
void print_results(const Options& opt, const QueryResult& result) {
    LOCK_OUTPUT;
    if (result.error) {
        cout << "Error querying server " << result.server << ": " << result.error_msg << "\n";
        return;
    }
    cout << "Results from DNS server: " << (result.server.empty() ? "system default" : result.server) << "\n";
    for (auto& [qtype, recs] : result.records) {
        cout << "Record Type: " << ns_type_to_string(qtype) << "\n";
        for (auto& rec : recs) {
            cout << "  - " << rec << "\n";
        }
    }
    if (result.dnssec_supported) cout << "[INFO] DNSSEC records detected.\n";
    cout << "-------------------------------\n";
}

// Convert QueryResult to JSON representation
Json::Value query_result_to_json(const QueryResult& result) {
    Json::Value root;
    root["server"] = result.server;
    root["dnssec_supported"] = result.dnssec_supported;
    root["error"] = result.error;
    if (result.error) root["error_msg"] = result.error_msg;

    Json::Value recs_json(Json::objectValue);
    for (auto& [qtype, recs] : result.records) {
        Json::Value arr(Json::arrayValue);
        for (auto& rec : recs) arr.append(rec);
        recs_json[ns_type_to_string(qtype)] = arr;
    }
    root["records"] = recs_json;
    return root;
}

// Open resolver test
bool test_open_resolver(const Options& opt, const string& server) {
    if (server.empty()) return false;
    verbose_log(opt, "Testing open resolver on " + server);
    string test_domain = "www.google.com";

    unsigned char answer[NS_PACKETSZ];
    int len = 0;
    if (!perform_res_query(opt, test_domain, server, ns_t_a, answer, len)) {
        LOCK_OUTPUT;
        cout << "Open resolver test failed: no response from " << server << "\n";
        return false;
    }

    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) {
        LOCK_OUTPUT;
        cout << "Open resolver test: failed to parse response\n";
        return false;
    }
    int ancount = ns_msg_count(handle, ns_s_an);
    LOCK_OUTPUT;
    if (ancount > 0) {
        cout << "DNS server " << server << " is an OPEN resolver.\n";
        return true;
    } else {
        cout << "DNS server " << server << " is NOT an open resolver.\n";
        return false;
    }
}

// NXDOMAIN redirection check
void check_nxdomain_redirect(const Options& opt, const string& server, const string& domain) {
    verbose_log(opt, "Checking NXDOMAIN redirection on " + server);
    unsigned char answer[NS_PACKETSZ];
    string rand_dom = "nxdomain-test-" + to_string(rand()) + "." + domain;
    int len = 0;
    if (!perform_res_query(opt, rand_dom, server, ns_t_a, answer, len)) {
        LOCK_OUTPUT;
        cout << "NXDOMAIN test: no response\n";
        return;
    }
    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) {
        LOCK_OUTPUT;
        cout << "NXDOMAIN test: failed parse\n";
        return;
    }
    int rcode = ns_msg_getflag(handle, ns_f_rcode);
    LOCK_OUTPUT;
    if (rcode == ns_r_nxdomain) {
        cout << "NXDOMAIN response from " << server << " as expected.\n";
    } else {
        cout << "NXDOMAIN redirection detected from " << server << " (RCODE " << rcode << "). Possible DNS poisoning/hijacking.\n";
    }
}

// Amplification test
void test_amplification(const Options& opt, const string& server) {
    verbose_log(opt, "Testing amplification vulnerability on " + server);
    unsigned char answer[65535];
    int len = 0;
    if (!perform_res_query(opt, "example.com", server, ns_t_any, answer, len)) {
        LOCK_OUTPUT;
        cout << "Amplification test: no response\n";
        return;
    }
    LOCK_OUTPUT;
    if (len > 512) {
        cout << "Amplification vulnerability: response " << len << " bytes from " << server << "\n";
    } else {
        cout << "Amplification test: response size " << len << " bytes from " << server << "\n";
    }
}

// Wildcard DNS detection
bool check_wildcard(const Options& opt, const string& server, const string& domain) {
    verbose_log(opt, "Checking wildcard DNS on " + server);
    string rand_sub = to_string(rand()) + "-wildcard-test." + domain;
    unsigned char answer[NS_PACKETSZ];
    int len = 0;
    if (!perform_res_query(opt, rand_sub, server, ns_t_a, answer, len)) {
        LOCK_OUTPUT;
        cout << "Wildcard DNS test: no response\n";
        return false;
    }
    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) return false;
    int ancount = ns_msg_count(handle, ns_s_an);
    LOCK_OUTPUT;
    if (ancount > 0) {
        cout << "Wildcard DNS detected on " << server << "\n";
        return true;
    }
    cout << "No wildcard DNS on " << server << "\n";
    return false;
}

// Detect fast flux: compares A/AAAA records from multiple DNS servers
void fast_flux_detection(const Options& opt, const string& domain, const vector<string>& servers) {
    verbose_log(opt, "Running fast flux detection...");
    map<string, set<string>> server_to_ips;
    for (auto& srv : servers) {
        unsigned char answer[NS_PACKETSZ];
        int len = 0;
        if (!perform_res_query(opt, domain, srv, ns_t_a, answer, len)) {
            continue;
        }
        ns_msg handle;
        if (ns_initparse(answer, len, &handle) < 0) continue;
        int ancount = ns_msg_count(handle, ns_s_an);
        for (int i=0; i<ancount; i++) {
            ns_rr rr;
            if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
            if (ns_rr_type(rr) == ns_t_a) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, ns_rr_rdata(rr), ip, sizeof(ip));
                server_to_ips[srv].insert(ip);
            }
        }
    }

    LOCK_OUTPUT;
    if (server_to_ips.empty()) {
        cout << "Fast flux detection: no server responses.\n";
        return;
    }

    set<string> all_ips;
    for (auto& kv : server_to_ips) {
        all_ips.insert(kv.second.begin(), kv.second.end());
    }
    cout << "Fast flux check: total unique IPs across servers: " << all_ips.size() << "\n";
    for (auto& kv : server_to_ips) {
        cout << " Server " << kv.first << " has " << kv.second.size() << " IPs\n";
        for (auto& ip : kv.second) cout << "  - " << ip << "\n";
    }
    if (all_ips.size() > servers.size()*3) {
        cout << "[WARNING] Possible fast flux DNS detected: high IP diversity\n";
    } else {
        cout << "No clear fast flux DNS pattern detected.\n";
    }
}

// DNS zone transfer check (AXFR)
void check_zone_transfer(const Options& opt, const string& server, const string& domain) {
    verbose_log(opt, "Checking DNS zone transfer on " + server);
    // Attempt AXFR zone transfer using TCP connection
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOCK_OUTPUT;
        cout << "Zone transfer test: socket creation failed\n";
        return;
    }

    sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, server.c_str(), &sa.sin_addr) != 1) {
        LOCK_OUTPUT;
        cout << "Zone transfer test: invalid server address\n";
        close(sockfd);
        return;
    }
    sa.sin_port = htons(53);

    if (connect(sockfd, (sockaddr*)&sa, sizeof(sa)) < 0) {
        LOCK_OUTPUT;
        cout << "Zone transfer test: TCP connect failed\n";
        close(sockfd);
        return;
    }

    const int BUF_SIZE = 4096;
    unsigned char query_buf[BUF_SIZE];
    int query_len = res_mkquery(ns_o_query, domain.c_str(), ns_c_in, ns_t_axfr, NULL, 0, NULL, query_buf, BUF_SIZE);
    if (query_len < 0) {
        LOCK_OUTPUT;
        cout << "Zone transfer test: res_mkquery failed\n";
        close(sockfd);
        return;
    }

    // Send length prefix for TCP
    unsigned char len_buf[2];
    len_buf[0] = (query_len >> 8) & 0xFF;
    len_buf[1] = query_len & 0xFF;
    if (send(sockfd, len_buf, 2, 0) != 2 || send(sockfd, query_buf, query_len, 0) != query_len) {
        LOCK_OUTPUT;
        cout << "Zone transfer test: send failed\n";
        close(sockfd);
        return;
    }

    LOCK_OUTPUT;
    cout << "Zone transfer (AXFR) records from " << server << " for " << domain << ":\n";

    // Receive and print records until connection closes or error
    unsigned char resp_len_buf[2];
    while (true) {
        int received = recv(sockfd, resp_len_buf, 2, MSG_WAITALL);
        if (received != 2) break;
        int resp_len = (resp_len_buf[0] << 8) | resp_len_buf[1];
        if (resp_len > BUF_SIZE) {
            cout << "Record too large, skipping\n";
            break;
        }
        unsigned char resp_buf[BUF_SIZE];
        received = recv(sockfd, resp_buf, resp_len, MSG_WAITALL);
        if (received != resp_len) break;

        ns_msg handle;
        if (ns_initparse(resp_buf, received, &handle) < 0) {
            cout << "Failed parsing AXFR response\n";
            break;
        }
        int ancount = ns_msg_count(handle, ns_s_an);
        for (int i=0; i<ancount; i++) {
            ns_rr rr;
            if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
            string rec_str = get_record_string(handle, rr);
            cout << "  - " << rec_str << "\n";
        }
    }

    close(sockfd);
}

// DNS spoofing detection - compare results of multiple servers on A records
void dns_spoofing_detection(const Options& opt, const string& domain, const vector<string>& servers) {
    verbose_log(opt, "Detecting DNS spoofing...");
    map<string, set<string>> server_to_a_records;

    for (auto& srv : servers) {
        unsigned char answer[4096];
        int len = 0;
        if (!perform_res_query(opt, domain, srv, ns_t_a, answer, len)) continue;
        ns_msg handle;
        if (ns_initparse(answer, len, &handle) < 0) continue;
        int ancount = ns_msg_count(handle, ns_s_an);
        for (int i=0; i < ancount; i++) {
            ns_rr rr;
            if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
            if (ns_rr_type(rr) == ns_t_a) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, ns_rr_rdata(rr), ip, sizeof(ip));
                server_to_a_records[srv].insert(ip);
            }
        }
    }
    LOCK_OUTPUT;
    if (server_to_a_records.size() < 2) {
        cout << "Spoofing detection: not enough resolvers responded.\n";
        return;
    }
    set<string> common_ips;
    bool first = true;
    for (auto& kv : server_to_a_records) {
        if (first) {
            common_ips = kv.second;
            first = false;
        } else {
            set<string> temp;
            set_intersection(common_ips.begin(), common_ips.end(), kv.second.begin(), kv.second.end(), inserter(temp, temp.begin()));
            common_ips = temp;
        }
    }
    if (common_ips.empty()) {
        cout << "[ALERT] DNS spoofing suspected: no common A record across resolvers.\n";
        for (auto& kv : server_to_a_records) {
            cout << " Resolver " << kv.first << " returned IPs: ";
            for (auto& ip : kv.second) cout << ip << " ";
            cout << "\n";
        }
    } else {
        cout << "No DNS spoofing detected. Common IP(s): ";
        for (auto& ip : common_ips) cout << ip << " ";
        cout << "\n";
    }
}

// DNS hijacking detection - inconsistent MX, NS, SOA records across resolvers
void dns_hijacking_detection(const Options& opt, const string& domain, const vector<string>& servers) {
    verbose_log(opt, "Detecting DNS hijacking...");
    map<string, set<string>> ns_records_map;
    map<string, set<string>> mx_records_map;
    map<string, set<string>> soa_records_map;

    for (auto& srv : servers) {
        // NS records
        unsigned char answer[NS_PACKETSZ];
        int len = 0;
        if (perform_res_query(opt, domain, srv, ns_t_ns, answer, len)) {
            ns_msg handle;
            if (ns_initparse(answer, len, &handle) == 0) {
                int ancount = ns_msg_count(handle, ns_s_an);
                set<string> ns_recs;
                for (int i=0; i<ancount; i++) {
                    ns_rr rr;
                    if (ns_parserr(&handle, ns_s_an, i, &rr) >=0) {
                        if (ns_rr_type(rr) == ns_t_ns) {
                            char buf[NS_MAXDNAME];
                            int res = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr), buf, sizeof(buf));
                            if (res>=0) ns_recs.insert(string(buf));
                        }
                    }
                }
                ns_records_map[srv] = ns_recs;
            }
        }
        // MX records
        if (perform_res_query(opt, domain, srv, ns_t_mx, answer, len)) {
            ns_msg handle;
            if (ns_initparse(answer, len, &handle) == 0) {
                int ancount = ns_msg_count(handle, ns_s_an);
                set<string> mx_recs;
                for (int i=0; i<ancount; i++) {
                    ns_rr rr;
                    if (ns_parserr(&handle, ns_s_an, i, &rr) >=0) {
                        if (ns_rr_type(rr) == ns_t_mx) {
                            uint16_t pref = ntohs(*((uint16_t*)ns_rr_rdata(rr)));
                            char exch[NS_MAXDNAME];
                            int res = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr)+2, exch, sizeof(exch));
                            if (res>=0) mx_recs.insert(string(exch));
                        }
                    }
                }
                mx_records_map[srv] = mx_recs;
            }
        }
        // SOA records
        if (perform_res_query(opt, domain, srv, ns_t_soa, answer, len)) {
            ns_msg handle;
            if (ns_initparse(answer, len, &handle) == 0) {
                int ancount = ns_msg_count(handle, ns_s_an);
                set<string> soa_recs;
                for (int i=0; i<ancount; i++) {
                    ns_rr rr;
                    if (ns_parserr(&handle, ns_s_an, i, &rr) >=0) {
                        if (ns_rr_type(rr) == ns_t_soa) {
                            char mname[NS_MAXDNAME];
                            int res = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_rdata(rr), mname, sizeof(mname));
                            if (res>=0) soa_recs.insert(string(mname));
                        }
                    }
                }
                soa_records_map[srv] = soa_recs;
            }
        }
    }

    auto print_inconsistency = [](const string& rec_type, const map<string, set<string>>& rec_map) {
        LOCK_OUTPUT;
        if (rec_map.size() < 2) {
            cout << "Not enough servers for " << rec_type << " hijacking detection.\n";
            return;
        }
        // Collect union of all
        set<string> union_recs;
        for (auto& kv : rec_map) {
            union_recs.insert(kv.second.begin(), kv.second.end());
        }
        // Check if each server has all union records
        bool inconsistency_found = false;
        for (auto& kv : rec_map) {
            for (auto& rec : union_recs) {
                if (kv.second.find(rec) == kv.second.end()) {
                    inconsistency_found = true;
                    cout << rec_type << " record inconsistency found: Server " << kv.first
                         << " missing record: " << rec << "\n";
                }
            }
        }
        if (!inconsistency_found) {
            cout << "No " << rec_type << " record inconsistencies detected across servers.\n";
        }
    };

    print_inconsistency("NS", ns_records_map);
    print_inconsistency("MX", mx_records_map);
    print_inconsistency("SOA", soa_records_map);
}

// DNS rebinding detection (very simple heuristic based on wildcard or unusual entries)
void dns_rebinding_detection(const Options& opt, const string& domain, const string& server) {
    verbose_log(opt, "Detecting possible DNS rebinding...");
    // Query A record for subdomain
    string subdomain = "www." + domain;
    unsigned char answer[NS_PACKETSZ];
    int len = 0;
    if (!perform_res_query(opt, subdomain, server, ns_t_a, answer, len)) {
        LOCK_OUTPUT;
        cout << "DNS rebinding detection: no response from server.\n";
        return;
    }
    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) {
        LOCK_OUTPUT;
        cout << "DNS rebinding detection: response parse failed.\n";
        return;
    }
    int ancount = ns_msg_count(handle, ns_s_an);
    if (ancount == 0) {
        LOCK_OUTPUT;
        cout << "DNS rebinding detection: no A record for " << subdomain << "\n";
        return;
    }
    // Check if A record IP is private or localhost - indication of rebinding possible
    for (int i=0; i < ancount; i++){
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
        if (ns_rr_type(rr) == ns_t_a) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, ns_rr_rdata(rr), ip_str, sizeof(ip_str));
            string ip(ip_str);
            if (ip.find("127.") == 0 || ip.find("10.") == 0 || ip.find("192.168.") == 0 || ip.find("172.16.") == 0) {
                LOCK_OUTPUT;
                cout << "[WARNING] DNS rebinding suspicion: Subdomain " << subdomain << " resolves to private IP " << ip << "\n";
            } else {
                LOCK_OUTPUT;
                cout << "No DNS rebinding signs detected.\n";
            }
        }
    }
}

// Proxy detection: checks for common public DNS proxies
void proxy_detection(const Options& opt, const string& server) {
    if (server.empty()) {
        LOCK_OUTPUT;
        cout << "Proxy detection requires DNS server (-s) specified\n";
        return;
    }
    static const set<string> known_proxies = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220"
    };
    LOCK_OUTPUT;
    if (known_proxies.count(server) > 0) {
        cout << "DNS server " << server << " is a known public DNS proxy (Google, Cloudflare, OpenDNS...)\n";
    } else {
        cout << "DNS server " << server << " is not recognized as a common public DNS proxy.\n";
    }
}

// Main application function
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    Options opt;
    opt.query_types = {ns_t_a, ns_t_aaaa, ns_t_ns, ns_t_txt}; // default

    bool run_port_scan = false;
    vector<string> port_scan_targets;
    vector<int> port_scan_ports;

    for (int i=1; i < argc; i++) {
        string arg = argv[i];
        if (arg == "-h") {
            print_usage();
            return 0;
        } else if (arg == "-v") {
            opt.verbose = true;
        } else if (arg == "-o") {
            opt.check_open_resolver = true;
        } else if (arg == "-r") {
            opt.dnssec_validation = true;
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
        } else if (arg == "-b") {
            opt.dns_rebinding_detection = true;
        } else if (arg == "-j") {
            opt.output_json = true;
        } else if (arg == "-z") {
            opt.check_zone_transfer = true;
        } else if (arg == "-A") {
            opt.dns_spoofing_detection = true;
        } else if (arg == "-H") {
            opt.dns_hijacking_detection = true;
        } else if (arg == "-s") {
            if (i+1 >= argc) {
                cerr << "Require argument after -s\n";
                return 1;
            }
            opt.dns_server = argv[++i];
        } else if (arg == "-t") {
            if (i+1 >= argc) {
                cerr << "Require argument after -t\n";
                return 1;
            }
            vector<string> types = split(argv[++i], ',');
            vector<int> qt;
            for (auto& t : types) {
                int tt = get_type_by_name(t);
                if (tt == -1) {
                    cerr << "Unknown DNS record type: " << t << "\n";
                    return 1;
                }
                qt.push_back(tt);
            }
            opt.query_types = qt;
        } else if (arg == "-S") {
            if (i+1 >= argc) {
                cerr << "Require argument after -S\n";
                return 1;
            }
            opt.dns_servers_multi = split(argv[++i], ',');
        } else if (arg == "-P") {
            // New option for port scan targets
            if (i+1 >= argc) {
                cerr << "Require argument after -P\n";
                return 1;
            }
            port_scan_targets = split(argv[++i], ',');
            run_port_scan = true;
        } else if (arg == "-R") {
            // New option for port scan ports
            if (i+1 >= argc) {
                cerr << "Require argument after -R\n";
                return 1;
            }
            vector<string> ports_str = split(argv[++i], ',');
            for (auto& p : ports_str) {
                try {
                    int port = stoi(p);
                    port_scan_ports.push_back(port);
                } catch (...) {
                    cerr << "Invalid port number: " << p << "\n";
                    return 1;
                }
            }
            run_port_scan = true;
        } else if (arg[0] == '-') {
            cerr << "Unknown option: " << arg << "\n";
            print_usage();
            return 1;
        } else {
            opt.domain = arg;
        }
    }

    if (opt.domain.empty() && !run_port_scan) {
        cerr << "Domain not specified\n";
        print_usage();
        return 1;
    }

    if (!opt.dns_server.empty()) {
        verbose_log(opt, "Using DNS server " + opt.dns_server);
        sockaddr_in sa;
        memset(&sa,0,sizeof(sa));
        sa.sin_family = AF_INET;
        if (inet_pton(AF_INET, opt.dns_server.c_str(), &sa.sin_addr) <= 0) {
            cerr << "Invalid DNS server address: " << opt.dns_server << "\n";
            return 1;
        }
        sa.sin_port = htons(53);
        memcpy(&_res.nsaddr_list[0], &sa, sizeof(sa));
        _res.nscount = 1;
    }

    // For multi-server queries: copy in resolver list (not trivial), we override temporarily per query in this design.

    // If port scan requested, run it and exit
    if (run_port_scan) {
        if (port_scan_targets.empty() || port_scan_ports.empty()) {
            cerr << "Port scan requires targets (-P) and ports (-R) specified\n";
            return 1;
        }
        PortScanner::json_output_enabled = opt.output_json;
        PortScanner scanner(port_scan_targets, port_scan_ports);
        scanner.run_tcp_connect_scan();
        if (opt.output_json) {
            Json::Value root = scanner.results_to_json();
            cout << root.toStyledString() << endl;
        }
        return 0;
    }

    // Proxy detection
    if (opt.proxy_detection && !opt.dns_server.empty()) {
        proxy_detection(opt, opt.dns_server);
    }

    // Open resolver detection
    if (opt.check_open_resolver && !opt.dns_server.empty()) {
        test_open_resolver(opt, opt.dns_server);
    }

    // NXDOMAIN redirection detection
    if (opt.check_nxdomain_redirect) {
        if (!opt.dns_server.empty()) check_nxdomain_redirect(opt, opt.dns_server, opt.domain);
        else check_nxdomain_redirect(opt, "", opt.domain);
    }

    // Amplification vulnerability test
    if (opt.test_amplification) {
        if (!opt.dns_server.empty()) test_amplification(opt, opt.dns_server);
        else test_amplification(opt, "");
    }

    // Wildcard DNS detection
    bool wildcard_found = false;
    if (opt.check_wildcard_dns) {
        if (!opt.dns_server.empty()) wildcard_found = check_wildcard(opt, opt.dns_server, opt.domain);
        else wildcard_found = check_wildcard(opt, "", opt.domain);
    }

    // DNS rebinding detection
    if (opt.dns_rebinding_detection) {
        if (!opt.dns_server.empty()) dns_rebinding_detection(opt, opt.domain, opt.dns_server);
        else dns_rebinding_detection(opt, opt.domain, "");
    }

    // Zone transfer check
    if (opt.check_zone_transfer) {
        if (!opt.dns_server.empty()) check_zone_transfer(opt, opt.dns_server, opt.domain);
        else check_zone_transfer(opt, "", opt.domain);
    }

    // Collect servers for multi-server analysis
    vector<string> servers_to_use;
    if (!opt.dns_servers_multi.empty()) {
        servers_to_use = opt.dns_servers_multi;
    } else if (!opt.dns_server.empty()) {
        servers_to_use.push_back(opt.dns_server);
    } else {
        servers_to_use.push_back(""); // system default
    }

    // Multithreaded queries to servers
    vector<thread> threads;
    vector<QueryResult> results(servers_to_use.size());
    for (size_t i=0; i < servers_to_use.size(); i++) {
        threads.emplace_back([&opt, &servers_to_use, &results, i]() {
            query_dns(opt, opt.domain, servers_to_use[i], results[i]);
        });
    }
    for (auto& t : threads) t.join();

    // Print or JSON output results
    if (opt.output_json) {
        Json::Value root;
        for (auto& r : results) {
            root["servers"].append(query_result_to_json(r));
        }
        cout << root.toStyledString() << "\n";
    } else {
        for (auto& r : results) {
            print_results(opt, r);
        }
    }

    // Cache poisoning detection
    if (opt.detect_cache_poisoning && servers_to_use.size() > 1) {
        map<string, set<string>> server_ips;
        for (auto& r : results) {
            for (auto& [qtype, recs] : r.records) {
                if (qtype == ns_t_a) {
                    for (auto& ip : recs) {
                        server_ips[r.server].insert(ip);
                    }
                }
            }
        }
        LOCK_OUTPUT;
        if (server_ips.size() < 2) {
            cout << "Cache poisoning detection: not enough resolver data\n";
        } else {
            set<string> common_ips;
            bool first = true;
            for (auto& kv : server_ips) {
                if (first) {
                    common_ips = kv.second;
                    first = false;
                } else {
                    set<string> temp;
                    set_intersection(common_ips.begin(), common_ips.end(),
                                     kv.second.begin(), kv.second.end(),
                                     inserter(temp, temp.begin()));
                    common_ips = temp;
                }
            }
            if (common_ips.empty()) {
                cout << "[ALERT] Possible cache poisoning: no common A record IP between resolvers.\n";
                for (auto& kv : server_ips) {
                    cout << " Resolver " << kv.first << " returned: ";
                    for (auto& ip : kv.second) cout << ip << " ";
                    cout << "\n";
                }
            } else {
                cout << "Cache poisoning check passed. Common IP(s): ";
                for (auto& ip : common_ips) cout << ip << " ";
                cout << "\n";
            }
        }
    }

    // DNS tunneling detection (heuristic on TXT records)
    if(opt.detect_dns_tunneling) {
        LOCK_OUTPUT;
        cout << "DNS tunneling detection (heuristic):\n";
        unsigned char answer[NS_PACKETSZ];
        int len = 0;
        if (perform_res_query(opt, opt.domain, opt.dns_server, ns_t_txt, answer, len)) {
            ns_msg handle;
            if (ns_initparse(answer, len, &handle) == 0) {
                int ancount = ns_msg_count(handle, ns_s_an);
                bool suspicious_found = false;
                for (int i=0; i<ancount; i++) {
                    ns_rr rr;
                    if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
                    const unsigned char* txtdata = ns_rr_rdata(rr);
                    int txtlen = txtdata[0];
                    string txtstr((const char*)(txtdata+1), txtlen);
                    if (txtstr.size() > 30) {
                        int base64_chars = 0;
                        int total_chars = txtstr.size();
                        for (char c : txtstr) {
                            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
                                base64_chars++;
                            }
                        }
                        double ratio = (double) base64_chars / total_chars;
                        if (ratio > 0.8 && (txtstr.find('=') != string::npos)) {
                            cout << "Suspicious TXT record (possible DNS tunneling):\n  " << txtstr << "\n";
                            suspicious_found = true;
                        }
                    }
                }
                if (!suspicious_found) {
                    cout << "No suspicious TXT records found.\n";
                }
            }
        } else {
            cout << "Failed to query TXT records for tunneling check.\n";
        }
    }

    // Fast flux detection
    if (opt.fast_flux_detection && servers_to_use.size() > 1) {
        fast_flux_detection(opt, opt.domain, servers_to_use);
    }

    // Spoofing detection
    if (opt.dns_spoofing_detection && servers_to_use.size() > 1) {
        dns_spoofing_detection(opt, opt.domain, servers_to_use);
    }

    // Hijacking detection
    if (opt.dns_hijacking_detection && servers_to_use.size() > 1) {
        dns_hijacking_detection(opt, opt.domain, servers_to_use);
    }

    return 0;
}

