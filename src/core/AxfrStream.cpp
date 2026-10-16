#include "whitedns/core/AxfrStream.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t invalid_socket_value = -1;
#endif

namespace whitedns {
namespace core {

namespace {

// 64-bucket HyperLogLog. Fixed 64 bytes. Cardinality ~ 64 * 0.709 * 2^mean.
struct Hll64 {
    std::array<uint8_t, 64> rank{};
    void add(uint32_t h) {
        int bucket = h & 63;
        int zeros = 1;
        uint32_t v = h >> 6;
        while (v && (v & 1) == 0 && zeros < 31) { zeros++; v >>= 1; }
        if (rank[bucket] < zeros) rank[bucket] = static_cast<uint8_t>(zeros);
    }
    int estimate() const {
        double sum = 0;
        for (uint8_t r : rank) sum += std::ldexp(1.0, -r);
        if (sum <= 0) return 0;
        double e = 64.0 * 0.709 * 64.0 / sum;
        return static_cast<int>(e);
    }
};

bool is_cdn(const std::string& s) {
    static const char* marks[] = {"cloudfront", "akamai", "fastly", "cdn", "edgekey", "edgesuite", "azureedge", "cloudflare"};
    for (const char* m : marks)
        if (s.find(m) != std::string::npos) return true;
    return false;
}

// Keep the registrable-ish suffix. Millions of CNAMEs collapse to a few CDN keys.
std::string suffix_key(const std::string& s) {
    int dots = 0;
    for (int i = static_cast<int>(s.size()) - 1; i >= 0; --i) {
        if (s[i] == '.' && ++dots == 3) return s.substr(static_cast<size_t>(i + 1));
    }
    return s;
}

// Count-Min sketch. 4 rows x 32 counters. 512 bytes. Frequency of CNAME targets.
struct CountMin {
    std::array<std::array<uint32_t, 32>, 4> cell{};
    void add(uint32_t h) {
        for (int r = 0; r < 4; ++r) cell[r][(h >> (r * 5)) & 31]++;
    }
    uint32_t est(uint32_t h) const {
        uint32_t m = cell[0][h & 31];
        for (int r = 1; r < 4; ++r) m = std::min(m, cell[r][(h >> (r * 5)) & 31]);
        return m;
    }
};

// Addon compressor. RLE over the summary text. Fixed, no zone payload.
std::string compress_summary(const std::string& s, int& out_bytes) {
    std::string out;
    out.reserve(s.size() / 2 + 8);
    for (size_t i = 0; i < s.size();) {
        char c = s[i];
        size_t n = 1;
        while (i + n < s.size() && s[i + n] == c && n < 9) n++;
        if (n >= 3) { out.push_back('~'); out.push_back(static_cast<char>('0' + n)); out.push_back(c); }
        else out.append(n, c);
        i += n;
    }
    out_bytes = static_cast<int>(out.size());
    return out;
}

uint32_t hash32(const std::string& s) {
    uint32_t h = 2166136261u;
    for (unsigned char c : s) { h ^= c; h *= 16777619u; }
    return h;
}

bool recv_all(socket_t sock, uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = recv(sock, reinterpret_cast<char*>(buf + got), static_cast<int>(n - got), 0);
        if (r <= 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

std::string name_at(const uint8_t* pkt, size_t len, size_t& off) {
    std::string out;
    int hops = 0;
    while (off < len && hops++ < 16) {
        uint8_t lab = pkt[off];
        if ((lab & 0xc0) == 0xc0) {
            if (off + 1 >= len) break;
            size_t ptr = ((lab & 0x3f) << 8) | pkt[off + 1];
            off += 2;
            if (ptr >= len) break;
            size_t saved = off;
            off = ptr;
            std::string rest = name_at(pkt, len, off);
            off = saved;
            if (!out.empty() && !rest.empty()) out += ".";
            out += rest;
            return out;
        }
        if (lab == 0) { off++; break; }
        if (off + 1 + lab > len) break;
        if (!out.empty()) out += ".";
        out.append(reinterpret_cast<const char*>(pkt + off + 1), lab);
        off += 1 + lab;
    }
    return out;
}

} // namespace

AxfrReport stream_axfr(const std::string& qname, const std::string& server) {
    AxfrReport r;
    r.qname = qname;
    r.server = server.empty() ? "8.8.8.8" : server;
    auto wall0 = std::chrono::steady_clock::now();
    auto tool0 = wall0;

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* resolved = nullptr;
    if (getaddrinfo(r.server.c_str(), "53", &hints, &resolved) != 0) {
        r.note = "resolve failed";
        return r;
    }
    socket_t sock = invalid_socket_value;
    for (addrinfo* a = resolved; a; a = a->ai_next) {
        sock = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (sock == invalid_socket_value) continue;
        if (connect(sock, a->ai_addr, static_cast<int>(a->ai_addrlen)) == 0) break;
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        sock = invalid_socket_value;
    }
    freeaddrinfo(resolved);
    if (sock == invalid_socket_value) { r.note = "tcp connect failed"; return r; }

    // Minimal AXFR query. Streaming reader never stores the zone.
    std::string labels;
    for (size_t i = 0; i < qname.size();) {
        auto d = qname.find('.', i);
        size_t n = (d == std::string::npos ? qname.size() : d) - i;
        labels.push_back(static_cast<char>(n));
        labels.append(qname, i, n);
        if (d == std::string::npos) break;
        i = d + 1;
    }
    labels.push_back(0);
    std::vector<uint8_t> q;
    q.push_back(0x21); q.push_back(0x43);
    q.push_back(0x00); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x01);
    q.insert(q.end(), 6, 0);
    q.insert(q.end(), labels.begin(), labels.end());
    q.push_back(0); q.push_back(252); // AXFR
    q.push_back(0); q.push_back(1);
    uint16_t flen = htons(static_cast<uint16_t>(q.size()));
    send(sock, reinterpret_cast<const char*>(&flen), 2, 0);
    send(sock, reinterpret_cast<const char*>(q.data()), static_cast<int>(q.size()), 0);

    Hll64 names;
    CountMin cname_cm;
    std::map<std::string, int> cdn_suffix; // bounded: one entry per CDN suffix, not per CNAME
    int soa = 0;
    double recv_ms = 0;
    auto tool_acc = std::chrono::milliseconds{0};
    std::vector<uint8_t> pkt;
    pkt.reserve(65535);
    while (r.messages < 200000) {
        uint8_t lb[2];
        auto r0 = std::chrono::steady_clock::now();
        if (!recv_all(sock, lb, 2)) break;
        uint16_t n = static_cast<uint16_t>((lb[0] << 8) | lb[1]);
        if (n < 12 || n > 65535) break;
        pkt.resize(n);
        if (!recv_all(sock, pkt.data(), n)) break;
        recv_ms += std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - r0).count();
        auto t0 = std::chrono::steady_clock::now();
        r.messages++;
        r.peak_bytes = std::max(r.peak_bytes, static_cast<int>(n));
        uint16_t an = static_cast<uint16_t>((pkt[6] << 8) | pkt[7]);
        uint16_t rcode = pkt[3] & 0x0f;
        if (rcode == 5) { r.refused = true; r.note = "refused"; break; }
        size_t off = 12;
        name_at(pkt.data(), pkt.size(), off);
        off += 4;
        for (int i = 0; i < an && off + 10 < pkt.size(); ++i) {
            std::string owner = name_at(pkt.data(), pkt.size(), off);
            if (off + 10 > pkt.size()) break;
            uint16_t typ = static_cast<uint16_t>((pkt[off] << 8) | pkt[off + 1]);
            uint16_t rdlen = static_cast<uint16_t>((pkt[off + 8] << 8) | pkt[off + 9]);
            off += 10;
            if (off + rdlen > pkt.size()) break;
            r.records++;
            names.add(hash32(owner));
            if (typ == 6) soa++;
            if (typ == 5) {
                r.cname++;
                size_t save = off;
                std::string tgt = name_at(pkt.data(), pkt.size(), off);
                uint32_t th = hash32(tgt);
                cname_cm.add(th);
                names.add(th);
                if (is_cdn(tgt)) {
                    r.cdn_cname++;
                    if (cdn_suffix.size() < 64) cdn_suffix[suffix_key(tgt)]++;
                }
                off = save + rdlen;
            } else {
                off += rdlen;
            }
        }
        tool_acc += std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
        if (soa >= 2) { r.open = true; break; }
    }
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    r.unique_est = names.estimate();
    r.cname_targets = static_cast<int>(cdn_suffix.size());
    r.wall_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - wall0).count();
    r.tool_ms = static_cast<double>(tool_acc.count());
    r.recv_ms = recv_ms;
    std::ostringstream sum;
    sum << "records=" << r.records << " cname=" << r.cname << " cdn=" << r.cdn_cname;
    for (const auto& kv : cdn_suffix) sum << " " << kv.first << "=" << kv.second;
    int cbytes = 0;
    r.compressed = compress_summary(sum.str(), cbytes);
    r.compressed_bytes = cbytes;
    if (r.note.empty())
        r.note = r.open ? "zone streamed. summary only, zone not stored." : "no full zone. wall time is the TCP transfer, not tool time.";
    return r;
}

void print_axfr(const AxfrReport& r) {
    std::cout << "WhiteDNS axfr  " << r.qname << " @" << r.server << "\n";
    std::cout << "open=" << (r.open ? "yes" : "no") << " refused=" << (r.refused ? "yes" : "no") << "\n";
    std::cout << "messages=" << r.messages << " records=" << r.records
              << " unique_est=" << r.unique_est << " peak_bytes=" << r.peak_bytes << "\n";
    std::cout << "cname=" << r.cname << " cdn_cname=" << r.cdn_cname
              << " cdn_suffixes=" << r.cname_targets << "\n";
    std::cout << "wall_ms=" << r.wall_ms << " recv_ms=" << r.recv_ms << " tool_ms=" << r.tool_ms << "\n";
    std::cout << "sketch=HLL-64+CountMin-4x32. compressor_bytes=" << r.compressed_bytes << "\n";
    std::cout << "compressed " << r.compressed << "\n";
    std::cout << r.note << "\n";
    std::cout << "Authorized secondaries only. RFC 5936. Public AXFR is a finding, not a goal.\n";
}

} // namespace core
} // namespace whitedns
