#include "whitedns/core/DohClient.h"

#include <cctype>
#include <cstdlib>
#include <sstream>
#include <vector>

#ifdef WHITEDNS_HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace whitedns {
namespace core {
namespace {

std::string url_encode(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '.' || c == '-' || c == '_') out << c;
        else {
            out << '%';
            out << "0123456789ABCDEF"[c >> 4];
            out << "0123456789ABCDEF"[c & 15];
        }
    }
    return out.str();
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<uint8_t> parse_hex(const std::string& hex) {
    std::vector<uint8_t> out;
    std::string h;
    for (char c : hex) {
        if (std::isxdigit(static_cast<unsigned char>(c))) h.push_back(c);
    }
    if (h.size() % 2) return {};
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        int hi = hex_nibble(h[i]);
        int lo = hex_nibble(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::vector<uint8_t> b64_decode(const std::string& in) {
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    std::vector<uint8_t> out;
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (c == '=' || c == ' ' || c == '\n') continue;
        if (T[c] < 0) continue;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<uint8_t>((val >> bits) & 0xff));
            bits -= 8;
        }
    }
    return out;
}

std::vector<std::string> split_ws(const std::string& s) {
    std::istringstream in(s);
    std::vector<std::string> parts;
    std::string p;
    while (in >> p) parts.push_back(p);
    return parts;
}

DnsRecord record_from_doh(int type, int ttl, const std::string& data) {
    DnsRecord rec;
    rec.type = static_cast<uint16_t>(type);
    rec.type_name = dns_type_to_string(rec.type);
    rec.ttl = static_cast<uint32_t>(ttl);
    rec.value = data;
    auto parts = split_ws(data);
    try {
        if (type == DNS_TYPE_DS && parts.size() >= 4) {
            uint16_t tag = static_cast<uint16_t>(std::stoi(parts[0]));
            uint8_t alg = static_cast<uint8_t>(std::stoi(parts[1]));
            uint8_t dt = static_cast<uint8_t>(std::stoi(parts[2]));
            auto digest = parse_hex(parts[3]);
            rec.rdata.push_back(static_cast<uint8_t>(tag >> 8));
            rec.rdata.push_back(static_cast<uint8_t>(tag & 0xff));
            rec.rdata.push_back(alg);
            rec.rdata.push_back(dt);
            rec.rdata.insert(rec.rdata.end(), digest.begin(), digest.end());
        } else if (type == DNS_TYPE_DNSKEY && parts.size() >= 4) {
            uint16_t flags = static_cast<uint16_t>(std::stoi(parts[0]));
            uint8_t proto = static_cast<uint8_t>(std::stoi(parts[1]));
            uint8_t alg = static_cast<uint8_t>(std::stoi(parts[2]));
            auto key = b64_decode(parts[3]);
            rec.rdata.push_back(static_cast<uint8_t>(flags >> 8));
            rec.rdata.push_back(static_cast<uint8_t>(flags & 0xff));
            rec.rdata.push_back(proto);
            rec.rdata.push_back(alg);
            rec.rdata.insert(rec.rdata.end(), key.begin(), key.end());
        }
    } catch (...) {
    }
    return rec;
}

#ifdef WHITEDNS_HAVE_OPENSSL
#ifndef _WIN32
std::string https_get(const std::string& host, const std::string& path) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), "443", &hints, &res) != 0) return {};
    int sock = -1;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) return {};

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        close(sock);
        return {};
    }
    SSL* ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return {};
    }
    std::ostringstream req;
    req << "GET " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "Accept: application/dns-json\r\n"
        << "User-Agent: WhiteDNS/2.0\r\n"
        << "Connection: close\r\n\r\n";
    std::string r = req.str();
    SSL_write(ssl, r.data(), static_cast<int>(r.size()));
    std::string buf;
    char chunk[2048];
    for (int i = 0; i < 64; ++i) {
        int n = SSL_read(ssl, chunk, sizeof(chunk));
        if (n <= 0) break;
        buf.append(chunk, static_cast<size_t>(n));
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    auto pos = buf.find("\r\n\r\n");
    if (pos == std::string::npos) return {};
    return buf.substr(pos + 4);
}
#else
std::string https_get(const std::string&, const std::string&) { return {}; }
#endif
#else
std::string https_get(const std::string&, const std::string&) { return {}; }
#endif

} // namespace

DohQueryResult doh_lookup(const std::string& qname, uint16_t qtype) {
    DohQueryResult out;
    const char* type_name = "A";
    if (qtype == DNS_TYPE_DS) type_name = "DS";
    else if (qtype == DNS_TYPE_DNSKEY) type_name = "DNSKEY";
    else if (qtype == DNS_TYPE_RRSIG) type_name = "RRSIG";
    else if (qtype == DNS_TYPE_NS) type_name = "NS";
    else if (qtype == DNS_TYPE_SOA) type_name = "SOA";
    else if (qtype == DNS_TYPE_AAAA) type_name = "AAAA";
    else if (qtype == DNS_TYPE_MX) type_name = "MX";
    else if (qtype == DNS_TYPE_TXT) type_name = "TXT";
    else if (qtype == DNS_TYPE_CAA) type_name = "CAA";

    struct Ep { const char* host; const char* path_prefix; };
    Ep endpoints[] = {
        {"dns.google", "/resolve?name="},
        {"cloudflare-dns.com", "/dns-query?name="},
    };

    for (const auto& ep : endpoints) {
        std::string path = std::string(ep.path_prefix) + url_encode(qname) + "&type=" + type_name;
        out.endpoint = std::string("https://") + ep.host + path;
        std::string body = https_get(ep.host, path);
        if (body.empty()) {
            out.error = "doh/empty";
            continue;
        }
        auto find_int = [&](const std::string& key) -> int {
            auto p = body.find("\"" + key + "\"");
            if (p == std::string::npos) return -1;
            p = body.find(':', p);
            if (p == std::string::npos) return -1;
            return std::atoi(body.c_str() + p + 1);
        };
        out.status = find_int("Status");
        size_t cursor = 0;
        while (true) {
            auto type_at = body.find("\"type\"", cursor);
            if (type_at == std::string::npos) break;
            int t = std::atoi(body.c_str() + body.find(':', type_at) + 1);
            auto ttl_at = body.find("\"TTL\"", type_at);
            int ttl = 0;
            if (ttl_at != std::string::npos && ttl_at < type_at + 120)
                ttl = std::atoi(body.c_str() + body.find(':', ttl_at) + 1);
            auto data_at = body.find("\"data\"", type_at);
            std::string data;
            if (data_at != std::string::npos && data_at < type_at + 200) {
                auto q1 = body.find('"', body.find(':', data_at) + 1);
                auto q2 = body.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos)
                    data = body.substr(q1 + 1, q2 - q1 - 1);
            }
            if (t > 0 && !data.empty()) out.records.push_back(record_from_doh(t, ttl, data));
            cursor = type_at + 6;
        }
        out.ok = true;
        out.error.clear();
        if (!out.records.empty() || out.status == 0) return out;
    }
    return out;
}

} // namespace core
} // namespace whitedns
