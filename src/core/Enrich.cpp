#include "whitedns/core/Enrich.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/ResolverEngine.h"

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
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

std::string curl_text(const std::string& url) {
    std::string cmd = "curl -fsS -A \"WhiteDNS/2.0\" --max-time 20 \"" + url + "\" 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::string body;
    char buf[4096];
    while (fgets(buf, sizeof(buf), pipe)) body.append(buf);
    pclose(pipe);
    return body;
}

std::string home_dir() {
    if (const char* h = std::getenv("HOME")) return h;
    return ".";
}

} // namespace

void print_dot(const std::string& name, const std::string& endpoint) {
    std::cout << "WhiteDNS DoT (RFC 7858)  " << name << "\n";
    std::string host = endpoint.empty() ? "1.1.1.1" : endpoint;
    int port = 853;
    auto colon = host.rfind(':');
    if (colon != std::string::npos && host.find('.') != std::string::npos) {
        port = std::atoi(host.c_str() + colon + 1);
        host = host.substr(0, colon);
    }
    if (host.rfind("tls://", 0) == 0) host = host.substr(6);
#ifndef WHITEDNS_HAVE_OPENSSL
    std::cout << "dot=unavailable openssl not linked\n";
    return;
#else
#ifndef _WIN32
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { std::cout << "dot=fail ctx\n"; return; }
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        std::cout << "dot=fail resolve " << host << "\n";
        SSL_CTX_free(ctx);
        return;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        std::cout << "dot=fail connect " << host << ":" << port << "\n";
        if (fd >= 0) close(fd);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        return;
    }
    freeaddrinfo(res);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    if (SSL_connect(ssl) != 1) {
        std::cout << "dot=fail handshake " << host << "\n";
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        return;
    }
    std::cout << "tls=" << SSL_get_version(ssl) << " cipher=" << SSL_get_cipher(ssl) << "\n";
    ResolverEngine engine;
    auto obs = engine.query(name, DNS_TYPE_A, "8.8.8.8");
    std::vector<uint8_t> pkt;
    /* send a minimal query built from a fresh UDP-shaped packet is not available here;
       use the wire we already can build by re-querying via the TLS channel with a crafted query. */
    uint8_t q[] = {
        0x00, 0x1c,
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    std::vector<uint8_t> wire(q, q + sizeof(q));
    for (size_t i = 0; i < name.size();) {
        auto dot = name.find('.', i);
        size_t len = (dot == std::string::npos ? name.size() : dot) - i;
        wire.push_back(static_cast<uint8_t>(len));
        wire.insert(wire.end(), name.begin() + static_cast<long>(i), name.begin() + static_cast<long>(i + len));
        if (dot == std::string::npos) break;
        i = dot + 1;
    }
    wire.push_back(0);
    wire.push_back(0); wire.push_back(1);
    wire.push_back(0); wire.push_back(1);
    wire[0] = static_cast<uint8_t>(((wire.size() - 2) >> 8) & 0xff);
    wire[1] = static_cast<uint8_t>((wire.size() - 2) & 0xff);
    SSL_write(ssl, wire.data(), static_cast<int>(wire.size()));
    uint8_t lenb[2];
    if (SSL_read(ssl, lenb, 2) == 2) {
        int n = (lenb[0] << 8) | lenb[1];
        std::string body(static_cast<size_t>(n), '\0');
        int got = 0;
        while (got < n) {
            int r = SSL_read(ssl, &body[got], n - got);
            if (r <= 0) break;
            got += r;
        }
        std::cout << "dot ok bytes=" << got << " rcode=" << ((got > 3) ? (body[3] & 0x0f) : -1) << "\n";
    } else {
        std::cout << "dot=fail read\n";
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    (void)obs;
#else
    std::cout << "dot=unavailable on this build\n";
#endif
#endif
}

void print_rdap(const std::string& name) {
    std::cout << "WhiteDNS rdap  " << name << "\n";
    std::string body = curl_text("https://rdap.verisign.com/com/v1/domain/" + name);
    if (body.empty()) body = curl_text("https://rdap.org/domain/" + name);
    if (body.empty()) { std::cout << "rdap=fail\n"; return; }
    auto grab = [&](const std::string& key) {
        auto p = body.find("\"" + key + "\"");
        if (p == std::string::npos) return std::string{};
        auto q1 = body.find('"', body.find(':', p) + 1);
        auto q2 = body.find('"', q1 + 1);
        if (q1 == std::string::npos || q2 == std::string::npos) return std::string{};
        return body.substr(q1 + 1, q2 - q1 - 1);
    };
    std::cout << "ldhName=" << grab("ldhName") << "\n";
    std::cout << "status=" << grab("status") << "\n";
    auto ns = body.find("\"nameservers\"");
    std::cout << "nameservers=" << (ns == std::string::npos ? "absent" : "present") << "\n";
    std::cout << "bytes=" << body.size() << "\n";
}

void print_asn(const std::string& name) {
    std::cout << "WhiteDNS asn  " << name << "\n";
    ResolverEngine engine;
    auto a = engine.query(name, DNS_TYPE_A, "8.8.8.8");
    for (const auto& rec : a.message.answers) {
        if (rec.type != DNS_TYPE_A || rec.value.empty()) continue;
        std::string ip = rec.value;
        std::string rev;
        std::stringstream ss(ip);
        std::string oct;
        std::vector<std::string> parts;
        while (std::getline(ss, oct, '.')) parts.push_back(oct);
        for (int i = static_cast<int>(parts.size()) - 1; i >= 0; --i) {
            if (!rev.empty()) rev += ".";
            rev += parts[static_cast<size_t>(i)];
        }
        auto txt = engine.query(rev + ".origin.asn.cymru.com", DNS_TYPE_TXT, "8.8.8.8");
        std::cout << "  " << ip;
        for (const auto& t : txt.message.answers) if (t.type == DNS_TYPE_TXT) std::cout << " ASN " << t.value;
        if (txt.message.answers.empty()) std::cout << " ASN unknown";
        std::cout << "\n";
    }
}

void print_pcap(const std::string& path) {
    std::cout << "WhiteDNS pcap  " << path << "\n";
    std::ifstream in(path, std::ios::binary);
    if (!in) { std::cout << "pcap=fail open\n"; return; }
    char magic[4];
    in.read(magic, 4);
    bool le = magic[0] == '\xd4' && magic[1] == '\xc3';
    bool be = magic[0] == '\xa1' && magic[1] == '\xb2';
    if (!le && !be) { std::cout << "pcap=fail magic\n"; return; }
    in.seekg(24);
    int dns = 0, packets = 0;
    while (in) {
        char hdr[16];
        in.read(hdr, 16);
        if (in.gcount() < 16) break;
        uint32_t incl = le ? (static_cast<unsigned char>(hdr[8]) | (static_cast<unsigned char>(hdr[9]) << 8) |
                              (static_cast<unsigned char>(hdr[10]) << 16) | (static_cast<unsigned char>(hdr[11]) << 24))
                           : (static_cast<unsigned char>(hdr[11]) | (static_cast<unsigned char>(hdr[10]) << 8));
        std::string pkt(incl, '\0');
        in.read(&pkt[0], incl);
        packets++;
        if (incl > 42) {
            int sport = (static_cast<unsigned char>(pkt[34]) << 8) | static_cast<unsigned char>(pkt[35]);
            int dport = (static_cast<unsigned char>(pkt[36]) << 8) | static_cast<unsigned char>(pkt[37]);
            if (sport == 53 || dport == 53) dns++;
        }
    }
    std::cout << "packets=" << packets << " dns_udp_53=" << dns << "\n";
    std::cout << "rate baseline needs more than one capture. This count is one observation.\n";
}

void print_feeds2(const std::string& name, const std::string& local_file) {
    std::cout << "WhiteDNS feed2  " << name << "\n";
    std::string body;
    if (!local_file.empty()) {
        std::ifstream in(local_file);
        std::stringstream ss;
        ss << in.rdbuf();
        body = ss.str();
        std::cout << "source=local\n";
    } else {
        body = curl_text("https://urlhaus.abuse.ch/downloads/text_online/");
        std::cout << "source=urlhaus-online\n";
    }
    bool hit = !body.empty() && body.find(name) != std::string::npos;
    std::cout << "listed=" << (hit ? "yes" : "no") << " bytes=" << body.size() << "\n";
    std::string malware = curl_text("https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt");
    bool mhit = !malware.empty() && malware.find(name) != std::string::npos;
    std::cout << "feed3=malware-filter listed=" << (mhit ? "yes" : "no") << " bytes=" << malware.size() << "\n";
}

void save_history(const std::string& name, const std::string& json) {
    std::string dir = home_dir() + "/.whitedns/history";
    std::string mk = "mkdir -p \"" + dir + "\"";
    std::system(mk.c_str());
    std::string path = dir + "/" + name + ".json";
    std::ifstream prev(path);
    if (prev) {
        std::ofstream bak(dir + "/" + name + ".prev.json");
        bak << prev.rdbuf();
    }
    std::ofstream out(path);
    out << json;
    std::cerr << "history " << path << "\n";
}

void save_fields(const std::string& name, const std::string& fields) {
    std::string dir = home_dir() + "/.whitedns/history";
    std::system(("mkdir -p \"" + dir + "\"").c_str());
    std::string path = dir + "/" + name + ".fields";
    std::ifstream prev(path);
    if (prev) {
        std::ofstream bak(dir + "/" + name + ".fields.prev");
        bak << prev.rdbuf();
    }
    std::ofstream out(path);
    out << fields;
}

std::string last_history(const std::string& name) {
    return home_dir() + "/.whitedns/history/" + name + ".prev.json";
}

std::string last_fields(const std::string& name) {
    return home_dir() + "/.whitedns/history/" + name + ".fields.prev";
}

} // namespace core
} // namespace whitedns
