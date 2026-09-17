#include "whitedns/core/Transport.h"

#include <chrono>
#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef MSG_WAITALL
#define MSG_WAITALL 0
#endif
using socket_t = SOCKET;
constexpr socket_t kInvalid = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t kInvalid = -1;
#endif

namespace whitedns {
namespace core {
namespace {

#ifdef _WIN32
struct WinsockOnce {
    WinsockOnce() {
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
    }
};
void ensure_sockets() { static WinsockOnce once; }
void close_sock(socket_t s) { closesocket(s); }
#else
void ensure_sockets() {}
void close_sock(socket_t s) { close(s); }
#endif

bool wait_sock(socket_t sock, bool write, std::chrono::milliseconds timeout) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    int n = select(static_cast<int>(sock + 1), write ? nullptr : &fds, write ? &fds : nullptr, nullptr, &tv);
    return n > 0 && FD_ISSET(sock, &fds);
}

} // namespace

const char* transport_name(TransportKind kind) {
    switch (kind) {
        case TransportKind::Udp: return "udp";
        case TransportKind::Tcp: return "tcp";
        case TransportKind::Tls: return "dot";
        case TransportKind::Https: return "doh";
    }
    return "unknown";
}

TransportResult UdpTransport::query(const std::string& server,
                                    uint16_t port,
                                    const std::vector<uint8_t>& packet,
                                    std::chrono::milliseconds timeout) {
    ensure_sockets();
    TransportResult out;
    out.kind = TransportKind::Udp;
    out.endpoint = server + ":" + std::to_string(port);
    auto start = std::chrono::steady_clock::now();

    addrinfo hints{};
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(server.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        out.error = "transport/resolve";
        return out;
    }
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        socket_t sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == kInvalid) continue;
        int sent = sendto(sock, reinterpret_cast<const char*>(packet.data()),
                          static_cast<int>(packet.size()), 0, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (sent != static_cast<int>(packet.size()) || !wait_sock(sock, false, timeout)) {
            close_sock(sock);
            continue;
        }
        std::vector<uint8_t> buf(4096);
        int n = recvfrom(sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0, nullptr, nullptr);
        close_sock(sock);
        if (n > 0) {
            buf.resize(static_cast<size_t>(n));
            out.ok = true;
            out.bytes = std::move(buf);
            out.rtt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
            freeaddrinfo(res);
            return out;
        }
    }
    freeaddrinfo(res);
    out.error = "transport/timeout";
    return out;
}

TransportResult TcpTransport::query(const std::string& server,
                                    uint16_t port,
                                    const std::vector<uint8_t>& packet,
                                    std::chrono::milliseconds timeout) {
    ensure_sockets();
    TransportResult out;
    out.kind = TransportKind::Tcp;
    out.endpoint = server + ":" + std::to_string(port);
    auto start = std::chrono::steady_clock::now();

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(server.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        out.error = "transport/resolve";
        return out;
    }
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        socket_t sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == kInvalid) continue;
        if (connect(sock, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) != 0) {
            close_sock(sock);
            continue;
        }
        uint8_t lenbuf[2] = {static_cast<uint8_t>(packet.size() >> 8), static_cast<uint8_t>(packet.size() & 0xff)};
        if (send(sock, reinterpret_cast<const char*>(lenbuf), 2, 0) != 2) {
            close_sock(sock);
            continue;
        }
        if (send(sock, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0) !=
            static_cast<int>(packet.size())) {
            close_sock(sock);
            continue;
        }
        if (!wait_sock(sock, false, timeout)) {
            close_sock(sock);
            continue;
        }
        uint8_t nlen[2];
        if (recv(sock, reinterpret_cast<char*>(nlen), 2, MSG_WAITALL) != 2) {
            close_sock(sock);
            continue;
        }
        uint16_t need = static_cast<uint16_t>((nlen[0] << 8) | nlen[1]);
        std::vector<uint8_t> buf(need);
        size_t got = 0;
        while (got < need) {
            if (!wait_sock(sock, false, timeout)) break;
            int n = recv(sock, reinterpret_cast<char*>(buf.data() + got), static_cast<int>(need - got), 0);
            if (n <= 0) break;
            got += static_cast<size_t>(n);
        }
        close_sock(sock);
        if (got == need) {
            out.ok = true;
            out.bytes = std::move(buf);
            out.rtt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
            freeaddrinfo(res);
            return out;
        }
    }
    freeaddrinfo(res);
    out.error = "transport/timeout";
    return out;
}

} // namespace core
} // namespace whitedns
