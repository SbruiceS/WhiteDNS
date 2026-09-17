#include "whitedns/PortScanner.h"

#include <thread>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
constexpr socket_t invalid_socket_value = INVALID_SOCKET;
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t invalid_socket_value = -1;
#endif

namespace whitedns {
namespace {

class SocketRuntime {
public:
    SocketRuntime() {
#ifdef _WIN32
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
#endif
    }

    ~SocketRuntime() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

SocketRuntime& socket_runtime() {
    static SocketRuntime runtime;
    return runtime;
}

void close_socket(socket_t sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

bool set_nonblocking(socket_t sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    return flags >= 0 && fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

bool connect_in_progress() {
#ifdef _WIN32
    int error = WSAGetLastError();
    return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
    return errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EAGAIN;
#endif
}

std::string socket_error() {
#ifdef _WIN32
    return "socket error " + std::to_string(WSAGetLastError());
#else
    return std::strerror(errno);
#endif
}

bool wait_for_connect(socket_t sock, int timeout_ms, bool& open) {
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);

    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ready = select(static_cast<int>(sock + 1), nullptr, &write_set, nullptr, &tv);
    if (ready <= 0 || !FD_ISSET(sock, &write_set)) {
        open = false;
        return true;
    }

    int socket_error_value = 0;
#ifdef _WIN32
    int len = sizeof(socket_error_value);
#else
    socklen_t len = sizeof(socket_error_value);
#endif
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error_value), &len) != 0) {
        open = false;
        return false;
    }

    open = socket_error_value == 0;
    return true;
}

} // namespace

PortScanner::PortScanner(std::vector<std::string> targets, std::vector<int> ports, int timeout_ms)
    : targets_(std::move(targets)), ports_(std::move(ports)), timeout_ms_(timeout_ms) {}

void PortScanner::run_tcp_connect_scan() {
    std::vector<std::thread> threads;
    for (const auto& target : targets_) {
        for (int port : ports_) {
            threads.emplace_back(&PortScanner::tcp_connect_scan, this, target, port);
        }
    }
    for (auto& thread : threads) {
        if (thread.joinable()) thread.join();
    }
}

const std::vector<ScanResult>& PortScanner::results() const {
    return results_;
}

void PortScanner::tcp_connect_scan(const std::string& target, int port) {
    socket_runtime();

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* resolved = nullptr;
    std::string port_text = std::to_string(port);
    if (getaddrinfo(target.c_str(), port_text.c_str(), &hints, &resolved) != 0) {
        record_result({target, port, "TCP", false, "failed to resolve target"});
        return;
    }

    std::string last_error;
    for (addrinfo* addr = resolved; addr != nullptr; addr = addr->ai_next) {
        socket_t sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock == invalid_socket_value) continue;

        if (!set_nonblocking(sock)) {
            last_error = "failed to set non-blocking mode";
            close_socket(sock);
            continue;
        }

        int result = connect(sock, addr->ai_addr, static_cast<int>(addr->ai_addrlen));
        if (result == 0) {
            close_socket(sock);
            freeaddrinfo(resolved);
            record_result({target, port, "TCP", true, ""});
            return;
        }

        if (!connect_in_progress()) {
            last_error = socket_error();
            close_socket(sock);
            continue;
        }

        bool open = false;
        bool known = wait_for_connect(sock, timeout_ms_, open);
        close_socket(sock);
        if (known && open) {
            freeaddrinfo(resolved);
            record_result({target, port, "TCP", true, ""});
            return;
        }
        last_error = known ? "closed or timed out" : socket_error();
    }

    freeaddrinfo(resolved);
    record_result({target, port, "TCP", false, last_error});
}

void PortScanner::record_result(ScanResult result) {
    std::lock_guard<std::mutex> lock(results_mutex_);
    results_.push_back(std::move(result));
}

Json::Value PortScanner::to_json() const {
    Json::Value root(Json::arrayValue);
    for (const auto& result : results_) {
        Json::Value item(Json::objectValue);
        item["target"] = result.target;
        item["port"] = result.port;
        item["protocol"] = result.protocol;
        item["open"] = result.open;
        item["error"] = result.error;
        root.append(item);
    }
    return root;
}

} // namespace whitedns
