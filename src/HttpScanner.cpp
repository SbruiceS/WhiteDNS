#include "whitedns/HttpScanner.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "Ws2_32.lib")
using socket_t = SOCKET;
constexpr socket_t invalid_socket_value = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
using socket_t = int;
constexpr socket_t invalid_socket_value = -1;
#endif

#include <algorithm>
#include <chrono>
#include <cctype>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>

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

bool is_alpha_digit(char c) {
    return std::isalnum(static_cast<unsigned char>(c));
}

std::string lowercase(std::string input) {
    std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return input;
}

bool wait_for_socket(socket_t sock, bool write, std::chrono::milliseconds timeout) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

    int result = select(static_cast<int>(sock + 1), write ? nullptr : &fds, write ? &fds : nullptr, nullptr, &tv);
    return result > 0 && FD_ISSET(sock, &fds);
}

std::string socket_error_message(const std::string& prefix) {
#ifdef _WIN32
    return prefix + ": socket error " + std::to_string(WSAGetLastError());
#else
    return prefix + ": " + std::strerror(errno);
#endif
}

std::string serialize_headers(const std::map<std::string, std::string>& headers) {
    std::ostringstream result;
    for (const auto& header : headers) {
        result << header.first << ": " << header.second << "\n";
    }
    return result.str();
}

#ifdef _WIN32
std::wstring utf8_to_wstring(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), &wstr[0], size_needed);
    return wstr;
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &utf8[0], size_needed, nullptr, nullptr);
    return utf8;
}

std::string winhttp_query_header(HINTERNET request, DWORD info_level) {
    DWORD size = 0;
    WinHttpQueryHeaders(request, info_level, WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return "";
    }
    std::wstring buffer(size / sizeof(wchar_t), 0);
    if (!WinHttpQueryHeaders(request, info_level, WINHTTP_HEADER_NAME_BY_INDEX, &buffer[0], &size, WINHTTP_NO_HEADER_INDEX)) {
        return "";
    }
    return wstring_to_utf8(buffer);
}
#endif

std::string build_redirect_url(const std::string& scheme,
                               const std::string& host,
                               int port,
                               const std::string& location) {
    if (location.rfind("http://", 0) == 0 || location.rfind("https://", 0) == 0) {
        return location;
    }

    std::ostringstream target;
    target << scheme << "://" << host;
    if ((scheme == "http" && port != 80) || (scheme == "https" && port != 443)) {
        target << ":" << port;
    }
    if (location.empty() || location[0] != '/') {
        target << "/" << location;
    } else {
        target << location;
    }
    return target.str();
}
} // namespace

HttpScanner::HttpScanner(std::vector<std::string> urls,
                         std::vector<std::string> asset_paths,
                         bool fetch_body,
                         bool follow_redirects,
                         int timeout_ms)
    : urls_(std::move(urls)),
      asset_paths_(std::move(asset_paths)),
      fetch_body_(fetch_body),
      follow_redirects_(follow_redirects),
      timeout_ms_(timeout_ms) {}

bool HttpScanner::parse_url(const std::string& url,
                            std::string& scheme,
                            std::string& host,
                            int& port,
                            std::string& path) const {
    std::string normalized = url;
    if (normalized.rfind("http://", 0) == 0) {
        scheme = "http";
        normalized.erase(0, 7);
        port = 80;
    } else if (normalized.rfind("https://", 0) == 0) {
        scheme = "https";
        normalized.erase(0, 8);
        port = 443;
    } else {
        scheme = "http";
        port = 80;
    }

    size_t path_start = normalized.find('/');
    path = path_start == std::string::npos ? "/" : normalized.substr(path_start);
    host = path_start == std::string::npos ? normalized : normalized.substr(0, path_start);

    if (host.empty()) {
        return false;
    }

    size_t colon = host.find(':');
    if (colon != std::string::npos) {
        std::string port_text = host.substr(colon + 1);
        host = host.substr(0, colon);
        try {
            port = std::stoi(port_text);
        } catch (...) {
            return false;
        }
    }

    if (host.empty() || !is_alpha_digit(host[0])) {
        return false;
    }

    return true;
}

#ifndef _WIN32
#ifdef WHITEDNS_HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

HttpProbeResult HttpScanner::probe_https_url(const std::string& url) {
    socket_runtime();
    HttpProbeResult result;
    result.url = url;
    if (!parse_url(url, result.scheme, result.host, result.port, result.path)) {
        result.error = "invalid URL";
        return result;
    }

#ifndef WHITEDNS_HAVE_OPENSSL
    result.error = "HTTPS probe requires OpenSSL on this platform";
    return result;
#else
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* resolved = nullptr;
    if (getaddrinfo(result.host.c_str(), std::to_string(result.port).c_str(), &hints, &resolved) != 0) {
        result.error = "failed to resolve host";
        return result;
    }

    socket_t sock = invalid_socket_value;
    for (addrinfo* addr = resolved; addr != nullptr; addr = addr->ai_next) {
        sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock == invalid_socket_value) continue;
        if (connect(sock, addr->ai_addr, static_cast<int>(addr->ai_addrlen)) == 0) break;
        close_socket(sock);
        sock = invalid_socket_value;
    }
    freeaddrinfo(resolved);
    if (sock == invalid_socket_value) {
        result.error = "TLS TCP connect failed";
        return result;
    }
    result.tls_port_open = true;

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        close_socket(sock);
        result.error = "SSL_CTX_new failed";
        return result;
    }
    SSL_CTX_set_default_verify_paths(ctx);
    SSL* ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, result.host.c_str());
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        result.error = "TLS handshake failed";
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close_socket(sock);
        return result;
    }

    std::ostringstream request;
    request << "GET " << result.path << " HTTP/1.1\r\n"
            << "Host: " << result.host << "\r\n"
            << "User-Agent: WhiteDNS-Enterprise/1.0\r\n"
            << "Connection: close\r\n\r\n";
    std::string req = request.str();
    SSL_write(ssl, req.data(), static_cast<int>(req.size()));

    std::string buffer;
    char chunk[2048];
    for (int i = 0; i < 32; ++i) {
        int n = SSL_read(ssl, chunk, sizeof(chunk));
        if (n <= 0) break;
        buffer.append(chunk, static_cast<size_t>(n));
        if (buffer.size() > 8192) break;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close_socket(sock);

    if (buffer.empty()) {
        result.error = "empty HTTPS response";
        return result;
    }
    result.reachable = true;
    std::istringstream status_stream(buffer.substr(0, buffer.find('\n')));
    std::string http_version;
    status_stream >> http_version >> result.status_code;

    size_t header_end = buffer.find("\r\n\r\n");
    size_t header_start = buffer.find("\r\n");
    if (header_end != std::string::npos && header_start != std::string::npos) {
        std::istringstream header_stream(buffer.substr(header_start + 2, header_end - header_start - 2));
        std::string line;
        while (std::getline(header_stream, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::string name = lowercase(line.substr(0, colon));
            std::string value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(value.begin());
            result.headers[name] = value;
            if (name == "server") result.server_header = value;
            if (name == "location") result.location = value;
        }
    }
    if (fetch_body_ && header_end != std::string::npos) {
        result.body_preview = buffer.substr(header_end + 4, 512);
    }
    return result;
#endif
}
#endif

#ifdef _WIN32
HttpProbeResult HttpScanner::probe_https_url(const std::string& url) {
    socket_runtime();

    HttpProbeResult result;
    result.url = url;
    if (!parse_url(url, result.scheme, result.host, result.port, result.path)) {
        result.error = "invalid URL";
        return result;
    }

    HINTERNET session = WinHttpOpen(
        utf8_to_wstring("WhiteDNS-Enterprise/1.0").c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!session) {
        result.error = "WinHTTP session failed";
        return result;
    }

    HINTERNET connect = WinHttpConnect(
        session,
        utf8_to_wstring(result.host).c_str(),
        static_cast<INTERNET_PORT>(result.port),
        0);
    if (!connect) {
        result.error = "WinHTTP connect failed";
        WinHttpCloseHandle(session);
        return result;
    }

    HINTERNET request = WinHttpOpenRequest(
        connect,
        L"GET",
        utf8_to_wstring(result.path).c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!request) {
        result.error = "WinHTTP request initialization failed";
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return result;
    }

    BOOL sent = WinHttpSendRequest(request,
                                   WINHTTP_NO_ADDITIONAL_HEADERS,
                                   0,
                                   WINHTTP_NO_REQUEST_DATA,
                                   0,
                                   0,
                                   0);
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        result.error = "WinHTTP request failed";
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return result;
    }

    result.reachable = true;
    result.tls_port_open = true;

    DWORD status_size = sizeof(DWORD);
    DWORD status_code = 0;
    if (WinHttpQueryHeaders(request,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &status_code,
                            &status_size,
                            WINHTTP_NO_HEADER_INDEX)) {
        result.status_code = static_cast<int>(status_code);
    }

    std::string raw_headers = winhttp_query_header(request, WINHTTP_QUERY_RAW_HEADERS_CRLF);
    std::istringstream header_stream(raw_headers);
    std::string line;
    while (std::getline(header_stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(":");
        if (colon == std::string::npos) continue;
        std::string name = lowercase(line.substr(0, colon));
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.erase(value.begin());
        }
        result.headers[name] = value;
        if (name == "server") result.server_header = value;
        if (name == "location") result.location = value;
    }

    if (fetch_body_ && result.status_code != 0) {
        DWORD bytes_available = 0;
        while (WinHttpQueryDataAvailable(request, &bytes_available) && bytes_available > 0) {
            std::vector<char> buffer(bytes_available + 1);
            DWORD bytes_read = 0;
            if (!WinHttpReadData(request, buffer.data(), bytes_available, &bytes_read) || bytes_read == 0) {
                break;
            }
            result.body_preview.append(buffer.data(), bytes_read);
            if (result.body_preview.size() >= 512) {
                result.body_preview.resize(512);
                break;
            }
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return result;
}
#endif

HttpProbeResult HttpScanner::probe_url(const std::string& url) {
    socket_runtime();

    HttpProbeResult result;
    result.url = url;

    std::string scheme;
    int port = 0;
    std::string path;
    if (!parse_url(url, scheme, result.host, port, path)) {
        result.error = "invalid URL";
        return result;
    }

    if (scheme == "https") {
        return probe_https_url(url);
    }

    std::string current_url = url;
    int redirects = 0;

    while (true) {
        if (!parse_url(current_url, result.scheme, result.host, result.port, result.path)) {
            result.error = "invalid URL";
            return result;
        }

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* resolved = nullptr;
        if (getaddrinfo(result.host.c_str(), std::to_string(result.port).c_str(), &hints, &resolved) != 0) {
            result.error = "failed to resolve host";
            return result;
        }

        std::string last_error;
        bool request_sent = false;
        bool buffer_ready = false;
        std::string buffer;

        for (addrinfo* addr = resolved; addr != nullptr; addr = addr->ai_next) {
            socket_t sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            if (sock == invalid_socket_value) {
                continue;
            }

            bool connected = false;
            if (connect(sock, addr->ai_addr, static_cast<int>(addr->ai_addrlen)) == 0) {
                connected = true;
            } else if (wait_for_socket(sock, true, std::chrono::milliseconds(timeout_ms_))) {
                connected = true;
            }

            if (!connected) {
                last_error = socket_error_message("connection failed");
                close_socket(sock);
                continue;
            }

            result.reachable = true;
            if (result.scheme == "https") {
                result.tls_port_open = true;
                close_socket(sock);
                freeaddrinfo(resolved);
                return result;
            }

            std::ostringstream request;
            request << "GET " << result.path << " HTTP/1.1\r\n"
                    << "Host: " << result.host << "\r\n"
                    << "User-Agent: WhiteDNS-Enterprise/1.0\r\n"
                    << "Connection: close\r\n\r\n";
            std::string request_text = request.str();
            if (send(sock, request_text.c_str(), static_cast<int>(request_text.size()), 0) < 0) {
                last_error = socket_error_message("send failed");
                close_socket(sock);
                continue;
            }

            request_sent = true;
            buffer.reserve(4096);
            char chunk[1024];
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms_);
            while (std::chrono::steady_clock::now() < deadline) {
                if (!wait_for_socket(sock, false, std::chrono::milliseconds(100))) {
                    continue;
                }
                int count = recv(sock, chunk, static_cast<int>(sizeof(chunk)), 0);
                if (count <= 0) break;
                buffer.append(chunk, static_cast<size_t>(count));
                if (buffer.find("\r\n\r\n") != std::string::npos) {
                    buffer_ready = true;
                    break;
                }
            }

            close_socket(sock);
            if (!buffer.empty()) {
                buffer_ready = true;
                break;
            }
            last_error = "no HTTP response";
        }

        freeaddrinfo(resolved);

        if (!buffer_ready) {
            result.error = last_error.empty() ? "connection failed" : last_error;
            return result;
        }

        size_t status_end = buffer.find('\n');
        if (status_end == std::string::npos) {
            result.error = "invalid HTTP status line";
            return result;
        }

        std::string status_line = buffer.substr(0, status_end);
        std::istringstream status_stream(status_line);
        std::string http_version;
        status_stream >> http_version >> result.status_code;

        size_t header_start = buffer.find("\r\n") + 2;
        size_t header_end = buffer.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            std::istringstream header_stream(buffer.substr(header_start, header_end - header_start));
            std::string line;
            while (std::getline(header_stream, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                size_t colon = line.find(':');
                if (colon != std::string::npos) {
                    std::string name = lowercase(line.substr(0, colon));
                    std::string value = line.substr(colon + 1);
                    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
                        value.erase(value.begin());
                    }
                    result.headers[name] = value;
                    if (name == "server") result.server_header = value;
                    if (name == "location") result.location = value;
                }
            }
        }

        if (fetch_body_) {
            size_t body_start = header_end == std::string::npos ? buffer.size() : header_end + 4;
            if (body_start < buffer.size()) {
                result.body_preview = buffer.substr(body_start, 512);
            }
        }

        if (follow_redirects_ && (result.status_code == 301 || result.status_code == 302 ||
                                  result.status_code == 303 || result.status_code == 307 ||
                                  result.status_code == 308) && !result.location.empty() &&
            redirects < 5) {
            redirects += 1;
            result.redirect_count = redirects;
            current_url = build_redirect_url(result.scheme, result.host, result.port, result.location);
            result.url = current_url;
            result.location.clear();
            result.headers.clear();
            result.body_preview.clear();
            result.status_code = 0;
            continue;
        }

        return result;
    }
}

WebAssetResult HttpScanner::probe_asset(const std::string& base_url, const std::string& asset_path) {
    WebAssetResult result;
    result.url = normalize_path(base_url, asset_path);
    result.reachable = false;
    result.status_code = 0;

    auto probe = probe_url(result.url);
    result.reachable = probe.reachable;
    result.status_code = probe.status_code;
    result.server_header = probe.server_header;
    result.error = probe.error;
    return result;
}

std::string HttpScanner::normalize_path(const std::string& prefix, const std::string& asset_path) const {
    std::string normalized = prefix;
    if (!asset_path.empty() && asset_path.front() != '/') {
        normalized.push_back('/');
    }
    normalized += asset_path;
    return normalized;
}

void HttpScanner::run() {
    if (urls_.empty()) {
        return;
    }

    std::vector<std::thread> threads;
    for (const auto& url : urls_) {
        threads.emplace_back([this, url]() {
            HttpProbeResult probe = probe_url(url);
            std::lock_guard<std::mutex> lock(results_mutex_);
            probe_results_.push_back(std::move(probe));
        });
    }

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    if (!asset_paths_.empty()) {
        std::vector<std::thread> asset_threads;
        for (const auto& url : urls_) {
            for (const auto& path : asset_paths_) {
                asset_threads.emplace_back([this, url, path]() {
                    WebAssetResult result = probe_asset(url, path);
                    std::lock_guard<std::mutex> lock(results_mutex_);
                    asset_results_.push_back(std::move(result));
                });
            }
        }
        for (auto& thread : asset_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }
}

const std::vector<HttpProbeResult>& HttpScanner::probes() const {
    return probe_results_;
}

const std::vector<WebAssetResult>& HttpScanner::assets() const {
    return asset_results_;
}

Json::Value HttpScanner::to_json() const {
    Json::Value root(Json::objectValue);
    Json::Value probes(Json::arrayValue);
    for (const auto& probe : probe_results_) {
        Json::Value item(Json::objectValue);
        item["url"] = probe.url;
        item["scheme"] = probe.scheme;
        item["host"] = probe.host;
        item["port"] = probe.port;
        item["path"] = probe.path;
        item["reachable"] = probe.reachable;
        item["tls_port_open"] = probe.tls_port_open;
        item["status_code"] = probe.status_code;
        item["server"] = probe.server_header;
        item["location"] = probe.location;
        item["error"] = probe.error;

        Json::Value headers(Json::objectValue);
        for (const auto& header : probe.headers) {
            headers[header.first] = header.second;
        }
        item["headers"] = headers;
        probes.append(item);
    }
    root["probes"] = probes;

    Json::Value assets(Json::arrayValue);
    for (const auto& asset : asset_results_) {
        Json::Value item(Json::objectValue);
        item["url"] = asset.url;
        item["reachable"] = asset.reachable;
        item["status_code"] = asset.status_code;
        item["server"] = asset.server_header;
        item["error"] = asset.error;
        assets.append(item);
    }
    root["assets"] = assets;
    return root;
}

} // namespace whitedns
