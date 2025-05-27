#include "PortScanner.h"
#include <iostream>
#include <thread>
#include <mutex>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <cstring>

using namespace std;

extern std::mutex output_mutex;

PortScanner::PortScanner(const vector<string>& targets, const vector<int>& ports, int timeout_ms)
    : targets_(targets), ports_(ports), timeout_ms_(timeout_ms) {}

void PortScanner::run_tcp_connect_scan() {
    vector<thread> threads;
    for (const auto& ip : targets_) {
        for (int port : ports_) {
            threads.emplace_back(&PortScanner::tcp_connect_scan, this, ip, port);
        }
    }
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
}

const vector<ScanResult>& PortScanner::get_results() const {
    return results_;
}

void PortScanner::tcp_connect_scan(const string& ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    fd_set fdset;
    timeval tv;
    tv.tv_sec = timeout_ms_ / 1000;
    tv.tv_usec = (timeout_ms_ % 1000) * 1000;

    int res = connect(sock, (sockaddr*)&addr, sizeof(addr));
    if (res == 0) {
        record_result(ip, port, "TCP", true);
        close(sock);
        return;
    } else if (errno != EINPROGRESS) {
        close(sock);
        record_result(ip, port, "TCP", false);
        return;
    }

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    res = select(sock + 1, NULL, &fdset, NULL, &tv);
    if (res > 0) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            record_result(ip, port, "TCP", true);
        } else {
            record_result(ip, port, "TCP", false);
        }
    } else {
        record_result(ip, port, "TCP", false);
    }
    close(sock);
}

#include <json/json.h>

void PortScanner::record_result(const string& ip, int port, const string& protocol, bool open) {
    lock_guard<mutex> lock(output_mutex);
    results_.push_back({ip, port, protocol, open});
    if (!json_output_enabled) {
        cout << ip << ":" << port << " " << protocol << " " << (open ? "open" : "closed") << endl;
    }
}

bool PortScanner::json_output_enabled = false;

Json::Value PortScanner::results_to_json() const {
    Json::Value root(Json::arrayValue);
    for (const auto& res : results_) {
        Json::Value obj;
        obj["ip"] = res.ip;
        obj["port"] = res.port;
        obj["protocol"] = res.protocol;
        obj["open"] = res.open;
        root.append(obj);
    }
    return root;
}
