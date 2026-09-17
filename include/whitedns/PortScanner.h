#ifndef WHITEDNS_PORT_SCANNER_H
#define WHITEDNS_PORT_SCANNER_H

#include <json/json.h>
#include <mutex>
#include <string>
#include <vector>

namespace whitedns {

struct ScanResult {
    std::string target;
    int port = 0;
    std::string protocol = "TCP";
    bool open = false;
    std::string error;
};

class PortScanner {
public:
    PortScanner(std::vector<std::string> targets, std::vector<int> ports, int timeout_ms = 500);

    void run_tcp_connect_scan();
    const std::vector<ScanResult>& results() const;
    Json::Value to_json() const;

private:
    void tcp_connect_scan(const std::string& target, int port);
    void record_result(ScanResult result);

    std::vector<std::string> targets_;
    std::vector<int> ports_;
    int timeout_ms_;
    std::vector<ScanResult> results_;
    std::mutex results_mutex_;
};

} // namespace whitedns

#endif // WHITEDNS_PORT_SCANNER_H
