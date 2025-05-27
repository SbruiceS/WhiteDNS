#ifndef PORTSCANNER_H
#define PORTSCANNER_H

#include <vector>
#include <string>
#include <json/json.h>

struct ScanResult {
    std::string ip;
    int port;
    std::string protocol;
    bool open;
};

class PortScanner {
public:
    PortScanner(const std::vector<std::string>& targets, const std::vector<int>& ports, int timeout_ms = 500);

    void run_tcp_connect_scan();

    const std::vector<ScanResult>& get_results() const;

    Json::Value results_to_json() const;

    static bool json_output_enabled;

private:
    void tcp_connect_scan(const std::string& ip, int port);
    void record_result(const std::string& ip, int port, const std::string& protocol, bool open);

    std::vector<std::string> targets_;
    std::vector<int> ports_;
    int timeout_ms_;
    std::vector<ScanResult> results_;
};

#endif // PORTSCANNER_H
