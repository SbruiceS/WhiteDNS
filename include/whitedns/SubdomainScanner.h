#ifndef WHITEDNS_SUBDOMAIN_SCANNER_H
#define WHITEDNS_SUBDOMAIN_SCANNER_H

#include <json/json.h>
#include <mutex>
#include <string>
#include <vector>

namespace whitedns {

struct SubdomainResult {
    std::string subdomain;
    bool resolved = false;
    std::vector<std::string> addresses;
    std::string error;
};

class SubdomainScanner {
public:
    SubdomainScanner(std::string domain,
                     std::vector<std::string> candidates,
                     std::string resolver = "8.8.8.8",
                     int timeout_ms = 2000);

    void run();
    const std::vector<SubdomainResult>& results() const;
    Json::Value to_json() const;

private:
    void probe_candidate(const std::string& candidate);
    std::vector<std::string> normalize_candidates(const std::vector<std::string>& candidates) const;

    std::string domain_;
    std::vector<std::string> candidates_;
    std::string resolver_;
    int timeout_ms_;
    std::vector<SubdomainResult> results_;
    std::mutex results_mutex_;
};

} // namespace whitedns

#endif // WHITEDNS_SUBDOMAIN_SCANNER_H
