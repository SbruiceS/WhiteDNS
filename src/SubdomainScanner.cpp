#include "whitedns/SubdomainScanner.h"
#include "whitedns/DnsClient.h"

#include <algorithm>
#include <mutex>
#include <thread>

namespace whitedns {

SubdomainScanner::SubdomainScanner(std::string domain,
                                   std::vector<std::string> candidates,
                                   std::string resolver,
                                   int timeout_ms)
    : domain_(std::move(domain)),
      candidates_(normalize_candidates(candidates)),
      resolver_(std::move(resolver)),
      timeout_ms_(timeout_ms) {}

std::vector<std::string> SubdomainScanner::normalize_candidates(const std::vector<std::string>& candidates) const {
    if (!candidates.empty()) {
        return candidates;
    }

    return {
        "www", "api", "mail", "ftp", "web", "dev", "staging", "admin",
        "portal", "ns", "secure", "git", "docs", "blog", "cdn", "static",
        "shop", "support", "test", "beta", "vpn", "api2", "m", "login",
        "smtp", "imap", "pop", "owa", "db", "graphql", "payments", "mobile",
        "app", "dashboard", "auth", "status", "assets", "media", "api-docs",
        "control", "gateway", "service", "mail2", "webmail", "email", "api3"
    };
}

void SubdomainScanner::probe_candidate(const std::string& candidate) {
    DnsClient client{std::chrono::milliseconds(timeout_ms_)};
    SubdomainResult result;
    result.subdomain = candidate + "." + domain_;

    auto collect_records = [&](uint16_t type) {
        DnsResponse response = client.query(result.subdomain, resolver_, type);
        if (response.error) {
            result.error = response.error_message;
            return;
        }

        for (const auto& record : response.answers) {
            if (record.type == type) {
                result.addresses.push_back(record.value);
                result.resolved = true;
            }
        }
    };

    collect_records(DNS_TYPE_A);
    collect_records(DNS_TYPE_AAAA);

    std::lock_guard<std::mutex> lock(results_mutex_);
    results_.push_back(std::move(result));
}

void SubdomainScanner::run() {
    std::vector<std::thread> workers;
    for (const auto& candidate : candidates_) {
        workers.emplace_back(&SubdomainScanner::probe_candidate, this, candidate);
    }
    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

const std::vector<SubdomainResult>& SubdomainScanner::results() const {
    return results_;
}

Json::Value SubdomainScanner::to_json() const {
    Json::Value array(Json::arrayValue);
    for (const auto& result : results_) {
        Json::Value item(Json::objectValue);
        item["subdomain"] = result.subdomain;
        item["resolved"] = result.resolved;
        item["error"] = result.error;
        Json::Value addresses(Json::arrayValue);
        for (const auto& address : result.addresses) {
            addresses.append(address);
        }
        item["addresses"] = addresses;
        array.append(item);
    }
    return array;
}

} // namespace whitedns
