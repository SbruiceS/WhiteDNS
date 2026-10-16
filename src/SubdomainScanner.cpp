#include "whitedns/SubdomainScanner.h"
#include "whitedns/DnsClient.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <thread>

namespace whitedns {

namespace {

double label_entropy(const std::string& s) {
    std::map<char, int> f;
    for (char c : s) f[c]++;
    if (s.empty()) return 0;
    double h = 0;
    for (const auto& kv : f) {
        double p = static_cast<double>(kv.second) / static_cast<double>(s.size());
        h -= p * std::log2(p);
    }
    return h;
}

std::string random_label() {
    static const char* alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::mt19937 rng(0x57444e53);
    std::uniform_int_distribution<int> pick(0, 35);
    std::string out = "wdns";
    for (int i = 0; i < 12; ++i) out.push_back(alphabet[pick(rng)]);
    return out;
}

} // namespace

SubdomainScanner::SubdomainScanner(std::string domain,
                                   std::vector<std::string> candidates,
                                   std::string resolver,
                                   int timeout_ms,
                                   int workers)
    : domain_(std::move(domain)),
      candidates_(normalize_candidates(candidates)),
      resolver_(std::move(resolver)),
      timeout_ms_(timeout_ms),
      workers_(workers < 1 ? 1 : workers) {}

std::vector<std::string> SubdomainScanner::normalize_candidates(const std::vector<std::string>& candidates) const {
    if (!candidates.empty()) {
        return candidates;
    }
    return {"www", "api", "mail", "dev", "staging", "admin", "vpn", "login", "cdn", "static"};
}

void SubdomainScanner::probe_candidate(const std::string& candidate) {
    probe_at(candidate, domain_, 1);
}

void SubdomainScanner::probe_at(const std::string& candidate, const std::string& base, int depth) {
    DnsClient client{std::chrono::milliseconds(timeout_ms_)};
    SubdomainResult result;
    result.subdomain = candidate + "." + base;
    result.depth = depth;
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

std::vector<std::string> SubdomainScanner::short_prefixes() const {
    return {"www", "api", "dev", "staging", "admin", "vpn", "login", "cdn",
            "static", "mail", "app", "auth", "status", "internal", "test",
            "beta", "stage", "prod", "gateway", "service", "edge", "origin"};
}

void SubdomainScanner::run_recursive(int depth) {
    if (depth < 1) depth = 1;
    if (depth > 5) depth = 5;
    run();
    std::vector<std::string> parents;
    for (const auto& row : results_) {
        if (row.resolved && row.depth == 1) parents.push_back(row.subdomain);
        if (parents.size() >= 40) break;
    }
    auto prefixes = short_prefixes();
    for (int level = 2; level <= depth; ++level) {
        std::vector<std::string> next_parents;
        std::cout << "recursive  depth=" << level << " parents=" << parents.size() << "\n";
        for (const auto& parent : parents) {
            size_t before = results_.size();
            const int workers_n = workers_;
            std::mutex next_mu;
            size_t next = 0;
            std::vector<std::thread> workers;
            for (int i = 0; i < workers_n; ++i) {
                workers.emplace_back([&, parent]() {
                    while (true) {
                        size_t idx = 0;
                        {
                            std::lock_guard<std::mutex> lock(next_mu);
                            if (next >= prefixes.size()) return;
                            idx = next++;
                        }
                        probe_at(prefixes[idx], parent, level);
                    }
                });
            }
            for (auto& worker : workers)
                if (worker.joinable()) worker.join();
            for (size_t i = before; i < results_.size(); ++i) {
                if (results_[i].resolved) next_parents.push_back(results_[i].subdomain);
                if (next_parents.size() >= 40) break;
            }
        }
        parents = next_parents;
        if (parents.empty()) break;
    }
    std::stable_sort(results_.begin(), results_.end(), [](const SubdomainResult& a, const SubdomainResult& b) {
        if (a.resolved != b.resolved) return a.resolved && !b.resolved;
        if (a.depth != b.depth) return a.depth < b.depth;
        return label_entropy(a.subdomain) < label_entropy(b.subdomain);
    });
}

void SubdomainScanner::run() {
    DnsClient client{std::chrono::milliseconds(timeout_ms_)};
    std::string probe = random_label() + "." + domain_;
    DnsResponse wild = client.query(probe, resolver_, DNS_TYPE_A);
    bool wildcard = false;
    std::vector<std::string> wild_a;
    if (!wild.error) {
        for (const auto& r : wild.answers)
            if (r.type == DNS_TYPE_A) wild_a.push_back(r.value);
        wildcard = !wild_a.empty();
    }

    const int workers_n = workers_;
    std::mutex next_mu;
    std::mutex prog_mu;
    size_t next = 0;
    size_t done = 0;
    const size_t total = candidates_.size();
    std::vector<std::thread> workers;
    for (int i = 0; i < workers_n; ++i) {
        workers.emplace_back([&]() {
            while (true) {
                size_t idx = 0;
                {
                    std::lock_guard<std::mutex> lock(next_mu);
                    if (next >= candidates_.size()) return;
                    idx = next++;
                }
                probe_candidate(candidates_[idx]);
                size_t n = 0;
                {
                    std::lock_guard<std::mutex> lock(prog_mu);
                    n = ++done;
                }
                if (total >= 10000 && n % 5000 == 0) {
                    std::cout << "brute  done=" << n << "/" << total << "\n";
                }
            }
        });
    }
    for (auto& worker : workers)
        if (worker.joinable()) worker.join();

    if (wildcard) {
        for (auto& row : results_) {
            if (!row.resolved) continue;
            bool same = !row.addresses.empty();
            for (const auto& a : row.addresses) {
                if (std::find(wild_a.begin(), wild_a.end(), a) == wild_a.end()) {
                    same = false;
                    break;
                }
            }
            if (same) {
                row.resolved = false;
                row.error = "wildcard";
            }
        }
    }

    std::stable_sort(results_.begin(), results_.end(), [](const SubdomainResult& a, const SubdomainResult& b) {
        if (a.resolved != b.resolved) return a.resolved && !b.resolved;
        return label_entropy(a.subdomain) < label_entropy(b.subdomain);
    });
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
        item["depth"] = result.depth;
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
