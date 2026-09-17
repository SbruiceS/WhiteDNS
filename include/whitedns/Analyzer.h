#ifndef WHITEDNS_ANALYZER_H
#define WHITEDNS_ANALYZER_H

#include "whitedns/DnsClient.h"

#include <json/json.h>
#include <string>
#include <vector>

namespace whitedns {

struct CheckResult {
    std::string name;
    std::string target;
    std::string status;
    std::string message;
    Json::Value details;
};

struct FirewallAssessment {
    int score = 0;
    std::string verdict;
    Json::Value signal_summary;
    Json::Value bypass_layers;
    Json::Value details;
};

CheckResult check_open_resolver(const DnsClient& client, const std::string& server);
CheckResult check_nxdomain_redirect(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_amplification(const DnsClient& client, const std::string& server);
CheckResult check_wildcard_dns(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_dnssec_readiness(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_zone_transfer(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_spf_dmarc(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_caa_policy(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_mta_sts(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_tlsa_policy(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_dnssec_chain(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_dns_tunneling(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_dns_rebinding(const DnsClient& client, const std::string& server, const std::string& domain);
CheckResult check_proxy_dns(const std::string& server);
CheckResult check_cache_poisoning(const std::vector<DnsResponse>& responses);
CheckResult check_dns_spoofing(const std::vector<DnsResponse>& responses);
CheckResult check_fast_flux(const std::vector<DnsResponse>& responses);
CheckResult check_dns_hijacking(const std::vector<DnsResponse>& responses);

Json::Value dns_response_to_json(const DnsResponse& response);
Json::Value check_result_to_json(const CheckResult& check);
FirewallAssessment assess_firewall_risk(const std::vector<CheckResult>& checks,
                                       const std::vector<DnsResponse>& responses,
                                       const Json::Value& web,
                                       const Json::Value& port_scan,
                                       const Json::Value& subdomains);
Json::Value firewall_assessment_to_json(const FirewallAssessment& assessment);

} // namespace whitedns

#endif // WHITEDNS_ANALYZER_H
