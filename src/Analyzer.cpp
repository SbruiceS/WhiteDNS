#include "whitedns/Analyzer.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <map>
#include <set>
#include <sstream>

namespace whitedns {
namespace {

CheckResult make_check(const std::string& name,
                       const std::string& target,
                       const std::string& status,
                       const std::string& message) {
    CheckResult result;
    result.name = name;
    result.target = target;
    result.status = status;
    result.message = message;
    result.details = Json::Value(Json::objectValue);
    return result;
}

std::set<std::string> values_for_type(const std::vector<DnsResponse>& responses, uint16_t type) {
    std::set<std::string> values;
    for (const auto& response : responses) {
        if (response.query_type != type || response.error) continue;
        for (const auto& record : response.answers) {
            if (record.type == type) values.insert(record.value);
        }
    }
    return values;
}

std::map<std::string, std::set<std::string>> server_values_for_type(const std::vector<DnsResponse>& responses, uint16_t type) {
    std::map<std::string, std::set<std::string>> values;
    for (const auto& response : responses) {
        if (response.query_type != type || response.error) continue;
        for (const auto& record : response.answers) {
            if (record.type == type) values[response.server].insert(record.value);
        }
    }
    return values;
}

std::set<std::string> intersection_of(const std::map<std::string, std::set<std::string>>& server_values) {
    std::set<std::string> common;
    bool first = true;
    for (const auto& item : server_values) {
        if (first) {
            common = item.second;
            first = false;
            continue;
        }
        std::set<std::string> temp;
        std::set_intersection(common.begin(), common.end(), item.second.begin(), item.second.end(), std::inserter(temp, temp.begin()));
        common = temp;
    }
    return common;
}

bool is_private_ipv4(const std::string& ip) {
    int a = 0;
    int b = 0;
    int c = 0;
    int d = 0;
    char dot1 = 0;
    char dot2 = 0;
    char dot3 = 0;
    std::istringstream stream(ip);
    if (!(stream >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d)) return false;
    if (dot1 != '.' || dot2 != '.' || dot3 != '.') return false;
    return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || a == 127 || (a == 169 && b == 254);
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool looks_like_known_txt_administration(const std::string& value) {
    std::string lowered = lowercase(value);
    static const std::vector<std::string> known_markers = {
        "v=spf1", "v=dmarc1", "google-site-verification", "domain-verification",
        "facebook-domain-verification", "ms-domain-verification", "docusign=",
        "atlassian-domain-verification", "zoom-domain-verification", "d365mktkey=",
        "v=mcpv1", "apple-domain-verification", "openai-domain-verification"
    };
    return std::any_of(known_markers.begin(), known_markers.end(), [&](const std::string& marker) {
        return lowered.find(marker) != std::string::npos;
    });
}

bool looks_like_dns_tunnel_txt(const std::string& value) {
    if (value.size() < 120 || looks_like_known_txt_administration(value)) return false;

    int encoded_chars = 0;
    int separators = 0;
    for (char item : value) {
        unsigned char c = static_cast<unsigned char>(item);
        if (std::isalnum(c) || item == '+' || item == '/' || item == '=' || item == '_' || item == '-') {
            ++encoded_chars;
        }
        if (item == '.' || item == ' ' || item == ';' || item == ':') {
            ++separators;
        }
    }

    double ratio = value.empty() ? 0.0 : static_cast<double>(encoded_chars) / static_cast<double>(value.size());
    return ratio > 0.92 && separators <= 2;
}

std::string extract_domain_apex(const std::string& domain) {
    std::vector<std::string> labels;
    std::istringstream stream(domain);
    std::string label;
    while (std::getline(stream, label, '.')) {
        if (!label.empty()) labels.push_back(label);
    }

    if (labels.size() < 2) return domain;
    return labels[labels.size() - 2] + "." + labels[labels.size() - 1];
}

const CheckResult* find_check(const std::vector<CheckResult>& checks, const std::string& name) {
    for (const auto& check : checks) {
        if (check.name == name) return &check;
    }
    return nullptr;
}

bool header_present(const Json::Value& probe, const std::string& key) {
    return probe.isObject() && !probe[key].asString().empty();
}

Json::Value make_firewall_layer(const std::string& layer,
                                const std::string& status,
                                const std::string& message,
                                int risk_points = 0) {
    Json::Value item(Json::objectValue);
    item["layer"] = layer;
    item["status"] = status;
    item["message"] = message;
    item["risk_points"] = risk_points;
    return item;
}

std::vector<int> open_port_list(const Json::Value& port_scan) {
    std::vector<int> ports;
    if (!port_scan.isArray()) return ports;
    for (const auto& result : port_scan) {
        if (result["open"].asBool()) ports.push_back(result["port"].asInt());
    }
    return ports;
}

bool has_sensitive_asset(const Json::Value& assets) {
    if (!assets.isArray()) return false;
    for (const auto& asset : assets) {
        std::string url = asset["url"].asString();
        int code = asset["status_code"].asInt();
        if (code >= 200 && code < 300) {
            if (url.find(".env") != std::string::npos || url.find(".git") != std::string::npos ||
                url.find("config.php") != std::string::npos || url.find("wp-login.php") != std::string::npos ||
                url.find("backup.zip") != std::string::npos || url.find("server-status") != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

bool has_security_policy_file(const Json::Value& assets) {
    if (!assets.isArray()) return false;
    for (const auto& asset : assets) {
        std::string url = asset["url"].asString();
        int code = asset["status_code"].asInt();
        if (code == 200 && (url.find("security.txt") != std::string::npos || url.find("robots.txt") != std::string::npos)) {
            return true;
        }
    }
    return false;
}

std::vector<std::string> waf_names() {
    return {
        "cloudflare", "akamai", "sucuri", "f5", "imperva", "barracuda", "modsecurity", "aws", "fastly",
        "edgecast", "incapsula", "protect"};
}

bool has_waf_header(const Json::Value& probe) {
    if (!probe.isObject()) return false;
    std::string server = probe["server"].asString();
    std::string via = probe["headers"]["via"].asString();
    std::string x_cd = probe["headers"]["x-cdn"].asString();
    for (const auto& name : waf_names()) {
        if (server.find(name) != std::string::npos || via.find(name) != std::string::npos || x_cd.find(name) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string normalize_layer_status(const std::string& status) {
    if (status == "critical" || status == "warning" || status == "pass" || status == "info") return status;
    return "info";
}

int layer_risk_points(const std::string& status) {
    if (status == "critical") return 15;
    if (status == "warning") return 7;
    if (status == "info") return 2;
    return 0;
}

std::string readable_layer_name(const std::string& name) {
    std::string result = name;
    if (result.empty()) return result;
    result[0] = static_cast<char>(std::toupper(result[0]));
    return result;
}

std::string build_layer_message(const std::string& base, const std::string& status, const std::string& fallback) {
    if (!base.empty()) return base;
    return fallback;
}

std::string probe_scheme(const Json::Value& probe) {
    return probe.isObject() ? probe["scheme"].asString() : "";
}

std::string probe_path(const Json::Value& probe) {
    return probe.isObject() ? probe["path"].asString() : "";
}

std::string probe_location(const Json::Value& probe) {
    return probe.isObject() ? probe["location"].asString() : "";
}

std::string probe_server_header(const Json::Value& probe) {
    return probe.isObject() ? probe["server"].asString() : "";
}

std::string probe_status_code(const Json::Value& probe) {
    if (!probe.isObject()) return "0";
    return std::to_string(probe["status_code"].asInt());
}

std::vector<std::string> txt_values(const DnsResponse& response) {
    std::vector<std::string> values;
    for (const auto& record : response.answers) {
        if (record.type == DNS_TYPE_TXT || record.type == DNS_TYPE_SPF) {
            values.push_back(record.value);
        }
    }
    return values;
}

Json::Value string_vector_to_json(const std::vector<std::string>& values) {
    Json::Value array(Json::arrayValue);
    for (const auto& value : values) array.append(value);
    return array;
}

Json::Value string_set_to_json(const std::set<std::string>& values) {
    Json::Value array(Json::arrayValue);
    for (const auto& value : values) array.append(value);
    return array;
}

Json::Value server_sets_to_json(const std::map<std::string, std::set<std::string>>& values) {
    Json::Value object(Json::objectValue);
    for (const auto& item : values) object[item.first] = string_set_to_json(item.second);
    return object;
}

std::string timestamp_suffix() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

int risk_points_for_check(const CheckResult& check) {
    if (check.status == "pass") return 0;
    if (check.status == "info") return 5;
    if (check.status == "warning") {
        if (check.name == "dns_tunneling" || check.name == "dns_hijacking" || check.name == "fast_flux") return 35;
        if (check.name == "open_resolver" || check.name == "amplification" || check.name == "dns_rebinding" || check.name == "proxy_dns") return 25;
        if (check.name == "dnssec_readiness" || check.name == "cache_poisoning" || check.name == "dns_spoofing") return 20;
        if (check.name == "wildcard_dns" || check.name == "nxdomain_redirect" || check.name == "spf_dmarc" || check.name == "caa_policy" || check.name == "tlsa_policy") return 15;
        return 10;
    }
    if (check.status == "critical") return 40;
    return 10;
}

} // namespace

FirewallAssessment assess_firewall_risk(const std::vector<CheckResult>& checks,
                                       const std::vector<DnsResponse>& responses,
                                       const Json::Value& web,
                                       const Json::Value& port_scan,
                                       const Json::Value& subdomains) {
    FirewallAssessment assessment;
    assessment.score = 0;
    Json::Value summary(Json::arrayValue);

    for (const auto& check : checks) {
        int points = risk_points_for_check(check);
        assessment.score += points;
        if (check.status != "pass") {
            Json::Value item(Json::objectValue);
            item["name"] = check.name;
            item["status"] = check.status;
            item["message"] = check.message;
            item["risk_points"] = points;
            summary.append(item);
        }
    }

    std::map<uint16_t, std::set<std::string>> server_value_sets;
    for (const auto& response : responses) {
        if (response.error) continue;
        for (const auto& record : response.answers) {
            server_value_sets[response.query_type].insert(record.value);
        }
    }

    for (const auto& item : server_value_sets) {
        if (item.second.size() > 5) {
            assessment.score += 10;
            Json::Value anomaly(Json::objectValue);
            anomaly["query_type"] = dns_type_to_string(item.first);
            anomaly["distinct_values"] = static_cast<int>(item.second.size());
            anomaly["message"] = "Multiple distinct values for the same query type may indicate inconsistent resolver behavior.";
            summary.append(anomaly);
        }
    }

    if (!web["probes"].empty()) {
        for (const auto& probe : web["probes"].asArray()) {
            if (probe["scheme"].asString() == "http" && probe["reachable"].asBool()) {
                assessment.score += 5;
                Json::Value item(Json::objectValue);
                item["name"] = "http_exposed";
                item["status"] = "warning";
                item["message"] = "HTTP service exposed alongside web security checks.";
                summary.append(item);
                break;
            }
        }
    }

    auto open_ports = open_port_list(port_scan);
    if (!open_ports.empty()) {
        assessment.score += 5;
        Json::Value item(Json::objectValue);
        item["name"] = "open_port";
        item["status"] = "warning";
        item["message"] = "Open service port detected during port scan.";
        item["open_ports"] = Json::Value(Json::arrayValue);
        for (int port : open_ports) item["open_ports"].append(port);
        summary.append(item);
    }

    if (!subdomains.empty() && subdomains.isArray() && subdomains.size() > 20) {
        assessment.score += 10;
        Json::Value item(Json::objectValue);
        item["name"] = "subdomain_exposure";
        item["status"] = "warning";
        item["message"] = "More than 20 discovered subdomains may increase attack surface.";
        summary.append(item);
    }

    std::vector<Json::Value> layers;
    bool http_reachable = false;
    bool https_reachable = false;
    bool had_http_redirect = false;
    bool security_policy = false;
    bool security_txt_present = false;
    bool robots_txt_present = false;
    bool sensitive_asset_exposed = has_sensitive_asset(web["assets"]);
    bool waf_detected = false;
    bool server_banner_visible = false;
    int total_assets = 0;
    int asset_200_count = 0;

    for (const auto& probe : web["probes"].asArray()) {
        std::string scheme = probe["scheme"].asString();
        bool reachable = probe["reachable"].asBool();
        if (scheme == "http" && reachable) {
            http_reachable = true;
            if (!probe["location"].asString().empty() && probe["location"].find("https://") == 0) {
                had_http_redirect = true;
            }
        }
        if (scheme == "https" && reachable) {
            https_reachable = true;
        }
        if (has_waf_header(probe)) waf_detected = true;
        if (!probe_server_header(probe).empty()) server_banner_visible = true;
    }

    for (const auto& asset : web["assets"].asArray()) {
        total_assets += 1;
        int code = asset["status_code"].asInt();
        if (code >= 200 && code < 300) asset_200_count += 1;
        std::string url = asset["url"].asString();
        if (url.find("security.txt") != std::string::npos && code == 200) security_txt_present = true;
        if (url.find("robots.txt") != std::string::npos && code == 200) robots_txt_present = true;
    }
    security_policy = security_txt_present || robots_txt_present;

    auto add_layer = [&](const std::string& name, const std::string& status, const std::string& message) {
        std::string normalized = normalize_layer_status(status);
        int points = layer_risk_points(normalized);
        Json::Value layer = make_firewall_layer(name, normalized, message, points);
        layers.push_back(layer);
        if (normalized == "warning" || normalized == "critical") {
            assessment.score += points;
            summary.append(layer);
        }
    };

    const CheckResult* dnssec_check = find_check(checks, "dnssec_readiness");
    const CheckResult* dnssec_chain = find_check(checks, "dnssec_chain");
    const CheckResult* open_resolver = find_check(checks, "open_resolver");
    const CheckResult* nxdomain = find_check(checks, "nxdomain_redirect");
    const CheckResult* wildcard = find_check(checks, "wildcard_dns");
    const CheckResult* zone_transfer = find_check(checks, "zone_transfer");
    const CheckResult* spf_dmarc = find_check(checks, "spf_dmarc");
    const CheckResult* caa = find_check(checks, "caa_policy");
    const CheckResult* mta_sts = find_check(checks, "mta_sts");
    const CheckResult* tlsa = find_check(checks, "tlsa_policy");
    const CheckResult* dns_tunnel = find_check(checks, "dns_tunneling");
    const CheckResult* dns_rebind = find_check(checks, "dns_rebinding");
    const CheckResult* proxy_dns = find_check(checks, "proxy_dns");
    const CheckResult* cache_poison = find_check(checks, "cache_poisoning");
    const CheckResult* dns_spoof = find_check(checks, "dns_spoofing");
    const CheckResult* fast_flux = find_check(checks, "fast_flux");
    const CheckResult* dns_hijack = find_check(checks, "dns_hijacking");

    add_layer("DNSSEC policy", dnssec_check ? dnssec_check->status : "warning",
              dnssec_check ? dnssec_check->message : "DNSSEC checks were not performed." );
    add_layer("DNSSEC chain", dnssec_chain ? dnssec_chain->status : "warning",
              dnssec_chain ? dnssec_chain->message : "DNSSEC chain validation was not performed." );
    add_layer("Open resolver protection", open_resolver ? open_resolver->status : "warning",
              open_resolver ? open_resolver->message : "Open resolver assessment was not performed." );
    add_layer("NXDOMAIN handling", nxdomain ? nxdomain->status : "warning",
              nxdomain ? nxdomain->message : "NXDOMAIN redirect behavior was not assessed." );
    add_layer("Wildcard DNS protection", wildcard ? wildcard->status : "warning",
              wildcard ? wildcard->message : "Wildcard DNS detection was not performed." );
    add_layer("Zone transfer protection", zone_transfer ? zone_transfer->status : "info",
              zone_transfer ? zone_transfer->message : "Zone transfer protection has limited coverage in this build." );
    add_layer("SPF/DMARC policy", spf_dmarc ? spf_dmarc->status : "warning",
              spf_dmarc ? spf_dmarc->message : "SPF/DMARC policy checks were not performed." );
    add_layer("CAA policy", caa ? caa->status : "warning",
              caa ? caa->message : "CAA policy checks were not performed." );
    add_layer("MTA-STS policy", mta_sts ? mta_sts->status : "warning",
              mta_sts ? mta_sts->message : "MTA-STS policy was not verified." );
    add_layer("TLSA policy", tlsa ? tlsa->status : "warning",
              tlsa ? tlsa->message : "TLSA policy checks were not performed." );
    add_layer("DNS tunneling blocking", dns_tunnel ? dns_tunnel->status : "warning",
              dns_tunnel ? dns_tunnel->message : "DNS tunneling signals were not fully evaluated." );
    add_layer("DNS rebinding protection", dns_rebind ? dns_rebind->status : "warning",
              dns_rebind ? dns_rebind->message : "DNS rebinding protections were not fully assessed." );
    add_layer("Proxy DNS detection", proxy_dns ? proxy_dns->status : "info",
              proxy_dns ? proxy_dns->message : "Proxy DNS exposure was not fully assessed." );
    add_layer("Cache poisoning resistance", cache_poison ? cache_poison->status : "warning",
              cache_poison ? cache_poison->message : "Cache poisoning resistance was not fully assessed." );
    add_layer("DNS spoofing resistance", dns_spoof ? dns_spoof->status : "warning",
              dns_spoof ? dns_spoof->message : "DNS spoofing protections were not fully assessed." );
    add_layer("Fast flux protection", fast_flux ? fast_flux->status : "warning",
              fast_flux ? fast_flux->message : "Fast flux detection was not fully assessed." );
    add_layer("DNS hijacking resistance", dns_hijack ? dns_hijack->status : "warning",
              dns_hijack ? dns_hijack->message : "DNS hijacking resistance was not fully assessed." );
    add_layer("TLS/HTTPS enforcement", https_reachable ? "pass" : "warning",
              https_reachable ? "HTTPS service is reachable." : "HTTPS service is not available or unreachable." );
    add_layer("HSTS header", http_reachable ? (has_security_policy_file(web["assets"]) ? "info" : "warning") : "warning",
              header_present(web["probes"][0], "strict-transport-security") ? "HSTS header is present." : "HSTS header is not present." );
    add_layer("Content Security Policy", http_reachable ? "info" : "warning",
              header_present(web["probes"][0], "content-security-policy") ? "CSP is present." : "CSP header is not present." );
    add_layer("X-Frame-Options header", header_present(web["probes"][0], "x-frame-options") ? "pass" : "warning",
              header_present(web["probes"][0], "x-frame-options") ? "Clickjacking protection header is present." : "Clickjacking protection header is not present." );
    add_layer("X-Content-Type-Options header", header_present(web["probes"][0], "x-content-type-options") ? "pass" : "warning",
              header_present(web["probes"][0], "x-content-type-options") ? "MIME sniffing protection header is present." : "MIME sniffing header is not present." );
    add_layer("Server banner hardening", server_banner_visible ? "warning" : "pass",
              server_banner_visible ? "Server banner is exposed." : "Server banner is hidden or minimal." );
    add_layer("WAF metadata protection", waf_detected ? "info" : "warning",
              waf_detected ? "WAF or CDN fingerprint detected." : "No WAF/CDN fingerprints were detected." );
    add_layer("HTTPS redirect enforcement", !http_reachable || had_http_redirect ? "pass" : "warning",
              !http_reachable ? "No HTTP endpoint exposed." : (had_http_redirect ? "HTTP redirects to HTTPS." : "HTTP does not redirect to HTTPS."));
    add_layer("Open port filtering", open_ports.empty() ? "pass" : "warning",
              open_ports.empty() ? "No additional open TCP ports were detected." : "One or more open TCP ports are present." );

    std::set<int> sensitive_ports = {22, 23, 25, 1433, 3306, 3389, 5900, 6379};
    bool sensitive_port_open = false;
    for (int port : open_ports) {
        if (sensitive_ports.count(port)) sensitive_port_open = true;
    }
    add_layer("Restricted management ports", sensitive_port_open ? "warning" : "pass",
              sensitive_port_open ? "A sensitive management port is open." : "No high-risk management ports were detected." );
    add_layer("Subdomain firewalling", subdomains.isArray() && subdomains.size() > 20 ? "warning" : "pass",
              subdomains.isArray() && subdomains.size() > 20 ? "Many subdomains were discovered, increasing surface area." : "Subdomain enumeration did not expose a large surface area." );
    add_layer("Sensitive asset exposure", sensitive_asset_exposed ? "warning" : "pass",
              sensitive_asset_exposed ? "Potential sensitive files or administration endpoints were found." : "Sensitive asset discovery did not reveal exposed targets." );
    add_layer("Security policy visibility", security_policy ? "info" : "warning",
              security_policy ? "Security policy files were found." : "Security policy files are not present." );

    assessment.bypass_layers = Json::Value(Json::arrayValue);
    for (const auto& layer : layers) assessment.bypass_layers.append(layer);

    if (assessment.score >= 100) {
        assessment.verdict = "severe";
    } else if (assessment.score >= 70) {
        assessment.verdict = "high";
    } else if (assessment.score >= 40) {
        assessment.verdict = "medium";
    } else {
        assessment.verdict = "low";
    }

    assessment.signal_summary = summary;
    assessment.details["score"] = assessment.score;
    assessment.details["verdict"] = assessment.verdict;
    assessment.details["signal_count"] = static_cast<int>(summary.size());
    assessment.details["checks"] = Json::Value(Json::arrayValue);
    for (const auto& item : summary.asArray()) assessment.details["checks"].append(item);
    assessment.details["bypass_layer_count"] = static_cast<int>(layers.size());
    assessment.details["bypass_layers"] = assessment.bypass_layers;
    return assessment;
}

Json::Value firewall_assessment_to_json(const FirewallAssessment& assessment) {
    Json::Value root(Json::objectValue);
    root["score"] = assessment.score;
    root["verdict"] = assessment.verdict;
    root["signal_summary"] = assessment.signal_summary;
    root["bypass_layers"] = assessment.bypass_layers;
    root["details"] = assessment.details;
    return root;
}

CheckResult check_zone_transfer(const DnsClient& client, const std::string& server, const std::string& domain) {
    DnsResponse response = client.query(domain, server, DNS_TYPE_A);
    // Zone transfer detection is not implemented in this build; it requires AXFR support and authority validation.
    CheckResult result = make_check("zone_transfer", domain, "info", "Zone transfer detection is not available in this build.");
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_open_resolver(const DnsClient& client, const std::string& server) {
    if (server.empty()) {
        return make_check("open_resolver", "default", "skipped", "Open resolver check requires an explicit DNS server.");
    }

    DnsResponse response = client.query("www.google.com", server, DNS_TYPE_A);
    CheckResult result = make_check("open_resolver", server, response.answers.empty() ? "pass" : "warning",
                                    response.answers.empty() ? "Server did not resolve an external recursive query." : "Server resolved an external recursive query.");
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_nxdomain_redirect(const DnsClient& client, const std::string& server, const std::string& domain) {
    std::string random_domain = "nxdomain-test-" + timestamp_suffix() + "." + domain;
    DnsResponse response = client.query(random_domain, server, DNS_TYPE_A);
    CheckResult result = make_check("nxdomain_redirect", response.server, response.rcode == 3 ? "pass" : "warning",
                                    response.rcode == 3 ? "Resolver returned NXDOMAIN as expected." : "Resolver returned a non-NXDOMAIN response for a random name.");
    result.details["query"] = random_domain;
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_amplification(const DnsClient& client, const std::string& server) {
    DnsResponse response = client.query("example.com", server, DNS_TYPE_ANY);
    CheckResult result = make_check("amplification", response.server, response.response_size > 512 ? "warning" : "pass",
                                    response.response_size > 512 ? "Large ANY response may be useful for amplification." : "ANY response size is modest.");
    result.details["response_bytes"] = static_cast<Json::UInt64>(response.response_size);
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_wildcard_dns(const DnsClient& client, const std::string& server, const std::string& domain) {
    std::string random_domain = "wildcard-test-" + timestamp_suffix() + "." + domain;
    DnsResponse response = client.query(random_domain, server, DNS_TYPE_A);
    CheckResult result = make_check("wildcard_dns", response.server, response.answers.empty() ? "pass" : "warning",
                                    response.answers.empty() ? "Random subdomain did not resolve." : "Random subdomain resolved, indicating wildcard DNS.");
    result.details["query"] = random_domain;
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_dnssec_readiness(const DnsClient& client, const std::string& server, const std::string& domain) {
    DnsResponse dnskey = client.query(domain, server, DNS_TYPE_DNSKEY, true);
    DnsResponse rrsig = client.query(domain, server, DNS_TYPE_RRSIG, true);
    bool has_dnskey = std::any_of(dnskey.answers.begin(), dnskey.answers.end(), [](const DnsRecord& record) {
        return record.type == DNS_TYPE_DNSKEY;
    });
    bool has_rrsig = std::any_of(rrsig.answers.begin(), rrsig.answers.end(), [](const DnsRecord& record) {
        return record.type == DNS_TYPE_RRSIG;
    });

    CheckResult result = make_check("dnssec_readiness", server.empty() ? "default" : server, (has_dnskey || has_rrsig) ? "info" : "warning",
                                    (has_dnskey || has_rrsig) ? "DNSSEC records were observed; cryptographic chain validation is not performed." : "No DNSSEC records were observed.");
    result.details["dnskey"] = dns_response_to_json(dnskey);
    result.details["rrsig"] = dns_response_to_json(rrsig);
    result.details["cryptographic_validation"] = false;
    return result;
}

CheckResult check_spf_dmarc(const DnsClient& client, const std::string& server, const std::string& domain) {
    DnsResponse response = client.query(domain, server, DNS_TYPE_TXT);
    Json::Value spf(Json::arrayValue);
    Json::Value dmarc(Json::arrayValue);

    for (const auto& record : response.answers) {
        if (record.type != DNS_TYPE_TXT) continue;
        std::string lowered = lowercase(record.value);
        if (lowered.rfind("v=spf1", 0) == 0) {
            spf.append(record.value);
        }
        if (lowered.rfind("v=dmarc1", 0) == 0 || lowered.find("_dmarc") != std::string::npos) {
            dmarc.append(record.value);
        }
    }

    std::string status = (spf.empty() && dmarc.empty()) ? "critical" : (spf.empty() || dmarc.empty()) ? "warning" : "info";
    std::string message;
    if (spf.empty() && dmarc.empty()) {
        message = "No SPF or DMARC records were detected.";
    } else if (spf.empty()) {
        message = "DMARC found, but no SPF record detected.";
    } else if (dmarc.empty()) {
        message = "SPF found, but no DMARC policy was detected.";
    } else {
        message = "SPF and DMARC records are present.";
    }

    CheckResult result = make_check("spf_dmarc", server.empty() ? "default" : server, status, message);
    result.details["spf_records"] = spf;
    result.details["dmarc_records"] = dmarc;
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_caa_policy(const DnsClient& client, const std::string& server, const std::string& domain) {
    DnsResponse response = client.query(domain, server, DNS_TYPE_CAA);
    bool has_caa = !response.answers.empty();
    CheckResult result = make_check("caa_policy", server.empty() ? "default" : server, has_caa ? "info" : "warning",
                                    has_caa ? "CAA records are present." : "No CAA records were found.");
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_mta_sts(const DnsClient& client, const std::string& server, const std::string& domain) {
    std::string apex = extract_domain_apex(domain);
    std::string record_name = "_mta-sts." + apex;
    DnsResponse response = client.query(record_name, server, DNS_TYPE_TXT);
    std::vector<std::string> values = txt_values(response);
    std::string status;
    std::string message;
    if (values.empty()) {
        status = "warning";
        message = "No MTA-STS TXT policy record was detected.";
    } else {
        status = "info";
        message = "MTA-STS TXT policy record exists.";
    }
    CheckResult result = make_check("mta_sts", server.empty() ? "default" : server, status, message);
    result.details["record_name"] = record_name;
    result.details["txt_records"] = string_vector_to_json(values);
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_tlsa_policy(const DnsClient& client, const std::string& server, const std::string& domain) {
    std::string apex = extract_domain_apex(domain);
    std::string record_name = "_443._tcp." + apex;
    DnsResponse response = client.query(record_name, server, DNS_TYPE_TLSA);
    bool has_tlsa = !response.answers.empty();
    CheckResult result = make_check("tlsa_policy", server.empty() ? "default" : server, has_tlsa ? "info" : "warning",
                                    has_tlsa ? "TLSA records were found for 443/tcp." : "No TLSA records found for 443/tcp.");
    result.details["record_name"] = record_name;
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_dnssec_chain(const DnsClient& client, const std::string& server, const std::string& domain) {
    std::string apex = extract_domain_apex(domain);
    DnsResponse dnskey = client.query(apex, server, DNS_TYPE_DNSKEY, true);
    DnsResponse rrsig = client.query(apex, server, DNS_TYPE_RRSIG, true);
    DnsResponse ds = client.query(apex, server, DNS_TYPE_DS);

    bool has_dnskey = std::any_of(dnskey.answers.begin(), dnskey.answers.end(), [](const DnsRecord& record) {
        return record.type == DNS_TYPE_DNSKEY;
    });
    bool has_rrsig = std::any_of(rrsig.answers.begin(), rrsig.answers.end(), [](const DnsRecord& record) {
        return record.type == DNS_TYPE_RRSIG;
    });
    bool has_ds = !ds.answers.empty();

    std::string status;
    std::string message;
    if (has_dnskey && has_rrsig && has_ds) {
        status = "info";
        message = "DNSSEC signatures and parent DS records were observed for the effective apex domain.";
    } else if (has_dnskey || has_rrsig) {
        status = "warning";
        message = "Partial DNSSEC evidence was found, but the chain is incomplete or parent DS records are missing.";
    } else {
        status = "critical";
        message = "No DNSSEC records were observed for the effective apex domain.";
    }

    CheckResult result = make_check("dnssec_chain", server.empty() ? "default" : server, status, message);
    result.details["apex_domain"] = apex;
    result.details["dnskey_response"] = dns_response_to_json(dnskey);
    result.details["rrsig_response"] = dns_response_to_json(rrsig);
    result.details["ds_response"] = dns_response_to_json(ds);
    return result;
}

CheckResult check_dns_tunneling(const DnsClient& client, const std::string& server, const std::string& domain) {
    DnsResponse response = client.query(domain, server, DNS_TYPE_TXT);
    Json::Value suspicious(Json::arrayValue);
    for (const auto& record : response.answers) {
        if (record.type == DNS_TYPE_TXT && looks_like_dns_tunnel_txt(record.value)) suspicious.append(record.value);
    }

    CheckResult result = make_check("dns_tunneling", response.server, suspicious.size() == 0 ? "pass" : "warning",
                                    suspicious.size() == 0 ? "No suspicious TXT records found." : "Suspicious TXT records resemble encoded tunnel payloads.");
    result.details["suspicious_txt"] = suspicious;
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_dns_rebinding(const DnsClient& client, const std::string& server, const std::string& domain) {
    DnsResponse response = client.query("www." + domain, server, DNS_TYPE_A);
    Json::Value private_ips(Json::arrayValue);
    for (const auto& record : response.answers) {
        if (record.type == DNS_TYPE_A && is_private_ipv4(record.value)) private_ips.append(record.value);
    }

    CheckResult result = make_check("dns_rebinding", response.server, private_ips.empty() ? "pass" : "warning",
                                    private_ips.empty() ? "No private IPv4 addresses found." : "Public name resolved to private IPv4 addresses.");
    result.details["private_ips"] = private_ips;
    result.details["response"] = dns_response_to_json(response);
    return result;
}

CheckResult check_proxy_dns(const std::string& server) {
    static const std::set<std::string> public_dns = {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220"
    };
    CheckResult result = make_check("proxy_dns", server, public_dns.count(server) ? "info" : "pass",
                                    public_dns.count(server) ? "Server is a known public recursive DNS provider." : "Server is not in the built-in public DNS list.");
    return result;
}

CheckResult check_cache_poisoning(const std::vector<DnsResponse>& responses) {
    auto values = server_values_for_type(responses, DNS_TYPE_A);
    if (values.size() < 2) return make_check("cache_poisoning", "multi-server", "skipped", "At least two resolver responses are required.");
    auto common = intersection_of(values);
    CheckResult result = make_check("cache_poisoning", "multi-server", common.empty() ? "warning" : "pass",
                                    common.empty() ? "No common A records across resolvers." : "Resolvers shared at least one A record.");
    result.details["servers"] = server_sets_to_json(values);
    result.details["common"] = string_set_to_json(common);
    return result;
}

CheckResult check_dns_spoofing(const std::vector<DnsResponse>& responses) {
    auto values = server_values_for_type(responses, DNS_TYPE_A);
    if (values.size() < 2) return make_check("dns_spoofing", "multi-server", "skipped", "At least two resolver responses are required.");
    auto common = intersection_of(values);
    CheckResult result = make_check("dns_spoofing", "multi-server", common.empty() ? "warning" : "pass",
                                    common.empty() ? "Resolver A records are fully divergent." : "Resolvers share common A records.");
    result.details["servers"] = server_sets_to_json(values);
    result.details["common"] = string_set_to_json(common);
    return result;
}

CheckResult check_fast_flux(const std::vector<DnsResponse>& responses) {
    auto values = values_for_type(responses, DNS_TYPE_A);
    size_t a_response_count = 0;
    for (const auto& response : responses) {
        if (response.query_type == DNS_TYPE_A) ++a_response_count;
    }
    CheckResult result = make_check("fast_flux", "multi-server", values.size() > a_response_count * 3 ? "warning" : "pass",
                                    values.size() > a_response_count * 3 ? "High IP diversity may indicate fast flux." : "No clear fast-flux pattern detected.");
    result.details["unique_a_records"] = string_set_to_json(values);
    return result;
}

CheckResult check_dns_hijacking(const std::vector<DnsResponse>& responses) {
    auto ns_values = server_values_for_type(responses, DNS_TYPE_NS);
    auto mx_values = server_values_for_type(responses, DNS_TYPE_MX);
    bool ns_divergent = ns_values.size() > 1 && intersection_of(ns_values).empty();
    bool mx_divergent = mx_values.size() > 1 && intersection_of(mx_values).empty();
    CheckResult result = make_check("dns_hijacking", "multi-server", (ns_divergent || mx_divergent) ? "warning" : "pass",
                                    (ns_divergent || mx_divergent) ? "Resolver authority records diverge." : "No NS/MX hijacking signal detected.");
    result.details["ns"] = server_sets_to_json(ns_values);
    result.details["mx"] = server_sets_to_json(mx_values);
    return result;
}

Json::Value dns_response_to_json(const DnsResponse& response) {
    Json::Value root(Json::objectValue);
    root["domain"] = response.domain;
    root["server"] = response.server;
    root["query_type"] = response.query_type_name;
    root["rcode"] = response.rcode;
    root["truncated"] = response.truncated;
    root["error"] = response.error;
    root["error_message"] = response.error_message;
    root["response_size"] = static_cast<Json::UInt64>(response.response_size);
    root["answer_count"] = response.answer_count;
    root["authority_count"] = response.authority_count;

    Json::Value answers(Json::arrayValue);
    for (const auto& record : response.answers) {
        Json::Value item(Json::objectValue);
        item["type"] = record.type_name;
        item["ttl"] = static_cast<Json::UInt64>(record.ttl);
        item["value"] = record.value;
        answers.append(item);
    }
    root["answers"] = answers;
    return root;
}

Json::Value check_result_to_json(const CheckResult& check) {
    Json::Value root(Json::objectValue);
    root["name"] = check.name;
    root["target"] = check.target;
    root["status"] = check.status;
    root["message"] = check.message;
    root["details"] = check.details;
    return root;
}

} // namespace whitedns
