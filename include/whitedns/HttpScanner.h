#ifndef WHITEDNS_HTTP_SCANNER_H
#define WHITEDNS_HTTP_SCANNER_H

#include <json/json.h>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace whitedns {

struct HttpProbeResult {
    std::string url;
    std::string scheme;
    std::string host;
    int port = 0;
    std::string path;
    bool reachable = false;
    bool tls_port_open = false;
    int status_code = 0;
    std::string server_header;
    std::string location;
    std::map<std::string, std::string> headers;
    std::string body_preview;
    int redirect_count = 0;
    std::string error;
};

struct WebAssetResult {
    std::string url;
    bool reachable = false;
    int status_code = 0;
    std::string server_header;
    std::string error;
};

class HttpScanner {
public:
    HttpScanner(std::vector<std::string> urls,
                std::vector<std::string> asset_paths = {},
                bool fetch_body = false,
                bool follow_redirects = false,
                int timeout_ms = 4000);

    void run();
    const std::vector<HttpProbeResult>& probes() const;
    const std::vector<WebAssetResult>& assets() const;
    Json::Value to_json() const;

private:
    bool parse_url(const std::string& url, std::string& scheme, std::string& host, int& port, std::string& path) const;
    HttpProbeResult probe_url(const std::string& url);
    HttpProbeResult probe_https_url(const std::string& url);
    WebAssetResult probe_asset(const std::string& base_url, const std::string& asset_path);
    std::string normalize_path(const std::string& prefix, const std::string& asset_path) const;

    std::vector<std::string> urls_;
    std::vector<std::string> asset_paths_;
    bool fetch_body_;
    bool follow_redirects_;
    int timeout_ms_;
    std::vector<HttpProbeResult> probe_results_;
    std::vector<WebAssetResult> asset_results_;
    std::mutex results_mutex_;
};

} // namespace whitedns

#endif // WHITEDNS_HTTP_SCANNER_H
