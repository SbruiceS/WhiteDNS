#ifndef WHITEDNS_CORE_AXFRSTREAM_H
#define WHITEDNS_CORE_AXFRSTREAM_H

#include <string>

namespace whitedns {
namespace core {

struct AxfrReport {
    std::string qname;
    std::string server;
    bool open = false;
    bool refused = false;
    int messages = 0;
    int records = 0;
    int cname = 0;
    int cdn_cname = 0;
    int unique_est = 0;
    int cname_targets = 0;
    int peak_bytes = 0;
    int compressed_bytes = 0;
    double wall_ms = 0;
    double tool_ms = 0;
    double recv_ms = 0;
    std::string note;
    std::string compressed;
};

AxfrReport stream_axfr(const std::string& qname, const std::string& server);
void print_axfr(const AxfrReport& r);

} // namespace core
} // namespace whitedns

#endif
