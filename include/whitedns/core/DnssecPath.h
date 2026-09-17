#ifndef WHITEDNS_CORE_DNSSEC_PATH_H
#define WHITEDNS_CORE_DNSSEC_PATH_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct DnssecPathReport {
    std::string qname;
    bool ds_present = false;
    bool dnskey_present = false;
    bool ds_matches_key = false;
    bool rrsig_present = false;
    bool nsec_present = false;
    bool nsec3_present = false;
    bool nx_has_nsec = false;
    int ds_count = 0;
    int dnskey_count = 0;
    int rrsig_count = 0;
    std::string chain_message;
    std::string klass; // CONFIRMED_BY_VALIDATION, OBSERVATION, ANOMALY
    std::vector<std::string> rrsig_covers;
    std::string notes;
};

DnssecPathReport run_dnssec_path(const std::string& qname, const std::string& resolver);
void print_dnssec_path(const DnssecPathReport& report);

} // namespace core
} // namespace whitedns

#endif
