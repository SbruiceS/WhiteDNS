#ifndef WHITEDNS_DNSSEC_H
#define WHITEDNS_DNSSEC_H

#include "whitedns/DnsTypes.h"

#include <json/json.h>
#include <string>
#include <vector>

namespace whitedns {

struct DnssecChainResult {
    bool attempted = false;
    bool ds_present = false;
    bool dnskey_present = false;
    bool ds_matches_key = false;
    bool rrsig_present = false;
    int matched_keys = 0;
    int ds_records = 0;
    int dnskey_records = 0;
    std::string message;
    Json::Value evidence;
};

// RFC 4034: DS digest must match a DNSKEY at the child.
// This is cryptographic chain validation to the parent, not mere presence.
DnssecChainResult validate_ds_dnskey_chain(const std::string& domain,
                                           const std::vector<DnsRecord>& ds_records,
                                           const std::vector<DnsRecord>& dnskey_records,
                                           const std::vector<DnsRecord>& rrsig_records);

} // namespace whitedns

#endif
