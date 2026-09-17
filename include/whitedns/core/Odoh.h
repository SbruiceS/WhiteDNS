#ifndef WHITEDNS_CORE_ODOH_H
#define WHITEDNS_CORE_ODOH_H

#include "whitedns/DnsTypes.h"

#include <cstdint>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct OdohConfig {
    uint16_t version = 0;
    uint16_t kem_id = 0;
    uint16_t kdf_id = 0;
    uint16_t aead_id = 0;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> contents_wire;
    std::vector<uint8_t> key_id;
};

struct OdohResult {
    bool ok = false;
    bool oblivious = false;
    std::string error;
    std::string proxy;
    std::string target;
    std::string key_id_hex;
    std::vector<DnsRecord> answers;
    uint16_t rcode = 2;
    size_t ciphertext_bytes = 0;
    size_t qname_len = 0;
    uint16_t kem_id = 0;
    uint16_t kdf_id = 0;
    uint16_t aead_id = 0;
};

std::vector<OdohConfig> parse_odoh_configs(const std::vector<uint8_t>& wire);
bool fetch_odoh_configs(const std::string& host, std::vector<OdohConfig>& out, std::string& error);

// Encrypt a DNS wire query for the target (RFC 9230 §6). Used by tests and the CLI.
bool odoh_encrypt_query(const OdohConfig& cfg,
                        const std::vector<uint8_t>& dns_query,
                        std::vector<uint8_t>& message_out,
                        std::vector<uint8_t>& enc_out,
                        std::vector<uint8_t>& exporter_secret_out,
                        std::vector<uint8_t>& q_plain_out,
                        std::string& error);

// Production pair: Cloudflare target + independent public relay (Fastly/Numa).
// Set proxy_url_template empty to use that pair. Set "direct" to skip the relay
// (NOT RFC 9230 oblivious).
OdohResult odoh_lookup(const std::string& qname,
                       uint16_t qtype,
                       const std::string& target_host,
                       const std::string& proxy_url_template);

const char* const kOdohProductionTarget = "odoh.cloudflare-dns.com";
const char* const kOdohProductionRelays[] = {
    "https://odoh-relay.edgecompute.app/{?targethost,targetpath}",
    "https://odoh-relay.numa.rs/relay{?targethost,targetpath}",
    nullptr
};

} // namespace core
} // namespace whitedns

#endif
