#ifndef WHITEDNS_DNS_TYPES_H
#define WHITEDNS_DNS_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace whitedns {

constexpr uint16_t DNS_TYPE_A = 1;
constexpr uint16_t DNS_TYPE_NS = 2;
constexpr uint16_t DNS_TYPE_SOA = 6;
constexpr uint16_t DNS_TYPE_MX = 15;
constexpr uint16_t DNS_TYPE_TXT = 16;
constexpr uint16_t DNS_TYPE_AAAA = 28;
constexpr uint16_t DNS_TYPE_CNAME = 5;
constexpr uint16_t DNS_TYPE_PTR = 12;
constexpr uint16_t DNS_TYPE_SRV = 33;
constexpr uint16_t DNS_TYPE_NAPTR = 35;
constexpr uint16_t DNS_TYPE_DS = 43;
constexpr uint16_t DNS_TYPE_SSHFP = 44;
constexpr uint16_t DNS_TYPE_SPF = 99;
constexpr uint16_t DNS_TYPE_RRSIG = 46;
constexpr uint16_t DNS_TYPE_DNSKEY = 48;
constexpr uint16_t DNS_TYPE_NSEC = 47;
constexpr uint16_t DNS_TYPE_NSEC3 = 50;
constexpr uint16_t DNS_TYPE_DNAME = 39;
constexpr uint16_t DNS_TYPE_TLSA = 52;
constexpr uint16_t DNS_TYPE_AXFR = 252;
constexpr uint16_t DNS_TYPE_CAA = 257;
constexpr uint16_t DNS_TYPE_ANY = 255;

struct DnsRecord {
    uint16_t type = 0;
    std::string type_name;
    std::string value;
    uint32_t ttl = 0;
    std::vector<uint8_t> rdata;
};

struct DnsResponse {
    std::string domain;
    std::string server;
    uint16_t query_type = 0;
    std::string query_type_name;
    uint16_t rcode = 0;
    bool truncated = false;
    bool error = false;
    std::string error_message;
    size_t response_size = 0;
    uint16_t answer_count = 0;
    uint16_t authority_count = 0;
    uint16_t additional_count = 0;
    bool authoritative = false;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authority;
};

std::string dns_type_to_string(uint16_t type);
int dns_type_from_string(const std::string& type);

} // namespace whitedns

#endif // WHITEDNS_DNS_TYPES_H
