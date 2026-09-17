#ifndef WHITEDNS_CORE_WIRE_H
#define WHITEDNS_CORE_WIRE_H

#include "whitedns/DnsTypes.h"

#include <cstdint>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct HeaderFlags {
    bool qr = false;
    uint8_t opcode = 0;
    bool aa = false;
    bool tc = false;
    bool rd = false;
    bool ra = false;
    bool ad = false;
    bool cd = false;
    uint16_t rcode = 0;
};

struct Question {
    std::string qname;
    uint16_t qtype = 0;
    uint16_t qclass = 1;
};

struct Message {
    uint16_t id = 0;
    HeaderFlags flags;
    Question question;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authority;
    std::vector<DnsRecord> additional;
    bool has_edns = false;
    uint16_t edns_udp_payload = 0;
    bool dnssec_ok = false;
    std::string parse_error;
};

std::vector<uint8_t> encode_qname(const std::string& name);
std::string decode_qname(const std::vector<uint8_t>& packet, size_t& offset, int jumps = 0);

std::vector<uint8_t> build_query_message(const std::string& qname,
                                         uint16_t qtype,
                                         uint16_t id,
                                         bool recursion_desired,
                                         bool edns_dnssec_ok);

Message parse_message(const std::vector<uint8_t>& packet);

} // namespace core
} // namespace whitedns

#endif
