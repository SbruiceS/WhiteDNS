#ifndef WHITEDNS_CORE_PROTOCOL_ENGINE_H
#define WHITEDNS_CORE_PROTOCOL_ENGINE_H

#include <cstdint>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct ProtoFinding {
    std::string category;
    size_t offset = 0;
    std::string detail;
};

struct ProtoView {
    bool ok = false;
    uint16_t id = 0;
    uint8_t opcode = 0;
    uint16_t rcode = 0;
    bool tc = false;
    bool aa = false;
    int questions = 0;
    int answers = 0;
    int opt = 0;
    std::string qname;
    std::vector<std::string> rdata_notes;
    std::vector<ProtoFinding> findings;
};

ProtoView parse_strict(const std::vector<uint8_t>& packet);
int run_protocol_selftest(std::ostream& out);

} // namespace core
} // namespace whitedns

#endif
