#include "whitedns/core/Wire.h"

#include "whitedns/IanaDns.h"

#include <cstdio>
#include <stdexcept>

namespace whitedns {
namespace core {
namespace {

void write_u16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

void write_u32(std::vector<uint8_t>& out, uint32_t value) {
    write_u16(out, static_cast<uint16_t>(value >> 16));
    write_u16(out, static_cast<uint16_t>(value & 0xffff));
}

uint16_t read_u16(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 2 > data.size()) throw std::runtime_error("parse/short");
    return static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
}

uint32_t read_u32(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 4 > data.size()) throw std::runtime_error("parse/short");
    return (static_cast<uint32_t>(read_u16(data, offset)) << 16) | read_u16(data, offset + 2);
}

} // namespace

std::vector<uint8_t> encode_qname(const std::string& name) {
    std::string n = name;
    while (!n.empty() && n.back() == '.') n.pop_back();
    if (n.size() > 253) throw std::runtime_error("parse/name-too-long");
    std::vector<uint8_t> out;
    if (n.empty()) {
        out.push_back(0);
        return out;
    }
    size_t start = 0;
    while (start < n.size()) {
        size_t end = n.find('.', start);
        if (end == std::string::npos) end = n.size();
        size_t len = end - start;
        if (len == 0 || len > 63) throw std::runtime_error("parse/bad-label");
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), n.begin() + static_cast<std::ptrdiff_t>(start),
                   n.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    out.push_back(0);
    return out;
}

std::string decode_qname(const std::vector<uint8_t>& packet, size_t& offset, int jumps) {
    if (jumps > 20) throw std::runtime_error("parse/pointer-loop");
    std::string name;
    size_t cursor = offset;
    bool jumped = false;
    int local_jumps = jumps;

    while (cursor < packet.size()) {
        uint8_t len = packet[cursor];
        if ((len & 0xc0) == 0xc0) {
            if (cursor + 1 >= packet.size()) throw std::runtime_error("parse/bad-pointer");
            uint16_t pointer = static_cast<uint16_t>(((len & 0x3f) << 8) | packet[cursor + 1]);
            if (pointer >= packet.size()) throw std::runtime_error("parse/bad-pointer");
            if (!jumped) offset = cursor + 2;
            size_t nested = pointer;
            std::string rest = decode_qname(packet, nested, local_jumps + 1);
            if (!name.empty() && !rest.empty() && rest != ".") name.push_back('.');
            name += (rest == "." ? "" : rest);
            if (name.empty()) name = ".";
            return name;
        }
        if (len == 0) {
            if (!jumped) offset = cursor + 1;
            return name.empty() ? "." : name;
        }
        if (len > 63) throw std::runtime_error("parse/bad-label");
        ++cursor;
        if (cursor + len > packet.size()) throw std::runtime_error("parse/short");
        if (!name.empty()) name.push_back('.');
        name.append(reinterpret_cast<const char*>(&packet[cursor]), len);
        cursor += len;
    }
    throw std::runtime_error("parse/unterminated-name");
}

std::vector<uint8_t> build_query_message(const std::string& qname,
                                         uint16_t qtype,
                                         uint16_t id,
                                         bool recursion_desired,
                                         bool edns_dnssec_ok) {
    std::vector<uint8_t> packet;
    write_u16(packet, id);
    write_u16(packet, recursion_desired ? 0x0100 : 0x0000);
    write_u16(packet, 1);
    write_u16(packet, 0);
    write_u16(packet, 0);
    write_u16(packet, edns_dnssec_ok ? 1 : 0);
    auto name = encode_qname(qname);
    packet.insert(packet.end(), name.begin(), name.end());
    write_u16(packet, qtype);
    write_u16(packet, 1);
    if (edns_dnssec_ok) {
        packet.push_back(0);
        write_u16(packet, 41);
        write_u16(packet, 1232);
        write_u32(packet, 0x00008000);
        write_u16(packet, 0);
    }
    return packet;
}

Message parse_message(const std::vector<uint8_t>& packet) {
    Message msg;
    if (packet.size() < 12) {
        msg.parse_error = "parse/short";
        return msg;
    }
    try {
        msg.id = read_u16(packet, 0);
        uint16_t flags = read_u16(packet, 2);
        msg.flags.qr = (flags & 0x8000) != 0;
        msg.flags.opcode = static_cast<uint8_t>((flags >> 11) & 0x0f);
        msg.flags.aa = (flags & 0x0400) != 0;
        msg.flags.tc = (flags & 0x0200) != 0;
        msg.flags.rd = (flags & 0x0100) != 0;
        msg.flags.ra = (flags & 0x0080) != 0;
        msg.flags.ad = (flags & 0x0020) != 0;
        msg.flags.cd = (flags & 0x0010) != 0;
        msg.flags.rcode = flags & 0x000f;

        uint16_t qd = read_u16(packet, 4);
        uint16_t an = read_u16(packet, 6);
        uint16_t ns = read_u16(packet, 8);
        uint16_t ar = read_u16(packet, 10);
        size_t offset = 12;

        if (qd > 0) {
            msg.question.qname = decode_qname(packet, offset);
            msg.question.qtype = read_u16(packet, offset);
            offset += 2;
            msg.question.qclass = read_u16(packet, offset);
            offset += 2;
            for (uint16_t i = 1; i < qd; ++i) {
                decode_qname(packet, offset);
                offset += 4;
            }
        }

        auto section = [&](uint16_t count, std::vector<DnsRecord>& out) {
            for (uint16_t i = 0; i < count; ++i) {
                decode_qname(packet, offset);
                DnsRecord rec;
                rec.type = read_u16(packet, offset);
                offset += 2;
                offset += 2;
                rec.ttl = read_u32(packet, offset);
                offset += 4;
                uint16_t rdlen = read_u16(packet, offset);
                offset += 2;
                if (offset + rdlen > packet.size()) throw std::runtime_error("parse/short-rdata");
                rec.rdata.assign(packet.begin() + static_cast<std::ptrdiff_t>(offset),
                                 packet.begin() + static_cast<std::ptrdiff_t>(offset + rdlen));
                rec.type_name = dns_type_to_string(rec.type);
                size_t name_at = offset;
                if (rec.type == 41) {
                    msg.has_edns = true;
                    msg.edns_udp_payload = rec.ttl > 0xffff ? 512 : static_cast<uint16_t>(rec.ttl ? rec.ttl : 512);
                    // class field was overwritten; payload is in CLASS of OPT — we skipped class.
                    msg.dnssec_ok = false;
                    offset += rdlen;
                    continue;
                }
                rec.value = rec.rdata.empty() ? "" : rec.type_name + "(" + std::to_string(rec.rdata.size()) + "B)";
                if (rec.type == DNS_TYPE_A && rec.rdata.size() == 4) {
                    rec.value = std::to_string(rec.rdata[0]) + "." + std::to_string(rec.rdata[1]) + "." +
                                std::to_string(rec.rdata[2]) + "." + std::to_string(rec.rdata[3]);
                } else if (rec.type == DNS_TYPE_AAAA && rec.rdata.size() == 16) {
                    char buf[64];
                    snprintf(buf, sizeof(buf),
                             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                             rec.rdata[0], rec.rdata[1], rec.rdata[2], rec.rdata[3], rec.rdata[4], rec.rdata[5],
                             rec.rdata[6], rec.rdata[7], rec.rdata[8], rec.rdata[9], rec.rdata[10], rec.rdata[11],
                             rec.rdata[12], rec.rdata[13], rec.rdata[14], rec.rdata[15]);
                    rec.value = buf;
                } else if (rec.type == DNS_TYPE_NS || rec.type == DNS_TYPE_CNAME || rec.type == DNS_TYPE_PTR) {
                    try {
                        rec.value = decode_qname(packet, name_at);
                    } catch (...) {
                    }
                } else if (rec.type == DNS_TYPE_MX && rec.rdata.size() >= 3) {
                    uint16_t pref = static_cast<uint16_t>((rec.rdata[0] << 8) | rec.rdata[1]);
                    size_t n = name_at + 2;
                    try {
                        rec.value = std::to_string(pref) + " " + decode_qname(packet, n);
                    } catch (...) {
                        rec.value = std::to_string(pref);
                    }
                } else if (rec.type == DNS_TYPE_SOA && rec.rdata.size() >= 22) {
                    size_t n = name_at;
                    try {
                        auto mname = decode_qname(packet, n);
                        auto rname = decode_qname(packet, n);
                        rec.value = mname + " " + rname;
                    } catch (...) {
                    }
                } else if (rec.type == DNS_TYPE_TXT) {
                    std::string text;
                    size_t i = 0;
                    while (i < rec.rdata.size()) {
                        uint8_t len = rec.rdata[i++];
                        if (i + len > rec.rdata.size()) break;
                        if (!text.empty()) text.push_back(' ');
                        text.append(reinterpret_cast<const char*>(rec.rdata.data() + i), len);
                        i += len;
                    }
                    rec.value = text;
                }
                offset += rdlen;
                out.push_back(rec);
            }
        };

        section(an, msg.answers);
        section(ns, msg.authority);
        section(ar, msg.additional);
    } catch (const std::exception& ex) {
        msg.parse_error = ex.what();
    }
    return msg;
}

} // namespace core
} // namespace whitedns
