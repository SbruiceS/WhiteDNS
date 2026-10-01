#include "whitedns/core/ProtocolEngine.h"

#include <iostream>
#include <set>
#include <sstream>

namespace whitedns {
namespace core {
namespace {

constexpr size_t kMaxName = 255;
constexpr int kMaxJumps = 16;
constexpr int kMaxLabels = 128;

bool need(const std::vector<uint8_t>& p, size_t off, size_t n, ProtoView& v, const char* cat) {
    if (off > p.size() || n > p.size() - off) {
        v.findings.push_back({cat, off, "read past packet"});
        return false;
    }
    return true;
}

uint16_t be16(const std::vector<uint8_t>& p, size_t off) {
    return static_cast<uint16_t>((p[off] << 8) | p[off + 1]);
}

bool read_name(const std::vector<uint8_t>& p, size_t& off, std::string& out, ProtoView& v) {
    size_t cursor = off;
    int jumps = 0;
    int labels = 0;
    size_t written = 0;
    bool jumped = false;
    std::set<size_t> seen;
    out.clear();
    while (labels < kMaxLabels) {
        if (!need(p, cursor, 1, v, "InvalidName")) return false;
        uint8_t len = p[cursor];
        if ((len & 0xc0) == 0xc0) {
            if (!need(p, cursor, 2, v, "CompressionOutOfBounds")) return false;
            size_t ptr = static_cast<size_t>(((len & 0x3f) << 8) | p[cursor + 1]);
            if (ptr >= p.size()) {
                v.findings.push_back({"CompressionOutOfBounds", cursor, "pointer past packet"});
                return false;
            }
            if (!seen.insert(ptr).second || jumps >= kMaxJumps) {
                v.findings.push_back({"CompressionLoop", cursor, "pointer cycle or depth"});
                return false;
            }
            if (!jumped) off = cursor + 2;
            jumped = true;
            cursor = ptr;
            jumps++;
            continue;
        }
        if (len == 0) {
            if (!jumped) off = cursor + 1;
            if (out.empty()) out = ".";
            return true;
        }
        if (len > 63) {
            v.findings.push_back({"InvalidName", cursor, "label longer than 63"});
            return false;
        }
        if (!need(p, cursor + 1, len, v, "InvalidName")) return false;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(&p[cursor + 1]), len);
        written += len + 1;
        if (written > kMaxName) {
            v.findings.push_back({"InvalidName", cursor, "name longer than 255"});
            return false;
        }
        cursor += 1 + len;
        labels++;
        if (!jumped) off = cursor;
    }
    v.findings.push_back({"CompressionDepthExceeded", cursor, "too many labels"});
    return false;
}

std::string note_rdata(uint16_t type, const std::vector<uint8_t>& rd, const std::vector<uint8_t>&, size_t rd_at, ProtoView& v) {
    std::ostringstream o;
    o << "type=" << type << " rdlen=" << rd.size();
    if (type == 1 && rd.size() == 4)
        o << " A " << int(rd[0]) << "." << int(rd[1]) << "." << int(rd[2]) << "." << int(rd[3]);
    else if (type == 28 && rd.size() == 16)
        o << " AAAA";
    else if (type == 15 && rd.size() >= 2)
        o << " MX pref=" << ((rd[0] << 8) | rd[1]);
    else if (type == 16) {
        size_t i = 0;
        int strings = 0;
        while (i < rd.size()) {
            uint8_t n = rd[i++];
            if (i + n > rd.size()) {
                v.findings.push_back({"InvalidRData", rd_at, "TXT string overruns rdlen"});
                break;
            }
            i += n;
            strings++;
        }
        o << " TXT strings=" << strings;
    } else if (type == 6 && rd.size() >= 20)
        o << " SOA";
    else if (type == 257 && rd.size() >= 2)
        o << " CAA taglen=" << int(rd[0]);
    else if (type == 33 && rd.size() >= 6)
        o << " SRV port=" << ((rd[4] << 8) | rd[5]);
    else if (type == 64 || type == 65) {
        if (rd.size() >= 2) o << (type == 65 ? " HTTPS" : " SVCB") << " prio=" << ((rd[0] << 8) | rd[1]);
    } else if (type == 43 && rd.size() >= 4)
        o << " DS keytag=" << ((rd[0] << 8) | rd[1]) << " alg=" << int(rd[2]);
    else if (type == 48 && rd.size() >= 4)
        o << " DNSKEY flags=" << ((rd[0] << 8) | rd[1]) << " alg=" << int(rd[3]);
    else if (type == 46 && rd.size() >= 18)
        o << " RRSIG covered=" << ((rd[0] << 8) | rd[1]);
    else if (type == 47)
        o << " NSEC";
    else if (type == 50)
        o << " NSEC3";
    else if (type == 41)
        o << " OPT";
    else
        o << " opaque";
    return o.str();
}

} // namespace

ProtoView parse_strict(const std::vector<uint8_t>& packet) {
    ProtoView v;
    if (packet.size() < 12) {
        v.findings.push_back({"PacketTooShort", 0, "header needs 12 bytes"});
        return v;
    }
    v.id = be16(packet, 0);
    uint16_t flags = be16(packet, 2);
    v.opcode = static_cast<uint8_t>((flags >> 11) & 0x0f);
    v.aa = flags & 0x0400;
    v.tc = flags & 0x0200;
    v.rcode = flags & 0x000f;
    if (v.opcode > 5) v.findings.push_back({"InvalidOpcode", 2, "reserved opcode kept, not fatal"});
    uint16_t qd = be16(packet, 4);
    uint16_t an = be16(packet, 6);
    uint16_t ns = be16(packet, 8);
    uint16_t ar = be16(packet, 10);
    size_t off = 12;
    for (uint16_t i = 0; i < qd; ++i) {
        std::string name;
        if (!read_name(packet, off, name, v)) return v;
        if (!need(packet, off, 4, v, "InvalidQuestion")) return v;
        if (i == 0) v.qname = name;
        off += 4;
        v.questions++;
    }
    auto section = [&](uint16_t count, bool additional) {
        for (uint16_t i = 0; i < count; ++i) {
            std::string name;
            if (!read_name(packet, off, name, v)) return false;
            if (!need(packet, off, 10, v, "InvalidRRLength")) return false;
            uint16_t type = be16(packet, off);
            uint16_t rdlen = be16(packet, off + 8);
            off += 10;
            if (!need(packet, off, rdlen, v, "InvalidRData")) return false;
            std::vector<uint8_t> rd(packet.begin() + static_cast<std::ptrdiff_t>(off),
                                    packet.begin() + static_cast<std::ptrdiff_t>(off + rdlen));
            off += rdlen;
            if (type == 41) {
                v.opt++;
                if (!additional) v.findings.push_back({"DuplicateOPT", off, "OPT outside additional"});
            }
            v.rdata_notes.push_back(note_rdata(type, rd, packet, off, v));
            if (!additional) v.answers++;
        }
        return true;
    };
    if (!section(an, false)) return v;
    if (!section(ns, false)) return v;
    if (!section(ar, true)) return v;
    if (v.rcode == 3) v.findings.push_back({"NXDOMAIN", 2, "name does not exist; not NODATA"});
    if (v.rcode == 0 && v.answers == 0 && qd > 0)
        v.findings.push_back({"NODATA", 6, "NOERROR and no answer; not NXDOMAIN"});
    if (v.opt > 1) v.findings.push_back({"DuplicateOPT", 0, "more than one OPT"});
    if (v.tc) v.findings.push_back({"TruncatedResponse", 2, "TC=1 does not mean records are absent"});
    v.ok = v.findings.empty() || (v.findings.size() == 1 && v.findings[0].category == "TruncatedResponse");
    return v;
}

int run_protocol_selftest(std::ostream& out) {
    int fail = 0;
    auto check = [&](const char* name, bool cond) {
        out << (cond ? "pass " : "fail ") << name << "\n";
        if (!cond) fail++;
    };
    std::vector<uint8_t> shortp{0, 1, 2};
    auto s = parse_strict(shortp);
    check("short header", !s.ok && !s.findings.empty() && s.findings[0].category == "PacketTooShort");

    std::vector<uint8_t> loop(12, 0);
    loop[5] = 1;
    loop.push_back(0xc0);
    loop.push_back(12);
    loop.push_back(0);
    loop.push_back(1);
    loop.push_back(0);
    loop.push_back(1);
    auto l = parse_strict(loop);
    check("compression loop", !l.ok);

    std::vector<uint8_t> okp = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 8, 8, 8, 8};
    auto g = parse_strict(okp);
    check("bounded A parse", g.ok && g.qname == "google.com" && g.answers == 1);

    std::vector<uint8_t> txt = {
        0, 1, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0,
        1, 'a', 0, 0, 16, 0, 1,
        0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 1, 0, 5, 4, 'v', '=', 's', '1'};
    auto t = parse_strict(txt);
    check("txt strings", t.ok && !t.rdata_notes.empty() && t.rdata_notes[0].find("TXT strings=1") != std::string::npos);

    std::vector<uint8_t> nx = {0, 2, 0x80, 3, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'b', 0, 0, 1, 0, 1};
    auto n = parse_strict(nx);
    bool saw_nx = false;
    for (const auto& f : n.findings) if (f.category == "NXDOMAIN") saw_nx = true;
    check("nxdomain not nodata", saw_nx);

    std::vector<uint8_t> badtxt = {
        0, 3, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0,
        1, 'c', 0, 0, 16, 0, 1,
        0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 1, 0, 2, 5, 'x'};
    auto bt = parse_strict(badtxt);
    bool overrun = false;
    for (const auto& f : bt.findings) if (f.category == "InvalidRData") overrun = true;
    check("txt overrun", overrun);
    out << "protocol selftest failures=" << fail << "\n";
    return fail == 0 ? 0 : 1;
}

} // namespace core
} // namespace whitedns
