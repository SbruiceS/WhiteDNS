#include "whitedns/DnsClient.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
constexpr socket_t invalid_socket_value = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t invalid_socket_value = -1;
#endif

namespace whitedns {
namespace {

class SocketRuntime {
public:
    SocketRuntime() {
#ifdef _WIN32
        WSADATA data;
        WSAStartup(MAKEWORD(2, 2), &data);
#endif
    }

    ~SocketRuntime() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

SocketRuntime& socket_runtime() {
    static SocketRuntime runtime;
    return runtime;
}

void close_socket(socket_t sock) {
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

bool set_nonblocking(socket_t sock, bool enabled) {
#ifdef _WIN32
    u_long mode = enabled ? 1UL : 0UL;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return false;
    if (enabled) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(sock, F_SETFL, flags) == 0;
#endif
}

std::string socket_error_message(const std::string& prefix) {
#ifdef _WIN32
    return prefix + ": socket error " + std::to_string(WSAGetLastError());
#else
    return prefix + ": " + std::strerror(errno);
#endif
}

bool would_block_error() {
#ifdef _WIN32
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS;
#else
    return errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS;
#endif
}

bool wait_for_socket(socket_t sock, bool write, std::chrono::milliseconds timeout) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    timeval tv;
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

    int result = select(static_cast<int>(sock + 1), write ? nullptr : &fds, write ? &fds : nullptr, nullptr, &tv);
    return result > 0 && FD_ISSET(sock, &fds);
}

void write_u16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

void write_u32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

uint16_t read_u16(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 2 > data.size()) throw std::runtime_error("short dns packet");
    return static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
}

uint32_t read_u32(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 4 > data.size()) throw std::runtime_error("short dns packet");
    return (static_cast<uint32_t>(data[offset]) << 24) |
           (static_cast<uint32_t>(data[offset + 1]) << 16) |
           (static_cast<uint32_t>(data[offset + 2]) << 8) |
           static_cast<uint32_t>(data[offset + 3]);
}

std::vector<uint8_t> encode_name(const std::string& domain) {
    std::vector<uint8_t> encoded;
    size_t start = 0;
    while (start < domain.size()) {
        size_t end = domain.find('.', start);
        if (end == std::string::npos) end = domain.size();
        size_t len = end - start;
        if (len == 0 || len > 63) throw std::runtime_error("invalid domain label");
        encoded.push_back(static_cast<uint8_t>(len));
        encoded.insert(encoded.end(), domain.begin() + static_cast<std::ptrdiff_t>(start), domain.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    encoded.push_back(0);
    return encoded;
}

std::string decode_name(const std::vector<uint8_t>& data, size_t& offset) {
    std::string name;
    size_t cursor = offset;
    size_t jumps = 0;
    bool jumped = false;

    while (cursor < data.size()) {
        uint8_t len = data[cursor];
        if ((len & 0xc0) == 0xc0) {
            if (cursor + 1 >= data.size()) throw std::runtime_error("bad compression pointer");
            uint16_t pointer = static_cast<uint16_t>(((len & 0x3f) << 8) | data[cursor + 1]);
            if (!jumped) offset = cursor + 2;
            cursor = pointer;
            jumped = true;
            if (++jumps > 20) throw std::runtime_error("dns compression loop");
            continue;
        }
        if (len == 0) {
            if (!jumped) offset = cursor + 1;
            return name.empty() ? "." : name;
        }
        ++cursor;
        if (cursor + len > data.size()) throw std::runtime_error("bad dns name");
        if (!name.empty()) name.push_back('.');
        name.append(reinterpret_cast<const char*>(&data[cursor]), len);
        cursor += len;
    }

    throw std::runtime_error("unterminated dns name");
}

std::vector<uint8_t> build_query(const std::string& domain, uint16_t query_type, uint16_t id, bool request_dnssec) {
    std::vector<uint8_t> packet;
    write_u16(packet, id);
    write_u16(packet, 0x0100);
    write_u16(packet, 1);
    write_u16(packet, 0);
    write_u16(packet, 0);
    write_u16(packet, request_dnssec ? 1 : 0);

    std::vector<uint8_t> name = encode_name(domain);
    packet.insert(packet.end(), name.begin(), name.end());
    write_u16(packet, query_type);
    write_u16(packet, 1);

    if (request_dnssec) {
        packet.push_back(0);
        write_u16(packet, 41);
        write_u16(packet, 1232);
        write_u32(packet, 0x00008000);
        write_u16(packet, 0);
    }

    return packet;
}

std::string parse_record_value(const std::vector<uint8_t>& data, const DnsRecord& record, size_t rdata_offset, uint16_t rdlength) {
    if (rdata_offset + rdlength > data.size()) return "<truncated rdata>";

    char address[INET6_ADDRSTRLEN] = {};
    if (record.type == DNS_TYPE_A && rdlength == 4) {
        inet_ntop(AF_INET, data.data() + rdata_offset, address, sizeof(address));
        return address;
    }

    if (record.type == DNS_TYPE_AAAA && rdlength == 16) {
        inet_ntop(AF_INET6, data.data() + rdata_offset, address, sizeof(address));
        return address;
    }

    if (record.type == DNS_TYPE_NS) {
        size_t name_offset = rdata_offset;
        return decode_name(data, name_offset);
    }

    if (record.type == DNS_TYPE_TXT) {
        std::string text;
        size_t cursor = rdata_offset;
        const size_t end = rdata_offset + rdlength;
        while (cursor < end) {
            uint8_t len = data[cursor++];
            if (cursor + len > end) break;
            if (!text.empty()) text.push_back(' ');
            text.append(reinterpret_cast<const char*>(&data[cursor]), len);
            cursor += len;
        }
        return text;
    }

    if (record.type == DNS_TYPE_MX && rdlength >= 3) {
        uint16_t preference = read_u16(data, rdata_offset);
        size_t name_offset = rdata_offset + 2;
        return decode_name(data, name_offset) + " (pref " + std::to_string(preference) + ")";
    }

    if (record.type == DNS_TYPE_SOA) {
        size_t name_offset = rdata_offset;
        std::string mname = decode_name(data, name_offset);
        std::string rname = decode_name(data, name_offset);
        if (name_offset + 20 > rdata_offset + rdlength) return "SOA " + mname + " " + rname;
        return "SOA " + mname + " " + rname + " serial " + std::to_string(read_u32(data, name_offset));
    }

    if (record.type == DNS_TYPE_DNSKEY && rdlength >= 4) {
        uint16_t flags = read_u16(data, rdata_offset);
        uint8_t protocol = data[rdata_offset + 2];
        uint8_t algorithm = data[rdata_offset + 3];
        return "DNSKEY flags " + std::to_string(flags) + " protocol " + std::to_string(protocol) +
               " algorithm " + std::to_string(algorithm) + " key-bytes " + std::to_string(rdlength - 4);
    }

    if (record.type == DNS_TYPE_RRSIG && rdlength >= 18) {
        uint16_t covered = read_u16(data, rdata_offset);
        uint8_t algorithm = data[rdata_offset + 2];
        uint16_t key_tag = read_u16(data, rdata_offset + 16);
        size_t signer_offset = rdata_offset + 18;
        std::string signer = decode_name(data, signer_offset);
        return "RRSIG " + dns_type_to_string(covered) + " algorithm " + std::to_string(algorithm) +
               " key-tag " + std::to_string(key_tag) + " signer " + signer;
    }

    if (record.type == DNS_TYPE_CAA && rdlength >= 2) {
        uint8_t flags = data[rdata_offset];
        uint8_t tag_length = data[rdata_offset + 1];
        std::string tag;
        std::string value;
        size_t cursor = rdata_offset + 2;
        if (cursor + tag_length <= rdata_offset + rdlength) {
            tag.assign(reinterpret_cast<const char*>(data.data() + cursor), tag_length);
            cursor += tag_length;
            if (cursor <= rdata_offset + rdlength) {
                value.assign(reinterpret_cast<const char*>(data.data() + cursor), rdata_offset + rdlength - cursor);
            }
        }
        return "CAA flags=" + std::to_string(flags) + " tag=" + tag + " value=" + value;
    }

    if (record.type == DNS_TYPE_SRV && rdlength >= 6) {
        uint16_t priority = read_u16(data, rdata_offset);
        uint16_t weight = read_u16(data, rdata_offset + 2);
        uint16_t port = read_u16(data, rdata_offset + 4);
        size_t target_offset = rdata_offset + 6;
        std::string target = decode_name(data, target_offset);
        return "SRV priority=" + std::to_string(priority) + " weight=" + std::to_string(weight) + " port=" + std::to_string(port) + " target=" + target;
    }

    if (record.type == DNS_TYPE_NAPTR && rdlength >= 5) {
        uint16_t order = read_u16(data, rdata_offset);
        uint16_t preference = read_u16(data, rdata_offset + 2);
        size_t cursor = rdata_offset + 4;
        uint8_t flags_len = data[cursor++];
        std::string flags(reinterpret_cast<const char*>(data.data() + cursor), flags_len);
        cursor += flags_len;
        uint8_t service_len = data[cursor++];
        std::string service(reinterpret_cast<const char*>(data.data() + cursor), service_len);
        cursor += service_len;
        uint8_t regexp_len = data[cursor++];
        std::string regexp(reinterpret_cast<const char*>(data.data() + cursor), regexp_len);
        cursor += regexp_len;
        std::string replacement = decode_name(data, cursor);
        return "NAPTR order=" + std::to_string(order) + " preference=" + std::to_string(preference) + " flags=" + flags + " service=" + service + " regexp=" + regexp + " replacement=" + replacement;
    }

    if (record.type == DNS_TYPE_DS && rdlength >= 4) {
        uint16_t key_tag = read_u16(data, rdata_offset);
        uint8_t algorithm = data[rdata_offset + 2];
        uint8_t digest_type = data[rdata_offset + 3];
        std::ostringstream hex;
        for (size_t i = rdata_offset + 4; i < rdata_offset + rdlength; ++i) {
            hex << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
        return "DS key_tag=" + std::to_string(key_tag) + " algorithm=" + std::to_string(algorithm) + " digest_type=" + std::to_string(digest_type) + " digest_hex=" + hex.str();
    }

    if (record.type == DNS_TYPE_TLSA && rdlength >= 3) {
        uint8_t usage = data[rdata_offset];
        uint8_t selector = data[rdata_offset + 1];
        uint8_t matching_type = data[rdata_offset + 2];
        std::ostringstream hex;
        for (size_t i = rdata_offset + 3; i < rdata_offset + rdlength; ++i) {
            hex << std::hex << std::uppercase << (data[i] >> 4);
            hex << std::hex << std::uppercase << (data[i] & 0x0F);
        }
        return "TLSA usage=" + std::to_string(usage) + " selector=" + std::to_string(selector) + " matching_type=" + std::to_string(matching_type) + " data=" + hex.str();
    }

    if (record.type == DNS_TYPE_SSHFP && rdlength >= 2) {
        uint8_t algorithm = data[rdata_offset];
        uint8_t fp_type = data[rdata_offset + 1];
        std::ostringstream hex;
        for (size_t i = rdata_offset + 2; i < rdata_offset + rdlength; ++i) {
            hex << std::hex << std::uppercase << (data[i] >> 4);
            hex << std::hex << std::uppercase << (data[i] & 0x0F);
        }
        return "SSHFP algorithm=" + std::to_string(algorithm) + " type=" + std::to_string(fp_type) + " fingerprint=" + hex.str();
    }

    if (record.type == DNS_TYPE_CNAME || record.type == DNS_TYPE_PTR || record.type == DNS_TYPE_DNAME) {
        size_t name_offset = rdata_offset;
        return decode_name(data, name_offset);
    }

    return "Record type " + std::to_string(record.type) + " (" + std::to_string(rdlength) + " bytes)";
}

DnsResponse parse_response(const std::vector<uint8_t>& data,
                           const std::string& domain,
                           const std::string& server,
                           uint16_t query_type) {
    if (data.size() < 12) throw std::runtime_error("short dns response");

    DnsResponse response;
    response.domain = domain;
    response.server = server;
    response.query_type = query_type;
    response.query_type_name = dns_type_to_string(query_type);
    response.response_size = data.size();

    uint16_t flags = read_u16(data, 2);
    response.truncated = (flags & 0x0200) != 0;
    response.rcode = flags & 0x000f;

    uint16_t questions = read_u16(data, 4);
    uint16_t answers = read_u16(data, 6);
    uint16_t authorities = read_u16(data, 8);
    uint16_t additionals = read_u16(data, 10);
    response.answer_count = answers;
    response.authority_count = authorities;
    response.additional_count = additionals;
    response.authoritative = (flags & 0x0400) != 0;

    size_t offset = 12;
    for (uint16_t i = 0; i < questions; ++i) {
        decode_name(data, offset);
        if (offset + 4 > data.size()) throw std::runtime_error("bad question section");
        offset += 4;
    }

    auto parse_section = [&](uint16_t count, std::vector<DnsRecord>& out, const char* label) {
        for (uint16_t i = 0; i < count; ++i) {
            decode_name(data, offset);
            if (offset + 10 > data.size()) throw std::runtime_error(std::string("bad ") + label + " section");
            DnsRecord record;
            record.type = read_u16(data, offset);
            record.type_name = dns_type_to_string(record.type);
            offset += 2;
            offset += 2;
            record.ttl = read_u32(data, offset);
            offset += 4;
            uint16_t rdlength = read_u16(data, offset);
            offset += 2;
            size_t rdata_offset = offset;
            if (rdata_offset + rdlength <= data.size()) {
                record.rdata.assign(data.begin() + static_cast<std::ptrdiff_t>(rdata_offset),
                                    data.begin() + static_cast<std::ptrdiff_t>(rdata_offset + rdlength));
            }
            record.value = parse_record_value(data, record, rdata_offset, rdlength);
            offset += rdlength;
            if (record.type != 41) out.push_back(record);
        }
    };

    parse_section(answers, response.answers, "answer");
    parse_section(authorities, response.authority, "authority");
    std::vector<DnsRecord> additional;
    parse_section(additionals, additional, "additional");
    for (const auto& rec : additional) {
        if (rec.type == DNS_TYPE_A || rec.type == DNS_TYPE_AAAA || rec.type == DNS_TYPE_DNSKEY || rec.type == DNS_TYPE_DS)
            response.answers.push_back(rec);
    }

    return response;
}

std::vector<uint8_t> query_udp(const std::string& server,
                               const std::vector<uint8_t>& query,
                               std::chrono::milliseconds timeout) {
    socket_runtime();

    addrinfo hints{};
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* resolved = nullptr;
    if (getaddrinfo(server.c_str(), "53", &hints, &resolved) != 0) {
        throw std::runtime_error("failed to resolve DNS server " + server);
    }

    std::vector<uint8_t> response(4096);
    std::string last_error;

    for (addrinfo* addr = resolved; addr != nullptr; addr = addr->ai_next) {
        socket_t sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock == invalid_socket_value) continue;

        int sent = sendto(sock, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0, addr->ai_addr, static_cast<int>(addr->ai_addrlen));
        if (sent < 0 || static_cast<size_t>(sent) != query.size()) {
            last_error = socket_error_message("sendto failed");
            close_socket(sock);
            continue;
        }

        if (!wait_for_socket(sock, false, timeout)) {
            last_error = "UDP query timed out";
            close_socket(sock);
            continue;
        }

        int received = recvfrom(sock, reinterpret_cast<char*>(response.data()), static_cast<int>(response.size()), 0, nullptr, nullptr);
        close_socket(sock);
        if (received > 0) {
            response.resize(static_cast<size_t>(received));
            freeaddrinfo(resolved);
            return response;
        }
        last_error = socket_error_message("recvfrom failed");
    }

    freeaddrinfo(resolved);
    throw std::runtime_error(last_error.empty() ? "UDP query failed" : last_error);
}

std::vector<uint8_t> query_tcp(const std::string& server,
                               const std::vector<uint8_t>& query,
                               std::chrono::milliseconds timeout) {
    socket_runtime();

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo* resolved = nullptr;
    if (getaddrinfo(server.c_str(), "53", &hints, &resolved) != 0) {
        throw std::runtime_error("failed to resolve DNS server " + server);
    }

    std::string last_error;
    for (addrinfo* addr = resolved; addr != nullptr; addr = addr->ai_next) {
        socket_t sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (sock == invalid_socket_value) continue;
        set_nonblocking(sock, true);

        int result = connect(sock, addr->ai_addr, static_cast<int>(addr->ai_addrlen));
        if (result != 0 && !would_block_error()) {
            last_error = socket_error_message("connect failed");
            close_socket(sock);
            continue;
        }

        if (result != 0 && !wait_for_socket(sock, true, timeout)) {
            last_error = "TCP query timed out";
            close_socket(sock);
            continue;
        }

        int socket_error_value = 0;
#ifdef _WIN32
        int socket_error_len = sizeof(socket_error_value);
#else
        socklen_t socket_error_len = sizeof(socket_error_value);
#endif
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error_value), &socket_error_len) != 0 || socket_error_value != 0) {
            last_error = "TCP connect failed";
            close_socket(sock);
            continue;
        }

        std::vector<uint8_t> framed;
        write_u16(framed, static_cast<uint16_t>(query.size()));
        framed.insert(framed.end(), query.begin(), query.end());

        size_t sent_total = 0;
        while (sent_total < framed.size()) {
            if (!wait_for_socket(sock, true, timeout)) break;
            int sent = send(sock, reinterpret_cast<const char*>(framed.data() + sent_total), static_cast<int>(framed.size() - sent_total), 0);
            if (sent <= 0) {
                if (would_block_error()) continue;
                break;
            }
            sent_total += static_cast<size_t>(sent);
        }

        std::array<uint8_t, 2> length_buf{};
        size_t length_read = 0;
        while (length_read < length_buf.size()) {
            if (!wait_for_socket(sock, false, timeout)) break;
            int received = recv(sock, reinterpret_cast<char*>(length_buf.data() + length_read), static_cast<int>(length_buf.size() - length_read), 0);
            if (received <= 0) {
                if (would_block_error()) continue;
                break;
            }
            length_read += static_cast<size_t>(received);
        }
        if (length_read != length_buf.size()) {
            last_error = socket_error_message("TCP response length read failed");
            close_socket(sock);
            continue;
        }

        uint16_t response_len = static_cast<uint16_t>((length_buf[0] << 8) | length_buf[1]);
        std::vector<uint8_t> response(response_len);
        size_t read_total = 0;
        while (read_total < response_len) {
            if (!wait_for_socket(sock, false, timeout)) break;
            int chunk = recv(sock, reinterpret_cast<char*>(response.data() + read_total), static_cast<int>(response_len - read_total), 0);
            if (chunk <= 0) {
                if (would_block_error()) continue;
                break;
            }
            read_total += static_cast<size_t>(chunk);
        }
        close_socket(sock);

        if (read_total == response_len) {
            freeaddrinfo(resolved);
            return response;
        }
        last_error = "short TCP DNS response";
    }

    freeaddrinfo(resolved);
    throw std::runtime_error(last_error.empty() ? "TCP query failed" : last_error);
}

uint16_t next_query_id() {
    static std::atomic<uint16_t> counter{0};
    static const uint16_t seed = static_cast<uint16_t>(std::random_device{}());
    return static_cast<uint16_t>(seed + counter.fetch_add(1));
}

} // namespace

DnsClient::DnsClient(std::chrono::milliseconds timeout) : timeout_(timeout) {}

DnsResponse DnsClient::query(const std::string& domain,
                             const std::string& server,
                             uint16_t query_type,
                             bool request_dnssec) const {
    std::string server_to_use = server.empty() ? "8.8.8.8" : server;
    DnsResponse response;
    response.domain = domain;
    response.server = server_to_use;
    response.query_type = query_type;
    response.query_type_name = dns_type_to_string(query_type);

    try {
        std::vector<uint8_t> packet = build_query(domain, query_type, next_query_id(), request_dnssec);
        std::vector<uint8_t> wire = query_type == DNS_TYPE_AXFR
            ? query_tcp(server_to_use, packet, timeout_)
            : query_udp(server_to_use, packet, timeout_);
        response = parse_response(wire, domain, server_to_use, query_type);
        if (response.truncated) {
            wire = query_tcp(server_to_use, packet, timeout_);
            response = parse_response(wire, domain, server_to_use, query_type);
        }
    } catch (const std::exception& ex) {
        response.error = true;
        response.error_message = ex.what();
    }

    return response;
}

std::string dns_type_to_string(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA: return "SOA";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        case DNS_TYPE_SRV: return "SRV";
        case DNS_TYPE_NAPTR: return "NAPTR";
        case DNS_TYPE_DS: return "DS";
        case DNS_TYPE_SSHFP: return "SSHFP";
        case DNS_TYPE_SPF: return "SPF";
        case DNS_TYPE_RRSIG: return "RRSIG";
        case DNS_TYPE_DNSKEY: return "DNSKEY";
        case DNS_TYPE_TLSA: return "TLSA";
        case DNS_TYPE_AXFR: return "AXFR";
        case DNS_TYPE_CAA: return "CAA";
        case DNS_TYPE_ANY: return "ANY";
        default: return "TYPE" + std::to_string(type);
    }
}

int dns_type_from_string(const std::string& raw_type) {
    std::string type = raw_type;
    std::transform(type.begin(), type.end(), type.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });

    if (type == "A") return DNS_TYPE_A;
    if (type == "AAAA") return DNS_TYPE_AAAA;
    if (type == "CNAME") return DNS_TYPE_CNAME;
    if (type == "NS") return DNS_TYPE_NS;
    if (type == "TXT") return DNS_TYPE_TXT;
    if (type == "SOA") return DNS_TYPE_SOA;
    if (type == "MX") return DNS_TYPE_MX;
    if (type == "SRV") return DNS_TYPE_SRV;
    if (type == "NAPTR") return DNS_TYPE_NAPTR;
    if (type == "DS") return DNS_TYPE_DS;
    if (type == "SSHFP") return DNS_TYPE_SSHFP;
    if (type == "DNSKEY") return DNS_TYPE_DNSKEY;
    if (type == "RRSIG") return DNS_TYPE_RRSIG;
    if (type == "TLSA") return DNS_TYPE_TLSA;
    if (type == "AXFR") return DNS_TYPE_AXFR;
    if (type == "CAA") return DNS_TYPE_CAA;
    if (type == "ANY") return DNS_TYPE_ANY;
    return -1;
}

} // namespace whitedns
