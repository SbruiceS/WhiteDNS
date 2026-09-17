#ifndef WHITEDNS_CORE_TRANSPORT_H
#define WHITEDNS_CORE_TRANSPORT_H

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace whitedns {
namespace core {

enum class TransportKind { Udp, Tcp, Tls, Https };

struct TransportResult {
    bool ok = false;
    std::vector<uint8_t> bytes;
    std::string error;
    std::chrono::milliseconds rtt{0};
    TransportKind kind = TransportKind::Udp;
    std::string endpoint;
};

class DnsTransport {
public:
    virtual ~DnsTransport() = default;
    virtual TransportResult query(const std::string& server,
                                  uint16_t port,
                                  const std::vector<uint8_t>& packet,
                                  std::chrono::milliseconds timeout) = 0;
    virtual TransportKind kind() const = 0;
};

class UdpTransport : public DnsTransport {
public:
    TransportResult query(const std::string& server,
                          uint16_t port,
                          const std::vector<uint8_t>& packet,
                          std::chrono::milliseconds timeout) override;
    TransportKind kind() const override { return TransportKind::Udp; }
};

class TcpTransport : public DnsTransport {
public:
    TransportResult query(const std::string& server,
                          uint16_t port,
                          const std::vector<uint8_t>& packet,
                          std::chrono::milliseconds timeout) override;
    TransportKind kind() const override { return TransportKind::Tcp; }
};

const char* transport_name(TransportKind kind);

} // namespace core
} // namespace whitedns

#endif
