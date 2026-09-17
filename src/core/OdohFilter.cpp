#include "whitedns/core/OdohFilter.h"

#include "whitedns/IanaDns.h"
#include "whitedns/core/ResolverEngine.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <set>
#include <sstream>

namespace whitedns {
namespace core {
namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string host_only(std::string url) {
    auto p = url.find("://");
    if (p != std::string::npos) url = url.substr(p + 3);
    auto slash = url.find('/');
    if (slash != std::string::npos) url = url.substr(0, slash);
    auto q = url.find('?');
    if (q != std::string::npos) url = url.substr(0, q);
    auto colon = url.find(':');
    if (colon != std::string::npos) url = url.substr(0, colon);
    return lower(url);
}

std::string registrable(const std::string& host) {
    auto a = host.rfind('.');
    if (a == std::string::npos || a == 0) return host;
    auto b = host.rfind('.', a - 1);
    if (b == std::string::npos) return host;
    return host.substr(b + 1);
}

bool is_internal_name(const std::string& qname) {
    std::string q = lower(qname);
    while (!q.empty() && q.back() == '.') q.pop_back();
    static const char* suf[] = {
        ".local", ".lan", ".home", ".corp", ".internal", ".intranet",
        ".private", ".lan.local", ".home.arpa", ".onion", nullptr};
    if (q == "localhost" || q == "localhost.localdomain") return true;
    for (int i = 0; suf[i]; ++i) {
        size_t n = std::char_traits<char>::length(suf[i]);
        if (q.size() >= n && q.compare(q.size() - n, n, suf[i]) == 0) return true;
    }
    if (q.find(".in-addr.arpa") != std::string::npos || q.find(".ip6.arpa") != std::string::npos)
        return false;
    return false;
}

bool dangerous_qtype(uint16_t t) {
    return t == DNS_TYPE_AXFR || t == DNS_TYPE_ANY;
}

bool allowlisted_relay(const std::string& host) {
    static const char* ok[] = {
        "odoh-relay.edgecompute.app",
        "odoh-relay.numa.rs",
        nullptr};
    for (int i = 0; ok[i]; ++i)
        if (host == ok[i]) return true;
    return host.empty();
}

OdohFilterFinding F(const char* id, const char* title, const std::string& status,
                    const std::string& sev, const std::string& klass,
                    const std::string& msg, const std::string& change = "") {
    OdohFilterFinding f;
    f.id = id;
    f.title = title;
    f.status = status;
    f.severity = sev;
    f.klass = klass;
    f.message = msg;
    f.change = change;
    return f;
}

int points(const OdohFilterFinding& f) {
    if (f.status == "pass" || f.status == "info") return 0;
    if (f.severity == "critical") return 40;
    if (f.severity == "high") return 25;
    if (f.severity == "medium") return 15;
    return 8;
}

} // namespace

OdohFilterReport run_odoh_filter(const std::string& qname,
                                 uint16_t qtype,
                                 const std::string& target,
                                 const std::string& proxy,
                                 const std::string& scope) {
    OdohFilterReport report;
    report.qname = qname;
    report.qtype = qtype;

    if (!in_scope(qname, scope)) {
        report.allow = false;
        report.posture = "blocked";
        report.score = 100;
        report.findings.push_back(F("ODOH-SCOPE-001", "Scope gate", "fail", "critical", "POLICY",
                                    "QNAME is outside --scope. Public ODoH would leak an unauthorized name.",
                                    "Do not send out-of-scope names to a public target."));
        return report;
    }

    if (is_internal_name(qname)) {
        report.findings.push_back(F("ODOH-LEAK-002", "Internal / split-horizon name", "warning", "low", "OBSERVATION",
                                    "QNAME looks internal (.internal/.corp/.local/…). Allowed: operator may resolve it over ODoH.",
                                    "The public target will see this name. That is accepted when the operator authorizes the query."));
    }

    if (dangerous_qtype(qtype)) {
        report.allow = false;
        report.posture = "blocked";
        report.score = 80;
        report.findings.push_back(F("ODOH-QTYPE-003", "Dangerous qtype", "fail", "high", "POLICY",
                                    "AXFR/ANY must not ride a public ODoH path.",
                                    "Use authorized authoritative channels for zone transfer tests."));
        return report;
    }

    report.path = odoh_lookup(qname, qtype, target, proxy);
    const auto& p = report.path;
    std::string relay = host_only(p.proxy);
    std::string tgt = host_only(p.target.empty() ? target : p.target);

    if (p.kem_id && (p.kem_id != 0x0020 || p.kdf_id != 0x0001 || p.aead_id != 0x0001)) {
        report.findings.push_back(F("ODOH-SUITE-004", "HPKE suite pin", "fail", "high", "ANOMALY",
                                    "Target advertised a non-default HPKE suite. WhiteDNS only pins X25519-HKDF-SHA256-AES-128-GCM.",
                                    "Reject unknown suites; rotate only via a signed config channel."));
    } else {
        report.findings.push_back(F("ODOH-SUITE-004", "HPKE suite pin", "pass", "info", "OBSERVATION",
                                    "Suite is X25519 / HKDF-SHA256 / AES-128-GCM (RFC 9230 default)."));
    }

    if (!p.ok) {
        report.findings.push_back(F("ODOH-PATH-005", "ODoH path", "fail", "high", "ANOMALY",
                                    "ODoH lookup failed: " + p.error,
                                    "Keep two independent relays. Direct fallback is not oblivious."));
    } else {
        report.findings.push_back(F("ODOH-PATH-005", "ODoH path", "pass", "info", "OBSERVATION",
                                    std::string("HPKE query/response opened. rcode=") + iana_rcode_name(p.rcode) +
                                        " ciphertext=" + std::to_string(p.ciphertext_bytes) + "B"));
    }

    if (!p.oblivious) {
        report.findings.push_back(F("ODOH-SPLIT-006", "Identity/query split", "fail", "high", "POLICY",
                                    "Path is not oblivious. The target can see this client IP and the QNAME together. That is DoH, not RFC 9230.",
                                    "Force a third-party relay. Never use --proxy direct in production."));
        report.allow = false;
    } else {
        report.findings.push_back(F("ODOH-SPLIT-006", "Identity/query split", "pass", "info", "OBSERVATION",
                                    "Relay " + relay + " forwarded ciphertext to " + tgt + "."));
    }

    if (!relay.empty() && registrable(relay) == registrable(tgt) && !tgt.empty()) {
        report.findings.push_back(F("ODOH-COLLUDE-007", "Relay/target org collision", "fail", "critical", "POLICY",
                                    "Relay and target share registrable domain " + registrable(tgt) +
                                    ". One entity can join IP and QNAME.",
                                    "Pair Cloudflare target with Fastly or Numa, never with a Cloudflare relay."));
        report.allow = false;
    } else if (p.oblivious) {
        report.findings.push_back(F("ODOH-COLLUDE-007", "Relay/target org collision", "pass", "info", "OBSERVATION",
                                    "Relay org (" + registrable(relay) + ") differs from target org (" +
                                    registrable(tgt) + "). Collusion is still a residual legal risk."));
    }

    if (p.oblivious && !allowlisted_relay(relay)) {
        report.findings.push_back(F("ODOH-RELAY-008", "Relay allowlist", "warning", "medium", "POLICY",
                                    "Relay " + relay + " is not on the shipped Fastly/Numa allowlist.",
                                    "Pin relays you operate or that publish a privacy policy you accept."));
    } else if (p.oblivious) {
        report.findings.push_back(F("ODOH-RELAY-008", "Relay allowlist", "pass", "info", "OBSERVATION",
                                    "Relay is on the production allowlist."));
    }

    if (p.ciphertext_bytes > 0 && p.qname_len > 0) {
        // With 128-byte block padding, size should not scale 1:1 with the label.
        bool tight = p.ciphertext_bytes < 80 + p.qname_len;
        report.findings.push_back(F(
            "ODOH-PAD-009", "Length hiding",
            tight ? "warning" : "pass",
            tight ? "low" : "info",
            tight ? "ANOMALY" : "OBSERVATION",
            "Ciphertext " + std::to_string(p.ciphertext_bytes) + "B for QNAME length " +
                std::to_string(p.qname_len) + ". Block padding is applied on send.",
            "Keep block padding; do not disable it for 'smaller packets'."));
    }

    if (p.key_id_hex.size() != 64) {
        report.findings.push_back(F("ODOH-KEYID-010", "key_id width", "warning", "medium", "ANOMALY",
                                    "key_id is not 32-byte SHA-256/HKDF width. Config may be malformed."));
    } else {
        report.findings.push_back(F("ODOH-KEYID-010", "key_id width", "pass", "info", "OBSERVATION",
                                    "key_id is 32 bytes: " + p.key_id_hex.substr(0, 16) + "..."));
    }

    bool rfc1918 = false;
    for (const auto& rec : p.answers) {
        if (rec.type != DNS_TYPE_A) continue;
        if (rec.value.rfind("10.", 0) == 0 || rec.value.rfind("192.168.", 0) == 0 ||
            rec.value.rfind("127.", 0) == 0)
            rfc1918 = true;
    }
    if (rfc1918) {
        report.findings.push_back(F("ODOH-ANS-011", "Private answer on public target", "warning", "medium", "SUSPICIOUS",
                                    "Public ODoH target returned RFC1918/loopback. Unexpected for a public name.",
                                    "Treat as observation; confirm the zone is supposed to publish that."));
    } else if (p.ok && !p.answers.empty()) {
        report.findings.push_back(F("ODOH-ANS-011", "Answer hygiene", "pass", "info", "OBSERVATION",
                                    "Answers are public-looking A/other records."));
    }

    report.findings.push_back(F("ODOH-META-012", "Residual metadata", "info", "info", "OBSERVATION",
                                "Client dials pinned IPs and omits SNI when the handshake allows it. "
                                "Access network should see IP:443, not the hostname. Target still sees QNAME."));

    report.findings.push_back(F("ODOH-LEGAL-013", "Two-party compulsion", "info", "info", "OBSERVATION",
                                "A lawful process served on both relay and target reconstructs the pair. "
                                "Pick jurisdictions you can explain in a workpaper."));

    for (const auto& f : report.findings) report.score += points(f);
    if (report.score > 100) report.score = 100;
    if (!report.allow) report.posture = "blocked";
    else if (report.score >= 40) report.posture = "leaky";
    else if (report.score >= 15) report.posture = "acceptable";
    else report.posture = "hardened";
    return report;
}

void print_odoh_filter(const OdohFilterReport& report) {
    std::cout << "WhiteDNS ODoH filter (RFC 9230 deep policy)\n";
    std::cout << "QNAME: " << report.qname << "  type=" << dns_type_to_string(report.qtype) << "\n";
    std::cout << "Posture: " << report.posture << "  score=" << report.score
              << "/100  allow=" << (report.allow ? "yes" : "NO") << "\n";
    std::cout << "Path: target=" << report.path.target
              << "  relay=" << (report.path.proxy.empty() ? "(none)" : report.path.proxy) << "\n";
    std::cout << "Oblivious: " << (report.path.oblivious ? "yes" : "no")
              << "  rcode=" << iana_rcode_name(report.path.rcode) << "\n";
    std::cout << "------------------------------------------------------------\n";
    for (const auto& f : report.findings) {
        std::cout << "[" << f.status << "] " << f.id << "  " << f.title << "\n";
        std::cout << "        " << f.message << "\n";
        std::cout << "        class=" << f.klass << " severity=" << f.severity << "\n";
        if (!f.change.empty()) std::cout << "        CHANGE: " << f.change << "\n";
    }
}

} // namespace core
} // namespace whitedns
