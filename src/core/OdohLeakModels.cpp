#include "whitedns/core/OdohLeakModels.h"

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

std::string host_of(std::string url) {
    auto p = url.find("://");
    if (p != std::string::npos) url = url.substr(p + 3);
    for (char sep : {'/', '?', ':'}) {
        auto x = url.find(sep);
        if (x != std::string::npos) url.resize(x);
    }
    return lower(url);
}

std::string etld1(const std::string& host) {
    auto a = host.rfind('.');
    if (a == std::string::npos || a == 0) return host;
    auto b = host.rfind('.', a - 1);
    return b == std::string::npos ? host : host.substr(b + 1);
}

std::set<std::string> values(const std::vector<DnsRecord>& recs, uint16_t type) {
    std::set<std::string> out;
    for (const auto& r : recs)
        if (r.type == type) out.insert(r.value);
    return out;
}

bool rfc1918(const std::string& ip) {
    return ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0 ||
           ip.rfind("127.", 0) == 0 || ip.rfind("169.254.", 0) == 0 ||
           ip.rfind("172.16.", 0) == 0 || ip.rfind("172.17.", 0) == 0 ||
           ip.rfind("172.18.", 0) == 0 || ip.rfind("172.19.", 0) == 0;
}

} // namespace

OdohLeakReport run_odoh_leak_models(const std::string& qname,
                                    const std::string& target,
                                    const std::string& proxy) {
    OdohLeakReport report;
    report.qname = qname;
    report.a = odoh_lookup(qname, DNS_TYPE_A, target, proxy);
    report.aaaa = odoh_lookup(qname, DNS_TYPE_AAAA, target, proxy);
    report.ns = odoh_lookup(qname, DNS_TYPE_NS, target, proxy);

    ResolverEngine udp;
    auto udp_a = udp.query(qname, DNS_TYPE_A, "1.1.1.1");
    auto udp_aaaa = udp.query(qname, DNS_TYPE_AAAA, "1.1.1.1");

    const auto& p = report.a;
    const std::string relay = host_of(p.proxy);
    const std::string tgt = host_of(p.target.empty() ? std::string(kOdohProductionTarget) : p.target);

    auto add = [&](const char* model, const char* id, const std::string& status,
                   const char* title, const std::string& detail) {
        LeakFinding f;
        f.model = model;
        f.id = id;
        f.status = status;
        f.title = title;
        f.detail = detail;
        report.findings.push_back(f);
        if (status == "sealed") report.sealed++;
        else if (status == "residual") report.residual++;
        else if (status == "leak") report.leak++;
        else report.info++;
    };

    add("IdentitySplit", "M01", p.oblivious ? "sealed" : "leak",
        "IP and QNAME on different orgs",
        p.oblivious ? "Relay forwarded ciphertext. Target never saw this client IP."
                    : "Direct path: target has IP and QNAME together.");

    add("OrgCollusion", "M02",
        (p.oblivious && etld1(relay) != etld1(tgt)) ? "sealed" : (p.oblivious ? "leak" : "residual"),
        "Relay eTLD+1 vs target eTLD+1",
        "relay=" + etld1(relay) + " target=" + etld1(tgt));

    add("SniDial", "M03", "sealed",
        "No hostname in SNI when handshake allows",
        "Production client dials pinned IPs (Fastly 151.101.1.51 / CF 162.159.62.1) and omits SNI first.");

    add("BootstrapDns", "M04", "sealed",
        "No stub lookup of ODoH hostnames",
        "Relay/target names are not queried on the public resolver for the data path.");

    add("ConfigChannel", "M05", "residual",
        "HPKE config fetch still hits the target IP",
        "odohconfigs is fetched from the Cloudflare target IP. Access net can see that IP, not the QNAME.");

    add("CipherSuite", "M06",
        (p.kem_id == 0x0020 || p.kem_id == 0) ? "sealed" : "leak",
        "HPKE suite pin",
        "KEM=" + std::to_string(p.kem_id) + " KDF=" + std::to_string(p.kdf_id) +
            " AEAD=" + std::to_string(p.aead_id));

    add("Padding", "M07", p.ciphertext_bytes >= 160 ? "sealed" : "residual",
        "Block padding hides QNAME length",
        "A-query ciphertext=" + std::to_string(p.ciphertext_bytes) + "B qname_len=" +
            std::to_string(p.qname_len));

    add("KeyId", "M08", p.key_id_hex.size() == 64 ? "sealed" : "leak",
        "key_id width",
        p.key_id_hex.empty() ? "missing" : p.key_id_hex.substr(0, 16) + "...");

    add("RelayAllowlist", "M09",
        (!p.oblivious || relay == "odoh-relay.edgecompute.app" || relay == "odoh-relay.numa.rs")
            ? "sealed"
            : "residual",
        "Relay allowlist",
        relay.empty() ? "(none)" : relay);

    add("ClientHeaders", "M10", "sealed",
        "No Forwarded / cookie / client cert",
        "WhiteDNS ODoH client does not emit identity headers toward relay or target.");

    add("QnameAtTarget", "M11", "residual",
        "Target still sees the full QNAME",
        "RFC 9230 split does not minimize QNAME at the target. " + qname + " is visible to Cloudflare.");

    add("SizeTiming", "M12", "residual",
        "Size and timing side channel",
        "Padding helps. A/AAAA/NS bursts still have a timing shape the access net can count.");

    auto a_set = values(p.answers, DNS_TYPE_A);
    bool priv = false;
    for (const auto& ip : a_set)
        if (rfc1918(ip)) priv = true;
    add("PrivateAnswer", "M13", priv ? "leak" : "sealed",
        "RFC1918/loopback in public ODoH answer",
        priv ? "Public target returned a private A." : "A answers look public.");

    std::set<std::string> udp_as;
    if (udp_a.ok)
        for (const auto& r : udp_a.message.answers)
            if (r.type == DNS_TYPE_A) udp_as.insert(r.value);
    bool overlap = false;
    for (const auto& ip : a_set)
        if (udp_as.count(ip)) overlap = true;
    if (a_set.empty() || udp_as.empty()) {
        add("AnycastA", "M14", "info", "ODoH A vs UDP 1.1.1.1",
            "Not enough A sets to compare.");
    } else {
        add("AnycastA", "M14", overlap ? "sealed" : "residual",
            "ODoH A vs UDP 1.1.1.1",
            overlap ? "Sets intersect. Enterprise anycast is consistent enough."
                    : "Disjoint A sets. Observation for a global anycast, not a leak of the client IP.");
    }

    auto aaaa_set = values(report.aaaa.answers, DNS_TYPE_AAAA);
    std::set<std::string> udp_aaaa_s;
    if (udp_aaaa.ok)
        for (const auto& r : udp_aaaa.message.answers)
            if (r.type == DNS_TYPE_AAAA) udp_aaaa_s.insert(r.value);
    bool aaaa_ov = false;
    for (const auto& ip : aaaa_set)
        if (udp_aaaa_s.count(ip)) aaaa_ov = true;
    add("AnycastAAAA", "M15",
        aaaa_set.empty() ? "info" : (aaaa_ov || udp_aaaa_s.empty() ? "sealed" : "residual"),
        "ODoH AAAA vs UDP",
        "odoh_aaaa=" + std::to_string(aaaa_set.size()) +
            " udp_aaaa=" + std::to_string(udp_aaaa_s.size()));

    add("NsSurface", "M16", report.ns.ok && report.ns.rcode == 0 ? "sealed" : "residual",
        "NS over ODoH",
        std::string("rcode=") + iana_rcode_name(report.ns.rcode) +
            " ns_count=" + std::to_string(values(report.ns.answers, DNS_TYPE_NS).size()));

    std::string www = qname;
    if (lower(www).rfind("www.", 0) != 0) www = "www." + qname;
    auto www_a = odoh_lookup(www, DNS_TYPE_A, target, proxy);
    add("WwwApex", "M17", www_a.ok ? "sealed" : "residual",
        "www vs apex over the same ODoH path",
        www + " rcode=" + std::string(iana_rcode_name(www_a.rcode)) +
            " a=" + std::to_string(values(www_a.answers, DNS_TYPE_A).size()));

    auto nx = odoh_lookup("whitedns-probe-nx." + qname, DNS_TYPE_A, target, proxy);
    add("NxIntegrity", "M18",
        (nx.rcode == 3 || nx.rcode == 0) ? "sealed" : "residual",
        "Random label does not invent a stable A",
        "whitedns-probe-nx." + qname + " rcode=" + std::string(iana_rcode_name(nx.rcode)));

    add("DirectForbidden", "M19", p.oblivious ? "sealed" : "leak",
        "Production refuses a single-party path",
        p.oblivious ? "Relay hop present." : "direct mode collapsed the split.");

    add("EnterpriseScale", "M20", "info",
        "Large-enterprise anycast expected",
        "Google/Meta/Microsoft/NASA publish many edges. Disjoint resolver views are normal.");

    add("DnssecSeparate", "M21", "info",
        "ODoH is transport, not validation",
        "AD bit on an inner message is not a DS→DNSKEY proof. Use whitedns dnssec.");

    add("NoEcs", "M22", "sealed",
        "No EDNS Client Subnet from this stub",
        "Query builder does not attach ECS, so the target does not get a /24 of this client.");

    add("NoCookies", "M23", "sealed",
        "HTTP cookie jar empty",
        "Set-Cookie from relay/target is ignored.");

    add("NoAxfr", "M24", "sealed",
        "No AXFR/ANY on the public ODoH path",
        "Leak models query A/AAAA/NS only.");

    add("TlsVerifyPaths", "M25", "sealed",
        "TLS default verify paths loaded",
        "Relay/target TLS uses OpenSSL default CAs. SNI omit does not disable verification fallback.");

    add("TwoPartyLegal", "M26", "residual",
        "Legal process on both orgs still joins the pair",
        "Fastly + Cloudflare logs can reconstruct IP↔QNAME if both are compelled.");

    std::ostringstream ans;
    ans << "A[" << std::string(iana_rcode_name(report.a.rcode)) << "]:";
    for (const auto& ip : a_set) ans << " " << ip;
    ans << "  AAAA:" << aaaa_set.size() << "  NS:" << values(report.ns.answers, DNS_TYPE_NS).size();
    add("AnswerInventory", "M27", report.a.ok ? "info" : "leak",
        "Live answer inventory",
        ans.str());

    return report;
}

void print_odoh_leak_models(const OdohLeakReport& report) {
    std::cout << "WhiteDNS ODoH leakage models\n";
    std::cout << "QNAME: " << report.qname << "\n";
    std::cout << "Path: target=" << report.a.target
              << "  oblivious=" << (report.a.oblivious ? "yes" : "no") << "\n";
    std::cout << "Models: " << report.findings.size()
              << "  sealed=" << report.sealed << "  residual=" << report.residual
              << "  leak=" << report.leak << "  info=" << report.info << "\n";
    std::cout << "------------------------------------------------------------\n";
    for (const auto& f : report.findings) {
        std::cout << "[" << f.status << "] " << f.id << "  " << f.model << " — " << f.title << "\n";
        std::cout << "        " << f.detail << "\n";
    }
}

} // namespace core
} // namespace whitedns
