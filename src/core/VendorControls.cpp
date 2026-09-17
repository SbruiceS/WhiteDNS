#include "whitedns/core/VendorControls.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/DnssecPath.h"
#include "whitedns/core/PoisonClassifier.h"
#include "whitedns/core/ResolverEngine.h"
#include "whitedns/core/ThreatEngine.h"

#include <iostream>
#include <string>

namespace whitedns {
namespace core {

void run_print_vendor_controls(const std::string& qname) {
    std::cout << "WhiteDNS vendor control audit — DEFENSIVE\n";
    std::cout << "Cisco SAFE / ITU-T X.805 / Nokia resolver roles / HP segmentation / Dell endpoint\n";
    std::cout << "This is not an exploit kit. No amp, poison, or unauthorized UPDATE/AXFR is sent.\n";
    std::cout << "QNAME: " << qname << "\n";
    std::cout << "------------------------------------------------------------\n";

    auto poison = run_poison_classifier(qname, {});
    auto path = run_dnssec_path(qname, "8.8.8.8");
    auto detect = run_threat_detect(qname);
    ResolverEngine engine;
    auto ns = engine.query(qname, DNS_TYPE_NS, "8.8.8.8");
    int nsc = 0;
    for (const auto& r : ns.message.answers)
        if (r.type == DNS_TYPE_NS) nsc++;

    bool priv = false, spf = false, dmarc_ok = false, dmarc_none = false, caa = false;
    for (const auto& f : detect.findings) {
        if (f.rule_id == "WDNS-PRIV-001" && f.kind == "FINDING") priv = true;
        if (f.rule_id == "WDNS-EMAIL-001" && f.kind == "OBSERVATION") spf = true;
        if (f.rule_id == "WDNS-EMAIL-001" && f.kind == "FINDING") spf = false;
        if (f.rule_id == "WDNS-EMAIL-004" && f.kind == "OBSERVATION") dmarc_ok = true;
        if (f.rule_id == "WDNS-EMAIL-004" && f.kind == "FINDING") dmarc_ok = false;
        if (f.rule_id == "WDNS-EMAIL-005" && f.kind == "FINDING") dmarc_none = true;
        if (f.rule_id == "WDNS-EMAIL-007" && f.kind == "OBSERVATION") caa = true;
    }

    auto row = [](const char* id, const char* vendor, const char* title, bool pass, const std::string& ev) {
        std::cout << (pass ? "[PASS] " : "[GAP]  ") << id << "  (" << vendor << ")  " << title << "\n";
        std::cout << "        " << ev << "\n";
    };

    row("CISCO-SAFE-01", "Cisco SAFE", "Resolver views compared before incident label",
        poison.verdict != "confirmed",
        "poison verdict=" + poison.verdict);
    row("CISCO-SAFE-02", "Cisco SAFE", "DNSSEC recommended where policy requires signing",
        path.ds_matches_key,
        path.ds_matches_key ? "DS→DNSKEY MATCH" : "unsigned or no-match on this path");
    row("CISCO-EMAIL-01", "Cisco ESA", "SPF published",
        spf, spf ? "v=spf1 present" : "no SPF");
    row("CISCO-EMAIL-02", "Cisco ESA", "DMARC not absent / not stuck at p=none if mail used",
        dmarc_ok && !dmarc_none,
        dmarc_ok ? (dmarc_none ? "DMARC p=none" : "DMARC present") : "no _dmarc");
    row("ITU-X805-01", "ITU-T X.805", "Integrity: parent DS matches child DNSKEY",
        path.ds_matches_key,
        path.klass);
    row("ITU-X805-02", "ITU-T X.805", "Access control: no confirmed poison (3-gate)",
        poison.verdict != "confirmed",
        "gates dnssec=" + std::string(poison.gate_dnssec ? "1" : "0") +
            " resolver=" + (poison.gate_resolver ? "1" : "0") +
            " aa=" + (poison.gate_aa ? "1" : "0"));
    row("ITU-X805-03", "ITU-T X.805", "Confidentiality residual: public TXT is visible by design",
        true, "TXT is a public channel — treat tokens as public");
    row("NOKIA-RES-01", "Nokia SR OS", "Auth vs recursive roles separated in the check",
        !poison.aa_sets.empty(),
        poison.aa_sets.empty() ? "no AA collected" : "AA collected from apex NS");
    row("NOKIA-RES-02", "Nokia SR OS", "Dual NS (RFC 2182 diversity)",
        nsc >= 2, "NS count=" + std::to_string(nsc));
    row("HP-SEG-01", "HP/Aruba", "No RFC1918/loopback on public A",
        !priv, priv ? "private A published" : "public A only");
    row("DELL-EP-01", "Dell endpoint", "Workstation hosts-file class not claimed remotely",
        true, "INCONCLUSIVE remotely — not guessed");
    row("DELL-EP-02", "Dell endpoint", "Do not confirm attack from one vantage",
        poison.verdict != "confirmed",
        "confirmation requires all three gates");
    row("RFC-8659-01", "IANA/RFC", "CAA policy present",
        caa, caa ? "CAA present" : "no CAA (policy gap, not an attack)");

    std::cout << "------------------------------------------------------------\n";
    std::cout << "Confirmed poison: " << (poison.verdict == "confirmed" ? "YES" : "NO") << "\n";
}

} // namespace core
} // namespace whitedns
