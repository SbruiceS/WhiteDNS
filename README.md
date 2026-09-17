<p align="center">
  <img src="logo/banner.svg" alt="WhiteDNS banner" width="100%" />
</p>

<p align="center">
  <img src="logo/whitedns.png" alt="WhiteDNS mark" width="280" />
</p>

<h1 align="center">WhiteDNS</h1>

<p align="center">
  <em>Advanced DNS Security · Forensics · Reconnaissance</em><br/>
  <strong>DETECT &nbsp;|&nbsp; ANALYZE &nbsp;|&nbsp; SECURE &nbsp;|&nbsp; EXPLORE</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" alt="C++17" />
  <img src="https://img.shields.io/badge/CMake-build-064F8C?style=for-the-badge&logo=cmake&logoColor=white" alt="CMake" />
  <img src="https://img.shields.io/badge/ODoH-RFC%209230-1a6dff?style=for-the-badge" alt="ODoH" />
  <img src="https://img.shields.io/badge/DNSSEC-DS→DNSKEY-6f42c1?style=for-the-badge" alt="DNSSEC" />
  <img src="https://img.shields.io/badge/Rules-161-ea580c?style=for-the-badge" alt="161 rules" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Linux-supported-111827?style=flat-square&logo=linux&logoColor=white" alt="Linux" />
  <img src="https://img.shields.io/badge/macOS-supported-111827?style=flat-square&logo=apple&logoColor=white" alt="macOS" />
  <img src="https://img.shields.io/badge/Windows-supported-111827?style=flat-square&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/Termux-supported-111827?style=flat-square&logo=android&logoColor=white" alt="Termux" />
  <img src="https://img.shields.io/badge/stance-defensive%20only-2ea44f?style=flat-square" alt="Defensive" />
  <a href="https://github.com/SbruiceS/WhiteDNS"><img src="https://img.shields.io/badge/GitHub-SbruiceS%2FWhiteDNS-181717?style=flat-square&logo=github" alt="GitHub" /></a>
</p>

<p align="center">
  A product of <b>Cosinfotech Solutions</b><br/>
  Designed &amp; engineered by <b>S. Bruice Singh</b>
</p>

---

<p align="center">
WhiteDNS is a production C++17 CLI for <b>authorized</b> DNS security work:<br/>
incident response, SOC review, lab research, and zone administration.<br/>
Every serious conclusion is tied to observable DNS evidence.
</p>

```
TARGET → SCOPE → QUERY PLAN → TRANSPORT (UDP / TCP / DoH / ODoH)
      → RESOLVER → PARSE → CORRELATE → ANALYZE → EVIDENCE → REPORT
```

> Observation ≠ anomaly ≠ finding ≠ confirmed attack.  
> Poisoning is confirmed only when **DNSSEC contradiction ∧ disjoint resolvers ∧ AA disagreement** all fire.

## Command map

| You want | Command |
|:---|:---|
| Framework audit (SANS · MITRE · RFC · IANA · ISACA) | `whitedns audit google.com` |
| Oblivious DoH (RFC 9230) | `whitedns odoh nasa.gov` |
| ODoH leak models | `whitedns odoh-leak` |
| Resolver intel (SOA / MX / SPF / DMARC / CAA) | `whitedns intel infosys.com` |
| DNSSEC DS → DNSKEY + RRSIG inventory | `whitedns dnssec-path infosys.com` |
| Poison 3-gate classifier | `whitedns poison infosys.com` |
| 161-rule taxonomy | `whitedns detect infosys.com` |
| Issues only (FINDING + ANOMALY) | `whitedns faults infosys.com` |
| Vendor **control** gaps (not exploits) | `whitedns controls google.com` |
| TTL / RTT baseline | `whitedns baseline infosys.com` |
| Rule catalog | `whitedns threats list` |

```bash
whitedns poison infosys.com
# verdict=none  gates dnssec=0 resolver=0 aa=0
# AA + 8.8.8.8 / 1.1.1.1 / 9.9.9.9  →  35.71.178.178
# DS→DNSKEY MATCH
```

## Why it looks strict

| Family | What you get |
|:---|:---|
| **ODoH** | Fastly relay + Cloudflare target. Relay sees your IP, not the QNAME. Target sees the QNAME, not your IP. |
| **DNSSEC** | Live parent DS digest vs child DNSKEY. Presence is not validation. |
| **Poison** | Three independent gates. Anycast on `google.com` stays `not-confirmed`. |
| **Taxonomy** | 161 `WDNS-*` rules, 24 families. Flood / C2 / amp without telemetry stay **INCONCLUSIVE**. |
| **Controls** | Cisco SAFE, ITU-T X.805, Nokia resolver roles, HP segmentation, Dell endpoint — **audit only**. |

No amplification engine. No unauthorized AXFR. No RFC 2136 UPDATE against third-party NS.

## Build

```bash
cmake -B build && cmake --build build
./build/whitedns --help
```

```powershell
cmake -B build
cmake --build build --config Release
.\build\Release\whitedns.exe --help
```

OpenSSL powers DNSSEC digests and ODoH/HPKE when available.

## Docs in this tree

| File | Contents |
|:---|:---|
| [`docs/PLATFORM.md`](docs/PLATFORM.md) | System architecture |
| [`docs/ODOH.md`](docs/ODOH.md) | RFC 9230 client + privacy split |
| [`docs/THREAT_TAXONOMY.md`](docs/THREAT_TAXONOMY.md) | Rule families & evidence model |
| [`FRAMEWORKS.md`](FRAMEWORKS.md) | SANS / MITRE / RFC / IANA / ISACA |

## License

See [`LICENSE`](LICENSE).

<p align="center">
  <sub>Cosinfotech Solutions · WhiteDNS · S. Bruice Singh</sub>
</p>
