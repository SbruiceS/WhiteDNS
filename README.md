<p align="center">
  <img src="logo/whitedns.png" alt="WhiteDNS — Detect · Analyze · Secure · Explore" width="520" />
</p>

<h1 align="center">WhiteDNS</h1>

<p align="center">
  <strong>Advanced DNS Security, Forensics &amp; Reconnaissance Toolkit</strong><br/>
  Detect · Analyze · Secure · Explore
</p>

<p align="center">
  <a href="https://github.com/SbruiceS/WhiteDNS/actions"><img src="https://img.shields.io/badge/build-CMake%20C%2B%2B17-2ea44f?style=flat-square" alt="CMake C++17" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-see%20LICENSE-blue?style=flat-square" alt="License" /></a>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-111827?style=flat-square" alt="Platforms" />
  <img src="https://img.shields.io/badge/RFC-9230%20ODoH-0052cc?style=flat-square" alt="RFC 9230 ODoH" />
  <img src="https://img.shields.io/badge/DNSSEC-DS%E2%86%92DNSKEY-6f42c1?style=flat-square" alt="DNSSEC" />
  <img src="https://img.shields.io/badge/taxonomy-161%20rules-orange?style=flat-square" alt="161 threat rules" />
  <img src="https://img.shields.io/badge/stance-defensive%20only-lightgrey?style=flat-square" alt="Defensive only" />
</p>

<p align="center">
  A product of <strong>Cosinfotech Solutions</strong> · Author <strong>S. Bruice Singh</strong><br/>
  <a href="https://github.com/SbruiceS/WhiteDNS">github.com/SbruiceS/WhiteDNS</a>
</p>

---

WhiteDNS is a C++17 command-line platform for **authorized** DNS security analysis, incident response, SOC work, lab research, and DNS administration.

It is **not** a vendor exploit kit. Cisco SAFE, ITU-T X.805, Nokia SR OS roles, HP/Aruba segmentation, and Dell endpoint notes are used as **defensive control mappings** only. No amplification, cache-poisoning exploit, or unauthorized AXFR/UPDATE is generated.

Design: [`docs/PLATFORM.md`](docs/PLATFORM.md) · ODoH: [`docs/ODOH.md`](docs/ODOH.md) · Taxonomy: [`docs/THREAT_TAXONOMY.md`](docs/THREAT_TAXONOMY.md) · Frameworks: [`FRAMEWORKS.md`](FRAMEWORKS.md)

## What it does

| Area | Command | Status |
|---|---|---|
| Record lookup / compare / trace | `lookup` `records` `resolve` `compare` `trace` | live |
| Framework audit (SANS / MITRE / RFC / IANA / ISACA) | `audit` | live |
| ODoH RFC 9230 + leak models | `odoh` `odoh-filter` `odoh-policy` `odoh-leak` | live (Fastly relay + Cloudflare target) |
| Resolver TTL / RTT baseline | `baseline` | live |
| RFC/SANS intel (SOA, MX, SPF, DMARC, CAA…) | `intel` | live |
| DNSSEC DS→DNSKEY + RRSIG/NSEC inventory | `dnssec-path` | live MATCH on infosys.com, nasa.gov |
| Poison 3-gate (DNSSEC ∧ disjoint resolvers ∧ AA) | `poison` | live; never invents “confirmed” |
| 161-rule threat taxonomy | `threats` `detect` `explain` `research` | live |
| FINDING/ANOMALY roll-up | `faults` | live |
| Vendor **control** gaps (not attacks) | `controls` | live |

**Poison confirmation rule:** DNSSEC contradiction **and** multi-resolver disjoint A-sets **and** authoritative AA disagreement. One-shot remote checks never invent a confirmed attack.

## Live snapshots (this tree)

**infosys.com** — poison `none` gates `0/0/0`, AA + recursors `35.71.178.178`, DNSSEC **MATCH**, controls 13/13 PASS. `faults` listed 7 low-confidence TXT-volume anomalies (public vendor tokens), not an incident.

**google.com** — poison `not-confirmed` gates `0/1/1` (anycast), DNSSEC unsigned on this path, controls GAP only on CISCO-SAFE-02 / ITU-X805-01 integrity.

## Platform support

- Linux (GCC/Clang + CMake)
- macOS (Apple Clang + CMake)
- Windows (MSVC / any C++17 + Winsock)
- Android Termux

No `libresolv` / `_res`. UDP/TCP, DoH, and ODoH go through the in-tree client.

## Build

```bash
cmake -B build
cmake --build build
./build/whitedns --help
```

Windows:

```powershell
cmake -B build
cmake --build build --config Release
.\build\Release\whitedns.exe --help
```

OpenSSL is used for DNSSEC digest and ODoH/HPKE when present (`WHITEDNS_HAVE_OPENSSL`).

## Usage

```bash
whitedns <command> [options] <domain>
```

```bash
whitedns audit google.com
whitedns odoh nasa.gov
whitedns odoh-leak
whitedns intel infosys.com
whitedns dnssec-path infosys.com
whitedns poison infosys.com
whitedns threats list
whitedns threats info WDNS-POISON-001
whitedns detect infosys.com
whitedns faults infosys.com
whitedns controls google.com
whitedns baseline infosys.com
```

Classic flags still work (`-t`, `-s`, `-S`, `-r`, `-n`, `-w`, `-c`, `-x`, `-A`, `-H`, `-j`).

Scope: set `WHITEDNS_SCOPE` or `--scope`. Safe profile does not send AXFR or RFC 2136 UPDATE to third-party nameservers.

## Architecture (additive)

```
TARGET → SCOPE → QUERY PLAN → TRANSPORT (UDP/TCP/DoH/ODoH)
      → RESOLVER ENGINE → PARSER → CORRELATION
      → SECURITY / ANOMALY / EVIDENCE / FINDING → REPORT
```

Core lives under `include/whitedns/core` and `src/core`. Existing `DnsClient`, `Analyzer`, `FrameworkAudit`, and scanners are unchanged.

## Tests

```bash
sh scripts/run-production-smoke.sh ./build/whitedns
cmake -B build -DWHITEDNS_ENABLE_NETWORK_TESTS=ON && ctest --test-dir build --output-on-failure
```

Production names used in live checks: `google.com`, `facebook.com`, `microsoft.com`, `nasa.gov`, `infosys.com`.

## License

See [`LICENSE`](LICENSE).
