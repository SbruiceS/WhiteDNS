<p align="center">
  <img src="logo/whitedns.png" alt="WhiteDNS" width="420" />
</p>

<h1 align="center">WhiteDNS</h1>

<p align="center">
  DNS security, forensics and reconnaissance CLI<br/>
  <strong>DETECT &nbsp;|&nbsp; ANALYZE &nbsp;|&nbsp; SECURE &nbsp;|&nbsp; EXPLORE</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white" alt="C++17" />
  <img src="https://img.shields.io/badge/CMake-build-064F8C?style=for-the-badge&logo=cmake&logoColor=white" alt="CMake" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-111827?style=for-the-badge" alt="platforms" />
</p>

<p align="center">
  Cosinfotech Solutions · S. Bruice Singh
</p>

License: use only. No changes to the source. See LICENSE.

## Install

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

Needs a C++17 compiler, CMake, OpenSSL, and jsoncpp.

```bash
# Debian, Ubuntu, Termux
sudo apt install cmake g++ libssl-dev libjsoncpp-dev
# Fedora
sudo dnf install cmake gcc-c++ openssl-devel jsoncpp-devel
# macOS
brew install cmake openssl jsoncpp
cmake -B build -DCMAKE_BUILD_TYPE=Release -DWHITEDNS_RELEASE=ON -DOPENSSL_ROOT_DIR="$(brew --prefix openssl)"
```

Windows with vcpkg:

```powershell
vcpkg install openssl:x64-windows jsoncpp:x64-windows
cmake -B build -DCMAKE_BUILD_TYPE=Release -DWHITEDNS_RELEASE=ON -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
.\build\Release\whitedns.exe doctor
```

CI builds Linux, macOS, and Windows. A tag `v*` also uploads those three binaries.

## Use

```bash
whitedns
whitedns doctor
```

| Command | What it does |
|---|---|
| `lookup` | One resolver, record inventory |
| `records` | Same inventory |
| `resolve` / `compare` | Several resolvers, not auto-classified |
| `trace` | Delegation walk |
| `baseline` | TTL cache and RTT |
| `odoh` | Oblivious DoH query |
| `odoh-filter` | ODoH policy checks |
| `odoh-policy` | Authorized-use policy scan |
| `odoh-leak` | Leak models |
| `dnssec` | DS to DNSKEY digest |
| `dnssec-path` | DS, DNSKEY, RRSIG, NSEC inventory |
| `intel` | SOA, MX, SPF, DMARC, CAA |
| `poison` | Three-gate classifier |
| `threats` | Rule list |
| `detect` | Run evaluators |
| `explain` | One rule |
| `faults` | Findings and anomalies |
| `controls` | Defensive control gaps |
| `audit` | Framework audit |
| `graph` | Edges and graph algorithms |
| `security` | Fusion plus poison gates |
| `report` | Security and graph |
| `dga` | Lexical screen |
| `wire-check` | Strict parser self-test |
| `assess` | DNSSEC, poison gates, faults, and mail/SOA facts |
| `summary` | Fused addresses, nameservers, agreement, lexical screen |
| `traffic` | 90-check observe pack. Alias `flow` |
| `traffic-proto` | Protocol counts |
| `traffic-route` | Graph route |
| `traffic-flow` | Agreement and drop |
| `traffic-fault` | Observation faults |
| `deep` | 50 computed label, TTL, EDNS, and fusion checks |
| `ct` | Certificate Transparency names from crt.sh |
| `cname` | Follow CNAME to the terminal A |
| `dnssec-path` | DS, DNSKEY, RRSIG path. Not readiness |
| `enum` | `-e` wordlist. `-b` 110000. `-r` depth 1..5 |
| `scale` | 30-feature threat snapshot and graph. Alias `intel-scale` |
| `doctor` | What this build does and does not do |
| `enum` | `-e` wordlist, `-b` 100000+, `-r` depth 1..5, `--dsl`, `--g4`, `--permute` |

```bash
whitedns lookup <name> -s 1.1.1.1
whitedns resolve <name> -S 8.8.8.8,1.1.1.1,9.9.9.9
whitedns dnssec-path <name>
whitedns poison <name>
whitedns detect <name>
```

Running `whitedns` with no arguments opens the dashboard.

`--format json` for machine output. `--color never` or `NO_COLOR` turns colour off.

## CI

Yes. `whitedns audit` writes JSON and exits 2 on degraded, 3 on exposed.

```bash
chmod +x ci/scan.sh
WHITEDNS_DOMAIN=google.com WHITEDNS_FAIL_ON=degraded ci/scan.sh
```

GitHub Actions: run the `domain-scan` workflow and set the domain and fail level. The JSON report is uploaded as `whitedns-audit`. Use it only on names you are allowed to query.

Poison is confirmed only when DNSSEC contradiction, disjoint resolver answers, and authoritative disagreement all fire.

## Features

| Area | Commands / modules |
|---|---|
| Collect | lookup, records, resolve, trace, baseline, enum, ct, cname, rdap, asn |
| Privacy | odoh, odoh-leak, odoh-filter, odoh-policy, dot |
| DNSSEC | dnssec-path, dnssec-path walk (parent DS to root DNSKEY) |
| Detection | poison (three gates), detect, faults, feeds, controls, scale, deep |
| Traffic | traffic, traffic-proto, traffic-route, traffic-flow, traffic-fault, pcap, stat |
| Monitoring | monitor, monitor status, monitor pause, monitor resume, --diff |
| Bulk | bulk --domains file (up to 50 names) |
| Graph | graph, graphintel (PageRank, degree, betweenness, algebraic connectivity) |
| Topology | topology (beta0, beta1, Euler, persistence) |
| Math | Kalman, Joseph form, EWMA, DFT, Welch PSD, KL, CUSUM, HMM |
| Dashboard | dashboard (optional FTXUI) |

## Docs

[docs/CLI.md](docs/CLI.md) · [docs/ENGINE_STATUS.md](docs/ENGINE_STATUS.md) · [docs/MONITORING.md](docs/MONITORING.md) · [docs/GRAPH_INTELLIGENCE.md](docs/GRAPH_INTELLIGENCE.md) · [docs/ACP.md](docs/ACP.md)

## License

See [LICENSE](LICENSE).
