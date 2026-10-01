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

Use only on names and resolvers you are allowed to query. This is an assessment tool for operators, incident response, and authorized tests. It does not send amplification, zone transfer, or dynamic update traffic.

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

Needs a C++17 compiler and CMake. OpenSSL is detected automatically. If it is installed, DNSSEC signature checks and ODoH link against it. If it is not, the build still succeeds and `whitedns doctor` says signature verify is off.

```bash
# Debian, Ubuntu, Termux
pkg install openssl-dev || sudo apt install libssl-dev
# Fedora
sudo dnf install openssl-devel
```

## Use

```bash
whitedns <command> [options] <name>
whitedns arch
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
| `arch` | Command map |
| `doctor` | What this build does and does not do |
| `dns` `web` `enum` | Older surface checks |

```bash
whitedns lookup <name> -s 1.1.1.1
whitedns resolve <name> -S 8.8.8.8,1.1.1.1,9.9.9.9
whitedns dnssec-path <name>
whitedns poison <name>
whitedns detect <name>
whitedns arch --color always
```

`--format json` for machine output. `--color never` or `NO_COLOR` turns colour off.

Poison is confirmed only when DNSSEC contradiction, disjoint resolver answers, and authoritative disagreement all fire.

## Docs

[docs/CLI.md](docs/CLI.md) · [docs/PLATFORM.md](docs/PLATFORM.md) · [docs/ODOH.md](docs/ODOH.md) · [docs/INTELLIGENCE.md](docs/INTELLIGENCE.md)

## License

See [LICENSE](LICENSE).
