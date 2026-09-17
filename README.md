<img src="logo/whitedns.jpg" alt="WhiteDNS logo" />

# WhiteDNS

WhiteDNS is a cross-platform DNS security, forensics, and reconnaissance platform in C++17 by **S. Bruice Singh** at **Cosinfotech Solutions**. It performs DNS record queries, resolver comparison, DNSSEC chain checks, wildcard/NXDOMAIN checks, TXT tunneling heuristics, AXFR exposure checks, TCP port scanning, and Phase-1 wire/transport/resolver engines. Design: `docs/PLATFORM.md`. Existing commands are kept; new commands are additive.

## Platform Support

- Linux: supported with GCC/Clang and CMake.
- macOS: supported with Apple Clang and CMake.
- Windows: supported with Visual Studio or another C++17 compiler through Winsock.

WhiteDNS no longer depends on `_res`, `res_query`, or `libresolv`; DNS packets are sent through a thread-safe socket client.

## Architecture

- `include/whitedns/DnsClient.h` and `src/DnsClient.cpp`: cross-platform UDP/TCP DNS client and packet parser.
- `include/whitedns/Analyzer.h` and `src/Analyzer.cpp`: security checks that return structured results.
- `include/whitedns/PortScanner.h` and `src/PortScanner.cpp`: non-blocking TCP connect scanner.
- `src/main.cpp`: CLI parsing, concurrent queries, and human/JSON report rendering.
- `scripts/` and `tests/`: live production smoke test tooling.

WhiteDNS includes a local lightweight JSON writer under `include/json/json.h`, so the command-line tool does not require jsoncpp to build.

## Features

- Query A, AAAA, NS, TXT, SOA, MX, DNSKEY, RRSIG, AXFR, and ANY records.
- Compare multiple DNS resolvers for spoofing, cache poisoning, fast-flux, and hijacking signals.
- Check DNSSEC readiness by requesting DNSKEY/RRSIG records with EDNS DNSSEC OK.
- Detect wildcard DNS, NXDOMAIN redirection, rebinding signals, and suspicious TXT payloads.
- Check AXFR exposure against an explicit DNS server.
- Run TCP port scans against hostnames or IP addresses.
- Emit one consistent JSON report for all enabled modules.

## Build

### Linux/macOS

```bash
cmake -B build
cmake --build build
./build/whitedns -h
```

### Windows PowerShell

```powershell
cmake -B build
cmake --build build --config Release
.\build\Release\whitedns.exe -h
```

The exact Windows binary path depends on the CMake generator. Single-config generators may place it at `.\build\whitedns.exe`.

## Usage

```bash
whitedns <command> [options] <domain|url>
whitedns --version
whitedns help
```

Platforms: Linux, Windows, macOS, Termux (`Android/Termux` in `--version`).

```bash
whitedns audit google.com
whitedns audit --format json --fail-on degraded --color never google.com
WHITEDNS_RESOLVERS=8.8.8.8,1.1.1.1 whitedns audit google.com
```

```bash
whitedns [options] domain
```

Common options:

- `-t <types>`: DNS record types, for example `A,AAAA,NS,MX,TXT`.
- `-s <server>`: DNS server hostname or IP. Defaults to `8.8.8.8`.
- `-S <servers>`: comma-separated resolver list for comparison.
- `-r`: DNSSEC readiness check using DNSKEY/RRSIG records.
- `-n`: NXDOMAIN redirection check.
- `-w`: wildcard DNS check.
- `-c`: cache poisoning signal check across resolvers.
- `-x`: DNS tunneling TXT heuristic.
- `-A`: DNS spoofing signal check across resolvers.
- `-H`: DNS hijacking signal check across resolvers.
- `-P <targets>`: comma-separated TCP port scan targets.
- `-R <ports>`: comma-separated TCP ports.
- `-j`: one structured JSON report.

Examples:

```bash
whitedns -j -r -n -w -x -t A,AAAA,NS,MX,TXT google.com
whitedns -S 1.1.1.1,8.8.8.8,9.9.9.9 -c -A -H microsoft.com
whitedns -P google.com,facebook.com,microsoft.com -R 80,443 -j
```

## Production Smoke Tests

Live smoke tests use:

- `google.com`
- `facebook.com`
- `microsoft.com`

Linux/macOS:

```bash
sh scripts/run-production-smoke.sh ./build/whitedns
```

Windows PowerShell:

```powershell
.\scripts\run-production-smoke.ps1 -Binary .\build\Release\whitedns.exe
```

CMake can also register live tests when explicitly enabled:

```bash
cmake -B build -DWHITEDNS_ENABLE_NETWORK_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## JSON Schema

JSON output always contains the same top-level fields:

```json
{
  "tool": "WhiteDNS",
  "schema_version": 1,
  "domain": "example.com",
  "queries": [],
  "checks": [],
  "port_scan": []
}
```

All modules write into this structure, so automation does not receive mixed text and JSON.
