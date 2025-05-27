<img src="logo/whitedns.jpg" alt="My Logo" />

# WhiteDNS
WhiteDNS is an open-source DNS Security Analysis Tool written in C++. It performs checks like DNSSEC validation, open resolver detection, cache poisoning, DNS tunneling, and wildcard detection. With multithreaded querying and JSON output support, it helps security researchers and system administrators effectively audit and analyze DNS.

# WhiteDNS - DNS Security Analysis Tool

**Author**: [@SbruiceS](https://github.com/SbruiceS)  
**License**: MIT  
**Language**: C++

## Overview

**WhiteDNS** is a powerful DNS security auditing tool built to help researchers, security teams, and infrastructure engineers analyze and harden their DNS systems. From DNSSEC validation to cache poisoning and tunneling detection, WhiteDNS provides in-depth DNS vulnerability analysis at enterprise and internet scale.

## Features

- DNSSEC Validation
- Open Resolver Detection
- Cache Poisoning Checks
- Wildcard Domain Analysis
- DNS Tunneling Detection
- JSON Output for Integration
- Multithreaded Performance

## Use Cases

- Enterprise DNS Auditing
- ISP Resolver Security
- Government Network Hardening
- Research & Academic Analysis
- Penetration Testing

## Installation

### Using Make (Linux/macOS)

```bash
git clone https://github.com/SbruiceS/WhiteDNS.git
cd WhiteDNS
make
sudo ./whitedns --help
```

### Using CMake (Linux/macOS/Windows)

Ensure you have CMake installed on your system.

```bash
git clone https://github.com/SbruiceS/WhiteDNS.git
cd WhiteDNS
cmake -B build
cmake --build build
sudo cmake --install build --prefix /usr/local
whitedns --help
```

On Windows, you can use the CMake GUI or command line to configure and build the project using Visual Studio or other generators.

## Output Example

```json
{
  "domain": "example.com",
  "dnssec": "valid",
  "open_resolver": false,
  "wildcard": false,
  "cache_poisoning_vuln": false,
  "tunneling_detected": false
}
```

## High Interactive GUI (Planned)

A high interactive graphical user interface (GUI) is planned to provide an enhanced user experience for configuring scans, visualizing DNS security analysis results, and managing reports. This GUI will support all core features of WhiteDNS with intuitive controls and real-time feedback.

Stay tuned for updates on the GUI development and releases.
