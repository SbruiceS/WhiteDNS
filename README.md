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

```bash
git clone https://github.com/SbruiceS/WhiteDNS.git
cd WhiteDNS
make
sudo ./whitedns --help

Output Example

{
  "domain": "example.com",
  "dnssec": "valid",
  "open_resolver": false,
  "wildcard": false,
  "cache_poisoning_vuln": false,
  "tunneling_detected": false
}



