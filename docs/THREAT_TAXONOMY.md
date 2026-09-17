# WhiteDNS Threat Taxonomy & Detection Engine

**Product:** WhiteDNS  
**Developer:** Cosinfotech Solutions  
**Author:** S. Bruice Singh  
**taxonomy_version:** 1.0  
**rule_version:** 1.0.0

References used for *defensive architecture*, not attack recipes: RFC 1034/1035, 2181, 2308, 4033–4035, 5155, 5358, 5452, 5936, 6891, 7208, 7489, 8020, 8482, 8484, 8659, 8767, 9230; IANA DNS parameters; ITU-T X.800/X.805; Cisco SAFE / Umbrella DNS guidance; Nokia SR OS resolver roles; HP/Aruba segmentation notes; Dell endpoint vs resolver split.

## Concepts (mandatory)

Observation ≠ Anomaly ≠ Security finding ≠ Confirmed attack.

Poisoning is confirmed only with DNSSEC contradiction + multi-resolver disagreement + authoritative disagreement.

## CLI

```
whitedns threats list
whitedns threats categories
whitedns threats info WDNS-POISON-001
whitedns threats validate
whitedns detect infosys.com
whitedns explain WDNS-POISON-001
whitedns research infosys.com
```

Catalog lives in `src/core/ThreatEngine.cpp` (≥100 unique `WDNS-*` IDs).  
Evaluators that can run on a single vantage collect A/TXT/MX/CAA/DMARC/wildcard/NX + poison compare + DNSSEC path.  
Flood, C2 beacon, amp ratios, registrar RDAP, and packet-level TXID/port rules stay **INCONCLUSIVE** without telemetry.

Safe profile does **not** send AXFR or RFC 2136 UPDATE to third-party nameservers.
