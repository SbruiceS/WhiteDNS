# WhiteDNS framework model

WhiteDNS `audit` maps live DNS observations to five reference systems. This is a defensive fault-finding and control-assessment engine. It does not implement attack payloads.

"Mattare attack system" is treated as **MITRE ATT&CK**.

## Sources

| System | What WhiteDNS uses |
|---|---|
| SANS | Ed Skoudis / SANS ISC DNS attack classes: hijack, cache poisoning, tunneling, amplification, fast-flux, NXDOMAIN abuse, registrar/NS change, DNSSEC signing **and** validation |
| MITRE ATT&CK | T1071.004 DNS C2, T1568.001 fast flux, T1583.002 / T1584.002 DNS servers, T1590.002 DNS reconnaissance, T1557 AitM class, T1498 availability |
| RFC | RFC 1034/1035 architecture; RFC 2181/2182 operations; RFC 3596 AAAA; RFC 4033-4035 DNSSEC; RFC 5936 AXFR; RFC 6895 IANA; RFC 7208 SPF; RFC 7489 DMARC; RFC 8020 NXDOMAIN; RFC 8659 CAA |
| IANA | DNS Parameters registries: RR TYPE, CLASS, OPCODE, RCODE |
| ISACA | COBIT 2019 language: DSS05 security services, DSS01 operations, DSS04 continuity, APO12 risk, APO13 security, BAI10 change, MEA01/MEA02 monitoring |

## Command

```bash
whitedns audit example.com
whitedns audit -j -S 8.8.8.8,1.1.1.1 cloudflare.com
```

Each finding includes status, severity, SANS class, ATT&CK ID, RFC cite, IANA registry note, and ISACA control text.

`fault_score` is a 0-100 roll-up. Posture is `resilient`, `degraded`, or `exposed`.

DNSSEC findings report record **presence** only. They do not validate the cryptographic chain. That matches SANS guidance: half-deployed DNSSEC is not DNSSEC.

## Finding catalog

| ID | Check |
|---|---|
| RFC-SOA-001 | SOA present (zone authority) |
| IANA-NS-002 | NS count and provider diversity |
| RFC-ADDR-003 | A / AAAA addressing |
| RFC-MX-004 | Mail exchangers |
| RFC-MAILAUTH-005 | SPF + DMARC |
| MITRE-T1071-006 | TXT entropy / length heuristic |
| SANS-POISON-007 | Multi-resolver A consistency |
| SANS-FLUX-008 | Sub-minute address TTLs |
| SANS-DNSSEC-009 | DNSKEY / DS / RRSIG presence |
| RFC-CAA-010 | CAA policy |
| IANA-RCODE-011 | SERVFAIL / FORMERR health |
| SANS-NX-012 | NXDOMAIN integrity |
| SANS-WILD-013 | Wildcard coverage |
| RFC-AXFR-014 | Zone-transfer exposure |

## Architecture roles (IANA / RFC)

SOA = zone-authority; NS = delegation; A/AAAA = addressing; CNAME/DNAME = alias; MX = mail-exchange; TXT = policy-or-payload; DNSKEY/DS/RRSIG/NSEC = dnssec-integrity; CAA/TLSA = certificate-binding; AXFR = zone-replication.
