# WhiteDNS Platform Design

**Product:** WhiteDNS — Advanced DNS Security, Forensics & Reconnaissance Platform  
**Developer:** Cosinfotech Solutions  
**Author:** S. Bruice Singh  
**Status:** Architecture complete. Phase 1 (DNS core) and Phase 2 (compare + TTL cache + RTT baseline) implemented in-tree. Later phases extend this design; they do not replace it.  
**Scope:** Authorized domains, operator-owned infrastructure, lab, enterprise SOC, IR, DNS administration, academic research.

WhiteDNS is not a query wrapper. Every conclusion must trace to an observation: resolver, transport, timestamp, wire evidence, and a confidence class.

---

## 1. System architecture

Pipeline (mandatory):

```
TARGET → SCOPE VALIDATOR → QUERY PLANNER → DNS TRANSPORT → RESOLVER ENGINE
      → RESPONSE PARSER → NORMALIZATION → CORRELATION → SECURITY ANALYSIS
      → ANOMALY ENGINE → EVIDENCE ENGINE → FINDING ENGINE
      → RISK/CONFIDENCE MODEL → REPORTING
```

Layers 0–14:

| Layer | Name | Phase-1 status |
|---|---|---|
| 0 | CLI / API | Existing commands kept; lookup/records/resolve/trace added |
| 1 | Scope & Policy | `--scope` + allowed-suffix check |
| 2 | Query Orchestration | Planner with type/resolver expansion + dedupe |
| 3 | DNS Transport | `DnsTransport` UDP + TCP (DoT/DoH interfaces reserved) |
| 4 | DNS Protocol | Wire codec: name, header, sections, EDNS |
| 5 | Resolution | Recursive / configured / authoritative / comparative |
| 6 | Record Intelligence | Normalization into `Observation` |
| 7 | DNSSEC | Existing OpenSSL DS→DNSKEY validator (Phase 3 complete-path) |
| 8–12 | Behavior / detection / evidence / report | Existing `audit` + workpaper; refined classifiers |
| 13 | Storage | JSONL observation log (SQLite/Postgres reserved) |
| 14 | Plugins | Interface headers only in Phase 1 |

Existing modules (`DnsClient`, `FrameworkAudit`, `HttpScanner`, …) remain the production implementation of later-layer behavior. New `whitedns::core` types are the stable interfaces those modules migrate onto.

---

## 2. Threat model

**Assets:** operator DNS zones, resolver honesty, collected evidence integrity, analyst workstation, output files.

**Adversaries:** on-path resolver, compromised NS, malicious RDATA, oversized/malformed packets, untrusted plugin, path-traversal via `--workpaper` names.

**In-scope abuse of DNS (detect, do not perform):** cache poisoning indicators, hijack, tunneling heuristics, lame delegation, AXFR exposure, dangling CNAME, wildcard catch-all.

**Out of scope:** stealth/evasion, unauthorized AXFR exploitation, cache injection, email sending, distributed scanning as concealment.

**Assumptions:** the operator named the target; public resolvers may geo-anycast; inconsistency ≠ poisoning.

---

## 3. Security model

- DNS bytes are untrusted input. Parser bounds: label ≤63, name ≤255, jumps ≤20, packet ≤4096 UDP / 65535 TCP.
- Findings use classes: `OBSERVATION`, `ANOMALY`, `SUSPICIOUS`, `STRONG_INDICATOR`, `CONFIRMED_BY_VALIDATION`.
- Severity ≠ confidence ≠ evidence strength.
- “Poisoning confirmed” is forbidden unless DNSSEC contradiction plus multi-resolver plus authoritative disagreement is documented.
- Output paths are sanitized (no `..`, no control chars).
- Record values are never passed to a shell.

---

## 4. DNS protocol architecture

Codec implements RFC 1035 message layout plus RFC 6891 EDNS(0).

Header fields modeled: ID, QR, Opcode, AA, TC, RD, RA, AD, CD, RCODE, QD/AN/NS/AR counts.

Sections: Question, Answer, Authority, Additional. OPT (type 41) is metadata, not a zone record.

RR types: IANA registry subset used by the platform (A–HTTPS/SVCB/CAA plus DNSSEC). Unknown types survive as RFC 3597 `TYPE####` + raw RDATA.

---

## 5. Resolver architecture

```
Resolver
  SystemResolver          // reserved
  RecursiveResolver       // 8.8.8.8 / 1.1.1.1 / operator list
  AuthoritativeResolver   // query a named NS
  UserConfiguredResolver  // --resolver / WHITEDNS_RESOLVERS
  ComparativeResolver     // fan-out + normalize
```

Each result carries: resolver identity, transport, RTT, flags, RCODE, records, error.

---

## 6. DNSSEC architecture

```
DS → DNSKEY → RRSIG → chain → AD view
```

Phase 1 exposes the existing OpenSSL DS digest match (`validate_ds_dnskey_chain`). Phase 3 adds RRSIG RRSet verify and NSEC/NSEC3 proofs. Presence-only is labeled `OBSERVATION`, not `CONFIRMED_BY_VALIDATION`.

---

## 7. Poisoning-detection methodology

Compare independently obtained A/AAAA/NS/SOA sets.

| Signal | Class if true alone |
|---|---|
| Different A, shared /16 | `OBSERVATION` (geo/anycast) |
| Different A, no prefix overlap, DNSSEC valid on one | `SUSPICIOUS` |
| Authoritative AA set ≠ recursive, DNSSEC fail | `STRONG_INDICATOR` |
| DNSSEC valid + answers match AA | not poisoning |

No cache-poisoning probes that write into foreign caches.

---

## 8. Subdomain architecture

Strategies (authorized scope only): dictionary, permutation, AXFR-if-permitted, record walking, wildcard pretest. Wildcard detection **before** brute force. CT/passive DNS are plugin slots.

---

## 9. Record graph

Nodes: Domain, Address, MailHost, Nameserver, Text, DnssecKey.  
Edges: A, AAAA, CNAME, MX, NS, TXT, CAA, SRV, DS/DNSKEY.  
Attributes: first_seen, last_seen, TTL, source, resolver, confidence.

Phase 1 emits a flattened graph JSON from `lookup`.

---

## 10. Database schema

```
targets(id, name, created_at)
observations(id, target, qname, qtype, resolver, transport, rcode,
             flags, rtt_ms, ts, packet_sha256)
records(id, observation_id, owner, type, ttl, rdata_text)
dnssec_events(id, target, ds_match, ts)
findings(id, target, rule_id, severity, confidence, class, ts)
evidence(id, finding_id, observation_id)
changes(id, target, kind, before, after, ts)
```

Phase 1 storage: JSONL (`--store file.jsonl`). SQLite/Postgres in Phase 6.

---

## 11. Evidence model

```
Finding → Rule → Observation → Wire/Response → Resolver → Timestamp
```

Evidence objects are hashable (SHA-256 of canonical JSON) for incident snapshots.

---

## 12. Detection-rule schema

```json
{
  "id": "WDNS-DNSSEC-001",
  "version": 1,
  "severity": "medium",
  "confidence": "high",
  "class": "ANOMALY",
  "description": "",
  "remediation": "",
  "references": ["RFC4034", "SANS-DNSSEC"]
}
```

Catalog: `rules/catalog.json`.

---

## 13. CLI specification

Global: `--json --quiet --verbose --debug --no-color --timeout --retries --resolver --transport --scope --store`

Commands (kept + new):

| Command | Phase |
|---|---|
| dns, web, enum, firewall, enterprise, audit | existing, kept |
| lookup, records, resolve, trace | Phase 1 |
| dnssec, poison-check, compare, wildcard, axfr-check, ns, email | wrap existing engines |
| subdomain, history, diff, ip, evidence, report, investigate, incident | later phases; stubs must not fake results |

---

## 14. Plugin API

Abstract bases: `TransportPlugin`, `ResolverPlugin`, `SecurityRule`, `StorageProvider`, `OutputPlugin`. Phase 1 ships headers only.

---

## 15. Configuration

Env: `WHITEDNS_RESOLVERS`, `NO_COLOR`, `WHITEDNS_SCOPE`, `WHITEDNS_STORE`.  
Optional future file: `whitedns.toml` (not required for Phase 1).

---

## 16. Error-code architecture

Process exits: 0 ok, 1 usage, 2 degraded, 3 exposed, 4 warning-threshold, 5 transport/parse failure.

Wire errors are structured strings: `parse/short`, `parse/pointer-loop`, `transport/timeout`, `scope/denied`.

---

## 17. Logging

`--debug` → stderr JSON lines `{ts,level,event,resolver,qname,rtt_ms}`. No secrets. No raw packet dumps unless `--debug`.

---

## 18. Testing architecture

- Unit: name codec, header flags, compression bounds (`tests/test_wire.cpp`)
- Live smoke: existing `tests/production_domains.txt`
- Property (later): parse(serialize(query)) identity

---

## 19. Fuzzing strategy

Targets: name decoder, message parser, TXT length prefixes. Corpus = truncated live packets. Phase 9.

---

## 20. Performance strategy

Bounded concurrency (existing thread fan-out). Cache by (qname,qtype,resolver) respecting TTL. Do not chase QPS as a security metric.

---

## 21. Deployment

CMake C++17, OpenSSL optional. Linux, Windows, macOS, Termux. Dockerfiles kept. No new runtime language.

---

## 22. Directory tree (additive)

```
WhiteDNS/
  docs/PLATFORM.md          this file
  include/whitedns/core/    Phase 1 interfaces
  src/core/                 Phase 1 implementation
  rules/catalog.json
  schema/observations.sql
  tests/test_wire.cpp
  src/*                     existing engines (untouched in purpose)
```

---

## 23. Roadmap

| Phase | Focus |
|---|---|
| 0 | This document |
| 1 | Wire, UDP/TCP transport, resolver, lookup/records/resolve/trace |
| 2 | Comparative resolver + cache + RTT baselines |
| 3 | Full DNSSEC RRSet + NSEC |
| 4 | Poisoning classifier with evidence classes |
| 5 | Subdomain + graph |
| 6 | JSONL/SQLite history + diff |
| 7 | Incident snapshot + evidence hash |
| 8 | API / plugins / metrics |
| 9 | Fuzz, SAST, benches |

Each phase extends interfaces above. None of the existing audit/web/enum tools are removed.
