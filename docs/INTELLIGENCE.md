# Intelligence pipeline

acquire, reduce, fuse, graph, reason, report.

Reduction drops exact duplicate keys of the form `resolver|type|value`. Raw counts are kept.

Fusion uses three resolvers. The fused address set is the union. A contradiction flag is set when the sets differ.

Confidence is source agreement, not a probability of compromise.

Graph edges: resolves-to, observed-by, delegates-to. Algorithms on that list: BFS, shortest path, degree, components, /24 buckets.

`whitedns dga <name>` applies rule v1: first-label entropy at least 3.0 and length at least 10. It is a lexical screen. It does not name a malware family.

ASN, RDAP, and TLS are not queried.

```bash
whitedns graph <name>
whitedns security <name>
whitedns report <name>
whitedns dga <name>
whitedns doctor
```
