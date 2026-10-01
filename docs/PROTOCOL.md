# Protocol engine

Strict parser. Counts and lengths are not trusted. Compression pointers are bounded and cannot loop.

```bash
whitedns wire-check
```

That runs the built-in vectors: short header, compression loop, one compressed A record.

Unknown types stay opaque. TC=1 is recorded and is not treated as an empty answer. NXDOMAIN is the header RCODE, not an empty NOERROR.

OPT is not stored as zone data. ASN, RDAP, and TLS are not part of this parser.
