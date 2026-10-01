# Protocol engine

Strict parser. Counts and lengths are not trusted. Compression pointers are bounded and cannot loop.

```bash
whitedns wire-check
```

That runs the built-in vectors: short header, compression loop, one compressed A record.

Typed notes now cover A, AAAA, MX, TXT strings, SOA, CAA, SRV, SVCB, HTTPS, DS, DNSKEY, RRSIG, NSEC, NSEC3, and OPT. Unknown types stay opaque. TXT overruns are InvalidRData. NXDOMAIN is not NODATA. Signature bytes are parsed, not verified here.

OPT is not stored as zone data. ASN, RDAP, and TLS are not part of this parser.
