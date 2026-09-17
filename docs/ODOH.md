# Oblivious DNS over HTTPS (ODoH)

**RFC 9230 (Experimental)**  
**WhiteDNS module:** `whitedns::core` ODoH client  
**Developer:** Cosinfotech Solutions · **Author:** S. Bruice Singh

## Why ODoH exists

DoH (RFC 8484) hides the query from the access network. It does **not** hide the query from the recursive operator. That operator still sees:

- client IP
- full QNAME and QTYPE
- a timestamped history of names

ODoH splits those two facts across two organizations.

```
Client
  │  HTTPS + HPKE ciphertext (name is inside)
  ▼
Proxy     knows: client IP, target host
          cannot: read DNS plaintext
  │  HTTPS + same ciphertext
  ▼
Target    knows: DNS plaintext, proxy IP
          cannot: see client IP
  │
  ▼
Recursive / auth DNS
```

RFC 9230: no single server entity is aware of both the client IP address and the DNS message contents, **provided the proxy and target do not collude**.

## Privacy benefits (what you actually gain)

1. **Unlinkability of identity and name.** The target cannot write “this subscriber resolved `intranet.example`.” It can only write “some client behind proxy P resolved `intranet.example`.”
2. **Unlinkability across IP changes.** The target never sees the stub IP, so it cannot stitch a device’s query history across home/LTE/VPN addresses by IP alone.
3. **Access-network blindness.** Same as DoH: the ISP sees HTTPS to a proxy, not QNAMEs.
4. **Operator choice.** The client picks the pair. A research lab can use a university proxy + Cloudflare target, or the reverse.
5. **No client identifiers in-band.** The RFC forbids forwarding `Forwarded`, cookies, or client auth from proxy to target. WhiteDNS does not send those headers.

## What ODoH does not give you

| Claim | Reality |
|---|---|
| Anonymity | The proxy still sees your IP and that you use ODoH. |
| Protection if proxy ≡ target | Same org on both sides = ordinary DoH. Cloudflare-as-target plus Cloudflare-as-proxy is not oblivious. |
| Protection against collusion | If P and T pool logs, the split collapses. |
| Protection against traffic analysis | Sizes and timing still leak. Padding helps; it is not perfect. |
| Protection if the target owns the zone | A malicious answer can point you at a target-controlled IP; the next TCP/TLS handshake re-identifies you. |
| Legal immunity | A warrant to *both* operators reconstructs the pair. |

μODoH (multiple random relays) exists because collusion is the residual risk.

## Comparison

| Property | UDP/53 | DoH | ODoH |
|---|---|---|---|
| On-path reads QNAME | yes | no | no |
| Resolver sees client IP | yes | yes | no (sees proxy) |
| Resolver sees QNAME | yes | yes | yes |
| Proxy sees QNAME | n/a | n/a | no |
| Needs two non-colluding orgs | no | no | **yes** |
| Easy to block | no | harder | harder |
| Extra latency | — | one TLS | two TLS + HPKE |

## WhiteDNS usage

```bash
whitedns odoh nasa.gov
# Production default is already oblivious:
#   target  odoh.cloudflare-dns.com          (Cloudflare)
#   relay   odoh-relay.edgecompute.app       (Fastly / crypto.sx)
#   fallback odoh-relay.numa.rs/relay        (Numa.rs, Hetzner DE)

whitedns odoh --proxy direct nasa.gov
export WHITEDNS_ODOH_PROXY='https://odoh-relay.numa.rs/relay{?targethost,targetpath}'
```

`--proxy direct` skips the relay (crypto only, `oblivious=no`). Never pair a Cloudflare relay with a Cloudflare target.

## Production pairing shipped in WhiteDNS

| Role | Operator | Endpoint |
|---|---|---|
| Target | Cloudflare | `odoh.cloudflare-dns.com` |
| Relay A | Fastly / crypto.sx | `https://odoh-relay.edgecompute.app/{?targethost,targetpath}` |
| Relay B | Numa.rs | `https://odoh-relay.numa.rs/relay{?targethost,targetpath}` |

Relays come from the DNSCrypt public ODoH list. The client tries A then B. Direct-to-target is last resort and is labeled `oblivious=no`.
