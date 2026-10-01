# ODoH

RFC 9230 client. The relay sees the client address, not the name. The target sees the name, not the client address, if the two do not collude.

```bash
whitedns odoh <name>
whitedns odoh-filter <name>
whitedns odoh-policy <name>
whitedns odoh-leak
```

Default target is the Cloudflare ODoH endpoint. A relay URL can be set with the existing proxy option. Internal names are allowed by the filter. Do not send queries you are not authorized to make.
