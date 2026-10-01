# Commands

```bash
whitedns <command> [options] <name>
whitedns arch
whitedns doctor
```

Colour: `--color always`, `--color auto`, `--color never`. `NO_COLOR` disables colour.

| Layer | Commands |
|---|---|
| collect | lookup, records, resolve, compare, trace, baseline |
| privacy | odoh, odoh-filter, odoh-policy, odoh-leak |
| validation | dnssec, dnssec-path, intel |
| detection | poison, threats, detect, explain, faults, controls, audit, dga |
| report | graph, security, report, arch, doctor |

Poison confirmation needs all three gates: DNSSEC contradiction, disjoint recursive answers, and authoritative disagreement.
