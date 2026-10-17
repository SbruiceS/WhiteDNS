# Protocol engine status

Implemented behind existing commands. No new CLI.

## Present

| Area | What | Where |
|---|---|---|
| ACP | Monoid of observation concatenation | docs/ACP.md |
| DSP | EWMA, first difference, DFT, Welch PSD | DnsMath |
| Kalman | Scalar filter and Joseph-form covariance | DnsMath |
| Information | Shannon entropy, KL divergence, CUSUM | DnsMath |
| Graph | Components, PageRank, degree, algebraic connectivity | graphintel |
| Topology | beta0, beta1, Euler, 0-d persistence | topology |
| Coding | GF(2) syndrome, nearest decode | AgCode |
| Dashboard | Optional FTXUI | -DWHITEDNS_FTXUI=ON |

## Not a finding

Entropy, KL, CUSUM, PageRank, Betti, and persistence are research indicators.
Poison confirmation still requires the three gates.

## Not complete

- Full AG decoding over algebraic curves
- Betweenness centrality
- Hidden Markov models
- Benchmarks with recorded hardware
