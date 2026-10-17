# ACP model

Observations form a monoid under concatenation.

- Identity: the empty observation.
- Operation: append a later observation to an earlier one.
- Associative: (a · b) · c = a · (b · c).
- Not a group: there is no inverse. A later observation does not undo an earlier one.

Invariants preserved by concatenation:

- Order of timestamps.
- Provenance of each sample.
- Raw values (filtering does not replace them).

Authentication is not an algebraic property. DNSSEC remains the integrity mechanism.

DSP and Kalman operate on the sequence. They do not change the monoid.
