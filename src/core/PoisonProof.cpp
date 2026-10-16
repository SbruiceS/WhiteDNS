#include "whitedns/core/PoisonProof.h"

#include <iostream>
#include <sstream>

namespace whitedns {
namespace core {

ProofResult prove_poison(bool dnssec, bool resolver, bool aa, double posterior) {
    ProofResult r;
    r.gate_dnssec = dnssec;
    r.gate_resolver = resolver;
    r.gate_aa = aa;
    r.posterior = posterior;
    // Theorem: confirmed <=> G_dnssec ∧ G_resolver ∧ G_aa
    r.confirmed = dnssec && resolver && aa;

    std::ostringstream t;
    t << "Theorem (confirmation). Let G_d, G_r, G_a be the DNSSEC, resolver, and AA gates. "
         "A poison finding is confirmed if and only if G_d ∧ G_r ∧ G_a. "
         "A Bayes posterior P(poison|data) is not a confirmation.";
    r.theorem = t.str();

    std::ostringstream p;
    p << "Axioms\n";
    p << "  A1. G_d holds only if a DS digest contradicts the DNSKEY set.\n";
    p << "  A2. G_r holds only if recursive answer sets are disjoint.\n";
    p << "  A3. G_a holds only if an authoritative answer disagrees with a recursive one.\n";
    p << "  A4. Confirmation is the conjunction of A1, A2, and A3.\n";
    p << "  A5. A posterior is a real in (0,1). It is not a gate.\n";
    p << "Proof\n";
    p << "  (=>) Assume confirmed. By A4 each of G_d, G_r, G_a holds.\n";
    p << "  (<=) Assume G_d, G_r, G_a. By A4 the finding is confirmed.\n";
    p << "  Lemma. Posterior does not imply confirmation.\n";
    p << "    Suppose P(poison|data) = p. A5 says p is not a gate. ";
    p << "A missing gate falsifies the conjunction, so confirmation is false.\n";
    p << "  Instantiation\n";
    p << "    G_d=" << (dnssec ? "1" : "0")
      << " G_r=" << (resolver ? "1" : "0")
      << " G_a=" << (aa ? "1" : "0")
      << " posterior=" << posterior << "\n";
    p << "    conjunction=" << (r.confirmed ? "true" : "false")
      << " therefore confirmed=" << (r.confirmed ? "yes" : "no") << ".\n";
    if (posterior > 0.5 && !r.confirmed)
        p << "    Posterior is high and a gate is missing, so the lemma applies.\n";
    r.proof = p.str();
    return r;
}

void print_poison_proof(const ProofResult& r) {
    std::cout << "WhiteDNS proof\n";
    std::cout << r.theorem << "\n";
    std::cout << r.proof;
}

} // namespace core
} // namespace whitedns
