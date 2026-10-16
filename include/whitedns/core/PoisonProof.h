#ifndef WHITEDNS_CORE_POISONPROOF_H
#define WHITEDNS_CORE_POISONPROOF_H

#include <string>

namespace whitedns {
namespace core {

struct ProofResult {
    bool gate_dnssec = false;
    bool gate_resolver = false;
    bool gate_aa = false;
    double posterior = 0;
    bool confirmed = false;
    std::string theorem;
    std::string proof;
};

ProofResult prove_poison(bool dnssec, bool resolver, bool aa, double posterior);
void print_poison_proof(const ProofResult& r);

} // namespace core
} // namespace whitedns

#endif
