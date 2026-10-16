#ifndef WHITEDNS_SUBDOMAIN_DSL_H
#define WHITEDNS_SUBDOMAIN_DSL_H

#include <string>
#include <vector>

namespace whitedns {

// Pattern DSL. Not a geometric manifold.
// {a|b|c} alternatives, {n} 0-9, {nn} 00-99, {env} {role} {region} {svc} named sets.
// Several patterns may be separated by ';'.
std::vector<std::string> expand_dsl(const std::string& pattern, int cap = 20000);

// G4: Cartesian product of four stem sets (env x role x region x svc), joined by '-'.
std::vector<std::string> generate_g4(int cap = 20000);

// Permutations of 2 and 3 distinct stems, joined by '-' and by concatenation.
std::vector<std::string> generate_permutations(int cap = 20000);

} // namespace whitedns

#endif
