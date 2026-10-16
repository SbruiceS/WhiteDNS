#ifndef WHITEDNS_CORE_STATDETECT_H
#define WHITEDNS_CORE_STATDETECT_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

struct StatReport {
    std::string qname;
    int samples = 0;
    double mean_rtt = 0;
    double var_rtt = 0;
    double z_rtt = 0;
    double sprt_llr = 0;          // Wald sequential log-likelihood ratio
    double poisson_p = 1;         // P(rate >= observed | baseline lambda)
    double amp_ratio = 0;         // response answers / 1 query
    double c2_entropy = 0;
    double poison_posterior = 0;  // Bayes, prior 0.01
    std::string flood;
    std::string amplify;
    std::string c2;
    std::string poison;
    std::string note;
};

StatReport run_stat_detect(const std::string& qname);
void print_stat_detect(const StatReport& r);

} // namespace core
} // namespace whitedns

#endif
