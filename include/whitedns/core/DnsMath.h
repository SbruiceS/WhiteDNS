#ifndef WHITEDNS_CORE_DNSMATH_H
#define WHITEDNS_CORE_DNSMATH_H

#include <string>
#include <vector>

namespace whitedns {
namespace core {

// Scalar Kalman filter for RTT or TTL.
// State is one number. Process noise q, measurement noise r.
struct Kalman1 {
    double x = 0;
    double p = 1;
    double q = 1;
    double r = 4;
    int n = 0;
    void update(double z);
};

struct MathReport {
    std::string qname;
    double entropy = 0;
    double smoothed_rtt_ms = 0;
    double innovation_ms = 0;
    double residual_sq = 0;   // convex in the innovation
    double confidence = 0;    // 1 / (1 + residual), in (0, 1]
    int samples = 0;
    std::string note;
};

double shannon_entropy(const std::string& s);
double ewma(const std::vector<double>& x, double alpha = 0.3);
double first_difference(const std::vector<double>& x);
// DFT magnitude on a regularly sampled window. Irregular DNS events must be binned first.
std::vector<double> dft_magnitude(const std::vector<double>& x);
MathReport score_name(const std::string& qname, const std::vector<double>& rtt_ms);

} // namespace core
} // namespace whitedns

#endif
