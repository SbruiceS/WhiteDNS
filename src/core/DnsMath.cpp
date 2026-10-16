#include "whitedns/core/DnsMath.h"

#include <cmath>
#include <map>

namespace whitedns {
namespace core {

void Kalman1::update(double z) {
    if (n == 0) {
        x = z;
        p = r;
        n = 1;
        return;
    }
    double p_pred = p + q;
    double k = p_pred / (p_pred + r);
    double innov = z - x;
    x = x + k * innov;
    p = (1.0 - k) * p_pred;
    n++;
}

double shannon_entropy(const std::string& s) {
    if (s.empty()) return 0;
    std::map<char, int> f;
    for (char c : s) f[c]++;
    double h = 0;
    for (const auto& kv : f) {
        double p = static_cast<double>(kv.second) / static_cast<double>(s.size());
        h -= p * std::log2(p);
    }
    return h;
}

MathReport score_name(const std::string& qname, const std::vector<double>& rtt_ms) {
    MathReport rep;
    rep.qname = qname;
    rep.entropy = shannon_entropy(qname);
    Kalman1 kf;
    kf.q = 2.0;
    kf.r = 9.0;
    double last_innov = 0;
    for (double z : rtt_ms) {
        double before = kf.x;
        kf.update(z);
        if (kf.n > 1) last_innov = z - before;
    }
    rep.samples = kf.n;
    rep.smoothed_rtt_ms = kf.x;
    rep.innovation_ms = last_innov;
    rep.residual_sq = last_innov * last_innov;
    rep.confidence = 1.0 / (1.0 + rep.residual_sq / (kf.r > 0 ? kf.r : 1.0));
    rep.note = "entropy is Shannon. residual_sq is convex in the innovation. "
               "Kalman is a scalar filter on RTT. "
               "Manifold, Lie algebra, and AG codes are not used: they do not describe DNS records.";
    return rep;
}

} // namespace core
} // namespace whitedns
