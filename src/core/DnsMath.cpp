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

double ewma(const std::vector<double>& x, double alpha) {
    if (x.empty()) return 0;
    double y = x[0];
    for (size_t i = 1; i < x.size(); ++i) y = alpha * x[i] + (1.0 - alpha) * y;
    return y;
}

double first_difference(const std::vector<double>& x) {
    if (x.size() < 2) return 0;
    return x.back() - x[x.size() - 2];
}

std::vector<double> dft_magnitude(const std::vector<double>& x) {
    std::vector<double> mag;
    int n = static_cast<int>(x.size());
    if (n < 2) return mag;
    int half = n / 2;
    mag.resize(half);
    for (int k = 0; k < half; ++k) {
        double re = 0, im = 0;
        for (int t = 0; t < n; ++t) {
            double ang = 2.0 * 3.141592653589793 * k * t / n;
            re += x[t] * std::cos(ang);
            im -= x[t] * std::sin(ang);
        }
        mag[k] = std::sqrt(re * re + im * im);
    }
    return mag;
}

std::vector<double> welch_psd(const std::vector<double>& x, int window, int overlap) {
    std::vector<double> acc;
    if (window < 4 || overlap >= window || static_cast<int>(x.size()) < window) return acc;
    int step = window - overlap;
    int count = 0;
    for (int start = 0; start + window <= static_cast<int>(x.size()); start += step) {
        std::vector<double> seg(x.begin() + start, x.begin() + start + window);
        auto mag = dft_magnitude(seg);
        if (acc.empty()) acc.assign(mag.size(), 0);
        for (size_t i = 0; i < mag.size() && i < acc.size(); ++i) acc[i] += mag[i] * mag[i];
        count++;
    }
    if (count > 0) for (double& v : acc) v /= count;
    return acc;
}

double kl_divergence(const std::vector<double>& p, const std::vector<double>& q) {
    if (p.size() != q.size() || p.empty()) return 0;
    double s = 0;
    for (size_t i = 0; i < p.size(); ++i) {
        if (p[i] <= 0 || q[i] <= 0) continue;
        s += p[i] * std::log2(p[i] / q[i]);
    }
    return s;
}

double cusum(const std::vector<double>& x, double target) {
    double s = 0, peak = 0;
    for (double v : x) {
        s = std::max(0.0, s + (v - target));
        peak = std::max(peak, s);
    }
    return peak;
}

void KalmanJoseph::update(double z) {
    if (n == 0) { x = z; p = r; n = 1; return; }
    double p_pred = p + q;
    double k = p_pred / (p_pred + r);
    double innov = z - x;
    x = x + k * innov;
    // Joseph form: P = (I-KH)P(I-KH)' + KRK'
    double ikh = 1.0 - k;
    p = ikh * p_pred * ikh + k * r * k;
    n++;
}

std::vector<int> Hmm2::viterbi(const std::vector<int>& obs) const {
    std::vector<int> path;
    if (obs.empty()) return path;
    double v0 = 0.5, v1 = 0.5;
    std::vector<int> prev0, prev1;
    for (int o : obs) {
        double e0 = (o == 0) ? b0 : (1.0 - b0);
        double e1 = (o == 0) ? b1 : (1.0 - b1);
        double n0 = std::max(v0 * a00, v1 * a10) * e0;
        double n1 = std::max(v0 * a01, v1 * a11) * e1;
        int p0 = (v0 * a00 >= v1 * a10) ? 0 : 1;
        int p1 = (v0 * a01 >= v1 * a11) ? 0 : 1;
        prev0.push_back(p0);
        prev1.push_back(p1);
        v0 = n0; v1 = n1;
    }
    int state = (v0 >= v1) ? 0 : 1;
    path.resize(obs.size());
    for (int t = static_cast<int>(obs.size()) - 1; t >= 0; --t) {
        path[t] = state;
        state = (state == 0) ? prev0[t] : prev1[t];
    }
    return path;
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
