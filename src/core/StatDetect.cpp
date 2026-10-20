#include "whitedns/core/StatDetect.h"
#include "whitedns/core/PoisonProof.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/DnsMath.h"
#include "whitedns/core/ResolverEngine.h"

#include <cmath>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <sstream>

namespace whitedns {
namespace core {

namespace {

double log_fact(int n) {
    double s = 0;
    for (int i = 2; i <= n; ++i) s += std::log(static_cast<double>(i));
    return s;
}

// Poisson tail via cumulative up to k-1, then 1 - cdf. Small k only.
double poisson_sf(int k, double lambda) {
    if (lambda <= 0) return 1;
    double cdf = 0;
    double term = std::exp(-lambda);
    for (int i = 0; i < k; ++i) {
        cdf += term;
        term *= lambda / (i + 1);
    }
    double p = 1.0 - cdf;
    if (p < 0) p = 0;
    if (p > 1) p = 1;
    return p;
}

std::string home() {
    if (const char* h = std::getenv("HOME")) return h;
    return ".";
}

std::vector<double> load_rtts(const std::string& qname) {
    std::vector<double> out;
    std::ifstream in(home() + "/.whitedns/history/" + qname + ".rtt");
    double v;
    while (in >> v) out.push_back(v);
    return out;
}

void save_rtt(const std::string& qname, double rtt) {
    std::string dir = home() + "/.whitedns/history";
    std::error_code ec; std::filesystem::create_directories(dir, ec);
    std::ofstream out(dir + "/" + qname + ".rtt", std::ios::app);
    out << rtt << "\n";
}

} // namespace

StatReport run_stat_detect(const std::string& qname) {
    StatReport r;
    r.qname = qname;
    ResolverEngine engine;
    const char* resolvers[] = {"8.8.8.8", "1.1.1.1", "9.9.9.9"};
    std::vector<double> fresh;
    int answers = 0;
    for (const char* res : resolvers) {
        auto o = engine.query(qname, DNS_TYPE_A, res);
        fresh.push_back(static_cast<double>(o.rtt.count()));
        answers += static_cast<int>(o.message.answers.size());
        save_rtt(qname, fresh.back());
    }
    auto hist = load_rtts(qname);
    r.samples = static_cast<int>(hist.size());
    double sum = 0;
    for (double v : hist) sum += v;
    r.mean_rtt = hist.empty() ? 0 : sum / hist.size();
    double ss = 0;
    for (double v : hist) ss += (v - r.mean_rtt) * (v - r.mean_rtt);
    r.var_rtt = hist.size() > 1 ? ss / (hist.size() - 1) : 0;
    double last = fresh.empty() ? r.mean_rtt : fresh.back();
    double sd = r.var_rtt > 0 ? std::sqrt(r.var_rtt) : 1;
    r.z_rtt = (last - r.mean_rtt) / sd;

    // Wald SPRT: H0 rate normal (lambda=1 per sample), H1 elevated (lambda=3).
    double llr = 0;
    for (double v : fresh) {
        double z = v > r.mean_rtt + sd ? 1 : 0;
        llr += z * std::log(3.0) + (1 - z) * std::log(0.5);
    }
    r.sprt_llr = llr;

    // Flood: treat answer count as a Poisson count against a baseline of 2.
    r.poisson_p = poisson_sf(answers, 2.0);
    r.flood = (r.samples >= 6 && r.z_rtt > 3 && r.sprt_llr > 2.0) ? "elevated" : "inconclusive";

    // Amplification: answers per query. One query, N answers. Ratio is an observation.
    r.amp_ratio = answers / 3.0;
    r.amplify = r.amp_ratio > 20 ? "high-ratio" : "normal";

    // C2: label entropy. High entropy + long first label is a lexical indicator, not a channel.
    r.c2_entropy = shannon_entropy(qname);
    auto dot = qname.find('.');
    std::string first = dot == std::string::npos ? qname : qname.substr(0, dot);
    r.c2 = (r.c2_entropy >= 3.5 && first.size() >= 12) ? "lexical-indicator" : "no";

    // Poison posterior. Prior 0.01. Likelihood from z and agreement, not a confirmation.
    double prior = 0.01;
    double like = 1.0 / (1.0 + std::exp(r.z_rtt));
    r.poison_posterior = (like * prior) / (like * prior + (1.0 - like) * (1.0 - prior));
    r.poison = r.poison_posterior > 0.5 ? "posterior-high" : "posterior-low";

    r.note = "SPRT and Poisson need a baseline. One sample stays inconclusive. "
             "Poison posterior is not a confirmed attack. Confirmation still needs the three gates.";
    return r;
}

void print_stat_detect(const StatReport& r) {
    std::cout << "WhiteDNS stat  " << r.qname << "\n";
    std::cout << "samples=" << r.samples << " mean_rtt=" << r.mean_rtt
              << " var=" << r.var_rtt << " z=" << r.z_rtt << "\n";
    std::cout << "sprt_llr=" << r.sprt_llr << " poisson_sf=" << r.poisson_p
              << " amp_ratio=" << r.amp_ratio << "\n";
    std::cout << "flood=" << r.flood << " amplify=" << r.amplify
              << " c2=" << r.c2 << " entropy=" << r.c2_entropy << "\n";
    std::cout << "poison_posterior=" << r.poison_posterior << " " << r.poison << "\n";
    std::cout << r.note << "\n";
    auto proof = prove_poison(false, false, false, r.poison_posterior);
    print_poison_proof(proof);
}

} // namespace core
} // namespace whitedns
