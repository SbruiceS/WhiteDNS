#include "whitedns/core/QueryControl.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/CliDraw.h"
#include "whitedns/core/DohClient.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>
#include <thread>
#include <vector>

namespace whitedns {
namespace core {

ControlReport run_query_control(const std::string& qname, const std::string& transport) {
    ControlReport r;
    r.qname = qname;
    r.transport = transport.empty() ? "doh" : transport;
    r.target_ms = 80;
    // PI controller on RTT error. u = Kp*e + Ki*integral.
    const double kp = 0.4;
    const double ki = 0.05;
    double integral = 0;
    double delay_ms = 20;
    std::vector<double> samples;
    std::string endpoint = "https://dns.google/dns-query";
    for (int i = 0; i < 6; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        auto d = doh_lookup_url(endpoint, qname, DNS_TYPE_A);
        double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        if (!d.ok && ms < 1) ms = 1000;
        samples.push_back(ms);
        double err = r.target_ms - ms;
        integral = std::clamp(integral + err, -500.0, 500.0);
        double u = kp * err + ki * integral;
        delay_ms = std::clamp(delay_ms - u * 0.1, 0.0, 200.0);
        if (delay_ms > 1) std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(delay_ms)));
    }
    r.samples = static_cast<int>(samples.size());
    double sum = 0;
    for (double v : samples) sum += v;
    r.mean_ms = samples.empty() ? 0 : sum / samples.size();
    // Little's law style: utilization ~ service time / (service + delay).
    r.util = r.mean_ms / (r.mean_ms + delay_ms + 1);
    r.rate = delay_ms <= 1 ? 0 : static_cast<int>(1000.0 / (r.mean_ms + delay_ms));
    r.note = "PI on RTT error. target 80 ms. util = service/(service+delay). not a flood.";
    return r;
}

void print_query_control(const ControlReport& r) {
    draw_banner("WhiteDNS query control", r.qname + "  " + r.transport);
    std::cout << "  samples=" << r.samples << "  target_ms=" << r.target_ms
              << "  mean_ms=" << r.mean_ms << "\n";
    draw_bar("mean rtt", r.mean_ms, std::max(r.target_ms, r.mean_ms));
    draw_bar("util", r.util, 1.0);
    std::cout << "  suggested_qps=" << r.rate << "\n";
    draw_rule();
    std::cout << "  " << r.note << "\n";
}

} // namespace core
} // namespace whitedns
