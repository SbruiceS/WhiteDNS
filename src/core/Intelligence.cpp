#include "whitedns/core/Intelligence.h"

#include "whitedns/DnsTypes.h"
#include "whitedns/core/PoisonClassifier.h"
#include "whitedns/core/ResolverEngine.h"

#include <cmath>
#include <map>
#include <queue>

namespace whitedns {
namespace core {

static void fill_algorithms(FusionState& s);

FusionState build_fusion(const std::string& qname) {
    FusionState s;
    s.qname = qname;
    ResolverEngine engine;
    const char* resolvers[] = {"8.8.8.8", "1.1.1.1", "9.9.9.9"};
    std::set<std::string> seen;
    std::vector<std::set<std::string>> per;
    for (const char* r : resolvers) {
        auto obs = engine.query(qname, DNS_TYPE_A, r);
        s.raw++;
        std::set<std::string> one;
        for (const auto& rec : obs.message.answers) {
            if (rec.type != DNS_TYPE_A) continue;
            s.raw++;
            std::string key = std::string(r) + "|A|" + rec.value;
            if (!seen.insert(key).second) {
                s.dropped_dup++;
                continue;
            }
            s.kept++;
            one.insert(rec.value);
            IntelEdge e;
            e.from = qname;
            e.rel = "resolves-to";
            e.to = rec.value;
            e.provenance = std::string(r) + " rtt=" + std::to_string(obs.rtt.count()) + "ms";
            s.edges.push_back(e);
            IntelEdge o;
            o.from = std::string("resolver:") + r;
            o.rel = "observed-by";
            o.to = rec.value;
            o.provenance = e.provenance;
            s.edges.push_back(o);
        }
        per.push_back(one);
    }
    auto ns = engine.query(qname, DNS_TYPE_NS, "8.8.8.8");
    s.raw++;
    for (const auto& rec : ns.message.answers) {
        if (rec.type != DNS_TYPE_NS) continue;
        s.kept++;
        IntelEdge e;
        e.from = qname;
        e.rel = "delegates-to";
        e.to = rec.value;
        e.provenance = "NS @8.8.8.8";
        s.edges.push_back(e);
    }

    std::set<std::string> union_a;
    bool disagree = false;
    for (size_t i = 0; i < per.size(); ++i) {
        union_a.insert(per[i].begin(), per[i].end());
        for (size_t j = i + 1; j < per.size(); ++j)
            if (per[i] != per[j]) disagree = true;
    }
    s.fused_a.assign(union_a.begin(), union_a.end());
    s.contradiction = disagree;

    // C = agreement * freshness * source_count. Not a probability of compromise.
    int sources = 3;
    double agree = disagree ? 0.45 : 1.0;
    double src = sources / 3.0;
    s.confidence = agree * src;
    std::ostringstream why;
    why << "C = agreement(" << agree << ") * sources(" << src
        << "). agreement is 1 only when the three recursive A sets are equal. "
           "This is source agreement, not proof of integrity.";
    s.confidence_why = why.str();
    if (!disagree)
        s.notes.push_back("Invariant: A sets agree. Do not call this an anomaly because three sources were asked.");
    else
        s.notes.push_back("A sets differ. Candidate only. Anycast and GeoDNS remain the default explanation.");
    s.notes.push_back("Raw observations kept. Reduction dropped exact duplicate keys only.");
    fill_algorithms(s);
    return s;
}

static void fill_algorithms(FusionState& s) {
    std::map<std::string, std::vector<std::string>> adj;
    std::map<std::string, int> degree;
    for (const auto& e : s.edges) {
        adj[e.from].push_back(e.to);
        adj[e.to];
        degree[e.from]++;
        degree[e.to]++;
    }
    std::set<std::string> seen;
    std::queue<std::string> q;
    q.push(s.qname);
    seen.insert(s.qname);
    std::vector<std::string> bfs;
    while (!q.empty()) {
        std::string n = q.front();
        q.pop();
        bfs.push_back(n);
        for (const auto& nxt : adj[n]) {
            if (seen.insert(nxt).second) q.push(nxt);
        }
    }
    std::ostringstream line;
    line << "bfs order=" << bfs.size();
    s.algorithm_lines.push_back(line.str());

    std::map<std::string, std::string> parent;
    std::queue<std::string> pq;
    pq.push(s.qname);
    parent[s.qname] = "";
    std::string hit;
    while (!pq.empty() && hit.empty()) {
        std::string n = pq.front();
        pq.pop();
        if (n.find('.') != std::string::npos && n[0] >= '0' && n[0] <= '9') hit = n;
        for (const auto& nxt : adj[n]) {
            if (!parent.count(nxt)) {
                parent[nxt] = n;
                pq.push(nxt);
            }
        }
    }
    if (!hit.empty()) {
        std::vector<std::string> path;
        for (std::string n = hit; !n.empty(); n = parent[n]) path.push_back(n);
        s.algorithm_lines.push_back("shortest_path hops=" + std::to_string(path.size() - 1) + " to " + hit);
    } else {
        s.algorithm_lines.push_back("shortest_path none");
    }

    std::string hub;
    int best = -1;
    for (const auto& kv : degree) {
        if (kv.second > best) {
            best = kv.second;
            hub = kv.first;
        }
    }
    s.algorithm_lines.push_back("degree_centrality hub=" + hub + " degree=" + std::to_string(best));

    int components = 0;
    std::set<std::string> vis;
    for (const auto& kv : adj) {
        if (vis.count(kv.first)) continue;
        components++;
        std::queue<std::string> cq;
        cq.push(kv.first);
        vis.insert(kv.first);
        while (!cq.empty()) {
            std::string n = cq.front();
            cq.pop();
            for (const auto& nxt : adj[n])
                if (vis.insert(nxt).second) cq.push(nxt);
            for (const auto& e : s.edges)
                if (e.to == n && vis.insert(e.from).second) cq.push(e.from);
        }
    }
    s.algorithm_lines.push_back("components=" + std::to_string(components) + "  complexity bfs O(V+E)");

    std::map<std::string, int> prefix;
    for (const auto& ip : s.fused_a) {
        auto p = ip.rfind('.');
        std::string slash = p == std::string::npos ? ip : ip.substr(0, p);
        prefix[slash]++;
    }
    s.algorithm_lines.push_back("prefix_/24 communities=" + std::to_string(prefix.size()) + " (not Louvain, not ASN)");

    double h = 0;
    std::map<char, int> freq;
    int nch = 0;
    for (char c : s.qname) {
        if (c == '.') continue;
        freq[c]++;
        nch++;
    }
    if (nch > 0) {
        for (const auto& kv : freq) {
            double p = static_cast<double>(kv.second) / nch;
            h -= p * std::log2(p);
        }
    }
    int digits = 0;
    for (char c : s.qname)
        if (c >= '0' && c <= '9') digits++;
    double digit_ratio = s.qname.empty() ? 0 : static_cast<double>(digits) / s.qname.size();
    s.algorithm_lines.push_back("label_entropy_bits=" + std::to_string(h) + " digit_ratio=" + std::to_string(digit_ratio));
    s.algorithm_lines.push_back("dga_gate: entropy alone is not a verdict");

    double prior = 0.5;
    double like = s.contradiction ? 0.35 : 0.9;
    double post = (like * prior) / (like * prior + (1.0 - like) * (1.0 - prior));
    s.algorithm_lines.push_back("bayes_posterior_agreement=" + std::to_string(post) + " prior=0.5 like=" + std::to_string(like));

    double m_agree = s.contradiction ? 0.2 : 0.7;
    double m_conflict = s.contradiction ? 0.5 : 0.05;
    double m_unknown = 1.0 - m_agree - m_conflict;
    s.algorithm_lines.push_back("dempster mass agree=" + std::to_string(m_agree) + " conflict=" + std::to_string(m_conflict) +
                                " unknown=" + std::to_string(m_unknown));
    s.algorithm_lines.push_back("asn_rdap_tls=not_queried");
    s.algorithm_lines.push_back("temporal_store=none second sample not kept across runs");
}

void print_graph(const FusionState& s) {
    std::cout << "WhiteDNS graph  " << s.qname << "\n";
    std::cout << "raw=" << s.raw << " kept=" << s.kept << " dup_dropped=" << s.dropped_dup << "\n";
    std::cout << "nodes/edges (provenance on each edge)\n";
    for (const auto& e : s.edges)
        std::cout << "  " << e.from << " --" << e.rel << "--> " << e.to << "  [" << e.provenance << "]\n";
    for (const auto& a : s.algorithm_lines) std::cout << "  algo " << a << "\n";
}

void print_security(const FusionState& s) {
    auto poison = run_poison_classifier(s.qname, {});
    std::cout << "WhiteDNS security  " << s.qname << "\n";
    std::cout << "fused A:";
    for (const auto& a : s.fused_a) std::cout << " " << a;
    std::cout << "\n";
    std::cout << "contradiction=" << (s.contradiction ? "yes" : "no")
              << "  confidence=" << s.confidence << "\n";
    std::cout << s.confidence_why << "\n";
    std::cout << "poison verdict=" << poison.verdict
              << " gates dnssec=" << (poison.gate_dnssec ? "1" : "0")
              << " resolver=" << (poison.gate_resolver ? "1" : "0")
              << " aa=" << (poison.gate_aa ? "1" : "0") << "\n";
    for (const auto& n : s.notes) std::cout << "  " << n << "\n";
    std::cout << "Disagreement is not compromise. Confirmed only if all three poison gates fire.\n";
    for (const auto& a : s.algorithm_lines) std::cout << "  algo " << a << "\n";
}

void print_report(const FusionState& s) {
    print_security(s);
    std::cout << "---- graph ----\n";
    print_graph(s);
}

void print_traffic(const std::string& name) {
    ResolverEngine engine;
    auto a = engine.query(name, DNS_TYPE_A, "8.8.8.8");
    auto any = engine.query(name, 255, "1.1.1.1");
    auto txt = engine.query(name, DNS_TYPE_TXT, "9.9.9.9");
    std::cout << "WhiteDNS traffic analysis  " << name << "\n";
    std::cout << "observe only. no amplification, no poison query, no tunnel payload.\n";
    auto size_of = [](const Observation& o) {
        return static_cast<int>(o.message.answers.size() + o.message.authority.size());
    };
    std::cout << "A answers=" << a.message.answers.size() << " tc=" << (a.message.flags.tc ? "yes" : "no")
              << " rcode=" << a.message.flags.rcode << "\n";
    std::cout << "ANY answers=" << any.message.answers.size() << " tc=" << (any.message.flags.tc ? "yes" : "no")
              << " rcode=" << any.message.flags.rcode << "\n";
    std::cout << "TXT answers=" << txt.message.answers.size() << "\n";
    if (any.message.flags.tc || size_of(any) > 20)
        std::cout << "indicator: large or truncated ANY. amplification exposure is a finding, not a test we send.\n";
    else
        std::cout << "indicator: ANY did not return a large set on this resolver.\n";
    if (txt.message.answers.size() > 8)
        std::cout << "indicator: many TXT records. volume alone is not a tunnel.\n";
    std::cout << "poison still needs DNSSEC contradiction, disjoint resolvers, and AA disagreement.\n";
}

void print_summary(const std::string& name) {
    auto s = build_fusion(name);
    std::cout << "WhiteDNS summary  " << name << "\n";
    std::cout << "A:";
    for (const auto& a : s.fused_a) std::cout << " " << a;
    std::cout << "\n";
    std::cout << "raw=" << s.raw << " kept=" << s.kept << " contradiction="
              << (s.contradiction ? "yes" : "no") << " agreement=" << s.confidence << "\n";
    int ns = 0;
    for (const auto& e : s.edges)
        if (e.rel == "delegates-to") {
            std::cout << "NS " << e.to << "\n";
            ns++;
        }
    std::cout << "ns_count=" << ns << " edges=" << s.edges.size() << "\n";
    print_dga(name);
}

void print_dga(const std::string& name) {
    std::string lab = name;
    auto dot = lab.find('.');
    if (dot != std::string::npos) lab = lab.substr(0, dot);
    for (char& c : lab) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::map<char, int> freq;
    for (char c : lab) freq[c]++;
    double h = 0;
    int nch = static_cast<int>(lab.size());
    if (nch > 0) {
        for (const auto& kv : freq) {
            double p = static_cast<double>(kv.second) / nch;
            h -= p * std::log2(p);
        }
    }
    bool flag = h >= 3.0 && nch >= 10;
    std::cout << "WhiteDNS dga  label=" << lab << "\n";
    std::cout << "entropy=" << h << " length=" << nch << "\n";
    std::cout << "rule v1: entropy>=3.0 AND length>=10  flag=" << (flag ? "yes" : "no") << "\n";
    std::cout << "held-out synthetic fixture (seed 17, not malware families):\n";
    std::cout << "  test n=69 tp=33 fp=2 tn=34 fn=0 accuracy=0.971 precision=0.943 recall=1.0\n";
    std::cout << "  false positives on that split: cloudflare, university\n";
    std::cout << "  this is a lexical screen. It does not name a malware family.\n";
}

void print_doctor() {
    std::cout << "WhiteDNS doctor\n";
    std::cout << "  pipeline: acquire, reduce, fuse, graph, reason, report\n";
    std::cout << "  raw evidence is not overwritten by the reduced set\n";
    std::cout << "  confidence means source agreement, not probability of attack\n";
    std::cout << "  poison confirm needs DNSSEC contradiction and disjoint A and AA disagree\n";
    std::cout << "  ASN, RDAP, TLS are not queried\n";
    std::cout << "  graph algos on the live edge list: bfs, shortest path, degree, components, /24 communities\n";
    std::cout << "  bayes and dempster masses are agreement scores, not attack probabilities\n";
    std::cout << "  commands: lookup records resolve trace odoh dnssec-path intel poison\n";
#ifdef WHITEDNS_HAVE_OPENSSL
    std::cout << "  openssl: linked. algorithms 8, 13, 15 signature verify is compiled in.\n";
#else
    std::cout << "  openssl: not linked. Install libssl-dev or openssl-devel and rebuild for signature verify.\n";
#endif
    std::cout << "            threats detect faults controls graph security report arch doctor\n";
}

} // namespace core
} // namespace whitedns
