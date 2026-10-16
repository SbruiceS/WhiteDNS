#include "whitedns/SubdomainDsl.h"

#include <cctype>
#include <cstdio>
#include <set>
#include <sstream>

namespace whitedns {

namespace {

std::vector<std::string> named_set(const std::string& name) {
    if (name == "env") return {"dev", "stg", "stage", "uat", "qa", "prod", "test", "lab", "demo", "beta"};
    if (name == "role") return {"api", "www", "app", "web", "mail", "vpn", "auth", "login", "cdn", "admin", "db", "edge"};
    if (name == "region") return {"eu", "us", "ap", "in", "uk", "de", "fr", "jp", "au", "sg", "ae"};
    if (name == "svc") return {"api", "web", "auth", "cdn", "db", "edge", "origin", "proxy", "lb", "static"};
    return {name};
}

std::vector<std::string> split_alts(const std::string& body) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : body) {
        if (c == '|') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

void add_unique(std::vector<std::string>& out, std::set<std::string>& seen, const std::string& s, int cap) {
    if (static_cast<int>(out.size()) >= cap) return;
    if (s.empty() || s.size() > 63) return;
    if (!seen.insert(s).second) return;
    out.push_back(s);
}

} // namespace

std::vector<std::string> expand_dsl(const std::string& pattern, int cap) {
    std::vector<std::string> out;
    std::set<std::string> seen;
    std::stringstream parts(pattern);
    std::string one;
    while (std::getline(parts, one, ';')) {
        std::vector<std::string> acc{""};
        for (size_t i = 0; i < one.size() && static_cast<int>(out.size()) < cap;) {
            if (one[i] == '{') {
                auto end = one.find('}', i);
                if (end == std::string::npos) break;
                std::string body = one.substr(i + 1, end - i - 1);
                std::vector<std::string> choices;
                if (body == "n") {
                    for (int n = 0; n <= 9; ++n) choices.push_back(std::to_string(n));
                } else if (body == "nn") {
                    for (int n = 0; n <= 99; ++n) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "%02d", n);
                        choices.push_back(buf);
                    }
                } else if (body.find('|') != std::string::npos) {
                    choices = split_alts(body);
                } else {
                    choices = named_set(body);
                }
                std::vector<std::string> next;
                for (const auto& prefix : acc) {
                    for (const auto& c : choices) {
                        if (static_cast<int>(next.size()) >= cap) break;
                        next.push_back(prefix + c);
                    }
                }
                acc.swap(next);
                i = end + 1;
            } else {
                for (auto& s : acc) s.push_back(one[i]);
                ++i;
            }
        }
        for (const auto& s : acc) add_unique(out, seen, s, cap);
    }
    return out;
}

std::vector<std::string> generate_g4(int cap) {
    auto env = named_set("env");
    auto role = named_set("role");
    auto region = named_set("region");
    auto svc = named_set("svc");
    std::vector<std::string> out;
    std::set<std::string> seen;
    for (const auto& e : env) {
        for (const auto& r : role) {
            for (const auto& g : region) {
                for (const auto& s : svc) {
                    if (static_cast<int>(out.size()) >= cap) return out;
                    add_unique(out, seen, e + "-" + r + "-" + g + "-" + s, cap);
                    add_unique(out, seen, r + "-" + e + "-" + g, cap);
                    add_unique(out, seen, r + g + s, cap);
                }
            }
        }
    }
    return out;
}

std::vector<std::string> generate_permutations(int cap) {
    std::vector<std::string> stems = {"api", "dev", "stg", "prod", "admin", "auth", "cdn", "edge",
                                      "app", "web", "mail", "vpn", "db", "login", "static", "internal"};
    std::vector<std::string> out;
    std::set<std::string> seen;
    for (size_t i = 0; i < stems.size() && static_cast<int>(out.size()) < cap; ++i) {
        for (size_t j = 0; j < stems.size() && static_cast<int>(out.size()) < cap; ++j) {
            if (i == j) continue;
            add_unique(out, seen, stems[i] + "-" + stems[j], cap);
            add_unique(out, seen, stems[i] + stems[j], cap);
            for (size_t k = 0; k < stems.size() && static_cast<int>(out.size()) < cap; ++k) {
                if (k == i || k == j) continue;
                add_unique(out, seen, stems[i] + "-" + stems[j] + "-" + stems[k], cap);
            }
        }
    }
    return out;
}

} // namespace whitedns
