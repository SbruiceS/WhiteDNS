#include "whitedns/core/Store.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace whitedns {
namespace core {

static std::string store_dir() {
    const char* h = std::getenv("HOME");
    std::string base = h ? h : ".";
    return base + "/.whitedns/store";
}

static std::string safe_key(const std::string& key) {
    std::string out;
    for (char c : key) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
            out.push_back(c);
        else
            out.push_back('_');
    }
    return out.empty() ? "empty" : out;
}

bool store_put(const std::string& key, const std::string& value) {
    std::string dir = store_dir();
    std::system(("mkdir -p \"" + dir + "\"").c_str());
    std::ofstream out(dir + "/" + safe_key(key));
    if (!out) return false;
    out << value;
    return true;
}

std::string store_get(const std::string& key) {
    std::ifstream in(store_dir() + "/" + safe_key(key));
    if (!in) return {};
    std::stringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

bool store_has(const std::string& key) {
    std::ifstream in(store_dir() + "/" + safe_key(key));
    return static_cast<bool>(in);
}

void scheduler_pause(const std::string& name) { store_put("sched." + name, "paused"); }
void scheduler_resume(const std::string& name) { store_put("sched." + name, "running"); }
bool scheduler_is_paused(const std::string& name) { return store_get("sched." + name) == "paused"; }

bool webhook_post(const std::string& payload) {
    const char* url = std::getenv("WHITEDNS_WEBHOOK");
    if (!url || !*url) return false;
    std::string tmp = store_dir() + "/webhook.body";
    std::system(("mkdir -p \"" + store_dir() + "\"").c_str());
    std::ofstream out(tmp);
    out << payload;
    out.close();
    std::string cmd = std::string("curl -s -m 10 -X POST -H 'Content-Type: application/json' --data @") + tmp + " \"" + url + "\" >/dev/null 2>&1";
    int rc = std::system(cmd.c_str());
    return rc == 0;
}

} // namespace core
} // namespace whitedns
