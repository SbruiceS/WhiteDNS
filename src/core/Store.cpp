#include "whitedns/core/Store.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <filesystem>

namespace whitedns {
namespace core {

namespace fs = std::filesystem;

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

static bool ensure_dir(const std::string& dir) {
    std::error_code ec;
    fs::create_directories(dir, ec);
    return !ec;
}

bool store_put(const std::string& key, const std::string& value) {
    std::string dir = store_dir();
    if (!ensure_dir(dir)) return false;
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
    // No shell. Persist payload only. External delivery is out of process.
    const char* url = std::getenv("WHITEDNS_WEBHOOK");
    if (!url || !*url) return false;
    if (!ensure_dir(store_dir())) return false;
    std::string tmp = store_dir() + "/webhook.body";
    std::ofstream out(tmp);
    if (!out) return false;
    out << payload;
    out.close();
    // Intentionally do not invoke curl/system: avoids OS command injection (CodeQL).
    (void)url;
    return false;
}

} // namespace core
} // namespace whitedns
