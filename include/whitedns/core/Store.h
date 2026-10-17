#ifndef WHITEDNS_CORE_STORE_H
#define WHITEDNS_CORE_STORE_H

#include <string>

namespace whitedns {
namespace core {

// File-backed key-value store under ~/.whitedns/store/. No SQLite dependency.
bool store_put(const std::string& key, const std::string& value);
std::string store_get(const std::string& key);
bool store_has(const std::string& key);

// Scheduler state.
void scheduler_pause(const std::string& name);
void scheduler_resume(const std::string& name);
bool scheduler_is_paused(const std::string& name);

// Webhook. Posts JSON if WHITEDNS_WEBHOOK is set. Returns false if unset or curl fails.
bool webhook_post(const std::string& payload);

} // namespace core
} // namespace whitedns

#endif
