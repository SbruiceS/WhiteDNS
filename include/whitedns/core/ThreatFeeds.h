#ifndef WHITEDNS_CORE_THREAT_FEEDS_H
#define WHITEDNS_CORE_THREAT_FEEDS_H

#include <string>

namespace whitedns {
namespace core {

void print_threat_feeds(const std::string& name, const std::string& local_urlhaus = "");
int feed_match(const std::string& name, const std::string& local_urlhaus);

} // namespace core
} // namespace whitedns

#endif
