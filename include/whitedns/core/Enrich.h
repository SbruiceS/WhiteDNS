#ifndef WHITEDNS_CORE_ENRICH_H
#define WHITEDNS_CORE_ENRICH_H

#include <string>

namespace whitedns {
namespace core {

void print_dot(const std::string& name, const std::string& endpoint);
void print_rdap(const std::string& name);
void print_asn(const std::string& name);
void print_pcap(const std::string& path);
void print_feeds2(const std::string& name, const std::string& local_file);
void save_history(const std::string& name, const std::string& json);
std::string last_history(const std::string& name);

} // namespace core
} // namespace whitedns

#endif
