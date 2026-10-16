#ifndef WHITEDNS_CORE_CLIDRAW_H
#define WHITEDNS_CORE_CLIDRAW_H

#include <string>

namespace whitedns {
namespace core {

void draw_banner(const std::string& title, const std::string& sub);
void draw_bar(const std::string& label, double value, double max_value, int width = 24);
void draw_rule();

} // namespace core
} // namespace whitedns

#endif
