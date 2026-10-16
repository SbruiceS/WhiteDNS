#include "whitedns/core/CliDraw.h"

#include <algorithm>
#include <iostream>

namespace whitedns {
namespace core {

namespace {
const char* C = "\x1b[36m";
const char* G = "\x1b[32m";
const char* Y = "\x1b[33m";
const char* D = "\x1b[2m";
const char* B = "\x1b[1m";
const char* R = "\x1b[0m";
}

void draw_banner(const std::string& title, const std::string& sub) {
    std::cout << C << "┌──────────────────────────────────────────────────────────────┐\n";
    std::cout << "│ " << B << title;
    if (title.size() < 60) std::cout << std::string(60 - title.size(), ' ');
    std::cout << R << C << "│\n";
    std::cout << "│ " << D << sub;
    if (sub.size() < 60) std::cout << std::string(60 - sub.size(), ' ');
    std::cout << R << C << "│\n";
    std::cout << "└──────────────────────────────────────────────────────────────┘" << R << "\n";
}

void draw_bar(const std::string& label, double value, double max_value, int width) {
    if (max_value <= 0) max_value = 1;
    int filled = static_cast<int>((value / max_value) * width);
    if (filled < 0) filled = 0;
    if (filled > width) filled = width;
    std::string name = label.size() > 22 ? label.substr(0, 22) : label;
    std::cout << "  " << name << std::string(22 - name.size(), ' ') << " " << G;
    for (int i = 0; i < filled; ++i) std::cout << "█";
    std::cout << D;
    for (int i = filled; i < width; ++i) std::cout << "░";
    std::cout << R << " " << Y << value << R << "\n";
}

void draw_rule() {
    std::cout << D << "  ────────────────────────────────────────────────────────" << R << "\n";
}

} // namespace core
} // namespace whitedns
