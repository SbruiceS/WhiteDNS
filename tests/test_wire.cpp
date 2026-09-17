#include "whitedns/core/Wire.h"

#include <cstdlib>
#include <iostream>

using namespace whitedns::core;

static int fails = 0;

void expect(bool cond, const char* what) {
    if (!cond) {
        std::cerr << "FAIL " << what << "\n";
        ++fails;
    }
}

int main() {
    auto name = encode_qname("www.example.com");
    size_t off = 0;
    std::string back = decode_qname(name, off);
    expect(back == "www.example.com", "roundtrip name");

    try {
        encode_qname(std::string(64, 'a') + ".com");
        expect(false, "oversize label should throw");
    } catch (...) {
        expect(true, "oversize label throws");
    }

    auto pkt = build_query_message("example.com", 1, 0x1111, true, false);
    expect(pkt.size() > 12, "query size");
    expect(pkt[0] == 0x11 && pkt[1] == 0x11, "query id");

    // pointer-loop packet: compression pointer to itself at offset 12
    std::vector<uint8_t> loop(14, 0);
    loop[12] = 0xc0;
    loop[13] = 12;
    size_t p = 12;
    try {
        decode_qname(loop, p);
        expect(false, "pointer loop should throw");
    } catch (const std::exception& ex) {
        expect(std::string(ex.what()).find("pointer") != std::string::npos, "pointer loop error");
    }

    Message empty = parse_message({});
    expect(!empty.parse_error.empty(), "short packet error");

    if (fails) {
        std::cerr << fails << " failures\n";
        return 1;
    }
    std::cout << "test_wire ok\n";
    return 0;
}
