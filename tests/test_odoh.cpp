#include "whitedns/core/Odoh.h"
#include "whitedns/core/Wire.h"

#include <iostream>

using namespace whitedns::core;

static int fails = 0;
void expect(bool c, const char* w) {
    if (!c) {
        std::cerr << "FAIL " << w << "\n";
        ++fails;
    }
}

int main() {
    // Live Cloudflare config captured 2026-09-17 (structure only; key rotates).
    const uint8_t sample[] = {
        0x00, 0x2c, 0x00, 0x01, 0x00, 0x28, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10};
    auto cfgs = parse_odoh_configs(std::vector<uint8_t>(sample, sample + sizeof(sample)));
    expect(!cfgs.empty(), "parse at least one config");
    if (!cfgs.empty()) {
        expect(cfgs[0].version == 1, "version 1");
        expect(cfgs[0].kem_id == 0x0020, "X25519 KEM");
        expect(cfgs[0].kdf_id == 0x0001, "HKDF-SHA256");
        expect(cfgs[0].aead_id == 0x0001, "AES-128-GCM");
        expect(cfgs[0].public_key.size() == 32, "32-byte public key");
        expect(cfgs[0].key_id.size() == 32, "key_id Nh=32");
    }

    auto q = build_query_message("nasa.gov", 1, 1, true, false);
    std::vector<uint8_t> msg, enc, exp, plain;
    std::string err;
    bool ok = !cfgs.empty() && odoh_encrypt_query(cfgs[0], q, msg, enc, exp, plain, err);
    expect(ok, err.empty() ? "encrypt" : err.c_str());
    if (ok) {
        expect(!msg.empty() && msg[0] == 0x01, "query message type");
        expect(enc.size() == 32, "HPKE enc is X25519 public");
        expect(plain.size() >= q.size() + 4, "plaintext wraps dns+padding vectors");
    }

    if (fails) {
        std::cerr << fails << " failures\n";
        return 1;
    }
    std::cout << "test_odoh ok\n";
    return 0;
}
