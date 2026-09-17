#include "whitedns/core/Odoh.h"

#include "whitedns/core/Wire.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#ifdef WHITEDNS_HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#endif

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace whitedns {
namespace core {
namespace {

std::string to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream o;
    o << std::hex << std::nouppercase << std::setfill('0');
    for (auto b : v) o << std::setw(2) << static_cast<int>(b);
    return o.str();
}

uint16_t ru16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

void wu16(std::vector<uint8_t>& o, uint16_t v) {
    o.push_back(static_cast<uint8_t>(v >> 8));
    o.push_back(static_cast<uint8_t>(v & 0xff));
}

void wvec(std::vector<uint8_t>& o, const std::vector<uint8_t>& v) {
    wu16(o, static_cast<uint16_t>(v.size()));
    o.insert(o.end(), v.begin(), v.end());
}

#ifdef WHITEDNS_HAVE_OPENSSL

std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
    unsigned int len = 0;
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &len);
    out.resize(len);
    return out;
}

std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm) {
    std::vector<uint8_t> s = salt;
    if (s.empty()) s.assign(32, 0);
    return hmac_sha256(s, ikm);
}

std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk, const std::vector<uint8_t>& info, size_t l) {
    std::vector<uint8_t> out, t;
    uint8_t counter = 1;
    while (out.size() < l) {
        std::vector<uint8_t> msg = t;
        msg.insert(msg.end(), info.begin(), info.end());
        msg.push_back(counter++);
        t = hmac_sha256(prk, msg);
        out.insert(out.end(), t.begin(), t.end());
    }
    out.resize(l);
    return out;
}

const char* HPKE_V1 = "HPKE-v1";

std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> o;
    for (const auto& p : parts) o.insert(o.end(), p.begin(), p.end());
    return o;
}

std::vector<uint8_t> labeled_extract(const std::vector<uint8_t>& suite,
                                     const std::vector<uint8_t>& salt,
                                     const std::string& label,
                                     const std::vector<uint8_t>& ikm) {
    std::vector<uint8_t> labeled;
    labeled.insert(labeled.end(), HPKE_V1, HPKE_V1 + 7);
    labeled.insert(labeled.end(), suite.begin(), suite.end());
    labeled.insert(labeled.end(), label.begin(), label.end());
    labeled.insert(labeled.end(), ikm.begin(), ikm.end());
    return hkdf_extract(salt, labeled);
}

std::vector<uint8_t> labeled_expand(const std::vector<uint8_t>& suite,
                                    const std::vector<uint8_t>& prk,
                                    const std::string& label,
                                    const std::vector<uint8_t>& info,
                                    size_t l) {
    std::vector<uint8_t> labeled;
    wu16(labeled, static_cast<uint16_t>(l));
    labeled.insert(labeled.end(), HPKE_V1, HPKE_V1 + 7);
    labeled.insert(labeled.end(), suite.begin(), suite.end());
    labeled.insert(labeled.end(), label.begin(), label.end());
    labeled.insert(labeled.end(), info.begin(), info.end());
    return hkdf_expand(prk, labeled, l);
}

bool x25519_generate(std::vector<uint8_t>& sk, std::vector<uint8_t>& pk) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519");
    if (!pkey) return false;
    sk.resize(32);
    pk.resize(32);
    size_t sl = 32, pl = 32;
    int ok = EVP_PKEY_get_raw_private_key(pkey, sk.data(), &sl) == 1 &&
             EVP_PKEY_get_raw_public_key(pkey, pk.data(), &pl) == 1;
    EVP_PKEY_free(pkey);
    return ok;
}

bool x25519_dh(const std::vector<uint8_t>& sk, const std::vector<uint8_t>& pk, std::vector<uint8_t>& out) {
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, sk.data(), sk.size());
    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, pk.data(), pk.size());
    if (!priv || !pub) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return false;
    }
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    out.assign(32, 0);
    size_t len = 32;
    bool ok = ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, pub) == 1 &&
              EVP_PKEY_derive(ctx, out.data(), &len) == 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    out.resize(len);
    return ok;
}

struct HpkeCtx {
    std::vector<uint8_t> key;
    std::vector<uint8_t> base_nonce;
    std::vector<uint8_t> exporter;
    uint64_t seq = 0;
};

std::vector<uint8_t> hpke_suite_id() {
    // "HPKE" || kem 0x0020 || kdf 0x0001 || aead 0x0001
    return {'H', 'P', 'K', 'E', 0x00, 0x20, 0x00, 0x01, 0x00, 0x01};
}

std::vector<uint8_t> kem_suite_id() { return {'K', 'E', 'M', 0x00, 0x20}; }

bool hpke_setup_sender(const std::vector<uint8_t>& pkR, const std::string& info, std::vector<uint8_t>& enc, HpkeCtx& ctx) {
    std::vector<uint8_t> skE, pkE;
    if (!x25519_generate(skE, pkE)) return false;
    std::vector<uint8_t> dh;
    if (!x25519_dh(skE, pkR, dh)) return false;
    enc = pkE;
    auto kem_id = kem_suite_id();
    auto kem_context = concat({enc, pkR});
    auto eae = labeled_extract(kem_id, {}, "eae_prk", dh);
    auto shared = labeled_expand(kem_id, eae, "shared_secret", kem_context, 32);

    auto suite = hpke_suite_id();
    auto psk_id_hash = labeled_extract(suite, {}, "psk_id_hash", {});
    std::vector<uint8_t> info_b(info.begin(), info.end());
    auto info_hash = labeled_extract(suite, {}, "info_hash", info_b);
    std::vector<uint8_t> ks_ctx;
    ks_ctx.push_back(0x00); // mode base
    ks_ctx.insert(ks_ctx.end(), psk_id_hash.begin(), psk_id_hash.end());
    ks_ctx.insert(ks_ctx.end(), info_hash.begin(), info_hash.end());
    auto secret = labeled_extract(suite, shared, "secret", {});
    ctx.key = labeled_expand(suite, secret, "key", ks_ctx, 16);
    ctx.base_nonce = labeled_expand(suite, secret, "base_nonce", ks_ctx, 12);
    ctx.exporter = labeled_expand(suite, secret, "exp", ks_ctx, 32);
    ctx.seq = 0;
    return true;
}

std::vector<uint8_t> xor_nonce(const std::vector<uint8_t>& base, uint64_t seq) {
    auto n = base;
    for (int i = 0; i < 8; ++i) n[n.size() - 1 - i] ^= static_cast<uint8_t>((seq >> (8 * i)) & 0xff);
    return n;
}

bool aead_seal(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
               const std::vector<uint8_t>& aad, const std::vector<uint8_t>& pt, std::vector<uint8_t>& ct) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    int ok = EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
             EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
             EVP_EncryptInit_ex(c, nullptr, nullptr, key.data(), nonce.data()) == 1;
    int outl = 0;
    if (ok && !aad.empty()) ok = EVP_EncryptUpdate(c, nullptr, &outl, aad.data(), static_cast<int>(aad.size())) == 1;
    ct.assign(pt.size() + 16, 0);
    int len = 0;
    if (ok) ok = EVP_EncryptUpdate(c, ct.data(), &len, pt.data(), static_cast<int>(pt.size())) == 1;
    int flen = 0;
    if (ok) ok = EVP_EncryptFinal_ex(c, ct.data() + len, &flen) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, ct.data() + len + flen) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return false;
    ct.resize(static_cast<size_t>(len + flen + 16));
    return true;
}

bool aead_open(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
               const std::vector<uint8_t>& aad, const std::vector<uint8_t>& ct, std::vector<uint8_t>& pt) {
    if (ct.size() < 16) return false;
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    const uint8_t* tag = ct.data() + ct.size() - 16;
    int clen = static_cast<int>(ct.size() - 16);
    int ok = EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
             EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
             EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), nonce.data()) == 1;
    int outl = 0;
    if (ok && !aad.empty()) ok = EVP_DecryptUpdate(c, nullptr, &outl, aad.data(), static_cast<int>(aad.size())) == 1;
    pt.assign(static_cast<size_t>(clen), 0);
    int len = 0;
    if (ok) ok = EVP_DecryptUpdate(c, pt.data(), &len, ct.data(), clen) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) == 1;
    int flen = 0;
    if (ok) ok = EVP_DecryptFinal_ex(c, pt.data() + len, &flen) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return false;
    pt.resize(static_cast<size_t>(len + flen));
    return true;
}

std::vector<uint8_t> hpke_export(const HpkeCtx& ctx, const std::string& label, size_t l) {
    std::vector<uint8_t> exp(label.begin(), label.end());
    return labeled_expand(hpke_suite_id(), ctx.exporter, "sec", exp, l);
}

#ifndef _WIN32
struct HttpResult {
    int status = 0;
    std::string body;
    std::string error;
};

HttpResult https_exchange(const std::string& host, const std::string& path, const std::string& method,
                          const std::string& content_type, const std::vector<uint8_t>& body,
                          bool hide_sni = true) {
    HttpResult out;
    std::string dial = host;
    if (host == "odoh-relay.edgecompute.app") dial = "151.101.1.51";
    else if (host == "odoh-relay.numa.rs") dial = "178.104.229.30";
    else if (host == "odoh.cloudflare-dns.com") dial = "162.159.62.1";
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (getaddrinfo(dial.c_str(), "443", &hints, &res) != 0) {
        out.error = "odoh/resolve";
        return out;
    }
    int sock = -1;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) {
        out.error = "odoh/connect";
        return out;
    }
    SSL_CTX* sctx = SSL_CTX_new(TLS_client_method());
    // Access network must not see the ODoH hostname in SNI. Cert check stays on.
    SSL_CTX_set_default_verify_paths(sctx);
    SSL* ssl = SSL_new(sctx);
    if (!hide_sni) SSL_set_tlsext_host_name(ssl, host.c_str());
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(sctx);
        close(sock);
        if (hide_sni) return https_exchange(host, path, method, content_type, body, false);
        out.error = "odoh/tls";
        return out;
    }
    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\nHost: " << host << "\r\n"
        << "User-Agent: WhiteDNS/2.0 ODoH\r\nConnection: close\r\n";
    if (method == "POST") {
        req << "Content-Type: " << content_type << "\r\nAccept: " << content_type
            << "\r\nContent-Length: " << body.size() << "\r\n\r\n";
    } else {
        req << "\r\n";
    }
    std::string hs = req.str();
    SSL_write(ssl, hs.data(), static_cast<int>(hs.size()));
    if (method == "POST" && !body.empty()) SSL_write(ssl, body.data(), static_cast<int>(body.size()));
    std::string buf;
    char chunk[2048];
    for (int i = 0; i < 64; ++i) {
        int n = SSL_read(ssl, chunk, sizeof(chunk));
        if (n <= 0) break;
        buf.append(chunk, static_cast<size_t>(n));
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    close(sock);
    auto line_end = buf.find("\r\n");
    if (line_end != std::string::npos) {
        auto sp = buf.find(' ');
        if (sp != std::string::npos) out.status = std::atoi(buf.c_str() + sp + 1);
    }
    auto pos = buf.find("\r\n\r\n");
    if (pos != std::string::npos) out.body = buf.substr(pos + 4);
    else out.error = "odoh/http";
    return out;
}
#else
struct HttpResult {
    int status = 0;
    std::string body;
    std::string error = "odoh/windows-https-not-wired";
};
HttpResult https_exchange(const std::string&, const std::string&, const std::string&, const std::string&,
                          const std::vector<uint8_t>&) {
    return {};
}
#endif

#endif // OPENSSL

} // namespace

std::vector<OdohConfig> parse_odoh_configs(const std::vector<uint8_t>& wire) {
    std::vector<OdohConfig> out;
    if (wire.size() < 2) return out;
    size_t n = ru16(wire.data());
    if (n + 2 > wire.size()) n = wire.size() - 2;
    size_t i = 2;
    size_t end = 2 + n;
    while (i + 4 <= end && i + 4 <= wire.size()) {
        OdohConfig c;
        c.version = ru16(wire.data() + i);
        uint16_t len = ru16(wire.data() + i + 2);
        i += 4;
        if (i + len > wire.size()) break;
        if (c.version == 1 && len >= 8) {
            const uint8_t* p = wire.data() + i;
            c.kem_id = ru16(p);
            c.kdf_id = ru16(p + 2);
            c.aead_id = ru16(p + 4);
            uint16_t pklen = ru16(p + 6);
            if (8u + pklen <= len) {
                c.public_key.assign(p + 8, p + 8 + pklen);
                c.contents_wire.assign(p, p + len);
#ifdef WHITEDNS_HAVE_OPENSSL
                auto prk = hkdf_extract({}, c.contents_wire);
                std::vector<uint8_t> info{'o', 'd', 'o', 'h', ' ', 'k', 'e', 'y', ' ', 'i', 'd'};
                c.key_id = hkdf_expand(prk, info, 32);
#endif
                out.push_back(c);
            }
        }
        i += len;
    }
    return out;
}

bool fetch_odoh_configs(const std::string& host, std::vector<OdohConfig>& out, std::string& error) {
#ifndef WHITEDNS_HAVE_OPENSSL
    error = "odoh/no-openssl";
    return false;
#else
    auto http = https_exchange(host, "/.well-known/odohconfigs", "GET", "", {});
    if (http.body.empty()) {
        error = http.error.empty() ? "odoh/config-empty" : http.error;
        return false;
    }
    std::vector<uint8_t> wire(http.body.begin(), http.body.end());
    out = parse_odoh_configs(wire);
    if (out.empty()) {
        error = "odoh/config-parse";
        return false;
    }
    return true;
#endif
}

bool odoh_encrypt_query(const OdohConfig& cfg,
                        const std::vector<uint8_t>& dns_query,
                        std::vector<uint8_t>& message_out,
                        std::vector<uint8_t>& enc_out,
                        std::vector<uint8_t>& exporter_secret_out,
                        std::vector<uint8_t>& q_plain_out,
                        std::string& error) {
#ifndef WHITEDNS_HAVE_OPENSSL
    error = "odoh/no-openssl";
    return false;
#else
    if (cfg.kem_id != 0x0020 || cfg.kdf_id != 0x0001 || cfg.aead_id != 0x0001 || cfg.public_key.size() != 32) {
        error = "odoh/unsupported-suite";
        return false;
    }
    q_plain_out.clear();
    wvec(q_plain_out, dns_query);
    // RFC 8467-style block padding so ciphertext length does not track QNAME.
    size_t raw = q_plain_out.size() + 2;
    size_t block = 128;
    size_t padn = (block - (raw % block)) % block;
    std::vector<uint8_t> pad(padn, 0);
    wvec(q_plain_out, pad);
    HpkeCtx ctx;
    if (!hpke_setup_sender(cfg.public_key, "odoh query", enc_out, ctx)) {
        error = "odoh/hpke-setup";
        return false;
    }
    std::vector<uint8_t> aad;
    aad.push_back(0x01);
    wvec(aad, cfg.key_id);
    auto nonce = xor_nonce(ctx.base_nonce, ctx.seq);
    std::vector<uint8_t> ct;
    if (!aead_seal(ctx.key, nonce, aad, q_plain_out, ct)) {
        error = "odoh/seal";
        return false;
    }
    std::vector<uint8_t> encrypted = enc_out;
    encrypted.insert(encrypted.end(), ct.begin(), ct.end());
    message_out.clear();
    message_out.push_back(0x01);
    wvec(message_out, cfg.key_id);
    wvec(message_out, encrypted);
    exporter_secret_out = ctx.exporter;
    return true;
#endif
}

OdohResult odoh_lookup(const std::string& qname,
                       uint16_t qtype,
                       const std::string& target_host,
                       const std::string& proxy_url_template) {
    OdohResult r;
    r.target = target_host.empty() ? "odoh.cloudflare-dns.com" : target_host;
    r.proxy = proxy_url_template;
#ifndef WHITEDNS_HAVE_OPENSSL
    r.error = "odoh/no-openssl";
    return r;
#else
    std::vector<OdohConfig> cfgs;
    std::string err;
    if (!fetch_odoh_configs(r.target, cfgs, err)) {
        r.error = err;
        return r;
    }
    const OdohConfig& cfg = cfgs.front();
    r.key_id_hex = to_hex(cfg.key_id);
    r.kem_id = cfg.kem_id;
    r.kdf_id = cfg.kdf_id;
    r.aead_id = cfg.aead_id;
    r.qname_len = qname.size();

    auto dns_q = build_query_message(qname, qtype, 0x1111, true, false);
    std::vector<uint8_t> msg, enc, exporter, qplain;
    if (!odoh_encrypt_query(cfg, dns_q, msg, enc, exporter, qplain, err)) {
        r.error = err;
        return r;
    }
    r.ciphertext_bytes = msg.size();

    std::vector<std::string> relays;
    if (proxy_url_template == "direct") {
        relays.emplace_back("");
    } else if (!proxy_url_template.empty()) {
        relays.push_back(proxy_url_template);
    } else {
        const char* env = std::getenv("WHITEDNS_ODOH_PROXY");
        if (env && *env) relays.push_back(env);
        for (int i = 0; kOdohProductionRelays[i]; ++i) relays.push_back(kOdohProductionRelays[i]);
        relays.emplace_back("");
    }

    HttpResult http;
    bool have_body = false;
    for (const auto& tmpl : relays) {
        std::string host = r.target;
        std::string path = "/dns-query";
        bool via_proxy = false;
        if (!tmpl.empty()) {
            std::string url = tmpl;
            auto replace = [&](const std::string& token, const std::string& value) {
                auto p = url.find(token);
                if (p != std::string::npos) url.replace(p, token.size(), value);
            };
            replace("{?targethost,targetpath}",
                    "?targethost=" + r.target + "&targetpath=%2Fdns-query");
            replace("{targethost}", r.target);
            replace("{targetpath}", "dns-query");
            auto scheme = url.find("://");
            auto slash = url.find('/', scheme == std::string::npos ? 0 : scheme + 3);
            if (scheme != std::string::npos) {
                host = url.substr(scheme + 3, slash == std::string::npos ? std::string::npos : slash - scheme - 3);
                path = slash == std::string::npos ? "/" : url.substr(slash);
                via_proxy = true;
                r.proxy = url;
            }
        } else {
            r.proxy.clear();
        }
        http = https_exchange(host, path, "POST", "application/oblivious-dns-message", msg);
        if (http.status == 200 && http.body.size() >= 5) {
            r.oblivious = via_proxy;
            have_body = true;
            break;
        }
        r.error = "odoh/http-" + std::to_string(http.status) + "@" + host;
    }
    if (!have_body) {
        r.ok = false;
        return r;
    }

    const auto& body = http.body;
    auto* p = reinterpret_cast<const uint8_t*>(body.data());
    size_t n = body.size();
    if (n < 5 || p[0] != 0x02) {
        r.error = "odoh/bad-response-type";
        return r;
    }
    uint16_t kid_len = ru16(p + 1);
    if (3u + kid_len + 2 > n) {
        r.error = "odoh/short";
        return r;
    }
    uint16_t enc_len = ru16(p + 3 + kid_len);
    const uint8_t* encp = p + 5 + kid_len;
    if (static_cast<size_t>(encp - p) + enc_len > n) {
        r.error = "odoh/short-ct";
        return r;
    }
    // Response layout used by Cloudflare: key_id carries resp_nonce (16 bytes),
    // encrypted_message is AEAD ciphertext||tag only.
    std::vector<uint8_t> resp_nonce;
    std::vector<uint8_t> rct;
    if (kid_len == 16) {
        resp_nonce.assign(p + 3, p + 3 + kid_len);
        rct.assign(encp, encp + enc_len);
    } else if (enc_len >= 32) {
        resp_nonce.assign(encp, encp + 16);
        rct.assign(encp + 16, encp + enc_len);
    } else {
        r.error = "odoh/short-nonce";
        return r;
    }

    // Reconstruct HPKE context export: we kept exporter from sender context.
    // derive_secrets(context, Q_plain, resp_nonce)
    auto secret = labeled_expand(hpke_suite_id(), exporter, "sec",
                                 std::vector<uint8_t>{'o', 'd', 'o', 'h', ' ', 'r', 'e', 's', 'p', 'o', 'n', 's', 'e'}, 16);
    std::vector<uint8_t> salt = qplain;
    wu16(salt, static_cast<uint16_t>(resp_nonce.size()));
    salt.insert(salt.end(), resp_nonce.begin(), resp_nonce.end());
    auto prk = hkdf_extract(salt, secret);
    auto key = hkdf_expand(prk, std::vector<uint8_t>{'o', 'd', 'o', 'h', ' ', 'k', 'e', 'y'}, 16);
    auto nonce = hkdf_expand(prk, std::vector<uint8_t>{'o', 'd', 'o', 'h', ' ', 'n', 'o', 'n', 'c', 'e'}, 12);
    std::vector<uint8_t> aad;
    aad.push_back(0x02);
    wvec(aad, resp_nonce);
    std::vector<uint8_t> rplain;
    if (!aead_open(key, nonce, aad, rct, rplain) || rplain.size() < 2) {
        r.error = "odoh/open kid=" + std::to_string(kid_len) + " enclen=" + std::to_string(enc_len) +
                  " blen=" + std::to_string(n) + " head=" +
                  to_hex(std::vector<uint8_t>(body.begin(), body.begin() + std::min<size_t>(n, 20)));
        return r;
    }
    uint16_t dns_len = ru16(rplain.data());
    if (2u + dns_len > rplain.size()) {
        r.error = "odoh/plain";
        return r;
    }
    std::vector<uint8_t> dns(rplain.begin() + 2, rplain.begin() + 2 + dns_len);
    auto parsed = parse_message(dns);
    r.answers = parsed.answers;
    r.rcode = parsed.flags.rcode;
    r.ok = parsed.parse_error.empty();
    if (!r.ok) r.error = parsed.parse_error;
    return r;
#endif
}

} // namespace core
} // namespace whitedns
