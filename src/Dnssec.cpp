#include "whitedns/Dnssec.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <vector>

#ifdef WHITEDNS_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace whitedns {
namespace {

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream out;
    out << std::hex << std::nouppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) out << std::setw(2) << static_cast<int>(data[i]);
    return out.str();
}

std::vector<uint8_t> canonical_owner(std::string domain) {
    std::transform(domain.begin(), domain.end(), domain.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    while (!domain.empty() && domain.back() == '.') domain.pop_back();

    std::vector<uint8_t> wire;
    size_t start = 0;
    while (start < domain.size()) {
        size_t end = domain.find('.', start);
        if (end == std::string::npos) end = domain.size();
        size_t len = end - start;
        if (len == 0 || len > 63) break;
        wire.push_back(static_cast<uint8_t>(len));
        wire.insert(wire.end(), domain.begin() + static_cast<std::ptrdiff_t>(start),
                    domain.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    wire.push_back(0);
    return wire;
}

uint16_t key_tag(const std::vector<uint8_t>& rdata) {
    unsigned long ac = 0;
    for (size_t i = 0; i < rdata.size(); ++i) {
        ac += (i & 1) ? rdata[i] : static_cast<unsigned long>(rdata[i]) << 8;
    }
    ac += (ac >> 16) & 0xFFFF;
    return static_cast<uint16_t>(ac & 0xFFFF);
}

#ifdef WHITEDNS_HAVE_OPENSSL
std::vector<uint8_t> digest_bytes(const std::vector<uint8_t>& data, int digest_type) {
    const EVP_MD* md = nullptr;
    if (digest_type == 1) md = EVP_sha1();
    else if (digest_type == 2) md = EVP_sha256();
    else if (digest_type == 4) md = EVP_sha384();
    if (!md) return {};

    std::vector<uint8_t> out(static_cast<size_t>(EVP_MD_size(md)));
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, md, nullptr) != 1) return {};
    out.resize(len);
    return out;
}
#else
std::vector<uint8_t> digest_bytes(const std::vector<uint8_t>&, int) {
    return {};
}
#endif

struct DsParts {
    uint16_t key_tag = 0;
    uint8_t algorithm = 0;
    uint8_t digest_type = 0;
    std::vector<uint8_t> digest;
};

DsParts parse_ds(const DnsRecord& rec) {
    DsParts ds;
    if (rec.rdata.size() < 4) return ds;
    ds.key_tag = static_cast<uint16_t>((rec.rdata[0] << 8) | rec.rdata[1]);
    ds.algorithm = rec.rdata[2];
    ds.digest_type = rec.rdata[3];
    ds.digest.assign(rec.rdata.begin() + 4, rec.rdata.end());
    return ds;
}

} // namespace

DnssecChainResult validate_ds_dnskey_chain(const std::string& domain,
                                           const std::vector<DnsRecord>& ds_records,
                                           const std::vector<DnsRecord>& dnskey_records,
                                           const std::vector<DnsRecord>& rrsig_records) {
    DnssecChainResult result;
    result.attempted = true;
    result.evidence = Json::Value(Json::objectValue);
    result.ds_records = static_cast<int>(ds_records.size());
    result.dnskey_records = static_cast<int>(dnskey_records.size());
    result.ds_present = !ds_records.empty();
    result.dnskey_present = !dnskey_records.empty();
    result.rrsig_present = !rrsig_records.empty();

#ifndef WHITEDNS_HAVE_OPENSSL
    result.message = "OpenSSL is not linked; DS/DNSKEY digest comparison cannot run.";
    result.evidence["backend"] = "none";
    return result;
#else
    result.evidence["backend"] = "openssl";
    result.evidence["rfc"] = "RFC4034 §5.1.4 DS digest over owner|DNSKEY RDATA";

    if (ds_records.empty() || dnskey_records.empty()) {
        result.message = "Cannot validate the parent chain: DS or DNSKEY RDATA is missing.";
        return result;
    }

    auto owner = canonical_owner(domain);
    Json::Value matches(Json::arrayValue);

    for (const auto& ds_rec : ds_records) {
        DsParts ds = parse_ds(ds_rec);
        if (ds.digest.empty()) continue;
        for (const auto& key : dnskey_records) {
            if (key.rdata.size() < 4) continue;
            uint8_t algorithm = key.rdata[3];
            if (algorithm != ds.algorithm) continue;
            if (key_tag(key.rdata) != ds.key_tag) continue;

            std::vector<uint8_t> material = owner;
            material.insert(material.end(), key.rdata.begin(), key.rdata.end());
            auto digest = digest_bytes(material, ds.digest_type);
            if (digest.empty()) continue;

            bool ok = digest == ds.digest;
            Json::Value row(Json::objectValue);
            row["key_tag"] = ds.key_tag;
            row["algorithm"] = ds.algorithm;
            row["digest_type"] = ds.digest_type;
            row["computed"] = to_hex(digest.data(), digest.size());
            row["ds_digest"] = to_hex(ds.digest.data(), ds.digest.size());
            row["match"] = ok;
            matches.append(row);
            if (ok) result.matched_keys += 1;
        }
    }

    result.evidence["comparisons"] = matches;
    result.ds_matches_key = result.matched_keys > 0;
    if (result.ds_matches_key) {
        result.message = "Cryptographic DS→DNSKEY match succeeded (" +
                         std::to_string(result.matched_keys) +
                         " key(s)). Parent chain is valid. Full RRSIG RRSet validation of every record type is not claimed.";
    } else {
        result.message = "DS records did not hash-match any DNSKEY (RFC 4034). The parent chain is broken or the resolver returned incomplete RDATA.";
    }
    result.evidence["rrsig_present"] = result.rrsig_present;
    return result;
#endif
}

} // namespace whitedns
