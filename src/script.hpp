#pragma once

#include "types.hpp"
#include "sha3_512.hpp"
#include "base64.hpp"
#include <vector>
#include <string>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bn.h>

namespace cryptex {
namespace script {

// -------------------------------------------------------------------
// Key pair generation, signing, verification
// -------------------------------------------------------------------

// Generate a new secp256k1 key pair using EVP (OpenSSL 3)
inline void generate_keypair(std::vector<uint8_t>& privkey, std::vector<uint8_t>& pubkey) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) throw std::runtime_error("PKEY_CTX EC create failed");
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_group_name(pctx, "secp256k1") <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("keygen init failed");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("keygen failed");
    }
    EVP_PKEY_CTX_free(pctx);

    // Export PKCS#8 DER private key to persist portable key material
    int pkcs8_len = i2d_PrivateKey(pkey, nullptr);
    if (pkcs8_len <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("i2d_PrivateKey failed");
    }
    privkey.resize(pkcs8_len);
    unsigned char* der_ptr = privkey.data();
    if (i2d_PrivateKey(pkey, &der_ptr) != pkcs8_len) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("i2d_PrivateKey length mismatch");
    }

    size_t pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("get pub size failed");
    }
    pubkey.resize(pub_len);
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey.size(), &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("get pub data failed");
    }
    EVP_PKEY_free(pkey);
}

// Sign a 32‑byte hash with the private key using EVP_PKEY sign (prehashed)
// FIX: use null digest to avoid double‑hashing
inline std::vector<uint8_t> sign_hash(const uint256_t& hash, const std::vector<uint8_t>& privkey) {
    auto hbytes = hash.to_bytes();
    const unsigned char* der_ptr = privkey.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &der_ptr, privkey.size());
    if (!pkey) {
        throw std::runtime_error("decode privkey failed");
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); throw std::runtime_error("md ctx failed"); }
    // FIX: use nullptr for digest to sign raw data (already hashed)
    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_PKEY_free(pkey); EVP_MD_CTX_free(mdctx); throw std::runtime_error("sign init failed");
    }
    size_t siglen = 0;
    if (EVP_DigestSign(mdctx, nullptr, &siglen, hbytes.data(), hbytes.size()) <= 0) {
        EVP_PKEY_free(pkey); EVP_MD_CTX_free(mdctx); throw std::runtime_error("sign size failed");
    }
    std::vector<uint8_t> signature(siglen);
    if (EVP_DigestSign(mdctx, signature.data(), &siglen, hbytes.data(), hbytes.size()) <= 0) {
        EVP_PKEY_free(pkey); EVP_MD_CTX_free(mdctx); throw std::runtime_error("sign failed");
    }
    signature.resize(siglen);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    return signature;
}

// Verify a signature against a public key and hash using EVP_PKEY verify
// FIX: use null digest to avoid double‑hashing
inline bool verify_signature(const uint256_t& hash, const std::vector<uint8_t>& signature,
                             const std::vector<uint8_t>& pubkey) {
    auto hbytes = hash.to_bytes();
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!kctx) throw std::runtime_error("PKEY_CTX create failed");
    if (EVP_PKEY_fromdata_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return false;
    }
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>("secp256k1"), 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, const_cast<uint8_t*>(pubkey.data()), pubkey.size());
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return false;
    }
    EVP_PKEY_CTX_free(kctx);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); return false; }
    // FIX: use nullptr for digest to verify raw data
    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey) <= 0) {
        EVP_PKEY_free(pkey); EVP_MD_CTX_free(mdctx); return false;
    }
    int ret = EVP_DigestVerify(mdctx, signature.data(), signature.size(), hbytes.data(), hbytes.size());
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    return ret == 1;
}

// Derive address from public key: Base64( RIPEMD160( SHA256( pubkey ) ) )
inline std::string pubkey_to_address(const std::vector<uint8_t>& pubkey) {
    // SHA256 of pubkey
    std::vector<uint8_t> sha256_out(32);
    SHA256(pubkey.data(), pubkey.size(), sha256_out.data());

    // RIPEMD160 of SHA256 via EVP to avoid deprecated direct call
    std::array<uint8_t, 20> ripe;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    const EVP_MD* md = EVP_ripemd160();
    if (!md || EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, sha256_out.data(), sha256_out.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, ripe.data(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("RIPEMD160 digest failed");
    }
    EVP_MD_CTX_free(mdctx);

    // Base64 encode
    return crypto::base64_encode(ripe.data(), ripe.size());
}

// Verify that a signature + pubkey match a given address (i.e., pubkey hashes to address)
inline bool check_address(const std::string& address, const std::vector<uint8_t>& pubkey) {
    return crypto::addresses_equal(pubkey_to_address(pubkey), address);
}

} // namespace script
} // namespace cryptex
