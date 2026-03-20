#pragma once

#include "types.hpp"
#include <vector>
#include <string>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/err.h>

namespace cryptex {
namespace crypto {

// One-shot SHA3-512
inline hash512_t sha3_512(const uint8_t* data, size_t len) {
    if (!data && len) throw std::invalid_argument("Null data with non-zero length");
    hash512_t result;
    unsigned int out_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    if (1 != EVP_DigestUpdate(ctx, data, len)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }
    if (1 != EVP_DigestFinal_ex(ctx, result.data(), &out_len)) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(ctx);
    if (out_len != 64) throw std::runtime_error("Unexpected hash length");
    return result;
}

inline hash512_t sha3_512(const std::vector<uint8_t>& data) {
    return sha3_512(data.data(), data.size());
}

inline hash512_t sha3_512(const std::string& data) {
    return sha3_512(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// Incremental hasher
class SHA3_512_Hasher {
    EVP_MD_CTX* ctx_;
    bool finalized_;
public:
    SHA3_512_Hasher() : ctx_(EVP_MD_CTX_new()), finalized_(false) {
        if (!ctx_) throw std::runtime_error("EVP_MD_CTX_new failed");
        if (1 != EVP_DigestInit_ex(ctx_, EVP_sha3_512(), nullptr)) {
            EVP_MD_CTX_free(ctx_);
            throw std::runtime_error("EVP_DigestInit_ex failed");
        }
    }
    SHA3_512_Hasher(const SHA3_512_Hasher& other) : ctx_(EVP_MD_CTX_new()), finalized_(other.finalized_) {
        if (!ctx_) throw std::runtime_error("EVP_MD_CTX_new failed");
        if (1 != EVP_MD_CTX_copy_ex(ctx_, other.ctx_)) {
            EVP_MD_CTX_free(ctx_);
            throw std::runtime_error("EVP_MD_CTX_copy_ex failed");
        }
    }
    SHA3_512_Hasher& operator=(const SHA3_512_Hasher& other) {
        if (this == &other) return *this;
        if (!ctx_) {
            ctx_ = EVP_MD_CTX_new();
            if (!ctx_) throw std::runtime_error("EVP_MD_CTX_new failed");
        }
        if (1 != EVP_MD_CTX_copy_ex(ctx_, other.ctx_)) {
            throw std::runtime_error("EVP_MD_CTX_copy_ex failed");
        }
        finalized_ = other.finalized_;
        return *this;
    }
    SHA3_512_Hasher(SHA3_512_Hasher&& other) noexcept : ctx_(other.ctx_), finalized_(other.finalized_) {
        other.ctx_ = nullptr;
        other.finalized_ = false;
    }
    SHA3_512_Hasher& operator=(SHA3_512_Hasher&& other) noexcept {
        if (this == &other) return *this;
        if (ctx_) EVP_MD_CTX_free(ctx_);
        ctx_ = other.ctx_;
        finalized_ = other.finalized_;
        other.ctx_ = nullptr;
        other.finalized_ = false;
        return *this;
    }
    ~SHA3_512_Hasher() { if (ctx_) EVP_MD_CTX_free(ctx_); }

    void update(const uint8_t* data, size_t len) {
        if (finalized_) throw std::runtime_error("Hasher already finalized");
        if (1 != EVP_DigestUpdate(ctx_, data, len))
            throw std::runtime_error("EVP_DigestUpdate failed");
    }
    void update(const std::vector<uint8_t>& data) { update(data.data(), data.size()); }
    void update(const std::string& data) { update(reinterpret_cast<const uint8_t*>(data.data()), data.size()); }

    hash512_t finalize() {
        if (finalized_) throw std::runtime_error("Hasher already finalized");
        hash512_t result;
        unsigned int out_len;
        if (1 != EVP_DigestFinal_ex(ctx_, result.data(), &out_len))
            throw std::runtime_error("EVP_DigestFinal_ex failed");
        finalized_ = true;
        if (out_len != 64) throw std::runtime_error("Unexpected hash length");
        return result;
    }

    void reset() {
        if (ctx_) EVP_MD_CTX_free(ctx_);
        ctx_ = EVP_MD_CTX_new();
        if (!ctx_) throw std::runtime_error("EVP_MD_CTX_new failed");
        if (1 != EVP_DigestInit_ex(ctx_, EVP_sha3_512(), nullptr)) {
            EVP_MD_CTX_free(ctx_);
            throw std::runtime_error("EVP_DigestInit_ex failed");
        }
        finalized_ = false;
    }

    void copy_state_from(const SHA3_512_Hasher& other) {
        if (!ctx_) {
            ctx_ = EVP_MD_CTX_new();
            if (!ctx_) throw std::runtime_error("EVP_MD_CTX_new failed");
        }
        if (1 != EVP_MD_CTX_copy_ex(ctx_, other.ctx_))
            throw std::runtime_error("EVP_MD_CTX_copy_ex failed");
        finalized_ = other.finalized_;
    }
};

} // namespace crypto
} // namespace cryptex
