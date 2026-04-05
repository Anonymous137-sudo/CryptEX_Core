#include "types.hpp"
#include <openssl/bn.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace cryptex {

// Helper to throw on BIGNUM error
static void check_bn(const BIGNUM* bn) {
    if (!bn) throw std::runtime_error("BIGNUM operation failed");
}

uint256_t::uint256_t() : bn_(BN_new()) {
    check_bn(bn_);
    BN_zero(bn_);
}

uint256_t::uint256_t(uint64_t v) : bn_(BN_new()) {
    check_bn(bn_);
    BN_set_word(bn_, v);
}

uint256_t::uint256_t(const std::array<uint8_t,32>& data) : bn_(BN_new()) {
    check_bn(bn_);
    BN_bin2bn(data.data(), data.size(), bn_);
}

uint256_t::uint256_t(const uint256_t& other) : bn_(BN_dup(other.bn_)) {
    check_bn(bn_);
}

uint256_t::uint256_t(uint256_t&& other) noexcept : bn_(other.bn_) {
    other.bn_ = nullptr;
}

uint256_t::~uint256_t() {
    if (bn_) BN_free(bn_);
}

uint256_t& uint256_t::operator=(const uint256_t& other) {
    if (this != &other) {
        BIGNUM* new_bn = BN_dup(other.bn_);
        check_bn(new_bn);
        BN_free(bn_);
        bn_ = new_bn;
    }
    return *this;
}

uint256_t& uint256_t::operator=(uint256_t&& other) noexcept {
    if (this != &other) {
        BN_free(bn_);
        bn_ = other.bn_;
        other.bn_ = nullptr;
    }
    return *this;
}

// Comparison
bool uint256_t::operator==(const uint256_t& other) const {
    return BN_cmp(bn_, other.bn_) == 0;
}

bool uint256_t::operator!=(const uint256_t& other) const {
    return !(*this == other);
}

bool uint256_t::operator<(const uint256_t& other) const {
    return BN_cmp(bn_, other.bn_) < 0;
}

bool uint256_t::operator<=(const uint256_t& other) const {
    return BN_cmp(bn_, other.bn_) <= 0;
}

bool uint256_t::operator>(const uint256_t& other) const {
    return BN_cmp(bn_, other.bn_) > 0;
}

bool uint256_t::operator>=(const uint256_t& other) const {
    return BN_cmp(bn_, other.bn_) >= 0;
}

// Arithmetic
uint256_t uint256_t::operator+(const uint256_t& other) const {
    BIGNUM* res = BN_new();
    check_bn(res);
    if (!BN_add(res, bn_, other.bn_)) {
        BN_free(res);
        throw std::runtime_error("BN_add failed");
    }
    return uint256_t(res);
}

uint256_t uint256_t::operator-(const uint256_t& other) const {
    BIGNUM* res = BN_new();
    check_bn(res);
    if (!BN_sub(res, bn_, other.bn_)) {
        BN_free(res);
        throw std::runtime_error("BN_sub failed");
    }
    return uint256_t(res);
}

uint256_t uint256_t::operator*(const uint256_t& other) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    BIGNUM* res = BN_new();
    check_bn(res);
    if (!BN_mul(res, bn_, other.bn_, ctx)) {
        BN_free(res);
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_mul failed");
    }
    BN_CTX_free(ctx);
    return uint256_t(res);
}

uint256_t uint256_t::operator/(const uint256_t& other) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    BIGNUM* res = BN_new();
    check_bn(res);
    if (!BN_div(res, nullptr, bn_, other.bn_, ctx)) {
        BN_free(res);
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_div failed");
    }
    BN_CTX_free(ctx);
    return uint256_t(res);
}

uint256_t uint256_t::operator%(const uint256_t& other) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    BIGNUM* res = BN_new();
    check_bn(res);
    if (!BN_mod(res, bn_, other.bn_, ctx)) {
        BN_free(res);
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_mod failed");
    }
    BN_CTX_free(ctx);
    return uint256_t(res);
}

// In-place arithmetic
uint256_t& uint256_t::operator+=(const uint256_t& other) {
    if (!BN_add(bn_, bn_, other.bn_))
        throw std::runtime_error("BN_add failed");
    return *this;
}

uint256_t& uint256_t::operator-=(const uint256_t& other) {
    if (!BN_sub(bn_, bn_, other.bn_))
        throw std::runtime_error("BN_sub failed");
    return *this;
}

uint256_t& uint256_t::operator*=(const uint256_t& other) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    BIGNUM* tmp = BN_dup(bn_);
    check_bn(tmp);
    if (!BN_mul(bn_, tmp, other.bn_, ctx)) {
        BN_free(tmp);
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_mul failed");
    }
    BN_free(tmp);
    BN_CTX_free(ctx);
    return *this;
}

uint256_t& uint256_t::operator/=(const uint256_t& other) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    BIGNUM* tmp = BN_dup(bn_);
    check_bn(tmp);
    if (!BN_div(bn_, nullptr, tmp, other.bn_, ctx)) {
        BN_free(tmp);
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_div failed");
    }
    BN_free(tmp);
    BN_CTX_free(ctx);
    return *this;
}

uint256_t& uint256_t::operator%=(const uint256_t& other) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");
    BIGNUM* tmp = BN_dup(bn_);
    check_bn(tmp);
    if (!BN_mod(bn_, tmp, other.bn_, ctx)) {
        BN_free(tmp);
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_mod failed");
    }
    BN_free(tmp);
    BN_CTX_free(ctx);
    return *this;
}

// Bitwise (simplified – using BN for some, but not all; we'll implement full set)
uint256_t uint256_t::operator&(const uint256_t& other) const {
    // BIGNUM doesn't have direct bitwise AND; we can convert to bytes and back
    auto a = to_bytes();
    auto b = other.to_bytes();
    std::array<uint8_t,32> res;
    for (size_t i = 0; i < 32; ++i) res[i] = a[i] & b[i];
    return uint256_t(res);
}

uint256_t uint256_t::operator|(const uint256_t& other) const {
    auto a = to_bytes();
    auto b = other.to_bytes();
    std::array<uint8_t,32> res;
    for (size_t i = 0; i < 32; ++i) res[i] = a[i] | b[i];
    return uint256_t(res);
}

uint256_t uint256_t::operator^(const uint256_t& other) const {
    auto a = to_bytes();
    auto b = other.to_bytes();
    std::array<uint8_t,32> res;
    for (size_t i = 0; i < 32; ++i) res[i] = a[i] ^ b[i];
    return uint256_t(res);
}

uint256_t uint256_t::operator~() const {
    auto a = to_bytes();
    std::array<uint8_t,32> res;
    for (size_t i = 0; i < 32; ++i) res[i] = ~a[i];
    return uint256_t(res);
}

uint256_t uint256_t::operator<<(int shift) const {
    BIGNUM* res = BN_new();
    check_bn(res);
    if (!BN_lshift(res, bn_, shift)) {
        BN_free(res);
        throw std::runtime_error("BN_lshift failed");
    }
    return uint256_t(res);
}

uint256_t uint256_t::operator>>(int shift) const {
    BIGNUM* res = BN_new();
    check_bn(res);
    if (!BN_rshift(res, bn_, shift)) {
        BN_free(res);
        throw std::runtime_error("BN_rshift failed");
    }
    return uint256_t(res);
}

// Conversion
std::array<uint8_t,32> uint256_t::to_bytes() const {
    auto padded = to_padded_bytes(32);
    std::array<uint8_t,32> out{};
    std::memcpy(out.data(), padded.data(), out.size());
    return out;
}

std::vector<uint8_t> uint256_t::to_padded_bytes(size_t width) const {
    int len = BN_num_bytes(bn_);
    if (len < 0) throw std::runtime_error("BN_num_bytes failed");
    if (static_cast<size_t>(len) > width) {
        throw std::runtime_error("BIGNUM too large for requested width");
    }
    std::vector<uint8_t> out(width, 0);
    if (len > 0) {
        BN_bn2bin(bn_, out.data() + (width - static_cast<size_t>(len)));
    }
    return out;
}

uint256_t uint256_t::from_bytes(const uint8_t* data, size_t len) {
    BIGNUM* bn = BN_bin2bn(data, len, nullptr);
    check_bn(bn);
    return uint256_t(bn);
}

std::string uint256_t::to_hex() const {
    return to_hex_padded(32);
}

std::string uint256_t::to_hex_padded(size_t width_bytes) const {
    char* hex = BN_bn2hex(bn_);
    if (!hex) throw std::runtime_error("BN_bn2hex failed");
    std::string s(hex);
    OPENSSL_free(hex);
    size_t width = width_bytes * 2;
    if (s.length() > width) {
        throw std::runtime_error("BIGNUM too large for requested hex width");
    }
    if (s.length() < width) s = std::string(width - s.length(), '0') + s;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

uint256_t uint256_t::from_hex(const std::string& hex) {
    BIGNUM* bn = nullptr;
    if (BN_hex2bn(&bn, hex.c_str()) == 0 || !bn) {
        if (bn) BN_free(bn);
        throw std::invalid_argument("invalid hex string");
    }
    return uint256_t(bn);
}

// Internal constructor
uint256_t::uint256_t(BIGNUM* bn) : bn_(bn) {
    if (!bn_) throw std::runtime_error("null BIGNUM");
}

void uint256_t::check() const {
    if (!bn_) throw std::runtime_error("using moved-from uint256_t");
}

// Compact target implementation
uint256_t compact_target::expand() const {
    uint32_t exponent = bits >> 24;
    uint32_t mantissa = bits & 0x007fffff;

    if (exponent <= 3) {
        // Compact form with exponent <= 3 means the target is just (mantissa >> (8*(3-exponent)))
        uint64_t val = mantissa;
        val >>= 8 * (3 - exponent);
        return uint256_t(val);
    }

    // Normal case: target = mantissa * 256^(exponent-3)
    uint256_t target = uint256_t(mantissa);
    target = target << (8 * (exponent - 3));
    return target;
}

compact_target compact_target::from_target(const uint256_t& target) {
    // Find the highest set byte
    auto bytes = target.to_padded_bytes(64);
    int idx = 0;
    while (idx < 64 && bytes[idx] == 0) ++idx;
    if (idx == 64) return {0}; // zero target (invalid for PoW)

    int exp = 64 - idx; // number of bytes from the first non-zero to the end
    // The mantissa should be the first 3 bytes of the compact representation
    // We take the next 3 bytes (or fewer if exp < 3)
    uint32_t mantissa = 0;
    if (exp >= 3) {
        mantissa = (bytes[idx] << 16) | (bytes[idx+1] << 8) | bytes[idx+2];
        exp -= 3;
    } else {
        // When exponent < 3, the mantissa is taken from the first exp bytes, shifted left
        for (int i = 0; i < exp; ++i) {
            mantissa |= bytes[idx + i] << (8 * (2 - i)); // place in the top bytes
        }
        exp = 0;
    }
    // The exponent is the number of bytes after the mantissa, plus 3
    uint32_t exponent = exp + 3;
    uint32_t bits = (exponent << 24) | (mantissa & 0x007fffff);
    return {bits};
}

} // namespace cryptex
