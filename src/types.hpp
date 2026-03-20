#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <string>
#include <functional>
#include <cstring>
#include <stdexcept>
#include <openssl/bn.h>

namespace cryptex {

using hash512_t = std::array<uint8_t,64>;

// 256-bit unsigned integer, backed by OpenSSL BIGNUM
class uint256_t {
public:
    // Constructors
    uint256_t();
    uint256_t(uint64_t v);
    uint256_t(const std::array<uint8_t,32>& data);
    uint256_t(const uint256_t& other);
    uint256_t(uint256_t&& other) noexcept;
    ~uint256_t();

    uint256_t& operator=(const uint256_t& other);
    uint256_t& operator=(uint256_t&& other) noexcept;

    // Comparison
    bool operator==(const uint256_t& other) const;
    bool operator!=(const uint256_t& other) const;
    bool operator<(const uint256_t& other) const;
    bool operator<=(const uint256_t& other) const;
    bool operator>(const uint256_t& other) const;
    bool operator>=(const uint256_t& other) const;

    // Arithmetic
    uint256_t operator+(const uint256_t& other) const;
    uint256_t operator-(const uint256_t& other) const;
    uint256_t operator*(const uint256_t& other) const;
    uint256_t operator/(const uint256_t& other) const;
    uint256_t operator%(const uint256_t& other) const;

    uint256_t& operator+=(const uint256_t& other);
    uint256_t& operator-=(const uint256_t& other);
    uint256_t& operator*=(const uint256_t& other);
    uint256_t& operator/=(const uint256_t& other);
    uint256_t& operator%=(const uint256_t& other);

    // Bitwise
    uint256_t operator&(const uint256_t& other) const;
    uint256_t operator|(const uint256_t& other) const;
    uint256_t operator^(const uint256_t& other) const;
    uint256_t operator~() const;
    uint256_t operator<<(int shift) const;
    uint256_t operator>>(int shift) const;

    // Conversion
    std::array<uint8_t,32> to_bytes() const; // big-endian
    std::vector<uint8_t> to_padded_bytes(size_t width) const; // big-endian, left-padded
    static uint256_t from_bytes(const uint8_t* data, size_t len); // big-endian, arbitrary width
    std::string to_hex() const;
    std::string to_hex_padded(size_t width_bytes) const;
    static uint256_t from_hex(const std::string& hex);

    // Access to OpenSSL BIGNUM (for internal use)
    const BIGNUM* bn() const { return bn_; }

private:
    BIGNUM* bn_;

    void check() const; // throw if null
    uint256_t(BIGNUM* bn); // internal constructor, takes ownership
};

// Compact target representation (like Bitcoin)
struct compact_target {
    uint32_t bits;

    uint256_t expand() const;   // convert to uint256_t target
    static compact_target from_target(const uint256_t& target);
};

// Network port
using port_t = uint16_t;

// IPv4 address
struct ip_address {
    uint32_t addr;

    std::string to_string() const {
        return std::to_string((addr >> 24) & 0xFF) + "." +
               std::to_string((addr >> 16) & 0xFF) + "." +
               std::to_string((addr >> 8) & 0xFF) + "." +
               std::to_string(addr & 0xFF);
    }

    static ip_address from_string(const std::string& str) {
        uint32_t a,b,c,d;
        if (sscanf(str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
            throw std::invalid_argument("Invalid IPv4");
        ip_address res;
        res.addr = (a << 24) | (b << 16) | (c << 8) | d;
        return res;
    }

    static ip_address from_uint32(uint32_t ip) { return {ip}; }
};

} // namespace cryptex

namespace std {
    template<> struct hash<cryptex::uint256_t> {
        size_t operator()(const cryptex::uint256_t& k) const {
            auto bytes = k.to_padded_bytes(64);
            return *reinterpret_cast<const size_t*>(bytes.data());
        }
    };
}
