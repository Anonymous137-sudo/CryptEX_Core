#pragma once

#include "constants.hpp"
#include <string>
#include <vector>
#include <array>
#include <stdexcept>
#include <cstdint>

namespace cryptex {
namespace crypto {

// Standard Base64 encoding/decoding (RFC 4648)
std::string base64_encode(const uint8_t* data, size_t len);
inline std::string base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}
inline std::string base64_encode(const std::string& data) {
    return base64_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::vector<uint8_t> base64_decode(const std::string& base64);
bool base64_is_valid(const std::string& base64);
std::string base58_encode(const uint8_t* data, size_t len);
std::vector<uint8_t> base58_decode(const std::string& text);
std::string address_to_bech32(const std::string& address);
bool hex_is_valid(const std::string& hex);
std::vector<uint8_t> hex_decode(const std::string& hex);
std::string hex_encode(const uint8_t* data, size_t len);
std::string canonicalize_address(const std::string& address);
bool addresses_equal(const std::string& lhs, const std::string& rhs);
std::string address_to_base64(const std::string& address);
std::string address_to_base58(const std::string& address);
std::string address_to_hex(const std::string& address);

// Address-specific (20-byte hash -> canonical padded Base64)
inline std::string encode_address(const std::array<uint8_t, 20>& addr_hash) {
    return base64_encode(addr_hash.data(), addr_hash.size());
}

inline std::string encode_address_base58(const std::array<uint8_t, 20>& addr_hash) {
    return address_to_base58(encode_address(addr_hash));
}

inline std::string encode_address_hex(const std::array<uint8_t, 20>& addr_hash) {
    return address_to_hex(encode_address(addr_hash));
}

inline std::array<uint8_t, 20> decode_address(const std::string& addr) {
    auto dec = base64_decode(canonicalize_address(addr));
    std::array<uint8_t, 20> res;
    std::copy(dec.begin(), dec.end(), res.begin());
    return res;
}

} // namespace crypto
} // namespace cryptex
