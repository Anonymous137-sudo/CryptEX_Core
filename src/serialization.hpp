#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace cryptex {
namespace serialization {

// Write an integer in little‑endian order
template<typename T>
inline void write_int(std::vector<uint8_t>& out, T value) {
    for (size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

// Read a little‑endian integer, advancing pointer and reducing remaining
template<typename T>
inline T read_int(const uint8_t*& data, size_t& remaining) {
    if (remaining < sizeof(T))
        throw std::runtime_error("Not enough data for integer");
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        value |= static_cast<T>(data[i]) << (i * 8);
    }
    data += sizeof(T);
    remaining -= sizeof(T);
    return value;
}

// Write a variable‑length integer (Bitcoin style)
inline void write_varint(std::vector<uint8_t>& out, uint64_t value) {
    if (value < 0xFD) {
        out.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xFFFF) {
        out.push_back(0xFD);
        write_int<uint16_t>(out, static_cast<uint16_t>(value));
    } else if (value <= 0xFFFFFFFF) {
        out.push_back(0xFE);
        write_int<uint32_t>(out, static_cast<uint32_t>(value));
    } else {
        out.push_back(0xFF);
        write_int<uint64_t>(out, value);
    }
}

// Read a variable‑length integer
inline uint64_t read_varint(const uint8_t*& data, size_t& remaining) {
    if (remaining < 1) throw std::runtime_error("Not enough data for varint");
    uint8_t first = data[0];
    data++; remaining--;
    if (first < 0xFD) return first;
    if (first == 0xFD) return read_int<uint16_t>(data, remaining);
    if (first == 0xFE) return read_int<uint32_t>(data, remaining);
    return read_int<uint64_t>(data, remaining);
}

// Write a byte vector with length prefix
inline void write_bytes(std::vector<uint8_t>& out, const uint8_t* bytes, size_t len) {
    write_varint(out, len);
    out.insert(out.end(), bytes, bytes + len);
}

// Read a byte vector with length prefix
inline std::vector<uint8_t> read_bytes(const uint8_t*& data, size_t& remaining) {
    uint64_t len = read_varint(data, remaining);
    if (remaining < len) throw std::runtime_error("Not enough data for byte vector");
    std::vector<uint8_t> res(data, data + len);
    data += len;
    remaining -= len;
    return res;
}

} // namespace serialization
} // namespace cryptex
