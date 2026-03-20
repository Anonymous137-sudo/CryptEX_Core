#pragma once

#include <cstdint>

// Simple CRC32 (polynomial 0xEDB88320) to avoid external zlib dependency.
inline uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return crc;
}

inline uint32_t crc32_finalize(uint32_t crc) {
    return crc ^ 0xFFFFFFFFu;
}
