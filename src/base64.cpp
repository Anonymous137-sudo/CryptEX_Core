#include "base64.hpp"
#include <cstring>

namespace cryptex {
namespace crypto {

static const char encoding_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
static uint8_t decoding_table[256];
static bool decoding_table_built = false;

static void build_decoding_table() {
    if (decoding_table_built) return;
    for (int i = 0; i < 256; ++i) decoding_table[i] = 0xFF;
    for (int i = 0; i < 64; ++i)
        decoding_table[static_cast<uint8_t>(encoding_table[i])] = i;
    decoding_table_built = true;
}

std::string base64_encode(const uint8_t* data, size_t len) {
    if (!data && len) throw std::invalid_argument("Null data with non-zero length");
    if (len == 0) return "";

    size_t out_len = ((len + 2) / 3) * 4;
    std::string res(out_len, '=');

    size_t i = 0;
    size_t j = 0;
    while (i + 3 <= len) {
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                          (static_cast<uint32_t>(data[i + 1]) << 8) |
                          static_cast<uint32_t>(data[i + 2]);
        res[j++] = encoding_table[(triple >> 18) & 0x3F];
        res[j++] = encoding_table[(triple >> 12) & 0x3F];
        res[j++] = encoding_table[(triple >> 6) & 0x3F];
        res[j++] = encoding_table[triple & 0x3F];
        i += 3;
    }

    size_t rem = len - i;
    if (rem == 1) {
        uint32_t triple = static_cast<uint32_t>(data[i]) << 16;
        res[j++] = encoding_table[(triple >> 18) & 0x3F];
        res[j++] = encoding_table[(triple >> 12) & 0x3F];
        res[j++] = '=';
        res[j++] = '=';
    } else if (rem == 2) {
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                          (static_cast<uint32_t>(data[i + 1]) << 8);
        res[j++] = encoding_table[(triple >> 18) & 0x3F];
        res[j++] = encoding_table[(triple >> 12) & 0x3F];
        res[j++] = encoding_table[(triple >> 6) & 0x3F];
        res[j++] = '=';
    }

    return res;
}

std::vector<uint8_t> base64_decode(const std::string& base64) {
    build_decoding_table();
    if (!base64_is_valid(base64))
        throw std::invalid_argument("Invalid Base64 string");

    size_t len = base64.size();
    size_t padding = 0;
    if (len >= 1 && base64[len-1] == '=') padding++;
    if (len >= 2 && base64[len-2] == '=') padding++;

    size_t out_len = (len * 3) / 4 - padding;
    std::vector<uint8_t> res(out_len);

    for (size_t i = 0, j = 0; i < len; i += 4) {
        uint32_t a = decoding_table[static_cast<uint8_t>(base64[i])];
        uint32_t b = decoding_table[static_cast<uint8_t>(base64[i + 1])];
        uint32_t c = base64[i + 2] == '=' ? 0 : decoding_table[static_cast<uint8_t>(base64[i + 2])];
        uint32_t d = base64[i + 3] == '=' ? 0 : decoding_table[static_cast<uint8_t>(base64[i + 3])];
        uint32_t triple = (a << 18) | (b << 12) | (c << 6) | d;

        res[j++] = static_cast<uint8_t>((triple >> 16) & 0xFF);
        if (base64[i + 2] != '=') {
            res[j++] = static_cast<uint8_t>((triple >> 8) & 0xFF);
        }
        if (base64[i + 3] != '=') {
            res[j++] = static_cast<uint8_t>(triple & 0xFF);
        }
    }
    return res;
}

bool base64_is_valid(const std::string& base64) {
    build_decoding_table();
    if (base64.empty()) return true;
    if (base64.size() % 4 != 0) return false;
    for (size_t i = 0; i < base64.size(); ++i) {
        char c = base64[i];
        if (c == '=') {
            // Padding can only appear at the end
            if (i < base64.size() - 2) return false;
            if (i == base64.size() - 2 && base64.back() != '=') return false;
        } else {
            if (decoding_table[static_cast<uint8_t>(c)] == 0xFF) return false;
        }
    }
    return true;
}

std::string canonicalize_address(const std::string& address) {
    std::string padded = address;
    while (padded.size() % 4) padded.push_back('=');

    auto decoded = base64_decode(padded);
    if (decoded.size() == 21 && decoded.back() == 0) {
        decoded.pop_back();
    }
    if (decoded.size() != 20) {
        throw std::runtime_error("Invalid address length");
    }
    return base64_encode(decoded.data(), decoded.size());
}

bool addresses_equal(const std::string& lhs, const std::string& rhs) {
    try {
        return canonicalize_address(lhs) == canonicalize_address(rhs);
    } catch (...) {
        return lhs == rhs;
    }
}

} // namespace crypto
} // namespace cryptex
