#include "base64.hpp"
#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <cctype>

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

static const char base58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char bech32_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static std::string trim_copy(const std::string& value) {
    auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch) != 0; });
    auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch) != 0; }).base();
    if (begin >= end) return "";
    return std::string(begin, end);
}

static std::array<uint8_t, 32> sha256_once(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> out{};
    SHA256(data, len, out.data());
    return out;
}

static std::array<uint8_t, 4> address_checksum(const uint8_t* data, size_t len) {
    auto first = sha256_once(data, len);
    auto second = sha256_once(first.data(), first.size());
    return {second[0], second[1], second[2], second[3]};
}

static uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = static_cast<uint8_t>(chk >> 25);
        chk = (chk & 0x1ffffff) << 5 ^ v;
        if (top & 1) chk ^= 0x3b6a57b2;
        if (top & 2) chk ^= 0x26508e6d;
        if (top & 4) chk ^= 0x1ea119fa;
        if (top & 8) chk ^= 0x3d4233dd;
        if (top & 16) chk ^= 0x2a1462b3;
    }
    return chk;
}

static std::vector<uint8_t> bech32_hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> out;
    out.reserve(hrp.size() * 2 + 1);
    for (char ch : hrp) out.push_back(static_cast<uint8_t>(std::tolower(static_cast<unsigned char>(ch)) >> 5));
    out.push_back(0);
    for (char ch : hrp) out.push_back(static_cast<uint8_t>(std::tolower(static_cast<unsigned char>(ch)) & 31));
    return out;
}

static std::vector<uint8_t> bech32_create_checksum(const std::string& hrp, const std::vector<uint8_t>& data) {
    auto values = bech32_hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);
    const uint32_t mod = bech32_polymod(values) ^ 1;
    std::vector<uint8_t> checksum(6, 0);
    for (size_t i = 0; i < checksum.size(); ++i) {
        checksum[i] = static_cast<uint8_t>((mod >> (5 * (5 - i))) & 31);
    }
    return checksum;
}

static bool bech32_verify_checksum(const std::string& hrp, const std::vector<uint8_t>& data) {
    auto values = bech32_hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    return bech32_polymod(values) == 1;
}

static std::vector<uint8_t> convert_bits(const std::vector<uint8_t>& input, int from_bits, int to_bits, bool pad) {
    int acc = 0;
    int bits = 0;
    const int maxv = (1 << to_bits) - 1;
    const int max_acc = (1 << (from_bits + to_bits - 1)) - 1;
    std::vector<uint8_t> out;
    out.reserve((input.size() * from_bits + to_bits - 1) / to_bits);

    for (uint8_t value : input) {
        if ((value >> from_bits) != 0) throw std::invalid_argument("invalid bit-group value");
        acc = ((acc << from_bits) | value) & max_acc;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }

    if (pad) {
        if (bits > 0) out.push_back(static_cast<uint8_t>((acc << (to_bits - bits)) & maxv));
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0) {
        throw std::invalid_argument("invalid incomplete bech32 group");
    }

    return out;
}

static std::string bech32_encode(const std::string& hrp, const std::vector<uint8_t>& data) {
    std::string out = hrp;
    out.push_back('1');
    auto checksum = bech32_create_checksum(hrp, data);
    for (uint8_t value : data) out.push_back(bech32_charset[value]);
    for (uint8_t value : checksum) out.push_back(bech32_charset[value]);
    return out;
}

static std::pair<std::string, std::vector<uint8_t>> bech32_decode(const std::string& value) {
    if (value.empty()) throw std::invalid_argument("empty bech32 string");
    bool saw_lower = false;
    bool saw_upper = false;
    for (char ch : value) {
        if (std::islower(static_cast<unsigned char>(ch))) saw_lower = true;
        if (std::isupper(static_cast<unsigned char>(ch))) saw_upper = true;
    }
    if (saw_lower && saw_upper) throw std::invalid_argument("mixed-case bech32 string");

    std::string lower;
    lower.reserve(value.size());
    for (char ch : value) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));

    const auto pos = lower.rfind('1');
    if (pos == std::string::npos || pos == 0 || pos + 7 > lower.size()) {
        throw std::invalid_argument("invalid bech32 separator");
    }

    std::array<int8_t, 128> map{};
    map.fill(-1);
    for (int i = 0; bech32_charset[i] != '\0'; ++i) map[static_cast<size_t>(bech32_charset[i])] = static_cast<int8_t>(i);

    std::string hrp = lower.substr(0, pos);
    std::vector<uint8_t> data;
    data.reserve(lower.size() - pos - 1);
    for (size_t i = pos + 1; i < lower.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(lower[i]);
        if (ch >= map.size() || map[ch] < 0) throw std::invalid_argument("invalid bech32 character");
        data.push_back(static_cast<uint8_t>(map[ch]));
    }
    if (!bech32_verify_checksum(hrp, data)) throw std::invalid_argument("invalid bech32 checksum");
    data.resize(data.size() - 6);
    return {hrp, data};
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

std::string base58_encode(const uint8_t* data, size_t len) {
    if (!data && len) throw std::invalid_argument("Null data with non-zero length");
    if (len == 0) return "";

    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) ++zeros;

    std::vector<uint8_t> input(data, data + len);
    std::vector<char> encoded;
    encoded.reserve(len * 2);

    size_t start = zeros;
    while (start < input.size()) {
        int remainder = 0;
        for (size_t i = start; i < input.size(); ++i) {
            int value = (remainder << 8) + input[i];
            input[i] = static_cast<uint8_t>(value / 58);
            remainder = value % 58;
        }
        encoded.push_back(base58_alphabet[remainder]);
        while (start < input.size() && input[start] == 0) ++start;
    }

    std::string out(zeros, '1');
    for (auto it = encoded.rbegin(); it != encoded.rend(); ++it) out.push_back(*it);
    return out;
}

std::vector<uint8_t> base58_decode(const std::string& text) {
    if (text.empty()) return {};

    std::array<int8_t, 128> map{};
    map.fill(-1);
    for (int i = 0; base58_alphabet[i] != '\0'; ++i) map[static_cast<size_t>(base58_alphabet[i])] = static_cast<int8_t>(i);

    size_t zeros = 0;
    while (zeros < text.size() && text[zeros] == '1') ++zeros;

    std::vector<uint8_t> decoded;
    decoded.reserve(text.size());

    for (char ch : text) {
        if (static_cast<unsigned char>(ch) >= map.size() || map[static_cast<size_t>(ch)] < 0) {
            throw std::invalid_argument("Invalid Base58 string");
        }
        int carry = map[static_cast<size_t>(ch)];
        for (auto it = decoded.rbegin(); it != decoded.rend(); ++it) {
            carry += 58 * (*it);
            *it = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        while (carry > 0) {
            decoded.insert(decoded.begin(), static_cast<uint8_t>(carry & 0xFF));
            carry >>= 8;
        }
    }

    std::vector<uint8_t> out(zeros, 0x00);
    out.insert(out.end(), decoded.begin(), decoded.end());
    return out;
}

bool hex_is_valid(const std::string& hex) {
    if (hex.empty() || (hex.size() % 2) != 0) return false;
    return std::all_of(hex.begin(), hex.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

std::vector<uint8_t> hex_decode(const std::string& hex) {
    auto trimmed = trim_copy(hex);
    if (trimmed.rfind("0x", 0) == 0 || trimmed.rfind("0X", 0) == 0) {
        trimmed = trimmed.substr(2);
    }
    if (!hex_is_valid(trimmed)) throw std::invalid_argument("Invalid hex string");

    auto hex_value = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
        if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
        return -1;
    };

    std::vector<uint8_t> out;
    out.reserve(trimmed.size() / 2);
    for (size_t i = 0; i < trimmed.size(); i += 2) {
        int hi = hex_value(trimmed[i]);
        int lo = hex_value(trimmed[i + 1]);
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string hex_encode(const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        out.push_back(hex[(byte >> 4) & 0x0F]);
        out.push_back(hex[byte & 0x0F]);
    }
    return out;
}

std::string canonicalize_address(const std::string& address) {
    std::string trimmed = trim_copy(address);
    if (trimmed.empty()) throw std::runtime_error("Invalid address");

    try {
        auto decoded = bech32_decode(trimmed);
        if (decoded.first == constants::ADDRESS_BECH32_HRP && !decoded.second.empty() && decoded.second[0] == 0) {
            std::vector<uint8_t> program5(decoded.second.begin() + 1, decoded.second.end());
            auto program = convert_bits(program5, 5, 8, false);
            if (program.size() != constants::ADDRESS_HASH_LENGTH) {
                throw std::runtime_error("Invalid bech32 address length");
            }
            return base64_encode(program.data(), program.size());
        }
    } catch (...) {
    }

    std::string maybe_hex = trimmed;
    if (maybe_hex.rfind("0x", 0) == 0 || maybe_hex.rfind("0X", 0) == 0) {
        maybe_hex = maybe_hex.substr(2);
    }
    if (maybe_hex.size() == constants::ADDRESS_HEX_LENGTH && hex_is_valid(maybe_hex)) {
        auto decoded = hex_decode(maybe_hex);
        if (decoded.size() != constants::ADDRESS_HASH_LENGTH) {
            throw std::runtime_error("Invalid address length");
        }
        return base64_encode(decoded.data(), decoded.size());
    }

    try {
        auto decoded = base58_decode(trimmed);
        if (decoded.size() == constants::ADDRESS_HASH_LENGTH + 1 + 4 &&
            decoded.front() == constants::ADDRESS_BASE58_VERSION) {
            auto checksum = address_checksum(decoded.data(), constants::ADDRESS_HASH_LENGTH + 1);
            if (std::equal(checksum.begin(), checksum.end(), decoded.begin() + constants::ADDRESS_HASH_LENGTH + 1)) {
                return base64_encode(decoded.data() + 1, constants::ADDRESS_HASH_LENGTH);
            }
        }
    } catch (...) {
    }

    std::string padded = trimmed;
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

std::string address_to_base64(const std::string& address) {
    return canonicalize_address(address);
}

std::string address_to_base58(const std::string& address) {
    auto decoded = base64_decode(canonicalize_address(address));
    std::array<uint8_t, 25> payload{};
    payload[0] = constants::ADDRESS_BASE58_VERSION;
    std::copy(decoded.begin(), decoded.end(), payload.begin() + 1);
    auto checksum = address_checksum(payload.data(), constants::ADDRESS_HASH_LENGTH + 1);
    std::copy(checksum.begin(), checksum.end(), payload.begin() + constants::ADDRESS_HASH_LENGTH + 1);
    return base58_encode(payload.data(), payload.size());
}

std::string address_to_hex(const std::string& address) {
    auto decoded = base64_decode(canonicalize_address(address));
    return std::string("0x") + hex_encode(decoded.data(), decoded.size());
}

std::string address_to_bech32(const std::string& address) {
    auto decoded = base64_decode(canonicalize_address(address));
    std::vector<uint8_t> data;
    data.push_back(0); // witness version style marker
    auto program = convert_bits(decoded, 8, 5, true);
    data.insert(data.end(), program.begin(), program.end());
    return bech32_encode(constants::ADDRESS_BECH32_HRP, data);
}

} // namespace crypto
} // namespace cryptex
