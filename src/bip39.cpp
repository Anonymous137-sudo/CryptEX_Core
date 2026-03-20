#include "bip39.hpp"

#include <array>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace cryptex {
namespace bip39 {

namespace {

constexpr std::array<const char*, 2048> kEnglishWords = {
#include "bip39_words.inc"
};

const std::unordered_map<std::string, uint16_t>& word_index() {
    static const std::unordered_map<std::string, uint16_t> map = []() {
        std::unordered_map<std::string, uint16_t> out;
        out.reserve(kEnglishWords.size());
        for (uint16_t i = 0; i < kEnglishWords.size(); ++i) {
            out.emplace(kEnglishWords[i], i);
        }
        return out;
    }();
    return map;
}

std::vector<std::string> split_words(const std::string& mnemonic) {
    std::istringstream in(mnemonic);
    std::vector<std::string> words;
    std::string word;
    while (in >> word) {
        words.push_back(word);
    }
    return words;
}

std::array<uint8_t, SHA256_DIGEST_LENGTH> sha256_bytes(const std::vector<uint8_t>& data) {
    std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
    SHA256(data.data(), data.size(), digest.data());
    return digest;
}

} // namespace

size_t entropy_bytes_for_words(size_t words) {
    switch (words) {
    case 12: return 16;
    case 15: return 20;
    case 18: return 24;
    case 21: return 28;
    case 24: return 32;
    default:
        throw std::runtime_error("BIP39 supports 12, 15, 18, 21, or 24 words");
    }
}

std::string entropy_to_mnemonic(const std::vector<uint8_t>& entropy) {
    if (entropy.empty()) throw std::runtime_error("entropy required");
    size_t ent_bits = entropy.size() * 8;
    if (ent_bits < 128 || ent_bits > 256 || ent_bits % 32 != 0) {
        throw std::runtime_error("invalid entropy size for BIP39");
    }

    size_t checksum_bits = ent_bits / 32;
    auto checksum = sha256_bytes(entropy);
    std::vector<uint8_t> bits;
    bits.reserve(ent_bits + checksum_bits);

    for (uint8_t byte : entropy) {
        for (int bit = 7; bit >= 0; --bit) {
            bits.push_back((byte >> bit) & 1u);
        }
    }
    for (size_t i = 0; i < checksum_bits; ++i) {
        bits.push_back((checksum[i / 8] >> (7 - (i % 8))) & 1u);
    }

    std::ostringstream out;
    size_t word_count = bits.size() / 11;
    for (size_t i = 0; i < word_count; ++i) {
        uint16_t index = 0;
        for (size_t j = 0; j < 11; ++j) {
            index = static_cast<uint16_t>((index << 1) | bits[i * 11 + j]);
        }
        if (i) out << ' ';
        out << kEnglishWords[index];
    }
    return out.str();
}

std::vector<uint8_t> mnemonic_to_entropy(const std::string& mnemonic) {
    auto words = split_words(mnemonic);
    size_t word_count = words.size();
    entropy_bytes_for_words(word_count); // validates count

    std::vector<uint8_t> bits;
    bits.reserve(word_count * 11);
    const auto& index = word_index();
    for (const auto& word : words) {
        auto it = index.find(word);
        if (it == index.end()) {
            throw std::runtime_error("unknown BIP39 word: " + word);
        }
        uint16_t value = it->second;
        for (int bit = 10; bit >= 0; --bit) {
            bits.push_back((value >> bit) & 1u);
        }
    }

    size_t total_bits = bits.size();
    size_t ent_bits = (total_bits * 32) / 33;
    size_t checksum_bits = total_bits - ent_bits;
    std::vector<uint8_t> entropy(ent_bits / 8, 0);

    for (size_t i = 0; i < ent_bits; ++i) {
        if (bits[i]) {
            entropy[i / 8] |= static_cast<uint8_t>(1u << (7 - (i % 8)));
        }
    }

    auto checksum = sha256_bytes(entropy);
    for (size_t i = 0; i < checksum_bits; ++i) {
        uint8_t expected = (checksum[i / 8] >> (7 - (i % 8))) & 1u;
        if (bits[ent_bits + i] != expected) {
            throw std::runtime_error("BIP39 checksum mismatch");
        }
    }

    return entropy;
}

std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic,
                                      const std::string& passphrase) {
    std::vector<uint8_t> seed(64);
    std::string salt = "mnemonic" + passphrase;
    if (PKCS5_PBKDF2_HMAC(mnemonic.c_str(),
                          static_cast<int>(mnemonic.size()),
                          reinterpret_cast<const uint8_t*>(salt.data()),
                          static_cast<int>(salt.size()),
                          2048,
                          EVP_sha512(),
                          static_cast<int>(seed.size()),
                          seed.data()) != 1) {
        throw std::runtime_error("BIP39 seed derivation failed");
    }
    return seed;
}

} // namespace bip39
} // namespace cryptex
