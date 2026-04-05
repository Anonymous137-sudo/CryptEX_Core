#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cryptex {
namespace bip39 {

size_t entropy_bytes_for_words(size_t words);
std::string entropy_to_mnemonic(const std::vector<uint8_t>& entropy);
std::vector<uint8_t> mnemonic_to_entropy(const std::string& mnemonic);
std::vector<uint8_t> mnemonic_to_seed(const std::string& mnemonic,
                                      const std::string& passphrase = "");

} // namespace bip39
} // namespace cryptex
