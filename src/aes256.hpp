#pragma once

#include "constants.hpp"
#include <vector>
#include <string>
#include <array>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>

namespace cryptex {
namespace crypto {

using AESKey = std::array<uint8_t, constants::AES_KEY_SIZE>;
using AESIV = std::array<uint8_t, constants::AES_IV_SIZE>;

// Basic CBC encryption/decryption
inline std::vector<uint8_t> aes256_encrypt_cbc(
    const uint8_t* plain, size_t plain_len,
    const AESKey& key, const AESIV& iv) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 1);

    std::vector<uint8_t> cipher(plain_len + constants::AES_BLOCK_SIZE);
    int out_len1 = 0, out_len2 = 0;

    if (1 != EVP_EncryptUpdate(ctx, cipher.data(), &out_len1, plain, plain_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    if (1 != EVP_EncryptFinal_ex(ctx, cipher.data() + out_len1, &out_len2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    cipher.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return cipher;
}

inline std::vector<uint8_t> aes256_decrypt_cbc(
    const uint8_t* cipher, size_t cipher_len,
    const AESKey& key, const AESIV& iv) {

    if (cipher_len % constants::AES_BLOCK_SIZE != 0)
        throw std::invalid_argument("Ciphertext length not multiple of block size");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 1);

    std::vector<uint8_t> plain(cipher_len);
    int out_len1 = 0, out_len2 = 0;

    if (1 != EVP_DecryptUpdate(ctx, plain.data(), &out_len1, cipher, cipher_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    if (1 != EVP_DecryptFinal_ex(ctx, plain.data() + out_len1, &out_len2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed (wrong key?)");
    }
    plain.resize(out_len1 + out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return plain;
}

// Wallet encryption helpers
inline AESKey derive_key_from_password(const std::string& password, const std::vector<uint8_t>& salt) {
    AESKey key;
    if (1 != PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                               salt.data(), salt.size(),
                               constants::PBKDF2_ITERATIONS,
                               EVP_sha512(), key.size(), key.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }
    return key;
}

inline AESIV generate_random_iv() {
    AESIV iv;
    if (1 != RAND_bytes(iv.data(), iv.size()))
        throw std::runtime_error("RAND_bytes failed");
    return iv;
}

inline std::vector<uint8_t> generate_random_salt(size_t len = 16) {
    std::vector<uint8_t> salt(len);
    if (1 != RAND_bytes(salt.data(), salt.size()))
        throw std::runtime_error("RAND_bytes failed");
    return salt;
}

// Encrypt wallet data: [salt(16)][iv(16)][ciphertext]
inline std::vector<uint8_t> encrypt_wallet(const std::vector<uint8_t>& wallet_data, const std::string& password) {
    auto salt = generate_random_salt(16);
    auto iv = generate_random_iv();
    auto key = derive_key_from_password(password, salt);
    auto cipher = aes256_encrypt_cbc(wallet_data.data(), wallet_data.size(), key, iv);

    std::vector<uint8_t> result;
    result.reserve(salt.size() + iv.size() + cipher.size());
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), cipher.begin(), cipher.end());
    return result;
}

// Decrypt wallet data
inline std::vector<uint8_t> decrypt_wallet(const std::vector<uint8_t>& encrypted_data, const std::string& password) {
    const size_t salt_size = 16;
    const size_t iv_size = constants::AES_IV_SIZE;
    if (encrypted_data.size() < salt_size + iv_size)
        throw std::runtime_error("Invalid encrypted wallet format");

    std::vector<uint8_t> salt(encrypted_data.begin(), encrypted_data.begin() + salt_size);
    AESIV iv;
    std::copy(encrypted_data.begin() + salt_size, encrypted_data.begin() + salt_size + iv_size, iv.begin());

    auto key = derive_key_from_password(password, salt);
    const uint8_t* cipher = encrypted_data.data() + salt_size + iv_size;
    size_t cipher_len = encrypted_data.size() - salt_size - iv_size;

    return aes256_decrypt_cbc(cipher, cipher_len, key, iv);
}

} // namespace crypto
} // namespace cryptex
