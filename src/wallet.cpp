#include "wallet.hpp"
#include "bip39.hpp"
#include "serialization.hpp"
#include "blockchain.hpp"
#include "debug.hpp"
#include "base64.hpp"
#include "sha3_512.hpp"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <unordered_set>
#include <unordered_map>
#include <array>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

namespace cryptex {

namespace {

constexpr uint32_t BIP32_HARDENED = 0x80000000u;
constexpr uint32_t BIP32_ACCOUNT_ZERO = BIP32_HARDENED;
constexpr uint32_t BIP32_EXTERNAL_CHAIN = 0;

struct BIP32Node {
    std::array<uint8_t, 32> secret{};
    std::array<uint8_t, 32> chain_code{};
};

const BIGNUM* secp256k1_order() {
    static BIGNUM* order = []() {
        BIGNUM* bn = nullptr;
        BN_hex2bn(&bn, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        return bn;
    }();
    return order;
}

void fill_random(std::vector<uint8_t>& bytes) {
    if (!bytes.empty() && RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
}

std::filesystem::path wallet_backup_path(const std::filesystem::path& wallet_path) {
    return wallet_path.string() + ".bak";
}

std::filesystem::path wallet_temp_path(const std::filesystem::path& wallet_path) {
    return wallet_path.string() + ".tmp";
}

std::filesystem::path wallet_chat_rsa_public_path(const std::filesystem::path& wallet_path) {
    return wallet_path.string() + ".chat_rsa_pub.pem";
}

std::filesystem::path wallet_chat_rsa_private_path(const std::filesystem::path& wallet_path) {
    return wallet_path.string() + ".chat_rsa_priv.pem";
}

std::vector<uint8_t> read_wallet_blob(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("wallet file not found");
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("wallet chat key file not found");
    }
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

void write_text_file(const std::filesystem::path& path, const std::string& text, bool private_file) {
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to write wallet chat key file");
    }
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    output.flush();
    output.close();
    if (private_file) {
        std::error_code ec;
        std::filesystem::permissions(path,
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace,
                                     ec);
    }
}

std::string bio_to_string(BIO* bio) {
    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(bio, &buffer);
    if (!buffer || !buffer->data || buffer->length == 0) {
        throw std::runtime_error("failed to serialize PEM data");
    }
    return std::string(buffer->data, buffer->length);
}

std::string private_key_to_unencrypted_pem(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("failed to allocate in-memory private key buffer");
    }
    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        throw std::runtime_error("failed to export unencrypted RSA private key");
    }
    auto pem = bio_to_string(bio);
    BIO_free(bio);
    return pem;
}

EVP_PKEY* load_private_pem(const std::string& pem, const std::string& password) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        throw std::runtime_error("failed to allocate PEM BIO");
    }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, const_cast<char*>(password.c_str()));
    BIO_free(bio);
    if (!pkey) {
        throw std::runtime_error("failed to decode encrypted RSA private key");
    }
    return pkey;
}

void validate_public_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        throw std::runtime_error("failed to allocate public PEM BIO");
    }
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        throw std::runtime_error("failed to decode RSA public key");
    }
    EVP_PKEY_free(pkey);
}

std::pair<std::string, std::string> generate_wallet_chat_rsa_pems(const std::string& password) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw std::runtime_error("failed to allocate RSA keygen context");
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("failed to initialize RSA key generation");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0 || !pkey) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("failed to generate RSA keypair");
    }
    EVP_PKEY_CTX_free(ctx);

    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (!pub_bio || !priv_bio) {
        if (pub_bio) BIO_free(pub_bio);
        if (priv_bio) BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("failed to allocate RSA PEM buffers");
    }

    if (PEM_write_bio_PUBKEY(pub_bio, pkey) != 1 ||
        PEM_write_bio_PrivateKey(priv_bio,
                                 pkey,
                                 EVP_aes_256_cbc(),
                                 reinterpret_cast<unsigned char*>(const_cast<char*>(password.data())),
                                 static_cast<int>(password.size()),
                                 nullptr,
                                 nullptr) != 1) {
        BIO_free(pub_bio);
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("failed to encode RSA keypair");
    }

    auto public_pem = bio_to_string(pub_bio);
    auto private_pem = bio_to_string(priv_bio);
    BIO_free(pub_bio);
    BIO_free(priv_bio);
    EVP_PKEY_free(pkey);
    return {public_pem, private_pem};
}

void ensure_wallet_chat_rsa_keys(const std::string& path, const std::string& password, Wallet& wallet) {
    const auto wallet_path = std::filesystem::path(path);
    const auto public_path = wallet_chat_rsa_public_path(wallet_path);
    const auto private_path = wallet_chat_rsa_private_path(wallet_path);

    std::error_code public_ec;
    std::error_code private_ec;
    const bool public_exists = std::filesystem::exists(public_path, public_ec);
    const bool private_exists = std::filesystem::exists(private_path, private_ec);
    if (public_ec || private_ec) {
        throw std::runtime_error("failed to inspect wallet RSA sidecar files");
    }

    if (!public_exists || !private_exists) {
        auto [public_pem, private_pem] = generate_wallet_chat_rsa_pems(password);
        write_text_file(public_path, public_pem, false);
        write_text_file(private_path, private_pem, true);
        wallet.chat_rsa_public_key_pem = std::move(public_pem);
        EVP_PKEY* private_key = load_private_pem(private_pem, password);
        wallet.chat_rsa_private_key_pem = private_key_to_unencrypted_pem(private_key);
        EVP_PKEY_free(private_key);
        return;
    }

    wallet.chat_rsa_public_key_pem = read_text_file(public_path);
    const auto encrypted_private = read_text_file(private_path);
    validate_public_pem(wallet.chat_rsa_public_key_pem);
    EVP_PKEY* private_key = load_private_pem(encrypted_private, password);
    wallet.chat_rsa_private_key_pem = private_key_to_unencrypted_pem(private_key);
    EVP_PKEY_free(private_key);
}

void reencrypt_wallet_chat_rsa_keys(const std::string& path,
                                    const std::string& old_password,
                                    const std::string& new_password,
                                    Wallet& wallet) {
    const auto wallet_path = std::filesystem::path(path);
    const auto public_path = wallet_chat_rsa_public_path(wallet_path);
    const auto private_path = wallet_chat_rsa_private_path(wallet_path);

    std::error_code public_ec;
    std::error_code private_ec;
    const bool public_exists = std::filesystem::exists(public_path, public_ec);
    const bool private_exists = std::filesystem::exists(private_path, private_ec);
    if (public_ec || private_ec) {
        throw std::runtime_error("failed to inspect wallet RSA sidecar files");
    }
    if (!public_exists || !private_exists) {
        ensure_wallet_chat_rsa_keys(path, new_password, wallet);
        return;
    }

    if (wallet.chat_rsa_public_key_pem.empty()) {
        wallet.chat_rsa_public_key_pem = read_text_file(public_path);
    }
    std::string encrypted_private = read_text_file(private_path);
    EVP_PKEY* pkey = load_private_pem(encrypted_private, old_password);
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (!priv_bio) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("failed to allocate RSA re-encryption buffer");
    }
    if (PEM_write_bio_PrivateKey(priv_bio,
                                 pkey,
                                 EVP_aes_256_cbc(),
                                 reinterpret_cast<unsigned char*>(const_cast<char*>(new_password.data())),
                                 static_cast<int>(new_password.size()),
                                 nullptr,
                                 nullptr) != 1) {
        BIO_free(priv_bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("failed to re-encrypt RSA private key");
    }
    const auto encrypted_pem = bio_to_string(priv_bio);
    BIO_free(priv_bio);
    wallet.chat_rsa_private_key_pem = private_key_to_unencrypted_pem(pkey);
    EVP_PKEY_free(pkey);

    write_text_file(public_path, wallet.chat_rsa_public_key_pem, false);
    write_text_file(private_path, encrypted_pem, true);
}

std::array<uint8_t, 64> hmac_sha512(const uint8_t* key, size_t key_len,
                                    const uint8_t* data, size_t data_len) {
    std::array<uint8_t, 64> out{};
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha512(), key, static_cast<int>(key_len), data, data_len, out.data(), &out_len) ||
        out_len != out.size()) {
        throw std::runtime_error("HMAC-SHA512 failed");
    }
    return out;
}

void write_be32(uint8_t* out, uint32_t value) {
    out[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(value & 0xFF);
}

std::array<uint8_t, 32> extract_secret_from_priv(const std::vector<uint8_t>& privkey) {
    const unsigned char* der_ptr = privkey.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &der_ptr, privkey.size());
    if (!pkey) {
        throw std::runtime_error("decode priv failed");
    }

    BIGNUM* priv_bn = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) <= 0 || !priv_bn) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("private key extract failed");
    }

    std::array<uint8_t, 32> secret{};
    if (BN_bn2binpad(priv_bn, secret.data(), secret.size()) != static_cast<int>(secret.size())) {
        BN_free(priv_bn);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("private key normalization failed");
    }

    BN_free(priv_bn);
    EVP_PKEY_free(pkey);
    return secret;
}

std::vector<uint8_t> compressed_pubkey_from_secret(const std::array<uint8_t, 32>& secret) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) throw std::runtime_error("EC_KEY_new_by_curve_name failed");

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    BN_CTX* bn_ctx = BN_CTX_new();
    BIGNUM* priv_bn = BN_bin2bn(secret.data(), secret.size(), nullptr);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!bn_ctx || !priv_bn || !pub_point) {
        if (pub_point) EC_POINT_free(pub_point);
        if (priv_bn) BN_free(priv_bn);
        if (bn_ctx) BN_CTX_free(bn_ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("pubkey allocation failed");
    }

    if (EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, bn_ctx) != 1) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("public key derivation failed");
    }

    size_t pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, nullptr, 0, bn_ctx);
    if (pub_len == 0) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("public key size failed");
    }

    std::vector<uint8_t> pubkey(pub_len);
    if (EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, pubkey.data(), pubkey.size(), bn_ctx) != pub_len) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("public key export failed");
    }

    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    BN_CTX_free(bn_ctx);
    EC_KEY_free(ec_key);
    return pubkey;
}

} // namespace

std::vector<uint8_t> derive_provider_key(const char* algorithm,
                                         const std::vector<uint8_t>& password,
                                         const std::vector<OSSL_PARAM>& params,
                                         size_t key_size) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, algorithm, nullptr);
    if (!kdf) {
        throw std::runtime_error(std::string("OpenSSL KDF unavailable: ") + algorithm);
    }
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) {
        throw std::runtime_error(std::string("KDF context allocation failed: ") + algorithm);
    }

    std::vector<OSSL_PARAM> local = params;
    local.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                      const_cast<unsigned char*>(password.data()),
                                                      password.size()));
    local.push_back(OSSL_PARAM_construct_end());

    std::vector<uint8_t> key(key_size);
    if (EVP_KDF_derive(ctx, key.data(), key.size(), local.data()) <= 0) {
        unsigned long err = ERR_peek_last_error();
        std::string message = std::string("KDF derive failed: ") + algorithm;
        if (err != 0) {
            message += " (";
            message += ERR_reason_error_string(err);
            message += ")";
        }
        EVP_KDF_CTX_free(ctx);
        throw std::runtime_error(message);
    }
    EVP_KDF_CTX_free(ctx);
    return key;
}

static std::vector<uint8_t> derive_key(const std::string& password,
                                       const std::vector<uint8_t>& salt,
                                       Wallet::KeyDerivation kdf) {
    std::vector<uint8_t> key(constants::AES_KEY_SIZE);
    if (kdf == Wallet::KeyDerivation::PBKDF2) {
        if (1 != PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                                   salt.data(), static_cast<int>(salt.size()),
                                   constants::PBKDF2_ITERATIONS,
                                   EVP_sha256(), key.size(), key.data())) {
            throw std::runtime_error("PBKDF2 failed");
        }
        return key;
    }

    const std::vector<uint8_t> password_bytes(password.begin(), password.end());
    std::vector<OSSL_PARAM> params;
    params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                       const_cast<unsigned char*>(salt.data()),
                                                       salt.size()));
    if (kdf == Wallet::KeyDerivation::Scrypt) {
        uint64_t n = constants::WALLET_SCRYPT_N;
        uint64_t r = constants::WALLET_SCRYPT_R;
        uint64_t p = constants::WALLET_SCRYPT_P;
        uint64_t maxmem = constants::WALLET_SCRYPT_MAXMEM;
        params.push_back(OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n));
        params.push_back(OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_R, &r));
        params.push_back(OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_P, &p));
        params.push_back(OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem));
        return derive_provider_key(OSSL_KDF_NAME_SCRYPT, password_bytes, params, constants::AES_KEY_SIZE);
    }

    unsigned int iter = constants::WALLET_ARGON2_ITERATIONS;
    unsigned int threads = constants::WALLET_ARGON2_THREADS;
    unsigned int lanes = constants::WALLET_ARGON2_LANES;
    unsigned int version = 0x13;
    uint64_t memcost = constants::WALLET_ARGON2_MEMCOST_KIB;
    params.push_back(OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter));
    params.push_back(OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads));
    params.push_back(OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &lanes));
    params.push_back(OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_VERSION, &version));
    params.push_back(OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost));
    return derive_provider_key("ARGON2ID", password_bytes, params, constants::AES_KEY_SIZE);
}

static std::vector<uint8_t> aes_encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit failed");
    }
    std::vector<uint8_t> ciphertext(plaintext.size() + constants::AES_BLOCK_SIZE);
    int len1 = 0, len2 = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len1, plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptUpdate failed");
    }
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len1, &len2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal failed");
    }
    ciphertext.resize(len1 + len2);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

static std::vector<uint8_t> aes_decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit failed");
    }
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len1 = 0, len2 = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len1, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptUpdate failed");
    }
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len1, &len2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptFinal failed");
    }
    plaintext.resize(len1 + len2);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

static std::vector<uint8_t> derive_pub_from_priv(const std::vector<uint8_t>& privkey) {
    const unsigned char* der_ptr = privkey.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &der_ptr, privkey.size());
    if (!pkey) {
        throw std::runtime_error("decode priv failed");
    }

    size_t pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("pub size failed");
    }
    std::vector<uint8_t> pubkey(pub_len);
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey.data(), pubkey.size(), &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("pub fetch failed");
    }
    EVP_PKEY_free(pkey);
    return pubkey;
}

static bool keypair_from_secret(const std::array<uint8_t, 32>& secret,
                                std::vector<uint8_t>& privkey,
                                std::vector<uint8_t>& pubkey) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) throw std::runtime_error("EC_KEY_new_by_curve_name failed");

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    BN_CTX* bn_ctx = BN_CTX_new();
    BIGNUM* priv_bn = BN_bin2bn(secret.data(), secret.size(), nullptr);
    BIGNUM* order = BN_new();
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!bn_ctx || !priv_bn || !order || !pub_point) {
        if (pub_point) EC_POINT_free(pub_point);
        if (order) BN_free(order);
        if (priv_bn) BN_free(priv_bn);
        if (bn_ctx) BN_CTX_free(bn_ctx);
        EC_KEY_free(ec_key);
        throw std::runtime_error("HD key allocation failed");
    }

    if (EC_GROUP_get_order(group, order, bn_ctx) != 1 ||
        BN_is_zero(priv_bn) ||
        BN_cmp(priv_bn, order) >= 0 ||
        EC_KEY_set_private_key(ec_key, priv_bn) != 1 ||
        EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, bn_ctx) != 1 ||
        EC_KEY_set_public_key(ec_key, pub_point) != 1) {
        EC_POINT_free(pub_point);
        BN_free(order);
        BN_free(priv_bn);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(ec_key);
        return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
        if (pkey) EVP_PKEY_free(pkey);
        EC_POINT_free(pub_point);
        BN_free(order);
        BN_free(priv_bn);
        BN_CTX_free(bn_ctx);
        EC_KEY_free(ec_key);
        return false;
    }
    ec_key = nullptr;

    int pkcs8_len = i2d_PrivateKey(pkey, nullptr);
    if (pkcs8_len <= 0) {
        EVP_PKEY_free(pkey);
        EC_POINT_free(pub_point);
        BN_free(order);
        BN_free(priv_bn);
        BN_CTX_free(bn_ctx);
        return false;
    }
    privkey.resize(pkcs8_len);
    unsigned char* der_ptr = privkey.data();
    if (i2d_PrivateKey(pkey, &der_ptr) != pkcs8_len) {
        EVP_PKEY_free(pkey);
        EC_POINT_free(pub_point);
        BN_free(order);
        BN_free(priv_bn);
        BN_CTX_free(bn_ctx);
        return false;
    }

    EVP_PKEY_free(pkey);
    EC_POINT_free(pub_point);
    BN_free(order);
    BN_free(priv_bn);
    BN_CTX_free(bn_ctx);
    pubkey = derive_pub_from_priv(privkey);
    return true;
}

static void derive_legacy_hd_keypair(const std::vector<uint8_t>& seed,
                                     uint32_t index,
                                     std::vector<uint8_t>& privkey,
                                     std::vector<uint8_t>& pubkey) {
    std::array<uint8_t, 32> secret{};
    std::array<uint8_t, 9> data{};
    data[0] = 'C';
    data[1] = 'X';
    data[2] = 'H';
    data[3] = 'D';
    data[4] = static_cast<uint8_t>(index & 0xFF);
    data[5] = static_cast<uint8_t>((index >> 8) & 0xFF);
    data[6] = static_cast<uint8_t>((index >> 16) & 0xFF);
    data[7] = static_cast<uint8_t>((index >> 24) & 0xFF);

    for (uint8_t attempt = 0; attempt < 255; ++attempt) {
        data[8] = attempt;
        auto digest = hmac_sha512(seed.data(), seed.size(), data.data(), data.size());
        std::memcpy(secret.data(), digest.data(), secret.size());
        if (keypair_from_secret(secret, privkey, pubkey)) {
            return;
        }
    }
    throw std::runtime_error("failed to derive HD child key");
}

static BIP32Node derive_bip32_master(const std::vector<uint8_t>& seed) {
    static constexpr char BIP32_SEED_KEY[] = "Bitcoin seed";
    auto digest = hmac_sha512(reinterpret_cast<const uint8_t*>(BIP32_SEED_KEY),
                              sizeof(BIP32_SEED_KEY) - 1,
                              seed.data(),
                              seed.size());

    BIP32Node node;
    std::memcpy(node.secret.data(), digest.data(), node.secret.size());
    std::memcpy(node.chain_code.data(), digest.data() + 32, node.chain_code.size());

    BIGNUM* master_bn = BN_bin2bn(node.secret.data(), node.secret.size(), nullptr);
    if (!master_bn) throw std::runtime_error("BIP32 master decode failed");
    bool valid = !BN_is_zero(master_bn) && BN_cmp(master_bn, secp256k1_order()) < 0;
    BN_free(master_bn);
    if (!valid) {
        throw std::runtime_error("BIP32 master key invalid");
    }
    return node;
}

static BIP32Node derive_bip32_child(const BIP32Node& parent, uint32_t index) {
    std::array<uint8_t, 37> data{};
    if (index >= BIP32_HARDENED) {
        data[0] = 0x00;
        std::memcpy(data.data() + 1, parent.secret.data(), parent.secret.size());
    } else {
        auto pubkey = compressed_pubkey_from_secret(parent.secret);
        if (pubkey.size() != 33) {
            throw std::runtime_error("BIP32 compressed pubkey size invalid");
        }
        std::memcpy(data.data(), pubkey.data(), pubkey.size());
    }
    write_be32(data.data() + 33, index);

    auto digest = hmac_sha512(parent.chain_code.data(), parent.chain_code.size(), data.data(), data.size());

    BN_CTX* bn_ctx = BN_CTX_new();
    BIGNUM* tweak = BN_bin2bn(digest.data(), 32, nullptr);
    BIGNUM* parent_bn = BN_bin2bn(parent.secret.data(), parent.secret.size(), nullptr);
    BIGNUM* child_bn = BN_new();
    if (!bn_ctx || !tweak || !parent_bn || !child_bn) {
        if (child_bn) BN_free(child_bn);
        if (parent_bn) BN_free(parent_bn);
        if (tweak) BN_free(tweak);
        if (bn_ctx) BN_CTX_free(bn_ctx);
        throw std::runtime_error("BIP32 child allocation failed");
    }

    if (BN_is_zero(tweak) || BN_cmp(tweak, secp256k1_order()) >= 0 ||
        BN_mod_add(child_bn, tweak, parent_bn, secp256k1_order(), bn_ctx) != 1 ||
        BN_is_zero(child_bn)) {
        BN_free(child_bn);
        BN_free(parent_bn);
        BN_free(tweak);
        BN_CTX_free(bn_ctx);
        throw std::runtime_error("BIP32 child derivation invalid");
    }

    BIP32Node child;
    if (BN_bn2binpad(child_bn, child.secret.data(), child.secret.size()) != static_cast<int>(child.secret.size())) {
        BN_free(child_bn);
        BN_free(parent_bn);
        BN_free(tweak);
        BN_CTX_free(bn_ctx);
        throw std::runtime_error("BIP32 child encoding failed");
    }
    std::memcpy(child.chain_code.data(), digest.data() + 32, child.chain_code.size());

    BN_free(child_bn);
    BN_free(parent_bn);
    BN_free(tweak);
    BN_CTX_free(bn_ctx);
    return child;
}

static void derive_bip32_keypair(const std::vector<uint8_t>& seed,
                                 uint32_t index,
                                 std::vector<uint8_t>& privkey,
                                 std::vector<uint8_t>& pubkey) {
    if (index >= BIP32_HARDENED) {
        throw std::runtime_error("BIP32 child index exhausted");
    }

    auto master = derive_bip32_master(seed);
    auto account = derive_bip32_child(master, BIP32_ACCOUNT_ZERO);
    auto external = derive_bip32_child(account, BIP32_EXTERNAL_CHAIN);
    auto child = derive_bip32_child(external, index);
    if (!keypair_from_secret(child.secret, privkey, pubkey)) {
        throw std::runtime_error("BIP32 child key material invalid");
    }
}

static void derive_wallet_keypair(Wallet::HdScheme scheme,
                                  const std::vector<uint8_t>& seed,
                                  uint32_t index,
                                  std::vector<uint8_t>& privkey,
                                  std::vector<uint8_t>& pubkey) {
    switch (scheme) {
    case Wallet::HdScheme::LegacyCxhd:
        derive_legacy_hd_keypair(seed, index, privkey, pubkey);
        return;
    case Wallet::HdScheme::Bip32:
        derive_bip32_keypair(seed, index, privkey, pubkey);
        return;
    case Wallet::HdScheme::None:
        break;
    }
    throw std::runtime_error("wallet is not HD-enabled");
}

static std::string format_wallet_address(const std::string& canonical_address,
                                         Wallet::AddressFormat format) {
    switch (format) {
    case Wallet::AddressFormat::Base64:
        return crypto::address_to_base64(canonical_address);
    case Wallet::AddressFormat::Base58:
        return crypto::address_to_base58(canonical_address);
    case Wallet::AddressFormat::Hex:
        return crypto::address_to_hex(canonical_address);
    case Wallet::AddressFormat::Bech32:
        return crypto::address_to_bech32(canonical_address);
    }
    return crypto::address_to_base58(canonical_address);
}

void Wallet::sync_primary() {
    if (privkeys.empty()) {
        privkey.clear();
        pubkey.clear();
        address.clear();
        return;
    }
    privkey = privkeys.front();
    pubkey = pubkeys.front();
    address = addresses.front();
}

void Wallet::append_key(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& pub) {
    privkeys.push_back(priv);
    pubkeys.push_back(pub);
    addresses.push_back(crypto::canonicalize_address(script::pubkey_to_address(pub)));
    sync_primary();
}

const char* Wallet::hd_mode() const {
    switch (hd_scheme_) {
    case HdScheme::LegacyCxhd:
        return "HD (Legacy CXHD)";
    case HdScheme::Bip32:
        return "HD (BIP32)";
    case HdScheme::None:
        return "Imported";
    }
    return "Unknown";
}

const char* Wallet::address_format_name() const {
    switch (address_format_) {
    case AddressFormat::Base64:
        return "base64";
    case AddressFormat::Base58:
        return "base58";
    case AddressFormat::Hex:
        return "hex";
    case AddressFormat::Bech32:
        return "bech32";
    }
    return "base64";
}

std::string Wallet::display_address(const std::string& address_value) const {
    return format_wallet_address(crypto::canonicalize_address(address_value), address_format_);
}

std::string Wallet::display_address(const std::string& address_value, AddressFormat format) const {
    return format_wallet_address(crypto::canonicalize_address(address_value), format);
}

std::optional<Wallet::AddressFormat> Wallet::parse_address_format(const std::string& text) {
    std::string normalized = text;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (normalized == "base64" || normalized == "cryptex" || normalized == "native") {
        return AddressFormat::Base64;
    }
    if (normalized == "base58" || normalized == "p2pkh") {
        return AddressFormat::Base58;
    }
    if (normalized == "hex" || normalized == "0x" || normalized == "eth" || normalized == "ethereum") {
        return AddressFormat::Hex;
    }
    if (normalized == "bech32") {
        return AddressFormat::Bech32;
    }
    return std::nullopt;
}

std::optional<Wallet::KeyDerivation> Wallet::parse_key_derivation(const std::string& text) {
    std::string normalized = text;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (normalized == "pbkdf2" || normalized == "pbkdf2-sha256") {
        return KeyDerivation::PBKDF2;
    }
    if (normalized == "scrypt") {
        return KeyDerivation::Scrypt;
    }
    if (normalized == "argon2" || normalized == "argon2id") {
        return KeyDerivation::Argon2id;
    }
    return std::nullopt;
}

const char* Wallet::kdf_name() const {
    switch (key_derivation_) {
    case KeyDerivation::PBKDF2:
        return "pbkdf2";
    case KeyDerivation::Scrypt:
        return "scrypt";
    case KeyDerivation::Argon2id:
        return "argon2id";
    }
    return "pbkdf2";
}

std::string Wallet::chat_rsa_public_key_b64() const {
    if (chat_rsa_public_key_pem.empty()) {
        return {};
    }
    return crypto::base64_encode(chat_rsa_public_key_pem);
}

std::vector<uint8_t> Wallet::serialize_plaintext() const {
    std::vector<uint8_t> out;
    serialization::write_int<uint32_t>(out, 7);
    serialization::write_int<uint32_t>(out, static_cast<uint32_t>(address_format_));
    serialization::write_int<uint32_t>(out, static_cast<uint32_t>(hd_scheme_));
    serialization::write_int<uint32_t>(out, next_hd_index_);
    serialization::write_bytes(out, mnemonic_entropy_.data(), mnemonic_entropy_.size());
    serialization::write_bytes(out, master_seed_.data(), master_seed_.size());
    serialization::write_varint(out, privkeys.size());
    for (const auto& key : privkeys) {
        serialization::write_bytes(out, key.data(), key.size());
    }
    serialization::write_varint(out, labels_.size());
    for (const auto& [address_key, label] : labels_) {
        serialization::write_bytes(out,
                                   reinterpret_cast<const uint8_t*>(address_key.data()),
                                   address_key.size());
        serialization::write_bytes(out,
                                   reinterpret_cast<const uint8_t*>(label.data()),
                                   label.size());
    }
    return out;
}

void Wallet::save_encrypted(const std::string& password, const std::string& path) const {
    std::vector<uint8_t> salt(constants::WALLET_KDF_SALT_SIZE);
    std::vector<uint8_t> iv(constants::AES_IV_SIZE);
    fill_random(salt);
    fill_random(iv);
    auto key_bytes = derive_key(password, salt, key_derivation_);
    auto ciphertext = aes_encrypt(serialize_plaintext(), key_bytes, iv);
    persist(path, key_derivation_, salt, iv, ciphertext);
}

Wallet Wallet::deserialize_plaintext(const std::vector<uint8_t>& plaintext) {
    Wallet w;
    if (plaintext.empty()) {
        throw std::runtime_error("wallet payload empty");
    }

    bool parsed_structured = false;
    if (plaintext.size() >= sizeof(uint32_t)) {
        const uint8_t* ptr = plaintext.data();
        size_t rem = plaintext.size();
        uint32_t version = serialization::read_int<uint32_t>(ptr, rem);
        if (version == 7) {
            uint32_t format = serialization::read_int<uint32_t>(ptr, rem);
            if (format > static_cast<uint32_t>(AddressFormat::Bech32)) {
                throw std::runtime_error("wallet address format unsupported");
            }
            w.address_format_ = static_cast<AddressFormat>(format);
            uint32_t scheme = serialization::read_int<uint32_t>(ptr, rem);
            if (scheme > static_cast<uint32_t>(HdScheme::Bip32)) {
                throw std::runtime_error("wallet HD scheme unsupported");
            }
            w.hd_scheme_ = static_cast<HdScheme>(scheme);
            w.next_hd_index_ = serialization::read_int<uint32_t>(ptr, rem);
            w.mnemonic_entropy_ = serialization::read_bytes(ptr, rem);
            w.master_seed_ = serialization::read_bytes(ptr, rem);
            uint64_t count = serialization::read_varint(ptr, rem);
            if (count == 0) throw std::runtime_error("wallet has no keys");
            for (uint64_t i = 0; i < count; ++i) {
                w.privkeys.push_back(serialization::read_bytes(ptr, rem));
            }
            uint64_t label_count = serialization::read_varint(ptr, rem);
            for (uint64_t i = 0; i < label_count; ++i) {
                auto key_bytes = serialization::read_bytes(ptr, rem);
                auto label_bytes = serialization::read_bytes(ptr, rem);
                w.labels_.emplace(std::string(key_bytes.begin(), key_bytes.end()),
                                  std::string(label_bytes.begin(), label_bytes.end()));
            }
            parsed_structured = true;
        } else if (version == 6) {
            uint32_t scheme = serialization::read_int<uint32_t>(ptr, rem);
            if (scheme > static_cast<uint32_t>(HdScheme::Bip32)) {
                throw std::runtime_error("wallet HD scheme unsupported");
            }
            w.hd_scheme_ = static_cast<HdScheme>(scheme);
            w.next_hd_index_ = serialization::read_int<uint32_t>(ptr, rem);
            w.mnemonic_entropy_ = serialization::read_bytes(ptr, rem);
            w.master_seed_ = serialization::read_bytes(ptr, rem);
            uint64_t count = serialization::read_varint(ptr, rem);
            if (count == 0) throw std::runtime_error("wallet has no keys");
            for (uint64_t i = 0; i < count; ++i) {
                w.privkeys.push_back(serialization::read_bytes(ptr, rem));
            }
            uint64_t label_count = serialization::read_varint(ptr, rem);
            for (uint64_t i = 0; i < label_count; ++i) {
                auto key_bytes = serialization::read_bytes(ptr, rem);
                auto label_bytes = serialization::read_bytes(ptr, rem);
                w.labels_.emplace(std::string(key_bytes.begin(), key_bytes.end()),
                                  std::string(label_bytes.begin(), label_bytes.end()));
            }
            parsed_structured = true;
        } else if (version == 5) {
            uint32_t scheme = serialization::read_int<uint32_t>(ptr, rem);
            if (scheme > static_cast<uint32_t>(HdScheme::Bip32)) {
                throw std::runtime_error("wallet HD scheme unsupported");
            }
            w.hd_scheme_ = static_cast<HdScheme>(scheme);
            w.next_hd_index_ = serialization::read_int<uint32_t>(ptr, rem);
            w.mnemonic_entropy_ = serialization::read_bytes(ptr, rem);
            w.master_seed_ = serialization::read_bytes(ptr, rem);
            uint64_t count = serialization::read_varint(ptr, rem);
            if (count == 0) throw std::runtime_error("wallet has no keys");
            for (uint64_t i = 0; i < count; ++i) {
                w.privkeys.push_back(serialization::read_bytes(ptr, rem));
            }
            parsed_structured = true;
        } else if (version == 4) {
            uint32_t scheme = serialization::read_int<uint32_t>(ptr, rem);
            if (scheme > static_cast<uint32_t>(HdScheme::Bip32)) {
                throw std::runtime_error("wallet HD scheme unsupported");
            }
            w.hd_scheme_ = static_cast<HdScheme>(scheme);
            w.next_hd_index_ = serialization::read_int<uint32_t>(ptr, rem);
            w.master_seed_ = serialization::read_bytes(ptr, rem);
            uint64_t count = serialization::read_varint(ptr, rem);
            if (count == 0) throw std::runtime_error("wallet has no keys");
            for (uint64_t i = 0; i < count; ++i) {
                w.privkeys.push_back(serialization::read_bytes(ptr, rem));
            }
            parsed_structured = true;
        } else if (version == 3) {
            uint32_t has_seed = serialization::read_int<uint32_t>(ptr, rem);
            w.next_hd_index_ = serialization::read_int<uint32_t>(ptr, rem);
            w.master_seed_ = serialization::read_bytes(ptr, rem);
            if (!has_seed) w.master_seed_.clear();
            w.hd_scheme_ = has_seed ? HdScheme::LegacyCxhd : HdScheme::None;
            uint64_t count = serialization::read_varint(ptr, rem);
            if (count == 0) throw std::runtime_error("wallet has no keys");
            for (uint64_t i = 0; i < count; ++i) {
                w.privkeys.push_back(serialization::read_bytes(ptr, rem));
            }
            parsed_structured = true;
        } else if (version == 2) {
            uint64_t count = serialization::read_varint(ptr, rem);
            if (count == 0) throw std::runtime_error("wallet has no keys");
            for (uint64_t i = 0; i < count; ++i) {
                w.privkeys.push_back(serialization::read_bytes(ptr, rem));
            }
            parsed_structured = true;
        }
    }

    if (!parsed_structured) {
        // Legacy wallet payload: a single DER-encoded private key blob.
        w.privkeys.push_back(plaintext);
    }
    for (const auto& key : w.privkeys) {
        auto pub = derive_pub_from_priv(key);
        w.pubkeys.push_back(pub);
        w.addresses.push_back(crypto::canonicalize_address(script::pubkey_to_address(pub)));
    }
    w.sync_primary();
    return w;
}

static std::unordered_set<std::string> owned_address_set(const Wallet& wallet) {
    std::unordered_set<std::string> owned;
    for (const auto& address : wallet.addresses) {
        owned.insert(crypto::canonicalize_address(address));
    }
    return owned;
}

static std::optional<std::string> try_canonical_address(const std::string& address) {
    try {
        return crypto::canonicalize_address(address);
    } catch (...) {
        return std::nullopt;
    }
}

static std::string normalize_label_key(const std::string& address) {
    try {
        return crypto::canonicalize_address(address);
    } catch (...) {
        return address;
    }
}

static std::string format_wallet_amount(int64_t sats) {
    std::ostringstream ss;
    auto whole = sats / 100000000LL;
    auto frac = std::llabs(sats % 100000000LL);
    ss << whole << "." << std::setw(8) << std::setfill('0') << frac << " CryptEX";
    return ss.str();
}

static bool address_has_chain_activity(const std::string& address, Blockchain& chain);

static size_t count_unused_addresses(const Wallet& wallet, Blockchain& chain) {
    size_t count = 0;
    for (const auto& candidate : wallet.addresses) {
        if (!address_has_chain_activity(candidate, chain)) {
            ++count;
        }
    }
    return count;
}

static std::optional<std::string> first_unused_wallet_address(const Wallet& wallet,
                                                              Blockchain& chain,
                                                              const std::optional<std::string>& exclude = std::nullopt) {
    std::optional<std::string> exclude_canonical;
    if (exclude && !exclude->empty()) {
        exclude_canonical = crypto::canonicalize_address(*exclude);
    }
    for (const auto& candidate : wallet.addresses) {
        auto canonical_candidate = crypto::canonicalize_address(candidate);
        if (exclude_canonical && *exclude_canonical == canonical_candidate) continue;
        if (!address_has_chain_activity(candidate, chain)) {
            return canonical_candidate;
        }
    }
    return std::nullopt;
}

static std::vector<std::string> dedupe_preserving_order(const std::vector<std::string>& values) {
    std::vector<std::string> out;
    std::unordered_set<std::string> seen;
    for (const auto& value : values) {
        if (value.empty()) continue;
        if (seen.insert(value).second) {
            out.push_back(value);
        }
    }
    return out;
}

static bool address_has_chain_activity(const std::string& address, Blockchain& chain) {
    auto canonical = crypto::canonicalize_address(address);
    for (uint64_t h = 0; h <= chain.best_height(); ++h) {
        auto blk = chain.get_block(h);
        if (!blk) continue;
        for (const auto& tx : blk->transactions) {
            for (const auto& out : tx.outputs) {
                if (crypto::addresses_equal(out.scriptPubKey, canonical)) {
                    return true;
                }
            }
        }
    }
    return false;
}

std::string Wallet::mnemonic_phrase() const {
    if (mnemonic_entropy_.empty()) {
        throw std::runtime_error("wallet has no stored BIP39 mnemonic");
    }
    return bip39::entropy_to_mnemonic(mnemonic_entropy_);
}

std::string Wallet::dump_private_key_hex(const std::optional<std::string>& requested_address) const {
    size_t index = 0;
    if (requested_address && !requested_address->empty()) {
        const auto wanted = crypto::canonicalize_address(*requested_address);
        bool found = false;
        for (size_t i = 0; i < addresses.size(); ++i) {
            if (crypto::addresses_equal(addresses[i], wanted)) {
                index = i;
                found = true;
                break;
            }
        }
        if (!found) {
            throw std::runtime_error("address not found in wallet");
        }
    }
    if (index >= privkeys.size()) {
        throw std::runtime_error("wallet key material missing");
    }
    auto secret = extract_secret_from_priv(privkeys[index]);
    return crypto::hex_encode(secret.data(), secret.size());
}

void Wallet::change_address_format(const std::string& password,
                                   const std::string& path,
                                   AddressFormat format) {
    *this = Wallet::load(password, path);
    address_format_ = format;
    save_encrypted(password, path);
}

Wallet Wallet::create_new(const std::string& password,
                          const std::string& path,
                          AddressFormat address_format,
                          size_t mnemonic_words,
                          const std::string& mnemonic_passphrase,
                          KeyDerivation kdf) {
    Wallet w;
    w.address_format_ = address_format;
    w.hd_scheme_ = HdScheme::Bip32;
    w.key_derivation_ = kdf;
    w.mnemonic_entropy_.resize(bip39::entropy_bytes_for_words(mnemonic_words));
    fill_random(w.mnemonic_entropy_);
    auto mnemonic = bip39::entropy_to_mnemonic(w.mnemonic_entropy_);
    w.master_seed_ = bip39::mnemonic_to_seed(mnemonic, mnemonic_passphrase);
    std::vector<uint8_t> new_priv;
    std::vector<uint8_t> new_pub;
    derive_wallet_keypair(w.hd_scheme_, w.master_seed_, w.next_hd_index_, new_priv, new_pub);
    w.next_hd_index_++;
    w.append_key(new_priv, new_pub);
    w.save_encrypted(password, path);
    ensure_wallet_chat_rsa_keys(path, password, w);
    return w;
}

Wallet Wallet::create_new(const std::string& password,
                          const std::string& path,
                          size_t mnemonic_words,
                          const std::string& mnemonic_passphrase,
                          KeyDerivation kdf) {
    return create_new(password, path, AddressFormat::Base64, mnemonic_words, mnemonic_passphrase, kdf);
}

Wallet Wallet::create_from_mnemonic(const std::string& password,
                                    const std::string& path,
                                    const std::string& mnemonic,
                                    AddressFormat address_format,
                                    const std::string& mnemonic_passphrase,
                                    KeyDerivation kdf) {
    Wallet w;
    w.address_format_ = address_format;
    w.hd_scheme_ = HdScheme::Bip32;
    w.key_derivation_ = kdf;
    w.mnemonic_entropy_ = bip39::mnemonic_to_entropy(mnemonic);
    auto canonical_mnemonic = bip39::entropy_to_mnemonic(w.mnemonic_entropy_);
    w.master_seed_ = bip39::mnemonic_to_seed(canonical_mnemonic, mnemonic_passphrase);

    std::vector<uint8_t> new_priv;
    std::vector<uint8_t> new_pub;
    derive_wallet_keypair(w.hd_scheme_, w.master_seed_, w.next_hd_index_, new_priv, new_pub);
    w.next_hd_index_++;
    w.append_key(new_priv, new_pub);
    w.save_encrypted(password, path);
    ensure_wallet_chat_rsa_keys(path, password, w);
    return w;
}

Wallet Wallet::create_from_mnemonic(const std::string& password,
                                    const std::string& path,
                                    const std::string& mnemonic,
                                    const std::string& mnemonic_passphrase,
                                    KeyDerivation kdf) {
    return create_from_mnemonic(password, path, mnemonic, AddressFormat::Base64, mnemonic_passphrase, kdf);
}

Wallet Wallet::load(const std::string& password, const std::string& path) {
    const std::filesystem::path wallet_path(path);
    const std::array<std::filesystem::path, 2> candidates{
        wallet_path,
        wallet_backup_path(wallet_path),
    };

    std::string last_error = "wallet file not found";
    for (const auto& candidate : candidates) {
        std::error_code ec;
        if (!std::filesystem::exists(candidate, ec)) continue;
        try {
            KeyDerivation kdf = KeyDerivation::PBKDF2;
            std::vector<uint8_t> salt, iv, ciphertext;
            read_file(candidate.string(), kdf, salt, iv, ciphertext);
            auto key = derive_key(password, salt, kdf);
            auto plaintext = aes_decrypt(ciphertext, key, iv);
            Wallet wallet = deserialize_plaintext(plaintext);
            wallet.key_derivation_ = kdf;
            ensure_wallet_chat_rsa_keys(wallet_path.string(), password, wallet);
            return wallet;
        } catch (const std::exception& ex) {
            last_error = ex.what();
        }
    }
    throw std::runtime_error(last_error);
}

Wallet::KeyDerivation Wallet::inspect_key_derivation(const std::string& path) {
    KeyDerivation kdf = KeyDerivation::PBKDF2;
    std::vector<uint8_t> salt, iv, ciphertext;
    read_file(path, kdf, salt, iv, ciphertext);
    return kdf;
}

Wallet Wallet::recover(const std::string& password, const std::string& path) {
    const std::filesystem::path wallet_path(path);
    const auto backup_path = wallet_backup_path(wallet_path);
    if (!std::filesystem::exists(backup_path)) {
        throw std::runtime_error("wallet backup file not found");
    }

    Wallet recovered = Wallet::load(password, backup_path.string());
    std::error_code ec;
    std::filesystem::copy_file(backup_path,
                               wallet_path,
                               std::filesystem::copy_options::overwrite_existing,
                               ec);
    if (ec) {
        throw std::runtime_error("failed to restore wallet backup: " + ec.message());
    }
    return recovered;
}

std::string Wallet::add_address(const std::string& password, const std::string& path) {
    *this = Wallet::load(password, path);

    std::vector<uint8_t> new_priv;
    std::vector<uint8_t> new_pub;
    if (master_seed_.empty()) {
        hd_scheme_ = HdScheme::Bip32;
        master_seed_.resize(64);
        fill_random(master_seed_);
    } else if (hd_scheme_ == HdScheme::None) {
        hd_scheme_ = HdScheme::Bip32;
    }
    derive_wallet_keypair(hd_scheme_, master_seed_, next_hd_index_, new_priv, new_pub);
    next_hd_index_++;
    append_key(new_priv, new_pub);
    save_encrypted(password, path);
    return display_address(addresses.back());
}

void Wallet::persist(const std::string& path,
                     KeyDerivation kdf,
                     const std::vector<uint8_t>& salt,
                     const std::vector<uint8_t>& iv,
                     const std::vector<uint8_t>& ciphertext) {
    std::filesystem::path wallet_path(path);
    if (wallet_path.has_parent_path()) {
        std::filesystem::create_directories(wallet_path.parent_path());
    }
    std::vector<uint8_t> out;
    serialization::write_int<uint32_t>(out, 2); // version
    serialization::write_int<uint32_t>(out, static_cast<uint32_t>(kdf));
    serialization::write_int<uint32_t>(out, static_cast<uint32_t>(salt.size()));
    out.insert(out.end(), salt.begin(), salt.end());
    serialization::write_int<uint32_t>(out, static_cast<uint32_t>(iv.size()));
    out.insert(out.end(), iv.begin(), iv.end());
    serialization::write_int<uint32_t>(out, static_cast<uint32_t>(ciphertext.size()));
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    const auto tmp_path = wallet_temp_path(wallet_path);
    const auto backup_path = wallet_backup_path(wallet_path);
    std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("failed to open wallet file for writing");
    f.write(reinterpret_cast<const char*>(out.data()), out.size());
    if (!f) throw std::runtime_error("failed to write wallet file");
    f.flush();
    f.close();

    std::error_code ec;
    if (std::filesystem::exists(backup_path, ec)) {
        std::filesystem::remove(backup_path, ec);
        ec.clear();
    }

    bool moved_existing = false;
    if (std::filesystem::exists(wallet_path, ec)) {
        std::filesystem::rename(wallet_path, backup_path, ec);
        if (ec) {
            std::filesystem::remove(tmp_path, ec);
            throw std::runtime_error("failed to rotate wallet backup: " + ec.message());
        }
        moved_existing = true;
    }

    ec.clear();
    std::filesystem::rename(tmp_path, wallet_path, ec);
    if (ec) {
        if (moved_existing) {
            std::error_code restore_ec;
            std::filesystem::rename(backup_path, wallet_path, restore_ec);
        }
        std::filesystem::remove(tmp_path, ec);
        throw std::runtime_error("failed to replace wallet file atomically: " + ec.message());
    }
}

void Wallet::read_file(const std::string& path,
                       KeyDerivation& kdf,
                       std::vector<uint8_t>& salt,
                       std::vector<uint8_t>& iv,
                       std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> data = read_wallet_blob(path);
    const uint8_t* ptr = data.data();
    size_t rem = data.size();
    uint32_t version = serialization::read_int<uint32_t>(ptr, rem);
    if (version == 1) {
        kdf = KeyDerivation::PBKDF2;
        if (rem < constants::AES_IV_SIZE * 2 + 4) throw std::runtime_error("wallet truncated");
        salt.assign(ptr, ptr + constants::AES_IV_SIZE);
        ptr += constants::AES_IV_SIZE; rem -= constants::AES_IV_SIZE;
        iv.assign(ptr, ptr + constants::AES_IV_SIZE);
        ptr += constants::AES_IV_SIZE; rem -= constants::AES_IV_SIZE;
    } else if (version == 2) {
        const auto raw_kdf = serialization::read_int<uint32_t>(ptr, rem);
        if (raw_kdf > static_cast<uint32_t>(KeyDerivation::Argon2id)) {
            throw std::runtime_error("wallet kdf unsupported");
        }
        kdf = static_cast<KeyDerivation>(raw_kdf);
        uint32_t salt_len = serialization::read_int<uint32_t>(ptr, rem);
        if (rem < salt_len) throw std::runtime_error("wallet salt truncated");
        salt.assign(ptr, ptr + salt_len);
        ptr += salt_len; rem -= salt_len;
        uint32_t iv_len = serialization::read_int<uint32_t>(ptr, rem);
        if (rem < iv_len) throw std::runtime_error("wallet iv truncated");
        iv.assign(ptr, ptr + iv_len);
        ptr += iv_len; rem -= iv_len;
    } else {
        throw std::runtime_error("wallet version unsupported");
    }
    uint32_t clen = serialization::read_int<uint32_t>(ptr, rem);
    if (rem < clen) throw std::runtime_error("wallet ciphertext truncated");
    ciphertext.assign(ptr, ptr + clen);
}

Transaction Wallet::create_payment(Blockchain& chain,
                                   const std::string& to_address,
                                   int64_t amount_sats,
                                   const std::string& op_return_msg,
                                   int64_t fee_per_kb,
                                   const std::vector<OutPoint>& selected_inputs,
                                   const std::optional<std::string>& change_address) const {
    if (!chain.wallet_state_approved()) {
        throw std::runtime_error("wallet is locked until chain sync is approved");
    }
    if (amount_sats <= 0) throw std::runtime_error("amount must be positive");
    std::string canonical_to;
    try {
        canonical_to = crypto::canonicalize_address(to_address);
    } catch (...) {
        throw std::runtime_error("invalid destination address format");
    }
    auto utxos = list_unspent(chain);
    std::unordered_map<OutPoint, UTXOEntry> available;
    for (const auto& [outpoint, entry] : utxos) {
        available.emplace(outpoint, entry);
    }
    int64_t total = 0;
    std::vector<std::pair<OutPoint, UTXOEntry>> selected;
    if (!selected_inputs.empty()) {
        for (const auto& outpoint : selected_inputs) {
            auto it = available.find(outpoint);
            if (it == available.end()) {
                throw std::runtime_error("selected input is not available in wallet");
            }
            selected.push_back({it->first, it->second});
            total += it->second.output.value;
        }
    } else {
        for (const auto& u : utxos) {
            selected.push_back(u);
            total += u.second.output.value;
            const size_t estimated_size = 4 + 4 + 1 + (selected.size() * (36 + 1 + 110 + 4)) + 1 + (2 * (8 + 1 + canonical_to.size()));
            const int64_t estimated_fee = static_cast<int64_t>((estimated_size + 999) / 1000) * fee_per_kb;
            if (total >= amount_sats + estimated_fee) break;
        }
    }
    if (total < amount_sats) throw std::runtime_error("insufficient funds");

    Transaction tx;
    tx.version = 1;
    tx.lockTime = 0;

    // Inputs
    for (const auto& [op, entry] : selected) {
        TxIn in;
        in.prevout = op;
        in.sequence = 0xFFFFFFFF;
        tx.inputs.push_back(in);
    }

    // Outputs
    TxOut out_to;
    out_to.value = amount_sats;
    out_to.scriptPubKey = canonical_to;
    tx.outputs.push_back(out_to);

    auto estimate_size = [&]() {
        size_t sz = 4 + 4; // version + locktime
        // inputs
        sz += 1; // varint count
        for (size_t i = 0; i < tx.inputs.size(); ++i) {
            sz += 36; // outpoint
            sz += 1 + 110; // script length + script (sig+pubkey)
            sz += 4; // sequence
        }
        // outputs
        sz += 1; // varint count
        for (const auto& o : tx.outputs) {
            sz += 8; // value
            sz += 1 + o.scriptPubKey.size();
        }
        return sz;
    };
    auto compute_fee = [&](size_t sz) {
        return static_cast<int64_t>((sz + 999) / 1000) * fee_per_kb;
    };

    int64_t fee = 0;
    while (true) {
        size_t est = estimate_size();
        fee = compute_fee(est);
        int64_t change = total - amount_sats - fee;
        // remove any previous change
        if (!tx.outputs.empty()) {
            while (tx.outputs.size() > (op_return_msg.empty() ? 1U : 2U))
                tx.outputs.pop_back();
        }
        if (change < 0) throw std::runtime_error("insufficient for fee");
        if (change >= constants::DUST_LIMIT_SATS) {
            TxOut change_out;
            change_out.value = change;
            if (change_address && !change_address->empty()) {
                try {
                    change_out.scriptPubKey = crypto::canonicalize_address(*change_address);
                } catch (...) {
                    throw std::runtime_error("invalid change address format");
                }
            } else if (auto privacy_change = first_unused_wallet_address(*this, chain, canonical_to)) {
                change_out.scriptPubKey = *privacy_change;
            } else {
                change_out.scriptPubKey = crypto::canonicalize_address(address);
            }
            tx.outputs.push_back(change_out);
        } else {
            fee += change; // absorb dust into fee
        }
        // single pass is enough with this estimation
        break;
    }
    if (!op_return_msg.empty()) {
        TxOut opret;
        opret.value = 0;
        auto sigmsg = op_return_msg;
        // sign message and embed base64 signature
        auto digest = crypto::sha3_512(std::vector<uint8_t>(sigmsg.begin(), sigmsg.end()));
        std::array<uint8_t,32> first{};
        std::memcpy(first.data(), digest.data(), 32);
        uint256_t h(first);
        auto sig = script::sign_hash(h, privkey);
        auto sig_b64 = crypto::base64_encode(sig.data(), sig.size());
        opret.scriptPubKey = "OP_RETURN:" + sig_b64;
        tx.outputs.push_back(opret);
    }

    std::unordered_map<std::string, size_t> signing_keys;
    for (size_t i = 0; i < addresses.size(); ++i) {
        signing_keys[crypto::canonicalize_address(addresses[i])] = i;
    }

    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        const auto& entry = selected[i].second;
        std::vector<uint8_t> script_pubkey_bytes(entry.output.scriptPubKey.begin(),
                                                  entry.output.scriptPubKey.end());
        uint256_t sigh = tx.sighash(i, script_pubkey_bytes);
        auto key_it = signing_keys.find(crypto::canonicalize_address(entry.output.scriptPubKey));
        if (key_it == signing_keys.end()) throw std::runtime_error("missing key for selected input");
        auto sig = script::sign_hash(sigh, privkeys[key_it->second]);
        std::vector<uint8_t> scriptSig = sig;
        scriptSig.insert(scriptSig.end(), pubkeys[key_it->second].begin(), pubkeys[key_it->second].end());
        tx.inputs[i].scriptSig = scriptSig;
    }

    return tx;
}

std::vector<std::pair<OutPoint, UTXOEntry>> Wallet::list_unspent(Blockchain& chain) const {
    std::vector<std::pair<OutPoint, UTXOEntry>> all;
    if (!chain.wallet_state_approved()) return all;
    uint32_t current_height = static_cast<uint32_t>(chain.best_height());
    for (const auto& addr : addresses) {
        auto utxos = chain.utxo().list_for_address(addr, current_height);
        all.insert(all.end(), utxos.begin(), utxos.end());
    }
    return all;
}

int64_t Wallet::balance(Blockchain& chain) const {
    return balance_summary(chain).spendable;
}

std::vector<Wallet::AddressBookEntry> Wallet::address_book() const {
    std::vector<AddressBookEntry> rows;
    rows.reserve(addresses.size());
    for (size_t i = 0; i < addresses.size(); ++i) {
        AddressBookEntry row;
        row.address = display_address(addresses[i]);
        row.address_base64 = crypto::address_to_base64(addresses[i]);
        row.address_base58 = crypto::address_to_base58(addresses[i]);
        row.address_hex = crypto::address_to_hex(addresses[i]);
        row.address_bech32 = crypto::address_to_bech32(addresses[i]);
        row.label = label_for(addresses[i]);
        row.pubkey_b64 = (i < pubkeys.size()) ? crypto::base64_encode(pubkeys[i]) : std::string();
        row.primary = (i == 0);
        row.hd_index = static_cast<uint32_t>(i);
        rows.push_back(std::move(row));
    }
    return rows;
}

std::string Wallet::label_for(const std::string& address_value) const {
    auto it = labels_.find(normalize_label_key(address_value));
    return it == labels_.end() ? std::string() : it->second;
}

void Wallet::set_label(const std::string& password,
                       const std::string& path,
                       const std::string& address_value,
                       const std::string& label) {
    *this = Wallet::load(password, path);
    const auto key = normalize_label_key(address_value);
    if (label.empty()) {
        labels_.erase(key);
    } else {
        labels_[key] = label;
    }

    save_encrypted(password, path);
}

void Wallet::set_primary_address(const std::string& password,
                                 const std::string& path,
                                 const std::string& address_value) {
    *this = Wallet::load(password, path);
    const auto target = crypto::canonicalize_address(address_value);
    auto it = std::find_if(addresses.begin(), addresses.end(), [&](const std::string& existing) {
        return crypto::addresses_equal(existing, target);
    });
    if (it == addresses.end()) {
        throw std::runtime_error("address not found in wallet");
    }

    const auto index = static_cast<size_t>(std::distance(addresses.begin(), it));
    if (index == 0) {
        return;
    }

    auto rotate_primary = [index](auto& rows) {
        if (rows.size() > index) {
            std::rotate(rows.begin(), rows.begin() + static_cast<std::ptrdiff_t>(index), rows.begin() + static_cast<std::ptrdiff_t>(index + 1));
        }
    };
    rotate_primary(privkeys);
    rotate_primary(pubkeys);
    rotate_primary(addresses);
    sync_primary();
    save_encrypted(password, path);
}

std::string Wallet::import_private_key_hex(const std::string& password,
                                           const std::string& path,
                                           const std::string& private_key_hex,
                                           const std::string& label) {
    *this = Wallet::load(password, path);
    auto raw = crypto::hex_decode(private_key_hex);
    if (raw.size() != 32) {
        throw std::runtime_error("private key must be 32 bytes in hex");
    }

    std::array<uint8_t, 32> secret{};
    std::copy(raw.begin(), raw.end(), secret.begin());
    std::vector<uint8_t> imported_priv;
    std::vector<uint8_t> imported_pub;
    if (!keypair_from_secret(secret, imported_priv, imported_pub)) {
        throw std::runtime_error("invalid secp256k1 private key");
    }

    std::string imported_address = crypto::canonicalize_address(script::pubkey_to_address(imported_pub));
    for (const auto& existing : addresses) {
        if (crypto::addresses_equal(existing, imported_address)) {
            if (!label.empty()) {
                labels_[normalize_label_key(imported_address)] = label;
                save_encrypted(password, path);
            }
            return display_address(existing);
        }
    }

    append_key(imported_priv, imported_pub);
    if (!label.empty()) {
        labels_[normalize_label_key(imported_address)] = label;
    }
    save_encrypted(password, path);
    return display_address(imported_address);
}

void Wallet::change_password(const std::string& old_password,
                             const std::string& new_password,
                             const std::string& path,
                             KeyDerivation new_kdf) {
    if (new_password.empty()) {
        throw std::runtime_error("new password cannot be empty");
    }
    *this = Wallet::load(old_password, path);
    key_derivation_ = new_kdf;
    save_encrypted(new_password, path);
    reencrypt_wallet_chat_rsa_keys(path, old_password, new_password, *this);
}

void Wallet::ensure_unused_pool(Blockchain& chain,
                                const std::string& password,
                                const std::string& path,
                                uint32_t min_unused) {
    *this = Wallet::load(password, path);
    if (min_unused == 0) min_unused = 1;
    if (hd_scheme_ == HdScheme::None || master_seed_.empty()) {
        return;
    }

    size_t unused = count_unused_addresses(*this, chain);
    bool changed = false;
    while (unused < min_unused) {
        std::vector<uint8_t> new_priv;
        std::vector<uint8_t> new_pub;
        derive_wallet_keypair(hd_scheme_, master_seed_, next_hd_index_, new_priv, new_pub);
        next_hd_index_++;
        append_key(new_priv, new_pub);
        ++unused;
        changed = true;
    }
    if (!changed) return;
    save_encrypted(password, path);
}

std::string Wallet::unused_receive_address(Blockchain& chain,
                                           const std::string& password,
                                           const std::string& path,
                                           uint32_t min_unused) {
    ensure_unused_pool(chain, password, path, min_unused);
    if (addresses.size() > 1) {
        for (size_t i = 1; i < addresses.size(); ++i) {
            if (!address_has_chain_activity(addresses[i], chain)) {
                return display_address(addresses[i]);
            }
        }
    }
    if (auto candidate = first_unused_wallet_address(*this, chain)) {
        return display_address(*candidate);
    }
    return display_address(address);
}

size_t Wallet::rescan(Blockchain& chain,
                      const std::string& password,
                      const std::string& path,
                      uint32_t gap_limit) {
    *this = Wallet::load(password, path);
    if (hd_scheme_ == HdScheme::None || master_seed_.empty()) {
        throw std::runtime_error("wallet is not HD-backed");
    }
    if (gap_limit == 0) gap_limit = 1;

    size_t original_count = addresses.size();
    uint32_t target_index = std::max<uint32_t>(next_hd_index_, static_cast<uint32_t>(addresses.size()));
    uint32_t highest_used_index = 0;
    uint32_t trailing_unused = 0;
    bool found_used = false;
    uint32_t index = 0;

    while (index < target_index || trailing_unused < gap_limit) {
        std::vector<uint8_t> derived_priv;
        std::vector<uint8_t> derived_pub;
        derive_wallet_keypair(hd_scheme_, master_seed_, index, derived_priv, derived_pub);
        std::string derived_address = script::pubkey_to_address(derived_pub);

        if (index >= addresses.size()) {
            append_key(derived_priv, derived_pub);
        }

        if (address_has_chain_activity(derived_address, chain)) {
            highest_used_index = index;
            found_used = true;
            trailing_unused = 0;
            target_index = std::max<uint32_t>(target_index, highest_used_index + gap_limit + 1);
        } else {
            ++trailing_unused;
        }
        ++index;
    }

    (void)found_used;
    next_hd_index_ = static_cast<uint32_t>(addresses.size());

    save_encrypted(password, path);
    return addresses.size() - original_count;
}

Wallet::BalanceSummary Wallet::balance_summary(Blockchain& chain) const {
    BalanceSummary summary;
    summary.approved = chain.wallet_state_approved();
    uint32_t current_height = static_cast<uint32_t>(chain.best_height());
    for (const auto& addr : addresses) {
        auto all_outputs = chain.utxo().list_for_address(addr, current_height, true);
        for (const auto& [outpoint, entry] : all_outputs) {
            (void)outpoint;
            if (!summary.approved) {
                summary.locked += entry.output.value;
            } else if (entry.is_coinbase &&
                       static_cast<uint64_t>(current_height) + 1 <
                           static_cast<uint64_t>(entry.block_height) + constants::COINBASE_MATURITY) {
                summary.immature += entry.output.value;
            } else {
                summary.spendable += entry.output.value;
            }
        }
    }
    return summary;
}

std::vector<std::string> Wallet::history(Blockchain& chain, bool include_mempool) const {
    auto detailed = history_entries(chain, include_mempool);
    std::vector<std::string> entries;
    int64_t balance = 0;
    for (const auto& entry : detailed) {
        balance += entry.net_sats;
        std::ostringstream ss;
        ss << (entry.in_mempool ? "Mempool" : ("H" + std::to_string(entry.block_height.value_or(0))))
           << " " << entry.direction
           << " net=" << entry.net_sats
           << " (" << format_wallet_amount(entry.net_sats) << ")"
           << " txid=" << entry.txid;
        if (!entry.summary_address.empty()) {
            ss << " counterparty=" << entry.summary_address;
        }
        if (entry.fee_sats > 0) {
            ss << " fee=" << entry.fee_sats;
        }
        entries.push_back(ss.str());
    }
    entries.push_back("Balance: " + std::to_string(balance));
    return entries;
}

std::vector<Wallet::HistoryEntry> Wallet::history_entries(Blockchain& chain, bool include_mempool) const {
    std::vector<HistoryEntry> entries;
    std::unordered_map<OutPoint, UTXOEntry> seen_outputs;
    auto owned = owned_address_set(*this);

    auto make_entry = [&](const Transaction& tx,
                          std::optional<uint64_t> block_height,
                          uint64_t timestamp,
                          bool in_mempool) -> std::optional<HistoryEntry> {
        int64_t total_input_value = 0;
        int64_t owned_input_value = 0;
        int64_t owned_output_value = 0;
        std::vector<std::string> from_addresses;
        std::vector<std::string> to_addresses;
        bool any_owned_input = false;
        bool any_owned_output = false;
        bool has_external_output = false;

        for (const auto& in : tx.inputs) {
            auto it = seen_outputs.find(in.prevout);
            if (it == seen_outputs.end()) continue;
            total_input_value += it->second.output.value;
            from_addresses.push_back(it->second.output.scriptPubKey);
            auto canonical = try_canonical_address(it->second.output.scriptPubKey);
            if (canonical && owned.count(*canonical)) {
                any_owned_input = true;
                owned_input_value += it->second.output.value;
            }
        }

        for (const auto& out : tx.outputs) {
            to_addresses.push_back(out.scriptPubKey);
            auto canonical = try_canonical_address(out.scriptPubKey);
            if (canonical && owned.count(*canonical)) {
                any_owned_output = true;
                owned_output_value += out.value;
            } else if (out.scriptPubKey.rfind("OP_RETURN:", 0) != 0) {
                has_external_output = true;
            }
        }

        if (!any_owned_input && !any_owned_output) {
            return std::nullopt;
        }

        HistoryEntry entry;
        entry.txid = tx.hash().to_hex();
        entry.from_addresses = dedupe_preserving_order(from_addresses);
        entry.to_addresses = dedupe_preserving_order(to_addresses);
        entry.received_sats = owned_output_value;
        entry.sent_sats = owned_input_value;
        entry.fee_sats = (!tx.is_coinbase() && total_input_value >= tx.total_output_value())
            ? (total_input_value - tx.total_output_value())
            : 0;
        entry.net_sats = owned_output_value - owned_input_value;
        entry.timestamp = timestamp;
        entry.block_height = block_height;
        entry.confirmations = block_height ? (chain.best_height() >= *block_height ? chain.best_height() - *block_height + 1 : 0) : 0;
        entry.coinbase = tx.is_coinbase();
        entry.in_mempool = in_mempool;

        if (tx.is_coinbase() && any_owned_output) {
            entry.direction = "mined";
        } else if (any_owned_input && has_external_output) {
            entry.direction = "sent";
        } else if (any_owned_input && any_owned_output) {
            entry.direction = "self";
        } else {
            entry.direction = "received";
        }

        if (entry.direction == "sent" || entry.direction == "self") {
            for (const auto& addr : entry.to_addresses) {
                auto canonical = try_canonical_address(addr);
                if (!canonical || !owned.count(*canonical)) {
                    entry.summary_address = addr;
                    break;
                }
            }
        }
        if (entry.summary_address.empty()) {
            for (const auto& addr : entry.to_addresses) {
                auto canonical = try_canonical_address(addr);
                if (canonical && owned.count(*canonical)) {
                    entry.summary_address = addr;
                    break;
                }
            }
        }
        if (entry.summary_address.empty() && !entry.from_addresses.empty()) {
            entry.summary_address = entry.from_addresses.front();
        }

        auto label = label_for(entry.summary_address);
        if (!label.empty()) {
            entry.summary_address = label + " <" + entry.summary_address + ">";
        }
        return entry;
    };

    for (uint64_t h = 0; h <= chain.best_height(); ++h) {
        auto blk = chain.get_block(h);
        if (!blk) continue;
        for (const auto& tx : blk->transactions) {
            if (auto entry = make_entry(tx, h, blk->header.timestamp, false)) {
                entries.push_back(*entry);
            }
            for (size_t i = 0; i < tx.outputs.size(); ++i) {
                seen_outputs[OutPoint{tx.hash(), static_cast<uint32_t>(i)}] =
                    UTXOEntry{tx.outputs[i], static_cast<uint32_t>(h), tx.is_coinbase()};
            }
        }
    }
    if (include_mempool) {
        auto txs = chain.mempool().get_transactions();
        for (const auto& tx : txs) {
            if (auto entry = make_entry(tx, std::nullopt, static_cast<uint64_t>(std::time(nullptr)), true)) {
                entries.push_back(*entry);
            }
            for (size_t i = 0; i < tx.outputs.size(); ++i) {
                seen_outputs[OutPoint{tx.hash(), static_cast<uint32_t>(i)}] =
                    UTXOEntry{tx.outputs[i], static_cast<uint32_t>(chain.best_height() + 1), tx.is_coinbase()};
            }
        }
    }

    std::sort(entries.begin(), entries.end(), [](const HistoryEntry& a, const HistoryEntry& b) {
        if (a.in_mempool != b.in_mempool) return a.in_mempool > b.in_mempool;
        if (a.block_height != b.block_height) return a.block_height.value_or(UINT64_MAX) > b.block_height.value_or(UINT64_MAX);
        return a.timestamp > b.timestamp;
    });
    return entries;
}

std::optional<Wallet::HistoryEntry> Wallet::transaction_detail(Blockchain& chain,
                                                               const std::string& txid_hex,
                                                               bool include_mempool) const {
    for (const auto& entry : history_entries(chain, include_mempool)) {
        if (entry.txid == txid_hex) {
            return entry;
        }
    }
    return std::nullopt;
}

} // namespace cryptex
