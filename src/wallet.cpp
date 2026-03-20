#include "wallet.hpp"
#include "bip39.hpp"
#include "serialization.hpp"
#include "blockchain.hpp"
#include "debug.hpp"
#include "base64.hpp"
#include "sha3_512.hpp"
#include <filesystem>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <array>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

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

static std::vector<uint8_t> derive_key(const std::string& password, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(constants::AES_KEY_SIZE);
    if (1 != PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                               salt.data(), static_cast<int>(salt.size()),
                               constants::PBKDF2_ITERATIONS,
                               EVP_sha256(), key.size(), key.data())) {
        throw std::runtime_error("PBKDF2 failed");
    }
    return key;
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
    addresses.push_back(script::pubkey_to_address(pub));
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

std::vector<uint8_t> Wallet::serialize_plaintext() const {
    std::vector<uint8_t> out;
    serialization::write_int<uint32_t>(out, 5);
    serialization::write_int<uint32_t>(out, static_cast<uint32_t>(hd_scheme_));
    serialization::write_int<uint32_t>(out, next_hd_index_);
    serialization::write_bytes(out, mnemonic_entropy_.data(), mnemonic_entropy_.size());
    serialization::write_bytes(out, master_seed_.data(), master_seed_.size());
    serialization::write_varint(out, privkeys.size());
    for (const auto& key : privkeys) {
        serialization::write_bytes(out, key.data(), key.size());
    }
    return out;
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
        if (version == 5) {
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
        w.addresses.push_back(script::pubkey_to_address(pub));
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

Wallet Wallet::create_new(const std::string& password,
                          const std::string& path,
                          size_t mnemonic_words,
                          const std::string& mnemonic_passphrase) {
    Wallet w;
    w.hd_scheme_ = HdScheme::Bip32;
    w.mnemonic_entropy_.resize(bip39::entropy_bytes_for_words(mnemonic_words));
    fill_random(w.mnemonic_entropy_);
    auto mnemonic = bip39::entropy_to_mnemonic(w.mnemonic_entropy_);
    w.master_seed_ = bip39::mnemonic_to_seed(mnemonic, mnemonic_passphrase);
    std::vector<uint8_t> new_priv;
    std::vector<uint8_t> new_pub;
    derive_wallet_keypair(w.hd_scheme_, w.master_seed_, w.next_hd_index_, new_priv, new_pub);
    w.next_hd_index_++;
    w.append_key(new_priv, new_pub);

    std::vector<uint8_t> salt(constants::AES_IV_SIZE);
    std::vector<uint8_t> iv(constants::AES_IV_SIZE);
    fill_random(salt);
    fill_random(iv);
    auto key = derive_key(password, salt);
    auto ciphertext = aes_encrypt(w.serialize_plaintext(), key, iv);
    persist(path, salt, iv, ciphertext);
    return w;
}

Wallet Wallet::create_from_mnemonic(const std::string& password,
                                    const std::string& path,
                                    const std::string& mnemonic,
                                    const std::string& mnemonic_passphrase) {
    Wallet w;
    w.hd_scheme_ = HdScheme::Bip32;
    w.mnemonic_entropy_ = bip39::mnemonic_to_entropy(mnemonic);
    auto canonical_mnemonic = bip39::entropy_to_mnemonic(w.mnemonic_entropy_);
    w.master_seed_ = bip39::mnemonic_to_seed(canonical_mnemonic, mnemonic_passphrase);

    std::vector<uint8_t> new_priv;
    std::vector<uint8_t> new_pub;
    derive_wallet_keypair(w.hd_scheme_, w.master_seed_, w.next_hd_index_, new_priv, new_pub);
    w.next_hd_index_++;
    w.append_key(new_priv, new_pub);

    std::vector<uint8_t> salt(constants::AES_IV_SIZE);
    std::vector<uint8_t> iv(constants::AES_IV_SIZE);
    fill_random(salt);
    fill_random(iv);
    auto key = derive_key(password, salt);
    auto ciphertext = aes_encrypt(w.serialize_plaintext(), key, iv);
    persist(path, salt, iv, ciphertext);
    return w;
}

Wallet Wallet::load(const std::string& password, const std::string& path) {
    std::vector<uint8_t> salt, iv, ciphertext;
    read_file(path, salt, iv, ciphertext);
    auto key = derive_key(password, salt);
    auto plaintext = aes_decrypt(ciphertext, key, iv);
    return deserialize_plaintext(plaintext);
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

    std::vector<uint8_t> salt(constants::AES_IV_SIZE);
    std::vector<uint8_t> iv(constants::AES_IV_SIZE);
    fill_random(salt);
    fill_random(iv);
    auto key = derive_key(password, salt);
    auto ciphertext = aes_encrypt(serialize_plaintext(), key, iv);
    persist(path, salt, iv, ciphertext);
    return addresses.back();
}

void Wallet::persist(const std::string& path,
                     const std::vector<uint8_t>& salt,
                     const std::vector<uint8_t>& iv,
                     const std::vector<uint8_t>& ciphertext) {
    std::filesystem::path wallet_path(path);
    if (wallet_path.has_parent_path()) {
        std::filesystem::create_directories(wallet_path.parent_path());
    }
    std::vector<uint8_t> out;
    serialization::write_int<uint32_t>(out, 1); // version
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), iv.begin(), iv.end());
    serialization::write_int<uint32_t>(out, static_cast<uint32_t>(ciphertext.size()));
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("failed to open wallet file for writing");
    f.write(reinterpret_cast<const char*>(out.data()), out.size());
    if (!f) throw std::runtime_error("failed to write wallet file");
}

void Wallet::read_file(const std::string& path,
                       std::vector<uint8_t>& salt,
                       std::vector<uint8_t>& iv,
                       std::vector<uint8_t>& ciphertext) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("wallet file not found");
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    const uint8_t* ptr = data.data();
    size_t rem = data.size();
    uint32_t version = serialization::read_int<uint32_t>(ptr, rem);
    if (version != 1) throw std::runtime_error("wallet version unsupported");
    if (rem < constants::AES_IV_SIZE * 2 + 4) throw std::runtime_error("wallet truncated");
    salt.assign(ptr, ptr + constants::AES_IV_SIZE);
    ptr += constants::AES_IV_SIZE; rem -= constants::AES_IV_SIZE;
    iv.assign(ptr, ptr + constants::AES_IV_SIZE);
    ptr += constants::AES_IV_SIZE; rem -= constants::AES_IV_SIZE;
    uint32_t clen = serialization::read_int<uint32_t>(ptr, rem);
    if (rem < clen) throw std::runtime_error("wallet ciphertext truncated");
    ciphertext.assign(ptr, ptr + clen);
}

Transaction Wallet::create_payment(Blockchain& chain,
                                   const std::string& to_address,
                                   int64_t amount_sats,
                                   const std::string& op_return_msg,
                                   int64_t fee_per_kb) const {
    if (amount_sats <= 0) throw std::runtime_error("amount must be positive");
    std::string canonical_to;
    try {
        canonical_to = crypto::canonicalize_address(to_address);
    } catch (...) {
        throw std::runtime_error("invalid destination address format");
    }
    auto utxos = list_unspent(chain);
    int64_t total = 0;
    std::vector<std::pair<OutPoint, UTXOEntry>> selected;
    for (const auto& u : utxos) {
        selected.push_back(u);
        total += u.second.output.value;
        if (total >= amount_sats) break;
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
            change_out.scriptPubKey = address;
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

    std::vector<uint8_t> salt(constants::AES_IV_SIZE);
    std::vector<uint8_t> iv(constants::AES_IV_SIZE);
    fill_random(salt);
    fill_random(iv);
    auto key = derive_key(password, salt);
    auto ciphertext = aes_encrypt(serialize_plaintext(), key, iv);
    persist(path, salt, iv, ciphertext);
    return addresses.size() - original_count;
}

Wallet::BalanceSummary Wallet::balance_summary(Blockchain& chain) const {
    BalanceSummary summary;
    uint32_t current_height = static_cast<uint32_t>(chain.best_height());
    for (const auto& addr : addresses) {
        auto spendable = chain.utxo().list_for_address(addr, current_height);
        for (const auto& [outpoint, entry] : spendable) {
            (void)outpoint;
            summary.spendable += entry.output.value;
        }
        auto all_outputs = chain.utxo().list_for_address(addr, current_height, true);
        for (const auto& [outpoint, entry] : all_outputs) {
            (void)outpoint;
            if (entry.is_coinbase && current_height + 1 < entry.block_height + constants::COINBASE_MATURITY) {
                summary.immature += entry.output.value;
            }
        }
    }
    return summary;
}

std::vector<std::string> Wallet::history(Blockchain& chain, bool include_mempool) const {
    std::vector<std::string> entries;
    int64_t balance = 0;
    std::unordered_map<OutPoint, TxOut> seen_outputs;
    auto owned = owned_address_set(*this);
    for (uint64_t h = 0; h <= chain.best_height(); ++h) {
        auto blk = chain.get_block(h);
        if (!blk) continue;
        for (const auto& tx : blk->transactions) {
            // outputs
            for (size_t i = 0; i < tx.outputs.size(); ++i) {
                const auto& o = tx.outputs[i];
                OutPoint op{tx.hash(), static_cast<uint32_t>(i)};
                seen_outputs[op] = o;
                auto canonical = try_canonical_address(o.scriptPubKey);
                if (canonical && owned.count(*canonical)) {
                    balance += o.value;
                    entries.push_back("H" + std::to_string(h) + " + " + std::to_string(o.value) + " -> " + o.scriptPubKey);
                }
            }
            // inputs spending ours
            for (const auto& in : tx.inputs) {
                auto it = seen_outputs.find(in.prevout);
                auto canonical = (it != seen_outputs.end()) ? try_canonical_address(it->second.scriptPubKey)
                                                            : std::nullopt;
                if (it != seen_outputs.end() && canonical && owned.count(*canonical)) {
                    balance -= it->second.value;
                    entries.push_back("H" + std::to_string(h) + " - " + std::to_string(it->second.value) + " <- " + it->second.scriptPubKey);
                }
            }
        }
    }
    if (include_mempool) {
        auto txs = chain.mempool().get_transactions();
        for (const auto& tx : txs) {
            for (size_t i = 0; i < tx.outputs.size(); ++i) {
                const auto& o = tx.outputs[i];
                auto canonical = try_canonical_address(o.scriptPubKey);
                if (canonical && owned.count(*canonical)) {
                    entries.push_back("Mempool + " + std::to_string(o.value) + " -> " + o.scriptPubKey);
                }
            }
            for (const auto& in : tx.inputs) {
                auto it = seen_outputs.find(in.prevout);
                auto canonical = (it != seen_outputs.end()) ? try_canonical_address(it->second.scriptPubKey)
                                                            : std::nullopt;
                if (it != seen_outputs.end() && canonical && owned.count(*canonical)) {
                    entries.push_back("Mempool - " + std::to_string(it->second.value) + " <- " + it->second.scriptPubKey);
                }
            }
        }
    }
    entries.push_back("Balance: " + std::to_string(balance));
    return entries;
}

} // namespace cryptex
