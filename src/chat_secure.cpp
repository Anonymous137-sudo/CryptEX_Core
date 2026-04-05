#include "chat_secure.hpp"

#include "base64.hpp"
#include "debug.hpp"
#include "script.hpp"
#include "serialization.hpp"
#include "sha3_512.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

namespace cryptex {
namespace chat {

namespace {

constexpr int64_t MAX_CHAT_AGE_SECONDS = 24 * 60 * 60;
constexpr int64_t MAX_CHAT_FUTURE_SKEW_SECONDS = 5 * 60;
constexpr size_t CHAT_IV_BYTES = 12;
constexpr size_t CHAT_KEY_BYTES = 32;
constexpr size_t CHAT_TAG_BYTES = 16;

int64_t now_seconds() {
    return static_cast<int64_t>(std::time(nullptr));
}

uint64_t random_nonce64() {
    uint64_t value = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
        throw std::runtime_error("chat nonce generation failed");
    }
    return value;
}

std::vector<uint8_t> random_bytes(size_t size) {
    std::vector<uint8_t> out(size);
    if (!out.empty() && RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("chat random generation failed");
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

std::string hex_encode(const hash512_t& hash) {
    return hex_encode(hash.data(), hash.size());
}

std::array<uint8_t, 32> digest32(const std::vector<uint8_t>& bytes) {
    auto digest = crypto::sha3_512(bytes);
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), digest.data(), out.size());
    return out;
}

std::vector<uint8_t> sign_blob(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& privkey) {
    return script::sign_hash(uint256_t(digest32(bytes)), privkey);
}

bool verify_blob(const std::vector<uint8_t>& bytes,
                 const std::vector<uint8_t>& signature,
                 const std::vector<uint8_t>& pubkey) {
    return script::verify_signature(uint256_t(digest32(bytes)), signature, pubkey);
}

std::optional<size_t> wallet_index_for_address(const Wallet& wallet, const std::string& address) {
    for (size_t i = 0; i < wallet.addresses.size(); ++i) {
        if (crypto::addresses_equal(wallet.addresses[i], address)) {
            return i;
        }
    }
    return std::nullopt;
}

std::optional<size_t> wallet_index_for_pubkey(const Wallet& wallet, const std::vector<uint8_t>& pubkey) {
    for (size_t i = 0; i < wallet.pubkeys.size(); ++i) {
        if (wallet.pubkeys[i] == pubkey) {
            return i;
        }
    }
    return std::nullopt;
}

size_t resolve_sender_index(const Wallet& wallet, const std::string& sender_address) {
    if (!sender_address.empty()) {
        if (auto idx = wallet_index_for_address(wallet, sender_address)) {
            return *idx;
        }
        throw std::runtime_error("sender address not found in wallet");
    }
    if (wallet.addresses.empty() || wallet.pubkeys.empty() || wallet.privkeys.empty()) {
        throw std::runtime_error("wallet has no keys for chat");
    }
    return 0;
}

EVP_PKEY* load_private_key(const std::vector<uint8_t>& privkey) {
    const unsigned char* der_ptr = privkey.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &der_ptr, privkey.size());
    if (!pkey) throw std::runtime_error("chat private key decode failed");
    return pkey;
}

EVP_PKEY* load_public_key(const std::vector<uint8_t>& pubkey) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!kctx) throw std::runtime_error("chat public key context failed");
    if (EVP_PKEY_fromdata_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("chat public key init failed");
    }
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 const_cast<char*>("secp256k1"),
                                                 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  const_cast<uint8_t*>(pubkey.data()),
                                                  pubkey.size());
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0 || !pkey) {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("chat public key decode failed");
    }
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

std::vector<uint8_t> derive_shared_secret(const std::vector<uint8_t>& local_privkey,
                                          const std::vector<uint8_t>& peer_pubkey) {
    EVP_PKEY* self = load_private_key(local_privkey);
    EVP_PKEY* peer = load_public_key(peer_pubkey);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(self, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer);
        EVP_PKEY_free(self);
        throw std::runtime_error("ECDH context init failed");
    }
    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        EVP_PKEY_free(self);
        throw std::runtime_error("ECDH derive init failed");
    }
    size_t out_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &out_len) <= 0 || out_len == 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        EVP_PKEY_free(self);
        throw std::runtime_error("ECDH size failed");
    }
    std::vector<uint8_t> secret(out_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &out_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        EVP_PKEY_free(self);
        throw std::runtime_error("ECDH derive failed");
    }
    secret.resize(out_len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(self);
    return secret;
}

std::vector<uint8_t> build_chat_aad(const net::ChatPayload& payload) {
    std::vector<uint8_t> out;
    out.push_back(payload.version);
    out.push_back(payload.chat_type);
    out.push_back(payload.flags);
    serialization::write_int<uint64_t>(out, payload.timestamp);
    serialization::write_int<uint64_t>(out, payload.nonce);
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(payload.sender.data()),
                               payload.sender.size());
    serialization::write_bytes(out, payload.sender_pubkey.data(), payload.sender_pubkey.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(payload.channel.data()),
                               payload.channel.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(payload.recipient.data()),
                               payload.recipient.size());
    serialization::write_bytes(out, payload.recipient_pubkey.data(), payload.recipient_pubkey.size());
    return out;
}

std::vector<uint8_t> build_signature_payload(const net::ChatPayload& payload) {
    auto out = build_chat_aad(payload);
    serialization::write_bytes(out, payload.iv.data(), payload.iv.size());
    serialization::write_bytes(out, payload.body.data(), payload.body.size());
    serialization::write_bytes(out, payload.auth_tag.data(), payload.auth_tag.size());
    return out;
}

std::array<uint8_t, CHAT_KEY_BYTES> derive_chat_key(const std::vector<uint8_t>& shared_secret,
                                                    const net::ChatPayload& payload) {
    std::vector<uint8_t> material = build_chat_aad(payload);
    material.insert(material.end(), shared_secret.begin(), shared_secret.end());
    auto digest = crypto::sha3_512(material);
    std::array<uint8_t, CHAT_KEY_BYTES> key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

void aes256_gcm_encrypt(const std::vector<uint8_t>& plaintext,
                        const std::array<uint8_t, CHAT_KEY_BYTES>& key,
                        const std::vector<uint8_t>& aad,
                        std::vector<uint8_t>& iv,
                        std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& tag) {
    iv = random_bytes(CHAT_IV_BYTES);
    ciphertext.assign(plaintext.size(), 0);
    tag.assign(CHAT_TAG_BYTES, 0);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("chat encrypt ctx failed");
    int len = 0;
    int written = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat encrypt init failed");
    }
    if (!aad.empty() && EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat encrypt aad failed");
    }
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx, ciphertext.data(), &written, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat encrypt failed");
    }
    len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + written, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat encrypt final failed");
    }
    ciphertext.resize(static_cast<size_t>(written + len));
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat encrypt tag failed");
    }
    EVP_CIPHER_CTX_free(ctx);
}

std::string aes256_gcm_decrypt(const std::vector<uint8_t>& ciphertext,
                               const std::array<uint8_t, CHAT_KEY_BYTES>& key,
                               const std::vector<uint8_t>& aad,
                               const std::vector<uint8_t>& iv,
                               const std::vector<uint8_t>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("chat decrypt ctx failed");
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat decrypt init failed");
    }
    int len = 0;
    int written = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat decrypt aad failed");
    }
    std::vector<uint8_t> plaintext(ciphertext.size());
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &written, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat decrypt failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat decrypt tag set failed");
    }
    len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + written, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("chat authentication failed");
    }
    plaintext.resize(static_cast<size_t>(written + len));
    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

std::string payload_message_id(const net::ChatPayload& payload) {
    auto digest = crypto::sha3_512(payload.serialize());
    return hex_encode(digest);
}

void validate_common_payload(const net::ChatPayload& payload) {
    if (payload.version < 2) return;
    if ((payload.flags & CHAT_FLAG_SIGNED) == 0) {
        throw std::runtime_error("secure chat payload missing signature flag");
    }
    if (payload.sender.empty() || payload.sender_pubkey.empty() || payload.signature.empty()) {
        throw std::runtime_error("secure chat payload missing sender identity");
    }
    if (!script::check_address(payload.sender, payload.sender_pubkey)) {
        throw std::runtime_error("chat sender address/pubkey mismatch");
    }
    auto now = now_seconds();
    if (payload.timestamp == 0 ||
        static_cast<int64_t>(payload.timestamp) > now + MAX_CHAT_FUTURE_SKEW_SECONDS ||
        static_cast<int64_t>(payload.timestamp) + MAX_CHAT_AGE_SECONDS < now) {
        throw std::runtime_error("chat payload timestamp outside allowed window");
    }
    if (!verify_blob(build_signature_payload(payload), payload.signature, payload.sender_pubkey)) {
        throw std::runtime_error("chat signature verification failed");
    }
    if (payload.chat_type == 1) {
        if ((payload.flags & CHAT_FLAG_ENCRYPTED) == 0) {
            throw std::runtime_error("private chat payload missing encryption flag");
        }
        if (payload.recipient.empty() || payload.recipient_pubkey.empty() || payload.iv.empty() || payload.auth_tag.empty()) {
            throw std::runtime_error("private chat payload missing encryption metadata");
        }
        if (!script::check_address(payload.recipient, payload.recipient_pubkey)) {
            throw std::runtime_error("chat recipient address/pubkey mismatch");
        }
    }
}

} // namespace

net::ChatPayload make_signed_public_chat(const Wallet& wallet,
                                         const std::string& sender_address,
                                         const std::string& channel,
                                         const std::string& message) {
    size_t idx = resolve_sender_index(wallet, sender_address);
    net::ChatPayload payload;
    payload.version = 2;
    payload.chat_type = 0;
    payload.flags = CHAT_FLAG_SIGNED;
    payload.timestamp = static_cast<uint64_t>(now_seconds());
    payload.nonce = random_nonce64();
    payload.sender = wallet.addresses[idx];
    payload.sender_pubkey = wallet.pubkeys[idx];
    payload.channel = channel;
    payload.body.assign(message.begin(), message.end());
    payload.signature = sign_blob(build_signature_payload(payload), wallet.privkeys[idx]);
    return payload;
}

net::ChatPayload make_encrypted_private_chat(const Wallet& wallet,
                                             const std::string& sender_address,
                                             const std::string& recipient_address,
                                             const std::vector<uint8_t>& recipient_pubkey,
                                             const std::string& message) {
    if (recipient_pubkey.empty()) {
        throw std::runtime_error("private chat requires recipient public key");
    }
    if (!recipient_address.empty() && !script::check_address(recipient_address, recipient_pubkey)) {
        throw std::runtime_error("recipient address does not match recipient public key");
    }

    size_t idx = resolve_sender_index(wallet, sender_address);
    net::ChatPayload payload;
    payload.version = 2;
    payload.chat_type = 1;
    payload.flags = CHAT_FLAG_SIGNED | CHAT_FLAG_ENCRYPTED;
    payload.timestamp = static_cast<uint64_t>(now_seconds());
    payload.nonce = random_nonce64();
    payload.sender = wallet.addresses[idx];
    payload.sender_pubkey = wallet.pubkeys[idx];
    payload.recipient = recipient_address.empty() ? script::pubkey_to_address(recipient_pubkey) : recipient_address;
    payload.recipient_pubkey = recipient_pubkey;

    auto shared_secret = derive_shared_secret(wallet.privkeys[idx], recipient_pubkey);
    auto aad = build_chat_aad(payload);
    auto key = derive_chat_key(shared_secret, payload);
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    aes256_gcm_encrypt(plaintext, key, aad, payload.iv, payload.body, payload.auth_tag);
    payload.signature = sign_blob(build_signature_payload(payload), wallet.privkeys[idx]);
    return payload;
}

std::string message_id(const net::ChatPayload& payload) {
    return payload_message_id(payload);
}

ParsedMessage parse_chat_payload(const net::ChatPayload& payload, const Wallet* wallet) {
    ParsedMessage parsed;
    parsed.sender_address = payload.sender;
    parsed.recipient_address = payload.recipient;
    parsed.channel = payload.channel;
    parsed.timestamp = payload.timestamp;
    parsed.nonce = payload.nonce;
    parsed.message_id = payload_message_id(payload);

    if (payload.version < 2) {
        parsed.legacy = true;
        parsed.encrypted = false;
        parsed.message.assign(payload.body.begin(), payload.body.end());
        return parsed;
    }

    validate_common_payload(payload);
    parsed.authenticated = true;
    parsed.encrypted = (payload.flags & CHAT_FLAG_ENCRYPTED) != 0;

    if (!parsed.encrypted) {
        parsed.message.assign(payload.body.begin(), payload.body.end());
        return parsed;
    }

    if (!wallet) {
        parsed.message = "<encrypted message>";
        return parsed;
    }

    std::optional<size_t> recipient_idx = wallet_index_for_pubkey(*wallet, payload.recipient_pubkey);
    if (!recipient_idx) {
        recipient_idx = wallet_index_for_address(*wallet, payload.recipient);
    }
    if (!recipient_idx) {
        parsed.message = "<encrypted message>";
        return parsed;
    }

    auto shared_secret = derive_shared_secret(wallet->privkeys[*recipient_idx], payload.sender_pubkey);
    auto key = derive_chat_key(shared_secret, payload);
    parsed.message = aes256_gcm_decrypt(payload.body, key, build_chat_aad(payload), payload.iv, payload.auth_tag);
    parsed.decrypted = true;
    return parsed;
}

} // namespace chat
} // namespace cryptex
