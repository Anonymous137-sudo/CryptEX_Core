#pragma once

#include "chat_content.hpp"
#include "network.hpp"
#include "wallet.hpp"
#include <string>

namespace cryptex {
namespace chat {

constexpr uint8_t CHAT_FLAG_SIGNED = 0x01;
constexpr uint8_t CHAT_FLAG_ENCRYPTED = 0x02;
constexpr uint8_t CHAT_TYPE_PUBLIC = 0;
constexpr uint8_t CHAT_TYPE_PRIVATE = 1;
constexpr uint8_t CHAT_TYPE_VOICE_CONTROL = 2;
constexpr uint8_t CHAT_TYPE_VOICE_FRAME = 3;

enum class KeyDerivation : uint8_t {
    LegacySha3 = 0,
    PBKDF2 = 1,
    Scrypt = 2,
    Argon2id = 3,
};

enum class EncryptionMode : uint8_t {
    ECDH = 0,
    RSA = 1,
};

struct ParsedMessage {
    bool legacy{false};
    bool authenticated{false};
    bool encrypted{false};
    bool decrypted{false};
    EncryptionMode encryption_mode{EncryptionMode::ECDH};
    std::string sender_address;
    std::string recipient_address;
    std::string channel;
    std::string message;
    uint64_t timestamp{0};
    uint64_t nonce{0};
    std::string message_id;
    ContentEnvelope content;
};

net::ChatPayload make_signed_public_chat(const Wallet& wallet,
                                         const std::string& sender_address,
                                         const std::string& channel,
                                         const ContentEnvelope& content);

net::ChatPayload make_signed_public_chat(const Wallet& wallet,
                                         const std::string& sender_address,
                                         const std::string& channel,
                                         const std::string& message);

net::ChatPayload make_signed_transport_chat(const Wallet& wallet,
                                            const std::string& sender_address,
                                            const std::string& recipient_address,
                                            const std::vector<uint8_t>& recipient_pubkey,
                                            const ContentEnvelope& content,
                                            uint8_t chat_type);

net::ChatPayload make_encrypted_private_chat(const Wallet& wallet,
                                             const std::string& sender_address,
                                             const std::string& recipient_address,
                                             const std::vector<uint8_t>& recipient_pubkey,
                                             const ContentEnvelope& content,
                                             KeyDerivation kdf = KeyDerivation::Argon2id,
                                             EncryptionMode mode = EncryptionMode::ECDH,
                                             const std::string& recipient_rsa_public_pem = {},
                                             uint8_t chat_type = CHAT_TYPE_PRIVATE);

net::ChatPayload make_encrypted_private_chat(const Wallet& wallet,
                                             const std::string& sender_address,
                                             const std::string& recipient_address,
                                             const std::vector<uint8_t>& recipient_pubkey,
                                             const std::string& message,
                                             KeyDerivation kdf = KeyDerivation::Argon2id);

std::string message_id(const net::ChatPayload& payload);
const char* kdf_name(KeyDerivation kdf);
std::optional<KeyDerivation> parse_kdf(const std::string& text);
const char* encryption_mode_name(EncryptionMode mode);
std::optional<EncryptionMode> parse_encryption_mode(const std::string& text);

ParsedMessage parse_chat_payload(const net::ChatPayload& payload,
                                 const Wallet* wallet = nullptr);

} // namespace chat
} // namespace cryptex
