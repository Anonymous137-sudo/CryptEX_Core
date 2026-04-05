#pragma once

#include "network.hpp"
#include "wallet.hpp"
#include <string>

namespace cryptex {
namespace chat {

constexpr uint8_t CHAT_FLAG_SIGNED = 0x01;
constexpr uint8_t CHAT_FLAG_ENCRYPTED = 0x02;

struct ParsedMessage {
    bool legacy{false};
    bool authenticated{false};
    bool encrypted{false};
    bool decrypted{false};
    std::string sender_address;
    std::string recipient_address;
    std::string channel;
    std::string message;
    uint64_t timestamp{0};
    uint64_t nonce{0};
    std::string message_id;
};

net::ChatPayload make_signed_public_chat(const Wallet& wallet,
                                         const std::string& sender_address,
                                         const std::string& channel,
                                         const std::string& message);

net::ChatPayload make_encrypted_private_chat(const Wallet& wallet,
                                             const std::string& sender_address,
                                             const std::string& recipient_address,
                                             const std::vector<uint8_t>& recipient_pubkey,
                                             const std::string& message);

std::string message_id(const net::ChatPayload& payload);

ParsedMessage parse_chat_payload(const net::ChatPayload& payload,
                                 const Wallet* wallet = nullptr);

} // namespace chat
} // namespace cryptex
