#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace cryptex {
namespace chat {

struct HistoryEntry {
    uint32_t version{1};
    std::string direction; // "in" or "out"
    bool legacy{false};
    bool authenticated{false};
    bool encrypted{false};
    bool decrypted{false};
    bool is_private{false};
    uint64_t timestamp{0};
    uint64_t nonce{0};
    std::string message_id;
    std::string sender_address;
    std::string sender_pubkey;
    std::string recipient_address;
    std::string recipient_pubkey;
    std::string channel;
    std::string message;
    std::string peer_label;
    std::string status;
};

struct HistoryQuery {
    size_t limit{50};
    std::optional<uint64_t> since_timestamp;
    std::optional<std::string> channel;
    std::optional<std::string> address;
    std::optional<std::string> direction;
    std::optional<bool> private_only;
};

void append_history_entry(const std::filesystem::path& path, const HistoryEntry& entry);
std::vector<HistoryEntry> load_history(const std::filesystem::path& path, const HistoryQuery& query = {});
size_t history_count(const std::filesystem::path& path);
std::string describe_history_entry(const HistoryEntry& entry);

} // namespace chat
} // namespace cryptex
