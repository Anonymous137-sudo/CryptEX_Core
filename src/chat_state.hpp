#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace cryptex {
namespace chatstate {

struct PrivateContact {
    std::string label;
    std::string address;
    std::string pubkey_b64;
    std::string rsa_pubkey_pem;
    std::string peer_label;
    std::string notes;
    uint64_t added_at{0};
    uint64_t last_used_at{0};
};

struct ProxyConfig {
    bool enabled{false};
    std::string host;
    uint16_t port{0};
    bool remote_dns{true};
};

struct IrcConfig {
    bool enabled{false};
    std::string server;
    uint16_t port{6667};
    std::string nick{"cryptex"};
    std::string username{"cryptex"};
    std::string realname{"CryptEX"};
    std::string channel{"#cryptex"};
    bool use_tls{false};
};

struct IrcLogEntry {
    uint64_t timestamp{0};
    std::string direction;
    std::string server;
    std::string channel;
    std::string nick;
    std::string message;
    std::string status;
};

std::vector<PrivateContact> load_private_contacts(const std::filesystem::path& path);
void save_private_contacts(const std::filesystem::path& path, const std::vector<PrivateContact>& contacts);

ProxyConfig load_proxy_config(const std::filesystem::path& path);
void save_proxy_config(const std::filesystem::path& path, const ProxyConfig& config);

IrcConfig load_irc_config(const std::filesystem::path& path);
void save_irc_config(const std::filesystem::path& path, const IrcConfig& config);

std::vector<IrcLogEntry> load_irc_log(const std::filesystem::path& path, size_t limit = 100);
void append_irc_log(const std::filesystem::path& path, const IrcLogEntry& entry);

} // namespace chatstate
} // namespace cryptex
