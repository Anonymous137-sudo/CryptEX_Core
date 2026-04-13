#include "chat_state.hpp"

#include "base64.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <system_error>

namespace cryptex {
namespace chatstate {

namespace {

std::string encode_field(const std::string& value) {
    return crypto::base64_encode(value);
}

std::string decode_field(const std::string& value) {
    auto bytes = crypto::base64_decode(value);
    return std::string(bytes.begin(), bytes.end());
}

std::vector<std::string> split_line(const std::string& line) {
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        auto pos = line.find('\t', start);
        if (pos == std::string::npos) {
            out.push_back(line.substr(start));
            break;
        }
        out.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

bool parse_bool(const std::string& value) {
    return value == "1" || value == "true" || value == "yes";
}

std::string bool_field(bool value) {
    return value ? "1" : "0";
}

void ensure_parent_dir(const std::filesystem::path& path) {
    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
    }
}

std::string trim_copy(std::string value) {
    auto not_space = [](unsigned char ch) { return std::isspace(ch) == 0; };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
                value.end());
    return value;
}

std::vector<std::string> split_csv_values(const std::string& value) {
    std::vector<std::string> out;
    std::string current;
    std::istringstream input(value);
    while (std::getline(input, current, ',')) {
        current = trim_copy(current);
        if (!current.empty()) {
            out.push_back(current);
        }
    }
    return out;
}

std::string join_csv_values(const std::vector<std::string>& values) {
    std::ostringstream out;
    bool first = true;
    for (const auto& value : values) {
        const auto trimmed = trim_copy(value);
        if (trimmed.empty()) continue;
        if (!first) out << ',';
        out << trimmed;
        first = false;
    }
    return out.str();
}

std::vector<std::pair<std::string, std::string>> read_kv_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::vector<std::pair<std::string, std::string>> rows;
    std::string line;
    while (std::getline(input, line)) {
        const auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        rows.push_back({trim_copy(line.substr(0, pos)), trim_copy(line.substr(pos + 1))});
    }
    return rows;
}

void write_kv_file(const std::filesystem::path& path,
                   const std::vector<std::pair<std::string, std::string>>& rows) {
    ensure_parent_dir(path);
    std::ofstream output(path, std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to write config file");
    }
    for (const auto& [key, value] : rows) {
        output << key << '=' << value << '\n';
    }
}

} // namespace

std::vector<PrivateContact> load_private_contacts(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) return {};

    std::vector<PrivateContact> contacts;
    std::string line;
    while (std::getline(input, line)) {
        auto fields = split_line(line);
        if (fields.size() != 7 && fields.size() != 8) continue;
        try {
            PrivateContact contact;
            contact.label = decode_field(fields[0]);
            contact.address = decode_field(fields[1]);
            contact.pubkey_b64 = decode_field(fields[2]);
            if (fields.size() == 8) {
                contact.rsa_pubkey_pem = decode_field(fields[3]);
                contact.peer_label = decode_field(fields[4]);
                contact.notes = decode_field(fields[5]);
                contact.added_at = std::stoull(fields[6]);
                contact.last_used_at = std::stoull(fields[7]);
            } else {
                contact.peer_label = decode_field(fields[3]);
                contact.notes = decode_field(fields[4]);
                contact.added_at = std::stoull(fields[5]);
                contact.last_used_at = std::stoull(fields[6]);
            }
            contacts.push_back(std::move(contact));
        } catch (...) {
        }
    }
    return contacts;
}

void save_private_contacts(const std::filesystem::path& path, const std::vector<PrivateContact>& contacts) {
    ensure_parent_dir(path);
    std::ofstream output(path, std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to write private contacts");
    }
    for (const auto& contact : contacts) {
        output << encode_field(contact.label) << '\t'
               << encode_field(contact.address) << '\t'
               << encode_field(contact.pubkey_b64) << '\t'
               << encode_field(contact.rsa_pubkey_pem) << '\t'
               << encode_field(contact.peer_label) << '\t'
               << encode_field(contact.notes) << '\t'
               << contact.added_at << '\t'
               << contact.last_used_at << '\n';
    }
}

ProxyConfig load_proxy_config(const std::filesystem::path& path) {
    ProxyConfig config;
    for (const auto& [key, value] : read_kv_file(path)) {
        if (key == "enabled") config.enabled = parse_bool(value);
        else if (key == "host") config.host = value;
        else if (key == "port") config.port = static_cast<uint16_t>(std::stoul(value));
        else if (key == "remote_dns") config.remote_dns = parse_bool(value);
    }
    if (config.host.empty() || config.port == 0) {
        config.enabled = false;
    }
    return config;
}

void save_proxy_config(const std::filesystem::path& path, const ProxyConfig& config) {
    write_kv_file(path, {
        {"enabled", bool_field(config.enabled)},
        {"host", config.host},
        {"port", std::to_string(config.port)},
        {"remote_dns", bool_field(config.remote_dns)},
    });
}

IrcConfig load_irc_config(const std::filesystem::path& path) {
    IrcConfig config;
    for (const auto& [key, value] : read_kv_file(path)) {
        if (key == "enabled") config.enabled = parse_bool(value);
        else if (key == "server") config.server = value;
        else if (key == "port") config.port = static_cast<uint16_t>(std::stoul(value));
        else if (key == "nick") config.nick = value;
        else if (key == "username") config.username = value;
        else if (key == "realname") config.realname = value;
        else if (key == "channel") config.channel = value;
        else if (key == "use_tls") config.use_tls = parse_bool(value);
    }
    return config;
}

void save_irc_config(const std::filesystem::path& path, const IrcConfig& config) {
    write_kv_file(path, {
        {"enabled", bool_field(config.enabled)},
        {"server", config.server},
        {"port", std::to_string(config.port)},
        {"nick", config.nick},
        {"username", config.username},
        {"realname", config.realname},
        {"channel", config.channel},
        {"use_tls", bool_field(config.use_tls)},
    });
}

std::vector<IrcLogEntry> load_irc_log(const std::filesystem::path& path, size_t limit) {
    std::ifstream input(path);
    if (!input) return {};

    std::vector<IrcLogEntry> rows;
    std::string line;
    while (std::getline(input, line)) {
        auto fields = split_line(line);
        if (fields.size() != 7) continue;
        try {
            IrcLogEntry row;
            row.timestamp = std::stoull(fields[0]);
            row.direction = decode_field(fields[1]);
            row.server = decode_field(fields[2]);
            row.channel = decode_field(fields[3]);
            row.nick = decode_field(fields[4]);
            row.message = decode_field(fields[5]);
            row.status = decode_field(fields[6]);
            rows.push_back(std::move(row));
        } catch (...) {
        }
    }
    std::sort(rows.begin(), rows.end(), [](const IrcLogEntry& a, const IrcLogEntry& b) {
        return a.timestamp < b.timestamp;
    });
    if (limit > 0 && rows.size() > limit) {
        rows.erase(rows.begin(), rows.end() - static_cast<std::ptrdiff_t>(limit));
    }
    return rows;
}

void append_irc_log(const std::filesystem::path& path, const IrcLogEntry& entry) {
    ensure_parent_dir(path);
    std::ofstream output(path, std::ios::app);
    if (!output) {
        throw std::runtime_error("failed to append IRC log");
    }
    output << entry.timestamp << '\t'
           << encode_field(entry.direction) << '\t'
           << encode_field(entry.server) << '\t'
           << encode_field(entry.channel) << '\t'
           << encode_field(entry.nick) << '\t'
           << encode_field(entry.message) << '\t'
           << encode_field(entry.status) << '\n';
}

MailSecurityConfig load_mail_security_config(const std::filesystem::path& path) {
    MailSecurityConfig config;
    for (const auto& [key, value] : read_kv_file(path)) {
        if (key == "two_factor_enabled") config.two_factor_enabled = parse_bool(value);
        else if (key == "totp_secret_b32") config.totp_secret_b32 = value;
        else if (key == "issuer") config.issuer = value;
    }
    if (config.totp_secret_b32.empty()) {
        config.two_factor_enabled = false;
    }
    return config;
}

void save_mail_security_config(const std::filesystem::path& path, const MailSecurityConfig& config) {
    write_kv_file(path, {
        {"two_factor_enabled", bool_field(config.two_factor_enabled)},
        {"totp_secret_b32", config.totp_secret_b32},
        {"issuer", config.issuer},
    });
}

MailPolicyConfig load_mail_policy_config(const std::filesystem::path& path) {
    MailPolicyConfig config;
    for (const auto& [key, value] : read_kv_file(path)) {
        if (key == "ttl_hours") config.ttl_hours = static_cast<uint32_t>(std::stoul(value));
        else if (key == "replica_target") config.replica_target = static_cast<uint32_t>(std::stoul(value));
        else if (key == "max_store_items") config.max_store_items = static_cast<uint32_t>(std::stoul(value));
        else if (key == "prune_imported") config.prune_imported = parse_bool(value);
        else if (key == "prune_expired") config.prune_expired = parse_bool(value);
        else if (key == "proof_of_storage") config.proof_of_storage = parse_bool(value);
        else if (key == "challenge_interval_minutes") config.challenge_interval_minutes = static_cast<uint32_t>(std::stoul(value));
        else if (key == "minimum_bond_sats") config.minimum_bond_sats = static_cast<uint64_t>(std::stoull(value));
        else if (key == "required_verified_replicas") config.required_verified_replicas = static_cast<uint32_t>(std::stoul(value));
        else if (key == "slash_on_failed_proof") config.slash_on_failed_proof = parse_bool(value);
        else if (key == "slash_penalty_score") config.slash_penalty_score = static_cast<uint32_t>(std::stoul(value));
        else if (key == "nat_assist") config.nat_assist = parse_bool(value);
        else if (key == "relay_fallback") config.relay_fallback = parse_bool(value);
        else if (key == "relay_peers") config.relay_peers = split_csv_values(value);
        else if (key == "stun_servers") config.stun_servers = split_csv_values(value);
        else if (key == "stun_timeout_ms") config.stun_timeout_ms = static_cast<uint32_t>(std::stoul(value));
    }
    if (config.ttl_hours == 0) config.ttl_hours = 168;
    if (config.replica_target == 0) config.replica_target = 1;
    if (config.max_store_items == 0) config.max_store_items = 5000;
    if (config.challenge_interval_minutes == 0) config.challenge_interval_minutes = 30;
    if (config.required_verified_replicas == 0) config.required_verified_replicas = 1;
    if (config.slash_penalty_score == 0) config.slash_penalty_score = 25;
    if (config.stun_timeout_ms == 0) config.stun_timeout_ms = 1200;
    return config;
}

void save_mail_policy_config(const std::filesystem::path& path, const MailPolicyConfig& config) {
    write_kv_file(path, {
        {"ttl_hours", std::to_string(std::max<uint32_t>(config.ttl_hours, 1))},
        {"replica_target", std::to_string(std::max<uint32_t>(config.replica_target, 1))},
        {"max_store_items", std::to_string(std::max<uint32_t>(config.max_store_items, 1))},
        {"prune_imported", bool_field(config.prune_imported)},
        {"prune_expired", bool_field(config.prune_expired)},
        {"proof_of_storage", bool_field(config.proof_of_storage)},
        {"challenge_interval_minutes", std::to_string(std::max<uint32_t>(config.challenge_interval_minutes, 1))},
        {"minimum_bond_sats", std::to_string(config.minimum_bond_sats)},
        {"required_verified_replicas", std::to_string(std::max<uint32_t>(config.required_verified_replicas, 1))},
        {"slash_on_failed_proof", bool_field(config.slash_on_failed_proof)},
        {"slash_penalty_score", std::to_string(std::max<uint32_t>(config.slash_penalty_score, 1))},
        {"nat_assist", bool_field(config.nat_assist)},
        {"relay_fallback", bool_field(config.relay_fallback)},
        {"relay_peers", join_csv_values(config.relay_peers)},
        {"stun_servers", join_csv_values(config.stun_servers)},
        {"stun_timeout_ms", std::to_string(std::max<uint32_t>(config.stun_timeout_ms, 100))},
    });
}

} // namespace chatstate
} // namespace cryptex
