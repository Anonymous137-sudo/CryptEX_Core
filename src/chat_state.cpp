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

} // namespace chatstate
} // namespace cryptex
