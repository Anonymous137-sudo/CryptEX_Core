#include "chat_history.hpp"

#include "base64.hpp"

#include <algorithm>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace cryptex {
namespace chat {

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

std::string bool_field(bool value) {
    return value ? "1" : "0";
}

bool parse_bool_field(const std::string& value) {
    return value == "1";
}

std::string format_timestamp(uint64_t timestamp) {
    std::time_t tt = static_cast<std::time_t>(timestamp);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S UTC");
    return out.str();
}

std::string sanitize_message(std::string message) {
    for (char& c : message) {
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    return message;
}

bool address_matches(const std::string& filter, const std::string& candidate) {
    if (filter.empty()) return true;
    if (candidate.empty()) return false;
    return crypto::addresses_equal(filter, candidate) || filter == candidate;
}

bool matches_query(const HistoryEntry& entry, const HistoryQuery& query) {
    if (query.since_timestamp && entry.timestamp < *query.since_timestamp) return false;
    if (query.channel && entry.channel != *query.channel) return false;
    if (query.direction && entry.direction != *query.direction) return false;
    if (query.private_only && entry.is_private != *query.private_only) return false;
    if (query.address &&
        !address_matches(*query.address, entry.sender_address) &&
        !address_matches(*query.address, entry.recipient_address)) {
        return false;
    }
    return true;
}

bool parse_history_entry(const std::string& line, HistoryEntry& entry) {
    auto fields = split_line(line);
    if (fields.size() != 18 && fields.size() != 25 && fields.size() != 26 && fields.size() != 27 && fields.size() != 30) return false;
    try {
        entry.version = static_cast<uint32_t>(std::stoul(fields[0]));
        entry.direction = fields[1];
        entry.is_private = parse_bool_field(fields[2]);
        entry.legacy = parse_bool_field(fields[3]);
        entry.authenticated = parse_bool_field(fields[4]);
        entry.encrypted = parse_bool_field(fields[5]);
        entry.decrypted = parse_bool_field(fields[6]);
        entry.timestamp = std::stoull(fields[7]);
        entry.nonce = std::stoull(fields[8]);
        entry.message_id = fields[9];
        entry.sender_address = decode_field(fields[10]);
        entry.sender_pubkey = decode_field(fields[11]);
        entry.recipient_address = decode_field(fields[12]);
        entry.recipient_pubkey = decode_field(fields[13]);
        entry.channel = decode_field(fields[14]);
        if (fields.size() >= 27) {
            entry.subject = decode_field(fields[15]);
            if (fields.size() >= 30) {
                entry.mail_to = decode_field(fields[16]);
                entry.mail_cc = decode_field(fields[17]);
                entry.mail_bcc = decode_field(fields[18]);
                entry.message = decode_field(fields[19]);
                entry.peer_label = decode_field(fields[20]);
                entry.status = decode_field(fields[21]);
            } else {
                entry.message = decode_field(fields[16]);
                entry.peer_label = decode_field(fields[17]);
                entry.status = decode_field(fields[18]);
            }
        } else {
            entry.message = decode_field(fields[15]);
            entry.peer_label = decode_field(fields[16]);
            entry.status = decode_field(fields[17]);
        }
        if (fields.size() >= 25) {
            const size_t offset = fields.size() >= 30 ? 4 : (fields.size() >= 27 ? 1 : 0);
            entry.content_type = decode_field(fields[18 + offset]);
            entry.mime_type = decode_field(fields[19 + offset]);
            entry.attachment_name = decode_field(fields[20 + offset]);
            entry.attachment_path = decode_field(fields[21 + offset]);
            entry.attachment_size = std::stoull(fields[22 + offset]);
            entry.audio_privacy = decode_field(fields[23 + offset]);
            entry.encryption_mode = decode_field(fields[24 + offset]);
            if (fields.size() >= 26 + offset) {
                entry.transcript = decode_field(fields[25 + offset]);
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

std::string serialize_history_entry(const HistoryEntry& entry) {
    std::ostringstream out;
    out << entry.version << '\t'
        << entry.direction << '\t'
        << bool_field(entry.is_private) << '\t'
        << bool_field(entry.legacy) << '\t'
        << bool_field(entry.authenticated) << '\t'
        << bool_field(entry.encrypted) << '\t'
        << bool_field(entry.decrypted) << '\t'
        << entry.timestamp << '\t'
        << entry.nonce << '\t'
        << entry.message_id << '\t'
        << encode_field(entry.sender_address) << '\t'
        << encode_field(entry.sender_pubkey) << '\t'
        << encode_field(entry.recipient_address) << '\t'
        << encode_field(entry.recipient_pubkey) << '\t'
        << encode_field(entry.channel) << '\t'
        << encode_field(entry.subject) << '\t'
        << encode_field(entry.mail_to) << '\t'
        << encode_field(entry.mail_cc) << '\t'
        << encode_field(entry.mail_bcc) << '\t'
        << encode_field(entry.message) << '\t'
        << encode_field(entry.peer_label) << '\t'
        << encode_field(entry.status) << '\t'
        << encode_field(entry.content_type) << '\t'
        << encode_field(entry.mime_type) << '\t'
        << encode_field(entry.attachment_name) << '\t'
        << encode_field(entry.attachment_path) << '\t'
        << entry.attachment_size << '\t'
        << encode_field(entry.audio_privacy) << '\t'
        << encode_field(entry.encryption_mode) << '\t'
        << encode_field(entry.transcript);
    return out.str();
}

} // namespace

void append_history_entry(const std::filesystem::path& path, const HistoryEntry& entry) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream out(path, std::ios::app);
    if (!out) {
        throw std::runtime_error("failed to open chat history file for append");
    }
    out << serialize_history_entry(entry) << '\n';
}

std::vector<HistoryEntry> load_history(const std::filesystem::path& path, const HistoryQuery& query) {
    std::ifstream in(path);
    if (!in) return {};

    std::vector<HistoryEntry> entries;
    std::string line;
    while (std::getline(in, line)) {
        HistoryEntry entry;
        if (!parse_history_entry(line, entry)) continue;
        if (!matches_query(entry, query)) continue;
        entries.push_back(std::move(entry));
    }

    std::sort(entries.begin(), entries.end(), [](const HistoryEntry& a, const HistoryEntry& b) {
        if (a.timestamp != b.timestamp) return a.timestamp < b.timestamp;
        return a.message_id < b.message_id;
    });

    if (query.limit > 0 && entries.size() > query.limit) {
        entries.erase(entries.begin(), entries.end() - static_cast<std::ptrdiff_t>(query.limit));
    }
    return entries;
}

size_t history_count(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) return 0;

    size_t count = 0;
    std::string line;
    while (std::getline(in, line)) {
        HistoryEntry entry;
        if (parse_history_entry(line, entry)) ++count;
    }
    return count;
}

bool delete_history_entry(const std::filesystem::path& path, const std::string& message_id) {
    if (message_id.empty()) return false;

    std::ifstream in(path);
    if (!in) return false;

    std::vector<std::string> kept_lines;
    kept_lines.reserve(128);
    bool removed = false;
    std::string line;
    while (std::getline(in, line)) {
        HistoryEntry entry;
        if (!parse_history_entry(line, entry)) {
            kept_lines.push_back(line);
            continue;
        }
        if (entry.message_id == message_id) {
            removed = true;
            continue;
        }
        kept_lines.push_back(line);
    }

    if (!removed) {
        return false;
    }

    const auto tmp_path = path.string() + ".tmp";
    {
        std::ofstream out(tmp_path, std::ios::trunc);
        if (!out) {
            throw std::runtime_error("failed to open temporary chat history file for rewrite");
        }
        for (const auto& kept : kept_lines) {
            out << kept << '\n';
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmp_path, path, ec);
    if (!ec) {
        return true;
    }

    std::filesystem::copy_file(tmp_path, path, std::filesystem::copy_options::overwrite_existing, ec);
    std::filesystem::remove(tmp_path, ec);
    if (ec) {
        throw std::runtime_error("failed to rewrite chat history file: " + ec.message());
    }
    return true;
}

std::string describe_history_entry(const HistoryEntry& entry) {
    std::ostringstream out;
    out << "[" << format_timestamp(entry.timestamp) << "] "
        << entry.direction << " "
        << (entry.is_private ? "private" : "public");
    if (!entry.channel.empty()) out << " channel=" << entry.channel;
    if (!entry.sender_address.empty()) out << " from=" << entry.sender_address;
    if (!entry.recipient_address.empty()) out << " to=" << entry.recipient_address;
    if (!entry.subject.empty()) out << " subject=\"" << sanitize_message(entry.subject) << "\"";
    if (!entry.mail_cc.empty()) out << " cc=\"" << sanitize_message(entry.mail_cc) << "\"";
    if (!entry.mail_bcc.empty()) out << " bcc=\"" << sanitize_message(entry.mail_bcc) << "\"";
    if (!entry.status.empty()) out << " status=" << entry.status;
    if (entry.authenticated) out << " auth=ok";
    if (entry.encrypted) out << (entry.decrypted ? " encrypted=decrypted" : " encrypted=opaque");
    if (!entry.content_type.empty() && entry.content_type != "text") {
        out << " type=" << entry.content_type;
    }
    if (!entry.attachment_path.empty()) {
        out << " attachment=" << entry.attachment_path;
    }
    if (!entry.transcript.empty()) {
        out << " transcript=\"" << sanitize_message(entry.transcript) << "\"";
    }
    out << " id=" << entry.message_id;
    out << " msg=\"" << sanitize_message(entry.message) << "\"";
    return out.str();
}

} // namespace chat
} // namespace cryptex
