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
    if (fields.size() != 18) return false;
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
        entry.message = decode_field(fields[15]);
        entry.peer_label = decode_field(fields[16]);
        entry.status = decode_field(fields[17]);
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
        << encode_field(entry.message) << '\t'
        << encode_field(entry.peer_label) << '\t'
        << encode_field(entry.status);
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

std::string describe_history_entry(const HistoryEntry& entry) {
    std::ostringstream out;
    out << "[" << format_timestamp(entry.timestamp) << "] "
        << entry.direction << " "
        << (entry.is_private ? "private" : "public");
    if (!entry.channel.empty()) out << " channel=" << entry.channel;
    if (!entry.sender_address.empty()) out << " from=" << entry.sender_address;
    if (!entry.recipient_address.empty()) out << " to=" << entry.recipient_address;
    if (!entry.status.empty()) out << " status=" << entry.status;
    if (entry.authenticated) out << " auth=ok";
    if (entry.encrypted) out << (entry.decrypted ? " encrypted=decrypted" : " encrypted=opaque");
    out << " id=" << entry.message_id;
    out << " msg=\"" << sanitize_message(entry.message) << "\"";
    return out.str();
}

} // namespace chat
} // namespace cryptex
