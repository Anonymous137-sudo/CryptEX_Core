#include "debug.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>

namespace cryptex {

namespace {

std::mutex g_log_mutex;
LogConfig g_log_config;
std::set<std::string> g_subsystems;
std::ofstream g_log_file;
std::atomic<bool> g_debug_flag{false};

std::string lowercase(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

std::string normalize_subsystem(std::string_view subsystem) {
    return lowercase(std::string(subsystem));
}

std::string iso8601_utc_now() {
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

std::string json_escape(std::string_view input) {
    std::string out;
    out.reserve(input.size() + 8);
    for (char c : input) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                std::ostringstream hex;
                hex << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(c));
                out += hex.str();
            } else {
                out.push_back(c);
            }
        }
    }
    return out;
}

bool level_enabled(LogLevel wanted, LogLevel minimum) {
    return static_cast<int>(wanted) >= static_cast<int>(minimum);
}

} // namespace

void configure_logging(const LogConfig& config) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_config = config;
    g_subsystems.clear();
    for (const auto& subsystem : config.subsystems) {
        auto normalized = normalize_subsystem(subsystem);
        if (!normalized.empty()) {
            g_subsystems.insert(normalized);
        }
    }

    g_log_file.close();
    if (!config.file_path.empty()) {
        if (config.file_path.has_parent_path()) {
            std::filesystem::create_directories(config.file_path.parent_path());
        }
        g_log_file.open(config.file_path, std::ios::app);
        if (!g_log_file) {
            throw std::runtime_error("failed to open log file: " + config.file_path.string());
        }
    }
}

const LogConfig& current_log_config() {
    return g_log_config;
}

void flush_logs() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file.is_open()) {
        g_log_file.flush();
    }
    std::cerr.flush();
}

std::optional<LogLevel> parse_log_level(const std::string& text) {
    auto level = lowercase(text);
    if (level == "trace") return LogLevel::Trace;
    if (level == "debug") return LogLevel::Debug;
    if (level == "info") return LogLevel::Info;
    if (level == "warn" || level == "warning") return LogLevel::Warn;
    if (level == "error") return LogLevel::Error;
    return std::nullopt;
}

std::string log_level_name(LogLevel level) {
    switch (level) {
    case LogLevel::Trace: return "trace";
    case LogLevel::Debug: return "debug";
    case LogLevel::Info: return "info";
    case LogLevel::Warn: return "warn";
    case LogLevel::Error: return "error";
    }
    return "info";
}

void set_debug(bool enabled) {
    g_debug_flag.store(enabled, std::memory_order_relaxed);
    if (enabled && static_cast<int>(g_log_config.level) > static_cast<int>(LogLevel::Debug)) {
        LogConfig updated = g_log_config;
        updated.level = LogLevel::Debug;
        configure_logging(updated);
    }
}

bool debug_enabled() {
    return g_debug_flag.load(std::memory_order_relaxed) ||
           static_cast<int>(g_log_config.level) <= static_cast<int>(LogLevel::Debug);
}

bool should_log(LogLevel level, std::string_view subsystem) {
    if (!level_enabled(level, g_log_config.level)) {
        return false;
    }
    if (g_subsystems.empty()) {
        return true;
    }
    return g_subsystems.count(normalize_subsystem(subsystem)) > 0;
}

void log_message(LogLevel level, std::string_view subsystem, const std::string& message) {
    if (!should_log(level, subsystem)) {
        return;
    }

    const auto ts = iso8601_utc_now();
    const auto level_name = log_level_name(level);
    const auto subsystem_name = normalize_subsystem(subsystem);

    std::ostringstream line;
    if (g_log_config.json) {
        line << "{\"ts\":\"" << json_escape(ts)
             << "\",\"level\":\"" << json_escape(level_name)
             << "\",\"subsystem\":\"" << json_escape(subsystem_name)
             << "\",\"msg\":\"" << json_escape(message) << "\"}";
    } else {
        line << ts
             << " level=" << level_name
             << " subsystem=" << subsystem_name
             << " msg=\"" << json_escape(message) << "\"";
    }

    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_config.console) {
        std::cerr << line.str() << '\n';
    }
    if (g_log_file.is_open()) {
        g_log_file << line.str() << '\n';
        g_log_file.flush();
    }
}

} // namespace cryptex
