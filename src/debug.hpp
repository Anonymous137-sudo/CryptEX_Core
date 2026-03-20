#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace cryptex {

enum class LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
};

struct LogConfig {
    LogLevel level{LogLevel::Info};
    bool console{true};
    bool json{false};
    std::filesystem::path file_path;
    std::vector<std::string> subsystems;
};

void configure_logging(const LogConfig& config);
const LogConfig& current_log_config();
void flush_logs();

std::optional<LogLevel> parse_log_level(const std::string& text);
std::string log_level_name(LogLevel level);

void set_debug(bool enabled);
bool debug_enabled();
bool should_log(LogLevel level, std::string_view subsystem = {});
void log_message(LogLevel level, std::string_view subsystem, const std::string& message);

inline void log_trace(std::string_view subsystem, const std::string& message) {
    log_message(LogLevel::Trace, subsystem, message);
}

inline void log_debug(std::string_view subsystem, const std::string& message) {
    log_message(LogLevel::Debug, subsystem, message);
}

inline void log_info(std::string_view subsystem, const std::string& message) {
    log_message(LogLevel::Info, subsystem, message);
}

inline void log_warn(std::string_view subsystem, const std::string& message) {
    log_message(LogLevel::Warn, subsystem, message);
}

inline void log_error(std::string_view subsystem, const std::string& message) {
    log_message(LogLevel::Error, subsystem, message);
}

} // namespace cryptex
