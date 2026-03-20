#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace cryptex {

std::string ConfigFile::trim(const std::string& value) {
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(start, end - start);
}

std::string ConfigFile::normalize_key(std::string key) {
    key = trim(key);
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        if (c == '.' || c == '-') return '_';
        return static_cast<char>(std::tolower(c));
    });
    return key;
}

ConfigFile ConfigFile::load(const std::filesystem::path& path, bool allow_missing) {
    ConfigFile config;
    config.source_path_ = path;
    std::ifstream in(path);
    if (!in) {
        if (allow_missing) {
            return config;
        }
        throw std::runtime_error("failed to open config file: " + path.string());
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    config = parse(buffer.str());
    config.source_path_ = path;
    return config;
}

ConfigFile ConfigFile::parse(const std::string& text) {
    ConfigFile config;
    std::istringstream in(text);
    std::string raw_line;
    size_t line_no = 0;
    while (std::getline(in, raw_line)) {
        ++line_no;
        auto line = trim(raw_line);
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        auto pos = line.find('=');
        if (pos == std::string::npos) {
            throw std::runtime_error("invalid config line " + std::to_string(line_no));
        }
        auto key = normalize_key(line.substr(0, pos));
        auto value = trim(line.substr(pos + 1));
        if (key.empty()) {
            throw std::runtime_error("empty config key on line " + std::to_string(line_no));
        }
        if (value.size() >= 2 &&
            ((value.front() == '"' && value.back() == '"') ||
             (value.front() == '\'' && value.back() == '\''))) {
            value = value.substr(1, value.size() - 2);
        }
        config.values_[key].push_back(value);
    }
    return config;
}

bool ConfigFile::contains(const std::string& key) const {
    return values_.count(normalize_key(key)) > 0;
}

std::optional<std::string> ConfigFile::get_string(const std::string& key) const {
    auto it = values_.find(normalize_key(key));
    if (it == values_.end() || it->second.empty()) {
        return std::nullopt;
    }
    return it->second.back();
}

std::vector<std::string> ConfigFile::get_all(const std::string& key) const {
    auto it = values_.find(normalize_key(key));
    if (it == values_.end()) {
        return {};
    }
    return it->second;
}

std::optional<bool> ConfigFile::get_bool(const std::string& key) const {
    auto value = get_string(key);
    if (!value) {
        return std::nullopt;
    }
    std::string lowered = *value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (lowered == "1" || lowered == "true" || lowered == "yes" || lowered == "on") return true;
    if (lowered == "0" || lowered == "false" || lowered == "no" || lowered == "off") return false;
    throw std::runtime_error("invalid boolean value for config key: " + normalize_key(key));
}

std::optional<int64_t> ConfigFile::get_i64(const std::string& key) const {
    auto value = get_string(key);
    if (!value) {
        return std::nullopt;
    }
    size_t idx = 0;
    auto parsed = std::stoll(*value, &idx, 10);
    if (idx != value->size()) {
        throw std::runtime_error("invalid integer value for config key: " + normalize_key(key));
    }
    return static_cast<int64_t>(parsed);
}

std::optional<uint64_t> ConfigFile::get_u64(const std::string& key) const {
    auto value = get_string(key);
    if (!value) {
        return std::nullopt;
    }
    size_t idx = 0;
    auto parsed = std::stoull(*value, &idx, 10);
    if (idx != value->size()) {
        throw std::runtime_error("invalid unsigned value for config key: " + normalize_key(key));
    }
    return static_cast<uint64_t>(parsed);
}

std::optional<unsigned int> ConfigFile::get_uint(const std::string& key) const {
    auto value = get_u64(key);
    if (!value) {
        return std::nullopt;
    }
    return static_cast<unsigned int>(*value);
}

} // namespace cryptex
