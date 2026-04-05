#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace cryptex {

class ConfigFile {
public:
    static ConfigFile load(const std::filesystem::path& path, bool allow_missing = true);
    static ConfigFile parse(const std::string& text);

    bool empty() const { return values_.empty(); }
    bool contains(const std::string& key) const;
    std::optional<std::string> get_string(const std::string& key) const;
    std::vector<std::string> get_all(const std::string& key) const;
    std::optional<bool> get_bool(const std::string& key) const;
    std::optional<int64_t> get_i64(const std::string& key) const;
    std::optional<uint64_t> get_u64(const std::string& key) const;
    std::optional<unsigned int> get_uint(const std::string& key) const;

    const std::filesystem::path& source_path() const { return source_path_; }

private:
    std::unordered_map<std::string, std::vector<std::string>> values_;
    std::filesystem::path source_path_;

    static std::string normalize_key(std::string key);
    static std::string trim(const std::string& value);
};

} // namespace cryptex
