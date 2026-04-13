#pragma once

#include "block.hpp"
#include <filesystem>
#include <optional>

namespace cryptex {

class BlockStore {
public:
    explicit BlockStore(const std::filesystem::path& data_dir);
    std::filesystem::path base_dir() const { return dir_; }
    bool store(uint64_t height, const Block& block);
    bool store_by_hash(const uint256_t& hash, const Block& block);
    void remove_height(uint64_t height);
    void remove_by_hash(const uint256_t& hash);
    void prune_height_files_after(uint64_t height);
    std::optional<Block> load(uint64_t height) const;
    std::optional<Block> load_by_hash(const uint256_t& hash) const;
    bool exists(uint64_t height) const;
    bool exists_by_hash(const uint256_t& hash) const;
private:
    bool write_block_file(const std::filesystem::path& path, const Block& block) const;
    std::optional<Block> load_block_file(const std::filesystem::path& primary,
                                         const std::optional<std::filesystem::path>& fallback = std::nullopt) const;
    std::filesystem::path block_path_for_height(uint64_t height) const;
    std::filesystem::path legacy_block_path_for_height(uint64_t height) const;
    std::filesystem::path block_path_for_hash(const uint256_t& hash) const;
    std::filesystem::path dir_;
};

} // namespace cryptex
