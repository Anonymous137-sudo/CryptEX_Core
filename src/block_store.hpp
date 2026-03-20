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
    std::optional<Block> load(uint64_t height) const;
    bool exists(uint64_t height) const;
private:
    std::filesystem::path dir_;
};

} // namespace cryptex
