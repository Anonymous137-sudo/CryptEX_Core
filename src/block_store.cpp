#include "block_store.hpp"
#include "chainparams.hpp"
#include "serialization.hpp"
#include <fstream>
#include <vector>

namespace cryptex {

BlockStore::BlockStore(const std::filesystem::path& data_dir) : dir_(data_dir) {
    std::filesystem::create_directories(dir_ / "blocks");
    std::filesystem::create_directories(dir_ / "blocks-by-hash");
}

bool BlockStore::store(uint64_t height, const Block& block) {
    return write_block_file(block_path_for_height(height), block);
}

bool BlockStore::store_by_hash(const uint256_t& hash, const Block& block) {
    return write_block_file(block_path_for_hash(hash), block);
}

std::optional<Block> BlockStore::load(uint64_t height) const {
    return load_block_file(block_path_for_height(height), legacy_block_path_for_height(height));
}

std::optional<Block> BlockStore::load_by_hash(const uint256_t& hash) const {
    return load_block_file(block_path_for_hash(hash));
}

bool BlockStore::exists(uint64_t height) const {
    return std::filesystem::exists(block_path_for_height(height)) ||
           std::filesystem::exists(legacy_block_path_for_height(height));
}

bool BlockStore::exists_by_hash(const uint256_t& hash) const {
    return std::filesystem::exists(block_path_for_hash(hash));
}

bool BlockStore::write_block_file(const std::filesystem::path& path, const Block& block) const {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    auto ser = block.serialize();
    uint32_t magic = message_magic();
    f.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    uint64_t len = ser.size();
    f.write(reinterpret_cast<const char*>(&len), sizeof(len));
    f.write(reinterpret_cast<const char*>(ser.data()), ser.size());
    return static_cast<bool>(f);
}

std::optional<Block> BlockStore::load_block_file(const std::filesystem::path& primary,
                                                 const std::optional<std::filesystem::path>& fallback) const {
    std::ifstream f(primary, std::ios::binary);
    if (!f && fallback) f.open(*fallback, std::ios::binary);
    if (!f) return std::nullopt;
    uint32_t magic;
    uint64_t len;
    f.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    f.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (magic != message_magic()) return std::nullopt;
    std::vector<uint8_t> data(len);
    f.read(reinterpret_cast<char*>(data.data()), len);
    const uint8_t* ptr = data.data();
    size_t rem = data.size();
    Block blk = Block::deserialize(ptr, rem);
    return blk;
}

std::filesystem::path BlockStore::block_path_for_height(uint64_t height) const {
    return dir_ / "blocks" / ("blk" + std::to_string(height) + ".dat");
}

std::filesystem::path BlockStore::legacy_block_path_for_height(uint64_t height) const {
    return dir_ / "blocks" / (std::to_string(height) + ".dat");
}

std::filesystem::path BlockStore::block_path_for_hash(const uint256_t& hash) const {
    return dir_ / "blocks-by-hash" / (hash.to_hex_padded(constants::POW_HASH_BYTES) + ".dat");
}

} // namespace cryptex
