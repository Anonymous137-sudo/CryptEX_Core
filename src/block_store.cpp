#include "block_store.hpp"
#include "chainparams.hpp"
#include "serialization.hpp"
#include <fstream>
#include <vector>

namespace cryptex {

BlockStore::BlockStore(const std::filesystem::path& data_dir) : dir_(data_dir) {
    std::filesystem::create_directories(dir_ / "blocks");
}

bool BlockStore::store(uint64_t height, const Block& block) {
    auto path = dir_ / "blocks" / ("blk" + std::to_string(height) + ".dat");
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    auto ser = block.serialize();
    uint32_t magic = message_magic();
    f.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    uint64_t len = ser.size();
    f.write(reinterpret_cast<const char*>(&len), sizeof(len));
    f.write(reinterpret_cast<const char*>(ser.data()), ser.size());
    return true;
}

std::optional<Block> BlockStore::load(uint64_t height) const {
    auto path_new = dir_ / "blocks" / ("blk" + std::to_string(height) + ".dat");
    auto path_old = dir_ / "blocks" / (std::to_string(height) + ".dat");
    std::ifstream f(path_new, std::ios::binary);
    if (!f) f.open(path_old, std::ios::binary); // backward compatibility
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

bool BlockStore::exists(uint64_t height) const {
    auto path_new = dir_ / "blocks" / ("blk" + std::to_string(height) + ".dat");
    auto path_old = dir_ / "blocks" / (std::to_string(height) + ".dat");
    return std::filesystem::exists(path_new) || std::filesystem::exists(path_old);
}

} // namespace cryptex
