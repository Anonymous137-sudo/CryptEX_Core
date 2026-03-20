#pragma once

#include "block_store.hpp"
#include "chainparams.hpp"
#include "mempool.hpp"
#include "utxo.hpp"
#include <unordered_map>
#include <map>
#include <filesystem>
#include <optional>

namespace cryptex {

class Blockchain {
public:
    explicit Blockchain(const std::filesystem::path& data_dir);

    uint64_t best_height() const { return best_height_; }
    uint256_t tip_hash() const { return tip_hash_; }
    uint32_t tip_bits() const { return tip_bits_; }

    bool connect_block(const Block& blk, bool skip_pow_check = false); // legacy direct-extend hook
    bool accept_block(const Block& blk, bool skip_pow_check = false);  // full fork-aware acceptance
    std::optional<Block> get_block(uint64_t height) const { return store_.load(height); }
    bool has_block(uint64_t height) const { return store_.exists(height); }
    std::optional<Block> get_block_by_hash(const uint256_t& hash) const;
    std::optional<BlockHeader> get_header_by_hash(const uint256_t& hash) const;
    std::optional<uint64_t> get_height_by_hash(const uint256_t& hash) const;
    bool knows_hash(const uint256_t& hash) const;
    std::vector<uint256_t> block_locator(size_t max_entries = 32) const;
    std::vector<BlockHeader> headers_after_locator(const std::vector<uint256_t>& locator_hashes,
                                                   size_t max_headers = 2000) const;
    uint32_t next_work_bits(uint32_t candidate_timestamp) const { return expected_bits(best_height_ + 1, candidate_timestamp); }

    UTXOSet& utxo() { return utxo_; }
    const UTXOSet& utxo() const { return utxo_; }
    Mempool& mempool() { return mempool_; }
    const Mempool& mempool() const { return mempool_; }

private:
    void ensure_genesis();
    uint256_t block_work(uint32_t bits) const;
    bool build_path_to_genesis(const uint256_t& tip, std::vector<uint256_t>& out_path) const;
    bool validate_path(const std::vector<uint256_t>& path, UTXOSet& out_utxo, uint32_t& out_tip_bits, bool skip_pow_check);
    bool activate_path(const std::vector<uint256_t>& path, UTXOSet& new_utxo, uint32_t new_tip_bits);
    uint32_t expected_bits(uint64_t height, uint32_t last_timestamp) const;
    uint32_t expected_bits_for(const std::map<uint64_t, uint256_t>& hmap,
                               const std::unordered_map<uint256_t, BlockHeader>& idx,
                               uint64_t height) const;
    std::optional<uint256_t> canonical_block_id_for(const uint256_t& hash) const;
    std::filesystem::path chainstate_path() const;
    bool load_chainstate_snapshot();
    void persist_chainstate() const;
    void save_index() const;
    void load_index();
    void persist_headers() const;
    void load_headers();
    void rebuild_from_blocks();
    void rebuild_utxo_from_active_chain();

    BlockStore store_;
    UTXOSet utxo_;
    Mempool mempool_;
    uint64_t best_height_{0};
    uint256_t tip_hash_{};
    uint32_t tip_bits_{pow_limit_bits()};
    std::map<uint64_t, uint256_t> height_map_;
    std::unordered_map<uint256_t, BlockHeader> index_;
    std::unordered_map<uint256_t, uint256_t> link_index_; // 256-bit header link hash -> canonical 512-bit block id
    std::unordered_map<uint256_t, uint64_t> height_index_; // active chain height lookup
    std::unordered_map<uint256_t, uint256_t> chain_work_;   // cumulative work per known header
    std::unordered_map<uint256_t, std::vector<uint256_t>> children_; // prev -> hashes
    std::unordered_map<uint256_t, Block> block_pool_; // all known blocks (main + side)
    // FIX: add map to store height for any block we know (including side chains)
    std::unordered_map<uint256_t, uint64_t> block_height_; // hash -> height for all known blocks
};

} // namespace cryptex
