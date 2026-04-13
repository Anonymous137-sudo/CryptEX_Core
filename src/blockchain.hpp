#pragma once

#include "block_store.hpp"
#include "chainparams.hpp"
#include "mempool.hpp"
#include "utxo.hpp"
#include <unordered_map>
#include <map>
#include <filesystem>
#include <optional>
#include <utility>

namespace cryptex {

class Blockchain {
public:
    struct SyncApprovalState {
        bool approved{true};
        uint64_t height{0};
        uint256_t tip{};
        uint64_t peer_count{0};
        uint64_t network_height{0};
    };

    struct CheckpointInfo {
        bool present{false};
        bool pinned{false};
        uint64_t height{0};
        uint256_t hash{};
    };

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
    bool wallet_state_approved() const;
    uint64_t approval_peer_count() const;
    uint64_t approval_network_height() const;
    CheckpointInfo checkpoint_info() const;
    uint64_t max_reorg_depth_limit() const;
    bool deep_reorgs_allowed() const;
    void pin_checkpoint_to_tip();
    void clear_checkpoint_pin();
    void refresh_checkpoint_now();
    std::optional<SyncApprovalState> sync_approval_state() const { return sync_approval_; }
    void set_sync_approval(bool approved, uint64_t peer_count = 0, uint64_t network_height = 0);

private:
    void ensure_genesis();
    uint256_t block_work(uint32_t bits) const;
    bool build_path_to_genesis(const uint256_t& tip, std::vector<uint256_t>& out_path) const;
    size_t validated_prefix_length(const std::vector<uint256_t>& path,
                                   UTXOSet& out_utxo,
                                   uint32_t& out_tip_bits,
                                   bool skip_pow_check,
                                   bool log_failures,
                                   std::string* failure_reason = nullptr,
                                   uint64_t* failure_height = nullptr) const;
    bool validate_path(const std::vector<uint256_t>& path, UTXOSet& out_utxo, uint32_t& out_tip_bits, bool skip_pow_check);
    bool activate_path(const std::vector<uint256_t>& path, UTXOSet& new_utxo, uint32_t new_tip_bits);
    void purge_cached_subtree(const uint256_t& root);
    uint32_t expected_bits(uint64_t height, uint32_t candidate_timestamp) const;
    uint32_t expected_bits_for(const std::map<uint64_t, uint256_t>& hmap,
                               const std::unordered_map<uint256_t, BlockHeader>& idx,
                               uint64_t height,
                               uint32_t candidate_timestamp) const;
    std::optional<uint256_t> canonical_block_id_for(const uint256_t& hash) const;
    std::filesystem::path chainstate_path() const;
    std::filesystem::path local_checkpoint_path() const;
    std::filesystem::path manual_checkpoint_path() const;
    bool load_chainstate_snapshot();
    bool load_local_checkpoint();
    bool load_manual_checkpoint();
    void persist_chainstate() const;
    void persist_local_checkpoint() const;
    void persist_manual_checkpoint() const;
    void save_index() const;
    void load_index();
    void persist_headers() const;
    void load_headers();
    void rebuild_from_blocks();
    void rebuild_utxo_from_active_chain();
    void rebuild_known_block_state();
    bool repair_active_chain_if_needed();
    bool repair_height_files_from_active_index_if_needed();
    bool clear_stale_local_checkpoint_if_needed();
    void refresh_local_checkpoint();
    bool candidate_matches_local_checkpoint(const std::vector<uint256_t>& path) const;
    bool active_chain_matches_local_checkpoint() const;
    std::filesystem::path sync_approval_path() const;
    bool load_sync_approval();
    void persist_sync_approval() const;

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
    std::optional<std::pair<uint64_t, uint256_t>> local_checkpoint_;
    bool manual_checkpoint_pinned_{false};
    std::optional<SyncApprovalState> sync_approval_;
};

} // namespace cryptex
