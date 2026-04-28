#include "blockchain.hpp"
#include "chainparams.hpp"
#include "debug.hpp"
#include <chrono>
#include "crc.hpp"
#include <unordered_set>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <cstdlib>
#include <sstream>

namespace cryptex {

namespace {

bool env_truthy(const char* value) {
    if (!value) return false;
    std::string normalized(value);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

uint64_t runtime_max_reorg_depth() {
    const char* raw = std::getenv("CRYPTEX_MAX_REORG_DEPTH");
    if (!raw || *raw == '\0') return constants::MAX_REORG_DEPTH;

    char* end = nullptr;
    unsigned long long parsed = std::strtoull(raw, &end, 10);
    if (end == raw || (end && *end != '\0')) {
        return constants::MAX_REORG_DEPTH;
    }
    return static_cast<uint64_t>(parsed);
}

bool allow_deep_reorg() {
    return env_truthy(std::getenv("CRYPTEX_ALLOW_DEEP_REORG"));
}

bool block_timestamp_too_far_in_future(uint32_t timestamp) {
    if (params().max_future_block_time_seconds == 0) return false;
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    return static_cast<uint64_t>(timestamp) > now + params().max_future_block_time_seconds;
}

bool block_timestamp_valid(const BlockHeader& header, const BlockHeader* parent) {
    if (block_timestamp_too_far_in_future(header.timestamp)) {
        return false;
    }
    if (parent && header.timestamp <= parent->timestamp) {
        return false;
    }
    return true;
}

uint64_t reorg_depth_from_candidate(const std::map<uint64_t, uint256_t>& active_height_map,
                                    uint64_t active_best_height,
                                    const std::vector<uint256_t>& candidate_path) {
    size_t shared_prefix = 0;
    const size_t active_size = static_cast<size_t>(active_best_height) + 1;
    const size_t limit = std::min(active_size, candidate_path.size());
    while (shared_prefix < limit) {
        auto it = active_height_map.find(static_cast<uint64_t>(shared_prefix));
        if (it == active_height_map.end() || it->second != candidate_path[shared_prefix]) break;
        ++shared_prefix;
    }
    if (shared_prefix >= active_size) return 0;
    return static_cast<uint64_t>(active_size - shared_prefix);
}

} // namespace

Blockchain::Blockchain(const std::filesystem::path& data_dir)
    : store_(data_dir) {
    load_index();
    load_headers();
    if (height_map_.empty() || index_.empty())
        rebuild_from_blocks();
    ensure_genesis();
    rebuild_known_block_state();
    load_local_checkpoint();
    load_manual_checkpoint();
    load_sync_approval();
    if (!load_chainstate_snapshot()) {
        rebuild_utxo_from_active_chain();
        persist_chainstate();
    }
    const bool repaired_active_chain = repair_active_chain_if_needed();
    const bool repaired_height_files = repair_height_files_from_active_index_if_needed();
    if (!active_chain_matches_local_checkpoint() &&
        (repaired_active_chain || clear_stale_local_checkpoint_if_needed())) {
        refresh_local_checkpoint();
    }
    if (!active_chain_matches_local_checkpoint()) {
        throw std::runtime_error("active chain violates local checkpoint");
    }
    refresh_local_checkpoint();
    if (!load_chainstate_snapshot()) {
        rebuild_utxo_from_active_chain();
        persist_chainstate();
    }
    if (repaired_height_files) {
        persist_chainstate();
    }
}

Blockchain::CheckpointInfo Blockchain::checkpoint_info() const {
    CheckpointInfo info;
    if (!local_checkpoint_) return info;
    info.present = true;
    info.pinned = manual_checkpoint_pinned_;
    info.height = local_checkpoint_->first;
    info.hash = local_checkpoint_->second;
    return info;
}

uint64_t Blockchain::max_reorg_depth_limit() const {
    return runtime_max_reorg_depth();
}

bool Blockchain::deep_reorgs_allowed() const {
    return allow_deep_reorg();
}

std::string Blockchain::diagnose_tip_candidate(const Block& blk, bool skip_pow_check) const {
    std::ostringstream reason;
    const uint64_t expected_height = best_height_ + 1;
    const auto prev = get_block(best_height_);
    const BlockHeader* parent_header = prev ? &prev->header : nullptr;
    const uint256_t expected_prev_link = parent_header ? parent_header->hash() : uint256_t();

    if (blk.header.prev_block_hash != expected_prev_link) {
        reason << "stale-prev-link expected=" << expected_prev_link.to_hex()
               << " have=" << blk.header.prev_block_hash.to_hex();
        return reason.str();
    }

    if (!skip_pow_check && blk.header.prev_block_hash != uint256_t()) {
        compact_target compact{blk.header.bits};
        if (!compact.is_canonical(constants::POW_HASH_BYTES)) {
            reason << "bits-encoding";
            return reason.str();
        }
        if (!blk.check_pow()) {
            reason << "pow";
            return reason.str();
        }
    }

    if (blk.compute_merkle_root() != blk.header.merkle_root) {
        reason << "merkle";
        return reason.str();
    }

    if (blk.transactions.size() > static_cast<size_t>(constants::MAX_TRANSACTIONS_PER_BLOCK)) {
        reason << "txcount";
        return reason.str();
    }

    const size_t block_size = blk.serialize().size();
    if (block_size > static_cast<size_t>(constants::MAX_BLOCK_SIZE_BYTES)) {
        reason << "size";
        return reason.str();
    }

    if (!block_timestamp_valid(blk.header, parent_header)) {
        reason << "timestamp candidate_ts=" << blk.header.timestamp
               << " parent_ts=" << (parent_header ? parent_header->timestamp : 0);
        return reason.str();
    }

    const uint32_t exp_bits = expected_bits(expected_height, blk.header.timestamp);
    if (blk.header.bits != exp_bits) {
        reason << "bits have=" << blk.header.bits
               << " expected=" << exp_bits;
        return reason.str();
    }

    if (blk.transactions.empty() || !blk.transactions[0].is_coinbase()) {
        reason << "coinbase-missing";
        return reason.str();
    }

    UTXOSet working = utxo_.snapshot();
    int64_t total_fees = 0;
    for (size_t tx_index = 0; tx_index < blk.transactions.size(); ++tx_index) {
        const auto& tx = blk.transactions[tx_index];
        int64_t fee = 0;
        if (!working.apply_transaction(tx, static_cast<uint32_t>(expected_height), &fee)) {
            reason << "tx-apply tx_index=" << tx_index;
            return reason.str();
        }
        if (!tx.is_coinbase()) total_fees += fee;
    }

    const int64_t expected_reward = Block::get_block_reward(expected_height);
    const int64_t coinbase_out = blk.transactions[0].total_output_value();
    if (coinbase_out > expected_reward + total_fees) {
        reason << "coinbase-overpay coinbase=" << coinbase_out
               << " allowed=" << (expected_reward + total_fees);
        return reason.str();
    }

    return "valid-tip-extension";
}

void Blockchain::pin_checkpoint_to_tip() {
    local_checkpoint_ = std::make_pair(best_height_, tip_hash_);
    manual_checkpoint_pinned_ = true;
    persist_manual_checkpoint();
    persist_local_checkpoint();
}

void Blockchain::clear_checkpoint_pin() {
    manual_checkpoint_pinned_ = false;
    std::error_code ec;
    std::filesystem::remove(manual_checkpoint_path(), ec);
    refresh_local_checkpoint();
    persist_local_checkpoint();
}

void Blockchain::refresh_checkpoint_now() {
    refresh_local_checkpoint();
}

void Blockchain::ensure_genesis() {
    if (!height_map_.empty() && !index_.empty()) {
        best_height_ = height_map_.rbegin()->first;
        tip_hash_ = height_map_.at(best_height_);
        if (index_.count(tip_hash_)) tip_bits_ = index_.at(tip_hash_).bits;
        // populate aux maps for known chain
        for (const auto& [h, hh] : height_map_) {
            link_index_[index_.at(hh).hash()] = hh;
            height_index_[hh] = h;
            chain_work_[hh] = (h == 0) ? block_work(index_.at(hh).bits)
                                       : chain_work_.at(link_index_.at(index_.at(hh).prev_block_hash)) + block_work(index_.at(hh).bits);
            block_height_[hh] = h; // FIX: store height for all active blocks
        }
        // cache blocks already on disk
        for (uint64_t h = 0; h <= best_height_; ++h) {
            if (auto blk = store_.load(h)) {
                block_pool_[blk->header.pow_hash()] = *blk;
                store_.store_by_hash(blk->header.pow_hash(), *blk);
            }
        }
        return;
    }
    if (store_.exists(0)) {
        auto g = store_.load(0);
        if (g) {
            best_height_ = 0;
            tip_hash_ = g->header.pow_hash();
            tip_bits_ = g->header.bits;
            height_map_[0] = tip_hash_;
            height_index_[tip_hash_] = 0;
            index_[tip_hash_] = g->header;
            link_index_[g->header.hash()] = tip_hash_;
            chain_work_[tip_hash_] = block_work(g->header.bits);
            block_pool_[tip_hash_] = *g;
            block_height_[tip_hash_] = 0; // FIX
            store_.store_by_hash(tip_hash_, *g);
            // UTXO bootstrap
            utxo_.apply_transaction(g->transactions[0], 0);
            save_index();
            persist_headers();
            return;
        }
    }
    Block g = Block::create_genesis();
    store_.store(0, g);
    uint256_t gh = g.header.pow_hash();
    best_height_ = 0;
    tip_hash_ = gh;
    tip_bits_ = g.header.bits;
    height_map_[0] = tip_hash_;
    height_index_[tip_hash_] = 0;
    index_[tip_hash_] = g.header;
    link_index_[g.header.hash()] = tip_hash_;
    chain_work_[tip_hash_] = block_work(g.header.bits);
    block_pool_[tip_hash_] = g;
    block_height_[tip_hash_] = 0; // FIX
    store_.store_by_hash(tip_hash_, g);
    utxo_.apply_transaction(g.transactions[0], 0);
    save_index();
    persist_headers();
}

bool Blockchain::connect_block(const Block& blk, bool skip_pow_check) {
    // Prefer the canonical active-height map when checking the current tip. If in-memory
    // tip metadata drifts, self-heal from the persisted active path before rejecting work.
    uint256_t active_tip = tip_hash_;
    auto active_it = height_map_.find(best_height_);
    if (active_it != height_map_.end()) {
        active_tip = active_it->second;
        if (active_tip != tip_hash_) {
            tip_hash_ = active_tip;
            auto header_it = index_.find(tip_hash_);
            if (header_it != index_.end()) {
                tip_bits_ = header_it->second.bits;
            }
            log_warn("chain", "corrected tip metadata drift height=" + std::to_string(best_height_) +
                              " tip=" + tip_hash_.to_hex_padded(constants::POW_HASH_BYTES));
        }
    }
    auto tip_it = index_.find(active_tip);
    if (tip_it == index_.end()) return false;
    if (blk.header.prev_block_hash != tip_it->second.hash()) return false;
    return accept_block(blk, skip_pow_check);
}

uint256_t Blockchain::block_work(uint32_t bits) const {
    compact_target compact{bits};
    if (compact.is_negative() || compact.is_zero() ||
        compact.overflows(constants::POW_HASH_BYTES) ||
        !compact.is_canonical(constants::POW_HASH_BYTES)) {
        return uint256_t();
    }
    uint256_t target = compact.expand();
    if (target > compact_target{pow_limit_bits()}.expand()) return uint256_t();
    if (target == uint256_t()) return uint256_t();
    uint256_t one(1);
    uint256_t max = (one << 511);
    max = max * uint256_t(2) - one; // 2^512 - 1
    return max / (target + one);
}

bool Blockchain::build_path_to_genesis(const uint256_t& tip, std::vector<uint256_t>& out_path) const {
    std::unordered_set<uint256_t> seen;
    uint256_t cursor = tip;
    while (true) {
        if (seen.count(cursor)) return false; // loop
        seen.insert(cursor);
        out_path.push_back(cursor);
        const auto it = index_.find(cursor);
        if (it == index_.end()) return false;
        auto prev = it->second.prev_block_hash;
        if (prev == uint256_t()) break; // reached genesis
        auto parent = link_index_.find(prev);
        if (parent == link_index_.end()) return false;
        cursor = parent->second;
    }
    std::reverse(out_path.begin(), out_path.end());
    return true;
}

uint32_t Blockchain::expected_bits_for(const std::map<uint64_t, uint256_t>& hmap,
                                       const std::unordered_map<uint256_t, BlockHeader>& idx,
                                       uint64_t height,
                                       uint32_t candidate_timestamp) const {
    if (height == 0) {
        auto h = hmap.at(0);
        return idx.at(h).bits;
    }
    uint64_t prev_h = height - 1;
    auto prev_hash = hmap.at(prev_h);
    uint32_t last_bits = idx.at(prev_hash).bits;
    return get_next_work_required(hmap, idx, prev_h, last_bits, candidate_timestamp);
}

size_t Blockchain::validated_prefix_length(const std::vector<uint256_t>& path,
                                           UTXOSet& out_utxo,
                                           uint32_t& out_tip_bits,
                                           bool skip_pow_check,
                                           bool log_failures,
                                           std::string* failure_reason,
                                           uint64_t* failure_height) const {
    std::map<uint64_t, uint256_t> hmap;
    std::unordered_map<uint256_t, BlockHeader> idx;
    out_utxo.clear();
    out_tip_bits = tip_bits_;
    if (failure_reason) failure_reason->clear();
    if (failure_height) *failure_height = 0;
    for (size_t i = 0; i < path.size(); ++i) {
        uint64_t height = static_cast<uint64_t>(i);
        const auto& h = path[i];
        auto blk_opt = get_block_by_hash(h);
        if (!blk_opt) {
            if (failure_reason) *failure_reason = "missing-block";
            if (failure_height) *failure_height = height;
            if (log_failures) {
                log_warn("chain", "candidate invalid reason=missing-block height=" + std::to_string(height));
            }
            return i;
        }
        const Block& blk = *blk_opt;
        hmap[height] = h;
        idx[h] = blk.header;

        // linkage
        if (height > 0 && blk.header.prev_block_hash != idx.at(path[i-1]).hash()) {
            if (failure_reason) *failure_reason = "prev-link";
            if (failure_height) *failure_height = height;
            if (log_failures) {
                log_warn("chain", "candidate invalid reason=prev-link height=" + std::to_string(height));
            }
            return i;
        }
        const BlockHeader* parent_header = (height > 0) ? &idx.at(path[i - 1]) : nullptr;
        if (!block_timestamp_valid(blk.header, parent_header)) {
            if (failure_reason) *failure_reason = "timestamp";
            if (failure_height) *failure_height = height;
            if (log_failures) {
                log_warn("chain", "candidate invalid reason=timestamp height=" + std::to_string(height) +
                                  " candidate_ts=" + std::to_string(blk.header.timestamp) +
                                  " parent_ts=" + std::to_string(parent_header ? parent_header->timestamp : 0));
            }
            return i;
        }
        // PoW & merkle
        if (height > 0 && !skip_pow_check) {
            compact_target compact{blk.header.bits};
            if (!compact.is_canonical(constants::POW_HASH_BYTES)) {
                if (failure_reason) *failure_reason = "bits-encoding";
                if (failure_height) *failure_height = height;
                if (log_failures) {
                    log_warn("chain", "candidate invalid reason=bits-encoding height=" +
                                      std::to_string(height) +
                                      " bits=" + std::to_string(blk.header.bits));
                }
                return i;
            }
            if (!blk.check_pow()) {
                if (failure_reason) *failure_reason = "pow";
                if (failure_height) *failure_height = height;
                if (log_failures) {
                    log_warn("chain", "candidate invalid reason=pow height=" + std::to_string(height));
                }
                return i;
            }
        }
        if (blk.compute_merkle_root() != blk.header.merkle_root) {
            if (failure_reason) *failure_reason = "merkle";
            if (failure_height) *failure_height = height;
            if (log_failures) {
                log_warn("chain", "candidate invalid reason=merkle height=" + std::to_string(height));
            }
            return i;
        }
        // bits
        uint32_t exp_bits = expected_bits_for(hmap, idx, height, blk.header.timestamp);
        if (blk.header.bits != exp_bits) {
            if (failure_reason) *failure_reason = "bits";
            if (failure_height) *failure_height = height;
            if (log_failures) {
                log_warn("chain", "candidate invalid reason=bits height=" + std::to_string(height) +
                                  " have=" + std::to_string(blk.header.bits) +
                                  " expected=" + std::to_string(exp_bits));
            }
            return i;
        }
        // transaction validation
        int64_t total_fees = 0;
        if (blk.transactions.empty() || !blk.transactions[0].is_coinbase()) {
            if (failure_reason) *failure_reason = "coinbase-missing";
            if (failure_height) *failure_height = height;
            if (log_failures) {
                log_warn("chain", "candidate invalid reason=coinbase-missing height=" + std::to_string(height));
            }
            return i;
        }
        for (size_t ti = 0; ti < blk.transactions.size(); ++ti) {
            const auto& tx = blk.transactions[ti];
            int64_t fee = 0;
            if (!out_utxo.apply_transaction(tx, static_cast<uint32_t>(height), &fee)) {
                if (failure_reason) *failure_reason = "tx-apply";
                if (failure_height) *failure_height = height;
                if (log_failures) {
                    log_warn("chain", "candidate invalid reason=tx-apply height=" + std::to_string(height) +
                                      " tx_index=" + std::to_string(ti));
                }
                return i;
            }
            if (!tx.is_coinbase()) total_fees += fee;
        }
        int64_t expected_reward = Block::get_block_reward(height);
        int64_t coinbase_out = blk.transactions[0].total_output_value();
        if (coinbase_out > expected_reward + total_fees) {
            if (failure_reason) *failure_reason = "coinbase-overpay";
            if (failure_height) *failure_height = height;
            if (log_failures) {
                log_warn("chain", "candidate invalid reason=coinbase-overpay height=" + std::to_string(height) +
                                  " coinbase=" + std::to_string(coinbase_out) +
                                  " allowed=" + std::to_string(expected_reward + total_fees));
            }
            return i;
        }
        out_tip_bits = blk.header.bits;
    }
    return path.size();
}

bool Blockchain::validate_path(const std::vector<uint256_t>& path, UTXOSet& out_utxo, uint32_t& out_tip_bits, bool skip_pow_check) {
    return validated_prefix_length(path, out_utxo, out_tip_bits, skip_pow_check, true) == path.size();
}

void Blockchain::purge_cached_subtree(const uint256_t& root) {
    std::vector<uint256_t> stack{root};
    std::unordered_set<uint256_t> seen;
    std::vector<uint256_t> purge_list;

    while (!stack.empty()) {
        const auto current = stack.back();
        stack.pop_back();
        if (!seen.insert(current).second) continue;

        auto header_it = index_.find(current);
        if (header_it != index_.end()) {
            auto kids = children_.find(header_it->second.hash());
            if (kids != children_.end()) {
                for (const auto& child : kids->second) {
                    stack.push_back(child);
                }
            }
        }

        purge_list.push_back(current);
    }

    bool mutated = false;
    for (const auto& hash : purge_list) {
        if (height_index_.count(hash)) continue;

        auto header_it = index_.find(hash);
        if (header_it != index_.end()) {
            link_index_.erase(header_it->second.hash());
            index_.erase(header_it);
            mutated = true;
        }
        mutated = block_pool_.erase(hash) > 0 || mutated;
        mutated = chain_work_.erase(hash) > 0 || mutated;
        mutated = block_height_.erase(hash) > 0 || mutated;
        mutated = height_index_.erase(hash) > 0 || mutated;
        store_.remove_by_hash(hash);
    }

    if (!mutated) return;

    rebuild_known_block_state();
    persist_headers();
}

bool Blockchain::activate_path(const std::vector<uint256_t>& path, UTXOSet& new_utxo, uint32_t new_tip_bits) {
    // Resolve the full path before mutating active state so a missing block does not
    // leave the chain half-rewritten in memory.
    std::vector<Block> resolved_blocks;
    resolved_blocks.reserve(path.size());
    std::map<uint64_t, uint256_t> next_height_map;
    std::unordered_map<uint256_t, uint64_t> next_height_index;
    std::unordered_map<uint256_t, uint64_t> next_block_height;
    std::unordered_map<uint256_t, uint256_t> next_chain_work;

    for (size_t i = 0; i < path.size(); ++i) {
        auto blk = get_block_by_hash(path[i]);
        if (!blk) {
            log_warn("chain", "activate_path missing block height=" + std::to_string(i) +
                              " hash=" + path[i].to_hex_padded(constants::POW_HASH_BYTES));
            return false;
        }
        resolved_blocks.push_back(*blk);
        next_height_map[static_cast<uint64_t>(i)] = path[i];
        next_height_index[path[i]] = static_cast<uint64_t>(i);
        next_block_height[path[i]] = static_cast<uint64_t>(i);
        uint256_t work_here = block_work(blk->header.bits);
        if (i == 0) next_chain_work[path[i]] = work_here;
        else next_chain_work[path[i]] = next_chain_work[path[i - 1]] + work_here;
    }

    for (size_t i = 0; i < path.size(); ++i) {
        if (!store_.store(static_cast<uint64_t>(i), resolved_blocks[i])) {
            log_warn("chain", "activate_path failed to write canonical block height=" + std::to_string(i));
            return false;
        }
        if (!store_.store_by_hash(path[i], resolved_blocks[i])) {
            log_warn("chain", "activate_path failed to refresh hash block height=" + std::to_string(i) +
                              " hash=" + path[i].to_hex_padded(constants::POW_HASH_BYTES));
            return false;
        }
    }

    height_map_ = std::move(next_height_map);
    height_index_ = std::move(next_height_index);
    block_height_ = std::move(next_block_height);
    chain_work_ = std::move(next_chain_work);
    best_height_ = path.empty() ? 0 : path.size() - 1;
    tip_hash_ = path.empty() ? tip_hash_ : path.back();
    tip_bits_ = new_tip_bits;
    store_.prune_height_files_after(best_height_);
    utxo_.swap_in(std::move(new_utxo));
    mempool_.clear();
    refresh_local_checkpoint();
    save_index();
    persist_headers();
    persist_chainstate();
    return true;
}

bool Blockchain::accept_block(const Block& blk, bool skip_pow_check) {
    uint256_t bh = blk.header.pow_hash();

    // Basic stateless checks (always run)
    if (!skip_pow_check && blk.header.prev_block_hash != uint256_t()) {
        compact_target compact{blk.header.bits};
        if (!compact.is_canonical(constants::POW_HASH_BYTES)) {
            log_warn("chain", "reject block non-canonical bits");
            return false;
        }
        if (!blk.check_pow()) {
            log_warn("chain", "reject block bad PoW");
            return false;
        }
    }
    if (blk.compute_merkle_root() != blk.header.merkle_root) {
        log_warn("chain", "reject block bad merkle");
        return false;
    }
    if (blk.transactions.size() > static_cast<size_t>(constants::MAX_TRANSACTIONS_PER_BLOCK)) {
        log_warn("chain", "reject block txcount");
        return false;
    }
    size_t block_size = blk.serialize().size();
    if (block_size > static_cast<size_t>(constants::MAX_BLOCK_SIZE_BYTES)) {
        log_warn("chain", "reject block size");
        return false;
    }

    auto parent_link = blk.header.prev_block_hash;
    uint256_t parent;
    const BlockHeader* parent_header = nullptr;
    if (parent_link != uint256_t()) {
        auto parent_it = link_index_.find(parent_link);
        if (parent_it != link_index_.end()) {
            parent = parent_it->second;
            auto header_it = index_.find(parent);
            if (header_it != index_.end()) {
                parent_header = &header_it->second;
            }
        }
    }
    if (!block_timestamp_valid(blk.header, parent_header)) {
        log_warn("chain", "reject block bad timestamp");
        return false;
    }

    // Cache block/header if new
    if (!index_.count(bh)) index_[bh] = blk.header;
    if (!block_pool_.count(bh)) block_pool_[bh] = blk;
    store_.store_by_hash(bh, blk);
    link_index_[blk.header.hash()] = bh;

    // If already fully processed (has chain_work), nothing else to do
    if (chain_work_.count(bh)) return true;

    if (parent_link != uint256_t() && (parent == uint256_t() || !chain_work_.count(parent))) {
        // Parent unknown yet; remember orphan
        children_[parent_link].push_back(bh);
        return true;
    }

    uint64_t height;
    if (parent_link == uint256_t()) {
        height = 0;
    } else {
        auto it = block_height_.find(parent);
        if (it == block_height_.end()) {
            log_warn("chain", "parent height not stored");
            return false;
        }
        height = it->second + 1;
    }
    const uint256_t candidate_work =
        ((parent_link == uint256_t()) ? uint256_t() : chain_work_.at(parent)) + block_work(blk.header.bits);
    const bool candidate_beats_tip =
        !chain_work_.count(tip_hash_) || candidate_work > chain_work_[tip_hash_];

    std::vector<uint256_t> path;
    if (!build_path_to_genesis(bh, path)) return false;

    UTXOSet new_utxo;
    uint32_t new_tip_bits = blk.header.bits;
    if (validated_prefix_length(path, new_utxo, new_tip_bits, skip_pow_check, true) != path.size()) {
        purge_cached_subtree(bh);
        log_warn("chain", "candidate chain invalid");
        return false;
    }

    // Determine best chain
    if (candidate_beats_tip) {
        if (!candidate_matches_local_checkpoint(path)) {
            log_warn("chain", "reject checkpoint mismatch candidate=" +
                              bh.to_hex_padded(constants::POW_HASH_BYTES));
            return false;
        }
        const uint64_t reorg_depth = reorg_depth_from_candidate(height_map_, best_height_, path);
        const uint64_t max_reorg_depth = runtime_max_reorg_depth();
        if (reorg_depth > max_reorg_depth && !allow_deep_reorg()) {
            log_warn("chain", "reject deep reorg depth=" + std::to_string(reorg_depth) +
                              " max=" + std::to_string(max_reorg_depth) +
                              " tip=" + tip_hash_.to_hex_padded(constants::POW_HASH_BYTES) +
                              " candidate=" + bh.to_hex_padded(constants::POW_HASH_BYTES));
            return false;
        }
        if (!activate_path(path, new_utxo, new_tip_bits)) {
            log_warn("chain", "candidate activation failed hash=" +
                              bh.to_hex_padded(constants::POW_HASH_BYTES) +
                              " height=" + std::to_string(height));
            return false;
        }
        log_info("chain", "switched to new tip " + bh.to_hex_padded(constants::POW_HASH_BYTES) +
                          " height=" + std::to_string(best_height_));
    } else {
        block_height_[bh] = height;
        chain_work_[bh] = candidate_work;
    }

    // Process any orphans that depended on this block
    auto self_link = blk.header.hash();
    if (children_.count(self_link)) {
        auto kids = children_[self_link]; // copy
        for (const auto& k : kids) {
            auto it = block_pool_.find(k);
            if (it != block_pool_.end()) {
                accept_block(it->second, skip_pow_check);
            }
        }
    }
    return true;
}

std::optional<uint256_t> Blockchain::canonical_block_id_for(const uint256_t& hash) const {
    if (index_.count(hash)) return hash;
    auto it = link_index_.find(hash);
    if (it != link_index_.end()) return it->second;
    return std::nullopt;
}

std::optional<Block> Blockchain::get_block_by_hash(const uint256_t& hash) const {
    auto canonical = canonical_block_id_for(hash);
    if (!canonical) return std::nullopt;

    // First check block_pool_
    auto itp = block_pool_.find(*canonical);
    if (itp != block_pool_.end()) return itp->second;

    // Then check if it's on active chain (height_index_)
    auto it = height_index_.find(*canonical);
    if (it != height_index_.end()) {
        return store_.load(it->second);
    }

    if (auto side = store_.load_by_hash(*canonical)) {
        return side;
    }
    return std::nullopt;
}

std::optional<uint64_t> Blockchain::get_height_by_hash(const uint256_t& hash) const {
    auto canonical = canonical_block_id_for(hash);
    if (!canonical) return std::nullopt;
    auto it = height_index_.find(*canonical);
    if (it == height_index_.end()) return std::nullopt;
    return it->second;
}

std::optional<BlockHeader> Blockchain::get_header_by_hash(const uint256_t& hash) const {
    auto canonical = canonical_block_id_for(hash);
    if (!canonical) return std::nullopt;
    auto it = index_.find(*canonical);
    if (it == index_.end()) return std::nullopt;
    return it->second;
}

bool Blockchain::knows_hash(const uint256_t& hash) const {
    return canonical_block_id_for(hash).has_value();
}

std::vector<uint256_t> Blockchain::block_locator(size_t max_entries) const {
    std::vector<uint256_t> out;
    if (height_map_.empty() || max_entries == 0) return out;

    uint64_t height = best_height_;
    uint64_t step = 1;
    size_t entries = 0;
    while (true) {
        out.push_back(height_map_.at(height));
        ++entries;
        if (height == 0 || entries >= max_entries) break;
        if (entries > 10) step *= 2;
        height = (height > step) ? (height - step) : 0;
    }
    return out;
}

std::vector<BlockHeader> Blockchain::headers_after_locator(const std::vector<uint256_t>& locator_hashes,
                                                           size_t max_headers) const {
    std::vector<BlockHeader> headers;
    if (height_map_.empty() || max_headers == 0) return headers;

    uint64_t start_height = 0;
    bool matched = false;
    for (const auto& locator : locator_hashes) {
        auto height = get_height_by_hash(locator);
        if (height) {
            start_height = *height + 1;
            matched = true;
            break;
        }
    }

    if (!matched && !locator_hashes.empty()) {
        start_height = 0;
    }

    for (uint64_t h = start_height; h <= best_height_ && headers.size() < max_headers; ++h) {
        auto block = get_block(h);
        if (!block) break;
        headers.push_back(block->header);
    }
    return headers;
}

void Blockchain::save_index() const {
    auto path = store_.base_dir() / "index.dat";
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return;
    uint8_t version = 2;
    f.write(reinterpret_cast<const char*>(&version), sizeof(version));
    uint64_t count = height_map_.size();
    uint32_t crc = 0xFFFFFFFF;
    f.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& [h, hash] : height_map_) {
        f.write(reinterpret_cast<const char*>(&h), sizeof(h));
        auto bytes = hash.to_padded_bytes(constants::POW_HASH_BYTES);
        f.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&h), sizeof(h));
        crc = crc32_update(crc, bytes.data(), bytes.size());
    }
    crc = crc32_finalize(crc);
    f.write(reinterpret_cast<const char*>(&crc), sizeof(crc));
}

void Blockchain::load_index() {
    auto path = store_.base_dir() / "index.dat";
    std::ifstream f(path, std::ios::binary);
    if (!f) return;
    uint8_t version = 0;
    f.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 2) { rebuild_from_blocks(); return; }
    uint64_t count = 0;
    uint32_t crc_stored = 0, crc_calc = 0xFFFFFFFF;
    f.read(reinterpret_cast<char*>(&count), sizeof(count));
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t h;
        std::array<uint8_t,constants::POW_HASH_BYTES> bytes{};
        f.read(reinterpret_cast<char*>(&h), sizeof(h));
        f.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
        crc_calc = crc32_update(crc_calc, reinterpret_cast<const uint8_t*>(&h), sizeof(h));
        crc_calc = crc32_update(crc_calc, bytes.data(), bytes.size());
        uint256_t hash = uint256_t::from_bytes(bytes.data(), bytes.size());
        height_map_[h] = hash;
        index_[hash] = BlockHeader(); // placeholder; will be re-filled on load of headers
    }
    crc_calc = crc32_finalize(crc_calc);
    f.read(reinterpret_cast<char*>(&crc_stored), sizeof(crc_stored));
    if (crc_calc != crc_stored) {
        height_map_.clear();
        index_.clear();
        rebuild_from_blocks();
    }
}

void Blockchain::persist_headers() const {
    auto path = store_.base_dir() / "headers.dat";
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return;
    uint8_t version = 2;
    f.write(reinterpret_cast<const char*>(&version), sizeof(version));
    uint64_t count = index_.size();
    uint32_t crc = 0xFFFFFFFF;
    f.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& [hash, hdr] : index_) {
        auto hbytes = hash.to_padded_bytes(constants::POW_HASH_BYTES);
        f.write(reinterpret_cast<const char*>(hbytes.data()), hbytes.size());
        auto ser = hdr.serialize();
        uint64_t len = ser.size();
        f.write(reinterpret_cast<const char*>(&len), sizeof(len));
        f.write(reinterpret_cast<const char*>(ser.data()), ser.size());
        crc = crc32_update(crc, hbytes.data(), hbytes.size());
        crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&len), sizeof(len));
        crc = crc32_update(crc, ser.data(), ser.size());
    }
    crc = crc32_finalize(crc);
    f.write(reinterpret_cast<const char*>(&crc), sizeof(crc));
}

void Blockchain::load_headers() {
    auto path = store_.base_dir() / "headers.dat";
    std::ifstream f(path, std::ios::binary);
    if (!f) return;
    uint8_t version = 0;
    f.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 2) { rebuild_from_blocks(); return; }
    uint64_t count = 0;
    uint32_t crc_calc = 0xFFFFFFFF, crc_stored = 0;
    f.read(reinterpret_cast<char*>(&count), sizeof(count));
    for (uint64_t i = 0; i < count; ++i) {
        std::array<uint8_t,constants::POW_HASH_BYTES> hb{};
        uint64_t len = 0;
        f.read(reinterpret_cast<char*>(hb.data()), hb.size());
        f.read(reinterpret_cast<char*>(&len), sizeof(len));
        std::vector<uint8_t> ser(len);
        f.read(reinterpret_cast<char*>(ser.data()), len);
        crc_calc = crc32_update(crc_calc, hb.data(), hb.size());
        crc_calc = crc32_update(crc_calc, reinterpret_cast<const uint8_t*>(&len), sizeof(len));
        crc_calc = crc32_update(crc_calc, ser.data(), ser.size());
        const uint8_t* ptr = ser.data();
        size_t rem = ser.size();
        BlockHeader hdr = BlockHeader::deserialize(ptr, rem);
        uint256_t h = uint256_t::from_bytes(hb.data(), hb.size());
        index_[h] = hdr;
        link_index_[hdr.hash()] = h;
    }
    crc_calc = crc32_finalize(crc_calc);
    f.read(reinterpret_cast<char*>(&crc_stored), sizeof(crc_stored));
    if (crc_calc != crc_stored) {
        index_.clear();
        rebuild_from_blocks();
        return;
    }
    // rebuild best_height_/tip bits if possible
    uint64_t maxh = 0;
    for (const auto& [height, hash] : height_map_) {
        if (height >= maxh) {
            maxh = height;
            tip_hash_ = hash;
            if (index_.count(hash)) tip_bits_ = index_.at(hash).bits;
            link_index_[index_.at(hash).hash()] = hash;
            height_index_[hash] = height;
            block_height_[hash] = height; // FIX
        }
    }
    best_height_ = maxh;
    // chain work reconstruct
    for (const auto& [h, hh] : height_map_) {
        if (h == 0) chain_work_[hh] = block_work(index_.at(hh).bits);
        else chain_work_[hh] = chain_work_.at(link_index_.at(index_.at(hh).prev_block_hash)) + block_work(index_.at(hh).bits);
    }
}

void Blockchain::rebuild_from_blocks() {
    height_map_.clear();
    index_.clear();
    link_index_.clear();
    height_index_.clear();
    chain_work_.clear();
    block_height_.clear();
    block_pool_.clear();
    children_.clear();
    uint64_t h = 0;
    while (store_.exists(h)) {
        auto blk = store_.load(h);
        if (!blk) break;
        uint256_t hash = blk->header.pow_hash();
        height_map_[h] = hash;
        index_[hash] = blk->header;
        link_index_[blk->header.hash()] = hash;
        height_index_[hash] = h;
        block_height_[hash] = h; // FIX
        block_pool_[hash] = *blk;
        ++h;
    }
    if (!height_map_.empty()) {
        best_height_ = height_map_.rbegin()->first;
        tip_hash_ = height_map_.at(best_height_);
        tip_bits_ = index_.at(tip_hash_).bits;
        for (const auto& [h, hh] : height_map_) {
            const auto& hdr = index_.at(hh);
            if (h == 0) chain_work_[hh] = block_work(hdr.bits);
            else chain_work_[hh] = chain_work_.at(link_index_.at(hdr.prev_block_hash)) + block_work(hdr.bits);
        }
        save_index();
        persist_headers();
    }
}

void Blockchain::rebuild_known_block_state() {
    children_.clear();
    chain_work_.clear();
    block_height_.clear();
    height_index_.clear();

    for (const auto& [height, hash] : height_map_) {
        height_index_[hash] = height;
        block_height_[hash] = height;
    }

    for (const auto& [hash, header] : index_) {
        if (header.prev_block_hash != uint256_t()) {
            children_[header.prev_block_hash].push_back(hash);
        }
    }

    bool progressed = true;
    while (progressed) {
        progressed = false;
        for (const auto& [hash, header] : index_) {
            if (chain_work_.count(hash)) continue;

            if (header.prev_block_hash == uint256_t()) {
                chain_work_[hash] = block_work(header.bits);
                block_height_[hash] = 0;
                progressed = true;
                continue;
            }

            auto parent = link_index_.find(header.prev_block_hash);
            if (parent == link_index_.end()) continue;

            auto parent_work = chain_work_.find(parent->second);
            auto parent_height = block_height_.find(parent->second);
            if (parent_work == chain_work_.end() || parent_height == block_height_.end()) continue;

            chain_work_[hash] = parent_work->second + block_work(header.bits);
            block_height_[hash] = parent_height->second + 1;
            height_index_[hash] = parent_height->second + 1;
            progressed = true;
        }
    }
}

std::filesystem::path Blockchain::chainstate_path() const {
    return store_.base_dir() / "chainstate.dat";
}

std::filesystem::path Blockchain::local_checkpoint_path() const {
    return store_.base_dir() / "local_checkpoint.dat";
}

std::filesystem::path Blockchain::manual_checkpoint_path() const {
    return store_.base_dir() / "manual_checkpoint.dat";
}

std::filesystem::path Blockchain::sync_approval_path() const {
    return store_.base_dir() / "sync_approval.dat";
}

bool Blockchain::load_local_checkpoint() {
    manual_checkpoint_pinned_ = false;
    local_checkpoint_.reset();
    std::ifstream f(local_checkpoint_path(), std::ios::binary);
    if (!f) return false;

    uint64_t height = 0;
    std::string hash_hex;
    if (!(f >> height >> hash_hex)) return false;

    try {
        local_checkpoint_ = std::make_pair(height, uint256_t::from_hex(hash_hex));
        return true;
    } catch (...) {
        local_checkpoint_.reset();
        return false;
    }
}

bool Blockchain::load_manual_checkpoint() {
    std::ifstream f(manual_checkpoint_path(), std::ios::binary);
    if (!f) return false;

    uint64_t height = 0;
    std::string hash_hex;
    if (!(f >> height >> hash_hex)) return false;

    try {
        local_checkpoint_ = std::make_pair(height, uint256_t::from_hex(hash_hex));
        manual_checkpoint_pinned_ = true;
        return true;
    } catch (...) {
        manual_checkpoint_pinned_ = false;
        return false;
    }
}

void Blockchain::persist_local_checkpoint() const {
    if (!local_checkpoint_) return;
    std::ofstream f(local_checkpoint_path(), std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << local_checkpoint_->first << " "
      << local_checkpoint_->second.to_hex_padded(constants::POW_HASH_BYTES) << "\n";
}

void Blockchain::persist_manual_checkpoint() const {
    if (!manual_checkpoint_pinned_ || !local_checkpoint_) return;
    std::ofstream f(manual_checkpoint_path(), std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << local_checkpoint_->first << " "
      << local_checkpoint_->second.to_hex_padded(constants::POW_HASH_BYTES) << "\n";
}

bool Blockchain::load_sync_approval() {
    sync_approval_.reset();
    std::ifstream f(sync_approval_path(), std::ios::binary);
    if (!f) return false;

    int approved_flag = 0;
    uint64_t height = 0;
    uint64_t peer_count = 0;
    uint64_t network_height = 0;
    std::string hash_hex;
    if (!(f >> approved_flag >> height >> peer_count >> hash_hex)) return false;

    try {
        SyncApprovalState state;
        state.approved = approved_flag != 0;
        state.height = height;
        state.peer_count = peer_count;
        state.tip = uint256_t::from_hex(hash_hex);
        if (!(f >> network_height)) {
            network_height = state.approved ? state.height : 0;
        }
        state.network_height = network_height;
        sync_approval_ = state;
        return true;
    } catch (...) {
        sync_approval_.reset();
        return false;
    }
}

void Blockchain::persist_sync_approval() const {
    if (!sync_approval_) return;
    std::ofstream f(sync_approval_path(), std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << (sync_approval_->approved ? 1 : 0) << " "
      << sync_approval_->height << " "
      << sync_approval_->peer_count << " "
      << sync_approval_->tip.to_hex_padded(constants::POW_HASH_BYTES) << " "
      << sync_approval_->network_height << "\n";
}

bool Blockchain::wallet_state_approved() const {
    if (best_height_ == 0) return false;
    if (!sync_approval_) return best_height_ > 0;
    if (sync_approval_->network_height > best_height_) return false;
    if (sync_approval_->height > best_height_) return false;
    auto it = height_map_.find(sync_approval_->height);
    if (it == height_map_.end()) return false;
    return it->second == sync_approval_->tip;
}

uint64_t Blockchain::approval_peer_count() const {
    return sync_approval_ ? sync_approval_->peer_count : 0;
}

uint64_t Blockchain::approval_network_height() const {
    return sync_approval_ ? sync_approval_->network_height : 0;
}

void Blockchain::set_sync_approval(bool approved, uint64_t peer_count, uint64_t network_height) {
    SyncApprovalState state = sync_approval_.value_or(SyncApprovalState{});
    bool keep_existing_anchor = false;
    if (sync_approval_ && sync_approval_->height <= best_height_) {
        auto it = height_map_.find(sync_approval_->height);
        keep_existing_anchor = it != height_map_.end() && it->second == sync_approval_->tip;
    }

    state.approved = approved;
    state.peer_count = peer_count;
    if (approved || !keep_existing_anchor) {
        state.height = best_height_;
        state.tip = tip_hash_;
    }
    if (approved) {
        state.network_height = std::max(best_height_, network_height);
    } else {
        const uint64_t required_height = network_height ? network_height : (best_height_ + 1);
        state.network_height = std::max(state.network_height, required_height);
    }
    sync_approval_ = state;
    persist_sync_approval();
}

void Blockchain::refresh_local_checkpoint() {
    if (manual_checkpoint_pinned_) return;
    if (height_map_.empty()) return;
    const uint64_t checkpoint_height =
        (best_height_ > constants::MAX_REORG_DEPTH) ? (best_height_ - constants::MAX_REORG_DEPTH) : 0;
    auto it = height_map_.find(checkpoint_height);
    if (it == height_map_.end()) return;

    const auto next_checkpoint = std::make_pair(checkpoint_height, it->second);
    if (local_checkpoint_ &&
        local_checkpoint_->first == next_checkpoint.first &&
        local_checkpoint_->second == next_checkpoint.second) {
        return;
    }

    local_checkpoint_ = next_checkpoint;
    persist_local_checkpoint();
}

bool Blockchain::candidate_matches_local_checkpoint(const std::vector<uint256_t>& path) const {
    if (!local_checkpoint_) return true;
    const auto [height, hash] = *local_checkpoint_;
    if (path.size() <= height) return false;
    return path[height] == hash;
}

bool Blockchain::active_chain_matches_local_checkpoint() const {
    if (!local_checkpoint_) return true;
    const auto [height, hash] = *local_checkpoint_;
    auto it = height_map_.find(height);
    if (it == height_map_.end()) return false;
    return it->second == hash;
}

bool Blockchain::load_chainstate_snapshot() {
    uint64_t stored_height = 0;
    uint256_t stored_tip;
    if (!utxo_.load_chainstate(chainstate_path(), stored_height, stored_tip)) {
        return false;
    }
    if (stored_height != best_height_ || stored_tip != tip_hash_) {
        utxo_.clear();
        return false;
    }
    return true;
}

void Blockchain::persist_chainstate() const {
    utxo_.flush_chainstate(chainstate_path(), best_height_, tip_hash_);
}

void Blockchain::rebuild_utxo_from_active_chain() {
    utxo_.clear();
    for (uint64_t h = 0; h <= best_height_; ++h) {
        auto blk = store_.load(h);
        if (!blk) break;
        for (const auto& tx : blk->transactions) {
            utxo_.apply_transaction(tx, static_cast<uint32_t>(h));
        }
    }
}

bool Blockchain::clear_stale_local_checkpoint_if_needed() {
    if (!local_checkpoint_) return false;
    const auto [height, hash] = *local_checkpoint_;
    (void)hash;
    if (height <= best_height_) return false;

    log_warn("chain", "clearing stale local checkpoint height=" + std::to_string(height) +
                      " best_height=" + std::to_string(best_height_));
    if (manual_checkpoint_pinned_) {
        manual_checkpoint_pinned_ = false;
        std::error_code ec;
        std::filesystem::remove(manual_checkpoint_path(), ec);
    }
    local_checkpoint_.reset();

    if (sync_approval_ && sync_approval_->height > best_height_) {
        sync_approval_->approved = false;
        sync_approval_->height = best_height_;
        sync_approval_->tip = tip_hash_;
        sync_approval_->network_height = std::max(sync_approval_->network_height, best_height_);
        persist_sync_approval();
    }

    return true;
}

bool Blockchain::repair_active_chain_if_needed() {
    if (height_map_.empty()) return false;

    std::vector<uint256_t> active_path;
    active_path.reserve(height_map_.size());
    for (const auto& [height, hash] : height_map_) {
        (void)height;
        active_path.push_back(hash);
    }

    UTXOSet repaired_utxo;
    uint32_t repaired_tip_bits = tip_bits_;
    std::string failure_reason;
    uint64_t failure_height = 0;
    const size_t valid_prefix = validated_prefix_length(
        active_path,
        repaired_utxo,
        repaired_tip_bits,
        /*skip_pow_check=*/false,
        /*log_failures=*/true,
        &failure_reason,
        &failure_height);
    if (valid_prefix == active_path.size()) {
        return false;
    }
    if (valid_prefix == 0) {
        log_warn("chain", "active chain repair aborted: genesis prefix invalid reason=" +
                          failure_reason +
                          " height=" + std::to_string(failure_height));
        return false;
    }

    for (size_t i = valid_prefix; i < active_path.size(); ++i) {
        const auto& hash = active_path[i];
        auto header_it = index_.find(hash);
        if (header_it != index_.end()) {
            link_index_.erase(header_it->second.hash());
            index_.erase(header_it);
        }
        block_pool_.erase(hash);
        chain_work_.erase(hash);
        block_height_.erase(hash);
        height_index_.erase(hash);
        store_.remove_by_hash(hash);
    }

    const uint64_t old_height = best_height_;
    std::vector<uint256_t> repaired_path(active_path.begin(), active_path.begin() + valid_prefix);
    if (!activate_path(repaired_path, repaired_utxo, repaired_tip_bits)) {
        return false;
    }

    rebuild_known_block_state();

    if (sync_approval_ &&
        (sync_approval_->height > best_height_ || sync_approval_->tip != tip_hash_)) {
        sync_approval_->approved = false;
        sync_approval_->height = best_height_;
        sync_approval_->tip = tip_hash_;
        sync_approval_->network_height = std::max(sync_approval_->network_height, best_height_);
        persist_sync_approval();
    }

    log_warn("chain", "repaired invalid active chain reason=" + failure_reason +
                      " failure_height=" + std::to_string(failure_height) +
                      " old_height=" + std::to_string(old_height) +
                      " new_height=" + std::to_string(best_height_));
    return true;
}

bool Blockchain::repair_height_files_from_active_index_if_needed() {
    if (height_map_.empty()) return false;

    uint64_t repaired = 0;
    for (const auto& [height, hash] : height_map_) {
        if (store_.exists(height)) continue;
        auto blk = store_.load_by_hash(hash);
        if (!blk) {
            log_warn("chain", "missing canonical height file and hash block for height=" +
                              std::to_string(height));
            continue;
        }
        if (!store_.store(height, *blk)) {
            log_warn("chain", "failed to restore canonical height file for height=" +
                              std::to_string(height));
            continue;
        }
        ++repaired;
    }

    if (repaired == 0) return false;

    store_.prune_height_files_after(best_height_);
    log_warn("chain", "restored missing canonical height files count=" + std::to_string(repaired) +
                      " tip_height=" + std::to_string(best_height_));
    return true;
}

uint32_t Blockchain::expected_bits(uint64_t height, uint32_t candidate_timestamp) const {
    if (height == 0 || height_map_.empty())
        return pow_limit_bits();
    return get_next_work_required(height_map_, index_, height - 1, tip_bits_, candidate_timestamp);
}

} // namespace cryptex
