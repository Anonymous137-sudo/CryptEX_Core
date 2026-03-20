#include "blockchain.hpp"
#include "chainparams.hpp"
#include "debug.hpp"
#include <chrono>
#include "crc.hpp"
#include <unordered_set>
#include <iostream>
#include <algorithm>

namespace cryptex {

Blockchain::Blockchain(const std::filesystem::path& data_dir)
    : store_(data_dir) {
    load_index();
    load_headers();
    if (height_map_.empty() || index_.empty())
        rebuild_from_blocks();
    ensure_genesis();
    if (!load_chainstate_snapshot()) {
        rebuild_utxo_from_active_chain();
        persist_chainstate();
    }
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
    utxo_.apply_transaction(g.transactions[0], 0);
    save_index();
    persist_headers();
}

bool Blockchain::connect_block(const Block& blk, bool skip_pow_check) {
    // Legacy path: only allow direct extension of active tip
    if (blk.header.prev_block_hash != index_.at(tip_hash_).hash()) return false;
    return accept_block(blk, skip_pow_check);
}

uint256_t Blockchain::block_work(uint32_t bits) const {
    uint256_t target = compact_target{bits}.expand();
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
                                       uint64_t height) const {
    if (height == 0) {
        auto h = hmap.at(0);
        return idx.at(h).bits;
    }
    uint64_t prev_h = height - 1;
    auto prev_hash = hmap.at(prev_h);
    uint32_t last_bits = idx.at(prev_hash).bits;
    uint32_t last_ts = idx.at(prev_hash).timestamp;
    uint64_t period_start_height = height / constants::DIFFICULTY_ADJUSTMENT_INTERVAL *
                                   constants::DIFFICULTY_ADJUSTMENT_INTERVAL;
    uint32_t first_ts = 0;
    if (period_start_height < height && hmap.count(period_start_height)) {
        auto ph = hmap.at(period_start_height);
        first_ts = idx.at(ph).timestamp;
    }
    return get_next_work_required(hmap, idx, prev_h, last_bits, last_ts, first_ts);
}

bool Blockchain::validate_path(const std::vector<uint256_t>& path, UTXOSet& out_utxo, uint32_t& out_tip_bits, bool skip_pow_check) {
    std::map<uint64_t, uint256_t> hmap;
    std::unordered_map<uint256_t, BlockHeader> idx;
    out_utxo.clear();
    for (size_t i = 0; i < path.size(); ++i) {
        uint64_t height = static_cast<uint64_t>(i);
        const auto& h = path[i];
        auto blk_opt = get_block_by_hash(h);
        if (!blk_opt) return false;
        const Block& blk = *blk_opt;
        hmap[height] = h;
        idx[h] = blk.header;
        // FIX: store height for this block
        block_height_[h] = height;

        // linkage
        if (height > 0 && blk.header.prev_block_hash != idx.at(path[i-1]).hash()) return false;
        // PoW & merkle
        if (height > 0 && !skip_pow_check && !blk.check_pow()) return false;
        if (blk.compute_merkle_root() != blk.header.merkle_root) return false;
        // bits
        uint32_t exp_bits = expected_bits_for(hmap, idx, height);
        if (blk.header.bits != exp_bits) return false;
        // transaction validation
        int64_t total_fees = 0;
        if (blk.transactions.empty() || !blk.transactions[0].is_coinbase()) return false;
        for (size_t ti = 0; ti < blk.transactions.size(); ++ti) {
            const auto& tx = blk.transactions[ti];
            int64_t fee = 0;
            if (!out_utxo.apply_transaction(tx, static_cast<uint32_t>(height), &fee)) return false;
            if (!tx.is_coinbase()) total_fees += fee;
        }
        int64_t expected_reward = Block::get_block_reward(height);
        int64_t coinbase_out = blk.transactions[0].total_output_value();
        if (coinbase_out > expected_reward + total_fees) return false;
    }
    out_tip_bits = path.empty() ? tip_bits_ : idx.at(path.back()).bits;
    return true;
}

bool Blockchain::activate_path(const std::vector<uint256_t>& path, UTXOSet& new_utxo, uint32_t new_tip_bits) {
    // Rewrite canonical files according to path
    height_map_.clear();
    height_index_.clear();
    chain_work_.clear();
    for (size_t i = 0; i < path.size(); ++i) {
        auto blk = get_block_by_hash(path[i]);
        if (!blk) return false;
        store_.store(static_cast<uint64_t>(i), *blk);
        height_map_[static_cast<uint64_t>(i)] = path[i];
        height_index_[path[i]] = static_cast<uint64_t>(i);
        block_height_[path[i]] = i; // FIX
        uint256_t work_here = block_work(blk->header.bits);
        if (i == 0) chain_work_[path[i]] = work_here;
        else chain_work_[path[i]] = chain_work_[path[i-1]] + work_here;
    }
    best_height_ = path.empty() ? 0 : path.size() - 1;
    tip_hash_ = path.empty() ? tip_hash_ : path.back();
    tip_bits_ = new_tip_bits;
    utxo_.swap_in(std::move(new_utxo));
    mempool_.clear();
    save_index();
    persist_headers();
    persist_chainstate();
    return true;
}

bool Blockchain::accept_block(const Block& blk, bool skip_pow_check) {
    uint256_t bh = blk.header.pow_hash();

    // Basic stateless checks (always run)
    if (!skip_pow_check && blk.header.prev_block_hash != uint256_t() && !blk.check_pow()) {
        log_warn("chain", "reject block bad PoW");
        return false;
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

    // Cache block/header if new
    if (!index_.count(bh)) index_[bh] = blk.header;
    if (!block_pool_.count(bh)) block_pool_[bh] = blk;
    link_index_[blk.header.hash()] = bh;

    // If already fully processed (has chain_work), nothing else to do
    if (chain_work_.count(bh)) return true;

    auto parent_link = blk.header.prev_block_hash;
    uint256_t parent;
    if (parent_link != uint256_t()) {
        auto it = link_index_.find(parent_link);
        if (it != link_index_.end()) parent = it->second;
    }
    if (parent_link != uint256_t() && (parent == uint256_t() || !chain_work_.count(parent))) {
        // Parent unknown yet; remember orphan
        children_[parent_link].push_back(bh);
        return true;
    }

    // FIX: compute height using block_height_ map (or recursively compute)
    uint64_t height;
    if (parent_link == uint256_t()) {
        height = 0;
    } else {
        // parent must have its height stored in block_height_
        auto it = block_height_.find(parent);
        if (it == block_height_.end()) {
            // This should not happen if parent is known (has chain_work)
            log_warn("chain", "parent height not stored");
            return false;
        }
        height = it->second + 1;
    }
    block_height_[bh] = height;
    height_index_[bh] = height; // for active chain later
    chain_work_[bh] = ((parent_link == uint256_t()) ? uint256_t() : chain_work_.at(parent)) + block_work(blk.header.bits);

    // Determine best chain
    if (!chain_work_.count(tip_hash_) || chain_work_[bh] > chain_work_[tip_hash_]) {
        std::vector<uint256_t> path;
        if (!build_path_to_genesis(bh, path)) return false;
        UTXOSet new_utxo;
        uint32_t new_tip_bits = blk.header.bits;
        if (!validate_path(path, new_utxo, new_tip_bits, skip_pow_check)) {
            log_warn("chain", "candidate chain invalid");
            return false;
        }
        if (!activate_path(path, new_utxo, new_tip_bits)) return false;
        log_info("chain", "switched to new tip " + bh.to_hex_padded(constants::POW_HASH_BYTES) +
                          " height=" + std::to_string(best_height_));
        tip_hash_ = bh;
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

    // Optionally check block_height_ for side chains (but those blocks aren't stored persistently)
    // Could try to load from disk if we have height, but side chains are not stored per-height.
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

std::filesystem::path Blockchain::chainstate_path() const {
    return store_.base_dir() / "chainstate.dat";
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

uint32_t Blockchain::expected_bits(uint64_t height, uint32_t last_timestamp) const {
    if (height == 0 || height_map_.empty())
        return pow_limit_bits();
    return get_next_work_required(height_map_, index_, height - 1, tip_bits_, last_timestamp, 0);
}

} // namespace cryptex
