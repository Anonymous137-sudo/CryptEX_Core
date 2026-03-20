#include "block.hpp"
#include "chainparams.hpp"
#include "transaction.hpp"  // Will be defined later; for now assume minimal Transaction
#include <algorithm>
#include <cstring>
#include <map>
#include <unordered_map>
#include <limits>
#include <cstdlib>

namespace cryptex {

// -------------------------------------------------------------------
// BlockHeader
// -------------------------------------------------------------------
uint256_t BlockHeader::hash() const {
    auto ser = serialize();
    auto h = crypto::sha3_512(ser);
    std::array<uint8_t,32> first{};
    std::memcpy(first.data(), h.data(), 32);
    return uint256_t(first);
}

uint256_t BlockHeader::pow_hash() const {
    auto ser = serialize();
    auto h = crypto::sha3_512(ser);
    return uint256_t::from_bytes(h.data(), h.size());
}

std::vector<uint8_t> BlockHeader::serialize() const {
    std::vector<uint8_t> out;
    serialization::write_int<int32_t>(out, version);
    auto prev_bytes = prev_block_hash.to_bytes();
    out.insert(out.end(), prev_bytes.begin(), prev_bytes.end());
    auto merkle_bytes = merkle_root.to_bytes();
    out.insert(out.end(), merkle_bytes.begin(), merkle_bytes.end());
    serialization::write_int<uint32_t>(out, timestamp);
    serialization::write_int<uint32_t>(out, bits);
    serialization::write_int<uint32_t>(out, nonce);
    return out;
}

BlockHeader BlockHeader::deserialize(const uint8_t*& data, size_t& remaining) {
    BlockHeader hdr;
    hdr.version = serialization::read_int<int32_t>(data, remaining);
    // Read prev_block_hash (32 bytes)
    if (remaining < 32) throw std::runtime_error("Not enough data for prev_block_hash");
    std::array<uint8_t,32> prev_bytes;
    std::memcpy(prev_bytes.data(), data, 32);
    data += 32; remaining -= 32;
    hdr.prev_block_hash = uint256_t(prev_bytes);
    // Read merkle_root (32 bytes)
    if (remaining < 32) throw std::runtime_error("Not enough data for merkle_root");
    std::array<uint8_t,32> merkle_bytes;
    std::memcpy(merkle_bytes.data(), data, 32);
    data += 32; remaining -= 32;
    hdr.merkle_root = uint256_t(merkle_bytes);
    hdr.timestamp = serialization::read_int<uint32_t>(data, remaining);
    hdr.bits = serialization::read_int<uint32_t>(data, remaining);
    hdr.nonce = serialization::read_int<uint32_t>(data, remaining);
    return hdr;
}

// -------------------------------------------------------------------
// Block
// -------------------------------------------------------------------
uint256_t Block::compute_merkle_root() const {
    if (transactions.empty())
        return uint256_t(); // all zeros (but should not happen in valid block)

    std::vector<uint256_t> hashes;
    for (const auto& tx : transactions) {
        hashes.push_back(tx.hash()); // Transaction::hash returns uint256_t
    }

    while (hashes.size() > 1) {
        if (hashes.size() % 2 == 1)
            hashes.push_back(hashes.back()); // duplicate last

        std::vector<uint256_t> next_level;
        for (size_t i = 0; i < hashes.size(); i += 2) {
            // Concatenate the two hashes (each 32 bytes) and hash them
            auto a = hashes[i].to_bytes();
            auto b = hashes[i+1].to_bytes();
            std::vector<uint8_t> concat;
            concat.reserve(64);
            concat.insert(concat.end(), a.begin(), a.end());
            concat.insert(concat.end(), b.begin(), b.end());

            auto h = crypto::sha3_512(concat);
            std::array<uint8_t,32> combined{};
            std::memcpy(combined.data(), h.data(), 32);
            next_level.push_back(uint256_t(combined));
        }
        hashes = std::move(next_level);
    }
    return hashes[0];
}

std::vector<uint8_t> Block::serialize() const {
    std::vector<uint8_t> out = header.serialize();
    serialization::write_varint(out, transactions.size());
    for (const auto& tx : transactions) {
        auto tx_ser = tx.serialize();   // Transaction::serialize() returns vector
        serialization::write_bytes(out, tx_ser.data(), tx_ser.size());
    }
    return out;
}

Block Block::deserialize(const uint8_t*& data, size_t& remaining) {
    Block blk;
    blk.header = BlockHeader::deserialize(data, remaining);
    uint64_t tx_count = serialization::read_varint(data, remaining);
    blk.transactions.reserve(tx_count);
    for (uint64_t i = 0; i < tx_count; ++i) {
        auto tx_data = serialization::read_bytes(data, remaining);
        const uint8_t* tx_ptr = tx_data.data();
        size_t tx_remaining = tx_data.size();
        blk.transactions.push_back(Transaction::deserialize(tx_ptr, tx_remaining));
    }
    return blk;
}

bool Block::check_pow() const {
    uint256_t target = compact_target{header.bits}.expand();
    auto h = header.pow_hash();
    return h <= target;  // using uint256_t operator<=
}

int64_t Block::get_block_reward(uint64_t height) {
    uint64_t halvings = height / constants::HALVING_INTERVAL_BLOCKS;
    if (halvings >= 64) return 0; // after many halvings, reward becomes 0
    int64_t reward = constants::INITIAL_BLOCK_REWARD * 100'000'000LL; // in satoshis
    reward >>= halvings; // right shift = division by 2^halvings
    return reward;
}

Block Block::genesis_template() {
    Block genesis;
    // Version 1
    genesis.header.version = 1;
    // Previous block hash: all zeros (no parent)
    genesis.header.prev_block_hash = uint256_t();
    // We'll set merkle root after adding the coinbase transaction
    genesis.header.timestamp = genesis_timestamp();
    genesis.header.bits = pow_limit_bits();
    genesis.header.nonce = 0; // Trusted genesis; PoW check skipped for height 0

    // Create coinbase transaction (simplified, will be fleshed out later)
    Transaction coinbase;
    coinbase.version = 1;
    coinbase.lockTime = 0;
    // Coinbase input: prevout null
    TxIn coinbase_in;
    coinbase_in.prevout.tx_hash = uint256_t();  // all zeros
    coinbase_in.prevout.index = 0xFFFFFFFF;      // special index
    coinbase_in.scriptSig = {};                   // empty for now
    coinbase_in.sequence = 0xFFFFFFFF;
    coinbase.inputs.push_back(coinbase_in);
    // Coinbase output: send block reward to a fixed address (or leave as placeholder)
    TxOut coinbase_out;
    coinbase_out.value = get_block_reward(0);    // 50 * 1e8
    coinbase_out.scriptPubKey = genesis_address();
    coinbase.outputs.push_back(coinbase_out);

    genesis.transactions.push_back(coinbase);
    genesis.header.merkle_root = genesis.compute_merkle_root();
    // Leave nonce as 0 for template
    return genesis;
}

Block Block::create_genesis() {
    Block genesis = Block::genesis_template();
    genesis.header.nonce = params().genesis_nonce;
    return genesis;
}

// -------------------------------------------------------------------
// Difficulty adjustment
// -------------------------------------------------------------------
uint32_t get_next_work_required(const std::map<uint64_t, uint256_t>& height_map,
                                const std::unordered_map<uint256_t, BlockHeader>& index,
                                uint64_t best_height,
                                uint32_t last_bits,
                                uint32_t last_timestamp,
                                uint32_t first_timestamp_of_period) {
    (void)last_timestamp;
    (void)first_timestamp_of_period;

    if (params().fixed_difficulty) {
        return pow_limit_bits();
    }

    if (params().allow_min_difficulty_blocks) {
        if (best_height == 0) return pow_limit_bits();
        const auto& last_hash = height_map.at(best_height);
        const auto& last_header = index.at(last_hash);
        if (last_timestamp > last_header.timestamp + constants::BLOCK_TIME_SECONDS * 2) {
            return pow_limit_bits();
        }
    }

    if (best_height == 0)
        return last_bits;

    const uint64_t window = std::min<uint64_t>(best_height, constants::DIFFICULTY_LWMA_WINDOW);
    if (window < 6)
        return last_bits;

    uint64_t weighted_solvetime = 0;
    uint64_t total_weight = 0;
    uint256_t weighted_targets(uint64_t{0});

    for (uint64_t offset = 0; offset < window; ++offset) {
        uint64_t current_height = best_height - window + 1 + offset;
        uint64_t previous_height = current_height - 1;
        const auto& current_hash = height_map.at(current_height);
        const auto& previous_hash = height_map.at(previous_height);
        const auto& current_header = index.at(current_hash);
        const auto& previous_header = index.at(previous_hash);

        int64_t solvetime = static_cast<int64_t>(current_header.timestamp) -
                            static_cast<int64_t>(previous_header.timestamp);
        if (solvetime < constants::DIFFICULTY_MIN_SOLVETIME)
            solvetime = constants::DIFFICULTY_MIN_SOLVETIME;
        if (solvetime > constants::DIFFICULTY_MAX_SOLVETIME)
            solvetime = constants::DIFFICULTY_MAX_SOLVETIME;

        uint64_t weight = offset + 1;
        weighted_solvetime += static_cast<uint64_t>(solvetime) * weight;
        total_weight += weight;
        weighted_targets += compact_target{current_header.bits}.expand() * uint256_t(weight);
    }

    uint256_t average_target = weighted_targets / uint256_t(total_weight);
    uint256_t next_target = (average_target * uint256_t(weighted_solvetime)) /
                            uint256_t(static_cast<uint64_t>(constants::BLOCK_TIME_SECONDS) * total_weight);

    // Dampen the adjustment so a short burst of odd timestamps cannot whipsaw difficulty.
    next_target = (next_target + average_target * uint256_t(3)) / uint256_t(4);

    uint256_t min_target = average_target / uint256_t(2);
    uint256_t max_target = average_target * uint256_t(2);
    if (next_target < min_target)
        next_target = min_target;
    if (next_target > max_target)
        next_target = max_target;

    uint256_t pow_limit = compact_target{pow_limit_bits()}.expand();
    if (next_target > pow_limit)
        next_target = pow_limit;

    return compact_target::from_target(next_target).bits;
}

} // namespace cryptex
