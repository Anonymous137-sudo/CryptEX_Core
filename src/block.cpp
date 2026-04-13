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

namespace {

int64_t clamp_solvetime(int64_t solvetime) {
    if (solvetime < constants::DIFFICULTY_MIN_SOLVETIME) {
        return constants::DIFFICULTY_MIN_SOLVETIME;
    }
    if (solvetime > constants::DIFFICULTY_MAX_SOLVETIME) {
        return constants::DIFFICULTY_MAX_SOLVETIME;
    }
    return solvetime;
}

uint256_t clamp_to_pow_limit(const uint256_t& target) {
    uint256_t pow_limit = compact_target{pow_limit_bits()}.expand();
    return target > pow_limit ? pow_limit : target;
}

bool is_emergency_min_difficulty_block(const BlockHeader& previous,
                                       const BlockHeader& current) {
    return params().emergency_min_difficulty_delay_seconds > 0 &&
           current.bits == pow_limit_bits() &&
           current.timestamp >=
               previous.timestamp + params().emergency_min_difficulty_delay_seconds;
}

uint32_t last_non_emergency_bits(const std::map<uint64_t, uint256_t>& height_map,
                                 const std::unordered_map<uint256_t, BlockHeader>& index,
                                 uint64_t best_height,
                                 uint32_t fallback_bits) {
    if (best_height == 0) return fallback_bits;

    for (uint64_t cursor = best_height; cursor > 0; --cursor) {
        const auto& current_hash = height_map.at(cursor);
        const auto& previous_hash = height_map.at(cursor - 1);
        const auto& current_header = index.at(current_hash);
        const auto& previous_header = index.at(previous_hash);
        if (!is_emergency_min_difficulty_block(previous_header, current_header)) {
            return current_header.bits;
        }
    }
    return fallback_bits;
}

bool pow_target_valid(uint32_t bits, uint256_t* out_target = nullptr) {
    compact_target compact{bits};
    if (compact.is_negative() || compact.is_zero() ||
        compact.overflows(constants::POW_HASH_BYTES)) {
        return false;
    }

    uint256_t target = compact.expand();
    if (target == uint256_t()) return false;
    if (target > compact_target{pow_limit_bits()}.expand()) return false;

    if (out_target) {
        *out_target = std::move(target);
    }
    return true;
}

} // namespace

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
    uint256_t target;
    if (!pow_target_valid(header.bits, &target)) {
        return false;
    }
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
                                uint32_t candidate_timestamp) {
    if (params().fixed_difficulty) {
        return pow_limit_bits();
    }

    if (best_height == 0) {
        return last_bits;
    }

    const auto& last_hash = height_map.at(best_height);
    const auto& last_header = index.at(last_hash);
    const uint32_t effective_candidate_timestamp =
        std::max<uint32_t>(candidate_timestamp, last_header.timestamp + 1);
    const int64_t candidate_gap = clamp_solvetime(
        static_cast<int64_t>(effective_candidate_timestamp) -
        static_cast<int64_t>(last_header.timestamp));
    const bool last_was_emergency =
        best_height > 0 &&
        is_emergency_min_difficulty_block(index.at(height_map.at(best_height - 1)), last_header);

    if (params().allow_min_difficulty_blocks) {
        if (effective_candidate_timestamp > last_header.timestamp + constants::BLOCK_TIME_SECONDS * 2) {
            return pow_limit_bits();
        }
    }

    if (params().emergency_min_difficulty_delay_seconds > 0 &&
        effective_candidate_timestamp >=
            last_header.timestamp + params().emergency_min_difficulty_delay_seconds) {
        return pow_limit_bits();
    }

    const uint32_t stable_last_bits =
        last_was_emergency ? last_non_emergency_bits(height_map, index, best_height, last_bits)
                           : last_bits;
    const uint256_t stable_last_target = compact_target{stable_last_bits}.expand();

    // Once the stalled network has been rescued by an emergency min-difficulty block,
    // immediately snap follow-up work back to the last stable non-emergency difficulty.
    if (last_was_emergency) {
        return stable_last_bits;
    }

    const uint64_t window = std::min<uint64_t>(best_height, constants::DIFFICULTY_LWMA_WINDOW);
    if (window < 6)
        return stable_last_bits;

    uint64_t weighted_solvetime = 0;
    uint64_t total_weight = 0;
    uint256_t weighted_targets(uint64_t{0});
    uint256_t last_stable_target = compact_target{index.at(height_map.at(best_height - window)).bits}.expand();

    for (uint64_t offset = 0; offset < window; ++offset) {
        uint64_t current_height = best_height - window + 1 + offset;
        uint64_t previous_height = current_height - 1;
        const auto& current_hash = height_map.at(current_height);
        const auto& previous_hash = height_map.at(previous_height);
        const auto& current_header = index.at(current_hash);
        const auto& previous_header = index.at(previous_hash);

        int64_t solvetime = clamp_solvetime(
            static_cast<int64_t>(current_header.timestamp) -
            static_cast<int64_t>(previous_header.timestamp));
        uint256_t sample_target = compact_target{current_header.bits}.expand();

        if (is_emergency_min_difficulty_block(previous_header, current_header)) {
            // Treat emergency rescue blocks as neutral history samples so they do not
            // drag the next several retargets back toward pow-limit difficulty.
            solvetime = constants::BLOCK_TIME_SECONDS;
            sample_target = last_stable_target;
        } else {
            last_stable_target = sample_target;
        }

        uint64_t weight = offset + 1;
        weighted_solvetime += static_cast<uint64_t>(solvetime) * weight;
        total_weight += weight;
        weighted_targets += sample_target * uint256_t(weight);
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

    if (params().use_ema_difficulty) {
        const uint64_t ema_window = std::min<uint64_t>(best_height, std::max<uint32_t>(params().ema_window, 1U));
        constexpr uint64_t kScale = 1024;
        uint64_t ema_solvetime = static_cast<uint64_t>(constants::BLOCK_TIME_SECONDS) * kScale;
        const uint64_t alpha_den = ema_window + 1;
        const uint64_t alpha_num = 2;
        const uint64_t start_height = best_height - ema_window + 1;

        for (uint64_t current_height = start_height; current_height <= best_height; ++current_height) {
            const auto& current_hash = height_map.at(current_height);
            const auto& previous_hash = height_map.at(current_height - 1);
            const auto& current_header = index.at(current_hash);
            const auto& previous_header = index.at(previous_hash);
            const uint64_t sample = static_cast<uint64_t>(clamp_solvetime(
                static_cast<int64_t>(current_header.timestamp) -
                static_cast<int64_t>(previous_header.timestamp)));
            ema_solvetime =
                ((alpha_den - alpha_num) * ema_solvetime + alpha_num * sample * kScale) / alpha_den;
        }

        ema_solvetime =
            ((alpha_den - alpha_num) * ema_solvetime +
             alpha_num * static_cast<uint64_t>(candidate_gap) * kScale) / alpha_den;

        uint256_t ema_target = stable_last_target * uint256_t(ema_solvetime);
        ema_target /= uint256_t(static_cast<uint64_t>(constants::BLOCK_TIME_SECONDS) * kScale);

        if (ema_target > next_target) {
            next_target = ema_target;
        }
    }

    if (candidate_gap > constants::BLOCK_TIME_SECONDS) {
        uint256_t realtime_target = stable_last_target * uint256_t(static_cast<uint64_t>(candidate_gap));
        realtime_target /= uint256_t(static_cast<uint64_t>(constants::BLOCK_TIME_SECONDS));
        if (realtime_target > next_target) {
            next_target = realtime_target;
        }
    }

    next_target = clamp_to_pow_limit(next_target);
    return compact_target::from_target(next_target).bits;
}

} // namespace cryptex
