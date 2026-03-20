#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <map>
#include <unordered_map>
#include "types.hpp"
#include "constants.hpp"
#include "transaction.hpp"
#include "serialization.hpp"

// -------------------------------------------------------------------
// Block header and block definitions
// -------------------------------------------------------------------
namespace cryptex {

struct BlockHeader {
    int32_t version{1};
    uint256_t prev_block_hash{};
    uint256_t merkle_root{};
    uint32_t timestamp{0};
    uint32_t bits{0};
    uint32_t nonce{0};

    uint256_t hash() const;     // 256-bit block identifier
    uint256_t pow_hash() const; // full 512-bit SHA3-512 PoW value in BIGNUM form
    std::vector<uint8_t> serialize() const;
    static BlockHeader deserialize(const uint8_t*& data, size_t& remaining);
};

class Block {
public:
    BlockHeader header;
    std::vector<Transaction> transactions;

    uint256_t compute_merkle_root() const;
    std::vector<uint8_t> serialize() const;
    static Block deserialize(const uint8_t*& data, size_t& remaining);
    bool check_pow() const;
    static int64_t get_block_reward(uint64_t height);
    static Block create_genesis();
    static Block genesis_template(); // nonce=0, no PoW search
};

uint32_t get_next_work_required(const std::map<uint64_t, uint256_t>& height_map,
                                const std::unordered_map<uint256_t, BlockHeader>& index,
                                uint64_t best_height,
                                uint32_t last_bits,
                                uint32_t last_timestamp,
                                uint32_t first_timestamp_of_period);

} // namespace cryptex
