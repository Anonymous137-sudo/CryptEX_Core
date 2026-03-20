#pragma once

#include "types.hpp"
#include "serialization.hpp"
#include "script.hpp"
#include <vector>
#include <string>
#include <cstdint>

namespace cryptex {

// OutPoint: identifies a specific UTXO
struct OutPoint {
    uint256_t tx_hash;
    uint32_t  index;

    bool operator==(const OutPoint& other) const {
        return tx_hash == other.tx_hash && index == other.index;
    }
    bool operator<(const OutPoint& other) const {
        if (tx_hash < other.tx_hash) return true;
        if (other.tx_hash < tx_hash) return false;
        return index < other.index;
    }

    std::vector<uint8_t> serialize() const;
    static OutPoint deserialize(const uint8_t*& data, size_t& remaining);
};

// Transaction input
struct TxIn {
    OutPoint prevout;
    std::vector<uint8_t> scriptSig;   // Contains signature and pubkey
    uint32_t sequence;

    std::vector<uint8_t> serialize() const;
    static TxIn deserialize(const uint8_t*& data, size_t& remaining);
};

// Transaction output
struct TxOut {
    int64_t value;                     // Amount in smallest unit (satoshis)
    std::string scriptPubKey;           // Base64 address

    std::vector<uint8_t> serialize() const;
    static TxOut deserialize(const uint8_t*& data, size_t& remaining);
};

// Transaction class
class Transaction {
public:
    int32_t version;
    std::vector<TxIn> inputs;
    std::vector<TxOut> outputs;
    uint32_t lockTime;

    // Compute SHA3‑512 hash of the transaction (used as txid)
    uint256_t hash() const;
    // SIGHASH_ALL equivalent using SHA3‑512: clears other input scripts, inserts given scriptPubKey at input_index
    uint256_t sighash(size_t input_index, const std::vector<uint8_t>& script_pubkey) const;

    // Serialization
    std::vector<uint8_t> serialize() const;
    static Transaction deserialize(const uint8_t*& data, size_t& remaining);

    // Check if this is a coinbase transaction (single input with null prevout)
    bool is_coinbase() const;

    // Get total output value
    int64_t total_output_value() const;

    // Basic validation without UTXO (structure, etc.)
    bool validate_basic() const;

    // Full validation with UTXO set (requires access to UTXO)
    // We'll define this later in transaction.cpp after UTXOSet is known.
};

} // namespace cryptex

namespace std {
    template<> struct hash<cryptex::OutPoint> {
        size_t operator()(const cryptex::OutPoint& op) const {
            size_t h1 = hash<cryptex::uint256_t>()(op.tx_hash);
            size_t h2 = hash<uint32_t>()(op.index);
            return h1 ^ (h2 << 1);
        }
    };
}
