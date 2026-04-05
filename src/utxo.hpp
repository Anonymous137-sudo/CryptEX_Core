#pragma once

#include "transaction.hpp"
#include <unordered_map>
#include <shared_mutex>
#include <string>
#include <fstream>
#include <filesystem>

namespace cryptex {

// Entry stored in UTXO set
struct UTXOEntry {
    TxOut output;
    uint32_t block_height;   // Height at which this output was created
    bool is_coinbase;        // True if coinbase output (requires maturity)

    // Serialization
    std::vector<uint8_t> serialize() const;
    static UTXOEntry deserialize(const uint8_t*& data, size_t& remaining);
};

class UTXOSet {
public:
    UTXOSet() = default;
    ~UTXOSet() = default;

    // Apply a transaction (remove spent outputs, add new ones)
    bool apply_transaction(const Transaction& tx, uint32_t block_height, int64_t* fee_out = nullptr);

    // Undo a transaction (for reorg)
    bool undo_transaction(const Transaction& tx, uint32_t block_height);

    // Check if an outpoint is unspent
    bool contains(const OutPoint& outpoint) const;

    // Get the UTXO entry (throws if not found)
    const UTXOEntry& get(const OutPoint& outpoint) const;

    // Get total balance for an address (slow, for wallet)
    int64_t get_balance(const std::string& address) const;

    // Flush to disk (binary file)
    bool flush(const std::string& filename);

    // Load from disk
    bool load(const std::string& filename);

    // Persist the active chainstate snapshot with tip metadata.
    bool flush_chainstate(const std::filesystem::path& filename,
                          uint64_t best_height,
                          const uint256_t& tip_hash) const;

    // Load a chainstate snapshot and return the metadata it was created for.
    bool load_chainstate(const std::filesystem::path& filename,
                         uint64_t& best_height_out,
                         uint256_t& tip_hash_out);

    // Clear all entries
    void clear();

    // Swap contents from another UTXO set (used during chain reorg)
    void swap_in(UTXOSet&& other);

    // List spendable UTXOs for an address at a given height
    std::vector<std::pair<OutPoint, UTXOEntry>> list_for_address(const std::string& address,
                                                                 uint32_t current_height,
                                                                 bool include_immature = false) const;

private:
    std::unordered_map<OutPoint, UTXOEntry> map_;
    mutable std::shared_mutex mutex_;
};

} // namespace cryptex
