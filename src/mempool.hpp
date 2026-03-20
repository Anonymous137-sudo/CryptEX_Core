#pragma once

#include "transaction.hpp"
#include "utxo.hpp"
#include <chrono>
#include <deque>
#include <set>
#include <shared_mutex>
#include <unordered_map>

namespace cryptex {

class Mempool {
public:
    Mempool() = default;

    enum class AcceptStatus {
        Accepted,
        Duplicate,
        Conflict,
        MissingInputs,
        Invalid,
        NonStandard,
        LowFee,
        PoolFull,
    };

    struct Stats {
        size_t tx_count{0};
        size_t total_bytes{0};
        size_t orphan_count{0};
    };

    // Add transaction if valid and not already present
    bool add_transaction(const Transaction& tx,
                         const UTXOSet& utxo,
                         uint32_t current_height,
                         AcceptStatus* status_out = nullptr);

    // Remove transaction (e.g., when included in a block)
    void remove_transaction(const uint256_t& tx_hash);

    // Get all transactions currently in mempool
    std::vector<Transaction> get_transactions() const;

    // Check if mempool contains transaction
    bool contains(const uint256_t& tx_hash) const;

    // Get transaction by hash (throws if not found)
    const Transaction& get_transaction(const uint256_t& tx_hash) const;

    // Clear mempool (e.g., on reorg)
    void clear();

    // Get total size in bytes
    size_t size_bytes() const;

    // Get count of transactions
    size_t size() const;

    // Remove transactions that have been in mempool too long (e.g., > 2 hours)
    void expire_old_transactions();

    size_t orphan_count() const;
    Stats stats() const;

private:
    struct TxEntry {
        Transaction tx;
        size_t size;
        int64_t fee;
        int64_t fee_rate_per_kb;
        std::chrono::steady_clock::time_point entry_time;
    };

    struct OrphanEntry {
        Transaction tx;
        std::chrono::steady_clock::time_point entry_time;
    };

    std::unordered_map<uint256_t, TxEntry> txs_;
    std::set<std::tuple<int64_t, int64_t, uint256_t>> sorted_by_feerate_; // ascending (feerate, fee, hash)
    std::unordered_map<OutPoint, uint256_t> spent_outpoints_; // outpoint -> tx hash that spends it
    std::unordered_map<uint256_t, OrphanEntry> orphans_;
    std::unordered_multimap<uint256_t, uint256_t> orphans_by_parent_;
    std::deque<uint256_t> orphan_order_;

    mutable std::shared_mutex mutex_;
    size_t total_bytes_ = 0;

    bool check_double_spend(const Transaction& tx) const;
    bool violates_standard_policy(const Transaction& tx, size_t tx_size) const;
    bool add_transaction_unlocked(const Transaction& tx,
                                  const UTXOSet& utxo,
                                  uint32_t current_height,
                                  AcceptStatus* status_out);
    void remove_transaction_unlocked(const uint256_t& tx_hash);
    void trim_to_limits_unlocked();
    void remove_orphan_unlocked(const uint256_t& tx_hash);
    void add_orphan_unlocked(const Transaction& tx, const std::vector<uint256_t>& missing_parents);
    void process_orphans_for_parent_unlocked(const uint256_t& parent_hash, const UTXOSet& utxo, uint32_t current_height);
};

} // namespace cryptex
