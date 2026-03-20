#include "mempool.hpp"

#include "base64.hpp"
#include "constants.hpp"
#include <algorithm>
#include <chrono>
#include <mutex>
#include <set>
#include <unordered_set>

namespace cryptex {

namespace {

bool is_op_return_script(const std::string& script_pub_key) {
    return script_pub_key.rfind("OP_RETURN:", 0) == 0;
}

bool is_standard_address(const std::string& script_pub_key) {
    if (script_pub_key.size() != constants::ADDRESS_BASE64_LENGTH) return false;
    return crypto::base64_decode(script_pub_key).size() ==
           static_cast<size_t>(constants::ADDRESS_HASH_LENGTH);
}

} // namespace

bool Mempool::add_transaction(const Transaction& tx,
                              const UTXOSet& utxo,
                              uint32_t current_height,
                              AcceptStatus* status_out) {
    std::unique_lock lock(mutex_);
    return add_transaction_unlocked(tx, utxo, current_height, status_out);
}

bool Mempool::add_transaction_unlocked(const Transaction& tx,
                                       const UTXOSet& utxo,
                                       uint32_t current_height,
                                       AcceptStatus* status_out) {
    auto set_status = [&](AcceptStatus status) {
        if (status_out) *status_out = status;
    };

    if (!tx.validate_basic()) {
        set_status(AcceptStatus::Invalid);
        return false;
    }
    if (tx.is_coinbase()) {
        set_status(AcceptStatus::Invalid);
        return false;
    }

    uint256_t tx_hash = tx.hash();
    if (txs_.count(tx_hash) || orphans_.count(tx_hash)) {
        set_status(AcceptStatus::Duplicate);
        return false;
    }

    size_t tx_size = tx.serialize().size();
    if (violates_standard_policy(tx, tx_size)) {
        set_status(AcceptStatus::NonStandard);
        return false;
    }
    if (check_double_spend(tx)) {
        set_status(AcceptStatus::Conflict);
        return false;
    }

    std::unordered_set<OutPoint> seen_inputs;
    std::vector<UTXOEntry> resolved_inputs(tx.inputs.size());
    std::vector<uint256_t> missing_parents;
    std::set<uint256_t> unique_missing;
    int64_t input_sum = 0;

    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        const auto& in = tx.inputs[i];
        if (!seen_inputs.insert(in.prevout).second) {
            set_status(AcceptStatus::Conflict);
            return false;
        }

        auto mempool_parent = txs_.find(in.prevout.tx_hash);
        if (utxo.contains(in.prevout)) {
            resolved_inputs[i] = utxo.get(in.prevout);
        } else if (mempool_parent != txs_.end()) {
            if (in.prevout.index >= mempool_parent->second.tx.outputs.size()) {
                set_status(AcceptStatus::Invalid);
                return false;
            }
            resolved_inputs[i] = UTXOEntry{
                mempool_parent->second.tx.outputs[in.prevout.index],
                current_height,
                mempool_parent->second.tx.is_coinbase(),
            };
        } else {
            if (unique_missing.insert(in.prevout.tx_hash).second) {
                missing_parents.push_back(in.prevout.tx_hash);
            }
            continue;
        }

        input_sum += resolved_inputs[i].output.value;
    }

    if (!missing_parents.empty()) {
        add_orphan_unlocked(tx, missing_parents);
        set_status(AcceptStatus::MissingInputs);
        return false;
    }

    int64_t output_sum = tx.total_output_value();
    int64_t fee = input_sum - output_sum;
    if (fee < 0) {
        set_status(AcceptStatus::Invalid);
        return false;
    }

    int64_t min_fee =
        static_cast<int64_t>(((tx_size + 999) / 1000) * constants::MIN_RELAY_FEE_SATS_PER_KB);
    if (fee < min_fee) {
        set_status(AcceptStatus::LowFee);
        return false;
    }

    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        const auto& in = tx.inputs[i];
        const auto& entry = resolved_inputs[i];
        const auto& sig = in.scriptSig;
        if (sig.size() < 65) {
            set_status(AcceptStatus::Invalid);
            return false;
        }

        size_t sig_len = sig.size() - 65;
        std::vector<uint8_t> signature(sig.begin(), sig.begin() + sig_len);
        std::vector<uint8_t> pubkey(sig.begin() + sig_len, sig.end());

        std::string addr = script::pubkey_to_address(pubkey);
        if (!crypto::addresses_equal(addr, entry.output.scriptPubKey)) {
            set_status(AcceptStatus::Invalid);
            return false;
        }

        std::vector<uint8_t> script_pubkey_bytes(entry.output.scriptPubKey.begin(),
                                                 entry.output.scriptPubKey.end());
        uint256_t sighash = tx.sighash(i, script_pubkey_bytes);
        if (!script::verify_signature(sighash, signature, pubkey)) {
            set_status(AcceptStatus::Invalid);
            return false;
        }

        if (entry.is_coinbase &&
            current_height + 1 < entry.block_height + constants::COINBASE_MATURITY) {
            set_status(AcceptStatus::Invalid);
            return false;
        }
    }

    int64_t fee_rate_per_kb = tx_size == 0
                                ? fee
                                : static_cast<int64_t>((fee * 1000) / static_cast<int64_t>(tx_size));
    TxEntry entry{tx, tx_size, fee, fee_rate_per_kb, std::chrono::steady_clock::now()};
    txs_[tx_hash] = entry;
    sorted_by_feerate_.insert({fee_rate_per_kb, fee, tx_hash});
    total_bytes_ += tx_size;

    for (const auto& in : tx.inputs) {
        spent_outpoints_[in.prevout] = tx_hash;
    }

    trim_to_limits_unlocked();
    if (!txs_.count(tx_hash)) {
        set_status(AcceptStatus::PoolFull);
        return false;
    }

    set_status(AcceptStatus::Accepted);
    process_orphans_for_parent_unlocked(tx_hash, utxo, current_height);
    return true;
}

void Mempool::remove_transaction(const uint256_t& tx_hash) {
    std::unique_lock lock(mutex_);
    remove_transaction_unlocked(tx_hash);
}

void Mempool::remove_transaction_unlocked(const uint256_t& tx_hash) {
    auto it = txs_.find(tx_hash);
    if (it == txs_.end()) return;

    for (const auto& in : it->second.tx.inputs) {
        auto spend_it = spent_outpoints_.find(in.prevout);
        if (spend_it != spent_outpoints_.end() && spend_it->second == tx_hash) {
            spent_outpoints_.erase(spend_it);
        }
    }

    sorted_by_feerate_.erase({it->second.fee_rate_per_kb, it->second.fee, tx_hash});
    total_bytes_ -= it->second.size;
    txs_.erase(it);
}

std::vector<Transaction> Mempool::get_transactions() const {
    std::shared_lock lock(mutex_);
    std::vector<Transaction> result;
    result.reserve(txs_.size());
    for (auto it = sorted_by_feerate_.rbegin(); it != sorted_by_feerate_.rend(); ++it) {
        result.push_back(txs_.at(std::get<2>(*it)).tx);
    }
    return result;
}

bool Mempool::contains(const uint256_t& tx_hash) const {
    std::shared_lock lock(mutex_);
    return txs_.find(tx_hash) != txs_.end();
}

const Transaction& Mempool::get_transaction(const uint256_t& tx_hash) const {
    std::shared_lock lock(mutex_);
    auto it = txs_.find(tx_hash);
    if (it == txs_.end()) {
        throw std::runtime_error("Transaction not found in mempool");
    }
    return it->second.tx;
}

void Mempool::clear() {
    std::unique_lock lock(mutex_);
    txs_.clear();
    sorted_by_feerate_.clear();
    spent_outpoints_.clear();
    orphans_.clear();
    orphans_by_parent_.clear();
    orphan_order_.clear();
    total_bytes_ = 0;
}

size_t Mempool::size_bytes() const {
    std::shared_lock lock(mutex_);
    return total_bytes_;
}

size_t Mempool::size() const {
    std::shared_lock lock(mutex_);
    return txs_.size();
}

void Mempool::expire_old_transactions() {
    auto now = std::chrono::steady_clock::now();
    std::unique_lock lock(mutex_);

    std::vector<uint256_t> to_remove;
    for (const auto& [hash, entry] : txs_) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - entry.entry_time).count();
        if (age > constants::MEMPOOL_TX_EXPIRY_SECONDS) {
            to_remove.push_back(hash);
        }
    }
    for (const auto& hash : to_remove) {
        remove_transaction_unlocked(hash);
    }

    std::vector<uint256_t> orphan_remove;
    for (const auto& [hash, entry] : orphans_) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - entry.entry_time).count();
        if (age > constants::MEMPOOL_TX_EXPIRY_SECONDS) {
            orphan_remove.push_back(hash);
        }
    }
    for (const auto& hash : orphan_remove) {
        remove_orphan_unlocked(hash);
    }
}

size_t Mempool::orphan_count() const {
    std::shared_lock lock(mutex_);
    return orphans_.size();
}

Mempool::Stats Mempool::stats() const {
    std::shared_lock lock(mutex_);
    return Stats{txs_.size(), total_bytes_, orphans_.size()};
}

bool Mempool::check_double_spend(const Transaction& tx) const {
    for (const auto& in : tx.inputs) {
        if (spent_outpoints_.find(in.prevout) != spent_outpoints_.end()) {
            return true;
        }
    }
    return false;
}

bool Mempool::violates_standard_policy(const Transaction& tx, size_t tx_size) const {
    if (tx_size > constants::MAX_STANDARD_TX_SIZE_BYTES) return true;
    if (tx.inputs.size() > constants::MAX_STANDARD_TX_INPUTS) return true;
    if (tx.outputs.size() > constants::MAX_STANDARD_TX_OUTPUTS) return true;

    bool saw_op_return = false;
    for (const auto& in : tx.inputs) {
        if (in.scriptSig.empty()) return true;
        if (in.scriptSig.size() > constants::MAX_STANDARD_SCRIPTSIG_BYTES) return true;
    }
    for (const auto& out : tx.outputs) {
        if (is_op_return_script(out.scriptPubKey)) {
            if (saw_op_return) return true;
            if (out.value != 0) return true;
            if (out.scriptPubKey.size() > 256) return true;
            saw_op_return = true;
            continue;
        }
        if (!is_standard_address(out.scriptPubKey)) return true;
        if (out.value < constants::DUST_LIMIT_SATS) return true;
    }
    return false;
}

void Mempool::trim_to_limits_unlocked() {
    while (!sorted_by_feerate_.empty() &&
           (total_bytes_ > constants::MAX_MEMPOOL_SIZE_BYTES ||
            txs_.size() > static_cast<size_t>(constants::MAX_MEMPOOL_TRANSACTIONS))) {
        auto it = sorted_by_feerate_.begin();
        remove_transaction_unlocked(std::get<2>(*it));
    }
}

void Mempool::remove_orphan_unlocked(const uint256_t& tx_hash) {
    auto it = orphans_.find(tx_hash);
    if (it == orphans_.end()) return;

    orphans_.erase(it);
    orphan_order_.erase(std::remove(orphan_order_.begin(), orphan_order_.end(), tx_hash),
                        orphan_order_.end());
    for (auto parent_it = orphans_by_parent_.begin(); parent_it != orphans_by_parent_.end();) {
        if (parent_it->second == tx_hash) {
            parent_it = orphans_by_parent_.erase(parent_it);
        } else {
            ++parent_it;
        }
    }
}

void Mempool::add_orphan_unlocked(const Transaction& tx, const std::vector<uint256_t>& missing_parents) {
    uint256_t tx_hash = tx.hash();
    if (orphans_.count(tx_hash)) return;

    while (orphan_order_.size() >= static_cast<size_t>(constants::MAX_MEMPOOL_ORPHANS)) {
        uint256_t evict = orphan_order_.front();
        orphan_order_.pop_front();
        remove_orphan_unlocked(evict);
    }

    orphans_[tx_hash] = OrphanEntry{tx, std::chrono::steady_clock::now()};
    orphan_order_.push_back(tx_hash);
    for (const auto& parent_hash : missing_parents) {
        orphans_by_parent_.emplace(parent_hash, tx_hash);
    }
}

void Mempool::process_orphans_for_parent_unlocked(const uint256_t& parent_hash,
                                                  const UTXOSet& utxo,
                                                  uint32_t current_height) {
    std::vector<uint256_t> ready;
    auto range = orphans_by_parent_.equal_range(parent_hash);
    for (auto it = range.first; it != range.second; ++it) {
        ready.push_back(it->second);
    }

    for (const auto& orphan_hash : ready) {
        auto orphan_it = orphans_.find(orphan_hash);
        if (orphan_it == orphans_.end()) continue;
        Transaction orphan_tx = orphan_it->second.tx;
        remove_orphan_unlocked(orphan_hash);
        AcceptStatus status = AcceptStatus::Invalid;
        add_transaction_unlocked(orphan_tx, utxo, current_height, &status);
    }
}

} // namespace cryptex
