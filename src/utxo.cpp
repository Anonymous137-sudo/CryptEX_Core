#include "utxo.hpp"
#include "base64.hpp"
#include "serialization.hpp"
#include "constants.hpp"
#include "crc.hpp"
#include <fstream>
#include <mutex>

namespace cryptex {

namespace {

constexpr uint32_t CHAINSTATE_MAGIC = 0x54535843; // "CXST"
constexpr uint8_t CHAINSTATE_VERSION = 1;

} // namespace

// -------------------------------------------------------------------
// UTXOEntry
// -------------------------------------------------------------------
std::vector<uint8_t> UTXOEntry::serialize() const {
    std::vector<uint8_t> out;
    // Serialize TxOut
    out = output.serialize();
    // Append block_height and is_coinbase
    serialization::write_int<uint32_t>(out, block_height);
    out.push_back(is_coinbase ? 1 : 0);
    return out;
}

UTXOEntry UTXOEntry::deserialize(const uint8_t*& data, size_t& remaining) {
    UTXOEntry entry;
    // Deserialize TxOut (it consumes data)
    entry.output = TxOut::deserialize(data, remaining);
    entry.block_height = serialization::read_int<uint32_t>(data, remaining);
    if (remaining < 1) throw std::runtime_error("Not enough data for UTXOEntry flags");
    entry.is_coinbase = (data[0] != 0);
    data++; remaining--;
    return entry;
}

// -------------------------------------------------------------------
// UTXOSet
// -------------------------------------------------------------------
bool UTXOSet::apply_transaction(const Transaction& tx, uint32_t block_height, int64_t* fee_out) {
    std::unique_lock lock(mutex_);

    int64_t input_sum = 0;
    int64_t output_sum = tx.total_output_value();

    // For coinbase, only check that inputs are not spent (they are null)
    if (tx.is_coinbase()) {
        // No inputs to check, just add outputs
    } else {
        // Check all inputs exist and are not spent (they are in map_)
        for (const auto& in : tx.inputs) {
            auto it = map_.find(in.prevout);
            if (it == map_.end()) return false; // spent or never existed
            input_sum += it->second.output.value;

            // Verify signature: extract pubkey and signature from scriptSig
            // scriptSig format: [signature][pubkey] (DER signature + 65-byte pubkey)
            // For simplicity, we assume scriptSig is exactly that.
            const auto& sig = in.scriptSig;
            if (sig.size() < 65) return false; // invalid script
            size_t sig_len = sig.size() - 65; // signature is variable length DER
            std::vector<uint8_t> signature(sig.begin(), sig.begin() + sig_len);
            std::vector<uint8_t> pubkey(sig.begin() + sig_len, sig.end());

            // Verify that pubkey hashes to the address in the referenced output
            std::string addr = script::pubkey_to_address(pubkey);
            if (!crypto::addresses_equal(addr, it->second.output.scriptPubKey)) return false;

            // FIX: Pass the actual scriptPubKey (as bytes) to sighash
            std::vector<uint8_t> script_pubkey_bytes(it->second.output.scriptPubKey.begin(),
                                                      it->second.output.scriptPubKey.end());
            uint256_t sighash = tx.sighash(&in - &tx.inputs[0], script_pubkey_bytes);
            if (!script::verify_signature(sighash, signature, pubkey))
                return false;

            // FIX: Use constant for coinbase maturity
            if (it->second.is_coinbase && block_height - it->second.block_height < constants::COINBASE_MATURITY)
                return false; // coinbase outputs must mature 100 blocks
        }

        // Remove spent outputs
        for (const auto& in : tx.inputs) {
            map_.erase(in.prevout);
        }

        if (fee_out) *fee_out = input_sum - output_sum;
        if (input_sum < output_sum) return false;
    }

    // Add new outputs
    for (size_t i = 0; i < tx.outputs.size(); ++i) {
        OutPoint op{tx.hash(), static_cast<uint32_t>(i)};
        UTXOEntry entry{tx.outputs[i], block_height, tx.is_coinbase()};
        map_[op] = entry;
    }
    return true;
}

bool UTXOSet::undo_transaction(const Transaction& tx, uint32_t block_height) {
    std::unique_lock lock(mutex_);
    // Remove outputs created by this tx
    for (size_t i = 0; i < tx.outputs.size(); ++i) {
        OutPoint op{tx.hash(), static_cast<uint32_t>(i)};
        map_.erase(op);
    }
    // Restore spent outputs – but we don't have them in UTXO anymore.
    // For proper reorg, we need an undo log. We'll implement that later.
    // For now, this is a stub; full reorg support will come with blockchain.
    return true;
}

bool UTXOSet::contains(const OutPoint& outpoint) const {
    std::shared_lock lock(mutex_);
    return map_.find(outpoint) != map_.end();
}

const UTXOEntry& UTXOSet::get(const OutPoint& outpoint) const {
    std::shared_lock lock(mutex_);
    auto it = map_.find(outpoint);
    if (it == map_.end())
        throw std::runtime_error("UTXO not found");
    return it->second;
}

int64_t UTXOSet::get_balance(const std::string& address) const {
    std::shared_lock lock(mutex_);
    int64_t total = 0;
    for (const auto& [op, entry] : map_) {
        if (crypto::addresses_equal(entry.output.scriptPubKey, address))
            total += entry.output.value;
    }
    return total;
}

bool UTXOSet::flush(const std::string& filename) {
    std::shared_lock lock(mutex_);
    std::ofstream file(filename, std::ios::binary);
    if (!file) return false;

    // Write number of entries (8 bytes)
    uint64_t count = map_.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& [op, entry] : map_) {
        auto op_ser = op.serialize();
        auto entry_ser = entry.serialize();

        // Write outpoint length + data
        uint64_t op_len = op_ser.size();
        file.write(reinterpret_cast<const char*>(&op_len), sizeof(op_len));
        file.write(reinterpret_cast<const char*>(op_ser.data()), op_len);

        // Write entry length + data
        uint64_t entry_len = entry_ser.size();
        file.write(reinterpret_cast<const char*>(&entry_len), sizeof(entry_len));
        file.write(reinterpret_cast<const char*>(entry_ser.data()), entry_len);
    }
    return true;
}

bool UTXOSet::load(const std::string& filename) {
    std::unique_lock lock(mutex_);
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;

    map_.clear();
    uint64_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));

    for (uint64_t i = 0; i < count; ++i) {
        uint64_t op_len, entry_len;
        file.read(reinterpret_cast<char*>(&op_len), sizeof(op_len));
        std::vector<uint8_t> op_data(op_len);
        file.read(reinterpret_cast<char*>(op_data.data()), op_len);
        const uint8_t* op_ptr = op_data.data();
        size_t op_remaining = op_len;
        OutPoint op = OutPoint::deserialize(op_ptr, op_remaining);

        file.read(reinterpret_cast<char*>(&entry_len), sizeof(entry_len));
        std::vector<uint8_t> entry_data(entry_len);
        file.read(reinterpret_cast<char*>(entry_data.data()), entry_len);
        const uint8_t* entry_ptr = entry_data.data();
        size_t entry_remaining = entry_len;
        UTXOEntry entry = UTXOEntry::deserialize(entry_ptr, entry_remaining);

        map_[op] = entry;
    }
    return true;
}

bool UTXOSet::flush_chainstate(const std::filesystem::path& filename,
                               uint64_t best_height,
                               const uint256_t& tip_hash) const {
    std::shared_lock lock(mutex_);
    std::filesystem::create_directories(filename.parent_path());

    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    if (!file) return false;

    uint32_t magic = CHAINSTATE_MAGIC;
    uint8_t version = CHAINSTATE_VERSION;
    uint64_t count = map_.size();
    uint32_t crc = 0xFFFFFFFF;
    auto tip_bytes = tip_hash.to_padded_bytes(constants::POW_HASH_BYTES);

    file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    file.write(reinterpret_cast<const char*>(&best_height), sizeof(best_height));
    file.write(reinterpret_cast<const char*>(tip_bytes.data()), tip_bytes.size());
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));

    crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&version), sizeof(version));
    crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&best_height), sizeof(best_height));
    crc = crc32_update(crc, tip_bytes.data(), tip_bytes.size());
    crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&count), sizeof(count));

    for (const auto& [op, entry] : map_) {
        auto op_ser = op.serialize();
        auto entry_ser = entry.serialize();
        uint64_t op_len = op_ser.size();
        uint64_t entry_len = entry_ser.size();

        file.write(reinterpret_cast<const char*>(&op_len), sizeof(op_len));
        file.write(reinterpret_cast<const char*>(op_ser.data()), op_ser.size());
        file.write(reinterpret_cast<const char*>(&entry_len), sizeof(entry_len));
        file.write(reinterpret_cast<const char*>(entry_ser.data()), entry_ser.size());

        crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&op_len), sizeof(op_len));
        crc = crc32_update(crc, op_ser.data(), op_ser.size());
        crc = crc32_update(crc, reinterpret_cast<const uint8_t*>(&entry_len), sizeof(entry_len));
        crc = crc32_update(crc, entry_ser.data(), entry_ser.size());
    }

    crc = crc32_finalize(crc);
    file.write(reinterpret_cast<const char*>(&crc), sizeof(crc));
    return static_cast<bool>(file);
}

bool UTXOSet::load_chainstate(const std::filesystem::path& filename,
                              uint64_t& best_height_out,
                              uint256_t& tip_hash_out) {
    std::unique_lock lock(mutex_);
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;

    uint32_t magic = 0;
    uint8_t version = 0;
    uint64_t best_height = 0;
    std::array<uint8_t, constants::POW_HASH_BYTES> tip_bytes{};
    uint64_t count = 0;
    uint32_t crc_calc = 0xFFFFFFFF;
    uint32_t crc_stored = 0;

    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (!file || magic != CHAINSTATE_MAGIC || version != CHAINSTATE_VERSION) {
        return false;
    }

    file.read(reinterpret_cast<char*>(&best_height), sizeof(best_height));
    file.read(reinterpret_cast<char*>(tip_bytes.data()), tip_bytes.size());
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!file) return false;

    crc_calc = crc32_update(crc_calc, reinterpret_cast<const uint8_t*>(&version), sizeof(version));
    crc_calc = crc32_update(crc_calc, reinterpret_cast<const uint8_t*>(&best_height), sizeof(best_height));
    crc_calc = crc32_update(crc_calc, tip_bytes.data(), tip_bytes.size());
    crc_calc = crc32_update(crc_calc, reinterpret_cast<const uint8_t*>(&count), sizeof(count));

    std::unordered_map<OutPoint, UTXOEntry> loaded;
    loaded.reserve(static_cast<size_t>(count));

    for (uint64_t i = 0; i < count; ++i) {
        uint64_t op_len = 0;
        uint64_t entry_len = 0;

        file.read(reinterpret_cast<char*>(&op_len), sizeof(op_len));
        if (!file) return false;
        std::vector<uint8_t> op_data(op_len);
        file.read(reinterpret_cast<char*>(op_data.data()), static_cast<std::streamsize>(op_data.size()));
        if (!file) return false;

        file.read(reinterpret_cast<char*>(&entry_len), sizeof(entry_len));
        if (!file) return false;
        std::vector<uint8_t> entry_data(entry_len);
        file.read(reinterpret_cast<char*>(entry_data.data()), static_cast<std::streamsize>(entry_data.size()));
        if (!file) return false;

        crc_calc = crc32_update(crc_calc, reinterpret_cast<const uint8_t*>(&op_len), sizeof(op_len));
        crc_calc = crc32_update(crc_calc, op_data.data(), op_data.size());
        crc_calc = crc32_update(crc_calc, reinterpret_cast<const uint8_t*>(&entry_len), sizeof(entry_len));
        crc_calc = crc32_update(crc_calc, entry_data.data(), entry_data.size());

        const uint8_t* op_ptr = op_data.data();
        size_t op_remaining = op_data.size();
        OutPoint op = OutPoint::deserialize(op_ptr, op_remaining);

        const uint8_t* entry_ptr = entry_data.data();
        size_t entry_remaining = entry_data.size();
        UTXOEntry entry = UTXOEntry::deserialize(entry_ptr, entry_remaining);

        loaded.emplace(std::move(op), std::move(entry));
    }

    file.read(reinterpret_cast<char*>(&crc_stored), sizeof(crc_stored));
    if (!file) return false;
    crc_calc = crc32_finalize(crc_calc);
    if (crc_calc != crc_stored) return false;

    map_ = std::move(loaded);
    best_height_out = best_height;
    tip_hash_out = uint256_t::from_bytes(tip_bytes.data(), tip_bytes.size());
    return true;
}

void UTXOSet::clear() {
    std::unique_lock lock(mutex_);
    map_.clear();
}

void UTXOSet::swap_in(UTXOSet&& other) {
    if (&other == this) return;
    std::unique_lock lock(mutex_);
    std::unique_lock lock_other(other.mutex_);
    map_.swap(other.map_);
}

std::vector<std::pair<OutPoint, UTXOEntry>> UTXOSet::list_for_address(const std::string& address,
                                                                      uint32_t current_height,
                                                                      bool include_immature) const {
    std::shared_lock lock(mutex_);
    std::vector<std::pair<OutPoint, UTXOEntry>> out;
    for (const auto& [op, entry] : map_) {
        if (!crypto::addresses_equal(entry.output.scriptPubKey, address)) continue;
        if (!include_immature &&
            entry.is_coinbase &&
            current_height + 1 < entry.block_height + constants::COINBASE_MATURITY)
            continue; // immature coinbase
        out.emplace_back(op, entry);
    }
    return out;
}

} // namespace cryptex
