#include "transaction.hpp"
#include "utxo.hpp"   // for UTXOSet
#include <cstring>

namespace cryptex {

// -------------------------------------------------------------------
// OutPoint
// -------------------------------------------------------------------
std::vector<uint8_t> OutPoint::serialize() const {
    std::vector<uint8_t> out;
    auto bytes = tx_hash.to_bytes();
    out.insert(out.end(), bytes.begin(), bytes.end());
    serialization::write_int<uint32_t>(out, index);
    return out;
}

OutPoint OutPoint::deserialize(const uint8_t*& data, size_t& remaining) {
    OutPoint op;
    if (remaining < 32) throw std::runtime_error("Not enough data for tx_hash");
    std::array<uint8_t,32> hash_bytes;
    std::memcpy(hash_bytes.data(), data, 32);
    data += 32; remaining -= 32;
    op.tx_hash = uint256_t(hash_bytes);
    op.index = serialization::read_int<uint32_t>(data, remaining);
    return op;
}

// -------------------------------------------------------------------
// TxIn
// -------------------------------------------------------------------
std::vector<uint8_t> TxIn::serialize() const {
    std::vector<uint8_t> out = prevout.serialize();
    serialization::write_bytes(out, scriptSig.data(), scriptSig.size());
    serialization::write_int<uint32_t>(out, sequence);
    return out;
}

TxIn TxIn::deserialize(const uint8_t*& data, size_t& remaining) {
    TxIn txin;
    txin.prevout = OutPoint::deserialize(data, remaining);
    txin.scriptSig = serialization::read_bytes(data, remaining);
    txin.sequence = serialization::read_int<uint32_t>(data, remaining);
    return txin;
}

// -------------------------------------------------------------------
// TxOut
// -------------------------------------------------------------------
std::vector<uint8_t> TxOut::serialize() const {
    std::vector<uint8_t> out;
    serialization::write_int<int64_t>(out, value);
    serialization::write_bytes(out,
        reinterpret_cast<const uint8_t*>(scriptPubKey.data()),
        scriptPubKey.size());
    return out;
}

TxOut TxOut::deserialize(const uint8_t*& data, size_t& remaining) {
    TxOut txout;
    txout.value = serialization::read_int<int64_t>(data, remaining);
    auto bytes = serialization::read_bytes(data, remaining);
    txout.scriptPubKey.assign(bytes.begin(), bytes.end());
    return txout;
}

// -------------------------------------------------------------------
// Transaction
// -------------------------------------------------------------------
uint256_t Transaction::hash() const {
    auto ser = serialize();
    auto h = crypto::sha3_512(ser);
    std::array<uint8_t,32> first{};
    std::memcpy(first.data(), h.data(), 32);
    return uint256_t(first);
}

uint256_t Transaction::sighash(size_t input_index, const std::vector<uint8_t>& script_pubkey) const {
    if (input_index >= inputs.size())
        throw std::out_of_range("input_index");
    Transaction copy = *this;
    for (size_t i = 0; i < copy.inputs.size(); ++i) {
        copy.inputs[i].scriptSig.clear();
        if (i == input_index) {
            copy.inputs[i].scriptSig = script_pubkey;
        }
    }
    auto ser = copy.serialize();
    auto h = crypto::sha3_512(ser);
    std::array<uint8_t,32> first{};
    std::memcpy(first.data(), h.data(), 32);
    return uint256_t(first);
}

std::vector<uint8_t> Transaction::serialize() const {
    std::vector<uint8_t> out;
    serialization::write_int<int32_t>(out, version);
    serialization::write_varint(out, inputs.size());
    for (const auto& in : inputs) {
        auto in_ser = in.serialize();
        out.insert(out.end(), in_ser.begin(), in_ser.end());
    }
    serialization::write_varint(out, outputs.size());
    for (const auto& out_ : outputs) {
        auto out_ser = out_.serialize();
        out.insert(out.end(), out_ser.begin(), out_ser.end());
    }
    serialization::write_int<uint32_t>(out, lockTime);
    return out;
}

Transaction Transaction::deserialize(const uint8_t*& data, size_t& remaining) {
    Transaction tx;
    tx.version = serialization::read_int<int32_t>(data, remaining);

    uint64_t in_count = serialization::read_varint(data, remaining);
    tx.inputs.reserve(in_count);
    for (uint64_t i = 0; i < in_count; ++i)
        tx.inputs.push_back(TxIn::deserialize(data, remaining));

    uint64_t out_count = serialization::read_varint(data, remaining);
    tx.outputs.reserve(out_count);
    for (uint64_t i = 0; i < out_count; ++i)
        tx.outputs.push_back(TxOut::deserialize(data, remaining));

    tx.lockTime = serialization::read_int<uint32_t>(data, remaining);
    return tx;
}

// FIX: added index check for coinbase
bool Transaction::is_coinbase() const {
    return inputs.size() == 1 && inputs[0].prevout.tx_hash == uint256_t() && inputs[0].prevout.index == 0xFFFFFFFF;
}

int64_t Transaction::total_output_value() const {
    int64_t sum = 0;
    for (const auto& out : outputs) sum += out.value;
    return sum;
}

bool Transaction::validate_basic() const {
    // Must have at least one output
    if (outputs.empty()) return false;
    // For non-coinbase, must have at least one input
    if (!is_coinbase() && inputs.empty()) return false;
    // No output value can be negative
    for (const auto& out : outputs) if (out.value < 0) return false;
    // Check total output does not exceed 21 million * 1e8 (but we'll rely on block reward)
    return true;
}

// Full validation with UTXO (to be defined after UTXOSet is complete)
// We'll move this to a separate function or make it a method of UTXOSet.
} // namespace cryptex
