#include "network.hpp"
#include "base64.hpp"
#include "blockchain.hpp"
#include "chat_secure.hpp"
#include "chainparams.hpp"
#include "debug.hpp"
#include "script.hpp"
#include "serialization.hpp"
#include "sha3_512.hpp"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <cstring>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <random>
#include <regex>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <openssl/ssl.h>

namespace cryptex {
namespace net {

namespace {

namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;

const char* mempool_status_name(Mempool::AcceptStatus status) {
    switch (status) {
    case Mempool::AcceptStatus::Accepted: return "accepted";
    case Mempool::AcceptStatus::Duplicate: return "duplicate";
    case Mempool::AcceptStatus::Conflict: return "conflict";
    case Mempool::AcceptStatus::MissingInputs: return "missing-inputs";
    case Mempool::AcceptStatus::Invalid: return "invalid";
    case Mempool::AcceptStatus::NonStandard: return "non-standard";
    case Mempool::AcceptStatus::LowFee: return "low-fee";
    case Mempool::AcceptStatus::PoolFull: return "pool-full";
    }
    return "unknown";
}

std::string endpoint_label(const ip_address& ip, uint16_t port) {
    return ip.to_string() + ":" + std::to_string(port);
}

std::optional<std::pair<std::string, uint16_t>> parse_host_port(const std::string& value,
                                                                uint16_t default_port) {
    if (value.empty()) return std::nullopt;
    auto pos = value.rfind(':');
    std::string host = value;
    uint16_t port = default_port;
    if (pos != std::string::npos && value.find(':') == pos) {
        host = value.substr(0, pos);
        if (host.empty()) return std::nullopt;
        try {
            port = static_cast<uint16_t>(std::stoul(value.substr(pos + 1)));
        } catch (...) {
            return std::nullopt;
        }
    }
    return std::make_pair(host, port);
}

bool looks_like_peer_label(const std::string& value) {
    return parse_host_port(value, default_p2p_port()).has_value();
}

bool is_ipv4_literal(const std::string& host) {
    try {
        boost::asio::ip::make_address_v4(host);
        return true;
    } catch (...) {
        return false;
    }
}

uint64_t now_millis() {
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t hash_key64(const std::string& value) {
    const auto digest = crypto::sha3_512(value);
    uint64_t out = 0;
    for (size_t i = 0; i < sizeof(out) && i < digest.size(); ++i) {
        out = (out << 8) | static_cast<uint64_t>(digest[i]);
    }
    return out;
}

uint64_t dht_distance64(const std::string& lhs, const std::string& rhs) {
    return hash_key64(lhs) ^ hash_key64(rhs);
}

std::string encode_mail_store_field(const std::string& value) {
    return crypto::base64_encode(value);
}

std::string decode_mail_store_field(const std::string& value) {
    auto bytes = crypto::base64_decode(value);
    return std::string(bytes.begin(), bytes.end());
}

std::vector<std::string> split_mail_store_line(const std::string& line) {
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        auto pos = line.find('\t', start);
        if (pos == std::string::npos) {
            out.push_back(line.substr(start));
            break;
        }
        out.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

struct DhtMailStorePayload {
    uint8_t version{1};
    NetworkNode::DistributedMailRecord record;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        serialization::write_int<uint8_t>(out, version);
        serialization::write_int<uint32_t>(out, record.version);
        serialization::write_int<uint64_t>(out, record.stored_at);
        serialization::write_int<uint64_t>(out, record.expires_at);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(record.message_id.data()), record.message_id.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(record.sender_address.data()), record.sender_address.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(record.recipient_address.data()), record.recipient_address.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(record.peer_label.data()), record.peer_label.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(record.payload_b64.data()), record.payload_b64.size());
        return out;
    }

    static DhtMailStorePayload deserialize(const std::vector<uint8_t>& data) {
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();
        DhtMailStorePayload payload;
        payload.version = serialization::read_int<uint8_t>(ptr, remaining);
        payload.record.version = serialization::read_int<uint32_t>(ptr, remaining);
        payload.record.stored_at = serialization::read_int<uint64_t>(ptr, remaining);
        payload.record.expires_at = serialization::read_int<uint64_t>(ptr, remaining);
        auto message_id = serialization::read_bytes(ptr, remaining);
        auto sender = serialization::read_bytes(ptr, remaining);
        auto recipient = serialization::read_bytes(ptr, remaining);
        auto peer = serialization::read_bytes(ptr, remaining);
        auto payload_b64 = serialization::read_bytes(ptr, remaining);
        payload.record.message_id.assign(message_id.begin(), message_id.end());
        payload.record.sender_address.assign(sender.begin(), sender.end());
        payload.record.recipient_address.assign(recipient.begin(), recipient.end());
        payload.record.peer_label.assign(peer.begin(), peer.end());
        payload.record.payload_b64.assign(payload_b64.begin(), payload_b64.end());
        return payload;
    }
};

struct DhtMailFindPayload {
    uint8_t version{1};
    std::string query_id;
    std::string recipient_address;
    std::string requester_label;
    uint32_t limit{64};
    uint8_t hops{1};

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        serialization::write_int<uint8_t>(out, version);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(query_id.data()), query_id.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(recipient_address.data()), recipient_address.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(requester_label.data()), requester_label.size());
        serialization::write_int<uint32_t>(out, limit);
        serialization::write_int<uint8_t>(out, hops);
        return out;
    }

    static DhtMailFindPayload deserialize(const std::vector<uint8_t>& data) {
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();
        DhtMailFindPayload payload;
        payload.version = serialization::read_int<uint8_t>(ptr, remaining);
        auto query_id = serialization::read_bytes(ptr, remaining);
        auto recipient = serialization::read_bytes(ptr, remaining);
        auto requester = serialization::read_bytes(ptr, remaining);
        payload.limit = serialization::read_int<uint32_t>(ptr, remaining);
        payload.hops = serialization::read_int<uint8_t>(ptr, remaining);
        payload.query_id.assign(query_id.begin(), query_id.end());
        payload.recipient_address.assign(recipient.begin(), recipient.end());
        payload.requester_label.assign(requester.begin(), requester.end());
        return payload;
    }
};

struct DhtMailResultsPayload {
    uint8_t version{1};
    std::string query_id;
    std::vector<NetworkNode::DistributedMailRecord> records;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        serialization::write_int<uint8_t>(out, version);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(query_id.data()), query_id.size());
        serialization::write_varint(out, records.size());
        for (const auto& record : records) {
            DhtMailStorePayload row;
            row.record = record;
            auto bytes = row.serialize();
            serialization::write_bytes(out, bytes.data(), bytes.size());
        }
        return out;
    }

    static DhtMailResultsPayload deserialize(const std::vector<uint8_t>& data) {
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();
        DhtMailResultsPayload payload;
        payload.version = serialization::read_int<uint8_t>(ptr, remaining);
        auto query_id = serialization::read_bytes(ptr, remaining);
        payload.query_id.assign(query_id.begin(), query_id.end());
        const auto count = serialization::read_varint(ptr, remaining);
        payload.records.reserve(static_cast<size_t>(count));
        for (uint64_t i = 0; i < count; ++i) {
            auto row = serialization::read_bytes(ptr, remaining);
            payload.records.push_back(DhtMailStorePayload::deserialize(row).record);
        }
        return payload;
    }
};

struct DhtMailReceiptPayload {
    uint8_t version{2};
    NetworkNode::MailStorageReceipt receipt;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        serialization::write_int<uint8_t>(out, version);
        serialization::write_int<uint32_t>(out, receipt.version);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(receipt.message_id.data()), receipt.message_id.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(receipt.recipient_address.data()), receipt.recipient_address.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(receipt.replica_label.data()), receipt.replica_label.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(receipt.storage_hash_hex.data()), receipt.storage_hash_hex.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(receipt.last_proof_hash_hex.data()), receipt.last_proof_hash_hex.size());
        serialization::write_int<uint64_t>(out, receipt.stored_at);
        serialization::write_int<uint64_t>(out, receipt.expires_at);
        serialization::write_int<uint64_t>(out, receipt.receipt_at);
        serialization::write_int<uint64_t>(out, receipt.verified_at);
        serialization::write_int<uint64_t>(out, receipt.last_challenged_at);
        serialization::write_int<uint8_t>(out, receipt.verified ? 1 : 0);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(receipt.provider_address.data()), receipt.provider_address.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(receipt.provider_pubkey_b64.data()), receipt.provider_pubkey_b64.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(receipt.provider_signature_b64.data()), receipt.provider_signature_b64.size());
        serialization::write_int<uint64_t>(out, receipt.bonded_balance_sats);
        serialization::write_int<uint8_t>(out, receipt.bond_satisfied ? 1 : 0);
        return out;
    }

    static DhtMailReceiptPayload deserialize(const std::vector<uint8_t>& data) {
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();
        DhtMailReceiptPayload payload;
        payload.version = serialization::read_int<uint8_t>(ptr, remaining);
        payload.receipt.version = serialization::read_int<uint32_t>(ptr, remaining);
        auto message_id = serialization::read_bytes(ptr, remaining);
        auto recipient = serialization::read_bytes(ptr, remaining);
        auto replica = serialization::read_bytes(ptr, remaining);
        auto storage_hash = serialization::read_bytes(ptr, remaining);
        auto last_proof_hash = serialization::read_bytes(ptr, remaining);
        payload.receipt.stored_at = serialization::read_int<uint64_t>(ptr, remaining);
        payload.receipt.expires_at = serialization::read_int<uint64_t>(ptr, remaining);
        payload.receipt.receipt_at = serialization::read_int<uint64_t>(ptr, remaining);
        payload.receipt.verified_at = serialization::read_int<uint64_t>(ptr, remaining);
        payload.receipt.last_challenged_at = serialization::read_int<uint64_t>(ptr, remaining);
        payload.receipt.verified = serialization::read_int<uint8_t>(ptr, remaining) != 0;
        if (payload.version >= 2 && remaining > 0) {
            auto provider_address = serialization::read_bytes(ptr, remaining);
            auto provider_pubkey = serialization::read_bytes(ptr, remaining);
            auto provider_signature = serialization::read_bytes(ptr, remaining);
            payload.receipt.bonded_balance_sats = serialization::read_int<uint64_t>(ptr, remaining);
            payload.receipt.bond_satisfied = serialization::read_int<uint8_t>(ptr, remaining) != 0;
            payload.receipt.provider_address.assign(provider_address.begin(), provider_address.end());
            payload.receipt.provider_pubkey_b64.assign(provider_pubkey.begin(), provider_pubkey.end());
            payload.receipt.provider_signature_b64.assign(provider_signature.begin(), provider_signature.end());
        }
        payload.receipt.message_id.assign(message_id.begin(), message_id.end());
        payload.receipt.recipient_address.assign(recipient.begin(), recipient.end());
        payload.receipt.replica_label.assign(replica.begin(), replica.end());
        payload.receipt.storage_hash_hex.assign(storage_hash.begin(), storage_hash.end());
        payload.receipt.last_proof_hash_hex.assign(last_proof_hash.begin(), last_proof_hash.end());
        return payload;
    }
};

struct DhtMailChallengePayload {
    uint8_t version{1};
    std::string challenge_id;
    std::string message_id;
    std::string recipient_address;
    std::string requester_label;
    std::string nonce_b64;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        serialization::write_int<uint8_t>(out, version);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(challenge_id.data()), challenge_id.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(message_id.data()), message_id.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(recipient_address.data()), recipient_address.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(requester_label.data()), requester_label.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(nonce_b64.data()), nonce_b64.size());
        return out;
    }

    static DhtMailChallengePayload deserialize(const std::vector<uint8_t>& data) {
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();
        DhtMailChallengePayload payload;
        payload.version = serialization::read_int<uint8_t>(ptr, remaining);
        auto challenge = serialization::read_bytes(ptr, remaining);
        auto message_id = serialization::read_bytes(ptr, remaining);
        auto recipient = serialization::read_bytes(ptr, remaining);
        auto requester = serialization::read_bytes(ptr, remaining);
        auto nonce = serialization::read_bytes(ptr, remaining);
        payload.challenge_id.assign(challenge.begin(), challenge.end());
        payload.message_id.assign(message_id.begin(), message_id.end());
        payload.recipient_address.assign(recipient.begin(), recipient.end());
        payload.requester_label.assign(requester.begin(), requester.end());
        payload.nonce_b64.assign(nonce.begin(), nonce.end());
        return payload;
    }
};

struct DhtMailProofPayload {
    uint8_t version{1};
    std::string challenge_id;
    std::string message_id;
    std::string recipient_address;
    std::string replica_label;
    std::string proof_hash_hex;
    uint64_t responded_at{0};

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        serialization::write_int<uint8_t>(out, version);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(challenge_id.data()), challenge_id.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(message_id.data()), message_id.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(recipient_address.data()), recipient_address.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(replica_label.data()), replica_label.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(proof_hash_hex.data()), proof_hash_hex.size());
        serialization::write_int<uint64_t>(out, responded_at);
        return out;
    }

    static DhtMailProofPayload deserialize(const std::vector<uint8_t>& data) {
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();
        DhtMailProofPayload payload;
        payload.version = serialization::read_int<uint8_t>(ptr, remaining);
        auto challenge = serialization::read_bytes(ptr, remaining);
        auto message_id = serialization::read_bytes(ptr, remaining);
        auto recipient = serialization::read_bytes(ptr, remaining);
        auto replica = serialization::read_bytes(ptr, remaining);
        auto proof = serialization::read_bytes(ptr, remaining);
        payload.responded_at = serialization::read_int<uint64_t>(ptr, remaining);
        payload.challenge_id.assign(challenge.begin(), challenge.end());
        payload.message_id.assign(message_id.begin(), message_id.end());
        payload.recipient_address.assign(recipient.begin(), recipient.end());
        payload.replica_label.assign(replica.begin(), replica.end());
        payload.proof_hash_hex.assign(proof.begin(), proof.end());
        return payload;
    }
};

struct DhtMailNatIntroPayload {
    uint8_t version{2};
    std::string initiator_label;
    std::string target_label;
    std::string purpose;
    uint64_t sent_at{0};
    uint8_t hops{2};
    bool request_reverse{true};
    bool reverse_response{false};
    std::vector<NetworkNode::NatCandidate> initiator_candidates;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        serialization::write_int<uint8_t>(out, version);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(initiator_label.data()), initiator_label.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(target_label.data()), target_label.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(purpose.data()), purpose.size());
        serialization::write_int<uint64_t>(out, sent_at);
        serialization::write_int<uint8_t>(out, hops);
        serialization::write_int<uint8_t>(out, request_reverse ? 1 : 0);
        serialization::write_int<uint8_t>(out, reverse_response ? 1 : 0);
        serialization::write_varint(out, initiator_candidates.size());
        for (const auto& candidate : initiator_candidates) {
            serialization::write_int<uint8_t>(out, candidate.type);
            serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(candidate.label.data()), candidate.label.size());
            serialization::write_int<uint32_t>(out, candidate.priority);
        }
        return out;
    }

    static DhtMailNatIntroPayload deserialize(const std::vector<uint8_t>& data) {
        const uint8_t* ptr = data.data();
        size_t remaining = data.size();
        DhtMailNatIntroPayload payload;
        payload.version = serialization::read_int<uint8_t>(ptr, remaining);
        auto initiator = serialization::read_bytes(ptr, remaining);
        auto target = serialization::read_bytes(ptr, remaining);
        auto purpose = serialization::read_bytes(ptr, remaining);
        payload.sent_at = serialization::read_int<uint64_t>(ptr, remaining);
        payload.hops = serialization::read_int<uint8_t>(ptr, remaining);
        if (payload.version >= 2 && remaining > 0) {
            payload.request_reverse = serialization::read_int<uint8_t>(ptr, remaining) != 0;
            payload.reverse_response = serialization::read_int<uint8_t>(ptr, remaining) != 0;
            const auto count = serialization::read_varint(ptr, remaining);
            payload.initiator_candidates.reserve(static_cast<size_t>(count));
            for (uint64_t i = 0; i < count; ++i) {
                NetworkNode::NatCandidate candidate;
                candidate.type = serialization::read_int<uint8_t>(ptr, remaining);
                auto label = serialization::read_bytes(ptr, remaining);
                candidate.priority = serialization::read_int<uint32_t>(ptr, remaining);
                candidate.label.assign(label.begin(), label.end());
                payload.initiator_candidates.push_back(std::move(candidate));
            }
        }
        payload.initiator_label.assign(initiator.begin(), initiator.end());
        payload.target_label.assign(target.begin(), target.end());
        payload.purpose.assign(purpose.begin(), purpose.end());
        return payload;
    }
};

std::string mail_storage_hash_hex(const NetworkNode::DistributedMailRecord& record) {
    const std::string material = record.payload_b64 + "\n" + record.message_id + "\n" + record.recipient_address;
    const auto digest = crypto::sha3_512(material);
    return crypto::hex_encode(digest.data(), digest.size());
}

std::string mail_storage_proof_hash_hex(const NetworkNode::DistributedMailRecord& record, const std::string& nonce_b64) {
    const std::string material = record.payload_b64 + "\n" + nonce_b64 + "\n" + record.message_id + "\n" + record.recipient_address;
    const auto digest = crypto::sha3_512(material);
    return crypto::hex_encode(digest.data(), digest.size());
}

std::array<uint8_t, 32> digest32_from_string(const std::string& text) {
    const auto digest = crypto::sha3_512(text);
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), digest.data(), out.size());
    return out;
}

std::string mail_receipt_signing_material(const NetworkNode::MailStorageReceipt& receipt) {
    std::ostringstream out;
    out << receipt.version << '\n'
        << receipt.message_id << '\n'
        << receipt.recipient_address << '\n'
        << receipt.replica_label << '\n'
        << receipt.storage_hash_hex << '\n'
        << receipt.stored_at << '\n'
        << receipt.expires_at << '\n'
        << receipt.receipt_at << '\n'
        << receipt.provider_address << '\n'
        << receipt.provider_pubkey_b64;
    return out.str();
}

bool verify_mail_receipt_signature(const NetworkNode::MailStorageReceipt& receipt) {
    if (receipt.provider_address.empty() || receipt.provider_pubkey_b64.empty() || receipt.provider_signature_b64.empty()) {
        return false;
    }
    try {
        const auto pubkey = crypto::base64_decode(receipt.provider_pubkey_b64);
        const auto signature = crypto::base64_decode(receipt.provider_signature_b64);
        if (!script::check_address(receipt.provider_address, pubkey)) {
            return false;
        }
        return script::verify_signature(uint256_t(digest32_from_string(mail_receipt_signing_material(receipt))),
                                        signature,
                                        pubkey);
    } catch (...) {
        return false;
    }
}

void refresh_mail_receipt_bond(NetworkNode::MailStorageReceipt& receipt,
                               const Blockchain* chain,
                               uint64_t minimum_bond_sats) {
    if (!chain || receipt.provider_address.empty()) {
        receipt.bonded_balance_sats = 0;
        receipt.bond_satisfied = minimum_bond_sats == 0 && !receipt.provider_signature_b64.empty();
        return;
    }
    try {
        receipt.bonded_balance_sats = static_cast<uint64_t>(std::max<int64_t>(0, chain->utxo().get_balance(receipt.provider_address)));
    } catch (...) {
        receipt.bonded_balance_sats = 0;
    }
    receipt.bond_satisfied = receipt.bonded_balance_sats >= minimum_bond_sats;
}

void sign_mail_receipt(NetworkNode::MailStorageReceipt& receipt,
                       const Wallet* wallet) {
    if (!wallet || wallet->addresses.empty() || wallet->pubkeys.empty() || wallet->privkeys.empty()) {
        return;
    }
    size_t index = 0;
    if (auto it = std::find(wallet->addresses.begin(), wallet->addresses.end(), wallet->address);
        it != wallet->addresses.end()) {
        index = static_cast<size_t>(std::distance(wallet->addresses.begin(), it));
    }
    if (index >= wallet->pubkeys.size() || index >= wallet->privkeys.size()) {
        index = 0;
    }
    receipt.provider_address = wallet->addresses[index];
    receipt.provider_pubkey_b64 = crypto::base64_encode(wallet->pubkeys[index]);
    const auto signature = script::sign_hash(uint256_t(digest32_from_string(mail_receipt_signing_material(receipt))),
                                             wallet->privkeys[index]);
    receipt.provider_signature_b64 = crypto::base64_encode(signature);
}

void append_unique_candidate(std::vector<NetworkNode::NatCandidate>& candidates,
                             std::unordered_set<std::string>& seen,
                             uint8_t type,
                             const std::string& label,
                             uint32_t priority) {
    if (label.empty() || !seen.insert(label).second) {
        return;
    }
    candidates.push_back(NetworkNode::NatCandidate{type, label, priority});
}

std::vector<std::string> discover_local_ipv4_candidate_labels(uint16_t port) {
    std::vector<std::string> labels;
    if (port == 0) return labels;
    try {
        boost::asio::io_context ctx;
        tcp::resolver resolver(ctx);
        const auto results = resolver.resolve(boost::asio::ip::host_name(), "");
        std::unordered_set<std::string> seen;
        for (const auto& entry : results) {
            const auto endpoint = entry.endpoint();
            if (!endpoint.address().is_v4() || endpoint.address().is_loopback()) continue;
            const auto label = endpoint.address().to_string() + ":" + std::to_string(port);
            if (seen.insert(label).second) {
                labels.push_back(label);
            }
        }
    } catch (...) {
    }
    return labels;
}

std::optional<std::string> parse_stun_mapped_ipv4(const std::vector<uint8_t>& response) {
    if (response.size() < 20) return std::nullopt;
    const uint16_t type = static_cast<uint16_t>((response[0] << 8) | response[1]);
    if (type != 0x0101) return std::nullopt;
    const std::array<uint8_t, 4> cookie{{0x21, 0x12, 0xA4, 0x42}};
    size_t offset = 20;
    while (offset + 4 <= response.size()) {
        const uint16_t attr_type = static_cast<uint16_t>((response[offset] << 8) | response[offset + 1]);
        const uint16_t attr_len = static_cast<uint16_t>((response[offset + 2] << 8) | response[offset + 3]);
        offset += 4;
        if (offset + attr_len > response.size()) break;
        const uint8_t* attr = response.data() + offset;
        if ((attr_type == 0x0020 || attr_type == 0x0001) && attr_len >= 8 && attr[1] == 0x01) {
            std::array<uint8_t, 4> ip_bytes{{attr[4], attr[5], attr[6], attr[7]}};
            if (attr_type == 0x0020) {
                for (size_t i = 0; i < ip_bytes.size(); ++i) {
                    ip_bytes[i] ^= cookie[i];
                }
            }
            boost::system::error_code ec;
            auto address = boost::asio::ip::address_v4(ip_bytes);
            if (!ec) return address.to_string();
        }
        offset += attr_len;
        if (attr_len % 4 != 0) {
            offset += 4 - (attr_len % 4);
        }
    }
    return std::nullopt;
}

std::optional<std::string> stun_probe_public_ip(const std::string& server,
                                                uint16_t announced_port,
                                                uint32_t timeout_ms) {
    if (server.empty()) return std::nullopt;
    const auto parsed = parse_host_port(server, 3478);
    if (!parsed) return std::nullopt;
    try {
        boost::asio::io_context ctx;
        udp::resolver resolver(ctx);
        udp::socket socket(ctx);
        socket.open(udp::v4());
        const auto endpoints = resolver.resolve(udp::v4(), parsed->first, std::to_string(parsed->second));
        auto endpoint_it = endpoints.begin();
        if (endpoint_it == endpoints.end()) return std::nullopt;
        std::array<uint8_t, 20> request{};
        request[0] = 0x00;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = 0x00;
        request[4] = 0x21;
        request[5] = 0x12;
        request[6] = 0xA4;
        request[7] = 0x42;
        std::random_device rd;
        for (size_t i = 8; i < request.size(); ++i) {
            request[i] = static_cast<uint8_t>(rd());
        }
        socket.send_to(boost::asio::buffer(request), endpoint_it->endpoint());
        socket.non_blocking(true);
        std::array<uint8_t, 512> response{};
        udp::endpoint sender;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::max<uint32_t>(timeout_ms, 100));
        while (std::chrono::steady_clock::now() < deadline) {
            boost::system::error_code ec;
            const size_t received = socket.receive_from(boost::asio::buffer(response), sender, 0, ec);
            if (!ec && received >= 20) {
                auto ip = parse_stun_mapped_ipv4(std::vector<uint8_t>(response.begin(), response.begin() + static_cast<std::ptrdiff_t>(received)));
                if (ip && !ip->empty()) {
                    return *ip + ":" + std::to_string(announced_port);
                }
                return std::nullopt;
            }
            if (ec != boost::asio::error::would_block && ec != boost::asio::error::try_again) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    } catch (...) {
    }
    return std::nullopt;
}

std::string random_nonce_b64(size_t bytes = 16) {
    std::vector<uint8_t> buffer(bytes);
    std::random_device rd;
    for (auto& byte : buffer) {
        byte = static_cast<uint8_t>(rd());
    }
    return crypto::base64_encode(buffer.data(), buffer.size());
}

bool parse_distributed_mail_record_line(const std::string& line, NetworkNode::DistributedMailRecord& record) {
    auto fields = split_mail_store_line(line);
    if (fields.size() != 8) return false;
    try {
        record.version = static_cast<uint32_t>(std::stoul(fields[0]));
        record.stored_at = std::stoull(fields[1]);
        record.expires_at = std::stoull(fields[2]);
        record.message_id = decode_mail_store_field(fields[3]);
        record.sender_address = decode_mail_store_field(fields[4]);
        record.recipient_address = decode_mail_store_field(fields[5]);
        record.peer_label = decode_mail_store_field(fields[6]);
        record.payload_b64 = decode_mail_store_field(fields[7]);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_mail_storage_receipt_line(const std::string& line, NetworkNode::MailStorageReceipt& receipt) {
    auto fields = split_mail_store_line(line);
    if (fields.size() != 11 && fields.size() != 16 && fields.size() != 20) return false;
    try {
        receipt.version = static_cast<uint32_t>(std::stoul(fields[0]));
        receipt.message_id = decode_mail_store_field(fields[1]);
        receipt.recipient_address = decode_mail_store_field(fields[2]);
        receipt.replica_label = decode_mail_store_field(fields[3]);
        receipt.storage_hash_hex = decode_mail_store_field(fields[4]);
        receipt.last_proof_hash_hex = decode_mail_store_field(fields[5]);
        receipt.stored_at = std::stoull(fields[6]);
        receipt.expires_at = std::stoull(fields[7]);
        receipt.receipt_at = std::stoull(fields[8]);
        receipt.verified_at = std::stoull(fields[9]);
        receipt.last_challenged_at = std::stoull(fields[10]);
        if (fields.size() >= 16) {
            receipt.provider_address = decode_mail_store_field(fields[11]);
            receipt.provider_pubkey_b64 = decode_mail_store_field(fields[12]);
            receipt.provider_signature_b64 = decode_mail_store_field(fields[13]);
            receipt.bonded_balance_sats = std::stoull(fields[14]);
            receipt.bond_satisfied = fields[15] == "1";
        } else {
            receipt.provider_address.clear();
            receipt.provider_pubkey_b64.clear();
            receipt.provider_signature_b64.clear();
            receipt.bonded_balance_sats = 0;
            receipt.bond_satisfied = false;
        }
        if (fields.size() >= 20) {
            receipt.slashed = fields[16] == "1";
            receipt.slashed_at = std::stoull(fields[17]);
            receipt.slash_reason = decode_mail_store_field(fields[18]);
            receipt.slash_evidence_hash_hex = decode_mail_store_field(fields[19]);
        } else {
            receipt.slashed = false;
            receipt.slashed_at = 0;
            receipt.slash_reason.clear();
            receipt.slash_evidence_hash_hex.clear();
        }
        receipt.verified = receipt.verified_at != 0;
        return true;
    } catch (...) {
        return false;
    }
}

std::string serialize_mail_storage_receipt_line(const NetworkNode::MailStorageReceipt& receipt) {
    std::ostringstream out;
    out << receipt.version << '\t'
        << encode_mail_store_field(receipt.message_id) << '\t'
        << encode_mail_store_field(receipt.recipient_address) << '\t'
        << encode_mail_store_field(receipt.replica_label) << '\t'
        << encode_mail_store_field(receipt.storage_hash_hex) << '\t'
        << encode_mail_store_field(receipt.last_proof_hash_hex) << '\t'
        << receipt.stored_at << '\t'
        << receipt.expires_at << '\t'
        << receipt.receipt_at << '\t'
        << receipt.verified_at << '\t'
        << receipt.last_challenged_at << '\t'
        << encode_mail_store_field(receipt.provider_address) << '\t'
        << encode_mail_store_field(receipt.provider_pubkey_b64) << '\t'
        << encode_mail_store_field(receipt.provider_signature_b64) << '\t'
        << receipt.bonded_balance_sats << '\t'
        << (receipt.bond_satisfied ? 1 : 0) << '\t'
        << (receipt.slashed ? 1 : 0) << '\t'
        << receipt.slashed_at << '\t'
        << encode_mail_store_field(receipt.slash_reason) << '\t'
        << encode_mail_store_field(receipt.slash_evidence_hash_hex);
    return out.str();
}

std::vector<NetworkNode::MailStorageReceipt> load_mail_storage_receipts_file(const std::filesystem::path& path,
                                                                             const std::optional<std::string>& message_id = std::nullopt) {
    std::ifstream input(path);
    if (!input) return {};

    std::vector<NetworkNode::MailStorageReceipt> out;
    std::string line;
    while (std::getline(input, line)) {
        NetworkNode::MailStorageReceipt receipt;
        if (!parse_mail_storage_receipt_line(line, receipt)) continue;
        if (message_id && !message_id->empty() && receipt.message_id != *message_id) continue;
        out.push_back(std::move(receipt));
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.message_id != b.message_id) return a.message_id < b.message_id;
        return a.replica_label < b.replica_label;
    });
    return out;
}

void save_mail_storage_receipts_file(const std::filesystem::path& path,
                                     const std::vector<NetworkNode::MailStorageReceipt>& receipts) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream output(path, std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to rewrite mail storage receipts");
    }
    for (const auto& receipt : receipts) {
        output << serialize_mail_storage_receipt_line(receipt) << '\n';
    }
}

std::string serialize_distributed_mail_record_line(const NetworkNode::DistributedMailRecord& record) {
    std::ostringstream out;
    out << record.version << '\t'
        << record.stored_at << '\t'
        << record.expires_at << '\t'
        << encode_mail_store_field(record.message_id) << '\t'
        << encode_mail_store_field(record.sender_address) << '\t'
        << encode_mail_store_field(record.recipient_address) << '\t'
        << encode_mail_store_field(record.peer_label) << '\t'
        << encode_mail_store_field(record.payload_b64);
    return out.str();
}

std::vector<NetworkNode::DistributedMailRecord> load_distributed_mail_records_file(const std::filesystem::path& path,
                                                                                   const std::optional<std::string>& recipient_address = std::nullopt,
                                                                                   size_t limit = 0) {
    std::ifstream input(path);
    if (!input) return {};

    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    std::vector<NetworkNode::DistributedMailRecord> out;
    std::string line;
    while (std::getline(input, line)) {
        NetworkNode::DistributedMailRecord record;
        if (!parse_distributed_mail_record_line(line, record)) continue;
        if (record.expires_at != 0 && record.expires_at < now) continue;
        if (recipient_address && !recipient_address->empty() &&
            !crypto::addresses_equal(*recipient_address, record.recipient_address)) {
            continue;
        }
        out.push_back(std::move(record));
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.stored_at != b.stored_at) return a.stored_at < b.stored_at;
        return a.message_id < b.message_id;
    });
    if (limit > 0 && out.size() > limit) {
        out.erase(out.begin(), out.end() - static_cast<std::ptrdiff_t>(limit));
    }
    return out;
}

bool append_distributed_mail_record_file(const std::filesystem::path& path,
                                         const NetworkNode::DistributedMailRecord& record) {
    auto existing = load_distributed_mail_records_file(path, std::nullopt, 0);
    if (std::any_of(existing.begin(), existing.end(), [&](const auto& item) {
            return item.message_id == record.message_id;
        })) {
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream output(path, std::ios::app);
    if (!output) {
        throw std::runtime_error("failed to append distributed mail store");
    }
    output << serialize_distributed_mail_record_line(record) << '\n';
    return true;
}

void save_distributed_mail_records_file(const std::filesystem::path& path,
                                        const std::vector<NetworkNode::DistributedMailRecord>& records) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream output(path, std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to rewrite distributed mail store");
    }
    for (const auto& record : records) {
        output << serialize_distributed_mail_record_line(record) << '\n';
    }
}

bool delete_distributed_mail_record_file(const std::filesystem::path& path, const std::string& message_id) {
    if (message_id.empty()) return false;
    std::ifstream input(path);
    if (!input) return false;

    std::vector<std::string> kept;
    kept.reserve(64);
    bool removed = false;
    std::string line;
    while (std::getline(input, line)) {
        NetworkNode::DistributedMailRecord record;
        if (parse_distributed_mail_record_line(line, record) && record.message_id == message_id) {
            removed = true;
            continue;
        }
        kept.push_back(line);
    }
    if (!removed) return false;

    const auto tmp = path.string() + ".tmp";
    std::ofstream output(tmp, std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to rewrite distributed mail store");
    }
    for (const auto& item : kept) {
        output << item << '\n';
    }
    output.close();
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        ec.clear();
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            throw std::runtime_error("failed to replace distributed mail store: " + ec.message());
        }
    }
    return true;
}

size_t distributed_mail_record_count_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) return 0;
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    size_t count = 0;
    std::string line;
    while (std::getline(input, line)) {
        NetworkNode::DistributedMailRecord record;
        if (!parse_distributed_mail_record_line(line, record)) continue;
        if (record.expires_at != 0 && record.expires_at < now) continue;
        ++count;
    }
    return count;
}

NetworkNode::DistributedMailRecord make_distributed_mail_record(const ChatPayload& payload,
                                                                const std::string& peer_label,
                                                                uint32_t ttl_hours) {
    NetworkNode::DistributedMailRecord record;
    record.version = 1;
    record.stored_at = static_cast<uint64_t>(std::time(nullptr));
    record.expires_at = record.stored_at + static_cast<uint64_t>(std::max<uint32_t>(ttl_hours, 1)) * 60ULL * 60ULL;
    record.message_id = chat::message_id(payload);
    record.sender_address = payload.sender;
    record.recipient_address = payload.recipient;
    record.peer_label = peer_label;
    record.payload_b64 = crypto::base64_encode(payload.serialize());
    return record;
}

std::vector<std::string> select_nearest_mail_peers(const std::vector<std::string>& labels,
                                                   const std::string& recipient_address,
                                                   size_t target,
                                                   const std::optional<std::string>& exclude_one = std::nullopt,
                                                   const std::optional<std::string>& exclude_two = std::nullopt) {
    std::vector<std::pair<uint64_t, std::string>> ranked;
    ranked.reserve(labels.size());
    for (const auto& label : labels) {
        if (exclude_one && *exclude_one == label) continue;
        if (exclude_two && *exclude_two == label) continue;
        ranked.emplace_back(dht_distance64(label, recipient_address), label);
    }
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
        if (a.first != b.first) return a.first < b.first;
        return a.second < b.second;
    });
    if (target > 0 && ranked.size() > target) {
        ranked.resize(target);
    }
    std::vector<std::string> out;
    out.reserve(ranked.size());
    for (const auto& item : ranked) out.push_back(item.second);
    return out;
}

std::optional<size_t> wallet_index_for_address(const Wallet& wallet, const std::string& address) {
    for (size_t i = 0; i < wallet.addresses.size(); ++i) {
        if (crypto::addresses_equal(wallet.addresses[i], address)) {
            return i;
        }
    }
    return std::nullopt;
}

size_t resolve_voice_sender_index(const Wallet& wallet, const std::string& address) {
    if (!address.empty()) {
        if (auto idx = wallet_index_for_address(wallet, address)) {
            return *idx;
        }
        throw std::runtime_error("voice sender address not found in wallet");
    }
    if (wallet.addresses.empty() || wallet.privkeys.empty() || wallet.pubkeys.empty()) {
        throw std::runtime_error("wallet has no voice-call key material");
    }
    return 0;
}

std::string voice_security_label(const net::NetworkNode::VoiceCallInfo& info) {
    const auto capabilities = voice::capability_summary(info.capability_flags);
    return "ECDH session | AES-GCM frames | " + info.codec + " | " + capabilities;
}

voice::SessionKey session_key_from_bytes(const std::vector<uint8_t>& bytes) {
    if (bytes.size() != voice::SessionKey{}.size()) {
        throw std::runtime_error("voice session key size invalid");
    }
    voice::SessionKey key{};
    std::memcpy(key.data(), bytes.data(), key.size());
    return key;
}

bool is_public_ipv4_address(const boost::asio::ip::address_v4& address) {
    const auto bytes = address.to_bytes();
    if (bytes[0] == 0 || bytes[0] == 10 || bytes[0] == 127) return false;
    if (bytes[0] == 169 && bytes[1] == 254) return false;
    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;
    if (bytes[0] == 192 && bytes[1] == 168) return false;
    if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return false;
    if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2) return false;
    if (bytes[0] == 198 && bytes[1] == 18) return false;
    if (bytes[0] == 198 && bytes[1] == 19) return false;
    if (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) return false;
    if (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) return false;
    if (bytes[0] == 224 || bytes[0] >= 240) return false;
    if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255) return false;
    return true;
}

std::string shell_escape(const std::string& value) {
    std::string out = "'";
    for (char ch : value) {
        if (ch == '\'') out += "'\\''";
        else out.push_back(ch);
    }
    out.push_back('\'');
    return out;
}

struct CommandResult {
    int exit_code{1};
    std::string output;
};

CommandResult run_command_capture(const std::string& command) {
    CommandResult result;
#ifdef _WIN32
    FILE* pipe = _popen(command.c_str(), "r");
#else
    FILE* pipe = popen(command.c_str(), "r");
#endif
    if (!pipe) {
        result.output = "failed to launch helper command";
        return result;
    }

    std::array<char, 256> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        result.output += buffer.data();
    }
#ifdef _WIN32
    result.exit_code = _pclose(pipe);
#else
    result.exit_code = pclose(pipe);
#endif
    return result;
}

bool command_available(const std::string& name) {
#ifdef _WIN32
    auto result = run_command_capture("where " + name + " >NUL 2>&1");
#else
    auto result = run_command_capture("command -v " + shell_escape(name) + " >/dev/null 2>&1");
#endif
    return result.exit_code == 0;
}

std::string parse_ipv4_literal_body(std::string body) {
    body.erase(body.begin(), std::find_if(body.begin(), body.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    body.erase(std::find_if(body.rbegin(), body.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), body.end());
    if (body.empty()) {
        throw std::invalid_argument("empty IP detection response");
    }
    auto parsed = boost::asio::ip::make_address_v4(body);
    if (!is_public_ipv4_address(parsed)) {
        throw std::invalid_argument("non-public IPv4");
    }
    return parsed.to_string();
}

std::string extract_first_ipv4_literal(const std::string& body) {
    static const std::regex ip_pattern(R"((\d{1,3}(?:\.\d{1,3}){3}))");
    std::smatch match;
    if (!std::regex_search(body, match, ip_pattern) || match.empty()) {
        throw std::invalid_argument("Invalid IPv4");
    }
    return match.str(1);
}

struct IpDetectService {
    std::string host;
    std::string port;
    std::string path;
};

std::string https_detect_ip(const IpDetectService& service) {
    boost::asio::io_context ctx;
    ssl::context ssl_ctx(ssl::context::tls_client);
    ssl_ctx.set_default_verify_paths();

    tcp::resolver resolver(ctx);
    beast::ssl_stream<beast::tcp_stream> stream(ctx, ssl_ctx);
    if (!SSL_set_tlsext_host_name(stream.native_handle(), service.host.c_str())) {
        throw std::runtime_error("ip detect tls sni setup failed");
    }
    stream.set_verify_mode(ssl::verify_peer);
    stream.set_verify_callback(ssl::host_name_verification(service.host));

    auto results = resolver.resolve(service.host, service.port);
    beast::get_lowest_layer(stream).connect(results);
    stream.handshake(ssl::stream_base::client);

    http::request<http::empty_body> req{http::verb::get, service.path, 11};
    req.set(http::field::host, service.host);
    req.set(http::field::user_agent, "CryptEX-IPDetect");

    http::write(stream, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(stream, buffer, res);

    beast::error_code ec;
    stream.shutdown(ec);
    if (ec == boost::asio::error::eof) {
        ec = {};
    }
    if (ec) {
        throw beast::system_error{ec};
    }
    if (res.result() != http::status::ok) {
        throw std::runtime_error("IP detect failed HTTP " + std::to_string(static_cast<unsigned>(res.result_int())));
    }
    return parse_ipv4_literal_body(res.body());
}

void read_exact(boost::asio::ip::tcp::socket& socket, void* data, std::size_t size) {
    boost::asio::read(socket, boost::asio::buffer(data, size));
}

void write_all(boost::asio::ip::tcp::socket& socket, const std::vector<uint8_t>& data) {
    boost::asio::write(socket, boost::asio::buffer(data.data(), data.size()));
}

boost::asio::ip::tcp::endpoint connect_via_socks5(boost::asio::io_context& ctx,
                                                  boost::asio::ip::tcp::socket& socket,
                                                  const std::string& proxy_host,
                                                  uint16_t proxy_port,
                                                  const std::string& host,
                                                  uint16_t port,
                                                  bool remote_dns) {
    boost::asio::ip::tcp::resolver resolver(ctx);
    auto proxy_endpoints = resolver.resolve(proxy_host, std::to_string(proxy_port));
    boost::asio::connect(socket, proxy_endpoints);

    write_all(socket, {0x05, 0x01, 0x00});
    std::array<uint8_t, 2> method_reply{};
    read_exact(socket, method_reply.data(), method_reply.size());
    if (method_reply[0] != 0x05 || method_reply[1] != 0x00) {
        throw std::runtime_error("SOCKS5 proxy does not allow unauthenticated access");
    }

    std::vector<uint8_t> request{0x05, 0x01, 0x00};
    if (is_ipv4_literal(host)) {
        request.push_back(0x01);
        auto addr = boost::asio::ip::make_address_v4(host).to_bytes();
        request.insert(request.end(), addr.begin(), addr.end());
    } else if (remote_dns) {
        if (host.size() > 255) throw std::runtime_error("SOCKS5 hostname too long");
        request.push_back(0x03);
        request.push_back(static_cast<uint8_t>(host.size()));
        request.insert(request.end(), host.begin(), host.end());
    } else {
        auto endpoints = resolver.resolve(host, std::to_string(port));
        auto endpoint = *endpoints.begin();
        if (!endpoint.endpoint().address().is_v4()) {
            throw std::runtime_error("SOCKS5 local resolve requires IPv4");
        }
        request.push_back(0x01);
        auto addr = endpoint.endpoint().address().to_v4().to_bytes();
        request.insert(request.end(), addr.begin(), addr.end());
    }
    request.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    request.push_back(static_cast<uint8_t>(port & 0xFF));
    write_all(socket, request);

    std::array<uint8_t, 4> reply{};
    read_exact(socket, reply.data(), reply.size());
    if (reply[0] != 0x05 || reply[1] != 0x00) {
        throw std::runtime_error("SOCKS5 connect request failed");
    }

    switch (reply[3]) {
    case 0x01: {
        std::array<uint8_t, 6> ignore{};
        read_exact(socket, ignore.data(), ignore.size());
        break;
    }
    case 0x03: {
        std::array<uint8_t, 1> len{};
        read_exact(socket, len.data(), len.size());
        std::vector<uint8_t> ignore(static_cast<size_t>(len[0]) + 2);
        read_exact(socket, ignore.data(), ignore.size());
        break;
    }
    case 0x04: {
        std::array<uint8_t, 18> ignore{};
        read_exact(socket, ignore.data(), ignore.size());
        break;
    }
    default:
        throw std::runtime_error("SOCKS5 reply address type unsupported");
    }

    if (is_ipv4_literal(host)) {
        return {boost::asio::ip::make_address(host), port};
    }
    return {};
}

std::string netgroup_from_host(const std::string& host) {
    try {
        auto address = boost::asio::ip::make_address(host);
        if (address.is_v4()) {
            auto bytes = address.to_v4().to_bytes();
            return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + ".0.0/16";
        }
    } catch (...) {
    }

    std::string lowered = host;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return "host:" + lowered;
}

std::string generate_lan_discovery_node_id() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream out;
    out << std::hex << dist(gen) << dist(gen);
    return out.str();
}

std::vector<std::string> split_discovery_fields(const std::string& payload) {
    std::vector<std::string> fields;
    std::stringstream ss(payload);
    std::string item;
    while (std::getline(ss, item, '|')) {
        fields.push_back(item);
    }
    return fields;
}

} // namespace

// ---------------- Message helpers ----------------
std::vector<uint8_t> Message::serialize() const {
    std::vector<uint8_t> out;
    uint32_t magic_be = htonl(message_magic());
    out.resize(4 + 1 + 4);
    std::memcpy(out.data(), &magic_be, 4);
    out[4] = static_cast<uint8_t>(type);
    uint32_t len = static_cast<uint32_t>(payload.size());
    uint32_t len_be = htonl(len);
    std::memcpy(out.data() + 5, &len_be, 4);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

Message Message::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 9) throw std::runtime_error("message too small");
    uint32_t magic;
    std::memcpy(&magic, data.data(), 4);
    magic = ntohl(magic);
    if (magic != message_magic()) throw std::runtime_error("bad magic");
    Message m;
    m.type = static_cast<MessageType>(data[4]);
    uint32_t len;
    std::memcpy(&len, data.data() + 5, 4);
    len = ntohl(len);
    if (data.size() != len + 9) throw std::runtime_error("length mismatch");
    m.payload.assign(data.begin() + 9, data.end());
    return m;
}

// ---------------- PeerAddress ----------------
std::array<uint8_t,7> PeerAddress::to_bytes() const {
    std::array<uint8_t,7> out{};
    uint32_t ip_be = htonl(ip.addr);
    std::memcpy(out.data(), &ip_be, 4);
    uint16_t port_be = htons(port);
    std::memcpy(out.data() + 4, &port_be, 2);
    out[6] = flags;
    return out;
}

PeerAddress PeerAddress::from_bytes(const uint8_t* data, size_t len) {
    if (len < 7) throw std::runtime_error("peer bytes too small");
    PeerAddress p;
    uint32_t ip_be;
    std::memcpy(&ip_be, data, 4);
    p.ip.addr = ntohl(ip_be);
    uint16_t port_be;
    std::memcpy(&port_be, data + 4, 2);
    p.port = ntohs(port_be);
    p.flags = data[6];
    return p;
}

// ---------------- ChatPayload ----------------
std::vector<uint8_t> ChatPayload::serialize() const {
    if (version < 2) {
        std::vector<uint8_t> out;
        out.push_back(chat_type);
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(channel.data()), channel.size());
        serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(recipient.data()), recipient.size());
        serialization::write_bytes(out, body.data(), body.size());
        return out;
    }

    std::vector<uint8_t> out;
    out.push_back(version);
    out.push_back(chat_type);
    out.push_back(flags);
    if (version >= 3) {
        out.push_back(kdf_profile);
    }
    if (version >= 4) {
        out.push_back(cipher_profile);
    }
    serialization::write_int<uint64_t>(out, timestamp);
    serialization::write_int<uint64_t>(out, nonce);
    serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(sender.data()), sender.size());
    serialization::write_bytes(out, sender_pubkey.data(), sender_pubkey.size());
    serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(channel.data()), channel.size());
    serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(recipient.data()), recipient.size());
    serialization::write_bytes(out, recipient_pubkey.data(), recipient_pubkey.size());
    serialization::write_bytes(out, wrapped_key.data(), wrapped_key.size());
    serialization::write_bytes(out, body.data(), body.size());
    serialization::write_bytes(out, iv.data(), iv.size());
    serialization::write_bytes(out, auth_tag.data(), auth_tag.size());
    serialization::write_bytes(out, signature.data(), signature.size());
    return out;
}

ChatPayload ChatPayload::deserialize(const std::vector<uint8_t>& data) {
    ChatPayload c;
    if (data.empty()) throw std::runtime_error("chat payload empty");
    const uint8_t* ptr = data.data();
    size_t rem = data.size();
    if (*ptr <= 1) {
        c.version = 1;
        c.chat_type = *ptr; ptr++; rem--;
        auto chan = serialization::read_bytes(ptr, rem);
        c.channel.assign(chan.begin(), chan.end());
        auto rec = serialization::read_bytes(ptr, rem);
        c.recipient.assign(rec.begin(), rec.end());
        c.body = serialization::read_bytes(ptr, rem);
        return c;
    }

    c.version = *ptr; ptr++; rem--;
    c.chat_type = serialization::read_int<uint8_t>(ptr, rem);
    c.flags = serialization::read_int<uint8_t>(ptr, rem);
    if (c.version >= 3) {
        c.kdf_profile = serialization::read_int<uint8_t>(ptr, rem);
    }
    if (c.version >= 4) {
        c.cipher_profile = serialization::read_int<uint8_t>(ptr, rem);
    }
    c.timestamp = serialization::read_int<uint64_t>(ptr, rem);
    c.nonce = serialization::read_int<uint64_t>(ptr, rem);
    auto sender = serialization::read_bytes(ptr, rem);
    c.sender.assign(sender.begin(), sender.end());
    c.sender_pubkey = serialization::read_bytes(ptr, rem);
    auto chan = serialization::read_bytes(ptr, rem);
    c.channel.assign(chan.begin(), chan.end());
    auto rec = serialization::read_bytes(ptr, rem);
    c.recipient.assign(rec.begin(), rec.end());
    c.recipient_pubkey = serialization::read_bytes(ptr, rem);
    c.wrapped_key = serialization::read_bytes(ptr, rem);
    c.body = serialization::read_bytes(ptr, rem);
    c.iv = serialization::read_bytes(ptr, rem);
    c.auth_tag = serialization::read_bytes(ptr, rem);
    c.signature = serialization::read_bytes(ptr, rem);
    return c;
}

// ---------------- WorkRequest ----------------
std::vector<uint8_t> WorkRequest::serialize() const {
    std::vector<uint8_t> out = header.serialize();
    serialization::write_int<uint32_t>(out, height);
    serialization::write_int<uint32_t>(out, nonce_start);
    serialization::write_int<uint32_t>(out, nonce_end);
    return out;
}

WorkRequest WorkRequest::deserialize(const std::vector<uint8_t>& data) {
    WorkRequest w;
    const uint8_t* ptr = data.data();
    size_t rem = data.size();
    w.header = BlockHeader::deserialize(ptr, rem);
    w.height = serialization::read_int<uint32_t>(ptr, rem);
    w.nonce_start = serialization::read_int<uint32_t>(ptr, rem);
    w.nonce_end = serialization::read_int<uint32_t>(ptr, rem);
    return w;
}

// ---------------- VersionPayload ----------------
std::vector<uint8_t> VersionPayload::serialize() const {
    std::vector<uint8_t> out;
    serialization::write_int<uint32_t>(out, protocol_version);
    serialization::write_int<uint32_t>(out, best_height);
    serialization::write_int<uint16_t>(out, listen_port);
    uint8_t encoded_flags = flags;
    if (advertised_ip) encoded_flags |= 0x01;
    out.push_back(encoded_flags);
    if (advertised_ip) {
        auto ip_be = htonl(advertised_ip->addr);
        const auto* ptr = reinterpret_cast<const uint8_t*>(&ip_be);
        out.insert(out.end(), ptr, ptr + sizeof(ip_be));
    }
    return out;
}

VersionPayload VersionPayload::deserialize(const std::vector<uint8_t>& data) {
    VersionPayload payload;
    if (data.size() < 8) throw std::runtime_error("version payload too small");
    const uint8_t* ptr = data.data();
    size_t rem = data.size();
    payload.protocol_version = serialization::read_int<uint32_t>(ptr, rem);
    payload.best_height = serialization::read_int<uint32_t>(ptr, rem);
    if (rem >= sizeof(uint16_t) + sizeof(uint8_t)) {
        payload.listen_port = serialization::read_int<uint16_t>(ptr, rem);
        payload.flags = *ptr++;
        --rem;
        if ((payload.flags & 0x01) != 0) {
            if (rem < 4) throw std::runtime_error("truncated advertised ip");
            uint32_t ip_be;
            std::memcpy(&ip_be, ptr, sizeof(ip_be));
            payload.advertised_ip = ip_address{ntohl(ip_be)};
            ptr += sizeof(ip_be);
            rem -= sizeof(ip_be);
        }
    } else {
        payload.listen_port = default_p2p_port();
        payload.flags = 0;
    }
    return payload;
}

// ---------------- PeerSession ----------------
PeerSession::PeerSession(boost::asio::ip::tcp::socket socket,
                         NetworkNode& owner,
                         std::optional<std::string> remote_label_override,
                         std::optional<boost::asio::ip::tcp::endpoint> endpoint_override)
: socket_(std::move(socket)),
  owner_(owner),
  remote_label_override_(std::move(remote_label_override)),
  endpoint_override_(std::move(endpoint_override)) {}

void PeerSession::start() {
    read_header();
}

void PeerSession::read_header() {
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(header_buf_),
        [this, self](std::error_code ec, std::size_t) {
            if (ec) {
                owner_.remove_session(self);
                return;
            }
            std::memcpy(&incoming_magic_, header_buf_.data(), sizeof(incoming_magic_));
            incoming_magic_ = ntohl(incoming_magic_);
            incoming_type_ = header_buf_[4];
            std::memcpy(&incoming_length_, header_buf_.data() + 5, sizeof(incoming_length_));
            incoming_length_ = ntohl(incoming_length_);
            if (incoming_magic_ != message_magic() || incoming_length_ > 8'000'000) {
                owner_.remove_session(self);
                return;
            }
            body_.resize(incoming_length_);
            read_body();
        });
}

void PeerSession::read_body() {
    auto self = shared_from_this();
    boost::asio::async_read(socket_, boost::asio::buffer(body_.data(), body_.size()),
        [this, self](std::error_code ec, std::size_t) {
            if (ec) {
                owner_.remove_session(self);
                return;
            }
            Message msg;
            msg.type = static_cast<MessageType>(incoming_type_);
            msg.payload = body_;
            handle_message(msg);
            read_header();
        });
}

void PeerSession::handle_message(const Message& msg) {
    if (owner_.handlers_.count(msg.type)) {
        owner_.handlers_[msg.type](msg, shared_from_this());
    }
}

void PeerSession::send(const Message& msg) {
    auto raw = msg.serialize();
    std::lock_guard<std::mutex> guard(write_mutex_);
    bool writing = !outbox_.empty();
    outbox_.push_back(std::move(raw));
    if (!writing) write_next();
}

void PeerSession::write_next() {
    if (outbox_.empty()) return;
    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(outbox_.front()),
        [this, self](std::error_code ec, std::size_t) {
            std::lock_guard<std::mutex> guard(write_mutex_);
            if (!ec) {
                outbox_.pop_front();
                if (!outbox_.empty()) write_next();
            } else {
                owner_.remove_session(self);
            }
        });
}

std::string PeerSession::remote_label() const {
    if (remote_label_override_) return *remote_label_override_;
    try {
        return socket_.remote_endpoint().address().to_string() + ":" +
               std::to_string(socket_.remote_endpoint().port());
    } catch (...) {
        return "unknown";
    }
}

boost::asio::ip::tcp::endpoint PeerSession::endpoint() const {
    if (endpoint_override_) return *endpoint_override_;
    try {
        return socket_.remote_endpoint();
    } catch (...) {
        return {boost::asio::ip::address_v4::any(), 0};
    }
}

void PeerSession::close() {
    boost::system::error_code ec;
    socket_.close(ec);
    owner_.remove_session(shared_from_this());
}

// ---------------- NetworkNode ----------------
NetworkNode::NetworkNode(boost::asio::io_context& ctx, uint16_t port, std::filesystem::path data_dir)
    : ctx_(ctx),
      acceptor_(ctx, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      listen_port_(port),
      peer_maintenance_timer_(ctx),
      lan_discovery_socket_(ctx),
      lan_discovery_timer_(ctx),
      lan_discovery_node_id_(generate_lan_discovery_node_id()),
      peers_file_(data_dir / "peers.dat"),
      peer_state_file_(data_dir / "peer_state.dat"),
      chat_inbox_file_(data_dir / "chat_inbox.log"),
      chat_history_file_(data_dir / "chat_history.dat"),
      mail_history_file_(data_dir / "p2pmail_history.dat"),
      distributed_mail_file_(data_dir / "p2pmail_store.dat"),
      mail_receipts_file_(data_dir / "p2pmail_receipts.dat") {
    load_peers();
    load_peer_state();
    register_default_handlers();
}

void NetworkNode::attach_blockchain(Blockchain* chain) {
    chain_ = chain;
    if (chain_) {
        best_height = chain_->best_height();
        update_chain_approval_state();
    }
}

void NetworkNode::start() {
    do_accept();
    start_lan_discovery();
    update_chain_approval_state();
    schedule_peer_maintenance();
}

void NetworkNode::stop() {
    {
        std::lock_guard<std::mutex> guard(sessions_mutex_);
        for (auto& s : sessions_) {
            std::error_code ec;
            s->send({MessageType::PING, {}}); // try flush
            s.reset();
        }
        sessions_.clear();
    }
    acceptor_.close();
    peer_maintenance_timer_.cancel();
    lan_discovery_timer_.cancel();
    if (lan_discovery_socket_.is_open()) {
        boost::system::error_code ec;
        lan_discovery_socket_.close(ec);
    }
    clear_port_mapping();
    {
        std::lock_guard<std::mutex> guard(pending_connect_mutex_);
        pending_connects_.clear();
    }
    save_peers();
    save_peer_state();
    update_chain_approval_state();
}

void NetworkNode::connect(const std::string& host, uint16_t port) {
    if (!network_active()) return;
    const auto requested_label = host + ":" + std::to_string(port);
    if (requested_label.empty() || is_self_label(requested_label)) return;
    if (!begin_pending_connect(requested_label)) return;
    record_peer_label(requested_label, "manual");

    if (proxy_) {
        boost::asio::post(ctx_, [this, host, port, requested_label]() {
            boost::asio::ip::tcp::socket socket(ctx_);
            std::optional<std::string> remote_label_override;
            std::optional<boost::asio::ip::tcp::endpoint> endpoint_override;
            try {
                remote_label_override = requested_label;
                auto logical_endpoint = connect_via_socks5(ctx_, socket, proxy_->host, proxy_->port, host, port, proxy_->remote_dns);
                if (logical_endpoint.port() != 0) {
                    endpoint_override = logical_endpoint;
                }
            } catch (const std::exception& ex) {
                end_pending_connect(requested_label);
                note_peer_connection_attempt(requested_label, false, ex.what());
                save_peer_state();
                log_warn("net", "outbound proxy connect failed peer=" + requested_label +
                                " reason=" + ex.what());
                return;
            }

            end_pending_connect(requested_label);
            auto session = std::make_shared<PeerSession>(std::move(socket), *this, remote_label_override, endpoint_override);
            auto label = session->remote_label();
            if (is_banned(label) || is_self_label(label)) {
                session->close();
                return;
            }
            {
                std::lock_guard<std::mutex> guard(sessions_mutex_);
                sessions_.push_back(session);
            }
            record_peer_label(label, "proxy");
            note_peer_connection_attempt(label, true);
            session->start();
            session->send(build_version_message());
            update_chain_approval_state();
        });
        return;
    }

    auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(ctx_);
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ctx_);
    resolver->async_resolve(host, std::to_string(port),
        [this, host, port, requested_label, resolver, socket](
            const boost::system::error_code& ec,
            boost::asio::ip::tcp::resolver::results_type endpoints) {
            if (ec || !network_active()) {
                end_pending_connect(requested_label);
                if (ec) {
                    note_peer_connection_attempt(requested_label, false, ec.message());
                    save_peer_state();
                    log_warn("net", "resolve failed peer=" + requested_label +
                                    " reason=" + ec.message());
                }
                return;
            }

            boost::asio::async_connect(*socket, endpoints,
                [this, host, port, requested_label, socket](
                    const boost::system::error_code& connect_ec,
                    const boost::asio::ip::tcp::endpoint& endpoint) {
                    end_pending_connect(requested_label);
                    if (connect_ec || !network_active()) {
                        if (connect_ec) {
                            note_peer_connection_attempt(requested_label, false, connect_ec.message());
                            save_peer_state();
                            log_warn("net", "outbound connect failed peer=" + requested_label +
                                            " reason=" + connect_ec.message());
                        }
                        return;
                    }

                    std::optional<std::string> remote_label_override;
                    if (!is_ipv4_literal(host)) {
                        remote_label_override = host + ":" + std::to_string(port);
                    }
                    auto session = std::make_shared<PeerSession>(std::move(*socket), *this, remote_label_override,
                                                                 std::optional<boost::asio::ip::tcp::endpoint>(endpoint));
                    const auto label = session->remote_label();
                    if (is_banned(label) || is_self_label(label)) {
                        session->close();
                        return;
                    }
                    {
                        std::lock_guard<std::mutex> guard(sessions_mutex_);
                        sessions_.push_back(session);
                    }
                    record_peer(session->endpoint());
                    note_peer_connection_attempt(label, true);
                    session->start();
                    session->send(build_version_message());
                    update_chain_approval_state();
                });
        });
}

void NetworkNode::broadcast(const Message& msg) {
    if (!network_active()) return;
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    for (auto& s : sessions_) s->send(msg);
}

bool NetworkNode::send_to(const std::string& label, const Message& msg) {
    if (!network_active()) return false;
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    for (auto& session : sessions_) {
        if (session && session->remote_label() == label) {
            session->send(msg);
            return true;
        }
    }
    return false;
}

size_t NetworkNode::broadcast_chat(const Message& msg, const std::shared_ptr<PeerSession>& exclude) {
    if (!network_active()) return 0;
    std::vector<std::shared_ptr<PeerSession>> preferred;
    std::vector<std::shared_ptr<PeerSession>> fallback;
    {
        std::lock_guard<std::mutex> guard(sessions_mutex_);
        for (const auto& session : sessions_) {
            if (!session) continue;
            if (exclude && session == exclude) continue;
            fallback.push_back(session);
            if (session->version_seen()) {
                preferred.push_back(session);
            }
        }
    }

    auto& recipients = preferred.empty() ? fallback : preferred;
    for (const auto& session : recipients) {
        session->send(msg);
    }
    return recipients.size();
}

void NetworkNode::set_handler(MessageType type, MessageHandler handler) {
    handlers_[type] = std::move(handler);
}

std::vector<PeerAddress> NetworkNode::peers() const {
    std::vector<PeerAddress> out;
    std::unordered_set<std::string> labels;
    {
        std::lock_guard<std::mutex> guard(peers_mutex_);
        labels = known_peers_;
    }
    if (advertised_self_) {
        labels.insert(endpoint_label(advertised_self_->ip, advertised_self_->port));
    }
    for (const auto& label : labels) {
        auto pos = label.find(':');
        if (pos == std::string::npos) continue;
        try {
            auto ip = ip_address::from_string(label.substr(0, pos));
            uint16_t port = static_cast<uint16_t>(std::stoi(label.substr(pos + 1)));
            PeerAddress p; p.ip = ip; p.port = port; p.flags = 0;
            out.push_back(p);
        } catch (...) {}
    }
    return out;
}

std::vector<std::string> NetworkNode::active_peer_labels() const {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    out.reserve(sessions_.size());
    for (const auto& session : sessions_) {
        if (session) out.push_back(session->remote_label());
    }
    return out;
}

std::vector<NetworkNode::PeerInfo> NetworkNode::peer_statuses() {
    std::unordered_set<std::string> connected_labels;
    std::unordered_map<std::string, uint32_t> heights;
    {
        std::lock_guard<std::mutex> guard(sessions_mutex_);
        for (const auto& session : sessions_) {
            if (session) connected_labels.insert(session->remote_label());
        }
    }
    {
        std::lock_guard<std::mutex> guard(sync_mutex_);
        heights = peer_heights_;
    }

    std::vector<PeerInfo> out;
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    {
        std::lock_guard<std::mutex> guard(peer_state_mutex_);
        for (const auto& label : connected_labels) {
            if (!peer_states_.count(label)) {
                peer_states_[label] = PeerState{};
                peer_states_[label].last_updated = now;
                peer_states_[label].netgroup = peer_netgroup(label);
            }
        }
        std::unordered_set<std::string> known_copy;
        {
            std::lock_guard<std::mutex> peers_guard(peers_mutex_);
            known_copy = known_peers_;
        }
        for (const auto& label : known_copy) {
            if (!peer_states_.count(label)) {
                peer_states_[label] = PeerState{};
                peer_states_[label].last_updated = now;
                peer_states_[label].netgroup = peer_netgroup(label);
            }
        }

        for (auto& [label, state] : peer_states_) {
            decay_peer_state_locked(label, now);
            PeerInfo info;
            info.label = label;
            info.score = state.score;
            info.banned = state.banned_until > now;
            info.banned_until = state.banned_until;
            info.connected = connected_labels.count(label) > 0;
            auto it = heights.find(label);
            info.announced_height = (it != heights.end()) ? it->second : 0;
            info.last_seen = state.last_seen;
            info.last_connected = state.last_connected;
            info.successful_connections = state.successful_connections;
            info.failed_connections = state.failed_connections;
            info.invalid_messages = state.invalid_messages;
            info.source = state.source;
            info.netgroup = state.netgroup;
            info.last_reason = state.last_reason;
            out.push_back(std::move(info));
        }
    }
    std::sort(out.begin(), out.end(), [](const PeerInfo& a, const PeerInfo& b) {
        return a.label < b.label;
    });
    return out;
}

NetworkNode::SyncStatus NetworkNode::sync_status() const {
    SyncStatus status;
    status.local_height = chain_ ? static_cast<uint32_t>(chain_->best_height()) : best_height;
    {
        std::lock_guard<std::mutex> guard(sessions_mutex_);
        status.connected_peers = sessions_.size();
        for (const auto& session : sessions_) {
            if (session && session->version_seen()) {
                ++status.validated_peers;
            }
        }
    }
    {
        std::lock_guard<std::mutex> guard(sync_mutex_);
        for (const auto& [label, height] : peer_heights_) {
            (void) label;
            status.best_peer_height = std::max(status.best_peer_height, height);
        }
        status.queued_blocks = queued_blocks_.size();
        status.inflight_blocks = inflight_blocks_.size();
    }
    status.syncing = status.best_peer_height > status.local_height ||
                     status.queued_blocks > 0 ||
                     status.inflight_blocks > 0;
    return status;
}

void NetworkNode::update_chain_approval_state() {
    if (!chain_) return;
    auto status = sync_status();
    const bool saw_network = status.validated_peers > 0 || status.best_peer_height > 0;
    bool approved = true;
    uint64_t peer_count = static_cast<uint64_t>(status.validated_peers);
    uint64_t network_height = status.best_peer_height;

    if (saw_network) {
        approved = !status.syncing && status.local_height >= status.best_peer_height;
    } else {
        approved = status.local_height > 0;
        peer_count = 0;
        network_height = approved ? status.local_height : (status.local_height + 1);
    }

    chain_->set_sync_approval(approved, peer_count, network_height);
}

void NetworkNode::remove_session(const std::shared_ptr<PeerSession>& peer) {
    if (!peer) return;
    const auto label = peer->remote_label();
    {
        std::lock_guard<std::mutex> guard(sessions_mutex_);
        sessions_.erase(std::remove_if(sessions_.begin(), sessions_.end(),
                                       [&](const auto& session) { return !session || session == peer; }),
                        sessions_.end());
    }
    {
        std::lock_guard<std::mutex> guard(sync_mutex_);
        peer_heights_.erase(label);
    }
    {
        std::lock_guard<std::mutex> guard(peer_state_mutex_);
        auto& state = peer_states_[label];
        const auto now = static_cast<int64_t>(std::time(nullptr));
        if (state.netgroup.empty()) state.netgroup = peer_netgroup(label);
        state.last_seen = now;
        state.last_updated = now;
    }
    update_chain_approval_state();
}

void NetworkNode::schedule_peer_maintenance() {
    peer_maintenance_timer_.expires_after(std::chrono::seconds(30));
    peer_maintenance_timer_.async_wait([this](const boost::system::error_code& ec) {
        if (ec || !acceptor_.is_open()) {
            return;
        }
        if (network_active()) {
            if (mail_policy_.nat_assist) {
                discover_public_endpoint();
            }
            resolve_seed_endpoints();
            save_peers();
            connect_known_peers(std::min<size_t>(4, constants::MAX_PEER_CONNECTIONS));
            maintain_mail_storage_proofs();
        }
        update_chain_approval_state();
        schedule_peer_maintenance();
    });
}

uint16_t NetworkNode::lan_discovery_port() const {
    const uint32_t base = listen_port_ ? listen_port_ : default_p2p_port();
    return static_cast<uint16_t>(std::min<uint32_t>(65535, base + constants::LAN_DISCOVERY_PORT_OFFSET));
}

void NetworkNode::start_lan_discovery() {
    if (!discovery_enabled_ || !network_active() || lan_discovery_socket_.is_open()) return;

    boost::system::error_code ec;
    const auto port = lan_discovery_port();
    lan_discovery_socket_.open(boost::asio::ip::udp::v4(), ec);
    if (ec) {
        log_warn("net", "LAN discovery socket open failed: " + ec.message());
        return;
    }
    lan_discovery_socket_.set_option(boost::asio::socket_base::reuse_address(true), ec);
    ec.clear();
    lan_discovery_socket_.set_option(boost::asio::socket_base::broadcast(true), ec);
    ec.clear();
    lan_discovery_socket_.bind({boost::asio::ip::udp::v4(), port}, ec);
    if (ec) {
        log_warn("net", "LAN discovery bind failed on UDP " + std::to_string(port) +
                        ": " + ec.message());
        boost::system::error_code close_ec;
        lan_discovery_socket_.close(close_ec);
        return;
    }

    log_info("net", "LAN discovery listening on UDP " + std::to_string(port));
    read_lan_discovery();
    announce_lan_presence();
    schedule_lan_discovery_announce();
}

void NetworkNode::schedule_lan_discovery_announce() {
    lan_discovery_timer_.expires_after(std::chrono::seconds(constants::LAN_DISCOVERY_INTERVAL_SECONDS));
    lan_discovery_timer_.async_wait([this](const boost::system::error_code& ec) {
        if (ec || !lan_discovery_socket_.is_open()) {
            return;
        }
        if (network_active()) {
            announce_lan_presence();
        }
        schedule_lan_discovery_announce();
    });
}

void NetworkNode::announce_lan_presence() {
    if (!lan_discovery_socket_.is_open() || !network_active()) return;
    const auto port = listen_port_ ? listen_port_ : default_p2p_port();
    const auto height = chain_ ? chain_->best_height() : best_height;
    auto payload = std::make_shared<std::string>(
        std::string(constants::LAN_DISCOVERY_MAGIC) + "|" +
        lan_discovery_node_id_ + "|" +
        std::to_string(message_magic()) + "|" +
        network_name(params().network) + "|" +
        std::to_string(port) + "|" +
        std::to_string(height));
    auto endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::broadcast(),
                                                   lan_discovery_port());
    lan_discovery_socket_.async_send_to(boost::asio::buffer(*payload), endpoint,
                                        [payload](const boost::system::error_code&, std::size_t) {});
}

void NetworkNode::read_lan_discovery() {
    if (!lan_discovery_socket_.is_open()) return;
    lan_discovery_socket_.async_receive_from(
        boost::asio::buffer(lan_discovery_buffer_),
        lan_discovery_remote_,
        [this](const boost::system::error_code& ec, std::size_t bytes) {
            if (!ec && bytes > 0) {
                try {
                    if (lan_discovery_remote_.address().is_v4()) {
                        const std::string payload(lan_discovery_buffer_.data(), bytes);
                        const auto fields = split_discovery_fields(payload);
                        if (fields.size() >= 6 &&
                            fields[0] == constants::LAN_DISCOVERY_MAGIC &&
                            fields[1] != lan_discovery_node_id_) {
                            const auto remote_magic = static_cast<uint32_t>(std::stoul(fields[2]));
                            const auto remote_network = fields[3];
                            const auto remote_port = static_cast<uint16_t>(std::stoul(fields[4]));
                            if (remote_magic == message_magic() &&
                                remote_network == network_name(params().network)) {
                                const auto label = lan_discovery_remote_.address().to_string() + ":" +
                                                   std::to_string(remote_port);
                                record_peer_label(label, "lan");
                                log_info("net", "discovered LAN peer=" + label);
                                connect_known_peers(1);
                            }
                        }
                    }
                } catch (...) {
                }
            }
            if (!ec || ec == boost::asio::error::message_size) {
                read_lan_discovery();
            }
        });
}

std::vector<chat::HistoryEntry> NetworkNode::chat_history(const chat::HistoryQuery& query) const {
    std::lock_guard<std::mutex> lock(chat_mutex_);
    return chat::load_history(chat_history_file_, query);
}

std::vector<chat::HistoryEntry> NetworkNode::mail_history(const chat::HistoryQuery& query) const {
    std::lock_guard<std::mutex> lock(mail_mutex_);
    return chat::load_history(mail_history_file_, query);
}

std::vector<NetworkNode::DistributedMailRecord> NetworkNode::distributed_mail_records(const std::optional<std::string>& recipient_address,
                                                                                      size_t limit) const {
    std::lock_guard<std::mutex> lock(distributed_mail_mutex_);
    return load_distributed_mail_records_file(distributed_mail_file_, recipient_address, limit);
}

std::filesystem::path NetworkNode::chat_history_path() const {
    return chat_history_file_;
}

std::filesystem::path NetworkNode::mail_history_path() const {
    return mail_history_file_;
}

std::filesystem::path NetworkNode::distributed_mail_path() const {
    return distributed_mail_file_;
}

void NetworkNode::record_chat_history(const chat::HistoryEntry& entry) {
    std::lock_guard<std::mutex> lock(chat_mutex_);
    chat::append_history_entry(chat_history_file_, entry);
}

void NetworkNode::record_mail_history(const chat::HistoryEntry& entry) {
    std::lock_guard<std::mutex> lock(mail_mutex_);
    chat::append_history_entry(mail_history_file_, entry);
}

void NetworkNode::record_distributed_mail(const ChatPayload& payload, const std::string& peer_label) {
    if (payload.chat_type != chat::CHAT_TYPE_MAIL || payload.recipient.empty()) {
        return;
    }
    store_distributed_mail_record(make_distributed_mail_record(payload, peer_label, mail_policy_.ttl_hours));
}

void NetworkNode::store_distributed_mail_record(const DistributedMailRecord& record) {
    std::lock_guard<std::mutex> lock(distributed_mail_mutex_);
    (void)append_distributed_mail_record_file(distributed_mail_file_, record);
    if (mail_policy_.prune_expired || distributed_mail_record_count_file(distributed_mail_file_) > mail_policy_.max_store_items) {
        auto records = load_distributed_mail_records_file(distributed_mail_file_, std::nullopt, 0);
        if (records.size() > mail_policy_.max_store_items) {
            records.erase(records.begin(),
                          records.end() - static_cast<std::ptrdiff_t>(mail_policy_.max_store_items));
        }
        save_distributed_mail_records_file(distributed_mail_file_, records);
    }
}

bool NetworkNode::send_to_or_relay_mail_peer(const std::string& label, const Message& msg, const std::string& purpose) {
    if (label.empty()) return false;
    if (send_to(label, msg)) {
        return true;
    }

    if (looks_like_peer_label(label)) {
        auto parsed = parse_host_port(label, listen_port_ ? listen_port_ : default_p2p_port());
        if (parsed) {
            connect(parsed->first, parsed->second);
            if (send_to(label, msg)) {
                return true;
            }
        }
    }

    if (!mail_policy_.nat_assist && !mail_policy_.relay_fallback) {
        return false;
    }

    ++dht_relay_attempts_;
    const auto self = advertised_endpoint();
    if (mail_policy_.nat_assist && self && looks_like_peer_label(label)) {
        const auto candidates = build_nat_candidates(std::make_optional(label));
        auto peers = active_peer_labels();
        if (!mail_policy_.relay_peers.empty()) {
            std::vector<std::string> preferred;
            preferred.reserve(mail_policy_.relay_peers.size());
            for (const auto& relay : mail_policy_.relay_peers) {
                if (std::find(peers.begin(), peers.end(), relay) != peers.end()) {
                    preferred.push_back(relay);
                }
            }
            if (!preferred.empty()) {
                peers = std::move(preferred);
            }
        }
        const auto relays = select_nearest_mail_peers(peers,
                                                      label,
                                                      std::min<size_t>(2, peers.size()),
                                                      label,
                                                      self);
        if (!relays.empty()) {
            Message intro;
            intro.type = MessageType::DHT_MAIL_NAT_INTRO;
            intro.payload = DhtMailNatIntroPayload{2,
                                                   *self,
                                                   label,
                                                   purpose,
                                                   static_cast<uint64_t>(std::time(nullptr)),
                                                   2,
                                                   true,
                                                   false,
                                                   candidates}.serialize();
            for (const auto& relay : relays) {
                (void)send_to(relay, intro);
            }
            dht_last_nat_intro_at_ = static_cast<uint64_t>(std::time(nullptr));
        }
    }

    if (!mail_policy_.relay_fallback) {
        return false;
    }

    const bool relay_safe =
        msg.type == MessageType::DHT_MAIL_STORE ||
        msg.type == MessageType::DHT_MAIL_FIND ||
        msg.type == MessageType::DHT_MAIL_RESULTS ||
        msg.type == MessageType::DHT_MAIL_RECEIPT ||
        msg.type == MessageType::DHT_MAIL_CHALLENGE ||
        msg.type == MessageType::DHT_MAIL_PROOF ||
        msg.type == MessageType::DHT_MAIL_NAT_INTRO;
    if (!relay_safe) {
        return false;
    }

    auto relays = active_peer_labels();
    if (!mail_policy_.relay_peers.empty()) {
        std::vector<std::string> preferred;
        preferred.reserve(mail_policy_.relay_peers.size());
        for (const auto& relay : mail_policy_.relay_peers) {
            if (relay.empty() || relay == label) continue;
            if (looks_like_peer_label(relay)) {
                auto parsed = parse_host_port(relay, listen_port_ ? listen_port_ : default_p2p_port());
                if (parsed) {
                    connect(parsed->first, parsed->second);
                }
            }
            if (std::find(relays.begin(), relays.end(), relay) != relays.end()) {
                preferred.push_back(relay);
            }
        }
        if (!preferred.empty()) {
            relays = std::move(preferred);
        }
    }
    relays.erase(std::remove(relays.begin(), relays.end(), label), relays.end());
    if (relays.empty()) {
        return false;
    }
    const size_t fanout = std::min<size_t>(std::max<uint32_t>(mail_policy_.replica_target, 1), relays.size());
    size_t sent = 0;
    for (size_t i = 0; i < fanout; ++i) {
        if (send_to(relays[i], msg)) {
            ++sent;
        }
    }
    if (sent > 0) {
        dht_relay_successes_ += sent;
    }
    return sent > 0;
}

std::vector<NetworkNode::NatCandidate> NetworkNode::build_nat_candidates(const std::optional<std::string>& target_label) const {
    std::vector<NatCandidate> candidates;
    std::unordered_set<std::string> seen;

    for (const auto& label : discover_local_ipv4_candidate_labels(listen_port_ ? listen_port_ : default_p2p_port())) {
        append_unique_candidate(candidates, seen, 0, label, 300);
    }
    if (const auto advertised = advertised_endpoint()) {
        append_unique_candidate(candidates, seen, 1, *advertised, 900);
    }
    const auto mapping = port_mapping_status();
    if (!mapping.external_endpoint.empty() && looks_like_peer_label(mapping.external_endpoint)) {
        append_unique_candidate(candidates, seen, 2, mapping.external_endpoint, 1000);
    }
    if (mail_policy_.nat_assist && !mail_policy_.stun_servers.empty()) {
        std::lock_guard<std::mutex> lock(stun_probe_mutex_);
        const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
        if (stun_reflexive_candidates_.empty() ||
            dht_last_stun_probe_at_ == 0 ||
            now > dht_last_stun_probe_at_ + 60) {
            stun_reflexive_candidates_.clear();
            const uint16_t announced_port = listen_port_ ? listen_port_ : default_p2p_port();
            for (const auto& server : mail_policy_.stun_servers) {
                if (auto reflexive = stun_probe_public_ip(server,
                                                          announced_port,
                                                          std::max<uint32_t>(mail_policy_.stun_timeout_ms, 100))) {
                    if (std::find(stun_reflexive_candidates_.begin(),
                                  stun_reflexive_candidates_.end(),
                                  *reflexive) == stun_reflexive_candidates_.end()) {
                        stun_reflexive_candidates_.push_back(*reflexive);
                    }
                    last_stun_server_ = server;
                }
            }
            dht_last_stun_probe_at_ = now;
        }
        for (const auto& candidate : stun_reflexive_candidates_) {
            append_unique_candidate(candidates, seen, 1, candidate, 950);
        }
    }
    (void)target_label;

    std::sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
        if (a.priority != b.priority) return a.priority > b.priority;
        if (a.type != b.type) return a.type < b.type;
        return a.label < b.label;
    });
    return candidates;
}

bool NetworkNode::attempt_nat_candidates(const std::vector<NatCandidate>& candidates) {
    bool attempted = false;
    if (candidates.empty()) return false;
    dht_last_candidate_attempt_at_ = static_cast<uint64_t>(std::time(nullptr));
    for (const auto& candidate : candidates) {
        if (candidate.label.empty() || !looks_like_peer_label(candidate.label) || is_self_label(candidate.label)) {
            continue;
        }
        auto parsed = parse_host_port(candidate.label, listen_port_ ? listen_port_ : default_p2p_port());
        if (!parsed) continue;
        connect(parsed->first, parsed->second);
        attempted = true;
    }
    return attempted;
}

void NetworkNode::slash_mail_receipt(const MailStorageReceipt& receipt,
                                     const std::string& reason,
                                     const std::string& evidence_material,
                                     const std::string& peer_label) {
    auto updated = receipt;
    updated.verified = false;
    updated.bond_satisfied = false;
    updated.slashed = true;
    updated.slashed_at = static_cast<uint64_t>(std::time(nullptr));
    updated.slash_reason = reason;
    const std::string evidence = updated.message_id + "\n" + updated.replica_label + "\n" + reason + "\n" + evidence_material;
    const auto digest = crypto::sha3_512(evidence);
    updated.slash_evidence_hash_hex = crypto::hex_encode(digest.data(), digest.size());
    upsert_mail_storage_receipt(updated);
    if (mail_policy_.slash_on_failed_proof) {
        punish_label(peer_label.empty() ? updated.replica_label : peer_label,
                     static_cast<int>(std::max<uint32_t>(mail_policy_.slash_penalty_score, 1)),
                     "mail storage proof failure: " + reason);
    }
}

void NetworkNode::upsert_mail_storage_receipt(const MailStorageReceipt& receipt) {
    std::lock_guard<std::mutex> lock(mail_receipts_mutex_);
    auto receipts = load_mail_storage_receipts_file(mail_receipts_file_);
    auto it = std::find_if(receipts.begin(), receipts.end(), [&](const auto& existing) {
        return existing.message_id == receipt.message_id && existing.replica_label == receipt.replica_label;
    });
    if (it == receipts.end()) {
        receipts.push_back(receipt);
    } else {
        *it = receipt;
    }
    save_mail_storage_receipts_file(mail_receipts_file_, receipts);
}

std::vector<NetworkNode::MailStorageReceipt> NetworkNode::mail_storage_receipts(const std::optional<std::string>& message_id) const {
    std::lock_guard<std::mutex> lock(mail_receipts_mutex_);
    return load_mail_storage_receipts_file(mail_receipts_file_, message_id);
}

size_t NetworkNode::verified_mail_storage_receipt_count() const {
    std::lock_guard<std::mutex> lock(mail_receipts_mutex_);
    const auto receipts = load_mail_storage_receipts_file(mail_receipts_file_);
    return static_cast<size_t>(std::count_if(receipts.begin(), receipts.end(), [](const auto& receipt) {
        return receipt.verified;
    }));
}

void NetworkNode::maybe_issue_mail_storage_challenge(const MailStorageReceipt& receipt) {
    if (!mail_policy_.proof_of_storage || receipt.message_id.empty() || receipt.replica_label.empty() || receipt.slashed) {
        return;
    }
    auto trusted = receipt;
    const bool signature_valid = verify_mail_receipt_signature(trusted);
    refresh_mail_receipt_bond(trusted, chain_, mail_policy_.minimum_bond_sats);
    if (!signature_valid) {
        trusted.bond_satisfied = false;
        slash_mail_receipt(trusted, "invalid receipt signature", trusted.provider_signature_b64, trusted.replica_label);
        return;
    }
    if (!signature_valid || !trusted.bond_satisfied) {
        upsert_mail_storage_receipt(trusted);
        return;
    }
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    if (trusted.last_challenged_at != 0 &&
        now < trusted.last_challenged_at + static_cast<uint64_t>(std::max<uint32_t>(mail_policy_.challenge_interval_minutes, 1)) * 60ULL) {
        return;
    }

    PendingMailProofChallenge pending;
    pending.challenge_id = lan_discovery_node_id_ + ":proof:" + std::to_string(now_millis()) + ":" + std::to_string(hash_key64(trusted.message_id + trusted.replica_label));
    pending.message_id = trusted.message_id;
    pending.recipient_address = trusted.recipient_address;
    pending.replica_label = trusted.replica_label;
    pending.nonce_b64 = random_nonce_b64();
    pending.created_at = now;
    {
        std::lock_guard<std::mutex> lock(dht_mutex_);
        pending_mail_challenges_[pending.challenge_id] = pending;
    }

    auto updated = trusted;
    updated.last_challenged_at = now;
    upsert_mail_storage_receipt(updated);

    Message msg;
    msg.type = MessageType::DHT_MAIL_CHALLENGE;
    msg.payload = DhtMailChallengePayload{1,
                                          pending.challenge_id,
                                          pending.message_id,
                                          pending.recipient_address,
                                          advertised_endpoint().value_or(""),
                                          pending.nonce_b64}.serialize();
    (void)send_to_or_relay_mail_peer(receipt.replica_label, msg, "mail-proof");
}

void NetworkNode::maintain_mail_storage_proofs() {
    if (!mail_policy_.proof_of_storage) return;
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    std::vector<PendingMailProofChallenge> expired;
    {
        std::lock_guard<std::mutex> lock(dht_mutex_);
        for (auto it = pending_mail_challenges_.begin(); it != pending_mail_challenges_.end();) {
            const uint64_t timeout_seconds =
                static_cast<uint64_t>(std::max<uint32_t>(mail_policy_.challenge_interval_minutes, 1)) * 120ULL;
            if (it->second.created_at != 0 && now > it->second.created_at + timeout_seconds) {
                expired.push_back(it->second);
                it = pending_mail_challenges_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (const auto& pending : expired) {
        auto receipts = mail_storage_receipts(std::make_optional(pending.message_id));
        auto receipt_it = std::find_if(receipts.begin(), receipts.end(), [&](const auto& receipt) {
            return receipt.replica_label == pending.replica_label;
        });
        if (receipt_it != receipts.end()) {
            slash_mail_receipt(*receipt_it, "proof challenge timed out", pending.challenge_id, pending.replica_label);
        }
    }
    auto receipts = mail_storage_receipts();
    for (const auto& receipt : receipts) {
        if (receipt.slashed) continue;
        if (receipt.expires_at != 0 && receipt.expires_at < now) {
            continue;
        }
        maybe_issue_mail_storage_challenge(receipt);
    }
}

size_t NetworkNode::dht_store_mail(const DistributedMailRecord& record) {
    if (record.recipient_address.empty()) return 0;
    auto labels = active_peer_labels();
    if (labels.empty()) return 0;
    const auto policy = mail_replication_policy();
    const size_t target = std::min<size_t>(std::max<uint32_t>(policy.replica_target, 1), labels.size());
    const auto nearest = select_nearest_mail_peers(labels, record.recipient_address, target);
    if (nearest.empty()) return 0;

    Message msg;
    msg.type = MessageType::DHT_MAIL_STORE;
    msg.payload = DhtMailStorePayload{1, record}.serialize();
    size_t sent = 0;
    for (const auto& label : nearest) {
        if (send_to_or_relay_mail_peer(label, msg, "mail-store")) ++sent;
    }
    return sent;
}

std::vector<NetworkNode::DistributedMailRecord> NetworkNode::dht_lookup_mail(const std::string& recipient_address,
                                                                             size_t limit,
                                                                             uint32_t timeout_ms) {
    std::string normalized;
    try {
        normalized = crypto::canonicalize_address(recipient_address);
    } catch (...) {
        return distributed_mail_records(std::nullopt, limit);
    }
    auto local = distributed_mail_records(normalized, limit);
    auto labels = active_peer_labels();
    if (labels.empty()) return local;

    const auto query_id = lan_discovery_node_id_ + ":" + std::to_string(now_millis()) + ":" + std::to_string(hash_key64(normalized + std::to_string(now_millis())));
    {
        std::lock_guard<std::mutex> lock(dht_mutex_);
        dht_pending_results_[query_id] = {};
        dht_last_lookup_at_ = static_cast<uint64_t>(std::time(nullptr));
    }

    DhtMailFindPayload query;
    query.query_id = query_id;
    query.recipient_address = normalized;
    query.requester_label = advertised_endpoint().value_or("");
    query.limit = static_cast<uint32_t>(std::max<size_t>(1, limit));
    query.hops = static_cast<uint8_t>(query.requester_label.empty() ? 0 : 1);
    Message msg;
    msg.type = MessageType::DHT_MAIL_FIND;
    msg.payload = query.serialize();

    const auto nearest = select_nearest_mail_peers(labels,
                                                   normalized,
                                                   std::min<size_t>(std::max<uint32_t>(mail_replication_policy().replica_target, 1), labels.size()));
    for (const auto& label : nearest) {
        (void)send_to_or_relay_mail_peer(label, msg, "mail-lookup");
    }

    std::unique_lock<std::mutex> lock(dht_mutex_);
    dht_results_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() {
        const auto it = dht_pending_results_.find(query_id);
        return it != dht_pending_results_.end() && !it->second.empty();
    });
    auto it = dht_pending_results_.find(query_id);
    if (it != dht_pending_results_.end()) {
        local.insert(local.end(), it->second.begin(), it->second.end());
        dht_pending_results_.erase(it);
    }
    lock.unlock();

    std::sort(local.begin(), local.end(), [](const auto& a, const auto& b) {
        if (a.stored_at != b.stored_at) return a.stored_at < b.stored_at;
        return a.message_id < b.message_id;
    });
    local.erase(std::unique(local.begin(), local.end(), [](const auto& a, const auto& b) {
        return a.message_id == b.message_id;
    }), local.end());
    if (limit > 0 && local.size() > limit) {
        local.erase(local.begin(), local.end() - static_cast<std::ptrdiff_t>(limit));
    }
    return local;
}

NetworkNode::DhtMailboxStatus NetworkNode::dht_mailbox_status() const {
    DhtMailboxStatus status;
    status.local_store_records = distributed_mail_count();
    status.active_peers = active_peer_labels().size();
    const auto policy = mail_replication_policy();
    status.replica_target = policy.replica_target;
    status.proof_of_storage = policy.proof_of_storage;
    status.minimum_bond_sats = policy.minimum_bond_sats;
    status.required_verified_replicas = policy.required_verified_replicas;
    status.slash_on_failed_proof = policy.slash_on_failed_proof;
    status.slash_penalty_score = policy.slash_penalty_score;
    status.nat_assist = policy.nat_assist;
    status.relay_fallback = policy.relay_fallback;
    status.relay_peer_count = policy.relay_peers.size();
    status.stun_server_count = policy.stun_servers.size();
    status.port_mapping_active = port_mapping_status().active;
    status.advertised_endpoint = advertised_endpoint().value_or("");
    {
        std::lock_guard<std::mutex> lock(stun_probe_mutex_);
        status.reflexive_endpoint = stun_reflexive_candidates_.empty() ? std::string() : stun_reflexive_candidates_.front();
        status.last_stun_probe_at = dht_last_stun_probe_at_;
    }
    status.candidate_count = build_nat_candidates().size();
    const auto receipts = mail_storage_receipts();
    status.receipt_count = receipts.size();
    status.verified_receipts = static_cast<size_t>(std::count_if(receipts.begin(), receipts.end(), [](const auto& receipt) {
        return receipt.verified;
    }));
    status.bond_satisfied_receipts = static_cast<size_t>(std::count_if(receipts.begin(), receipts.end(), [](const auto& receipt) {
        return receipt.bond_satisfied;
    }));
    status.trusted_verified_receipts = static_cast<size_t>(std::count_if(receipts.begin(), receipts.end(), [](const auto& receipt) {
        return receipt.verified && receipt.bond_satisfied && !receipt.provider_signature_b64.empty() && !receipt.slashed;
    }));
    status.slashed_receipts = static_cast<size_t>(std::count_if(receipts.begin(), receipts.end(), [](const auto& receipt) {
        return receipt.slashed;
    }));
    status.last_proof_at = dht_last_proof_at_;
    status.last_nat_intro_at = dht_last_nat_intro_at_;
    status.last_reverse_intro_at = dht_last_reverse_intro_at_;
    status.last_candidate_attempt_at = dht_last_candidate_attempt_at_;
    status.relay_attempts = dht_relay_attempts_;
    status.relay_successes = dht_relay_successes_;
    std::lock_guard<std::mutex> lock(dht_mutex_);
    status.pending_queries = dht_pending_results_.size();
    status.seen_queries = dht_seen_queries_.size();
    status.pending_proofs = pending_mail_challenges_.size();
    status.last_lookup_at = dht_last_lookup_at_;
    status.last_results_at = dht_last_results_at_;
    return status;
}

NetworkNode::NatTraversalStatus NetworkNode::nat_traversal_status() const {
    NatTraversalStatus status;
    const auto policy = mail_replication_policy();
    status.enabled = policy.nat_assist;
    status.relay_fallback = policy.relay_fallback;
    status.relay_peer_count = policy.relay_peers.size();
    status.stun_server_count = policy.stun_servers.size();
    status.port_mapping_active = port_mapping_status().active;
    status.advertised_endpoint = advertised_endpoint().value_or("");
    {
        std::lock_guard<std::mutex> lock(stun_probe_mutex_);
        status.reflexive_endpoint = stun_reflexive_candidates_.empty() ? std::string() : stun_reflexive_candidates_.front();
        status.last_stun_probe_at = dht_last_stun_probe_at_;
    }
    status.candidate_count = build_nat_candidates().size();
    status.last_intro_at = dht_last_nat_intro_at_;
    status.last_reverse_intro_at = dht_last_reverse_intro_at_;
    status.last_candidate_attempt_at = dht_last_candidate_attempt_at_;
    status.relay_attempts = dht_relay_attempts_;
    status.relay_successes = dht_relay_successes_;
    return status;
}

bool NetworkNode::delete_chat_message(const std::string& message_id) {
    std::lock_guard<std::mutex> lock(chat_mutex_);
    return chat::delete_history_entry(chat_history_file_, message_id);
}

bool NetworkNode::delete_mail_message(const std::string& message_id) {
    std::lock_guard<std::mutex> lock(mail_mutex_);
    return chat::delete_history_entry(mail_history_file_, message_id);
}

bool NetworkNode::delete_distributed_mail(const std::string& message_id) {
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(distributed_mail_mutex_);
        removed = delete_distributed_mail_record_file(distributed_mail_file_, message_id);
    }
    if (removed) {
        std::lock_guard<std::mutex> receipts_lock(mail_receipts_mutex_);
        auto receipts = load_mail_storage_receipts_file(mail_receipts_file_);
        receipts.erase(std::remove_if(receipts.begin(), receipts.end(), [&](const auto& receipt) {
            return receipt.message_id == message_id;
        }), receipts.end());
        save_mail_storage_receipts_file(mail_receipts_file_, receipts);
    }
    return removed;
}

size_t NetworkNode::distributed_mail_count() const {
    std::lock_guard<std::mutex> lock(distributed_mail_mutex_);
    return distributed_mail_record_count_file(distributed_mail_file_);
}

void NetworkNode::set_mail_replication_policy(const MailReplicationPolicy& policy) {
    std::lock_guard<std::mutex> lock(distributed_mail_mutex_);
    mail_policy_.ttl_hours = std::max<uint32_t>(policy.ttl_hours, 1);
    mail_policy_.replica_target = std::max<uint32_t>(policy.replica_target, 1);
    mail_policy_.max_store_items = std::max<uint32_t>(policy.max_store_items, 1);
    mail_policy_.prune_imported = policy.prune_imported;
    mail_policy_.prune_expired = policy.prune_expired;
    mail_policy_.proof_of_storage = policy.proof_of_storage;
    mail_policy_.challenge_interval_minutes = std::max<uint32_t>(policy.challenge_interval_minutes, 1);
    mail_policy_.minimum_bond_sats = policy.minimum_bond_sats;
    mail_policy_.required_verified_replicas = std::max<uint32_t>(policy.required_verified_replicas, 1);
    mail_policy_.slash_on_failed_proof = policy.slash_on_failed_proof;
    mail_policy_.slash_penalty_score = std::max<uint32_t>(policy.slash_penalty_score, 1);
    mail_policy_.nat_assist = policy.nat_assist;
    mail_policy_.relay_fallback = policy.relay_fallback;
    mail_policy_.relay_peers = policy.relay_peers;
    mail_policy_.stun_servers = policy.stun_servers;
    mail_policy_.stun_timeout_ms = std::max<uint32_t>(policy.stun_timeout_ms, 100);
    {
        std::lock_guard<std::mutex> stun_lock(stun_probe_mutex_);
        stun_reflexive_candidates_.clear();
        last_stun_server_.clear();
        dht_last_stun_probe_at_ = 0;
    }
}

NetworkNode::MailReplicationPolicy NetworkNode::mail_replication_policy() const {
    std::lock_guard<std::mutex> lock(distributed_mail_mutex_);
    return mail_policy_;
}

size_t NetworkNode::prune_distributed_mail_store() {
    std::lock_guard<std::mutex> lock(distributed_mail_mutex_);
    auto records = load_distributed_mail_records_file(distributed_mail_file_, std::nullopt, 0);
    const size_t before = records.size();
    if (records.size() > mail_policy_.max_store_items) {
        records.erase(records.begin(),
                      records.end() - static_cast<std::ptrdiff_t>(mail_policy_.max_store_items));
    }
    save_distributed_mail_records_file(distributed_mail_file_, records);
    {
        std::lock_guard<std::mutex> receipts_lock(mail_receipts_mutex_);
        auto receipts = load_mail_storage_receipts_file(mail_receipts_file_);
        receipts.erase(std::remove_if(receipts.begin(), receipts.end(), [&](const auto& receipt) {
            return std::none_of(records.begin(), records.end(), [&](const auto& record) {
                return record.message_id == receipt.message_id;
            });
        }), receipts.end());
        save_mail_storage_receipts_file(mail_receipts_file_, receipts);
    }
    return before >= records.size() ? before - records.size() : 0;
}

void NetworkNode::punish_label(const std::string& label, int score, const std::string& reason) {
    if (label.empty()) return;

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    int new_score = 0;
    bool banned = false;
    {
        std::lock_guard<std::mutex> guard(peer_state_mutex_);
        auto& state = peer_states_[label];
        if (state.last_updated == 0) state.last_updated = now;
        if (state.netgroup.empty()) state.netgroup = peer_netgroup(label);
        decay_peer_state_locked(label, now);
        state.score += score;
        state.last_updated = now;
        state.last_seen = now;
        state.invalid_messages += 1;
        state.last_reason = reason;
        if (state.score >= ban_threshold_) {
            state.banned_until = std::max(state.banned_until,
                                          now + constants::BANNED_PEER_DURATION_SECONDS);
        }
        new_score = state.score;
        banned = state.banned_until > now;
    }
    save_peer_state();
    log_warn("net", "misbehavior peer=" + label +
                    " score_delta=" + std::to_string(score) +
                    " total=" + std::to_string(new_score) +
                    " reason=" + reason +
                    (banned ? " banned=true" : ""));
}

void NetworkNode::set_ban(const std::string& label, int duration_seconds) {
    if (label.empty()) return;
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    {
        std::lock_guard<std::mutex> guard(peer_state_mutex_);
        auto& state = peer_states_[label];
        if (state.netgroup.empty()) state.netgroup = peer_netgroup(label);
        state.score = std::max(state.score, ban_threshold_);
        state.banned_until = now + std::max(duration_seconds, 1);
        state.last_updated = now;
        state.last_seen = now;
        state.last_reason = "manual ban";
    }
    save_peer_state();
}

void NetworkNode::clear_bans() {
    {
        std::lock_guard<std::mutex> guard(peer_state_mutex_);
        for (auto& [label, state] : peer_states_) {
            state.score = 0;
            state.banned_until = 0;
            state.last_updated = static_cast<int64_t>(std::time(nullptr));
        }
    }
    save_peer_state();
}

void NetworkNode::set_dns_seeds(std::vector<std::string> seeds) {
    dns_seeds_ = std::move(seeds);
}

void NetworkNode::set_external_address(const std::string& address) {
    auto parsed = parse_host_port(address, listen_port_ ? listen_port_ : default_p2p_port());
    if (!parsed) {
        throw std::runtime_error("invalid external address: " + address);
    }
    boost::asio::ip::tcp::resolver resolver(ctx_);
    auto endpoints = resolver.resolve(parsed->first, std::to_string(parsed->second));
    for (const auto& endpoint : endpoints) {
        if (!endpoint.endpoint().address().is_v4()) continue;
        PeerAddress peer;
        peer.ip = ip_address::from_string(endpoint.endpoint().address().to_string());
        peer.port = parsed->second;
        peer.flags = 0x01;
        advertised_self_ = peer;
        log_info("net", "configured advertised endpoint=" +
                            endpoint_label(peer.ip, peer.port));
        return;
    }
    throw std::runtime_error("failed to resolve external address: " + address);
}

void NetworkNode::set_ip_detection_service(std::string host, std::string port, std::string path) {
    if (!host.empty()) ip_detect_host_ = std::move(host);
    if (!port.empty()) ip_detect_port_ = std::move(port);
    if (!path.empty()) ip_detect_path_ = std::move(path);
}

void NetworkNode::set_socks5_proxy(const std::string& host, uint16_t port, bool remote_dns) {
    if (host.empty() || port == 0) {
        proxy_.reset();
        return;
    }
    proxy_ = ProxySettings{host, port, remote_dns};
    log_info("net", "configured SOCKS5 proxy=" + host + ":" + std::to_string(port) +
                    (remote_dns ? " remote_dns=true" : " remote_dns=false"));
}

void NetworkNode::enable_port_mapping(bool upnp_enabled, bool natpmp_enabled, int lease_seconds) {
    std::lock_guard<std::mutex> guard(port_mapping_mutex_);
    upnp_enabled_ = upnp_enabled;
    natpmp_enabled_ = natpmp_enabled;
    nat_mapping_lease_seconds_ = std::max(lease_seconds, 60);
    port_mapping_status_.enabled = upnp_enabled_ || natpmp_enabled_;
    port_mapping_status_.lease_seconds = nat_mapping_lease_seconds_;
}

void NetworkNode::set_chat_wallet(std::shared_ptr<const Wallet> wallet) {
    chat_wallet_ = std::move(wallet);
}

NetworkNode::VoiceCallInfo NetworkNode::voice_call_state() const {
    std::lock_guard<std::mutex> lock(voice_call_mutex_);
    return voice_call_;
}

void NetworkNode::clear_voice_call_locked(const std::string& status) {
    voice_call_ = VoiceCallInfo{};
    voice_call_.status = status;
    voice_audio_inbox_.clear();
}

size_t NetworkNode::dispatch_chat_payload(const ChatPayload& payload, const std::string& preferred_peer) {
    Message msg;
    msg.type = MessageType::CHAT;
    msg.payload = payload.serialize();
    remember_chat_message(chat::message_id(payload));
    if (!preferred_peer.empty() && send_to(preferred_peer, msg)) {
        return 1;
    }
    return broadcast_chat(msg);
}

bool NetworkNode::start_voice_call(const std::string& recipient_address,
                                   const std::vector<uint8_t>& recipient_pubkey,
                                   const std::string& recipient_rsa_public_pem,
                                   const std::string& peer_label,
                                   const std::string& from_address,
                                   bool obfuscate_audio,
                                   chat::EncryptionMode encryption_mode) {
    if (!chat_wallet_) {
        return false;
    }
    if (recipient_address.empty() || recipient_pubkey.empty()) {
        return false;
    }
    (void)recipient_rsa_public_pem;
    (void)encryption_mode;

    VoiceCallInfo snapshot;
    size_t sender_index = 0;
    {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (voice_call_.active) {
            return false;
        }
        try {
            sender_index = resolve_voice_sender_index(*chat_wallet_, from_address);
        } catch (...) {
            return false;
        }
        snapshot.active = true;
        snapshot.outgoing = true;
        snapshot.ringing = true;
        snapshot.connected = false;
        snapshot.session_ready = false;
        snapshot.obfuscate_audio = obfuscate_audio;
        snapshot.started_at = static_cast<uint64_t>(std::time(nullptr));
        snapshot.last_signal_at = snapshot.started_at;
        snapshot.call_id = generate_lan_discovery_node_id();
        snapshot.local_address = chat_wallet_->addresses[sender_index];
        snapshot.remote_address = recipient_address;
        snapshot.caller_address = snapshot.local_address;
        snapshot.callee_address = recipient_address;
        snapshot.remote_pubkey_b64 = crypto::base64_encode(recipient_pubkey);
        snapshot.peer_label = peer_label;
        snapshot.encryption_mode = "ECDH / AES-GCM / Opus";
        snapshot.frame_duration_ms = 20;
        snapshot.capability_flags = voice::CAPABILITY_AES_GCM |
                                    voice::CAPABILITY_OPUS |
                                    voice::CAPABILITY_AUDIO_CLOAK |
                                    voice::CAPABILITY_LIVE_WAVEFORM;
        snapshot.codec = voice::codec_name(voice::CODEC_OPUS);
        snapshot.status = "calling";
        try {
            const auto session_key = voice::derive_session_key(chat_wallet_->privkeys[sender_index],
                                                               recipient_pubkey,
                                                               snapshot.call_id,
                                                               snapshot.local_address,
                                                               snapshot.remote_address);
            snapshot.session_key.assign(session_key.begin(), session_key.end());
            snapshot.session_ready = true;
        } catch (...) {
            clear_voice_call_locked("key-agreement-failed");
            return false;
        }
        voice_call_ = snapshot;
    }

    voice::CallSignal offer;
    offer.type = voice::SignalType::Offer;
    offer.timestamp = snapshot.started_at;
    offer.call_id = snapshot.call_id;
    offer.caller_address = snapshot.caller_address;
    offer.callee_address = snapshot.callee_address;
    offer.peer_label = peer_label;
    offer.caller_pubkey_b64 = crypto::base64_encode(chat_wallet_->pubkeys[sender_index]);
    offer.caller_rsa_public_pem = chat_wallet_->chat_rsa_public_key_pem;
    offer.encryption_mode = static_cast<uint8_t>(chat::EncryptionMode::ECDH);
    offer.obfuscate_audio = obfuscate_audio;
    offer.sample_rate = snapshot.sample_rate;
    offer.channels = snapshot.channels;
    offer.bits_per_sample = snapshot.bits_per_sample;
    offer.frame_duration_ms = snapshot.frame_duration_ms;
    offer.capability_flags = snapshot.capability_flags;
    offer.codec = snapshot.codec;

    auto payload = chat::make_encrypted_private_chat(*chat_wallet_,
                                                     snapshot.local_address,
                                                     snapshot.remote_address,
                                                     recipient_pubkey,
                                                     voice::make_signal_content(offer),
                                                     chat::KeyDerivation::Argon2id,
                                                     chat::EncryptionMode::ECDH,
                                                     {},
                                                     chat::CHAT_TYPE_VOICE_CONTROL);
    const auto peers = dispatch_chat_payload(payload, peer_label);
    if (peers == 0) {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        clear_voice_call_locked("no-route");
        return false;
    }
    return true;
}

bool NetworkNode::accept_voice_call() {
    if (!chat_wallet_) {
        return false;
    }
    VoiceCallInfo snapshot;
    size_t sender_index = 0;
    {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (!voice_call_.active || !voice_call_.incoming || !voice_call_.ringing) {
            return false;
        }
        if (!voice_call_.session_ready) {
            voice_call_.status = "key-agreement-failed";
            return false;
        }
        try {
            sender_index = resolve_voice_sender_index(*chat_wallet_, voice_call_.local_address);
        } catch (...) {
            voice_call_.status = "local-address-unavailable";
            return false;
        }
        snapshot = voice_call_;
        voice_call_.connected = true;
        voice_call_.ringing = false;
        voice_call_.status = "connected";
        voice_call_.connected_at = static_cast<uint64_t>(std::time(nullptr));
        voice_call_.last_signal_at = voice_call_.connected_at;
        snapshot = voice_call_;
    }

    if (snapshot.remote_pubkey_b64.empty()) {
        return false;
    }
    const auto recipient_pubkey = crypto::base64_decode(snapshot.remote_pubkey_b64);

    voice::CallSignal answer;
    answer.type = voice::SignalType::Answer;
    answer.timestamp = snapshot.connected_at;
    answer.call_id = snapshot.call_id;
    answer.caller_address = snapshot.caller_address;
    answer.callee_address = snapshot.callee_address;
    answer.peer_label = snapshot.peer_label;
    answer.caller_pubkey_b64 = crypto::base64_encode(chat_wallet_->pubkeys[sender_index]);
    answer.encryption_mode = static_cast<uint8_t>(chat::EncryptionMode::ECDH);
    answer.obfuscate_audio = snapshot.obfuscate_audio;
    answer.sample_rate = snapshot.sample_rate;
    answer.channels = snapshot.channels;
    answer.bits_per_sample = snapshot.bits_per_sample;
    answer.frame_duration_ms = snapshot.frame_duration_ms;
    answer.capability_flags = snapshot.capability_flags;
    answer.codec = snapshot.codec;

    auto payload = chat::make_encrypted_private_chat(*chat_wallet_,
                                                     snapshot.local_address,
                                                     snapshot.remote_address,
                                                     recipient_pubkey,
                                                     voice::make_signal_content(answer),
                                                     chat::KeyDerivation::Argon2id,
                                                     chat::EncryptionMode::ECDH,
                                                     {},
                                                     chat::CHAT_TYPE_VOICE_CONTROL);
    return dispatch_chat_payload(payload, snapshot.peer_label) > 0;
}

bool NetworkNode::decline_voice_call(const std::string& note) {
    if (!chat_wallet_) {
        return false;
    }
    VoiceCallInfo snapshot;
    {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (!voice_call_.active) {
            return false;
        }
        snapshot = voice_call_;
        clear_voice_call_locked("declined");
    }

    if (snapshot.remote_address.empty()) {
        return false;
    }
    if (snapshot.remote_address.empty() || snapshot.remote_pubkey_b64.empty()) {
        return false;
    }
    const auto recipient_pubkey = crypto::base64_decode(snapshot.remote_pubkey_b64);
    voice::CallSignal signal;
    signal.type = voice::SignalType::Decline;
    signal.timestamp = static_cast<uint64_t>(std::time(nullptr));
    signal.call_id = snapshot.call_id;
    signal.caller_address = snapshot.caller_address;
    signal.callee_address = snapshot.callee_address;
    signal.peer_label = snapshot.peer_label;
    signal.encryption_mode = static_cast<uint8_t>(chat::EncryptionMode::ECDH);
    signal.capability_flags = snapshot.capability_flags;
    signal.codec = snapshot.codec;
    signal.note = note;
    auto payload = chat::make_encrypted_private_chat(*chat_wallet_,
                                                     snapshot.local_address,
                                                     snapshot.remote_address,
                                                     recipient_pubkey,
                                                     voice::make_signal_content(signal),
                                                     chat::KeyDerivation::Argon2id,
                                                     chat::EncryptionMode::ECDH,
                                                     {},
                                                     chat::CHAT_TYPE_VOICE_CONTROL);
    dispatch_chat_payload(payload, snapshot.peer_label);
    return true;
}

bool NetworkNode::end_voice_call(const std::string& note) {
    if (!chat_wallet_) {
        return false;
    }
    VoiceCallInfo snapshot;
    {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (!voice_call_.active) {
            return false;
        }
        snapshot = voice_call_;
        clear_voice_call_locked("ended");
    }

    if (snapshot.remote_address.empty()) {
        return false;
    }
    if (snapshot.remote_address.empty() || snapshot.remote_pubkey_b64.empty()) {
        return false;
    }
    const auto recipient_pubkey = crypto::base64_decode(snapshot.remote_pubkey_b64);
    voice::CallSignal signal;
    signal.type = voice::SignalType::Hangup;
    signal.timestamp = static_cast<uint64_t>(std::time(nullptr));
    signal.call_id = snapshot.call_id;
    signal.caller_address = snapshot.caller_address;
    signal.callee_address = snapshot.callee_address;
    signal.peer_label = snapshot.peer_label;
    signal.encryption_mode = static_cast<uint8_t>(chat::EncryptionMode::ECDH);
    signal.capability_flags = snapshot.capability_flags;
    signal.codec = snapshot.codec;
    signal.note = note;
    auto payload = chat::make_encrypted_private_chat(*chat_wallet_,
                                                     snapshot.local_address,
                                                     snapshot.remote_address,
                                                     recipient_pubkey,
                                                     voice::make_signal_content(signal),
                                                     chat::KeyDerivation::Argon2id,
                                                     chat::EncryptionMode::ECDH,
                                                     {},
                                                     chat::CHAT_TYPE_VOICE_CONTROL);
    dispatch_chat_payload(payload, snapshot.peer_label);
    return true;
}

size_t NetworkNode::send_voice_audio(const std::vector<uint8_t>& pcm_bytes,
                                     uint32_t sample_rate,
                                     uint16_t channels,
                                     uint16_t bits_per_sample,
                                     bool obfuscated) {
    if (!chat_wallet_ || pcm_bytes.empty()) {
        return 0;
    }

    VoiceCallInfo snapshot;
    {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (!voice_call_.active || !voice_call_.connected || !voice_call_.session_ready) {
            return 0;
        }
        snapshot = voice_call_;
    }
    if (snapshot.remote_pubkey_b64.empty()) {
        return 0;
    }
    const auto recipient_pubkey = crypto::base64_decode(snapshot.remote_pubkey_b64);
    uint64_t sequence = 0;
    {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        sequence = voice_call_.next_outgoing_sequence++;
    }
    try {
        auto frame = voice::make_encrypted_audio_frame(pcm_bytes,
                                                       session_key_from_bytes(snapshot.session_key),
                                                       snapshot.call_id,
                                                       now_millis(),
                                                       sequence,
                                                       sample_rate,
                                                       channels,
                                                       bits_per_sample,
                                                       snapshot.frame_duration_ms,
                                                       obfuscated);
        auto payload = chat::make_signed_transport_chat(*chat_wallet_,
                                                        snapshot.local_address,
                                                        snapshot.remote_address,
                                                        recipient_pubkey,
                                                        voice::make_audio_frame_content(frame),
                                                        chat::CHAT_TYPE_VOICE_FRAME);
        return dispatch_chat_payload(payload, snapshot.peer_label);
    } catch (const std::exception& ex) {
        log_warn("voice", "failed to encode/send voice frame: " + std::string(ex.what()));
        return 0;
    }
}

std::vector<voice::AudioFrame> NetworkNode::take_voice_audio_frames(size_t max_frames) {
    std::vector<voice::AudioFrame> out;
    std::lock_guard<std::mutex> lock(voice_call_mutex_);
    while (!voice_audio_inbox_.empty() && out.size() < max_frames) {
        out.push_back(std::move(voice_audio_inbox_.front()));
        voice_audio_inbox_.pop_front();
    }
    return out;
}

void NetworkNode::remember_chat_message(const std::string& message_id) {
    if (message_id.empty()) return;
    mark_chat_seen(message_id, static_cast<int64_t>(std::time(nullptr)));
}

bool NetworkNode::mark_chat_seen(const std::string& message_id, int64_t now) {
    std::lock_guard<std::mutex> lock(chat_mutex_);
    for (auto it = recent_chat_ids_.begin(); it != recent_chat_ids_.end();) {
        if (now - it->second > 24 * 60 * 60) it = recent_chat_ids_.erase(it);
        else ++it;
    }
    auto [it, inserted] = recent_chat_ids_.emplace(message_id, now);
    if (!inserted) {
        it->second = now;
        return true;
    }
    return false;
}

void NetworkNode::handle_voice_signal(const voice::CallSignal& signal,
                                      const chat::ParsedMessage& parsed,
                                      const ChatPayload& payload,
                                      const std::shared_ptr<PeerSession>& peer) {
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    const auto remote_pubkey = !payload.sender_pubkey.empty()
        ? payload.sender_pubkey
        : (signal.caller_pubkey_b64.empty() ? std::vector<uint8_t>{}
                                            : crypto::base64_decode(signal.caller_pubkey_b64));
    switch (signal.type) {
    case voice::SignalType::Offer: {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (voice_call_.active && voice_call_.call_id != signal.call_id) {
            return;
        }
        if (!chat_wallet_ || remote_pubkey.empty()) {
            clear_voice_call_locked("key-agreement-failed");
            return;
        }
        const auto local_address = signal.callee_address.empty() ? parsed.recipient_address : signal.callee_address;
        const auto local_index = wallet_index_for_address(*chat_wallet_, local_address);
        if (!local_index) {
            clear_voice_call_locked("local-address-unavailable");
            return;
        }
        voice::SessionKey session_key{};
        try {
            session_key = voice::derive_session_key(chat_wallet_->privkeys[*local_index],
                                                    remote_pubkey,
                                                    signal.call_id,
                                                    local_address,
                                                    signal.caller_address.empty() ? parsed.sender_address : signal.caller_address);
        } catch (...) {
            clear_voice_call_locked("key-agreement-failed");
            return;
        }
        clear_voice_call_locked("incoming");
        voice_call_.active = true;
        voice_call_.incoming = true;
        voice_call_.outgoing = false;
        voice_call_.ringing = true;
        voice_call_.connected = false;
        voice_call_.session_ready = true;
        voice_call_.status = "incoming";
        voice_call_.started_at = signal.timestamp;
        voice_call_.last_signal_at = now;
        voice_call_.call_id = signal.call_id;
        voice_call_.local_address = local_address;
        voice_call_.remote_address = signal.caller_address.empty() ? parsed.sender_address : signal.caller_address;
        voice_call_.caller_address = signal.caller_address.empty() ? parsed.sender_address : signal.caller_address;
        voice_call_.callee_address = signal.callee_address.empty() ? local_address : signal.callee_address;
        voice_call_.remote_pubkey_b64 = crypto::base64_encode(remote_pubkey);
        voice_call_.remote_rsa_public_pem = signal.caller_rsa_public_pem;
        voice_call_.peer_label = peer ? peer->remote_label() : signal.peer_label;
        voice_call_.encryption_mode = "ECDH / AES-GCM / Opus";
        voice_call_.obfuscate_audio = signal.obfuscate_audio;
        voice_call_.sample_rate = signal.sample_rate;
        voice_call_.channels = signal.channels;
        voice_call_.bits_per_sample = signal.bits_per_sample;
        voice_call_.frame_duration_ms = signal.frame_duration_ms == 0 ? 20 : signal.frame_duration_ms;
        voice_call_.capability_flags = signal.capability_flags == 0
            ? (voice::CAPABILITY_AES_GCM | voice::CAPABILITY_OPUS)
            : signal.capability_flags;
        voice_call_.codec = signal.codec.empty() ? voice::codec_name(voice::CODEC_OPUS) : signal.codec;
        voice_call_.session_key.assign(session_key.begin(), session_key.end());
        break;
    }
    case voice::SignalType::Answer: {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (!voice_call_.active || voice_call_.call_id != signal.call_id) {
            return;
        }
        if (!remote_pubkey.empty()) {
            voice_call_.remote_pubkey_b64 = crypto::base64_encode(remote_pubkey);
        }
        if (!voice_call_.session_ready && chat_wallet_ && !voice_call_.remote_pubkey_b64.empty()) {
            const auto local_index = wallet_index_for_address(*chat_wallet_, voice_call_.local_address);
            if (local_index) {
                try {
                    const auto session_key = voice::derive_session_key(chat_wallet_->privkeys[*local_index],
                                                                       crypto::base64_decode(voice_call_.remote_pubkey_b64),
                                                                       voice_call_.call_id,
                                                                       voice_call_.local_address,
                                                                       voice_call_.remote_address);
                    voice_call_.session_key.assign(session_key.begin(), session_key.end());
                    voice_call_.session_ready = true;
                } catch (...) {
                    clear_voice_call_locked("key-agreement-failed");
                    return;
                }
            }
        }
        voice_call_.incoming = false;
        voice_call_.ringing = false;
        voice_call_.connected = true;
        voice_call_.status = "connected";
        voice_call_.connected_at = now;
        voice_call_.last_signal_at = now;
        voice_call_.peer_label = peer ? peer->remote_label() : voice_call_.peer_label;
        voice_call_.frame_duration_ms = signal.frame_duration_ms == 0 ? voice_call_.frame_duration_ms : signal.frame_duration_ms;
        if (signal.capability_flags != 0) {
            voice_call_.capability_flags = signal.capability_flags;
        }
        if (!signal.codec.empty()) {
            voice_call_.codec = signal.codec;
        }
        break;
    }
    case voice::SignalType::Decline: {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (!voice_call_.active || voice_call_.call_id != signal.call_id) {
            return;
        }
        clear_voice_call_locked("declined");
        break;
    }
    case voice::SignalType::Hangup: {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (!voice_call_.active || voice_call_.call_id != signal.call_id) {
            return;
        }
        clear_voice_call_locked("ended");
        break;
    }
    }
}

void NetworkNode::handle_voice_frame(const voice::AudioFrame& frame,
                                     const chat::ParsedMessage&,
                                     const ChatPayload&,
                                     const std::shared_ptr<PeerSession>&) {
    voice::AudioFrame decoded = frame;
    voice::SessionKey session_key{};
    {
        std::lock_guard<std::mutex> lock(voice_call_mutex_);
        if (!voice_call_.active || voice_call_.call_id != frame.call_id || !voice_call_.session_ready) {
            return;
        }
        try {
            session_key = session_key_from_bytes(voice_call_.session_key);
        } catch (...) {
            return;
        }
    }
    if (!voice::decrypt_audio_frame_inplace(decoded, session_key)) {
        return;
    }

    const auto arrival_ms = now_millis();
    uint64_t sample_latency = 0;
    if (decoded.timestamp > 0 && arrival_ms >= decoded.timestamp && (arrival_ms - decoded.timestamp) < 15000) {
        sample_latency = arrival_ms - decoded.timestamp;
    }

    std::lock_guard<std::mutex> lock(voice_call_mutex_);
    if (!voice_call_.active || voice_call_.call_id != frame.call_id) {
        return;
    }
    voice_call_.last_audio_at = static_cast<uint64_t>(std::time(nullptr));
    if (sample_latency > 0) {
        const auto previous_latency = voice_call_.latency_ms;
        voice_call_.latency_ms = previous_latency == 0
            ? sample_latency
            : ((previous_latency * 7) + sample_latency) / 8;
        const auto latency_delta = previous_latency > sample_latency
            ? (previous_latency - sample_latency)
            : (sample_latency - previous_latency);
        voice_call_.jitter_ms = voice_call_.jitter_ms == 0
            ? latency_delta
            : ((voice_call_.jitter_ms * 7) + latency_delta) / 8;
    }
    if (voice_audio_inbox_.size() >= 64) {
        voice_audio_inbox_.pop_front();
    }
    voice_audio_inbox_.push_back(std::move(decoded));
}

void NetworkNode::append_chat_inbox(const std::string& line) {
    std::lock_guard<std::mutex> lock(chat_mutex_);
    std::filesystem::create_directories(chat_inbox_file_.parent_path());
    std::ofstream out(chat_inbox_file_, std::ios::app);
    if (out) out << line << '\n';
}

void NetworkNode::bootstrap(bool auto_connect) {
    if (!network_active()) return;
    discover_public_endpoint();
    refresh_port_mapping();
    resolve_seed_endpoints();
    save_peers();
    if (auto_connect) {
        connect_known_peers(std::min<size_t>(4, constants::MAX_PEER_CONNECTIONS));
    }
}

void NetworkNode::bootstrap_chat_routing() {
    if (!network_active()) return;
    resolve_seed_endpoints();
    save_peers();
    connect_known_peers(std::min<size_t>(4, constants::MAX_PEER_CONNECTIONS));
}

std::optional<std::string> NetworkNode::advertised_endpoint() const {
    if (!advertised_self_) return std::nullopt;
    return endpoint_label(advertised_self_->ip, advertised_self_->port);
}

ip_address NetworkNode::public_ip() {
    if (advertised_self_) return advertised_self_->ip;
    return detect_public_ip(ctx_, ip_detect_host_, ip_detect_port_, ip_detect_path_);
}

NetworkNode::PortMappingStatus NetworkNode::port_mapping_status() const {
    std::lock_guard<std::mutex> guard(port_mapping_mutex_);
    return port_mapping_status_;
}

std::optional<NetworkNode::ProxySettings> NetworkNode::proxy_settings() const {
    return proxy_;
}

Message NetworkNode::build_getheaders_request() const {
    Message request{MessageType::GETHEADERS, {}};
    if (!chain_) {
        serialization::write_varint(request.payload, 0);
        return request;
    }

    auto locator = chain_->block_locator();
    serialization::write_varint(request.payload, locator.size());
    for (const auto& hash : locator) {
        auto bytes = hash.to_padded_bytes(constants::POW_HASH_BYTES);
        request.payload.insert(request.payload.end(), bytes.begin(), bytes.end());
    }
    return request;
}

Message NetworkNode::build_version_message() const {
    Message ver;
    ver.type = MessageType::VERSION;
    VersionPayload payload;
    payload.protocol_version = constants::PROTOCOL_VERSION;
    payload.best_height = best_height;
    payload.listen_port = listen_port_ ? listen_port_ : default_p2p_port();
    if (advertised_self_) {
        payload.advertised_ip = advertised_self_->ip;
    }
    ver.payload = payload.serialize();
    return ver;
}

void NetworkNode::request_headers_from(const std::shared_ptr<PeerSession>& peer) {
    if (!peer || !chain_) return;
    peer->send(build_getheaders_request());
}

void NetworkNode::enqueue_block_download(const uint256_t& hash, const std::shared_ptr<PeerSession>& peer) {
    if (!chain_ || !peer) return;
    if (chain_->get_block_by_hash(hash)) return;

    {
        std::lock_guard<std::mutex> guard(sync_mutex_);
        if (queued_blocks_.count(hash) || inflight_blocks_.count(hash)) return;
        block_download_queue_.push_back({hash, peer});
        queued_blocks_.insert(hash);
    }
    pump_block_downloads();
}

void NetworkNode::pump_block_downloads() {
    std::vector<std::pair<std::shared_ptr<PeerSession>, Message>> sends;
    {
        std::lock_guard<std::mutex> guard(sync_mutex_);
        while (inflight_blocks_.size() < constants::MAX_PARALLEL_BLOCK_DOWNLOADS &&
               !block_download_queue_.empty()) {
            auto pending = block_download_queue_.front();
            block_download_queue_.pop_front();
            auto peer = pending.peer.lock();
            queued_blocks_.erase(pending.hash);
            if (!peer) continue;
            if (chain_ && chain_->get_block_by_hash(pending.hash)) continue;

            Message req;
            req.type = MessageType::GETBLOCK;
            auto bytes = pending.hash.to_padded_bytes(constants::POW_HASH_BYTES);
            req.payload.assign(bytes.begin(), bytes.end());
            inflight_blocks_.insert(pending.hash);
            sends.emplace_back(std::move(peer), std::move(req));
        }
    }

    for (auto& [peer, request] : sends) {
        peer->send(request);
    }
}

void NetworkNode::finish_block_download(const uint256_t& hash) {
    {
        std::lock_guard<std::mutex> guard(sync_mutex_);
        inflight_blocks_.erase(hash);
        queued_blocks_.erase(hash);
    }
    pump_block_downloads();
}

void NetworkNode::maybe_continue_sync(const std::shared_ptr<PeerSession>& peer) {
    if (!peer || !chain_) return;

    bool should_request = false;
    {
        std::lock_guard<std::mutex> guard(sync_mutex_);
        auto it = peer_heights_.find(peer->remote_label());
        should_request = (it != peer_heights_.end()) &&
                         (it->second > chain_->best_height()) &&
                         block_download_queue_.empty() &&
                         inflight_blocks_.empty();
    }

    if (should_request) {
        request_headers_from(peer);
    }
}

void NetworkNode::do_accept() {
    acceptor_.async_accept([this](std::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            if (!network_active()) {
                boost::system::error_code close_ec;
                socket.close(close_ec);
                do_accept();
                return;
            }
            std::string label = "unknown";
            std::string netgroup = "unknown";
            try {
                auto remote = socket.remote_endpoint();
                label = remote.address().to_string() + ":" + std::to_string(remote.port());
                netgroup = netgroup_from_host(remote.address().to_string());
            } catch (...) {
            }
            try {
                bool over_netgroup_limit = false;
                {
                    std::lock_guard<std::mutex> guard(sessions_mutex_);
                    size_t same_group = 0;
                    for (const auto& session : sessions_) {
                        if (!session) continue;
                        if (peer_netgroup(session->remote_label()) == netgroup) {
                            ++same_group;
                        }
                    }
                    over_netgroup_limit = same_group >= static_cast<size_t>(constants::MAX_INBOUND_PEERS_PER_NETGROUP);
                }
                if (is_banned(label) || over_netgroup_limit) {
                    if (over_netgroup_limit) {
                        log_warn("net", "reject inbound peer due to netgroup concentration peer=" + label +
                                        " netgroup=" + netgroup);
                    }
                    socket.close();
                } else {
                    auto session = std::make_shared<PeerSession>(std::move(socket), *this);
                    {
                        std::lock_guard<std::mutex> guard(sessions_mutex_);
                        sessions_.push_back(session);
                    }
                    session->start();
                }
            } catch (...) {
            }
        }
        do_accept();
    });
}

void NetworkNode::register_default_handlers() {
    set_handler(MessageType::PING, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        Message resp{MessageType::PONG, m.payload};
        peer->send(resp);
    });

    set_handler(MessageType::VERSION, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        Message ack{MessageType::VERACK, {}};
        peer->send(ack);
        peer->send(build_version_message());
        peer->send({MessageType::GETPEERS, {}});
        try {
            auto version = VersionPayload::deserialize(m.payload);
            peer->mark_version_seen();
            auto advertised = canonical_peer_label_from_version(peer->endpoint(), version);
            if (advertised) {
                record_peer_label(*advertised, "handshake");
                peer->adopt_remote_label(*advertised);
            }
            {
                std::lock_guard<std::mutex> guard(sync_mutex_);
                peer_heights_[peer->remote_label()] = version.best_height;
            }
            {
                std::lock_guard<std::mutex> guard(peer_state_mutex_);
                auto& state = peer_states_[peer->remote_label()];
                const auto now = static_cast<int64_t>(std::time(nullptr));
                if (state.netgroup.empty()) state.netgroup = peer_netgroup(peer->remote_label());
                state.last_seen = now;
                state.last_connected = now;
                state.last_updated = now;
                state.successful_connections += 1;
                state.last_announced_height = version.best_height;
                if (state.source.empty()) state.source = "handshake";
            }
            save_peer_state();
            update_chain_approval_state();
            if (chain_ && version.best_height > chain_->best_height()) {
                request_headers_from(peer);
            }
        } catch (...) {
            punish(peer, 10, "invalid version payload");
        }
    });

    set_handler(MessageType::GETHEADERS, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        if (!chain_) return;
        try {
            Message resp;
            resp.type = MessageType::HEADERS;
            std::vector<uint8_t> payload;
            std::vector<BlockHeader> headers;

            if (m.payload.size() == sizeof(uint64_t)) {
                // Backward compatibility with the old height-based request format.
                const uint8_t* ptr = m.payload.data();
                size_t rem = m.payload.size();
                uint64_t start = serialization::read_int<uint64_t>(ptr, rem);
                uint64_t tip = chain_->best_height();
                for (uint64_t h = start; h <= tip && headers.size() < constants::MAX_HEADERS_PER_MESSAGE; ++h) {
                    auto blk = chain_->get_block(h);
                    if (!blk) break;
                    headers.push_back(blk->header);
                }
            } else {
                const uint8_t* ptr = m.payload.data();
                size_t rem = m.payload.size();
                std::vector<uint256_t> locator_hashes;
                if (rem > 0) {
                    uint64_t count = serialization::read_varint(ptr, rem);
                    if (count > 64) {
                        punish(peer, 5, "oversized block locator");
                        return;
                    }
                    locator_hashes.reserve(static_cast<size_t>(count));
                    for (uint64_t i = 0; i < count; ++i) {
                        if (rem < constants::POW_HASH_BYTES) {
                            punish(peer, 10, "truncated block locator");
                            return;
                        }
                        locator_hashes.push_back(uint256_t::from_bytes(ptr, constants::POW_HASH_BYTES));
                        ptr += constants::POW_HASH_BYTES;
                        rem -= constants::POW_HASH_BYTES;
                    }
                }
                headers = chain_->headers_after_locator(locator_hashes, constants::MAX_HEADERS_PER_MESSAGE);
            }

            serialization::write_varint(payload, headers.size());
            for (const auto& header : headers) {
                auto ser = header.serialize();
                serialization::write_bytes(payload, ser.data(), ser.size());
            }
            resp.payload = payload;
            peer->send(resp);
        } catch (...) {
            punish(peer, 10, "invalid getheaders payload");
        }
    });

    set_handler(MessageType::GETBLOCK, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        if (!chain_ || (m.payload.size() != 32 && m.payload.size() != constants::POW_HASH_BYTES)) return;
        uint256_t hash = uint256_t::from_bytes(m.payload.data(), m.payload.size());
        auto blk = chain_->get_block_by_hash(hash);
        if (blk) {
            Message resp;
            resp.type = MessageType::BLOCK;
            auto ser = blk->serialize();
            resp.payload = ser;
            peer->send(resp);
        }
    });

    set_handler(MessageType::BLOCK, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        if (!chain_) return;
        const uint8_t* ptr = m.payload.data();
        size_t rem = m.payload.size();
        try {
            Block blk = Block::deserialize(ptr, rem);
            auto block_hash = blk.header.pow_hash();
            bool ok = chain_->accept_block(blk);
            finish_block_download(block_hash);
            if (ok) {
                best_height = chain_->best_height();
                update_chain_approval_state();
                // Broadcast inventory for the new block
                Message inv;
                inv.type = MessageType::INV;
                std::vector<uint8_t> payload;
                serialization::write_varint(payload, 1);
                payload.push_back(1); // block type
                auto hb = block_hash.to_padded_bytes(constants::POW_HASH_BYTES);
                payload.insert(payload.end(), hb.begin(), hb.end());
                inv.payload = payload;
                broadcast(inv);
                maybe_continue_sync(peer);
            } else {
                update_chain_approval_state();
                punish(peer, 5, "rejected block");
            }
        } catch (...) {
            punish(peer, 10, "invalid block payload");
        }
    });

    set_handler(MessageType::GETPEERS, [this](const Message&, std::shared_ptr<PeerSession> peer) {
        Message resp;
        resp.type = MessageType::PEERS;
        std::vector<uint8_t> payload;
        auto list = peers();
        serialization::write_varint(payload, list.size());
        for (const auto& p : list) {
            auto bytes = p.to_bytes();
            payload.insert(payload.end(), bytes.begin(), bytes.end());
        }
        resp.payload = payload;
        peer->send(resp);
    });

    set_handler(MessageType::PEERS, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        (void) peer;
        try {
            const uint8_t* ptr = m.payload.data();
            size_t rem = m.payload.size();
            uint64_t count = serialization::read_varint(ptr, rem);
            if (count > 1024) {
                return;
            }
            for (uint64_t i = 0; i < count; ++i) {
                if (rem < 7) break;
                auto p = PeerAddress::from_bytes(ptr, 7);
                ptr += 7;
                rem -= 7;
                record_peer_label(endpoint_label(p.ip, p.port));
            }
            save_peers();
        } catch (...) {
        }
    });

    set_handler(MessageType::HEADERS, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        if (!chain_) return;
        try {
            const uint8_t* ptr = m.payload.data();
            size_t rem = m.payload.size();
            uint64_t count = serialization::read_varint(ptr, rem);
            if (count > constants::MAX_HEADERS_PER_MESSAGE) {
                punish(peer, 5, "too many headers");
                return;
            }
            uint256_t previous_link;
            for (uint64_t i = 0; i < count && rem > 0; ++i) {
                auto hbytes = serialization::read_bytes(ptr, rem);
                const uint8_t* hp = hbytes.data();
                size_t hrem = hbytes.size();
                BlockHeader hdr = BlockHeader::deserialize(hp, hrem);
                uint256_t canonical = hdr.pow_hash();

                if (i == 0) {
                    if (hdr.prev_block_hash != uint256_t() && !chain_->knows_hash(hdr.prev_block_hash)) {
                        punish(peer, 10, "headers do not connect to known chain");
                        return;
                    }
                } else if (hdr.prev_block_hash != previous_link) {
                    punish(peer, 10, "header batch discontinuity");
                    return;
                }
                previous_link = hdr.hash();

                if (!chain_->get_block_by_hash(canonical)) {
                    enqueue_block_download(canonical, peer);
                }
            }
            pump_block_downloads();
            if (count == 0) {
                maybe_continue_sync(peer);
            }
        } catch (...) {
            punish(peer, 10, "invalid headers payload");
        }
    });

    set_handler(MessageType::CHAT, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        try {
            auto chat_payload = ChatPayload::deserialize(m.payload);
            auto parsed = chat::parse_chat_payload(chat_payload, chat_wallet_.get());
            auto now = static_cast<int64_t>(std::time(nullptr));
            if (mark_chat_seen(parsed.message_id, now)) {
                log_warn("chat", "duplicate chat ignored id=" + parsed.message_id +
                                     " from=" + peer->remote_label());
                return;
            }

            const bool is_voice_control = chat_payload.chat_type == chat::CHAT_TYPE_VOICE_CONTROL;
            const bool is_voice_frame = chat_payload.chat_type == chat::CHAT_TYPE_VOICE_FRAME;
            const bool is_mail = chat_payload.chat_type == chat::CHAT_TYPE_MAIL;
            if (is_mail) {
                record_distributed_mail(chat_payload, peer->remote_label());
            }
            if (is_voice_control || is_voice_frame) {
                if (is_voice_control) {
                    if (parsed.decrypted) {
                        if (auto signal = voice::parse_signal_content(parsed.content)) {
                            handle_voice_signal(*signal, parsed, chat_payload, peer);
                        }
                    }
                } else if (auto frame = voice::parse_audio_frame_content(parsed.content)) {
                    handle_voice_frame(*frame, parsed, chat_payload, peer);
                }
                auto relayed = broadcast_chat(m, peer);
                if (relayed > 0) {
                    log_info("voice", "relayed voice payload id=" + parsed.message_id +
                                         " peers=" + std::to_string(relayed));
                }
                return;
            }

            chat::HistoryEntry entry;
            entry.direction = "in";
            entry.legacy = parsed.legacy;
            entry.authenticated = parsed.authenticated;
            entry.encrypted = parsed.encrypted;
            entry.decrypted = parsed.decrypted;
            entry.is_private = chat_payload.chat_type != chat::CHAT_TYPE_PUBLIC;
            entry.timestamp = parsed.timestamp;
            entry.nonce = parsed.nonce;
            entry.message_id = parsed.message_id;
            entry.sender_address = parsed.sender_address;
            entry.sender_pubkey = crypto::base64_encode(chat_payload.sender_pubkey);
            entry.recipient_address = parsed.recipient_address;
            entry.recipient_pubkey = crypto::base64_encode(chat_payload.recipient_pubkey);
            entry.channel = parsed.channel;
            entry.subject = parsed.content.subject;
            entry.mail_to = parsed.content.mail_to;
            entry.mail_cc = parsed.content.mail_cc;
            entry.message = parsed.message;
            entry.peer_label = peer->remote_label();
            entry.status = parsed.encrypted && !parsed.decrypted ? "received-opaque" : "received";
            entry.content_type = chat::content_type_name(parsed.content.type);
            entry.mime_type = parsed.content.mime_type;
            entry.attachment_name = parsed.content.attachment_name;
            entry.attachment_size = static_cast<uint64_t>(parsed.content.attachment_bytes.size());
            entry.audio_privacy = chat::audio_privacy_name(parsed.content.audio_privacy);
            entry.transcript = parsed.content.transcript;
            entry.encryption_mode = chat::encryption_mode_name(parsed.encryption_mode);
            if (!parsed.content.attachment_bytes.empty()) {
                entry.attachment_path = chat::persist_attachment(parsed.content,
                                                                 (is_mail ? mail_history_file_ : chat_history_file_).parent_path(),
                                                                 parsed.message_id,
                                                                 is_mail ? "p2pmail_media" : "chat_media").string();
            }

            auto summary = chat::describe_history_entry(entry);
            log_info(is_mail ? "mail" : "chat", summary);
            if (is_mail) {
                record_mail_history(entry);
            } else {
                record_chat_history(entry);
                append_chat_inbox(summary);
            }
            auto relayed = broadcast_chat(m, peer);
            if (relayed > 0) {
                log_info(is_mail ? "mail" : "chat",
                         std::string("relayed ") + (is_mail ? "mail" : "chat") +
                         " id=" + parsed.message_id +
                         " peers=" + std::to_string(relayed));
            }
        } catch (const std::exception& ex) {
            punish(peer, 10, std::string("invalid chat payload: ") + ex.what());
        }
    });

    set_handler(MessageType::DHT_MAIL_STORE, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        try {
            auto payload = DhtMailStorePayload::deserialize(m.payload);
            if (payload.record.message_id.empty() || payload.record.recipient_address.empty()) {
                return;
            }
            if (payload.record.peer_label.empty()) {
                payload.record.peer_label = peer->remote_label();
            }
            store_distributed_mail_record(payload.record);
            MailStorageReceipt receipt;
            receipt.message_id = payload.record.message_id;
            receipt.recipient_address = payload.record.recipient_address;
            receipt.replica_label = advertised_endpoint().value_or(peer->remote_label());
            receipt.storage_hash_hex = mail_storage_hash_hex(payload.record);
            receipt.stored_at = payload.record.stored_at;
            receipt.expires_at = payload.record.expires_at;
            receipt.receipt_at = static_cast<uint64_t>(std::time(nullptr));
            sign_mail_receipt(receipt, chat_wallet_.get());
            refresh_mail_receipt_bond(receipt, chain_, mail_policy_.minimum_bond_sats);
            upsert_mail_storage_receipt(receipt);

            Message ack;
            ack.type = MessageType::DHT_MAIL_RECEIPT;
            ack.payload = DhtMailReceiptPayload{2, receipt}.serialize();
            peer->send(ack);
        } catch (const std::exception& ex) {
            punish(peer, 5, std::string("invalid dht mail store: ") + ex.what());
        }
    });

    set_handler(MessageType::DHT_MAIL_RECEIPT, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        try {
            auto payload = DhtMailReceiptPayload::deserialize(m.payload);
            if (payload.receipt.message_id.empty()) return;
            if (payload.receipt.replica_label.empty()) {
                payload.receipt.replica_label = peer->remote_label();
            }
            refresh_mail_receipt_bond(payload.receipt, chain_, mail_policy_.minimum_bond_sats);
            if (!verify_mail_receipt_signature(payload.receipt)) {
                slash_mail_receipt(payload.receipt, "invalid receipt signature", payload.receipt.provider_signature_b64, peer->remote_label());
                return;
            }
            upsert_mail_storage_receipt(payload.receipt);
            maybe_issue_mail_storage_challenge(payload.receipt);
        } catch (const std::exception& ex) {
            punish(peer, 5, std::string("invalid dht mail receipt: ") + ex.what());
        }
    });

    set_handler(MessageType::DHT_MAIL_FIND, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        try {
            auto query = DhtMailFindPayload::deserialize(m.payload);
            if (query.query_id.empty() || query.recipient_address.empty()) {
                return;
            }
            bool fresh = false;
            {
                std::lock_guard<std::mutex> lock(dht_mutex_);
                fresh = dht_seen_queries_.insert(query.query_id).second;
            }
            if (!fresh) return;

            auto matches = distributed_mail_records(query.recipient_address, query.limit);
            if (!matches.empty()) {
                Message resp;
                resp.type = MessageType::DHT_MAIL_RESULTS;
                resp.payload = DhtMailResultsPayload{1, query.query_id, matches}.serialize();
                bool delivered = false;
                if (!query.requester_label.empty() && query.requester_label != peer->remote_label()) {
                    delivered = send_to_or_relay_mail_peer(query.requester_label, resp, "mail-results");
                }
                if (!delivered) {
                    peer->send(resp);
                }
            }

            if (query.hops > 0 && !query.requester_label.empty()) {
                auto labels = active_peer_labels();
                const auto policy = mail_replication_policy();
                const auto forwards = select_nearest_mail_peers(labels,
                                                                query.recipient_address,
                                                                std::min<size_t>(std::max<uint32_t>(policy.replica_target, 1), labels.size()),
                                                                peer->remote_label(),
                                                                query.requester_label.empty() ? std::nullopt : std::make_optional(query.requester_label));
                if (!forwards.empty()) {
                    query.hops = static_cast<uint8_t>(query.hops - 1);
                    Message fwd;
                    fwd.type = MessageType::DHT_MAIL_FIND;
                    fwd.payload = query.serialize();
                    for (const auto& label : forwards) {
                        (void)send_to_or_relay_mail_peer(label, fwd, "mail-find-forward");
                    }
                }
            }
        } catch (const std::exception& ex) {
            punish(peer, 5, std::string("invalid dht mail find: ") + ex.what());
        }
    });

    set_handler(MessageType::DHT_MAIL_RESULTS, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        try {
            auto payload = DhtMailResultsPayload::deserialize(m.payload);
            if (payload.query_id.empty()) return;
            {
                std::lock_guard<std::mutex> lock(dht_mutex_);
                auto it = dht_pending_results_.find(payload.query_id);
                if (it == dht_pending_results_.end()) {
                    return;
                }
                auto& rows = it->second;
                for (auto record : payload.records) {
                    if (record.peer_label.empty()) {
                        record.peer_label = peer->remote_label();
                    }
                    const bool exists = std::any_of(rows.begin(), rows.end(), [&](const auto& existing) {
                        return existing.message_id == record.message_id;
                    });
                    if (!exists) {
                        rows.push_back(std::move(record));
                    }
                }
                dht_last_results_at_ = static_cast<uint64_t>(std::time(nullptr));
            }
            dht_results_cv_.notify_all();
        } catch (const std::exception& ex) {
            punish(peer, 5, std::string("invalid dht mail results: ") + ex.what());
        }
    });

    set_handler(MessageType::DHT_MAIL_CHALLENGE, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        try {
            auto challenge = DhtMailChallengePayload::deserialize(m.payload);
            if (challenge.challenge_id.empty() || challenge.message_id.empty()) return;
            const auto matches = distributed_mail_records(std::make_optional(challenge.recipient_address), 0);
            auto it = std::find_if(matches.begin(), matches.end(), [&](const auto& record) {
                return record.message_id == challenge.message_id;
            });
            if (it == matches.end()) return;

            DhtMailProofPayload proof;
            proof.challenge_id = challenge.challenge_id;
            proof.message_id = challenge.message_id;
            proof.recipient_address = challenge.recipient_address;
            proof.replica_label = advertised_endpoint().value_or(peer->remote_label());
            proof.proof_hash_hex = mail_storage_proof_hash_hex(*it, challenge.nonce_b64);
            proof.responded_at = static_cast<uint64_t>(std::time(nullptr));

            Message resp;
            resp.type = MessageType::DHT_MAIL_PROOF;
            resp.payload = proof.serialize();
            if (!challenge.requester_label.empty() && challenge.requester_label != peer->remote_label()) {
                if (!send_to_or_relay_mail_peer(challenge.requester_label, resp, "mail-proof-response")) {
                    peer->send(resp);
                }
            } else {
                peer->send(resp);
            }
        } catch (const std::exception& ex) {
            punish(peer, 5, std::string("invalid dht mail challenge: ") + ex.what());
        }
    });

    set_handler(MessageType::DHT_MAIL_PROOF, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        try {
            auto proof = DhtMailProofPayload::deserialize(m.payload);
            PendingMailProofChallenge pending;
            {
                std::lock_guard<std::mutex> lock(dht_mutex_);
                auto it = pending_mail_challenges_.find(proof.challenge_id);
                if (it == pending_mail_challenges_.end()) return;
                pending = it->second;
                pending_mail_challenges_.erase(it);
            }
            const auto local = distributed_mail_records(std::make_optional(pending.recipient_address), 0);
            auto it = std::find_if(local.begin(), local.end(), [&](const auto& record) {
                return record.message_id == pending.message_id;
            });
            if (it == local.end()) return;

            const auto expected = mail_storage_proof_hash_hex(*it, pending.nonce_b64);
            if (expected != proof.proof_hash_hex) {
                auto receipts = mail_storage_receipts(std::make_optional(pending.message_id));
                auto receipt_it = std::find_if(receipts.begin(), receipts.end(), [&](const auto& receipt) {
                    return receipt.replica_label == pending.replica_label || receipt.replica_label == proof.replica_label;
                });
                if (receipt_it != receipts.end()) {
                    slash_mail_receipt(*receipt_it, "invalid proof hash", proof.proof_hash_hex, peer->remote_label());
                } else {
                    punish(peer, 5, "invalid dht mail proof");
                }
                return;
            }

            auto receipts = mail_storage_receipts(std::make_optional(pending.message_id));
            auto receipt_it = std::find_if(receipts.begin(), receipts.end(), [&](const auto& receipt) {
                return receipt.replica_label == pending.replica_label || receipt.replica_label == proof.replica_label;
            });
            if (receipt_it != receipts.end()) {
                auto receipt = *receipt_it;
                if (!proof.replica_label.empty()) {
                    receipt.replica_label = proof.replica_label;
                }
                refresh_mail_receipt_bond(receipt, chain_, mail_policy_.minimum_bond_sats);
                if (!verify_mail_receipt_signature(receipt) || !receipt.bond_satisfied) {
                    slash_mail_receipt(receipt, "receipt lost trust during proof verification", proof.proof_hash_hex, peer->remote_label());
                    return;
                }
                receipt.last_proof_hash_hex = proof.proof_hash_hex;
                receipt.verified = true;
                receipt.verified_at = proof.responded_at;
                receipt.last_challenged_at = pending.created_at;
                upsert_mail_storage_receipt(receipt);
                dht_last_proof_at_ = proof.responded_at;
            }
        } catch (const std::exception& ex) {
            punish(peer, 5, std::string("invalid dht mail proof: ") + ex.what());
        }
    });

    set_handler(MessageType::DHT_MAIL_NAT_INTRO, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        try {
            auto intro = DhtMailNatIntroPayload::deserialize(m.payload);
            if (intro.target_label.empty() || intro.initiator_label.empty()) return;
            if (intro.hops == 0) return;
            dht_last_nat_intro_at_ = static_cast<uint64_t>(std::time(nullptr));
            if (is_self_label(intro.target_label) && looks_like_peer_label(intro.initiator_label)) {
                bool attempted = attempt_nat_candidates(intro.initiator_candidates);
                if (!attempted) {
                    auto parsed = parse_host_port(intro.initiator_label, listen_port_ ? listen_port_ : default_p2p_port());
                    if (parsed) {
                        connect(parsed->first, parsed->second);
                    }
                }
                if (intro.request_reverse) {
                    const auto self = advertised_endpoint().value_or(peer->remote_label());
                    Message reverse;
                    reverse.type = MessageType::DHT_MAIL_NAT_INTRO;
                    reverse.payload = DhtMailNatIntroPayload{2,
                                                             self,
                                                             intro.initiator_label,
                                                             intro.purpose,
                                                             static_cast<uint64_t>(std::time(nullptr)),
                                                             2,
                                                             false,
                                                             true,
                                                             build_nat_candidates(std::make_optional(intro.initiator_label))}.serialize();
                    (void)send_to_or_relay_mail_peer(intro.initiator_label, reverse, "mail-nat-reverse");
                    dht_last_reverse_intro_at_ = static_cast<uint64_t>(std::time(nullptr));
                }
                return;
            }
            if (send_to(intro.target_label, m)) {
                ++dht_relay_successes_;
                return;
            }

            auto relays = active_peer_labels();
            relays.erase(std::remove(relays.begin(), relays.end(), peer->remote_label()), relays.end());
            relays.erase(std::remove(relays.begin(), relays.end(), intro.target_label), relays.end());
            intro.hops = static_cast<uint8_t>(intro.hops - 1);
            Message fwd = m;
            fwd.payload = intro.serialize();
            const size_t fanout = std::min<size_t>(2, relays.size());
            for (size_t i = 0; i < fanout; ++i) {
                (void)send_to(relays[i], fwd);
            }
        } catch (const std::exception& ex) {
            punish(peer, 3, std::string("invalid dht nat intro: ") + ex.what());
        }
    });

    set_handler(MessageType::GETWORK, [this](const Message&, std::shared_ptr<PeerSession> peer) {
        if (!chain_) return;
        // Minimal work template: last header, nonce range 0..0x00ffffff
        WorkRequest wr;
        wr.height = chain_->best_height() + 1;
        auto prev = chain_->get_block(chain_->best_height());
        wr.header = prev ? prev->header : BlockHeader{};
        wr.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
        wr.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
        wr.header.bits = chain_->next_work_bits(wr.header.timestamp);
        wr.header.nonce = 0;
        wr.nonce_start = 0;
        wr.nonce_end = 0x00ffffff;
        Message resp;
        resp.type = MessageType::GETWORK;
        resp.payload = wr.serialize();
        peer->send(resp);
    });

    set_handler(MessageType::SUBMITWORK, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        if (!chain_) return;
        const uint8_t* ptr = m.payload.data();
        size_t rem = m.payload.size();
        try {
            Block blk = Block::deserialize(ptr, rem);
            bool ok = chain_->accept_block(blk);
            if (ok) {
                best_height = chain_->best_height();
                update_chain_approval_state();
                Message inv;
                inv.type = MessageType::INV;
                std::vector<uint8_t> payload;
                serialization::write_varint(payload, 1);
                payload.push_back(1); // block
                auto hb = blk.header.pow_hash().to_padded_bytes(constants::POW_HASH_BYTES);
                payload.insert(payload.end(), hb.begin(), hb.end());
                inv.payload = payload;
                broadcast(inv);
            } else {
                update_chain_approval_state();
                punish(peer, 5, "rejected submitted work");
            }
        } catch (...) {
            punish(peer, 10, "submitwork deserialize failed");
        }
    });

    set_handler(MessageType::INV, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        if (!chain_) return;
        try {
            const uint8_t* ptr = m.payload.data();
            size_t rem = m.payload.size();
            uint64_t count = serialization::read_varint(ptr, rem);
            for (uint64_t i = 0; i < count; ++i) {
                if (rem < 1) break;
                uint8_t inv_type = *ptr; ptr++; rem--;
                if (inv_type == 1) { // block
                    if (rem < constants::POW_HASH_BYTES) break;
                    uint256_t h = uint256_t::from_bytes(ptr, constants::POW_HASH_BYTES);
                    ptr += constants::POW_HASH_BYTES;
                    rem -= constants::POW_HASH_BYTES;
                    if (!chain_->get_block_by_hash(h)) {
                        enqueue_block_download(h, peer);
                    }
                } else if (inv_type == 2) { // tx
                    if (rem < 32) break;
                    std::array<uint8_t,32> hbytes{};
                    std::memcpy(hbytes.data(), ptr, 32);
                    ptr += 32; rem -= 32;
                    uint256_t h(hbytes);
                    if (!chain_->mempool().contains(h)) {
                        Message req;
                        req.type = MessageType::GETTX;
                        req.payload.assign(hbytes.begin(), hbytes.end());
                        peer->send(req);
                    }
                }
            }
            pump_block_downloads();
        } catch (...) {
            punish(peer, 10, "invalid inventory payload");
        }
    });

    set_handler(MessageType::GETTX, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        if (!chain_ || m.payload.size() != 32) return;
        std::array<uint8_t,32> hbytes{};
        std::memcpy(hbytes.data(), m.payload.data(), 32);
        uint256_t hash(hbytes);
        if (!chain_->mempool().contains(hash)) return;
        const auto& tx = chain_->mempool().get_transaction(hash);
        Message resp;
        resp.type = MessageType::TX;
        resp.payload = tx.serialize();
        peer->send(resp);
    });

    set_handler(MessageType::TX, [this](const Message& m, std::shared_ptr<PeerSession> peer) {
        if (!chain_) return;
        const uint8_t* ptr = m.payload.data();
        size_t rem = m.payload.size();
        try {
            Transaction tx = Transaction::deserialize(ptr, rem);
            uint256_t h = tx.hash();
            if (chain_->mempool().contains(h)) return;
            Mempool::AcceptStatus status = Mempool::AcceptStatus::Invalid;
            bool ok = chain_->mempool().add_transaction(
                tx, chain_->utxo(), static_cast<uint32_t>(chain_->best_height()), &status);
            if (ok) {
                Message inv;
                inv.type = MessageType::INV;
                std::vector<uint8_t> payload;
                serialization::write_varint(payload, 1);
                payload.push_back(2); // tx type
                auto hb = h.to_bytes();
                payload.insert(payload.end(), hb.begin(), hb.end());
                inv.payload = payload;
                broadcast(inv);
            } else {
                if (status == Mempool::AcceptStatus::MissingInputs ||
                    status == Mempool::AcceptStatus::Duplicate) {
                    return;
                }
                int penalty = (status == Mempool::AcceptStatus::LowFee ||
                               status == Mempool::AcceptStatus::NonStandard)
                                  ? 1
                                  : 5;
                punish(peer, penalty,
                       "tx rejected status=" + std::string(mempool_status_name(status)));
            }
        } catch (...) {
            punish(peer, 10, "tx deserialize failed");
        }
    });
}

// ---------------- IP detection ----------------
void NetworkNode::record_peer(const boost::asio::ip::tcp::endpoint& ep) {
    if (!ep.address().is_v4()) return;
    record_peer_label(ep.address().to_string() + ":" + std::to_string(ep.port()), "peer");
}

void NetworkNode::record_peer_label(const std::string& label, const std::string& source) {
    if (label.empty() || is_self_label(label)) return;
    {
        std::lock_guard<std::mutex> guard(peers_mutex_);
        known_peers_.insert(label);
    }
    {
        std::lock_guard<std::mutex> guard(peer_state_mutex_);
        auto& state = peer_states_[label];
        if (state.netgroup.empty()) state.netgroup = peer_netgroup(label);
        if (!source.empty() && (state.source.empty() || state.source == "peer")) {
            state.source = source;
        }
        if (state.last_updated == 0) state.last_updated = static_cast<int64_t>(std::time(nullptr));
    }
}

bool NetworkNode::begin_pending_connect(const std::string& label) {
    std::lock_guard<std::mutex> guard(pending_connect_mutex_);
    return pending_connects_.insert(label).second;
}

void NetworkNode::end_pending_connect(const std::string& label) {
    std::lock_guard<std::mutex> guard(pending_connect_mutex_);
    pending_connects_.erase(label);
}

void NetworkNode::load_peers() {
    if (peers_file_.empty()) return;
    std::ifstream in(peers_file_);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            std::lock_guard<std::mutex> guard(peers_mutex_);
            known_peers_.insert(line);
        }
    }
}

void NetworkNode::save_peers() {
    if (peers_file_.empty()) return;
    std::ofstream out(peers_file_, std::ios::trunc);
    if (!out) return;
    std::unordered_set<std::string> peers_copy;
    {
        std::lock_guard<std::mutex> guard(peers_mutex_);
        peers_copy = known_peers_;
    }
    for (const auto& p : peers_copy) out << p << "\n";
}

void NetworkNode::load_peer_state() {
    if (peer_state_file_.empty()) return;
    std::ifstream in(peer_state_file_);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        std::string label;
        PeerState state;
        if (!std::getline(ss, label, '\t')) continue;
        if (!(ss >> state.score >> state.banned_until >> state.last_updated)) continue;
        ss >> state.last_seen >> state.last_connected
           >> state.successful_connections >> state.failed_connections
           >> state.invalid_messages >> state.last_announced_height
           >> state.source >> state.netgroup;
        std::string reason;
        std::getline(ss >> std::ws, reason);
        state.last_reason = reason;
        if (state.netgroup.empty()) state.netgroup = peer_netgroup(label);
        if (state.source.empty()) state.source = "peer";
        peer_states_[label] = state;
    }
}

void NetworkNode::save_peer_state() const {
    if (peer_state_file_.empty()) return;
    std::filesystem::create_directories(peer_state_file_.parent_path());
    std::lock_guard<std::mutex> guard(peer_state_mutex_);
    std::ofstream out(peer_state_file_, std::ios::trunc);
    if (!out) return;
    for (const auto& [label, state] : peer_states_) {
        if (state.score == 0 && state.banned_until == 0 &&
            state.successful_connections == 0 && state.failed_connections == 0 &&
            state.invalid_messages == 0 && state.last_seen == 0 &&
            state.last_connected == 0 && state.last_reason.empty()) {
            continue;
        }
        out << label << '\t'
            << state.score << '\t'
            << state.banned_until << '\t'
            << state.last_updated << '\t'
            << state.last_seen << '\t'
            << state.last_connected << '\t'
            << state.successful_connections << '\t'
            << state.failed_connections << '\t'
            << state.invalid_messages << '\t'
            << state.last_announced_height << '\t'
            << state.source << '\t'
            << state.netgroup << '\t'
            << state.last_reason << "\n";
    }
}

void NetworkNode::decay_peer_state_locked(const std::string& label, int64_t now) const {
    auto it = peer_states_.find(label);
    if (it == peer_states_.end()) return;
    auto& state = it->second;
    if (state.last_updated == 0) {
        state.last_updated = now;
        return;
    }
    int64_t elapsed = now - state.last_updated;
    if (elapsed >= constants::PEER_SCORE_DECAY_INTERVAL_SECONDS) {
        int64_t intervals = elapsed / constants::PEER_SCORE_DECAY_INTERVAL_SECONDS;
        int decay = static_cast<int>(intervals) * constants::PEER_SCORE_DECAY_POINTS;
        state.score = std::max(0, state.score - decay);
        state.last_updated += intervals * constants::PEER_SCORE_DECAY_INTERVAL_SECONDS;
    }
    if (state.banned_until <= now) state.banned_until = 0;
}

bool NetworkNode::is_banned(const std::string& label) {
    if (label.empty()) return false;
    bool banned = false;
    bool changed = false;
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    {
        std::lock_guard<std::mutex> guard(peer_state_mutex_);
        auto it = peer_states_.find(label);
        if (it == peer_states_.end()) return false;
        int64_t old_banned_until = it->second.banned_until;
        int old_score = it->second.score;
        decay_peer_state_locked(label, now);
        banned = it->second.banned_until > now;
        changed = it->second.banned_until != old_banned_until || it->second.score != old_score;
    }
    if (changed) save_peer_state();
    return banned;
}

void NetworkNode::punish(const std::shared_ptr<PeerSession>& peer, int score, const std::string& reason) {
    auto label = peer ? peer->remote_label() : std::string("unknown");
    punish_label(label, score, reason);
    if (peer && is_banned(label)) peer->close();
}

void NetworkNode::discover_public_endpoint() {
    if (advertised_self_ || !discovery_enabled_) return;
    try {
        auto ip = detect_public_ip(ctx_, ip_detect_host_, ip_detect_port_, ip_detect_path_);
        advertised_self_ = PeerAddress{ip, listen_port_ ? listen_port_ : default_p2p_port(), 0x01};
        log_info("net", "detected public endpoint=" +
                            endpoint_label(advertised_self_->ip, advertised_self_->port));
    } catch (const std::exception& ex) {
        log_warn("net", std::string("public ip detection failed: ") + ex.what());
    }
}

void NetworkNode::resolve_seed_endpoints() {
    if (!network_active()) return;
    for (const auto& seed : dns_seeds_) {
        auto parsed = parse_host_port(seed, listen_port_ ? listen_port_ : default_p2p_port());
        if (!parsed) {
            log_warn("net", "invalid seed entry=" + seed);
            continue;
        }
        if (proxy_ && proxy_->remote_dns && !is_ipv4_literal(parsed->first)) {
            record_peer_label(parsed->first + ":" + std::to_string(parsed->second), "seed");
            log_info("net", "queued seed for proxy DNS seed=" + seed);
            continue;
        }
        try {
            boost::asio::ip::tcp::resolver resolver(ctx_);
            auto endpoints = resolver.resolve(parsed->first, std::to_string(parsed->second));
            size_t resolved = 0;
            for (const auto& endpoint : endpoints) {
                if (!endpoint.endpoint().address().is_v4()) continue;
                record_peer_label(endpoint.endpoint().address().to_string() + ":" + std::to_string(parsed->second), "seed");
                ++resolved;
            }
            log_info("net", "resolved seed=" + seed + " peers=" + std::to_string(resolved));
        } catch (const std::exception& ex) {
            log_warn("net", "seed resolution failed seed=" + seed + " reason=" + ex.what());
        }
    }
}

void NetworkNode::connect_known_peers(size_t max_connections) {
    if (!network_active()) return;
    struct Candidate {
        std::string label;
        std::string host;
        uint16_t port{0};
        std::string netgroup;
        std::string source;
        int score{0};
        uint64_t successes{0};
        uint64_t failures{0};
        int64_t last_seen{0};
    };

    std::vector<std::string> labels;
    {
        std::lock_guard<std::mutex> guard(peers_mutex_);
        labels.assign(known_peers_.begin(), known_peers_.end());
    }
    std::unordered_map<std::string, size_t> connected_netgroups;
    {
        std::lock_guard<std::mutex> guard(sessions_mutex_);
        for (const auto& session : sessions_) {
            if (!session) continue;
            connected_netgroups[peer_netgroup(session->remote_label())] += 1;
        }
    }
    std::unordered_set<std::string> active_labels;
    {
        std::lock_guard<std::mutex> sessions_guard(sessions_mutex_);
        for (const auto& session : sessions_) {
            if (session) active_labels.insert(session->remote_label());
        }
    }
    {
        std::lock_guard<std::mutex> pending_guard(pending_connect_mutex_);
        active_labels.insert(pending_connects_.begin(), pending_connects_.end());
    }

    std::vector<Candidate> candidates;
    candidates.reserve(labels.size());
    bool peer_state_changed = false;
    {
        std::lock_guard<std::mutex> guard(peer_state_mutex_);
        for (const auto& label : labels) {
            if (label.empty() || is_self_label(label)) continue;
            auto parsed = parse_host_port(label, listen_port_ ? listen_port_ : default_p2p_port());
            if (!parsed) continue;
            if (active_labels.count(label) > 0) continue;

            auto& state = peer_states_[label];
            const auto now = static_cast<int64_t>(std::time(nullptr));
            if (state.last_updated == 0) state.last_updated = now;
            if (state.netgroup.empty()) state.netgroup = peer_netgroup(label);
            const auto old_banned_until = state.banned_until;
            const auto old_score = state.score;
            decay_peer_state_locked(label, now);
            if (state.banned_until != old_banned_until || state.score != old_score) {
                peer_state_changed = true;
            }
            if (state.banned_until > now) continue;

            candidates.push_back(Candidate{
                label,
                parsed->first,
                parsed->second,
                state.netgroup.empty() ? peer_netgroup(label) : state.netgroup,
                state.source,
                state.score,
                state.successful_connections,
                state.failed_connections,
                state.last_seen
            });
        }
    }
    if (peer_state_changed) save_peer_state();
    auto source_rank = [](const std::string& source) {
        if (source == "manual") return 0;
        if (source == "lan") return 1;
        if (source == "seed") return 2;
        if (source == "handshake") return 3;
        if (source == "proxy") return 4;
        return 5;
    };
    std::sort(candidates.begin(), candidates.end(), [&](const Candidate& a, const Candidate& b) {
        if (source_rank(a.source) != source_rank(b.source)) return source_rank(a.source) < source_rank(b.source);
        if (a.score != b.score) return a.score < b.score;
        if (a.failures != b.failures) return a.failures < b.failures;
        if (a.successes != b.successes) return a.successes > b.successes;
        if (a.last_seen != b.last_seen) return a.last_seen > b.last_seen;
        return a.label < b.label;
    });

    size_t connected = 0;
    std::unordered_map<std::string, size_t> chosen_netgroups = connected_netgroups;
    for (const auto& candidate : candidates) {
        if (connected >= max_connections) break;
        if (chosen_netgroups[candidate.netgroup] > 0) continue;
        connect(candidate.host, candidate.port);
        chosen_netgroups[candidate.netgroup] += 1;
        ++connected;
    }
    for (const auto& candidate : candidates) {
        if (connected >= max_connections) break;
        if (chosen_netgroups[candidate.netgroup] >= constants::MAX_OUTBOUND_PEERS_PER_NETGROUP) continue;
        connect(candidate.host, candidate.port);
        chosen_netgroups[candidate.netgroup] += 1;
        ++connected;
    }
}

void NetworkNode::set_network_active(bool active) {
    const bool was_active = network_active_.exchange(active, std::memory_order_relaxed);
    if (was_active == active) return;

    if (!active) {
        std::vector<std::shared_ptr<PeerSession>> sessions_to_close;
        {
            std::lock_guard<std::mutex> guard(sessions_mutex_);
            sessions_to_close.swap(sessions_);
        }
        for (auto& session : sessions_to_close) {
            if (session) {
                session->close();
            }
        }
        {
            std::lock_guard<std::mutex> guard(sync_mutex_);
            peer_heights_.clear();
            block_download_queue_.clear();
            queued_blocks_.clear();
            inflight_blocks_.clear();
        }
        {
            std::lock_guard<std::mutex> guard(pending_connect_mutex_);
            pending_connects_.clear();
        }
        lan_discovery_timer_.cancel();
        if (lan_discovery_socket_.is_open()) {
            boost::system::error_code ec;
            lan_discovery_socket_.close(ec);
        }
        clear_port_mapping();
        log_info("net", "network activity disabled");
    } else {
        log_info("net", "network activity enabled");
        discover_public_endpoint();
        refresh_port_mapping();
        start_lan_discovery();
        resolve_seed_endpoints();
        save_peers();
        connect_known_peers(std::min<size_t>(4, constants::MAX_PEER_CONNECTIONS));
    }
    update_chain_approval_state();
}

void NetworkNode::note_peer_connection_attempt(const std::string& label, bool success, const std::string& reason) {
    if (label.empty()) return;
    std::lock_guard<std::mutex> guard(peer_state_mutex_);
    auto& state = peer_states_[label];
    const auto now = static_cast<int64_t>(std::time(nullptr));
    if (state.netgroup.empty()) state.netgroup = peer_netgroup(label);
    state.last_updated = now;
    state.last_seen = now;
    if (success) {
        if (state.source.empty()) state.source = "manual";
    } else {
        state.failed_connections += 1;
        state.last_reason = reason;
        state.score = std::min(ban_threshold_, state.score + 2);
    }
}

void NetworkNode::note_peer_connected(const std::string& label) {
    if (label.empty()) return;
    std::lock_guard<std::mutex> guard(peer_state_mutex_);
    auto& state = peer_states_[label];
    const auto now = static_cast<int64_t>(std::time(nullptr));
    if (state.netgroup.empty()) state.netgroup = peer_netgroup(label);
    state.last_seen = now;
    state.last_connected = now;
    state.last_updated = now;
    state.successful_connections += 1;
}

std::string NetworkNode::peer_netgroup(const std::string& label) const {
    auto parsed = parse_host_port(label, listen_port_ ? listen_port_ : default_p2p_port());
    if (!parsed) return "unknown";
    return netgroup_from_host(parsed->first);
}

void NetworkNode::refresh_port_mapping() {
    PortMappingStatus next;
    {
        std::lock_guard<std::mutex> guard(port_mapping_mutex_);
        next = port_mapping_status_;
        next.enabled = upnp_enabled_ || natpmp_enabled_;
        next.lease_seconds = nat_mapping_lease_seconds_;
    }
    if (!next.enabled || listen_port_ == 0) {
        next.message = "automatic port mapping disabled";
        std::lock_guard<std::mutex> guard(port_mapping_mutex_);
        port_mapping_status_ = next;
        return;
    }

    const std::string port = std::to_string(listen_port_);
    auto update_success = [&](const std::string& protocol, const CommandResult& result) {
        next.active = true;
        next.available = true;
        next.protocol = protocol;
        next.refreshed_at = static_cast<int64_t>(std::time(nullptr));
        try {
            auto ip = extract_first_ipv4_literal(result.output);
            next.external_endpoint = ip + ":" + port;
        } catch (...) {
            if (advertised_self_) {
                next.external_endpoint = endpoint_label(advertised_self_->ip, listen_port_);
            }
        }
        next.message = protocol + " port mapping active";
    };

    if (upnp_enabled_ && command_available("upnpc")) {
        auto result = run_command_capture("upnpc -e CryptEX -r " + port + " tcp 2>&1");
        if (result.exit_code == 0) {
            update_success("UPnP", result);
            std::lock_guard<std::mutex> guard(port_mapping_mutex_);
            port_mapping_status_ = next;
            return;
        }
        next.available = true;
        next.message = "UPnP helper failed: " + result.output;
    }

    if (natpmp_enabled_ && command_available("natpmpc")) {
        auto result = run_command_capture("natpmpc -a " + port + " " + port + " tcp " +
                                          std::to_string(std::max(nat_mapping_lease_seconds_, 60)) + " 2>&1");
        if (result.exit_code == 0) {
            update_success("NAT-PMP", result);
            std::lock_guard<std::mutex> guard(port_mapping_mutex_);
            port_mapping_status_ = next;
            return;
        }
        next.available = true;
        next.message = "NAT-PMP helper failed: " + result.output;
    }

    if (!upnp_enabled_ && !natpmp_enabled_) {
        next.message = "automatic port mapping disabled";
    } else if (!command_available("upnpc") && !command_available("natpmpc")) {
        next.message = "no port-mapping helper found (install upnpc or natpmpc)";
    }

    std::lock_guard<std::mutex> guard(port_mapping_mutex_);
    port_mapping_status_ = next;
}

void NetworkNode::clear_port_mapping() {
    if (listen_port_ == 0) return;
    if (upnp_enabled_ && command_available("upnpc")) {
        (void) run_command_capture("upnpc -d " + std::to_string(listen_port_) + " tcp 2>&1");
    }
    std::lock_guard<std::mutex> guard(port_mapping_mutex_);
    port_mapping_status_.active = false;
}

std::optional<std::string> NetworkNode::canonical_peer_label_from_version(
    const boost::asio::ip::tcp::endpoint& remote,
    const VersionPayload& version) const {
    uint16_t port = version.listen_port ? version.listen_port : default_p2p_port();
    if (version.advertised_ip) {
        return endpoint_label(*version.advertised_ip, port);
    }
    if (remote.address().is_v4() && (port == default_p2p_port() || remote.port() == port)) {
        return remote.address().to_string() + ":" + std::to_string(port);
    }
    return std::nullopt;
}

bool NetworkNode::is_self_label(const std::string& label) const {
    if (label.empty()) return false;
    if (advertised_self_ && label == endpoint_label(advertised_self_->ip, advertised_self_->port)) {
        return true;
    }
    std::string local_default = "127.0.0.1:" + std::to_string(listen_port_ ? listen_port_ : default_p2p_port());
    return label == local_default;
}

// ---------------- IP detection ----------------
ip_address detect_public_ip(boost::asio::io_context& ctx) {
    return detect_public_ip(ctx, constants::IP_DETECT_HOST, constants::IP_DETECT_PORT, constants::IP_DETECT_PATH);
}

ip_address detect_public_ip(boost::asio::io_context& ctx,
                            const std::string& host,
                            const std::string& port,
                            const std::string& path) {
    (void)ctx;
    const std::string effective_port = (port == "80") ? "443" : port;
    const bool using_default_service =
        host == constants::IP_DETECT_HOST &&
        (port == constants::IP_DETECT_PORT || effective_port == constants::IP_DETECT_PORT) &&
        path == constants::IP_DETECT_PATH;

    std::vector<IpDetectService> services;
    services.push_back({host, effective_port, path});
    if (using_default_service) {
        services.push_back({"api.ipify.org", "443", "/"});
        services.push_back({"ipv4.icanhazip.com", "443", "/"});
    }

    std::unordered_map<std::string, size_t> counts;
    std::optional<std::string> last_success;
    for (const auto& service : services) {
        try {
            auto ip = https_detect_ip(service);
            last_success = ip;
            const auto next = ++counts[ip];
            if (next >= 2 || services.size() == 1) {
                return ip_address::from_string(ip);
            }
        } catch (const std::exception& ex) {
            log_warn("network", std::string("public IP detect failed for ") + service.host + ": " + ex.what());
        }
    }

    if (last_success) {
        return ip_address::from_string(*last_success);
    }
    throw std::runtime_error("secure IP detect failed");
}

} // namespace net
} // namespace cryptex
