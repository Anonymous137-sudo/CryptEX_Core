#pragma once

#include "constants.hpp"
#include "chainparams.hpp"
#include "block.hpp"
#include "chat_history.hpp"
#include "voice_call.hpp"
#include "transaction.hpp"
#include "types.hpp"
#include "serialization.hpp"
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <array>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <string>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <filesystem>

namespace cryptex {
class Blockchain;
class Wallet;
namespace chat {
enum class EncryptionMode : uint8_t;
struct ParsedMessage;
}
namespace net {

enum class MessageType : uint8_t {
    VERSION = 1,
    VERACK = 2,
    PING = 3,
    PONG = 4,
    GETHEADERS = 5,
    HEADERS = 6,
    GETBLOCK = 7,
    BLOCK = 8,
    GETPEERS = 9,
    PEERS = 10,
    CHAT = 11,
    GETWORK = 12,
    SUBMITWORK = 13,
    INV = 14,
    GETTX = 15,
    TX = 16,
    DHT_MAIL_STORE = 17,
    DHT_MAIL_FIND = 18,
    DHT_MAIL_RESULTS = 19,
    DHT_MAIL_RECEIPT = 20,
    DHT_MAIL_CHALLENGE = 21,
    DHT_MAIL_PROOF = 22,
    DHT_MAIL_NAT_INTRO = 23
};

struct Message {
    MessageType type;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> serialize() const;
    static Message deserialize(const std::vector<uint8_t>& data);
};

// Serialized peer address: 4 bytes IP, 2 bytes port, 1 byte flags
struct PeerAddress {
    ip_address ip;
    port_t port;
    uint8_t flags{0};

    std::array<uint8_t,7> to_bytes() const;
    static PeerAddress from_bytes(const uint8_t* data, size_t len);
};

struct ChatPayload {
    uint8_t version{4};
    uint8_t chat_type{0}; // 0 public, 1 private
    uint8_t flags{0}; // bit0 signed, bit1 encrypted
    uint8_t kdf_profile{0}; // version >= 3 private chat key derivation
    uint8_t cipher_profile{0}; // version >= 4 private chat transport
    uint64_t timestamp{0};
    uint64_t nonce{0};
    std::string sender;
    std::vector<uint8_t> sender_pubkey;
    std::string channel;
    std::string recipient; // for private
    std::vector<uint8_t> recipient_pubkey;
    std::vector<uint8_t> wrapped_key;
    std::vector<uint8_t> body; // plaintext for public chat, ciphertext for private chat
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;
    std::vector<uint8_t> signature;

    std::vector<uint8_t> serialize() const;
    static ChatPayload deserialize(const std::vector<uint8_t>& data);
};

struct WorkRequest {
    uint32_t height;
    uint32_t nonce_start;
    uint32_t nonce_end;
    BlockHeader header;

    std::vector<uint8_t> serialize() const;
    static WorkRequest deserialize(const std::vector<uint8_t>& data);
};

struct VersionPayload {
    uint32_t protocol_version{constants::PROTOCOL_VERSION};
    uint32_t best_height{0};
    uint16_t listen_port{default_p2p_port()};
    uint8_t flags{0};
    std::optional<ip_address> advertised_ip;

    std::vector<uint8_t> serialize() const;
    static VersionPayload deserialize(const std::vector<uint8_t>& data);
};

class NetworkNode;

class PeerSession : public std::enable_shared_from_this<PeerSession> {
public:
    PeerSession(boost::asio::ip::tcp::socket socket,
                NetworkNode& owner,
                std::optional<std::string> remote_label_override = std::nullopt,
                std::optional<boost::asio::ip::tcp::endpoint> endpoint_override = std::nullopt);
    void start();
    void send(const Message& msg);
    std::string remote_label() const;
    boost::asio::ip::tcp::endpoint endpoint() const;
    void close();
    void mark_version_seen() { version_seen_.store(true, std::memory_order_relaxed); }
    bool version_seen() const { return version_seen_.load(std::memory_order_relaxed); }
    void adopt_remote_label(std::string label) { remote_label_override_ = std::move(label); }
private:
    void read_header();
    void read_body();
    void handle_message(const Message& msg);
    void write_next();

    boost::asio::ip::tcp::socket socket_;
    NetworkNode& owner_;
    std::optional<std::string> remote_label_override_;
    std::optional<boost::asio::ip::tcp::endpoint> endpoint_override_;
    uint32_t incoming_magic_{0};
    uint8_t incoming_type_{0};
    uint32_t incoming_length_{0};
    std::array<uint8_t, 9> header_buf_{};
    std::vector<uint8_t> body_;
    std::deque<std::vector<uint8_t>> outbox_;
    std::mutex write_mutex_;
    std::atomic<bool> version_seen_{false};
};

class NetworkNode {
public:
    using MessageHandler = std::function<void(const Message&, std::shared_ptr<PeerSession>)>;

    struct PeerInfo {
        std::string label;
        int score{0};
        bool banned{false};
        int64_t banned_until{0};
        bool connected{false};
        uint32_t announced_height{0};
        int64_t last_seen{0};
        int64_t last_connected{0};
        uint64_t successful_connections{0};
        uint64_t failed_connections{0};
        uint64_t invalid_messages{0};
        std::string source;
        std::string netgroup;
        std::string last_reason;
    };

    struct PortMappingStatus {
        bool enabled{false};
        bool active{false};
        bool available{false};
        std::string protocol;
        std::string external_endpoint;
        std::string message;
        int lease_seconds{0};
        int64_t refreshed_at{0};
    };

    struct SyncStatus {
        uint32_t local_height{0};
        uint32_t best_peer_height{0};
        size_t queued_blocks{0};
        size_t inflight_blocks{0};
        size_t connected_peers{0};
        size_t validated_peers{0};
        bool syncing{false};
    };

    struct ProxySettings {
        std::string host;
        uint16_t port{0};
        bool remote_dns{true};
    };

    struct DistributedMailRecord {
        uint32_t version{1};
        uint64_t stored_at{0};
        uint64_t expires_at{0};
        std::string message_id;
        std::string sender_address;
        std::string recipient_address;
        std::string peer_label;
        std::string payload_b64;
    };

    struct MailReplicationPolicy {
        uint32_t ttl_hours{168};
        uint32_t replica_target{3};
        uint32_t max_store_items{5000};
        bool prune_imported{false};
        bool prune_expired{true};
        bool proof_of_storage{true};
        uint32_t challenge_interval_minutes{30};
        uint64_t minimum_bond_sats{0};
        uint32_t required_verified_replicas{1};
        bool slash_on_failed_proof{true};
        uint32_t slash_penalty_score{25};
        bool nat_assist{true};
        bool relay_fallback{true};
        std::vector<std::string> relay_peers{};
        std::vector<std::string> stun_servers{};
        uint32_t stun_timeout_ms{1200};
    };

    struct MailStorageReceipt {
        uint32_t version{1};
        std::string message_id;
        std::string recipient_address;
        std::string replica_label;
        std::string storage_hash_hex;
        std::string last_proof_hash_hex;
        uint64_t stored_at{0};
        uint64_t expires_at{0};
        uint64_t receipt_at{0};
        uint64_t verified_at{0};
        uint64_t last_challenged_at{0};
        std::string provider_address;
        std::string provider_pubkey_b64;
        std::string provider_signature_b64;
        uint64_t bonded_balance_sats{0};
        bool bond_satisfied{false};
        bool verified{false};
        bool slashed{false};
        uint64_t slashed_at{0};
        std::string slash_reason;
        std::string slash_evidence_hash_hex;
    };

    struct NatCandidate {
        uint8_t type{0}; // 0 host, 1 reflexive, 2 mapped
        std::string label;
        uint32_t priority{0};
    };

    struct NatTraversalStatus {
        bool enabled{true};
        bool relay_fallback{true};
        bool port_mapping_active{false};
        std::string advertised_endpoint;
        std::string reflexive_endpoint;
        size_t candidate_count{0};
        size_t stun_server_count{0};
        size_t relay_peer_count{0};
        uint64_t last_intro_at{0};
        uint64_t last_reverse_intro_at{0};
        uint64_t last_candidate_attempt_at{0};
        uint64_t last_stun_probe_at{0};
        size_t relay_attempts{0};
        size_t relay_successes{0};
    };

    struct DhtMailboxStatus {
        bool enabled{true};
        size_t local_store_records{0};
        size_t pending_queries{0};
        size_t seen_queries{0};
        size_t active_peers{0};
        uint64_t last_lookup_at{0};
        uint64_t last_results_at{0};
        uint64_t last_proof_at{0};
        uint32_t replica_target{3};
        size_t receipt_count{0};
        size_t verified_receipts{0};
        size_t bond_satisfied_receipts{0};
        size_t trusted_verified_receipts{0};
        size_t slashed_receipts{0};
        size_t pending_proofs{0};
        bool proof_of_storage{true};
        uint64_t minimum_bond_sats{0};
        uint32_t required_verified_replicas{1};
        bool slash_on_failed_proof{true};
        uint32_t slash_penalty_score{25};
        bool nat_assist{true};
        bool relay_fallback{true};
        bool port_mapping_active{false};
        std::string advertised_endpoint;
        std::string reflexive_endpoint;
        size_t candidate_count{0};
        size_t stun_server_count{0};
        size_t relay_peer_count{0};
        uint64_t last_nat_intro_at{0};
        uint64_t last_reverse_intro_at{0};
        uint64_t last_candidate_attempt_at{0};
        uint64_t last_stun_probe_at{0};
        size_t relay_attempts{0};
        size_t relay_successes{0};
    };

    struct VoiceCallInfo {
        bool active{false};
        bool incoming{false};
        bool outgoing{false};
        bool ringing{false};
        bool connected{false};
        bool session_ready{false};
        bool obfuscate_audio{false};
        uint64_t started_at{0};
        uint64_t connected_at{0};
        uint64_t last_signal_at{0};
        uint64_t last_audio_at{0};
        uint64_t next_outgoing_sequence{1};
        uint64_t latency_ms{0};
        uint64_t jitter_ms{0};
        uint32_t sample_rate{16000};
        uint16_t channels{1};
        uint16_t bits_per_sample{16};
        uint16_t frame_duration_ms{20};
        uint32_t capability_flags{voice::CAPABILITY_AES_GCM | voice::CAPABILITY_OPUS | voice::CAPABILITY_AUDIO_CLOAK | voice::CAPABILITY_LIVE_WAVEFORM};
        std::string status;
        std::string call_id;
        std::string local_address;
        std::string remote_address;
        std::string caller_address;
        std::string callee_address;
        std::string remote_pubkey_b64;
        std::string remote_rsa_public_pem;
        std::string peer_label;
        std::string encryption_mode;
        std::string codec{"opus"};
        std::vector<uint8_t> session_key;
    };

    NetworkNode(boost::asio::io_context& ctx, uint16_t port, std::filesystem::path data_dir = ".");
    void start();
    void stop();
    void connect(const std::string& host, uint16_t port);
    void broadcast(const Message& msg);
    bool send_to(const std::string& label, const Message& msg);
    size_t broadcast_chat(const Message& msg, const std::shared_ptr<PeerSession>& exclude = nullptr);
    void set_handler(MessageType type, MessageHandler handler);
    void attach_blockchain(Blockchain* chain);
    std::vector<PeerAddress> peers() const;
    std::vector<std::string> active_peer_labels() const;
    std::vector<PeerInfo> peer_statuses();
    SyncStatus sync_status() const;
    std::vector<chat::HistoryEntry> chat_history(const chat::HistoryQuery& query = {}) const;
    std::vector<chat::HistoryEntry> mail_history(const chat::HistoryQuery& query = {}) const;
    std::vector<DistributedMailRecord> distributed_mail_records(const std::optional<std::string>& recipient_address = std::nullopt,
                                                                size_t limit = 200) const;
    std::filesystem::path chat_history_path() const;
    std::filesystem::path mail_history_path() const;
    std::filesystem::path distributed_mail_path() const;
    void record_chat_history(const chat::HistoryEntry& entry);
    void record_mail_history(const chat::HistoryEntry& entry);
    void record_distributed_mail(const ChatPayload& payload, const std::string& peer_label = {});
    void store_distributed_mail_record(const DistributedMailRecord& record);
    bool delete_chat_message(const std::string& message_id);
    bool delete_mail_message(const std::string& message_id);
    bool delete_distributed_mail(const std::string& message_id);
    size_t distributed_mail_count() const;
    void set_mail_replication_policy(const MailReplicationPolicy& policy);
    MailReplicationPolicy mail_replication_policy() const;
    size_t prune_distributed_mail_store();
    std::vector<MailStorageReceipt> mail_storage_receipts(const std::optional<std::string>& message_id = std::nullopt) const;
    size_t verified_mail_storage_receipt_count() const;
    size_t dht_store_mail(const DistributedMailRecord& record);
    std::vector<DistributedMailRecord> dht_lookup_mail(const std::string& recipient_address,
                                                       size_t limit = 128,
                                                       uint32_t timeout_ms = 800);
    DhtMailboxStatus dht_mailbox_status() const;
    NatTraversalStatus nat_traversal_status() const;
    void punish_label(const std::string& label, int score, const std::string& reason);
    void set_ban(const std::string& label, int duration_seconds = constants::BANNED_PEER_DURATION_SECONDS);
    void clear_bans();
    void set_network_active(bool active);
    bool network_active() const { return network_active_.load(std::memory_order_relaxed); }
    void set_dns_seeds(std::vector<std::string> seeds);
    void set_external_address(const std::string& address);
    void set_ip_detection_service(std::string host, std::string port, std::string path);
    void set_socks5_proxy(const std::string& host, uint16_t port, bool remote_dns = true);
    void enable_port_mapping(bool upnp_enabled, bool natpmp_enabled, int lease_seconds = constants::DEFAULT_NAT_MAPPING_LEASE_SECONDS);
    void set_chat_wallet(std::shared_ptr<const Wallet> wallet);
    void remember_chat_message(const std::string& message_id);
    VoiceCallInfo voice_call_state() const;
    bool start_voice_call(const std::string& recipient_address,
                          const std::vector<uint8_t>& recipient_pubkey,
                          const std::string& recipient_rsa_public_pem,
                          const std::string& peer_label,
                          const std::string& from_address,
                          bool obfuscate_audio,
                          chat::EncryptionMode encryption_mode);
    bool accept_voice_call();
    bool decline_voice_call(const std::string& note = {});
    bool end_voice_call(const std::string& note = {});
    size_t send_voice_audio(const std::vector<uint8_t>& pcm_bytes,
                            uint32_t sample_rate,
                            uint16_t channels,
                            uint16_t bits_per_sample,
                            bool obfuscated);
    std::vector<voice::AudioFrame> take_voice_audio_frames(size_t max_frames = 16);
    void enable_discovery(bool enabled) { discovery_enabled_ = enabled; }
    void bootstrap(bool auto_connect = true);
    void bootstrap_chat_routing();
    std::optional<std::string> advertised_endpoint() const;
    PortMappingStatus port_mapping_status() const;
    std::optional<ProxySettings> proxy_settings() const;
    ip_address public_ip();
    uint32_t best_height{0};
    Block latest_block;
private:
    friend class PeerSession;
    void do_accept();
    void register_default_handlers();
    void record_peer(const boost::asio::ip::tcp::endpoint& ep);
    void load_peers();
    void save_peers();
    void load_peer_state();
    void save_peer_state() const;
    void record_peer_label(const std::string& label, const std::string& source = "peer");
    bool is_banned(const std::string& label);
    void punish(const std::shared_ptr<PeerSession>& peer, int score, const std::string& reason);
    void decay_peer_state_locked(const std::string& label, int64_t now) const;
    Message build_getheaders_request() const;
    Message build_version_message() const;
    void request_headers_from(const std::shared_ptr<PeerSession>& peer);
    void enqueue_block_download(const uint256_t& hash, const std::shared_ptr<PeerSession>& peer);
    void pump_block_downloads();
    void finish_block_download(const uint256_t& hash);
    void maybe_continue_sync(const std::shared_ptr<PeerSession>& peer);
    void update_chain_approval_state();
    void remove_session(const std::shared_ptr<PeerSession>& peer);
    void schedule_peer_maintenance();
    void start_lan_discovery();
    void schedule_lan_discovery_announce();
    void announce_lan_presence();
    void read_lan_discovery();
    uint16_t lan_discovery_port() const;
    void discover_public_endpoint();
    void resolve_seed_endpoints();
    void connect_known_peers(size_t max_connections);
    void note_peer_connection_attempt(const std::string& label, bool success, const std::string& reason = {});
    void note_peer_connected(const std::string& label);
    std::string peer_netgroup(const std::string& label) const;
    void refresh_port_mapping();
    void clear_port_mapping();
    bool mark_chat_seen(const std::string& message_id, int64_t now);
    size_t dispatch_chat_payload(const ChatPayload& payload, const std::string& preferred_peer = {});
    void handle_voice_signal(const voice::CallSignal& signal,
                             const chat::ParsedMessage& parsed,
                             const ChatPayload& payload,
                             const std::shared_ptr<PeerSession>& peer);
    void handle_voice_frame(const voice::AudioFrame& frame,
                            const chat::ParsedMessage& parsed,
                            const ChatPayload& payload,
                            const std::shared_ptr<PeerSession>& peer);
    void clear_voice_call_locked(const std::string& status = {});
    void append_chat_inbox(const std::string& line);
    bool begin_pending_connect(const std::string& label);
    void end_pending_connect(const std::string& label);
    std::optional<std::string> canonical_peer_label_from_version(const boost::asio::ip::tcp::endpoint& remote,
                                                                 const VersionPayload& version) const;
    bool is_self_label(const std::string& label) const;

    struct PeerState {
        int score{0};
        int64_t banned_until{0};
        int64_t last_updated{0};
        int64_t last_seen{0};
        int64_t last_connected{0};
        uint64_t successful_connections{0};
        uint64_t failed_connections{0};
        uint64_t invalid_messages{0};
        uint32_t last_announced_height{0};
        std::string source{"peer"};
        std::string netgroup;
        std::string last_reason;
    };

    struct PendingBlockDownload {
        uint256_t hash;
        std::weak_ptr<PeerSession> peer;
    };

    boost::asio::io_context& ctx_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::vector<std::shared_ptr<PeerSession>> sessions_;
    std::unordered_map<MessageType, MessageHandler> handlers_;
    mutable std::mutex sessions_mutex_;
    Blockchain* chain_{nullptr};
    mutable std::mutex peers_mutex_;
    std::unordered_set<std::string> known_peers_;
    std::filesystem::path peers_file_;
    std::filesystem::path peer_state_file_;
    mutable std::mutex peer_state_mutex_;
    mutable std::unordered_map<std::string, PeerState> peer_states_;
    mutable std::mutex sync_mutex_;
    std::deque<PendingBlockDownload> block_download_queue_;
    std::unordered_set<uint256_t> queued_blocks_;
    std::unordered_set<uint256_t> inflight_blocks_;
    std::unordered_map<std::string, uint32_t> peer_heights_;
    int ban_threshold_ = 100;
    uint16_t listen_port_{0};
    bool discovery_enabled_{true};
    std::vector<std::string> dns_seeds_;
    std::string ip_detect_host_{constants::IP_DETECT_HOST};
    std::string ip_detect_port_{constants::IP_DETECT_PORT};
    std::string ip_detect_path_{constants::IP_DETECT_PATH};
    std::optional<PeerAddress> advertised_self_;
    std::optional<ProxySettings> proxy_;
    boost::asio::steady_timer peer_maintenance_timer_;
    boost::asio::ip::udp::socket lan_discovery_socket_;
    boost::asio::ip::udp::endpoint lan_discovery_remote_;
    std::array<char, 512> lan_discovery_buffer_{};
    boost::asio::steady_timer lan_discovery_timer_;
    std::string lan_discovery_node_id_;
    mutable std::mutex port_mapping_mutex_;
    PortMappingStatus port_mapping_status_;
    bool upnp_enabled_{false};
    bool natpmp_enabled_{false};
    int nat_mapping_lease_seconds_{constants::DEFAULT_NAT_MAPPING_LEASE_SECONDS};
    std::shared_ptr<const Wallet> chat_wallet_;
    std::filesystem::path chat_inbox_file_;
    std::filesystem::path chat_history_file_;
    std::filesystem::path mail_history_file_;
    std::filesystem::path distributed_mail_file_;
    std::filesystem::path mail_receipts_file_;
    mutable std::mutex chat_mutex_;
    mutable std::mutex mail_mutex_;
    mutable std::mutex distributed_mail_mutex_;
    mutable std::mutex mail_receipts_mutex_;
    MailReplicationPolicy mail_policy_;
    mutable std::mutex dht_mutex_;
    std::condition_variable dht_results_cv_;
    std::unordered_set<std::string> dht_seen_queries_;
    std::unordered_map<std::string, std::vector<DistributedMailRecord>> dht_pending_results_;
    struct PendingMailProofChallenge {
        std::string challenge_id;
        std::string message_id;
        std::string recipient_address;
        std::string replica_label;
        std::string nonce_b64;
        uint64_t created_at{0};
    };
    std::unordered_map<std::string, PendingMailProofChallenge> pending_mail_challenges_;
    uint64_t dht_last_lookup_at_{0};
    uint64_t dht_last_results_at_{0};
    uint64_t dht_last_proof_at_{0};
    uint64_t dht_last_nat_intro_at_{0};
    uint64_t dht_last_reverse_intro_at_{0};
    uint64_t dht_last_candidate_attempt_at_{0};
    size_t dht_relay_attempts_{0};
    size_t dht_relay_successes_{0};
    mutable std::mutex stun_probe_mutex_;
    mutable std::vector<std::string> stun_reflexive_candidates_;
    mutable std::string last_stun_server_;
    mutable uint64_t dht_last_stun_probe_at_{0};
    std::unordered_map<std::string, int64_t> recent_chat_ids_;
    mutable std::mutex voice_call_mutex_;
    VoiceCallInfo voice_call_;
    std::deque<voice::AudioFrame> voice_audio_inbox_;
    mutable std::mutex pending_connect_mutex_;
    std::unordered_set<std::string> pending_connects_;
    std::atomic<bool> network_active_{true};

    bool send_to_or_relay_mail_peer(const std::string& label, const Message& msg, const std::string& purpose);
    std::vector<NatCandidate> build_nat_candidates(const std::optional<std::string>& target_label = std::nullopt) const;
    bool attempt_nat_candidates(const std::vector<NatCandidate>& candidates);
    void upsert_mail_storage_receipt(const MailStorageReceipt& receipt);
    void maybe_issue_mail_storage_challenge(const MailStorageReceipt& receipt);
    void maintain_mail_storage_proofs();
    void slash_mail_receipt(const MailStorageReceipt& receipt,
                            const std::string& reason,
                            const std::string& evidence_material = {},
                            const std::string& peer_label = {});
};

ip_address detect_public_ip(boost::asio::io_context& ctx);
ip_address detect_public_ip(boost::asio::io_context& ctx,
                            const std::string& host,
                            const std::string& port,
                            const std::string& path);

} // namespace net
} // namespace cryptex
