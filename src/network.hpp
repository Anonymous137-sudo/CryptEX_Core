#pragma once

#include "constants.hpp"
#include "chainparams.hpp"
#include "block.hpp"
#include "chat_history.hpp"
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
    TX = 16
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
    uint8_t version{2};
    uint8_t chat_type{0}; // 0 public, 1 private
    uint8_t flags{0}; // bit0 signed, bit1 encrypted
    uint64_t timestamp{0};
    uint64_t nonce{0};
    std::string sender;
    std::vector<uint8_t> sender_pubkey;
    std::string channel;
    std::string recipient; // for private
    std::vector<uint8_t> recipient_pubkey;
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
    std::filesystem::path chat_history_path() const;
    void record_chat_history(const chat::HistoryEntry& entry);
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
    void enable_discovery(bool enabled) { discovery_enabled_ = enabled; }
    void bootstrap(bool auto_connect = true);
    void bootstrap_chat_routing();
    std::optional<std::string> advertised_endpoint() const;
    PortMappingStatus port_mapping_status() const;
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

    struct ProxySettings {
        std::string host;
        uint16_t port{0};
        bool remote_dns{true};
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
    mutable std::mutex chat_mutex_;
    std::unordered_map<std::string, int64_t> recent_chat_ids_;
    mutable std::mutex pending_connect_mutex_;
    std::unordered_set<std::string> pending_connects_;
    std::atomic<bool> network_active_{true};
};

ip_address detect_public_ip(boost::asio::io_context& ctx);
ip_address detect_public_ip(boost::asio::io_context& ctx,
                            const std::string& host,
                            const std::string& port,
                            const std::string& path);

} // namespace net
} // namespace cryptex
