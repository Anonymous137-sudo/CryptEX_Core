#pragma once

#include "constants.hpp"
#include "chainparams.hpp"
#include "block.hpp"
#include "chat_history.hpp"
#include "transaction.hpp"
#include "types.hpp"
#include "serialization.hpp"
#include <boost/asio.hpp>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
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
    };

    struct SyncStatus {
        uint32_t local_height{0};
        uint32_t best_peer_height{0};
        size_t queued_blocks{0};
        size_t inflight_blocks{0};
        size_t connected_peers{0};
        bool syncing{false};
    };

    NetworkNode(boost::asio::io_context& ctx, uint16_t port, std::filesystem::path data_dir = ".");
    void start();
    void stop();
    void connect(const std::string& host, uint16_t port);
    void broadcast(const Message& msg);
    bool send_to(const std::string& label, const Message& msg);
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
    void set_dns_seeds(std::vector<std::string> seeds);
    void set_external_address(const std::string& address);
    void set_ip_detection_service(std::string host, std::string port, std::string path);
    void set_socks5_proxy(const std::string& host, uint16_t port, bool remote_dns = true);
    void set_chat_wallet(std::shared_ptr<const Wallet> wallet);
    void enable_discovery(bool enabled) { discovery_enabled_ = enabled; }
    void bootstrap(bool auto_connect = true);
    std::optional<std::string> advertised_endpoint() const;
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
    void record_peer_label(const std::string& label);
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
    void discover_public_endpoint();
    void resolve_seed_endpoints();
    void connect_known_peers(size_t max_connections);
    bool mark_chat_seen(const std::string& message_id, int64_t now);
    void append_chat_inbox(const std::string& line);
    std::optional<std::string> canonical_peer_label_from_version(const boost::asio::ip::tcp::endpoint& remote,
                                                                 const VersionPayload& version) const;
    bool is_self_label(const std::string& label) const;

    struct PeerState {
        int score{0};
        int64_t banned_until{0};
        int64_t last_updated{0};
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
    std::shared_ptr<const Wallet> chat_wallet_;
    std::filesystem::path chat_inbox_file_;
    std::filesystem::path chat_history_file_;
    mutable std::mutex chat_mutex_;
    std::unordered_map<std::string, int64_t> recent_chat_ids_;
};

ip_address detect_public_ip(boost::asio::io_context& ctx);
ip_address detect_public_ip(boost::asio::io_context& ctx,
                            const std::string& host,
                            const std::string& port,
                            const std::string& path);

} // namespace net
} // namespace cryptex
