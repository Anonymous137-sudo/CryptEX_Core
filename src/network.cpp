#include "network.hpp"
#include "blockchain.hpp"
#include "chat_secure.hpp"
#include "chainparams.hpp"
#include "debug.hpp"
#include "serialization.hpp"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <algorithm>
#include <iostream>
#include <sstream>
#include <cstring>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <boost/asio.hpp>

namespace cryptex {
namespace net {

namespace {

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

bool is_ipv4_literal(const std::string& host) {
    try {
        boost::asio::ip::make_address_v4(host);
        return true;
    } catch (...) {
        return false;
    }
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
    serialization::write_int<uint64_t>(out, timestamp);
    serialization::write_int<uint64_t>(out, nonce);
    serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(sender.data()), sender.size());
    serialization::write_bytes(out, sender_pubkey.data(), sender_pubkey.size());
    serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(channel.data()), channel.size());
    serialization::write_bytes(out, reinterpret_cast<const uint8_t*>(recipient.data()), recipient.size());
    serialization::write_bytes(out, recipient_pubkey.data(), recipient_pubkey.size());
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
            if (ec) return;
            std::memcpy(&incoming_magic_, header_buf_.data(), sizeof(incoming_magic_));
            incoming_magic_ = ntohl(incoming_magic_);
            incoming_type_ = header_buf_[4];
            std::memcpy(&incoming_length_, header_buf_.data() + 5, sizeof(incoming_length_));
            incoming_length_ = ntohl(incoming_length_);
            if (incoming_magic_ != message_magic() || incoming_length_ > 8'000'000) {
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
            if (ec) return;
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
}

// ---------------- NetworkNode ----------------
NetworkNode::NetworkNode(boost::asio::io_context& ctx, uint16_t port, std::filesystem::path data_dir)
    : ctx_(ctx),
      acceptor_(ctx, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      listen_port_(port),
      peers_file_(data_dir / "peers.dat"),
      peer_state_file_(data_dir / "peer_state.dat"),
      chat_inbox_file_(data_dir / "chat_inbox.log"),
      chat_history_file_(data_dir / "chat_history.dat") {
    load_peers();
    load_peer_state();
    register_default_handlers();
}

void NetworkNode::attach_blockchain(Blockchain* chain) {
    chain_ = chain;
    if (chain_) best_height = chain_->best_height();
}

void NetworkNode::start() {
    do_accept();
}

void NetworkNode::stop() {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    for (auto& s : sessions_) {
        std::error_code ec;
        s->send({MessageType::PING, {}}); // try flush
        s.reset();
    }
    sessions_.clear();
    acceptor_.close();
    save_peers();
    save_peer_state();
}

void NetworkNode::connect(const std::string& host, uint16_t port) {
    boost::asio::ip::tcp::socket socket(ctx_);
    std::optional<std::string> remote_label_override;
    std::optional<boost::asio::ip::tcp::endpoint> endpoint_override;

    try {
        if (proxy_) {
            remote_label_override = host + ":" + std::to_string(port);
            auto logical_endpoint = connect_via_socks5(ctx_, socket, proxy_->host, proxy_->port, host, port, proxy_->remote_dns);
            if (logical_endpoint.port() != 0) {
                endpoint_override = logical_endpoint;
            }
        } else {
            boost::asio::ip::tcp::resolver resolver(ctx_);
            auto endpoints = resolver.resolve(host, std::to_string(port));
            boost::asio::connect(socket, endpoints);
            if (!is_ipv4_literal(host)) {
                remote_label_override = host + ":" + std::to_string(port);
            }
        }
    } catch (const std::exception& ex) {
        log_warn("net", "outbound connect failed peer=" + host + ":" + std::to_string(port) +
                        " reason=" + ex.what());
        return;
    }

    auto session = std::make_shared<PeerSession>(std::move(socket), *this, remote_label_override, endpoint_override);
    auto label = session->remote_label();
    if (is_banned(label)) {
        session->close();
        return;
    }
    {
        std::lock_guard<std::mutex> guard(sessions_mutex_);
        sessions_.push_back(session);
    }
    if (endpoint_override) {
        record_peer_label(label);
    } else {
        record_peer(session->endpoint());
    }
    session->start();
    session->send(build_version_message());
}

void NetworkNode::broadcast(const Message& msg) {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    for (auto& s : sessions_) s->send(msg);
}

bool NetworkNode::send_to(const std::string& label, const Message& msg) {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    for (auto& session : sessions_) {
        if (session && session->remote_label() == label) {
            session->send(msg);
            return true;
        }
    }
    return false;
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
                peer_states_[label] = PeerState{0, 0, now};
            }
        }
        std::unordered_set<std::string> known_copy;
        {
            std::lock_guard<std::mutex> peers_guard(peers_mutex_);
            known_copy = known_peers_;
        }
        for (const auto& label : known_copy) {
            if (!peer_states_.count(label)) {
                peer_states_[label] = PeerState{0, 0, now};
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

std::vector<chat::HistoryEntry> NetworkNode::chat_history(const chat::HistoryQuery& query) const {
    std::lock_guard<std::mutex> lock(chat_mutex_);
    return chat::load_history(chat_history_file_, query);
}

std::filesystem::path NetworkNode::chat_history_path() const {
    return chat_history_file_;
}

void NetworkNode::record_chat_history(const chat::HistoryEntry& entry) {
    std::lock_guard<std::mutex> lock(chat_mutex_);
    chat::append_history_entry(chat_history_file_, entry);
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
        decay_peer_state_locked(label, now);
        state.score += score;
        state.last_updated = now;
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
        state.score = std::max(state.score, ban_threshold_);
        state.banned_until = now + std::max(duration_seconds, 1);
        state.last_updated = now;
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

void NetworkNode::set_chat_wallet(std::shared_ptr<const Wallet> wallet) {
    chat_wallet_ = std::move(wallet);
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

void NetworkNode::append_chat_inbox(const std::string& line) {
    std::lock_guard<std::mutex> lock(chat_mutex_);
    std::filesystem::create_directories(chat_inbox_file_.parent_path());
    std::ofstream out(chat_inbox_file_, std::ios::app);
    if (out) out << line << '\n';
}

void NetworkNode::bootstrap(bool auto_connect) {
    discover_public_endpoint();
    resolve_seed_endpoints();
    save_peers();
    if (auto_connect) {
        connect_known_peers(std::min<size_t>(4, constants::MAX_PEER_CONNECTIONS));
    }
}

std::optional<std::string> NetworkNode::advertised_endpoint() const {
    if (!advertised_self_) return std::nullopt;
    return endpoint_label(advertised_self_->ip, advertised_self_->port);
}

ip_address NetworkNode::public_ip() {
    if (advertised_self_) return advertised_self_->ip;
    return detect_public_ip(ctx_, ip_detect_host_, ip_detect_port_, ip_detect_path_);
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
            std::string label = "unknown";
            try {
                auto remote = socket.remote_endpoint();
                label = remote.address().to_string() + ":" + std::to_string(remote.port());
            } catch (...) {
            }
            try {
                if (is_banned(label)) {
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
            auto advertised = canonical_peer_label_from_version(peer->endpoint(), version);
            if (advertised) {
                record_peer_label(*advertised);
            }
            {
                std::lock_guard<std::mutex> guard(sync_mutex_);
                peer_heights_[peer->remote_label()] = version.best_height;
                if (advertised) peer_heights_[*advertised] = version.best_height;
            }
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

            chat::HistoryEntry entry;
            entry.direction = "in";
            entry.legacy = parsed.legacy;
            entry.authenticated = parsed.authenticated;
            entry.encrypted = parsed.encrypted;
            entry.decrypted = parsed.decrypted;
            entry.is_private = chat_payload.chat_type == 1;
            entry.timestamp = parsed.timestamp;
            entry.nonce = parsed.nonce;
            entry.message_id = parsed.message_id;
            entry.sender_address = parsed.sender_address;
            entry.sender_pubkey = crypto::base64_encode(chat_payload.sender_pubkey);
            entry.recipient_address = parsed.recipient_address;
            entry.recipient_pubkey = crypto::base64_encode(chat_payload.recipient_pubkey);
            entry.channel = parsed.channel;
            entry.message = parsed.message;
            entry.peer_label = peer->remote_label();
            entry.status = parsed.encrypted && !parsed.decrypted ? "received-opaque" : "received";

            auto summary = chat::describe_history_entry(entry);
            log_info("chat", summary);
            record_chat_history(entry);
            append_chat_inbox(summary);
        } catch (const std::exception& ex) {
            punish(peer, 10, std::string("invalid chat payload: ") + ex.what());
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
    record_peer_label(ep.address().to_string() + ":" + std::to_string(ep.port()));
}

void NetworkNode::record_peer_label(const std::string& label) {
    if (label.empty() || is_self_label(label)) return;
    std::lock_guard<std::mutex> guard(peers_mutex_);
    known_peers_.insert(label);
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
        if (state.score == 0 && state.banned_until == 0) continue;
        out << label << '\t'
            << state.score << ' '
            << state.banned_until << ' '
            << state.last_updated << "\n";
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
    for (const auto& seed : dns_seeds_) {
        auto parsed = parse_host_port(seed, listen_port_ ? listen_port_ : default_p2p_port());
        if (!parsed) {
            log_warn("net", "invalid seed entry=" + seed);
            continue;
        }
        if (proxy_ && proxy_->remote_dns && !is_ipv4_literal(parsed->first)) {
            record_peer_label(parsed->first + ":" + std::to_string(parsed->second));
            log_info("net", "queued seed for proxy DNS seed=" + seed);
            continue;
        }
        try {
            boost::asio::ip::tcp::resolver resolver(ctx_);
            auto endpoints = resolver.resolve(parsed->first, std::to_string(parsed->second));
            size_t resolved = 0;
            for (const auto& endpoint : endpoints) {
                if (!endpoint.endpoint().address().is_v4()) continue;
                record_peer_label(endpoint.endpoint().address().to_string() + ":" + std::to_string(parsed->second));
                ++resolved;
            }
            log_info("net", "resolved seed=" + seed + " peers=" + std::to_string(resolved));
        } catch (const std::exception& ex) {
            log_warn("net", "seed resolution failed seed=" + seed + " reason=" + ex.what());
        }
    }
}

void NetworkNode::connect_known_peers(size_t max_connections) {
    std::vector<std::string> candidates;
    {
        std::lock_guard<std::mutex> guard(peers_mutex_);
        candidates.assign(known_peers_.begin(), known_peers_.end());
    }
    size_t connected = 0;
    for (const auto& label : candidates) {
        if (connected >= max_connections) break;
        if (label.empty() || is_self_label(label) || is_banned(label)) continue;
        auto parsed = parse_host_port(label, listen_port_ ? listen_port_ : default_p2p_port());
        if (!parsed) continue;
        bool already_connected = false;
        {
            std::lock_guard<std::mutex> guard(sessions_mutex_);
            for (const auto& session : sessions_) {
                if (session && session->remote_label() == label) {
                    already_connected = true;
                    break;
                }
            }
        }
        if (already_connected) continue;
        connect(parsed->first, parsed->second);
        ++connected;
    }
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
    boost::asio::ip::tcp::resolver resolver(ctx);
    boost::asio::ip::tcp::socket socket(ctx);
    auto endpoints = resolver.resolve(host, port);
    boost::asio::connect(socket, endpoints);

    std::string req = "GET " + path + " HTTP/1.1\r\nHost: " +
                      host + "\r\nConnection: close\r\n\r\n";
    boost::asio::write(socket, boost::asio::buffer(req));

    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\r\n\r\n");
    std::istream resp_stream(&response);
    std::string http_version;
    unsigned int status_code;
    std::string status_message;
    resp_stream >> http_version >> status_code;
    std::getline(resp_stream, status_message);
    if (!resp_stream || http_version.substr(0,5) != "HTTP/" || status_code != 200)
        throw std::runtime_error("IP detect failed");

    std::string body;
    if (response.size() > 0) {
        std::ostringstream ss;
        ss << resp_stream.rdbuf();
        body = ss.str();
    } else {
        boost::asio::read(socket, response, boost::asio::transfer_all());
        std::ostringstream ss;
        ss << &response;
        body = ss.str();
    }
    // Body is IP string
    auto ip = ip_address::from_string(body.substr(0, body.find_first_of("\r\n ")));
    return ip;
}

} // namespace net
} // namespace cryptex
