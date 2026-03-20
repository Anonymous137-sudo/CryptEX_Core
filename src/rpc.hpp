#pragma once

#include "chainparams.hpp"
#include "constants.hpp"
#include <boost/asio.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace cryptex {

class Blockchain;
namespace net { class NetworkNode; }

namespace rpc {

struct RpcConfig {
    std::string bind{"127.0.0.1"};
    uint16_t port{default_rpc_port()};
    std::string username;
    std::string password;
    std::vector<std::string> auth_entries;
    std::vector<std::string> allow_ips;
    size_t max_body_bytes{1'048'576};
    std::optional<std::string> wallet_path;
    std::optional<std::string> wallet_password;
};

class RpcService {
public:
    RpcService(Blockchain& chain,
               net::NetworkNode* node,
               std::optional<std::string> wallet_path,
               std::optional<std::string> wallet_password,
               uint16_t rpc_port = default_rpc_port());

    void set_stop_callback(std::function<void()> callback);
    std::string handle_jsonrpc(const std::string& body, bool& stop_requested) const;

private:
    Blockchain& chain_;
    net::NetworkNode* node_;
    std::optional<std::string> wallet_path_;
    std::optional<std::string> wallet_password_;
    uint16_t rpc_port_;
    std::function<void()> stop_callback_;
};

class RpcServer {
public:
    RpcServer(boost::asio::io_context& ctx,
              const RpcConfig& config,
              Blockchain& chain,
              net::NetworkNode* node = nullptr);

    void start();
    void stop();
    void set_stop_callback(std::function<void()> callback);

private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace rpc
} // namespace cryptex
