#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cryptex {

enum class NetworkKind : uint8_t {
    Mainnet = 0,
    Testnet = 1,
    Regtest = 2,
};

struct ChainParams {
    NetworkKind network{NetworkKind::Mainnet};
    const char* name{"mainnet"};
    const char* data_dir_suffix{""};
    uint16_t default_p2p_port{9333};
    uint16_t default_rpc_port{9332};
    uint32_t message_magic{0x43584558};
    uint32_t pow_limit_bits{0x3e00ffff};
    uint32_t genesis_timestamp{1741478400};
    const char* genesis_address{"AAECAwQFBgcICQoLDA0ODxAREhM="};
    uint32_t genesis_nonce{14946014};
    bool allow_min_difficulty_blocks{false};
    bool fixed_difficulty{false};
    std::vector<std::string> default_dns_seeds{};
};

const ChainParams& params();
const ChainParams& params_for(NetworkKind network);
void select_network(NetworkKind network);
NetworkKind parse_network_name(std::string_view name);
std::string network_name(NetworkKind network);

inline uint16_t default_p2p_port() { return params().default_p2p_port; }
inline uint16_t default_rpc_port() { return params().default_rpc_port; }
inline uint32_t message_magic() { return params().message_magic; }
inline uint32_t pow_limit_bits() { return params().pow_limit_bits; }
inline uint32_t genesis_timestamp() { return params().genesis_timestamp; }
inline const std::string genesis_address() { return params().genesis_address; }

} // namespace cryptex
