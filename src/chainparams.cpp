#include "chainparams.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace cryptex {

namespace {

const ChainParams kMainnet{
    NetworkKind::Mainnet,
    "mainnet",
    "",
    9333,
    9332,
    0x43584558, // CXEX
    0x3e00ffff,
    1741478400,
    "AAECAwQFBgcICQoLDA0ODxAREhM=",
    14590424,
    false,
    false,
    {}
};

const ChainParams kTestnet{
    NetworkKind::Testnet,
    "testnet",
    "testnet",
    19333,
    19332,
    0x43585454, // CXTT
    0x3f00ffff,
    1741478401,
    "AAECAwQFBgcICQoLDA0ODxAREhM=",
    78355,
    true,
    false,
    {}
};

const ChainParams kRegtest{
    NetworkKind::Regtest,
    "regtest",
    "regtest",
    19444,
    19443,
    0x43585247, // CXRG
    0x407fffff,
    1741478402,
    "AAECAwQFBgcICQoLDA0ODxAREhM=",
    8,
    true,
    true,
    {}
};

const ChainParams* g_params = &kMainnet;

std::string lower_copy(std::string_view text) {
    std::string out(text.begin(), text.end());
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

} // namespace

const ChainParams& params() {
    return *g_params;
}

const ChainParams& params_for(NetworkKind network) {
    switch (network) {
    case NetworkKind::Mainnet: return kMainnet;
    case NetworkKind::Testnet: return kTestnet;
    case NetworkKind::Regtest: return kRegtest;
    }
    return kMainnet;
}

void select_network(NetworkKind network) {
    g_params = &params_for(network);
}

NetworkKind parse_network_name(std::string_view name) {
    auto lowered = lower_copy(name);
    if (lowered.empty() || lowered == "main" || lowered == "mainnet") return NetworkKind::Mainnet;
    if (lowered == "test" || lowered == "testnet") return NetworkKind::Testnet;
    if (lowered == "reg" || lowered == "regtest") return NetworkKind::Regtest;
    throw std::runtime_error("unknown network: " + std::string(name));
}

std::string network_name(NetworkKind network) {
    return params_for(network).name;
}

} // namespace cryptex
