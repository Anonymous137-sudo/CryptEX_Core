#include "block.hpp"
#include "blockchain.hpp"
#include "chainparams.hpp"
#include "chat_history.hpp"
#include "chat_secure.hpp"
#include "config.hpp"
#include "constants.hpp"
#include "duckdns.hpp"
#include "network.hpp"
#include "rpc.hpp"
#include "wallet.hpp"
#include "debug.hpp"
#include "base64.hpp"
#include "sha3_512.hpp"
#include "serialization.hpp"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <string>
#include <ctime>
#include <filesystem>
#include <memory>
#include <optional>
#include <array>
#include <vector>
#include <atomic>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <boost/asio.hpp>
#include <openssl/hmac.h>
#include <openssl/rand.h>

using namespace cryptex;

static std::string format_rate(double hps) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    if (hps >= 1e9) ss << (hps / 1e9) << " GH/s";
    else if (hps >= 1e6) ss << (hps / 1e6) << " MH/s";
    else if (hps >= 1e3) ss << (hps / 1e3) << " kH/s";
    else ss << hps << " H/s";
    return ss.str();
}

static std::string format_coin_amount(int64_t satoshis) {
    static constexpr int64_t SATOSHIS_PER_COIN = 100'000'000LL;
    const bool negative = satoshis < 0;
    uint64_t absolute = static_cast<uint64_t>(negative ? -satoshis : satoshis);
    uint64_t whole = absolute / SATOSHIS_PER_COIN;
    uint64_t fractional = absolute % SATOSHIS_PER_COIN;

    std::ostringstream ss;
    if (negative) ss << "-";
    ss << whole << "." << std::setw(8) << std::setfill('0') << fractional
       << " " << constants::COIN_NAME;
    return ss.str();
}

static std::string format_chat_timestamp(uint64_t timestamp) {
    std::time_t tt = static_cast<std::time_t>(timestamp);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &tt);
#else
    localtime_r(&tt, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

static chat::HistoryEntry build_outbound_chat_entry(const net::ChatPayload& payload,
                                                    const std::string& plaintext,
                                                    const std::string& peer_label) {
    chat::HistoryEntry entry;
    entry.direction = "out";
    entry.legacy = payload.version < 2;
    entry.authenticated = (payload.flags & chat::CHAT_FLAG_SIGNED) != 0;
    entry.encrypted = (payload.flags & chat::CHAT_FLAG_ENCRYPTED) != 0;
    entry.decrypted = true;
    entry.is_private = payload.chat_type == 1;
    entry.timestamp = payload.timestamp;
    entry.nonce = payload.nonce;
    entry.message_id = chat::message_id(payload);
    entry.sender_address = payload.sender;
    entry.sender_pubkey = crypto::base64_encode(payload.sender_pubkey);
    entry.recipient_address = payload.recipient;
    entry.recipient_pubkey = crypto::base64_encode(payload.recipient_pubkey);
    entry.channel = payload.channel;
    entry.message = plaintext;
    entry.peer_label = peer_label;
    entry.status = "queued";
    return entry;
}

static std::string format_sync_status(const net::NetworkNode::SyncStatus& status) {
    std::ostringstream ss;
    ss << "local=" << status.local_height
       << " peer=" << status.best_peer_height
       << " queued=" << status.queued_blocks
       << " inflight=" << status.inflight_blocks
       << " peers=" << status.connected_peers;
    return ss.str();
}

static bool wait_for_mining_sync(net::NetworkNode& node, uint64_t max_wait_ms, bool verbose) {
    using namespace std::chrono_literals;

    const auto start = std::chrono::steady_clock::now();
    auto last_report = start - 1s;
    bool saw_peer = false;

    while (true) {
        auto status = node.sync_status();
        saw_peer = saw_peer || status.connected_peers > 0 || status.best_peer_height > 0;

        const bool caught_up =
            status.connected_peers > 0 &&
            status.local_height >= status.best_peer_height &&
            status.queued_blocks == 0 &&
            status.inflight_blocks == 0;

        if (caught_up) {
            if (verbose) {
                std::cout << "[sync] caught up: " << format_sync_status(status) << "\n";
            }
            return true;
        }

        const auto now = std::chrono::steady_clock::now();
        if (!saw_peer && now - start >= 5s) {
            if (verbose) {
                std::cout << "[sync] no peer state received, proceeding with local chain\n";
            }
            return false;
        }

        if (saw_peer && !status.syncing && status.connected_peers > 0) {
            if (verbose) {
                std::cout << "[sync] peer chain already aligned: " << format_sync_status(status) << "\n";
            }
            return true;
        }

        if (max_wait_ms > 0 &&
            now - start >= std::chrono::milliseconds(max_wait_ms)) {
            if (verbose) {
                std::cout << "[sync] timed out waiting for peer sync: "
                          << format_sync_status(status) << "\n";
            }
            return false;
        }

        if (verbose && now - last_report >= 1s) {
            std::cout << "[sync] waiting: " << format_sync_status(status) << "\n";
            last_report = now;
        }

        std::this_thread::sleep_for(250ms);
    }
}

static std::string lower_hex(const unsigned char* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        unsigned char byte = data[i];
        out.push_back(hex[(byte >> 4) & 0x0F]);
        out.push_back(hex[byte & 0x0F]);
    }
    return out;
}

static std::string hmac_sha256_hex_text(const std::string& key, const std::string& data) {
    unsigned int out_len = 0;
    unsigned char out[EVP_MAX_MD_SIZE];
    if (!HMAC(EVP_sha256(),
              key.data(),
              static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(data.data()),
              data.size(),
              out,
              &out_len)) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }
    return lower_hex(out, out_len);
}

static std::filesystem::path g_default_data_dir = std::filesystem::current_path() / "data";

static std::optional<std::filesystem::path> home_directory() {
#ifdef _WIN32
    if (const char* appdata = std::getenv("APPDATA")) return std::filesystem::path(appdata);
    if (const char* userprofile = std::getenv("USERPROFILE")) return std::filesystem::path(userprofile) / "AppData/Roaming";
    const char* drive = std::getenv("HOMEDRIVE");
    const char* path = std::getenv("HOMEPATH");
    if (drive && path) return std::filesystem::path(std::string(drive) + std::string(path)) / "AppData/Roaming";
#else
    if (const char* home = std::getenv("HOME")) return std::filesystem::path(home);
#endif
    return std::nullopt;
}

static std::filesystem::path legacy_data_dir_from_binary(const char* argv0) {
    std::error_code ec;
    std::filesystem::path binary_path = std::filesystem::absolute(argv0, ec);
    if (!ec) binary_path = binary_path.lexically_normal();
    std::filesystem::path binary_dir = ec ? std::filesystem::current_path() : binary_path.parent_path();
    if (binary_dir.empty()) binary_dir = std::filesystem::current_path();

    auto project_data = (binary_dir.parent_path() / "data").lexically_normal();
    if (!project_data.empty()) return project_data;
    return std::filesystem::current_path() / "data";
}

static std::vector<std::filesystem::path> legacy_wallet_candidates_from_binary(const char* argv0) {
    std::error_code ec;
    std::filesystem::path binary_path = std::filesystem::absolute(argv0, ec);
    if (!ec) binary_path = binary_path.lexically_normal();
    std::filesystem::path binary_dir = ec ? std::filesystem::current_path() : binary_path.parent_path();
    if (binary_dir.empty()) binary_dir = std::filesystem::current_path();

    std::vector<std::filesystem::path> out;
    out.push_back(binary_dir / "Wallet.dat");
    out.push_back(binary_dir.parent_path() / "Wallet.dat");
    out.push_back(legacy_data_dir_from_binary(argv0) / "Wallet.dat");
    return out;
}

static std::filesystem::path system_default_data_dir() {
#ifdef _WIN32
    if (auto home = home_directory()) return *home / "CryptEX";
#elif defined(__APPLE__)
    if (auto home = home_directory()) return *home / "Library/Application Support/CryptEX";
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME")) {
        return std::filesystem::path(xdg) / "CryptEX";
    }
    if (auto home = home_directory()) return *home / ".local/share/CryptEX";
#endif
    return std::filesystem::current_path() / "data";
}

static std::filesystem::path network_default_data_dir(NetworkKind network) {
    auto base = system_default_data_dir();
    const auto& network_params = params_for(network);
    if (network == NetworkKind::Mainnet || std::string(network_params.data_dir_suffix).empty()) {
        return base;
    }
    return base / network_params.data_dir_suffix;
}

static bool path_exists_nonempty(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec) && !std::filesystem::is_empty(path, ec);
}

static bool datadir_has_chainstate(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path / "headers.dat", ec) ||
           std::filesystem::exists(path / "index.dat", ec) ||
           std::filesystem::exists(path / "chainstate.dat", ec);
}

static bool datadir_is_incomplete_stub(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return false;
    bool has_blocks = std::filesystem::exists(path / "blocks", ec);
    bool has_chain = datadir_has_chainstate(path);
    return has_blocks && !has_chain;
}

static std::filesystem::path no_legacy_migration_sentinel(const std::filesystem::path& path) {
    return path / ".no_legacy_migration";
}

static void copy_tree_contents(const std::filesystem::path& source,
                               const std::filesystem::path& target,
                               bool overwrite_existing) {
    std::error_code ec;
    if (!std::filesystem::exists(source, ec)) return;
    std::filesystem::create_directories(target, ec);
    for (const auto& entry : std::filesystem::recursive_directory_iterator(source, ec)) {
        if (ec) break;
        auto relative = std::filesystem::relative(entry.path(), source, ec);
        if (ec || relative.empty()) continue;
        auto destination = target / relative;
        if (entry.is_directory(ec)) {
            std::filesystem::create_directories(destination, ec);
            continue;
        }
        std::filesystem::create_directories(destination.parent_path(), ec);
        if (entry.is_regular_file(ec)) {
            auto option = overwrite_existing
                ? std::filesystem::copy_options::overwrite_existing
                : std::filesystem::copy_options::skip_existing;
            std::filesystem::copy_file(entry.path(), destination, option, ec);
        }
    }
}

static void copy_file_if_needed(const std::filesystem::path& source,
                                const std::filesystem::path& target,
                                bool overwrite_existing) {
    std::error_code ec;
    if (!std::filesystem::exists(source, ec)) return;
    std::filesystem::create_directories(target.parent_path(), ec);
    auto option = overwrite_existing
        ? std::filesystem::copy_options::overwrite_existing
        : std::filesystem::copy_options::skip_existing;
    std::filesystem::copy_file(source, target, option, ec);
}

static void migrate_legacy_state_if_needed(const char* argv0, const std::filesystem::path& target_datadir) {
    const auto legacy_datadir = legacy_data_dir_from_binary(argv0);
    if (legacy_datadir == target_datadir) return;

    std::error_code ec;
    std::filesystem::create_directories(target_datadir, ec);
    if (std::filesystem::exists(no_legacy_migration_sentinel(target_datadir), ec)) return;

    const bool target_has_chain = datadir_has_chainstate(target_datadir);
    const bool target_stub = datadir_is_incomplete_stub(target_datadir);
    const bool legacy_has_chain = datadir_has_chainstate(legacy_datadir);
    const bool legacy_has_any = path_exists_nonempty(legacy_datadir);

    if (legacy_has_any && (!target_has_chain || target_stub) && legacy_has_chain) {
        copy_tree_contents(legacy_datadir, target_datadir, true);
    } else if (legacy_has_any && !path_exists_nonempty(target_datadir)) {
        copy_tree_contents(legacy_datadir, target_datadir, false);
    }

    const auto target_wallet = (target_datadir / "Wallet.dat").lexically_normal();
    for (const auto& candidate : legacy_wallet_candidates_from_binary(argv0)) {
        if (candidate.lexically_normal() == target_wallet) continue;
        if (std::filesystem::exists(candidate, ec)) {
            copy_file_if_needed(candidate, target_wallet, !std::filesystem::exists(target_wallet, ec));
            break;
        }
    }
}

static std::filesystem::path prepare_data_dir(std::filesystem::path path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    return path;
}

struct GlobalCliOptions {
    std::optional<NetworkKind> network;
    std::optional<std::filesystem::path> datadir;
    std::optional<std::filesystem::path> conf_path;
    std::optional<LogLevel> log_level;
    std::optional<std::filesystem::path> log_file;
    std::optional<bool> log_console;
    std::optional<bool> log_json;
    std::optional<std::string> log_subsystems;
    bool debug{false};
};

struct RuntimeOptions {
    NetworkKind network{NetworkKind::Mainnet};
    ConfigFile config;
    std::filesystem::path datadir;
    std::filesystem::path conf_path;
};

static std::optional<bool> parse_bool_text(const std::string& value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (lowered == "1" || lowered == "true" || lowered == "yes" || lowered == "on") return true;
    if (lowered == "0" || lowered == "false" || lowered == "no" || lowered == "off") return false;
    return std::nullopt;
}

static std::vector<std::string> split_csv(const std::string& text) {
    std::vector<std::string> out;
    std::string current;
    std::istringstream in(text);
    while (std::getline(in, current, ',')) {
        size_t start = 0;
        while (start < current.size() && std::isspace(static_cast<unsigned char>(current[start]))) ++start;
        size_t end = current.size();
        while (end > start && std::isspace(static_cast<unsigned char>(current[end - 1]))) --end;
        if (end > start) {
            out.push_back(current.substr(start, end - start));
        }
    }
    return out;
}

static bool is_global_option(const std::string& arg) {
    return arg == "--network" || arg == "--testnet" || arg == "--regtest" || arg == "--mainnet" ||
           arg == "--datadir" || arg == "--conf" || arg == "--debug" ||
           arg == "--loglevel" || arg == "--logfile" || arg == "--logconsole" ||
           arg == "--logjson" || arg == "--logsubsystems";
}

static bool global_option_requires_value(const std::string& arg) {
    return arg == "--network" || arg == "--datadir" || arg == "--conf" ||
           arg == "--loglevel" || arg == "--logfile" || arg == "--logconsole" ||
           arg == "--logsubsystems";
}

static int find_command_index(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (!is_global_option(arg)) {
            return i;
        }
        if (global_option_requires_value(arg) && i + 1 < argc) {
            ++i;
        }
    }
    return -1;
}

static std::optional<std::pair<std::string, uint16_t>> parse_hostport_value(const std::string& text,
                                                                            uint16_t default_port = 0) {
    if (text.empty()) return std::nullopt;
    auto pos = text.rfind(':');
    if (pos == std::string::npos || text.find(':') != pos) {
        if (default_port == 0) return std::nullopt;
        return std::make_pair(text, default_port);
    }
    try {
        return std::make_pair(text.substr(0, pos), static_cast<uint16_t>(std::stoul(text.substr(pos + 1))));
    } catch (...) {
        return std::nullopt;
    }
}

static GlobalCliOptions scan_global_options(int argc, char** argv) {
    GlobalCliOptions opts;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--network" && i + 1 < argc) {
            opts.network = parse_network_name(argv[++i]);
        } else if (arg == "--testnet") {
            opts.network = NetworkKind::Testnet;
        } else if (arg == "--regtest") {
            opts.network = NetworkKind::Regtest;
        } else if (arg == "--mainnet") {
            opts.network = NetworkKind::Mainnet;
        } else if (arg == "--datadir" && i + 1 < argc) {
            opts.datadir = argv[++i];
        } else if (arg == "--conf" && i + 1 < argc) {
            opts.conf_path = argv[++i];
        } else if (arg == "--debug") {
            opts.debug = true;
        } else if (arg == "--loglevel" && i + 1 < argc) {
            auto parsed = parse_log_level(argv[++i]);
            if (!parsed) {
                throw std::runtime_error("invalid --loglevel value");
            }
            opts.log_level = *parsed;
        } else if (arg == "--logfile" && i + 1 < argc) {
            opts.log_file = argv[++i];
        } else if (arg == "--logconsole" && i + 1 < argc) {
            auto parsed = parse_bool_text(argv[++i]);
            if (!parsed) {
                throw std::runtime_error("invalid --logconsole value");
            }
            opts.log_console = *parsed;
        } else if (arg == "--logjson") {
            opts.log_json = true;
        } else if (arg == "--logsubsystems" && i + 1 < argc) {
            opts.log_subsystems = argv[++i];
        }
    }
    return opts;
}

static std::string default_wallet_path(const RuntimeOptions& runtime) {
    if (auto configured = runtime.config.get_string("wallet")) {
        std::filesystem::path path(*configured);
        if (path.is_relative()) {
            path = runtime.datadir / path;
        }
        return path.string();
    }
    return (runtime.datadir / "Wallet.dat").string();
}

static std::string resolve_wallet_path(const RuntimeOptions& runtime, const std::string& raw_path) {
    std::filesystem::path path(raw_path);
    if (path.is_relative()) {
        path = runtime.datadir / path;
    }
    return path.string();
}

static RuntimeOptions initialize_runtime(int argc, char** argv) {
    auto cli = scan_global_options(argc, argv);

    RuntimeOptions runtime;
    runtime.network = cli.network.value_or(NetworkKind::Mainnet);
    select_network(runtime.network);
    g_default_data_dir = network_default_data_dir(runtime.network);
    runtime.datadir = cli.datadir.value_or(g_default_data_dir);
    if (!cli.datadir) {
        migrate_legacy_state_if_needed(argv[0], runtime.datadir);
    }
    runtime.conf_path = cli.conf_path.value_or(runtime.datadir / "cryptex.conf");
    runtime.config = ConfigFile::load(runtime.conf_path, true);
    if (!cli.network) {
        if (auto configured_network = runtime.config.get_string("network")) {
            runtime.network = parse_network_name(*configured_network);
            select_network(runtime.network);
            g_default_data_dir = network_default_data_dir(runtime.network);
            if (!cli.datadir) {
                runtime.datadir = g_default_data_dir;
                runtime.conf_path = cli.conf_path.value_or(runtime.datadir / "cryptex.conf");
                runtime.config = ConfigFile::load(runtime.conf_path, true);
            }
        }
    }
    if (!cli.datadir) {
        if (auto configured_datadir = runtime.config.get_string("datadir")) {
            runtime.datadir = std::filesystem::path(*configured_datadir);
        }
    }
    runtime.datadir = runtime.datadir.lexically_normal();

    LogConfig log_config;
    if (auto level = runtime.config.get_string("loglevel")) {
        auto parsed = parse_log_level(*level);
        if (!parsed) {
            throw std::runtime_error("invalid loglevel in config");
        }
        log_config.level = *parsed;
    }
    if (auto debug = runtime.config.get_bool("debug")) {
        if (*debug && static_cast<int>(log_config.level) > static_cast<int>(LogLevel::Debug)) {
            log_config.level = LogLevel::Debug;
        }
    }
    if (auto console = runtime.config.get_bool("logconsole")) {
        log_config.console = *console;
    }
    if (auto json = runtime.config.get_bool("logjson")) {
        log_config.json = *json;
    }
    if (auto file = runtime.config.get_string("logfile")) {
        log_config.file_path = *file;
    }
    if (auto subsystems = runtime.config.get_string("logsubsystems")) {
        log_config.subsystems = split_csv(*subsystems);
    }

    if (cli.log_level) log_config.level = *cli.log_level;
    if (cli.log_console) log_config.console = *cli.log_console;
    if (cli.log_json) log_config.json = *cli.log_json;
    if (cli.log_file) log_config.file_path = *cli.log_file;
    if (cli.log_subsystems) log_config.subsystems = split_csv(*cli.log_subsystems);
    if (cli.debug && static_cast<int>(log_config.level) > static_cast<int>(LogLevel::Debug)) {
        log_config.level = LogLevel::Debug;
    }
    if (!log_config.file_path.empty() && log_config.file_path.is_relative()) {
        log_config.file_path = runtime.datadir / log_config.file_path;
    }

    configure_logging(log_config);
    set_debug(cli.debug);
    if (std::filesystem::exists(runtime.conf_path)) {
        log_info("config", "loaded configuration from " + runtime.conf_path.string());
    }
    return runtime;
}

static void write_u32_le(std::array<uint8_t, 80>& buffer, size_t offset, uint32_t value) {
    buffer[offset + 0] = static_cast<uint8_t>(value & 0xFF);
    buffer[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buffer[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

static std::array<uint8_t, 80> serialize_header_fast(const BlockHeader& header) {
    std::array<uint8_t, 80> buffer{};
    write_u32_le(buffer, 0, static_cast<uint32_t>(header.version));
    auto prev = header.prev_block_hash.to_bytes();
    auto merkle = header.merkle_root.to_bytes();
    std::memcpy(buffer.data() + 4, prev.data(), prev.size());
    std::memcpy(buffer.data() + 36, merkle.data(), merkle.size());
    write_u32_le(buffer, 68, header.timestamp);
    write_u32_le(buffer, 72, header.bits);
    write_u32_le(buffer, 76, header.nonce);
    return buffer;
}

static bool hash_meets_target(const std::array<uint8_t, constants::POW_HASH_BYTES>& hash_bytes,
                              const std::array<uint8_t, constants::POW_HASH_BYTES>& target_bytes) {
    return std::memcmp(hash_bytes.data(), target_bytes.data(), hash_bytes.size()) <= 0;
}

template <size_t N>
static std::string short_hex(const std::array<uint8_t, N>& bytes, size_t chars = 16) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(chars);
    size_t byte_count = std::min(bytes.size(), (chars + 1) / 2);
    for (size_t i = 0; i < byte_count && out.size() < chars; ++i) {
        out.push_back(hex[(bytes[i] >> 4) & 0x0F]);
        if (out.size() < chars) {
            out.push_back(hex[bytes[i] & 0x0F]);
        }
    }
    return out;
}

static std::string format_mining_status(uint64_t iterations,
                                        uint32_t nonce,
                                        const std::array<uint8_t, constants::POW_HASH_BYTES>& hash_bytes,
                                        double rate) {
    std::ostringstream ss;
    ss << "[mine] iter=" << iterations
       << " nonce=" << nonce
       << " powhash=" << short_hex(hash_bytes) << "..."
       << " rate=" << format_rate(rate);
    return ss.str();
}

static std::vector<uint8_t> make_coinbase_script_sig(uint64_t height,
                                                     uint32_t timestamp,
                                                     const uint256_t& prev_hash) {
    std::vector<uint8_t> script_sig;
    script_sig.reserve(8 + 4 + 8);
    serialization::write_int<uint64_t>(script_sig, height);
    serialization::write_int<uint32_t>(script_sig, timestamp);
    auto prev_bytes = prev_hash.to_bytes();
    script_sig.insert(script_sig.end(), prev_bytes.begin(), prev_bytes.begin() + 8);
    return script_sig;
}

static void usage() {
    std::cout << "cryptex-client commands:\n"
              << "  global: [--network mainnet|testnet|regtest] [--testnet] [--regtest] [--conf path] [--loglevel trace|debug|info|warn|error] [--logfile path] [--logjson] [--logconsole 0|1] [--logsubsystems a,b,c]\n"
              << "  wallet-create <password> [wallet.dat] [--words 12|15|18|21|24] [--mnemonic-passphrase text]\n"
              << "  wallet-import-mnemonic <password> <mnemonic> [wallet.dat] [--mnemonic-passphrase text]\n"
              << "  wallet-dump-mnemonic <password> [wallet.dat]\n"
              << "  wallet-new-address <password> [wallet.dat]\n"
              << "  wallet-info <password> [wallet.dat]\n"
              << "  wallet-balance <password> [wallet.dat] [--datadir path]\n"
              << "  wallet-history <password> [wallet.dat] [--datadir path] [--mempool]\n"
              << "  wallet-rescan <password> [wallet.dat] [--datadir path] [--gap-limit N]\n"
              << "  wallet-unspent <password> [wallet.dat] [--datadir path]\n"
              << "  wallet-send <password> <to_addr> <amount_sats> [wallet.dat] [--datadir path] [--connect host:port] [--opret msg] [--debug]\n"
              << "  sign-message <password> <message> [wallet.dat]\n"
              << "  rpcauth-generate <user> <password>\n"
              << "  node [--connect host:port] [--seed host[:port]] [--externalip ip[:port]] [--discover 0|1] [--ipdetecthost host] [--ipdetectport n] [--ipdetectpath path] [--duckdns-domain name] [--duckdns-token token] [--duckdns-interval seconds] [--proxy host:port] [--proxydns 0|1] [--datadir path] [--debug] [--rpcbind ip] [--rpcport n] [--rpcuser u] [--rpcpassword p] [--rpcauth spec] [--rpcallowip rule] [--rpcmaxbody bytes] [--wallet path] [--walletpass p]\n"
              << "  chat-public <host:port> <channel> <message> [--wallet path] [--walletpass p] [--from address] [--datadir path] [--wait-ms n]\n"
              << "  chat-private <host:port> <recipient-address> <message> --recipient-pubkey base64 [--wallet path] [--walletpass p] [--from address] [--datadir path] [--wait-ms n]\n"
              << "  chat-inbox [--datadir path] [--limit N] [--channel name] [--address addr] [--direction in|out] [--private|--public]\n"
              << "  chat-history [--datadir path] [--limit N] [--channel name] [--address addr] [--direction in|out] [--private|--public]\n"
              << "  mine [--cycles N] [--block-cycles N] [--datadir path] [--connect host:port] [--address addr] [--threads N] [--sync-wait-ms N] [--debug]\n"
              << "     (set --cycles 0 for infinite mining)\n"
              << "  genesis-mine [--threads N] [--start nonce] [--limit N]\n"
              << "default datadir: " << g_default_data_dir.string() << "\n";
}

static Block build_coinbase_only(uint64_t height) {
    Block blk;
    blk.header.version = 1;
    blk.header.prev_block_hash = uint256_t(); // genesis placeholder
    blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    blk.header.bits = pow_limit_bits();
    blk.header.nonce = 0;

    Transaction coinbase;
    coinbase.version = 1;
    TxIn in;
    in.prevout.tx_hash = uint256_t();
    in.prevout.index = 0xFFFFFFFF;
    in.scriptSig = make_coinbase_script_sig(height, blk.header.timestamp, blk.header.prev_block_hash);
    in.sequence = 0xFFFFFFFF;
    coinbase.inputs.push_back(in);

    TxOut out;
    out.value = Block::get_block_reward(height);
    out.scriptPubKey = "AAECAwQFBgcICQoLDA0ODxAREhM="; // replaced by wallet when mining realistically
    coinbase.outputs.push_back(out);
    coinbase.lockTime = 0;

    blk.transactions.push_back(coinbase);
    blk.header.merkle_root = blk.compute_merkle_root();
    return blk;
}

static Block build_template(Blockchain& chain, const std::string& coinbase_addr) {
    uint64_t height = chain.best_height() + 1;
    Block blk;
    blk.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    blk.header.bits = chain.next_work_bits(blk.header.timestamp);
    blk.header.nonce = 0;

    Transaction coinbase;
    coinbase.version = 1;
    TxIn in;
    in.prevout.tx_hash = uint256_t();
    in.prevout.index = 0xFFFFFFFF;
    in.scriptSig = make_coinbase_script_sig(height, blk.header.timestamp, blk.header.prev_block_hash);
    in.sequence = 0xFFFFFFFF;
    coinbase.inputs.push_back(in);

    TxOut out;
    out.value = Block::get_block_reward(height);
    out.scriptPubKey = coinbase_addr;
    if (coinbase_addr != "genesis") {
        try {
            out.scriptPubKey = crypto::canonicalize_address(coinbase_addr);
        } catch (...) {
        }
    }
    coinbase.outputs.push_back(out);
    coinbase.lockTime = 0;
    blk.transactions.push_back(coinbase);

    auto txs = chain.mempool().get_transactions();
    size_t total_size = coinbase.serialize().size();
    for (const auto& tx : txs) {
        auto sz = tx.serialize().size();
        if (total_size + sz > constants::MAX_BLOCK_SIZE_BYTES) break;
        blk.transactions.push_back(tx);
        total_size += sz;
    }
    blk.header.merkle_root = blk.compute_merkle_root();
    return blk;
}

int main(int argc, char** argv) {
    g_default_data_dir = system_default_data_dir();
    if (argc < 2) { usage(); return 1; }
    try {
    auto runtime = initialize_runtime(argc, argv);
    std::vector<std::string> normalized_args_storage;
    std::vector<char*> normalized_argv;
    int cmd_index = find_command_index(argc, argv);
    if (cmd_index < 0) { usage(); return 1; }
    normalized_args_storage.reserve(static_cast<size_t>(argc - cmd_index + 1));
    normalized_args_storage.emplace_back(argv[0]);
    for (int i = cmd_index; i < argc; ++i) {
        normalized_args_storage.emplace_back(argv[i]);
    }
    normalized_argv.reserve(normalized_args_storage.size() + 1);
    for (auto& arg : normalized_args_storage) {
        normalized_argv.push_back(arg.data());
    }
    normalized_argv.push_back(nullptr);
    argc = static_cast<int>(normalized_args_storage.size());
    argv = normalized_argv.data();

    std::string cmd = argv[1];

    if (cmd == "wallet-create") {
        if (argc < 3) { usage(); return 1; }
        std::string pass = argv[2];
        std::string path = default_wallet_path(runtime);
        size_t mnemonic_words = 24;
        std::string mnemonic_passphrase;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--words" && i + 1 < argc) {
                mnemonic_words = static_cast<size_t>(std::stoul(argv[++i]));
            } else if (arg == "--mnemonic-passphrase" && i + 1 < argc) {
                mnemonic_passphrase = argv[++i];
            } else if (arg[0] != '-') {
                path = resolve_wallet_path(runtime, arg);
            }
        }
        auto w = Wallet::create_new(pass, path, mnemonic_words, mnemonic_passphrase);
        std::cout << "Created wallet at " << path
                  << "\nAddress: " << w.address
                  << "\nMnemonic: " << w.mnemonic_phrase() << "\n";
        return 0;
    }

    if (cmd == "wallet-import-mnemonic") {
        if (argc < 4) { usage(); return 1; }
        std::string pass = argv[2];
        std::string mnemonic = argv[3];
        std::string path = default_wallet_path(runtime);
        std::string mnemonic_passphrase;
        for (int i = 4; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--mnemonic-passphrase" && i + 1 < argc) {
                mnemonic_passphrase = argv[++i];
            } else if (arg[0] != '-') {
                path = resolve_wallet_path(runtime, arg);
            }
        }
        auto w = Wallet::create_from_mnemonic(pass, path, mnemonic, mnemonic_passphrase);
        std::cout << "Imported mnemonic into " << path << "\nAddress: " << w.address << "\n";
        return 0;
    }

    if (cmd == "wallet-dump-mnemonic") {
        if (argc < 3) { usage(); return 1; }
        std::string pass = argv[2];
        std::string path = (argc >= 4) ? resolve_wallet_path(runtime, argv[3]) : default_wallet_path(runtime);
        auto w = Wallet::load(pass, path);
        std::cout << w.mnemonic_phrase() << "\n";
        return 0;
    }

    if (cmd == "wallet-new-address") {
        if (argc < 3) { usage(); return 1; }
        std::string pass = argv[2];
        std::string path = (argc >= 4) ? resolve_wallet_path(runtime, argv[3]) : default_wallet_path(runtime);
        auto w = Wallet::load(pass, path);
        auto addr = w.add_address(pass, path);
        std::cout << "Added address to " << path << "\nAddress: " << addr << "\n";
        return 0;
    }

    if (cmd == "wallet-info") {
        if (argc < 3) { usage(); return 1; }
        std::string pass = argv[2];
        std::string path = (argc >= 4) ? resolve_wallet_path(runtime, argv[3]) : default_wallet_path(runtime);
        auto w = Wallet::load(pass, path);
        std::cout << "Loaded wallet " << path << "\nPrimary address: " << w.address
                  << "\nMode: " << w.hd_mode()
                  << "\nMnemonic: " << (w.has_mnemonic() ? "BIP39" : "none")
                  << "\nAddresses (" << w.all_addresses().size() << "):\n";
        for (size_t i = 0; i < w.all_addresses().size(); ++i) {
            std::cout << "  " << w.all_addresses()[i]
                      << " pubkey=" << crypto::base64_encode(w.pubkeys[i]) << "\n";
        }
        return 0;
    }

    if (cmd == "wallet-balance") {
        if (argc < 3) { usage(); return 1; }
        std::string pass = argv[2];
        std::string path = (argc >= 4 && argv[3][0] != '-') ? resolve_wallet_path(runtime, argv[3]) : default_wallet_path(runtime);
        std::filesystem::path datadir = runtime.datadir;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--datadir" && i + 1 < argc) datadir = argv[++i];
        }
        datadir = prepare_data_dir(datadir);
        auto w = Wallet::load(pass, path);
        Blockchain chain(datadir);
        auto summary = w.balance_summary(chain);
        std::cout << "Balance across " << w.all_addresses().size() << " addresses:\n"
                  << "  Spendable: " << format_coin_amount(summary.spendable) << "\n"
                  << "  Immature:  " << format_coin_amount(summary.immature) << "\n"
                  << "  Total:     " << format_coin_amount(summary.total()) << "\n";
        return 0;
    }

    if (cmd == "wallet-history") {
        if (argc < 3) { usage(); return 1; }
        std::string pass = argv[2];
        std::string path = (argc >= 4 && argv[3][0] != '-') ? resolve_wallet_path(runtime, argv[3]) : default_wallet_path(runtime);
        std::filesystem::path datadir = runtime.datadir;
        bool include_mempool = false;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--datadir" && i + 1 < argc) datadir = argv[++i];
            if (arg == "--mempool") include_mempool = true;
        }
        datadir = prepare_data_dir(datadir);
        auto w = Wallet::load(pass, path);
        Blockchain chain(datadir);
        auto hist = w.history(chain, include_mempool);
        for (const auto& e : hist) std::cout << e << "\n";
        return 0;
    }

    if (cmd == "wallet-rescan") {
        if (argc < 3) { usage(); return 1; }
        std::string pass = argv[2];
        std::string path = (argc >= 4 && argv[3][0] != '-') ? resolve_wallet_path(runtime, argv[3]) : default_wallet_path(runtime);
        std::filesystem::path datadir = runtime.datadir;
        uint32_t gap_limit = 20;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--datadir" && i + 1 < argc) datadir = argv[++i];
            else if (arg == "--gap-limit" && i + 1 < argc) gap_limit = static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        datadir = prepare_data_dir(datadir);
        Blockchain chain(datadir);
        auto w = Wallet::load(pass, path);
        auto discovered = w.rescan(chain, pass, path, gap_limit);
        std::cout << "Rescan complete. Discovered " << discovered
                  << " new addresses. Total addresses: " << w.all_addresses().size() << "\n";
        return 0;
    }

    if (cmd == "sign-message") {
        if (argc < 4) { usage(); return 1; }
        std::string pass = argv[2];
        std::string msg = argv[3];
        std::string path = (argc >= 5) ? resolve_wallet_path(runtime, argv[4]) : default_wallet_path(runtime);
        auto w = Wallet::load(pass, path);
        auto digest = crypto::sha3_512(std::vector<uint8_t>(msg.begin(), msg.end()));
        std::array<uint8_t,32> first{};
        std::memcpy(first.data(), digest.data(), 32);
        uint256_t h(first);
        auto sig = script::sign_hash(h, w.privkey);
        std::cout << "Signature(base64): " << crypto::base64_encode(sig.data(), sig.size()) << "\n";
        return 0;
    }

    if (cmd == "rpcauth-generate") {
        if (argc < 4) { usage(); return 1; }
        std::string user = argv[2];
        std::string password = argv[3];
        std::vector<uint8_t> salt_bytes(16);
        if (RAND_bytes(salt_bytes.data(), static_cast<int>(salt_bytes.size())) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        std::string salt = lower_hex(salt_bytes.data(), salt_bytes.size());
        std::string hash = hmac_sha256_hex_text(salt, password);
        std::cout << "rpcauth=" << user << ":" << salt << "$" << hash << "\n";
        return 0;
    }

    if (cmd == "wallet-unspent") {
        if (argc < 3) { usage(); return 1; }
        std::string pass = argv[2];
        std::string path = (argc >= 4 && argv[3][0] != '-') ? resolve_wallet_path(runtime, argv[3]) : default_wallet_path(runtime);
        std::filesystem::path datadir = runtime.datadir;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--datadir" && i + 1 < argc) datadir = argv[++i];
        }
        datadir = prepare_data_dir(datadir);
        auto w = Wallet::load(pass, path);
        Blockchain chain(datadir);
        auto utxos = w.list_unspent(chain);
        int64_t total = 0;
        for (const auto& [op, entry] : utxos) {
            total += entry.output.value;
            std::cout << op.tx_hash.to_hex() << ":" << op.index << " value=" << entry.output.value
                      << " address=" << entry.output.scriptPubKey
                      << " height=" << entry.block_height << (entry.is_coinbase ? " (coinbase)" : "") << "\n";
        }
        std::cout << "Total: " << total << " satoshis\n";
        return 0;
    }

    if (cmd == "wallet-send") {
        if (argc < 5) { usage(); return 1; }
        std::string pass = argv[2];
        std::string to = argv[3];
        int64_t amount = std::strtoll(argv[4], nullptr, 10);
        std::string path = default_wallet_path(runtime);
        std::filesystem::path datadir = runtime.datadir;
        std::string hostport = runtime.config.get_all("connect").empty() ? std::string() : runtime.config.get_all("connect").front();
        std::string opret_msg;
        bool debug = debug_enabled();
        for (int i = 5; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--datadir" && i + 1 < argc) datadir = argv[++i];
            else if (arg == "--connect" && i + 1 < argc) hostport = argv[++i];
            else if (arg == "--opret" && i + 1 < argc) opret_msg = argv[++i];
            else if (arg == "--debug") debug = true;
            else if (arg[0] != '-') path = resolve_wallet_path(runtime, arg);
        }
        datadir = prepare_data_dir(datadir);
        set_debug(debug);
        auto w = Wallet::load(pass, path);
        Blockchain chain(datadir);
        auto tx = w.create_payment(chain, to, amount, opret_msg);
        Mempool::AcceptStatus status = Mempool::AcceptStatus::Invalid;
        if (!chain.mempool().add_transaction(
                tx, chain.utxo(), static_cast<uint32_t>(chain.best_height()), &status)) {
            auto status_text = [&]() {
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
            };
            std::cerr << "Transaction rejected by mempool: " << status_text() << "\n";
            return 1;
        }
        std::cout << "Created tx " << tx.hash().to_hex() << " broadcasting...\n";
        if (!hostport.empty()) {
            boost::asio::io_context ctx;
            net::NetworkNode node(ctx, 0);
            if (auto proxy_value = runtime.config.get_string("proxy")) {
                if (auto parsed = parse_hostport_value(*proxy_value)) {
                    node.set_socks5_proxy(parsed->first, parsed->second,
                                          runtime.config.get_bool("proxydns").value_or(true));
                }
            }
            node.attach_blockchain(&chain);
            node.start();
            auto pos = hostport.find(':');
            if (pos != std::string::npos) {
                node.connect(hostport.substr(0, pos),
                             static_cast<uint16_t>(std::stoi(hostport.substr(pos + 1))));
            }
            net::Message inv;
            inv.type = net::MessageType::INV;
            std::vector<uint8_t> payload;
            serialization::write_varint(payload, 1);
            payload.push_back(2);
            auto hbytes = tx.hash().to_bytes();
            payload.insert(payload.end(), hbytes.begin(), hbytes.end());
            inv.payload = payload;
            net::Message txmsg;
            txmsg.type = net::MessageType::TX;
            txmsg.payload = tx.serialize();
            // give small delay to connect then send
            boost::asio::steady_timer timer(ctx, std::chrono::milliseconds(200));
            timer.async_wait([&](const std::error_code&) {
                node.broadcast(inv);
                node.broadcast(txmsg);
            });
            ctx.run_for(std::chrono::seconds(2));
        }
        return 0;
    }

    if (cmd == "node") {
        std::filesystem::path datadir = runtime.datadir;
        std::vector<std::string> connects = runtime.config.get_all("connect");
        std::vector<std::string> seeds = runtime.config.get_all("seed");
        if (seeds.empty()) seeds = params().default_dns_seeds;
        std::vector<std::string> duckdns_domains = runtime.config.get_all("duckdns_domain");
        std::string duckdns_token = runtime.config.get_string("duckdns_token").value_or("");
        int duckdns_interval = static_cast<int>(runtime.config.get_i64("duckdns_interval").value_or(300));
        std::string proxy_host;
        uint16_t proxy_port = 0;
        bool proxy_remote_dns = runtime.config.get_bool("proxydns").value_or(true);
        if (auto proxy_value = runtime.config.get_string("proxy")) {
            if (auto parsed = parse_hostport_value(*proxy_value)) {
                proxy_host = parsed->first;
                proxy_port = parsed->second;
            }
        }
        bool debug = debug_enabled();
        bool discover = runtime.config.get_bool("discover").value_or(true);
        std::optional<std::string> externalip = runtime.config.get_string("externalip");
        std::string ip_detect_host = runtime.config.get_string("ipdetecthost").value_or(constants::IP_DETECT_HOST);
        std::string ip_detect_port = runtime.config.get_string("ipdetectport").value_or(constants::IP_DETECT_PORT);
        std::string ip_detect_path = runtime.config.get_string("ipdetectpath").value_or(constants::IP_DETECT_PATH);
        rpc::RpcConfig rpc_cfg;
        bool rpc_requested = false;
        if (auto bind = runtime.config.get_string("rpcbind")) {
            rpc_cfg.bind = *bind;
            rpc_requested = true;
        }
        if (auto port = runtime.config.get_u64("rpcport")) {
            rpc_cfg.port = static_cast<uint16_t>(*port);
            rpc_requested = true;
        }
        if (auto user = runtime.config.get_string("rpcuser")) {
            rpc_cfg.username = *user;
            rpc_requested = true;
        }
        if (auto pass = runtime.config.get_string("rpcpassword")) {
            rpc_cfg.password = *pass;
            rpc_requested = true;
        }
        rpc_cfg.auth_entries = runtime.config.get_all("rpcauth");
        rpc_cfg.allow_ips = runtime.config.get_all("rpcallowip");
        if (auto max_body = runtime.config.get_u64("rpcmaxbody")) {
            rpc_cfg.max_body_bytes = static_cast<size_t>(*max_body);
        }
        if (!rpc_cfg.auth_entries.empty()) {
            rpc_requested = true;
        }
        if (auto wallet = runtime.config.get_string("wallet")) {
            std::filesystem::path wallet_path(*wallet);
            if (wallet_path.is_relative()) wallet_path = datadir / wallet_path;
            rpc_cfg.wallet_path = wallet_path.string();
        }
        if (auto walletpass = runtime.config.get_string("walletpass")) {
            rpc_cfg.wallet_password = *walletpass;
        }
        if (auto enabled = runtime.config.get_bool("rpcenable")) {
            rpc_requested = *enabled || rpc_requested;
        }
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--datadir" && i + 1 < argc) {
                datadir = argv[++i];
            } else if (arg == "--connect" && i + 1 < argc) {
                connects.push_back(argv[++i]);
            } else if (arg == "--seed" && i + 1 < argc) {
                seeds.push_back(argv[++i]);
            } else if (arg == "--externalip" && i + 1 < argc) {
                externalip = argv[++i];
            } else if (arg == "--discover" && i + 1 < argc) {
                auto parsed = parse_bool_text(argv[++i]);
                if (!parsed) throw std::runtime_error("invalid --discover value");
                discover = *parsed;
            } else if (arg == "--ipdetecthost" && i + 1 < argc) {
                ip_detect_host = argv[++i];
            } else if (arg == "--ipdetectport" && i + 1 < argc) {
                ip_detect_port = argv[++i];
            } else if (arg == "--ipdetectpath" && i + 1 < argc) {
                ip_detect_path = argv[++i];
            } else if (arg == "--duckdns-domain" && i + 1 < argc) {
                duckdns_domains.push_back(argv[++i]);
            } else if (arg == "--duckdns-token" && i + 1 < argc) {
                duckdns_token = argv[++i];
            } else if (arg == "--duckdns-interval" && i + 1 < argc) {
                duckdns_interval = static_cast<int>(std::stoi(argv[++i]));
            } else if (arg == "--proxy" && i + 1 < argc) {
                auto parsed = parse_hostport_value(argv[++i]);
                if (!parsed) throw std::runtime_error("invalid --proxy value");
                proxy_host = parsed->first;
                proxy_port = parsed->second;
            } else if (arg == "--proxydns" && i + 1 < argc) {
                auto parsed = parse_bool_text(argv[++i]);
                if (!parsed) throw std::runtime_error("invalid --proxydns value");
                proxy_remote_dns = *parsed;
            } else if (arg == "--debug") {
                debug = true;
            } else if (arg == "--rpcbind" && i + 1 < argc) {
                rpc_cfg.bind = argv[++i];
                rpc_requested = true;
            } else if (arg == "--rpcport" && i + 1 < argc) {
                rpc_cfg.port = static_cast<uint16_t>(std::stoul(argv[++i]));
                rpc_requested = true;
            } else if (arg == "--rpcuser" && i + 1 < argc) {
                rpc_cfg.username = argv[++i];
                rpc_requested = true;
            } else if (arg == "--rpcpassword" && i + 1 < argc) {
                rpc_cfg.password = argv[++i];
                rpc_requested = true;
            } else if (arg == "--rpcauth" && i + 1 < argc) {
                rpc_cfg.auth_entries.push_back(argv[++i]);
                rpc_requested = true;
            } else if (arg == "--rpcallowip" && i + 1 < argc) {
                rpc_cfg.allow_ips.push_back(argv[++i]);
                rpc_requested = true;
            } else if (arg == "--rpcmaxbody" && i + 1 < argc) {
                rpc_cfg.max_body_bytes = static_cast<size_t>(std::stoull(argv[++i]));
                rpc_requested = true;
            } else if (arg == "--wallet" && i + 1 < argc) {
                rpc_cfg.wallet_path = resolve_wallet_path(runtime, argv[++i]);
            } else if (arg == "--walletpass" && i + 1 < argc) {
                rpc_cfg.wallet_password = argv[++i];
            }
        }
        datadir = prepare_data_dir(datadir);
        set_debug(debug);
        if (rpc_requested && rpc_cfg.auth_entries.empty() &&
            (rpc_cfg.username.empty() || rpc_cfg.password.empty())) {
            std::cerr << "RPC requires either --rpcauth or both --rpcuser and --rpcpassword\n";
            return 1;
        }
        if (rpc_cfg.wallet_password && !rpc_cfg.wallet_path) {
            rpc_cfg.wallet_path = (datadir / "Wallet.dat").string();
        }

        Blockchain chain(datadir);
        boost::asio::io_context ctx;
        net::NetworkNode node(ctx, default_p2p_port(), datadir);
        node.attach_blockchain(&chain);
        node.best_height = chain.best_height();
        node.enable_discovery(discover);
        node.set_dns_seeds(seeds);
        node.set_ip_detection_service(ip_detect_host, ip_detect_port, ip_detect_path);
        if (!proxy_host.empty() && proxy_port != 0) {
            node.set_socks5_proxy(proxy_host, proxy_port, proxy_remote_dns);
        }
        if (externalip) {
            node.set_external_address(*externalip);
        }
        std::shared_ptr<Wallet> chat_wallet;
        if (rpc_cfg.wallet_path && rpc_cfg.wallet_password) {
            try {
                chat_wallet = std::make_shared<Wallet>(Wallet::load(*rpc_cfg.wallet_password, *rpc_cfg.wallet_path));
                node.set_chat_wallet(chat_wallet);
                log_info("chat", "loaded local chat wallet with " + std::to_string(chat_wallet->all_addresses().size()) + " addresses");
            } catch (const std::exception& ex) {
                std::cerr << "Failed to load wallet for secure chat: " << ex.what() << "\n";
                return 1;
            }
        }
        node.start();
        node.bootstrap(connects.empty());
        log_info("node", "started " + network_name(runtime.network) +
                          " p2p node on port " + std::to_string(default_p2p_port()) +
                          " height=" + std::to_string(chain.best_height()));
        if (auto advertised = node.advertised_endpoint()) {
            log_info("net", "advertised endpoint " + *advertised);
        }
        std::unique_ptr<rpc::RpcServer> rpc_server;
        std::unique_ptr<DuckDnsUpdater> duckdns_updater;
        if (rpc_requested) {
            rpc_server = std::make_unique<rpc::RpcServer>(ctx, rpc_cfg, chain, &node);
            rpc_server->set_stop_callback([&]() {
                if (rpc_server) rpc_server->stop();
                node.stop();
                ctx.stop();
            });
            rpc_server->start();
            log_info("rpc", "rpc server listening on " + rpc_cfg.bind + ":" + std::to_string(rpc_cfg.port));
        }
        if (!duckdns_domains.empty() && !duckdns_token.empty()) {
            duckdns_updater = std::make_unique<DuckDnsUpdater>(ctx, duckdns_domains, duckdns_token, duckdns_interval);
            duckdns_updater->start();
        }
        for (const auto& hostport : connects) {
            auto pos = hostport.find(':');
            if (pos != std::string::npos) {
                node.connect(hostport.substr(0, pos),
                             static_cast<uint16_t>(std::stoi(hostport.substr(pos + 1))));
            }
        }
        ctx.run();
        return 0;
    }

    if (cmd == "chat-inbox" || cmd == "chat-history") {
        chat::HistoryQuery query;
        std::filesystem::path datadir = runtime.datadir;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--datadir" && i + 1 < argc) {
                datadir = argv[++i];
            } else if (arg == "--limit" && i + 1 < argc) {
                query.limit = static_cast<size_t>(std::stoull(argv[++i]));
            } else if (arg == "--channel" && i + 1 < argc) {
                query.channel = argv[++i];
            } else if (arg == "--address" && i + 1 < argc) {
                query.address = argv[++i];
            } else if (arg == "--direction" && i + 1 < argc) {
                query.direction = argv[++i];
            } else if (arg == "--private") {
                query.private_only = true;
            } else if (arg == "--public") {
                query.private_only = false;
            }
        }
        datadir = prepare_data_dir(datadir);
        auto history_path = datadir / "chat_history.dat";
        auto entries = chat::load_history(history_path, query);
        if (entries.empty()) {
            std::cout << "No chat messages in " << history_path.string() << "\n";
            return 0;
        }
        std::cout << "Chat history from " << history_path.string()
                  << " (" << entries.size() << " messages)\n";
        for (const auto& entry : entries) {
            std::cout << "  [" << format_chat_timestamp(entry.timestamp) << "] "
                      << entry.direction << " "
                      << (entry.is_private ? "private" : "public");
            if (!entry.channel.empty()) std::cout << " channel=" << entry.channel;
            if (!entry.sender_address.empty()) std::cout << " from=" << entry.sender_address;
            if (!entry.recipient_address.empty()) std::cout << " to=" << entry.recipient_address;
            if (!entry.status.empty()) std::cout << " status=" << entry.status;
            std::cout << "\n    " << entry.message << "\n";
        }
        return 0;
    }

    if (cmd == "chat-public" || cmd == "chat-private") {
        if (argc < 5) { usage(); return 1; }
        std::string hostport = argv[2];
        std::string channel_or_recipient = argv[3];
        std::string message = argv[4];
        std::filesystem::path datadir = runtime.datadir;
        std::string wallet_path = runtime.config.get_string("wallet")
                                      ? resolve_wallet_path(runtime, *runtime.config.get_string("wallet"))
                                      : default_wallet_path(runtime);
        std::optional<std::string> wallet_pass = runtime.config.get_string("walletpass");
        std::string sender_address;
        std::string recipient_pubkey_b64;
        uint64_t wait_ms = 1200;
        auto pos = hostport.find(':');
        if (pos == std::string::npos) { usage(); return 1; }
        std::string host = hostport.substr(0, pos);
        uint16_t port = static_cast<uint16_t>(std::stoi(hostport.substr(pos + 1)));
        for (int i = 5; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--wallet" && i + 1 < argc) {
                wallet_path = resolve_wallet_path(runtime, argv[++i]);
            } else if (arg == "--walletpass" && i + 1 < argc) {
                wallet_pass = argv[++i];
            } else if (arg == "--from" && i + 1 < argc) {
                sender_address = argv[++i];
            } else if (arg == "--recipient-pubkey" && i + 1 < argc) {
                recipient_pubkey_b64 = argv[++i];
            } else if (arg == "--datadir" && i + 1 < argc) {
                datadir = argv[++i];
            } else if (arg == "--wait-ms" && i + 1 < argc) {
                wait_ms = std::stoull(argv[++i]);
            }
        }
        if (!wallet_pass) {
            std::cerr << "Secure chat requires --walletpass or walletpass in config\n";
            return 1;
        }
        Wallet wallet = Wallet::load(*wallet_pass, wallet_path);
        datadir = prepare_data_dir(datadir);

        boost::asio::io_context ctx;
        net::NetworkNode node(ctx, 0, datadir);
        if (auto proxy_value = runtime.config.get_string("proxy")) {
            if (auto parsed = parse_hostport_value(*proxy_value)) {
                node.set_socks5_proxy(parsed->first, parsed->second,
                                      runtime.config.get_bool("proxydns").value_or(true));
            }
        }
        node.start();
        node.connect(host, port);
        net::ChatPayload payload;
        if (cmd == "chat-public") {
            payload = chat::make_signed_public_chat(wallet, sender_address, channel_or_recipient, message);
        } else {
            if (recipient_pubkey_b64.empty()) {
                std::cerr << "chat-private requires --recipient-pubkey <base64>\n";
                return 1;
            }
            payload = chat::make_encrypted_private_chat(wallet,
                                                        sender_address,
                                                        channel_or_recipient,
                                                        crypto::base64_decode(recipient_pubkey_b64),
                                                        message);
        }
        net::Message m;
        m.type = net::MessageType::CHAT;
        m.payload = payload.serialize();
        auto history_entry = build_outbound_chat_entry(payload, message, hostport);

        boost::asio::steady_timer send_timer(ctx, std::chrono::milliseconds(350));
        send_timer.async_wait([&](const std::error_code&) {
            bool sent = node.send_to(hostport, m);
            history_entry.status = sent ? "sent" : "no-peer";
            try {
                chat::append_history_entry(datadir / "chat_history.dat", history_entry);
            } catch (const std::exception& ex) {
                std::cerr << "Failed to write chat history: " << ex.what() << "\n";
            }
            if (sent) {
                std::cout << "Sent " << (history_entry.is_private ? "private" : "public")
                          << " chat id=" << history_entry.message_id
                          << " via " << hostport << "\n";
            } else {
                std::cerr << "No peer session available for " << hostport << "\n";
            }
        });
        boost::asio::steady_timer stop_timer(ctx, std::chrono::milliseconds(wait_ms));
        stop_timer.async_wait([&](const std::error_code&) {
            node.stop();
            ctx.stop();
        });
        ctx.run();
        return 0;
    }
  if (cmd == "mine") {
    uint64_t cycles = 10'000'000; // set 0 for infinite
    uint64_t block_cycles = 1;    // set 0 for infinite block chaining
    std::filesystem::path datadir = runtime.datadir;
    std::string hostport = runtime.config.get_all("connect").empty() ? std::string() : runtime.config.get_all("connect").front();
    std::string coinbase_addr = runtime.config.get_string("mine_address").value_or("genesis");
    bool debug = debug_enabled();
    bool infinite = false;
    bool infinite_block_cycles = false;
    unsigned int thread_count = runtime.config.get_uint("mine_threads").value_or(std::max(1u, std::thread::hardware_concurrency()));
    uint64_t sync_wait_ms = runtime.config.get_u64("mine_sync_wait_ms").value_or(0);
    if (auto configured_cycles = runtime.config.get_u64("mine_cycles")) cycles = *configured_cycles;
    if (auto configured_block_cycles = runtime.config.get_u64("mine_block_cycles")) block_cycles = *configured_block_cycles;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--cycles" && i + 1 < argc) cycles = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--block-cycles" && i + 1 < argc) block_cycles = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--datadir" && i + 1 < argc) datadir = argv[++i];
        else if (arg == "--connect" && i + 1 < argc) hostport = argv[++i];
        else if (arg == "--address" && i + 1 < argc) coinbase_addr = argv[++i];
        else if (arg == "--debug") debug = true;
        else if (arg == "--threads" && i + 1 < argc) thread_count = static_cast<unsigned int>(std::stoul(argv[++i]));
        else if (arg == "--sync-wait-ms" && i + 1 < argc) sync_wait_ms = std::strtoull(argv[++i], nullptr, 10);
    }
    datadir = prepare_data_dir(datadir);
    if (cycles == 0) infinite = true;
    if (block_cycles == 0) infinite_block_cycles = true;
    set_debug(debug);
    log_info("mine", "starting miner threads=" + std::to_string(thread_count) +
                     " datadir=" + datadir.string() +
                     " address=" + coinbase_addr +
                     (infinite ? " cycles=infinite" : " cycles=" + std::to_string(cycles)) +
                     (infinite_block_cycles ? " block_cycles=infinite" : " block_cycles=" + std::to_string(block_cycles)));

    Blockchain chain(datadir);
    boost::asio::io_context ctx;
    std::unique_ptr<net::NetworkNode> node;
    std::unique_ptr<std::thread> net_thread;
    if (!hostport.empty()) {
        node = std::make_unique<net::NetworkNode>(ctx, 0, datadir);
        if (auto proxy_value = runtime.config.get_string("proxy")) {
            if (auto parsed = parse_hostport_value(*proxy_value)) {
                node->set_socks5_proxy(parsed->first, parsed->second,
                                       runtime.config.get_bool("proxydns").value_or(true));
            }
        }
        node->attach_blockchain(&chain);
        node->best_height = chain.best_height();
        node->start();
        auto pos = hostport.find(':');
        if (pos != std::string::npos) {
            node->connect(hostport.substr(0, pos),
                         static_cast<uint16_t>(std::stoi(hostport.substr(pos + 1))));
        }
        net_thread = std::make_unique<std::thread>([&ctx]() { ctx.run(); });
        wait_for_mining_sync(*node, sync_wait_ms, true);
    }

    uint64_t blocks_mined = 0;
    bool stopped_without_block = false;

    while (infinite_block_cycles || blocks_mined < block_cycles) {
        const uint64_t target_index = blocks_mined + 1;
        if (node) {
            node->best_height = static_cast<uint32_t>(chain.best_height());
            wait_for_mining_sync(*node, sync_wait_ms, debug || target_index == 1);
        }

        if (debug || infinite_block_cycles || block_cycles > 1) {
            std::cout << "[mine] starting block cycle "
                      << (infinite_block_cycles ? std::to_string(target_index) + "/infinite"
                                                : std::to_string(target_index) + "/" + std::to_string(block_cycles))
                      << " at height " << chain.best_height() + 1 << "\n";
        }

        // Shared mining job state
        std::atomic<uint64_t> job_version{0};
        std::mutex job_mutex;
        Block current_job = build_template(chain, coinbase_addr);

        // Console output mutex
        std::mutex cout_mutex;
        std::atomic<size_t> status_width{0};

        // Background thread to refresh the job every 5 seconds
        std::atomic<bool> refresh_running{true};
        std::thread refresh_thread([&]() {
            while (refresh_running) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                auto new_job = build_template(chain, coinbase_addr);
                bool job_reset_needed = false;
                {
                    std::lock_guard<std::mutex> lock(job_mutex);
                    if (new_job.header.prev_block_hash != current_job.header.prev_block_hash) {
                        job_reset_needed = true;
                        current_job = new_job;
                        job_version++;
                    } else if (new_job.header.timestamp != current_job.header.timestamp) {
                        current_job = new_job;
                    }
                }
                if (job_reset_needed && debug_enabled()) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "\n[refresh] New block received, mining at height " << chain.best_height() + 1 << "\n";
                }
            }
        });

        std::atomic<bool> found{false};
        std::atomic<uint64_t> iterations{0};
        std::atomic<uint32_t> found_nonce{0};
        std::mutex found_mutex;
        Block found_block;
        uint256_t found_hash;

        auto start = std::chrono::steady_clock::now();
        auto last_report_time = start;
        uint64_t last_report_iter = 0;
        const auto status_interval = std::chrono::milliseconds(250);

        auto worker = [&](unsigned int tid) {
            Block local_job;
            std::array<uint8_t, constants::POW_HASH_BYTES> local_target_bytes{};
            std::array<uint8_t, 80> header_bytes{};
            crypto::SHA3_512_Hasher prefix_hasher;
            crypto::SHA3_512_Hasher nonce_hasher;
            uint32_t nonce = tid;
            uint64_t local_job_version = 0;

            {
                std::lock_guard<std::mutex> lock(job_mutex);
                local_job = current_job;
                auto target_vec = compact_target{local_job.header.bits}.expand().to_padded_bytes(constants::POW_HASH_BYTES);
                std::memcpy(local_target_bytes.data(), target_vec.data(), local_target_bytes.size());
                header_bytes = serialize_header_fast(local_job.header);
                prefix_hasher.reset();
                prefix_hasher.update(header_bytes.data(), 76);
                local_job_version = job_version.load();
            }

            while (!found.load(std::memory_order_relaxed) && (infinite || iterations.load(std::memory_order_relaxed) < cycles)) {
                uint64_t cur_ver = job_version.load();
                if (cur_ver != local_job_version) {
                    std::lock_guard<std::mutex> lock(job_mutex);
                    local_job = current_job;
                    auto target_vec = compact_target{local_job.header.bits}.expand().to_padded_bytes(constants::POW_HASH_BYTES);
                    std::memcpy(local_target_bytes.data(), target_vec.data(), local_target_bytes.size());
                    header_bytes = serialize_header_fast(local_job.header);
                    prefix_hasher.reset();
                    prefix_hasher.update(header_bytes.data(), 76);
                    local_job_version = cur_ver;
                    nonce = tid;
                }

                local_job.header.nonce = nonce;
                write_u32_le(header_bytes, 76, nonce);
                nonce_hasher.copy_state_from(prefix_hasher);
                nonce_hasher.update(header_bytes.data() + 76, 4);
                auto digest = nonce_hasher.finalize();
                std::array<uint8_t, constants::POW_HASH_BYTES> pow_hash{};
                std::memcpy(pow_hash.data(), digest.data(), pow_hash.size());
                uint64_t cur_iter = iterations.fetch_add(1, std::memory_order_relaxed) + 1;
                bool ok = hash_meets_target(pow_hash, local_target_bytes);
                if (ok) {
                    if (!found.exchange(true)) {
                        std::lock_guard<std::mutex> lk(found_mutex);
                        found_block = local_job;
                        found_hash = uint256_t::from_bytes(pow_hash.data(), pow_hash.size());
                        found_nonce = nonce;
                    }
                    break;
                }
                if (debug && tid == 0) {
                    auto now = std::chrono::steady_clock::now();
                    if (now - last_report_time >= status_interval) {
                        double secs = std::chrono::duration_cast<std::chrono::duration<double>>(now - last_report_time).count();
                        double rate = secs > 0 ? static_cast<double>(cur_iter - last_report_iter) / secs : 0.0;
                        std::string line = format_mining_status(cur_iter, nonce, pow_hash, rate);
                        {
                            std::lock_guard<std::mutex> lock(cout_mutex);
                            size_t width = std::max(status_width.load(), line.size());
                            std::cout << '\r' << line;
                            if (line.size() < width) {
                                std::cout << std::string(width - line.size(), ' ');
                            }
                            std::cout << std::flush;
                            status_width = width;
                        }
                        last_report_time = now;
                        last_report_iter = cur_iter;
                    }
                }
                nonce += thread_count;
            }
        };

        std::vector<std::thread> workers;
        workers.reserve(thread_count);
        for (unsigned int t = 0; t < thread_count; ++t) {
            workers.emplace_back(worker, t);
        }
        for (auto& t : workers) t.join();

        refresh_running = false;
        refresh_thread.join();

        if (debug) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << '\r' << std::string(status_width.load(), ' ') << "\r";
        }

        auto end = std::chrono::steady_clock::now();
        uint64_t total_iter = iterations.load();
        if (found.load()) {
            double secs = std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count();
            double avg_rate = secs > 0 ? static_cast<double>(total_iter) / secs : 0.0;
            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "Found block nonce=" << found_nonce.load()
                          << " powhash=" << found_hash.to_hex_padded(constants::POW_HASH_BYTES)
                          << " after " << total_iter << " iterations in "
                          << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
                          << " ms using " << thread_count << " threads"
                          << " avg_rate=" << format_rate(avg_rate) << "\n";

                uint256_t block_target = compact_target{found_block.header.bits}.expand();
                std::cout << "Target:  " << block_target.to_hex_padded(constants::POW_HASH_BYTES) << std::endl;
                std::cout << "PoWHash: " << found_hash.to_hex_padded(constants::POW_HASH_BYTES) << std::endl;
                std::cout << "LinkHash: " << found_block.header.hash().to_hex() << std::endl;
            }

            if (!chain.connect_block(found_block)) {
                log_warn("mine", "block was found locally but rejected by chain");
                std::cerr << "ERROR: Block was rejected by the chain (stale or invalid)!\n";
            } else {
                ++blocks_mined;
                log_info("mine", "block accepted at height " + std::to_string(chain.best_height()));
                std::cout << "Block successfully added to chain.\n";
            }
            if (node) {
                node->best_height = static_cast<uint32_t>(chain.best_height());
                net::Message msg;
                msg.type = net::MessageType::BLOCK;
                msg.payload = found_block.serialize();
                node->broadcast(msg);
            }
        } else {
            stopped_without_block = true;
            std::cout << "No block found in " << total_iter << " iterations\n";
            break;
        }
    }

    if (!infinite_block_cycles) {
        if (stopped_without_block && blocks_mined < block_cycles) {
            std::cout << "Mining session ended early after " << blocks_mined
                      << " successful block(s) out of requested " << block_cycles << "\n";
        } else if (block_cycles > 1) {
            std::cout << "Mining session complete: mined " << blocks_mined
                      << " block(s)\n";
        }
    }
    if (node) {
        node->stop();
        ctx.stop();
        if (net_thread && net_thread->joinable()) net_thread->join();
    }
    return 0;
}
     

    if (cmd == "genesis-mine") {
        unsigned int thread_count = std::max(1u, std::thread::hardware_concurrency());
        uint32_t start_nonce = 0;
        uint64_t limit = 0; // 0 = unbounded
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--threads" && i + 1 < argc) thread_count = static_cast<unsigned int>(std::stoul(argv[++i]));
            else if (arg == "--start" && i + 1 < argc) start_nonce = static_cast<uint32_t>(std::stoul(argv[++i]));
            else if (arg == "--limit" && i + 1 < argc) limit = std::strtoull(argv[++i], nullptr, 10);
        }
        Block base = Block::genesis_template();
        uint256_t target = compact_target{base.header.bits}.expand();
        std::atomic<bool> found{false};
        std::atomic<uint32_t> found_nonce{0};
        std::atomic<uint64_t> total{0};
        uint256_t best = (uint256_t(1) << 511);
        best = best * uint256_t(2) - uint256_t(1);
        std::mutex best_mutex;
        auto start = std::chrono::steady_clock::now();
        auto worker = [&](unsigned int tid) {
            Block blk = base;
            uint32_t nonce = start_nonce + tid;
            while (!found.load(std::memory_order_relaxed)) {
                blk.header.nonce = nonce;
                auto h = blk.header.pow_hash();
                uint64_t cur = total.fetch_add(1, std::memory_order_relaxed) + 1;
                {
                    std::lock_guard<std::mutex> lk(best_mutex);
                    if (h <= best) {
                        best = h;
                        found_nonce = nonce;
                    }
                }
                if (h <= target) {
                    found = true;
                    found_nonce = nonce;
                    break;
                }
                if (limit && cur >= limit) break;
                nonce += thread_count;
                if (nonce == 0) {
                    blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
                }
                if (tid == 0 && cur % 1'000'000 == 0) {
                    auto now = std::chrono::steady_clock::now();
                    double secs = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
                    double rate = secs > 0 ? static_cast<double>(cur) / secs : 0.0;
                    std::cout << "\r[genesis] best_powhash=" << best.to_hex_padded(constants::POW_HASH_BYTES)
                              << " nonce=" << found_nonce.load()
                              << " tried=" << cur << " rate=" << format_rate(rate) << std::flush;
                }
            }
        };
        std::vector<std::thread> workers;
        for (unsigned int t = 0; t < thread_count; ++t) workers.emplace_back(worker, t);
        for (auto& t : workers) t.join();
        auto end = std::chrono::steady_clock::now();
        std::cout << "\n";
        double secs = std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count();
        double rate = secs > 0 ? static_cast<double>(total.load()) / secs : 0.0;
        std::cout << "Genesis search finished. Found=" << (found ? "yes" : "no")
                  << " best_powhash=" << best.to_hex_padded(constants::POW_HASH_BYTES)
                  << " best_nonce=" << found_nonce.load()
                  << " total=" << total.load() << " avg_rate=" << format_rate(rate) << "\n";
        if (found) {
            std::cout << "Bake into code: set GENESIS_TIMESTAMP=" << base.header.timestamp
                      << " bits=0x" << std::hex << base.header.bits << std::dec
                      << " nonce=" << found_nonce.load() << "\n";
        }
        return 0;
    }

    usage();
    return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
