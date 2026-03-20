#pragma once

#include <cstdint>
#include <cstddef>

namespace cryptex {
namespace constants {

// Blockchain parameters
constexpr const char* COIN_NAME = "CryptEX";
constexpr uint64_t TOTAL_SUPPLY = 1'000'000'000;
constexpr uint64_t INITIAL_BLOCK_REWARD = 2500;
constexpr int HALVING_INTERVAL_BLOCKS = 200000;
constexpr int BLOCK_TIME_SECONDS = 600; // 10 minutes
constexpr size_t POW_HASH_BYTES = 64; // full SHA3-512 output
// Bootstrap difficulty using the full 512-bit SHA3 output. 0x3e00ffff keeps the
// same relative "quick bootstrap" difficulty we previously used on truncated-256.
constexpr uint32_t POW_LIMIT_BITS = 0x3e00ffff;
constexpr int DIFFICULTY_ADJUSTMENT_INTERVAL = 2016; // 2 weeks worth
constexpr int DIFFICULTY_LWMA_WINDOW = 72; // 12 hours at 10 min blocks
constexpr int DIFFICULTY_MAX_SOLVETIME = BLOCK_TIME_SECONDS * 6;
constexpr int DIFFICULTY_MIN_SOLVETIME = BLOCK_TIME_SECONDS / 6;
constexpr int COINBASE_MATURITY = 100; // conservative maturity like Bitcoin
constexpr int MAX_BLOCK_SIZE_BYTES = 1'000'000; // 1MB
constexpr int MAX_TRANSACTIONS_PER_BLOCK = 5000;

// Network constants
constexpr uint16_t DEFAULT_P2P_PORT = 9333;
constexpr uint16_t DEFAULT_RPC_PORT = 9332;
constexpr int MAX_PEER_CONNECTIONS = 125;
constexpr int PEER_DISCOVERY_INTERVAL_SECONDS = 300; // 5 minutes
constexpr int PING_INTERVAL_SECONDS = 30;
constexpr int CONNECTION_TIMEOUT_SECONDS = 10;
constexpr size_t MAX_HEADERS_PER_MESSAGE = 2000;
constexpr size_t MAX_PARALLEL_BLOCK_DOWNLOADS = 8;
constexpr uint32_t MESSAGE_MAGIC = 0x43584558; // 'CXEX' for framing
constexpr const char* IP_DETECT_HOST = "ifconfig.me";
constexpr const char* IP_DETECT_PORT = "80";
constexpr const char* IP_DETECT_PATH = "/";
constexpr int BAN_THRESHOLD = 100;
constexpr int BANNED_PEER_DURATION_SECONDS = 6 * 60 * 60;
constexpr int PEER_SCORE_DECAY_INTERVAL_SECONDS = 30 * 60;
constexpr int PEER_SCORE_DECAY_POINTS = 5;

// Protocol versions
constexpr uint32_t PROTOCOL_VERSION = 1;
constexpr uint32_t MIN_PROTOCOL_VERSION = 1;

// Genesis
// 20-byte payload (0x00..0x13) base64-encoded; length 28 with padding
constexpr const char* GENESIS_ADDRESS = "AAECAwQFBgcICQoLDA0ODxAREhM=";
constexpr uint32_t GENESIS_TIMESTAMP = 1741478400; // 2025-03-09 00:00:00 UTC

// Mempool limits
constexpr size_t MAX_MEMPOOL_SIZE_BYTES = 300'000'000; // 300MB
constexpr int MAX_MEMPOOL_TRANSACTIONS = 50'000;
constexpr int MAX_MEMPOOL_ORPHANS = 256;
constexpr int MEMPOOL_TX_EXPIRY_SECONDS = 2 * 60 * 60;
constexpr int64_t MIN_RELAY_FEE_SATS_PER_KB = 1000;
constexpr size_t MAX_STANDARD_TX_SIZE_BYTES = 100'000;
constexpr size_t MAX_STANDARD_TX_INPUTS = 128;
constexpr size_t MAX_STANDARD_TX_OUTPUTS = 128;
constexpr size_t MAX_STANDARD_SCRIPTSIG_BYTES = 1650;
constexpr int64_t DUST_LIMIT_SATS = 546; // standard dust threshold

// Address format - Base64 encoded 20-byte hash
constexpr int ADDRESS_HASH_LENGTH = 20;
constexpr int ADDRESS_BASE64_LENGTH = 28; // Ceil(20*4/3) rounded up

// Wallet encryption
constexpr int AES_KEY_SIZE = 32; // 256 bits
constexpr int AES_IV_SIZE = 16;
constexpr int AES_BLOCK_SIZE = 16;
constexpr int PBKDF2_ITERATIONS = 100000; // For key derivation

} // namespace constants
} // namespace cryptex
