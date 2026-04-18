#include "block.hpp"
#include "blockchain.hpp"
#include "chainparams.hpp"
#include "constants.hpp"
#include "network.hpp"
#include "debug.hpp"
#include "sha3_512.hpp"
#include "serialization.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

using namespace cryptex;

namespace {

struct PowWorkerJob {
    std::array<uint8_t, 80> header{};
    std::array<uint8_t, constants::POW_HASH_BYTES> target{};
    uint32_t start_nonce{0};
    uint32_t nonce_step{1};
    uint64_t max_iterations{0};
};

struct PowWorkerResult {
    bool found{false};
    uint32_t nonce{0};
    uint64_t iterations{0};
    std::array<uint8_t, constants::POW_HASH_BYTES> hash{};
};

struct NonceSearchResult {
    bool found{false};
    uint32_t nonce{0};
    uint32_t next_nonce{0};
    uint64_t iterations{0};
    std::array<uint8_t, constants::POW_HASH_BYTES> hash{};
};

static constexpr char kPowWorkerJobMagic[8] = {'C','R','X','P','O','W','2','!'};
static constexpr char kPowWorkerResultMagic[8] = {'C','R','X','R','E','S','2','!'};

uint32_t read_u32_le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

uint64_t read_u64_le(const uint8_t* data) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(data[i]) << (i * 8);
    }
    return value;
}

void write_u64_le_bytes(uint8_t* data, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        data[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
    }
}

void append_u32_le(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void append_u64_le(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

std::vector<uint8_t> read_binary_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

inline void set_header_nonce_le(std::array<uint8_t, 80>& header, uint32_t nonce) {
    header[76] = static_cast<uint8_t>(nonce & 0xFF);
    header[77] = static_cast<uint8_t>((nonce >> 8) & 0xFF);
    header[78] = static_cast<uint8_t>((nonce >> 16) & 0xFF);
    header[79] = static_cast<uint8_t>((nonce >> 24) & 0xFF);
}

bool hash_meets_target_scalar(const std::array<uint8_t, constants::POW_HASH_BYTES>& hash_bytes,
                              const std::array<uint8_t, constants::POW_HASH_BYTES>& target_bytes) {
    return std::memcmp(hash_bytes.data(), target_bytes.data(), hash_bytes.size()) <= 0;
}

NonceSearchResult run_nonce_search_scalar(const std::array<uint8_t, 80>& header_template,
                                          const std::array<uint8_t, constants::POW_HASH_BYTES>& target_bytes,
                                          const crypto::SHA3_512_Hasher& prefix_hasher,
                                          uint32_t start_nonce,
                                          uint32_t nonce_step,
                                          uint64_t max_iterations) {
    NonceSearchResult result;
    auto header_bytes = header_template;
    crypto::SHA3_512_Hasher nonce_hasher;
    uint32_t nonce = start_nonce;

    while (max_iterations == 0 || result.iterations < max_iterations) {
        set_header_nonce_le(header_bytes, nonce);
        nonce_hasher.copy_state_from(prefix_hasher);
        nonce_hasher.update(header_bytes.data() + 76, 4);
        const auto digest = nonce_hasher.finalize();
        std::memcpy(result.hash.data(), digest.data(), result.hash.size());
        ++result.iterations;
        result.next_nonce = nonce + nonce_step;
        if (hash_meets_target_scalar(result.hash, target_bytes)) {
            result.found = true;
            result.nonce = nonce;
            return result;
        }
        nonce += nonce_step;
    }

    return result;
}

#if defined(__x86_64__) || defined(_M_X64)
bool cpu_supports_avx2() {
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2");
#else
    return false;
#endif
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("avx2")))
#endif
bool hash_meets_target_avx2(const std::array<uint8_t, constants::POW_HASH_BYTES>& hash_bytes,
                            const std::array<uint8_t, constants::POW_HASH_BYTES>& target_bytes) {
    for (size_t offset = 0; offset < constants::POW_HASH_BYTES; offset += 32) {
        const auto* hash_ptr = reinterpret_cast<const __m256i*>(hash_bytes.data() + offset);
        const auto* target_ptr = reinterpret_cast<const __m256i*>(target_bytes.data() + offset);
        const __m256i hash_chunk = _mm256_loadu_si256(hash_ptr);
        const __m256i target_chunk = _mm256_loadu_si256(target_ptr);
        const __m256i equal_mask = _mm256_cmpeq_epi8(hash_chunk, target_chunk);
        const uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(equal_mask));
        if (mask != 0xFFFFFFFFu) {
            const uint32_t diff = ~mask;
#if defined(__GNUC__) || defined(__clang__)
            const uint32_t lane = static_cast<uint32_t>(__builtin_ctz(diff));
#else
            uint32_t lane = 0;
            while (lane < 32 && ((diff >> lane) & 1u) == 0u) ++lane;
#endif
            const uint8_t hash_byte = hash_bytes[offset + lane];
            const uint8_t target_byte = target_bytes[offset + lane];
            return hash_byte < target_byte;
        }
    }
    return true;
}

bool hash_meets_target_x86_64(const std::array<uint8_t, constants::POW_HASH_BYTES>& hash_bytes,
                              const std::array<uint8_t, constants::POW_HASH_BYTES>& target_bytes,
                              bool use_avx2) {
    if (use_avx2) {
        return hash_meets_target_avx2(hash_bytes, target_bytes);
    }
    return hash_meets_target_scalar(hash_bytes, target_bytes);
}

constexpr std::array<uint64_t, 24> kKeccakRoundConstants{
    0x0000000000000001ull, 0x0000000000008082ull,
    0x800000000000808aull, 0x8000000080008000ull,
    0x000000000000808bull, 0x0000000080000001ull,
    0x8000000080008081ull, 0x8000000000008009ull,
    0x000000000000008aull, 0x0000000000000088ull,
    0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull,
    0x8000000000008089ull, 0x8000000000008003ull,
    0x8000000000008002ull, 0x8000000000000080ull,
    0x000000000000800aull, 0x800000008000000aull,
    0x8000000080008081ull, 0x8000000000008080ull,
    0x0000000080000001ull, 0x8000000080008008ull,
};

constexpr std::array<int, 25> kKeccakRhoOffsets{
    0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

inline uint64_t rotl64(uint64_t value, int shift) {
    if (shift == 0) return value;
    return (value << shift) | (value >> (64 - shift));
}

void keccakf_scalar_state(uint64_t state[25]) {
    uint64_t b[25]{};
    uint64_t c[5]{};
    uint64_t d[5]{};

    for (size_t round = 0; round < kKeccakRoundConstants.size(); ++round) {
        for (int x = 0; x < 5; ++x) {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                state[x + 5 * y] ^= d[x];
            }
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                const int index = x + 5 * y;
                const int dest_x = y;
                const int dest_y = (2 * x + 3 * y) % 5;
                b[dest_x + 5 * dest_y] = rotl64(state[index], kKeccakRhoOffsets[index]);
            }
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                const uint64_t lane = b[x + 5 * y];
                const uint64_t lane1 = b[((x + 1) % 5) + 5 * y];
                const uint64_t lane2 = b[((x + 2) % 5) + 5 * y];
                state[x + 5 * y] = lane ^ ((~lane1) & lane2);
            }
        }
        state[0] ^= kKeccakRoundConstants[round];
    }
}

std::array<uint64_t, 25> prepare_prefix_state_x86_64(const std::array<uint8_t, 80>& header_template) {
    std::array<uint64_t, 25> state{};
    for (size_t lane = 0; lane < 9; ++lane) {
        state[lane] = read_u64_le(header_template.data() + lane * 8);
    }
    keccakf_scalar_state(state.data());
    return state;
}

std::array<uint8_t, constants::POW_HASH_BYTES> finalize_suffix_scalar_x86_64(const std::array<uint64_t, 25>& prefix_state,
                                                                              uint32_t bits,
                                                                              uint32_t nonce) {
    auto state = prefix_state;
    state[0] ^= static_cast<uint64_t>(bits) | (static_cast<uint64_t>(nonce) << 32);
    state[1] ^= 0x06ull;
    state[8] ^= (1ull << 63);
    keccakf_scalar_state(state.data());

    std::array<uint8_t, constants::POW_HASH_BYTES> hash{};
    for (size_t lane = 0; lane < 8; ++lane) {
        write_u64_le_bytes(hash.data() + lane * 8, state[lane]);
    }
    return hash;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("avx2")))
#endif
__m256i rotl64_avx2(__m256i value, int shift) {
    switch (shift) {
    case 0: return value;
    case 1: return _mm256_or_si256(_mm256_slli_epi64(value, 1), _mm256_srli_epi64(value, 63));
    case 2: return _mm256_or_si256(_mm256_slli_epi64(value, 2), _mm256_srli_epi64(value, 62));
    case 3: return _mm256_or_si256(_mm256_slli_epi64(value, 3), _mm256_srli_epi64(value, 61));
    case 6: return _mm256_or_si256(_mm256_slli_epi64(value, 6), _mm256_srli_epi64(value, 58));
    case 8: return _mm256_or_si256(_mm256_slli_epi64(value, 8), _mm256_srli_epi64(value, 56));
    case 10: return _mm256_or_si256(_mm256_slli_epi64(value, 10), _mm256_srli_epi64(value, 54));
    case 14: return _mm256_or_si256(_mm256_slli_epi64(value, 14), _mm256_srli_epi64(value, 50));
    case 15: return _mm256_or_si256(_mm256_slli_epi64(value, 15), _mm256_srli_epi64(value, 49));
    case 18: return _mm256_or_si256(_mm256_slli_epi64(value, 18), _mm256_srli_epi64(value, 46));
    case 20: return _mm256_or_si256(_mm256_slli_epi64(value, 20), _mm256_srli_epi64(value, 44));
    case 21: return _mm256_or_si256(_mm256_slli_epi64(value, 21), _mm256_srli_epi64(value, 43));
    case 25: return _mm256_or_si256(_mm256_slli_epi64(value, 25), _mm256_srli_epi64(value, 39));
    case 27: return _mm256_or_si256(_mm256_slli_epi64(value, 27), _mm256_srli_epi64(value, 37));
    case 28: return _mm256_or_si256(_mm256_slli_epi64(value, 28), _mm256_srli_epi64(value, 36));
    case 36: return _mm256_or_si256(_mm256_slli_epi64(value, 36), _mm256_srli_epi64(value, 28));
    case 39: return _mm256_or_si256(_mm256_slli_epi64(value, 39), _mm256_srli_epi64(value, 25));
    case 41: return _mm256_or_si256(_mm256_slli_epi64(value, 41), _mm256_srli_epi64(value, 23));
    case 43: return _mm256_or_si256(_mm256_slli_epi64(value, 43), _mm256_srli_epi64(value, 21));
    case 44: return _mm256_or_si256(_mm256_slli_epi64(value, 44), _mm256_srli_epi64(value, 20));
    case 45: return _mm256_or_si256(_mm256_slli_epi64(value, 45), _mm256_srli_epi64(value, 19));
    case 55: return _mm256_or_si256(_mm256_slli_epi64(value, 55), _mm256_srli_epi64(value, 9));
    case 56: return _mm256_or_si256(_mm256_slli_epi64(value, 56), _mm256_srli_epi64(value, 8));
    case 61: return _mm256_or_si256(_mm256_slli_epi64(value, 61), _mm256_srli_epi64(value, 3));
    case 62: return _mm256_or_si256(_mm256_slli_epi64(value, 62), _mm256_srli_epi64(value, 2));
    default: return value;
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("avx2")))
#endif
void keccakf4x_avx2(__m256i state[25]) {
    __m256i b[25];
    __m256i c[5];
    __m256i d[5];

    for (size_t round = 0; round < kKeccakRoundConstants.size(); ++round) {
        for (int x = 0; x < 5; ++x) {
            c[x] = _mm256_xor_si256(
                _mm256_xor_si256(state[x], state[x + 5]),
                _mm256_xor_si256(_mm256_xor_si256(state[x + 10], state[x + 15]), state[x + 20]));
        }
        for (int x = 0; x < 5; ++x) {
            d[x] = _mm256_xor_si256(c[(x + 4) % 5], rotl64_avx2(c[(x + 1) % 5], 1));
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                state[x + 5 * y] = _mm256_xor_si256(state[x + 5 * y], d[x]);
            }
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                const int index = x + 5 * y;
                const int dest_x = y;
                const int dest_y = (2 * x + 3 * y) % 5;
                b[dest_x + 5 * dest_y] = rotl64_avx2(state[index], kKeccakRhoOffsets[index]);
            }
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                const __m256i lane = b[x + 5 * y];
                const __m256i lane1 = b[((x + 1) % 5) + 5 * y];
                const __m256i lane2 = b[((x + 2) % 5) + 5 * y];
                state[x + 5 * y] = _mm256_xor_si256(lane, _mm256_andnot_si256(lane1, lane2));
            }
        }
        state[0] = _mm256_xor_si256(state[0], _mm256_set1_epi64x(static_cast<long long>(kKeccakRoundConstants[round])));
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("avx2")))
#endif
void finalize_suffix_batch4_x86_64(const std::array<uint64_t, 25>& prefix_state,
                                   uint32_t bits,
                                   const std::array<uint32_t, 4>& nonces,
                                   std::array<std::array<uint8_t, constants::POW_HASH_BYTES>, 4>& hashes) {
    __m256i state[25];
    for (size_t lane = 0; lane < 25; ++lane) {
        state[lane] = _mm256_set1_epi64x(static_cast<long long>(prefix_state[lane]));
    }

    alignas(32) uint64_t suffix_words[4] = {
        static_cast<uint64_t>(bits) | (static_cast<uint64_t>(nonces[0]) << 32),
        static_cast<uint64_t>(bits) | (static_cast<uint64_t>(nonces[1]) << 32),
        static_cast<uint64_t>(bits) | (static_cast<uint64_t>(nonces[2]) << 32),
        static_cast<uint64_t>(bits) | (static_cast<uint64_t>(nonces[3]) << 32),
    };

    state[0] = _mm256_xor_si256(state[0], _mm256_load_si256(reinterpret_cast<const __m256i*>(suffix_words)));
    state[1] = _mm256_xor_si256(state[1], _mm256_set1_epi64x(0x06));
    state[8] = _mm256_xor_si256(state[8], _mm256_set1_epi64x(static_cast<long long>(1ull << 63)));
    keccakf4x_avx2(state);

    alignas(32) uint64_t lane_words[4];
    for (auto& hash : hashes) {
        hash.fill(0);
    }
    for (size_t lane = 0; lane < 8; ++lane) {
        _mm256_store_si256(reinterpret_cast<__m256i*>(lane_words), state[lane]);
        for (size_t candidate = 0; candidate < 4; ++candidate) {
            write_u64_le_bytes(hashes[candidate].data() + lane * 8, lane_words[candidate]);
        }
    }
}

NonceSearchResult run_nonce_search_x86_64(const std::array<uint64_t, 25>& prefix_state,
                                          uint32_t bits,
                                          const std::array<uint8_t, constants::POW_HASH_BYTES>& target_bytes,
                                          uint32_t start_nonce,
                                          uint32_t nonce_step,
                                          uint64_t max_iterations,
                                          bool use_avx2) {
    NonceSearchResult result;
    uint32_t nonce = start_nonce;

    while (max_iterations == 0 || result.iterations < max_iterations) {
        if (use_avx2) {
            const uint64_t remaining = max_iterations == 0
                ? 4
                : std::min<uint64_t>(4, max_iterations - result.iterations);
            std::array<uint32_t, 4> nonces{nonce, nonce + nonce_step, nonce + nonce_step * 2u, nonce + nonce_step * 3u};
            std::array<std::array<uint8_t, constants::POW_HASH_BYTES>, 4> hashes{};
            finalize_suffix_batch4_x86_64(prefix_state, bits, nonces, hashes);
            for (size_t i = 0; i < remaining; ++i) {
                ++result.iterations;
                result.hash = hashes[i];
                result.next_nonce = nonces[i] + nonce_step;
                if (hash_meets_target_x86_64(hashes[i], target_bytes, true)) {
                    result.found = true;
                    result.nonce = nonces[i];
                    return result;
                }
            }
            nonce = nonces[static_cast<size_t>(remaining - 1)] + nonce_step;
            continue;
        }

        result.hash = finalize_suffix_scalar_x86_64(prefix_state, bits, nonce);
        ++result.iterations;
        result.next_nonce = nonce + nonce_step;
        if (hash_meets_target_x86_64(result.hash, target_bytes, false)) {
            result.found = true;
            result.nonce = nonce;
            return result;
        }
        nonce += nonce_step;
    }

    return result;
}

PowWorkerResult run_worker_job_x86_64(const PowWorkerJob& job) {
    PowWorkerResult result;
    const bool use_avx2 = cpu_supports_avx2();
    const auto prefix_state = prepare_prefix_state_x86_64(job.header);
    const uint32_t bits = read_u32_le(job.header.data() + 72);
    uint32_t nonce = job.start_nonce;
    constexpr uint64_t kChunkIterations = 4096;

    while (job.max_iterations == 0 || result.iterations < job.max_iterations) {
        const uint64_t remaining = job.max_iterations == 0
            ? kChunkIterations
            : std::min<uint64_t>(kChunkIterations, job.max_iterations - result.iterations);
        const auto chunk = run_nonce_search_x86_64(prefix_state,
                                                   bits,
                                                   job.target,
                                                   nonce,
                                                   job.nonce_step,
                                                   remaining,
                                                   use_avx2);
        if (chunk.iterations == 0) {
            break;
        }
        result.iterations += chunk.iterations;
        result.hash = chunk.hash;
        nonce = chunk.next_nonce;
        if (chunk.found) {
            result.found = true;
            result.nonce = chunk.nonce;
            return result;
        }
    }

    return result;
}
#endif

bool write_binary_file(const std::filesystem::path& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return out.good();
}

std::optional<PowWorkerJob> decode_worker_job(const std::vector<uint8_t>& payload) {
    if (payload.size() != 168) return std::nullopt;
    if (!std::equal(std::begin(kPowWorkerJobMagic), std::end(kPowWorkerJobMagic), payload.begin())) {
        return std::nullopt;
    }
    PowWorkerJob job;
    std::memcpy(job.header.data(), payload.data() + 8, job.header.size());
    std::memcpy(job.target.data(), payload.data() + 88, job.target.size());
    job.start_nonce = read_u32_le(payload.data() + 152);
    job.nonce_step = read_u32_le(payload.data() + 156);
    job.max_iterations = read_u64_le(payload.data() + 160);
    if (job.nonce_step == 0) job.nonce_step = 1;
    return job;
}

std::vector<uint8_t> encode_worker_result(const PowWorkerResult& result) {
    std::vector<uint8_t> payload;
    payload.reserve(88);
    payload.insert(payload.end(), std::begin(kPowWorkerResultMagic), std::end(kPowWorkerResultMagic));
    append_u32_le(payload, result.found ? 1u : 0u);
    append_u32_le(payload, result.nonce);
    append_u64_le(payload, result.iterations);
    payload.insert(payload.end(), result.hash.begin(), result.hash.end());
    return payload;
}

std::string format_rate(double hps) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    if (hps >= 1e9) ss << (hps / 1e9) << " GH/s";
    else if (hps >= 1e6) ss << (hps / 1e6) << " MH/s";
    else if (hps >= 1e3) ss << (hps / 1e3) << " kH/s";
    else ss << hps << " H/s";
    return ss.str();
}

std::optional<std::filesystem::path> home_directory() {
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

std::filesystem::path system_default_data_dir() {
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

std::filesystem::path network_default_data_dir(NetworkKind network) {
    auto base = system_default_data_dir();
    const auto& network_params = params_for(network);
    if (network == NetworkKind::Mainnet || std::string(network_params.data_dir_suffix).empty()) {
        return base;
    }
    return base / network_params.data_dir_suffix;
}

std::filesystem::path prepare_data_dir(std::filesystem::path path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    return path;
}

std::string format_sync_status(const net::NetworkNode::SyncStatus& status) {
    std::ostringstream ss;
    ss << "local=" << status.local_height
       << " peer=" << status.best_peer_height
       << " queued=" << status.queued_blocks
       << " inflight=" << status.inflight_blocks
       << " peers=" << status.connected_peers
       << " valid=" << status.validated_peers;
    return ss.str();
}

bool wait_for_mining_sync(net::NetworkNode& node, uint64_t max_wait_ms, bool verbose) {
    using namespace std::chrono_literals;

    const auto start = std::chrono::steady_clock::now();
    auto last_report = start - 1s;
    bool saw_peer = false;

    while (true) {
        auto status = node.sync_status();
        saw_peer = saw_peer || status.validated_peers > 0 || status.best_peer_height > 0;

        const bool caught_up =
            status.validated_peers > 0 &&
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

        if (saw_peer && !status.syncing && status.validated_peers > 0) {
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

void write_u32_le(std::array<uint8_t, 80>& buffer, size_t offset, uint32_t value) {
    buffer[offset + 0] = static_cast<uint8_t>(value & 0xFF);
    buffer[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buffer[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

std::array<uint8_t, 80> serialize_header_fast(const BlockHeader& header) {
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

bool hash_meets_target(const std::array<uint8_t, constants::POW_HASH_BYTES>& hash_bytes,
                       const std::array<uint8_t, constants::POW_HASH_BYTES>& target_bytes) {
    return hash_meets_target_scalar(hash_bytes, target_bytes);
}

PowWorkerResult run_worker_job(const PowWorkerJob& job) {
#if defined(__x86_64__) || defined(_M_X64)
    return run_worker_job_x86_64(job);
#else
    PowWorkerResult result;
    crypto::SHA3_512_Hasher prefix_hasher;
    prefix_hasher.update(job.header.data(), 76);
    const auto search = run_nonce_search_scalar(job.header,
                                                job.target,
                                                prefix_hasher,
                                                job.start_nonce,
                                                job.nonce_step,
                                                job.max_iterations);
    result.found = search.found;
    result.nonce = search.nonce;
    result.iterations = search.iterations;
    result.hash = search.hash;
    return result;
#endif
}

int maybe_run_worker_protocol_mode(int argc, char* argv[]) {
    if (argc != 3) return -1;
    const std::filesystem::path job_path = argv[1];
    const std::filesystem::path result_path = argv[2];
    auto payload = read_binary_file(job_path);
    auto job = decode_worker_job(payload);
    if (!job) return -1;
    const auto result = run_worker_job(*job);
    if (!write_binary_file(result_path, encode_worker_result(result))) {
        std::cerr << "failed to write pow worker result\n";
        return 1;
    }
    return 0;
}

template <size_t N>
std::string short_hex(const std::array<uint8_t, N>& bytes, size_t chars = 16) {
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

std::string format_mining_status(uint64_t iterations,
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

std::vector<uint8_t> make_coinbase_script_sig(uint64_t height,
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

Block build_template(Blockchain& chain, const std::string& coinbase_addr) {
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

std::string lower_hex(const unsigned char* data, size_t len) {
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

void usage() {
    std::cout << "cryptex external pow miner\n"
              << "usage: cryptex_powminer [--network mainnet|testnet|regtest] [--mainnet|--testnet|--regtest] mine "
              << "[--cycles N] [--block-cycles N] [--datadir path] [--connect host:port] [--address addr] [--threads N] [--sync-wait-ms N] [--proxy host:port] [--proxydns 0|1] [--debug]\n";
}

} // namespace

extern "C" int cryptex_powminer_entry(int argc, char** argv) {
    if (const int worker_mode_rc = maybe_run_worker_protocol_mode(argc, argv); worker_mode_rc >= 0) {
        return worker_mode_rc;
    }
    if (argc < 2) {
        usage();
        return 1;
    }

    NetworkKind network = NetworkKind::Mainnet;
    std::filesystem::path datadir;
    std::string cmd;
    int cmd_index = -1;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--network" && i + 1 < argc) {
            network = parse_network_name(argv[++i]);
        } else if (arg == "--testnet") {
            network = NetworkKind::Testnet;
        } else if (arg == "--regtest") {
            network = NetworkKind::Regtest;
        } else if (arg == "--mainnet") {
            network = NetworkKind::Mainnet;
        } else if (arg == "mine") {
            cmd = arg;
            cmd_index = i;
            break;
        }
    }
    if (cmd != "mine") {
        usage();
        return 1;
    }

    uint64_t cycles = 10'000'000;
    uint64_t block_cycles = 1;
    std::string hostport;
    std::string coinbase_addr = "genesis";
    bool debug = false;
    bool infinite = false;
    bool infinite_block_cycles = false;
    unsigned int thread_count = std::max(1u, std::thread::hardware_concurrency());
    uint64_t sync_wait_ms = 0;
    std::string proxy_host;
    uint16_t proxy_port = 0;
    bool proxy_remote_dns = true;

    select_network(network);
    datadir = network_default_data_dir(network);

    for (int i = cmd_index + 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--cycles" && i + 1 < argc) cycles = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--block-cycles" && i + 1 < argc) block_cycles = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--datadir" && i + 1 < argc) datadir = argv[++i];
        else if (arg == "--connect" && i + 1 < argc) hostport = argv[++i];
        else if (arg == "--address" && i + 1 < argc) coinbase_addr = argv[++i];
        else if (arg == "--debug") debug = true;
        else if (arg == "--threads" && i + 1 < argc) thread_count = static_cast<unsigned int>(std::stoul(argv[++i]));
        else if (arg == "--sync-wait-ms" && i + 1 < argc) sync_wait_ms = std::strtoull(argv[++i], nullptr, 10);
        else if (arg == "--proxy" && i + 1 < argc) {
            const auto value = std::string(argv[++i]);
            const auto pos = value.rfind(':');
            if (pos != std::string::npos) {
                proxy_host = value.substr(0, pos);
                proxy_port = static_cast<uint16_t>(std::stoul(value.substr(pos + 1)));
            }
        } else if (arg == "--proxydns" && i + 1 < argc) {
            proxy_remote_dns = std::string(argv[++i]) != "0";
        }
    }

    datadir = prepare_data_dir(datadir);
    if (cycles == 0) infinite = true;
    if (block_cycles == 0) infinite_block_cycles = true;
    set_debug(debug);

    std::cout << "[powminer] external SHA3-512 worker starting threads=" << thread_count
              << " datadir=" << datadir.string()
              << " address=" << coinbase_addr
              << (infinite ? " cycles=infinite" : " cycles=" + std::to_string(cycles))
              << (infinite_block_cycles ? " block_cycles=infinite" : " block_cycles=" + std::to_string(block_cycles))
              << "\n";
#if defined(__x86_64__) || defined(_M_X64)
    std::cout << "[powminer] x86_64 backend="
              << (cpu_supports_avx2() ? "batched-avx2-compare" : "batched-scalar")
              << "\n";
#endif

    Blockchain chain(datadir);
    if (hostport.empty() && !chain.wallet_state_approved()) {
        std::cout << "[policy] offline mining is allowed, but this datadir is currently behind an observed network tip"
                  << " (network height " << chain.approval_network_height() << ")."
                  << " New rewards will stay locked until the chain catches up or is revalidated.\n";
    }

    boost::asio::io_context ctx;
    std::unique_ptr<net::NetworkNode> node;
    std::unique_ptr<std::thread> net_thread;
    if (!hostport.empty()) {
        node = std::make_unique<net::NetworkNode>(ctx, 0, datadir);
        if (!proxy_host.empty() && proxy_port != 0) {
            node->set_socks5_proxy(proxy_host, proxy_port, proxy_remote_dns);
        }
        node->attach_blockchain(&chain);
        node->best_height = chain.best_height();
        node->start();
        const auto pos = hostport.find(':');
        if (pos != std::string::npos) {
            node->connect(hostport.substr(0, pos), static_cast<uint16_t>(std::stoi(hostport.substr(pos + 1))));
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

        std::atomic<uint64_t> job_version{0};
        std::mutex job_mutex;
        Block current_job = build_template(chain, coinbase_addr);

        std::mutex cout_mutex;
        std::atomic<size_t> status_width{0};

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
#if defined(__x86_64__) || defined(_M_X64)
        const bool use_avx2 = cpu_supports_avx2();
#endif

        auto worker = [&](unsigned int tid) {
            Block local_job;
            std::array<uint8_t, constants::POW_HASH_BYTES> local_target_bytes{};
            std::array<uint8_t, 80> header_bytes{};
#if defined(__x86_64__) || defined(_M_X64)
            std::array<uint64_t, 25> prefix_state{};
            uint32_t header_bits = 0;
#else
            crypto::SHA3_512_Hasher prefix_hasher;
            crypto::SHA3_512_Hasher nonce_hasher;
#endif
            uint32_t nonce = tid;
            uint64_t local_job_version = 0;
#if defined(__x86_64__) || defined(_M_X64)
            constexpr uint64_t kBatchIterations = 256;
#endif

            {
                std::lock_guard<std::mutex> lock(job_mutex);
                local_job = current_job;
                auto target_vec = compact_target{local_job.header.bits}.expand().to_padded_bytes(constants::POW_HASH_BYTES);
                std::memcpy(local_target_bytes.data(), target_vec.data(), local_target_bytes.size());
                header_bytes = serialize_header_fast(local_job.header);
#if defined(__x86_64__) || defined(_M_X64)
                prefix_state = prepare_prefix_state_x86_64(header_bytes);
                header_bits = local_job.header.bits;
#else
                prefix_hasher.reset();
                prefix_hasher.update(header_bytes.data(), 76);
#endif
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
#if defined(__x86_64__) || defined(_M_X64)
                    prefix_state = prepare_prefix_state_x86_64(header_bytes);
                    header_bits = local_job.header.bits;
#else
                    prefix_hasher.reset();
                    prefix_hasher.update(header_bytes.data(), 76);
#endif
                    local_job_version = cur_ver;
                    nonce = tid;
                }

                std::array<uint8_t, constants::POW_HASH_BYTES> pow_hash{};
                uint64_t attempted = 0;
                bool ok = false;
                uint32_t candidate_nonce = nonce;
                uint32_t status_nonce = nonce;

#if defined(__x86_64__) || defined(_M_X64)
                const uint64_t current_total = iterations.load(std::memory_order_relaxed);
                if (!infinite && current_total >= cycles) {
                    break;
                }
                const uint64_t remaining = infinite
                    ? kBatchIterations
                    : std::max<uint64_t>(1, std::min<uint64_t>(
                          kBatchIterations,
                          (cycles - current_total + static_cast<uint64_t>(thread_count) - 1) /
                              static_cast<uint64_t>(thread_count)));
                const auto batch = run_nonce_search_x86_64(prefix_state,
                                                           header_bits,
                                                           local_target_bytes,
                                                           nonce,
                                                           thread_count,
                                                           remaining,
                                                           use_avx2);
                attempted = batch.iterations;
                pow_hash = batch.hash;
                ok = batch.found;
                candidate_nonce = batch.nonce;
                nonce = batch.next_nonce;
                if (attempted > 0) {
                    status_nonce = static_cast<uint32_t>(batch.next_nonce - thread_count);
                }
#else
                local_job.header.nonce = nonce;
                write_u32_le(header_bytes, 76, nonce);
                nonce_hasher.copy_state_from(prefix_hasher);
                nonce_hasher.update(header_bytes.data() + 76, 4);
                auto digest = nonce_hasher.finalize();
                std::memcpy(pow_hash.data(), digest.data(), pow_hash.size());
                attempted = 1;
                ok = hash_meets_target(pow_hash, local_target_bytes);
                candidate_nonce = nonce;
                status_nonce = nonce;
                nonce += thread_count;
#endif

                if (attempted == 0) {
                    break;
                }

                uint64_t cur_iter = iterations.fetch_add(attempted, std::memory_order_relaxed) + attempted;
                if (ok) {
                    if (!found.exchange(true)) {
                        std::lock_guard<std::mutex> lk(found_mutex);
                        found_block = local_job;
                        found_block.header.nonce = candidate_nonce;
                        found_hash = uint256_t::from_bytes(pow_hash.data(), pow_hash.size());
                        found_nonce = candidate_nonce;
                    }
                    break;
                }
                if (debug && tid == 0) {
                    auto now = std::chrono::steady_clock::now();
                    if (now - last_report_time >= status_interval) {
                        double secs = std::chrono::duration_cast<std::chrono::duration<double>>(now - last_report_time).count();
                        double rate = secs > 0 ? static_cast<double>(cur_iter - last_report_iter) / secs : 0.0;
                        std::string line = format_mining_status(cur_iter, status_nonce, pow_hash, rate);
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

            const auto previous_height = chain.best_height();
            if (!chain.connect_block(found_block) ||
                chain.tip_hash() != found_block.header.pow_hash() ||
                chain.best_height() != previous_height + 1) {
                log_warn("powminer", "block was found locally but rejected by chain");
                std::cerr << "ERROR: Block was rejected by the chain (stale or invalid)!\n";
            } else {
                bool approved_tip = true;
                uint64_t approval_peer_count = 0;
                uint64_t approval_network_height = 0;
                if (node) {
                    auto status = node->sync_status();
                    approval_peer_count = static_cast<uint64_t>(status.validated_peers);
                    approval_network_height = static_cast<uint64_t>(status.best_peer_height);
                    const bool saw_network = status.validated_peers > 0 || status.best_peer_height > 0;
                    approved_tip = !saw_network ||
                                   (!status.syncing && status.local_height >= status.best_peer_height);
                } else {
                    approval_peer_count = chain.approval_peer_count();
                    approval_network_height = chain.approval_network_height();
                    approved_tip = chain.wallet_state_approved();
                }
                chain.set_sync_approval(approved_tip, approval_peer_count, approval_network_height);
                ++blocks_mined;
                log_info("powminer", "block accepted at height " + std::to_string(chain.best_height()));
                std::cout << "Block successfully added to chain.\n";
                if (!approved_tip) {
                    std::cout << "[policy] block accepted locally, but funds remain locked until the chain is synced/approved.\n";
                }
                const auto block_bytes = found_block.serialize();
                std::cout << "MinedBlockHex: " << lower_hex(block_bytes.data(), block_bytes.size()) << "\n";
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

#if !defined(CRYPTEX_ASM_ENTRY_STUB)
int main(int argc, char** argv) {
    return cryptex_powminer_entry(argc, argv);
}
#endif
