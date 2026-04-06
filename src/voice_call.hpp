#pragma once

#include "chat_content.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cryptex {
namespace voice {

using SessionKey = std::array<uint8_t, 32>;

constexpr uint32_t CAPABILITY_AES_GCM = 1u << 0;
constexpr uint32_t CAPABILITY_OPUS = 1u << 1;
constexpr uint32_t CAPABILITY_AUDIO_CLOAK = 1u << 2;
constexpr uint32_t CAPABILITY_LIVE_WAVEFORM = 1u << 3;
constexpr uint8_t CODEC_OPUS = 1;

enum class SignalType : uint8_t {
    Offer = 0,
    Answer = 1,
    Decline = 2,
    Hangup = 3,
};

struct CallSignal {
    uint8_t version{2};
    SignalType type{SignalType::Offer};
    uint64_t timestamp{0};
    std::string call_id;
    std::string caller_address;
    std::string callee_address;
    std::string peer_label;
    std::string caller_pubkey_b64;
    std::string caller_rsa_public_pem;
    uint8_t encryption_mode{0};
    bool obfuscate_audio{false};
    uint32_t sample_rate{16000};
    uint16_t channels{1};
    uint16_t bits_per_sample{16};
    uint16_t frame_duration_ms{20};
    uint32_t capability_flags{CAPABILITY_AES_GCM | CAPABILITY_OPUS | CAPABILITY_AUDIO_CLOAK | CAPABILITY_LIVE_WAVEFORM};
    std::string codec{"opus"};
    std::string note;
};

struct AudioFrame {
    uint8_t version{2};
    uint64_t timestamp{0};
    uint64_t sequence{0};
    std::string call_id;
    uint32_t sample_rate{16000};
    uint16_t channels{1};
    uint16_t bits_per_sample{16};
    uint16_t frame_duration_ms{20};
    uint8_t codec{CODEC_OPUS};
    bool encrypted{true};
    bool obfuscated{false};
    std::vector<uint8_t> iv;
    std::vector<uint8_t> auth_tag;
    std::vector<uint8_t> encoded_audio;
    std::vector<uint8_t> pcm_bytes; // local-only decoded PCM, not serialized
};

chat::ContentEnvelope make_signal_content(const CallSignal& signal);
chat::ContentEnvelope make_audio_frame_content(const AudioFrame& frame);

std::optional<CallSignal> parse_signal_content(const chat::ContentEnvelope& content);
std::optional<AudioFrame> parse_audio_frame_content(const chat::ContentEnvelope& content);

SessionKey derive_session_key(const std::vector<uint8_t>& local_privkey,
                              const std::vector<uint8_t>& peer_pubkey,
                              const std::string& call_id,
                              const std::string& local_address,
                              const std::string& remote_address);

AudioFrame make_encrypted_audio_frame(const std::vector<uint8_t>& pcm_bytes,
                                      const SessionKey& session_key,
                                      const std::string& call_id,
                                      uint64_t timestamp_ms,
                                      uint64_t sequence,
                                      uint32_t sample_rate,
                                      uint16_t channels,
                                      uint16_t bits_per_sample,
                                      uint16_t frame_duration_ms,
                                      bool obfuscate_audio);

bool decrypt_audio_frame_inplace(AudioFrame& frame, const SessionKey& session_key);
std::vector<uint8_t> apply_voice_cloak(const std::vector<uint8_t>& pcm_bytes, uint16_t channels);
bool is_supported_opus_rate(uint32_t sample_rate);
const char* signal_type_name(SignalType type);
const char* codec_name(uint8_t codec);
std::string capability_summary(uint32_t capability_flags);

} // namespace voice
} // namespace cryptex
