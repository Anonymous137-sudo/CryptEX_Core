#include "voice_call.hpp"

#include "base64.hpp"
#include "serialization.hpp"
#include "sha3_512.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <opus.h>

namespace cryptex {
namespace voice {

namespace {

constexpr const char* kSignalMime = "application/x-cryptex-voice-signal";
constexpr const char* kFrameMime = "audio/x-cryptex-live-opus";
constexpr const char* kSignalAttachmentName = "voice-call.signal";
constexpr const char* kFrameAttachmentName = "voice-call-frame.opus";
constexpr size_t kFrameIvBytes = 12;
constexpr size_t kFrameTagBytes = 16;
constexpr int kOpusMaxPacketBytes = 4096;
constexpr int kOpusApplication = OPUS_APPLICATION_VOIP;
constexpr const char* kVoiceSessionDomain = "CryptexVoiceSessionV2";

uint64_t random_nonce64() {
    uint64_t value = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
        throw std::runtime_error("voice nonce generation failed");
    }
    return value;
}

std::vector<uint8_t> random_bytes(size_t size) {
    std::vector<uint8_t> out(size);
    if (!out.empty() && RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("voice random generation failed");
    }
    return out;
}

EVP_PKEY* load_private_key(const std::vector<uint8_t>& privkey) {
    const unsigned char* der_ptr = privkey.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &der_ptr, static_cast<long>(privkey.size()));
    if (!pkey) {
        throw std::runtime_error("voice private key decode failed");
    }
    return pkey;
}

EVP_PKEY* load_public_key(const std::vector<uint8_t>& pubkey) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!kctx) {
        throw std::runtime_error("voice public key context failed");
    }
    if (EVP_PKEY_fromdata_init(kctx) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("voice public key init failed");
    }
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 const_cast<char*>("secp256k1"),
                                                 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  const_cast<uint8_t*>(pubkey.data()),
                                                  pubkey.size());
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0 || !pkey) {
        EVP_PKEY_CTX_free(kctx);
        throw std::runtime_error("voice public key decode failed");
    }
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

std::vector<uint8_t> derive_ecdh_secret(const std::vector<uint8_t>& local_privkey,
                                        const std::vector<uint8_t>& peer_pubkey) {
    EVP_PKEY* self = load_private_key(local_privkey);
    EVP_PKEY* peer = load_public_key(peer_pubkey);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(self, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer);
        EVP_PKEY_free(self);
        throw std::runtime_error("voice ECDH context init failed");
    }
    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        EVP_PKEY_free(self);
        throw std::runtime_error("voice ECDH derive init failed");
    }
    size_t out_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &out_len) <= 0 || out_len == 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        EVP_PKEY_free(self);
        throw std::runtime_error("voice ECDH size failed");
    }
    std::vector<uint8_t> secret(out_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &out_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer);
        EVP_PKEY_free(self);
        throw std::runtime_error("voice ECDH derive failed");
    }
    secret.resize(out_len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(self);
    return secret;
}

std::vector<uint8_t> serialize_signal(const CallSignal& signal) {
    std::vector<uint8_t> out;
    out.push_back(signal.version);
    out.push_back(static_cast<uint8_t>(signal.type));
    serialization::write_int<uint64_t>(out, signal.timestamp);
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(signal.call_id.data()),
                               signal.call_id.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(signal.caller_address.data()),
                               signal.caller_address.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(signal.callee_address.data()),
                               signal.callee_address.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(signal.peer_label.data()),
                               signal.peer_label.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(signal.caller_pubkey_b64.data()),
                               signal.caller_pubkey_b64.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(signal.caller_rsa_public_pem.data()),
                               signal.caller_rsa_public_pem.size());
    out.push_back(signal.encryption_mode);
    out.push_back(signal.obfuscate_audio ? 1 : 0);
    serialization::write_int<uint32_t>(out, signal.sample_rate);
    serialization::write_int<uint16_t>(out, signal.channels);
    serialization::write_int<uint16_t>(out, signal.bits_per_sample);
    serialization::write_int<uint16_t>(out, signal.frame_duration_ms);
    serialization::write_int<uint32_t>(out, signal.capability_flags);
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(signal.codec.data()),
                               signal.codec.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(signal.note.data()),
                               signal.note.size());
    return out;
}

CallSignal deserialize_signal(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 2 + sizeof(uint64_t)) {
        throw std::runtime_error("voice call signal truncated");
    }
    const uint8_t* ptr = bytes.data();
    size_t remaining = bytes.size();
    CallSignal signal;
    signal.version = serialization::read_int<uint8_t>(ptr, remaining);
    signal.type = static_cast<SignalType>(serialization::read_int<uint8_t>(ptr, remaining));
    signal.timestamp = serialization::read_int<uint64_t>(ptr, remaining);
    auto call_id = serialization::read_bytes(ptr, remaining);
    auto caller = serialization::read_bytes(ptr, remaining);
    auto callee = serialization::read_bytes(ptr, remaining);
    auto peer = serialization::read_bytes(ptr, remaining);
    auto caller_pubkey = serialization::read_bytes(ptr, remaining);
    auto caller_rsa = serialization::read_bytes(ptr, remaining);
    signal.call_id.assign(call_id.begin(), call_id.end());
    signal.caller_address.assign(caller.begin(), caller.end());
    signal.callee_address.assign(callee.begin(), callee.end());
    signal.peer_label.assign(peer.begin(), peer.end());
    signal.caller_pubkey_b64.assign(caller_pubkey.begin(), caller_pubkey.end());
    signal.caller_rsa_public_pem.assign(caller_rsa.begin(), caller_rsa.end());
    signal.encryption_mode = serialization::read_int<uint8_t>(ptr, remaining);
    signal.obfuscate_audio = serialization::read_int<uint8_t>(ptr, remaining) != 0;
    signal.sample_rate = serialization::read_int<uint32_t>(ptr, remaining);
    signal.channels = serialization::read_int<uint16_t>(ptr, remaining);
    signal.bits_per_sample = serialization::read_int<uint16_t>(ptr, remaining);
    signal.frame_duration_ms = signal.version >= 2 ? serialization::read_int<uint16_t>(ptr, remaining) : 20;
    signal.capability_flags = signal.version >= 2 ? serialization::read_int<uint32_t>(ptr, remaining)
                                                  : (CAPABILITY_AES_GCM | CAPABILITY_OPUS);
    auto codec = signal.version >= 2 ? serialization::read_bytes(ptr, remaining) : std::vector<uint8_t>{};
    auto note = serialization::read_bytes(ptr, remaining);
    signal.codec.assign(codec.begin(), codec.end());
    if (signal.codec.empty()) {
        signal.codec = "opus";
    }
    signal.note.assign(note.begin(), note.end());
    return signal;
}

std::vector<uint8_t> build_frame_aad(const AudioFrame& frame) {
    std::vector<uint8_t> out;
    out.push_back(frame.version);
    serialization::write_int<uint64_t>(out, frame.timestamp);
    serialization::write_int<uint64_t>(out, frame.sequence);
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(frame.call_id.data()),
                               frame.call_id.size());
    serialization::write_int<uint32_t>(out, frame.sample_rate);
    serialization::write_int<uint16_t>(out, frame.channels);
    serialization::write_int<uint16_t>(out, frame.bits_per_sample);
    serialization::write_int<uint16_t>(out, frame.frame_duration_ms);
    out.push_back(frame.codec);
    out.push_back(frame.encrypted ? 1 : 0);
    out.push_back(frame.obfuscated ? 1 : 0);
    return out;
}

std::vector<uint8_t> serialize_audio_frame(const AudioFrame& frame) {
    std::vector<uint8_t> out = build_frame_aad(frame);
    serialization::write_bytes(out, frame.iv.data(), frame.iv.size());
    serialization::write_bytes(out, frame.auth_tag.data(), frame.auth_tag.size());
    serialization::write_bytes(out, frame.encoded_audio.data(), frame.encoded_audio.size());
    return out;
}

AudioFrame deserialize_audio_frame(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 1 + sizeof(uint64_t) * 2) {
        throw std::runtime_error("voice call frame truncated");
    }
    const uint8_t* ptr = bytes.data();
    size_t remaining = bytes.size();
    AudioFrame frame;
    frame.version = serialization::read_int<uint8_t>(ptr, remaining);
    frame.timestamp = serialization::read_int<uint64_t>(ptr, remaining);
    frame.sequence = serialization::read_int<uint64_t>(ptr, remaining);
    auto call_id = serialization::read_bytes(ptr, remaining);
    frame.call_id.assign(call_id.begin(), call_id.end());
    frame.sample_rate = serialization::read_int<uint32_t>(ptr, remaining);
    frame.channels = serialization::read_int<uint16_t>(ptr, remaining);
    frame.bits_per_sample = serialization::read_int<uint16_t>(ptr, remaining);
    frame.frame_duration_ms = frame.version >= 2 ? serialization::read_int<uint16_t>(ptr, remaining) : 20;
    frame.codec = frame.version >= 2 ? serialization::read_int<uint8_t>(ptr, remaining) : CODEC_OPUS;
    frame.encrypted = frame.version >= 2 ? serialization::read_int<uint8_t>(ptr, remaining) != 0 : true;
    frame.obfuscated = serialization::read_int<uint8_t>(ptr, remaining) != 0;
    frame.iv = serialization::read_bytes(ptr, remaining);
    frame.auth_tag = serialization::read_bytes(ptr, remaining);
    frame.encoded_audio = serialization::read_bytes(ptr, remaining);
    return frame;
}

void aes256_gcm_encrypt(const std::vector<uint8_t>& plaintext,
                        const SessionKey& key,
                        const std::vector<uint8_t>& aad,
                        std::vector<uint8_t>& iv,
                        std::vector<uint8_t>& ciphertext,
                        std::vector<uint8_t>& tag) {
    iv = random_bytes(kFrameIvBytes);
    ciphertext.assign(plaintext.size(), 0);
    tag.assign(kFrameTagBytes, 0);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("voice encrypt ctx failed");
    }
    int len = 0;
    int written = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice encrypt init failed");
    }
    if (!aad.empty() && EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice encrypt aad failed");
    }
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx, ciphertext.data(), &written, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice encrypt failed");
    }
    len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + written, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice encrypt final failed");
    }
    ciphertext.resize(static_cast<size_t>(written + len));
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice encrypt tag failed");
    }
    EVP_CIPHER_CTX_free(ctx);
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& ciphertext,
                                        const SessionKey& key,
                                        const std::vector<uint8_t>& aad,
                                        const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("voice decrypt ctx failed");
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice decrypt init failed");
    }
    int len = 0;
    int written = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice decrypt aad failed");
    }
    std::vector<uint8_t> plaintext(ciphertext.size());
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &written, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice decrypt failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice decrypt tag set failed");
    }
    len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + written, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("voice authentication failed");
    }
    plaintext.resize(static_cast<size_t>(written + len));
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

int opus_frame_size(uint32_t sample_rate, uint16_t frame_duration_ms) {
    return static_cast<int>((static_cast<uint64_t>(sample_rate) * frame_duration_ms) / 1000ull);
}

std::vector<uint8_t> encode_opus_frame(const std::vector<uint8_t>& pcm_bytes,
                                       uint32_t sample_rate,
                                       uint16_t channels) {
    if (pcm_bytes.empty()) {
        return {};
    }
    if ((pcm_bytes.size() % (sizeof(opus_int16) * channels)) != 0) {
        throw std::runtime_error("voice PCM frame alignment invalid for Opus encode");
    }
    const int frame_size = static_cast<int>(pcm_bytes.size() / (sizeof(opus_int16) * channels));
    std::vector<opus_int16> pcm(static_cast<size_t>(frame_size) * channels);
    std::memcpy(pcm.data(), pcm_bytes.data(), pcm_bytes.size());

    int opus_error = OPUS_OK;
    OpusEncoder* encoder = opus_encoder_create(static_cast<opus_int32>(sample_rate),
                                               channels,
                                               kOpusApplication,
                                               &opus_error);
    if (opus_error != OPUS_OK || !encoder) {
        throw std::runtime_error("voice Opus encoder creation failed");
    }
    opus_encoder_ctl(encoder, OPUS_SET_BITRATE(OPUS_AUTO));
    opus_encoder_ctl(encoder, OPUS_SET_COMPLEXITY(8));
    opus_encoder_ctl(encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));

    std::vector<uint8_t> encoded(kOpusMaxPacketBytes);
    const int encoded_len = opus_encode(encoder, pcm.data(), frame_size, encoded.data(), static_cast<opus_int32>(encoded.size()));
    opus_encoder_destroy(encoder);
    if (encoded_len < 0) {
        throw std::runtime_error(std::string("voice Opus encode failed: ") + opus_strerror(encoded_len));
    }
    encoded.resize(static_cast<size_t>(encoded_len));
    return encoded;
}

std::vector<uint8_t> decode_opus_frame(const std::vector<uint8_t>& encoded_bytes,
                                       uint32_t sample_rate,
                                       uint16_t channels,
                                       uint16_t frame_duration_ms) {
    if (encoded_bytes.empty()) {
        return {};
    }
    int opus_error = OPUS_OK;
    OpusDecoder* decoder = opus_decoder_create(static_cast<opus_int32>(sample_rate), channels, &opus_error);
    if (opus_error != OPUS_OK || !decoder) {
        throw std::runtime_error("voice Opus decoder creation failed");
    }
    const int max_frame_samples = std::max(opus_frame_size(sample_rate, std::max<uint16_t>(frame_duration_ms, 20)),
                                           opus_frame_size(sample_rate, 60));
    std::vector<opus_int16> pcm(static_cast<size_t>(max_frame_samples) * channels);
    const int decoded_samples = opus_decode(decoder,
                                            encoded_bytes.data(),
                                            static_cast<opus_int32>(encoded_bytes.size()),
                                            pcm.data(),
                                            max_frame_samples,
                                            0);
    opus_decoder_destroy(decoder);
    if (decoded_samples < 0) {
        throw std::runtime_error("voice Opus decode failed");
    }
    std::vector<uint8_t> out(static_cast<size_t>(decoded_samples) * channels * sizeof(opus_int16));
    std::memcpy(out.data(), pcm.data(), out.size());
    return out;
}

} // namespace

chat::ContentEnvelope make_signal_content(const CallSignal& signal) {
    chat::ContentEnvelope content;
    content.type = chat::ContentType::VoiceControl;
    content.mime_type = kSignalMime;
    content.attachment_name = kSignalAttachmentName;
    content.attachment_bytes = serialize_signal(signal);
    return content;
}

chat::ContentEnvelope make_audio_frame_content(const AudioFrame& frame) {
    chat::ContentEnvelope content;
    content.type = chat::ContentType::VoiceFrame;
    content.mime_type = kFrameMime;
    content.attachment_name = kFrameAttachmentName;
    content.audio_privacy = frame.obfuscated ? chat::AudioPrivacy::Deepened : chat::AudioPrivacy::None;
    content.attachment_bytes = serialize_audio_frame(frame);
    return content;
}

std::optional<CallSignal> parse_signal_content(const chat::ContentEnvelope& content) {
    if (content.type != chat::ContentType::VoiceControl) {
        return std::nullopt;
    }
    return deserialize_signal(content.attachment_bytes);
}

std::optional<AudioFrame> parse_audio_frame_content(const chat::ContentEnvelope& content) {
    if (content.type != chat::ContentType::VoiceFrame) {
        return std::nullopt;
    }
    return deserialize_audio_frame(content.attachment_bytes);
}

SessionKey derive_session_key(const std::vector<uint8_t>& local_privkey,
                              const std::vector<uint8_t>& peer_pubkey,
                              const std::string& call_id,
                              const std::string& local_address,
                              const std::string& remote_address) {
    auto shared_secret = derive_ecdh_secret(local_privkey, peer_pubkey);
    std::vector<uint8_t> material;
    material.reserve(shared_secret.size() + call_id.size() + local_address.size() + remote_address.size() + 32);
    material.insert(material.end(), shared_secret.begin(), shared_secret.end());
    material.insert(material.end(), kVoiceSessionDomain, kVoiceSessionDomain + std::strlen(kVoiceSessionDomain));
    const auto [left, right] = std::minmax(local_address, remote_address);
    material.insert(material.end(), left.begin(), left.end());
    material.push_back('|');
    material.insert(material.end(), right.begin(), right.end());
    material.push_back('|');
    material.insert(material.end(), call_id.begin(), call_id.end());
    auto digest = crypto::sha3_512(material);
    SessionKey key{};
    std::memcpy(key.data(), digest.data(), key.size());
    return key;
}

AudioFrame make_encrypted_audio_frame(const std::vector<uint8_t>& pcm_bytes,
                                      const SessionKey& session_key,
                                      const std::string& call_id,
                                      uint64_t timestamp_ms,
                                      uint64_t sequence,
                                      uint32_t sample_rate,
                                      uint16_t channels,
                                      uint16_t bits_per_sample,
                                      uint16_t frame_duration_ms,
                                      bool obfuscate_audio) {
    if (!is_supported_opus_rate(sample_rate)) {
        throw std::runtime_error("voice sample rate unsupported for Opus");
    }
    if (channels == 0 || channels > 2) {
        throw std::runtime_error("voice channel count unsupported for Opus");
    }
    if (bits_per_sample != 16) {
        throw std::runtime_error("voice transport currently requires 16-bit PCM input");
    }

    AudioFrame frame;
    frame.timestamp = timestamp_ms;
    frame.sequence = sequence;
    frame.call_id = call_id;
    frame.sample_rate = sample_rate;
    frame.channels = channels;
    frame.bits_per_sample = bits_per_sample;
    frame.frame_duration_ms = frame_duration_ms;
    frame.codec = CODEC_OPUS;
    frame.encrypted = true;
    frame.obfuscated = obfuscate_audio;

    std::vector<uint8_t> processed = obfuscate_audio ? apply_voice_cloak(pcm_bytes, channels) : pcm_bytes;
    frame.pcm_bytes = processed;
    const auto encoded = encode_opus_frame(processed, sample_rate, channels);
    frame.encoded_audio = encoded;
    const auto aad = build_frame_aad(frame);
    aes256_gcm_encrypt(encoded, session_key, aad, frame.iv, frame.encoded_audio, frame.auth_tag);
    return frame;
}

bool decrypt_audio_frame_inplace(AudioFrame& frame, const SessionKey& session_key) {
    try {
        if (frame.codec != CODEC_OPUS) {
            throw std::runtime_error("voice codec unsupported");
        }
        const auto aad = build_frame_aad(frame);
        const auto encoded = frame.encrypted
            ? aes256_gcm_decrypt(frame.encoded_audio, session_key, aad, frame.iv, frame.auth_tag)
            : frame.encoded_audio;
        frame.pcm_bytes = decode_opus_frame(encoded, frame.sample_rate, frame.channels, frame.frame_duration_ms);
        return true;
    } catch (...) {
        frame.pcm_bytes.clear();
        return false;
    }
}

std::vector<uint8_t> apply_voice_cloak(const std::vector<uint8_t>& pcm_bytes, uint16_t channels) {
    if (pcm_bytes.empty() || channels == 0 || (pcm_bytes.size() % (channels * 2)) != 0) {
        return pcm_bytes;
    }
    const int frame_count = static_cast<int>(pcm_bytes.size() / (channels * 2));
    if (frame_count <= 0) {
        return pcm_bytes;
    }

    const auto* input = reinterpret_cast<const int16_t*>(pcm_bytes.data());
    constexpr double kPitchFactor = 0.82;
    const int output_frames = frame_count;
    std::vector<uint8_t> out(static_cast<size_t>(output_frames) * channels * 2);
    auto* output = reinterpret_cast<int16_t*>(out.data());

    auto sample_at = [&](int frame, int channel) -> int16_t {
        return input[(frame * channels) + channel];
    };

    for (int out_frame = 0; out_frame < output_frames; ++out_frame) {
        const double src_pos = std::min<double>(frame_count - 1, out_frame * kPitchFactor);
        const int base = static_cast<int>(src_pos);
        const int next = std::min(frame_count - 1, base + 1);
        const double alpha = src_pos - base;
        for (int channel = 0; channel < channels; ++channel) {
            const double left = static_cast<double>(sample_at(base, channel));
            const double right = static_cast<double>(sample_at(next, channel));
            double sample = left + ((right - left) * alpha);
            if (out_frame > 0) {
                const double prev = static_cast<double>(output[((out_frame - 1) * channels) + channel]);
                sample = (sample * 0.78) + (prev * 0.22);
            }
            output[(out_frame * channels) + channel] = static_cast<int16_t>(std::clamp(sample, -32768.0, 32767.0));
        }
    }
    return out;
}

bool is_supported_opus_rate(uint32_t sample_rate) {
    switch (sample_rate) {
    case 8000:
    case 12000:
    case 16000:
    case 24000:
    case 48000:
        return true;
    default:
        return false;
    }
}

const char* signal_type_name(SignalType type) {
    switch (type) {
    case SignalType::Offer:
        return "offer";
    case SignalType::Answer:
        return "answer";
    case SignalType::Decline:
        return "decline";
    case SignalType::Hangup:
        return "hangup";
    }
    return "offer";
}

const char* codec_name(uint8_t codec) {
    switch (codec) {
    case CODEC_OPUS:
        return "opus";
    default:
        return "unknown";
    }
}

std::string capability_summary(uint32_t capability_flags) {
    std::vector<std::string> parts;
    if ((capability_flags & CAPABILITY_OPUS) != 0) {
        parts.emplace_back("Opus");
    }
    if ((capability_flags & CAPABILITY_AES_GCM) != 0) {
        parts.emplace_back("AES-GCM");
    }
    if ((capability_flags & CAPABILITY_AUDIO_CLOAK) != 0) {
        parts.emplace_back("voice-cloak");
    }
    if ((capability_flags & CAPABILITY_LIVE_WAVEFORM) != 0) {
        parts.emplace_back("live-waveform");
    }
    if (parts.empty()) {
        return "none";
    }
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            out += ", ";
        }
        out += parts[i];
    }
    return out;
}

} // namespace voice
} // namespace cryptex
