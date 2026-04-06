#include "chat_content.hpp"

#include "constants.hpp"
#include "serialization.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <system_error>

namespace cryptex {
namespace chat {

namespace {

constexpr std::array<uint8_t, 4> CONTENT_MAGIC{{'C', 'X', 'M', '1'}};
constexpr size_t MAX_CHAT_ATTACHMENT_BYTES = 6'000'000;

uint16_t read_le16(const uint8_t* ptr) {
    return static_cast<uint16_t>(ptr[0]) |
           (static_cast<uint16_t>(ptr[1]) << 8);
}

uint32_t read_le32(const uint8_t* ptr) {
    return static_cast<uint32_t>(ptr[0]) |
           (static_cast<uint32_t>(ptr[1]) << 8) |
           (static_cast<uint32_t>(ptr[2]) << 16) |
           (static_cast<uint32_t>(ptr[3]) << 24);
}

void write_le16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void write_le32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::vector<uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open attachment file");
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(input)),
                                std::istreambuf_iterator<char>());
}

std::string detect_mime_type(const std::filesystem::path& path, ContentType type) {
    const auto ext = lower_copy(path.extension().string());
    switch (type) {
    case ContentType::Image:
        if (ext == ".png") return "image/png";
        if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
        if (ext == ".gif") return "image/gif";
        if (ext == ".webp") return "image/webp";
        if (ext == ".bmp") return "image/bmp";
        return "image/octet-stream";
    case ContentType::Video:
        if (ext == ".mp4") return "video/mp4";
        if (ext == ".mov") return "video/quicktime";
        if (ext == ".webm") return "video/webm";
        if (ext == ".mkv") return "video/x-matroska";
        if (ext == ".avi") return "video/x-msvideo";
        return "video/octet-stream";
    case ContentType::Audio:
        if (ext == ".wav") return "audio/wav";
        if (ext == ".mp3") return "audio/mpeg";
        if (ext == ".ogg") return "audio/ogg";
        if (ext == ".m4a") return "audio/mp4";
        if (ext == ".flac") return "audio/flac";
        if (ext == ".aac") return "audio/aac";
        return "audio/octet-stream";
    case ContentType::VoiceControl:
        return "application/x-cryptex-voice-signal";
    case ContentType::VoiceFrame:
        return "audio/x-cryptex-live-pcm";
    case ContentType::Text:
        break;
    }
    return "text/plain";
}

std::optional<ContentType> detect_content_type(const std::filesystem::path& path) {
    const auto ext = lower_copy(path.extension().string());
    if (ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".webp" || ext == ".bmp") {
        return ContentType::Image;
    }
    if (ext == ".mp4" || ext == ".mov" || ext == ".webm" || ext == ".mkv" || ext == ".avi") {
        return ContentType::Video;
    }
    if (ext == ".wav" || ext == ".mp3" || ext == ".ogg" || ext == ".m4a" || ext == ".flac" || ext == ".aac") {
        return ContentType::Audio;
    }
    return std::nullopt;
}

std::string sanitize_filename_component(std::string value) {
    for (char& ch : value) {
        if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '-' || ch == '_')) {
            ch = '_';
        }
    }
    return value;
}

std::vector<uint8_t> obfuscate_wav_audio(const std::vector<uint8_t>& input) {
    if (input.size() < 44 || std::string(reinterpret_cast<const char*>(input.data()), 4) != "RIFF" ||
        std::string(reinterpret_cast<const char*>(input.data() + 8), 4) != "WAVE") {
        throw std::runtime_error("audio obfuscation currently requires PCM WAV input");
    }

    size_t offset = 12;
    uint16_t audio_format = 0;
    uint16_t channels = 0;
    uint32_t sample_rate = 0;
    uint16_t block_align = 0;
    uint16_t bits_per_sample = 0;
    std::vector<uint8_t> data_chunk;

    while (offset + 8 <= input.size()) {
        const std::string chunk_id(reinterpret_cast<const char*>(input.data() + offset), 4);
        const uint32_t chunk_size = read_le32(input.data() + offset + 4);
        offset += 8;
        if (offset + chunk_size > input.size()) {
            throw std::runtime_error("wav chunk truncated");
        }
        if (chunk_id == "fmt ") {
            if (chunk_size < 16) throw std::runtime_error("wav fmt chunk too small");
            audio_format = read_le16(input.data() + offset + 0);
            channels = read_le16(input.data() + offset + 2);
            sample_rate = read_le32(input.data() + offset + 4);
            block_align = read_le16(input.data() + offset + 12);
            bits_per_sample = read_le16(input.data() + offset + 14);
        } else if (chunk_id == "data") {
            data_chunk.assign(input.begin() + static_cast<std::ptrdiff_t>(offset),
                              input.begin() + static_cast<std::ptrdiff_t>(offset + chunk_size));
        }
        offset += chunk_size + (chunk_size % 2);
    }

    if (audio_format != 1 || bits_per_sample != 16 || channels == 0 || block_align == 0 || data_chunk.empty()) {
        throw std::runtime_error("audio obfuscation currently supports 16-bit PCM WAV only");
    }

    const size_t frame_count = data_chunk.size() / block_align;
    if (frame_count == 0) {
        throw std::runtime_error("wav data chunk is empty");
    }

    const double pitch_factor = 0.82;
    const size_t output_frames = static_cast<size_t>(std::ceil(static_cast<double>(frame_count) / pitch_factor));
    std::vector<uint8_t> output_data;
    output_data.reserve(output_frames * block_align);

    auto sample_at = [&](size_t frame, uint16_t channel) -> int16_t {
        const size_t sample_offset = frame * block_align + static_cast<size_t>(channel) * 2;
        return static_cast<int16_t>(read_le16(data_chunk.data() + sample_offset));
    };

    for (size_t out_frame = 0; out_frame < output_frames; ++out_frame) {
        const double src_pos = std::min(static_cast<double>(frame_count - 1), out_frame * pitch_factor);
        const size_t base = static_cast<size_t>(src_pos);
        const size_t next = std::min(frame_count - 1, base + 1);
        const double alpha = src_pos - static_cast<double>(base);
        for (uint16_t channel = 0; channel < channels; ++channel) {
            const double left = static_cast<double>(sample_at(base, channel));
            const double right = static_cast<double>(sample_at(next, channel));
            double sample = left + ((right - left) * alpha);
            if (out_frame > 0) {
                const size_t prev_offset = output_data.size() - static_cast<size_t>(channels - channel) * 2;
                const int16_t prev = static_cast<int16_t>(read_le16(output_data.data() + prev_offset));
                sample = (sample * 0.78) + (static_cast<double>(prev) * 0.22);
            }
            const auto clipped = static_cast<int16_t>(std::clamp(sample, -32768.0, 32767.0));
            write_le16(output_data, static_cast<uint16_t>(clipped));
        }
    }

    std::vector<uint8_t> out;
    out.reserve(44 + output_data.size());
    out.insert(out.end(), {'R', 'I', 'F', 'F'});
    write_le32(out, static_cast<uint32_t>(36 + output_data.size()));
    out.insert(out.end(), {'W', 'A', 'V', 'E'});
    out.insert(out.end(), {'f', 'm', 't', ' '});
    write_le32(out, 16);
    write_le16(out, audio_format);
    write_le16(out, channels);
    write_le32(out, sample_rate);
    write_le32(out, sample_rate * block_align);
    write_le16(out, block_align);
    write_le16(out, bits_per_sample);
    out.insert(out.end(), {'d', 'a', 't', 'a'});
    write_le32(out, static_cast<uint32_t>(output_data.size()));
    out.insert(out.end(), output_data.begin(), output_data.end());
    return out;
}

} // namespace

ContentEnvelope make_text_content(const std::string& text) {
    ContentEnvelope content;
    content.type = ContentType::Text;
    content.text = text;
    content.mime_type = "text/plain";
    return content;
}

ContentEnvelope load_attachment_content(const std::filesystem::path& path,
                                       std::optional<ContentType> requested_type,
                                       const std::string& text,
                                       bool obfuscate_audio,
                                       const std::optional<std::string>& mime_override,
                                       const std::optional<std::string>& attachment_name_override,
                                       const std::optional<std::string>& transcript_override) {
    if (path.empty()) {
        throw std::runtime_error("attachment path is required");
    }
    auto type = requested_type ? *requested_type : detect_content_type(path).value_or(ContentType::Text);
    if (type == ContentType::Text) {
        throw std::runtime_error("attachment type must be image, video, or audio");
    }

    ContentEnvelope content;
    content.type = type;
    content.text = text;
    content.attachment_name = attachment_name_override && !attachment_name_override->empty()
        ? *attachment_name_override
        : path.filename().string();
    content.mime_type = mime_override && !mime_override->empty()
        ? *mime_override
        : detect_mime_type(path, type);
    if (transcript_override && !transcript_override->empty()) {
        content.transcript = *transcript_override;
    }
    content.attachment_bytes = read_file_bytes(path);

    if (obfuscate_audio) {
        if (type != ContentType::Audio) {
            throw std::runtime_error("audio privacy processing is only valid for audio attachments");
        }
        content.attachment_bytes = obfuscate_wav_audio(content.attachment_bytes);
        content.audio_privacy = AudioPrivacy::Deepened;
        if (content.mime_type.empty() || content.mime_type == "audio/octet-stream") {
            content.mime_type = "audio/wav";
        }
        if (std::filesystem::path(content.attachment_name).extension().empty()) {
            content.attachment_name += ".wav";
        }
    }

    if (content.attachment_bytes.empty()) {
        throw std::runtime_error("attachment file is empty");
    }
    if (content.attachment_bytes.size() > MAX_CHAT_ATTACHMENT_BYTES) {
        throw std::runtime_error("attachment exceeds chat payload size budget");
    }
    return content;
}

std::vector<uint8_t> serialize_content(const ContentEnvelope& content) {
    std::vector<uint8_t> out(CONTENT_MAGIC.begin(), CONTENT_MAGIC.end());
    out.push_back(content.version);
    out.push_back(static_cast<uint8_t>(content.type));
    out.push_back(static_cast<uint8_t>(content.audio_privacy));
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(content.mime_type.data()),
                               content.mime_type.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(content.attachment_name.data()),
                               content.attachment_name.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(content.text.data()),
                               content.text.size());
    serialization::write_bytes(out,
                               reinterpret_cast<const uint8_t*>(content.transcript.data()),
                               content.transcript.size());
    serialization::write_bytes(out, content.attachment_bytes.data(), content.attachment_bytes.size());
    return out;
}

ContentEnvelope deserialize_content(const std::vector<uint8_t>& data) {
    if (data.size() < CONTENT_MAGIC.size() + 3 ||
        !std::equal(CONTENT_MAGIC.begin(), CONTENT_MAGIC.end(), data.begin())) {
        return make_text_content(std::string(data.begin(), data.end()));
    }

    const uint8_t* ptr = data.data() + CONTENT_MAGIC.size();
    size_t remaining = data.size() - CONTENT_MAGIC.size();
    ContentEnvelope content;
    content.version = serialization::read_int<uint8_t>(ptr, remaining);
    content.type = static_cast<ContentType>(serialization::read_int<uint8_t>(ptr, remaining));
    content.audio_privacy = static_cast<AudioPrivacy>(serialization::read_int<uint8_t>(ptr, remaining));
    auto mime = serialization::read_bytes(ptr, remaining);
    auto name = serialization::read_bytes(ptr, remaining);
    auto text = serialization::read_bytes(ptr, remaining);
    std::vector<uint8_t> transcript;
    if (content.version >= 2) {
        transcript = serialization::read_bytes(ptr, remaining);
    }
    content.mime_type.assign(mime.begin(), mime.end());
    content.attachment_name.assign(name.begin(), name.end());
    content.text.assign(text.begin(), text.end());
    content.transcript.assign(transcript.begin(), transcript.end());
    content.attachment_bytes = serialization::read_bytes(ptr, remaining);
    return content;
}

const char* content_type_name(ContentType type) {
    switch (type) {
    case ContentType::Text:
        return "text";
    case ContentType::Image:
        return "image";
    case ContentType::Video:
        return "video";
    case ContentType::Audio:
        return "audio";
    case ContentType::VoiceControl:
        return "voice-control";
    case ContentType::VoiceFrame:
        return "voice-frame";
    }
    return "text";
}

std::optional<ContentType> parse_content_type(const std::string& text) {
    const auto normalized = lower_copy(text);
    if (normalized.empty() || normalized == "text") return ContentType::Text;
    if (normalized == "image" || normalized == "img") return ContentType::Image;
    if (normalized == "video" || normalized == "vid") return ContentType::Video;
    if (normalized == "audio" || normalized == "voice") return ContentType::Audio;
    if (normalized == "voice-control" || normalized == "call-control") return ContentType::VoiceControl;
    if (normalized == "voice-frame" || normalized == "call-audio") return ContentType::VoiceFrame;
    return std::nullopt;
}

const char* audio_privacy_name(AudioPrivacy mode) {
    switch (mode) {
    case AudioPrivacy::None:
        return "none";
    case AudioPrivacy::Deepened:
        return "deepened";
    }
    return "none";
}

std::string content_summary(const ContentEnvelope& content) {
    if (!content.text.empty()) {
        return content.text;
    }
    if (content.type == ContentType::Text) {
        return {};
    }
    if (content.type == ContentType::VoiceControl) {
        return "[voice call control]";
    }
    if (content.type == ContentType::VoiceFrame) {
        return content.audio_privacy == AudioPrivacy::Deepened
            ? "[voice call audio, deepened]"
            : "[voice call audio]";
    }
    std::string summary = "[";
    summary += content_type_name(content.type);
    summary += ": ";
    summary += content.attachment_name.empty() ? std::string("attachment") : content.attachment_name;
    if (content.type == ContentType::Audio && content.audio_privacy == AudioPrivacy::Deepened) {
        summary += ", deepened";
    }
    summary += "]";
    return summary;
}

std::filesystem::path persist_attachment(const ContentEnvelope& content,
                                         const std::filesystem::path& data_dir,
                                         const std::string& message_id) {
    if (content.attachment_bytes.empty()) {
        return {};
    }
    if (content.type == ContentType::VoiceControl || content.type == ContentType::VoiceFrame) {
        return {};
    }

    std::filesystem::path media_dir = data_dir / "chat_media";
    std::error_code ec;
    std::filesystem::create_directories(media_dir, ec);
    if (ec) {
        throw std::runtime_error("failed to create chat media directory: " + ec.message());
    }

    std::string base_name = content.attachment_name.empty() ? std::string("attachment") : content.attachment_name;
    base_name = sanitize_filename_component(base_name);
    if (base_name.empty()) {
        base_name = "attachment";
    }
    const std::string prefix = sanitize_filename_component(message_id.substr(0, std::min<size_t>(message_id.size(), 16)));
    const auto output_path = media_dir / (prefix + "_" + base_name);
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to write chat attachment file");
    }
    output.write(reinterpret_cast<const char*>(content.attachment_bytes.data()),
                 static_cast<std::streamsize>(content.attachment_bytes.size()));
    if (!output) {
        throw std::runtime_error("failed to persist chat attachment bytes");
    }
    return output_path;
}

} // namespace chat
} // namespace cryptex
