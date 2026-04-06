#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace cryptex {
namespace chat {

enum class ContentType : uint8_t {
    Text = 0,
    Image = 1,
    Video = 2,
    Audio = 3,
    VoiceControl = 4,
    VoiceFrame = 5,
};

enum class AudioPrivacy : uint8_t {
    None = 0,
    Deepened = 1,
};

struct ContentEnvelope {
    uint8_t version{2};
    ContentType type{ContentType::Text};
    AudioPrivacy audio_privacy{AudioPrivacy::None};
    std::string mime_type;
    std::string attachment_name;
    std::string text;
    std::string transcript;
    std::vector<uint8_t> attachment_bytes;
};

ContentEnvelope make_text_content(const std::string& text);
ContentEnvelope load_attachment_content(const std::filesystem::path& path,
                                       std::optional<ContentType> requested_type = std::nullopt,
                                       const std::string& text = {},
                                       bool obfuscate_audio = false,
                                       const std::optional<std::string>& mime_override = std::nullopt,
                                       const std::optional<std::string>& attachment_name_override = std::nullopt,
                                       const std::optional<std::string>& transcript_override = std::nullopt);

std::vector<uint8_t> serialize_content(const ContentEnvelope& content);
ContentEnvelope deserialize_content(const std::vector<uint8_t>& data);

const char* content_type_name(ContentType type);
std::optional<ContentType> parse_content_type(const std::string& text);
const char* audio_privacy_name(AudioPrivacy mode);
std::string content_summary(const ContentEnvelope& content);
std::filesystem::path persist_attachment(const ContentEnvelope& content,
                                         const std::filesystem::path& data_dir,
                                         const std::string& message_id);

} // namespace chat
} // namespace cryptex
