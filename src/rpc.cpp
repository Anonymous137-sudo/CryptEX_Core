#include "rpc.hpp"

#include "base64.hpp"
#include "block.hpp"
#include "blockchain.hpp"
#include "chat_secure.hpp"
#include "network.hpp"
#include "serialization.hpp"
#include "wallet.hpp"
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
#include <fstream>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

namespace cryptex {
namespace rpc {

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

namespace {

class RpcException : public std::runtime_error {
public:
    RpcException(int code, std::string message)
        : std::runtime_error(message), code_(code) {}

    int code() const { return code_; }

private:
    int code_;
};

class JsonValue {
public:
    enum class Type {
        Null,
        Bool,
        Number,
        String,
        Array,
        Object,
    };

    using array_t = std::vector<JsonValue>;
    using object_t = std::vector<std::pair<std::string, JsonValue>>;

    JsonValue() = default;
    explicit JsonValue(bool value) : type_(Type::Bool), bool_value_(value) {}
    static JsonValue number(std::string raw) {
        JsonValue v;
        v.type_ = Type::Number;
        v.scalar_ = std::move(raw);
        return v;
    }
    static JsonValue number(int64_t value) { return number(std::to_string(value)); }
    static JsonValue number(uint64_t value) { return number(std::to_string(value)); }
    static JsonValue number(double value) {
        std::ostringstream ss;
        ss << std::setprecision(16) << value;
        return number(ss.str());
    }
    static JsonValue string(std::string value) {
        JsonValue v;
        v.type_ = Type::String;
        v.scalar_ = std::move(value);
        return v;
    }
    static JsonValue array(array_t value) {
        JsonValue v;
        v.type_ = Type::Array;
        v.array_ = std::move(value);
        return v;
    }
    static JsonValue object(object_t value = {}) {
        JsonValue v;
        v.type_ = Type::Object;
        v.object_ = std::move(value);
        return v;
    }

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Bool; }
    bool is_number() const { return type_ == Type::Number; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }

    bool as_bool() const {
        if (!is_bool()) throw RpcException(-32602, "expected bool");
        return bool_value_;
    }

    int64_t as_i64() const {
        if (!is_number()) throw RpcException(-32602, "expected integer");
        size_t idx = 0;
        long long value = std::stoll(scalar_, &idx, 10);
        if (idx != scalar_.size()) throw RpcException(-32602, "invalid integer");
        return static_cast<int64_t>(value);
    }

    uint64_t as_u64() const {
        auto value = as_i64();
        if (value < 0) throw RpcException(-32602, "expected non-negative integer");
        return static_cast<uint64_t>(value);
    }

    double as_double() const {
        if (!is_number()) throw RpcException(-32602, "expected number");
        size_t idx = 0;
        double value = std::stod(scalar_, &idx);
        if (idx != scalar_.size()) throw RpcException(-32602, "invalid number");
        return value;
    }

    const std::string& as_string() const {
        if (!is_string()) throw RpcException(-32602, "expected string");
        return scalar_;
    }

    const std::string& number_text() const {
        if (!is_number()) throw RpcException(-32602, "expected number");
        return scalar_;
    }

    const array_t& as_array() const {
        if (!is_array()) throw RpcException(-32602, "expected array");
        return array_;
    }

    const object_t& as_object() const {
        if (!is_object()) throw RpcException(-32602, "expected object");
        return object_;
    }

    void push_back(JsonValue value) {
        if (!is_array()) throw RpcException(-32603, "not an array");
        array_.push_back(std::move(value));
    }

    void set(std::string key, JsonValue value) {
        if (!is_object()) throw RpcException(-32603, "not an object");
        for (auto& [existing_key, existing_value] : object_) {
            if (existing_key == key) {
                existing_value = std::move(value);
                return;
            }
        }
        object_.push_back({std::move(key), std::move(value)});
    }

    const JsonValue* find(const std::string& key) const {
        if (!is_object()) return nullptr;
        for (const auto& [existing_key, value] : object_) {
            if (existing_key == key) return &value;
        }
        return nullptr;
    }

private:
    Type type_{Type::Null};
    bool bool_value_{false};
    std::string scalar_;
    array_t array_;
    object_t object_;
};

class JsonParser {
public:
    explicit JsonParser(const std::string& input) : input_(input) {}

    JsonValue parse() {
        skip_ws();
        auto value = parse_value();
        skip_ws();
        if (pos_ != input_.size()) throw RpcException(-32700, "trailing JSON data");
        return value;
    }

private:
    JsonValue parse_value() {
        if (pos_ >= input_.size()) throw RpcException(-32700, "unexpected end of JSON");
        switch (input_[pos_]) {
        case 'n': return parse_null();
        case 't':
        case 'f': return parse_bool();
        case '"': return JsonValue::string(parse_string());
        case '[': return parse_array();
        case '{': return parse_object();
        default:
            if (input_[pos_] == '-' || std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
                return parse_number();
            }
        }
        throw RpcException(-32700, "invalid JSON value");
    }

    JsonValue parse_null() {
        expect("null");
        return JsonValue();
    }

    JsonValue parse_bool() {
        if (consume("true")) return JsonValue(true);
        if (consume("false")) return JsonValue(false);
        throw RpcException(-32700, "invalid JSON boolean");
    }

    JsonValue parse_number() {
        size_t start = pos_;
        if (input_[pos_] == '-') ++pos_;
        if (pos_ >= input_.size()) throw RpcException(-32700, "invalid JSON number");
        if (input_[pos_] == '0') {
            ++pos_;
        } else if (std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
        } else {
            throw RpcException(-32700, "invalid JSON number");
        }
        if (pos_ < input_.size() && input_[pos_] == '.') {
            ++pos_;
            if (pos_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
                throw RpcException(-32700, "invalid JSON number");
            }
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
        }
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) ++pos_;
            if (pos_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[pos_]))) {
                throw RpcException(-32700, "invalid JSON number");
            }
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_]))) ++pos_;
        }
        return JsonValue::number(input_.substr(start, pos_ - start));
    }

    std::string parse_string() {
        if (input_[pos_] != '"') throw RpcException(-32700, "expected JSON string");
        ++pos_;
        std::string out;
        while (pos_ < input_.size()) {
            char ch = input_[pos_++];
            if (ch == '"') return out;
            if (ch == '\\') {
                if (pos_ >= input_.size()) throw RpcException(-32700, "unterminated escape");
                char esc = input_[pos_++];
                switch (esc) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    if (pos_ + 4 > input_.size()) throw RpcException(-32700, "short unicode escape");
                    unsigned int code = 0;
                    for (size_t i = 0; i < 4; ++i) {
                        code <<= 4;
                        char hex = input_[pos_++];
                        if (hex >= '0' && hex <= '9') code |= hex - '0';
                        else if (hex >= 'a' && hex <= 'f') code |= 10 + (hex - 'a');
                        else if (hex >= 'A' && hex <= 'F') code |= 10 + (hex - 'A');
                        else throw RpcException(-32700, "invalid unicode escape");
                    }
                    if (code <= 0x7F) out.push_back(static_cast<char>(code));
                    else if (code <= 0x7FF) {
                        out.push_back(static_cast<char>(0xC0 | ((code >> 6) & 0x1F)));
                        out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    } else {
                        out.push_back(static_cast<char>(0xE0 | ((code >> 12) & 0x0F)));
                        out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                        out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    }
                    break;
                }
                default:
                    throw RpcException(-32700, "invalid string escape");
                }
            } else {
                out.push_back(ch);
            }
        }
        throw RpcException(-32700, "unterminated JSON string");
    }

    JsonValue parse_array() {
        ++pos_;
        JsonValue value = JsonValue::array({});
        skip_ws();
        if (pos_ < input_.size() && input_[pos_] == ']') {
            ++pos_;
            return value;
        }
        while (true) {
            skip_ws();
            value.push_back(parse_value());
            skip_ws();
            if (pos_ >= input_.size()) throw RpcException(-32700, "unterminated JSON array");
            if (input_[pos_] == ']') {
                ++pos_;
                return value;
            }
            if (input_[pos_] != ',') throw RpcException(-32700, "expected ',' in array");
            ++pos_;
        }
    }

    JsonValue parse_object() {
        ++pos_;
        JsonValue value = JsonValue::object();
        skip_ws();
        if (pos_ < input_.size() && input_[pos_] == '}') {
            ++pos_;
            return value;
        }
        while (true) {
            skip_ws();
            if (pos_ >= input_.size() || input_[pos_] != '"') throw RpcException(-32700, "expected object key");
            std::string key = parse_string();
            skip_ws();
            if (pos_ >= input_.size() || input_[pos_] != ':') throw RpcException(-32700, "expected ':' in object");
            ++pos_;
            skip_ws();
            value.set(std::move(key), parse_value());
            skip_ws();
            if (pos_ >= input_.size()) throw RpcException(-32700, "unterminated JSON object");
            if (input_[pos_] == '}') {
                ++pos_;
                return value;
            }
            if (input_[pos_] != ',') throw RpcException(-32700, "expected ',' in object");
            ++pos_;
        }
    }

    void skip_ws() {
        while (pos_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[pos_]))) ++pos_;
    }

    void expect(const char* text) {
        if (!consume(text)) throw RpcException(-32700, "unexpected JSON token");
    }

    bool consume(const char* text) {
        size_t len = std::strlen(text);
        if (input_.compare(pos_, len, text) != 0) return false;
        pos_ += len;
        return true;
    }

    const std::string& input_;
    size_t pos_{0};
};

std::string json_escape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 8);
    for (unsigned char ch : input) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                std::ostringstream ss;
                ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch);
                out += ss.str();
            } else {
                out.push_back(static_cast<char>(ch));
            }
        }
    }
    return out;
}

std::string json_serialize(const JsonValue& value) {
    switch (value.type()) {
    case JsonValue::Type::Null:
        return "null";
    case JsonValue::Type::Bool:
        return value.as_bool() ? "true" : "false";
    case JsonValue::Type::Number:
        return value.number_text();
    case JsonValue::Type::String:
        return "\"" + json_escape(value.as_string()) + "\"";
    case JsonValue::Type::Array: {
        std::string out = "[";
        bool first = true;
        for (const auto& item : value.as_array()) {
            if (!first) out += ",";
            first = false;
            out += json_serialize(item);
        }
        out += "]";
        return out;
    }
    case JsonValue::Type::Object: {
        std::string out = "{";
        bool first = true;
        for (const auto& [key, item] : value.as_object()) {
            if (!first) out += ",";
            first = false;
            out += "\"" + json_escape(key) + "\":" + json_serialize(item);
        }
        out += "}";
        return out;
    }
    }
    return "null";
}

JsonValue json_number_string(const std::string& raw) {
    return JsonValue::number(raw);
}

std::string lower_hex(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        out.push_back(hex[(byte >> 4) & 0x0F]);
        out.push_back(hex[byte & 0x0F]);
    }
    return out;
}

bool timing_safe_equal(const std::string& lhs, const std::string& rhs) {
    if (lhs.size() != rhs.size()) return false;
    return CRYPTO_memcmp(lhs.data(), rhs.data(), lhs.size()) == 0;
}

std::string hmac_sha256_hex(std::string_view key, std::string_view data) {
    unsigned int out_len = 0;
    unsigned char out[EVP_MAX_MD_SIZE];
    if (!HMAC(EVP_sha256(),
              key.data(),
              static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(data.data()),
              data.size(),
              out,
              &out_len)) {
        throw RpcException(-32603, "HMAC-SHA256 failed");
    }
    return lower_hex(std::vector<uint8_t>(out, out + out_len));
}

std::optional<std::pair<std::string, std::string>> parse_basic_credentials(
    const http::request<http::string_body>& request) {
    auto auth = request.find(http::field::authorization);
    if (auth == request.end()) return std::nullopt;
    std::string header(auth->value().data(), auth->value().size());
    constexpr const char* kPrefix = "Basic ";
    if (header.rfind(kPrefix, 0) != 0) return std::nullopt;
    auto decoded = crypto::base64_decode(header.substr(std::strlen(kPrefix)));
    std::string credentials(decoded.begin(), decoded.end());
    auto pos = credentials.find(':');
    if (pos == std::string::npos) return std::nullopt;
    return std::make_pair(credentials.substr(0, pos), credentials.substr(pos + 1));
}

bool is_loopback_endpoint(const tcp::endpoint& endpoint) {
    return endpoint.address().is_loopback();
}

bool address_allowed(const std::vector<std::string>& allow_ips, const tcp::endpoint& remote) {
    if (allow_ips.empty()) return is_loopback_endpoint(remote);

    for (const auto& rule : allow_ips) {
        if (rule == "*" || rule == "0.0.0.0/0" || rule == "::/0") return true;
        try {
            if (rule.find('/') != std::string::npos && remote.address().is_v4()) {
                auto network = boost::asio::ip::make_network_v4(rule);
                auto remote_u32 = remote.address().to_v4().to_uint();
                auto mask_u32 = network.netmask().to_uint();
                if ((remote_u32 & mask_u32) == network.network().to_uint()) {
                    return true;
                }
                continue;
            }
        } catch (...) {
        }
        try {
            auto allowed = boost::asio::ip::make_address(rule);
            if (allowed == remote.address()) return true;
        } catch (...) {
        }
    }
    return false;
}

bool matches_rpcauth_entry(const std::string& entry,
                           const std::string& username,
                           const std::string& password) {
    auto colon = entry.find(':');
    auto dollar = entry.find('$');
    if (colon == std::string::npos || dollar == std::string::npos || dollar <= colon + 1) {
        return false;
    }
    std::string configured_user = entry.substr(0, colon);
    std::string salt = entry.substr(colon + 1, dollar - colon - 1);
    std::string expected_hash = entry.substr(dollar + 1);
    if (!timing_safe_equal(configured_user, username)) return false;
    auto computed = hmac_sha256_hex(salt, password);
    return timing_safe_equal(expected_hash, computed);
}

std::vector<uint8_t> parse_hex_string(const std::string& input) {
    if (input.size() % 2 != 0) throw RpcException(-32602, "hex string must have even length");
    auto hex_value = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
        if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
        return -1;
    };

    std::vector<uint8_t> out;
    out.reserve(input.size() / 2);
    for (size_t i = 0; i < input.size(); i += 2) {
        int hi = hex_value(input[i]);
        int lo = hex_value(input[i + 1]);
        if (hi < 0 || lo < 0) throw RpcException(-32602, "invalid hex string");
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::optional<std::pair<Transaction, std::optional<uint64_t>>> find_transaction(
    const Blockchain& chain,
    const uint256_t& txid) {
    if (chain.mempool().contains(txid)) {
        return std::make_pair(chain.mempool().get_transaction(txid), std::optional<uint64_t>{});
    }
    for (uint64_t h = 0; h <= chain.best_height(); ++h) {
        auto block = chain.get_block(h);
        if (!block) continue;
        for (const auto& tx : block->transactions) {
            if (tx.hash() == txid) return std::make_pair(tx, std::optional<uint64_t>{h});
        }
    }
    return std::nullopt;
}

double difficulty_from_bits(uint32_t bits) {
    auto expected_hashes_from_bits = [](uint32_t value) -> long double {
        uint32_t exponent = value >> 24;
        uint32_t mantissa = value & 0x007fffff;
        if (mantissa == 0) return 0.0L;
        return std::pow(256.0L, static_cast<long double>(constants::POW_HASH_BYTES) -
                                      static_cast<long double>(exponent) + 3.0L) /
               static_cast<long double>(mantissa);
    };
    long double baseline = expected_hashes_from_bits(pow_limit_bits());
    if (baseline == 0.0L) return 0.0;
    return static_cast<double>(expected_hashes_from_bits(bits) / baseline);
}

double expected_hashes_from_bits(uint32_t bits) {
    int exponent = static_cast<int>((bits >> 24) & 0xFF);
    double mantissa = static_cast<double>(bits & 0x007fffff);
    if (mantissa <= 0.0) return 0.0;
    return std::pow(256.0, static_cast<double>(constants::POW_HASH_BYTES - exponent + 3)) / mantissa;
}

std::string bits_to_hex(uint32_t bits) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << std::nouppercase << bits;
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

Block build_block_template(Blockchain& chain, const std::string& coinbase_address) {
    uint64_t height = chain.best_height() + 1;
    Block block;
    block.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    block.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    block.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    block.header.bits = chain.next_work_bits(block.header.timestamp);
    block.header.nonce = 0;

    Transaction coinbase;
    coinbase.version = 1;
    TxIn input;
    input.prevout.tx_hash = uint256_t();
    input.prevout.index = 0xFFFFFFFF;
    input.scriptSig = make_coinbase_script_sig(height, block.header.timestamp, block.header.prev_block_hash);
    input.sequence = 0xFFFFFFFF;
    coinbase.inputs.push_back(input);

    TxOut output;
    output.value = Block::get_block_reward(height);
    output.scriptPubKey = crypto::canonicalize_address(coinbase_address);
    coinbase.outputs.push_back(output);
    coinbase.lockTime = 0;
    block.transactions.push_back(coinbase);

    auto txs = chain.mempool().get_transactions();
    size_t total_size = coinbase.serialize().size();
    for (const auto& tx : txs) {
        auto tx_size = tx.serialize().size();
        if (total_size + tx_size > constants::MAX_BLOCK_SIZE_BYTES) break;
        block.transactions.push_back(tx);
        total_size += tx_size;
    }
    block.header.merkle_root = block.compute_merkle_root();
    return block;
}

std::string address_for_display(const std::string& address);
void add_address_formats(JsonValue& object,
                         const std::string& key,
                         const std::string& address,
                         const std::optional<std::string>& preferred_display = std::nullopt);

JsonValue tx_to_json(const Transaction& tx) {
    JsonValue obj = JsonValue::object();
    obj.set("txid", JsonValue::string(tx.hash().to_hex()));
    obj.set("version", JsonValue::number(static_cast<int64_t>(tx.version)));
    obj.set("size", JsonValue::number(static_cast<uint64_t>(tx.serialize().size())));
    obj.set("locktime", JsonValue::number(static_cast<uint64_t>(tx.lockTime)));
    obj.set("coinbase", JsonValue(tx.is_coinbase()));

    JsonValue vin = JsonValue::array({});
    for (const auto& in : tx.inputs) {
        JsonValue in_obj = JsonValue::object();
        in_obj.set("txid", JsonValue::string(in.prevout.tx_hash.to_hex()));
        in_obj.set("vout", JsonValue::number(static_cast<uint64_t>(in.prevout.index)));
        in_obj.set("scriptsig", JsonValue::string(lower_hex(in.scriptSig)));
        in_obj.set("sequence", JsonValue::number(static_cast<uint64_t>(in.sequence)));
        vin.push_back(std::move(in_obj));
    }
    obj.set("vin", std::move(vin));

    JsonValue vout = JsonValue::array({});
    for (size_t i = 0; i < tx.outputs.size(); ++i) {
        const auto& out = tx.outputs[i];
        JsonValue out_obj = JsonValue::object();
        out_obj.set("n", JsonValue::number(static_cast<uint64_t>(i)));
        out_obj.set("value_sats", JsonValue::number(out.value));
        out_obj.set("script_hex", JsonValue::string(lower_hex(
            std::vector<uint8_t>(out.scriptPubKey.begin(), out.scriptPubKey.end()))));
        if (!out.scriptPubKey.empty() && static_cast<uint8_t>(out.scriptPubKey[0]) == 0x6a) {
            out_obj.set("script_type", JsonValue::string("op_return"));

            const auto bytes = std::vector<uint8_t>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            size_t cursor = 1;
            std::vector<uint8_t> payload;
            if (cursor < bytes.size()) {
                uint8_t opcode = bytes[cursor++];
                if (opcode <= 75 && cursor + opcode <= bytes.size()) {
                    payload.assign(bytes.begin() + static_cast<long>(cursor),
                                   bytes.begin() + static_cast<long>(cursor + opcode));
                } else if (opcode == 0x4c && cursor < bytes.size()) {
                    size_t len = bytes[cursor++];
                    if (cursor + len <= bytes.size()) {
                        payload.assign(bytes.begin() + static_cast<long>(cursor),
                                       bytes.begin() + static_cast<long>(cursor + len));
                    }
                } else if (opcode == 0x4d && cursor + 1 < bytes.size()) {
                    size_t len = static_cast<size_t>(bytes[cursor]) |
                                 (static_cast<size_t>(bytes[cursor + 1]) << 8);
                    cursor += 2;
                    if (cursor + len <= bytes.size()) {
                        payload.assign(bytes.begin() + static_cast<long>(cursor),
                                       bytes.begin() + static_cast<long>(cursor + len));
                    }
                }
            }

            out_obj.set("op_return_hex", JsonValue::string(lower_hex(payload)));
            bool printable = !payload.empty() &&
                             std::all_of(payload.begin(), payload.end(), [](uint8_t ch) {
                                 return ch == '\n' || ch == '\r' || ch == '\t' || (ch >= 32 && ch <= 126);
                             });
            if (printable) {
                out_obj.set("op_return_text", JsonValue::string(std::string(payload.begin(), payload.end())));
            } else {
                out_obj.set("op_return_text", JsonValue());
            }
        } else {
            out_obj.set("script_type", JsonValue::string("pay_to_address"));
            add_address_formats(out_obj, "address", out.scriptPubKey);
        }
        vout.push_back(std::move(out_obj));
    }
    obj.set("vout", std::move(vout));
    return obj;
}

std::string address_for_display(const std::string& address) {
    try {
        return crypto::address_to_base58(address);
    } catch (...) {
        return address;
    }
}

std::string address_for_wallet_display(const Wallet& wallet, const std::string& value) {
    try {
        return wallet.display_address(value);
    } catch (...) {
        return value;
    }
}

void add_address_formats(JsonValue& object,
                         const std::string& key,
                         const std::string& address,
                         const std::optional<std::string>& preferred_display) {
    try {
        auto base58 = crypto::address_to_base58(address);
        object.set(key, JsonValue::string(preferred_display.value_or(crypto::address_to_base64(address))));
        object.set(key + "_base58", JsonValue::string(base58));
        object.set(key + "_base64", JsonValue::string(crypto::address_to_base64(address)));
        object.set(key + "_hex", JsonValue::string(crypto::address_to_hex(address)));
        object.set(key + "_bech32", JsonValue::string(crypto::address_to_bech32(address)));
    } catch (...) {
        object.set(key, JsonValue::string(address));
        object.set(key + "_base58", JsonValue());
        object.set(key + "_base64", JsonValue());
        object.set(key + "_hex", JsonValue());
        object.set(key + "_bech32", JsonValue());
    }
}

JsonValue wallet_address_to_json(const Wallet::AddressBookEntry& entry) {
    JsonValue obj = JsonValue::object();
    obj.set("address", JsonValue::string(entry.address));
    obj.set("address_base64", JsonValue::string(entry.address_base64));
    obj.set("address_base58", JsonValue::string(entry.address_base58));
    obj.set("address_hex", JsonValue::string(entry.address_hex));
    obj.set("address_bech32", JsonValue::string(entry.address_bech32));
    obj.set("label", JsonValue::string(entry.label));
    obj.set("pubkey_b64", JsonValue::string(entry.pubkey_b64));
    obj.set("primary", JsonValue(entry.primary));
    obj.set("hd_index", JsonValue::number(static_cast<uint64_t>(entry.hd_index)));
    return obj;
}

JsonValue wallet_history_to_json(const Wallet::HistoryEntry& entry) {
    JsonValue obj = JsonValue::object();
    obj.set("txid", JsonValue::string(entry.txid));
    obj.set("direction", JsonValue::string(entry.direction));
    obj.set("summary_address", JsonValue::string(entry.summary_address));
    obj.set("net_sats", JsonValue::number(entry.net_sats));
    obj.set("received_sats", JsonValue::number(entry.received_sats));
    obj.set("sent_sats", JsonValue::number(entry.sent_sats));
    obj.set("fee_sats", JsonValue::number(entry.fee_sats));
    obj.set("timestamp", JsonValue::number(entry.timestamp));
    if (entry.block_height) obj.set("block_height", JsonValue::number(*entry.block_height));
    else obj.set("block_height", JsonValue());
    obj.set("confirmations", JsonValue::number(entry.confirmations));
    obj.set("coinbase", JsonValue(entry.coinbase));
    obj.set("in_mempool", JsonValue(entry.in_mempool));

    JsonValue from = JsonValue::array({});
    for (const auto& address : entry.from_addresses) {
        from.push_back(JsonValue::string(address));
    }
    obj.set("from_addresses", std::move(from));

    JsonValue to = JsonValue::array({});
    for (const auto& address : entry.to_addresses) {
        to.push_back(JsonValue::string(address));
    }
    obj.set("to_addresses", std::move(to));
    return obj;
}

JsonValue block_header_to_json(const BlockHeader& header,
                               std::optional<uint64_t> height,
                               uint64_t best_height) {
    JsonValue obj = JsonValue::object();
    obj.set("hash", JsonValue::string(header.pow_hash().to_hex_padded(constants::POW_HASH_BYTES)));
    obj.set("linkhash", JsonValue::string(header.hash().to_hex()));
    if (height) {
        obj.set("height", JsonValue::number(*height));
        obj.set("confirmations", JsonValue::number(best_height >= *height ? best_height - *height + 1 : 0));
    } else {
        obj.set("confirmations", JsonValue::number(static_cast<int64_t>(0)));
    }
    obj.set("version", JsonValue::number(static_cast<int64_t>(header.version)));
    obj.set("previousblockhash", JsonValue::string(header.prev_block_hash.to_hex()));
    obj.set("merkleroot", JsonValue::string(header.merkle_root.to_hex()));
    obj.set("time", JsonValue::number(static_cast<uint64_t>(header.timestamp)));
    obj.set("bits", JsonValue::string(bits_to_hex(header.bits)));
    obj.set("difficulty", JsonValue::number(difficulty_from_bits(header.bits)));
    obj.set("nonce", JsonValue::number(static_cast<uint64_t>(header.nonce)));
    return obj;
}

JsonValue block_to_json(const Block& block,
                        std::optional<uint64_t> height,
                        uint64_t best_height,
                        uint64_t verbosity) {
    if (verbosity == 0) {
        return JsonValue::string(lower_hex(block.serialize()));
    }

    JsonValue obj = block_header_to_json(block.header, height, best_height);
    obj.set("size", JsonValue::number(static_cast<uint64_t>(block.serialize().size())));
    obj.set("txcount", JsonValue::number(static_cast<uint64_t>(block.transactions.size())));
    JsonValue txs = JsonValue::array({});
    for (const auto& tx : block.transactions) {
        if (verbosity >= 2) txs.push_back(tx_to_json(tx));
        else txs.push_back(JsonValue::string(tx.hash().to_hex()));
    }
    obj.set("tx", std::move(txs));
    return obj;
}

JsonValue make_error_object(int code, const std::string& message) {
    JsonValue error = JsonValue::object();
    error.set("code", JsonValue::number(static_cast<int64_t>(code)));
    error.set("message", JsonValue::string(message));
    return error;
}

JsonValue make_response(const JsonValue& id, const JsonValue& result, std::optional<JsonValue> error) {
    JsonValue response = JsonValue::object();
    response.set("jsonrpc", JsonValue::string("2.0"));
    if (error) {
        response.set("result", JsonValue());
        response.set("error", *error);
    } else {
        response.set("result", result);
        response.set("error", JsonValue());
    }
    response.set("id", id);
    return response;
}

const JsonValue* require_object_key(const JsonValue& object, const std::string& key) {
    const JsonValue* value = object.find(key);
    if (!value) throw RpcException(-32600, "missing key: " + key);
    return value;
}

const JsonValue::array_t& request_params(const JsonValue& request) {
    const JsonValue* params = request.find("params");
    if (!params) {
        static const JsonValue::array_t empty;
        return empty;
    }
    return params->as_array();
}

std::pair<std::string, uint16_t> parse_hostport(const std::string& hostport) {
    auto pos = hostport.find(':');
    if (pos == std::string::npos) throw RpcException(-32602, "expected host:port");
    auto host = hostport.substr(0, pos);
    auto port = static_cast<uint16_t>(std::stoul(hostport.substr(pos + 1)));
    return {host, port};
}

net::Message tx_inv_message(const Transaction& tx) {
    net::Message inv;
    inv.type = net::MessageType::INV;
    serialization::write_varint(inv.payload, 1);
    inv.payload.push_back(2);
    auto bytes = tx.hash().to_bytes();
    inv.payload.insert(inv.payload.end(), bytes.begin(), bytes.end());
    return inv;
}

net::Message tx_message(const Transaction& tx) {
    net::Message msg;
    msg.type = net::MessageType::TX;
    msg.payload = tx.serialize();
    return msg;
}

net::Message block_inv_message(const Block& block) {
    net::Message inv;
    inv.type = net::MessageType::INV;
    serialization::write_varint(inv.payload, 1);
    inv.payload.push_back(1);
    auto bytes = block.header.pow_hash().to_padded_bytes(constants::POW_HASH_BYTES);
    inv.payload.insert(inv.payload.end(), bytes.begin(), bytes.end());
    return inv;
}

JsonValue txout_to_json(const UTXOEntry& entry, uint64_t best_height, const uint256_t& tip_hash) {
    JsonValue out = JsonValue::object();
    uint64_t confirmations = best_height >= entry.block_height
                               ? best_height - entry.block_height + 1
                               : 0;
    out.set("bestblock", JsonValue::string(tip_hash.to_hex_padded(constants::POW_HASH_BYTES)));
    out.set("confirmations", JsonValue::number(confirmations));
    out.set("value_sats", JsonValue::number(entry.output.value));
    add_address_formats(out, "address", entry.output.scriptPubKey);
    out.set("coinbase", JsonValue(entry.is_coinbase));
    out.set("height", JsonValue::number(static_cast<uint64_t>(entry.block_height)));
    return out;
}

OutPoint parse_outpoint_from_json(const JsonValue& value) {
    if (!value.is_object()) throw RpcException(-32602, "coin-control input must be an object");
    const auto* txid = value.find("txid");
    const auto* vout = value.find("vout");
    if (!txid || !vout) throw RpcException(-32602, "coin-control input requires txid and vout");
    OutPoint outpoint;
    outpoint.tx_hash = uint256_t::from_hex(txid->as_string());
    outpoint.index = static_cast<uint32_t>(vout->as_u64());
    return outpoint;
}

struct SendOptions {
    std::string op_return;
    int64_t fee_per_kb{1000};
    std::vector<OutPoint> selected_inputs;
    std::optional<std::string> change_address;
};

struct WalletMetadataRecord {
    std::string name;
    std::string format;
};

std::filesystem::path wallet_metadata_path(const std::filesystem::path& wallet_file) {
    return std::filesystem::path(wallet_file.string() + ".meta");
}

std::string trim_copy(std::string value) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

std::string sanitize_wallet_name(std::string name) {
    name = trim_copy(std::move(name));
    if (name.empty()) return "Wallet";
    for (char& ch : name) {
        if (ch == '\n' || ch == '\r' || ch == '\t') ch = ' ';
    }
    return name;
}

WalletMetadataRecord read_wallet_metadata(const std::filesystem::path& wallet_file) {
    WalletMetadataRecord record;
    std::ifstream input(wallet_metadata_path(wallet_file));
    if (!input) {
        return record;
    }
    std::string line;
    while (std::getline(input, line)) {
        const auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        auto key = trim_copy(line.substr(0, pos));
        auto value = trim_copy(line.substr(pos + 1));
        if (key == "name") {
            record.name = value;
        } else if (key == "format") {
            record.format = value;
        }
    }
    return record;
}

void write_wallet_metadata(const std::filesystem::path& wallet_file,
                           const std::string& suggested_name,
                           const std::string& format) {
    const auto meta_path = wallet_metadata_path(wallet_file);
    std::error_code ec;
    if (meta_path.has_parent_path()) {
        std::filesystem::create_directories(meta_path.parent_path(), ec);
        if (ec) {
            throw RpcException(-32603, "failed to create wallet metadata directory: " + ec.message());
        }
    }
    std::ofstream output(meta_path, std::ios::trunc);
    if (!output) {
        throw RpcException(-32603, "failed to write wallet metadata");
    }
    output << "name=" << sanitize_wallet_name(suggested_name.empty() ? wallet_file.stem().string() : suggested_name) << "\n";
    output << "format=" << trim_copy(format) << "\n";
}

void remove_wallet_metadata(const std::filesystem::path& wallet_file) {
    std::error_code ec;
    std::filesystem::remove(wallet_metadata_path(wallet_file), ec);
}

std::string infer_wallet_format_from_path(const std::filesystem::path& wallet_file) {
    const auto stem = wallet_file.stem().string();
    if (stem.find("base64") != std::string::npos) return "base64";
    if (stem.find("base58") != std::string::npos) return "base58";
    if (stem.find("bech32") != std::string::npos) return "bech32";
    if (stem.find("hex") != std::string::npos || stem.find("evm") != std::string::npos) return "hex";
    return {};
}

JsonValue wallet_listing_json(const std::filesystem::path& wallet_file,
                              const WalletMetadataRecord& metadata,
                              const std::optional<std::string>& active_wallet) {
    JsonValue info = JsonValue::object();
    const auto normalized = wallet_file.lexically_normal().string();
    const auto active = active_wallet && std::filesystem::path(*active_wallet).lexically_normal() == wallet_file.lexically_normal();
    const auto name = metadata.name.empty() ? sanitize_wallet_name(wallet_file.stem().string()) : metadata.name;
    const auto format = !metadata.format.empty() ? metadata.format : infer_wallet_format_from_path(wallet_file);
    const bool managed = wallet_file.parent_path().filename() == "wallets";
    info.set("name", JsonValue::string(name));
    info.set("path", JsonValue::string(normalized));
    info.set("active", JsonValue(active));
    info.set("address_format", format.empty() ? JsonValue() : JsonValue::string(format));
    info.set("managed", JsonValue(managed));
    return info;
}

std::vector<std::filesystem::path> discover_wallet_files(const std::optional<std::string>& wallet_directory,
                                                         const std::optional<std::string>& active_wallet) {
    std::set<std::filesystem::path> unique_paths;
    if (wallet_directory && !wallet_directory->empty()) {
        std::error_code ec;
        const std::filesystem::path root(*wallet_directory);
        if (std::filesystem::exists(root, ec) && std::filesystem::is_directory(root, ec)) {
            for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
                if (ec) break;
                if (!entry.is_regular_file()) continue;
                const auto path = entry.path();
                if (path.extension() == ".dat") {
                    unique_paths.insert(path.lexically_normal());
                }
            }
        }
        const auto legacy_wallet = (root.parent_path() / "Wallet.dat").lexically_normal();
        if (std::filesystem::exists(legacy_wallet, ec) && std::filesystem::is_regular_file(legacy_wallet, ec)) {
            unique_paths.insert(legacy_wallet);
        }
    }
    if (active_wallet && !active_wallet->empty()) {
        unique_paths.insert(std::filesystem::path(*active_wallet).lexically_normal());
    }
    return std::vector<std::filesystem::path>(unique_paths.begin(), unique_paths.end());
}

void parse_send_options_object(const JsonValue& object, SendOptions& options) {
    if (!object.is_object()) throw RpcException(-32602, "send options must be an object");
    if (const JsonValue* value = object.find("op_return")) options.op_return = value->as_string();
    if (const JsonValue* value = object.find("fee_per_kb")) options.fee_per_kb = value->as_i64();
    if (const JsonValue* value = object.find("change_address")) {
        auto change = value->as_string();
        if (!change.empty()) options.change_address = change;
    }
    if (const JsonValue* value = object.find("inputs")) {
        for (const auto& input : value->as_array()) {
            options.selected_inputs.push_back(parse_outpoint_from_json(input));
        }
    }
}

JsonValue recent_block_to_json(const Block& block, uint64_t height, uint64_t best_height) {
    JsonValue obj = block_header_to_json(block.header, height, best_height);
    obj.set("txcount", JsonValue::number(static_cast<uint64_t>(block.transactions.size())));
    obj.set("size", JsonValue::number(static_cast<uint64_t>(block.serialize().size())));
    return obj;
}

struct AddressActivitySummary {
    std::string address;
    int64_t balance_sats{0};
    int64_t spendable_balance_sats{0};
    int64_t immature_balance_sats{0};
    int64_t received_sats{0};
    int64_t sent_sats{0};
    uint64_t tx_count{0};
    uint64_t unspent_count{0};
    std::optional<uint64_t> last_height;
    std::vector<std::string> txids;
};

AddressActivitySummary scan_address_summary(const Blockchain& chain,
                                           const std::string& address,
                                           bool include_mempool) {
    AddressActivitySummary summary;
    try {
        summary.address = crypto::canonicalize_address(address);
    } catch (...) {
        summary.address = address;
    }

    const uint32_t current_height = static_cast<uint32_t>(chain.best_height());
    auto mature = chain.utxo().list_for_address(summary.address, current_height, false);
    auto all = chain.utxo().list_for_address(summary.address, current_height, true);
    summary.unspent_count = static_cast<uint64_t>(all.size());
    for (const auto& [outpoint, entry] : all) {
        (void)outpoint;
        summary.balance_sats += entry.output.value;
    }
    for (const auto& [outpoint, entry] : mature) {
        (void)outpoint;
        summary.spendable_balance_sats += entry.output.value;
    }
    summary.immature_balance_sats = summary.balance_sats - summary.spendable_balance_sats;

    std::unordered_map<OutPoint, UTXOEntry> seen_outputs;
    auto process_tx = [&](const Transaction& tx, std::optional<uint64_t> height) {
        bool matched = false;
        for (const auto& input : tx.inputs) {
            auto it = seen_outputs.find(input.prevout);
            if (it == seen_outputs.end()) continue;
            if (crypto::addresses_equal(it->second.output.scriptPubKey, summary.address)) {
                summary.sent_sats += it->second.output.value;
                matched = true;
            }
        }
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            const auto& output = tx.outputs[i];
            if (crypto::addresses_equal(output.scriptPubKey, summary.address)) {
                summary.received_sats += output.value;
                matched = true;
            }
            seen_outputs[OutPoint{tx.hash(), static_cast<uint32_t>(i)}] =
                UTXOEntry{output, static_cast<uint32_t>(height.value_or(chain.best_height() + 1)), tx.is_coinbase()};
        }
        if (matched) {
            ++summary.tx_count;
            summary.txids.push_back(tx.hash().to_hex());
            if (height && (!summary.last_height || *height > *summary.last_height)) {
                summary.last_height = *height;
            }
        }
    };

    for (uint64_t height = 0; height <= chain.best_height(); ++height) {
        auto block = chain.get_block(height);
        if (!block) continue;
        for (const auto& tx : block->transactions) {
            process_tx(tx, height);
        }
    }
    if (include_mempool) {
        for (const auto& tx : chain.mempool().get_transactions()) {
            process_tx(tx, std::nullopt);
        }
    }
    return summary;
}

JsonValue address_summary_to_json(const AddressActivitySummary& summary) {
    JsonValue obj = JsonValue::object();
    add_address_formats(obj, "address", summary.address);
    obj.set("balance_sats", JsonValue::number(summary.balance_sats));
    obj.set("spendable_balance_sats", JsonValue::number(summary.spendable_balance_sats));
    obj.set("immature_balance_sats", JsonValue::number(summary.immature_balance_sats));
    obj.set("received_sats", JsonValue::number(summary.received_sats));
    obj.set("sent_sats", JsonValue::number(summary.sent_sats));
    obj.set("tx_count", JsonValue::number(summary.tx_count));
    obj.set("unspent_count", JsonValue::number(summary.unspent_count));
    if (summary.last_height) obj.set("last_height", JsonValue::number(*summary.last_height));
    else obj.set("last_height", JsonValue());
    JsonValue txids = JsonValue::array({});
    for (const auto& txid : summary.txids) txids.push_back(JsonValue::string(txid));
    obj.set("txids", std::move(txids));
    return obj;
}

std::string mempool_status_text(Mempool::AcceptStatus status) {
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
}

JsonValue chat_entry_to_json(const chat::HistoryEntry& entry) {
    JsonValue obj = JsonValue::object();
    obj.set("direction", JsonValue::string(entry.direction));
    obj.set("private", JsonValue(entry.is_private));
    obj.set("legacy", JsonValue(entry.legacy));
    obj.set("authenticated", JsonValue(entry.authenticated));
    obj.set("encrypted", JsonValue(entry.encrypted));
    obj.set("decrypted", JsonValue(entry.decrypted));
    obj.set("timestamp", JsonValue::number(entry.timestamp));
    obj.set("nonce", JsonValue::number(entry.nonce));
    obj.set("messageid", JsonValue::string(entry.message_id));
    obj.set("sender", JsonValue::string(entry.sender_address));
    obj.set("sender_pubkey", JsonValue::string(entry.sender_pubkey));
    obj.set("recipient", JsonValue::string(entry.recipient_address));
    obj.set("recipient_pubkey", JsonValue::string(entry.recipient_pubkey));
    obj.set("channel", JsonValue::string(entry.channel));
    obj.set("message", JsonValue::string(entry.message));
    obj.set("peer", JsonValue::string(entry.peer_label));
    obj.set("status", JsonValue::string(entry.status));
    return obj;
}

void update_chat_query_from_object(const JsonValue& object, chat::HistoryQuery& query) {
    if (!object.is_object()) throw RpcException(-32602, "chat filter must be an object");
    if (const JsonValue* value = object.find("limit")) query.limit = static_cast<size_t>(value->as_u64());
    if (const JsonValue* value = object.find("since")) query.since_timestamp = value->as_u64();
    if (const JsonValue* value = object.find("channel")) query.channel = value->as_string();
    if (const JsonValue* value = object.find("address")) query.address = value->as_string();
    if (const JsonValue* value = object.find("direction")) query.direction = value->as_string();
    if (const JsonValue* value = object.find("private_only")) query.private_only = value->as_bool();
}

chat::HistoryQuery chat_query_from_params(const JsonValue::array_t& params) {
    chat::HistoryQuery query;
    if (params.empty()) return query;
    if (params[0].is_number()) {
        query.limit = static_cast<size_t>(params[0].as_u64());
        if (params.size() > 1) update_chat_query_from_object(params[1], query);
    } else {
        update_chat_query_from_object(params[0], query);
    }
    return query;
}

chat::HistoryEntry build_outbound_chat_history(const net::ChatPayload& payload,
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

bool looks_like_peer_label(const std::string& value) {
    auto pos = value.rfind(':');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= value.size()) return false;
    if (value.find(':') != pos) return false;
    return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(pos + 1),
                       value.end(),
                       [](unsigned char ch) { return std::isdigit(ch) != 0; });
}

struct ChatSendRequest {
    std::optional<std::string> peer_label;
    std::string route;
    std::string recipient_address;
    std::string recipient_pubkey_b64;
    std::string message;
    std::string from_address;
};

ChatSendRequest parse_chat_send_request(const JsonValue::array_t& params, bool private_chat) {
    ChatSendRequest request;

    if (!params.empty() && params[0].is_object()) {
        const auto& object = params[0];
        if (const auto* peer = object.find("peer")) request.peer_label = peer->as_string();
        if (const auto* from = object.find("from_address")) request.from_address = from->as_string();
        else if (const auto* from = object.find("from")) request.from_address = from->as_string();

        if (!private_chat) {
            const auto* channel = object.find("channel");
            const auto* message = object.find("message");
            if (!channel || !message) {
                throw RpcException(-32602, "sendchatpublic object expects {channel, message, peer?, from_address?}");
            }
            request.route = channel->as_string();
            request.message = message->as_string();
        } else {
            const auto* recipient = object.find("recipient_address");
            const auto* pubkey = object.find("recipient_pubkey_b64")
                                      ? object.find("recipient_pubkey_b64")
                                      : object.find("recipient_pubkey");
            const auto* message = object.find("message");
            if (!recipient || !pubkey || !message) {
                throw RpcException(-32602, "sendchatprivate object expects {recipient_address, recipient_pubkey_b64, message, peer?, from_address?}");
            }
            request.recipient_address = recipient->as_string();
            request.recipient_pubkey_b64 = pubkey->as_string();
            request.message = message->as_string();
        }
        return request;
    }

    if (!private_chat) {
        if (params.size() < 2 || params.size() > 4) {
            throw RpcException(-32602,
                               "sendchatpublic expects [channel, message, from_address?] or [peer, channel, message, from_address?]");
        }
        size_t index = 0;
        if (params.size() >= 3 && params[0].is_string() && looks_like_peer_label(params[0].as_string())) {
            request.peer_label = params[0].as_string();
            index = 1;
        }
        request.route = params[index].as_string();
        request.message = params[index + 1].as_string();
        if (params.size() > index + 2) request.from_address = params[index + 2].as_string();
        return request;
    }

    if (params.size() < 3 || params.size() > 5) {
        throw RpcException(-32602,
                           "sendchatprivate expects [recipient_address, recipient_pubkey_b64, message, from_address?] or [peer, recipient_address, recipient_pubkey_b64, message, from_address?]");
    }
    size_t index = 0;
    if (params.size() >= 4 && params[0].is_string() && looks_like_peer_label(params[0].as_string())) {
        request.peer_label = params[0].as_string();
        index = 1;
    }
    request.recipient_address = params[index].as_string();
    request.recipient_pubkey_b64 = params[index + 1].as_string();
    request.message = params[index + 2].as_string();
    if (params.size() > index + 3) request.from_address = params[index + 3].as_string();
    return request;
}

} // namespace

RpcService::RpcService(Blockchain& chain,
                       net::NetworkNode* node,
                       std::optional<std::string> wallet_path,
                       std::optional<std::string> wallet_password,
                       uint16_t rpc_port,
                       std::optional<std::string> wallet_directory)
    : chain_(chain),
      node_(node),
      wallet_path_(std::move(wallet_path)),
      wallet_password_(std::move(wallet_password)),
      rpc_port_(rpc_port),
      wallet_directory_(std::move(wallet_directory)) {}

bool RpcService::has_wallet_session() const {
    return wallet_path_.has_value() && wallet_password_.has_value();
}

void RpcService::set_wallet_session(const std::string& wallet_path, const std::string& wallet_password) {
    wallet_path_ = wallet_path;
    wallet_password_ = wallet_password;
    if (node_) {
        node_->set_chat_wallet(std::make_shared<Wallet>(Wallet::load(wallet_password, wallet_path)));
    }
}

void RpcService::clear_wallet_session() {
    wallet_path_.reset();
    wallet_password_.reset();
    if (node_) {
        node_->set_chat_wallet({});
    }
}

void RpcService::set_stop_callback(std::function<void()> callback) {
    stop_callback_ = std::move(callback);
}

std::string RpcService::handle_jsonrpc(const std::string& body, bool& stop_requested) {
    stop_requested = false;
    JsonValue id;
    try {
        JsonValue request = JsonParser(body).parse();
        if (!request.is_object()) throw RpcException(-32600, "request must be an object");
        const JsonValue* method_value = request.find("method");
        if (!method_value || !method_value->is_string()) throw RpcException(-32600, "method must be a string");
        if (const JsonValue* id_value = request.find("id")) id = *id_value;

        const auto& method = method_value->as_string();
        const auto& params = request_params(request);
        JsonValue result;
        auto require_wallet_session = [&]() {
            if (!has_wallet_session()) {
                throw RpcException(-32603, "no wallet is open; use createwallet or openwallet first");
            }
        };
        auto load_session_wallet = [&]() -> Wallet {
            require_wallet_session();
            return Wallet::load(*wallet_password_, *wallet_path_);
        };

        if (method == "help") {
            JsonValue methods = JsonValue::array({});
            for (const char* name : {
                     "help", "getblockcount", "getbestblockhash", "getblockhash",
                     "getblockheader", "getblock", "getblockchaininfo", "getchaintips",
                     "getrecentblocks", "getaddresssummary", "getaddresstxids", "searchchain",
                     "getdifficulty", "getrawmempool", "getrawtransaction", "gettxout",
                     "decoderawtransaction", "sendrawtransaction", "submitblock",
                     "getblocktemplate",
                     "getwalletsessioninfo", "listwallets", "createwallet", "openwallet", "closewallet", "deletewallet",
                     "getcheckpointinfo", "pincheckpoint", "clearcheckpointpin", "refreshcheckpoint",
                     "getchatinfo", "getchatinbox", "sendchatpublic", "sendchatprivate",
                     "getpeerinfo", "getpeergraph", "getnetworkinfo", "getportmappinginfo", "getmininginfo", "getmempoolinfo",
                     "getwalletinfo", "getbalance", "listunspent", "getwalletaddresses",
                     "getwalletaddressbook", "setaddresslabel",
                     "getwallethistory", "getwallettransactions", "getwallettransaction", "getnewaddress", "getunusedaddress",
                     "setwalletformat",
                     "dumpprivkey", "importprivkey", "importmnemonic", "backupwallet", "recoverwallet", "walletpassphrasechange",
                     "sendtoaddress", "addnode", "setban", "clearbanned", "setnetworkactive",
                     "listbanned", "stop"}) {
                methods.push_back(JsonValue::string(name));
            }
            result = std::move(methods);
        } else if (method == "getblockcount") {
            result = JsonValue::number(chain_.best_height());
        } else if (method == "getbestblockhash") {
            result = JsonValue::string(chain_.tip_hash().to_hex_padded(constants::POW_HASH_BYTES));
        } else if (method == "getblockhash") {
            if (params.size() != 1) throw RpcException(-32602, "getblockhash expects [height]");
            uint64_t height = params[0].as_u64();
            auto block = chain_.get_block(height);
            if (!block) throw RpcException(-5, "block height not found");
            result = JsonValue::string(block->header.pow_hash().to_hex_padded(constants::POW_HASH_BYTES));
        } else if (method == "getblockheader") {
            if (params.empty() || params.size() > 2) throw RpcException(-32602, "getblockheader expects [hash, verbose?]");
            auto hash = uint256_t::from_hex(params[0].as_string());
            auto block = chain_.get_block_by_hash(hash);
            if (!block) throw RpcException(-5, "block not found");
            bool verbose = params.size() < 2 || params[1].as_bool();
            auto height = chain_.get_height_by_hash(hash);
            result = verbose ? block_header_to_json(block->header, height, chain_.best_height())
                             : JsonValue::string(lower_hex(block->header.serialize()));
        } else if (method == "getblock") {
            if (params.empty() || params.size() > 2) throw RpcException(-32602, "getblock expects [hash, verbosity?]");
            auto hash = uint256_t::from_hex(params[0].as_string());
            auto block = chain_.get_block_by_hash(hash);
            if (!block) throw RpcException(-5, "block not found");
            uint64_t verbosity = params.size() >= 2 ? params[1].as_u64() : 1;
            auto height = chain_.get_height_by_hash(hash);
            result = block_to_json(*block, height, chain_.best_height(), verbosity);
        } else if (method == "getrecentblocks") {
            uint64_t limit = params.empty() ? 10 : params[0].as_u64();
            if (limit == 0) limit = 1;
            JsonValue blocks = JsonValue::array({});
            uint64_t emitted = 0;
            for (uint64_t height = chain_.best_height() + 1; height > 0 && emitted < limit; --height) {
                auto block = chain_.get_block(height - 1);
                if (!block) continue;
                blocks.push_back(recent_block_to_json(*block, height - 1, chain_.best_height()));
                ++emitted;
            }
            result = std::move(blocks);
        } else if (method == "getdifficulty") {
            result = JsonValue::number(difficulty_from_bits(chain_.tip_bits()));
        } else if (method == "getblockchaininfo") {
            JsonValue info = JsonValue::object();
            auto tip = chain_.get_block(chain_.best_height());
            auto sync = node_ ? node_->sync_status() : net::NetworkNode::SyncStatus{};
            uint64_t serialized_bytes = 0;
            for (uint64_t h = 0; h <= chain_.best_height(); ++h) {
                auto block = chain_.get_block(h);
                if (!block) continue;
                serialized_bytes += static_cast<uint64_t>(block->serialize().size());
            }
            const uint64_t local_height = chain_.best_height();
            const uint64_t best_peer_height = std::max<uint64_t>(local_height, static_cast<uint64_t>(sync.best_peer_height));
            const uint64_t blocks_left = best_peer_height > local_height ? best_peer_height - local_height : 0;
            const double verification_progress = best_peer_height == 0
                ? 1.0
                : static_cast<double>(local_height + 1) / static_cast<double>(best_peer_height + 1);
            info.set("chain", JsonValue::string(network_name(cryptex::params().network)));
            info.set("blocks", JsonValue::number(local_height));
            info.set("headers", JsonValue::number(best_peer_height));
            info.set("bestblockhash", JsonValue::string(chain_.tip_hash().to_hex_padded(constants::POW_HASH_BYTES)));
            info.set("difficulty", JsonValue::number(difficulty_from_bits(chain_.tip_bits())));
            info.set("mediantime", JsonValue::number(static_cast<uint64_t>(tip ? tip->header.timestamp : 0)));
            info.set("verificationprogress", JsonValue::number(verification_progress));
            info.set("initialblockdownload", JsonValue(sync.syncing));
            info.set("bestpeerheight", JsonValue::number(static_cast<uint64_t>(sync.best_peer_height)));
            info.set("blocksleft", JsonValue::number(blocks_left));
            info.set("queuedblocks", JsonValue::number(static_cast<uint64_t>(sync.queued_blocks)));
            info.set("inflightblocks", JsonValue::number(static_cast<uint64_t>(sync.inflight_blocks)));
            info.set("chain_approved", JsonValue(chain_.wallet_state_approved()));
            info.set("approvalpeers", JsonValue::number(chain_.approval_peer_count()));
            auto checkpoint = chain_.checkpoint_info();
            info.set("checkpoint_height", JsonValue::number(checkpoint.height));
            info.set("checkpoint_hash", JsonValue::string(checkpoint.present
                ? checkpoint.hash.to_hex_padded(constants::POW_HASH_BYTES)
                : std::string()));
            info.set("checkpoint_pinned", JsonValue(checkpoint.pinned));
            info.set("pruned", JsonValue(false));
            info.set("size_on_disk", JsonValue::number(serialized_bytes));
            info.set("warnings", JsonValue::string(""));
            result = std::move(info);
        } else if (method == "getchaintips") {
            JsonValue tips = JsonValue::array({});
            JsonValue tip = JsonValue::object();
            tip.set("height", JsonValue::number(chain_.best_height()));
            tip.set("hash", JsonValue::string(chain_.tip_hash().to_hex_padded(constants::POW_HASH_BYTES)));
            tip.set("branchlen", JsonValue::number(static_cast<uint64_t>(0)));
            tip.set("status", JsonValue::string("active"));
            tips.push_back(std::move(tip));
            result = std::move(tips);
        } else if (method == "getrawmempool") {
            JsonValue txids = JsonValue::array({});
            for (const auto& tx : chain_.mempool().get_transactions()) {
                txids.push_back(JsonValue::string(tx.hash().to_hex()));
            }
            result = std::move(txids);
        } else if (method == "getrawtransaction") {
            if (params.empty() || params.size() > 2) throw RpcException(-32602, "getrawtransaction expects [txid, verbose?]");
            auto txid = uint256_t::from_hex(params[0].as_string());
            bool verbose = params.size() >= 2 && params[1].as_bool();
            auto located = find_transaction(chain_, txid);
            if (!located) throw RpcException(-5, "transaction not found");
            const auto& [tx, height] = *located;
            if (!verbose) {
                result = JsonValue::string(lower_hex(tx.serialize()));
            } else {
                JsonValue info = tx_to_json(tx);
                if (height) {
                    info.set("blockheight", JsonValue::number(*height));
                    info.set("confirmations", JsonValue::number(chain_.best_height() - *height + 1));
                } else {
                    info.set("blockheight", JsonValue());
                    info.set("confirmations", JsonValue::number(static_cast<uint64_t>(0)));
                }
                result = std::move(info);
            }
        } else if (method == "getaddresssummary") {
            if (params.empty() || params.size() > 2) throw RpcException(-32602, "getaddresssummary expects [address, include_mempool?]");
            const bool include_mempool = params.size() >= 2 && params[1].as_bool();
            result = address_summary_to_json(scan_address_summary(chain_, params[0].as_string(), include_mempool));
        } else if (method == "getaddresstxids") {
            if (params.empty() || params.size() > 3) throw RpcException(-32602, "getaddresstxids expects [address, include_mempool?, limit?]");
            const bool include_mempool = params.size() >= 2 && params[1].as_bool();
            uint64_t limit = params.size() >= 3 ? params[2].as_u64() : 100;
            auto summary = scan_address_summary(chain_, params[0].as_string(), include_mempool);
            JsonValue txids = JsonValue::array({});
            uint64_t emitted = 0;
            for (const auto& txid : summary.txids) {
                if (emitted++ >= limit) break;
                txids.push_back(JsonValue::string(txid));
            }
            result = std::move(txids);
        } else if (method == "searchchain") {
            if (params.size() != 1) throw RpcException(-32602, "searchchain expects [query]");
            const std::string query = params[0].as_string();
            JsonValue search = JsonValue::object();

            bool handled = false;
            bool numeric_only = !query.empty() &&
                std::all_of(query.begin(), query.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; });
            if (numeric_only) {
                uint64_t height = std::strtoull(query.c_str(), nullptr, 10);
                if (auto block = chain_.get_block(height)) {
                    search.set("type", JsonValue::string("block"));
                    search.set("result", recent_block_to_json(*block, height, chain_.best_height()));
                    handled = true;
                }
            }

            if (!handled) {
                try {
                    auto hash = uint256_t::from_hex(query);
                    if (auto block = chain_.get_block_by_hash(hash)) {
                        auto height = chain_.get_height_by_hash(hash);
                        search.set("type", JsonValue::string("block"));
                        search.set("result", block_to_json(*block, height, chain_.best_height(), 1));
                        handled = true;
                    } else if (auto tx = find_transaction(chain_, hash)) {
                        JsonValue tx_obj = tx_to_json(tx->first);
                        if (tx->second) tx_obj.set("blockheight", JsonValue::number(*tx->second));
                        else tx_obj.set("blockheight", JsonValue());
                        search.set("type", JsonValue::string("transaction"));
                        search.set("result", std::move(tx_obj));
                        handled = true;
                    }
                } catch (...) {
                }
            }

            if (!handled) {
                auto summary = scan_address_summary(chain_, query, true);
                if (summary.tx_count > 0 || summary.balance_sats > 0 || summary.unspent_count > 0) {
                    search.set("type", JsonValue::string("address"));
                    search.set("result", address_summary_to_json(summary));
                    handled = true;
                }
            }

            if (!handled) {
                search.set("type", JsonValue::string("none"));
                search.set("query", JsonValue::string(query));
            }
            result = std::move(search);
        } else if (method == "gettxout") {
            if (params.size() < 2 || params.size() > 3) throw RpcException(-32602, "gettxout expects [txid, vout, include_mempool?]");
            auto txid = uint256_t::from_hex(params[0].as_string());
            uint32_t vout = static_cast<uint32_t>(params[1].as_u64());
            OutPoint outpoint{txid, vout};
            if (!chain_.utxo().contains(outpoint)) {
                result = JsonValue();
            } else {
                result = txout_to_json(chain_.utxo().get(outpoint), chain_.best_height(), chain_.tip_hash());
            }
        } else if (method == "decoderawtransaction") {
            if (params.size() != 1) throw RpcException(-32602, "decoderawtransaction expects [hex]");
            auto raw = parse_hex_string(params[0].as_string());
            const uint8_t* ptr = raw.data();
            size_t rem = raw.size();
            auto tx = Transaction::deserialize(ptr, rem);
            result = tx_to_json(tx);
        } else if (method == "sendrawtransaction") {
            if (params.size() != 1) throw RpcException(-32602, "sendrawtransaction expects [hex]");
            auto raw = parse_hex_string(params[0].as_string());
            const uint8_t* ptr = raw.data();
            size_t rem = raw.size();
            auto tx = Transaction::deserialize(ptr, rem);
            Mempool::AcceptStatus status = Mempool::AcceptStatus::Invalid;
            if (!chain_.mempool().add_transaction(
                    tx, chain_.utxo(), static_cast<uint32_t>(chain_.best_height()), &status)) {
                throw RpcException(-26, "transaction rejected by mempool: " + mempool_status_text(status));
            }
            if (node_) {
                node_->broadcast(tx_inv_message(tx));
                node_->broadcast(tx_message(tx));
            }
            result = JsonValue::string(tx.hash().to_hex());
        } else if (method == "submitblock") {
            if (params.size() != 1) throw RpcException(-32602, "submitblock expects [hex]");
            auto raw = parse_hex_string(params[0].as_string());
            const uint8_t* ptr = raw.data();
            size_t rem = raw.size();
            auto block = Block::deserialize(ptr, rem);
            auto block_hash = block.header.pow_hash();
            if (chain_.knows_hash(block_hash)) {
                result = JsonValue::string("duplicate");
            } else if (!chain_.accept_block(block)) {
                result = JsonValue::string("rejected");
            } else {
                if (node_) node_->broadcast(block_inv_message(block));
                result = JsonValue::string("accepted");
            }
        } else if (method == "getblocktemplate") {
            std::string coinbase_address;
            std::optional<std::string> coinbase_display;
            if (!params.empty()) {
                if (params[0].is_string()) {
                    coinbase_address = params[0].as_string();
                    coinbase_display = coinbase_address;
                } else if (params[0].is_object()) {
                    if (const JsonValue* value = params[0].find("coinbase_address")) coinbase_address = value->as_string();
                    else if (const JsonValue* value = params[0].find("address")) coinbase_address = value->as_string();
                    if (!coinbase_address.empty()) coinbase_display = coinbase_address;
                } else {
                    throw RpcException(-32602, "getblocktemplate expects [coinbase_address?]");
                }
            }
            if (coinbase_address.empty()) {
                require_wallet_session();
                Wallet wallet = load_session_wallet();
                coinbase_address = wallet.address;
                coinbase_display = wallet.display_address(wallet.address);
            }

            auto block = build_block_template(chain_, coinbase_address);
            JsonValue info = JsonValue::object();
            JsonValue capabilities = JsonValue::array({});
            capabilities.push_back(JsonValue::string("proposal"));
            capabilities.push_back(JsonValue::string("coinbasetxn"));
            info.set("capabilities", std::move(capabilities));
            info.set("version", JsonValue::number(static_cast<int64_t>(block.header.version)));
            info.set("height", JsonValue::number(chain_.best_height() + 1));
            info.set("curtime", JsonValue::number(static_cast<uint64_t>(block.header.timestamp)));
            info.set("bits", JsonValue::string(bits_to_hex(block.header.bits)));
            info.set("difficulty", JsonValue::number(difficulty_from_bits(block.header.bits)));
            info.set("target", JsonValue::string(compact_target{block.header.bits}.expand().to_hex_padded(constants::POW_HASH_BYTES)));
            info.set("previousblockhash", JsonValue::string(chain_.tip_hash().to_hex_padded(constants::POW_HASH_BYTES)));
            info.set("previouslinkhash", JsonValue::string(block.header.prev_block_hash.to_hex()));
            info.set("coinbasevalue", JsonValue::number(block.transactions.front().outputs.front().value));
            add_address_formats(info,
                                "coinbase_address",
                                block.transactions.front().outputs.front().scriptPubKey,
                                coinbase_display);
            info.set("blockhex", JsonValue::string(lower_hex(block.serialize())));
            info.set("coinbasetxn", tx_to_json(block.transactions.front()));
            JsonValue txs = JsonValue::array({});
            for (size_t i = 1; i < block.transactions.size(); ++i) {
                JsonValue tx = tx_to_json(block.transactions[i]);
                tx.set("data", JsonValue::string(lower_hex(block.transactions[i].serialize())));
                txs.push_back(std::move(tx));
            }
            info.set("transactions", std::move(txs));
            result = std::move(info);
        } else if (method == "getchatinfo") {
            if (!node_) throw RpcException(-32603, "chat node unavailable");
            JsonValue info = JsonValue::object();
            auto history_path = node_->chat_history_path();
            auto sync = node_->sync_status();
            info.set("historyfile", JsonValue::string(history_path.string()));
            info.set("messages", JsonValue::number(static_cast<uint64_t>(chat::history_count(history_path))));
            info.set("wallet_loaded", JsonValue(has_wallet_session()));
            info.set("connections", JsonValue::number(static_cast<uint64_t>(sync.connected_peers)));
            info.set("validated_peers", JsonValue::number(static_cast<uint64_t>(sync.validated_peers)));
            info.set("routing_mode", JsonValue::string(sync.connected_peers > 0
                ? "peer-network"
                : "awaiting-peers"));
            result = std::move(info);
        } else if (method == "getchatinbox") {
            if (!node_) throw RpcException(-32603, "chat node unavailable");
            auto query = chat_query_from_params(params);
            JsonValue rows = JsonValue::array({});
            for (const auto& entry : node_->chat_history(query)) {
                rows.push_back(chat_entry_to_json(entry));
            }
            result = std::move(rows);
        } else if (method == "sendchatpublic" || method == "sendchatprivate") {
            if (!node_) throw RpcException(-32603, "chat node unavailable");
            require_wallet_session();
            const bool private_chat = method == "sendchatprivate";
            auto request = parse_chat_send_request(params, private_chat);
            Wallet wallet = load_session_wallet();
            net::ChatPayload payload;
            std::string plaintext;

            if (!private_chat) {
                plaintext = request.message;
                payload = chat::make_signed_public_chat(wallet, request.from_address, request.route, plaintext);
            } else {
                plaintext = request.message;
                payload = chat::make_encrypted_private_chat(wallet,
                                                            request.from_address,
                                                            request.recipient_address,
                                                            crypto::base64_decode(request.recipient_pubkey_b64),
                                                            plaintext);
            }

            net::Message msg;
            msg.type = net::MessageType::CHAT;
            msg.payload = payload.serialize();
            auto history = build_outbound_chat_history(payload, plaintext, request.peer_label.value_or("network"));
            node_->remember_chat_message(history.message_id);

            size_t peers = 0;
            if (request.peer_label) {
                auto [host, port] = parse_hostport(*request.peer_label);
                node_->connect(host, port);
                peers = node_->send_to(*request.peer_label, msg) ? 1 : 0;
                history.status = peers > 0 ? "sent" : "no-peer";
            } else {
                if (node_->active_peer_labels().empty()) {
                    node_->bootstrap_chat_routing();
                }
                peers = node_->broadcast_chat(msg);
                history.status = peers > 0 ? "broadcast" : "no-peer";
            }
            node_->record_chat_history(history);

            JsonValue info = JsonValue::object();
            info.set("messageid", JsonValue::string(history.message_id));
            info.set("status", JsonValue::string(history.status));
            info.set("peers", JsonValue::number(static_cast<uint64_t>(peers)));
            info.set("peer", JsonValue::string(request.peer_label.value_or("network")));
            info.set("historyfile", JsonValue::string(node_->chat_history_path().string()));
            result = std::move(info);
        } else if (method == "getcheckpointinfo") {
            auto checkpoint = chain_.checkpoint_info();
            JsonValue info = JsonValue::object();
            info.set("present", JsonValue(checkpoint.present));
            info.set("pinned", JsonValue(checkpoint.pinned));
            info.set("height", JsonValue::number(checkpoint.height));
            info.set("hash", JsonValue::string(checkpoint.present
                ? checkpoint.hash.to_hex_padded(constants::POW_HASH_BYTES)
                : std::string()));
            info.set("max_reorg_depth", JsonValue::number(chain_.max_reorg_depth_limit()));
            info.set("allow_deep_reorg", JsonValue(chain_.deep_reorgs_allowed()));
            info.set("chain_approved", JsonValue(chain_.wallet_state_approved()));
            result = std::move(info);
        } else if (method == "pincheckpoint") {
            chain_.pin_checkpoint_to_tip();
            result = JsonValue(true);
        } else if (method == "clearcheckpointpin") {
            chain_.clear_checkpoint_pin();
            result = JsonValue(true);
        } else if (method == "refreshcheckpoint") {
            chain_.refresh_checkpoint_now();
            result = JsonValue(true);
        } else if (method == "getpeerinfo" || method == "getpeergraph") {
            JsonValue peers = JsonValue::array({});
            if (node_) {
                for (const auto& entry : node_->peer_statuses()) {
                    JsonValue peer = JsonValue::object();
                    peer.set("addr", JsonValue::string(entry.label));
                    peer.set("connected", JsonValue(entry.connected));
                    peer.set("banscore", JsonValue::number(static_cast<int64_t>(entry.score)));
                    peer.set("banned", JsonValue(entry.banned));
                    peer.set("banned_until", JsonValue::number(entry.banned_until));
                    peer.set("startingheight", JsonValue::number(static_cast<uint64_t>(entry.announced_height)));
                    peer.set("source", JsonValue::string(entry.source));
                    peer.set("netgroup", JsonValue::string(entry.netgroup));
                    peer.set("lastseen", JsonValue::number(static_cast<uint64_t>(std::max<int64_t>(entry.last_seen, 0))));
                    peer.set("lastconnected", JsonValue::number(static_cast<uint64_t>(std::max<int64_t>(entry.last_connected, 0))));
                    peer.set("successful_connections", JsonValue::number(entry.successful_connections));
                    peer.set("failed_connections", JsonValue::number(entry.failed_connections));
                    peer.set("invalid_messages", JsonValue::number(entry.invalid_messages));
                    peer.set("last_reason", JsonValue::string(entry.last_reason));
                    peers.push_back(std::move(peer));
                }
            }
            result = std::move(peers);
        } else if (method == "getnetworkinfo") {
            JsonValue info = JsonValue::object();
            auto peers = node_ ? node_->peer_statuses() : std::vector<net::NetworkNode::PeerInfo>{};
            auto advertised = node_ ? node_->advertised_endpoint() : std::optional<std::string>{};
            auto mapping = node_ ? node_->port_mapping_status() : net::NetworkNode::PortMappingStatus{};
            auto sync = node_ ? node_->sync_status() : net::NetworkNode::SyncStatus{};
            uint64_t banned = 0;
            for (const auto& peer : peers) {
                if (peer.banned) ++banned;
            }
            info.set("version", JsonValue::number(static_cast<uint64_t>(constants::PROTOCOL_VERSION)));
            info.set("protocolversion", JsonValue::number(static_cast<uint64_t>(constants::PROTOCOL_VERSION)));
            info.set("connections", JsonValue::number(static_cast<uint64_t>(node_ ? node_->active_peer_labels().size() : 0)));
            info.set("validatedpeers", JsonValue::number(static_cast<uint64_t>(sync.validated_peers)));
            info.set("knownpeers", JsonValue::number(static_cast<uint64_t>(peers.size())));
            info.set("networkactive", JsonValue(node_ ? node_->network_active() : false));
            info.set("bannedpeers", JsonValue::number(banned));
            info.set("relayfee_sats_per_kb", JsonValue::number(constants::MIN_RELAY_FEE_SATS_PER_KB));
            info.set("p2pport", JsonValue::number(static_cast<uint64_t>(default_p2p_port())));
            info.set("rpcport", JsonValue::number(static_cast<uint64_t>(rpc_port_)));
            info.set("externalip", JsonValue::string(advertised ? *advertised : ""));
            info.set("localheight", JsonValue::number(static_cast<uint64_t>(sync.local_height)));
            info.set("bestpeerheight", JsonValue::number(static_cast<uint64_t>(sync.best_peer_height)));
            info.set("queuedblocks", JsonValue::number(static_cast<uint64_t>(sync.queued_blocks)));
            info.set("inflightblocks", JsonValue::number(static_cast<uint64_t>(sync.inflight_blocks)));
            info.set("syncing", JsonValue(sync.syncing));
            info.set("chain_approved", JsonValue(chain_.wallet_state_approved()));
            info.set("approvalpeers", JsonValue::number(chain_.approval_peer_count()));
            info.set("portmapping_enabled", JsonValue(mapping.enabled));
            info.set("portmapping_active", JsonValue(mapping.active));
            info.set("portmapping_available", JsonValue(mapping.available));
            info.set("portmapping_protocol", JsonValue::string(mapping.protocol));
            info.set("portmapping_external", JsonValue::string(mapping.external_endpoint));
            info.set("portmapping_message", JsonValue::string(mapping.message));
            result = std::move(info);
        } else if (method == "getportmappinginfo") {
            JsonValue info = JsonValue::object();
            auto mapping = node_ ? node_->port_mapping_status() : net::NetworkNode::PortMappingStatus{};
            info.set("enabled", JsonValue(mapping.enabled));
            info.set("active", JsonValue(mapping.active));
            info.set("available", JsonValue(mapping.available));
            info.set("protocol", JsonValue::string(mapping.protocol));
            info.set("external_endpoint", JsonValue::string(mapping.external_endpoint));
            info.set("message", JsonValue::string(mapping.message));
            info.set("lease_seconds", JsonValue::number(static_cast<uint64_t>(std::max(mapping.lease_seconds, 0))));
            info.set("refreshed_at", JsonValue::number(static_cast<uint64_t>(std::max<int64_t>(mapping.refreshed_at, 0))));
            result = std::move(info);
        } else if (method == "getmininginfo") {
            JsonValue info = JsonValue::object();
            double difficulty = difficulty_from_bits(chain_.tip_bits());
            auto mempool_stats = chain_.mempool().stats();
            info.set("blocks", JsonValue::number(chain_.best_height()));
            info.set("difficulty", JsonValue::number(difficulty));
            info.set("mempooltx", JsonValue::number(static_cast<uint64_t>(mempool_stats.tx_count)));
            info.set("mempoolbytes", JsonValue::number(static_cast<uint64_t>(mempool_stats.total_bytes)));
            info.set("orphantx", JsonValue::number(static_cast<uint64_t>(mempool_stats.orphan_count)));
            info.set("networkhashps", JsonValue::number(expected_hashes_from_bits(chain_.tip_bits()) / constants::BLOCK_TIME_SECONDS));
            info.set("chain", JsonValue::string(network_name(cryptex::params().network)));
            result = std::move(info);
        } else if (method == "getmempoolinfo") {
            auto mempool_stats = chain_.mempool().stats();
            JsonValue info = JsonValue::object();
            info.set("size", JsonValue::number(static_cast<uint64_t>(mempool_stats.tx_count)));
            info.set("bytes", JsonValue::number(static_cast<uint64_t>(mempool_stats.total_bytes)));
            info.set("orphans", JsonValue::number(static_cast<uint64_t>(mempool_stats.orphan_count)));
            info.set("maxmempool", JsonValue::number(static_cast<uint64_t>(constants::MAX_MEMPOOL_SIZE_BYTES)));
            info.set("minrelaytxfee_sats_per_kb", JsonValue::number(constants::MIN_RELAY_FEE_SATS_PER_KB));
            result = std::move(info);
        } else if (method == "getwalletsessioninfo") {
            JsonValue info = JsonValue::object();
            info.set("wallet_loaded", JsonValue(has_wallet_session()));
            if (wallet_directory_ && !wallet_directory_->empty()) {
                info.set("walletroot", JsonValue::string(*wallet_directory_));
            }
            if (has_wallet_session()) {
                Wallet wallet = load_session_wallet();
                info.set("walletfile", JsonValue::string(*wallet_path_));
                info.set("address_format", JsonValue::string(wallet.address_format_name()));
                info.set("mode", JsonValue::string(wallet.hd_mode()));
                info.set("addresscount", JsonValue::number(static_cast<uint64_t>(wallet.all_addresses().size())));
                info.set("mnemonic_backed", JsonValue(wallet.has_mnemonic()));
                add_address_formats(info, "primaryaddress", wallet.address);
                info.set("primaryaddress", JsonValue::string(wallet.display_address(wallet.address)));
            }
            result = std::move(info);
        } else if (method == "listwallets") {
            JsonValue::array_t rows;
            for (const auto& wallet_file : discover_wallet_files(wallet_directory_, wallet_path_)) {
                if (!std::filesystem::exists(wallet_file)) {
                    continue;
                }
                rows.push_back(wallet_listing_json(wallet_file,
                                                   read_wallet_metadata(wallet_file),
                                                   wallet_path_));
            }
            result = JsonValue::array(std::move(rows));
        } else if (method == "createwallet") {
            if (params.size() < 2 || params.size() > 6) {
                throw RpcException(-32602, "createwallet expects [path, password, format?, words?, mnemonic_passphrase?, mnemonic?]");
            }
            std::filesystem::path wallet_file(params[0].as_string());
            if (wallet_file.empty()) {
                throw RpcException(-32602, "wallet path cannot be empty");
            }
            const std::string wallet_password = params[1].as_string();
            if (wallet_password.empty()) {
                throw RpcException(-32602, "wallet password cannot be empty");
            }
            auto format = Wallet::AddressFormat::Base64;
            if (params.size() >= 3 && !params[2].is_null()) {
                auto parsed = Wallet::parse_address_format(params[2].as_string());
                if (!parsed) {
                    throw RpcException(-32602, "unknown wallet format");
                }
                format = *parsed;
            }
            const size_t mnemonic_words = params.size() >= 4 && !params[3].is_null()
                ? static_cast<size_t>(params[3].as_u64())
                : 24u;
            const std::string mnemonic_passphrase =
                (params.size() >= 5 && !params[4].is_null()) ? params[4].as_string() : std::string();
            const std::string mnemonic =
                (params.size() >= 6 && !params[5].is_null()) ? params[5].as_string() : std::string();

            std::error_code ec;
            if (std::filesystem::exists(wallet_file, ec)) {
                throw RpcException(-4, "wallet file already exists");
            }
            if (wallet_file.has_parent_path()) {
                std::filesystem::create_directories(wallet_file.parent_path(), ec);
                if (ec) {
                    throw RpcException(-32603, "failed to create wallet directory: " + ec.message());
                }
            }

            Wallet wallet = mnemonic.empty()
                ? Wallet::create_new(wallet_password, wallet_file.string(), format, mnemonic_words, mnemonic_passphrase)
                : Wallet::create_from_mnemonic(wallet_password, wallet_file.string(), mnemonic, format, mnemonic_passphrase);
            write_wallet_metadata(wallet_file, wallet_file.stem().string(), wallet.address_format_name());
            set_wallet_session(wallet_file.string(), wallet_password);

            JsonValue info = JsonValue::object();
            info.set("wallet_loaded", JsonValue(true));
            info.set("walletfile", JsonValue::string(wallet_file.string()));
            info.set("address_format", JsonValue::string(wallet.address_format_name()));
            info.set("mode", JsonValue::string(wallet.hd_mode()));
            info.set("addresscount", JsonValue::number(static_cast<uint64_t>(wallet.all_addresses().size())));
            info.set("mnemonic_backed", JsonValue(wallet.has_mnemonic()));
            add_address_formats(info, "primaryaddress", wallet.address);
            info.set("primaryaddress", JsonValue::string(wallet.display_address(wallet.address)));
            if (wallet.has_mnemonic()) {
                info.set("mnemonic", JsonValue::string(wallet.mnemonic_phrase()));
            }
            result = std::move(info);
        } else if (method == "openwallet") {
            if (params.size() != 2) {
                throw RpcException(-32602, "openwallet expects [path, password]");
            }
            const std::string wallet_path = params[0].as_string();
            const std::string wallet_password = params[1].as_string();
            Wallet wallet = Wallet::load(wallet_password, wallet_path);
            write_wallet_metadata(std::filesystem::path(wallet_path),
                                  std::filesystem::path(wallet_path).stem().string(),
                                  wallet.address_format_name());
            set_wallet_session(wallet_path, wallet_password);
            JsonValue info = JsonValue::object();
            info.set("wallet_loaded", JsonValue(true));
            info.set("walletfile", JsonValue::string(wallet_path));
            info.set("address_format", JsonValue::string(wallet.address_format_name()));
            info.set("mode", JsonValue::string(wallet.hd_mode()));
            info.set("addresscount", JsonValue::number(static_cast<uint64_t>(wallet.all_addresses().size())));
            info.set("mnemonic_backed", JsonValue(wallet.has_mnemonic()));
            add_address_formats(info, "primaryaddress", wallet.address);
            info.set("primaryaddress", JsonValue::string(wallet.display_address(wallet.address)));
            result = std::move(info);
        } else if (method == "closewallet") {
            clear_wallet_session();
            result = JsonValue(true);
        } else if (method == "deletewallet") {
            if (params.size() != 1) {
                throw RpcException(-32602, "deletewallet expects [path]");
            }
            std::filesystem::path wallet_file(params[0].as_string());
            if (wallet_file.empty()) {
                throw RpcException(-32602, "wallet path cannot be empty");
            }
            std::error_code ec;
            if (!std::filesystem::exists(wallet_file, ec)) {
                throw RpcException(-5, "wallet file not found");
            }
            if (has_wallet_session() && std::filesystem::path(*wallet_path_) == wallet_file) {
                clear_wallet_session();
            }
            if (!std::filesystem::remove(wallet_file, ec) || ec) {
                throw RpcException(-32603, "failed to delete wallet file: " + ec.message());
            }
            remove_wallet_metadata(wallet_file);
            result = JsonValue(true);
        } else if (method == "getwalletinfo" || method == "getbalance" || method == "listunspent" ||
                   method == "getwalletaddresses" || method == "getwalletaddressbook" ||
                   method == "getwallethistory" || method == "getwallettransactions" ||
                   method == "getwallettransaction" || method == "setaddresslabel" ||
                   method == "getnewaddress" || method == "getunusedaddress" ||
                   method == "setwalletformat" ||
                   method == "dumpprivkey" || method == "importprivkey" ||
                   method == "importmnemonic" || method == "backupwallet" || method == "recoverwallet" ||
                   method == "walletpassphrasechange" || method == "sendtoaddress" ||
                   method == "dumpmnemonic" || method == "rescanwallet") {
            require_wallet_session();
            if (method == "getnewaddress") {
                if (params.size() > 1) {
                    throw RpcException(-32602, "getnewaddress expects [format?]");
                }
                Wallet wallet = load_session_wallet();
                auto address = wallet.add_address(*wallet_password_, *wallet_path_);
                if (params.size() == 1 && !params[0].is_null()) {
                    auto requested = Wallet::parse_address_format(params[0].as_string());
                    if (!requested) {
                        throw RpcException(-32602, "unknown address format");
                    }
                    address = wallet.display_address(address, *requested);
                }
                result = JsonValue::string(address);
            } else if (method == "getunusedaddress") {
                if (params.size() > 1) {
                    throw RpcException(-32602, "getunusedaddress expects [format?]");
                }
                Wallet wallet = load_session_wallet();
                auto address = wallet.unused_receive_address(chain_, *wallet_password_, *wallet_path_);
                if (params.size() == 1 && !params[0].is_null()) {
                    auto requested = Wallet::parse_address_format(params[0].as_string());
                    if (!requested) {
                        throw RpcException(-32602, "unknown address format");
                    }
                    address = wallet.display_address(address, *requested);
                }
                result = JsonValue::string(address);
            } else if (method == "setwalletformat") {
                if (params.size() != 1) {
                    throw RpcException(-32602, "setwalletformat expects [format]");
                }
                auto requested = Wallet::parse_address_format(params[0].as_string());
                if (!requested) {
                    throw RpcException(-32602, "unknown wallet format");
                }
                Wallet wallet = load_session_wallet();
                wallet.change_address_format(*wallet_password_, *wallet_path_, *requested);
                wallet = Wallet::load(*wallet_password_, *wallet_path_);
                if (wallet_path_) {
                    write_wallet_metadata(std::filesystem::path(*wallet_path_),
                                          std::filesystem::path(*wallet_path_).stem().string(),
                                          wallet.address_format_name());
                }
                JsonValue info = JsonValue::object();
                info.set("address_format", JsonValue::string(wallet.address_format_name()));
                add_address_formats(info, "primaryaddress", wallet.address);
                info.set("primaryaddress", JsonValue::string(wallet.display_address(wallet.address)));
                info.set("addresscount", JsonValue::number(static_cast<uint64_t>(wallet.all_addresses().size())));
                result = std::move(info);
            } else if (method == "setaddresslabel") {
                if (params.size() != 2) throw RpcException(-32602, "setaddresslabel expects [address, label]");
                Wallet wallet = load_session_wallet();
                wallet.set_label(*wallet_password_, *wallet_path_, params[0].as_string(), params[1].as_string());
                result = JsonValue(true);
            } else if (method == "dumpmnemonic") {
                Wallet wallet = load_session_wallet();
                result = JsonValue::string(wallet.mnemonic_phrase());
            } else if (method == "dumpprivkey") {
                if (params.size() > 1) {
                    throw RpcException(-32602, "dumpprivkey expects [address?]");
                }
                Wallet wallet = load_session_wallet();
                std::optional<std::string> requested_address;
                if (!params.empty()) {
                    requested_address = params[0].as_string();
                }
                result = JsonValue::string(wallet.dump_private_key_hex(requested_address));
            } else if (method == "importprivkey") {
                if (params.empty() || params.size() > 2) {
                    throw RpcException(-32602, "importprivkey expects [private_key_hex, label?]");
                }
                Wallet wallet = load_session_wallet();
                const std::string label = params.size() == 2 ? params[1].as_string() : std::string();
                result = JsonValue::string(
                    wallet.import_private_key_hex(*wallet_password_,
                                                  *wallet_path_,
                                                  params[0].as_string(),
                                                  label));
            } else if (method == "importmnemonic") {
                if (params.empty() || params.size() > 2) {
                    throw RpcException(-32602, "importmnemonic expects [mnemonic, mnemonic_passphrase?]");
                }
                std::filesystem::path wallet_file(*wallet_path_);
                std::filesystem::path backup_file = wallet_file;
                backup_file += ".before-import.bak";
                std::error_code ec;
                if (std::filesystem::exists(wallet_file, ec)) {
                    std::filesystem::copy_file(wallet_file,
                                               backup_file,
                                               std::filesystem::copy_options::overwrite_existing,
                                               ec);
                    if (ec) {
                        throw RpcException(-32603, "failed to back up wallet before mnemonic import: " + ec.message());
                    }
                }
                const std::string mnemonic_passphrase =
                    params.size() == 2 ? params[1].as_string() : std::string();
                Wallet current_wallet = load_session_wallet();
                Wallet restored = Wallet::create_from_mnemonic(*wallet_password_,
                                                               *wallet_path_,
                                                               params[0].as_string(),
                                                               current_wallet.address_format(),
                                                               mnemonic_passphrase);
                JsonValue info = JsonValue::object();
                info.set("walletfile", JsonValue::string(*wallet_path_));
                info.set("backupfile", JsonValue::string(backup_file.string()));
                info.set("addresscount", JsonValue::number(static_cast<uint64_t>(restored.all_addresses().size())));
                info.set("address_format", JsonValue::string(restored.address_format_name()));
                add_address_formats(info, "primaryaddress", restored.address);
                info.set("primaryaddress", JsonValue::string(restored.display_address(restored.address)));
                result = std::move(info);
            } else if (method == "backupwallet") {
                if (params.size() != 1) {
                    throw RpcException(-32602, "backupwallet expects [destination_path]");
                }
                std::filesystem::path source(*wallet_path_);
                std::filesystem::path destination(params[0].as_string());
                if (destination.empty()) {
                    throw RpcException(-32602, "backupwallet destination path cannot be empty");
                }
                std::error_code ec;
                if (std::filesystem::exists(destination, ec) &&
                    std::filesystem::is_directory(destination, ec)) {
                    destination /= source.filename();
                }
                if (destination.has_parent_path()) {
                    std::filesystem::create_directories(destination.parent_path(), ec);
                    if (ec) {
                        throw RpcException(-32603, "failed to create backup directory: " + ec.message());
                    }
                }
                std::filesystem::copy_file(source,
                                           destination,
                                           std::filesystem::copy_options::overwrite_existing,
                                           ec);
                if (ec) {
                    throw RpcException(-32603, "failed to back up wallet: " + ec.message());
                }
                result = JsonValue::string(destination.string());
            } else if (method == "recoverwallet") {
                if (!params.empty()) {
                    throw RpcException(-32602, "recoverwallet expects []");
                }
                Wallet recovered = Wallet::recover(*wallet_password_, *wallet_path_);
                JsonValue info = JsonValue::object();
                info.set("walletfile", JsonValue::string(*wallet_path_));
                info.set("backupfile", JsonValue::string((std::filesystem::path(*wallet_path_).string() + ".bak")));
                info.set("addresscount", JsonValue::number(static_cast<uint64_t>(recovered.all_addresses().size())));
                info.set("address_format", JsonValue::string(recovered.address_format_name()));
                add_address_formats(info, "primaryaddress", recovered.address);
                info.set("primaryaddress", JsonValue::string(recovered.display_address(recovered.address)));
                result = std::move(info);
            } else if (method == "walletpassphrasechange") {
                if (params.size() != 2) {
                    throw RpcException(-32602, "walletpassphrasechange expects [old_password, new_password]");
                }
                Wallet wallet = Wallet::load(params[0].as_string(), *wallet_path_);
                wallet.change_password(params[0].as_string(), params[1].as_string(), *wallet_path_);
                set_wallet_session(*wallet_path_, params[1].as_string());
                result = JsonValue(true);
            } else if (method == "rescanwallet") {
                Wallet wallet = load_session_wallet();
                uint32_t gap_limit = params.empty() ? 20u : static_cast<uint32_t>(params[0].as_i64());
                auto discovered = wallet.rescan(chain_, *wallet_password_, *wallet_path_, gap_limit);
                JsonValue info = JsonValue::object();
                info.set("discovered", JsonValue::number(static_cast<uint64_t>(discovered)));
                info.set("addresscount", JsonValue::number(static_cast<uint64_t>(wallet.all_addresses().size())));
                result = std::move(info);
            } else if (method == "sendtoaddress") {
                if (params.size() < 2 || params.size() > 4) {
                    throw RpcException(-32602, "sendtoaddress expects [address, amount_sats, op_return?|options?, options?]");
                }
                if (!chain_.wallet_state_approved()) {
                    throw RpcException(-32010, "wallet is locked until chain sync is approved");
                }
                SendOptions options;
                if (params.size() >= 3) {
                    if (params[2].is_string()) {
                        options.op_return = params[2].as_string();
                    } else if (params[2].is_object()) {
                        parse_send_options_object(params[2], options);
                    } else {
                        throw RpcException(-32602, "third sendtoaddress parameter must be string or object");
                    }
                }
                if (params.size() >= 4) {
                    if (!params[3].is_object()) throw RpcException(-32602, "fourth sendtoaddress parameter must be an options object");
                    parse_send_options_object(params[3], options);
                }
                Wallet wallet = load_session_wallet();
                wallet.ensure_unused_pool(chain_, *wallet_password_, *wallet_path_);
                auto tx = wallet.create_payment(chain_,
                                                params[0].as_string(),
                                                params[1].as_i64(),
                                                options.op_return,
                                                options.fee_per_kb,
                                                options.selected_inputs,
                                                options.change_address);
                Mempool::AcceptStatus status = Mempool::AcceptStatus::Invalid;
                if (!chain_.mempool().add_transaction(
                        tx, chain_.utxo(), static_cast<uint32_t>(chain_.best_height()), &status)) {
                    throw RpcException(-26, "transaction rejected by mempool: " + mempool_status_text(status));
                }
                if (node_) {
                    node_->broadcast(tx_inv_message(tx));
                    node_->broadcast(tx_message(tx));
                }
                result = JsonValue::string(tx.hash().to_hex());
            } else {
                Wallet wallet = load_session_wallet();
                auto summary = wallet.balance_summary(chain_);
                if (method == "getwalletinfo") {
                    JsonValue info = JsonValue::object();
                    info.set("walletfile", JsonValue::string(*wallet_path_));
                    info.set("wallet_loaded", JsonValue(true));
                    info.set("mode", JsonValue::string(wallet.hd_mode()));
                    info.set("address_format", JsonValue::string(wallet.address_format_name()));
                    info.set("addresscount", JsonValue::number(static_cast<uint64_t>(wallet.all_addresses().size())));
                    add_address_formats(info, "primaryaddress", wallet.address);
                    info.set("primaryaddress", JsonValue::string(wallet.display_address(wallet.address)));
                    info.set("mnemonic_backed", JsonValue(wallet.has_mnemonic()));
                    info.set("chain_approved", JsonValue(summary.approved));
                    info.set("balance_sats", JsonValue::number(summary.spendable));
                    info.set("immature_balance_sats", JsonValue::number(summary.immature));
                    info.set("locked_balance_sats", JsonValue::number(summary.locked));
                    info.set("total_balance_sats", JsonValue::number(summary.total()));
                    result = std::move(info);
                } else if (method == "getbalance") {
                    result = JsonValue::number(summary.spendable);
                } else if (method == "getwalletaddresses") {
                    JsonValue addresses = JsonValue::array({});
                    for (const auto& address : wallet.all_addresses()) {
                        addresses.push_back(JsonValue::string(wallet.display_address(address)));
                    }
                    result = std::move(addresses);
                } else if (method == "getwalletaddressbook") {
                    JsonValue addresses = JsonValue::array({});
                    for (const auto& entry : wallet.address_book()) {
                        addresses.push_back(wallet_address_to_json(entry));
                    }
                    result = std::move(addresses);
                } else if (method == "getwallethistory") {
                    if (params.size() > 1) {
                        throw RpcException(-32602, "getwallethistory expects [include_mempool?]");
                    }
                    bool include_mempool = params.size() == 1 && params[0].as_bool();
                    JsonValue history = JsonValue::array({});
                    for (const auto& entry : wallet.history(chain_, include_mempool)) {
                        history.push_back(JsonValue::string(entry));
                    }
                    result = std::move(history);
                } else if (method == "getwallettransactions") {
                    if (params.size() > 1) {
                        throw RpcException(-32602, "getwallettransactions expects [include_mempool?]");
                    }
                    bool include_mempool = params.size() == 1 && params[0].as_bool();
                    JsonValue history = JsonValue::array({});
                    for (const auto& entry : wallet.history_entries(chain_, include_mempool)) {
                        auto row = wallet_history_to_json(entry);
                        row.set("summary_address", JsonValue::string(address_for_wallet_display(wallet, entry.summary_address)));
                        JsonValue from = JsonValue::array({});
                        for (const auto& address : entry.from_addresses) {
                            from.push_back(JsonValue::string(address_for_wallet_display(wallet, address)));
                        }
                        row.set("from_addresses", std::move(from));
                        JsonValue to = JsonValue::array({});
                        for (const auto& address : entry.to_addresses) {
                            to.push_back(JsonValue::string(address_for_wallet_display(wallet, address)));
                        }
                        row.set("to_addresses", std::move(to));
                        history.push_back(std::move(row));
                    }
                    result = std::move(history);
                } else if (method == "getwallettransaction") {
                    if (params.empty() || params.size() > 2) {
                        throw RpcException(-32602, "getwallettransaction expects [txid, include_mempool?]");
                    }
                    bool include_mempool = params.size() == 2 && params[1].as_bool();
                    auto detail = wallet.transaction_detail(chain_, params[0].as_string(), include_mempool);
                    if (!detail) throw RpcException(-5, "wallet transaction not found");
                    auto row = wallet_history_to_json(*detail);
                    row.set("summary_address", JsonValue::string(address_for_wallet_display(wallet, detail->summary_address)));
                    JsonValue from = JsonValue::array({});
                    for (const auto& address : detail->from_addresses) {
                        from.push_back(JsonValue::string(address_for_wallet_display(wallet, address)));
                    }
                    row.set("from_addresses", std::move(from));
                    JsonValue to = JsonValue::array({});
                    for (const auto& address : detail->to_addresses) {
                        to.push_back(JsonValue::string(address_for_wallet_display(wallet, address)));
                    }
                    row.set("to_addresses", std::move(to));
                    result = std::move(row);
                } else {
                    JsonValue utxos = JsonValue::array({});
                    for (const auto& [outpoint, entry] : wallet.list_unspent(chain_)) {
                        JsonValue row = JsonValue::object();
                        row.set("txid", JsonValue::string(outpoint.tx_hash.to_hex()));
                        row.set("vout", JsonValue::number(static_cast<uint64_t>(outpoint.index)));
                        row.set("amount_sats", JsonValue::number(entry.output.value));
                        add_address_formats(row, "address", entry.output.scriptPubKey);
                        row.set("address", JsonValue::string(wallet.display_address(entry.output.scriptPubKey)));
                        row.set("height", JsonValue::number(static_cast<uint64_t>(entry.block_height)));
                        row.set("coinbase", JsonValue(entry.is_coinbase));
                        utxos.push_back(std::move(row));
                    }
                    result = std::move(utxos);
                }
            }
        } else if (method == "addnode") {
            if (!node_) throw RpcException(-32603, "p2p node unavailable");
            if (params.size() != 1) throw RpcException(-32602, "addnode expects [host:port]");
            auto [host, port] = parse_hostport(params[0].as_string());
            node_->connect(host, port);
            result = JsonValue(true);
        } else if (method == "setban") {
            if (!node_) throw RpcException(-32603, "p2p node unavailable");
            if (params.empty() || params.size() > 2) throw RpcException(-32602, "setban expects [host:port, duration_seconds?]");
            int duration = params.size() >= 2 ? static_cast<int>(params[1].as_i64())
                                              : constants::BANNED_PEER_DURATION_SECONDS;
            node_->set_ban(params[0].as_string(), duration);
            result = JsonValue(true);
        } else if (method == "clearbanned") {
            if (!node_) throw RpcException(-32603, "p2p node unavailable");
            node_->clear_bans();
            result = JsonValue(true);
        } else if (method == "setnetworkactive") {
            if (!node_) throw RpcException(-32603, "p2p node unavailable");
            if (params.size() != 1) throw RpcException(-32602, "setnetworkactive expects [true|false]");
            node_->set_network_active(params[0].as_bool());
            result = JsonValue(node_->network_active());
        } else if (method == "listbanned") {
            JsonValue banned = JsonValue::array({});
            if (node_) {
                for (const auto& entry : node_->peer_statuses()) {
                    if (!entry.banned) continue;
                    JsonValue row = JsonValue::object();
                    row.set("addr", JsonValue::string(entry.label));
                    row.set("banscore", JsonValue::number(static_cast<int64_t>(entry.score)));
                    row.set("banned_until", JsonValue::number(entry.banned_until));
                    banned.push_back(std::move(row));
                }
            }
            result = std::move(banned);
        } else if (method == "stop") {
            stop_requested = true;
            result = JsonValue::string("stopping");
        } else {
            throw RpcException(-32601, "method not found");
        }

        return json_serialize(make_response(id, result, std::nullopt));
    } catch (const RpcException& ex) {
        return json_serialize(make_response(id, JsonValue(), make_error_object(ex.code(), ex.what())));
    } catch (const std::exception& ex) {
        return json_serialize(make_response(id, JsonValue(), make_error_object(-32603, ex.what())));
    } catch (...) {
        return json_serialize(make_response(id, JsonValue(), make_error_object(-32603, "unknown RPC error")));
    }
}

class RpcServer::Impl : public std::enable_shared_from_this<RpcServer::Impl> {
public:
    Impl(boost::asio::io_context& ctx,
         const RpcConfig& config,
         Blockchain& chain,
         net::NetworkNode* node)
        : ctx_(ctx),
          config_(config),
          service_(chain, node, config.wallet_path, config.wallet_password, config.port, config.wallet_directory),
          acceptor_(ctx) {}

    void start() {
        tcp::endpoint endpoint(boost::asio::ip::make_address(config_.bind), config_.port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(boost::asio::socket_base::max_listen_connections);
        do_accept();
    }

    void stop() {
        beast::error_code ec;
        acceptor_.close(ec);
    }

    void set_stop_callback(std::function<void()> callback) {
        stop_callback_ = std::move(callback);
        service_.set_stop_callback(stop_callback_);
    }

private:
    struct RateWindow {
        std::deque<std::chrono::steady_clock::time_point> requests;
    };

    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(tcp::socket socket, std::shared_ptr<Impl> owner)
            : socket_(std::move(socket)), owner_(std::move(owner)) {}

        void start() { do_read(); }

    private:
        void do_read() {
            auto self = shared_from_this();
            parser_.body_limit(owner_->config_.max_body_bytes);
            http::async_read(socket_, buffer_, parser_,
                [self](beast::error_code ec, std::size_t) {
                    if (ec == http::error::body_limit) {
                        self->response_.version(11);
                        self->response_.set(http::field::server, "CryptEX-RPC");
                        self->response_.keep_alive(false);
                        self->response_.result(http::status::payload_too_large);
                        self->response_.set(http::field::content_type, "application/json");
                        self->response_.body() = "{\"error\":\"request too large\"}";
                        self->response_.prepare_payload();
                        return self->do_write(false);
                    }
                    if (ec) return;
                    self->request_ = self->parser_.release();
                    self->process();
                });
        }

        void process() {
            response_.version(request_.version());
            response_.set(http::field::server, "CryptEX-RPC");
            response_.keep_alive(false);

            if (!owner_->allowed(socket_.remote_endpoint())) {
                response_.result(http::status::forbidden);
                response_.body() = "{\"error\":\"forbidden\"}";
                response_.set(http::field::content_type, "application/json");
                response_.prepare_payload();
                return do_write(false);
            }

            if (!owner_->allow_rate(socket_.remote_endpoint())) {
                response_.result(static_cast<http::status>(429));
                response_.set(http::field::retry_after,
                              std::to_string(owner_->config_.rate_limit_window_seconds));
                response_.body() = "{\"error\":\"rate limit exceeded\"}";
                response_.set(http::field::content_type, "application/json");
                response_.prepare_payload();
                return do_write(false);
            }

            if (!owner_->authorized(request_)) {
                response_.result(http::status::unauthorized);
                response_.set(http::field::www_authenticate, "Basic realm=\"CryptEX RPC\"");
                response_.body() = "{\"error\":\"unauthorized\"}";
                response_.set(http::field::content_type, "application/json");
                response_.prepare_payload();
                return do_write(false);
            }

            if (request_.method() != http::verb::post) {
                response_.result(http::status::method_not_allowed);
                response_.body() = "{\"error\":\"POST required\"}";
                response_.set(http::field::content_type, "application/json");
                response_.prepare_payload();
                return do_write(false);
            }

            bool stop_requested = false;
            response_.result(http::status::ok);
            response_.set(http::field::content_type, "application/json");
            response_.set(http::field::cache_control, "no-store");
            response_.body() = owner_->service_.handle_jsonrpc(request_.body(), stop_requested);
            response_.prepare_payload();
            do_write(stop_requested);
        }

        void do_write(bool stop_requested) {
            auto self = shared_from_this();
            http::async_write(socket_, response_,
                [self, stop_requested](beast::error_code ec, std::size_t) {
                    beast::error_code ignored;
                    self->socket_.shutdown(tcp::socket::shutdown_send, ignored);
                    if (!ec && stop_requested && self->owner_->stop_callback_) {
                        boost::asio::post(self->owner_->ctx_, self->owner_->stop_callback_);
                    }
                });
        }

        tcp::socket socket_;
        beast::flat_buffer buffer_;
        http::request_parser<http::string_body> parser_;
        http::request<http::string_body> request_;
        http::response<http::string_body> response_;
        std::shared_ptr<Impl> owner_;
    };

    bool authorized(const http::request<http::string_body>& request) const {
        std::optional<std::pair<std::string, std::string>> credentials;
        try {
            credentials = parse_basic_credentials(request);
        } catch (...) {
            return false;
        }
        if (!credentials) return false;

        if (!config_.auth_entries.empty()) {
            for (const auto& entry : config_.auth_entries) {
                if (matches_rpcauth_entry(entry, credentials->first, credentials->second)) {
                    return true;
                }
            }
        }

        if (config_.username.empty() && config_.password.empty()) {
            return config_.auth_entries.empty();
        }
        return timing_safe_equal(config_.username, credentials->first) &&
               timing_safe_equal(config_.password, credentials->second);
    }

    bool allowed(const tcp::endpoint& remote) const {
        return address_allowed(config_.allow_ips, remote);
    }

    bool allow_rate(const tcp::endpoint& remote) {
        if (config_.max_requests_per_window == 0 || config_.rate_limit_window_seconds == 0) {
            return true;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto cutoff = now - std::chrono::seconds(config_.rate_limit_window_seconds);
        const std::string key = remote.address().to_string();

        std::lock_guard<std::mutex> guard(rate_limit_mutex_);
        auto& window = rate_windows_[key].requests;
        while (!window.empty() && window.front() < cutoff) {
            window.pop_front();
        }
        if (window.size() >= config_.max_requests_per_window) {
            return false;
        }
        window.push_back(now);
        return true;
    }

    void do_accept() {
        auto self = shared_from_this();
        acceptor_.async_accept([self](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::make_shared<Session>(std::move(socket), self)->start();
            }
            if (self->acceptor_.is_open()) self->do_accept();
        });
    }

    boost::asio::io_context& ctx_;
    RpcConfig config_;
    RpcService service_;
    tcp::acceptor acceptor_;
    std::function<void()> stop_callback_;
    std::mutex rate_limit_mutex_;
    std::unordered_map<std::string, RateWindow> rate_windows_;
};

RpcServer::RpcServer(boost::asio::io_context& ctx,
                     const RpcConfig& config,
                     Blockchain& chain,
                     net::NetworkNode* node)
    : impl_(std::make_shared<Impl>(ctx, config, chain, node)) {}

void RpcServer::start() {
    impl_->start();
}

void RpcServer::stop() {
    impl_->stop();
}

void RpcServer::set_stop_callback(std::function<void()> callback) {
    impl_->set_stop_callback(std::move(callback));
}

} // namespace rpc
} // namespace cryptex
