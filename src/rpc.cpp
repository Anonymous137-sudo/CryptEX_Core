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
#include <cctype>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <functional>
#include <iomanip>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
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
        out_obj.set("address", JsonValue::string(out.scriptPubKey));
        vout.push_back(std::move(out_obj));
    }
    obj.set("vout", std::move(vout));
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
    out.set("address", JsonValue::string(entry.output.scriptPubKey));
    out.set("coinbase", JsonValue(entry.is_coinbase));
    out.set("height", JsonValue::number(static_cast<uint64_t>(entry.block_height)));
    return out;
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

} // namespace

RpcService::RpcService(Blockchain& chain,
                       net::NetworkNode* node,
                       std::optional<std::string> wallet_path,
                       std::optional<std::string> wallet_password,
                       uint16_t rpc_port)
    : chain_(chain),
      node_(node),
      wallet_path_(std::move(wallet_path)),
      wallet_password_(std::move(wallet_password)),
      rpc_port_(rpc_port) {}

void RpcService::set_stop_callback(std::function<void()> callback) {
    stop_callback_ = std::move(callback);
}

std::string RpcService::handle_jsonrpc(const std::string& body, bool& stop_requested) const {
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

        if (method == "help") {
            JsonValue methods = JsonValue::array({});
            for (const char* name : {
                     "help", "getblockcount", "getbestblockhash", "getblockhash",
                     "getblockheader", "getblock", "getblockchaininfo", "getchaintips",
                     "getdifficulty", "getrawmempool", "getrawtransaction", "gettxout",
                     "decoderawtransaction", "sendrawtransaction", "submitblock",
                     "getchatinfo", "getchatinbox", "sendchatpublic", "sendchatprivate",
                     "getpeerinfo", "getnetworkinfo", "getmininginfo", "getmempoolinfo",
                     "getwalletinfo", "getbalance", "listunspent", "getwalletaddresses",
                     "getwallethistory", "getnewaddress",
                     "sendtoaddress", "addnode", "setban", "clearbanned",
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
        } else if (method == "getdifficulty") {
            result = JsonValue::number(difficulty_from_bits(chain_.tip_bits()));
        } else if (method == "getblockchaininfo") {
            JsonValue info = JsonValue::object();
            auto tip = chain_.get_block(chain_.best_height());
            uint64_t serialized_bytes = 0;
            for (uint64_t h = 0; h <= chain_.best_height(); ++h) {
                auto block = chain_.get_block(h);
                if (!block) continue;
                serialized_bytes += static_cast<uint64_t>(block->serialize().size());
            }
            info.set("chain", JsonValue::string(network_name(cryptex::params().network)));
            info.set("blocks", JsonValue::number(chain_.best_height()));
            info.set("headers", JsonValue::number(chain_.best_height()));
            info.set("bestblockhash", JsonValue::string(chain_.tip_hash().to_hex_padded(constants::POW_HASH_BYTES)));
            info.set("difficulty", JsonValue::number(difficulty_from_bits(chain_.tip_bits())));
            info.set("mediantime", JsonValue::number(static_cast<uint64_t>(tip ? tip->header.timestamp : 0)));
            info.set("verificationprogress", JsonValue::number(1.0));
            info.set("initialblockdownload", JsonValue(false));
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
        } else if (method == "getchatinfo") {
            if (!node_) throw RpcException(-32603, "chat node unavailable");
            JsonValue info = JsonValue::object();
            auto history_path = node_->chat_history_path();
            info.set("historyfile", JsonValue::string(history_path.string()));
            info.set("messages", JsonValue::number(static_cast<uint64_t>(chat::history_count(history_path))));
            info.set("wallet_loaded", JsonValue(static_cast<bool>(wallet_path_ && wallet_password_)));
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
            if (!wallet_path_ || !wallet_password_) {
                throw RpcException(-32603, "chat RPC requires --wallet and --walletpass on node startup");
            }
            const bool private_chat = method == "sendchatprivate";
            if ((!private_chat && (params.size() < 3 || params.size() > 4)) ||
                (private_chat && (params.size() < 4 || params.size() > 5))) {
                throw RpcException(-32602,
                                   private_chat
                                       ? "sendchatprivate expects [host:port, recipient_address, recipient_pubkey_b64, message, from_address?]"
                                       : "sendchatpublic expects [host:port, channel, message, from_address?]");
            }

            Wallet wallet = Wallet::load(*wallet_password_, *wallet_path_);
            const std::string peer_label = params[0].as_string();
            auto [host, port] = parse_hostport(peer_label);
            net::ChatPayload payload;
            std::string plaintext;
            std::string from_address;

            if (!private_chat) {
                if (params.size() == 4) from_address = params[3].as_string();
                plaintext = params[2].as_string();
                payload = chat::make_signed_public_chat(wallet, from_address, params[1].as_string(), plaintext);
            } else {
                if (params.size() == 5) from_address = params[4].as_string();
                plaintext = params[3].as_string();
                payload = chat::make_encrypted_private_chat(wallet,
                                                            from_address,
                                                            params[1].as_string(),
                                                            crypto::base64_decode(params[2].as_string()),
                                                            plaintext);
            }

            net::Message msg;
            msg.type = net::MessageType::CHAT;
            msg.payload = payload.serialize();

            node_->connect(host, port);
            auto history = build_outbound_chat_history(payload, plaintext, peer_label);
            history.status = node_->send_to(peer_label, msg) ? "sent" : "no-peer";
            node_->record_chat_history(history);

            JsonValue info = JsonValue::object();
            info.set("messageid", JsonValue::string(history.message_id));
            info.set("status", JsonValue::string(history.status));
            info.set("historyfile", JsonValue::string(node_->chat_history_path().string()));
            result = std::move(info);
        } else if (method == "getpeerinfo") {
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
                    peers.push_back(std::move(peer));
                }
            }
            result = std::move(peers);
        } else if (method == "getnetworkinfo") {
            JsonValue info = JsonValue::object();
            auto peers = node_ ? node_->peer_statuses() : std::vector<net::NetworkNode::PeerInfo>{};
            auto advertised = node_ ? node_->advertised_endpoint() : std::optional<std::string>{};
            uint64_t banned = 0;
            for (const auto& peer : peers) {
                if (peer.banned) ++banned;
            }
            info.set("version", JsonValue::number(static_cast<uint64_t>(constants::PROTOCOL_VERSION)));
            info.set("protocolversion", JsonValue::number(static_cast<uint64_t>(constants::PROTOCOL_VERSION)));
            info.set("connections", JsonValue::number(static_cast<uint64_t>(node_ ? node_->active_peer_labels().size() : 0)));
            info.set("knownpeers", JsonValue::number(static_cast<uint64_t>(peers.size())));
            info.set("bannedpeers", JsonValue::number(banned));
            info.set("relayfee_sats_per_kb", JsonValue::number(constants::MIN_RELAY_FEE_SATS_PER_KB));
            info.set("p2pport", JsonValue::number(static_cast<uint64_t>(default_p2p_port())));
            info.set("rpcport", JsonValue::number(static_cast<uint64_t>(rpc_port_)));
            info.set("externalip", JsonValue::string(advertised ? *advertised : ""));
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
        } else if (method == "getwalletinfo" || method == "getbalance" || method == "listunspent" ||
                   method == "getwalletaddresses" || method == "getwallethistory" ||
                   method == "getnewaddress" || method == "sendtoaddress" ||
                   method == "dumpmnemonic" || method == "rescanwallet") {
            if (!wallet_path_ || !wallet_password_) {
                throw RpcException(-32603, "wallet RPC requires --wallet and --walletpass on node startup");
            }
            if (method == "getnewaddress") {
                Wallet wallet = Wallet::load(*wallet_password_, *wallet_path_);
                auto address = wallet.add_address(*wallet_password_, *wallet_path_);
                result = JsonValue::string(address);
            } else if (method == "dumpmnemonic") {
                Wallet wallet = Wallet::load(*wallet_password_, *wallet_path_);
                result = JsonValue::string(wallet.mnemonic_phrase());
            } else if (method == "rescanwallet") {
                Wallet wallet = Wallet::load(*wallet_password_, *wallet_path_);
                uint32_t gap_limit = params.empty() ? 20u : static_cast<uint32_t>(params[0].as_i64());
                auto discovered = wallet.rescan(chain_, *wallet_password_, *wallet_path_, gap_limit);
                JsonValue info = JsonValue::object();
                info.set("discovered", JsonValue::number(static_cast<uint64_t>(discovered)));
                info.set("addresscount", JsonValue::number(static_cast<uint64_t>(wallet.all_addresses().size())));
                result = std::move(info);
            } else if (method == "sendtoaddress") {
                if (params.size() < 2 || params.size() > 3) {
                    throw RpcException(-32602, "sendtoaddress expects [address, amount_sats, op_return?]");
                }
                Wallet wallet = Wallet::load(*wallet_password_, *wallet_path_);
                auto tx = wallet.create_payment(chain_, params[0].as_string(), params[1].as_i64(),
                                                params.size() >= 3 ? params[2].as_string() : "");
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
                Wallet wallet = Wallet::load(*wallet_password_, *wallet_path_);
                auto summary = wallet.balance_summary(chain_);
                if (method == "getwalletinfo") {
                    JsonValue info = JsonValue::object();
                    info.set("walletfile", JsonValue::string(*wallet_path_));
                    info.set("mode", JsonValue::string(wallet.hd_mode()));
                    info.set("addresscount", JsonValue::number(static_cast<uint64_t>(wallet.all_addresses().size())));
                    info.set("primaryaddress", JsonValue::string(wallet.address));
                    info.set("mnemonic_backed", JsonValue(wallet.has_mnemonic()));
                    info.set("balance_sats", JsonValue::number(summary.spendable));
                    info.set("immature_balance_sats", JsonValue::number(summary.immature));
                    info.set("total_balance_sats", JsonValue::number(summary.total()));
                    result = std::move(info);
                } else if (method == "getbalance") {
                    result = JsonValue::number(summary.spendable);
                } else if (method == "getwalletaddresses") {
                    JsonValue addresses = JsonValue::array({});
                    for (const auto& address : wallet.all_addresses()) {
                        addresses.push_back(JsonValue::string(address));
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
                } else {
                    JsonValue utxos = JsonValue::array({});
                    for (const auto& [outpoint, entry] : wallet.list_unspent(chain_)) {
                        JsonValue row = JsonValue::object();
                        row.set("txid", JsonValue::string(outpoint.tx_hash.to_hex()));
                        row.set("vout", JsonValue::number(static_cast<uint64_t>(outpoint.index)));
                        row.set("amount_sats", JsonValue::number(entry.output.value));
                        row.set("address", JsonValue::string(entry.output.scriptPubKey));
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
          service_(chain, node, config.wallet_path, config.wallet_password, config.port),
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
