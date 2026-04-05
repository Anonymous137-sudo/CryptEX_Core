#include "script_1.hpp"
#include "sha3_512.hpp"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <algorithm>
#include <array>

namespace cryptex {
namespace script {

ScriptMachine::ScriptMachine() : pc_(0) {}

void ScriptMachine::set_script(const std::vector<uint8_t>& script) {
    script_ = script;
    pc_ = 0;
}

void ScriptMachine::set_signature_checker(const SignatureChecker& checker) {
    sig_checker_ = checker;
}

void ScriptMachine::reset() {
    script_.clear();
    pc_ = 0;
    stack_.clear();
    alt_stack_.clear();
    sig_checker_ = nullptr;
}

ScriptResult ScriptMachine::execute() {
    while (pc_ < script_.size()) {
        ScriptResult res = step();
        if (res != ScriptResult::OK) {
            return res;
        }
    }
    // After execution, the top of stack (if any) determines truth: non-zero and non-empty is true
    // But actual validation is done by the caller using the final stack.
    return ScriptResult::OK;
}

ScriptResult ScriptMachine::step() {
    if (pc_ >= script_.size()) return ScriptResult::ERROR;

    uint8_t op = script_[pc_++];

    // Data push opcodes
    if (op <= OP_PUSHDATA4) {
        if (op == OP_0) {
            push_stack({});
            return ScriptResult::OK;
        } else if (op >= 0x01 && op <= 0x4b) {
            // Push next `op` bytes
            return push_data(op);
        } else if (op == OP_PUSHDATA1) {
            if (pc_ + 1 > script_.size()) return ScriptResult::INVALID_OP;
            uint8_t len = script_[pc_++];
            return push_data(len);
        } else if (op == OP_PUSHDATA2) {
            if (pc_ + 2 > script_.size()) return ScriptResult::INVALID_OP;
            uint16_t len = script_[pc_] | (script_[pc_+1] << 8);
            pc_ += 2;
            return push_data(len);
        } else if (op == OP_PUSHDATA4) {
            if (pc_ + 4 > script_.size()) return ScriptResult::INVALID_OP;
            uint32_t len = script_[pc_] | (script_[pc_+1] << 8) | (script_[pc_+2] << 16) | (script_[pc_+3] << 24);
            pc_ += 4;
            return push_data(len);
        } else {
            return ScriptResult::INVALID_OP;
        }
    } else {
        return exec_opcode(op);
    }
}

ScriptResult ScriptMachine::push_data(size_t len) {
    if (pc_ + len > script_.size()) return ScriptResult::INVALID_OP;
    StackElement data(script_.begin() + pc_, script_.begin() + pc_ + len);
    pc_ += len;
    push_stack(data);
    return ScriptResult::OK;
}

ScriptResult ScriptMachine::exec_opcode(uint8_t op) {
    switch (op) {
        // Stack operations
        case OP_DUP: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            push_stack(stack_.back());
            return ScriptResult::OK;
        }
        case OP_DROP: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            pop_stack();
            return ScriptResult::OK;
        }
        case OP_SWAP: {
            if (stack_size() < 2) return ScriptResult::INCOMPLETE;
            auto a = pop_stack();
            auto b = pop_stack();
            push_stack(a);
            push_stack(b);
            return ScriptResult::OK;
        }
        case OP_ROT: {
            if (stack_size() < 3) return ScriptResult::INCOMPLETE;
            auto a = pop_stack();
            auto b = pop_stack();
            auto c = pop_stack();
            push_stack(b);
            push_stack(a);
            push_stack(c);
            return ScriptResult::OK;
        }
        case OP_OVER: {
            if (stack_size() < 2) return ScriptResult::INCOMPLETE;
            push_stack(stack_[stack_.size()-2]);
            return ScriptResult::OK;
        }
        case OP_PICK: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            auto idx_elem = pop_stack();
            int64_t idx = cast_to_int(idx_elem);
            if (idx < 0 || static_cast<size_t>(idx) >= stack_.size()) return ScriptResult::ERROR;
            push_stack(stack_[stack_.size() - 1 - idx]);
            return ScriptResult::OK;
        }
        case OP_ROLL: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            auto idx_elem = pop_stack();
            int64_t idx = cast_to_int(idx_elem);
            if (idx < 0 || static_cast<size_t>(idx) >= stack_.size()) return ScriptResult::ERROR;
            auto elem = stack_[stack_.size() - 1 - idx];
            stack_.erase(stack_.end() - 1 - idx);
            push_stack(elem);
            return ScriptResult::OK;
        }
        case OP_DEPTH: {
            push_stack(cast_from_int(stack_.size()));
            return ScriptResult::OK;
        }

        // Arithmetic
        case OP_ADD: {
            if (stack_size() < 2) return ScriptResult::INCOMPLETE;
            auto a = pop_stack();
            auto b = pop_stack();
            int64_t sum = cast_to_int(a) + cast_to_int(b);
            push_stack(cast_from_int(sum));
            return ScriptResult::OK;
        }
        case OP_SUB: {
            if (stack_size() < 2) return ScriptResult::INCOMPLETE;
            auto a = pop_stack();
            auto b = pop_stack();
            int64_t diff = cast_to_int(b) - cast_to_int(a); // note order: b - a
            push_stack(cast_from_int(diff));
            return ScriptResult::OK;
        }

        // Equality
        case OP_EQUAL: {
            if (stack_size() < 2) return ScriptResult::INCOMPLETE;
            auto a = pop_stack();
            auto b = pop_stack();
            bool eq = (a == b);
            push_stack(eq ? std::vector<uint8_t>{1} : std::vector<uint8_t>{0});
            return ScriptResult::OK;
        }
        case OP_EQUALVERIFY: {
            if (stack_size() < 2) return ScriptResult::INCOMPLETE;
            auto a = pop_stack();
            auto b = pop_stack();
            if (a != b) return ScriptResult::VERIFY_FAIL;
            return ScriptResult::OK;
        }

        // Crypto
        case OP_HASH160: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            auto data = pop_stack();
            push_stack(hash160(data));
            return ScriptResult::OK;
        }
        case OP_HASH256: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            auto data = pop_stack();
            push_stack(hash256(data));
            return ScriptResult::OK;
        }
        case OP_SHA1: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            auto data = pop_stack();
            push_stack(sha1(data));
            return ScriptResult::OK;
        }
        case OP_SHA256: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            auto data = pop_stack();
            push_stack(sha256(data));
            return ScriptResult::OK;
        }
        case OP_CHECKSIG:
        case OP_CHECKSIGVERIFY: {
            if (stack_size() < 2) return ScriptResult::INCOMPLETE;
            auto pubkey = pop_stack();
            auto signature = pop_stack();
            if (!sig_checker_) return ScriptResult::ERROR; // no checker provided
            // FIX: use the stored sighash instead of placeholder
            bool valid = sig_checker_(current_sighash_, signature, pubkey);
            if (op == OP_CHECKSIG) {
                push_stack(valid ? std::vector<uint8_t>{1} : std::vector<uint8_t>{0});
            } else {
                if (!valid) return ScriptResult::VERIFY_FAIL;
            }
            return ScriptResult::OK;
        }
        case OP_CHECKMULTISIG:
        case OP_CHECKMULTISIGVERIFY: {
            // Not implemented, but could be added later
            return ScriptResult::INVALID_OP;
        }

        // Control flow
        case OP_IF:
        case OP_NOTIF: {
            // Not implemented – would require conditional jumps
            return ScriptResult::INVALID_OP;
        }
        case OP_VERIFY: {
            if (stack_empty()) return ScriptResult::INCOMPLETE;
            auto top = pop_stack();
            if (top.size() == 1 && top[0] == 0) return ScriptResult::VERIFY_FAIL;
            return ScriptResult::OK;
        }
        case OP_RETURN: {
            return ScriptResult::FALSE; // immediate failure
        }

        default:
            return ScriptResult::INVALID_OP;
    }
}

StackElement ScriptMachine::pop_stack() {
    if (stack_.empty()) throw std::runtime_error("pop from empty stack");
    auto val = stack_.back();
    stack_.pop_back();
    return val;
}

void ScriptMachine::push_stack(const StackElement& elem) {
    stack_.push_back(elem);
}

int64_t ScriptMachine::cast_to_int(const StackElement& elem) const {
    if (elem.empty()) return 0;
    // Script numbers are little-endian, minimal encoding? We'll just convert from little-endian.
    int64_t val = 0;
    for (size_t i = 0; i < elem.size(); ++i) {
        val |= static_cast<int64_t>(elem[i]) << (i * 8);
    }
    // Sign extend? In Bitcoin, numbers are minimally encoded with sign in the high bit of the last byte.
    if (!elem.empty() && (elem.back() & 0x80)) {
        // negative: we need to handle properly. For simplicity, we treat as unsigned.
        // Real implementation would handle negative properly. We'll skip for now.
    }
    return val;
}

StackElement ScriptMachine::cast_from_int(int64_t val) const {
    if (val == 0) return {};
    StackElement elem;
    uint64_t uval = static_cast<uint64_t>(val);
    while (uval) {
        elem.push_back(static_cast<uint8_t>(uval & 0xFF));
        uval >>= 8;
    }
    // If high bit set, add a zero byte to avoid sign misinterpretation (Bitcoin's minimal encoding rule)
    if (elem.back() & 0x80) {
        elem.push_back(0);
    }
    return elem;
}

StackElement ScriptMachine::hash160(const StackElement& data) const {
    uint8_t sha256[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), sha256);
    std::array<uint8_t, 20> ripe{};
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    const EVP_MD* md = EVP_ripemd160();
    if (!md || EVP_DigestInit_ex(mdctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, sha256, SHA256_DIGEST_LENGTH) != 1 ||
        EVP_DigestFinal_ex(mdctx, ripe.data(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("RIPEMD160 digest failed");
    }
    EVP_MD_CTX_free(mdctx);
    return StackElement(ripe.begin(), ripe.end());
}

StackElement ScriptMachine::hash256(const StackElement& data) const {
    uint8_t sha1[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), sha1);
    uint8_t sha2[SHA256_DIGEST_LENGTH];
    SHA256(sha1, SHA256_DIGEST_LENGTH, sha2);
    return StackElement(sha2, sha2 + SHA256_DIGEST_LENGTH);
}

StackElement ScriptMachine::sha1(const StackElement& data) const {
    uint8_t hash[SHA_DIGEST_LENGTH];
    SHA1(data.data(), data.size(), hash);
    return StackElement(hash, hash + SHA_DIGEST_LENGTH);
}

StackElement ScriptMachine::sha256(const StackElement& data) const {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), hash);
    return StackElement(hash, hash + SHA256_DIGEST_LENGTH);
}

// Utility functions
std::vector<uint8_t> create_p2pkh_script(const std::array<uint8_t,20>& hash) {
    std::vector<uint8_t> script;
    script.push_back(OP_DUP);
    script.push_back(OP_HASH160);
    script.push_back(20);
    script.insert(script.end(), hash.begin(), hash.end());
    script.push_back(OP_EQUALVERIFY);
    script.push_back(OP_CHECKSIG);
    return script;
}

std::vector<uint8_t> create_p2pkh_sig_script(const std::vector<uint8_t>& signature,
                                             const std::vector<uint8_t>& pubkey) {
    std::vector<uint8_t> script;
    // Push signature
    if (signature.size() <= 75) {
        script.push_back(static_cast<uint8_t>(signature.size()));
    } else {
        // Use OP_PUSHDATA1
        script.push_back(OP_PUSHDATA1);
        script.push_back(static_cast<uint8_t>(signature.size()));
    }
    script.insert(script.end(), signature.begin(), signature.end());

    // Push pubkey
    if (pubkey.size() <= 75) {
        script.push_back(static_cast<uint8_t>(pubkey.size()));
    } else {
        script.push_back(OP_PUSHDATA1);
        script.push_back(static_cast<uint8_t>(pubkey.size()));
    }
    script.insert(script.end(), pubkey.begin(), pubkey.end());
    return script;
}

bool extract_p2pkh_address(const std::vector<uint8_t>& scriptPubKey, std::array<uint8_t,20>& hash) {
    // Pattern: OP_DUP OP_HASH160 <20> <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (scriptPubKey.size() != 25) return false;
    if (scriptPubKey[0] != OP_DUP) return false;
    if (scriptPubKey[1] != OP_HASH160) return false;
    if (scriptPubKey[2] != 20) return false;
    if (scriptPubKey[23] != OP_EQUALVERIFY) return false;
    if (scriptPubKey[24] != OP_CHECKSIG) return false;
    std::copy(scriptPubKey.begin() + 3, scriptPubKey.begin() + 23, hash.begin());
    return true;
}

} // namespace script
} // namespace cryptex
