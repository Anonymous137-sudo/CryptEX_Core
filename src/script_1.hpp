#pragma once

#include "types.hpp"
#include "base64.hpp"
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>

namespace cryptex {
namespace script {

// Opcodes (subset of Bitcoin's, but can be extended)
enum Opcode : uint8_t {
    // Constants
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // Stack ops
    OP_DUP = 0x76,
    OP_DROP = 0x75,
    OP_SWAP = 0x7c,
    OP_ROT = 0x7b,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_DEPTH = 0x74,

    // Arithmetic (simplified)
    OP_ADD = 0x93,
    OP_SUB = 0x94,

    // Bitwise logic
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,

    // Crypto
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // Control flow
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // Misc
    OP_CODESEPARATOR = 0xab,
};

// Script execution result
enum class ScriptResult {
    OK,
    FALSE,
    ERROR,
    INCOMPLETE,  // not enough data on stack
    INVALID_OP,
    VERIFY_FAIL,
};

// A stack element is a byte vector
using StackElement = std::vector<uint8_t>;

// Signature checker: given a sighash, signature, and pubkey, returns true if valid
using SignatureChecker = std::function<bool(const uint256_t& sighash,
                                            const std::vector<uint8_t>& signature,
                                            const std::vector<uint8_t>& pubkey)>;

class ScriptMachine {
public:
    ScriptMachine();
    ~ScriptMachine() = default;

    // Set the script to be executed
    void set_script(const std::vector<uint8_t>& script);

    // Set the signature checker function (called by OP_CHECKSIG)
    void set_signature_checker(const SignatureChecker& checker);

    // Set the current sighash for signature verification
    void set_sighash(const uint256_t& sighash) { current_sighash_ = sighash; }

    // Execute the script, consuming stack elements if provided
    ScriptResult execute();

    // Get the final stack after execution
    const std::vector<StackElement>& stack() const { return stack_; }

    // Clear the machine state
    void reset();

private:
    std::vector<uint8_t> script_;
    size_t pc_;                         // program counter
    std::vector<StackElement> stack_;
    std::vector<StackElement> alt_stack_; // for OP_TOALTSTACK etc.
    SignatureChecker sig_checker_;
    uint256_t current_sighash_;          // FIX: added to hold sighash for CHECKSIG

    // Step through one instruction
    ScriptResult step();

    // Helper to push data of given length (for OP_PUSHDATA)
    ScriptResult push_data(size_t len);

    // Execute an opcode
    ScriptResult exec_opcode(uint8_t opcode);

    // Stack manipulation helpers
    StackElement pop_stack();
    void push_stack(const StackElement& elem);
    bool stack_empty() const { return stack_.empty(); }
    size_t stack_size() const { return stack_.size(); }

    // Arithmetic helpers (simple int conversion from stack element)
    int64_t cast_to_int(const StackElement& elem) const;
    StackElement cast_from_int(int64_t val) const;

    // Hashing helpers
    StackElement hash160(const StackElement& data) const;
    StackElement hash256(const StackElement& data) const;
    StackElement sha1(const StackElement& data) const;
    StackElement sha256(const StackElement& data) const;
};

// Utility functions to create standard scripts
std::vector<uint8_t> create_p2pkh_script(const std::array<uint8_t,20>& hash);
std::vector<uint8_t> create_p2pkh_sig_script(const std::vector<uint8_t>& signature,
                                             const std::vector<uint8_t>& pubkey);

// Extract address from a P2PKH scriptPubKey (if it matches pattern)
bool extract_p2pkh_address(const std::vector<uint8_t>& scriptPubKey, std::array<uint8_t,20>& hash);

} // namespace script
} // namespace cryptex
