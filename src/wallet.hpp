#pragma once

#include "constants.hpp"
#include "script.hpp"
#include "transaction.hpp"
#include "utxo.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cryptex {

class Blockchain;

class Wallet {
public:
    enum class HdScheme : uint32_t {
        None = 0,
        LegacyCxhd = 1,
        Bip32 = 2,
    };

    struct BalanceSummary {
        int64_t spendable{0};
        int64_t immature{0};
        int64_t total() const { return spendable + immature; }
    };

    std::vector<uint8_t> privkey;
    std::vector<uint8_t> pubkey;
    std::string address;
    std::vector<std::vector<uint8_t>> privkeys;
    std::vector<std::vector<uint8_t>> pubkeys;
    std::vector<std::string> addresses;

    static Wallet create_new(const std::string& password,
                             const std::string& path,
                             size_t mnemonic_words = 24,
                             const std::string& mnemonic_passphrase = "");
    static Wallet create_from_mnemonic(const std::string& password,
                                       const std::string& path,
                                       const std::string& mnemonic,
                                       const std::string& mnemonic_passphrase = "");
    static Wallet load(const std::string& password, const std::string& path);
    std::string add_address(const std::string& password, const std::string& path);
    const std::vector<std::string>& all_addresses() const { return addresses; }
    std::vector<std::pair<OutPoint, UTXOEntry>> list_unspent(Blockchain& chain) const;
    int64_t balance(Blockchain& chain) const;
    BalanceSummary balance_summary(Blockchain& chain) const;
    bool is_hd() const { return hd_scheme_ != HdScheme::None; }
    bool is_bip32() const { return hd_scheme_ == HdScheme::Bip32; }
    bool has_mnemonic() const { return !mnemonic_entropy_.empty(); }
    std::string mnemonic_phrase() const;
    const char* hd_mode() const;
    size_t rescan(Blockchain& chain,
                  const std::string& password,
                  const std::string& path,
                  uint32_t gap_limit = 20);

    // Build and sign a payment transaction (amount in satoshis). Optionally attach OP_RETURN message.
    Transaction create_payment(Blockchain& chain,
                               const std::string& to_address,
                               int64_t amount_sats,
                               const std::string& op_return_msg = "",
                               int64_t fee_per_kb = 1000) const;

    // Scan chain for history entries involving this wallet
    std::vector<std::string> history(Blockchain& chain, bool include_mempool = false) const;

private:
    HdScheme hd_scheme_{HdScheme::None};
    std::vector<uint8_t> master_seed_;
    std::vector<uint8_t> mnemonic_entropy_;
    uint32_t next_hd_index_{0};

    void sync_primary();
    void append_key(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& pub);
    std::vector<uint8_t> serialize_plaintext() const;
    static Wallet deserialize_plaintext(const std::vector<uint8_t>& plaintext);
    static void persist(const std::string& path,
                        const std::vector<uint8_t>& salt,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& ciphertext);
    static void read_file(const std::string& path,
                          std::vector<uint8_t>& salt,
                          std::vector<uint8_t>& iv,
                          std::vector<uint8_t>& ciphertext);
};

} // namespace cryptex
