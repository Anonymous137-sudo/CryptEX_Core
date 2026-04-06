#pragma once

#include "constants.hpp"
#include "script.hpp"
#include "transaction.hpp"
#include "utxo.hpp"
#include <cstdint>
#include <unordered_map>
#include <optional>
#include <string>
#include <vector>

namespace cryptex {

class Blockchain;

class Wallet {
public:
    enum class AddressFormat : uint32_t {
        Base64 = 0,
        Base58 = 1,
        Hex = 2,
        Bech32 = 3,
    };

    enum class HdScheme : uint32_t {
        None = 0,
        LegacyCxhd = 1,
        Bip32 = 2,
    };

    enum class KeyDerivation : uint32_t {
        PBKDF2 = 0,
        Scrypt = 1,
        Argon2id = 2,
    };

    struct BalanceSummary {
        int64_t spendable{0};
        int64_t immature{0};
        int64_t locked{0};
        bool approved{true};
        int64_t total() const { return spendable + immature + locked; }
    };

    struct AddressBookEntry {
        std::string address;
        std::string address_base64;
        std::string address_base58;
        std::string address_hex;
        std::string address_bech32;
        std::string label;
        std::string pubkey_b64;
        bool primary{false};
        uint32_t hd_index{0};
    };

    struct HistoryEntry {
        std::string txid;
        std::string direction;
        std::string summary_address;
        std::vector<std::string> from_addresses;
        std::vector<std::string> to_addresses;
        int64_t net_sats{0};
        int64_t received_sats{0};
        int64_t sent_sats{0};
        int64_t fee_sats{0};
        uint64_t timestamp{0};
        std::optional<uint64_t> block_height;
        uint64_t confirmations{0};
        bool coinbase{false};
        bool in_mempool{false};
    };

    std::vector<uint8_t> privkey;
    std::vector<uint8_t> pubkey;
    std::string address;
    std::string chat_rsa_public_key_pem;
    std::string chat_rsa_private_key_pem;
    std::vector<std::vector<uint8_t>> privkeys;
    std::vector<std::vector<uint8_t>> pubkeys;
    std::vector<std::string> addresses;

    static Wallet create_new(const std::string& password,
                             const std::string& path,
                             AddressFormat address_format = AddressFormat::Base64,
                             size_t mnemonic_words = 24,
                             const std::string& mnemonic_passphrase = "",
                             KeyDerivation kdf = KeyDerivation::Argon2id);
    static Wallet create_new(const std::string& password,
                             const std::string& path,
                             size_t mnemonic_words,
                             const std::string& mnemonic_passphrase = "",
                             KeyDerivation kdf = KeyDerivation::Argon2id);
    static Wallet create_from_mnemonic(const std::string& password,
                                       const std::string& path,
                                       const std::string& mnemonic,
                                       AddressFormat address_format = AddressFormat::Base64,
                                       const std::string& mnemonic_passphrase = "",
                                       KeyDerivation kdf = KeyDerivation::Argon2id);
    static Wallet create_from_mnemonic(const std::string& password,
                                       const std::string& path,
                                       const std::string& mnemonic,
                                       const std::string& mnemonic_passphrase,
                                       KeyDerivation kdf = KeyDerivation::Argon2id);
    static Wallet load(const std::string& password, const std::string& path);
    static Wallet recover(const std::string& password, const std::string& path);
    static KeyDerivation inspect_key_derivation(const std::string& path);
    std::string add_address(const std::string& password, const std::string& path);
    const std::vector<std::string>& all_addresses() const { return addresses; }
    std::vector<std::pair<OutPoint, UTXOEntry>> list_unspent(Blockchain& chain) const;
    int64_t balance(Blockchain& chain) const;
    BalanceSummary balance_summary(Blockchain& chain) const;
    std::vector<AddressBookEntry> address_book() const;
    std::string label_for(const std::string& address) const;
    void set_label(const std::string& password,
                   const std::string& path,
                   const std::string& address,
                   const std::string& label);
    void set_primary_address(const std::string& password,
                             const std::string& path,
                             const std::string& address);
    std::string import_private_key_hex(const std::string& password,
                                       const std::string& path,
                                       const std::string& private_key_hex,
                                       const std::string& label = "");
    void change_password(const std::string& old_password,
                         const std::string& new_password,
                         const std::string& path,
                         KeyDerivation new_kdf = KeyDerivation::Argon2id);
    void ensure_unused_pool(Blockchain& chain,
                            const std::string& password,
                            const std::string& path,
                            uint32_t min_unused = constants::WALLET_TARGET_UNUSED_ADDRESSES);
    std::string unused_receive_address(Blockchain& chain,
                                       const std::string& password,
                                       const std::string& path,
                                       uint32_t min_unused = constants::WALLET_TARGET_UNUSED_ADDRESSES);
    bool is_hd() const { return hd_scheme_ != HdScheme::None; }
    bool is_bip32() const { return hd_scheme_ == HdScheme::Bip32; }
    bool has_mnemonic() const { return !mnemonic_entropy_.empty(); }
    std::string mnemonic_phrase() const;
    std::string dump_private_key_hex(const std::optional<std::string>& address = std::nullopt) const;
    void change_address_format(const std::string& password,
                               const std::string& path,
                               AddressFormat format);
    const char* hd_mode() const;
    const char* address_format_name() const;
    const char* kdf_name() const;
    bool has_chat_rsa_keys() const { return !chat_rsa_public_key_pem.empty() && !chat_rsa_private_key_pem.empty(); }
    std::string chat_rsa_public_key_b64() const;
    AddressFormat address_format() const { return address_format_; }
    KeyDerivation key_derivation() const { return key_derivation_; }
    std::string display_address(const std::string& address_value) const;
    std::string display_address(const std::string& address_value, AddressFormat format) const;
    static std::optional<AddressFormat> parse_address_format(const std::string& text);
    static std::optional<KeyDerivation> parse_key_derivation(const std::string& text);
    size_t rescan(Blockchain& chain,
                  const std::string& password,
                  const std::string& path,
                  uint32_t gap_limit = 20);

    // Build and sign a payment transaction (amount in satoshis). Optionally attach OP_RETURN message.
    Transaction create_payment(Blockchain& chain,
                               const std::string& to_address,
                               int64_t amount_sats,
                               const std::string& op_return_msg = "",
                               int64_t fee_per_kb = 1000,
                               const std::vector<OutPoint>& selected_inputs = {},
                               const std::optional<std::string>& change_address = std::nullopt) const;

    // Scan chain for history entries involving this wallet
    std::vector<std::string> history(Blockchain& chain, bool include_mempool = false) const;
    std::vector<HistoryEntry> history_entries(Blockchain& chain, bool include_mempool = false) const;
    std::optional<HistoryEntry> transaction_detail(Blockchain& chain,
                                                   const std::string& txid_hex,
                                                   bool include_mempool = true) const;

private:
    AddressFormat address_format_{AddressFormat::Base64};
    HdScheme hd_scheme_{HdScheme::None};
    KeyDerivation key_derivation_{KeyDerivation::PBKDF2};
    std::vector<uint8_t> master_seed_;
    std::vector<uint8_t> mnemonic_entropy_;
    uint32_t next_hd_index_{0};
    std::unordered_map<std::string, std::string> labels_;

    void sync_primary();
    void append_key(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& pub);
    std::vector<uint8_t> serialize_plaintext() const;
    void save_encrypted(const std::string& password, const std::string& path) const;
    static Wallet deserialize_plaintext(const std::vector<uint8_t>& plaintext);
    static void persist(const std::string& path,
                        KeyDerivation kdf,
                        const std::vector<uint8_t>& salt,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& ciphertext);
    static void read_file(const std::string& path,
                          KeyDerivation& kdf,
                          std::vector<uint8_t>& salt,
                          std::vector<uint8_t>& iv,
                          std::vector<uint8_t>& ciphertext);
};

} // namespace cryptex
