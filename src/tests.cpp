#include "base64.hpp"
#include "bip39.hpp"
#include "chainparams.hpp"
#include "chat_secure.hpp"
#include "config.hpp"
#include "debug.hpp"
#include "network.hpp"
#include "transaction.hpp"
#include "utxo.hpp"
#include "script.hpp"
#include "block.hpp"
#include "blockchain.hpp"
#include "rpc.hpp"
#include "serialization.hpp"
#include "wallet.hpp"
#include <filesystem>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <thread>
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

using namespace cryptex;

namespace {

struct NetworkScope {
    NetworkKind previous;
    explicit NetworkScope(NetworkKind next)
        : previous(params().network) {
        select_network(next);
    }
    ~NetworkScope() {
        select_network(previous);
    }
};

struct TestKey {
    std::vector<uint8_t> priv;
    std::vector<uint8_t> pub;
    std::string address;
};

TestKey make_test_key() {
    TestKey key;
    script::generate_keypair(key.priv, key.pub);
    key.address = script::pubkey_to_address(key.pub);
    return key;
}

void remove_all_if_exists(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

std::filesystem::path unique_temp_path(const std::string& stem, const std::string& suffix = "") {
    static std::atomic<uint64_t> counter{0};
#ifdef _WIN32
    const auto pid = static_cast<uint64_t>(_getpid());
#else
    const auto pid = static_cast<uint64_t>(getpid());
#endif
    const auto seq = counter.fetch_add(1, std::memory_order_relaxed);
    const auto now = static_cast<uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    return std::filesystem::temp_directory_path() /
           (stem + "_" + std::to_string(pid) + "_" + std::to_string(now) + "_" +
            std::to_string(seq) + suffix);
}

Transaction make_coinbase_tx(const std::string& address, int64_t value) {
    Transaction tx;
    tx.version = 1;
    TxIn in;
    in.prevout.tx_hash = uint256_t();
    in.prevout.index = 0xFFFFFFFF;
    in.sequence = 0xFFFFFFFF;
    tx.inputs.push_back(in);
    TxOut out;
    out.value = value;
    out.scriptPubKey = address;
    tx.outputs.push_back(out);
    tx.lockTime = 0;
    return tx;
}

Transaction make_signed_spend(const OutPoint& prevout,
                              const TxOut& prev_output,
                              const TestKey& signer,
                              const std::vector<TxOut>& outputs) {
    Transaction tx;
    tx.version = 1;
    tx.lockTime = 0;
    TxIn in;
    in.prevout = prevout;
    in.sequence = 0xFFFFFFFF;
    tx.inputs.push_back(in);
    tx.outputs = outputs;

    std::vector<uint8_t> script_bytes(prev_output.scriptPubKey.begin(), prev_output.scriptPubKey.end());
    auto sighash = tx.sighash(0, script_bytes);
    auto sig = script::sign_hash(sighash, signer.priv);
    tx.inputs[0].scriptSig = sig;
    tx.inputs[0].scriptSig.insert(tx.inputs[0].scriptSig.end(), signer.pub.begin(), signer.pub.end());
    return tx;
}

uint16_t pick_free_port() {
    boost::asio::io_context ctx;
    boost::asio::ip::tcp::acceptor acceptor(ctx, {boost::asio::ip::tcp::v4(), 0});
    return acceptor.local_endpoint().port();
}

Block mine_valid_block(Blockchain& chain, const std::string& address) {
    Block blk;
    blk.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    blk.header.timestamp = std::max<uint32_t>(
        static_cast<uint32_t>(std::time(nullptr)),
        prev ? prev->header.timestamp + 1 : static_cast<uint32_t>(std::time(nullptr)));
    blk.header.bits = chain.next_work_bits(blk.header.timestamp);

    auto coinbase = make_coinbase_tx(address, Block::get_block_reward(chain.best_height() + 1));
    serialization::write_int<uint32_t>(coinbase.inputs[0].scriptSig, static_cast<uint32_t>(chain.best_height() + 1));
    serialization::write_int<uint32_t>(coinbase.inputs[0].scriptSig, blk.header.timestamp);
    blk.transactions.push_back(std::move(coinbase));
    blk.header.merkle_root = blk.compute_merkle_root();

    for (uint32_t nonce = 0;; ++nonce) {
        blk.header.nonce = nonce;
        if (blk.check_pow()) break;
    }
    return blk;
}

std::vector<uint8_t> make_coinbase_marker(uint64_t height,
                                          uint32_t timestamp,
                                          const uint256_t& prev_hash);

Block make_test_block(Blockchain& chain,
                      const std::string& address,
                      uint32_t timestamp) {
    Block blk;
    blk.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    blk.header.timestamp = prev ? std::max<uint32_t>(timestamp, prev->header.timestamp + 1) : timestamp;
    blk.header.bits = chain.next_work_bits(blk.header.timestamp);
    blk.header.nonce = 0;

    auto coinbase = make_coinbase_tx(address, Block::get_block_reward(chain.best_height() + 1));
    coinbase.inputs[0].scriptSig = make_coinbase_marker(chain.best_height() + 1,
                                                        blk.header.timestamp,
                                                        blk.header.prev_block_hash);
    blk.transactions.push_back(std::move(coinbase));
    blk.header.merkle_root = blk.compute_merkle_root();
    return blk;
}

Block make_branch_block(const BlockHeader& parent,
                        uint64_t height,
                        const std::string& address,
                        uint32_t branch_salt) {
    Block blk;
    blk.header.version = 1;
    blk.header.prev_block_hash = parent.hash();
    blk.header.timestamp = parent.timestamp + 1 + branch_salt;
    blk.header.bits = parent.bits;

    auto coinbase = make_coinbase_tx(address, Block::get_block_reward(height));
    coinbase.inputs[0].scriptSig = make_coinbase_marker(height, blk.header.timestamp, blk.header.prev_block_hash);
    serialization::write_int<uint32_t>(coinbase.inputs[0].scriptSig, branch_salt);
    blk.transactions.push_back(std::move(coinbase));
    blk.header.merkle_root = blk.compute_merkle_root();
    blk.header.nonce = branch_salt;
    return blk;
}

void set_env_var(const char* key, const char* value) {
#ifdef _WIN32
    _putenv_s(key, value ? value : "");
#else
    if (value) setenv(key, value, 1);
    else unsetenv(key);
#endif
}

std::string hex_encode(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        out.push_back(hex[(byte >> 4) & 0x0F]);
        out.push_back(hex[byte & 0x0F]);
    }
    return out;
}

std::string make_legacy_address(const std::string& canonical) {
    auto decoded = crypto::base64_decode(crypto::address_to_base64(canonical));
    decoded.push_back(0);
    return crypto::base64_encode(decoded);
}

std::vector<uint8_t> make_coinbase_marker(uint64_t height,
                                          uint32_t timestamp,
                                          const uint256_t& prev_hash) {
    std::vector<uint8_t> script_sig;
    serialization::write_int<uint64_t>(script_sig, height);
    serialization::write_int<uint32_t>(script_sig, timestamp);
    auto prev_bytes = prev_hash.to_bytes();
    script_sig.insert(script_sig.end(), prev_bytes.begin(), prev_bytes.begin() + 8);
    return script_sig;
}

} // namespace

static void test_base64_address() {
    std::array<uint8_t,20> data{};
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
    auto addr = crypto::base64_encode(data.data(), data.size());
    auto decoded_vec = crypto::base64_decode(addr);
    if (decoded_vec.size() != data.size()) {
        throw std::runtime_error("base64 address decode size mismatch");
    }
    std::array<uint8_t,20> decoded{};
    std::copy(decoded_vec.begin(), decoded_vec.end(), decoded.begin());
    assert(decoded == data);
}

static void test_multi_format_address_support() {
    auto key = make_test_key();
    auto canonical = crypto::address_to_base64(key.address);
    auto base58 = crypto::address_to_base58(canonical);
    auto hex = crypto::address_to_hex(canonical);

    assert(base58 == key.address);
    assert(crypto::canonicalize_address(base58) == canonical);
    assert(crypto::canonicalize_address(hex) == canonical);
    assert(crypto::addresses_equal(base58, canonical));
    assert(crypto::addresses_equal(hex, canonical));
    assert(crypto::addresses_equal(base58, hex));
}

static void test_genesis_pow_full_512() {
    auto genesis = Block::create_genesis();
    assert(genesis.check_pow());
    assert(genesis.header.pow_hash().to_hex_padded(constants::POW_HASH_BYTES) ==
           "000000ebd1f4a050003997d5be294b41345fc5717ae39468a55f01a7e4285c9dc9ead014b906a333a565764f329d1771b1abe3950459b1aaefc7f3787524b6b3");
}

static void test_reward_schedule_matches_new_consensus() {
    assert(constants::TOTAL_SUPPLY == 1'000'000'000ULL);
    assert(constants::INITIAL_BLOCK_REWARD == 2500);
    assert(constants::HALVING_INTERVAL_BLOCKS == 200000);
    assert(Block::get_block_reward(0) == 2500LL * 100000000LL);
    assert(Block::get_block_reward(constants::HALVING_INTERVAL_BLOCKS - 1) == 2500LL * 100000000LL);
    assert(Block::get_block_reward(constants::HALVING_INTERVAL_BLOCKS) == 1250LL * 100000000LL);
    assert(Block::get_block_reward(constants::HALVING_INTERVAL_BLOCKS * 2ULL) == 625LL * 100000000LL);
}

static void test_network_modes() {
    {
        NetworkScope scope(NetworkKind::Testnet);
        assert(default_p2p_port() == 19333);
        assert(default_rpc_port() == 19332);
        assert(message_magic() == 0x43585454);
        auto genesis = Block::create_genesis();
        assert(genesis.header.bits == 0x3f00ffff);
        assert(genesis.header.timestamp == 1741478401);
        assert(genesis.header.nonce == 78355);
        assert(genesis.check_pow());
    }
    {
        NetworkScope scope(NetworkKind::Regtest);
        assert(default_p2p_port() == 19444);
        assert(default_rpc_port() == 19443);
        assert(message_magic() == 0x43585247);
        auto genesis = Block::create_genesis();
        assert(genesis.header.bits == 0x407fffff);
        assert(genesis.header.timestamp == 1741478402);
        assert(genesis.header.nonce == 8);
        assert(genesis.check_pow());
    }
    {
        NetworkScope scope(NetworkKind::Testnet);
        std::filesystem::path tmp = unique_temp_path("cryptex_rpc_testnet");
        remove_all_if_exists(tmp);
        Blockchain chain(tmp);
        bool stop_requested = false;
        rpc::RpcService rpc_service(chain, nullptr, std::nullopt, std::nullopt, default_rpc_port());
        auto resp = rpc_service.handle_jsonrpc(
            R"({"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]})",
            stop_requested);
        assert(resp.find("\"chain\":\"testnet\"") != std::string::npos);
        remove_all_if_exists(tmp);
    }
}

static void test_legacy_address_compatibility() {
    NetworkScope scope(NetworkKind::Regtest);
    auto key = make_test_key();
    auto legacy = make_legacy_address(key.address);
    assert(crypto::canonicalize_address(legacy) == crypto::address_to_base64(key.address));
    assert(crypto::addresses_equal(legacy, key.address));

    UTXOSet standalone;
    Transaction funding = make_coinbase_tx(legacy, 50 * 100000000LL);
    assert(standalone.apply_transaction(funding, 0));
    assert(standalone.get_balance(key.address) == funding.outputs[0].value);
    assert(standalone.list_for_address(key.address, 101, true).size() == 1);

    std::filesystem::path tmp = unique_temp_path("cryptex_legacy_addr_chain");
    remove_all_if_exists(tmp);
    Blockchain chain(tmp);

    for (int i = 0; i < 101; ++i) {
        auto blk = mine_valid_block(chain, i == 0 ? legacy : key.address);
        assert(chain.accept_block(blk));
    }

    Wallet wallet;
    wallet.privkey = key.priv;
    wallet.pubkey = key.pub;
    wallet.address = key.address;
    wallet.privkeys.push_back(key.priv);
    wallet.pubkeys.push_back(key.pub);
    wallet.addresses.push_back(key.address);

    auto summary = wallet.balance_summary(chain);
    assert(summary.spendable >= 50 * 100000000LL);

    auto spend = wallet.create_payment(chain, key.address, 10 * 100000000LL);
    Mempool::AcceptStatus status = Mempool::AcceptStatus::Invalid;
    assert(chain.mempool().add_transaction(spend, chain.utxo(), static_cast<uint32_t>(chain.best_height()), &status));
    assert(status == Mempool::AcceptStatus::Accepted);

    remove_all_if_exists(tmp);
}

static void test_mainnet_emergency_difficulty_allows_low_hash_takeover() {
    NetworkScope scope(NetworkKind::Mainnet);
    std::filesystem::path tmp = unique_temp_path("cryptex_diff_takeover");
    remove_all_if_exists(tmp);

    Blockchain chain(tmp);
    auto miner = make_test_key();
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    constexpr uint32_t kFastSpacing = 60;
    constexpr int kFastBlocks = 16;
    const uint32_t emergency_delay = params().emergency_min_difficulty_delay_seconds;
    const uint32_t start_timestamp =
        now - emergency_delay - 30 - static_cast<uint32_t>((kFastBlocks - 1) * kFastSpacing);

    for (int i = 0; i < kFastBlocks; ++i) {
        auto blk = make_test_block(chain, miner.address, start_timestamp + static_cast<uint32_t>(i) * kFastSpacing);
        assert(chain.accept_block(blk, /*skip_pow_check=*/true));
    }

    auto tip = chain.get_block(chain.best_height());
    assert(tip.has_value());
    const uint256_t tip_target = compact_target{tip->header.bits}.expand();
    const uint256_t pow_limit_target = compact_target{pow_limit_bits()}.expand();
    assert(tip_target < pow_limit_target);

    const uint32_t takeover_timestamp = tip->header.timestamp + emergency_delay + 1;
    assert(takeover_timestamp <= now + params().max_future_block_time_seconds);
    assert(chain.next_work_bits(takeover_timestamp) == pow_limit_bits());

    auto takeover_block = make_test_block(chain, miner.address, takeover_timestamp);
    assert(takeover_block.header.bits == pow_limit_bits());
    assert(chain.accept_block(takeover_block, /*skip_pow_check=*/true));

    remove_all_if_exists(tmp);
}

static void test_future_timestamp_block_is_rejected() {
    NetworkScope scope(NetworkKind::Mainnet);
    std::filesystem::path tmp = unique_temp_path("cryptex_future_block_reject");
    remove_all_if_exists(tmp);

    Blockchain chain(tmp);
    auto miner = make_test_key();
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    auto future_block = make_test_block(
        chain,
        miner.address,
        now + params().max_future_block_time_seconds + 60);
    assert(!chain.accept_block(future_block, /*skip_pow_check=*/true));

    remove_all_if_exists(tmp);
}

static void test_wallet_unused_pool_and_privacy_change() {
    NetworkScope scope(NetworkKind::Regtest);
    std::filesystem::path tmp = unique_temp_path("cryptex_wallet_privacy");
    remove_all_if_exists(tmp);

    auto wallet_path = (tmp / "wallet.dat").string();
    auto chain_path = tmp / "chain";
    auto wallet = Wallet::create_new("privacy-pass", wallet_path);
    Blockchain chain(chain_path);
    auto external = make_test_key();

    wallet.ensure_unused_pool(chain, "privacy-pass", wallet_path, 3);
    wallet = Wallet::load("privacy-pass", wallet_path);
    assert(wallet.all_addresses().size() >= 3);

    auto unused_receive = wallet.unused_receive_address(chain, "privacy-pass", wallet_path, 3);
    assert(!unused_receive.empty());
    assert(unused_receive != wallet.address);

    for (int i = 0; i < 101; ++i) {
        auto blk = mine_valid_block(chain, wallet.address);
        assert(chain.accept_block(blk));
    }

    wallet.ensure_unused_pool(chain, "privacy-pass", wallet_path, 3);
    wallet = Wallet::load("privacy-pass", wallet_path);

    auto tx = wallet.create_payment(chain, external.address, 10 * 100000000LL);
    bool saw_change = false;
    for (const auto& output : tx.outputs) {
        if (output.value <= 0) continue;
        if (crypto::addresses_equal(output.scriptPubKey, external.address)) continue;
        saw_change = true;
        assert(!crypto::addresses_equal(output.scriptPubKey, wallet.address));
        assert(crypto::addresses_equal(output.scriptPubKey, unused_receive));
    }
    assert(saw_change);

    remove_all_if_exists(tmp);
}

static void test_unique_coinbase_rewards_accumulate() {
    auto key = make_test_key();
    std::filesystem::path tmp = unique_temp_path("cryptex_unique_coinbase_chain");
    remove_all_if_exists(tmp);
    Blockchain chain(tmp);

    for (int i = 0; i < 2; ++i) {
        Block blk;
        blk.header.version = 1;
        auto prev = chain.get_block(chain.best_height());
        blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
        blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr)) + static_cast<uint32_t>(i);
        blk.header.bits = chain.next_work_bits(blk.header.timestamp);
        blk.header.nonce = 0;

        Transaction coinbase = make_coinbase_tx(key.address, Block::get_block_reward(chain.best_height() + 1));
        coinbase.inputs[0].scriptSig = make_coinbase_marker(chain.best_height() + 1,
                                                            blk.header.timestamp,
                                                            blk.header.prev_block_hash);
        blk.transactions.push_back(std::move(coinbase));
        blk.header.merkle_root = blk.compute_merkle_root();
        assert(chain.connect_block(blk, /*skip_pow_check=*/true));
    }

    auto outputs = chain.utxo().list_for_address(key.address, static_cast<uint32_t>(chain.best_height()), true);
    assert(outputs.size() == 2);

    Wallet wallet;
    wallet.privkey = key.priv;
    wallet.pubkey = key.pub;
    wallet.address = key.address;
    wallet.privkeys.push_back(key.priv);
    wallet.pubkeys.push_back(key.pub);
    wallet.addresses.push_back(key.address);

    auto summary = wallet.balance_summary(chain);
    int64_t reward = Block::get_block_reward(1);
    assert(summary.immature == reward * 2);
    assert(summary.total() == reward * 2);

    remove_all_if_exists(tmp);
}

static void test_sighash_and_signature() {
    std::vector<uint8_t> priv, pub;
    script::generate_keypair(priv, pub);
    std::string addr = script::pubkey_to_address(pub);

    Transaction funding;
    funding.version = 1;
    TxIn coin;
    coin.prevout.tx_hash = uint256_t();
    coin.prevout.index = 0xFFFFFFFF;
    coin.scriptSig = {};
    coin.sequence = 0xFFFFFFFF;
    funding.inputs.push_back(coin);
    TxOut out;
    out.value = 50 * 100000000LL;
    out.scriptPubKey = addr;
    funding.outputs.push_back(out);
    funding.lockTime = 0;

    // Spend funding output
    Transaction spend;
    spend.version = 1;
    TxIn in;
    in.prevout.tx_hash = funding.hash();
    in.prevout.index = 0;
    in.sequence = 0xFFFFFFFF;
    spend.inputs.push_back(in);
    TxOut out2;
    out2.value = 10 * 100000000LL;
    out2.scriptPubKey = addr;
    spend.outputs.push_back(out2);
    spend.lockTime = 0;

    // FIX: use actual scriptPubKey bytes (the address string) for sighash
    std::vector<uint8_t> script_bytes(addr.begin(), addr.end());
    uint256_t sigh = spend.sighash(0, script_bytes);
    auto sig = script::sign_hash(sigh, priv);
    in.scriptSig = sig;
    in.scriptSig.insert(in.scriptSig.end(), pub.begin(), pub.end());
    spend.inputs[0] = in;
    assert(script::verify_signature(sigh, sig, pub));
}

static void test_utxo_apply_and_fee() {
    std::vector<uint8_t> priv, pub;
    script::generate_keypair(priv, pub);
    std::string addr = script::pubkey_to_address(pub);
    UTXOSet set;

    Transaction coinbase;
    coinbase.version = 1;
    TxIn ci;
    ci.prevout.tx_hash = uint256_t();
    ci.prevout.index = 0xFFFFFFFF;
    ci.sequence = 0xFFFFFFFF;
    coinbase.inputs.push_back(ci);
    TxOut co;
    co.value = 50 * 100000000LL;
    co.scriptPubKey = addr;
    coinbase.outputs.push_back(co);
    coinbase.lockTime = 0;
    assert(set.apply_transaction(coinbase, 0));

    Transaction spend;
    spend.version = 1;
    TxIn in;
    in.prevout.tx_hash = coinbase.hash();
    in.prevout.index = 0;
    in.sequence = 0xFFFFFFFF;
    spend.inputs.push_back(in);
    TxOut o1;
    o1.value = 49 * 100000000LL;
    o1.scriptPubKey = addr;
    TxOut o2;
    o2.value = 0; // fee of 1 coin
    o2.scriptPubKey = addr;
    spend.outputs.push_back(o1);
    spend.outputs.push_back(o2);
    spend.lockTime = 0;

    // FIX: use actual scriptPubKey bytes (the address string) for sighash
    std::vector<uint8_t> script_bytes(addr.begin(), addr.end());
    uint256_t sigh = spend.sighash(0, script_bytes);
    auto sig = script::sign_hash(sigh, priv);
    in.scriptSig = sig;
    in.scriptSig.insert(in.scriptSig.end(), pub.begin(), pub.end());
    spend.inputs[0] = in;

    int64_t fee = 0;
    assert(set.apply_transaction(spend, 101, &fee));
    assert(fee == (50 * 100000000LL) - (49 * 100000000LL));
}

static void test_wallet_multi_address() {
    std::filesystem::path wallet_path = unique_temp_path("cryptex_multi_wallet", ".dat");
    std::filesystem::remove(wallet_path);
    auto wallet = Wallet::create_new("testpass", wallet_path.string());
    assert(wallet.is_bip32());
    auto first = wallet.address;
    auto second = wallet.add_address("testpass", wallet_path.string());
    auto loaded = Wallet::load("testpass", wallet_path.string());
    assert(loaded.is_hd());
    assert(loaded.is_bip32());
    assert(loaded.all_addresses().size() == 2);
    assert(loaded.all_addresses()[0] == first);
    assert(loaded.display_address(loaded.all_addresses()[1]) == second);
    loaded.set_label("testpass", wallet_path.string(), first, "Primary Treasury");
    auto labeled = Wallet::load("testpass", wallet_path.string());
    assert(labeled.label_for(first) == "Primary Treasury");
    assert(!labeled.address_book().empty());
    assert(labeled.address_book()[0].label == "Primary Treasury");
    std::filesystem::remove(wallet_path);
}

static void test_bip39_known_vector() {
    std::vector<uint8_t> entropy(16, 0x00);
    auto mnemonic = bip39::entropy_to_mnemonic(entropy);
    assert(mnemonic == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    auto decoded = bip39::mnemonic_to_entropy(mnemonic);
    assert(decoded == entropy);
}

static void test_wallet_mnemonic_import_roundtrip() {
    std::filesystem::path wallet_a = unique_temp_path("cryptex_mnemonic_a", ".dat");
    std::filesystem::path wallet_b = unique_temp_path("cryptex_mnemonic_b", ".dat");
    std::filesystem::remove(wallet_a);
    std::filesystem::remove(wallet_b);

    auto original = Wallet::create_new("testpass", wallet_a.string(), 12, "pepper");
    auto mnemonic = original.mnemonic_phrase();
    auto imported = Wallet::create_from_mnemonic("testpass", wallet_b.string(), mnemonic, "pepper");

    assert(original.address == imported.address);
    assert(imported.is_bip32());
    assert(imported.has_mnemonic());
    assert(imported.mnemonic_phrase() == mnemonic);

    std::filesystem::remove(wallet_a);
    std::filesystem::remove(wallet_b);
}

static void test_config_parse() {
    auto cfg = ConfigFile::parse(
        "# comment\n"
        "datadir = /tmp/cryptex\n"
        "log.level = debug\n"
        "logjson = true\n"
        "connect = 127.0.0.1:9333\n"
        "connect = 10.0.0.5:9333\n"
        "seed = seed1.cryptex.test\n"
        "seed = 198.51.100.42:19444\n"
        "externalip = 203.0.113.9:9333\n"
        "discover = no\n"
        "ipdetectpath = /ip\n"
        "rpc_enable = yes\n");

    assert(cfg.get_string("datadir").value() == "/tmp/cryptex");
    assert(cfg.get_string("log_level").value() == "debug");
    assert(cfg.get_bool("logjson").value());
    assert(cfg.get_bool("rpc-enable").value());
    assert(!cfg.get_bool("discover").value());
    assert(cfg.get_string("externalip").value() == "203.0.113.9:9333");
    assert(cfg.get_string("ipdetectpath").value() == "/ip");
    auto peers = cfg.get_all("connect");
    assert(peers.size() == 2);
    assert(peers[0] == "127.0.0.1:9333");
    assert(peers[1] == "10.0.0.5:9333");
    auto seeds = cfg.get_all("seed");
    assert(seeds.size() == 2);
    assert(seeds[0] == "seed1.cryptex.test");
    assert(seeds[1] == "198.51.100.42:19444");
}

static void test_version_payload_and_seed_bootstrap() {
    net::VersionPayload payload;
    payload.protocol_version = 7;
    payload.best_height = 321;
    payload.listen_port = 19444;
    payload.advertised_ip = ip_address::from_string("203.0.113.9");
    auto encoded = payload.serialize();
    auto decoded = net::VersionPayload::deserialize(encoded);
    assert(decoded.protocol_version == 7);
    assert(decoded.best_height == 321);
    assert(decoded.listen_port == 19444);
    assert(decoded.advertised_ip.has_value());
    assert(decoded.advertised_ip->to_string() == "203.0.113.9");

    std::filesystem::path tmp = unique_temp_path("cryptex_seed_bootstrap");
    remove_all_if_exists(tmp);
    std::filesystem::create_directories(tmp);
    boost::asio::io_context ctx;
    net::NetworkNode node(ctx, 0, tmp);
    node.enable_discovery(false);
    node.set_external_address("203.0.113.9:19444");
    assert(node.advertised_endpoint().value() == "203.0.113.9:19444");
    node.set_dns_seeds({"198.51.100.42:9333"});
    node.bootstrap(false);
    auto peer_list = node.peers();
    bool saw_seed = false;
    bool saw_self = false;
    for (const auto& peer : peer_list) {
        if (peer.ip.to_string() == "198.51.100.42" && peer.port == 9333) {
            saw_seed = true;
        }
        if (peer.ip.to_string() == "203.0.113.9" && peer.port == 19444) {
            saw_self = true;
        }
    }
    assert(saw_seed);
    assert(saw_self);
    remove_all_if_exists(tmp);
}

static void test_secure_chat_roundtrip() {
    auto sender_key = make_test_key();
    Wallet sender;
    sender.privkey = sender_key.priv;
    sender.pubkey = sender_key.pub;
    sender.address = sender_key.address;
    sender.privkeys.push_back(sender.privkey);
    sender.pubkeys.push_back(sender.pubkey);
    sender.addresses.push_back(sender.address);

    Wallet recipient;
    auto recipient_key = make_test_key();
    recipient.privkey = recipient_key.priv;
    recipient.pubkey = recipient_key.pub;
    recipient.address = recipient_key.address;
    recipient.privkeys.push_back(recipient.privkey);
    recipient.pubkeys.push_back(recipient.pubkey);
    recipient.addresses.push_back(recipient.address);

    auto public_msg = chat::make_signed_public_chat(sender, sender.address, "dev", "hello world");
    auto public_decoded = chat::parse_chat_payload(public_msg, nullptr);
    assert(public_decoded.authenticated);
    assert(!public_decoded.encrypted);
    assert(public_decoded.message == "hello world");
    assert(public_decoded.channel == "dev");

    auto private_msg = chat::make_encrypted_private_chat(sender,
                                                         sender.address,
                                                         recipient.address,
                                                         recipient.pubkey,
                                                         "secret hello");
    auto opaque = chat::parse_chat_payload(private_msg, nullptr);
    assert(opaque.authenticated);
    assert(opaque.encrypted);
    assert(!opaque.decrypted);

    auto decrypted = chat::parse_chat_payload(private_msg, &recipient);
    assert(decrypted.authenticated);
    assert(decrypted.encrypted);
    assert(decrypted.decrypted);
    assert(decrypted.message == "secret hello");
    assert(decrypted.recipient_address == recipient.address);
}

static void test_structured_logging_to_file() {
    std::filesystem::path tmp = unique_temp_path("cryptex_logger_test");
    remove_all_if_exists(tmp);
    std::filesystem::create_directories(tmp);
    auto log_path = tmp / "cryptex.log";

    LogConfig config;
    config.level = LogLevel::Info;
    config.console = false;
    config.json = true;
    config.file_path = log_path;
    config.subsystems = {"chain"};
    configure_logging(config);

    log_info("chain", "tip advanced");
    log_info("rpc", "should be filtered");
    flush_logs();

    std::ifstream in(log_path);
    std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    assert(contents.find("\"level\":\"info\"") != std::string::npos);
    assert(contents.find("\"subsystem\":\"chain\"") != std::string::npos);
    assert(contents.find("\"msg\":\"tip advanced\"") != std::string::npos);
    assert(contents.find("should be filtered") == std::string::npos);

    LogConfig quiet;
    quiet.console = false;
    configure_logging(quiet);
    remove_all_if_exists(tmp);
}

static void test_wallet_balance_summary() {
    std::filesystem::path tmp = unique_temp_path("cryptex_balance_chain");
    remove_all_if_exists(tmp);

    auto wallet = Wallet::create_new("testpass", (tmp / "Wallet.dat").string());
    Blockchain chain(tmp);

    Block blk;
    blk.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    blk.header.bits = chain.next_work_bits(blk.header.timestamp);
    blk.header.nonce = 0;

    Transaction cb;
    cb.version = 1;
    TxIn in;
    in.prevout.tx_hash = uint256_t();
    in.prevout.index = 0xFFFFFFFF;
    in.sequence = 0xFFFFFFFF;
    cb.inputs.push_back(in);
    TxOut out;
    out.value = Block::get_block_reward(chain.best_height() + 1);
    out.scriptPubKey = wallet.address;
    cb.outputs.push_back(out);
    cb.lockTime = 0;
    blk.transactions.push_back(cb);
    blk.header.merkle_root = blk.compute_merkle_root();
    assert(chain.connect_block(blk, /*skip_pow_check=*/true));

    Blockchain reloaded(tmp);
    auto summary = wallet.balance_summary(reloaded);
    assert(summary.spendable == 0);
    assert(summary.immature == out.value);
    assert(summary.total() == out.value);

    remove_all_if_exists(tmp);
}

static void test_coinbase_matures_on_100th_confirmation_boundary() {
    NetworkScope scope(NetworkKind::Regtest);
    std::filesystem::path tmp = unique_temp_path("cryptex_coinbase_boundary");
    remove_all_if_exists(tmp);

    auto wallet = Wallet::create_new("testpass", (tmp / "Wallet.dat").string());
    auto external_key = make_test_key();
    Blockchain chain(tmp);

    auto mined = mine_valid_block(chain, wallet.address);
    assert(chain.accept_block(mined));

    for (int i = 0; i < constants::COINBASE_MATURITY - 2; ++i) {
        auto filler = mine_valid_block(chain, external_key.address);
        assert(chain.accept_block(filler));
    }

    auto before_boundary = wallet.balance_summary(chain);
    assert(before_boundary.spendable == 0);
    assert(before_boundary.immature == Block::get_block_reward(1));

    auto boundary_filler = mine_valid_block(chain, external_key.address);
    assert(chain.accept_block(boundary_filler));

    auto boundary_tx = wallet.create_payment(chain, external_key.address, 1 * 100000000LL);
    Mempool::AcceptStatus status = Mempool::AcceptStatus::Invalid;
    assert(chain.mempool().add_transaction(boundary_tx,
                                           chain.utxo(),
                                           static_cast<uint32_t>(chain.best_height()),
                                           &status));
    assert(status == Mempool::AcceptStatus::Accepted);

    auto on_boundary = wallet.balance_summary(chain);
    assert(on_boundary.spendable == Block::get_block_reward(1));
    assert(on_boundary.immature == 0);

    remove_all_if_exists(tmp);
}

static void test_wallet_rescan_discovers_used_hd_address() {
    std::filesystem::path tmp = unique_temp_path("cryptex_rescan_chain");
    remove_all_if_exists(tmp);

    auto wallet_a_path = (tmp / "WalletA.dat").string();
    auto wallet_b_path = (tmp / "WalletB.dat").string();
    auto wallet_a = Wallet::create_new("testpass", wallet_a_path, 12, "pepper");
    auto mnemonic = wallet_a.mnemonic_phrase();
    auto wallet_b = Wallet::create_from_mnemonic("testpass", wallet_b_path, mnemonic, "pepper");
    std::string target_address = wallet_b.address;
    for (int i = 0; i < 6; ++i) {
        target_address = wallet_b.add_address("testpass", wallet_b_path);
    }

    Blockchain chain(tmp);
    Block blk;
    blk.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    blk.header.bits = chain.next_work_bits(blk.header.timestamp);
    blk.header.nonce = 0;

    Transaction cb;
    cb.version = 1;
    TxIn in;
    in.prevout.tx_hash = uint256_t();
    in.prevout.index = 0xFFFFFFFF;
    in.sequence = 0xFFFFFFFF;
    cb.inputs.push_back(in);
    TxOut out;
    out.value = Block::get_block_reward(chain.best_height() + 1);
    out.scriptPubKey = target_address;
    cb.outputs.push_back(out);
    cb.lockTime = 0;
    blk.transactions.push_back(cb);
    blk.header.merkle_root = blk.compute_merkle_root();
    assert(chain.connect_block(blk, /*skip_pow_check=*/true));

    auto before = wallet_a.balance_summary(chain);
    assert(before.total() == 0);

    auto discovered = wallet_a.rescan(chain, "testpass", wallet_a_path, 20);
    assert(discovered >= 7);
    assert(wallet_a.all_addresses().size() >= 7);
    bool found = false;
    for (const auto& addr : wallet_a.all_addresses()) {
        if (wallet_a.display_address(addr) == target_address) {
            found = true;
            break;
        }
    }
    assert(found);
    auto after = wallet_a.balance_summary(chain);
    assert(after.immature == out.value);
    assert(after.total() == out.value);

    remove_all_if_exists(tmp);
}

static void test_chainstate_snapshot_reload() {
    std::filesystem::path tmp = unique_temp_path("cryptex_chainstate_chain");
    remove_all_if_exists(tmp);

    auto wallet = Wallet::create_new("testpass", (tmp / "Wallet.dat").string());
    Blockchain chain(tmp);

    Block blk;
    blk.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    blk.header.bits = chain.next_work_bits(blk.header.timestamp);
    blk.header.nonce = 0;

    Transaction cb;
    cb.version = 1;
    TxIn in;
    in.prevout.tx_hash = uint256_t();
    in.prevout.index = 0xFFFFFFFF;
    in.sequence = 0xFFFFFFFF;
    cb.inputs.push_back(in);
    TxOut out;
    out.value = Block::get_block_reward(chain.best_height() + 1);
    out.scriptPubKey = wallet.address;
    cb.outputs.push_back(out);
    cb.lockTime = 0;
    blk.transactions.push_back(cb);
    blk.header.merkle_root = blk.compute_merkle_root();
    assert(chain.connect_block(blk, /*skip_pow_check=*/true));

    auto chainstate_path = tmp / "chainstate.dat";
    assert(std::filesystem::exists(chainstate_path));

    std::filesystem::remove(tmp / "blocks" / "blk1.dat");
    Blockchain reloaded(tmp);
    auto summary = wallet.balance_summary(reloaded);
    assert(summary.immature == out.value);
    assert(summary.total() == out.value);

    remove_all_if_exists(tmp);
}

static void test_wallet_balance_locks_when_chain_unapproved() {
    std::filesystem::path tmp = unique_temp_path("cryptex_unapproved_balance_chain");
    remove_all_if_exists(tmp);

    auto wallet = Wallet::create_new("testpass", (tmp / "Wallet.dat").string());
    Blockchain chain(tmp);

    Block blk;
    blk.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    blk.header.bits = chain.next_work_bits(blk.header.timestamp);
    blk.header.nonce = 0;

    Transaction cb = make_coinbase_tx(wallet.address, Block::get_block_reward(chain.best_height() + 1));
    cb.inputs[0].scriptSig = make_coinbase_marker(chain.best_height() + 1,
                                                  blk.header.timestamp,
                                                  blk.header.prev_block_hash);
    blk.transactions.push_back(cb);
    blk.header.merkle_root = blk.compute_merkle_root();
    assert(chain.connect_block(blk, /*skip_pow_check=*/true));

    chain.set_sync_approval(false, 2, chain.best_height() + 1);
    auto summary = wallet.balance_summary(chain);
    assert(!summary.approved);
    assert(summary.spendable == 0);
    assert(summary.immature == 0);
    assert(summary.locked == cb.outputs[0].value);

    bool threw = false;
    try {
        wallet.create_payment(chain, wallet.address, 1);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);

    remove_all_if_exists(tmp);
}

static void test_offline_tip_extension_after_network_approval_stays_approved() {
    std::filesystem::path tmp = unique_temp_path("cryptex_offline_tip_approved");
    remove_all_if_exists(tmp);

    auto wallet = Wallet::create_new("testpass", (tmp / "Wallet.dat").string());
    Blockchain chain(tmp);

    auto first = mine_valid_block(chain, wallet.address);
    assert(chain.accept_block(first));
    chain.set_sync_approval(true, 2);

    auto second = mine_valid_block(chain, wallet.address);
    assert(chain.accept_block(second));

    auto summary = wallet.balance_summary(chain);
    assert(summary.approved);
    assert(summary.locked == 0);
    assert(summary.immature == Block::get_block_reward(1) + Block::get_block_reward(2));

    remove_all_if_exists(tmp);
}

static void test_sync_approval_survives_backend_attach_without_peers() {
    NetworkScope scope(NetworkKind::Regtest);
    std::filesystem::path tmp = unique_temp_path("cryptex_sync_approval_attach");
    remove_all_if_exists(tmp);

    auto wallet = Wallet::create_new("testpass", (tmp / "Wallet.dat").string());
    Blockchain chain(tmp);

    auto first = mine_valid_block(chain, wallet.address);
    assert(chain.accept_block(first));
    chain.set_sync_approval(false, 2, chain.best_height() + 1);

    boost::asio::io_context ctx;
    net::NetworkNode node(ctx, 0, tmp);
    node.attach_blockchain(&chain);

    auto summary = wallet.balance_summary(chain);
    assert(!summary.approved);
    assert(summary.locked == Block::get_block_reward(1));

    remove_all_if_exists(tmp);
}

static void test_fresh_genesis_node_is_not_auto_approved() {
    NetworkScope scope(NetworkKind::Regtest);
    std::filesystem::path tmp = unique_temp_path("cryptex_fresh_genesis_unapproved");
    remove_all_if_exists(tmp);

    Blockchain chain(tmp);
    assert(!chain.wallet_state_approved());

    boost::asio::io_context ctx;
    net::NetworkNode node(ctx, 0, tmp);
    node.attach_blockchain(&chain);

    assert(!chain.wallet_state_approved());

    remove_all_if_exists(tmp);
}

static void test_mempool_policy_rejections() {
    auto key = make_test_key();
    UTXOSet utxo;
    Transaction funding = make_coinbase_tx(key.address, 50 * 100000000LL);
    assert(utxo.apply_transaction(funding, 0));

    OutPoint prevout{funding.hash(), 0};
    Mempool pool;

    TxOut low_fee_out;
    low_fee_out.value = funding.outputs[0].value - 1;
    low_fee_out.scriptPubKey = key.address;
    auto low_fee_tx = make_signed_spend(prevout, funding.outputs[0], key, {low_fee_out});

    Mempool::AcceptStatus status = Mempool::AcceptStatus::Accepted;
    assert(!pool.add_transaction(low_fee_tx, utxo, 99, &status));
    assert(status == Mempool::AcceptStatus::LowFee);

    TxOut dust_out;
    dust_out.value = 100;
    dust_out.scriptPubKey = key.address;
    auto dust_tx = make_signed_spend(prevout, funding.outputs[0], key, {dust_out});
    assert(!pool.add_transaction(dust_tx, utxo, 99, &status));
    assert(status == Mempool::AcceptStatus::NonStandard);

    auto stats = pool.stats();
    assert(stats.tx_count == 0);
    assert(stats.orphan_count == 0);
}

static void test_mempool_orphan_promotion() {
    auto key = make_test_key();
    UTXOSet utxo;
    Transaction funding = make_coinbase_tx(key.address, 50 * 100000000LL);
    assert(utxo.apply_transaction(funding, 0));

    TxOut parent_out;
    parent_out.value = funding.outputs[0].value - 2000;
    parent_out.scriptPubKey = key.address;
    auto parent = make_signed_spend({funding.hash(), 0}, funding.outputs[0], key, {parent_out});

    TxOut child_out;
    child_out.value = parent_out.value - 1000;
    child_out.scriptPubKey = key.address;
    auto child = make_signed_spend({parent.hash(), 0}, parent.outputs[0], key, {child_out});

    Mempool pool;
    Mempool::AcceptStatus status = Mempool::AcceptStatus::Accepted;
    assert(!pool.add_transaction(child, utxo, 99, &status));
    assert(status == Mempool::AcceptStatus::MissingInputs);
    assert(pool.size() == 0);
    assert(pool.orphan_count() == 1);

    assert(pool.add_transaction(parent, utxo, 99, &status));
    assert(status == Mempool::AcceptStatus::Accepted);
    assert(pool.size() == 2);
    assert(pool.orphan_count() == 0);
    assert(pool.contains(parent.hash()));
    assert(pool.contains(child.hash()));
}

static void test_peer_state_persistence() {
    std::filesystem::path tmp = unique_temp_path("cryptex_peer_state");
    remove_all_if_exists(tmp);

    {
        boost::asio::io_context ctx;
        net::NetworkNode node(ctx, 0, tmp);
        node.punish_label("1.2.3.4:9333", constants::BAN_THRESHOLD, "test");
        auto peers = node.peer_statuses();
        auto it = std::find_if(peers.begin(), peers.end(), [](const auto& peer) {
            return peer.label == "1.2.3.4:9333";
        });
        assert(it != peers.end());
        assert(it->banned);
        assert(it->score >= constants::BAN_THRESHOLD);
        assert(it->invalid_messages >= 1);
        assert(!it->netgroup.empty());
        assert(it->last_reason.find("test") != std::string::npos);
        node.stop();
    }

    {
        boost::asio::io_context ctx;
        net::NetworkNode node(ctx, 0, tmp);
        auto peers = node.peer_statuses();
        auto it = std::find_if(peers.begin(), peers.end(), [](const auto& peer) {
            return peer.label == "1.2.3.4:9333";
        });
        assert(it != peers.end());
        assert(it->banned);
        assert(it->score >= constants::BAN_THRESHOLD);
        assert(it->invalid_messages >= 1);
        assert(!it->netgroup.empty());
        node.stop();
    }

    remove_all_if_exists(tmp);
}

static void test_block_locator_and_header_slice() {
    std::filesystem::path tmp = unique_temp_path("cryptex_locator_chain");
    remove_all_if_exists(tmp);

    Blockchain chain(tmp);
    for (int i = 0; i < 3; ++i) {
        Block blk;
        blk.header.version = 1;
        auto prev = chain.get_block(chain.best_height());
        blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
        blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr)) + static_cast<uint32_t>(i);
        blk.header.bits = chain.next_work_bits(blk.header.timestamp);
        blk.header.nonce = 0;

        Transaction cb;
        cb.version = 1;
        TxIn in;
        in.prevout.tx_hash = uint256_t();
        in.prevout.index = 0xFFFFFFFF;
        in.sequence = 0xFFFFFFFF;
        cb.inputs.push_back(in);
        TxOut out;
        out.value = Block::get_block_reward(chain.best_height() + 1);
        out.scriptPubKey = "AAECAwQFBgcICQoLDA0ODxAREhM=";
        cb.outputs.push_back(out);
        cb.lockTime = 0;
        blk.transactions.push_back(cb);
        blk.header.merkle_root = blk.compute_merkle_root();
        assert(chain.connect_block(blk, /*skip_pow_check=*/true));
    }

    auto locator = chain.block_locator();
    assert(!locator.empty());
    assert(locator.front() == chain.tip_hash());

    auto first_non_genesis = chain.get_block(1);
    assert(first_non_genesis.has_value());
    std::vector<uint256_t> remote_locator{first_non_genesis->header.pow_hash()};
    auto headers = chain.headers_after_locator(remote_locator, 2000);
    assert(headers.size() == 2);
    assert(headers.front().prev_block_hash == first_non_genesis->header.hash());

    remove_all_if_exists(tmp);
}

static void test_rpc_service() {
    std::filesystem::path tmp = unique_temp_path("cryptex_rpc_chain");
    remove_all_if_exists(tmp);

    auto wallet_path = (tmp / "Wallet.dat").string();
    auto wallet = Wallet::create_new("testpass", wallet_path);
    Blockchain chain(tmp);
    boost::asio::io_context rpc_ctx;
    net::NetworkNode rpc_node(rpc_ctx, 0, tmp);
    auto external_key = make_test_key();

    chat::HistoryEntry seeded_chat;
    seeded_chat.direction = "in";
    seeded_chat.is_private = false;
    seeded_chat.authenticated = true;
    seeded_chat.timestamp = static_cast<uint64_t>(std::time(nullptr));
    seeded_chat.nonce = 42;
    seeded_chat.message_id = "seeded-chat-id";
    seeded_chat.sender_address = wallet.address;
    seeded_chat.channel = "dev";
    seeded_chat.message = "hello from history";
    seeded_chat.peer_label = "127.0.0.1:9333";
    seeded_chat.status = "received";
    rpc_node.record_chat_history(seeded_chat);

    Block blk;
    blk.header.version = 1;
    auto prev = chain.get_block(chain.best_height());
    blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
    blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
    blk.header.bits = chain.next_work_bits(blk.header.timestamp);
    blk.header.nonce = 0;

    Transaction cb;
    cb.version = 1;
    TxIn in;
    in.prevout.tx_hash = uint256_t();
    in.prevout.index = 0xFFFFFFFF;
    in.scriptSig = make_coinbase_marker(chain.best_height() + 1, blk.header.timestamp, blk.header.prev_block_hash);
    in.sequence = 0xFFFFFFFF;
    cb.inputs.push_back(in);
    TxOut out;
    out.value = Block::get_block_reward(chain.best_height() + 1);
    out.scriptPubKey = wallet.address;
    cb.outputs.push_back(out);
    cb.lockTime = 0;
    blk.transactions.push_back(cb);
    blk.header.merkle_root = blk.compute_merkle_root();
    assert(chain.connect_block(blk, /*skip_pow_check=*/true));

    for (int i = 0; i < constants::COINBASE_MATURITY; ++i) {
        Block filler;
        filler.header.version = 1;
        auto filler_prev = chain.get_block(chain.best_height());
        filler.header.prev_block_hash = filler_prev ? filler_prev->header.hash() : uint256_t();
        filler.header.timestamp = static_cast<uint32_t>(std::time(nullptr)) + static_cast<uint32_t>(i + 1);
        filler.header.bits = chain.next_work_bits(filler.header.timestamp);
        filler.header.nonce = 0;

        Transaction filler_cb = make_coinbase_tx(external_key.address, Block::get_block_reward(chain.best_height() + 1));
        filler_cb.inputs[0].scriptSig = make_coinbase_marker(chain.best_height() + 1,
                                                             filler.header.timestamp,
                                                             filler.header.prev_block_hash);
        filler.transactions.push_back(std::move(filler_cb));
        filler.header.merkle_root = filler.compute_merkle_root();
        assert(chain.connect_block(filler, /*skip_pow_check=*/true));
    }

    rpc::RpcService rpc_service(chain, &rpc_node, wallet_path, std::string("testpass"));
    bool stop_requested = false;

    auto count_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]})",
        stop_requested);
    assert(!stop_requested);
    assert(count_resp.find("\"result\":101") != std::string::npos);

    auto wallet_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":2,"method":"getwalletinfo","params":[]})",
        stop_requested);
    assert(wallet_resp.find("\"balance_sats\":" + std::to_string(out.value)) != std::string::npos);
    assert(wallet_resp.find("\"immature_balance_sats\":0") != std::string::npos);
    assert(wallet_resp.find("\"mnemonic_backed\":true") != std::string::npos);

    auto mempool_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":7,"method":"getmempoolinfo","params":[]})",
        stop_requested);
    assert(mempool_resp.find("\"maxmempool\":300000000") != std::string::npos);

    auto chatinfo_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":14,"method":"getchatinfo","params":[]})",
        stop_requested);
    assert(chatinfo_resp.find("\"messages\":1") != std::string::npos);
    assert(chatinfo_resp.find("chat_history.dat") != std::string::npos);
    assert(chatinfo_resp.find("\"routing_mode\":\"awaiting-peers\"") != std::string::npos);

    auto chatinbox_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":15,"method":"getchatinbox","params":[{"channel":"dev"}]})",
        stop_requested);
    assert(chatinbox_resp.find("seeded-chat-id") != std::string::npos);
    assert(chatinbox_resp.find("hello from history") != std::string::npos);

    auto chaininfo_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":8,"method":"getblockchaininfo","params":[]})",
        stop_requested);
    assert(chaininfo_resp.find("\"chain\":\"mainnet\"") != std::string::npos);
    assert(chaininfo_resp.find("\"blocks\":101") != std::string::npos);
    assert(chaininfo_resp.find("\"checkpoint_height\":99") != std::string::npos);

    auto checkpoint_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":34,"method":"getcheckpointinfo","params":[]})",
        stop_requested);
    assert(checkpoint_resp.find("\"present\":true") != std::string::npos);
    assert(checkpoint_resp.find("\"pinned\":false") != std::string::npos);

    auto pin_checkpoint_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":35,"method":"pincheckpoint","params":[]})",
        stop_requested);
    assert(pin_checkpoint_resp.find("\"result\":true") != std::string::npos);

    auto pinned_checkpoint_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":36,"method":"getcheckpointinfo","params":[]})",
        stop_requested);
    assert(pinned_checkpoint_resp.find("\"pinned\":true") != std::string::npos);

    auto clear_checkpoint_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":37,"method":"clearcheckpointpin","params":[]})",
        stop_requested);
    assert(clear_checkpoint_resp.find("\"result\":true") != std::string::npos);

    auto chaintips_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":9,"method":"getchaintips","params":[]})",
        stop_requested);
    assert(chaintips_resp.find("\"status\":\"active\"") != std::string::npos);

    auto txid = cb.hash().to_hex();
    auto txout_req = std::string(R"({"jsonrpc":"2.0","id":10,"method":"gettxout","params":[")") +
                     txid + R"(",0]})";
    auto txout_resp = rpc_service.handle_jsonrpc(txout_req, stop_requested);
    assert(txout_resp.find("\"value_sats\":" + std::to_string(out.value)) != std::string::npos);
    assert(txout_resp.find(wallet.display_address(wallet.address)) != std::string::npos);

    auto rawtx_req = std::string(R"({"jsonrpc":"2.0","id":11,"method":"getrawtransaction","params":[")") +
                     txid + R"(",true]})";
    auto rawtx_resp = rpc_service.handle_jsonrpc(rawtx_req, stop_requested);
    assert(rawtx_resp.find("\"txid\":\"" + txid + "\"") != std::string::npos);
    assert(rawtx_resp.find("\"blockheight\":1") != std::string::npos);

    auto decode_req = std::string(R"({"jsonrpc":"2.0","id":12,"method":"decoderawtransaction","params":[")") +
                      hex_encode(cb.serialize()) + R"("]})";
    auto decode_resp = rpc_service.handle_jsonrpc(decode_req, stop_requested);
    assert(decode_resp.find("\"txid\":\"" + txid + "\"") != std::string::npos);

    auto dump_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":5,"method":"dumpmnemonic","params":[]})",
        stop_requested);
    assert(dump_resp.find(wallet.mnemonic_phrase()) != std::string::npos);

    auto expected_privkey_hex = wallet.dump_private_key_hex();
    auto dumpprivkey_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":17,"method":"dumpprivkey","params":[]})",
        stop_requested);
    assert(dumpprivkey_resp.find(expected_privkey_hex) != std::string::npos);

    auto dumpprivkey_specific_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":17,"method":"dumpprivkey","params":[")") + crypto::address_to_base64(wallet.address) + R"("]})",
        stop_requested);
    assert(dumpprivkey_specific_resp.find(expected_privkey_hex) != std::string::npos);

    auto import_source_path = unique_temp_path("cryptex_import_wallet", ".dat");
    auto import_source_wallet = Wallet::create_new("importpass", import_source_path.string());
    auto import_hex = import_source_wallet.dump_private_key_hex();
    auto imported_display_address = wallet.display_address(import_source_wallet.address);

    auto importprivkey_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":38,"method":"importprivkey","params":[")") +
        import_hex + R"(","Imported Key"]})",
        stop_requested);
    assert(importprivkey_resp.find(imported_display_address) != std::string::npos);

    auto imported_addressbook_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":39,"method":"getwalletaddressbook","params":[]})",
        stop_requested);
    assert(imported_addressbook_resp.find("Imported Key") != std::string::npos);
    assert(imported_addressbook_resp.find(imported_display_address) != std::string::npos);

    auto backup_path = unique_temp_path("cryptex_wallet_backup", ".dat");
    auto backupwallet_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":40,"method":"backupwallet","params":[")") +
        backup_path.string() + R"("]})",
        stop_requested);
    assert(backupwallet_resp.find(backup_path.string()) != std::string::npos);
    assert(std::filesystem::exists(backup_path));
    auto backup_wallet = Wallet::load("testpass", backup_path.string());
    assert(!backup_wallet.all_addresses().empty());
    assert(std::find(backup_wallet.all_addresses().begin(),
                     backup_wallet.all_addresses().end(),
                     import_source_wallet.address) != backup_wallet.all_addresses().end());

    auto addresses_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":18,"method":"getwalletaddresses","params":[]})",
        stop_requested);
    assert(addresses_resp.find(wallet.display_address(wallet.address)) != std::string::npos);

    auto unused_address_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":18,"method":"getunusedaddress","params":[]})",
        stop_requested);
    assert(unused_address_resp.find("\"result\":\"") != std::string::npos);

    auto setlabel_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":20,"method":"setaddresslabel","params":[")") +
        wallet.display_address(wallet.address) + R"(","Primary Treasury"]})",
        stop_requested);
    assert(setlabel_resp.find("\"result\":true") != std::string::npos);

    auto addressbook_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":21,"method":"getwalletaddressbook","params":[]})",
        stop_requested);
    assert(addressbook_resp.find("Primary Treasury") != std::string::npos);
    assert(addressbook_resp.find(wallet.display_address(wallet.address)) != std::string::npos);
    assert(addressbook_resp.find("\"address_base64\":\"") != std::string::npos);
    assert(addressbook_resp.find("\"address_hex\":\"0x") != std::string::npos);

    auto history_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":19,"method":"getwallethistory","params":[true]})",
        stop_requested);
    assert(history_resp.find("Balance: " + std::to_string(out.value)) != std::string::npos);

    auto wallet_txs_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":22,"method":"getwallettransactions","params":[true]})",
        stop_requested);
    assert(wallet_txs_resp.find("\"direction\":\"mined\"") != std::string::npos);

    auto wallet_tx_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":23,"method":"getwallettransaction","params":[")") + txid + R"(",true]})",
        stop_requested);
    assert(wallet_tx_resp.find("\"txid\":\"" + txid + "\"") != std::string::npos);
    assert(wallet_tx_resp.find("\"coinbase\":true") != std::string::npos);

    auto rescan_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":6,"method":"rescanwallet","params":[5]})",
        stop_requested);
    assert(rescan_resp.find("\"addresscount\":6") != std::string::npos);

    auto recent_blocks_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":24,"method":"getrecentblocks","params":[3]})",
        stop_requested);
    assert(recent_blocks_resp.find("\"height\":101") != std::string::npos);
    assert(recent_blocks_resp.find("\"height\":100") != std::string::npos);

    auto address_summary_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":25,"method":"getaddresssummary","params":[")") + wallet.address + R"(",true]})",
        stop_requested);
    assert(address_summary_resp.find("\"balance_sats\":" + std::to_string(out.value)) != std::string::npos);
    assert(address_summary_resp.find("\"tx_count\":1") != std::string::npos);
    assert(address_summary_resp.find("\"address_base64\":\"") != std::string::npos);

    auto address_txids_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":26,"method":"getaddresstxids","params":[")") + wallet.address + R"(",true,10]})",
        stop_requested);
    assert(address_txids_resp.find(txid) != std::string::npos);

    auto search_block_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":27,"method":"searchchain","params":["101"]})"),
        stop_requested);
    assert(search_block_resp.find("\"type\":\"block\"") != std::string::npos);

    auto search_tx_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":28,"method":"searchchain","params":[")") + txid + R"("]})",
        stop_requested);
    assert(search_tx_resp.find("\"type\":\"transaction\"") != std::string::npos);

    auto search_address_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":29,"method":"searchchain","params":[")") + wallet.address + R"("]})",
        stop_requested);
    assert(search_address_resp.find("\"type\":\"address\"") != std::string::npos);

    auto block_hash = blk.header.pow_hash().to_hex_padded(constants::POW_HASH_BYTES);
    auto block_req = std::string(R"({"jsonrpc":"2.0","id":3,"method":"getblock","params":[")") +
                     block_hash + R"(",1]})";
    auto block_resp = rpc_service.handle_jsonrpc(block_req, stop_requested);
    assert(block_resp.find("\"hash\":\"" + block_hash + "\"") != std::string::npos);

    auto block_template_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":30,"method":"getblocktemplate","params":[")") + wallet.address + R"("]})",
        stop_requested);
    assert(block_template_resp.find("\"coinbase_address\":\"" + wallet.display_address(wallet.address) + "\"") != std::string::npos);
    assert(block_template_resp.find("\"coinbase_address_base64\":\"") != std::string::npos);
    assert(block_template_resp.find("\"height\":102") != std::string::npos);

    auto submitblock_req = std::string(R"({"jsonrpc":"2.0","id":13,"method":"submitblock","params":[")") +
                           hex_encode(blk.serialize()) + R"("]})";
    auto submitblock_resp = rpc_service.handle_jsonrpc(submitblock_req, stop_requested);
    assert(submitblock_resp.find("\"result\":\"duplicate\"") != std::string::npos);

    auto send_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":31,"method":"sendtoaddress","params":[")") +
        external_key.address +
        R"(",100000000,{"op_return":"rpc coin control","change_address":")" +
        wallet.address +
        R"(","inputs":[{"txid":")" +
        txid +
        R"(","vout":0}]}]})",
        stop_requested);
    assert(send_resp.find("\"result\":\"") != std::string::npos);

    auto mempool_after_send = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":32,"method":"getrawmempool","params":[]})",
        stop_requested);
    assert(mempool_after_send.find("\"") != std::string::npos);

    auto wallet_txs_after_send = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":33,"method":"getwallettransactions","params":[true]})",
        stop_requested);
    assert(wallet_txs_after_send.find("rpc coin control") == std::string::npos); // OP_RETURN note is not exposed as wallet text
    assert(wallet_txs_after_send.find("\"direction\":\"sent\"") != std::string::npos ||
           wallet_txs_after_send.find("\"direction\":\"self\"") != std::string::npos);

    auto sendchat_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":16,"method":"sendchatpublic","params":["127.0.0.1:1","ops","hello rpc"]})",
        stop_requested);
    assert(sendchat_resp.find("\"status\":\"no-peer\"") != std::string::npos);
    assert(sendchat_resp.find("\"messageid\":\"") != std::string::npos);

    auto sendchat_network_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":40,"method":"sendchatpublic","params":["ops","hello network rpc"]})",
        stop_requested);
    assert(sendchat_network_resp.find("\"status\":\"no-peer\"") != std::string::npos);
    assert(sendchat_network_resp.find("\"peer\":\"network\"") != std::string::npos);

    auto peer_graph_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":38,"method":"getpeergraph","params":[]})",
        stop_requested);
    assert(peer_graph_resp.find("\"result\":[") != std::string::npos);

    auto port_mapping_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":39,"method":"getportmappinginfo","params":[]})",
        stop_requested);
    assert(port_mapping_resp.find("\"enabled\":false") != std::string::npos);

    auto chatinbox_after_send = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":17,"method":"getchatinbox","params":[10,{"direction":"out"}]})",
        stop_requested);
    assert(chatinbox_after_send.find("hello rpc") != std::string::npos);
    assert(chatinbox_after_send.find("hello network rpc") != std::string::npos);
    assert(chatinbox_after_send.find("\"status\":\"no-peer\"") != std::string::npos);

    auto walletpassphrasechange_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":41,"method":"walletpassphrasechange","params":["testpass","freshpass"]})",
        stop_requested);
    assert(walletpassphrasechange_resp.find("\"result\":true") != std::string::npos);

    auto wallet_after_passchange = Wallet::load("freshpass", wallet_path);
    assert(wallet_after_passchange.mnemonic_phrase() == wallet.mnemonic_phrase());

    auto mnemonic_after_passchange_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":42,"method":"dumpmnemonic","params":[]})",
        stop_requested);
    assert(mnemonic_after_passchange_resp.find(wallet.mnemonic_phrase()) != std::string::npos);

    auto importmnemonic_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":43,"method":"importmnemonic","params":[")") +
        wallet.mnemonic_phrase() + R"("]})",
        stop_requested);
    assert(importmnemonic_resp.find(".before-import.bak") != std::string::npos);
    assert(importmnemonic_resp.find(crypto::address_to_base58(wallet.address)) != std::string::npos);
    assert(std::filesystem::exists(wallet_path + ".before-import.bak"));

    auto restored_wallet = Wallet::load("freshpass", wallet_path);
    assert(restored_wallet.address == wallet.address);

    auto stop_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":4,"method":"stop","params":[]})",
        stop_requested);
    assert(stop_requested);
    assert(stop_resp.find("\"result\":\"stopping\"") != std::string::npos);

    remove_all_if_exists(tmp);
}

static void test_late_node_syncs_to_best_chain() {
    NetworkScope scope(NetworkKind::Regtest);
    auto source_dir = unique_temp_path("cryptex_sync_source");
    auto sink_dir = unique_temp_path("cryptex_sync_sink");
    remove_all_if_exists(source_dir);
    remove_all_if_exists(sink_dir);

    auto wallet_path = (source_dir / "Wallet.dat").string();
    auto wallet = Wallet::create_new("syncpass", wallet_path);

    Blockchain source_chain(source_dir);
    Blockchain sink_chain(sink_dir);

    auto blk1 = mine_valid_block(source_chain, wallet.address);
    assert(source_chain.accept_block(blk1));
    auto blk2 = mine_valid_block(source_chain, wallet.address);
    assert(source_chain.accept_block(blk2));
    assert(source_chain.best_height() == 2);
    assert(sink_chain.best_height() == 0);

    boost::asio::io_context source_ctx;
    boost::asio::io_context sink_ctx;
    uint16_t source_port = pick_free_port();

    net::NetworkNode source_node(source_ctx, source_port, source_dir);
    source_node.attach_blockchain(&source_chain);
    source_node.best_height = static_cast<uint32_t>(source_chain.best_height());
    source_node.start();

    net::NetworkNode sink_node(sink_ctx, 0, sink_dir);
    sink_node.attach_blockchain(&sink_chain);
    sink_node.best_height = static_cast<uint32_t>(sink_chain.best_height());
    sink_node.start();

    std::thread source_thread([&]() { source_ctx.run(); });
    std::thread sink_thread([&]() { sink_ctx.run(); });

    sink_node.connect("127.0.0.1", source_port);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline &&
           sink_chain.best_height() < source_chain.best_height()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto status = sink_node.sync_status();
    assert(sink_chain.best_height() == source_chain.best_height());
    assert(status.local_height == source_chain.best_height());
    assert(status.best_peer_height >= source_chain.best_height());
    assert(status.queued_blocks == 0);
    assert(status.inflight_blocks == 0);

    sink_node.stop();
    source_node.stop();
    sink_ctx.stop();
    source_ctx.stop();
    if (sink_thread.joinable()) sink_thread.join();
    if (source_thread.joinable()) source_thread.join();

    remove_all_if_exists(source_dir);
    remove_all_if_exists(sink_dir);
}

static void test_deep_reorg_policy_blocks_history_rewrite() {
    NetworkScope scope(NetworkKind::Regtest);
    auto key = make_test_key();
    auto tmp = unique_temp_path("cryptex_deep_reorg_guard");
    remove_all_if_exists(tmp);

    set_env_var("CRYPTEX_ALLOW_DEEP_REORG", nullptr);
    set_env_var("CRYPTEX_MAX_REORG_DEPTH", nullptr);

    Blockchain chain(tmp);
    auto genesis = chain.get_block(0);
    assert(genesis.has_value());

    auto a1 = make_branch_block(genesis->header, 1, key.address, 1);
    auto a2 = make_branch_block(a1.header, 2, key.address, 1);
    auto a3 = make_branch_block(a2.header, 3, key.address, 1);
    auto a4 = make_branch_block(a3.header, 4, key.address, 1);
    assert(chain.accept_block(a1, /*skip_pow_check=*/true));
    assert(chain.accept_block(a2, /*skip_pow_check=*/true));
    assert(chain.accept_block(a3, /*skip_pow_check=*/true));
    assert(chain.accept_block(a4, /*skip_pow_check=*/true));
    assert(chain.best_height() == 4);
    auto original_tip = chain.tip_hash();

    auto b1 = make_branch_block(genesis->header, 1, key.address, 10);
    auto b2 = make_branch_block(b1.header, 2, key.address, 10);
    auto b3 = make_branch_block(b2.header, 3, key.address, 10);
    auto b4 = make_branch_block(b3.header, 4, key.address, 10);
    auto b5 = make_branch_block(b4.header, 5, key.address, 10);
    assert(chain.accept_block(b1, /*skip_pow_check=*/true));
    assert(chain.accept_block(b2, /*skip_pow_check=*/true));
    assert(chain.accept_block(b3, /*skip_pow_check=*/true));
    assert(chain.accept_block(b4, /*skip_pow_check=*/true));
    assert(!chain.accept_block(b5, /*skip_pow_check=*/true));
    assert(chain.best_height() == 4);
    assert(chain.tip_hash() == original_tip);

    remove_all_if_exists(tmp);
}

static void test_shallow_reorg_within_limit_is_allowed() {
    NetworkScope scope(NetworkKind::Regtest);
    auto key = make_test_key();
    auto tmp = unique_temp_path("cryptex_shallow_reorg_guard");
    remove_all_if_exists(tmp);

    set_env_var("CRYPTEX_ALLOW_DEEP_REORG", nullptr);
    set_env_var("CRYPTEX_MAX_REORG_DEPTH", nullptr);

    Blockchain chain(tmp);
    auto genesis = chain.get_block(0);
    assert(genesis.has_value());

    auto a1 = make_branch_block(genesis->header, 1, key.address, 1);
    auto a2 = make_branch_block(a1.header, 2, key.address, 1);
    assert(chain.accept_block(a1, /*skip_pow_check=*/true));
    assert(chain.accept_block(a2, /*skip_pow_check=*/true));
    assert(chain.best_height() == 2);

    auto b1 = make_branch_block(genesis->header, 1, key.address, 20);
    auto b2 = make_branch_block(b1.header, 2, key.address, 20);
    auto b3 = make_branch_block(b2.header, 3, key.address, 20);
    assert(chain.accept_block(b1, /*skip_pow_check=*/true));
    assert(chain.accept_block(b2, /*skip_pow_check=*/true));
    assert(chain.accept_block(b3, /*skip_pow_check=*/true));
    assert(chain.best_height() == 3);
    assert(chain.tip_hash() == b3.header.pow_hash());

    remove_all_if_exists(tmp);
}

static void test_local_checkpoint_persists_and_blocks_deep_rewrite() {
    NetworkScope scope(NetworkKind::Regtest);
    auto key = make_test_key();
    auto tmp = unique_temp_path("cryptex_local_checkpoint_guard");
    remove_all_if_exists(tmp);

    set_env_var("CRYPTEX_ALLOW_DEEP_REORG", nullptr);
    set_env_var("CRYPTEX_MAX_REORG_DEPTH", nullptr);

    {
        Blockchain chain(tmp);
        auto genesis = chain.get_block(0);
        assert(genesis.has_value());

        auto a1 = make_branch_block(genesis->header, 1, key.address, 3);
        auto a2 = make_branch_block(a1.header, 2, key.address, 3);
        auto a3 = make_branch_block(a2.header, 3, key.address, 3);
        auto a4 = make_branch_block(a3.header, 4, key.address, 3);
        assert(chain.accept_block(a1, /*skip_pow_check=*/true));
        assert(chain.accept_block(a2, /*skip_pow_check=*/true));
        assert(chain.accept_block(a3, /*skip_pow_check=*/true));
        assert(chain.accept_block(a4, /*skip_pow_check=*/true));
        assert(std::filesystem::exists(tmp / "local_checkpoint.dat"));
    }

    set_env_var("CRYPTEX_ALLOW_DEEP_REORG", "1");

    {
        Blockchain chain(tmp);
        auto genesis = chain.get_block(0);
        assert(genesis.has_value());
        assert(chain.best_height() == 4);

        auto b1 = make_branch_block(genesis->header, 1, key.address, 30);
        auto b2 = make_branch_block(b1.header, 2, key.address, 30);
        auto b3 = make_branch_block(b2.header, 3, key.address, 30);
        auto b4 = make_branch_block(b3.header, 4, key.address, 30);
        auto b5 = make_branch_block(b4.header, 5, key.address, 30);
        assert(chain.accept_block(b1, /*skip_pow_check=*/true));
        assert(chain.accept_block(b2, /*skip_pow_check=*/true));
        assert(chain.accept_block(b3, /*skip_pow_check=*/true));
        assert(chain.accept_block(b4, /*skip_pow_check=*/true));
        assert(!chain.accept_block(b5, /*skip_pow_check=*/true));
        assert(chain.best_height() == 4);
    }

    set_env_var("CRYPTEX_ALLOW_DEEP_REORG", nullptr);
    remove_all_if_exists(tmp);
}

static void test_wallet_session_rpc_independent_of_startup_wallet_flags() {
    NetworkScope scope(NetworkKind::Regtest);
    auto tmp = unique_temp_path("cryptex_wallet_session_rpc");
    remove_all_if_exists(tmp);

    Blockchain chain(tmp);
    auto wallet_root = (tmp / "wallets").string();
    rpc::RpcService rpc_service(chain, nullptr, std::nullopt, std::nullopt, default_rpc_port(), wallet_root);
    bool stop_requested = false;
    auto wallet_path = (tmp / "wallets" / "HexWallet.dat").string();

    auto session_before = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":1,"method":"getwalletsessioninfo","params":[]})",
        stop_requested);
    assert(session_before.find("\"wallet_loaded\":false") != std::string::npos);

    auto wallet_create = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":2,"method":"createwallet","params":[")") +
        wallet_path + R"(","hex-pass","hex"]})",
        stop_requested);
    assert(wallet_create.find("\"wallet_loaded\":true") != std::string::npos);
    assert(wallet_create.find("\"address_format\":\"hex\"") != std::string::npos);
    assert(wallet_create.find("\"primaryaddress\":\"0x") != std::string::npos);

    auto wallet_list = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":21,"method":"listwallets","params":[]})",
        stop_requested);
    assert(wallet_list.find("\"name\":\"HexWallet\"") != std::string::npos);
    assert(wallet_list.find("\"address_format\":\"hex\"") != std::string::npos);
    assert(wallet_list.find("\"active\":true") != std::string::npos);

    auto default_wallet_path = (tmp / "wallets" / "NativeWallet.dat").string();
    auto create_default_wallet = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":22,"method":"createwallet","params":[")") +
        default_wallet_path + R"(","native-pass"]})",
        stop_requested);
    assert(create_default_wallet.find("\"address_format\":\"base64\"") != std::string::npos);

    auto close_default_wallet = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":23,"method":"closewallet","params":[]})",
        stop_requested);
    assert(close_default_wallet.find("\"result\":true") != std::string::npos);

    auto reopen_hex_wallet = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":24,"method":"openwallet","params":[")") +
        wallet_path + R"(","hex-pass"]})",
        stop_requested);
    assert(reopen_hex_wallet.find("\"address_format\":\"hex\"") != std::string::npos);

    auto wallet_info = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":3,"method":"getwalletinfo","params":[]})",
        stop_requested);
    assert(wallet_info.find("\"address_format\":\"hex\"") != std::string::npos);
    assert(wallet_info.find("\"wallet_loaded\":true") != std::string::npos);

    auto format_change = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":31,"method":"setwalletformat","params":["bech32"]})",
        stop_requested);
    assert(format_change.find("\"address_format\":\"bech32\"") != std::string::npos);

    auto wallet_info_after_change = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":32,"method":"getwalletinfo","params":[]})",
        stop_requested);
    assert(wallet_info_after_change.find("\"address_format\":\"bech32\"") != std::string::npos);

    auto unused_after_change = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":33,"method":"getunusedaddress","params":[]})",
        stop_requested);
    assert(unused_after_change.find("\"result\":\"crx1") != std::string::npos);

    auto close_resp = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":4,"method":"closewallet","params":[]})",
        stop_requested);
    assert(close_resp.find("\"result\":true") != std::string::npos);

    auto wallet_info_after_close = rpc_service.handle_jsonrpc(
        R"({"jsonrpc":"2.0","id":5,"method":"getwalletinfo","params":[]})",
        stop_requested);
    assert(wallet_info_after_close.find("no wallet is open") != std::string::npos);

    auto open_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":6,"method":"openwallet","params":[")") +
        wallet_path + R"(","hex-pass"]})",
        stop_requested);
    assert(open_resp.find("\"wallet_loaded\":true") != std::string::npos);
    assert(open_resp.find("\"address_format\":\"bech32\"") != std::string::npos);

    auto delete_resp = rpc_service.handle_jsonrpc(
        std::string(R"({"jsonrpc":"2.0","id":7,"method":"deletewallet","params":[")") +
        wallet_path + R"("]})",
        stop_requested);
    assert(delete_resp.find("\"result\":true") != std::string::npos);
    assert(!std::filesystem::exists(wallet_path));
    assert(!std::filesystem::exists(wallet_path + ".meta"));

    remove_all_if_exists(tmp);
}

int main() {
    LogConfig quiet_logs;
    quiet_logs.console = false;
    configure_logging(quiet_logs);

    test_base64_address();
    test_multi_format_address_support();
    test_bip39_known_vector();
    test_config_parse();
    test_version_payload_and_seed_bootstrap();
    test_structured_logging_to_file();
    test_genesis_pow_full_512();
    test_reward_schedule_matches_new_consensus();
    test_network_modes();
    test_secure_chat_roundtrip();
    test_legacy_address_compatibility();
    test_mainnet_emergency_difficulty_allows_low_hash_takeover();
    test_future_timestamp_block_is_rejected();
    test_unique_coinbase_rewards_accumulate();
    test_sighash_and_signature();
    test_utxo_apply_and_fee();
    test_wallet_multi_address();
    test_wallet_mnemonic_import_roundtrip();
    test_wallet_balance_summary();
    test_coinbase_matures_on_100th_confirmation_boundary();
    test_wallet_rescan_discovers_used_hd_address();
    test_wallet_unused_pool_and_privacy_change();
    test_chainstate_snapshot_reload();
    test_wallet_balance_locks_when_chain_unapproved();
    test_offline_tip_extension_after_network_approval_stays_approved();
    test_sync_approval_survives_backend_attach_without_peers();
    test_fresh_genesis_node_is_not_auto_approved();
    test_mempool_policy_rejections();
    test_mempool_orphan_promotion();
    test_peer_state_persistence();
    test_block_locator_and_header_slice();
    test_late_node_syncs_to_best_chain();
    test_deep_reorg_policy_blocks_history_rewrite();
    test_shallow_reorg_within_limit_is_allowed();
    test_local_checkpoint_persists_and_blocks_deep_rewrite();
    test_wallet_session_rpc_independent_of_startup_wallet_flags();
    test_rpc_service();
    // Block reward enforcement: overpay coinbase should fail, correct should pass
    {
        std::filesystem::path tmp = unique_temp_path("cryptex_test_chain");
        remove_all_if_exists(tmp);
        Blockchain chain(tmp);
        Block blk;
        blk.header.version = 1;
        auto prev = chain.get_block(chain.best_height());
        blk.header.prev_block_hash = prev ? prev->header.hash() : uint256_t();
        blk.header.timestamp = static_cast<uint32_t>(std::time(nullptr));
        blk.header.bits = chain.tip_bits();
        blk.header.nonce = 0;

        Transaction cb;
        cb.version = 1;
        TxIn in;
        in.prevout.tx_hash = uint256_t();
        in.prevout.index = 0xFFFFFFFF;
        in.sequence = 0xFFFFFFFF;
        cb.inputs.push_back(in);
        TxOut out;
        out.value = Block::get_block_reward(chain.best_height() + 1) + 1; // overpay by 1 sat
        out.scriptPubKey = "genesis";
        cb.outputs.push_back(out);
        cb.lockTime = 0;
        blk.transactions.push_back(cb);
        blk.header.merkle_root = blk.compute_merkle_root();
        assert(!chain.connect_block(blk, /*skip_pow_check=*/true));

        // Fix reward
        blk.transactions[0].outputs[0].value = Block::get_block_reward(chain.best_height() + 1);
        blk.header.merkle_root = blk.compute_merkle_root();
        assert(chain.connect_block(blk, /*skip_pow_check=*/true));
        remove_all_if_exists(tmp);
    }
    std::cout << "All tests passed\n";
    return 0;
}
