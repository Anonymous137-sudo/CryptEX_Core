# CryptEX Whitepaper

Implementation Reference for the Current CryptEX Node

Version: March 19, 2026

## Abstract

CryptEX is a UTXO-based cryptocurrency implemented in C++ with a single command-line node, wallet, miner, and JSON-RPC interface. It combines SHA3-512 proof of work, Boost.Asio-based peer-to-peer networking, AES-encrypted wallet storage, BIP39/BIP32 hierarchical deterministic wallets, headers-first chain synchronization, binary on-disk blockchain storage, and a conservative security posture inspired by Bitcoin-style full-node validation.

This whitepaper is not a speculative design memo. It describes how the current CryptEX implementation behaves today. Where the implementation is intentionally simplified or where a constant is present but not yet fully enforced in consensus, this paper states that directly.

## 1. Design Goals

CryptEX is designed around the following goals:

1. Use SHA3-512 as the network's proof-of-work primitive.
2. Keep a Bitcoin-like full-node architecture with local validation, UTXO tracking, and cumulative-work chain selection.
3. Provide a single executable that can act as wallet, miner, node, and RPC server.
4. Keep network operation practical for small and early-stage deployments with built-in peer discovery, peer persistence, and direct miner interfaces.
5. Store the blockchain and wallet in binary files under system application-data locations by default, so deleting the binary does not delete the chain.

## 2. High-Level Architecture

CryptEX consists of five major subsystems:

1. Consensus and block validation
2. Transaction and UTXO management
3. Wallet and key management
4. Peer-to-peer networking and synchronization
5. Operator interfaces through CLI, config, logging, and JSON-RPC

At runtime, a typical node works as follows:

1. Load block index, headers, and chainstate snapshot from disk.
2. Ensure the baked genesis block exists.
3. Start the P2P listener on TCP port 9333.
4. Optionally start JSON-RPC on TCP port 9332.
5. Discover peers through manual connection, saved peers, DNS seeds, and peer exchange.
6. Synchronize headers first, then fetch blocks in parallel.
7. Validate candidate chains by recomputing proof of work, Merkle root, transaction validity, reward rules, and cumulative work.

## 3. Monetary Policy

### 3.1 Unit of Account

CryptEX uses 100,000,000 base units per coin. User-facing wallet balance output is displayed in whole CryptEX units with 8 decimal places, while internal accounting uses satoshi-style integer units for exact arithmetic.

### 3.2 Target Block Interval

The target block interval is:

- 600 seconds
- 10 minutes per block

### 3.3 Block Reward

The initial subsidy is:

- 2500.00000000 CryptEX per block

The subsidy halves every:

- 200,000 blocks
- Approximately 3.8 years at a 10-minute block interval

Coinbase outputs must mature for:

- 100 blocks

before they become spendable.

### 3.4 Declared Supply and Emission Curve

The codebase now declares a nominal total supply constant of 1,000,000,000 CryptEX. Issuance remains determined by:

1. The initial block reward of 2500 CryptEX
2. The halving interval of 200000 blocks
3. Repeated right-shift halving until the reward reaches zero

## 4. Consensus Model

### 4.1 Proof of Work

CryptEX uses SHA3-512 for block-header hashing. The consensus-critical proof-of-work comparison uses the full 512-bit digest, not a truncated digest.

The current proof-of-work limit is encoded as:

- `0x3e00ffff`

This value was chosen to give the network a practical bootstrap difficulty when using a 512-bit hash output.

### 4.2 Header Structure

The serialized block header is 80 bytes and contains:

1. `version` (4 bytes)
2. `prev_block_hash` (32 bytes)
3. `merkle_root` (32 bytes)
4. `timestamp` (4 bytes)
5. `bits` (4 bytes)
6. `nonce` (4 bytes)

This format is intentionally close to Bitcoin's 80-byte header layout.

### 4.3 Dual Hash Semantics

CryptEX currently distinguishes between two header-related hashes:

1. `pow_hash`
   - Full 512-bit SHA3-512 digest of the serialized header
   - Used for proof-of-work validation
   - Used as the canonical block identifier in the active chain index, RPC, chainwork, inventory exchange, and block requests

2. `hash`
   - First 32 bytes of the SHA3-512 digest
   - Used as the 256-bit link hash for `prev_block_hash`

This means CryptEX is already 512-bit for proof of work and canonical block identity, while block linkage remains 256-bit in the current header schema.

### 4.4 Chain Selection

CryptEX uses most cumulative work, not longest-by-height, to select the active chain. For each block:

1. The compact target is expanded into a full-width target.
2. Block work is approximated as `(2^512 - 1) / (target + 1)`.
3. Cumulative work is tracked across the known chain graph.
4. If a candidate tip has more cumulative work than the current tip, the node reconstructs the full path to genesis and validates it before activation.

### 4.5 Fork Resolution

Fork resolution is conservative:

1. A candidate chain must be fully linked back to genesis.
2. Every block on the candidate path must validate:
   - linkage
   - proof of work
   - Merkle root
   - expected difficulty bits
   - transaction structure
   - transaction signatures
   - coinbase reward ceiling including fees
3. Only then is the path activated as the canonical chain.

This keeps chain switching deterministic and full-node verified.

## 5. Difficulty Adjustment

CryptEX does not use Bitcoin's original 2016-block retarget rule as its primary live adjustment behavior. Instead, the implementation uses a damped LWMA-style per-block retarget based on a recent moving window.

Current tuning:

- Window: 72 blocks
- Intended lookback: about 12 hours
- Minimum solvetime per sample: `target / 6`
- Maximum solvetime per sample: `target * 6`
- Per-step target clamp: between `0.5x` and `2x` of the window average target
- Final target capped by the protocol proof-of-work limit

The algorithm computes weighted recent solvetimes and weighted recent targets, then derives the next target with damping to reduce timestamp whipsaw. This makes the chain more responsive than long-window Bitcoin retargeting while still resisting short bursts of timestamp manipulation.

## 6. Genesis Block

CryptEX uses a pre-mined genesis block baked into the software.

Current genesis parameters:

- Timestamp: `1741478400`
- Human date: `2025-03-09 00:00:00 UTC`
- Bits: `0x3e00ffff`
- Nonce: `14946014`
- Genesis payout address: `AAECAwQFBgcICQoLDA0ODxAREhM=`

Current full 512-bit genesis proof-of-work hash:

`000000e8f28fa5c9f9ec942afaf8e17e71e80b56e1ccad87d08d1eaf920d2748e700b810a4d2c598fc01e973facc6fe51333d71a3381cfb7b1fa12bec6db6c79`

CryptEX also includes a `genesis-mine` utility for offline genesis mining and validation. That tool is used to find and bake in a valid nonce for a selected genesis template.

## 7. Transaction Model

### 7.1 UTXO Accounting

CryptEX uses a standard unspent transaction output model:

1. Transactions consume previously created outputs.
2. New outputs are inserted into the UTXO set.
3. Validation checks signatures, ownership, input existence, value conservation, and maturity rules.

Each UTXO entry records:

- output value
- destination address
- creation height
- whether the output came from a coinbase transaction

### 7.2 Transaction Identifiers

Transaction IDs are currently the first 32 bytes of the SHA3-512 digest of the serialized transaction. In other words:

- transaction hashing uses SHA3-512
- txids are still 256-bit identifiers in the current implementation

This is one of the protocol boundaries that still separates full 512-bit proof-of-work identity from the transaction layer.

### 7.3 Signature and Ownership Model

CryptEX uses:

- `secp256k1` keys
- ECDSA signatures via OpenSSL

Transaction unlocking today is simpler than a fully general Bitcoin Script execution model. The validation path effectively checks:

1. the referenced UTXO exists
2. the provided public key maps to the destination address
3. the signature verifies against the transaction sighash

A more general script engine exists in the codebase, but routine value-transfer validation is currently address-and-signature oriented rather than fully script-programmable.

### 7.4 Coinbase Transactions

A valid block must start with a coinbase transaction. The node enforces:

1. a coinbase must be first
2. the coinbase payout must not exceed block subsidy plus collected fees
3. coinbase outputs require 100 confirmations of maturity before spending

The coinbase `scriptSig` includes height, timestamp, and a fragment of the previous hash so coinbase transactions remain unique across blocks.

### 7.5 OP_RETURN Style Payloads

The wallet can optionally attach an `OP_RETURN:`-prefixed output when creating a transaction. In the current implementation, this output carries a Base64-encoded signature artifact derived from the caller-supplied message. It is best understood as a signed attachment mechanism, not a full arbitrary on-chain messaging protocol.

## 8. Address Format

CryptEX addresses are Base64-encoded 20-byte hashes.

Address derivation:

1. SHA-256 of the compressed secp256k1 public key
2. RIPEMD-160 of that SHA-256 digest
3. RFC 4648 Base64 encoding of the 20-byte result

Important properties:

- canonical length: 28 characters
- padding is part of the canonical form
- the node normalizes legacy variants so older non-canonical Base64 strings can still be matched to the same underlying 20-byte address

Example address shape:

- `37n70q2VSr4H+0dSpMO+hH8HOGg=`

## 9. Wallet Architecture

### 9.1 Encrypted Wallet Storage

`Wallet.dat` is encrypted at rest using:

- PBKDF2-HMAC-SHA256 for key derivation
- 100,000 PBKDF2 iterations
- AES-256-CBC for payload encryption

The wallet file contains:

1. a file version
2. a salt
3. an IV
4. ciphertext length
5. encrypted wallet payload

### 9.2 HD Wallets

New wallets are mnemonic-backed HD wallets using:

- BIP39 mnemonic generation and restoration
- BIP32 deterministic derivation

The current derivation path is:

- `m/0'/0/i`

where `i` is the address index.

Wallets can:

1. create a new mnemonic-backed wallet
2. import from a mnemonic
3. derive additional addresses
4. rescan the chain with a configurable gap limit

### 9.3 Legacy Compatibility

The loader keeps backward compatibility with:

- legacy single-key wallets
- older multi-key payload versions
- legacy internal HD wallets used before the BIP32 migration

This makes CryptEX relatively forgiving during wallet format evolution.

### 9.4 Multi-Address Accounting

Wallets support multiple addresses in a single encrypted file. Balance reporting is split into:

1. spendable balance
2. immature balance
3. total balance

This is particularly important for miners, because newly mined coinbase rewards are visible immediately but are not spendable until maturity.

## 10. Peer-to-Peer Network

### 10.1 Transport and Implementation

CryptEX networking is implemented with Boost.Asio over TCP. The default peer-to-peer port is:

- `9333`

Messages are framed with:

- a 4-byte magic value
- a 1-byte message type
- a 4-byte payload length
- the serialized payload

The current network magic is:

- `0x43584558`

### 10.2 Protocol Messages

The node currently supports at least the following message types:

1. `VERSION`
2. `VERACK`
3. `PING`
4. `PONG`
5. `GETHEADERS`
6. `HEADERS`
7. `GETBLOCK`
8. `BLOCK`
9. `GETPEERS`
10. `PEERS`
11. `CHAT`
12. `GETWORK`
13. `SUBMITWORK`
14. `INV`
15. `GETTX`
16. `TX`

### 10.3 Peer Discovery

CryptEX supports several bootstrap paths:

1. Manual `--connect host:port`
2. Saved peers from previous sessions
3. Peer exchange through `GETPEERS` / `PEERS`
4. DNS seeds
5. Optional external IP detection and self-advertisement

Serialized peer addresses are compact and include:

- 4 bytes IPv4 address
- 2 bytes port
- 1 byte flags

This allows a node to pass known reachable peers to other nodes in a simple binary format.

### 10.4 External Address Discovery

The node can discover its apparent public IP using an HTTP-based detection service. The current defaults are:

- host: `ifconfig.me`
- port: `80`
- path: `/`

This is an operational convenience feature, not a consensus rule. Operators should understand that it introduces trust in the chosen external IP service.

### 10.5 Peer Reputation and Bans

CryptEX includes a persisted peer reputation system with:

- misbehavior scoring
- automatic bans after threshold crossing
- score decay over time
- ban persistence on disk

Peer state is stored in:

- `peer_state.dat`

Known peers are stored in:

- `peers.dat`

This gives the network basic resilience against invalid payloads, malformed protocol messages, and spammy peers.

### 10.6 Public and Private Chat

CryptEX includes a non-consensus chat message type supporting:

- signed public chat
- signed and encrypted private chat

Public chat messages are authenticated with the sender wallet key. Private chat messages are authenticated and encrypted using an ECDH-derived AES-256-GCM session key bound to the recipient public key. Timestamp and nonce fields are included to reduce replay risk.

## 11. Synchronization and Block Propagation

### 11.1 Headers-First Sync

CryptEX uses a headers-first synchronization strategy:

1. Exchange best heights during version handshake
2. Request headers using a block locator
3. Validate header continuity
4. Queue missing blocks for download
5. Download blocks in parallel

Current operational limits include:

- up to 2,000 headers per `HEADERS` message
- up to 8 parallel block downloads

### 11.2 Block Locators

Block locators are built from the active chain using a stepped-back sequence similar to Bitcoin's locator approach:

1. recent blocks are listed densely
2. older history becomes exponentially sparser

This allows a reconnecting peer to find its last common ancestor efficiently.

### 11.3 Inventory Exchange

Transactions and blocks are announced through inventory messages:

- blocks use the canonical 512-bit proof-of-work block ID
- transactions use current 256-bit txids

This reflects the current mixed-width state of the protocol.

## 12. Mempool Policy

CryptEX enforces a standardness and fee policy for relay and mempool admission. Current policy includes:

1. no coinbase transactions in mempool
2. minimum relay fee of 1,000 base units per kB
3. maximum standard transaction size of 100,000 bytes
4. input limit of 128
5. output limit of 128
6. maximum scriptSig size of 1,650 bytes
7. dust rejection below 546 base units
8. only one `OP_RETURN` output per standard transaction
9. mempool conflict detection for double-spends
10. orphan transaction storage and later promotion when parents arrive
11. fee-rate-based eviction when mempool limits are reached

The mempool is therefore policy-aware, not just a raw transaction bucket.

## 13. Storage Model

### 13.1 On-Disk Files

CryptEX stores blockchain state as binary files. The active chain data directory contains files such as:

1. `blocks/blk<height>.dat`
2. `headers.dat`
3. `index.dat`
4. `chainstate.dat`
5. `peers.dat`
6. `peer_state.dat`
7. `Wallet.dat`
8. `cryptex.conf`

### 13.2 Block Storage

Active-chain blocks are stored by height as:

- `blk0.dat`
- `blk1.dat`
- `blk2.dat`
- and so on

This gives a very transparent active-chain storage model. The node rewrites canonical height files when a stronger chain becomes active.

### 13.3 Chainstate Snapshot

CryptEX persists a chainstate snapshot to:

- `chainstate.dat`

This file stores:

1. tip metadata
2. the active UTXO set
3. a checksum

On startup, the node first tries to load `chainstate.dat`. If the snapshot is missing, stale, or corrupt, it rebuilds the UTXO set from the active block files.

### 13.4 Default Data Locations

By default, CryptEX now stores data in system application-data locations:

- macOS: `~/Library/Application Support/CryptEX`
- Linux: `$XDG_DATA_HOME/CryptEX` or `~/.local/share/CryptEX`
- Windows: `%APPDATA%\\CryptEX`

This avoids accidental chain loss when binaries or build directories are deleted.

## 14. Mining

### 14.1 Local CPU Mining

CryptEX includes a built-in CPU miner that:

1. builds a block template from the active tip
2. creates a unique coinbase
3. includes mempool transactions until block size is reached
4. hashes candidate headers with SHA3-512
5. compares the full 512-bit digest against the target

Mining supports:

- multi-threaded CPU use
- configurable thread count
- infinite mining mode with `--cycles 0`
- debug output for hash-rate and current proof-of-work attempts

### 14.2 External Miner Interface

CryptEX exposes a `GETWORK` / `SUBMITWORK` flow over the P2P layer. This provides a lightweight external-miner interface.

Important boundary:

- CryptEX does expose getwork-style mining support
- CryptEX does not yet implement a full `getblocktemplate` stack
- CryptEX does not yet implement a full decentralized P2Pool system

## 15. JSON-RPC and Operator Interface

### 15.1 RPC Transport

CryptEX exposes an HTTP JSON-RPC server with:

- configurable bind address
- configurable port
- Basic authentication

Default RPC port:

- `9332`

For normal operation, RPC should remain bound to `127.0.0.1` unless a trusted network perimeter is in place.

### 15.2 RPC Coverage

The current RPC surface includes:

#### Blockchain and node inspection

- `getblockcount`
- `getbestblockhash`
- `getblockhash`
- `getblockheader`
- `getblock`
- `getblockchaininfo`
- `getchaintips`
- `getdifficulty`
- `getpeerinfo`
- `getnetworkinfo`
- `getmininginfo`
- `getmempoolinfo`

#### Transaction and mempool operations

- `getrawmempool`
- `getrawtransaction`
- `gettxout`
- `decoderawtransaction`
- `sendrawtransaction`
- `submitblock`

#### Wallet operations

- `getwalletinfo`
- `getbalance`
- `listunspent`
- `getnewaddress`
- `sendtoaddress`
- `dumpmnemonic`
- `rescanwallet`

#### Peer administration

- `addnode`
- `setban`
- `clearbanned`
- `listbanned`
- `stop`

### 15.3 Config and Logging

CryptEX supports a configuration file:

- `cryptex.conf`

and structured logging with:

- configurable log level
- console/file output
- JSON log mode
- subsystem filters

This is important for node operations, debugging, and deployments across multiple machines.

## 16. Security Properties

CryptEX's security posture today includes:

1. Full local proof-of-work validation
2. Full Merkle-root recomputation on block validation
3. Signature verification on transaction spends
4. Coinbase maturity enforcement
5. Cumulative-work-based chain selection
6. Binary wallet encryption at rest
7. Peer misbehavior scoring and persisted bans
8. Checksummed chainstate, header, and index persistence

These are meaningful full-node properties. A node does not simply trust remote peers for chain validity.

## 17. Current Implementation Boundaries

CryptEX already has a solid base, but the current code also has boundaries that users should understand clearly.

### 17.1 Full 512-Bit Proof of Work, Partial 512-Bit Data Model

CryptEX is fully 512-bit where proof of work and chainwork matter most:

- full 512-bit PoW digest
- full 512-bit canonical block ID
- 512-bit target/work arithmetic

However, the following are still 256-bit in the current implementation:

- `prev_block_hash` linkage
- transaction IDs
- Merkle root leaves and internal Merkle combinations
- outpoint transaction references

So the network is best described as a 512-bit proof-of-work chain with a partially 256-bit transaction and header-linkage model.

### 17.2 Emission Tradeoff

The 1 billion coin target is achieved by pairing a 2,500-coin starting reward with a 200,000-block halving interval. This is a deliberate monetary-policy choice, not a bug.

### 17.3 Side-Chain Persistence

Active-chain blocks are persisted by height. Known side-chain blocks are tracked in memory while the node is running, and headers are persisted, but raw side-branch block storage is not yet as complete as a full hash-addressed archival design. This is acceptable for an early full node, but it is not yet equivalent to Bitcoin Core's mature block/undo archival model.

### 17.4 RPC Transport Security

RPC uses Basic authentication over HTTP. It is suitable for localhost or a trusted private network, but it is not a replacement for TLS, a VPN, or SSH tunneling.

### 17.5 External IP Detection Trust

Automatic public-IP detection depends on an external service. This helps usability, but it is a trust and privacy tradeoff.

## 18. Why CryptEX Is Distinct

CryptEX is distinct from a minimal clone in several ways:

1. SHA3-512 proof of work with full-width target comparison
2. A single binary that combines wallet, node, mining, and RPC roles
3. Base64 address encoding instead of Base58 or Bech32
4. Built-in peer exchange, DNS-seed bootstrap, and external endpoint advertisement
5. Built-in public/private chat transport over the P2P layer
6. Built-in `GETWORK` support for external miners
7. Encrypted HD wallets with mnemonic restore

At the same time, it deliberately keeps a Bitcoin-like validation mindset: UTXOs, full-node checks, chainwork, mature coinbase rules, and explicit reorg handling.

## 19. Conclusion

CryptEX is a serious early-stage full-node cryptocurrency implementation rather than a toy chain launcher. Its strongest technical characteristics today are:

1. full 512-bit SHA3 proof of work
2. fork-aware cumulative-work chain selection
3. headers-first synchronization
4. persisted chainstate snapshots
5. encrypted HD wallets with mnemonic restore
6. integrated JSON-RPC and operator tooling

Its most important current caveats are also clear:

1. proof-of-work identity is fully 512-bit, but transaction and linkage identities are still partially 256-bit
2. the early issuance profile is intentionally much steeper than Bitcoin's historical launch profile
3. side-chain raw block persistence is not yet as mature as a long-running production chain would ultimately want

Those caveats do not erase the value of the system. They define the next engineering steps. As implemented today, CryptEX is best understood as a compact, security-minded, Bitcoin-inspired SHA3-512 network with modernized wallet recovery, practical peer discovery, and a clear path toward a more mature production protocol.
