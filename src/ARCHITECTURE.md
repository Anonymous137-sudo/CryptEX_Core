# CryptEX Architecture

## Overview
- CryptEX implements a SHA3-512 Proof-of-Work chain with 10-minute block spacing, a 2,500-coin starting reward, and a declared 1 billion coin monetary cap. The halving interval is `200,000` blocks, which keeps the implemented emission curve aligned with that target.
- The goal is to keep the chain professional grade: binary block storage, strict serialization primitives, AES-protected wallets, Base64 addresses, integrated mining/wallet CLI, and an advanced peer network that mirrors torrent-like discovery.

## Storage & Serialization
- Blocks and transactions must stay binary, using the serialization helpers from `block.hpp`/`serialization.hpp`. Every persisted block file should contain the serialized block payload, prefixed by a magic marker and length to allow fast seek, and be validated by recomputing the Merkle root with `Block::compute_merkle_root`.
- The chain data directory exposes:
  - `blocks/<height>.dat`: serialized block (header + txs). Reader rewinds using `serialization::read_varint`.
  - `chainstate/utxo.db`: flat binary snapshot of the UTXO set (OutPoint, value, script). A Merkle-backed metadata blob allows fast reorg detection.

## Consensus & Rewards
- Block reward logic lives in `Block::get_block_reward`. It halves every `HALVING_INTERVAL_BLOCKS` (`200,000` blocks, about 3.8 years at 10-minute spacing) and caps after 64 halvings. Keep rewards in satoshis (1e8) for precision, and only expose Base64 addresses via `crypto::encode_address`.
- Difficulty uses the current adjustment routine but must run every `DIFFICULTY_ADJUSTMENT_INTERVAL` blocks with `get_next_work_required` (respecting dynamic actual/target timespans).
- The miner computes candidate headers by incrementing the nonce, calling `BlockHeader::hash()` (SHA3-512) until `check_pow()` succeeds. PoW is purely SHA3-512 hashed over the serialized header.

## Wallet & Addresses
- Wallets hold Base64 addresses (20-byte hash), AES-256-CBC encrypted `Wallet.dat`, and expose a CLI to create keys, view balances, and sign transactions. The AES utilities in `aes256.hpp` should wrap OpenSSL EVP with PBKDF2-derived keys (`PBKDF2_ITERATIONS`) and random IVs stored alongside ciphertext.
- Wallet.dat structure:
  ```
  || version (4 bytes) || salt (16) || iv (16) || ciphertext (...)
  ```
  ```
  ciphertext := AES_256_CBC_encrypt(seed material + metadata, derive_key(password, salt))
  ```
- The CLI uses a single binary (`cryptex-client`) with subcommands:
  - `wallet create | import | export`: manage keys and addresses.
  - `wallet balance <address>`: query UTXO set via RPC.
  - `mine start`: start PoW worker that submits to the built-in GetWork server.
  - `chat public|private`: connect to chat channels over the P2P overlay.

## Networking
- All P2P networking uses a single-header `asio.hpp` to keep dependencies simple. The overlay exposes:
  - TCP handshake that exchanges `VersionMessage` (protocol version, height, base64 peer ID).
  - Direct IP lookup via an IP detection service (HTTP GET `https://ipdetect.example/api/self`) to find the node's IPv4, which is then serialized as `NetAddr := [4 bytes IP][2 bytes port][1 byte flags]`.
  - A peer table with serialized entries sorted by reachability; entries are exchanged using `SerializePeerTable(peer_list)` and update in real time whenever a connection drops or a new peer is discovered (botched peers are evicted after 2 minutes).
  - Block requests use `GetBlock(hash)`/`Block` exchange similar to Bitcoin but without hardcoded seeds (use persistent peer table and manual entry). A peer discovery thread polls the IP detection service every 5 minutes and cross-checks with DNS-less rendezvous.
  - Chat is layered above the block sync channel:
    * Public chat: broadcast `ChatMessage { type=Public, channel, payload }`.
    * Private chat: encrypt payload with the recipient's public identity, send as `ChatMessage { type=Private, recipient_id, payload }`.
  - GetWork server: exposes `GetWorkRequest`/`GetWorkResponse` to miners. Each worker pulls the latest header template and nonce range (10k nonce per request) for p2pool-style decentralized mining.

## Mining & GetWork
- The GetWork protocol sits on top of the CLI miner. The server keeps:
  - `latest_header`: refreshed whenever mempool or best block changes.
  - `target_bits`: computed via `get_next_work_required`.
  - Nonce assignment logic (tracking ranges of 2^24 nonces per worker) so distributed workers can operate without central coordination.
- Workers submit solutions `SubmitWork(nonce, extra)`; the server validates by recomputing the header hash and, if valid, broadcasts the new block.
- Mining threads poll the mempool for transactions (respecting `MAX_TRANSACTIONS_PER_BLOCK`), build coinbase transactions paying up to `MAX_BLOCK_SIZE_BYTES`, compute the merkle root, and send `MinedBlock` over the P2P network.

## Peer Routing & Failure Recovery
- Nodes maintain a `PeerTable` of serialized IP/port tuples; every entry is exactly 7 bytes (`4-byte IP`, `2-byte port`, `1-byte flags`). The table is rotated every 20 seconds, and the `flags` byte encodes reachability, chat support, and last-success timestamp (encoded as a bucket index). When a peer disconnects, the node immediately requests an updated table broadcast from remaining peers, similar to BitTorrent’s distributed tracker updates.
- Peer discovery avoids seeds by combining:
  1. Configurable static peer file `peers.dat`.
  2. IP detection service for external connectivity checks.
  3. Optional rendezvous nodes (run by operators) publishing new peers via `NetTable` messages.

## Block Sync & Binary Storage
- Synchronization uses a two-stage handshake:
  - Send `GetHeaders(start_height)`; receive `Headers{list}`.
  - For each unknown header, send `GetBlock(hash)` and store the binary payload file.
- Blocks remain binary, but `HeaderDatabase` stores metadata indexed by height/hash for quick lookup.
- When syncing, nodes compare the tip hashes and request the missing segment; each request is hashed to avoid replay.

## CLI + Chat Experience
- `cryptex-client` uses commands for mining, wallet, and chat. Example usage:
  ```
  cryptex-client --datadir ~/CryptEX wallet create --name Alice
  cryptex-client --datadir ~/CryptEX mine start --threads 4
  cryptex-client chat public --channel dev --message "Block 12342 confirmed"
  cryptex-client chat private --peer <recipient-address> --recipient-pubkey <base64-pubkey> --message "<encrypted text>"
  ```
- Chat messages embed authenticated timestamps and nonces to resist replay. Public messages are signed by the sender wallet key, while private messages are signed and encrypted with an ECDH-derived AES-256-GCM session key bound to the recipient public key.

## Next Steps
1. Wire the AES wallet helpers into `Wallet.dat` read/write routines and expose CLI primitives for key creation and secure storage.
2. Implement the `PeerTable`, `GetWork`, `BlockFetcher`, and chat servers within a single Asio-based event loop that handles peer discovery, block syncing, and message routing.
3. Build a `cryptex-client` binary that links the wallet, miner, and chat modules together, using the serialization helpers and constants already defined for consensus.

## Cross-compiling from macOS
- **Windows**: install `mingw-w64` (`brew install mingw-w64`), then `cmake -S . -B build-win -DCMAKE_TOOLCHAIN_FILE=toolchains/mingw-w64.cmake -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=/path/to/windows/openssl`. Boost is header-only here; OpenSSL must be a Windows build (vcpkg or custom static).
- **Linux**: supply a Linux sysroot with glibc/headers/OpenSSL, export `LINUX_SYSROOT=/path/to/sysroot`, then `cmake -S . -B build-linux -DCMAKE_TOOLCHAIN_FILE=toolchains/linux-clang.cmake -DCMAKE_BUILD_TYPE=Release`.
