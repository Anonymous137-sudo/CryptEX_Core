# CryptEX v0.5.3 Release Notes

These notes describe the CryptEX v0.5.3 release as of April 2026. The project now spans the native chain, desktop GUI, wallet and RPC stack, networking and sync infrastructure, website, and the wrapped-asset EVM workspace.

## Featured Changes

- Full **SHA3-512 proof of work** with **512-bit target math** and cumulative-work chain selection
- Separate **Qt GUI** and **backend daemon** with a wallet-first desktop flow and a dedicated node window
- Hybrid adaptive difficulty controller combining **LWMA**, **EMA**, **real-time overdue easing**, and **emergency minimum-difficulty recovery**
- Expanded wallet system with encrypted storage, HD support, recovery tooling, multiple address encodings, and wallet management RPCs
- Stronger network stack with peer persistence, bans, DNS bootstrap, **LAN/WLAN auto-discovery**, peer activity controls, and sync-aware mining
- FastAPI-based website with live downloads, reserve-status surfacing, and deployment configs
- EVM workspace for **Wrapped CryptEX (`wCRX`)** plus bridge automation and reserve reporting tooling

## Core Protocol and Consensus

- Native **mainnet**, **testnet**, and **regtest** profiles
- Full-width SHA3-512 proof-of-work validation
- 512-bit target expansion and chainwork accounting
- Genesis baked into network parameters for deterministic startup
- Cumulative-work chain selection rather than height-only chain choice
- Conservative fork handling with local path reconstruction and revalidation before activation
- Local approval and reorg-safety logic for stronger full-node behavior during sync and competing-chain observations

## Difficulty and Liveness

- Adaptive retargeting now uses a hybrid controller instead of a slow legacy-only retarget model
- Current controller components:
  - damped LWMA-style estimator
  - EMA smoothing term
  - real-time overdue easing
  - emergency minimum-difficulty fallback after clear stall conditions
- Timestamp sanity checks and bounded solve-time behavior help reduce timestamp-based retarget abuse
- The chain is explicitly tuned to recover when a strong miner leaves and only low hash-rate miners remain

## Wallets and Addresses

- Encrypted `Wallet.dat` storage
- BIP32 HD derivation
- BIP39 mnemonic generation and restore
- Safer wallet persistence through temp-file write and backup rotation
- Recovery path from backup copies via wallet recovery tooling
- Wallet manager support in the GUI
- Wallet session handling decoupled from node-startup settings
- Legacy root `Wallet.dat` discovery now works alongside managed wallet paths

Supported address encodings now include:

- Base64
- Base58
- `0x` + hex
- Bech32

The current implementation treats these as multiple encodings over the same underlying address payload while preserving native Base64 compatibility for existing CryptEX wallets.

## Wallet RPC and Maintenance

Current wallet-facing RPC coverage includes:

- `getnewaddress`
- `getunusedaddress`
- `listwallets`
- `createwallet`
- `openwallet`
- `closewallet`
- `deletewallet`
- `setwalletformat`
- `dumpmnemonic`
- `dumpprivkey`
- `importprivkey`
- `importmnemonic`
- `backupwallet`
- `recoverwallet`
- `walletpassphrasechange`
- `rescanwallet`

Additional wallet behavior updates:

- better immature / spendable / locked / total balance reporting
- corrected coinbase maturity boundary handling
- improved GUI balance and wallet-state refresh behavior
- better wallet-password prompting and restart handling in the desktop client

## GUI and Desktop Client

The Qt client is now a serious desktop surface rather than a thin wrapper over CLI functionality.

Main user tabs:

- Overview
- Send
- Receive
- Transactions

Advanced functionality is moved into a separate **Node Window**, including:

- information
- wallet manager
- wallet tools
- console
- system log
- terminal
- miner output
- network tools
- chat
- settings

Desktop improvements include:

- wallet-first layout inspired by Bitcoin Core structure
- startup splash and sync-details behavior
- bottom sync / peer / network activity indicators
- explicit node controls separated from ordinary wallet use
- address-format chooser dialogs
- improved wallet table stability and reduced refresh churn
- refresh-on-open behavior instead of heavy background refresh loops

## Networking and Synchronization

- Boost.Asio-based TCP peer-to-peer transport
- Peer persistence through `peers.dat`
- Peer reputation and ban persistence through `peer_state.dat`
- Headers-first synchronization with bounded parallel block downloads
- DNS bootstrap support
- Peer exchange through protocol messages
- Direct peer connection support
- LAN/WLAN auto-discovery for same-network nodes
- Optional SOCKS5/Tor outbound proxy support
- Optional external IP discovery and self-advertisement

Additional sync/network changes:

- better sync status reporting through RPC and GUI
- explicit network activity enable/disable control
- improved separation of backend-unreachable vs RPC-auth-failure states
- safer async outbound connect behavior to reduce startup stalls
- peer maintenance and reconnection logic hardened for long-running nodes

## Mining

- Multi-threaded CPU mining
- Sync-before-mining behavior when peers are present
- Continuous or bounded nonce-cycle mining
- Chained multi-block mining via `--block-cycles`
- `GETWORK` support
- `getblocktemplate` support
- Dedicated miner-output tooling in the GUI node window

The current mining and retarget path is designed to preserve liveness under unstable network hash-rate rather than assuming a large, steady industrial mining base.

## RPC and Operator Surface

- JSON-RPC for blockchain, wallet, networking, mempool, mining, and chat operations
- Strict JSON parsing and parameter type enforcement
- Allowlist support
- Request-size limits
- Per-IP RPC rate limiting
- `setnetworkactive` support for runtime network control
- Better peer, sync, and approval telemetry through RPC
- Structured logging and config-file support

## Secure Chat

CryptEX includes a non-consensus authenticated messaging layer between nodes.

Current chat support includes:

- signed public chat
- encrypted private chat
- inbox/history retrieval
- peer-routed delivery

Private chat currently uses an ECDH-derived AES-256-GCM session flow bound to recipient key material.

## Storage and Persistence

- Binary block storage by height
- Header and block-index persistence
- Chainstate snapshots
- Hash-addressed known-block persistence improvements for side-branch continuity
- Wallet backup rotation and recovery-aware save paths
- System datadir defaults on macOS, Linux, and Windows so chain and wallet state survive binary replacement or deletion

## Website and Release Infrastructure

The repository now includes a real web stack rather than a placeholder landing page.

Current website features:

- FastAPI backend
- Jinja templates
- home / downloads / technology / network / explorer / reserve / security / roadmap pages
- deployment examples for Caddy, nginx, and systemd
- release-directory surfacing on the downloads page
- reserve-status JSON and public reserve page integration

Release engineering additions include:

- cross-platform build matrix helpers
- Linux AppImage packaging
- Windows runtime packaging
- whitepaper PDF generation tooling

## EVM and Bridge Workspace

The repository now contains a dedicated `evm/` workspace for Wrapped CryptEX.

Current EVM implementation includes:

- `WrappedCryptEX.sol`
- `wCRX` deployment script
- Foundry configuration and tests
- operator runbooks
- automated bridge daemon
- reserve snapshot tooling
- deployment helper scripts

Bridge-related operational assets include:

- reserve-status publication
- deposit ID helper tooling
- example macOS and Linux service definitions
- mainnet deployment checklist and bridge operator runbook

## Platform Outputs

Current repository packaging targets include:

- macOS ARM64
- Linux x86_64
- Linux ARM64
- Windows x86_64

Release artifacts in this flow include:

- backend daemon binaries
- GUI applications
- test binaries
- Linux AppImages
- Windows runtime bundle
- whitepaper PDF

## Documentation

Current top-level documentation surfaces:

- Whitepaper PDF: `WHITEPAPER.pdf`
- Whitepaper source: `archives/CryptEX_Whitepaper_Source_April_2026.md`
- Release notes: `RELEASE_NOTES.md`

## Known Boundaries and Active Work

The current implementation is substantial, but a few areas are still improving:

- side-branch persistence and archival completeness are improving relative to long-lived production networks
- some wallet cryptography code paths still emit OpenSSL deprecation warnings on newer toolchains
- RPC transport is authenticated HTTP, not TLS-secured remote transport
- the EVM bridge stack is present and documented, but operational rollout still depends on reserve management and deployment policy
- the project has broad regression coverage, but continued hardening and cleanup remain active engineering work

## Suggested GitHub Release Title

`CryptEX Current Release`

## Suggested Short GitHub Release Summary

Current CryptEX release with 512-bit SHA3 proof of work, hybrid adaptive difficulty control, separate GUI and daemon, expanded wallet and RPC tooling, LAN-aware networking, website and release infrastructure, and a full Wrapped CryptEX EVM workspace.
