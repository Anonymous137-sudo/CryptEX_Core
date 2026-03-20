# CryptEX

CryptEX is a C++ cryptocurrency node and miner focused on SHA3-512 proof of work, a CLI-first workflow, P2P networking, wallet support, secure chat, JSON-RPC, and multi-network development modes.

## Current Highlights

- SHA3-512 proof of work with full 512-bit consensus math
- Mainnet, testnet, and regtest network profiles
- Base64 address format
- Encrypted wallet storage with HD wallet support
- Solo mining with multi-threaded CPU mining
- P2P networking with peer exchange, sync, and longest-chain selection
- JSON-RPC server for node, wallet, mining, and chat operations
- Secure public/private chat support

## Repository Layout

- `/src` — core node, wallet, networking, mining, RPC, tests
- `/scripts` — build/release helper scripts
- `/toolchains` — cross-compilation toolchain files
- `/WHITEPAPER.md` — protocol and implementation whitepaper
- `/GUI_MODE_PLAN.md` — roadmap for GUI mode

## Build

Native macOS ARM64 example:

```bash
cmake -S . -B build-release/macOS-ARM64 -DCMAKE_BUILD_TYPE=Release
cmake --build build-release/macOS-ARM64 --target cryptexd cryptex_tests -j4
```

Release matrix helper:

```bash
./scripts/build-release-matrix.sh all
```

## Run

Start a node:

```bash
./build-release/macOS-ARM64/cryptexd_osx node
```

Start mining:

```bash
./build-release/macOS-ARM64/cryptexd_osx mine --address <your_address> --cycles 0
```

Mine multiple blocks in sequence:

```bash
./build-release/macOS-ARM64/cryptexd_osx mine --address <your_address> --cycles 0 --block-cycles 4
```

## Documentation

- Whitepaper: [WHITEPAPER.md](./WHITEPAPER.md)
- GUI roadmap: [GUI_MODE_PLAN.md](./GUI_MODE_PLAN.md)
