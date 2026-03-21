# CryptEX

CryptEX is a C++ SHA3-512 cryptocurrency with full 512-bit proof-of-work math, a separate Qt GUI and backend CLI, encrypted HD wallets, secure chat, JSON-RPC, and multi-network support across mainnet, testnet, and regtest.

## Current Highlights

- SHA3-512 proof of work with full 512-bit consensus math and chainwork
- Mainnet, testnet, and regtest network profiles
- Separate GUI app and backend CLI/node binary
- Base64 address format
- Encrypted `Wallet.dat` storage with BIP32/BIP39 HD wallet support
- Multi-threaded solo mining with sync-before-mining behavior and `--block-cycles`
- P2P networking with peer exchange, DNS seeds, headers-first sync, and longest-chain selection
- JSON-RPC for node, wallet, mining, chat, and operator functions
- Secure public/private chat support
- System datadir defaults so chain and wallet data survive binary deletion

## Repository Layout

- `/src` — core node, wallet, networking, mining, RPC, storage, tests
- `/gui` — Qt desktop client
- `/website` — FastAPI/Jinja website and deployment files
- `/scripts` — build, packaging, and release helpers
- `/toolchains` — cross-compilation toolchain files
- `/build-release` — per-platform build outputs
- `/dist` — exported release artifacts
- `/WHITEPAPER.md` — protocol and implementation whitepaper
- `/RELEASE_NOTES.md` — current release notes

## Build

Native macOS ARM64 backend example:

```bash
cmake -S . -B build-release/macOS-ARM64 -DCMAKE_BUILD_TYPE=Release
cmake --build build-release/macOS-ARM64 --target cryptexd cryptex_tests -j4
```

Full release matrix:

```bash
./scripts/build-release-matrix.sh all
```

## Run

Start the backend node:

```bash
./build-release/macOS-ARM64/cryptexd_osx node
```

Start mining forever:

```bash
./build-release/macOS-ARM64/cryptexd_osx mine --address <your_address> --cycles 0
```

Mine multiple blocks in sequence:

```bash
./build-release/macOS-ARM64/cryptexd_osx mine --address <your_address> --cycles 0 --block-cycles 4
```

Start the GUI:

```bash
open /Users/gitanshchakravarty/Desktop/CryptEX/build-release/macOS-ARM64/cryptexqt_osx.app
```

## Website

The project website is now a real FastAPI application rather than a static HTML page.

Run it locally:

```bash
cd /Users/gitanshchakravarty/Desktop/CryptEX/website
./run.sh
```

By default the website runner now binds to `0.0.0.0:8080`, so other machines on the same network can reach it through:

```bash
http://<your-machine-ip>:8080
```

## Data Locations

By default, CryptEX stores chain and wallet data in system application-data locations:

- macOS: `~/Library/Application Support/CryptEX`
- Linux: `$XDG_DATA_HOME/CryptEX` or `~/.local/share/CryptEX`
- Windows: `%APPDATA%\\CryptEX`

## Documentation

- Whitepaper: [WHITEPAPER.md](./WHITEPAPER.md)
- Release notes: [RELEASE_NOTES.md](./RELEASE_NOTES.md)
