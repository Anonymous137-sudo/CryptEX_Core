# CryptEX v0.6.3 Release Notes

Public contact: `Anon-Sec-BTCC@proton.me`

These notes describe the CryptEX `v0.6.3` maintenance release as of April 2026. This release focuses on unifying the GUI and CLI mining paths so they operate on one backend chain state, while carrying forward the recent chain-repair, activation, and external-worker hardening work.

## Highlights

- Unified the GUI miner and CLI miner around the live backend RPC session instead of maintaining a separate `gui-miner` blockchain state
- Added RPC-backed mining to `cryptexd mine`, using `getblocktemplate` plus `submitblock` as the single mining control path
- Removed the GUI mined-block replay glue that existed only because of the old split datadir model
- Kept the external SHA3-512 PoW worker architecture intact, including the dedicated ARM64 and x86_64 handwritten assembly workers
- Carried forward the recent fixes for chain repair, activation-path integrity, stale-template rejection diagnostics, and bundled daemon/worker sync

## Unified Mining

- `cryptexd mine` now supports:
  - `--rpc-url`
  - `--rpcuser`
  - `--rpcpassword`
  - `--rpcallowselfsigned`
  - `--rpccacert`
- In RPC-backed mining mode, the miner no longer opens its own `Blockchain` instance
- The miner now fetches candidate blocks from the running backend with `getblocktemplate`
- Found blocks are submitted back through `submitblock` on the same backend that the GUI wallet and dashboard are already using
- The GUI mining page now launches this RPC-backed path by default, using the active backend RPC settings from the desktop client

## Desktop Behavior Changes

- The GUI miner no longer defaults to a dedicated `gui-miner` subdirectory for blockchain state
- The GUI no longer parses `MinedBlockHex` from miner stdout and resubmits it itself
- The old pending mined-block reconciliation flow was removed from the GUI refresh cycle
- Mining status text and hints in the GUI were updated to reflect the new single-backend model

## Chain Integrity and Acceptance

- Preserved the recent active-chain repair behavior for stale and broken local tails
- Preserved the safer activation-path handling so valid candidates are resolved before live active state is mutated
- Preserved the hardened tip-candidate diagnostics used when a PoW worker result is rejected after validation
- Preserved the macOS bundle refresh behavior so the Qt app launches the same daemon and worker binaries that were just rebuilt

## PoW Worker Notes

- ARM64 macOS and Linux builds continue to use dedicated handwritten assembly workers
- Linux x86_64 and Windows x86_64 continue to ship dedicated handwritten assembly workers with AVX2-focused nonce search
- Consensus still remains entirely in the daemon; workers only search nonce ranges and return candidate results

## Packaging and Release Infrastructure

- Updated release metadata to `v0.6.3` across the desktop app, docs, and packaging helpers
- Rebuilt the release assets from the current source tree before tagging
- Regenerated staged release artifacts and SHA-256 checksums for the GitHub release payload

## Upgrade Guidance

- Replace older app bundles with the `v0.6.3` binaries before starting the GUI miner
- Existing legacy `gui-miner` folders from older runs are not auto-deleted, but new GUI mining sessions no longer rely on them
- If you previously depended on standalone local-chain mining behavior, switch to backend-RPC mining so wallet, dashboard, node state, and mining all stay aligned
