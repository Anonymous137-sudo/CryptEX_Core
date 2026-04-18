# CryptEX v0.6.2 Release Notes

Public contact: `Anon-Sec-BTCC@proton.me`

These notes describe the CryptEX v0.6.2 maintenance release as of April 2026. This release focuses on consensus hardening, miner/backend correctness, chain repair, and desktop startup stability after the broader v0.6.0 feature wave.

## Highlights

- Hardened compact-target handling with canonical `bits` validation, overflow/sign-bit checks, and documented SHA3-512 target rules
- Reduced difficulty oscillation by preventing emergency min-difficulty rescue blocks from poisoning later LWMA/EMA retarget history
- Repaired invalid active-chain tails automatically on startup for both `bits` and `missing-block` failures
- Tightened mining acceptance so PoW success is separated cleanly from consensus acceptance and stale replay blocks do not loop forever in the GUI
- Added dedicated handwritten x86_64 external assembly PoW workers for Linux and Windows with AVX2-focused four-lane nonce search
- Improved desktop/backend startup behavior when ports are busy, checkpoints are stale, or RPC comes up before peer approval does

## Consensus and Difficulty

- Added compact-target round-trip validation (`bits -> target -> bits`) and canonical encoding enforcement at consensus boundaries
- Rejected malformed compact targets with sign-bit misuse, zero targets, or 512-bit overflow conditions
- Documented proof-of-work header serialization, target expansion, and comparison rules in `docs/pow.md`
- Adjusted the hybrid difficulty controller so emergency low-difficulty rescue blocks do not destabilize follow-on retargets
- Restored post-recovery difficulty from the last stable non-emergency target rather than letting rescue blocks drag the network back toward `pow_limit`

## Chain Repair and Datadir Recovery

- Added automatic repair for stale checkpoints that pinned chains beyond the real valid tip
- Broadened startup repair so invalid active tails caused by missing canonical blocks are truncated back to the last valid prefix
- Pruned stale canonical height files after repair so broken tails do not silently reappear
- Cleaned up rejected contextual candidates from hash-addressed storage instead of leaving them behind in by-hash caches

## Mining and Backend

- Confirmed the ARM64 assembly PoW worker against the C++ reference path and fixed the only mismatch found: bounded no-hit iteration accounting
- Added self-contained dedicated x86_64 `.S` worker sources for Linux and Windows instead of the earlier mixed include/C++ fallback path
- Validated the Linux x86_64 worker against SHA3-512 reference jobs across randomized worker-protocol cases
- Ensured the GUI bundle is refreshed with the current daemon and PoW worker during release builds so the app does not launch stale binaries
- Prevented replayed stale mined blocks from being retried indefinitely after the backend rejects them
- Exempted localhost RPC traffic from generic rate limiting so local mined-block reconciliation does not self-throttle
- Completed the external PoW worker protocol on non-ARM platforms so Linux x86_64 and Windows x86_64 builds ship dedicated worker binaries that the daemon can launch directly

## Desktop and Wallet Behavior

- Reworked startup bootstrap handling so backend launch failures surface as failures instead of endless “starting” loops
- Improved bind-conflict handling so the GUI stops retrying aggressively when another process already owns the RPC or P2P port
- Preserved the distinction between “locally caught up” and approval-gated wallet state more consistently during recovery scenarios
- Improved mining and backend log clarity around rejected candidates and repair reasons

## Packaging and Release Infrastructure

- Updated release metadata to `v0.6.2` across the desktop app, docs, and packaging helpers
- Refreshed macOS ARM64 release assets from the current source tree
- Added Linux x86_64, Linux ARM64, and Windows x86_64 release artifacts to the build matrix
- Added a reproducible Windows x86_64 dependency bootstrap path for the MinGW OpenSSL and Opus prefixes used by the release build

## Known Notes

- Public IP autodetect may still emit warning noise on networks where the HTTPS lookup endpoints are blocked or truncated
- Wallet balances remain approval-gated when the node has not established enough confidence in chain state; this release improves recovery behavior but does not remove the approval model

## Upgrade Guidance

- Replace older app bundles with the v0.6.2 binaries before starting the GUI miner
- If you previously mined on a stale or partially corrupted local chain, allow the backend to complete its startup repair once before judging final chain height
- If a very old mined-block backlog exists, v0.6.2 will reconcile and discard stale rejected entries instead of replaying them forever
