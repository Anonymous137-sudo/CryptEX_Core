# CryptEX PoW Rules

This document defines the proof-of-work target and validation rules used by CryptEX consensus.

## Header Hash

The proof-of-work hash is the full 64-byte SHA3-512 digest of the serialized block header.

Header serialization is exactly:

1. `version` as little-endian `int32`
2. `prev_block_hash` as 32 raw bytes
3. `merkle_root` as 32 raw bytes
4. `timestamp` as little-endian `uint32`
5. `bits` as little-endian `uint32`
6. `nonce` as little-endian `uint32`

The resulting 80-byte header is hashed once:

```text
pow_hash = SHA3-512(header80)
```

Consensus compares the hash and target as unsigned big-endian 512-bit integers:

```text
valid iff pow_hash <= target(bits)
```

## Compact Target Encoding

`bits` uses a Bitcoin-style compact target encoding:

- `exponent = bits >> 24`
- `mantissa = bits & 0x007fffff`
- `0x00800000` is the sign bit and must not be set for a valid PoW target

Expansion rules:

```text
if exponent <= 3:
    target = mantissa >> (8 * (3 - exponent))
else:
    target = mantissa << (8 * (exponent - 3))
```

Canonical encoding rules:

1. sign bit must be clear
2. mantissa must be non-zero
3. encoding must not overflow the 64-byte SHA3-512 target width
4. `bits -> target -> bits` must round-trip exactly

Malformed or non-canonical `bits` values are rejected by consensus.

## Pow Limit

The mainnet maximum target is defined by:

```text
pow_limit_bits = 0x3e00ffff
```

Expanded to 64 bytes:

```text
000000ffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Targets larger than `pow_limit` are invalid.

## Difficulty Retarget

CryptEX adjusts difficulty per block using a weighted moving average over recent solve times and targets.

Constants:

- target block time: `600` seconds
- LWMA window: `72` blocks

Core calculation:

```text
average_target = sum(target_i * weight_i) / sum(weight_i)
next_target = average_target * weighted_solvetime / (600 * sum(weight_i))
```

Then:

1. damp toward the average target
2. clamp per-step movement to `[average_target / 2, average_target * 2]`
3. optionally apply EMA-based easing
4. optionally apply a realtime slowdown floor
5. clamp to `pow_limit`
6. re-encode with canonical compact encoding

## Worker Backends

Every release platform ships an external `cryptex_powminer` worker binary, but the worker backend differs by platform:

- macOS ARM64: dedicated handwritten ARM64 assembly worker in `src/asm/powminer_darwin_arm64.S`
- Linux ARM64: dedicated handwritten ARM64 assembly worker in `src/asm/powminer_linux_arm64.S`
- Linux x86_64: external C++ worker in `src/powminer_main.cpp`, using the same file-based worker protocol and the platform OpenSSL SHA3 backend
- Windows x86_64: external C++ worker in `src/powminer_main.cpp`, packaged with the same file-based worker protocol and a MinGW/OpenSSL toolchain

## Implementation Notes

- The daemon computes the canonical target from `bits` and passes that target to the external PoW worker.
- The worker does not define independent consensus rules.
- Any alternate implementation must preserve:
  - exact header byte layout
  - SHA3-512 variant
  - big-endian numeric comparison
  - canonical compact-target encoding
