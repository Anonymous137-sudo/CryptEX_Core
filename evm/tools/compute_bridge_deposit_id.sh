#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <native_txid_bytes32> <output_index_uint32> <recipient_evm_address> <amount_sats>" >&2
  echo "example: $0 0xabc123... 0 0x1234... 5000000000" >&2
  exit 1
fi

if ! command -v cast >/dev/null 2>&1; then
  echo "cast not found. Install Foundry first." >&2
  exit 1
fi

native_txid="$1"
output_index="$2"
recipient="$3"
amount_sats="$4"

encoded="$(cast abi-encode "f(bytes32,uint32,address,uint256)" "$native_txid" "$output_index" "$recipient" "$amount_sats")"
cast keccak "$encoded"
