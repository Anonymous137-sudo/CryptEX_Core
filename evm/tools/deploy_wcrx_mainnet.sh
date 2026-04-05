#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v forge >/dev/null 2>&1; then
  echo "forge not found. Install Foundry first." >&2
  exit 1
fi

if ! command -v cast >/dev/null 2>&1; then
  echo "cast not found. Install Foundry first." >&2
  exit 1
fi

if [[ -z "${PRIVATE_KEY:-}" ]]; then
  echo "PRIVATE_KEY is required." >&2
  exit 1
fi

if [[ -z "${RPC_URL:-}" ]]; then
  echo "RPC_URL is required." >&2
  exit 1
fi

DEPLOYER_ADDRESS="$(cast wallet address --private-key "$PRIVATE_KEY")"
export WRAPPED_CRX_ADMIN="${WRAPPED_CRX_ADMIN:-$DEPLOYER_ADDRESS}"
export WRAPPED_CRX_MINTER="${WRAPPED_CRX_MINTER:-$DEPLOYER_ADDRESS}"
export WRAPPED_CRX_PAUSER="${WRAPPED_CRX_PAUSER:-$DEPLOYER_ADDRESS}"
export WRAPPED_CRX_NAME="${WRAPPED_CRX_NAME:-Wrapped CryptEX}"
export WRAPPED_CRX_SYMBOL="${WRAPPED_CRX_SYMBOL:-wCRX}"

cd "$ROOT"

echo "Deployer: $DEPLOYER_ADDRESS"
echo "Admin:    $WRAPPED_CRX_ADMIN"
echo "Minter:   $WRAPPED_CRX_MINTER"
echo "Pauser:   $WRAPPED_CRX_PAUSER"
echo "Name:     $WRAPPED_CRX_NAME"
echo "Symbol:   $WRAPPED_CRX_SYMBOL"
echo

echo "Running build and tests before broadcast..."
forge build
forge test -vv

echo
echo "Broadcasting deployment..."
forge script script/DeployWrappedCryptEX.s.sol:DeployWrappedCryptEXScript \
  --rpc-url "$RPC_URL" \
  --broadcast
