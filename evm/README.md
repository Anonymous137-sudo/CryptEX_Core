## Wrapped CryptEX EVM Workspace

This directory contains the professional-grade EVM contract workspace for the
wrapped CryptEX asset.

Current primary contract:
- `WrappedCryptEX.sol`

Default deployment identity:
- name: `Wrapped CryptEX`
- symbol: `wCRX`
- decimals: `18`
- initial supply: `0`

Core behavior:
- capped to the native CryptEX maximum supply: `1,000,000,000`
- enforces exact native-to-EVM unit conversion (`1 sat = 10^10 wei`)
- role-gated bridge minting
- explicit redemption burns for native-chain release workflows
- emergency pause
- EIP-2612 permit support
- default-admin transfer delay through OpenZeppelin `AccessControlDefaultAdminRules`

## Why this contract exists

This token is intended to be the wrapped visibility and liquidity layer for
native CRX on an EVM chain. It is not supposed to mint arbitrary supply.

Bridge policy:
- `totalSupply(wCRX) <= locked native CRX reserve`
- every bridge mint should reference a unique native deposit
- every redemption burns on EVM and emits a destination event for native payout

## Tooling

This workspace uses Foundry.

Useful commands:

```sh
cd /path/to/CryptEX/evm
forge build
forge test
forge fmt
```

Operator helpers:

```sh
/path/to/CryptEX/evm/tools/compute_bridge_deposit_id.sh <native_txid> <vout> <recipient> <amount_sats>
python3 /path/to/CryptEX/evm/tools/write_reserve_status.py --help
python3 /path/to/CryptEX/evm/bridge/bridge_daemon.py --config /path/to/CryptEX/evm/config/bridge_config.example.json --once
```

## Contract overview

### `WrappedCryptEX`

Roles:
- `DEFAULT_ADMIN_ROLE`
- `MINTER_ROLE`
- `PAUSER_ROLE`

Operational functions:
- `mintFromBridge(...)`
- `requestRedemption(...)`
- `requestRedemptionFrom(...)`
- `pause()`
- `unpause()`

Safety features:
- duplicate deposit protection through `depositId`
- hard max supply cap
- no public minting
- no generic rescue of wrapped token supply

## Recommended operational setup

For mainnet deployment, do not use one hot wallet for everything.

Recommended separation:
- admin: multisig
- minter: bridge operator or bridge service multisig
- pauser: security multisig

## Deployment

Set environment variables:

```sh
export PRIVATE_KEY=0x...
export WRAPPED_CRX_ADMIN=0x...
export WRAPPED_CRX_MINTER=0x...
export WRAPPED_CRX_PAUSER=0x...
export WRAPPED_CRX_NAME="Wrapped CryptEX"
export WRAPPED_CRX_SYMBOL="wCRX"
```

Then run:

```sh
cd /path/to/CryptEX/evm
forge script script/DeployWrappedCryptEX.s.sol:DeployWrappedCryptEXScript \
  --rpc-url "$RPC_URL" \
  --broadcast \
  --verify
```

## Additional docs

- bridge operator workflow:
  - `/path/to/CryptEX/evm/docs/BRIDGE_OPERATOR_RUNBOOK.md`
- automated bridge daemon:
  - `/path/to/CryptEX/evm/docs/AUTOMATED_BRIDGE.md`
- daemon service examples:
  - `/path/to/CryptEX/evm/deploy/com.cryptex.bridge-daemon.plist.example`
  - `/path/to/CryptEX/evm/deploy/cryptex-bridge.service.example`
- mainnet checklist:
  - `/path/to/CryptEX/evm/docs/MAINNET_DEPLOYMENT_CHECKLIST.md`

## Bridge note

The current contract is designed for a first-stage custodial bridge.

Recommended deposit ID rule:
- compute `depositId = keccak256(nativeTxId || outputIndex || recipient || amount)`

That keeps bridge mints idempotent and auditable.
