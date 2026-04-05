# Automated Wrapped CryptEX Bridge

This daemon reduces the manual workload around the first-stage custodial bridge.

It automates four things:
- watching the native CryptEX reserve address for confirmed deposits
- minting `wCRX` on the EVM side for valid deposits
- watching EVM redemption events
- refreshing the public reserve snapshot used by the website

By default it does **not** auto-release native CRX on redemption. That stays operator-reviewed until you explicitly enable it.

## Deposit format

A native deposit must:
- send CRX to the reserve address
- include an `OP_RETURN` memo in this format:

```text
EVM:0x1234...abcd
```

That memo tells the daemon which EVM address should receive `wCRX`.

## Safety defaults

- `auto_mint = true`
- `auto_release_redemptions = false`
- duplicate EVM minting is blocked by `depositId`
- mint amounts and redemption amounts must map exactly between native 8 decimals and EVM 18 decimals
- reserve status is rewritten every cycle for website transparency

## Configure it

Start from:
- `/path/to/CryptEX/evm/config/bridge_config.example.json`

Set these carefully:
- native reserve address
- native RPC credentials
- EVM RPC URL
- deployed `wCRX` contract address
- `CRYPTEX_BRIDGE_EVM_PRIVATE_KEY` environment variable

Optional:
- set `auto_release_redemptions` to `true` only after the reserve wallet flow is proven and the native node is running with the reserve wallet loaded.

## Run one cycle

```sh
export CRYPTEX_BRIDGE_NATIVE_RPC_PASSWORD='your_native_rpc_password'
export CRYPTEX_BRIDGE_EVM_PRIVATE_KEY='0xYOUR_EVM_MINTER_KEY'

python3 /path/to/CryptEX/evm/bridge/bridge_daemon.py \
  --config /path/to/CryptEX/evm/config/bridge_config.example.json \
  --once
```

## Run continuously

```sh
export CRYPTEX_BRIDGE_NATIVE_RPC_PASSWORD='your_native_rpc_password'
export CRYPTEX_BRIDGE_EVM_PRIVATE_KEY='0xYOUR_EVM_MINTER_KEY'

python3 /path/to/CryptEX/evm/bridge/bridge_daemon.py \
  --config /path/to/CryptEX/evm/config/bridge_config.example.json
```

## Run it as a service

Examples are included for both desktop and server setups:
- macOS `launchd`:
  - `/path/to/CryptEX/evm/deploy/com.cryptex.bridge-daemon.plist.example`
- Linux `systemd`:
  - `/path/to/CryptEX/evm/deploy/cryptex-bridge.service.example`

## Files it maintains

- state file:
  - `/path/to/CryptEX/evm/data/bridge_state.runtime.json`
- reserve website snapshot:
  - `/path/to/CryptEX/website/data/reserve_status.json`

## Operational notes

- `totalSupply(wCRX)` must never exceed locked native CRX backing.
- The daemon uses the reserve address balance as the native locked reserve view.
- If you ever lose confidence in reserve accounting, pause the EVM contract before doing anything else.
