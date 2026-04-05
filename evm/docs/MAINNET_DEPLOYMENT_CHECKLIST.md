# Wrapped CryptEX Mainnet Deployment Checklist

## Before deployment

- choose final token name and symbol
- decide final admin multisig
- decide final minter address
- decide final pauser address
- confirm reserve wallet on native CryptEX chain
- confirm public reserve page path
- run `forge test -vv`
- run `forge build`

## Deployment inputs

Required environment variables:

```sh
export PRIVATE_KEY=0x...
export WRAPPED_CRX_ADMIN=0x...
export WRAPPED_CRX_MINTER=0x...
export WRAPPED_CRX_PAUSER=0x...
export WRAPPED_CRX_NAME="Wrapped CryptEX"
export WRAPPED_CRX_SYMBOL="wCRX"
export RPC_URL=https://...
```

## Deploy

```sh
cd /path/to/CryptEX/evm
forge script script/DeployWrappedCryptEX.s.sol:DeployWrappedCryptEXScript \
  --rpc-url "$RPC_URL" \
  --broadcast
```

## Immediately after deployment

- verify contract source on the explorer
- record contract address in the reserve snapshot
- confirm:
  - total supply is `0`
  - admin is correct
  - minter is correct
  - pauser is correct
- do a tiny internal mint/redeem drill before public announcement

## Before public launch

- website reserve page live
- reserve wallet funded
- bridge operator runbook reviewed
- pause procedure tested
- depositId procedure fixed and documented
- operator logs and reconciliation process in place
