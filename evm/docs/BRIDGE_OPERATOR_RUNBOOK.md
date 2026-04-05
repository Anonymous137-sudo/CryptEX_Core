# Wrapped CryptEX Bridge Operator Runbook

This is the first-stage custodial bridge workflow for `wCRX`.

The operator can still run it manually, but the recommended path now is to use:
- `/path/to/CryptEX/evm/bridge/bridge_daemon.py`

That daemon can:
- watch native deposits
- submit EVM mints
- watch EVM redemptions
- update the public reserve snapshot

## Core rule

`totalSupply(wCRX) <= locked native CRX reserve`

Never mint first and hope to reconcile later.

## Native CRX -> wCRX

1. User sends native CRX to the reserve address on the CryptEX chain.
2. Operator verifies:
   - transaction is confirmed on the approved chain
   - amount is correct
   - reserve actually controls the destination output
3. Operator computes a deterministic `depositId`.
4. Operator mints `wCRX` on Ethereum using `mintFromBridge(...)`.
5. Operator updates the reserve snapshot file for the website.

### Computing `depositId`

Use the helper:

```sh
/path/to/CryptEX/evm/tools/compute_bridge_deposit_id.sh \
  <native_txid_bytes32> \
  <output_index_uint32> \
  <recipient_evm_address> \
  <amount_sats>
```

Recommended input rule:
- `nativeTxId`
- native output index
- EVM recipient
- native amount in satoshis

That gives you an idempotent mint key.

### Minting on EVM

Example with `cast`:

```sh
cast send <WRAPPED_CRX_ADDRESS> \
  "mintFromBridge(address,uint256,bytes32,bytes32,string)" \
  <RECIPIENT_EVM_ADDRESS> \
  <AMOUNT_WEI> \
  <DEPOSIT_ID> \
  <NATIVE_TXID_BYTES32> \
  "<NATIVE_SENDER_REFERENCE>" \
  --private-key $PRIVATE_KEY \
  --rpc-url $RPC_URL
```

## wCRX -> native CRX

1. User calls:
   - `requestRedemption(amount, nativeDestination)`
   - or `requestRedemptionFrom(...)`
2. Contract burns the wrapped amount.
3. Contract emits `RedemptionRequested(...)`.
4. Operator verifies the event and amount.
5. Operator releases the matching native CRX from reserve.
6. Operator updates the reserve snapshot file.

## Reserve transparency update

Update the website snapshot:

```sh
python3 /path/to/CryptEX/evm/tools/write_reserve_status.py \
  --output /path/to/CryptEX/website/data/reserve_status.json \
  --wrapped-contract-address <WRAPPED_CRX_ADDRESS> \
  --reserve-wallet-address <CRYPTEX_RESERVE_ADDRESS> \
  --evm-chain-name "Ethereum Mainnet" \
  --evm-chain-id 1 \
  --explorer-url "https://etherscan.io/token/<WRAPPED_CRX_ADDRESS>" \
  --native-locked-sats <LOCKED_SATS> \
  --wrapped-supply-wei <WRAPPED_SUPPLY_WEI> \
  --notes "manual reconciliation after mint batch"
```

## Operational safety

- admin should be a multisig
- minter should be a separate operator or multisig
- pauser should be a security key or multisig
- pause first if reserve accounting ever becomes uncertain
- do not reuse `depositId`
- do not process redemptions from stale or unapproved chain data
