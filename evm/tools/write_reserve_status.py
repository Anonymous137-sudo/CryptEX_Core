#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a manual reserve snapshot for the CryptEX website.")
    parser.add_argument("--output", type=Path, required=True, help="Path to reserve_status.json")
    parser.add_argument("--wrapped-contract-address", default="", help="Wrapped token contract address")
    parser.add_argument("--reserve-wallet-address", default="", help="Native CryptEX reserve wallet address")
    parser.add_argument("--evm-chain-name", default="Ethereum Mainnet")
    parser.add_argument("--evm-chain-id", type=int, default=1)
    parser.add_argument("--explorer-url", default="")
    parser.add_argument("--operator-mode", default="manual-custodial")
    parser.add_argument("--status", default="live")
    parser.add_argument("--native-locked-sats", type=int, required=True)
    parser.add_argument("--wrapped-supply-wei", type=int, required=True)
    parser.add_argument("--notes", default="")
    parser.add_argument("--last-reconciled-at", default="", help="ISO8601 timestamp. Defaults to now UTC.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "wrapped_contract_address": args.wrapped_contract_address,
        "reserve_wallet_address": args.reserve_wallet_address,
        "evm_chain_name": args.evm_chain_name,
        "evm_chain_id": args.evm_chain_id,
        "explorer_url": args.explorer_url,
        "operator_mode": args.operator_mode,
        "status": args.status,
        "native_locked_sats": args.native_locked_sats,
        "wrapped_supply_wei": args.wrapped_supply_wei,
        "last_reconciled_at": args.last_reconciled_at or datetime.now(timezone.utc).isoformat(),
        "notes": args.notes,
    }
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
