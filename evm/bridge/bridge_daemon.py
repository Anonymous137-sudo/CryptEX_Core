#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BRIDGE_UNIT_WEI = 10_000_000_000
REDEMPTION_REQUESTED_TOPIC0 = "0x481c6f6c5619b8b3c685ace71e6256ac5a45feb7d2d92341ef124b8974a61ee0"
EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


class BridgeError(RuntimeError):
    pass


@dataclass
class NativeConfig:
    rpc_url: str
    rpc_user: str
    rpc_password: str
    reserve_address: str
    deposit_confirmations: int
    release_confirmations: int
    scan_limit: int


@dataclass
class EvmConfig:
    rpc_url: str
    wrapped_contract_address: str
    minter_private_key: str
    confirmations: int
    start_block: int
    chain_name: str
    chain_id: int
    explorer_url: str


@dataclass
class AutomationConfig:
    poll_interval_seconds: int
    auto_mint: bool
    auto_release_redemptions: bool
    deposit_memo_prefix: str
    mint_resubmit_after_seconds: int
    redemption_block_batch_size: int
    state_path: Path
    reserve_status_path: Path
    operator_mode: str
    notes: str


@dataclass
class BridgeConfig:
    native: NativeConfig
    evm: EvmConfig
    automation: AutomationConfig


class NativeRpcClient:
    def __init__(self, url: str, username: str, password: str, timeout: float = 10.0) -> None:
        self.url = url
        self.username = username
        self.password = password
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": params or [],
        }).encode("utf-8")
        request = urllib.request.Request(self.url, data=payload, headers={"Content-Type": "application/json"})
        if self.username:
            auth = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
            request.add_header("Authorization", f"Basic {auth}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise BridgeError(f"native RPC HTTP {exc.code}: {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise BridgeError(f"native RPC unreachable: {exc.reason}") from exc
        except TimeoutError as exc:
            raise BridgeError("native RPC timeout") from exc

        error = body.get("error")
        if error:
            if isinstance(error, dict):
                raise BridgeError(error.get("message", "native RPC error"))
            raise BridgeError(str(error))
        return body.get("result")


class EvmRpcClient:
    def __init__(self, url: str, timeout: float = 15.0) -> None:
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": self._id,
            "method": method,
            "params": params or [],
        }).encode("utf-8")
        request = urllib.request.Request(self.url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise BridgeError(f"EVM RPC HTTP {exc.code}: {detail or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise BridgeError(f"EVM RPC unreachable: {exc.reason}") from exc
        except TimeoutError as exc:
            raise BridgeError("EVM RPC timeout") from exc

        error = body.get("error")
        if error:
            if isinstance(error, dict):
                raise BridgeError(error.get("message", "EVM RPC error"))
            raise BridgeError(str(error))
        return body.get("result")

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def get_logs(self, address: str, topic0: str, from_block: int, to_block: int) -> list[dict[str, Any]]:
        if to_block < from_block:
            return []
        params = [{
            "address": address,
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
            "topics": [topic0],
        }]
        result = self.call("eth_getLogs", params)
        if not isinstance(result, list):
            raise BridgeError("unexpected eth_getLogs response")
        return result


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(message: str) -> None:
    print(f"[{utc_now_iso()}] {message}", flush=True)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists() or not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)


def resolve_secret(section: dict[str, Any], key: str, env_key: str) -> str:
    env_name = str(section.get(env_key, "")).strip()
    if env_name:
        value = os.getenv(env_name, "").strip()
        if not value:
            raise BridgeError(f"required environment variable {env_name} is empty")
        return value
    return str(section.get(key, "")).strip()


def parse_config(path: Path) -> BridgeConfig:
    raw = load_json(path, None)
    if not isinstance(raw, dict):
        raise BridgeError(f"invalid bridge config at {path}")

    native_raw = raw.get("native", {})
    evm_raw = raw.get("evm", {})
    automation_raw = raw.get("automation", {})

    native = NativeConfig(
        rpc_url=str(native_raw.get("rpc_url", "http://127.0.0.1:9332/")).strip(),
        rpc_user=str(native_raw.get("rpc_user", "")).strip(),
        rpc_password=resolve_secret(native_raw, "rpc_password", "rpc_password_env"),
        reserve_address=str(native_raw.get("reserve_address", "")).strip(),
        deposit_confirmations=max(1, int(native_raw.get("deposit_confirmations", 6))),
        release_confirmations=max(1, int(native_raw.get("release_confirmations", 1))),
        scan_limit=max(25, int(native_raw.get("scan_limit", 500))),
    )
    evm = EvmConfig(
        rpc_url=str(evm_raw.get("rpc_url", "")).strip(),
        wrapped_contract_address=str(evm_raw.get("wrapped_contract_address", "")).strip(),
        minter_private_key=resolve_secret(evm_raw, "minter_private_key", "minter_private_key_env"),
        confirmations=max(1, int(evm_raw.get("confirmations", 12))),
        start_block=max(0, int(evm_raw.get("start_block", 0))),
        chain_name=str(evm_raw.get("chain_name", "Ethereum Mainnet")).strip() or "Ethereum Mainnet",
        chain_id=max(1, int(evm_raw.get("chain_id", 1))),
        explorer_url=str(evm_raw.get("explorer_url", "")).strip(),
    )
    automation = AutomationConfig(
        poll_interval_seconds=max(5, int(automation_raw.get("poll_interval_seconds", 15))),
        auto_mint=bool(automation_raw.get("auto_mint", True)),
        auto_release_redemptions=bool(automation_raw.get("auto_release_redemptions", False)),
        deposit_memo_prefix=str(automation_raw.get("deposit_memo_prefix", "EVM:")).strip() or "EVM:",
        mint_resubmit_after_seconds=max(30, int(automation_raw.get("mint_resubmit_after_seconds", 300))),
        redemption_block_batch_size=max(100, int(automation_raw.get("redemption_block_batch_size", 2000))),
        state_path=Path(str(automation_raw.get("state_path", path.parent.parent / "data" / "bridge_state.runtime.json"))),
        reserve_status_path=Path(str(automation_raw.get("reserve_status_path", path.parents[1] / "website" / "data" / "reserve_status.json"))),
        operator_mode=str(automation_raw.get("operator_mode", "automated-custodial")).strip() or "automated-custodial",
        notes=str(automation_raw.get("notes", "Automated bridge daemon reserve snapshot.")).strip(),
    )

    if not native.reserve_address:
        raise BridgeError("native.reserve_address is required")
    if not evm.rpc_url:
        raise BridgeError("evm.rpc_url is required")
    if not EVM_ADDRESS_RE.match(evm.wrapped_contract_address):
        raise BridgeError("evm.wrapped_contract_address must be a 0x-prefixed 20-byte address")
    if automation.auto_mint and not evm.minter_private_key:
        raise BridgeError("evm minter private key is required when automation.auto_mint is enabled")
    return BridgeConfig(native=native, evm=evm, automation=automation)


class CastRunner:
    def __init__(self, evm_rpc_url: str, private_key: str) -> None:
        self.evm_rpc_url = evm_rpc_url
        self.private_key = private_key

    def run(self, *args: str) -> str:
        command = ["cast", *args]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip() or "cast command failed"
            raise BridgeError(f"{' '.join(command)} failed: {stderr}")
        return completed.stdout.strip()

    def compute_deposit_id(self, native_txid: str, output_index: int, recipient: str, amount_sats: int) -> str:
        encoded = self.run(
            "abi-encode",
            "f(bytes32,uint32,address,uint256)",
            ensure_bytes32(native_txid),
            str(output_index),
            normalize_evm_address(recipient),
            str(amount_sats),
        )
        return self.run("keccak", encoded).splitlines()[-1].strip().lower()

    def contract_total_supply(self, contract: str) -> int:
        output = self.run("call", normalize_evm_address(contract), "totalSupply()(uint256)", "--rpc-url", self.evm_rpc_url)
        return int(output.splitlines()[-1].strip(), 10)

    def contract_is_processed_deposit(self, contract: str, deposit_id: str) -> bool:
        output = self.run(
            "call",
            normalize_evm_address(contract),
            "isProcessedDeposit(bytes32)(bool)",
            ensure_bytes32(deposit_id),
            "--rpc-url",
            self.evm_rpc_url,
        )
        tail = output.splitlines()[-1].strip().lower()
        return tail == "true"

    def submit_bridge_mint(
        self,
        contract: str,
        recipient: str,
        amount_wei: int,
        deposit_id: str,
        native_txid: str,
        native_sender: str,
    ) -> str:
        output = self.run(
            "send",
            "--async",
            "--rpc-url",
            self.evm_rpc_url,
            "--private-key",
            self.private_key,
            normalize_evm_address(contract),
            "mintFromBridge(address,uint256,bytes32,bytes32,string)",
            normalize_evm_address(recipient),
            str(amount_wei),
            ensure_bytes32(deposit_id),
            ensure_bytes32(native_txid),
            native_sender,
        )
        return output.splitlines()[-1].strip()


class BridgeDaemon:
    def __init__(self, config: BridgeConfig) -> None:
        self.config = config
        self.native = NativeRpcClient(config.native.rpc_url, config.native.rpc_user, config.native.rpc_password)
        self.evm = EvmRpcClient(config.evm.rpc_url)
        self.cast = CastRunner(config.evm.rpc_url, config.evm.minter_private_key)
        self._native_tx_cache: dict[str, dict[str, Any]] = {}
        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        payload = load_json(
            self.config.automation.state_path,
            {
                "last_evm_block": self.config.evm.start_block - 1 if self.config.evm.start_block > 0 else -1,
                "processed_deposits": {},
                "pending_mints": {},
                "processed_redemptions": {},
                "pending_releases": {},
            },
        )
        payload.setdefault("last_evm_block", self.config.evm.start_block - 1 if self.config.evm.start_block > 0 else -1)
        payload.setdefault("processed_deposits", {})
        payload.setdefault("pending_mints", {})
        payload.setdefault("processed_redemptions", {})
        payload.setdefault("pending_releases", {})
        return payload

    def persist_state(self) -> None:
        self.state["updated_at"] = utc_now_iso()
        write_json_atomic(self.config.automation.state_path, self.state)

    def run_forever(self) -> None:
        log("bridge daemon started")
        while True:
            try:
                self.run_cycle()
            except Exception as exc:  # noqa: BLE001
                log(f"cycle failed: {exc}")
            time.sleep(self.config.automation.poll_interval_seconds)

    def run_cycle(self) -> None:
        self.refresh_pending_mints()
        self.scan_native_deposits()
        self.scan_evm_redemptions()
        self.refresh_pending_releases()
        self.write_reserve_snapshot()
        self.persist_state()

    def fetch_native_transaction(self, txid: str, *, cache: bool = False) -> dict[str, Any]:
        if cache and txid in self._native_tx_cache:
            return self._native_tx_cache[txid]
        tx = self.native.call("getrawtransaction", [txid, True])
        if not isinstance(tx, dict):
            raise BridgeError(f"unexpected native transaction payload for {txid}")
        if cache:
            self._native_tx_cache[txid] = tx
        return tx

    def scan_native_deposits(self) -> None:
        txids = self.native.call(
            "getaddresstxids",
            [self.config.native.reserve_address, False, self.config.native.scan_limit],
        )
        if not isinstance(txids, list):
            raise BridgeError("unexpected getaddresstxids response")

        for txid in txids:
            txid = str(txid)
            tx = self.fetch_native_transaction(txid)
            confirmations = int(tx.get("confirmations", 0) or 0)
            if confirmations < self.config.native.deposit_confirmations:
                continue
            if tx.get("coinbase"):
                continue

            recipient = self.extract_recipient_from_tx(tx)
            if not recipient:
                continue
            native_sender = self.extract_sender_reference(tx)

            for output in tx.get("vout", []):
                if output.get("address") != self.config.native.reserve_address:
                    continue
                amount_sats = int(output.get("value_sats", 0) or 0)
                if amount_sats <= 0:
                    continue
                deposit_id = self.cast.compute_deposit_id(txid, int(output.get("n", 0)), recipient, amount_sats)
                if deposit_id in self.state["processed_deposits"] or deposit_id in self.state["pending_mints"]:
                    continue
                if self.cast.contract_is_processed_deposit(self.config.evm.wrapped_contract_address, deposit_id):
                    self.state["processed_deposits"][deposit_id] = {
                        "deposit_id": deposit_id,
                        "native_txid": txid,
                        "output_index": int(output.get("n", 0)),
                        "recipient": recipient,
                        "amount_sats": amount_sats,
                        "amount_wei": amount_sats * BRIDGE_UNIT_WEI,
                        "native_sender": native_sender,
                        "confirmations": confirmations,
                        "status": "already-processed-onchain",
                        "updated_at": utc_now_iso(),
                    }
                    log(f"deposit {deposit_id} already processed on EVM, state reconciled")
                    continue
                self.enqueue_or_submit_mint(
                    deposit_id=deposit_id,
                    native_txid=txid,
                    output_index=int(output.get("n", 0)),
                    recipient=recipient,
                    amount_sats=amount_sats,
                    confirmations=confirmations,
                    native_sender=native_sender,
                )

    def enqueue_or_submit_mint(
        self,
        *,
        deposit_id: str,
        native_txid: str,
        output_index: int,
        recipient: str,
        amount_sats: int,
        confirmations: int,
        native_sender: str,
    ) -> None:
        entry = {
            "deposit_id": deposit_id,
            "native_txid": native_txid,
            "output_index": output_index,
            "recipient": recipient,
            "amount_sats": amount_sats,
            "amount_wei": amount_sats * BRIDGE_UNIT_WEI,
            "confirmations": confirmations,
            "native_sender": native_sender,
            "attempts": 0,
            "status": "awaiting-mint",
            "updated_at": utc_now_iso(),
        }
        if not self.config.automation.auto_mint:
            self.state["pending_mints"][deposit_id] = entry
            log(f"queued deposit {deposit_id} for manual mint")
            return
        tx_hash = self.cast.submit_bridge_mint(
            self.config.evm.wrapped_contract_address,
            recipient,
            entry["amount_wei"],
            deposit_id,
            native_txid,
            native_sender,
        )
        entry["attempts"] = 1
        entry["evm_tx_hash"] = tx_hash
        entry["last_submit_at"] = utc_now_iso()
        entry["status"] = "mint-submitted"
        self.state["pending_mints"][deposit_id] = entry
        log(f"submitted mint for deposit {deposit_id}: {tx_hash}")

    def refresh_pending_mints(self) -> None:
        completed: list[str] = []
        now = time.time()
        for deposit_id, entry in list(self.state["pending_mints"].items()):
            if self.cast.contract_is_processed_deposit(self.config.evm.wrapped_contract_address, deposit_id):
                entry["status"] = "minted"
                entry["updated_at"] = utc_now_iso()
                self.state["processed_deposits"][deposit_id] = entry
                completed.append(deposit_id)
                log(f"mint confirmed onchain for deposit {deposit_id}")
                continue
            if not self.config.automation.auto_mint:
                continue
            last_submit = entry.get("last_submit_at")
            if last_submit:
                last_submit_ts = datetime.fromisoformat(last_submit).timestamp()
            else:
                last_submit_ts = 0.0
            if now - last_submit_ts < self.config.automation.mint_resubmit_after_seconds:
                continue
            tx_hash = self.cast.submit_bridge_mint(
                self.config.evm.wrapped_contract_address,
                entry["recipient"],
                int(entry["amount_wei"]),
                deposit_id,
                entry["native_txid"],
                entry["native_sender"],
            )
            entry["attempts"] = int(entry.get("attempts", 0)) + 1
            entry["evm_tx_hash"] = tx_hash
            entry["last_submit_at"] = utc_now_iso()
            entry["status"] = "mint-resubmitted"
            entry["updated_at"] = utc_now_iso()
            log(f"resubmitted mint for deposit {deposit_id}: {tx_hash}")
        for deposit_id in completed:
            self.state["pending_mints"].pop(deposit_id, None)

    def scan_evm_redemptions(self) -> None:
        latest_block = self.evm.block_number()
        finalized_block = latest_block - self.config.evm.confirmations + 1
        if finalized_block < 0:
            return
        from_block = max(int(self.state.get("last_evm_block", -1)) + 1, self.config.evm.start_block)
        if finalized_block < from_block:
            return
        batch = self.config.automation.redemption_block_batch_size
        current = from_block
        while current <= finalized_block:
            upper = min(finalized_block, current + batch - 1)
            logs = self.evm.get_logs(
                normalize_evm_address(self.config.evm.wrapped_contract_address),
                REDEMPTION_REQUESTED_TOPIC0,
                current,
                upper,
            )
            for raw_log in logs:
                event = decode_redemption_requested(raw_log)
                redemption_id = event["redemption_id"]
                if redemption_id in self.state["processed_redemptions"]:
                    continue
                existing = self.state["pending_releases"].get(redemption_id, {})
                merged = {**existing, **event}
                merged.setdefault("status", "awaiting-release")
                merged["updated_at"] = utc_now_iso()
                self.state["pending_releases"][redemption_id] = merged
                log(f"observed redemption {redemption_id} for {merged['native_destination']} amount {merged['amount_sats']} sats")
                if self.config.automation.auto_release_redemptions and not merged.get("native_release_txid"):
                    self.submit_native_release(redemption_id, merged)
            self.state["last_evm_block"] = upper
            current = upper + 1

    def submit_native_release(self, redemption_id: str, entry: dict[str, Any]) -> None:
        if not bool(self.native.call("getblockchaininfo", []).get("chain_approved", True)):
            entry["status"] = "waiting-for-native-chain-approval"
            entry["updated_at"] = utc_now_iso()
            return
        txid = self.native.call(
            "sendtoaddress",
            [entry["native_destination"], int(entry["amount_sats"]), {"op_return": f"BRIDGE-REDEEM:{redemption_id}"}],
        )
        entry["native_release_txid"] = str(txid)
        entry["status"] = "native-release-submitted"
        entry["updated_at"] = utc_now_iso()
        log(f"submitted native release for redemption {redemption_id}: {txid}")

    def refresh_pending_releases(self) -> None:
        completed: list[str] = []
        for redemption_id, entry in list(self.state["pending_releases"].items()):
            txid = str(entry.get("native_release_txid", "")).strip()
            if not txid:
                if self.config.automation.auto_release_redemptions:
                    try:
                        self.submit_native_release(redemption_id, entry)
                    except Exception as exc:  # noqa: BLE001
                        entry["status"] = f"release-error: {exc}"
                        entry["updated_at"] = utc_now_iso()
                continue
            try:
                tx = self.fetch_native_transaction(txid)
            except Exception as exc:  # noqa: BLE001
                entry["status"] = f"release-pending: {exc}"
                entry["updated_at"] = utc_now_iso()
                continue
            confirmations = int(tx.get("confirmations", 0) or 0)
            entry["native_release_confirmations"] = confirmations
            entry["updated_at"] = utc_now_iso()
            if confirmations >= self.config.native.release_confirmations:
                entry["status"] = "released"
                self.state["processed_redemptions"][redemption_id] = entry
                completed.append(redemption_id)
                log(f"native release confirmed for redemption {redemption_id}")
        for redemption_id in completed:
            self.state["pending_releases"].pop(redemption_id, None)

    def write_reserve_snapshot(self) -> None:
        native_summary = self.native.call("getaddresssummary", [self.config.native.reserve_address, False])
        native_locked_sats = int(native_summary.get("balance_sats", 0) or 0)
        wrapped_supply_wei = self.cast.contract_total_supply(self.config.evm.wrapped_contract_address)
        payload = {
            "wrapped_contract_address": normalize_evm_address(self.config.evm.wrapped_contract_address),
            "reserve_wallet_address": self.config.native.reserve_address,
            "evm_chain_name": self.config.evm.chain_name,
            "evm_chain_id": self.config.evm.chain_id,
            "explorer_url": self.config.evm.explorer_url,
            "operator_mode": self.config.automation.operator_mode,
            "status": "live" if native_locked_sats * BRIDGE_UNIT_WEI >= wrapped_supply_wei else "under-collateralized",
            "native_locked_sats": native_locked_sats,
            "wrapped_supply_wei": wrapped_supply_wei,
            "last_reconciled_at": utc_now_iso(),
            "notes": self.config.automation.notes,
            "pending_mint_count": len(self.state["pending_mints"]),
            "pending_release_count": len(self.state["pending_releases"]),
            "processed_deposit_count": len(self.state["processed_deposits"]),
            "processed_redemption_count": len(self.state["processed_redemptions"]),
        }
        write_json_atomic(self.config.automation.reserve_status_path, payload)

    def extract_recipient_from_tx(self, tx: dict[str, Any]) -> str | None:
        prefix = self.config.automation.deposit_memo_prefix
        for output in tx.get("vout", []):
            memo = output.get("op_return_text")
            if not isinstance(memo, str):
                continue
            if not memo.startswith(prefix):
                continue
            recipient = memo[len(prefix):].strip()
            if EVM_ADDRESS_RE.match(recipient):
                return normalize_evm_address(recipient)
        return None

    def extract_sender_reference(self, tx: dict[str, Any]) -> str:
        addresses: list[str] = []
        seen: set[str] = set()
        for vin in tx.get("vin", []):
            prev_txid = str(vin.get("txid", "")).strip()
            if not prev_txid or prev_txid == "0":
                continue
            try:
                prev_tx = self.fetch_native_transaction(prev_txid, cache=True)
                prev_index = int(vin.get("vout", 0) or 0)
                prev_outputs = prev_tx.get("vout", [])
                if prev_index >= len(prev_outputs):
                    continue
                address = str(prev_outputs[prev_index].get("address", "")).strip()
                if address and address not in seen:
                    seen.add(address)
                    addresses.append(address)
            except Exception:
                continue
        if not addresses:
            return f"native-tx:{tx.get('txid', '')}"[:128]
        reference = ",".join(addresses)
        return reference[:128]


def ensure_bytes32(value: str) -> str:
    normalized = value.lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise BridgeError(f"expected 32-byte hex value, got {value}")
    return "0x" + normalized


def normalize_evm_address(address: str) -> str:
    lowered = address.strip().lower()
    if not EVM_ADDRESS_RE.match(lowered):
        raise BridgeError(f"invalid EVM address: {address}")
    return lowered


def decode_redemption_requested(raw_log: dict[str, Any]) -> dict[str, Any]:
    topics = raw_log.get("topics", [])
    if len(topics) < 4:
        raise BridgeError("unexpected RedemptionRequested log: missing topics")
    data_hex = str(raw_log.get("data", "0x"))
    data = bytes.fromhex(data_hex[2:] if data_hex.startswith("0x") else data_hex)
    if len(data) < 96:
        raise BridgeError("unexpected RedemptionRequested log payload")

    offset = int.from_bytes(data[0:32], "big")
    amount_wei = int.from_bytes(data[32:64], "big")
    nonce = int.from_bytes(data[64:96], "big")
    if amount_wei % BRIDGE_UNIT_WEI != 0:
        raise BridgeError(f"redemption amount {amount_wei} is not convertible to native CRX units")
    if offset + 32 > len(data):
        raise BridgeError("invalid dynamic string offset in redemption event")
    string_length = int.from_bytes(data[offset:offset + 32], "big")
    string_start = offset + 32
    string_end = string_start + string_length
    if string_end > len(data):
        raise BridgeError("invalid dynamic string length in redemption event")
    native_destination = data[string_start:string_end].decode("utf-8")

    return {
        "redemption_id": ensure_bytes32(topics[1]),
        "account": "0x" + topics[2][-40:].lower(),
        "operator": "0x" + topics[3][-40:].lower(),
        "native_destination": native_destination,
        "amount_wei": amount_wei,
        "amount_sats": amount_wei // BRIDGE_UNIT_WEI,
        "nonce": nonce,
        "evm_tx_hash": ensure_bytes32(raw_log.get("transactionHash", "")),
        "evm_block_number": int(str(raw_log.get("blockNumber", "0x0")), 16),
        "evm_log_index": int(str(raw_log.get("logIndex", "0x0")), 16),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Automated bridge daemon for Wrapped CryptEX")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "config" / "bridge_config.example.json",
        help="Path to bridge config JSON",
    )
    parser.add_argument("--once", action="store_true", help="Run a single cycle and exit")
    args = parser.parse_args()

    config = parse_config(args.config)
    daemon = BridgeDaemon(config)
    if args.once:
        daemon.run_cycle()
    else:
        daemon.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
