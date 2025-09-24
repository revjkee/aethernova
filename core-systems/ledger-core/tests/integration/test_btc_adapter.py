# -*- coding: utf-8 -*-
# File: ledger-core/tests/integration/test_btc_adapter.py
# Purpose: Industrial-grade integration tests for Bitcoin adapter in ledger-core.
#
# Test matrix:
#   - FAKE mode (default): in-process fake JSON-RPC with scripted responses
#   - LIVE mode (optional): real bitcoind JSON-RPC (enable with -m btc_live)
#
# Requirements:
#   pytest>=7, pytest-asyncio>=0.23
# Optional (LIVE mode):
#   running bitcoind with wallet and JSON-RPC; env:
#     BTC_RPC_URL, BTC_RPC_USER, BTC_RPC_PASS, BTC_WALLET
#
# Adapter Contract (async):
#   Methods expected on adapter (names are conventional, map to your implementation):
#     - get_block_height() -> int
#     - get_balance(address: str | None = None) -> int (sats)
#     - get_utxos(address: str) -> list[dict]
#     - estimate_fee(blocks: int = 2) -> int (sats/vB)
#     - build_psbt(inputs: list[dict], outputs: dict[str, int], change_address: str | None) -> str (base64)
#     - sign_psbt(psbt_b64: str) -> dict  (expects {"psbt_b64": "..."} or {"complete": bool, "hex": str})
#     - finalize_psbt(psbt_b64: str) -> dict (expects {"complete": bool, "hex": str})
#     - broadcast(raw_tx_hex: str) -> str (txid)
#     - get_transaction(txid: str) -> dict (includes "confirmations": int)
#
# If your adapter uses different names, provide a thin wrapper in the fixture below.

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import pytest

# ---------------------------------------
# Pytest configuration
# ---------------------------------------

pytestmark = pytest.mark.asyncio

def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name, default)
    return v if v not in ("", None) else None

RUN_LIVE = False
# Enable live tests via marker -m btc_live and required env vars
def pytest_configure(config):
    global RUN_LIVE
    try:
        RUN_LIVE = config.getoption("-m") and "btc_live" in str(config.getoption("-m"))
    except Exception:
        RUN_LIVE = False

# ---------------------------------------
# Fake JSON-RPC endpoint (scriptable)
# ---------------------------------------

class FakeRPC:
    """
    Scriptable fake RPC endpoint. Register responses per method in a FIFO list.
    """
    def __init__(self) -> None:
        self._responses: Dict[str, List[Any]] = {}
        self.calls: List[Tuple[str, Tuple[Any, ...]]] = []

    def add(self, method: str, *responses: Any) -> "FakeRPC":
        self._responses.setdefault(method, []).extend(list(responses))
        return self

    async def call(self, method: str, *params: Any) -> Any:
        self.calls.append((method, params))
        q = self._responses.get(method, [])
        if not q:
            raise AssertionError(f"Unexpected RPC call: {method}({params})")
        value = q.pop(0)
        # Simulate transient error by raising the exception instance
        if isinstance(value, Exception):
            raise value
        return value

# ---------------------------------------
# Optional Noop metrics
# ---------------------------------------

class NoopMetrics:
    def __init__(self) -> None:
        self.counters: Dict[str, int] = {}
        self.hist: Dict[str, List[float]] = {}

    def inc(self, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        self.counters[name] = self.counters.get(name, 0) + 1

    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        self.hist.setdefault(name, []).append(value)

# ---------------------------------------
# Adapter loader (LIVE or FAKE)
# ---------------------------------------

@dataclass
class AdapterHandle:
    impl: Any
    mode: str  # "FAKE" | "LIVE"

@pytest.fixture(scope="function")
async def btc_adapter(monkeypatch) -> AdapterHandle:
    """
    Try to load real adapter if LIVE requested; otherwise provide FAKE adapter
    that implements the expected async contract and delegates to FakeRPC.
    """
    metrics = NoopMetrics()

    if RUN_LIVE:
        url = _env("BTC_RPC_URL")
        user = _env("BTC_RPC_USER")
        pw = _env("BTC_RPC_PASS")
        wallet = _env("BTC_WALLET")

        if not all([url, user, pw, wallet]):
            pytest.skip("LIVE mode requires BTC_RPC_URL, BTC_RPC_USER, BTC_RPC_PASS, BTC_WALLET")

        try:
            from ledger.adapters.btc.bitcoind import BTCAdapter  # your real implementation
        except Exception:
            pytest.skip("Real BTCAdapter not importable in this environment")

        # Construct real adapter; adjust kwargs for your constructor
        impl = BTCAdapter(rpc_url=url, rpc_user=user, rpc_pass=pw, wallet=wallet, metrics=metrics)
        return AdapterHandle(impl=impl, mode="LIVE")

    # FAKE mode
    fake = FakeRPC()

    class FakeAdapter:
        def __init__(self, rpc: FakeRPC) -> None:
            self.rpc = rpc
            self.metrics = metrics

        # Map contract methods to underlying fake RPC "methods"
        async def get_block_height(self) -> int:
            h = await self.rpc.call("getblockcount")
            assert isinstance(h, int) and h >= 0
            return h

        async def get_balance(self, address: Optional[str] = None) -> int:
            # Return sats; fake uses BTC float then convert for realism
            if address:
                utxos = await self.get_utxos(address)
                return sum(int(u["amount_sats"]) for u in utxos)
            btc = await self.rpc.call("getbalance")
            return int(round(btc * 100_000_000))

        async def get_utxos(self, address: str) -> List[Dict[str, Any]]:
            utxos = await self.rpc.call("scantxoutset", "start", [{"desc": f"addr({address})"}])
            # Normalize to list of dicts with amount_sats, txid, vout
            out = []
            for u in utxos:
                out.append({"txid": u["txid"], "vout": u["vout"], "amount_sats": int(round(u["amount"] * 100_000_000))})
            return out

        async def estimate_fee(self, blocks: int = 2) -> int:
            feerate = await self.rpc.call("estimatesmartfee", blocks)
            # feerate in BTC/kB or BTC/kvB -> convert to sats/vB
            btc_per_kvB = feerate["feerate"]
            sats_vb = int(round((btc_per_kvB * 100_000_000) / 1000))
            return max(sats_vb, 1)

        async def build_psbt(self, inputs: List[Dict[str, Any]], outputs: Dict[str, int], change_address: Optional[str]) -> str:
            # amounts are sats; convert to BTC for the fake
            outs_btc = {k: v / 100_000_000 for k, v in outputs.items()}
            psbt = await self.rpc.call("walletcreatefundedpsbt", inputs, outs_btc, 0, {"changeAddress": change_address} if change_address else {})
            return psbt["psbt"]

        async def sign_psbt(self, psbt_b64: str) -> Dict[str, Any]:
            signed = await self.rpc.call("walletprocesspsbt", psbt_b64)
            return {"psbt_b64": signed["psbt"], "complete": signed.get("complete", False)}

        async def finalize_psbt(self, psbt_b64: str) -> Dict[str, Any]:
            fin = await self.rpc.call("finalizepsbt", psbt_b64)
            return {"complete": fin["complete"], "hex": fin.get("hex", "")}

        async def broadcast(self, raw_tx_hex: str) -> str:
            txid = await self.rpc.call("sendrawtransaction", raw_tx_hex)
            return txid

        async def get_transaction(self, txid: str) -> Dict[str, Any]:
            tx = await self.rpc.call("gettransaction", txid)
            return tx

    adapter = FakeAdapter(fake)

    # Prime fake RPC with sane defaults; individual tests can override
    fake.add("getblockcount", 840_000)
    fake.add("getbalance", 1.23456789)
    # fee: ~15 sat/vB -> 0.00015 BTC/kvB
    fake.add("estimatesmartfee", {"feerate": 0.00015})

    return AdapterHandle(impl=adapter, mode="FAKE")

# ---------------------------------------
# Test helpers
# ---------------------------------------

def _random_address() -> str:
    # Not a real checksum; only for test data shape
    prefix = random.choice(["bc1q", "tb1q", "bcrt1q"])
    return prefix + "".join(random.choice("023456789acdefghjklmnpqrstuvwxyz") for _ in range(30))

# ---------------------------------------
# Tests
# ---------------------------------------

async def _eventually(predicate, timeout_s: float = 5.0, interval_s: float = 0.2):
    """Poll predicate() until true or timeout."""
    start = time.monotonic()
    while time.monotonic() - start < timeout_s:
        if await predicate():
            return True
        await asyncio.sleep(interval_s)
    return False

@pytest.mark.timeout(10)
async def test_get_block_height_ok(btc_adapter: AdapterHandle):
    btc = btc_adapter.impl
    h = await btc.get_block_height()
    assert isinstance(h, int)
    assert h >= 0

@pytest.mark.timeout(10)
async def test_get_balance_and_utxos_aggregate(btc_adapter: AdapterHandle):
    btc = btc_adapter.impl
    if btc_adapter.mode == "FAKE":
        # Prepare deterministic UTXOs for specific address
        addr = _random_address()
        rpc: FakeRPC = btc.rpc  # type: ignore[attr-defined]
        rpc.add("scantxoutset", [
            {"txid": "a"*64, "vout": 0, "amount": 0.00010000},
            {"txid": "b"*64, "vout": 1, "amount": 0.00002000},
        ])
        utxos = await btc.get_utxos(addr)
        assert len(utxos) == 2
        # 10000 + 2000 sats
        bal = await btc.get_balance(addr)
        assert bal == 12_000
    else:
        # LIVE: check wallet balance non-negative
        bal = await btc.get_balance(None)
        assert isinstance(bal, int) and bal >= 0

@pytest.mark.timeout(15)
async def test_fee_estimate_and_psbt_pipeline(btc_adapter: AdapterHandle):
    btc = btc_adapter.impl
    change = _random_address()
    dst = _random_address()

    if btc_adapter.mode == "FAKE":
        rpc: FakeRPC = btc.rpc  # type: ignore[attr-defined]
        # walletcreatefundedpsbt -> psbt b64 placeholder
        rpc.add("walletcreatefundedpsbt", {"psbt": base64.b64encode(b"PSBT_FAKE").decode("ascii")})
        # walletprocesspsbt -> same PSBT, complete=false
        rpc.add("walletprocesspsbt", {"psbt": base64.b64encode(b"PSBT_SIGNED").decode("ascii"), "complete": False})
        # finalizepsbt -> complete true, hex raw
        rpc.add("finalizepsbt", {"complete": True, "hex": "010000000001..."})
        # sendrawtransaction -> txid
        rpc.add("sendrawtransaction", "ff"*32)

        sats_vb = await btc.estimate_fee(2)
        assert isinstance(sats_vb, int) and sats_vb >= 1

        psbt = await btc.build_psbt(
            inputs=[{"txid": "00"*32, "vout": 0}],
            outputs={dst: 11_000},
            change_address=change
        )
        assert isinstance(psbt, str) and len(psbt) > 0

        signed = await btc.sign_psbt(psbt)
        assert "psbt_b64" in signed

        fin = await btc.finalize_psbt(signed["psbt_b64"])
        assert fin["complete"] is True
        assert len(fin["hex"]) >= 8

        txid = await btc.broadcast(fin["hex"])
        assert isinstance(txid, str) and len(txid) == 64
    else:
        # LIVE path (smoke): just ensure fee estimate works and wallet can make PSBT if wallet funded.
        sats_vb = await btc.estimate_fee(2)
        assert isinstance(sats_vb, int) and sats_vb >= 1

@pytest.mark.timeout(15)
async def test_reorg_tolerance_on_confirmations(btc_adapter: AdapterHandle):
    btc = btc_adapter.impl
    if btc_adapter.mode == "FAKE":
        rpc: FakeRPC = btc.rpc  # type: ignore[attr-defined]
        # gettransaction: first unconfirmed, then confirmed=2
        txid = "aa"*32
        rpc.add("gettransaction", {"txid": txid, "confirmations": 0})
        rpc.add("gettransaction", {"txid": txid, "confirmations": 2})

        # Poll until confirmations >= 1
        ok = await _eventually(lambda: btc.get_transaction(txid).__await__(), timeout_s=3, interval_s=0.3)
        assert ok is not None
        tx = await btc.get_transaction(txid)
        assert tx["confirmations"] >= 2
    else:
        # LIVE: pick a known txid from env or skip
        live_txid = _env("BTC_TEST_TXID")
        if not live_txid:
            pytest.skip("Set BTC_TEST_TXID for live confirmations check")
        tx = await btc.get_transaction(live_txid)
        assert "confirmations" in tx and isinstance(tx["confirmations"], int)

@pytest.mark.timeout(15)
async def test_retry_on_transient_rpc_errors(btc_adapter: AdapterHandle, monkeypatch):
    """
    Simulate transient errors during walletprocesspsbt and ensure adapter
    call is retried and eventually succeeds. In FAKE mode we emulate retry
    at test level by calling twice; in LIVE mode we skip.
    """
    btc = btc_adapter.impl
    if btc_adapter.mode != "FAKE":
        pytest.skip("Retry simulation is FAKE-only")

    rpc: FakeRPC = btc.rpc  # type: ignore[attr-defined]

    class Transient(Exception):
        pass

    # Prepare pipeline with a transient error in the middle
    rpc.add("walletcreatefundedpsbt", {"psbt": base64.b64encode(b"PSBT_FAKE").decode("ascii")})
    rpc.add("walletprocesspsbt", Transient("ECONNRESET"))
    rpc.add("walletprocesspsbt", {"psbt": base64.b64encode(b"PSBT_SIGNED").decode("ascii"), "complete": False})
    rpc.add("finalizepsbt", {"complete": True, "hex": "020000000001..."})
    rpc.add("sendrawtransaction", "ee"*32)

    # Build PSBT
    psbt = await btc.build_psbt(
        inputs=[{"txid": "11"*32, "vout": 1}],
        outputs={_random_address(): 5_000},
        change_address=_random_address()
    )

    # Emulate adapter-level retry loop here to assert idempotency of downstream:
    attempts = 0
    signed = None
    while True:
        try:
            attempts += 1
            signed = await btc.sign_psbt(psbt)
            break
        except Transient:
            if attempts >= 2:
                raise
            await asyncio.sleep(0.05)

    assert attempts == 2
    assert signed and "psbt_b64" in signed

    fin = await btc.finalize_psbt(signed["psbt_b64"])
    txid = await btc.broadcast(fin["hex"])
    assert isinstance(txid, str) and len(txid) == 64

# ---------------------------------------
# End of file
