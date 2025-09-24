# ledger/workers/anchor_worker.py
# Industrial-grade async worker to anchor ledger batches into blockchain.
# - Async batching with Merkle tree
# - Idempotency, checkpointing, retries with jitter
# - Pluggable queue and publisher backends
# - Health & metrics endpoints
# - Structured logging
#
# Python: 3.11+
# External deps: pydantic>=2, aiohttp>=3
# Optional deps used by Ethereum publisher: web3>=6, eth-account (via your EthereumAdapter)
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import random
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

from pydantic import BaseModel, Field, ValidationError

# -------------------------
# Logging
# -------------------------
logger = logging.getLogger("ledger.workers.anchor")
if not logger.handlers:
    _h = logging.StreamHandler()
    _f = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    _h.setFormatter(_f)
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# -------------------------
# Utility: sha256 and keccak256
# -------------------------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

try:
    # Python 3.11+ includes sha3_* in hashlib; keccak via pysha3 if installed.
    keccak256 = hashlib.sha3_256  # fallback to SHA3-256 if keccak not present
    def _keccak(data: bytes) -> bytes:
        return keccak256(data).digest()
except Exception:  # pragma: no cover
    def _keccak(data: bytes) -> bytes:
        return sha256(data)  # safe fallback

# -------------------------
# Merkle tree (binary, SHA-256 by default)
# -------------------------
def _pair_hash(left: bytes, right: bytes, use_keccak: bool) -> bytes:
    h = _keccak if use_keccak else sha256
    return h(left + right)

def merkle_root(leaves: List[bytes], use_keccak: bool = False) -> bytes:
    if not leaves:
        # root of empty set: hash of empty string
        return (_keccak(b"") if use_keccak else sha256(b""))
    level = [(_keccak(x) if use_keccak else sha256(x)) for x in leaves]
    while len(level) > 1:
        nxt: List[bytes] = []
        it = iter(level)
        for a in it:
            b = next(it, a)  # duplicate last if odd
            nxt.append(_pair_hash(a, b, use_keccak))
        level = nxt
    return level[0]

# -------------------------
# Queue Protocols
# -------------------------
@dataclass(frozen=True)
class AnchorItem:
    # Payload must be deterministic bytes for hashing
    key: str           # logical id of record (e.g., tx id)
    payload: bytes     # canonical-serialized ledger record (e.g., JSON Canonical Form)
    created_at: float  # unix ts

class AnchorQueue(Protocol):
    async def pull(self, max_items: int, timeout_sec: float) -> List[AnchorItem]: ...
    async def ack(self, items: List[AnchorItem]) -> None: ...
    async def requeue(self, items: List[AnchorItem], delay_sec: float = 0) -> None: ...
    async def size(self) -> int: ...

# In-memory queue (for tests/local usage)
class InMemoryAnchorQueue:
    def __init__(self) -> None:
        self._q: asyncio.Queue[AnchorItem] = asyncio.Queue()

    async def pull(self, max_items: int, timeout_sec: float) -> List[AnchorItem]:
        items: List[AnchorItem] = []
        try:
            it = await asyncio.wait_for(self._q.get(), timeout=timeout_sec)
            items.append(it)
        except asyncio.TimeoutError:
            return items
        while len(items) < max_items and not self._q.empty():
            items.append(self._q.get_nowait())
        return items

    async def ack(self, items: List[AnchorItem]) -> None:
        # already removed from queue; nothing to do
        return

    async def requeue(self, items: List[AnchorItem], delay_sec: float = 0) -> None:
        if delay_sec > 0:
            await asyncio.sleep(delay_sec)
        for it in items:
            await self._q.put(it)

    async def size(self) -> int:
        return self._q.qsize()

    # helper for tests
    async def put(self, it: AnchorItem) -> None:
        await self._q.put(it)

# -------------------------
# Checkpoint store (idempotency)
# -------------------------
class AnchorCheckpointStore(Protocol):
    async def get_last_batch_id(self) -> Optional[str]: ...
    async def set_last_batch_id(self, batch_id: str) -> None: ...
    async def is_seen(self, batch_id: str) -> bool: ...

class FileCheckpointStore:
    def __init__(self, path: str) -> None:
        self._path = path
        self._seen: set[str] = set()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    async def get_last_batch_id(self) -> Optional[str]:
        if not os.path.exists(self._path):
            return None
        try:
            with open(self._path, "rt", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("last_batch_id")
        except Exception:
            return None

    async def set_last_batch_id(self, batch_id: str) -> None:
        tmp = self._path + ".tmp"
        with open(tmp, "wt", encoding="utf-8") as f:
            json.dump({"last_batch_id": batch_id, "updated_at": time.time()}, f)
        os.replace(tmp, self._path)
        self._seen.add(batch_id)

    async def is_seen(self, batch_id: str) -> bool:
        if batch_id in self._seen:
            return True
        last = await self.get_last_batch_id()
        return last == batch_id

# -------------------------
# Anchor Publisher Protocol
# -------------------------
@dataclass(frozen=True)
class PublishResult:
    tx_hash: str
    chain_id: int
    submitted_at: float

class AnchorPublisher(Protocol):
    async def publish(self, root: bytes, batch_id: bytes, meta: Dict[str, Any]) -> PublishResult: ...
    async def confirm(self, tx_hash: str, confirmations: int, timeout_sec: float) -> Dict[str, Any]: ...

# -------------------------
# Ethereum Publisher (uses your EthereumAdapter)
# -------------------------
class EthereumAnchorPublisher:
    """
    Assumes an on-chain contract with ABI:
      function anchor(bytes32 root, bytes32 batchId, string calldata meta) external;
    """
    def __init__(self, adapter: "EthereumAdapter", contract_address: str, contract_abi: List[Dict[str, Any]]) -> None:
        self._adapter = adapter
        self._address = contract_address
        self._abi = contract_abi

    async def publish(self, root: bytes, batch_id: bytes, meta: Dict[str, Any]) -> PublishResult:
        # Normalize to hex strings for ABI (web3 handles bytes32 if bytes provided)
        root32 = root[:32] if len(root) >= 32 else root.ljust(32, b"\x00")
        bid32 = batch_id[:32] if len(batch_id) >= 32 else batch_id.ljust(32, b"\x00")
        meta_json = json.dumps(meta, separators=(",", ":"), ensure_ascii=False)
        tx_hash = await self._adapter.send_contract_tx(
            self._address,
            self._abi,
            "anchor",
            root32,
            bid32,
            meta_json,
        )
        chain_id = await self._adapter.get_chain_id()
        return PublishResult(tx_hash=tx_hash, chain_id=chain_id, submitted_at=time.time())

    async def confirm(self, tx_hash: str, confirmations: int, timeout_sec: float) -> Dict[str, Any]:
        rcpt = await self._adapter.wait_for_confirmations(tx_hash, confirmations=confirmations, timeout_sec=timeout_sec)
        return {"status": int(rcpt.get("status", 0)), "blockNumber": rcpt.get("blockNumber"), "txHash": tx_hash}

# -------------------------
# Config
# -------------------------
class AnchorWorkerConfig(BaseModel):
    # batching
    max_batch_items: int = Field(1000, ge=1, le=10_000)
    max_batch_bytes: int = Field(512 * 1024, ge=4 * 1024, le=8 * 1024 * 1024)
    max_batch_wait_sec: float = Field(2.0, ge=0.05, le=30.0)
    hash_algo: str = Field("sha256", description="sha256|keccak256")

    # queue
    queue_pull_timeout_sec: float = Field(0.5, ge=0.05, le=5.0)

    # publishing
    publish_confirmations: int = Field(2, ge=0, le=64)
    publish_timeout_sec: float = Field(180.0, ge=5.0, le=3600.0)
    retry_max_attempts: int = Field(8, ge=0, le=20)
    retry_initial_delay_sec: float = Field(0.5, ge=0.05, le=10.0)
    retry_max_delay_sec: float = Field(8.0, ge=0.1, le=120.0)

    # checkpoint
    checkpoint_path: str = Field(".state/anchor_checkpoint.json")

    # http endpoints
    http_bind: str = Field("127.0.0.1")
    http_port: int = Field(8088, ge=1, le=65535)

    # telemetry
    metrics_enabled: bool = Field(True)

# -------------------------
# Metrics (simple counters in-memory)
# -------------------------
class Metrics:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.total_pulled = 0
        self.total_anchored = 0
        self.total_retried = 0
        self.total_failed = 0
        self.inflight_batches = 0
        self.last_batch_duration_ms = 0.0
        self.queue_depth = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_pulled": self.total_pulled,
            "total_anchored": self.total_anchored,
            "total_retried": self.total_retried,
            "total_failed": self.total_failed,
            "inflight_batches": self.inflight_batches,
            "last_batch_duration_ms": self.last_batch_duration_ms,
            "queue_depth": self.queue_depth,
        }

# -------------------------
# Worker
# -------------------------
class AnchorWorker:
    def __init__(
        self,
        cfg: AnchorWorkerConfig,
        queue: AnchorQueue,
        publisher: AnchorPublisher,
        checkpoint: Optional[AnchorCheckpointStore] = None,
    ) -> None:
        self._cfg = cfg
        self._queue = queue
        self._publisher = publisher
        self._checkpoint = checkpoint or FileCheckpointStore(cfg.checkpoint_path)
        self._stop = asyncio.Event()
        self._metrics = Metrics()
        self._inflight: Dict[str, PublishResult] = {}

    async def start(self) -> None:
        logger.info("AnchorWorker starting")
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)
        # Launch http server for health/metrics
        self._http_task = asyncio.create_task(self._http_server(), name="anchor.http")

        try:
            await self._run()
        finally:
            self._stop.set()
            await self._shutdown_http()
            logger.info("AnchorWorker stopped")

    async def stop(self) -> None:
        self._stop.set()

    async def _run(self) -> None:
        while not self._stop.is_set():
            t0 = time.perf_counter()
            batch, meta = await self._collect_batch()
            if not batch:
                continue

            root, batch_id = self._build_anchor_artifacts(batch, meta)
            # Idempotency guard
            if await self._checkpoint.is_seen(batch_id.hex()):
                logger.warning("Duplicate batch detected, skipping: %s", batch_id.hex())
                continue

            # Publish with retries
            pub_res = await self._publish_with_retry(root, batch_id, meta)
            if not pub_res:
                self._metrics.total_failed += 1
                # requeue failed items with delay to avoid hot loop
                await self._queue.requeue(batch, delay_sec=1.0)
                continue

            self._inflight[pub_res.tx_hash] = pub_res
            # Confirmation (non-blocking of main loop)
            asyncio.create_task(self._confirm_and_checkpoint(pub_res, batch, batch_id), name=f"confirm.{pub_res.tx_hash}")

            self._metrics.total_anchored += len(batch)
            self._metrics.last_batch_duration_ms = (time.perf_counter() - t0) * 1000.0

    async def _collect_batch(self) -> Tuple[List[AnchorItem], Dict[str, Any]]:
        max_items = self._cfg.max_batch_items
        max_bytes = self._cfg.max_batch_bytes
        wait_deadline = time.monotonic() + self._cfg.max_batch_wait_sec

        items: List[AnchorItem] = []
        size_bytes = 0

        while not self._stop.is_set():
            remaining = wait_deadline - time.monotonic()
            if remaining <= 0 and items:
                break

            pulled = await self._queue.pull(max_items=max_items - len(items), timeout_sec=min(max(remaining, 0.05), self._cfg.queue_pull_timeout_sec))
            self._metrics.total_pulled += len(pulled)

            for it in pulled:
                item_size = len(it.payload)
                if len(items) >= max_items or (size_bytes + item_size) > max_bytes:
                    # push back overflow into queue head
                    await self._queue.requeue([it])
                    remaining = 0  # break cycle
                    break
                items.append(it)
                size_bytes += item_size

            if len(items) >= max_items or size_bytes >= max_bytes:
                break
            if not pulled and time.monotonic() >= wait_deadline and items:
                break

            # update queue depth metric
            self._metrics.queue_depth = await self._queue.size()

            if not pulled:
                await asyncio.sleep(0.01)  # backoff when idle

        meta = {
            "count": len(items),
            "bytes": size_bytes,
            "windowSec": self._cfg.max_batch_wait_sec,
            "ts": int(time.time()),
        }
        return items, meta

    def _build_anchor_artifacts(self, batch: List[AnchorItem], meta: Dict[str, Any]) -> Tuple[bytes, bytes]:
        # Canonical leaves: sha256(payload) to avoid extremely large leaves
        use_keccak = (self._cfg.hash_algo.lower() == "keccak256")
        leaf_hashes = [(_keccak(it.payload) if use_keccak else sha256(it.payload)) for it in batch]
        root = merkle_root(leaf_hashes, use_keccak=use_keccak)
        # Deterministic batch_id: H(root || minKey || maxKey || ts)
        keys_sorted = sorted(x.key for x in batch)
        min_key = keys_sorted[0].encode("utf-8") if keys_sorted else b""
        max_key = keys_sorted[-1].encode("utf-8") if keys_sorted else b""
        ts_bytes = str(meta.get("ts", int(time.time()))).encode("ascii")
        h = _keccak if use_keccak else sha256
        batch_id = h(root + min_key + max_key + ts_bytes)
        return root, batch_id

    async def _publish_with_retry(self, root: bytes, batch_id: bytes, meta: Dict[str, Any]) -> Optional[PublishResult]:
        delay = self._cfg.retry_initial_delay_sec
        for attempt in range(1, self._cfg.retry_max_attempts + 1):
            try:
                self._metrics.inflight_batches += 1
                res = await self._publisher.publish(root, batch_id, meta)
                logger.info("Published anchor | tx=%s | chain=%s | batch=%s", res.tx_hash, res.chain_id, batch_id.hex())
                return res
            except Exception as e:
                self._metrics.total_retried += 1
                j = random.uniform(0.5, 1.5)
                logger.warning("Publish attempt %d failed: %s; retrying in %.2fs", attempt, e, delay * j)
                await asyncio.sleep(delay * j)
                delay = min(delay * 2, self._cfg.retry_max_delay_sec)
        logger.error("Publish exhausted retries for batch=%s", batch_id.hex())
        return None
    async def _confirm_and_checkpoint(self, pub_res: PublishResult, batch: List[AnchorItem], batch_id: bytes) -> None:
        try:
            conf = await self._publisher.confirm(pub_res.tx_hash, confirmations=self._cfg.publish_confirmations, timeout_sec=self._cfg.publish_timeout_sec)
            if int(conf.get("status", 0)) != 1:
                raise RuntimeError(f"Anchor tx failed on-chain: {conf}")
            # ack queue only after on-chain confirmation
            await self._queue.ack(batch)
            await self._checkpoint.set_last_batch_id(batch_id.hex())
            logger.info("Anchor confirmed | tx=%s | block=%s | batch=%s", pub_res.tx_hash, conf.get("blockNumber"), batch_id.hex())
        except Exception as e:
            logger.error("Confirmation failed | tx=%s | err=%s | will requeue batch", pub_res.tx_hash, e)
            # Return batch for reprocessing; idempotency will skip if already anchored
            await self._queue.requeue(batch, delay_sec=1.0)
        finally:
            self._inflight.pop(pub_res.tx_hash, None)
            self._metrics.inflight_batches = max(0, self._metrics.inflight_batches - 1)

    # -------------------------
    # HTTP health/metrics
    # -------------------------
    async def _http_server(self) -> None:
        try:
            from aiohttp import web
        except Exception:
            logger.warning("aiohttp not installed; health/metrics disabled")
            await self._stop.wait()
            return

        async def health(_req: "web.Request") -> "web.Response":
            body = {"ok": True, "inflight": list(self._inflight.keys()), "time": int(time.time())}
            return web.json_response(body)

        async def metrics(_req: "web.Request") -> "web.Response":
            return web.json_response(self._metrics.to_dict())

        app = web.Application()
        app.add_routes([web.get("/health", health), web.get("/metrics", metrics)])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self._cfg.http_bind, self._cfg.http_port)
        await site.start()
        logger.info("HTTP health/metrics on http://%s:%d", self._cfg.http_bind, self._cfg.http_port)
        try:
            await self._stop.wait()
        finally:
            await runner.cleanup()

    async def _shutdown_http(self) -> None:
        # aiohttp runner cleaned up in _http_server
        return

# -------------------------
# Wiring helpers (example bootstrap)
# -------------------------
# The following are optional conveniences to wire EthereumAdapter into the worker.
# They are not executed on import.
#
# from ledger.adapters.chains.ethereum_adapter import EthereumAdapter, build_ethereum_adapter
#
# ETH_ANCHOR_ABI = [
#   {"inputs":[{"internalType":"bytes32","name":"root","type":"bytes32"},
#              {"internalType":"bytes32","name":"batchId","type":"bytes32"},
#              {"internalType":"string","name":"meta","type":"string"}],
#    "name":"anchor","outputs":[],"stateMutability":"nonpayable","type":"function"}
# ]
#
# async def run_anchor_worker():
#     adapter = build_ethereum_adapter({
#         "rpc_url": "https://mainnet.infura.io/v3/<key>",
#         "private_key": "<hex>",
#         "default_sender": "0xYourAddr",
#         "confirmation_blocks": 2
#     })
#     await adapter.connect()
#     publisher = EthereumAnchorPublisher(adapter, "0xContractAddr", ETH_ANCHOR_ABI)
#     queue = InMemoryAnchorQueue()  # replace with your MQ implementation
#     cfg = AnchorWorkerConfig()
#     worker = AnchorWorker(cfg, queue, publisher)
#     await worker.start()
#
# if __name__ == "__main__":
#     asyncio.run(run_anchor_worker())
