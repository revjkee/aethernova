# ledger/workers/finalize_worker.py
# Industrial-grade finalization worker for ledger-core
# Standard library only. All integrations are inverted via Protocols.

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import random
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Tuple, Union, Iterable

UTC = dt.timezone.utc

# ==============================
# Utilities
# ==============================

def utcnow() -> dt.datetime:
    return dt.datetime.now(tz=UTC)

def iso(ts: Optional[dt.datetime] = None) -> str:
    ts = ts or utcnow()
    return ts.astimezone(UTC).isoformat(timespec="milliseconds")

def sha256(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def rand_jitter(base: float) -> float:
    return base * (0.8 + random.random() * 0.4)

def gen_uuid() -> str:
    return uuid.uuid4().hex

# ==============================
# Metrics (optional hook)
# ==============================

class Metrics(Protocol):
    def inc(self, name: str, labels: Optional[Dict[str, str]] = None) -> None: ...
    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None: ...

class _NoopMetrics:
    def inc(self, name: str, labels: Optional[Dict[str, str]] = None) -> None: ...
    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None: ...

# ==============================
# Auditor (optional hook)
# ==============================

class Auditor(Protocol):
    async def log(self, *, type: Any, severity: Any, actor: str, action: str, resource: str, status: Optional[str] = None, code: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Any: ...

# ==============================
# KMS‑like signer
# ==============================

class Signer(Protocol):
    async def sign(self, message: bytes, *, digest_alg: str = "SHA256", key_version_name: Optional[str] = None) -> Dict[str, str]: ...
    async def get_public_key_pem(self, *, key_version_name: Optional[str] = None) -> str: ...

# ==============================
# Queue and Store protocols
# ==============================

@dataclass(frozen=True)
class FinalizeTask:
    task_id: str
    batch_id: str
    ledger_scope: str  # e.g. "mainnet"|"testnet"|"region:eu"
    entries: List[Dict[str, Any]]  # normalized ledger entries or tx ids
    created_at: str
    attempt: int = 0
    idempotency_key: Optional[str] = None

class TaskQueue(Protocol):
    async def pull(self, *, max_messages: int, visibility_timeout_s: int) -> List[FinalizeTask]: ...
    async def ack(self, task: FinalizeTask) -> None: ...
    async def nack(self, task: FinalizeTask, *, delay_s: int) -> None: ...
    async def dead_letter(self, task: FinalizeTask, reason: str) -> None: ...

class LedgerStore(Protocol):
    async def is_batch_finalized(self, batch_id: str) -> bool: ...
    async def load_entries(self, batch_id: str) -> List[Dict[str, Any]]: ...
    async def mark_finalized(self,
                             *,
                             batch_id: str,
                             commitment: str,
                             merkle_root: str,
                             signature_b64: str,
                             signer_key_version: Optional[str],
                             finalized_at: str,
                             meta: Dict[str, Any]) -> None: ...
    async def publish_event(self, *, topic: str, payload: Dict[str, Any]) -> None: ...
    async def save_idempotency(self, key: str, value: Dict[str, Any]) -> None: ...
    async def get_idempotency(self, key: str) -> Optional[Dict[str, Any]]: ...

# ==============================
# Merkle tree implementation
# ==============================

def _hash_leaf(item: Dict[str, Any]) -> str:
    # Stable hash of entry; application may pre-normalize entries
    return sha256(stable_json(item))

def _merkle_layer(nodes: List[str]) -> List[str]:
    if not nodes:
        return []
    if len(nodes) == 1:
        return nodes
    out: List[str] = []
    it = iter(nodes)
    for a in it:
        b = next(it, a)  # duplicate last if odd
        out.append(sha256(a + b))
    return out

def compute_merkle_root(entries: List[Dict[str, Any]]) -> Tuple[str, List[List[str]]]:
    leaves = [_hash_leaf(e) for e in entries]
    if not leaves:
        # Empty batch convention: root = SHA256("EMPTY")
        return sha256("EMPTY"), [["EMPTY"]]
    layers: List[List[str]] = [leaves]
    current = leaves
    while len(current) > 1:
        current = _merkle_layer(current)
        layers.append(current)
    return current[0], layers

# ==============================
# Config
# ==============================

class FinalizeMode(str, Enum):
    STRICT = "STRICT"   # fail on any inconsistency
    LENIENT = "LENIENT" # skip broken entries; still finalize if non-empty

@dataclass
class FinalizeWorkerConfig:
    worker_id: str = field(default_factory=lambda: f"finalize-{gen_uuid()[:8]}")
    concurrency: int = 8
    poll_interval_s: float = 0.5
    visibility_timeout_s: int = 60
    max_messages_per_poll: int = 16

    max_retries: int = 8
    initial_backoff_s: float = 0.5
    max_backoff_s: float = 20.0

    finalize_mode: FinalizeMode = FinalizeMode.STRICT
    signer_key_version: Optional[str] = None

    # commitment = SHA256(scope | batch_id | merkle_root | created_at | entries_count)
    commitment_salt: Optional[str] = None

    metrics_labels: Dict[str, str] = field(default_factory=dict)

# ==============================
# Worker
# ==============================

class FinalizeWorker:
    def __init__(self,
                 *,
                 cfg: FinalizeWorkerConfig,
                 queue: TaskQueue,
                 store: LedgerStore,
                 signer: Signer,
                 auditor: Optional[Auditor] = None,
                 metrics: Optional[Metrics] = None) -> None:
        self.cfg = cfg
        self.queue = queue
        self.store = store
        self.signer = signer
        self.auditor = auditor
        self.metrics = metrics or _NoopMetrics()
        self._stop = asyncio.Event()
        self._sem = asyncio.Semaphore(cfg.concurrency)
        self._tasks: List[asyncio.Task] = []
        self._logger = logging.getLogger("ledger.workers.finalize")
        if not self._logger.handlers:
            h = logging.StreamHandler()
            fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
            h.setFormatter(fmt)
            self._logger.addHandler(h)
        self._logger.setLevel(logging.INFO)

    # ---------- Lifecycle ----------

    async def start(self) -> None:
        self._logger.info("FinalizeWorker %s starting", self.cfg.worker_id)
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)
        self._tasks = [asyncio.create_task(self._poll_loop())]
        self.metrics.inc("finalize_worker_started", self.cfg.metrics_labels)

    async def stop(self) -> None:
        self._logger.info("FinalizeWorker %s stopping", self.cfg.worker_id)
        self._stop.set()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        self.metrics.inc("finalize_worker_stopped", self.cfg.metrics_labels)

    # ---------- Core loops ----------

    async def _poll_loop(self) -> None:
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                tasks = await self.queue.pull(
                    max_messages=self.cfg.max_messages_per_poll,
                    visibility_timeout_s=self.cfg.visibility_timeout_s
                )
                if not tasks:
                    await asyncio.sleep(self.cfg.poll_interval_s)
                    continue
                for task in tasks:
                    await self._sem.acquire()
                    asyncio.create_task(self._wrap_process(task))
            except Exception as e:
                self._logger.exception("Poll loop error: %s", e)
                await asyncio.sleep(rand_jitter(self.cfg.poll_interval_s))
            finally:
                self.metrics.observe("finalize_poll_latency_seconds", time.monotonic() - t0, self.cfg.metrics_labels)

    async def _wrap_process(self, task: FinalizeTask) -> None:
        try:
            await self._process(task)
        except Exception as e:
            self._logger.exception("Unhandled error processing task %s: %s", task.task_id, e)
            # Ensure at-least-once visibility extension via nack
            await self._safe_nack(task, reason="unhandled", delay_s=self._backoff_for(task.attempt + 1))
        finally:
            self._sem.release()

    # ---------- Processing ----------

    async def _process(self, t: FinalizeTask) -> None:
        lbl = dict(self.cfg.metrics_labels, scope=t.ledger_scope)
        self._logger.info("Processing task=%s batch=%s scope=%s attempt=%d", t.task_id, t.batch_id, t.ledger_scope, t.attempt)
        t_start = time.monotonic()

        # Idempotency key: if provided, check stored result
        idem_key = t.idempotency_key or f"finalize:{t.ledger_scope}:{t.batch_id}"
        cached = await self.store.get_idempotency(idem_key)
        if cached:
            self.metrics.inc("finalize_idempotent_hit", lbl)
            self._logger.info("Idempotent hit for batch=%s", t.batch_id)
            await self.queue.ack(t)
            return

        # Already finalized?
        if await self.store.is_batch_finalized(t.batch_id):
            self.metrics.inc("finalize_already_done", lbl)
            await self.store.save_idempotency(idem_key, {"ts": iso(), "status": "already_finalized"})
            await self.queue.ack(t)
            return

        # Ensure entries present
        entries = t.entries or await self.store.load_entries(t.batch_id)
        entries = self._sanitize_entries(entries)
        if not entries:
            if self.cfg.finalize_mode is FinalizeMode.STRICT:
                await self._fail_and_deadletter(t, "empty_entries")
                return
            # lenient: finalize empty batch with EMPTY root
        # Compute merkle
        merkle_root, layers = compute_merkle_root(entries)

        # Commitment
        commitment = self._make_commitment(scope=t.ledger_scope, batch_id=t.batch_id, merkle_root=merkle_root, created_at=t.created_at, count=len(entries))
        # Sign
        sign_t0 = time.monotonic()
        sig = await self.signer.sign(commitment.encode("utf-8"), digest_alg="SHA256", key_version_name=self.cfg.signer_key_version)
        self.metrics.observe("finalize_sign_latency_seconds", time.monotonic() - sign_t0, lbl)

        # Atomically persist finalization
        await self.store.mark_finalized(
            batch_id=t.batch_id,
            commitment=commitment,
            merkle_root=merkle_root,
            signature_b64=sig["signature_b64"],
            signer_key_version=sig.get("key_version") or self.cfg.signer_key_version,
            finalized_at=iso(),
            meta={
                "worker_id": self.cfg.worker_id,
                "layers": len(layers),
                "entries": len(entries),
            },
        )

        # Publish event
        await self.store.publish_event(
            topic="ledger.finalized",
            payload={
                "batch_id": t.batch_id,
                "scope": t.ledger_scope,
                "commitment": commitment,
                "merkle_root": merkle_root,
                "signature_b64": sig["signature_b64"],
                "signer_key_version": sig.get("key_version") or self.cfg.signer_key_version,
                "finalized_at": iso(),
                "entries": len(entries),
            },
        )

        # Idempotency cache store
        await self.store.save_idempotency(idem_key, {
            "batch_id": t.batch_id,
            "commitment": commitment,
            "merkle_root": merkle_root,
            "signature_b64": sig["signature_b64"],
            "ts": iso(),
        })

        # Audit
        if self.auditor:
            with contextlib.suppress(Exception):
                await self.auditor.log(
                    type="TRANSACTION",
                    severity="NOTICE",
                    actor="finalize-worker",
                    action="finalize.batch",
                    resource=f"batch:{t.batch_id}",
                    status="SUCCESS",
                    meta={"scope": t.ledger_scope, "entries": len(entries), "commitment": commitment}
                )

        # Ack
        await self.queue.ack(t)

        self.metrics.inc("finalize_success", lbl)
        self.metrics.observe("finalize_task_latency_seconds", time.monotonic() - t_start, lbl)
        self._logger.info("Finalized batch=%s entries=%d", t.batch_id, len(entries))

    # ---------- Helpers ----------

    def _sanitize_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        clean: List[Dict[str, Any]] = []
        for e in entries or []:
            try:
                # Minimal schema check
                if not isinstance(e, dict):
                    continue
                # Remove volatile fields if present
                e2 = {k: v for k, v in e.items() if k not in ("_debug", "_trace")}
                clean.append(e2)
            except Exception:
                continue
        if self.cfg.finalize_mode is FinalizeMode.STRICT and len(clean) != len(entries):
            # If strict, any malformed entry is a failure
            return []
        return clean

    def _make_commitment(self, *, scope: str, batch_id: str, merkle_root: str, created_at: str, count: int) -> str:
        parts = [scope, batch_id, merkle_root, created_at, str(count)]
        if self.cfg.commitment_salt:
            parts.append(self.cfg.commitment_salt)
        return sha256("|".join(parts))

    def _backoff_for(self, attempt: int) -> int:
        base = min(self.cfg.max_backoff_s, self.cfg.initial_backoff_s * (2 ** max(0, attempt - 1)))
        return int(rand_jitter(base))

    async def _fail_and_deadletter(self, t: FinalizeTask, reason: str) -> None:
        self.metrics.inc("finalize_dead_letter", dict(self.cfg.metrics_labels, reason=reason))
        if self.auditor:
            with contextlib.suppress(Exception):
                await self.auditor.log(
                    type="AUDIT",
                    severity="ERROR",
                    actor="finalize-worker",
                    action="finalize.deadletter",
                    resource=f"batch:{t.batch_id}",
                    status="FAILED",
                    code=reason,
                    meta={"task_id": t.task_id, "attempt": t.attempt}
                )
        await self.queue.dead_letter(t, reason=reason)

    async def _safe_nack(self, t: FinalizeTask, *, reason: str, delay_s: int) -> None:
        if t.attempt + 1 >= self.cfg.max_retries:
            await self._fail_and_deadletter(t, reason=f"{reason}:max_retries")
            return
        await self.queue.nack(dataclasses.replace(t, attempt=t.attempt + 1), delay_s=delay_s)
        self.metrics.inc("finalize_retry", dict(self.cfg.metrics_labels, reason=reason))

# ==============================
# In-memory demo implementations (for tests/dev)
# ==============================

class InMemoryQueue(TaskQueue):
    def __init__(self) -> None:
        self._q: asyncio.Queue[FinalizeTask] = asyncio.Queue()
        self._dlq: List[Tuple[FinalizeTask, str]] = []

    async def push(self, task: FinalizeTask) -> None:
        await self._q.put(task)

    async def pull(self, *, max_messages: int, visibility_timeout_s: int) -> List[FinalizeTask]:
        items: List[FinalizeTask] = []
        try:
            first = await asyncio.wait_for(self._q.get(), timeout=0.05)
        except asyncio.TimeoutError:
            return []
        items.append(first)
        for _ in range(max_messages - 1):
            if self._q.empty():
                break
            items.append(self._q.get_nowait())
        return items

    async def ack(self, task: FinalizeTask) -> None:
        # In-memory queue removes on pull; nothing to do
        return

    async def nack(self, task: FinalizeTask, *, delay_s: int) -> None:
        await asyncio.sleep(delay_s / 1000 if delay_s > 0 and delay_s < 1 else 0)
        await self._q.put(task)

    async def dead_letter(self, task: FinalizeTask, reason: str) -> None:
        self._dlq.append((task, reason))

class InMemoryStore(LedgerStore):
    def __init__(self) -> None:
        self._finalized: Dict[str, Dict[str, Any]] = {}
        self._entries: Dict[str, List[Dict[str, Any]]] = {}
        self._events: List[Dict[str, Any]] = {}
        self._idem: Dict[str, Dict[str, Any]] = {}

    async def is_batch_finalized(self, batch_id: str) -> bool:
        return batch_id in self._finalized

    async def load_entries(self, batch_id: str) -> List[Dict[str, Any]]:
        return list(self._entries.get(batch_id, []))

    async def mark_finalized(self, **kwargs: Any) -> None:
        self._finalized[kwargs["batch_id"]] = kwargs

    async def publish_event(self, *, topic: str, payload: Dict[str, Any]) -> None:
        self._events.setdefault(topic, {})
        self._events[topic][payload["batch_id"]] = payload

    async def save_idempotency(self, key: str, value: Dict[str, Any]) -> None:
        self._idem[key] = value

    async def get_idempotency(self, key: str) -> Optional[Dict[str, Any]]:
        return self._idem.get(key)

class DummySigner(Signer):
    async def sign(self, message: bytes, *, digest_alg: str = "SHA256", key_version_name: Optional[str] = None) -> Dict[str, str]:
        # Not secure; for tests only: signature = HMAC("secret", message)
        mac = hmac.new(b"secret", message, hashlib.sha256).digest()
        import base64
        return {"signature_b64": base64.b64encode(mac).decode("ascii"), "key_version": key_version_name or "dummy"}

    async def get_public_key_pem(self, *, key_version_name: Optional[str] = None) -> str:
        return "-----BEGIN PUBLIC KEY-----\nDUMMY\n-----END PUBLIC KEY-----\n"

# ==============================
# CLI self-test
# ==============================

async def _selftest() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    queue = InMemoryQueue()
    store = InMemoryStore()
    signer = DummySigner()
    cfg = FinalizeWorkerConfig(concurrency=2, finalize_mode=FinalizeMode.STRICT)

    # Seed entries
    batch_id = "batch-001"
    store._entries[batch_id] = [{"txid": "t1", "amount": "10"}, {"txid": "t2", "amount": "25"}]
    task = FinalizeTask(task_id=gen_uuid(), batch_id=batch_id, ledger_scope="testnet", entries=[], created_at=iso())

    await queue.push(task)

    worker = FinalizeWorker(cfg=cfg, queue=queue, store=store, signer=signer, auditor=None, metrics=_NoopMetrics())
    await worker.start()

    # Wait for processing
    await asyncio.sleep(1.0)
    await worker.stop()

    # Check finalized
    assert await store.is_batch_finalized(batch_id), "Batch not finalized in selftest"
    print("Selftest OK")
    return 0

if __name__ == "__main__":
    try:
        rc = asyncio.run(_selftest())
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)
