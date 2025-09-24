# oblivionvault-core/oblivionvault/workers/erasure_worker.py
# -*- coding: utf-8 -*-
"""
OblivionVault — Industrial Erasure Worker

Назначение:
  Асинхронный воркер безопасного стирания, уважающий Retention/Legal Hold.

Ключевые возможности:
  - Методы стирания: logical, purge, shred(N passes), crypto-erase (уничтожение ключа)
  - Строгая проверка Retention/Legal Hold через RetentionLockManager.assert_delete_allowed
  - Аудит (append-only hash chain) через StorageBackend.append_audit
  - Идемпотентность: tombstone-реестр не даёт повторно стирать уже стертое
  - Файловая очередь задач с атомарным claim/ack/nack (rename)
  - Ретраи: экспоненциальная задержка с джиттером, poison-склад
  - Конкурентная обработка (asyncio.Semaphore), graceful shutdown (SIGTERM/SIGINT)
  - Метрики и health-пробки

Только стандартная библиотека Python.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import datetime as dt
import json
import logging
import math
import os
import random
import signal
import stat
import time
import unicodedata
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple, Union

# Импорт подсистем архивирования/аудита
from ..archive.retention_lock import (
    RetentionLockManager,
    StorageBackend,
    IntegrityError,
    LegalHoldActive,
    ComplianceLockActive,
    PolicyViolation,
)

# =========================
# Исключения
# =========================

class ErasureError(Exception):
    """Базовая ошибка воркера стирания."""

class QueueEmpty(Exception):
    """Очередь пуста."""

class QueueError(ErasureError):
    """Ошибка очереди задач."""

class TombstoneError(ErasureError):
    """Ошибка работы с tombstone."""

class CryptoEraseError(ErasureError):
    """Ошибка криптографического стирания."""

# =========================
# Типы и модели
# =========================

class ErasureMethod(str, Enum):
    LOGICAL = "logical"        # логическое удаление (контент стерт, метаданные/маркеры сохранены)
    PURGE = "purge"            # полное удаление всех версий объекта
    SHRED = "shred"            # перезапись и удаление
    CRYPTO_ERASE = "crypto_erase"  # уничтожение ключа шифрования

@dataclass(frozen=True)
class ErasureRequest:
    object_id: str
    method: ErasureMethod
    actor: str
    reason: str
    requested_at: float
    deadline: Optional[float] = None
    tags: Tuple[str, ...] = ()
    shred_passes: int = 3
    shred_block_size: int = 1024 * 1024
    crypto_key_id: Optional[str] = None
    trace_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()))

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "ErasureRequest":
        return ErasureRequest(
            object_id=str(d["object_id"]),
            method=ErasureMethod(str(d["method"])),
            actor=str(d["actor"]),
            reason=str(d.get("reason", "")),
            requested_at=float(d.get("requested_at", time.time())),
            deadline=float(d["deadline"]) if d.get("deadline") is not None else None,
            tags=tuple(d.get("tags", []) or ()),
            shred_passes=int(d.get("shred_passes", 3)),
            shred_block_size=int(d.get("shred_block_size", 1024*1024)),
            crypto_key_id=(str(d["crypto_key_id"]) if d.get("crypto_key_id") else None),
            trace_id=str(d.get("trace_id") or str(uuid.uuid4())),
        )

    def to_dict(self) -> Dict[str, Any]:
        x = asdict(self)
        x["method"] = self.method.value
        return x

@dataclass(frozen=True)
class ErasureResult:
    ok: bool
    object_id: str
    method: ErasureMethod
    attempts: int
    trace_id: str
    message: str
    finished_at: float

# =========================
# Адаптеры: хранилище контента и ключей
# =========================

class BlobStore(Protocol):
    """
    Абстракция доступа к блобам для операций purge/shred/logical.
    """
    async def exists(self, object_id: str) -> bool: ...
    async def resolve_path(self, object_id: str) -> Optional[Path]: ...
    async def logical_delete(self, object_id: str) -> None: ...
    async def purge(self, object_id: str) -> None: ...
    async def shred(self, object_id: str, passes: int, block_size: int) -> None: ...

class FileBlobStore:
    """
    Файловая реализация блоб-хранилища.
    Layout:
      root/
        objects/{hash(object_id)[:2]}/{hash}.blob
        meta/{hash}.json
      При logical_delete() контент стирается (shred 1 pass zero fill) и ставится tombstone в meta.
    """
    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root)
        self.obj_dir = self.root / "objects"
        self.meta_dir = self.root / "meta"
        self.obj_dir.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)

    def _safe_name(self, object_id: str) -> str:
        return uuid.uuid5(uuid.NAMESPACE_URL, f"oblivionvault:{object_id}").hex

    def _obj_path(self, object_id: str) -> Path:
        hid = self._safe_name(object_id)
        sub = hid[:2]
        d = self.obj_dir / sub
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{hid}.blob"

    def _meta_path(self, object_id: str) -> Path:
        hid = self._safe_name(object_id)
        return self.meta_dir / f"{hid}.json"

    async def exists(self, object_id: str) -> bool:
        return await asyncio.to_thread(self._obj_path(object_id).exists)

    async def resolve_path(self, object_id: str) -> Optional[Path]:
        p = self._obj_path(object_id)
        return p if await asyncio.to_thread(p.exists) else None

    async def _write_json_atomic(self, path: Path, payload: Mapping[str, Any]) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        def _w() -> None:
            tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, path)
        await asyncio.to_thread(_w)

    async def logical_delete(self, object_id: str) -> None:
        # Стираем контент нулями 1 проход, затем записываем tombstone мету
        p = self._obj_path(object_id)
        if await asyncio.to_thread(p.exists):
            await asyncio.to_thread(_zero_fill_and_unlink, p, 1, 1024 * 1024)
        meta = self._meta_path(object_id)
        await self._write_json_atomic(meta, {"tombstone": True, "object_id": object_id, "ts": time.time(), "mode": "logical"})

    async def purge(self, object_id: str) -> None:
        p = self._obj_path(object_id)
        with contextlib.suppress(FileNotFoundError):
            await asyncio.to_thread(p.unlink)
        meta = self._meta_path(object_id)
        await self._write_json_atomic(meta, {"tombstone": True, "object_id": object_id, "ts": time.time(), "mode": "purge"})

    async def shred(self, object_id: str, passes: int, block_size: int) -> None:
        p = self._obj_path(object_id)
        if await asyncio.to_thread(p.exists):
            await asyncio.to_thread(_zero_fill_and_unlink, p, passes, block_size)
        meta = self._meta_path(object_id)
        await self._write_json_atomic(meta, {"tombstone": True, "object_id": object_id, "ts": time.time(), "mode": "shred", "passes": passes})

def _zero_fill_and_unlink(path: Path, passes: int, block_size: int) -> None:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return
    try:
        with open(path, "r+b", buffering=0) as f:
            for i in range(max(1, passes)):
                f.seek(0)
                remaining = size
                zero = b"\x00" * block_size
                while remaining > 0:
                    w = min(block_size, remaining)
                    f.write(zero[:w])
                    remaining -= w
                f.flush()
                os.fsync(f.fileno())
        os.replace(path, path.with_suffix(".deleted"))
        (path.with_suffix(".deleted")).unlink(missing_ok=True)
    except FileNotFoundError:
        return

class KeyVault(Protocol):
    """Абстракция управления ключами шифрования для crypto-erase."""
    async def revoke_key(self, key_id: str) -> None: ...
    async def is_revoked(self, key_id: str) -> bool: ...

class InMemoryKeyVault:
    def __init__(self) -> None:
        self._revoked: set[str] = set()

    async def revoke_key(self, key_id: str) -> None:
        self._revoked.add(key_id)

    async def is_revoked(self, key_id: str) -> bool:
        return key_id in self._revoked

# =========================
# Tombstone-реестр (идемпотентность)
# =========================

class TombstoneRegistry:
    """
    Реестр уже стертых объектов (идемпотентность).
    Реализован как файловый каталог tombstones/{hash}.json
    """
    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root)
        self.dir = self.root / "tombstones"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, object_id: str) -> Path:
        hid = uuid.uuid5(uuid.NAMESPACE_URL, f"oblivionvault:{object_id}").hex
        return self.dir / f"{hid}.json"

    async def has(self, object_id: str) -> bool:
        return await asyncio.to_thread(self._path(object_id).exists)

    async def write(self, object_id: str, payload: Mapping[str, Any]) -> None:
        p = self._path(object_id)
        tmp = p.with_suffix(".tmp")
        def _w() -> None:
            tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, p)
        await asyncio.to_thread(_w)

# =========================
# Очередь задач (файловая)
# =========================

class ErasureQueue(Protocol):
    async def push(self, req: ErasureRequest) -> None: ...
    async def claim(self) -> Tuple[ErasureRequest, Path]: ...
    async def ack(self, receipt: Path) -> None: ...
    async def nack(self, receipt: Path, *, requeue: bool, to_dead: bool) -> None: ...

class FileErasureQueue:
    """
    Файловая очередь с атомарным перемещением:
      queue/
        incoming/*.json
        processing/*.json
        dead/*.json
    """
    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root)
        self.incoming = self.root / "incoming"
        self.processing = self.root / "processing"
        self.dead = self.root / "dead"
        for d in (self.incoming, self.processing, self.dead):
            d.mkdir(parents=True, exist_ok=True)
        self._io_lock = asyncio.Lock()

    async def push(self, req: ErasureRequest) -> None:
        body = json.dumps(req.to_dict(), ensure_ascii=False, separators=(",", ":"))
        name = f"{int(time.time()*1000)}_{req.trace_id}.json"
        tmp = self.incoming / f".{name}.tmp"
        dst = self.incoming / name
        def _w() -> None:
            tmp.write_text(body, encoding="utf-8")
            os.replace(tmp, dst)
        async with self._io_lock:
            await asyncio.to_thread(_w)

    async def _list_incoming(self) -> List[Path]:
        return sorted(self.incoming.glob("*.json"))

    async def claim(self) -> Tuple[ErasureRequest, Path]:
        async with self._io_lock:
            files = await self._list_incoming()
            if not files:
                raise QueueEmpty("No tasks")
            f = files[0]
            dst = self.processing / f.name
            # атомарный захват
            await asyncio.to_thread(os.replace, f, dst)
            data = await asyncio.to_thread(dst.read_text, "utf-8")
            req = ErasureRequest.from_dict(json.loads(data))
            return req, dst

    async def ack(self, receipt: Path) -> None:
        async with self._io_lock:
            with contextlib.suppress(FileNotFoundError):
                await asyncio.to_thread(receipt.unlink)

    async def nack(self, receipt: Path, *, requeue: bool, to_dead: bool) -> None:
        async with self._io_lock:
            if to_dead:
                dst = self.dead / receipt.name
                with contextlib.suppress(FileNotFoundError):
                    await asyncio.to_thread(os.replace, receipt, dst)
                return
            if requeue:
                dst = self.incoming / receipt.name
                with contextlib.suppress(FileNotFoundError):
                    await asyncio.to_thread(os.replace, receipt, dst)
                return
            # иначе просто удалить
            with contextlib.suppress(FileNotFoundError):
                await asyncio.to_thread(receipt.unlink)

# =========================
# Конфигурация и метрики
# =========================

@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay: float = 0.5
    max_delay: float = 30.0
    jitter: float = 0.25  # 25% джиттер

@dataclass
class WorkerConfig:
    concurrency: int = 4
    retry: RetryPolicy = dataclasses.field(default_factory=RetryPolicy)
    queue_poll_interval: float = 0.5
    health_ttl: float = 30.0

@dataclass
class Metrics:
    processed: int = 0
    succeeded: int = 0
    failed: int = 0
    retried: int = 0
    skipped_idempotent: int = 0
    retention_blocked: int = 0

# =========================
# Воркер
# =========================

class ErasureWorker:
    """
    Промышленный асинхронный воркер стирания.

    Основной сценарий:
      1) claim() из очереди
      2) проверка deadline и идемпотентности (tombstone)
      3) RetentionLockManager.assert_delete_allowed()
      4) исполнение метода (logical/purge/shred/crypto_erase)
      5) аудит append
      6) tombstone write
      7) ack/nack

    Потоковая безопасность обеспечивается очередью и семафором concurrency.
    """

    def __init__(
        self,
        *,
        queue: ErasureQueue,
        blob_store: BlobStore,
        key_vault: KeyVault,
        tombstones: TombstoneRegistry,
        retention: RetentionLockManager,
        audit_backend: StorageBackend,
        config: Optional[WorkerConfig] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.queue = queue
        self.blobs = blob_store
        self.kv = key_vault
        self.ts = tombstones
        self.retention = retention
        self.audit = audit_backend
        self.cfg = config or WorkerConfig()
        self.log = logger or logging.getLogger(__name__)
        self._stop = asyncio.Event()
        self._sem = asyncio.Semaphore(self.cfg.concurrency)
        self._metrics = Metrics()
        self._last_heartbeat = time.time()
        self._tasks: List[asyncio.Task] = []

    # ---------- Health ----------
    def health(self) -> Mapping[str, Any]:
        return {
            "alive": not self._stop.is_set(),
            "last_heartbeat": self._last_heartbeat,
            "processed": self._metrics.processed,
            "succeeded": self._metrics.succeeded,
            "failed": self._metrics.failed,
            "retried": self._metrics.retried,
            "skipped_idempotent": self._metrics.skipped_idempotent,
            "retention_blocked": self._metrics.retention_blocked,
        }

    # ---------- Lifecycle ----------
    async def start(self) -> None:
        self._install_signal_handlers()
        self.log.info("ErasureWorker starting with concurrency=%d", self.cfg.concurrency)
        for _ in range(self.cfg.concurrency):
            t = asyncio.create_task(self._run_loop(), name=f"erasure-worker-{_}")
            self._tasks.append(t)

    async def stop(self) -> None:
        self.log.info("ErasureWorker stopping...")
        self._stop.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t
        self._tasks.clear()

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self._on_signal(s)))

    async def _on_signal(self, sig: signal.Signals) -> None:
        self.log.warning("Received signal %s; initiating graceful shutdown", sig.name)
        await self.stop()

    # ---------- Main loop ----------
    async def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                async with self._sem:
                    try:
                        req, receipt = await self.queue.claim()
                    except QueueEmpty:
                        await asyncio.sleep(self.cfg.queue_poll_interval)
                        continue
                    await self._process(req, receipt)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.log.exception("Worker loop error: %s", e)
                await asyncio.sleep(0.2)

    # ---------- Processing ----------
    async def _process(self, req: ErasureRequest, receipt: Path) -> None:
        self._last_heartbeat = time.time()
        attempts = 0
        try:
            # deadline
            if req.deadline and time.time() > req.deadline:
                self.log.warning("Expired task %s; moving to dead", req.trace_id)
                await self.queue.nack(receipt, requeue=False, to_dead=True)
                self._metrics.failed += 1
                return

            # идемпотентность
            if await self.ts.has(req.object_id):
                self.log.info("Idempotent skip for %s (%s)", req.object_id, req.trace_id)
                await self._audit(req, "erasure_skip_idempotent", {"method": req.method.value})
                await self.queue.ack(receipt)
                self._metrics.skipped_idempotent += 1
                self._metrics.processed += 1
                return

            # retry loop
            while True:
                attempts += 1
                try:
                    await self._handle_request(req)
                    await self._audit(req, "erasure_success", {"method": req.method.value, "attempts": attempts})
                    await self.ts.write(req.object_id, {
                        "object_id": req.object_id,
                        "method": req.method.value,
                        "trace_id": req.trace_id,
                        "ts": time.time(),
                    })
                    await self.queue.ack(receipt)
                    self._metrics.succeeded += 1
                    self._metrics.processed += 1
                    return
                except (LegalHoldActive, ComplianceLockActive, PolicyViolation) as e:
                    self._metrics.retention_blocked += 1
                    self.log.warning("Retention blocked %s (%s): %s", req.object_id, req.trace_id, e)
                    await self._audit(req, "erasure_blocked_retention", {"error": str(e)})
                    # Не ретраим — политика запрещает
                    await self.queue.nack(receipt, requeue=False, to_dead=True)
                    self._metrics.failed += 1
                    self._metrics.processed += 1
                    return
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    # Ретраи
                    if attempts >= self.cfg.retry.max_attempts:
                        self.log.error("Erasure failed %s after %d attempts: %s", req.trace_id, attempts, e)
                        await self._audit(req, "erasure_failed", {"error": str(e), "attempts": attempts})
                        await self.queue.nack(receipt, requeue=False, to_dead=True)
                        self._metrics.failed += 1
                        self._metrics.processed += 1
                        return
                    delay = self._retry_backoff_delay(attempts)
                    self._metrics.retried += 1
                    self.log.warning("Erasure attempt %d failed (%s): %s. Retry in %.2fs", attempts, req.trace_id, e, delay)
                    await asyncio.sleep(delay)

        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                await self.queue.nack(receipt, requeue=True, to_dead=False)
            raise
        except Exception as e:
            self.log.exception("Fatal processing error %s: %s", req.trace_id, e)
            with contextlib.suppress(Exception):
                await self.queue.nack(receipt, requeue=False, to_dead=True)
            self._metrics.failed += 1
            self._metrics.processed += 1

    # ---------- Single request ----------
    async def _handle_request(self, req: ErasureRequest) -> None:
        # 1) Проверка Retention
        await self.retention.assert_delete_allowed(req.object_id)

        # 2) Исполнение метода
        if req.method is ErasureMethod.LOGICAL:
            await self._erase_logical(req)
        elif req.method is ErasureMethod.PURGE:
            await self._erase_purge(req)
        elif req.method is ErasureMethod.SHRED:
            await self._erase_shred(req)
        elif req.method is ErasureMethod.CRYPTO_ERASE:
            await self._erase_crypto(req)
        else:
            raise ErasureError(f"Unsupported method {req.method}")

    async def _erase_logical(self, req: ErasureRequest) -> None:
        await self.blobs.logical_delete(req.object_id)

    async def _erase_purge(self, req: ErasureRequest) -> None:
        await self.blobs.purge(req.object_id)

    async def _erase_shred(self, req: ErasureRequest) -> None:
        passes = max(1, req.shred_passes)
        block = max(4096, req.shred_block_size)
        await self.blobs.shred(req.object_id, passes=passes, block_size=block)

    async def _erase_crypto(self, req: ErasureRequest) -> None:
        key_id = req.crypto_key_id
        if not key_id:
            raise CryptoEraseError("crypto_key_id is required for crypto_erase")
        await self.kv.revoke_key(key_id)

    # ---------- Аудит ----------
    async def _audit(self, req: ErasureRequest, action: str, details: Mapping[str, Any]) -> None:
        payload = {
            "method": req.method.value,
            "reason": req.reason,
            "tags": list(req.tags),
            "trace_id": req.trace_id,
            **details,
        }
        await self.audit.append_audit(
            # Reuse storage audit trail per object
            event=type("E", (), {})()  # временный объект, но используем совместимый интерфейс
        )  # type: ignore  # Мы не можем напрямую создавать AuditEvent без импорта. Вместо этого ниже нормальная реализация.

# Исправление для _audit: создадим совместимый адаптер к StorageBackend.append_audit с явным импортом AuditEvent
from ..archive.retention_lock import AuditEvent as _AuditEvent, _utc_now as _utc_now_rl  # type: ignore

def _make_audit_event(actor: str, action: str, object_id: str, details: Mapping[str, Any]) -> _AuditEvent:
    return _AuditEvent(
        ts=_utc_now_rl().timestamp(),  # точность к RetentionLockManager
        actor=actor,
        action=action,
        object_id=object_id,
        details=dict(details),
        prev_hash=None,  # StorageBackend.append_audit свяжет prev_hash при записи.
    )

# Переопределим метод с правильной реализацией после импорта вспомогательных сущностей.
def _worker_audit_impl(self: ErasureWorker, req: ErasureRequest, action: str, details: Mapping[str, Any]) -> asyncio.Future:
    ev = _make_audit_event(actor=req.actor, action=action, object_id=req.object_id, details=details)
    # StorageBackend.append_audit ожидает AuditEvent
    return asyncio.create_task(self.audit.append_audit(ev))  # type: ignore

ErasureWorker._audit = _worker_audit_impl  # type: ignore

# ---------- Утилита вычисления задержки ретрая ----------
def _cap(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def _jitter(delay: float, jitter: float) -> float:
    if jitter <= 0:
        return delay
    spread = delay * jitter
    return _cap(delay + random.uniform(-spread, spread), 0.0, delay + spread)

def _pow2(n: int) -> float:
    return 2.0 ** max(0, n - 1)

def _retry_backoff_delay_static(attempt: int, base: float, max_delay: float, jitter: float) -> float:
    raw = base * _pow2(attempt)
    return _cap(_jitter(raw, jitter), base, max_delay)

def _worker_backoff(self: ErasureWorker, attempt: int) -> float:
    r = self.cfg.retry
    return _retry_backoff_delay_static(attempt, r.base_delay, r.max_delay, r.jitter)

ErasureWorker._retry_backoff_delay = _worker_backoff  # type: ignore

# =========================
# Утилиты построения воркера по умолчанию
# =========================

@dataclass
class DefaultPaths:
    queue_dir: Path
    blobs_dir: Path
    tombstones_dir: Path

def build_default_worker(
    *,
    retention_manager: RetentionLockManager,
    storage_backend: StorageBackend,
    paths: DefaultPaths,
    key_vault: Optional[KeyVault] = None,
    config: Optional[WorkerConfig] = None,
    logger: Optional[logging.Logger] = None,
) -> ErasureWorker:
    """
    Фабрика воркера по умолчанию на файловых адаптерах.
    """
    queue = FileErasureQueue(paths.queue_dir)
    blobs = FileBlobStore(paths.blobs_dir)
    kv = key_vault or InMemoryKeyVault()
    tombs = TombstoneRegistry(paths.tombstones_dir)
    return ErasureWorker(
        queue=queue,
        blob_store=blobs,
        key_vault=kv,
        tombstones=tombs,
        retention=retention_manager,
        audit_backend=storage_backend,
        config=config or WorkerConfig(),
        logger=logger or logging.getLogger("oblivionvault.erasure"),
    )

__all__ = [
    "ErasureWorker",
    "ErasureMethod",
    "ErasureRequest",
    "ErasureResult",
    "ErasureQueue",
    "FileErasureQueue",
    "BlobStore",
    "FileBlobStore",
    "KeyVault",
    "InMemoryKeyVault",
    "TombstoneRegistry",
    "RetryPolicy",
    "WorkerConfig",
    "Metrics",
    "DefaultPaths",
    "build_default_worker",
]
