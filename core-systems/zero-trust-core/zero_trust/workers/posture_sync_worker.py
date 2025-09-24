# path: zero-trust-core/zero_trust/workers/posture_sync_worker.py
# -*- coding: utf-8 -*-
"""
Posture Sync Worker for Zero-Trust Core
Industrial-grade, async, resilient, observable.

Features:
- Async pipeline: fetch -> validate -> dedup -> concurrent submit -> commit
- Backoff with jitter, bounded retries, graceful degradation
- TTL rolling deduplication (idempotency window)
- Checkpoint/Bookmark persistence (atomic fs write)
- Structured JSON logging with sensitive redaction
- Health/Ready probes and runtime stats
- Metrics/Tracing via Protocols (dependency injection)
- ENV-driven configuration with sane defaults
- Clean shutdown on SIGINT/SIGTERM

Dependencies:
- Python 3.11+
- pydantic>=2.6
- httpx>=0.27 (transitively via CASB adapter if used)

This worker expects a CASBAdapter compatible with:
  zero_trust.adapters.casb_adapter.GenericRESTCASBAdapter
and domain models DevicePosture, Metrics, Tracer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import random
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, Mapping, Optional, Protocol, Sequence, Tuple

try:
    from pydantic import BaseModel, Field, ValidationError
except Exception as e:  # pragma: no cover
    raise ImportError("pydantic v2 is required: pip install pydantic>=2.6") from e

# Import shared domain/adapter types
try:
    from zero_trust.adapters.casb_adapter import (
        DevicePosture,
        Metrics,
        Tracer,
        CASBConfig,
        GenericRESTCASBAdapter,
        CASBAdapter,
        CASBRateLimitError,
        CASBCircuitOpenError,
        CASBError,
    )
except Exception as e:  # pragma: no cover
    raise ImportError(
        "Expected zero_trust.adapters.casb_adapter with DevicePosture, CASBAdapter, GenericRESTCASBAdapter"
    ) from e


# ------------------------- Logging -------------------------

_LOG = logging.getLogger("zero_trust.posture_sync_worker")
if not _LOG.handlers:
    _h = logging.StreamHandler()
    _f = logging.Formatter(fmt='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":%(message)s}', datefmt="%Y-%m-%dT%H:%M:%S%z")
    _h.setFormatter(_f)
    _LOG.addHandler(_h)
_LOG.setLevel(logging.INFO)


def _j(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return json.dumps({"repr": repr(obj)}, ensure_ascii=False)


def _redact(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


# ------------------------- Config -------------------------

@dataclass(frozen=True)
class WorkerConfig:
    interval_sec: float = 5.0
    batch_size: int = 200
    concurrency: int = 8
    max_retries: int = 4
    backoff_base_sec: float = 0.5
    backoff_max_sec: float = 20.0
    dedup_ttl_sec: float = 600.0
    bookmark_path: Path = Path(os.getenv("ZT_WORKER_BOOKMARK_PATH", ".posture_bookmark.json"))
    health_port: Optional[int] = None  # reserved for future HTTP health
    provider_kind: str = os.getenv("ZT_POSTURE_PROVIDER", "null")  # e.g., "null" or custom
    # commit every N successfully sent records to reduce fs churn
    commit_interval_records: int = 200

    @staticmethod
    def from_env() -> "WorkerConfig":
        def g(name: str, default: Optional[str] = None) -> Optional[str]:
            return os.getenv(name, default)
        return WorkerConfig(
            interval_sec=float(g("ZT_WORKER_INTERVAL_SEC", "5")),
            batch_size=int(g("ZT_WORKER_BATCH_SIZE", "200")),
            concurrency=int(g("ZT_WORKER_CONCURRENCY", "8")),
            max_retries=int(g("ZT_WORKER_MAX_RETRIES", "4")),
            backoff_base_sec=float(g("ZT_WORKER_BACKOFF_BASE_SEC", "0.5")),
            backoff_max_sec=float(g("ZT_WORKER_BACKOFF_MAX_SEC", "20")),
            dedup_ttl_sec=float(g("ZT_WORKER_DEDUP_TTL_SEC", "600")),
            bookmark_path=Path(g("ZT_WORKER_BOOKMARK_PATH", ".posture_bookmark.json")),
            health_port=int(g("ZT_WORKER_HEALTH_PORT", "0")) or None,
            provider_kind=g("ZT_POSTURE_PROVIDER", "null") or "null",
            commit_interval_records=int(g("ZT_WORKER_COMMIT_INTERVAL", "200")),
        )


# ------------------------- Provider Protocol -------------------------

class PostureProvider(Protocol):
    """
    Abstract provider of device posture records.
    Implementations may pull from MDM/EDR/SIEM, files, streams, etc.
    """
    name: str

    async def fetch(self, since: Optional[datetime], limit: int) -> Sequence[DevicePosture]:
        """
        Return up to `limit` new DevicePosture items newer than `since` (UTC).
        Must be idempotent and safe to call repeatedly.
        """
        ...


class NullPostureProvider:
    """No-op provider; useful for dry runs."""
    name = "null"

    async def fetch(self, since: Optional[datetime], limit: int) -> Sequence[DevicePosture]:
        await asyncio.sleep(0.1)
        return []


# ------------------------- Bookmark Store -------------------------

class Bookmark(BaseModel):
    last_success_iso: Optional[str] = None  # ISO timestamp of last successful processed posture


class BookmarkStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._state = Bookmark()

    async def load(self) -> None:
        async with self._lock:
            if self._path.exists():
                try:
                    data = json.loads(self._path.read_text(encoding="utf-8"))
                    self._state = Bookmark(**data)
                except Exception:
                    _LOG.warning(_j({"event": "bookmark_load_failed"}))

    async def get_since(self) -> Optional[datetime]:
        async with self._lock:
            if not self._state.last_success_iso:
                return None
            try:
                return datetime.fromisoformat(self._state.last_success_iso.replace("Z", "+00:00")).astimezone(timezone.utc)
            except Exception:
                return None

    async def commit(self, dt: datetime) -> None:
        iso = dt.astimezone(timezone.utc).isoformat()
        async with self._lock:
            self._state.last_success_iso = iso
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            try:
                tmp.write_text(self._state.model_dump_json(), encoding="utf-8")
                tmp.replace(self._path)
            finally:
                try:
                    if tmp.exists():
                        tmp.unlink(missing_ok=True)
                except Exception:
                    pass


# ------------------------- Rolling TTL Deduper -------------------------

class RollingDeduper:
    """
    Simple TTL deduper: remembers composite keys during idempotency window.
    """
    def __init__(self, ttl_sec: float) -> None:
        self._ttl = ttl_sec
        self._data: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def key(device_id: str, assessed_at: datetime, posture: Mapping[str, Any]) -> str:
        # Compute compact, order-insensitive digest
        try:
            # canonicalize posture by dumping with sorted keys
            payload = json.dumps(posture, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            payload = repr(posture)
        stamp = int(assessed_at.timestamp())
        # lightweight hash: FNV-1a like on utf-8 bytes
        h = 2166136261
        for b in (f"{device_id}|{stamp}|{payload}").encode("utf-8", errors="ignore"):
            h ^= b
            h = (h * 16777619) & 0xFFFFFFFF
        return f"{device_id}:{stamp}:{h:08x}"

    async def seen(self, k: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            self._evict(now)
            return k in self._data

    async def add(self, k: str) -> None:
        now = time.monotonic()
        async with self._lock:
            self._evict(now)
            self._data[k] = now

    def _evict(self, now: float) -> None:
        ttl = self._ttl
        if not self._data:
            return
        stale = [k for k, t in self._data.items() if (now - t) > ttl]
        for k in stale:
            self._data.pop(k, None)


# ------------------------- Worker -------------------------

class PostureSyncWorker:
    def __init__(
        self,
        adapter: CASBAdapter,
        provider: PostureProvider,
        config: WorkerConfig,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
    ) -> None:
        self.adapter = adapter
        self.provider = provider
        self.cfg = config
        self.metrics = metrics
        self.tracer = tracer
        self.bookmarks = BookmarkStore(config.bookmark_path)
        self.deduper = RollingDeduper(config.dedup_ttl_sec)
        self._stop = asyncio.Event()
        self._inflight = 0
        self._last_health_ok = True
        self._processed_since_commit = 0

    # ---------- lifecycle ----------

    def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        await self.bookmarks.load()
        _LOG.info(_j({"event": "worker_started", "provider": self.provider.name, "cfg": {
            "interval_sec": self.cfg.interval_sec,
            "batch_size": self.cfg.batch_size,
            "concurrency": self.cfg.concurrency,
        }}))
        try:
            while not self._stop.is_set():
                await self._cycle()
                await asyncio.wait_for(self._stop.wait(), timeout=self._with_jitter(self.cfg.interval_sec))
        except asyncio.TimeoutError:
            # normal wakeup
            pass
        except asyncio.CancelledError:
            _LOG.info(_j({"event": "worker_cancelled"}))
        finally:
            _LOG.info(_j({"event": "worker_stopped"}))

    # ---------- single cycle ----------

    async def _cycle(self) -> None:
        # probe CASB health (cached in adapter)
        health_ok = await self.adapter.health_check()
        self._last_health_ok = health_ok
        if not health_ok:
            if self.metrics:
                self.metrics.gauge("posture.casb_health", 0.0)
            _LOG.warning(_j({"event": "casb_unhealthy"}))
        else:
            if self.metrics:
                self.metrics.gauge("posture.casb_health", 1.0)

        since = await self.bookmarks.get_since()
        try:
            items = await self.provider.fetch(since=since, limit=self.cfg.batch_size)
        except Exception as e:
            _LOG.error(_j({"event": "provider_fetch_failed", "error": repr(e)}))
            if self.metrics:
                self.metrics.increment("posture.provider_fetch_failed")
            await self._sleep_backoff(1)  # minor pause before next loop
            return

        if not items:
            if self.metrics:
                self.metrics.gauge("posture.fetched", 0.0)
            _LOG.info(_j({"event": "no_items"}))
            return

        if self.metrics:
            self.metrics.gauge("posture.fetched", float(len(items)))

        # validate and dedup
        valid: list[DevicePosture] = []
        latest_ts: Optional[datetime] = since
        for p in items:
            try:
                model = DevicePosture(**p.model_dump()) if isinstance(p, DevicePosture) else DevicePosture(**p)  # type: ignore[arg-type]
            except ValidationError as ve:
                _LOG.warning(_j({"event": "posture_validation_failed", "error": str(ve)[:300]}))
                if self.metrics:
                    self.metrics.increment("posture.validation_failed")
                continue

            key = RollingDeduper.key(model.device_id, model.assessed_at, model.posture)
            if await self.deduper.seen(key):
                if self.metrics:
                    self.metrics.increment("posture.dedup_hit")
                continue
            await self.deduper.add(key)
            valid.append(model)
            if latest_ts is None or model.assessed_at > latest_ts:
                latest_ts = model.assessed_at

        if not valid:
            _LOG.info(_j({"event": "all_deduped_or_invalid"}))
            return

        # concurrent submit with bounded semaphore
        sem = asyncio.Semaphore(self.cfg.concurrency)
        results: list[bool] = []

        async def submit_one(dp: DevicePosture) -> None:
            nonlocal results
            async with sem:
                ok = await self._submit_with_retries(dp)
                results.append(ok)

        await asyncio.gather(*(submit_one(dp) for dp in valid))

        sent = sum(1 for r in results if r)
        failed = len(results) - sent
        if self.metrics:
            self.metrics.gauge("posture.sent", float(sent))
            self.metrics.gauge("posture.failed", float(failed))
        _LOG.info(_j({"event": "batch_done", "sent": sent, "failed": failed}))

        # commit bookmark if we successfully sent at least one and have newer ts
        if sent > 0 and latest_ts:
            self._processed_since_commit += sent
            if self._processed_since_commit >= self.cfg.commit_interval_records:
                await self.bookmarks.commit(latest_ts)
                self._processed_since_commit = 0
                _LOG.info(_j({"event": "bookmark_committed", "last_success_iso": latest_ts.astimezone(timezone.utc).isoformat()}))

    # ---------- submit with retry/backoff ----------

    async def _submit_with_retries(self, dp: DevicePosture) -> bool:
        maxr = self.cfg.max_retries
        base = self.cfg.backoff_base_sec
        for attempt in range(maxr + 1):
            t0 = time.perf_counter()
            try:
                await self.adapter.submit_device_posture(dp)
                dt = time.perf_counter() - t0
                if self.metrics:
                    self.metrics.observe("posture.submit_latency_sec", dt, {"ok": "true"})
                _LOG.info(_j({
                    "event": "posture_submitted",
                    "device_id": _redact(dp.device_id),
                    "assessed_at": dp.assessed_at.isoformat(),
                }))
                return True
            except (CASBRateLimitError, CASBCircuitOpenError) as e:
                if attempt >= maxr:
                    self._log_submit_fail(dp, e, attempt)
                    if self.metrics:
                        self.metrics.increment("posture.submit_rate_limited")
                    return False
                await self._sleep_backoff(attempt, base)
            except (CASBError, Exception) as e:
                # network and generic errors
                if attempt >= maxr:
                    self._log_submit_fail(dp, e, attempt)
                    if self.metrics:
                        self.metrics.increment("posture.submit_failed")
                    return False
                await self._sleep_backoff(attempt, base)

    async def _sleep_backoff(self, attempt: int, base: Optional[float] = None) -> None:
        b = self.cfg.backoff_base_sec if base is None else base
        # exponential backoff with decorrelated jitter
        sleep = min(self.cfg.backoff_max_sec, b * (2 ** attempt)) * (0.5 + random.random() * 0.75)
        await asyncio.sleep(sleep)

    def _log_submit_fail(self, dp: DevicePosture, err: Exception, attempt: int) -> None:
        _LOG.error(_j({
            "event": "posture_submit_failed",
            "device_id": _redact(dp.device_id),
            "attempt": attempt,
            "error": repr(err),
        }))

    # ---------- health ----------

    async def health(self) -> Dict[str, Any]:
        return {
            "ok": self._last_health_ok,
            "provider": self.provider.name,
            "concurrency": self.cfg.concurrency,
            "interval_sec": self.cfg.interval_sec,
            "inflight": self._inflight,
        }


# ------------------------- Wiring / CLI -------------------------

async def _build_adapter_and_provider(cfg: WorkerConfig) -> Tuple[CASBAdapter, PostureProvider]:
    # CASB adapter from ENV (see CASBConfig.from_env)
    casb_cfg = CASBConfig.from_env(prefix=os.getenv("CASB_PREFIX", "CASB_"))
    adapter = GenericRESTCASBAdapter(casb_cfg)

    # Provider selection (extend with your own kinds)
    kind = (cfg.provider_kind or "null").lower()
    if kind == "null":
        provider: PostureProvider = NullPostureProvider()
    else:
        # Placeholder for custom discovery, can be replaced with importlib-based factory
        provider = NullPostureProvider()
        _LOG.warning(_j({"event": "unknown_provider_kind", "kind": kind, "fallback": "null"}))

    return adapter, provider


async def _amain() -> int:
    # Basic logging level from env
    level = os.getenv("ZT_LOG_LEVEL", "INFO").upper()
    try:
        _LOG.setLevel(getattr(logging, level))
    except Exception:
        pass

    cfg = WorkerConfig.from_env()
    adapter, provider = await _build_adapter_and_provider(cfg)
    worker = PostureSyncWorker(adapter=adapter, provider=provider, config=cfg)

    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGINT, worker.stop)
        loop.add_signal_handler(signal.SIGTERM, worker.stop)
    except NotImplementedError:
        # Signals may be unsupported on some platforms (e.g., Windows)
        pass

    try:
        await worker.run()
        return 0
    finally:
        try:
            await adapter.close()
        except Exception:
            pass


def main() -> None:
    """CLI entrypoint."""
    try:
        rc = asyncio.run(_amain())
    except KeyboardInterrupt:
        rc = 130
    sys.exit(rc)


if __name__ == "__main__":
    main()
