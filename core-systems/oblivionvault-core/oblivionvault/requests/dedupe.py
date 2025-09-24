# -*- coding: utf-8 -*-
"""
Idempotency & request deduplication utilities for oblivionvault-core.

Features:
- Stable idempotency key resolution:
  * Prefer explicit Idempotency-Key (or custom header)
  * Fallback to deterministic content fingerprint (method, path, filtered headers, body hash)
- Two-tier deduplication:
  * Local single-flight (per-process) with asyncio.Event
  * Distributed lock via Redis (SETNX + TTL) with result cache and backoff polling
- Safe, bounded result caching with TTL (bytes or JSON-serializable objects)
- Timeouts, jitter backoff, and storm protection
- Typed, framework-agnostic (works with ASGI/FastAPI, gRPC, background tasks)

Requires: Python 3.10+. Redis backend requires `redis>=4.2` (redis.asyncio).
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import json
import logging
import os
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timedelta
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
    Union,
)

logger = logging.getLogger("oblivionvault.dedupe")

try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore


# ---------------------------
# Exceptions
# ---------------------------

class DedupeError(Exception):
    pass

class ResultTooLargeError(DedupeError):
    pass

class WaitTimeoutError(DedupeError):
    pass

class BackendUnavailableError(DedupeError):
    pass


# ---------------------------
# Serialization helpers
# ---------------------------

def _json_dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _json_loads(b: bytes) -> Any:
    return json.loads(b.decode("utf-8"))


# ---------------------------
# Backend protocol
# ---------------------------

class DedupeBackend(Protocol):
    """
    Storage backend for distributed deduplication.
    Keys are opaque strings (already namespaced by controller).
    """

    async def try_lock(self, key: str, ttl_seconds: int) -> bool:
        """Attempt to acquire 'inflight' lock for key with TTL. Return True if owner."""
        ...

    async def release_lock(self, key: str) -> None:
        """Release lock early (best effort)."""
        ...

    async def put_result(self, key: str, value: bytes, ttl_seconds: int, is_error: bool) -> None:
        """Store final result for key with TTL. Overwrites previous result."""
        ...

    async def get_result(self, key: str) -> Optional[Tuple[bytes, bool]]:
        """Fetch result bytes and error flag if present. Return None if missing/expired."""
        ...


# ---------------------------
# In-memory backend (per-process)
# ---------------------------

@dataclass
class _MemEntry:
    value: Optional[bytes]
    is_error: bool
    expires_at: float

class InMemoryBackend(DedupeBackend):
    """
    Simple in-process backend with TTL. Not distributed.
    Useful as a fallback or for tests.
    """
    def __init__(self) -> None:
        self._locks: set[str] = set()
        self._results: Dict[str, _MemEntry] = {}
        self._mux = asyncio.Lock()

    async def try_lock(self, key: str, ttl_seconds: int) -> bool:
        async with self._mux:
            self._gc()
            if key in self._locks:
                return False
            self._locks.add(key)
            # we don't expire locks automatically here; controller relies on result publish or finally release
            return True

    async def release_lock(self, key: str) -> None:
        async with self._mux:
            self._locks.discard(key)

    async def put_result(self, key: str, value: bytes, ttl_seconds: int, is_error: bool) -> None:
        async with self._mux:
            self._results[key] = _MemEntry(value=value, is_error=is_error, expires_at=time.time() + ttl_seconds)
            # releasing lock is controller's responsibility

    async def get_result(self, key: str) -> Optional[Tuple[bytes, bool]]:
        async with self._mux:
            self._gc()
            ent = self._results.get(key)
            if not ent:
                return None
            if ent.expires_at <= time.time():
                self._results.pop(key, None)
                return None
            return ent.value or b"", ent.is_error

    def _gc(self) -> None:
        now = time.time()
        pop_keys = [k for k, v in self._results.items() if v.expires_at <= now]
        for k in pop_keys:
            self._results.pop(k, None)


# ---------------------------
# Redis backend (distributed)
# ---------------------------

class RedisBackend(DedupeBackend):
    """
    Redis-backed deduplication storage. Keys layout:

        <ns>:lock:<key>    -> "1" (string), PX=lock_ttl_ms, NX
        <ns>:res:<key>     -> JSON blob: {"b64": "<base64>", "err": true|false}, EX=result_ttl_s

    The controller does polling with exponential backoff to see the result key.
    """
    def __init__(self, redis: "aioredis.Redis", namespace: str = "ov:dedupe") -> None:
        if aioredis is None:
            raise BackendUnavailableError("redis.asyncio is not available")
        self._r = redis
        self._ns = namespace

    def _lock_key(self, key: str) -> str:
        return f"{self._ns}:lock:{key}"

    def _res_key(self, key: str) -> str:
        return f"{self._ns}:res:{key}"

    async def try_lock(self, key: str, ttl_seconds: int) -> bool:
        k = self._lock_key(key)
        try:
            return bool(await self._r.set(k, "1", nx=True, ex=ttl_seconds))
        except Exception as e:
            logger.exception("Redis try_lock failed")
            raise BackendUnavailableError(str(e)) from e

    async def release_lock(self, key: str) -> None:
        try:
            await self._r.delete(self._lock_key(key))
        except Exception:
            # best effort
            pass

    async def put_result(self, key: str, value: bytes, ttl_seconds: int, is_error: bool) -> None:
        payload = _json_dumps({"b64": base64.b64encode(value).decode("ascii") if value else "", "err": is_error})
        try:
            await self._r.set(self._res_key(key), payload, ex=ttl_seconds)
            # we DO NOT delete the lock here; controller manages lock lifecycle to avoid races
        except Exception as e:
            logger.exception("Redis put_result failed")
            raise BackendUnavailableError(str(e)) from e

    async def get_result(self, key: str) -> Optional[Tuple[bytes, bool]]:
        try:
            raw = await self._r.get(self._res_key(key))
            if not raw:
                return None
            obj = _json_loads(raw)
            b = base64.b64decode(obj.get("b64", "") or "")
            return b, bool(obj.get("err", False))
        except Exception as e:
            logger.exception("Redis get_result failed")
            raise BackendUnavailableError(str(e)) from e


# ---------------------------
# Controller
# ---------------------------

@dataclass
class DedupeConfig:
    # TTLs
    lock_ttl_seconds: int = int(os.getenv("OV_DEDUPE_LOCK_TTL", "60"))             # how long a single flight may run
    result_ttl_seconds: int = int(os.getenv("OV_DEDUPE_RESULT_TTL", "300"))        # how long to cache result
    wait_timeout_seconds: int = int(os.getenv("OV_DEDUPE_WAIT_TIMEOUT", "55"))     # how long a duplicate waits for result
    # Poll/backoff
    initial_backoff_ms: int = int(os.getenv("OV_DEDUPE_BACKOFF_MS", "50"))
    max_backoff_ms: int = int(os.getenv("OV_DEDUPE_BACKOFF_MAX_MS", "1200"))
    # Limits
    max_cached_result_bytes: int = int(os.getenv("OV_DEDUPE_MAX_RESULT_BYTES", "131072"))  # 128 KiB
    cache_results: bool = True
    # Namespace (prefix for backend keys)
    namespace: str = "ov:dedupe"

class DedupeController:
    """
    Orchestrates local single-flight and distributed backend.
    """
    def __init__(self, backend: Optional[DedupeBackend] = None, config: Optional[DedupeConfig] = None) -> None:
        self.cfg = config or DedupeConfig()
        self.backend = backend or InMemoryBackend()
        # per-process single-flight state
        self._local_events: Dict[str, asyncio.Event] = {}
        self._local_mux = asyncio.Lock()

    def _ns_key(self, key: str) -> str:
        return f"{self.cfg.namespace}:{key}"

    async def execute(self, key: str, fn: Callable[[], Awaitable[Union[bytes, str, Mapping[str, Any]]]]) -> Any:
        """
        Execute `fn` once per dedupe key (distributed), returning cached/computed result.
        Result is cached (bytes) up to max_cached_result_bytes if enabled.

        Returns:
            bytes | str | Mapping
        Raises:
            WaitTimeoutError if waiting for other owner timed out
            DedupeError on backend failures or oversized results (if caching enabled)
        """
        key = self._ns_key(key)

        # 1) Fast path: try get cached result
        res = await self.backend.get_result(key)
        if res:
            data, is_err = res
            if is_err:
                raise DedupeError(_safe_decode(data) or "upstream execution error (cached)")
            return _decode_payload(data)

        # 2) Local single-flight event
        async with self._local_mux:
            ev = self._local_events.get(key)
            if ev is None:
                ev = asyncio.Event()
                self._local_events[key] = ev
                owner_local = True
            else:
                owner_local = False

        if owner_local:
            # I am local owner: try distributed lock
            owner_dist = await self.backend.try_lock(key, self.cfg.lock_ttl_seconds)
            if not owner_dist:
                # Someone in cluster is already owner; wait for their result
                try:
                    return await self._wait_for_result(key)
                finally:
                    # local event must be cleared; no result to set locally here
                    async with self._local_mux:
                        self._local_events.pop(key, None)

            # I am the distributed owner: run fn and publish result
            try:
                value = await fn()
                data = _encode_payload(value)
                if self.cfg.cache_results:
                    if len(data) > self.cfg.max_cached_result_bytes:
                        raise ResultTooLargeError(f"result {len(data)} bytes exceeds limit {self.cfg.max_cached_result_bytes}")
                    await self.backend.put_result(key, data, self.cfg.result_ttl_seconds, is_error=False)
                return value
            except BaseException as e:
                # store error marker for duplicates (short TTL to avoid poisoning cache)
                err_msg = str(e).encode("utf-8")[: min(2048, self.cfg.max_cached_result_bytes)]
                try:
                    await self.backend.put_result(key, err_msg, min(60, self.cfg.result_ttl_seconds), is_error=True)
                except Exception:
                    pass
                raise
            finally:
                # release distributed lock and wake local waiters
                try:
                    await self.backend.release_lock(key)
                finally:
                    ev.set()
                    async with self._local_mux:
                        self._local_events.pop(key, None)
        else:
            # Not local owner: wait for local event OR distributed result
            try:
                return await self._wait_for_result(key, local_event=ev)
            finally:
                async with self._local_mux:
                    self._local_events.pop(key, None)

    async def _wait_for_result(self, key: str, local_event: Optional[asyncio.Event] = None) -> Any:
        deadline = time.monotonic() + self.cfg.wait_timeout_seconds
        backoff = self.cfg.initial_backoff_ms / 1000.0

        # First, quick spin to avoid immediate sleep on hot path
        for _ in range(2):
            res = await self.backend.get_result(key)
            if res:
                data, is_err = res
                if is_err:
                    raise DedupeError(_safe_decode(data) or "upstream execution error (cached)")
                return _decode_payload(data)

        # Then poll with exponential backoff and optional local event
        while time.monotonic() < deadline:
            # check result
            res = await self.backend.get_result(key)
            if res:
                data, is_err = res
                if is_err:
                    raise DedupeError(_safe_decode(data) or "upstream execution error (cached)")
                return _decode_payload(data)

            # if we have a local event (same-process owner), await it with timeout slice
            if local_event is not None and not local_event.is_set():
                try:
                    timeout_slice = min(0.25, deadline - time.monotonic())
                    await asyncio.wait_for(local_event.wait(), timeout=max(0.0, timeout_slice))
                    # after event, loop again to read result (or owner failed and didn't cache)
                    continue
                except asyncio.TimeoutError:
                    pass

            # sleep with jitter
            await asyncio.sleep(backoff + random.uniform(0, backoff * 0.2))
            backoff = min(backoff * 2, self.cfg.max_backoff_ms / 1000.0)

        raise WaitTimeoutError(f"timeout waiting for result for key={key}")


# ---------------------------
# Key builders
# ---------------------------

def idempotency_key_from_headers(
    headers: Mapping[str, str],
    header_names: Tuple[str, ...] = ("idempotency-key", "x-idempotency-key"),
) -> Optional[str]:
    for h in header_names:
        v = headers.get(h) or headers.get(h.lower()) or headers.get(h.upper())
        if v:
            return v.strip()
    return None


def fingerprint_request(
    method: str,
    path_qs: str,
    body: Optional[bytes],
    headers: Mapping[str, str],
    include_headers: Tuple[str, ...] = ("content-type", "content-length"),
    actor_id: Optional[str] = None,
) -> str:
    """
    Deterministic request fingerprint. Use when Idempotency-Key absent.

    Args:
        method: HTTP method or logical operation name
        path_qs: path with query string
        body: request body bytes (will be hashed with SHA256)
        headers: request headers (case-insensitive)
        include_headers: whitelist of headers to include in hash
        actor_id: optional subject identifier to scope the operation to actor
    """
    h = hashlib.sha256()
    h.update(method.upper().encode())
    h.update(b"\n")
    h.update(path_qs.encode())
    h.update(b"\n")
    canon_headers = []
    for name in include_headers:
        v = headers.get(name) or headers.get(name.lower()) or headers.get(name.upper())
        if v is not None:
            canon_headers.append(f"{name.lower()}={v.strip()}")
    canon_headers.sort()
    for line in canon_headers:
        h.update(line.encode())
        h.update(b"\n")
    if body:
        h.update(b"\n")
        h.update(hashlib.sha256(body).digest())
    if actor_id:
        h.update(b"\nactor=" + actor_id.encode())
    return h.hexdigest()


def build_dedupe_key(
    headers: Mapping[str, str],
    method: str,
    path_qs: str,
    body: Optional[bytes],
    actor_id: Optional[str] = None,
    header_names: Tuple[str, ...] = ("idempotency-key", "x-idempotency-key"),
    include_headers: Tuple[str, ...] = ("content-type", "content-length"),
    namespace: str = "http",
) -> str:
    """
    Compose final dedupe key, preferring Idempotency-Key.
    """
    idem = idempotency_key_from_headers(headers, header_names)
    if idem:
        return f"{namespace}:idem:{idem}"
    fp = fingerprint_request(method, path_qs, body, headers, include_headers, actor_id)
    return f"{namespace}:fp:{fp}"


# ---------------------------
# Payload encoding helpers
# ---------------------------

def _encode_payload(value: Union[bytes, str, Mapping[str, Any]]) -> bytes:
    if isinstance(value, bytes):
        return b"\x00" + value  # tag 0: bytes
    if isinstance(value, str):
        return b"\x01" + value.encode("utf-8")  # tag 1: utf8 string
    # assume JSON-serializable mapping
    return b"\x02" + _json_dumps(value)

def _decode_payload(data: bytes) -> Union[bytes, str, Mapping[str, Any]]:
    if not data:
        return b""
    tag, payload = data[:1], data[1:]
    if tag == b"\x00":
        return payload
    if tag == b"\x01":
        return payload.decode("utf-8")
    if tag == b"\x02":
        return _json_loads(payload)
    # unknown tag: return raw
    return data

def _safe_decode(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


# ---------------------------
# ASGI convenience wrapper
# ---------------------------

async def asgi_single_flight(
    controller: DedupeController,
    scope: Mapping[str, Any],
    body_supplier: Callable[[], Awaitable[bytes]],
    actor_id: Optional[str],
    compute: Callable[[], Awaitable[Union[bytes, str, Mapping[str, Any]]]],
) -> Any:
    """
    Convenience for ASGI apps: builds dedupe key and executes compute() under dedupe control.

    Args:
      controller: DedupeController
      scope: ASGI scope (expects 'method', 'path', 'query_string', 'headers')
      body_supplier: awaitable that returns request body bytes (read once, e.g. cached by middleware)
      actor_id: subject identifier (e.g., user id)
      compute: coroutine to run once per dedupe key
    """
    method = str(scope.get("method", "GET"))
    raw_path = scope.get("path") or "/"
    qs = scope.get("query_string") or b""
    path_qs = f"{raw_path}?{qs.decode()}" if qs else str(raw_path)
    headers = _lower_headers(scope.get("headers") or [])
    try:
        body = await body_supplier()
    except Exception:
        body = b""
    dedupe_key = build_dedupe_key(headers=headers, method=method, path_qs=path_qs, body=body, actor_id=actor_id)
    return await controller.execute(dedupe_key, compute)


# ---------------------------
# Redis factory
# ---------------------------

async def redis_backend_from_url(url: Optional=str, namespace: str = "ov:dedupe") -> RedisBackend:
    """
    Create RedisBackend from URL. Example URL: redis://localhost:6379/0
    """
    if aioredis is None:
        raise BackendUnavailableError("redis.asyncio is not available")
    url = url or os.getenv("REDIS_URL") or "redis://localhost:6379/0"
    client = aioredis.from_url(url, encoding=None, decode_responses=False)
    # ping to validate connectivity
    try:
        await client.ping()
    except Exception as e:
        raise BackendUnavailableError(f"cannot connect to Redis: {e}") from e
    return RedisBackend(client, namespace=namespace)


# ---------------------------
# Example usage (docstring)
# ---------------------------

__doc__ += r"""

Example (FastAPI):

    from fastapi import FastAPI, Request, Response
    from oblivionvault.requests.dedupe import DedupeController, RedisBackend, build_dedupe_key

    app = FastAPI()
    dedupe = DedupeController()  # InMemory by default; use RedisBackend in prod

    @app.post("/v1/items")
    async def create_item(req: Request):
        body = await req.body()
        headers = {k.lower(): v for k, v in req.headers.items()}
        key = build_dedupe_key(headers, req.method, str(req.url), body, actor_id=headers.get("x-user-id"))
        async def compute():
            # your business logic here
            return {"status": "ok"}
        result = await dedupe.execute(key, compute)
        return result

Switching to Redis:

    import asyncio
    from oblivionvault.requests.dedupe import DedupeController, redis_backend_from_url

    async def setup():
        backend = await redis_backend_from_url("redis://redis:6379/0")
        return DedupeController(backend=backend)

Notes:
- lock_ttl_seconds should exceed worst-case execution time of compute()
- result_ttl_seconds defines how long duplicates will receive cached result
- if caching large results, adjust max_cached_result_bytes or set cache_results=False

"""
