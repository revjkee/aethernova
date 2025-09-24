# policy-core/policy_core/adapters/datafabric_adapter.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import random
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union
import asyncio

__all__ = [
    "DataFabricError",
    "DataFabricUnavailable",
    "DataFabricTimeout",
    "DataFabricAuthError",
    "DataFabricBadResponse",
    "SchemaMapping",
    "MappingRule",
    "ParamType",
    "AdapterConfig",
    "CircuitBreakerState",
    "DataFabricAdapter",
]

# --------------------------
# Exceptions
# --------------------------

class DataFabricError(RuntimeError):
    pass

class DataFabricUnavailable(DataFabricError):
    pass

class DataFabricTimeout(DataFabricError):
    pass

class DataFabricAuthError(DataFabricError):
    pass

class DataFabricBadResponse(DataFabricError):
    pass


# --------------------------
# Types / helpers
# --------------------------

MetricHook = Callable[[str, float, Mapping[str, Any]], None]
AuditHook = Callable[[Mapping[str, Any]], None]

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def to_rfc3339(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)

def redact(value: Any) -> Any:
    return "***REDACTED***"

def _dot_get(data: Any, path: str, default: Any = None) -> Any:
    """
    Safe dot-path resolver: "a.b[0].c"
    """
    if path in ("", None):
        return data
    cur = data
    try:
        for part in path.split("."):
            if "[" in part and part.endswith("]"):
                name, idx = part[:-1].split("[")
                if name:
                    cur = cur.get(name) if isinstance(cur, dict) else getattr(cur, name)
                cur = cur[int(idx)]
            else:
                cur = cur.get(part) if isinstance(cur, dict) else getattr(cur, part)
        return cur
    except Exception:
        return default

# --------------------------
# Schema mapping
# --------------------------

class ParamType(Enum):
    STRING = "STRING"
    INT = "INT"
    FLOAT = "FLOAT"
    BOOL = "BOOL"
    JSON = "JSON"
    BYTES_B64 = "BYTES_B64"
    TIMESTAMP = "TIMESTAMP"  # RFC3339Z

@dataclass(frozen=True)
class MappingRule:
    """
    Правило: откуда брать значение и как его привести.
    """
    source_path: str                       # dot-path в ответе Data Fabric
    target_key: str                        # ключ в activation/policy
    type: ParamType = ParamType.JSON
    default: Any = None
    required: bool = False
    pii: bool = False                      # при аудите редактировать
    transform_lambda: Optional[Callable[[Any], Any]] = None  # опциональная трансформация

@dataclass(frozen=True)
class SchemaMapping:
    """
    Схема нормализации ответа Data Fabric → activation dict.
    """
    rules: Sequence[MappingRule] = field(default_factory=tuple)
    allow_extras: bool = False             # пропускать неизрасходованные поля

    def apply(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        missing: List[str] = []
        for r in self.rules:
            raw = _dot_get(payload, r.source_path, r.default)
            if raw is None and r.required:
                missing.append(r.source_path)
                continue
            val = self._coerce(r, raw)
            if r.transform_lambda:
                try:
                    val = r.transform_lambda(val)
                except Exception as e:
                    raise DataFabricBadResponse(f"Transform failed for {r.target_key}: {e}") from e
            out[r.target_key] = val
        if missing:
            raise DataFabricBadResponse(f"Missing required fields: {missing}")
        if self.allow_extras:
            # добавим оставшиеся верхнеуровневые ключи для совместимости
            for k, v in payload.items():
                if k not in out:
                    out[k] = v
        return out

    def _coerce(self, rule: MappingRule, value: Any) -> Any:
        if value is None:
            return None
        try:
            t = rule.type
            if t is ParamType.STRING:
                return str(value)
            if t is ParamType.INT:
                if isinstance(value, bool):
                    raise ValueError("bool is not allowed for INT")
                return int(value)
            if t is ParamType.FLOAT:
                if isinstance(value, bool):
                    raise ValueError("bool is not allowed for FLOAT")
                return float(value)
            if t is ParamType.BOOL:
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    v = value.strip().lower()
                    if v in ("true", "1", "yes", "y", "on"):
                        return True
                    if v in ("false", "0", "no", "n", "off"):
                        return False
                return bool(value)
            if t is ParamType.JSON:
                json.loads(json.dumps(value, default=str))
                return value
            if t is ParamType.BYTES_B64:
                if isinstance(value, (bytes, bytearray)):
                    return base64.b64encode(value).decode("ascii")
                if isinstance(value, str):
                    # validate
                    base64.b64decode(value.encode("ascii"), validate=True)
                    return value
                raise ValueError("BYTES_B64 requires bytes or base64 string")
            if t is ParamType.TIMESTAMP:
                if isinstance(value, str):
                    # простая проверка на Z-окончание
                    if not value.endswith("Z"):
                        raise ValueError("TIMESTAMP must be RFC3339 with 'Z'")
                    return value
                if isinstance(value, datetime):
                    return to_rfc3339(value)
                raise ValueError("TIMESTAMP expects str or datetime")
        except Exception as e:
            raise DataFabricBadResponse(f"Coercion failed for {rule.target_key}: {e}") from e
        return value


# --------------------------
# Cache with TTL + LRU + negative caching
# --------------------------

class _TTLCache:
    def __init__(self, maxsize: int, ttl_seconds: float, negative_ttl_seconds: float):
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._neg_ttl = negative_ttl_seconds
        self._data: Dict[str, Tuple[float, Any, bool]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            ts, value, negative = v
            exp = ts + (self._neg_ttl if negative else self._ttl)
            if time.time() > exp:
                self._data.pop(key, None)
                return None
            return value

    def set(self, key: str, value: Any, *, negative: bool = False) -> None:
        with self._lock:
            if len(self._data) >= self._maxsize:
                # naive LRU-ish eviction: drop oldest
                oldest_key = min(self._data.items(), key=lambda x: x[1][0])[0]
                self._data.pop(oldest_key, None)
            self._data[key] = (time.time(), value, negative)

    def invalidate(self, prefix: Optional[str] = None) -> None:
        with self._lock:
            if prefix is None:
                self._data.clear()
                return
            dead = [k for k in self._data.keys() if k.startswith(prefix)]
            for k in dead:
                self._data.pop(k, None)


# --------------------------
# Circuit Breaker
# --------------------------

class CircuitBreakerState(Enum):
    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()

class _CircuitBreaker:
    def __init__(self, failure_threshold: int, recovery_time_s: float, half_open_max_calls: int):
        self._state = CircuitBreakerState.CLOSED
        self._failures = 0
        self._last_opened = 0.0
        self._half_open_calls = 0
        self._failure_threshold = max(1, failure_threshold)
        self._recovery_time_s = max(0.1, recovery_time_s)
        self._half_open_max_calls = max(1, half_open_max_calls)
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.time()
            if self._state is CircuitBreakerState.OPEN:
                if now - self._last_opened >= self._recovery_time_s:
                    self._state = CircuitBreakerState.HALF_OPEN
                    self._half_open_calls = 0
                else:
                    return False
            if self._state is CircuitBreakerState.HALF_OPEN:
                if self._half_open_calls >= self._half_open_max_calls:
                    return False
                self._half_open_calls += 1
            return True

    def on_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = CircuitBreakerState.CLOSED
            self._half_open_calls = 0

    def on_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._failure_threshold:
                self._state = CircuitBreakerState.OPEN
                self._last_opened = time.time()

    @property
    def state(self) -> CircuitBreakerState:
        return self._state


# --------------------------
# Config
# --------------------------

@dataclass(frozen=True)
class AdapterConfig:
    base_url: str
    attributes_path: str = "/v1/attributes:resolve"
    batch_path: str = "/v1/attributes:batchResolve"
    health_path: str = "/health"
    connect_timeout_s: float = 1.0
    read_timeout_s: float = 1.5
    retries: int = 2
    retry_base_delay_ms: int = 120
    retry_max_delay_ms: int = 1200
    retry_jitter_ratio: float = 0.2
    cache_size: int = 1024
    cache_ttl_s: float = 5.0
    negative_cache_ttl_s: float = 1.0
    breaker_fail_threshold: int = 5
    breaker_recovery_time_s: float = 5.0
    breaker_half_open_calls: int = 2
    hmac_key_id: Optional[str] = None
    hmac_secret: Optional[str] = None         # base64 or hex or raw
    hmac_header: str = "X-Signature"
    hmac_ts_header: str = "X-Timestamp"
    hmac_algo: str = "SHA256"
    redact_pii_in_audit: bool = True
    default_headers: Mapping[str, str] = field(default_factory=lambda: {"Content-Type": "application/json"})
    metric_hook: Optional[MetricHook] = None
    audit_hook: Optional[AuditHook] = None
    debug_logging: bool = False


# --------------------------
# Adapter
# --------------------------

class DataFabricAdapter:
    """
    Промышленный адаптер для получения атрибутов из внешней Data Fabric.
    - HTTP без внешних зависимостей (urllib), sync + async (через to_thread).
    - Ретраи, джиттер, таймауты, circuit breaker.
    - LRU+TTL кэш и негативное кэширование.
    - Нормализация схемы, приведение типов.
    - HMAC-подпись запроса (опционально).
    - Метрики и аудит с редакцией PII.
    """

    def __init__(self, config: AdapterConfig, schema: SchemaMapping) -> None:
        self._cfg = config
        self._schema = schema
        self._cache = _TTLCache(config.cache_size, config.cache_ttl_s, config.negative_cache_ttl_s)
        self._breaker = _CircuitBreaker(
            failure_threshold=config.breaker_fail_threshold,
            recovery_time_s=config.breaker_recovery_time_s,
            half_open_max_calls=config.breaker_half_open_calls,
        )
        self._lock = threading.Lock()

    # ------------- Public API -------------

    def fetch_attributes(
        self,
        *,
        subject: str,
        resource: str,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        cache_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Синхронное получение атрибутов и нормализация.
        """
        key = cache_key or self._make_cache_key(subject, resource, action, context)
        cached = self._cache.get(key)
        if cached is not None:
            self._emit_metric("datafabric.cache_hit", 1.0, {"hit": True})
            return cached

        if not self._breaker.allow():
            self._emit_metric("datafabric.breaker_block", 1.0, {"state": self._breaker.state.name})
            raise DataFabricUnavailable("Circuit breaker is open")

        url = self._cfg.base_url.rstrip("/") + self._cfg.attributes_path
        payload = {
            "subject": subject,
            "resource": resource,
            "action": action,
            "context": context or {},
        }

        t0 = time.time()
        try:
            raw = self._http_json("POST", url, payload, timeout_s=self._cfg.connect_timeout_s + self._cfg.read_timeout_s)
            # ожидаем ответ вида {"data": {...}} или {"attributes": {...}} — гибко
            doc = json.loads(raw)
            core = doc.get("attributes") or doc.get("data") or doc
            normalized = self._schema.apply(core)
            self._cache.set(key, normalized, negative=False)
            self._breaker.on_success()
            self._emit_metric("datafabric.request_ms", (time.time() - t0) * 1000.0, {"ok": True})
            self._audit_event("attributes_ok", payload, normalized)
            return normalized
        except DataFabricError as e:
            self._breaker.on_failure()
            self._emit_metric("datafabric.request_ms", (time.time() - t0) * 1000.0, {"ok": False, "err": type(e).__name__})
            self._audit_event("attributes_error", payload, {"error": str(e)})
            # негативное кэширование для снижения штормов
            self._cache.set(key, {}, negative=True)
            raise

    async def fetch_attributes_async(
        self,
        *,
        subject: str,
        resource: str,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        cache_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Асинхронное получение (использует sync через to_thread для stdlib совместимости).
        """
        return await asyncio.to_thread(
            self.fetch_attributes,
            subject=subject,
            resource=resource,
            action=action,
            context=context,
            cache_key=cache_key,
        )

    def batch_fetch(
        self,
        batch: Sequence[Mapping[str, Any]],
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Батч-режим: batch = [{"subject": "...", "resource": "...", "action": "..."}, ...]
        Кэш используется покейсно.
        """
        results: List[Dict[str, Any]] = []
        to_query: List[Tuple[int, Mapping[str, Any], str]] = []
        for i, item in enumerate(batch):
            ck = self._make_cache_key(item.get("subject",""), item.get("resource",""), item.get("action",""), context)
            cached = self._cache.get(ck)
            if cached is not None:
                results.append(cached)
            else:
                to_query.append((i, item, ck))
                results.append({})  # placeholder

        if not to_query:
            return results

        if not self._breaker.allow():
            self._emit_metric("datafabric.breaker_block", 1.0, {"state": self._breaker.state.name})
            raise DataFabricUnavailable("Circuit breaker is open")

        url = self._cfg.base_url.rstrip("/") + self._cfg.batch_path
        payload = {"items": batch, "context": context or {}}

        t0 = time.time()
        try:
            raw = self._http_json("POST", url, payload, timeout_s=self._cfg.connect_timeout_s + self._cfg.read_timeout_s)
            doc = json.loads(raw)
            data = doc.get("results") or doc.get("data") or []
            if not isinstance(data, list) or len(data) != len(batch):
                raise DataFabricBadResponse("Batch result shape mismatch")
            for i, item in enumerate(data):
                core = item.get("attributes") or item.get("data") or item
                normalized = self._schema.apply(core)
                ck = self._make_cache_key(batch[i].get("subject",""), batch[i].get("resource",""), batch[i].get("action",""), context)
                self._cache.set(ck, normalized, negative=False)
                results[i] = normalized
            self._breaker.on_success()
            self._emit_metric("datafabric.batch_ms", (time.time() - t0) * 1000.0, {"ok": True, "size": len(batch)})
            self._audit_event("attributes_batch_ok", payload, {"size": len(batch)})
            return results
        except DataFabricError as e:
            self._breaker.on_failure()
            self._emit_metric("datafabric.batch_ms", (time.time() - t0) * 1000.0, {"ok": False, "err": type(e).__name__, "size": len(batch)})
            self._audit_event("attributes_batch_error", payload, {"error": str(e)})
            # негативное кэширование точек
            for _, item, ck in to_query:
                self._cache.set(ck, {}, negative=True)
            raise

    async def batch_fetch_async(
        self,
        batch: Sequence[Mapping[str, Any]],
        *,
        context: Optional[Mapping[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self.batch_fetch, batch, context=context)

    def health_check(self) -> bool:
        url = self._cfg.base_url.rstrip("/") + self._cfg.health_path
        try:
            self._raw_request("GET", url, headers=self._cfg.default_headers, body=None, timeout_s=self._cfg.connect_timeout_s)
            return True
        except DataFabricError:
            return False

    def invalidate_cache(self, prefix: Optional[str] = None) -> None:
        self._cache.invalidate(prefix=prefix)

    # ------------- Internals -------------

    def _make_cache_key(self, subject: str, resource: str, action: str, ctx: Optional[Mapping[str, Any]]) -> str:
        blob = canonical_json({"s": subject, "r": resource, "a": action, "c": ctx or {}}).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _emit_metric(self, name: str, value: float, tags: Mapping[str, Any]) -> None:
        try:
            if self._cfg.metric_hook:
                self._cfg.metric_hook(name, float(value), dict(tags))
        except Exception:
            # не нарушаем поток выполнения
            if self._cfg.debug_logging:
                pass

    def _audit_event(self, event: str, req: Mapping[str, Any], res: Mapping[str, Any]) -> None:
        if not self._cfg.audit_hook:
            return
        safe_req = dict(req)
        if self._cfg.redact_pii_in_audit:
            # грубая редактция возможных PII
            if isinstance(safe_req.get("subject"), str):
                safe_req["subject"] = redact(safe_req["subject"])
            if isinstance(safe_req.get("resource"), str):
                safe_req["resource"] = safe_req["resource"][:64] + ("..." if len(safe_req["resource"]) > 64 else "")
        ev = {
            "component": "policy_core.adapters.datafabric",
            "event": event,
            "request": safe_req,
            "response_keys": list(res.keys()) if isinstance(res, Mapping) else [],
            "ts": to_rfc3339(utc_now()),
        }
        try:
            self._cfg.audit_hook(ev)
        except Exception:
            if self._cfg.debug_logging:
                pass

    # HTTP core with retries and HMAC

    def _http_json(self, method: str, url: str, json_body: Mapping[str, Any], *, timeout_s: float) -> str:
        body = canonical_json(json_body).encode("utf-8")
        headers = dict(self._cfg.default_headers)
        self._maybe_sign(headers, body)
        attempt = 0
        last_err: Optional[Exception] = None

        total_retries = max(0, self._cfg.retries)
        while attempt <= total_retries:
            t0 = time.time()
            try:
                raw = self._raw_request(method, url, headers=headers, body=body, timeout_s=timeout_s)
                self._emit_metric("datafabric.http_ms", (time.time() - t0) * 1000.0, {"ok": True, "attempt": attempt})
                return raw
            except DataFabricTimeout as e:
                last_err = e
            except DataFabricUnavailable as e:
                last_err = e
            except DataFabricAuthError:
                # нет смысла ретраить 401/403
                raise
            except DataFabricBadResponse as e:
                last_err = e
                # 4xx кроме 408/429 не ретраим
                if getattr(e, "_retryable", False) is False:
                    raise
            # backoff with jitter
            attempt += 1
            if attempt > total_retries:
                break
            delay = self._compute_backoff_ms(attempt) / 1000.0
            time.sleep(delay)
        if isinstance(last_err, Exception):
            raise last_err
        raise DataFabricUnavailable("Unknown error during HTTP JSON call")

    def _raw_request(self, method: str, url: str, *, headers: Mapping[str, str], body: Optional[bytes], timeout_s: float) -> str:
        req = urllib.request.Request(url=url, data=body, method=method)
        for k, v in headers.items():
            req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                status = getattr(resp, "status", 200)
                data = resp.read()
                if status == 200:
                    return data.decode("utf-8", errors="replace")
                if status in (401, 403):
                    raise DataFabricAuthError(f"Auth failed with status {status}")
                if status in (408, 429, 500, 502, 503, 504):
                    e = DataFabricBadResponse(f"Retryable status {status}")
                    setattr(e, "_retryable", True)
                    raise e
                raise DataFabricBadResponse(f"Unexpected HTTP status {status}")
        except urllib.error.HTTPError as e:
            status = getattr(e, "code", 0)
            if status in (401, 403):
                raise DataFabricAuthError(f"Auth failed with status {status}") from e
            if status in (408, 429, 500, 502, 503, 504):
                err = DataFabricBadResponse(f"Retryable status {status}")
                setattr(err, "_retryable", True)
                raise err
            raise DataFabricBadResponse(f"HTTP error {status}") from e
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", None)
            if isinstance(reason, TimeoutError):
                raise DataFabricTimeout("Network timeout") from e
            # DNS/Connect errors → как недоступность
            raise DataFabricUnavailable(f"Network error: {reason}") from e

    def _compute_backoff_ms(self, attempt: int) -> int:
        base = max(1, self._cfg.retry_base_delay_ms)
        delay = base * (2 ** (attempt - 1))
        delay = min(delay, self._cfg.retry_max_delay_ms)
        if self._cfg.retry_jitter_ratio > 0:
            jitter = delay * self._cfg.retry_jitter_ratio
            delay = int(max(1, random.uniform(delay - jitter, delay + jitter)))
        return delay

    def _maybe_sign(self, headers: MutableMapping[str, str], body: Optional[bytes]) -> None:
        if not self._cfg.hmac_secret:
            return
        ts = str(int(time.time()))
        secret = self._decode_secret(self._cfg.hmac_secret)
        algo = self._cfg.hmac_algo.upper()
        msg = (ts + "\n").encode("utf-8") + (body or b"")
        if algo == "SHA256":
            digest = hmac.new(secret, msg, hashlib.sha256).hexdigest()
        elif algo == "SHA512":
            digest = hmac.new(secret, msg, hashlib.sha512).hexdigest()
        else:
            raise DataFabricError(f"Unsupported HMAC algo: {self._cfg.hmac_algo}")
        headers[self._cfg.hmac_ts_header] = ts
        headers[self._cfg.hmac_header] = digest
        if self._cfg.hmac_key_id:
            headers["X-Key-ID"] = self._cfg.hmac_key_id

    @staticmethod
    def _decode_secret(secret: str) -> bytes:
        # auto-detect hex or base64, fallback raw utf-8
        s = secret.strip()
        try:
            if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
                return bytes.fromhex(s)
            return base64.b64decode(s, validate=True)
        except Exception:
            return s.encode("utf-8")
