# cybersecurity-core/cybersecurity/workers/intel_sync_worker.py
from __future__ import annotations

import asyncio
import contextlib
import csv
import hashlib
import io
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

# ---- Локальные типы из модуля intel.matcher (совместимость без жёсткой зависимости)
try:
    # Если проектные типы доступны — используем их напрямую
    from cybersecurity.intel.matcher import Indicator, IndicatorType  # type: ignore
except Exception:
    # Иначе объявляем совместимые "минимальные" типы для независимой сборки
    from enum import Enum
    from dataclasses import dataclass as _dataclass

    class IndicatorType(str, Enum):
        IP = "ip"
        CIDR = "cidr"
        DOMAIN = "domain"
        SUBDOMAIN = "subdomain"
        URL = "url"
        EMAIL = "email"
        MD5 = "md5"
        SHA1 = "sha1"
        SHA256 = "sha256"
        REGEX = "regex"
        TEXT = "text"
        FILEPATH = "filepath"

    @_dataclass(slots=True)
    class Indicator:
        id: str
        type: IndicatorType
        pattern: str
        confidence: int = 80
        severity: str = "medium"
        source: Optional[str] = None
        actor: Optional[str] = None
        tags: Tuple[str, ...] = tuple()
        valid_from: Optional[datetime] = None
        valid_until: Optional[datetime] = None
        ttl: Optional[int] = None
        metadata: Mapping[str, Any] = field(default_factory=dict)
        enabled: bool = True


# =========================================
# ЛОГИРОВАНИЕ
# =========================================
logger = logging.getLogger("cybersecurity.workers.intel_sync")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# =========================================
# ПРОТОКОЛЫ И ИСКЛЮЧЕНИЯ
# =========================================
class Metrics(Protocol):
    def counter(self, name: str, value: int = 1, **labels: str) -> None: ...
    def histogram(self, name: str, value: float, **labels: str) -> None: ...
    def gauge(self, name: str, value: float, **labels: str) -> None: ...

class IndicatorSink(Protocol):
    """
    Хранилище индикаторов (например, обёртка над IntelMatcher + персистентность).
    Все операции должны быть идемпотентны.
    """
    async def upsert_many(self, feed_id: str, indicators: Sequence[Indicator]) -> None: ...
    async def disable_missing(self, feed_id: str, present_indicator_ids: Sequence[str]) -> int: ...
    async def commit_checkpoint(self, feed_id: str, state: "FeedState") -> None: ...

class FeedRepository(Protocol):
    """
    Источник конфигураций фидов и сохранение состояния синхронизации.
    """
    async def list_enabled(self) -> List["FeedConfig"]: ...
    async def update_state(self, feed_id: str, state: "FeedState") -> None: ...
    async def try_acquire_lock(self, feed_id: str, owner_id: str, ttl_sec: int) -> bool: ...
    async def release_lock(self, feed_id: str, owner_id: str) -> None: ...

class RemoteFeedClient(Protocol):
    async def fetch(self, feed: "FeedConfig", state: "FeedState") -> "FetchResult": ...
    async def close(self) -> None: ...


class ApiError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, code: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.code = code

class RateLimitError(Exception): ...
class CircuitOpenError(Exception): ...


# =========================================
# МОДЕЛИ КОНФИГА/СОСТОЯНИЯ
# =========================================
@dataclass(slots=True)
class FeedState:
    last_sync_at: Optional[datetime] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None  # RFC 1123 string
    cursor: Optional[str] = None
    # статистика
    total_seen: int = 0
    total_upserted: int = 0
    total_disabled: int = 0

@dataclass(slots=True)
class FeedAuth:
    api_key: Optional[str] = None
    bearer_token: Optional[str] = None
    hmac_secret: Optional[bytes] = None
    hmac_key_prefix: Optional[str] = None

@dataclass(slots=True)
class FeedConfig:
    id: str
    name: str
    url: str
    fmt: str  # "stix21" | "json" | "csv"
    enabled: bool = True
    interval_sec: int = 900
    rate_limit_per_sec: float = 0.0
    max_batch_upsert: int = 5000
    tags: Tuple[str, ...] = tuple()
    default_confidence: int = 80
    default_severity: str = "medium"
    source: Optional[str] = None
    actor: Optional[str] = None
    map_subdomains_as_suffix: bool = True
    auth: FeedAuth = field(default_factory=FeedAuth)
    request_timeout_ms: int = 30000
    retry_max: int = 3
    retry_base_ms: int = 300
    retry_max_ms: int = 10000
    circuit_failure_threshold: int = 5
    circuit_cooldown_sec: float = 15.0
    http_headers: Dict[str, str] = field(default_factory=dict)

    # поля, управляемые репозиторием/воркером
    state: FeedState = field(default_factory=FeedState)

# =========================================
# ВСПОМОГАТЕЛЬНОЕ
# =========================================
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _uuid() -> str:
    return str(uuid.uuid4())

def _sha1_hex(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()

def _stable_indicator_id(feed_id: str, itype: IndicatorType, pattern: str) -> str:
    raw = f"{feed_id}|{itype.value}|{pattern}".encode("utf-8")
    return _sha1_hex(raw)

def _clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))

async def _sleep(ms: int) -> None:
    await asyncio.sleep(ms / 1000)

# =========================================
# TOKEN BUCKET & CIRCUIT
# =========================================
class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: Optional[int] = None) -> None:
        self.rate = max(0.0, rate_per_sec)
        self.capacity = max(1, burst if burst is not None else int(max(1.0, self.rate * 2)))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._cond = asyncio.Condition()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.updated
        if self.rate > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        else:
            self.tokens = self.capacity
        self.updated = now

    async def acquire(self, timeout_sec: float | None) -> None:
        if self.rate == 0:
            return
        start = time.monotonic()
        async with self._cond:
            while True:
                self._refill()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                if timeout_sec is not None and (time.monotonic() - start) >= timeout_sec:
                    raise RateLimitError("rate limit acquire timeout")
                await asyncio.wait_for(self._cond.wait(), timeout=0.05)

class _Circuit:
    def __init__(self, failure_threshold: int = 5, cooldown_sec: float = 15.0) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown = max(0.1, cooldown_sec)
        self.state = "closed"   # closed|open|half
        self.failures = 0
        self.opened_at = 0.0
        self._half_inflight = False

    def allow(self) -> bool:
        now = time.monotonic()
        if self.state == "closed":
            return True
        if self.state == "open":
            if now - self.opened_at >= self.cooldown:
                self.state = "half"
                self._half_inflight = False
                return True
            return False
        if not self._half_inflight:
            self._half_inflight = True
            return True
        return False

    def ok(self) -> None:
        self.failures = 0
        self.state = "closed"
        self._half_inflight = False

    def fail(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = "open"
            self.opened_at = time.monotonic()
            self._half_inflight = False

# =========================================
# HTTP КЛИЕНТ (aiohttp или stdlib)
# =========================================
class _HttpResponse:
    def __init__(self, status: int, headers: Mapping[str, str], body: bytes) -> None:
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self._body = body
    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())
    def json(self) -> Any:
        return json.loads(self._body.decode("utf-8") if self._body else "null")
    def text(self) -> str:
        return self._body.decode("utf-8", errors="replace")
    def bytes(self) -> bytes:
        return self._body

class _HttpClient:
    def __init__(self) -> None:
        self._use_aiohttp = False
        with contextlib.suppress(Exception):
            import aiohttp  # type: ignore
            self._use_aiohttp = True
            self._session = aiohttp.ClientSession(raise_for_status=False)

    async def request(self, method: str, url: str, *, headers: Mapping[str, str], data: bytes | None, timeout: float) -> _HttpResponse:
        if self._use_aiohttp:
            import aiohttp  # type: ignore
            try:
                async with self._session.request(method, url, headers=dict(headers), data=data, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    body = await resp.read()
                    return _HttpResponse(resp.status, resp.headers, body)
            except asyncio.TimeoutError:
                raise ApiError("timeout", status=None)
        else:
            import urllib.request
            import urllib.error
            req = urllib.request.Request(url=url, method=method, data=data)
            for k, v in headers.items():
                req.add_header(k, v)
            def _call() -> _HttpResponse:
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        return _HttpResponse(r.status, r.headers, r.read())
                except urllib.error.HTTPError as e:
                    return _HttpResponse(e.code, e.headers, e.read())
                except urllib.error.URLError as e:
                    raise ApiError(f"net error: {e.reason}", status=None)
            return await asyncio.to_thread(_call)

    async def close(self) -> None:
        if self._use_aiohttp:
            await self._session.close()

# =========================================
# FETCH LAYER (ретраи, HMAC, условные запросы)
# =========================================
@dataclass(slots=True)
class FetchResult:
    status: int
    not_modified: bool
    content_type: str
    body: bytes
    etag: Optional[str]
    last_modified: Optional[str]

class DefaultRemoteClient(RemoteFeedClient):
    def __init__(self) -> None:
        self.http = _HttpClient()
        self._buckets: Dict[str, _TokenBucket] = {}
        self._circuits: Dict[str, _Circuit] = {}

    async def close(self) -> None:
        await self.http.close()

    async def fetch(self, feed: FeedConfig, state: FeedState) -> FetchResult:
        # rate & circuit by feed
        bucket = self._buckets.setdefault(feed.id, _TokenBucket(feed.rate_limit_per_sec))
        circuit = self._circuits.setdefault(feed.id, _Circuit(feed.circuit_failure_threshold, feed.circuit_cooldown_sec))
        if not circuit.allow():
            raise CircuitOpenError("circuit open")

        await bucket.acquire(timeout_sec=30.0)

        headers = {"Accept": "application/json,text/csv,*/*", **feed.http_headers}
        if feed.auth.api_key:
            headers.setdefault("X-API-Key", feed.auth.api_key)
        if feed.auth.bearer_token:
            headers.setdefault("Authorization", f"Bearer {feed.auth.bearer_token}")
        if state.etag:
            headers["If-None-Match"] = state.etag
        if state.last_modified:
            headers["If-Modified-Since"] = state.last_modified

        # ретраи
        attempt = 0
        last_err: Optional[Exception] = None
        while True:
            try:
                async with asyncio.timeout(feed.request_timeout_ms / 1000):
                    resp = await self.http.request("GET", feed.url, headers=headers, data=None, timeout=feed.request_timeout_ms / 1000)
                if resp.status in (429, 500, 502, 503, 504) and attempt < feed.retry_max:
                    attempt += 1
                    await _sleep(self._backoff_ms(feed, attempt))
                    continue
                if resp.status == 304:
                    circuit.ok()
                    return FetchResult(status=304, not_modified=True, content_type=resp.header("content-type") or "", body=b"", etag=resp.header("etag"), last_modified=resp.header("last-modified"))
                if resp.status >= 400:
                    circuit.fail()
                    raise ApiError(f"HTTP {resp.status}", status=resp.status)
                circuit.ok()
                return FetchResult(
                    status=resp.status,
                    not_modified=False,
                    content_type=(resp.header("content-type") or "").split(";")[0].strip(),
                    body=resp.bytes(),
                    etag=resp.header("etag"),
                    last_modified=resp.header("last-modified"),
                )
            except Exception as ex:
                last_err = ex
                if attempt < feed.retry_max:
                    attempt += 1
                    await _sleep(self._backoff_ms(feed, attempt))
                    continue
                circuit.fail()
                raise last_err

    @staticmethod
    def _backoff_ms(feed: FeedConfig, attempt: int) -> int:
        base = feed.retry_base_ms * (2 ** (attempt - 1))
        capped = int(_clamp(base, feed.retry_base_ms, feed.retry_max_ms))
        # full jitter
        return int(os.urandom(1)[0] / 255 * capped)

# =========================================
# ПАРСЕРЫ ФИДОВ
# =========================================
class ParseError(Exception): ...

def parse_feed(feed: FeedConfig, fr: FetchResult) -> List[Indicator]:
    if fr.not_modified:
        return []
    ct = (fr.content_type or "").lower()
    body = fr.body
    if feed.fmt == "stix21":
        # допускаем application/json / application/stix+json
        return _parse_stix21_json(feed, body)
    if feed.fmt == "json" or ct.endswith("/json") or ct.endswith("+json"):
        return _parse_generic_json(feed, body)
    if feed.fmt == "csv" or ct.endswith("/csv") or ct == "text/csv":
        return _parse_csv(feed, body)
    # fallback: пытаемся как json
    try:
        return _parse_generic_json(feed, body)
    except Exception:
        return _parse_csv(feed, body)

def _parse_generic_json(feed: FeedConfig, body: bytes) -> List[Indicator]:
    data = json.loads(body.decode("utf-8"))
    if isinstance(data, dict) and "items" in data:
        items = data["items"]
    elif isinstance(data, list):
        items = data
    else:
        raise ParseError("unsupported json shape")

    out: List[Indicator] = []
    for it in items:
        itype = _coerce_type(str(it.get("type", "")).lower())
        pattern = str(it.get("pattern") or it.get("value") or it.get("indicator") or "").strip()
        if not itype or not pattern:
            continue
        conf = int(it.get("confidence", feed.default_confidence))
        sev = str(it.get("severity", feed.default_severity))
        tags = tuple(it.get("tags", ())) + tuple(feed.tags)
        vf = _parse_dt(it.get("valid_from"))
        vu = _parse_dt(it.get("valid_until"))
        ttl = int(it["ttl"]) if it.get("ttl") is not None else None
        ind_id = _stable_indicator_id(feed.id, itype, pattern)
        out.append(Indicator(
            id=ind_id, type=itype, pattern=pattern,
            confidence=conf, severity=sev,
            source=it.get("source", feed.source), actor=it.get("actor", feed.actor),
            tags=tags, valid_from=vf, valid_until=vu, ttl=ttl,
            metadata={"feed_id": feed.id, "feed_name": feed.name, **{k: v for k, v in it.items() if k not in ("pattern", "value")}},
            enabled=bool(it.get("enabled", True)),
        ))
    return out

def _parse_csv(feed: FeedConfig, body: bytes) -> List[Indicator]:
    # Ожидаемые колонки: type, pattern, confidence?, severity?, tags?, valid_from?, valid_until?, ttl?
    text = body.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    out: List[Indicator] = []
    for row in reader:
        itype = _coerce_type(str(row.get("type", "")).lower())
        pattern = str(row.get("pattern", "")).strip()
        if not itype or not pattern:
            continue
        conf = int(row["confidence"]) if row.get("confidence") else feed.default_confidence
        sev = row.get("severity") or feed.default_severity
        tags = tuple((row.get("tags") or "").split("|")) if row.get("tags") else tuple()
        vf = _parse_dt(row.get("valid_from"))
        vu = _parse_dt(row.get("valid_until"))
        ttl = int(row["ttl"]) if row.get("ttl") else None
        ind_id = _stable_indicator_id(feed.id, itype, pattern)
        out.append(Indicator(
            id=ind_id, type=itype, pattern=pattern,
            confidence=conf, severity=sev, source=feed.source, actor=feed.actor,
            tags=tuple(feed.tags) + tags, valid_from=vf, valid_until=vu, ttl=ttl,
            metadata={"feed_id": feed.id, "feed_name": feed.name, **row},
            enabled=True,
        ))
    return out

def _parse_stix21_json(feed: FeedConfig, body: bytes) -> List[Indicator]:
    # Минимальная поддержка bundle{objects[]} и indicator pattern STIX
    data = json.loads(body.decode("utf-8"))
    objs = []
    if isinstance(data, dict) and data.get("type") == "bundle":
        objs = data.get("objects", [])
    elif isinstance(data, list):
        objs = data
    else:
        raise ParseError("unsupported stix json")

    out: List[Indicator] = []
    for obj in objs:
        t = obj.get("type")
        if t == "indicator":
            patt = obj.get("pattern") or ""
            # поддержим простые равенства и IN-списки
            for itype, value in _extract_from_stix_pattern(patt):
                ind_id = _stable_indicator_id(feed.id, itype, value)
                out.append(Indicator(
                    id=ind_id, type=itype, pattern=value,
                    confidence=int(obj.get("confidence", feed.default_confidence)),
                    severity=feed.default_severity,
                    source=obj.get("created_by_ref", feed.source),
                    actor=feed.actor,
                    tags=tuple(feed.tags) + tuple(obj.get("labels", [])),
                    valid_from=_parse_dt(obj.get("valid_from") or obj.get("created")),
                    valid_until=_parse_dt(obj.get("valid_until") or obj.get("modified")),
                    ttl=None,
                    metadata={"stix_id": obj.get("id"), "feed_id": feed.id, "feed_name": feed.name, "pattern": patt},
                    enabled=True,
                ))
        elif t in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file"):
            # STIX observable — извлечём как прямой индикатор
            for itype, value in _extract_from_stix_observable(t, obj):
                ind_id = _stable_indicator_id(feed.id, itype, value)
                out.append(Indicator(
                    id=ind_id, type=itype, pattern=value,
                    confidence=feed.default_confidence, severity=feed.default_severity,
                    source=feed.source, actor=feed.actor,
                    tags=tuple(feed.tags) + tuple(obj.get("labels", [])),
                    metadata={"stix_id": obj.get("id"), "feed_id": feed.id, "feed_name": feed.name},
                    enabled=True,
                ))
    return out

def _coerce_type(t: str) -> Optional[IndicatorType]:
    m = {
        "ip": IndicatorType.IP, "ipv4": IndicatorType.IP, "ipv6": IndicatorType.IP,
        "cidr": IndicatorType.CIDR,
        "domain": IndicatorType.DOMAIN, "fqdn": IndicatorType.DOMAIN,
        "subdomain": IndicatorType.SUBDOMAIN,
        "url": IndicatorType.URL,
        "email": IndicatorType.EMAIL, "email-addr": IndicatorType.EMAIL,
        "md5": IndicatorType.MD5, "sha1": IndicatorType.SHA1, "sha256": IndicatorType.SHA256,
        "regex": IndicatorType.REGEX, "text": IndicatorType.TEXT,
        "filepath": IndicatorType.FILEPATH,
    }
    return m.get(t)

def _parse_dt(s: Any) -> Optional[datetime]:
    if not s:
        return None
    try:
        # поддержка ISO-8601
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def _extract_from_stix_observable(t: str, obj: Mapping[str, Any]) -> List[Tuple[IndicatorType, str]]:
    out: List[Tuple[IndicatorType, str]] = []
    if t in ("ipv4-addr", "ipv6-addr"):
        v = obj.get("value")
        if v:
            out.append((IndicatorType.IP, str(v)))
    elif t == "domain-name":
        v = obj.get("value")
        if v:
            out.append((IndicatorType.DOMAIN, str(v)))
    elif t == "url":
        v = obj.get("value")
        if v:
            out.append((IndicatorType.URL, str(v)))
    elif t == "email-addr":
        v = obj.get("value")
        if v:
            out.append((IndicatorType.EMAIL, str(v)))
    elif t == "file":
        hashes = obj.get("hashes", {})
        for algo, val in hashes.items():
            algo_l = str(algo).lower()
            if algo_l == "md5":
                out.append((IndicatorType.MD5, str(val)))
            elif algo_l == "sha1":
                out.append((IndicatorType.SHA1, str(val)))
            elif algo_l in ("sha256", "sha-256"):
                out.append((IndicatorType.SHA256, str(val)))
    return out

def _extract_from_stix_pattern(patt: str) -> List[Tuple[IndicatorType, str]]:
    """
    Очень упрощённый разбор STIX-паттернов вида:
      [domain-name:value = 'a.b'] OR [url:value IN ('u1','u2')] OR [file:hashes.'SHA-256' = '...']
    """
    import re
    out: List[Tuple[IndicatorType, str]] = []
    # Единичные равенства
    eq_rx = re.compile(r"\[(?P=objtype>[a-z\-]+):(?P<field>[a-z\.'\-]+)\s*=\s*'(?P<val>[^']+)'\]", re.IGNORECASE)
    # IN-списки
    in_rx = re.compile(r"\[(?P=objtype>[a-z\-]+):(?P<field>[a-z\.'\-]+)\s+IN\s+\((?P<vals>[^)]+)\)\]", re.IGNORECASE)
    for m in eq_rx.finditer(patt):
        obj = m.group("objtype").lower()
        field = m.group("field").lower()
        val = m.group("val")
        t = _map_stix_field(obj, field)
        if t:
            out.append((t, val))
    for m in in_rx.finditer(patt):
        obj = m.group("objtype").lower()
        field = m.group("field").lower()
        vals = [v.strip().strip("'") for v in m.group("vals").split(",")]
        t = _map_stix_field(obj, field)
        if t:
            out += [(t, v) for v in vals if v]
    return out

def _map_stix_field(obj: str, field: str) -> Optional[IndicatorType]:
    if obj in ("domain-name",) and field.startswith("value"):
        return IndicatorType.DOMAIN
    if obj in ("ipv4-addr", "ipv6-addr") and field.startswith("value"):
        return IndicatorType.IP
    if obj == "url" and field.startswith("value"):
        return IndicatorType.URL
    if obj == "email-addr" and field.startswith("value"):
        return IndicatorType.EMAIL
    if obj == "file" and field.startswith("hashes.'md5'"):
        return IndicatorType.MD5
    if obj == "file" and ("'sha-1'" in field or "'sha1'" in field):
        return IndicatorType.SHA1
    if obj == "file" and ("'sha-256'" in field or "'sha256'" in field):
        return IndicatorType.SHA256
    return None

# =========================================
# ВОРКЕР СИНХРОНИЗАЦИИ
# =========================================
@dataclass(slots=True)
class WorkerConfig:
    max_concurrency: int = 4
    schedule_tick_sec: float = 1.0
    lock_ttl_sec: int = 600

class IntelSyncWorker:
    """
    Асинхронный воркер периодической синхронизации фидов Threat Intelligence.
    """
    def __init__(self,
                 repository: FeedRepository,
                 sink: IndicatorSink,
                 metrics: Optional[Metrics] = None,
                 client: Optional[RemoteFeedClient] = None,
                 wcfg: Optional[WorkerConfig] = None) -> None:
        self.repo = repository
        self.sink = sink
        self.metrics = metrics or _NoopMetrics()
        self.client = client or DefaultRemoteClient()
        self.cfg = wcfg or WorkerConfig()
        self._stopping = asyncio.Event()
        self._owner_id = f"intel-sync-{_uuid()}"
        self._semaphore = asyncio.Semaphore(self.cfg.max_concurrency)

    async def run(self) -> None:
        logger.info("intel_sync_worker_start owner=%s", self._owner_id)
        try:
            while not self._stopping.is_set():
                feeds = await self.repo.list_enabled()
                now = _utcnow()
                tasks: List[asyncio.Task[None]] = []
                for feed in feeds:
                    if not feed.enabled:
                        continue
                    due = (feed.state.last_sync_at or datetime.fromtimestamp(0, tz=timezone.utc)) + timedelta(seconds=feed.interval_sec)
                    if now < due:
                        continue
                    if not await self.repo.try_acquire_lock(feed.id, self._owner_id, ttl_sec=self.cfg.lock_ttl_sec):
                        continue
                    tasks.append(asyncio.create_task(self._sync_one(feed)))
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(self.cfg.schedule_tick_sec)
        finally:
            await self.client.close()
            logger.info("intel_sync_worker_stop owner=%s", self._owner_id)

    def stop(self) -> None:
        self._stopping.set()

    async def _sync_one(self, feed: FeedConfig) -> None:
        async with _acquire(self._semaphore):
            start = time.perf_counter()
            logger.info("feed_sync_start id=%s name=%s url=%s", feed.id, feed.name, feed.url)
            try:
                fetch_res = await self.client.fetch(feed, feed.state)
                if fetch_res.not_modified:
                    feed.state.last_sync_at = _utcnow()
                    await self.repo.update_state(feed.id, feed.state)
                    await self.repo.release_lock(feed.id, self._owner_id)
                    self.metrics.counter("intel_sync_not_modified", 1, feed=feed.id)
                    logger.info("feed_not_modified id=%s", feed.id)
                    return

                indicators = parse_feed(feed, fetch_res)
                self.metrics.counter("intel_sync_fetched_items", len(indicators), feed=feed.id)
                # идемпотентное обновление
                await self._upsert_in_batches(feed, indicators)
                # мягкая очистка устаревших индикаторов (опционально)
                present_ids = [i.id for i in indicators]
                disabled = await self.sink.disable_missing(feed.id, present_ids)
                feed.state.total_disabled += int(disabled)

                # обновляем состояние
                feed.state.etag = fetch_res.etag or feed.state.etag
                feed.state.last_modified = fetch_res.last_modified or feed.state.last_modified
                feed.state.last_sync_at = _utcnow()
                feed.state.total_seen += len(indicators)
                feed.state.total_upserted += len(indicators)
                await self.sink.commit_checkpoint(feed.id, feed.state)
                await self.repo.update_state(feed.id, feed.state)
                self.metrics.histogram("intel_sync_duration_ms", (time.perf_counter() - start) * 1000, feed=feed.id)
                logger.info("feed_sync_done id=%s seen=%d disabled=%d", feed.id, len(indicators), disabled)
            except Exception as ex:
                logger.exception("feed_sync_error id=%s err=%s", feed.id, ex)
            finally:
                with contextlib.suppress(Exception):
                    await self.repo.release_lock(feed.id, self._owner_id)

    async def _upsert_in_batches(self, feed: FeedConfig, indicators: List[Indicator]) -> None:
        batch = max(1, int(feed.max_batch_upsert))
        if len(indicators) <= batch:
            await self.sink.upsert_many(feed.id, indicators)
            return
        for i in range(0, len(indicators), batch):
            await self.sink.upsert_many(feed.id, indicators[i:i+batch])

# =========================================
# УТИЛИТЫ
# =========================================
@contextlib.asynccontextmanager
async def _acquire(sem: asyncio.Semaphore):
    await sem.acquire()
    try:
        yield
    finally:
        sem.release()

class _NoopMetrics:
    def counter(self, name: str, value: int = 1, **labels: str) -> None:
        logger.debug("metric_counter name=%s value=%s labels=%s", name, value, labels)
    def histogram(self, name: str, value: float, **labels: str) -> None:
        logger.debug("metric_histogram name=%s value=%s labels=%s", name, value, labels)
    def gauge(self, name: str, value: float, **labels: str) -> None:
        logger.debug("metric_gauge name=%s value=%s labels=%s", name, value, labels)

# =========================================
# ДОКСТРИНГА ПРИМЕРА ИНТЕГРАЦИИ
# =========================================
"""
Пример интеграции:

class InMemoryRepo(FeedRepository):
    def __init__(self, feeds: List[FeedConfig]): self._feeds = {f.id: f}
    async def list_enabled(self): return [f for f in self._feeds.values() if f.enabled]
    async def update_state(self, feed_id, state): self._feeds[feed_id].state = state
    async def try_acquire_lock(self, feed_id, owner_id, ttl_sec): return True
    async def release_lock(self, feed_id, owner_id): return None

class MySink(IndicatorSink):
    async def upsert_many(self, feed_id, indicators): ...
    async def disable_missing(self, feed_id, present_indicator_ids): return 0
    async def commit_checkpoint(self, feed_id, state): ...

repo = InMemoryRepo([
    FeedConfig(id="feed1", name="Example JSON", url="https://ti.example/json", fmt="json", interval_sec=300),
])
sink = MySink()
worker = IntelSyncWorker(repo, sink)
await worker.run()
"""

__all__ = [
    "IntelSyncWorker",
    "WorkerConfig",
    "FeedConfig",
    "FeedState",
    "FeedAuth",
    "IndicatorSink",
    "FeedRepository",
    "RemoteFeedClient",
    "DefaultRemoteClient",
    "ParseError",
]
