# zero-trust-core/zero_trust/adapters/edr_adapter.py
# Industrial-grade EDR adapter layer for Zero Trust core.
# Stdlib-only. Async-first. Safe HTTP client with OAuth2/static token, rate limiting, retries, TLS context.
from __future__ import annotations

import abc
import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import random
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib import request as _urlreq
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin

logger = logging.getLogger(__name__)

EpochS = float

# =========================
# Utilities
# =========================

def _now() -> EpochS:
    return time.time()

def _utc_iso(ts: Union[int, float, datetime]) -> str:
    if isinstance(ts, (int, float)):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    elif isinstance(ts, datetime):
        dt = ts.astimezone(timezone.utc)
    else:
        dt = datetime.now(tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")

def _parse_iso(s: str) -> datetime:
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        # fallback RFC 3339-ish
        try:
            return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z")
        except Exception:
            return datetime.fromtimestamp(0, tz=timezone.utc)

def _clamp(x: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, x))

# =========================
# Redaction (privacy)
# =========================

@dataclass
class RedactionConfig:
    redact_keys: Tuple[str, ...] = ("username", "email", "userPrincipalName", "serialNumber", "deviceSerial", "apiKey", "token", "secret")
    replacement: str = "[REDACTED]"

def redact(obj: Any, cfg: RedactionConfig) -> Any:
    try:
        if isinstance(obj, Mapping):
            out = {}
            for k, v in obj.items():
                out[k] = cfg.replacement if k in cfg.redact_keys else redact(v, cfg)
            return out
        if isinstance(obj, list):
            return [redact(v, cfg) for v in obj]
        return obj
    except Exception:
        return cfg.replacement

# =========================
# Normalized models
# =========================

Severity = str  # "low"|"medium"|"high"|"critical"
State = str     # "open"|"in_progress"|"resolved"|"dismissed"|"unknown"

@dataclass
class EDRThreat:
    id: str
    vendor: str
    severity: Severity
    state: State
    device_id: str
    hostname: str = ""
    user: str = ""
    technique: str = ""
    rule: str = ""
    category: str = ""
    time_first: str = ""     # ISO8601
    time_last: str = ""      # ISO8601
    confidence: Optional[int] = None     # 0..100
    score: Optional[int] = None          # 0..100
    indicators: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EDRDevice:
    id: str
    platform: str
    hostname: str
    serial: str = ""
    os_version: str = ""
    last_seen: str = ""
    online: Optional[bool] = None
    isolation: Optional[str] = None
    sensor_version: str = ""
    health_status: str = ""
    risk_score: Optional[int] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    owner: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

# =========================
# HTTP Client with OAuth2/Token, retries, rate limiting
# =========================

@dataclass
class OAuth2Config:
    token_url: str
    client_id: str
    client_secret: str
    scope: Optional[str] = None
    audience: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)

@dataclass
class HttpClientConfig:
    base_url: str
    verify_ssl: bool = True
    ca_path: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    proxy: Optional[str] = None
    timeout_s: float = 10.0
    rate_per_sec: float = 10.0
    burst: int = 20
    max_retries: int = 4
    retry_backoff_s: float = 0.2
    retry_backoff_max_s: float = 3.0
    redaction: RedactionConfig = RedactionConfig()

class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = max(0.001, rate_per_sec)
        self.capacity = max(1, burst)
        self.tokens = self.capacity
        self.ts = _now()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            while True:
                now = _now()
                self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rate)
                self.ts = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                sleep_for = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(sleep_for)

class _AccessToken:
    def __init__(self):
        self.value: Optional[str] = None
        self.expiry: float = 0.0
        self.lock = threading.RLock()

    def get(self) -> Optional[str]:
        with self.lock:
            if self.value and _now() < self.expiry - 30:
                return self.value
            return None

    def set(self, token: str, expires_in: int) -> None:
        with self.lock:
            self.value = token
            self.expiry = _now() + max(60, expires_in)

class EDRHttpClient:
    def __init__(self, cfg: HttpClientConfig, *, static_bearer: Optional[str] = None, oauth2: Optional[OAuth2Config] = None, default_headers: Optional[Dict[str, str]] = None):
        self.cfg = cfg
        self.static_bearer = static_bearer
        self.oauth2 = oauth2
        self._token = _AccessToken()
        self._bucket = _TokenBucket(cfg.rate_per_sec, cfg.burst)
        self._default_headers = default_headers or {}

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.cfg.verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if not (self.cfg.ca_path or self.cfg.client_cert):
            return None
        ctx = ssl.create_default_context(cafile=self.cfg.ca_path if self.cfg.ca_path else None)
        if self.cfg.client_cert:
            ctx.load_cert_chain(self.cfg.client_cert, keyfile=self.cfg.client_key)
        return ctx

    async def _get_token(self) -> Optional[str]:
        if self.static_bearer:
            return self.static_bearer
        if not self.oauth2:
            return None
        cached = self._token.get()
        if cached:
            return cached
        # fetch new token (blocking in thread to keep stdlib)
        loop = asyncio.get_running_loop()
        def _do_fetch() -> Tuple[str, int]:
            data = {
                "grant_type": "client_credentials",
                "client_id": self.oauth2.client_id,
                "client_secret": self.oauth2.client_secret,
            }
            if self.oauth2.scope:
                data["scope"] = self.oauth2.scope
            if self.oauth2.audience:
                data["audience"] = self.oauth2.audience
            data.update(self.oauth2.extra or {})
            body = urlencode(data).encode("utf-8")
            req = _urlreq.Request(self.oauth2.token_url, data=body, headers={"content-type": "application/x-www-form-urlencoded"}, method="POST")
            ctx = self._ssl_context()
            with _urlreq.urlopen(req, timeout=self.cfg.timeout_s, context=ctx) as resp:
                b = resp.read().decode("utf-8", "replace")
                j = json.loads(b)
                token = j.get("access_token")
                expires = int(j.get("expires_in") or 3600)
                if not token:
                    raise RuntimeError("oauth2: no access_token")
                return token, expires
        token, expires = await loop.run_in_executor(None, _do_fetch)
        self._token.set(token, expires)
        return token

    async def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, json_body: Optional[Dict[str, Any]] = None) -> Tuple[int, Dict[str, str], str]:
        await self._bucket.acquire()
        url = urljoin(self.cfg.base_url.rstrip("/") + "/", path.lstrip("/"))
        if params:
            q = urlencode({k: v for k, v in params.items() if v is not None})
            if q:
                url = f"{url}?{q}"
        body_bytes: Optional[bytes] = None
        hdrs: Dict[str, str] = dict(self._default_headers)
        hdrs.update(headers or {})
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            hdrs.setdefault("content-type", "application/json")
        token = await self._get_token()
        if token:
            hdrs.setdefault("authorization", f"Bearer {token}")

        req = _urlreq.Request(url, data=body_bytes, headers=hdrs, method=method.upper())
        ctx = self._ssl_context()

        # retries with backoff
        retries = self.cfg.max_retries
        back = self.cfg.retry_backoff_s
        loop = asyncio.get_running_loop()
        while True:
            try:
                def _do():
                    opener = _urlreq.build_opener()
                    if self.cfg.proxy:
                        opener.add_handler(_urlreq.ProxyHandler({"http": self.cfg.proxy, "https": self.cfg.proxy}))
                    _urlreq.install_opener(opener)
                    with _urlreq.urlopen(req, timeout=self.cfg.timeout_s, context=ctx) as resp:
                        code = resp.getcode()
                        headers = {k.lower(): v for k, v in resp.getheaders()}
                        text = resp.read().decode(headers.get("content-type", "utf-8"), "replace")
                        return code, headers, text
                code, hdrs_r, text = await loop.run_in_executor(None, _do)
                if code >= 500 and retries > 0:
                    raise RuntimeError(f"http {code}")
                return code, hdrs_r, text
            except (HTTPError, URLError, RuntimeError) as e:
                if retries <= 0:
                    if isinstance(e, HTTPError):
                        try:
                            txt = e.read().decode("utf-8", "replace")
                        except Exception:
                            txt = str(e)
                        return e.code, {}, txt
                    raise
                # exponential backoff with jitter
                sleep = min(self.cfg.retry_backoff_max_s, back * (2 ** (self.cfg.max_retries - retries))) * (0.7 + 0.6 * random.random())
                await asyncio.sleep(sleep)
                retries -= 1

    async def get_json(self, path: str, *, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        code, hdrs, txt = await self._request("GET", path, params=params, headers=headers)
        if code >= 400:
            raise RuntimeError(f"GET {path} -> {code}: {txt[:200]}")
        try:
            return json.loads(txt)
        except Exception as e:
            raise RuntimeError(f"bad json: {e}") from e

    async def post_json(self, path: str, *, json_body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        code, hdrs, txt = await self._request("POST", path, json_body=json_body, headers=headers)
        if code >= 400:
            raise RuntimeError(f"POST {path} -> {code}: {txt[:200]}")
        try:
            return json.loads(txt) if txt else {}
        except Exception as e:
            raise RuntimeError(f"bad json: {e}") from e

# =========================
# Base adapter
# =========================

@dataclass
class Page:
    items: List[Any]
    next_cursor: Optional[str] = None

class BaseEDRAdapter(abc.ABC):
    """
    Base interface for EDR adapters; implementations should normalize vendor objects
    into EDRThreat / EDRDevice. All methods are async and stdlib-only.
    """
    def __init__(self, vendor: str, http: EDRHttpClient, *, redaction: RedactionConfig = RedactionConfig()):
        self.vendor = vendor
        self.http = http
        self.redaction = redaction

    @abc.abstractmethod
    async def fetch_detections(self, *, since: Optional[datetime] = None, until: Optional[datetime] = None, cursor: Optional[str] = None, limit: int = 200) -> Page:
        ...

    @abc.abstractmethod
    async def fetch_device(self, device_id: str) -> Optional[EDRDevice]:
        ...

    @abc.abstractmethod
    async def fetch_devices(self, *, filter: Optional[str] = None, cursor: Optional[str] = None, limit: int = 200) -> Page:
        ...

    @abc.abstractmethod
    async def isolate_device(self, device_id: str, *, reason: str = "", duration_minutes: Optional[int] = None) -> bool:
        ...

    @abc.abstractmethod
    async def release_isolation(self, device_id: str) -> bool:
        ...

    # Helpers: severity/state normalization
    @staticmethod
    def norm_severity(s: Any) -> Severity:
        if s is None:
            return "low"
        sv = str(s).strip().lower()
        if sv in ("critical", "crit", "severe"):
            return "critical"
        if sv in ("high", "sev3", "sev4"):
            return "high"
        if sv in ("medium", "moderate", "sev2"):
            return "medium"
        return "low"

    @staticmethod
    def norm_state(s: Any) -> State:
        if s is None:
            return "unknown"
        st = str(s).strip().lower()
        if st in ("new", "open", "opened", "unresolved"):
            return "open"
        if st in ("in_progress", "investigating", "triaged"):
            return "in_progress"
        if st in ("closed", "resolved", "fixed"):
            return "resolved"
        if st in ("suppressed", "dismissed", "ignored"):
            return "dismissed"
        return "unknown"

# =========================
# Generic JSON adapter (configurable mapping)
# =========================

@dataclass
class MappingSpec:
    # Detections
    det_list_path: str                       # JSON path to array with detections (dot.notation)
    det_cursor_path: Optional[str] = None    # JSON path to cursor/next token
    det_fields: Dict[str, str] = field(default_factory=dict)  # map normalized field -> json path
    det_time_first_fallback: Optional[str] = None
    det_time_last_fallback: Optional[str] = None

    # Devices
    dev_object_path: Optional[str] = None        # for single device fetch (optional)
    dev_list_path: Optional[str] = None
    dev_cursor_path: Optional[str] = None
    dev_fields: Dict[str, str] = field(default_factory=dict)

@dataclass
class GenericJSONConfig:
    # API paths (relative)
    detections_path: str
    devices_path: Optional[str] = None
    device_by_id_path: Optional[str] = None   # e.g. "/devices/{id}"
    isolate_path: Optional[str] = None        # e.g. "/devices/{id}/isolate"
    release_isolation_path: Optional[str] = None  # e.g. "/devices/{id}/unisolate"
    # Query parameter names
    qp_since: str = "since"
    qp_until: str = "until"
    qp_limit: str = "limit"
    qp_cursor: str = "cursor"
    # Mapping spec
    mapping: MappingSpec = field(default_factory=MappingSpec)

def _jget(obj: Any, path: Optional[str]) -> Any:
    if not path:
        return None
    cur = obj
    for p in path.split("."):
        if not isinstance(cur, Mapping) or p not in cur:
            return None
        cur = cur[p]
    return cur

class GenericJSONEDRAdapter(BaseEDRAdapter):
    """
    Generic adapter for JSON EDR APIs using a mapping spec. No vendor specifics inside.
    """
    def __init__(self, vendor: str, http: EDRHttpClient, cfg: GenericJSONConfig):
        super().__init__(vendor, http)
        self.cfg = cfg

    async def fetch_detections(self, *, since: Optional[datetime] = None, until: Optional[datetime] = None, cursor: Optional[str] = None, limit: int = 200) -> Page:
        params: Dict[str, Any] = {}
        if cursor:
            params[self.cfg.qp_cursor] = cursor
        else:
            if since:
                params[self.cfg.qp_since] = _utc_iso(since)
            if until:
                params[self.cfg.qp_until] = _utc_iso(until)
        params[self.cfg.qp_limit] = _clamp(limit, 1, 1000)

        data = await self.http.get_json(self.cfg.detections_path, params=params)
        arr = _jget(data, self.cfg.mapping.det_list_path) or []
        next_cursor = _jget(data, self.cfg.mapping.det_cursor_path)
        items: List[EDRThreat] = []
        for it in arr:
            t = self._map_detection(it)
            items.append(t)
        return Page(items=items, next_cursor=next_cursor)

    async def fetch_device(self, device_id: str) -> Optional[EDRDevice]:
        if not self.cfg.device_by_id_path:
            return None
        path = self.cfg.device_by_id_path.format(id=device_id)
        data = await self.http.get_json(path)
        obj = data if self.cfg.mapping.dev_object_path is None else _jget(data, self.cfg.mapping.dev_object_path)
        if obj is None:
            return None
        return self._map_device(obj)

    async def fetch_devices(self, *, filter: Optional[str] = None, cursor: Optional[str] = None, limit: int = 200) -> Page:
        if not self.cfg.devices_path or not self.cfg.mapping.dev_list_path:
            return Page(items=[], next_cursor=None)
        params: Dict[str, Any] = {self.cfg.qp_limit: _clamp(limit, 1, 1000)}
        if cursor:
            params[self.cfg.qp_cursor] = cursor
        if filter:
            params["filter"] = filter
        data = await self.http.get_json(self.cfg.devices_path, params=params)
        arr = _jget(data, self.cfg.mapping.dev_list_path) or []
        next_cursor = _jget(data, self.cfg.mapping.dev_cursor_path)
        items = [self._map_device(it) for it in arr]
        return Page(items=items, next_cursor=next_cursor)

    async def isolate_device(self, device_id: str, *, reason: str = "", duration_minutes: Optional[int] = None) -> bool:
        if not self.cfg.isolate_path:
            return False
        path = self.cfg.isolate_path.format(id=device_id)
        payload = {"reason": reason}
        if duration_minutes:
            payload["duration_minutes"] = int(duration_minutes)
        try:
            await self.http.post_json(path, json_body=payload)
            return True
        except Exception as e:
            logger.warning("isolate_device failed: %s", e)
            return False

    async def release_isolation(self, device_id: str) -> bool:
        if not self.cfg.release_isolation_path:
            return False
        path = self.cfg.release_isolation_path.format(id=device_id)
        try:
            await self.http.post_json(path, json_body={})
            return True
        except Exception as e:
            logger.warning("release_isolation failed: %s", e)
            return False

    # ----- Mapping helpers -----

    def _map_detection(self, obj: Mapping[str, Any]) -> EDRThreat:
        m = self.cfg.mapping.det_fields
        def f(name: str) -> Any:
            return _jget(obj, m.get(name))
        sid = str(f("id") or f("alert_id") or f("detection_id") or "")
        dev = str(f("device_id") or f("agent_id") or f("host_id") or "")
        sev = self.norm_severity(f("severity"))
        st = self.norm_state(f("state"))
        t_first = f("time_first") or f("created_at") or f("timestamp") or ""
        t_last  = f("time_last")  or f("updated_at") or f("timestamp") or ""
        if not t_first and self.cfg.mapping.det_time_first_fallback:
            t_first = _jget(obj, self.cfg.mapping.det_time_first_fallback) or ""
        if not t_last and self.cfg.mapping.det_time_last_fallback:
            t_last = _jget(obj, self.cfg.mapping.det_time_last_fallback) or t_first
        try:
            t_first = _utc_iso(_parse_iso(str(t_first)))
        except Exception:
            t_first = ""
        try:
            t_last = _utc_iso(_parse_iso(str(t_last)))
        except Exception:
            t_last = ""

        ind = f("indicators") or []
        if isinstance(ind, str):
            ind = [ind]
        tags = f("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        raw = redact(dict(obj), self.redaction) if isinstance(obj, dict) else {}

        return EDRThreat(
            id=sid or hashlib.sha1(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:16],
            vendor=self.vendor,
            severity=sev,
            state=st,
            device_id=dev,
            hostname=str(f("hostname") or ""),
            user=str(f("user") or f("principal") or ""),
            technique=str(f("technique") or ""),
            rule=str(f("rule") or f("rule_name") or ""),
            category=str(f("category") or ""),
            time_first=t_first,
            time_last=t_last,
            confidence=self._to_int(f("confidence")),
            score=self._to_int(f("score")),
            indicators=[str(x) for x in ind if x is not None],
            tags=[str(x) for x in tags if x is not None],
            raw=raw,
        )

    def _map_device(self, obj: Mapping[str, Any]) -> EDRDevice:
        m = self.cfg.mapping.dev_fields
        def f(name: str) -> Any:
            return _jget(obj, m.get(name))
        last_seen = str(f("last_seen") or "")
        try:
            last_seen = _utc_iso(_parse_iso(last_seen)) if last_seen else ""
        except Exception:
            pass
        raw = redact(dict(obj), self.redaction) if isinstance(obj, dict) else {}
        return EDRDevice(
            id=str(f("id") or f("device_id") or f("agent_id") or ""),
            platform=str(f("platform") or "").lower(),
            hostname=str(f("hostname") or f("device_name") or ""),
            serial=str(f("serial") or ""),
            os_version=str(f("os_version") or ""),
            last_seen=last_seen,
            online=self._to_bool(f("online")),
            isolation=str(f("isolation") or ""),
            sensor_version=str(f("sensor_version") or ""),
            health_status=str(f("health_status") or ""),
            risk_score=self._to_int(f("risk_score")),
            ip=str(f("ip") or ""),
            mac=str(f("mac") or ""),
            owner=str(f("owner") or ""),
            raw=raw,
        )

    @staticmethod
    def _to_int(v: Any) -> Optional[int]:
        try:
            return int(v)
        except Exception:
            return None

    @staticmethod
    def _to_bool(v: Any) -> Optional[bool]:
        if v is None:
            return None
        if isinstance(v, bool):
            return v
        s = str(v).lower().strip()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off"):
            return False
        return None

# =========================
# Example vendor skeletons (заготовки)
# Примечание: эндпойнты/поля зависят от конкретной версии API вендора; требуется конфигурация.
# Я не подтверждаю конкретные URL/поля для любых вендоров — это каркас.
# =========================

class CrowdStrikeAdapter(GenericJSONEDRAdapter):
    """
    Каркас: заполните GenericJSONConfig маппингом под официальный API.
    I cannot verify this.
    """
    pass

class DefenderATPAdapter(GenericJSONEDRAdapter):
    """
    Каркас: заполните GenericJSONConfig маппингом под официальный API.
    I cannot verify this.
    """
    pass

class SentinelOneAdapter(GenericJSONEDRAdapter):
    """
    Каркас: заполните GenericJSONConfig маппингом под официальный API.
    I cannot verify this.
    """
    pass

# =========================
# High-level helpers
# =========================

async def sync_windowed(
    adapter: BaseEDRAdapter,
    *,
    since: datetime,
    until: datetime,
    step: timedelta = timedelta(minutes=15),
    page_limit: int = 500,
) -> List[EDRThreat]:
    """
    Итератор по окнам времени для API без курсоров: разбивает диапазон на окна и собирает все детекции.
    """
    results: List[EDRThreat] = []
    cur = since
    while cur < until:
        nxt = min(cur + step, until)
        page = await adapter.fetch_detections(since=cur, until=nxt, limit=page_limit)
        results.extend(page.items)
        cur = nxt
    return results

async def sync_cursor_paginated(
    adapter: BaseEDRAdapter,
    *,
    cursor: Optional[str] = None,
    page_limit: int = 500,
    max_pages: int = 100,
) -> Tuple[List[EDRThreat], Optional[str]]:
    """
    Итератор по курсору для API с постраничной навигацией: собирает до max_pages страниц.
    """
    out: List[EDRThreat] = []
    cur = cursor
    pages = 0
    while pages < max_pages:
        page = await adapter.fetch_detections(cursor=cur, limit=page_limit)
        out.extend(page.items)
        if not page.next_cursor:
            return out, None
        cur = page.next_cursor
        pages += 1
    return out, cur

# =========================
# Example configuration (без фактических URL/полей)
# =========================

def example_adapter() -> GenericJSONEDRAdapter:
    """
    Пример инициализации универсального адаптера. Все пути/поля — заглушки.
    I cannot verify this.
    """
    http = EDRHttpClient(
        HttpClientConfig(base_url="https://edr.example.com/api/", verify_ssl=True, rate_per_sec=5.0, burst=10),
        static_bearer=os.getenv("EDR_BEARER_TOKEN"),
        oauth2=None,
        default_headers={"accept": "application/json"},
    )
    mapping = MappingSpec(
        det_list_path="data.detections",
        det_cursor_path="meta.next",
        det_fields={
            "id": "id",
            "device_id": "device.id",
            "severity": "severity",
            "state": "status",
            "hostname": "device.hostname",
            "user": "user.name",
            "technique": "mitre.technique",
            "rule": "rule.name",
            "category": "category",
            "time_first": "timestamps.first",
            "time_last": "timestamps.last",
            "confidence": "confidence",
            "score": "score",
            "indicators": "iocs",
            "tags": "tags",
        },
        dev_list_path="data.devices",
        dev_cursor_path="meta.next",
        dev_fields={
            "id": "id",
            "platform": "platform",
            "hostname": "hostname",
            "serial": "serial",
            "os_version": "os.version",
            "last_seen": "last_seen",
            "online": "online",
            "isolation": "isolation.state",
            "sensor_version": "sensor.version",
            "health_status": "health.status",
            "risk_score": "risk.score",
            "ip": "network.ip",
            "mac": "network.mac",
            "owner": "owner",
        },
    )
    cfg = GenericJSONConfig(
        detections_path="/v1/detections",
        devices_path="/v1/devices",
        device_by_id_path="/v1/devices/{id}",
        isolate_path="/v1/devices/{id}/isolate",
        release_isolation_path="/v1/devices/{id}/unisolate",
        mapping=mapping,
    )
    return GenericJSONEDRAdapter("generic-edr", http, cfg)
