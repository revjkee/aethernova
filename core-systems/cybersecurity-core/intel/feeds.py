# cybersecurity-core/cybersecurity/intel/feeds.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Threat Intelligence Feeds ingestion module.

Highlights:
- Async ingestion engine with pluggable connectors:
  * TAXII 2.1 (collections polling via added_after cursor)
  * Generic HTTP feed (JSON path mapping / CSV)
- Strict Pydantic models (v2 preferred; v1 compatible)
- Indicator normalization & validation (ip, domain, url, hashes)
- Idempotent bulk upsert via repository interface
- Resilience: retry with exponential backoff + jitter, token-bucket rate limiting
- HTTP caching: ETag/If-None-Match, gzip/deflate handling
- Optional OpenTelemetry spans
- Optional GPG signature verification (detached signature)
- Structured logs with correlation IDs, ingestion metrics & per-feed report

Dependencies:
    httpx>=0.25
    pydantic>=1.10 (v2 supported)
Optional:
    opentelemetry-api (tracing)
    python-gnupg or system gpg (via subprocess; auto-detected)
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import hashlib
import io
import json
import logging
import os
import re
import shlex
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    Any,
    AsyncIterator,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

import httpx

# --- Pydantic v2/v1 compatibility --------------------------------------------
try:
    from pydantic import BaseModel, Field, ValidationError  # type: ignore
    from pydantic import __version__ as _pyd_ver  # type: ignore

    PydanticV2 = _pyd_ver.startswith("2.")
except Exception:  # pragma: no cover
    from pydantic.v1 import BaseModel, Field, ValidationError  # type: ignore

    PydanticV2 = False

# --- Optional OpenTelemetry ---------------------------------------------------
try:
    from opentelemetry import trace  # type: ignore

    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None  # type: ignore

# --- Logging ------------------------------------------------------------------
logger = logging.getLogger("ti_feeds")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(os.getenv("TI_FEEDS_LOG_LEVEL", "INFO"))

# --- Utilities ----------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = int(burst)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            await self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            deficit = tokens - self._tokens
            wait_s = max(0.0, deficit / self.rate) if self.rate > 0 else 0.0
            if wait_s > 0:
                await asyncio.sleep(wait_s)
            await self._refill()
            self._tokens = max(0.0, self._tokens - tokens)

    async def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + delta * self.rate)


@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay_ms: int = 200
    max_delay_ms: int = 5000
    multiplier: float = 2.0
    jitter_ms: int = 100
    retry_on_status: Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)

    def delay_ms(self, attempt: int) -> int:
        from random import randint

        if attempt <= 1:
            backoff = self.base_delay_ms
        else:
            backoff = min(int(self.base_delay_ms * (self.multiplier ** (attempt - 1))), self.max_delay_ms)
        return backoff + randint(0, self.jitter_ms)

    def should_retry(self, attempt: int, status: Optional[int], exc: Optional[Exception]) -> bool:
        if attempt >= self.max_attempts:
            return False
        if exc is not None:
            return True
        return status in self.retry_on_status if status is not None else False


# --- Indicator models & helpers ----------------------------------------------
IndicatorType = Union[
    "ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email", "cidr"
]


class Indicator(BaseModel):
    key: str  # stable unique key (type:value normalized)
    type: str  # one of IndicatorType
    value: str  # normalized
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    tlp: Optional[str] = Field(default=None, regex=r"^(?i)(tlp:(clear|white|green|amber|red))$")
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    description: Optional[str] = None
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    raw: Optional[Dict[str, Any]] = None


class FeedState(BaseModel):
    cursor: Optional[str] = None        # e.g., TAXII added_after or vendor cursor
    etag: Optional[str] = None          # ETag for HTTP caching
    last_status: Optional[int] = None
    last_success_at: Optional[datetime] = None
    last_error_at: Optional[datetime] = None


class FeedMetrics(BaseModel):
    bytes_in: int = 0
    http_status: Optional[int] = None
    indicators_total: int = 0
    indicators_new: int = 0
    indicators_updated: int = 0
    errors: int = 0
    started_at: datetime = Field(default_factory=now_utc)
    finished_at: Optional[datetime] = None
    duration_s: Optional[float] = None


class FeedReport(BaseModel):
    feed: str
    source: str
    state_before: FeedState
    state_after: FeedState
    metrics: FeedMetrics
    errors: List[str] = Field(default_factory=list)


class FeedConfig(BaseModel):
    name: str
    kind: str  # "taxii21" | "http-json" | "http-csv"
    url: str
    method: str = "GET"
    headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, Any] = Field(default_factory=dict)
    verify_tls: bool = True
    proxies: Optional[Mapping[str, str]] = None
    timeout_s: float = 20.0

    # For TAXII 2.1
    taxii_collection: Optional[str] = None          # collection URL or ID
    taxii_added_after_field: str = "added_after"    # query param name

    # For http-json/http-csv mapping
    json_path_items: Optional[str] = None           # dotted path to list in JSON
    json_mapping: Dict[str, str] = Field(default_factory=dict)  # type -> value path, e.g. {"type": "kind", "value": "ioc"}
    csv_dialect: str = "excel"
    csv_has_header: bool = True
    csv_columns: Dict[str, str] = Field(default_factory=dict)   # mapping of csv column -> indicator parts

    # Security & rate limit
    require_gpg: bool = False
    gpg_sig_url: Optional[str] = None
    rate_limit_per_sec: float = 5.0
    rate_burst: int = 10

    # Correlation
    correlation_id: Optional[str] = None


# --- Repository protocol ------------------------------------------------------
class IntelRepository(Protocol):
    async def get_state(self, feed_name: str) -> FeedState:
        ...

    async def save_state(self, feed_name: str, state: FeedState) -> None:
        ...

    async def bulk_upsert(self, indicators: List[Indicator]) -> Tuple[int, int]:
        """
        Upsert list of indicators.
        Returns (new_count, updated_count).
        """
        ...


# Optional in-memory repo for tests/smoke --------------------------------------
class MemoryIntelRepository:
    def __init__(self) -> None:
        self._state: Dict[str, FeedState] = {}
        self._store: Dict[str, Indicator] = {}

    async def get_state(self, feed_name: str) -> FeedState:
        return self._state.get(feed_name, FeedState())

    async def save_state(self, feed_name: str, state: FeedState) -> None:
        self._state[feed_name] = state

    async def bulk_upsert(self, indicators: List[Indicator]) -> Tuple[int, int]:
        new = 0
        updated = 0
        for ind in indicators:
            prev = self._store.get(ind.key)
            if prev is None:
                self._store[ind.key] = ind
                new += 1
            else:
                # Update minimal mutable fields
                changed = False
                for attr in ("confidence", "tlp", "tags", "valid_from", "valid_until", "description", "modified_at", "raw", "source"):
                    nv = getattr(ind, attr)
                    pv = getattr(prev, attr)
                    if nv != pv and nv is not None:
                        setattr(prev, attr, nv)
                        changed = True
                updated += 1 if changed else 0
        return new, updated


# --- IoC normalization & validation ------------------------------------------
_i_ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_i_ipv6 = re.compile(r"^[0-9A-Fa-f:]+$")
_i_domain = re.compile(r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
_i_email = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_i_url = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://")
_i_md5 = re.compile(r"^[a-fA-F0-9]{32}$")
_i_sha1 = re.compile(r"^[a-fA-F0-9]{40}$")
_i_sha256 = re.compile(r"^[a-fA-F0-9]{64}$")

def _norm(value: str) -> str:
    return value.strip()

def _norm_domain(v: str) -> str:
    return v.strip().lower().rstrip(".")

def _norm_url(v: str) -> str:
    v = v.strip()
    # lower scheme+host; keep path/query
    try:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(v)
        netloc = parts.netloc.lower()
        scheme = parts.scheme.lower()
        # remove default ports
        if ":" in netloc:
            host, port = netloc.rsplit(":", 1)
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host
        # drop fragment
        return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    except Exception:
        return v

def _norm_ip(v: str) -> str:
    return v.strip().lower()

def _norm_hash(v: str) -> str:
    return v.strip().lower()

def indicator_key(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{value}"

def normalize_indicator(ioc_type: str, value: str) -> Optional[Tuple[str, str]]:
    t = ioc_type.lower().strip()
    v = value.strip()
    if t == "ipv4":
        if _i_ipv4.match(v): return t, _norm_ip(v)
        return None
    if t == "ipv6":
        if _i_ipv6.match(v): return t, _norm_ip(v)
        return None
    if t == "domain":
        if _i_domain.match(_norm_domain(v)): return t, _norm_domain(v)
        return None
    if t == "url":
        if _i_url.match(v): return t, _norm_url(v)
        return None
    if t == "email":
        if _i_email.match(v): return t, v.lower()
        return None
    if t in ("md5", "sha1", "sha256"):
        if (t == "md5" and _i_md5.match(v)) or (t == "sha1" and _i_sha1.match(v)) or (t == "sha256" and _i_sha256.match(v)):
            return t, _norm_hash(v)
        return None
    if t == "cidr":
        return t, v.lower()
    return None


# --- STIX/TAXII helpers -------------------------------------------------------
_stix_indicator_pat = re.compile(
    r"^\s*\[\s*([a-z0-9\-]+):([a-z0-9_\-]+)\s*=\s*'([^']+)'\s*\]\s*$", re.I
)

def parse_stix_indicator(obj: Mapping[str, Any]) -> Optional[Indicator]:
    """
    Minimal STIX 2.1 indicator parser for patterns like:
      [domain-name:value = 'example.com']
      [ipv4-addr:value = '1.2.3.4']
      [url:value = 'http://x']
      [file:hashes.'SHA-256' = '...']  -> simplified mapping to type 'sha256'
    """
    t = obj.get("type")
    if t != "indicator":
        return None
    pattern = obj.get("pattern") or ""
    m = _stix_indicator_pat.match(pattern)
    if not m:
        # Try file hash special case
        if "file:hashes" in pattern and "SHA-256" in pattern.upper():
            hv = re.search(r"(?i)file:hashes\.'?SHA-256'?\s*=\s*'([A-Fa-f0-9]{64})'", pattern)
            if hv:
                tp, val = "sha256", hv.group(1)
            else:
                return None
        else:
            return None
    else:
        obj_type, field, val = m.group(1), m.group(2), m.group(3)
        mapping = {
            "domain-name": ("domain", val),
            "ipv4-addr": ("ipv4", val),
            "ipv6-addr": ("ipv6", val),
            "url": ("url", val),
            "email-addr": ("email", val),
        }
        if obj_type in mapping:
            tp, val = mapping[obj_type]
        else:
            return None

    # Normalize & build indicator
    norm = normalize_indicator(tp, val)
    if not norm:
        return None
    tp, valn = norm
    key = indicator_key(tp, valn)
    conf = obj.get("confidence")
    conf = int(conf) if isinstance(conf, (int, float)) else None
    tlp = None
    # STIX marking TLP parse (simplified)
    for mdef in obj.get("object_marking_refs", []):
        if isinstance(mdef, str) and "tlp" in mdef.lower():
            if "red" in mdef.lower(): tlp = "tlp:red"
            elif "amber" in mdef.lower(): tlp = "tlp:amber"
            elif "green" in mdef.lower(): tlp = "tlp:green"
            elif "white" in mdef.lower() or "clear" in mdef.lower(): tlp = "tlp:clear"
    created = obj.get("created")
    modified = obj.get("modified")
    def _dt(s):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
    return Indicator(
        key=key,
        type=tp,
        value=valn,
        confidence=conf,
        tlp=tlp,
        source="taxii",
        created_at=_dt(created),
        modified_at=_dt(modified),
        description=obj.get("name") or obj.get("description"),
        raw=obj if isinstance(obj, dict) else None,
    )


# --- HTTP client wrapper ------------------------------------------------------
class Http:
    def __init__(self, verify: bool, proxies: Optional[Mapping[str, str]], timeout_s: float, retry: RetryPolicy, rate: TokenBucket) -> None:
        self.verify = verify
        self.proxies = proxies
        self.timeout_s = timeout_s
        self.retry = retry
        self.rate = rate
        self._client = httpx.AsyncClient(verify=verify, proxies=proxies, timeout=timeout_s, headers={"User-Agent": "Aethernova-TI/1.0"})

    async def close(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        data: Optional[Union[bytes, Mapping[str, Any]]] = None,
        etag: Optional[str] = None,
    ) -> httpx.Response:
        await self.rate.acquire()
        hdrs = dict(headers or {})
        if etag:
            hdrs["If-None-Match"] = etag

        attempt = 0
        last_status = None
        last_exc: Optional[Exception] = None
        while True:
            attempt += 1
            try:
                resp = await self._client.request(method, url, headers=hdrs, params=params, data=data)
                if resp.status_code == 304:
                    return resp
                if resp.status_code < 400:
                    return resp
                last_status = resp.status_code
                if self.retry.should_retry(attempt, last_status, None):
                    await asyncio.sleep(self.retry.delay_ms(attempt) / 1000.0)
                    continue
                return resp
            except httpx.RequestError as exc:
                last_exc = exc
                if self.retry.should_retry(attempt, None, exc):
                    await asyncio.sleep(self.retry.delay_ms(attempt) / 1000.0)
                    continue
                raise


# --- GPG signature verification (optional) -----------------------------------
def verify_gpg_detached(content: bytes, sig_bytes: bytes) -> bool:
    """
    Uses system gpg if available. Returns True if signature verifies.
    """
    gpg = "gpg"
    try:
        proc = subprocess.run([gpg, "--batch", "--status-fd", "1", "--verify", "-"], input=sig_bytes + b"\n", capture_output=True)
        # The above won't work without a file; fallback to temp files
        raise RuntimeError("pipe-verify not supported")
    except Exception:
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as f_content, tempfile.NamedTemporaryFile(delete=False) as f_sig:
            f_content.write(content)
            f_content.flush()
            f_sig.write(sig_bytes)
            f_sig.flush()
            try:
                proc = subprocess.run([gpg, "--batch", "--verify", f_sig.name, f_content.name], capture_output=True)
                return proc.returncode == 0
            finally:
                try:
                    os.unlink(f_content.name)
                except Exception:
                    pass
                try:
                    os.unlink(f_sig.name)
                except Exception:
                    pass


# --- Connector Protocol -------------------------------------------------------
class FeedConnector(Protocol):
    async def fetch(self, http: Http, cfg: FeedConfig, state: FeedState) -> Tuple[List[Indicator], FeedState, FeedMetrics, List[str]]:
        """
        Return indicators, new state, metrics, errors.
        Must not raise on normal HTTP errors; convert to report errors and propagate state.
        """
        ...


# --- TAXII 2.1 connector ------------------------------------------------------
class Taxii21Connector:
    """
    Minimal TAXII 2.1 polling against a collection URL.
    Expects cfg.url == collection objects endpoint or collection URL (auto appends /objects).
    Uses state.cursor as added_after (RFC3339).
    """
    def __init__(self) -> None:
        pass

    async def fetch(self, http: Http, cfg: FeedConfig, state: FeedState) -> Tuple[List[Indicator], FeedState, FeedMetrics, List[str]]:
        metrics = FeedMetrics()
        errors: List[str] = []

        url = cfg.url.rstrip("/")
        if not url.endswith("/objects"):
            url = f"{url}/objects"

        params = dict(cfg.params or {})
        if state.cursor:
            params[cfg.taxii_added_after_field] = state.cursor

        # TAXII pages via next parameter in response 'more' and 'next'
        collected: List[Indicator] = []
        next_val: Optional[str] = None
        page = 0

        while True:
            page += 1
            if next_val:
                params["next"] = next_val

            resp = await http.request(cfg.method, url, headers=cfg.headers, params=params, etag=None)
            metrics.http_status = resp.status_code
            if resp.status_code == 304:
                # not modified
                break
            if resp.status_code >= 400:
                errors.append(f"HTTP {resp.status_code} on page {page}: {resp.text[:200]}")
                state.last_status = resp.status_code
                state.last_error_at = now_utc()
                break

            data = resp.content
            metrics.bytes_in += len(data)
            try:
                payload = json.loads(data.decode("utf-8"))
            except Exception as e:
                errors.append(f"Invalid JSON: {e}")
                break

            objs = payload.get("objects", [])
            for obj in objs:
                try:
                    ind = parse_stix_indicator(obj)
                    if not ind:
                        continue
                    collected.append(ind)
                except Exception as e:
                    errors.append(f"STIX parse error: {e}")

            # Cursor management
            more = bool(payload.get("more"))
            next_val = payload.get("next")
            if not more or not next_val:
                # Advance cursor to current time (conservative) or use 'next' if RFC3339
                state.cursor = datetime.now(timezone.utc).isoformat()
                break

        metrics.indicators_total = len(collected)
        state.last_status = metrics.http_status
        if errors:
            state.last_error_at = now_utc()
        else:
            state.last_success_at = now_utc()
        metrics.finished_at = now_utc()
        metrics.duration_s = (metrics.finished_at - metrics.started_at).total_seconds()
        return collected, state, metrics, errors


# --- Generic HTTP JSON/CSV connector -----------------------------------------
def _get_dotted(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                idx = int(part)
                cur = cur[idx]
            except Exception:
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


class HttpGenericConnector:
    """
    Supports:
      - http-json: parse JSON list under json_path_items and map fields via json_mapping
      - http-csv: parse CSV (with or without header) and use csv_columns mapping
    """
    def __init__(self) -> None:
        pass

    async def fetch(self, http: Http, cfg: FeedConfig, state: FeedState) -> Tuple[List[Indicator], FeedState, FeedMetrics, List[str]]:
        metrics = FeedMetrics()
        errors: List[str] = []

        # GET with ETag
        resp = await http.request(cfg.method, cfg.url, headers=cfg.headers, params=cfg.params, etag=state.etag)
        metrics.http_status = resp.status_code
        if resp.status_code == 304:
            metrics.finished_at = now_utc()
            metrics.duration_s = (metrics.finished_at - metrics.started_at).total_seconds()
            return [], state, metrics, errors

        if resp.status_code >= 400:
            errors.append(f"HTTP {resp.status_code}: {resp.text[:200]}")
            state.last_status = resp.status_code
            state.last_error_at = now_utc()
            metrics.finished_at = now_utc()
            metrics.duration_s = (metrics.finished_at - metrics.started_at).total_seconds()
            return [], state, metrics, errors

        # ETag update
        etag = resp.headers.get("ETag")
        if etag:
            state.etag = etag

        # Decompress if needed
        content = resp.content
        metrics.bytes_in += len(content)
        ct = resp.headers.get("Content-Type", "")

        # Optional GPG verification (detached signature)
        if cfg.require_gpg:
            if not cfg.gpg_sig_url:
                errors.append("GPG required but no gpg_sig_url provided")
                return [], state, metrics, errors
            sig_resp = await http.request("GET", cfg.gpg_sig_url, headers=cfg.headers, params=None)
            if sig_resp.status_code >= 400:
                errors.append(f"GPG signature fetch failed: HTTP {sig_resp.status_code}")
                return [], state, metrics, errors
            sig_bytes = sig_resp.content
            if not verify_gpg_detached(content, sig_bytes):
                errors.append("GPG signature verification failed")
                return [], state, metrics, errors

        if resp.headers.get("Content-Encoding", "").lower() == "gzip" or (ct and "gzip" in ct.lower()):
            try:
                content = gzip.decompress(content)
            except Exception:
                pass

        indicators: List[Indicator] = []
        if cfg.kind == "http-json":
            try:
                doc = json.loads(content.decode("utf-8"))
            except Exception as e:
                errors.append(f"Invalid JSON: {e}")
                return [], state, metrics, errors
            items = doc
            if cfg.json_path_items:
                items = _get_dotted(doc, cfg.json_path_items) or []
            if not isinstance(items, list):
                errors.append("json_path_items does not point to a list")
                return [], state, metrics, errors
            for row in items:
                try:
                    i_type_raw = _get_dotted(row, cfg.json_mapping.get("type", "type"))
                    i_value_raw = _get_dotted(row, cfg.json_mapping.get("value", "value"))
                    if i_type_raw is None or i_value_raw is None:
                        continue
                    norm = normalize_indicator(str(i_type_raw), str(i_value_raw))
                    if not norm:
                        continue
                    i_type, i_value = norm
                    ind = Indicator(
                        key=indicator_key(i_type, i_value),
                        type=i_type,
                        value=i_value,
                        confidence=_safe_int(_get_dotted(row, cfg.json_mapping.get("confidence", "confidence"))),
                        tlp=_safe_tlp(_get_dotted(row, cfg.json_mapping.get("tlp", "tlp"))),
                        source=cfg.name,
                        tags=_listify(_get_dotted(row, cfg.json_mapping.get("tags", "tags"))),
                        valid_from=_safe_dt(_get_dotted(row, cfg.json_mapping.get("valid_from", "valid_from"))),
                        valid_until=_safe_dt(_get_dotted(row, cfg.json_mapping.get("valid_until", "valid_until"))),
                        description=_stringify(_get_dotted(row, cfg.json_mapping.get("description", "description"))),
                        created_at=_safe_dt(_get_dotted(row, cfg.json_mapping.get("created_at", "created_at"))),
                        modified_at=_safe_dt(_get_dotted(row, cfg.json_mapping.get("modified_at", "modified_at"))),
                        raw=row if isinstance(row, dict) else None,
                    )
                    indicators.append(ind)
                except Exception as e:
                    errors.append(f"row error: {e}")

        elif cfg.kind == "http-csv":
            buf = io.StringIO(content.decode("utf-8", errors="ignore"))
            reader = csv.DictReader(buf) if cfg.csv_has_header else csv.reader(buf, dialect=cfg.csv_dialect)
            for row in reader:
                try:
                    if cfg.csv_has_header:
                        i_type_raw = row.get(cfg.csv_columns.get("type", "type"))
                        i_value_raw = row.get(cfg.csv_columns.get("value", "value"))
                    else:
                        # for csv without header, user must provide numeric indices in csv_columns
                        def _col(name: str) -> Optional[str]:
                            idx = int(cfg.csv_columns.get(name, "-1"))
                            return row[idx] if isinstance(row, list) and 0 <= idx < len(row) else None
                        i_type_raw = _col("type")
                        i_value_raw = _col("value")
                    if not i_type_raw or not i_value_raw:
                        continue
                    norm = normalize_indicator(str(i_type_raw), str(i_value_raw))
                    if not norm:
                        continue
                    i_type, i_value = norm
                    ind = Indicator(
                        key=indicator_key(i_type, i_value),
                        type=i_type,
                        value=i_value,
                        confidence=_safe_int(_get_col(row, cfg, "confidence")),
                        tlp=_safe_tlp(_get_col(row, cfg, "tlp")),
                        source=cfg.name,
                        tags=_listify(_get_col(row, cfg, "tags")),
                        description=_stringify(_get_col(row, cfg, "description")),
                    )
                    indicators.append(ind)
                except Exception as e:
                    errors.append(f"csv row error: {e}")
        else:
            errors.append(f"Unsupported kind for HttpGenericConnector: {cfg.kind}")

        metrics.indicators_total = len(indicators)
        state.last_status = metrics.http_status
        if errors:
            state.last_error_at = now_utc()
        else:
            state.last_success_at = now_utc()
        metrics.finished_at = now_utc()
        metrics.duration_s = (metrics.finished_at - metrics.started_at).total_seconds()
        return indicators, state, metrics, errors


def _safe_dt(v: Any) -> Optional[datetime]:
    if not v:
        return None
    try:
        s = str(v)
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _safe_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except Exception:
        return None


def _safe_tlp(v: Any) -> Optional[str]:
    if not v:
        return None
    s = str(v).lower()
    if s.startswith("tlp:"):
        return s
    if s in ("clear", "white", "green", "amber", "red"):
        return f"tlp:{s}"
    return None


def _listify(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def _get_col(row: Union[Mapping[str, Any], Sequence[Any]], cfg: FeedConfig, field: str) -> Any:
    if cfg.csv_has_header and isinstance(row, Mapping):
        col = cfg.csv_columns.get(field, field)
        return row.get(col)
    if not cfg.csv_has_header and isinstance(row, Sequence):
        try:
            idx = int(cfg.csv_columns.get(field, "-1"))
            return row[idx] if 0 <= idx < len(row) else None
        except Exception:
            return None
    return None


# --- Orchestrator -------------------------------------------------------------
class FeedsOrchestrator:
    """
    Orchestrates ingestion across multiple feeds with shared HTTP client,
    rate limiting and per-feed isolation.
    """
    def __init__(self, repository: IntelRepository, retry: Optional[RetryPolicy] = None) -> None:
        self.repo = repository
        self.retry = retry or RetryPolicy()

    async def ingest_feed(self, cfg: FeedConfig) -> FeedReport:
        correlation_id = cfg.correlation_id or str(uuid.uuid4())
        rate = TokenBucket(cfg.rate_limit_per_sec, cfg.rate_burst)
        http = Http(cfg.verify_tls, cfg.proxies, cfg.timeout_s, self.retry, rate)
        state_before = await self.repo.get_state(cfg.name)
        state = FeedState(**(state_before.dict() if hasattr(state_before, "dict") else state_before.__dict__))  # shallow copy

        # Choose connector
        connector: FeedConnector
        if cfg.kind == "taxii21":
            connector = Taxii21Connector()
        elif cfg.kind in ("http-json", "http-csv"):
            connector = HttpGenericConnector()
        else:
            # Unknown kind
            report = FeedReport(
                feed=cfg.name,
                source=cfg.url,
                state_before=state_before,
                state_after=state_before,
                metrics=FeedMetrics(),
                errors=[f"Unsupported feed kind: {cfg.kind}"],
            )
            await http.close()
            return report

        # Tracing
        span_ctx = _tracer.start_as_current_span(f"ti.ingest.{cfg.kind}") if _tracer else None
        if span_ctx:  # pragma: no cover
            span_ctx.__enter__()

        try:
            indicators, new_state, metrics, errors = await connector.fetch(http, cfg, state)

            # Deduplicate locally by key
            uniq: Dict[str, Indicator] = {}
            for ind in indicators:
                uniq[ind.key] = ind
            indicators = list(uniq.values())

            # Upsert
            new, upd = (0, 0)
            if indicators:
                new, upd = await self.repo.bulk_upsert(indicators)

            metrics.indicators_new = new
            metrics.indicators_updated = upd
            report = FeedReport(
                feed=cfg.name,
                source=cfg.url,
                state_before=state_before,
                state_after=new_state,
                metrics=metrics,
                errors=errors,
            )

            # Persist state
            await self.repo.save_state(cfg.name, new_state)
            logger.info(
                "Feed ingested",
                extra={
                    "feed": cfg.name,
                    "correlation_id": correlation_id,
                    "metrics": metrics.dict() if hasattr(metrics, "dict") else {},
                    "errors": len(errors),
                },
            )
            return report
        finally:
            if span_ctx:  # pragma: no cover
                span_ctx.__exit__(None, None, None)
            await http.close()

    async def ingest_many(self, feeds: Sequence[FeedConfig], concurrency: int = 4) -> List[FeedReport]:
        sem = asyncio.Semaphore(max(1, concurrency))
        reports: List[FeedReport] = []

        async def _run(cfg: FeedConfig):
            async with sem:
                try:
                    rep = await self.ingest_feed(cfg)
                except Exception as e:
                    rep = FeedReport(
                        feed=cfg.name,
                        source=cfg.url,
                        state_before=await self.repo.get_state(cfg.name),
                        state_after=await self.repo.get_state(cfg.name),
                        metrics=FeedMetrics(),
                        errors=[f"Unhandled error: {e}"],
                    )
                reports.append(rep)

        tasks = [asyncio.create_task(_run(f)) for f in feeds]
        for t in asyncio.as_completed(tasks):
            await t
        return reports


# --- Public convenience -------------------------------------------------------
async def ingest_once(
    repository: Optional[IntelRepository],
    feed: FeedConfig,
) -> FeedReport:
    repo = repository or MemoryIntelRepository()
    orch = FeedsOrchestrator(repo)
    return await orch.ingest_feed(feed)


async def ingest_all(
    repository: Optional[IntelRepository],
    feeds: Sequence[FeedConfig],
    concurrency: int = 4,
) -> List[FeedReport]:
    repo = repository or MemoryIntelRepository()
    orch = FeedsOrchestrator(repo)
    return await orch.ingest_many(feeds, concurrency=concurrency)


# --- __all__ ------------------------------------------------------------------
__all__ = [
    # Models
    "Indicator",
    "FeedConfig",
    "FeedState",
    "FeedMetrics",
    "FeedReport",
    # Repo
    "IntelRepository",
    "MemoryIntelRepository",
    # Orchestrator
    "FeedsOrchestrator",
    "ingest_once",
    "ingest_all",
]
