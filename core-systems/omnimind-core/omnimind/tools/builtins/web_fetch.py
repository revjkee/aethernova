# path: omnimind-core/omnimind/tools/builtins/web_fetch.py
# License: MIT
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import math
import os
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional, Tuple, Union
from urllib.parse import urlparse, urlunparse, quote, unquote

# ---------- Optional deps (fail-safe) ----------
try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("web_fetch requires httpx to be installed") from e

try:
    from charset_normalizer import from_bytes as _detect_encoding  # type: ignore
except Exception:  # pragma: no cover
    _detect_encoding = None

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore

try:
    from pdfminer.high_level import extract_text as _pdfminer_extract_text  # type: ignore
except Exception:  # pragma: no cover
    _pdfminer_extract_text = None

# Optional latency metrics integration
try:
    from observability_core.logging.latency.latency_tracker import track_latency  # type: ignore
except Exception:  # pragma: no cover
    @contextlib.asynccontextmanager
    async def track_latency(*args, **kwargs):
        yield

# ---------- Utilities ----------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _jitter(base: float, frac: float) -> float:
    return base if frac <= 0 else base * (1.0 - frac) + random.random() * base * 2.0 * frac

def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def _clean_hostname(h: str) -> str:
    return h.strip(".").lower()

def _canonicalize_url(url: str) -> str:
    """
    Normalize URL: lower scheme/host, remove default ports, strip fragments,
    percent-encode path/query safely.
    """
    p = urlparse(url)
    scheme = (p.scheme or "http").lower()
    host = _clean_hostname(p.hostname or "")
    if not host:
        return url
    port = p.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = host
    else:
        netloc = f"{host}:{port}" if port else host
    path = quote(unquote(p.path or "/"), safe="/%:@")
    query = "&".join(sorted(filter(None, (q for q in (p.query or "").split("&")))))
    return urlunparse((scheme, netloc, path or "/", p.params, query, ""))

# ---------- TokenBucket & per-host gates ----------
@dataclass
class _Bucket:
    capacity: int
    fill_rate: float  # tokens per second
    tokens: float = field(init=False)
    ts: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)
        self.ts = time.monotonic()

    async def consume(self, n: int = 1) -> None:
        while True:
            now = time.monotonic()
            elapsed = now - self.ts
            self.ts = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
            if self.tokens >= n:
                self.tokens -= n
                return
            await asyncio.sleep(_clamp((n - self.tokens) / max(self.fill_rate, 1e-6), 0.005, 0.2))

# ---------- Robots.txt cache ----------
class _RobotsCache:
    def __init__(self, ttl: int, user_agent: str) -> None:
        self._ttl = ttl
        self._ua = user_agent
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def allowed(self, client: httpx.AsyncClient, url: str) -> bool:
        try:
            p = urlparse(url)
            base = f"{p.scheme}://{p.netloc}"
            async with self._lock:
                entry = self._cache.get(base)
                if entry and time.time() - entry[0] < self._ttl:
                    rp = entry[1]
                else:
                    rp = await self._load(client, base)
                    self._cache[base] = (time.time(), rp)
            # Use robotparser-like API
            return bool(rp.can_fetch(self._ua, url))
        except Exception:
            # Fail-closed? In production обычно fail-open, чтобы не блокировать из-за ошибок сети.
            return True

    async def _load(self, client: httpx.AsyncClient, base: str):
        import urllib.robotparser as robotparser
        rp = robotparser.RobotFileParser()
        try:
            robots_url = f"{base}/robots.txt"
            r = await client.get(robots_url, timeout=5.0)
            if r.status_code == 200 and r.content:
                text = r.text
                rp.parse(text.splitlines())
            else:
                rp.parse([])
        except Exception:
            rp.parse([])
        return rp

# ---------- ETag/Last-Modified cache (conditional requests) ----------
@dataclass
class _CacheEntry:
    expires_at: float
    etag: Optional[str]
    last_modified: Optional[str]
    media_type: str
    encoding: Optional[str]
    body: bytes
    headers: Dict[str, str]
    status: int

class _ResponseCache:
    def __init__(self, ttl: int) -> None:
        self._ttl = ttl
        self._data: Dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[_CacheEntry]:
        async with self._lock:
            e = self._data.get(key)
            if not e:
                return None
            if time.time() > e.expires_at:
                self._data.pop(key, None)
                return None
            return e

    async def set(self, key: str, entry: _CacheEntry) -> None:
        async with self._lock:
            self._data[key] = entry

# ---------- Config & Result ----------
@dataclass
class FetchConfig:
    user_agent: str = "OmniMindBot/1.0 (+https://example.invalid) httpx"
    connect_timeout: float = 8.0
    read_timeout: float = 20.0
    total_timeout: float = 30.0
    retries: int = 3
    backoff_base: float = 0.5
    backoff_factor: float = 2.0
    backoff_jitter: float = 0.2
    per_host_rps: float = 4.0
    per_host_concurrency: int = 4
    global_concurrency: int = 64
    respect_robots: bool = True
    robots_ttl_sec: int = 600
    cache_ttl_sec: int = 900
    enable_etag_cache: bool = True
    max_bytes: int = 8 * 1024 * 1024
    allowed_schemes: Tuple[str, ...] = ("http", "https")
    verify_tls: Union[bool, str] = True
    proxies: Optional[Union[str, Dict[str, str]]] = None
    headers: Dict[str, str] = field(default_factory=lambda: {
        "Accept": "text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })

@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    media_type: str
    encoding: Optional[str]
    headers: Dict[str, str]
    content: bytes
    text: Optional[str]
    json: Optional[Any]
    from_cache: bool
    fetched_at: datetime
    elapsed_ms: float

# ---------- WebFetcher ----------
class WebFetcher:
    def __init__(self, config: Optional[FetchConfig] = None) -> None:
        self.cfg = config or FetchConfig()
        limits = httpx.Limits(max_connections=self.cfg.global_concurrency, max_keepalive_connections=self.cfg.global_concurrency)
        self._client = httpx.AsyncClient(
            headers={"User-Agent": self.cfg.user_agent, **self.cfg.headers},
            timeout=httpx.Timeout(self.cfg.total_timeout, connect=self.cfg.connect_timeout, read=self.cfg.read_timeout),
            http2=True,
            limits=limits,
            verify=self.cfg.verify_tls,
            proxies=self.cfg.proxies,
            follow_redirects=True,
        )
        self._robots = _RobotsCache(self.cfg.robots_ttl_sec, self.cfg.user_agent)
        self._cache = _ResponseCache(self.cfg.cache_ttl_sec)
        self._host_buckets: Dict[str, _Bucket] = {}
        self._host_sems: Dict[str, asyncio.Semaphore] = {}
        self._g_lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- public helpers ----
    async def fetch(self, url: str, *, want: str = "auto") -> FetchResult:
        url = _canonicalize_url(url)
        p = urlparse(url)
        if p.scheme not in self.cfg.allowed_schemes:
            raise ValueError(f"scheme_not_allowed:{p.scheme}")
        host = _clean_hostname(p.hostname or "")
        if not host:
            raise ValueError("bad_url")

        # robots
        if self.cfg.respect_robots:
            allowed = await self._robots.allowed(self._client, url)
            if not allowed:
                return FetchResult(
                    url=url, final_url=url, status=451, media_type="text/plain", encoding="utf-8",
                    headers={}, content=b"blocked_by_robots", text="blocked_by_robots", json=None,
                    from_cache=False, fetched_at=_utcnow(), elapsed_ms=0.0
                )

        # conditional cache
        headers: Dict[str, str] = {}
        cache_key = url
        cached = await self._cache.get(cache_key) if self.cfg.enable_etag_cache else None
        if cached:
            if cached.etag:
                headers["If-None-Match"] = cached.etag
            if cached.last_modified:
                headers["If-Modified-Since"] = cached.last_modified

        # per-host gates
        bucket = await self._get_bucket(host)
        sem = await self._get_semaphore(host)

        # retries with backoff
        attempt = 0
        start_wall = time.perf_counter()
        async with track_latency("web_fetch_latency_ms", {"host": host}):
            async with sem:
                while True:
                    attempt += 1
                    await bucket.consume(1)
                    try:
                        r = await self._client.get(url, headers=headers)
                        if r.status_code == 304 and cached:
                            return FetchResult(
                                url=url,
                                final_url=str(r.request.url),
                                status=200,
                                media_type=cached.media_type,
                                encoding=cached.encoding,
                                headers=cached.headers,
                                content=cached.body,
                                text=self._maybe_text(cached.body, cached.media_type, cached.encoding),
                                json=self._maybe_json(cached.body, cached.media_type),
                                from_cache=True,
                                fetched_at=_utcnow(),
                                elapsed_ms=(time.perf_counter() - start_wall) * 1000.0,
                            )
                        # enforce size limit safely
                        body = await self._read_limited(r, self.cfg.max_bytes)
                        media_type = self._media_type_of(r)
                        encoding = self._encoding_of(r, body, media_type)
                        # store cache if ok
                        if self.cfg.enable_etag_cache and r.status_code == 200:
                            etag = r.headers.get("ETag")
                            lm = r.headers.get("Last-Modified")
                            await self._cache.set(cache_key, _CacheEntry(
                                expires_at=time.time() + self.cfg.cache_ttl_sec,
                                etag=etag, last_modified=lm, media_type=media_type,
                                encoding=encoding, body=body,
                                headers=dict(r.headers), status=r.status_code,
                            ))
                        return FetchResult(
                            url=url,
                            final_url=str(r.request.url),
                            status=r.status_code,
                            media_type=media_type,
                            encoding=encoding,
                            headers=dict(r.headers),
                            content=body,
                            text=self._maybe_text(body, media_type, encoding) if want in ("auto", "text") else None,
                            json=self._maybe_json(body, media_type) if want in ("auto", "json") else None,
                            from_cache=False,
                            fetched_at=_utcnow(),
                            elapsed_ms=(time.perf_counter() - start_wall) * 1000.0,
                        )
                    except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError, httpx.TransportError) as e:
                        if attempt >= self.cfg.retries:
                            raise
                        await asyncio.sleep(self._backoff(attempt))
                        continue

    async def fetch_text(self, url: str) -> FetchResult:
        return await self.fetch(url, want="text")

    async def fetch_json(self, url: str) -> FetchResult:
        return await self.fetch(url, want="json")

    async def fetch_pdf_text(self, url: str) -> FetchResult:
        res = await self.fetch(url, want="auto")
        if not res.media_type.startswith("application/pdf"):
            return res
        text = self._pdf_to_text(res.content)
        return dataclasses.replace(res, text=text)

    # ---- internals ----
    async def _get_bucket(self, host: str) -> _Bucket:
        async with self._g_lock:
            b = self._host_buckets.get(host)
            if b is None:
                b = _Bucket(capacity=max(1, int(self.cfg.per_host_rps)), fill_rate=max(0.1, float(self.cfg.per_host_rps)))
                self._host_buckets[host] = b
            return b

    async def _get_semaphore(self, host: str) -> asyncio.Semaphore:
        async with self._g_lock:
            s = self._host_sems.get(host)
            if s is None:
                s = asyncio.Semaphore(value=max(1, int(self.cfg.per_host_concurrency)))
                self._host_sems[host] = s
            return s

    def _backoff(self, attempt: int) -> float:
        return _jitter(self.cfg.backoff_base * (self.cfg.backoff_factor ** (attempt - 1)), self.cfg.backoff_jitter)

    async def _read_limited(self, r: httpx.Response, limit: int) -> bytes:
        # If Content-Length exceeds limit, abort early
        try:
            cl = int(r.headers.get("Content-Length", "0"))
            if cl > 0 and cl > limit:
                raise httpx.HTTPStatusError("payload_too_large", request=r.request, response=r)
        except Exception:
            pass
        chunks: list[bytes] = []
        read = 0
        async for chunk in r.aiter_bytes():
            if not chunk:
                continue
            read += len(chunk)
            if read > limit:
                raise httpx.HTTPStatusError("payload_too_large", request=r.request, response=r)
            chunks.append(chunk)
        return b"".join(chunks)

    def _media_type_of(self, r: httpx.Response) -> str:
        ct = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ct:
            return ct
        # naive sniff
        b = r.content[:8]
        if b.startswith(b"%PDF-"):
            return "application/pdf"
        if b.startswith(b"{") or b.startswith(b"["):
            return "application/json"
        return "application/octet-stream"

    def _encoding_of(self, r: httpx.Response, body: bytes, media_type: str) -> Optional[str]:
        # from header
        m = re.search(r"charset=([\w\-\.:]+)", r.headers.get("Content-Type", ""), re.IGNORECASE)
        if m:
            return m.group(1).strip().lower()
        # HTML meta
        if media_type in ("text/html", "application/xhtml+xml"):
            if body:
                head = body[:8192].decode("ascii", errors="ignore")
                m1 = re.search(r'<meta[^>]+charset=["\']?([\w\-:\.]+)', head, re.I)
                if m1:
                    return m1.group(1).lower()
        # Detector
        if _detect_encoding:
            res = _detect_encoding(body)
            best = res.best() if res else None
            if best:
                return (best.encoding or "utf-8").lower()
        # defaults
        if media_type.startswith("text/") or media_type.endswith("+xml") or media_type.endswith("+json"):
            return "utf-8"
        if media_type in ("application/json", "application/xml"):
            return "utf-8"
        return None

    def _maybe_text(self, body: bytes, media_type: str, encoding: Optional[str]) -> Optional[str]:
        if media_type.startswith("text/") or media_type in ("application/json", "application/xml", "application/xhtml+xml"):
            enc = encoding or "utf-8"
            try:
                text = body.decode(enc, errors="replace")
            except Exception:
                text = body.decode("utf-8", errors="replace")
            # For HTML, strip scripts/styles if BS4 available
            if media_type in ("text/html", "application/xhtml+xml") and BeautifulSoup:
                try:
                    soup = BeautifulSoup(text, "lxml") if "lxml" in (BeautifulSoup.__module__ or "") else BeautifulSoup(text, "html.parser")
                    for tag in soup(["script", "style", "noscript"]):
                        tag.decompose()
                    return soup.get_text(separator="\n", strip=True)
                except Exception:
                    return text
            return text
        return None

    def _maybe_json(self, body: bytes, media_type: str) -> Optional[Any]:
        if media_type == "application/json" or media_type.endswith("+json"):
            try:
                return json.loads(body.decode("utf-8", errors="replace"))
            except Exception:
                return None
        return None

    def _pdf_to_text(self, body: bytes) -> Optional[str]:
        if not body:
            return None
        if _pdfminer_extract_text:
            try:
                # pdfminer expects a file-like object; use BytesIO
                import io
                return _pdfminer_extract_text(io.BytesIO(body))
            except Exception:
                return None
        return None  # graceful degrade if dependency is absent


# ---------- Singleton helpers ----------
_default_fetcher: Optional[WebFetcher] = None
_default_lock = asyncio.Lock()

async def get_fetcher() -> WebFetcher:
    global _default_fetcher
    async with _default_lock:
        if _default_fetcher is None:
            _default_fetcher = WebFetcher()
        return _default_fetcher

# Convenience wrappers
async def fetch(url: str, *, want: str = "auto") -> FetchResult:
    f = await get_fetcher()
    return await f.fetch(url, want=want)

async def fetch_text(url: str) -> FetchResult:
    f = await get_fetcher()
    return await f.fetch_text(url)

async def fetch_json(url: str) -> FetchResult:
    f = await get_fetcher()
    return await f.fetch_json(url)

async def fetch_pdf_text(url: str) -> FetchResult:
    f = await get_fetcher()
    return await f.fetch_pdf_text(url)
