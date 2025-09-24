# -*- coding: utf-8 -*-
"""
Mythos Core — Data Fabric Adapter (industrial)
Асинхронный адаптер для поиска, получения и загрузки документов в Data Fabric.
Готовит данные под RAG: возвращает RAGSnippet и Citation (из mythos.context).

Особенности:
- httpx (если установлен) или стандартный urllib (fallback).
- Таймауты, экспоненциальные ретраи с джиттером, простой circuit breaker.
- Ограничение конкурентности (asyncio.Semaphore).
- TTL-кеш семантически идемпотентных запросов (e.g., search()).
- HMAC-подпись запроса (X-API-Key/X-Signature/X-Timestamp) и/или Bearer.
- Телеметрия через metrics_hook(payload: dict).
- Конвертация результатов в RAGSnippet/Citation для LLM-пайплайна.

Зависимости: только стандартная библиотека (httpx — опционально).
Python: 3.11+
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from types import TracebackType
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Type, Union
from urllib.parse import urlencode, urljoin

# Опциональный httpx
try:  # pragma: no cover
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

# Локальные модели для RAG
try:
    from mythos.context import RAGSnippet, Citation
except Exception as _e:  # pragma: no cover
    # Минимальные локальные заглушки для типизации (если модуль ещё не доступен)
    from dataclasses import dataclass as _dc

    @_dc(frozen=True)
    class Citation:  # type: ignore
        source_id: str
        title: Optional[str] = None
        url: Optional[str] = None
        locator: Optional[str] = None
        snippet: Optional[str] = None
        score: Optional[float] = None

    @_dc(frozen=True)
    class RAGSnippet:  # type: ignore
        text: str
        citations: Tuple[Citation, ...] = tuple()


# =========================
# Вспомогательные структуры
# =========================

MetricsHook = Callable[[Mapping[str, Any]], Awaitable[None] | None]


@dataclass(frozen=True)
class AdapterConfig:
    base_url: str
    api_key: Optional[str] = None
    api_secret: Optional[str] = None  # для HMAC подписи
    bearer_token: Optional[str] = None
    timeout_s: float = 10.0
    connect_timeout_s: float = 5.0
    max_retries: int = 3
    backoff_base_s: float = 0.25
    backoff_max_s: float = 2.0
    breaker_fail_threshold: int = 5
    breaker_reset_timeout_s: float = 30.0
    max_concurrency: int = 16
    cache_ttl_s: float = 30.0
    user_agent: str = "Mythos-Core-DataFabricAdapter/1.0"


# -------------------------
# TTL-кеш для search()
# -------------------------

class _TTLCache:
    def __init__(self, ttl_s: float = 30.0, max_items: int = 2048) -> None:
        self._ttl = float(ttl_s)
        self._max = int(max_items)
        self._store: MutableMapping[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            rec = self._store.get(key)
            if not rec:
                return None
            exp, val = rec
            if exp < time.monotonic():
                self._store.pop(key, None)
                return None
            return val

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            if len(self._store) >= self._max:
                # простая эвикция случайным элементом (достаточно для кеша запросов)
                self._store.pop(next(iter(self._store)), None)
            self._store[key] = (time.monotonic() + self._ttl, value)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()


# -------------------------
# Простой circuit breaker
# -------------------------

class _CircuitBreaker:
    def __init__(self, fail_threshold: int, reset_timeout_s: float) -> None:
        self._fail_threshold = max(1, int(fail_threshold))
        self._reset_timeout_s = float(reset_timeout_s)
        self._state = "closed"  # closed|open|half-open
        self._fails = 0
        self._opened_at = 0.0
        self._lock = asyncio.Lock()

    async def on_success(self) -> None:
        async with self._lock:
            self._fails = 0
            if self._state in ("half-open", "open"):
                self._state = "closed"

    async def on_failure(self) -> None:
        async with self._lock:
            self._fails += 1
            if self._state == "closed" and self._fails >= self._fail_threshold:
                self._state = "open"
                self._opened_at = time.monotonic()

    async def allow(self) -> bool:
        async with self._lock:
            if self._state == "closed":
                return True
            if self._state == "open":
                if (time.monotonic() - self._opened_at) >= self._reset_timeout_s:
                    self._state = "half-open"
                    return True
                return False
            # half-open допускаем один пробывочный вызов
            self._state = "open"  # если не переопределят в on_success
            self._opened_at = time.monotonic()
            return True


# -------------------------
# HTTP-клиент (httpx/urllib)
# -------------------------

class _HttpClient:
    def __init__(self, cfg: AdapterConfig) -> None:
        self._cfg = cfg
        self._client = None
        self._use_httpx = httpx is not None

    async def __aenter__(self) -> "_HttpClient":
        if self._use_httpx:  # pragma: no cover
            # Пул соединений и таймауты
            timeout = httpx.Timeout(self._cfg.timeout_s, connect=self._cfg.connect_timeout_s)
            limits = httpx.Limits(max_connections=64, max_keepalive_connections=16)
            self._client = httpx.AsyncClient(timeout=timeout, limits=limits, headers={"User-Agent": self._cfg.user_agent})
        return self

    async def __aexit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        if self._use_httpx and self._client is not None:  # pragma: no cover
            await self._client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        json_body: Any | None = None,
        data: Any | None = None,
        stream: bool = False,
    ) -> Tuple[int, Mapping[str, str], Union[bytes, AsyncGenerator[bytes, None]]]:
        if self._use_httpx:  # pragma: no cover
            assert self._client is not None
            resp = await self._client.request(method, url, headers=headers, params=params, json=json_body, data=data)
            if stream:
                async def agen() -> AsyncGenerator[bytes, None]:
                    async for chunk in resp.aiter_bytes():
                        yield chunk
                return resp.status_code, dict(resp.headers), agen()
            return resp.status_code, dict(resp.headers), await resp.aread()

        # Fallback: urllib (без асинхронного стрима; эмулируем простым bytes)
        import urllib.request
        import urllib.error

        req_url = url
        if params:
            qs = urlencode(params, doseq=True)
            sep = "&" if ("?" in url) else "?"
            req_url = f"{url}{sep}{qs}"

        req = urllib.request.Request(req_url, method=method.upper())
        for k, v in (headers or {}).items():
            req.add_header(k, v)

        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            req.add_header("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, (bytes, bytearray)):
                body = bytes(data)
            else:
                body = str(data).encode("utf-8")
        else:
            body = None

        try:
            with urllib.request.urlopen(req, data=body, timeout=self._cfg.timeout_s) as r:  # nosec - контролируемый URL
                status = r.getcode()
                hdrs = dict(r.headers.items())
                payload = r.read()
                return status, hdrs, payload
        except urllib.error.HTTPError as e:
            status = e.code
            hdrs = dict(e.headers.items()) if e.headers else {}
            payload = e.read() if hasattr(e, "read") else b""
            return status, hdrs, payload
        except Exception as e:
            raise e


# =========================
# Адаптер Data Fabric
# =========================

@dataclass
class DataFabricAdapter:
    """
    Высокоуровневый адаптер Data Fabric.

    Ожидаемая совместимость API (пример):
      GET  /v1/health
      POST /v1/search          {query, top_k, min_score, filters, corpus} -> {hits:[{id, text, score, source:{id,title,url,locator}}]}
      GET  /v1/docs/{id}       -> {id, title, url, text, meta}
      GET  /v1/chunks/{id}     -> {id, text, source:{...}, meta}
      POST /v1/corpora/{corpus}/upsert  [{id?, text, meta}] -> {upserted:[{id}]}

    При необходимости адаптируйте path’ы в методах ниже.
    """
    config: AdapterConfig
    metrics_hook: Optional[MetricsHook] = None

    def __post_init__(self) -> None:
        self._sem = asyncio.Semaphore(self.config.max_concurrency)
        self._breaker = _CircuitBreaker(self.config.breaker_fail_threshold, self.config.breaker_reset_timeout_s)
        self._cache = _TTLCache(ttl_s=self.config.cache_ttl_s)
        self._ua_headers = {"User-Agent": self.config.user_agent}

    # --------- Публичные методы ---------

    async def healthcheck(self) -> bool:
        status, _, _ = await self._call("GET", "/v1/health")
        return 200 <= status < 300

    async def search(
        self,
        *,
        query: str,
        top_k: int = 6,
        min_score: float = 0.0,
        filters: Optional[Mapping[str, Any]] = None,
        corpus: Optional[str] = None,
        use_cache: bool = True,
    ) -> List[RAGSnippet]:
        """
        Возвращает RAGSnippet с корректно заполненными Citation.
        """
        payload = {
            "query": query,
            "top_k": int(max(1, top_k)),
            "min_score": float(min_score),
            "filters": filters or {},
            "corpus": corpus,
        }
        cache_key = self._cache_key("search", payload)
        if use_cache:
            cached = await self._cache.get(cache_key)
            if cached is not None:
                return cached

        status, _, body = await self._call("POST", "/v1/search", json_body=payload)
        if status >= 400:
            raise RuntimeError(f"DataFabric search failed: HTTP {status}")

        if isinstance(body, (bytes, bytearray)):
            data = json.loads(body.decode("utf-8") or "{}")
        else:  # stream case не используется здесь
            data = {}

        hits = data.get("hits", [])
        results: List[RAGSnippet] = []
        for h in hits:
            text = (h.get("text") or "").strip()
            score = float(h.get("score") or 0.0)
            src = h.get("source") or {}
            cit = Citation(
                source_id=str(src.get("id") or h.get("id") or ""),
                title=src.get("title"),
                url=src.get("url"),
                locator=src.get("locator"),
                snippet=text[:240] if text else None,
                score=score,
            )
            results.append(RAGSnippet(text=text, citations=(cit,)))
        if use_cache:
            await self._cache.set(cache_key, results)
        return results

    async def get_document(self, *, doc_id: str) -> Dict[str, Any]:
        status, _, body = await self._call("GET", f"/v1/docs/{doc_id}")
        if status >= 400:
            raise RuntimeError(f"DataFabric get_document failed: HTTP {status}")
        if isinstance(body, (bytes, bytearray)):
            return json.loads(body.decode("utf-8") or "{}")
        return {}

    async def get_chunk_text(self, *, chunk_id: str) -> str:
        status, _, body = await self._call("GET", f"/v1/chunks/{chunk_id}")
        if status >= 400:
            raise RuntimeError(f"DataFabric get_chunk_text failed: HTTP {status}")
        data = json.loads(body.decode("utf-8") or "{}") if isinstance(body, (bytes, bytearray)) else {}
        return (data.get("text") or "").strip()

    async def upsert_documents(
        self,
        *,
        corpus: str,
        documents: Iterable[Mapping[str, Any]],
    ) -> List[str]:
        """
        Upsert документов в корпус (для офлайн-подготовки знаний).
        documents: [{id?, text, meta}]
        """
        payload = list(documents)
        status, _, body = await self._call("POST", f"/v1/corpora/{corpus}/upsert", json_body=payload)
        if status >= 400:
            raise RuntimeError(f"DataFabric upsert_documents failed: HTTP {status}")
        data = json.loads(body.decode("utf-8") or "{}") if isinstance(body, (bytes, bytearray)) else {}
        ids = [str(it.get("id")) for it in data.get("upserted", []) if "id" in it]
        return ids

    # --------- Низкоуровневые вызовы ---------

    async def _call(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any | None = None,
        data: Any | None = None,
        stream: bool = False,
    ) -> Tuple[int, Mapping[str, str], Union[bytes, AsyncGenerator[bytes, None]]]:
        """
        Универсальный вызов с ретраями/бэк-оффом, circuit breaker, семафором и телеметрией.
        """
        url = urljoin(self.config.base_url.rstrip("/") + "/", path.lstrip("/"))
        headers = dict(self._ua_headers)
        self._apply_auth(headers, method, path, params, json_body)

        # Circuit breaker gate
        allowed = await self._breaker.allow()
        if not allowed:
            await self._emit_metrics({"event": "breaker_block", "path": path, "method": method})
            raise RuntimeError("Circuit breaker is open")

        attempt = 0
        started = time.monotonic()
        async with self._sem:
            while True:
                attempt += 1
                try:
                    async with _HttpClient(self.config) as client:
                        status, resp_headers, body = await client.request(
                            method, url, headers=headers, params=params, json_body=json_body, data=data, stream=stream
                        )
                    if 200 <= status < 300:
                        await self._breaker.on_success()
                        await self._emit_metrics({
                            "event": "http_ok",
                            "path": path,
                            "method": method,
                            "status": status,
                            "attempt": attempt,
                            "latency_ms": int((time.monotonic() - started) * 1000),
                        })
                        return status, resp_headers, body
                    # 5xx → ретрай, 4xx → нет
                    if status >= 500 and attempt <= self.config.max_retries:
                        await self._breaker.on_failure()
                        await self._sleep_backoff(attempt)
                        continue
                    await self._breaker.on_failure()
                    await self._emit_metrics({
                        "event": "http_error",
                        "path": path,
                        "method": method,
                        "status": status,
                        "attempt": attempt,
                        "latency_ms": int((time.monotonic() - started) * 1000),
                    })
                    return status, resp_headers, body
                except Exception as e:
                    await self._breaker.on_failure()
                    await self._emit_metrics({
                        "event": "http_exception",
                        "path": path,
                        "method": method,
                        "attempt": attempt,
                        "error": type(e).__name__,
                    })
                    if attempt >= self.config.max_retries:
                        raise
                    await self._sleep_backoff(attempt)

    # --------- Вспомогательные утилиты ---------

    def _apply_auth(
        self,
        headers: Dict[str, str],
        method: str,
        path: str,
        params: Mapping[str, Any] | None,
        json_body: Any | None,
    ) -> None:
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        if self.config.api_key and self.config.api_secret:
            ts = datetime.now(tz=timezone.utc).isoformat()
            headers["X-API-Key"] = self.config.api_key
            headers["X-Timestamp"] = ts
            # Подпись над каноническим представлением
            canonical = "\n".join([
                method.upper(),
                path,
                json.dumps(params or {}, sort_keys=True, ensure_ascii=False),
                json.dumps(json_body or {}, sort_keys=True, ensure_ascii=False),
                ts,
            ]).encode("utf-8")
            sig = hmac.new(self.config.api_secret.encode("utf-8"), canonical, hashlib.sha256).digest()
            headers["X-Signature"] = base64.b64encode(sig).decode("ascii")

        if json_body is not None:
            headers.setdefault("Content-Type", "application/json")

    async def _sleep_backoff(self, attempt: int) -> None:
        base = self.config.backoff_base_s
        cap = self.config.backoff_max_s
        # экспоненциальный рост с decorrelated jitter
        sleep = min(cap, base * (2 ** (attempt - 1)))
        sleep = random.uniform(0.5 * sleep, 1.5 * sleep)
        await asyncio.sleep(sleep)

    async def _emit_metrics(self, payload: Mapping[str, Any]) -> None:
        if not self.metrics_hook:
            return
        try:
            res = self.metrics_hook(payload)
            if asyncio.iscoroutine(res):
                await res
        except Exception:
            # не ломаем рабочий поток
            pass

    @staticmethod
    def _cache_key(kind: str, payload: Mapping[str, Any]) -> str:
        raw = json.dumps({"k": kind, "p": payload}, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


# =========================
# Пример использования
# =========================

async def _example() -> None:  # pragma: no cover
    adapter = DataFabricAdapter(
        AdapterConfig(
            base_url="https://datafabric.local",
            api_key="ak_123",
            api_secret="sh_456",
            timeout_s=8.0,
            max_retries=2,
            max_concurrency=8,
        )
    )

    ok = await adapter.healthcheck()
    print("health:", ok)

    snippets = await adapter.search(query="стражи северного рубежа", top_k=5, min_score=0.2, corpus="mythos-lore")
    for sn in snippets:
        print(sn.text[:80], sn.citations)

    doc = await adapter.get_document(doc_id="doc_42")
    print("doc.title:", doc.get("title"))

    ids = await adapter.upsert_documents(
        corpus="mythos-lore",
        documents=[{"text": "новый фрагмент лора", "meta": {"lang": "ru"}}],
    )
    print("upserted:", ids)


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_example())
