# neuroforge-core/neuroforge/adapters/veilmind_adapter.py
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

try:
    import httpx
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "veilmind_adapter requires 'httpx' (pip install httpx>=0.24)."
    ) from exc

log = logging.getLogger(__name__)

# =========================
# Метрики (абстракция)
# =========================

class MetricsSink:
    async def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None: ...
    async def observe(self, name: str, labels: Mapping[str, str], value: float) -> None: ...

class NoopMetrics(MetricsSink):
    async def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None:
        return
    async def observe(self, name: str, labels: Mapping[str, str], value: float) -> None:
        return

# =========================
# Исключения адаптера
# =========================

class VeilmindError(RuntimeError):
    def __init__(self, code: str, message: str, *, status: Optional[int] = None, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details or {}

class VeilmindAuthError(VeilmindError): ...
class VeilmindRateLimit(VeilmindError): ...
class VeilmindInvalidRequest(VeilmindError): ...
class VeilmindServerError(VeilmindError): ...
class VeilmindTimeout(VeilmindError): ...
class VeilmindUnavailable(VeilmindError): ...
class VeilmindBadStream(VeilmindError): ...

# =========================
# Конфигурация
# =========================

@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay_s: float = 0.2
    max_delay_s: float = 8.0
    jitter: float = 0.2  # 0..1

@dataclass
class RateLimit:
    rate_per_sec: float = 50.0
    burst: int = 200

@dataclass
class BreakerPolicy:
    fail_threshold: int = 20
    reset_seconds: float = 30.0

@dataclass
class VeilmindConfig:
    base_url: str
    api_key: str
    # Маршруты. Я не могу подтвердить реальные пути Veilmind — I cannot verify this.
    chat_route: str = "/v1/chat"
    embeddings_route: str = "/v1/embeddings"
    health_route: str = "/v1/health"

    # Сетевые настройки
    timeout_s: float = 30.0
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 30.0
    write_timeout_s: float = 30.0

    # Политики
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    ratelimit: RateLimit = field(default_factory=RateLimit)
    breaker: BreakerPolicy = field(default_factory=BreakerPolicy)

    # Пользовательский агент/заголовки
    user_agent: str = "neuroforge-veilmind-adapter/1.0"
    organization: Optional[str] = None
    extra_headers: Dict[str, str] = field(default_factory=dict)

    # Кэширование детерминированных вызовов (в памяти)
    cache_ttl_s: float = 0.0  # 0 — выключено

    def headers(self) -> Dict[str, str]:
        hdrs = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.organization:
            hdrs["X-Organization"] = self.organization
        hdrs.update(self.extra_headers)
        return hdrs

# =========================
# Помощники: редактирование секретов, RL, CB, кэш
# =========================

def _redact(s: str) -> str:
    if not s:
        return s
    if len(s) <= 8:
        return "***"
    return s[:4] + "…" + s[-4:]

class _TokenBucket:
    def __init__(self, rate: float, burst: int) -> None:
        self.rate = float(max(rate, 0.0))
        self.capacity = float(max(burst, 1))
        self.tokens = self.capacity
        self.ts = time.time()
        self._lock = asyncio.Lock()

    async def allow(self) -> bool:
        async with self._lock:
            now = time.time()
            dt = max(0.0, now - self.ts)
            self.ts = now
            self.tokens = min(self.capacity, self.tokens + dt * self.rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

class _CircuitBreaker:
    def __init__(self, threshold: int, reset_s: float) -> None:
        self.threshold = max(1, threshold)
        self.reset_s = max(1.0, reset_s)
        self.fail = 0
        self.opened_at: Optional[float] = None
        self._lock = asyncio.Lock()

    async def guard(self) -> None:
        async with self._lock:
            if self.opened_at is not None:
                if (time.time() - self.opened_at) >= self.reset_s:
                    self.fail = 0
                    self.opened_at = None
                else:
                    raise VeilmindUnavailable("circuit_open", "Circuit breaker is open")

    async def report(self, ok: bool) -> None:
        async with self._lock:
            if ok:
                self.fail = 0
                self.opened_at = None
            else:
                self.fail += 1
                if self.fail >= self.threshold:
                    self.opened_at = time.time()

class _TTLCache:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            ent = self._data.get(key)
            if not ent:
                return None
            exp, val = ent
            if exp <= time.time():
                self._data.pop(key, None)
                return None
            return val

    async def put(self, key: str, value: Any, ttl: float) -> None:
        async with self._lock:
            self._data[key] = (time.time() + ttl, value)

def _jittered_backoff(attempt: int, base: float, cap: float, jitter: float) -> float:
    b = min(cap, base * (2 ** max(0, attempt - 1)))
    j = random.uniform(1.0 - jitter, 1.0 + jitter)
    return b * j

# =========================
# Модели запросов/ответов (минимум)
# =========================

@dataclass
class ChatMessage:
    role: str
    content: Union[str, Dict[str, Any], List[Dict[str, Any]]]

@dataclass
class ChatResponse:
    model: str
    content: str
    finish_reason: Optional[str]
    usage: Optional[Dict[str, int]] = None
    raw: Optional[Dict[str, Any]] = None
    latency_ms: float = 0.0

@dataclass
class ChatChunk:
    delta: str
    raw: Optional[Dict[str, Any]] = None

@dataclass
class EmbeddingResponse:
    model: str
    vectors: List[List[float]]
    usage: Optional[Dict[str, int]] = None
    raw: Optional[Dict[str, Any]] = None
    latency_ms: float = 0.0

# Тип парсера стрим-чанков: на вход строка/байты одной «строки» потока (NDJSON/SSE), на выход delta и raw.
StreamParser = Callable[[bytes], Optional[ChatChunk]]

def ndjson_parser(line: bytes) -> Optional[ChatChunk]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line.decode("utf-8"))
    except Exception:
        return None
    # Конвенция: { "delta": "...", ... }
    delta = ""
    if isinstance(obj, dict):
        delta = str(obj.get("delta", obj.get("content", "")))
    return ChatChunk(delta=delta, raw=obj)

def sse_parser(line: bytes) -> Optional[ChatChunk]:
    # Простейший SSE: строки "data: {...json...}"
    m = re.match(rb"^data:\s*(.+)$", line.strip())
    if not m:
        return None
    try:
        obj = json.loads(m.group(1).decode("utf-8"))
    except Exception:
        return None
    delta = str(obj.get("delta", obj.get("content", "")))
    return ChatChunk(delta=delta, raw=obj)

# =========================
# Адаптер
# =========================

class VeilmindAdapter:
    """
    Унифицированный безопасный адаптер к Veilmind API.
    Я не подтверждаю фактический формат/маршруты провайдера — I cannot verify this.
    Все пути/форматы настраиваются через VeilmindConfig.
    """
    def __init__(self, cfg: VeilmindConfig, *, metrics: Optional[MetricsSink] = None) -> None:
        self.cfg = cfg
        self.metrics = metrics or NoopMetrics()
        self._client: Optional[httpx.AsyncClient] = None
        self._bucket = _TokenBucket(cfg.ratelimit.rate_per_sec, cfg.ratelimit.burst)
        self._breaker = _CircuitBreaker(cfg.breaker.fail_threshold, cfg.breaker.reset_seconds)
        self._cache = _TTLCache() if cfg.cache_ttl_s > 0 else None

    # ---- lifecycle ----
    async def __aenter__(self) -> "VeilmindAdapter":
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _ensure_client(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.cfg.base_url.rstrip("/"),
                headers=self.cfg.headers(),
                timeout=httpx.Timeout(
                    self.cfg.timeout_s,
                    connect=self.cfg.connect_timeout_s,
                    read=self.cfg.read_timeout_s,
                    write=self.cfg.write_timeout_s,
                ),
                http2=True,
            )

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ---- публичные методы ----

    async def achat(
        self,
        *,
        model: str,
        messages: Sequence[ChatMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> ChatResponse:
        """
        Непотоковая генерация.
        """
        await self._ensure_client()
        assert self._client is not None

        payload = {
            "model": model,
            "messages": [vars(m) for m in messages],
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if metadata:
            payload["metadata"] = metadata
        if extra:
            payload.update(extra)

        cache_key = None
        if self._cache is not None and not extra:
            cache_key = f"chat|{model}|{json.dumps(payload, sort_keys=True, ensure_ascii=False)}"
            cached = await self._cache.get(cache_key)
            if cached:
                return cached  # type: ignore[return-value]

        labels = {"op": "chat", "model": model}
        await self.metrics.inc("veilmind_calls_started_total", labels)
        t0 = time.perf_counter()

        resp_obj = await self._request_json(
            method="POST",
            url=self.cfg.chat_route,
            json_payload=payload,
            idempotency_key=idempotency_key,
        )

        dur = (time.perf_counter() - t0) * 1000.0
        await self.metrics.observe("veilmind_call_latency_ms", labels, dur)

        # Приведение к общему виду без предположений о схеме ответа
        content = ""
        finish = None
        usage = None
        if isinstance(resp_obj, dict):
            content = str(
                resp_obj.get("content")
                or resp_obj.get("output")
                or resp_obj.get("choices", [{}])[0].get("message", {}).get("content", "")
            )
            finish = resp_obj.get("finish_reason") or resp_obj.get("reason")
            usage = resp_obj.get("usage")

        out = ChatResponse(model=model, content=content, finish_reason=finish, usage=usage, raw=resp_obj, latency_ms=dur)

        if cache_key and self._cache:
            await self._cache.put(cache_key, out, self.cfg.cache_ttl_s)
        await self.metrics.inc("veilmind_calls_success_total", labels)
        return out

    async def astream_chat(
        self,
        *,
        model: str,
        messages: Sequence[ChatMessage],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        stream_parser: StreamParser = ndjson_parser,
        extra: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[ChatChunk, None]:
        """
        Потоковая генерация: возвращает чанки, парсимые указанным парсером.
        По умолчанию — NDJSON. Для SSE передайте sse_parser или свой парсер.
        """
        await self._ensure_client()
        assert self._client is not None

        payload = {
            "model": model,
            "messages": [vars(m) for m in messages],
            "stream": True,
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if metadata:
            payload["metadata"] = metadata
        if extra:
            payload.update(extra)

        labels = {"op": "chat_stream", "model": model}
        await self.metrics.inc("veilmind_calls_started_total", labels)

        async for line in self._request_stream(
            method="POST", url=self.cfg.chat_route, json_payload=payload, idempotency_key=idempotency_key
        ):
            try:
                chunk = stream_parser(line)
            except Exception as e:
                raise VeilmindBadStream("bad_stream", f"stream parser error: {type(e).__name__}") from e
            if chunk:
                yield chunk

        await self.metrics.inc("veilmind_calls_success_total", labels)

    async def aembed(
        self,
        *,
        model: str,
        inputs: Sequence[Union[str, Mapping[str, Any]]],
        idempotency_key: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> EmbeddingResponse:
        """
        Получение эмбеддингов.
        """
        await self._ensure_client()
        assert self._client is not None

        payload: Dict[str, Any] = {"model": model, "input": list(inputs)}
        if extra:
            payload.update(extra)

        cache_key = None
        if self._cache is not None and not extra:
            cache_key = f"embed|{model}|{json.dumps(payload, sort_keys=True, ensure_ascii=False)}"
            cached = await self._cache.get(cache_key)
            if cached:
                return cached  # type: ignore[return-value]

        labels = {"op": "embeddings", "model": model}
        await self.metrics.inc("veilmind_calls_started_total", labels)
        t0 = time.perf_counter()

        resp_obj = await self._request_json(
            method="POST",
            url=self.cfg.embeddings_route,
            json_payload=payload,
            idempotency_key=idempotency_key,
        )
        dur = (time.perf_counter() - t0) * 1000.0
        await self.metrics.observe("veilmind_call_latency_ms", labels, dur)

        vectors: List[List[float]] = []
        usage = None
        if isinstance(resp_obj, dict):
            # наиболее распространенные поля: data: [{embedding: [...]}], usage: {...}
            data = resp_obj.get("data") or resp_obj.get("embeddings")
            if isinstance(data, list):
                for item in data:
                    vec = item.get("embedding") if isinstance(item, dict) else None
                    if isinstance(vec, list):
                        vectors.append([float(x) for x in vec])
            usage = resp_obj.get("usage")

        out = EmbeddingResponse(model=model, vectors=vectors, usage=usage, raw=resp_obj, latency_ms=dur)
        if cache_key and self._cache:
            await self._cache.put(cache_key, out, self.cfg.cache_ttl_s)
        await self.metrics.inc("veilmind_calls_success_total", labels)
        return out

    async def ahealth(self) -> bool:
        """
        Простой health-check эндпоинта.
        """
        await self._ensure_client()
        try:
            _ = await self._request_json(method="GET", url=self.cfg.health_route)
            return True
        except VeilmindError:
            return False

    # ---- низкоуровневые запросы ----

    async def _request_json(
        self,
        *,
        method: str,
        url: str,
        json_payload: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        raw = await self._request_raw(method=method, url=url, json_payload=json_payload, idempotency_key=idempotency_key)
        try:
            return raw.json()
        except Exception as e:
            body = raw.text[:512] if hasattr(raw, "text") else "<binary>"
            log.error("Veilmind JSON decode failed: %s…", body)
            raise VeilmindServerError("bad_json", "failed to decode JSON response", status=raw.status_code) from e

    async def _request_stream(
        self,
        *,
        method: str,
        url: str,
        json_payload: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> AsyncGenerator[bytes, None]:
        await self._ensure_client()
        assert self._client is not None

        await self._breaker.guard()
        if not await self._bucket.allow():
            await self.metrics.inc("veilmind_rl_dropped_total", {"op": "stream"})
            raise VeilmindRateLimit("rate_limited", "rate limit exceeded (client)")

        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        attempt = 0
        while True:
            attempt += 1
            try:
                req = self._client.build_request(method.upper(), url, json=json_payload, headers=headers)
                async with self._client.stream(req.method, req.url, headers=req.headers, content=req.content) as resp:
                    if resp.status_code >= 400:
                        await self._handle_http_error(resp)
                    async for line in resp.aiter_lines():
                        if line is None:
                            continue
                        yield line.encode("utf-8")
                    await self._breaker.report(True)
                    return
            except VeilmindError:
                await self._breaker.report(False)
                raise
            except (httpx.ConnectError, httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError, httpx.HTTPStatusError) as e:
                if attempt >= self.cfg.retry.max_attempts:
                    await self._breaker.report(False)
                    raise VeilmindUnavailable("network_error", f"network/stream error: {type(e).__name__}") from e
                await asyncio.sleep(_jittered_backoff(attempt, self.cfg.retry.base_delay_s, self.cfg.retry.max_delay_s, self.cfg.retry.jitter))
                continue
            except httpx.TimeoutException as e:
                await self._breaker.report(False)
                raise VeilmindTimeout("timeout", "stream timeout") from e

    async def _request_raw(
        self,
        *,
        method: str,
        url: str,
        json_payload: Optional[Dict[str, Any]],
        idempotency_key: Optional[str],
    ) -> httpx.Response:
        await self._ensure_client()
        assert self._client is not None

        await self._breaker.guard()
        if not await self._bucket.allow():
            await self.metrics.inc("veilmind_rl_dropped_total", {"op": "call"})
            raise VeilmindRateLimit("rate_limited", "rate limit exceeded (client)")

        headers = {}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self._client.request(method.upper(), url, json=json_payload, headers=headers)
                if resp.status_code >= 400:
                    await self._handle_http_error(resp)
                await self._breaker.report(True)
                return resp
            except VeilmindError as e:
                retry_after = None
                if isinstance(e, VeilmindRateLimit):
                    retry_after = self._parse_retry_after(getattr(e, "details", {}).get("retry_after"))
                if self._should_retry(e, attempt):
                    await asyncio.sleep(retry_after or _jittered_backoff(attempt, self.cfg.retry.base_delay_s, self.cfg.retry.max_delay_s, self.cfg.retry.jitter))
                    continue
                await self._breaker.report(False)
                raise
            except (httpx.ConnectError, httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError, httpx.HTTPStatusError) as e:
                if attempt >= self.cfg.retry.max_attempts:
                    await self._breaker.report(False)
                    raise VeilmindUnavailable("network_error", f"network error: {type(e).__name__}") from e
                await asyncio.sleep(_jittered_backoff(attempt, self.cfg.retry.base_delay_s, self.cfg.retry.max_delay_s, self.cfg.retry.jitter))
                continue
            except httpx.TimeoutException as e:
                await self._breaker.report(False)
                raise VeilmindTimeout("timeout", "request timeout") from e

    async def _handle_http_error(self, resp: httpx.Response) -> None:
        status = resp.status_code
        text = ""
        try:
            obj = resp.json()
            text = obj.get("error", {}).get("message") or obj.get("message") or resp.text
        except Exception:
            text = resp.text

        labels = {"status": str(status)}
        await self.metrics.inc("veilmind_http_errors_total", labels)

        if status in (401, 403):
            raise VeilmindAuthError("auth", "authentication/authorization error", status=status, details={"message": text})
        if status == 400:
            raise VeilmindInvalidRequest("invalid_request", text or "invalid request", status=status)
        if status == 404:
            raise VeilmindInvalidRequest("not_found", "resource not found", status=status)
        if status == 409:
            raise VeilmindInvalidRequest("conflict", text or "conflict", status=status)
        if status == 429:
            retry_after = self._retry_after_header(resp)
            raise VeilmindRateLimit("rate_limited", "rate limited by server", status=status, details={"retry_after": retry_after, "message": text})
        if 500 <= status < 600:
            raise VeilmindServerError("server_error", text or "server error", status=status)
        # Прочее — как внутреннюю ошибку
        raise VeilmindError("http_error", text or f"http {status}", status=status)

    def _retry_after_header(self, resp: httpx.Response) -> Optional[float]:
        ra = resp.headers.get("Retry-After")
        return self._parse_retry_after(ra)

    @staticmethod
    def _parse_retry_after(value: Optional[str]) -> Optional[float]:
        if not value:
            return None
        try:
            # seconds
            return float(value)
        except Exception:
            return None

    def _should_retry(self, err: VeilmindError, attempt: int) -> bool:
        if attempt >= self.cfg.retry.max_attempts:
            return False
        if isinstance(err, (VeilmindUnavailable, VeilmindServerError, VeilmindRateLimit)):
            return True
        return False

# =========================
# Пример использования (docstring)
# =========================
"""
Пример (асинхронно):

    import asyncio

    async def main():
        cfg = VeilmindConfig(
            base_url="https://api.veilmind.example",  # I cannot verify this
            api_key=os.environ["VEILMIND_API_KEY"],
            chat_route="/v1/chat",
            embeddings_route="/v1/embeddings",
        )
        async with VeilmindAdapter(cfg) as vm:
            # chat
            resp = await vm.achat(
                model="vm-llm-001",
                messages=[ChatMessage(role="user", content="Напиши краткий слоган про ИИ.")],
                temperature=0.7,
                max_tokens=128,
            )
            print(resp.content)

            # stream
            async for chunk in vm.astream_chat(
                model="vm-llm-001",
                messages=[ChatMessage(role="user", content="Сгенерируй ответ потоково.")],
                temperature=0.5,
                stream_parser=ndjson_parser,   # или sse_parser
            ):
                print(chunk.delta, end="", flush=True)

            # embeddings
            emb = await vm.aembed(model="vm-emb-001", inputs=["hello", "привет"])
            print(len(emb.vectors), "vectors")

    # asyncio.run(main())
"""
__all__ = [
    "VeilmindConfig", "VeilmindAdapter",
    "ChatMessage", "ChatResponse", "ChatChunk", "EmbeddingResponse",
    "VeilmindError", "VeilmindAuthError", "VeilmindRateLimit", "VeilmindInvalidRequest", "VeilmindServerError",
    "VeilmindTimeout", "VeilmindUnavailable", "VeilmindBadStream",
    "MetricsSink", "NoopMetrics",
    "ndjson_parser", "sse_parser",
]
