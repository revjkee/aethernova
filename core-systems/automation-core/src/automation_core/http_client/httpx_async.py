# automation-core/src/automation_core/http_client/httpx_async.py
from __future__ import annotations

import asyncio
import json
import math
import os
import random
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Iterable, Mapping, MutableMapping, Optional, Union

import httpx

try:
    # Настройки проекта (pydantic-settings), см. config/settings.py
    from automation_core.config.settings import settings
except Exception as e:  # pragma: no cover
    raise RuntimeError("Settings are required. Ensure config/settings.py is importable.") from e

try:
    # Опциональный rate-limiter проекта
    from automation_core.concurrency.rate_limiter import RateLimiter  # type: ignore
except Exception:  # pragma: no cover
    RateLimiter = None  # type: ignore

try:
    # Опциональный circuit breaker проекта
    from automation_core.http_client.circuit_breaker import CircuitBreaker, CircuitOpenError  # type: ignore
except Exception:  # pragma: no cover
    CircuitBreaker = None  # type: ignore

try:
    # Опциональные метрики/трейсинг
    from automation_core.observability.metrics import record_counter, record_histogram  # type: ignore
except Exception:  # pragma: no cover
    def record_counter(*args: Any, **kwargs: Any) -> None:
        pass

    def record_histogram(*args: Any, **kwargs: Any) -> None:
        pass

try:
    # OpenTelemetry (если подключен)
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer("automation-core.http-client")
except Exception:  # pragma: no cover
    _tracer = None  # type: ignore


JSONType = Union[Mapping[str, Any], Iterable[Any], list[Any], dict[str, Any]]
Headers = MutableMapping[str, str]
QueryParams = Union[Mapping[str, Any], list[tuple[str, Any]], None]

_RETRIABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}
_RETRIABLE_EXC = (
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.TransportError,
)

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int
    initial_backoff_s: float
    max_backoff_s: float
    multiplier: float
    jitter: float  # 0..1


def _default_retry_policy() -> RetryPolicy:
    return RetryPolicy(
        max_attempts=max(1, settings.http.max_retries + 1),  # attempts = 1 + retries
        initial_backoff_s=0.25,
        max_backoff_s=min(20.0, settings.http.total_timeout_s),
        multiplier=2.0,
        jitter=0.25,
    )


def _compute_backoff(attempt: int, policy: RetryPolicy) -> float:
    if attempt <= 1:
        base = policy.initial_backoff_s
    else:
        base = policy.initial_backoff_s * (policy.multiplier ** (attempt - 1))
    base = min(base, policy.max_backoff_s)
    if policy.jitter > 0:
        delta = base * policy.jitter
        return max(0.0, random.uniform(base - delta, base + delta))
    return base


def _compose_headers(user_headers: Optional[Headers]) -> Headers:
    headers: Headers = {
        "User-Agent": settings.http.user_agent,
        "Accept": "*/*",
    }
    if user_headers:
        # user overrides default
        for k, v in user_headers.items():
            headers[k] = v
    return headers


def _effective_timeout() -> httpx.Timeout:
    # httpx.Timeout(connect, read, write, pool)
    return httpx.Timeout(
        connect=settings.http.connect_timeout_s,
        read=settings.http.read_timeout_s,
        write=settings.http.read_timeout_s,
        pool=settings.http.total_timeout_s,
    )


def _effective_limits() -> httpx.Limits:
    # Пул соединений; значения по умолчанию httpx подходят; можно вынести в настройки при необходимости
    return httpx.Limits(max_keepalive_connections=20, max_connections=100)


def _effective_proxies() -> Optional[Union[str, Mapping[str, str]]]:
    # Поддержка системных прокси и явных настроек через окружение
    # PRIORITY: explicit env HTTP(S)_PROXY -> system env -> None
    http_proxy = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
    https_proxy = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
    if http_proxy or https_proxy:
        proxies: dict[str, str] = {}
        if http_proxy:
            proxies["http://"] = http_proxy
        if https_proxy:
            proxies["https://"] = https_proxy
        return proxies
    return None


class _NullBreaker:  # pragma: no cover
    def __init__(self, *_, **__): ...
    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc, tb): ...
    def allow(self) -> bool: return True
    def record_success(self) -> None: ...
    def record_failure(self) -> None: ...


class AsyncHTTPClient:
    """
    Промышленный асинхронный HTTP-клиент на базе httpx.AsyncClient:
      - Тайм-ауты/верификация TLS/прокси из настроек
      - Ретраи с экспоненциальным бэкоффом и джиттером
      - Опциональный circuit-breaker и rate-limiter
      - Метрики/трейсинг (если доступны)
      - Удобные хелперы get/post/put/delete/patch/head/options
      - Стриминговая загрузка в файл
    """

    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        headers: Optional[Headers] = None,
        verify: Optional[bool] = None,
        follow_redirects: bool = True,
        retry_policy: Optional[RetryPolicy] = None,
        rate_limiter: Optional[Any] = None,
        breaker: Optional[Any] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._retry = retry_policy or _default_retry_policy()
        self._headers = _compose_headers(headers)
        self._verify = settings.http.verify_tls if verify is None else verify
        self._rate_limiter = rate_limiter if rate_limiter is not None else (RateLimiter(permits_per_sec=settings.concurrency.rate_limit_per_s) if RateLimiter else None)  # type: ignore
        self._breaker = breaker if breaker is not None else (_NullBreaker() if CircuitBreaker is None else CircuitBreaker(name="httpx_async"))
        self._client = client or httpx.AsyncClient(
            base_url=base_url or "",
            headers=self._headers,
            timeout=_effective_timeout(),
            verify=self._verify,
            limits=_effective_limits(),
            follow_redirects=follow_redirects,
            proxies=_effective_proxies(),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncHTTPClient":
        await self._client.__aenter__()
        if hasattr(self._breaker, "__aenter__"):
            await self._breaker.__aenter__()  # type: ignore[func-returns-value]
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        try:
            if hasattr(self._breaker, "__aexit__"):
                await self._breaker.__aexit__(exc_type, exc, tb)  # type: ignore[misc]
        finally:
            await self._client.__aexit__(exc_type, exc, tb)

    # -----------------------
    # High-level HTTP verbs
    # -----------------------
    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    # -----------------------
    # Core request with retry
    # -----------------------
    async def request(
        self,
        method: str,
        url: str,
        *,
        params: QueryParams = None,
        headers: Optional[Headers] = None,
        json_: Optional[JSONType] = None,
        data: Optional[Mapping[str, Any] | bytes] = None,
        files: Optional[Mapping[str, Any]] = None,
        auth: Optional[httpx.Auth] = None,
        timeout: Optional[Union[float, httpx.Timeout]] = None,
        allow_statuses: Optional[set[int]] = None,
        stream: bool = False,
    ) -> httpx.Response:
        """
        Универсальный запрос с повторными попытками.
        - allow_statuses: статусы, которые считаются допустимыми и не приводят к ретраю/ошибке.
        - json_: чтобы не конфликтовать с именем параметра json из httpx.
        - stream=True возвращает Response, который нужно читить через aiter_bytes/aiter_raw.
        """
        hdrs = _compose_headers(headers)
        timeout = timeout if timeout is not None else _effective_timeout()
        allow_statuses = allow_statuses or set()

        attempt = 1
        last_exc: Optional[BaseException] = None

        while attempt <= self._retry.max_attempts:
            if self._rate_limiter:
                # Блокируемся до квоты; реализация зависит от конкретного RateLimiter
                await self._rate_limiter.acquire()

            # Трейсинг (если есть OpenTelemetry)
            if _tracer:
                span_ctx = _tracer.start_as_current_span(
                    "http.request",
                    attributes={
                        "http.method": method,
                        "http.url": url,
                        "net.peer.name": self._client.base_url.host if self._client.base_url else "",
                    },
                )
            else:
                @asynccontextmanager
                async def span_ctx():  # type: ignore
                    yield

            try:
                async with span_ctx:
                    # Circuit breaker gating
                    if hasattr(self._breaker, "allow") and not self._breaker.allow():  # type: ignore[attr-defined]
                        raise httpx.ConnectError("Circuit is open")

                    response = await self._client.request(
                        method=method,
                        url=url,
                        params=params,
                        headers=hdrs,
                        json=json_,
                        data=data,
                        files=files,
                        auth=auth,
                        timeout=timeout,
                        stream=stream,
                    )

                    # Метрики
                    record_counter(
                        name="http_client_requests_total",
                        value=1,
                        attributes={
                            "method": method,
                            "host": response.request.url.host,
                            "status_code": response.status_code,
                        },
                    )
                    record_histogram(
                        name="http_client_response_size_bytes",
                        value=len(await response.aread() if not stream else b""),
                        attributes={"method": method},
                    ) if not stream else None

                    # Успех или допустимый статус
                    if response.status_code < 400 or response.status_code in allow_statuses:
                        if hasattr(self._breaker, "record_success"):
                            self._breaker.record_success()  # type: ignore[call-arg]
                        return response

                    # Решение о ретрае
                    if response.status_code in _RETRIABLE_STATUS and attempt < self._retry.max_attempts:
                        backoff = _compute_backoff(attempt, self._retry)
                        await asyncio.sleep(backoff)
                        attempt += 1
                        continue

                    # Недопустимый статус — бросаем
                    response.raise_for_status()
                    return response  # на случай нестандартного поведения

            except _RETRIABLE_EXC as exc:
                last_exc = exc
                if hasattr(self._breaker, "record_failure"):
                    self._breaker.record_failure()  # type: ignore[call-arg]
                if attempt < self._retry.max_attempts:
                    backoff = _compute_backoff(attempt, self._retry)
                    await asyncio.sleep(backoff)
                    attempt += 1
                    continue
                raise

            except Exception as exc:
                last_exc = exc
                if hasattr(self._breaker, "record_failure"):
                    self._breaker.record_failure()  # type: ignore[call-arg]
                # Неретраибл: пробрасываем сразу
                raise

        # Если сюда дошли — ретраи исчерпаны
        if last_exc:
            raise last_exc
        raise httpx.HTTPError("HTTP request failed with no further details.")

    # -----------------------
    # Convenience helpers
    # -----------------------
    async def json(
        self,
        method: str,
        url: str,
        *,
        params: QueryParams = None,
        headers: Optional[Headers] = None,
        json_: Optional[JSONType] = None,
        data: Optional[Mapping[str, Any] | bytes] = None,
        files: Optional[Mapping[str, Any]] = None,
        auth: Optional[httpx.Auth] = None,
        timeout: Optional[Union[float, httpx.Timeout]] = None,
        allow_statuses: Optional[set[int]] = None,
    ) -> Any:
        """Выполняет запрос и возвращает распарсенный JSON c проверкой Content-Type."""
        resp = await self.request(
            method,
            url,
            params=params,
            headers=headers,
            json_=json_,
            data=data,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_statuses=allow_statuses,
        )
        ctype = resp.headers.get("Content-Type", "")
        if "application/json" not in ctype:
            # Всё же попробуем прочитать JSON, но сообщим о несоответствии
            try:
                return resp.json()
            except Exception as e:
                raise httpx.HTTPError(
                    f"Expected JSON response, got '{ctype}' and failed to parse."
                ) from e
        return resp.json()

    async def download(
        self,
        url: str,
        dest_path: str,
        *,
        chunk_size: int = 1 << 15,  # 32 KiB
        headers: Optional[Headers] = None,
        params: QueryParams = None,
        timeout: Optional[Union[float, httpx.Timeout]] = None,
        md5: Optional[str] = None,
    ) -> str:
        """
        Потоковое скачивание в файл с возобновлением при поддержке сервера (HTTP Range).
        Если передан md5 — можно реализовать послетестовую валидацию (опционально).
        """
        # Проверка возобновления (простая версия: если файл уже существует — пробуем Range)
        resume_from = 0
        try:
            import os
            if os.path.exists(dest_path):
                resume_from = os.path.getsize(dest_path)
        except Exception:
            resume_from = 0

        hdrs = _compose_headers(headers)
        if resume_from > 0:
            hdrs["Range"] = f"bytes={resume_from}-"

        resp = await self.request(
            "GET",
            url,
            headers=hdrs,
            params=params,
            timeout=timeout,
            stream=True,
            allow_statuses={206},  # Partial Content допустим при возобновлении
        )

        mode = "ab" if resume_from > 0 and resp.status_code == 206 else "wb"
        async with await self._client.stream("GET", url, headers=hdrs, params=params, timeout=timeout) as r:
            r.raise_for_status()
            with open(dest_path, mode) as f:
                async for chunk in r.aiter_bytes(chunk_size):
                    f.write(chunk)

        # (Опционально) Валидация md5 — не реализуем по умолчанию, чтобы не тянуть hashlib без необходимости
        return dest_path


# -----------------------
# Фабрика по умолчанию
# -----------------------
@asynccontextmanager
async def default_http_client() -> AsyncIterator[AsyncHTTPClient]:
    """
    Контекстный менеджер с настройками по умолчанию из settings.http.
    Пример:
        async with default_http_client() as cli:
            resp = await cli.get("https://example.com")
    """
    client = AsyncHTTPClient()
    async with client:
        yield client
