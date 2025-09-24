# policy-core/sdks/python/policy_client.py
# -*- coding: utf-8 -*-
"""
Промышленный Python SDK для policy-core.

Зависимости:
  - httpx>=0.24
  - (необязательно) opentelemetry-api, opentelemetry-sdk — для трассировки

Пример:
    from policy_client import PolicyClient, AsyncPolicyClient, EvaluateRequest

    with PolicyClient.from_env() as client:
        pol = client.get_policy("policy_123")
        for item in client.list_policies(page_size=50):
            ...
        decision = client.evaluate(EvaluateRequest(entrypoint="policy_core.rbac.allow",
                                                   input={"subject": "alice", "action": "read", "resource": "doc"}))
        if decision.allow:
            ...

    # Async
    import asyncio
    async def main():
        async with AsyncPolicyClient.from_env() as aclient:
            res = await aclient.evaluate(EvaluateRequest(entrypoint="policy_core.rbac.allow",
                                                         input={"subject": "alice", "action": "read", "resource": "doc"}))
            print(res.allow)
    asyncio.run(main())
"""
from __future__ import annotations

import json
import os
import time
import uuid
import math
import typing as t
from dataclasses import dataclass, field

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise ImportError("policy_client requires httpx>=0.24. Install via: pip install httpx") from e


# ----------------------------
# Конфиги и модели
# ----------------------------

@dataclass(frozen=True)
class TimeoutConfig:
    connect: float = 2.0
    read: float = 30.0
    write: float = 30.0
    pool: float = 30.0

    def to_httpx(self) -> httpx.Timeout:
        return httpx.Timeout(connect=self.connect, read=self.read, write=self.write, pool=self.pool)


@dataclass(frozen=True)
class RetryConfig:
    max_attempts: int = 5
    backoff_factor: float = 0.3  # экспоненциальный * джиттер
    max_backoff: float = 10.0
    retry_on_status: t.Tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    retry_on_exceptions: t.Tuple[type[BaseException], ...] = (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.TransportError)


@dataclass(frozen=True)
class RateLimitConfig:
    rate_per_sec: float = 0.0  # 0 = выключено
    burst: int = 1


@dataclass(frozen=True)
class CircuitBreakerConfig:
    failure_threshold: int = 10
    recovery_seconds: int = 30


@dataclass
class ClientConfig:
    base_url: str
    api_base_path: str = "/api/v1"
    api_key: t.Optional[str] = None
    oauth_token: t.Optional[str] = None
    timeout: TimeoutConfig = field(default_factory=TimeoutConfig)
    retries: RetryConfig = field(default_factory=RetryConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    user_agent: str = "policy-core-python-sdk/1.0"
    verify_ssl: bool = True
    proxies: t.Optional[dict] = None
    extra_headers: t.Dict[str, str] = field(default_factory=dict)
    # идемпотентность POST/PUT по умолчанию включена; можно отключать на уровне методов
    default_idempotency: bool = True

    @staticmethod
    def from_env() -> "ClientConfig":
        return ClientConfig(
            base_url=os.getenv("POLICY_CORE_BASE_URL", "http://localhost:8080"),
            api_base_path=os.getenv("POLICY_CORE_API_BASE", "/api/v1"),
            api_key=os.getenv("POLICY_CORE_API_KEY"),
            oauth_token=os.getenv("POLICY_CORE_OAUTH_TOKEN"),
            timeout=TimeoutConfig(
                connect=float(os.getenv("POLICY_CORE_TIMEOUT_CONNECT", "2")),
                read=float(os.getenv("POLICY_CORE_TIMEOUT_READ", "30")),
                write=float(os.getenv("POLICY_CORE_TIMEOUT_WRITE", "30")),
                pool=float(os.getenv("POLICY_CORE_TIMEOUT_POOL", "30")),
            ),
            retries=RetryConfig(
                max_attempts=int(os.getenv("POLICY_CORE_RETRIES", "5")),
                backoff_factor=float(os.getenv("POLICY_CORE_BACKOFF", "0.3")),
                max_backoff=float(os.getenv("POLICY_CORE_MAX_BACKOFF", "10")),
            ),
            rate_limit=RateLimitConfig(
                rate_per_sec=float(os.getenv("POLICY_CORE_RPS", "0")),
                burst=int(os.getenv("POLICY_CORE_BURST", "1")),
            ),
            circuit_breaker=CircuitBreakerConfig(
                failure_threshold=int(os.getenv("POLICY_CORE_CB_FAILS", "10")),
                recovery_seconds=int(os.getenv("POLICY_CORE_CB_RECOVERY", "30")),
            ),
            user_agent=os.getenv("POLICY_CORE_USER_AGENT", "policy-core-python-sdk/1.0"),
            verify_ssl=os.getenv("POLICY_CORE_VERIFY_SSL", "true").lower() not in ("0", "false", "no"),
        )


# ---- Доменные модели ----

@dataclass
class Policy:
    id: str
    name: str | None = None
    version: str | None = None
    spec: dict | None = None


@dataclass
class EvaluateRequest:
    entrypoint: str
    input: dict
    include_explain: bool = False
    include_metrics: bool = False


@dataclass
class EvaluateResult:
    allow: bool
    decision_id: str | None = None
    explain: t.Any | None = None
    metrics: dict | None = None
    raw: dict | None = None


# ----------------------------
# Исключения
# ----------------------------

class ApiError(Exception):
    def __init__(self, message: str, status: int | None = None, code: str | None = None, request_id: str | None = None, details: t.Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id
        self.details = details

    def __str__(self) -> str:  # pragma: no cover - строковое представление
        base = super().__str__()
        parts = []
        if self.status is not None:
            parts.append(f"status={self.status}")
        if self.code:
            parts.append(f"code={self.code}")
        if self.request_id:
            parts.append(f"request_id={self.request_id}")
        return f"{base} ({', '.join(parts)})" if parts else base


class AuthError(ApiError):
    pass


class RateLimitError(ApiError):
    retry_after: float | None = None


class NotFoundError(ApiError):
    pass


class ServerError(ApiError):
    pass


# ----------------------------
# Вспомогательные механики (троттлинг, CB, ретраи)
# ----------------------------

class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = max(0.0, rate_per_sec)
        self.burst = max(1, burst)
        self._tokens = float(self.burst)
        self._ts = time.monotonic()

    def acquire(self) -> None:
        if self.rate <= 0.0:
            return  # disabled
        now = time.monotonic()
        elapsed = now - self._ts
        self._ts = now
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return
        # подождать недостающие токены
        need = 1.0 - self._tokens
        sleep = need / self.rate
        time.sleep(sleep)
        self._tokens = 0.0  # токен израсходован


class _CircuitBreaker:
    def __init__(self, cfg: CircuitBreakerConfig) -> None:
        self.cfg = cfg
        self._fails = 0
        self._opened_at: float | None = None

    def before(self) -> None:
        if self._opened_at is None:
            return
        if time.monotonic() - self._opened_at >= self.cfg.recovery_seconds:
            # half-open
            return
        raise ServerError("circuit breaker is open; skipping request")

    def record_success(self) -> None:
        self._fails = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._fails += 1
        if self._fails >= self.cfg.failure_threshold:
            self._opened_at = time.monotonic()


def _compute_backoff(attempt: int, cfg: RetryConfig) -> float:
    base = cfg.backoff_factor * (2 ** (attempt - 1))
    # полумножитель джиттера (full jitter)
    return min(cfg.max_backoff, base * (0.5 + 0.5 * os.urandom(1)[0] / 255.0))


def _mk_headers(cfg: ClientConfig, extra: t.Optional[dict] = None, idempotent: bool = False) -> dict:
    headers = {
        "User-Agent": cfg.user_agent,
        "Accept": "application/json",
    }
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    elif cfg.oauth_token:
        headers["Authorization"] = f"Bearer {cfg.oauth_token}"
    headers.update(cfg.extra_headers)
    if extra:
        headers.update(extra)
    if idempotent:
        headers.setdefault("Idempotency-Key", str(uuid.uuid4()))
    headers.setdefault("X-Request-Id", str(uuid.uuid4()))
    return headers


def _join_url(base: str, path: str) -> str:
    if base.endswith("/"):
        base = base[:-1]
    if not path.startswith("/"):
        path = "/" + path
    return base + path


# ----------------------------
# Базовый Sync клиент
# ----------------------------

class PolicyClient:
    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        base = config.base_url.rstrip("/")
        api_base = config.api_base_path
        self.base_url = _join_url(base, api_base)
        self._client = httpx.Client(
            timeout=config.timeout.to_httpx(),
            verify=config.verify_ssl,
            proxies=config.proxies,
            headers=_mk_headers(config),
        )
        self._bucket = _TokenBucket(config.rate_limit.rate_per_sec, config.rate_limit.burst)
        self._cb = _CircuitBreaker(config.circuit_breaker)

        # Опциональная телеметрия
        self._tracer = None
        try:
            from opentelemetry import trace  # type: ignore
            self._tracer = trace.get_tracer("policy-core-python-sdk")
        except Exception:
            self._tracer = None

    # ---- фабрики ----
    @classmethod
    def from_env(cls) -> "PolicyClient":
        return cls(ClientConfig.from_env())

    # ---- контекстный менеджер ----
    def __enter__(self) -> "PolicyClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ---- ресурсы ----
    def close(self) -> None:
        self._client.close()

    # ---- HTTP слой с ретраями/CB/троттлингом ----
    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: t.Any | None = None,
        data: t.Any | None = None,
        files: t.Any | None = None,
        headers: dict | None = None,
        stream: bool = False,
        idempotent: bool | None = None,
    ) -> httpx.Response:
        idempotent = self.config.default_idempotency if idempotent is None else idempotent
        url = _join_url(self.base_url, path)
        attempts = 0
        last_exc: BaseException | None = None

        while True:
            attempts += 1
            self._cb.before()
            self._bucket.acquire()
            req_headers = _mk_headers(self.config, headers, idempotent=idempotent and method.upper() in ("POST", "PUT", "PATCH"))
            span_cm = _noop_cm()
            if self._tracer:
                span_cm = self._tracer.start_as_current_span(f"http {method.upper()} {path}")

            with span_cm:
                try:
                    resp = self._client.request(
                        method,
                        url,
                        params=params,
                        json=json_body,
                        data=data,
                        files=files,
                        headers=req_headers,
                        timeout=self.config.timeout.to_httpx(),
                        stream=stream,
                    )
                    if self._should_retry(resp.status_code) and attempts < self.config.retries.max_attempts:
                        self._cb.record_failure()
                        sleep = _compute_backoff(attempts, self.config.retries)
                        _assign_retry_after(resp, sleep)
                        time.sleep(sleep)
                        continue
                    self._cb.record_success()
                    self._raise_for_status(resp)
                    return resp
                except self.config.retries.retry_on_exceptions as ex:
                    last_exc = ex
                    self._cb.record_failure()
                    if attempts >= self.config.retries.max_attempts:
                        raise ServerError(f"network failure after {attempts} attempts: {ex}") from ex
                    time.sleep(_compute_backoff(attempts, self.config.retries))
                except ApiError:
                    # уже нормализовано
                    raise

    def _should_retry(self, status: int) -> bool:
        return status in self.config.retries.retry_on_status

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if 200 <= resp.status_code < 300:
            return
        message = f"HTTP {resp.status_code}"
        request_id = resp.headers.get("X-Request-Id") or resp.headers.get("x-request-id")
        code = None
        details = None
        try:
            payload = resp.json()
            message = payload.get("message") or payload.get("error") or message
            code = payload.get("code")
            details = payload.get("details")
        except Exception:
            payload = None  # не JSON — оставляем message

        if resp.status_code in (401, 403):
            raise AuthError(message, status=resp.status_code, code=code, request_id=request_id, details=details)
        if resp.status_code == 404:
            raise NotFoundError(message, status=resp.status_code, code=code, request_id=request_id, details=details)
        if resp.status_code == 429:
            err = RateLimitError(message, status=resp.status_code, code=code, request_id=request_id, details=details)
            ra = resp.headers.get("Retry-After")
            if ra:
                try:
                    err.retry_after = float(ra)
                except Exception:
                    err.retry_after = None
            raise err
        if 400 <= resp.status_code < 500:
            raise ApiError(message, status=resp.status_code, code=code, request_id=request_id, details=details)
        raise ServerError(message, status=resp.status_code, code=code, request_id=request_id, details=details)

    # ------------- Доменные методы -------------
    # Policies
    def get_policy(self, policy_id: str) -> Policy:
        resp = self._request("GET", f"/policies/{policy_id}")
        obj = resp.json()
        return Policy(id=str(obj.get("id") or policy_id), name=obj.get("name"), version=obj.get("version"), spec=obj.get("spec"))

    def list_policies(
        self,
        *,
        page: int | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        extra_params: dict | None = None,
    ) -> t.Iterator[dict]:
        """
        Итератор по политикам. Поддерживает page/page_size ИЛИ cursor (лента).
        Если задан limit — останавливается после limit элементов.
        """
        fetched = 0
        params = dict(extra_params or {})
        if cursor:
            params["cursor"] = cursor
        elif page is not None or page_size is not None:
            if page is not None:
                params["page"] = page
            if page_size is not None:
                params["page_size"] = page_size

        while True:
            resp = self._request("GET", "/policies", params=params)
            payload = resp.json()
            items = payload.get("items") or payload.get("data") or []
            for it in items:
                yield it
                fetched += 1
                if limit is not None and fetched >= limit:
                    return
            # пагинация cursor
            nxt = payload.get("next") or payload.get("next_cursor")
            if nxt:
                params = dict(extra_params or {})
                params["cursor"] = nxt
                continue
            # пагинация page
            if "page" in params:
                total_pages = payload.get("total_pages")
                current_page = payload.get("page") or params.get("page", 1)
                if total_pages and current_page < total_pages:
                    params["page"] = current_page + 1
                    continue
            break

    def create_policy(self, spec: dict, *, name: str | None = None, idempotent: bool | None = None) -> dict:
        body = {"spec": spec}
        if name:
            body["name"] = name
        resp = self._request("POST", "/policies", json_body=body, idempotent=idempotent)
        return resp.json()

    def update_policy(self, policy_id: str, spec: dict, *, if_match: str | None = None, idempotent: bool | None = None) -> dict:
        headers = {"If-Match": if_match} if if_match else None
        resp = self._request("PUT", f"/policies/{policy_id}", json_body={"spec": spec}, headers=headers, idempotent=idempotent)
        return resp.json()

    def delete_policy(self, policy_id: str) -> None:
        self._request("DELETE", f"/policies/{policy_id}")
        return None

    # Evaluation
    def evaluate(self, req: EvaluateRequest) -> EvaluateResult:
        body = {
            "entrypoint": req.entrypoint,
            "input": req.input,
            "options": {"explain": req.include_explain, "metrics": req.include_metrics},
        }
        resp = self._request("POST", "/evaluate", json_body=body, idempotent=True)
        data = resp.json()
        allow = bool(data.get("allow") if "allow" in data else data.get("result") in (True, "allow"))
        return EvaluateResult(
            allow=allow,
            decision_id=data.get("decision_id") or data.get("id"),
            explain=data.get("explain"),
            metrics=data.get("metrics"),
            raw=data,
        )

    # Bundles/Manifest
    def get_bundle_manifest(self) -> dict:
        resp = self._request("GET", "/policies/bundle/manifest")
        return resp.json()

    def upload_bundle(self, tar_stream: t.BinaryIO, *, content_type: str = "application/gzip", idempotent: bool | None = None) -> dict:
        headers = {"Content-Type": content_type}
        resp = self._request("POST", "/policies/bundle", data=tar_stream, headers=headers, idempotent=idempotent)
        return resp.json()

    # Generic helpers
    def get(self, path: str, *, params: dict | None = None) -> dict:
        resp = self._request("GET", path, params=params)
        return resp.json()

    def post(self, path: str, *, json_body: t.Any = None, idempotent: bool | None = None) -> dict:
        resp = self._request("POST", path, json_body=json_body, idempotent=idempotent)
        return resp.json()


# ----------------------------
# Асинхронный клиент
# ----------------------------

class AsyncPolicyClient:
    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        base = config.base_url.rstrip("/")
        self.base_url = _join_url(base, config.api_base_path)
        self._client = httpx.AsyncClient(
            timeout=config.timeout.to_httpx(),
            verify=config.verify_ssl,
            proxies=config.proxies,
            headers=_mk_headers(config),
        )
        self._bucket = _TokenBucket(config.rate_limit.rate_per_sec, config.rate_limit.burst)
        self._cb = _CircuitBreaker(config.circuit_breaker)

        self._tracer = None
        try:
            from opentelemetry import trace  # type: ignore
            self._tracer = trace.get_tracer("policy-core-python-sdk")
        except Exception:
            self._tracer = None

    @classmethod
    def from_env(cls) -> "AsyncPolicyClient":
        return cls(ClientConfig.from_env())

    async def __aenter__(self) -> "AsyncPolicyClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _arequest(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: t.Any | None = None,
        data: t.Any | None = None,
        files: t.Any | None = None,
        headers: dict | None = None,
        stream: bool = False,
        idempotent: bool | None = None,
    ) -> httpx.Response:
        idempotent = self.config.default_idempotency if idempotent is None else idempotent
        url = _join_url(self.base_url, path)
        attempts = 0

        while True:
            attempts += 1
            self._cb.before()
            self._bucket.acquire()  # простая синхронная задержка достаточна
            req_headers = _mk_headers(self.config, headers, idempotent=idempotent and method.upper() in ("POST", "PUT", "PATCH"))
            span_cm = _noop_cm()
            if self._tracer:
                span_cm = self._tracer.start_as_current_span(f"http {method.upper()} {path}")

            async with span_cm:
                try:
                    resp = await self._client.request(
                        method,
                        url,
                        params=params,
                        json=json_body,
                        data=data,
                        files=files,
                        headers=req_headers,
                        timeout=self.config.timeout.to_httpx(),
                        stream=stream,
                    )
                    if self._should_retry(resp.status_code) and attempts < self.config.retries.max_attempts:
                        self._cb.record_failure()
                        sleep = _compute_backoff(attempts, self.config.retries)
                        _assign_retry_after(resp, sleep)
                        await _asleep(sleep)
                        continue
                    self._cb.record_success()
                    self._raise_for_status(resp)
                    return resp
                except self.config.retries.retry_on_exceptions as ex:
                    self._cb.record_failure()
                    if attempts >= self.config.retries.max_attempts:
                        raise ServerError(f"network failure after {attempts} attempts: {ex}") from ex
                    await _asleep(_compute_backoff(attempts, self.config.retries))
                except ApiError:
                    raise

    def _should_retry(self, status: int) -> bool:
        return status in self.config.retries.retry_on_status

    def _raise_for_status(self, resp: httpx.Response) -> None:
        # переиспользуем логику из синхронного клиента
        PolicyClient._raise_for_status(self, resp)

    # --- доменные методы (зеркало синхронных) ---
    async def get_policy(self, policy_id: str) -> Policy:
        resp = await self._arequest("GET", f"/policies/{policy_id}")
        obj = resp.json()
        return Policy(id=str(obj.get("id") or policy_id), name=obj.get("name"), version=obj.get("version"), spec=obj.get("spec"))

    async def list_policies(
        self,
        *,
        page: int | None = None,
        page_size: int | None = None,
        cursor: str | None = None,
        limit: int | None = None,
        extra_params: dict | None = None,
    ) -> t.AsyncIterator[dict]:
        fetched = 0
        params = dict(extra_params or {})
        if cursor:
            params["cursor"] = cursor
        elif page is not None or page_size is not None:
            if page is not None:
                params["page"] = page
            if page_size is not None:
                params["page_size"] = page_size

        while True:
            resp = await self._arequest("GET", "/policies", params=params)
            payload = resp.json()
            items = payload.get("items") or payload.get("data") or []
            for it in items:
                yield it
                fetched += 1
                if limit is not None and fetched >= limit:
                    return
            nxt = payload.get("next") or payload.get("next_cursor")
            if nxt:
                params = dict(extra_params or {})
                params["cursor"] = nxt
                continue
            if "page" in params:
                total_pages = payload.get("total_pages")
                current_page = payload.get("page") or params.get("page", 1)
                if total_pages and current_page < total_pages:
                    params["page"] = current_page + 1
                    continue
            break

    async def create_policy(self, spec: dict, *, name: str | None = None, idempotent: bool | None = None) -> dict:
        body = {"spec": spec}
        if name:
            body["name"] = name
        resp = await self._arequest("POST", "/policies", json_body=body, idempotent=idempotent)
        return resp.json()

    async def update_policy(self, policy_id: str, spec: dict, *, if_match: str | None = None, idempotent: bool | None = None) -> dict:
        headers = {"If-Match": if_match} if if_match else None
        resp = await self._arequest("PUT", f"/policies/{policy_id}", json_body={"spec": spec}, headers=headers, idempotent=idempotent)
        return resp.json()

    async def delete_policy(self, policy_id: str) -> None:
        await self._arequest("DELETE", f"/policies/{policy_id}")
        return None

    async def evaluate(self, req: EvaluateRequest) -> EvaluateResult:
        body = {
            "entrypoint": req.entrypoint,
            "input": req.input,
            "options": {"explain": req.include_explain, "metrics": req.include_metrics},
        }
        resp = await self._arequest("POST", "/evaluate", json_body=body, idempotent=True)
        data = resp.json()
        allow = bool(data.get("allow") if "allow" in data else data.get("result") in (True, "allow"))
        return EvaluateResult(
            allow=allow,
            decision_id=data.get("decision_id") or data.get("id"),
            explain=data.get("explain"),
            metrics=data.get("metrics"),
            raw=data,
        )

    async def get_bundle_manifest(self) -> dict:
        resp = await self._arequest("GET", "/policies/bundle/manifest")
        return resp.json()

    async def upload_bundle(self, tar_stream: t.BinaryIO, *, content_type: str = "application/gzip", idempotent: bool | None = None) -> dict:
        headers = {"Content-Type": content_type}
        resp = await self._arequest("POST", "/policies/bundle", data=tar_stream, headers=headers, idempotent=idempotent)
        return resp.json()


# ----------------------------
# Внутренние утилиты
# ----------------------------

class _noop_cm:
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        return False
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False


async def _asleep(sec: float) -> None:
    # без asyncio.sleep импорта на верхнем уровне
    import asyncio
    await asyncio.sleep(sec)


def _assign_retry_after(resp: httpx.Response, fallback: float) -> None:
    # Устанавливает Retry-After если его нет, только для удобства отладки/логирования
    try:
        resp.headers.setdefault("Retry-After", f"{fallback:.3f}")
    except Exception:
        pass


# ----------------------------
# Мини-тест самопроверки (локально)
# ----------------------------

if __name__ == "__main__":  # pragma: no cover
    cfg = ClientConfig.from_env()
    print("Base URL:", cfg.base_url)
    print("API Base:", cfg.api_base_path)
    print("Timeouts:", cfg.timeout)
    print("Retries:", cfg.retries)
    # Не делаем реальных вызовов; модуль должен импортироваться без побочных эффектов.
