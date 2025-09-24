# mythos-core/sdks/python/mythos_client.py
# -*- coding: utf-8 -*-
"""
Промышленный Python SDK для Mythos Core API.

Зависимости:
  - httpx>=0.24
  - (опционально) opentelemetry-api, opentelemetry-sdk, opentelemetry-instrumentation-httpx

Возможности:
  - Синхронный и асинхронный клиенты (httpx).
  - Ретраи с экспоненциальным джиттером, чтение Retry-After, поддержка 5xx/429/сетевых ошибок.
  - Таймауты по умолчанию (connect/read/write/total).
  - Rate limiter (token bucket), Circuit Breaker.
  - Идемпотентные POST через заголовок Idempotency-Key.
  - Пагинация с генераторами/асинк-генераторами.
  - Стриминг событий (Server-Sent Events) — watch_entities().
  - Структурированное логирование (logging), X-Request-ID для трассировки.
  - Опциональная интеграция с OpenTelemetry (span-атрибуты и контекст), если установлена.
  - Строгая типизация моделей (минимальная валидация), удобные алиасы.

ПРИМЕЧАНИЕ:
  Эндпоинты/контракты выведены из имен сервисов:
    /v1/entities
    /v1/entities/{id}
    /v1/entities:batchUpsert
    /v1/entities:search
    /v1/entities:watch   (SSE stream, text/event-stream)
  Адаптируйте при несовпадении.

Автор: Aethernova
Лицензия: Apache-2.0
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, AsyncIterator, Dict, Generator, Iterable, List, Literal, Mapping, Optional, Tuple, Union

import httpx

try:
    # Опционально: OpenTelemetry (если установлен)
    from opentelemetry import trace as _otel_trace  # type: ignore
    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover
    _OTEL_AVAILABLE = False

__all__ = [
    "MythosClient",
    "AsyncMythosClient",
    "ClientConfig",
    "Entity",
    "Relationship",
    "Lifecycle",
    "SortDirection",
    "APIError",
    "RateLimitError",
    "AuthType",
]

logger = logging.getLogger("mythos.sdk")


# --------------------------- Конфигурация/ENUMы --------------------------- #

AuthType = Literal["bearer", "api_key", "none"]

@dataclass(frozen=True)
class ClientConfig:
    base_url: str = "https://api.mythos.local"
    auth_type: AuthType = "bearer"
    token: Optional[str] = None              # Bearer <token> или API Key (для auth_type='api_key')
    api_key_header: str = "X-API-Key"        # Для api_key
    timeout_connect: float = 5.0
    timeout_read: float = 30.0
    timeout_write: float = 30.0
    timeout: float = 35.0                    # total timeout
    retry_attempts: int = 3
    retry_backoff_base: float = 0.25         # базовый интервал
    retry_backoff_cap: float = 5.0           # максимум между попытками
    retry_statuses: Tuple[int, ...] = (429, 500, 502, 503, 504)
    retry_methods: Tuple[str, ...] = ("GET", "POST", "PUT", "PATCH", "DELETE")
    rate_limit_rps: Optional[float] = None   # токенов в секунду
    rate_limit_burst: int = 10
    circuit_fail_threshold: int = 5
    circuit_reset_timeout: float = 30.0
    default_headers: Mapping[str, str] = field(default_factory=dict)
    user_agent: str = "mythos-core-sdk/1.0 (+https://aethernova.dev)"
    verify_ssl: Union[bool, str] = True      # путь к CA bundle или True/False
    proxies: Optional[Union[str, Mapping[str, str]]] = None
    sse_read_timeout: float = 60.0           # таймаут простоя чтения SSE


class Lifecycle:
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    ARCHIVED = "ARCHIVED"
    DELETED = "DELETED"


class SortDirection:
    ASC = "ASC"
    DESC = "DESC"


# --------------------------- Модели данных --------------------------- #

@dataclass
class Relationship:
    type: str
    source_id: str
    target_id: str
    direction: Literal["OUTBOUND", "INBOUND", "BIDIRECTIONAL"] = "OUTBOUND"
    weight: Optional[float] = None
    properties: Optional[Dict[str, Any]] = None


@dataclass
class Entity:
    id: str
    tenant_id: Optional[str] = None
    namespace: Optional[str] = None
    kind: Optional[str] = None
    name: Optional[str] = None
    display_name: Optional[str] = None
    description: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    version: Optional[int] = None
    etag: Optional[str] = None
    lifecycle: Optional[str] = None
    owner: Optional[str] = None
    created_at: Optional[str] = None  # ISO8601
    updated_at: Optional[str] = None
    deleted_at: Optional[str] = None
    relationships: List[Relationship] = field(default_factory=list)
    external_refs: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def from_json(data: Mapping[str, Any]) -> "Entity":
        rels = []
        for r in data.get("relationships", []) or []:
            rels.append(Relationship(
                type=r.get("type", ""),
                source_id=r.get("source_id", r.get("sourceId", "")),
                target_id=r.get("target_id", r.get("targetId", "")),
                direction=r.get("direction", "OUTBOUND"),
                weight=r.get("weight"),
                properties=r.get("properties"),
            ))
        return Entity(
            id=data.get("id", ""),
            tenant_id=data.get("tenant_id") or data.get("tenantId"),
            namespace=data.get("namespace"),
            kind=data.get("kind"),
            name=data.get("name"),
            display_name=data.get("display_name") or data.get("displayName"),
            description=data.get("description"),
            labels=dict(data.get("labels") or {}),
            tags=list(data.get("tags") or []),
            attributes=dict(data.get("attributes") or {}),
            version=data.get("version"),
            etag=data.get("etag"),
            lifecycle=data.get("lifecycle"),
            owner=data.get("owner"),
            created_at=data.get("created_at") or data.get("createdAt"),
            updated_at=data.get("updated_at") or data.get("updatedAt"),
            deleted_at=data.get("deleted_at") or data.get("deletedAt"),
            relationships=rels,
            external_refs=dict(data.get("external_refs") or data.get("externalRefs") or {}),
        )

    def to_json(self) -> Dict[str, Any]:
        data = asdict(self)
        # Простейшая нормализация имён (snake_case → camelCase, если требуется)
        # Оставляем snake_case как сервер-независимый формат.
        return data


# --------------------------- Исключения --------------------------- #

class APIError(Exception):
    def __init__(self, status: int, message: str, code: Optional[str] = None, details: Any = None):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.code = code
        self.details = details


class RateLimitError(APIError):
    pass


# --------------------------- Политики устойчивости --------------------------- #

class _TokenBucket:
    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.capacity = burst
        self.tokens = burst
        self.timestamp = time.monotonic()

    def consume(self, amount: int = 1) -> float:
        now = time.monotonic()
        delta = now - self.timestamp
        self.timestamp = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        if self.tokens >= amount:
            self.tokens -= amount
            return 0.0
        need = amount - self.tokens
        wait = need / self.rate if self.rate > 0 else float("inf")
        self.tokens = 0.0
        return wait


class _CircuitBreaker:
    def __init__(self, fail_threshold: int, reset_timeout: float):
        self.fail_threshold = fail_threshold
        self.reset_timeout = reset_timeout
        self.fail_count = 0
        self.opened_at: Optional[float] = None

    def on_success(self) -> None:
        self.fail_count = 0
        self.opened_at = None

    def on_failure(self) -> None:
        self.fail_count += 1
        if self.fail_count >= self.fail_threshold:
            self.opened_at = time.monotonic()

    def can_pass(self) -> bool:
        if self.opened_at is None:
            return True
        if (time.monotonic() - self.opened_at) >= self.reset_timeout:
            # half-open
            self.fail_count = max(0, self.fail_threshold - 1)
            self.opened_at = None
            return True
        return False


def _compute_backoff(attempt: int, base: float, cap: float) -> float:
    # Экспоненциальный backoff с полным джиттером (AWS strategy)
    import random
    return min(cap, random.random() * (2 ** attempt) * base)


# --------------------------- Общие утилиты --------------------------- #

def _make_headers(cfg: ClientConfig, idempotency_key: Optional[str] = None) -> Dict[str, str]:
    h = {"User-Agent": cfg.user_agent, "Accept": "application/json"}
    if cfg.auth_type == "bearer" and cfg.token:
        h["Authorization"] = f"Bearer {cfg.token}"
    elif cfg.auth_type == "api_key" and cfg.token:
        h[cfg.api_key_header] = cfg.token
    if idempotency_key:
        h["Idempotency-Key"] = idempotency_key
    # Впрыскиваем трассировочный заголовок, если есть активный OTEL span
    if _OTEL_AVAILABLE:
        span = _otel_trace.get_current_span()
        ctx = span.get_span_context() if span else None
        if ctx and ctx.is_valid:
            h.setdefault("X-Trace-Id", format(ctx.trace_id, "032x"))
            h.setdefault("X-Span-Id", format(ctx.span_id, "016x"))
    return {**h, **dict(cfg.default_headers)}


def _default_timeout(cfg: ClientConfig) -> httpx.Timeout:
    return httpx.Timeout(
        timeout=cfg.timeout,
        connect=cfg.timeout_connect,
        read=cfg.timeout_read,
        write=cfg.timeout_write,
        pool=None,
    )


# --------------------------- Таблица путей --------------------------- #

PATHS = {
    "entities": "/v1/entities",
    "entity": "/v1/entities/{id}",
    "batch_upsert": "/v1/entities:batchUpsert",
    "search": "/v1/entities:search",
    "watch": "/v1/entities:watch",  # SSE
}


# =========================== СИНХРОННЫЙ КЛИЕНТ =========================== #

class MythosClient:
    """
    Синхронный клиент Mythos Core.

    Использование:
        cfg = ClientConfig(base_url="https://api.mythos.example", token="...")  # Bearer
        with MythosClient(cfg) as cli:
            ent = cli.get_entity("123")
            for e in cli.list_entities(kind="model"):
                print(e.id)
    """

    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self._client = httpx.Client(
            base_url=cfg.base_url,
            timeout=_default_timeout(cfg),
            verify=cfg.verify_ssl,
            proxies=cfg.proxies,
            headers=_make_headers(cfg),
        )
        self._bucket = _TokenBucket(cfg.rate_limit_rps, cfg.rate_limit_burst) if cfg.rate_limit_rps else None
        self._circuit = _CircuitBreaker(cfg.circuit_fail_threshold, cfg.circuit_reset_timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "MythosClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ---------- ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ---------- #

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        stream: bool = False,
    ) -> httpx.Response:
        if self._bucket:
            wait = self._bucket.consume()
            if wait > 0:
                time.sleep(wait)

        if not self._circuit.can_pass():
            raise APIError(503, "Circuit breaker open")

        req_headers = _make_headers(self.cfg, idempotency_key)
        if headers:
            req_headers.update(headers)
        req_headers.setdefault("X-Request-Id", str(uuid.uuid4()))

        attempts = max(0, self.cfg.retry_attempts)
        last_exc: Optional[Exception] = None

        for attempt in range(attempts + 1):
            try:
                resp = self._client.request(
                    method, path, params=params, json=json_body, headers=req_headers, stream=stream
                )
                if resp.status_code in self.cfg.retry_statuses and method.upper() in self.cfg.retry_methods:
                    if resp.status_code == 429:
                        # Уважаем Retry-After
                        ra = resp.headers.get("Retry-After")
                        delay = float(ra) if ra and ra.isdigit() else _compute_backoff(attempt, self.cfg.retry_backoff_base, self.cfg.retry_backoff_cap)
                        logger.warning("429 received, retrying in %.3fs", delay, extra={"attempt": attempt, "status": resp.status_code})
                        time.sleep(delay)
                        continue
                    delay = _compute_backoff(attempt, self.cfg.retry_backoff_base, self.cfg.retry_backoff_cap)
                    logger.warning("Retryable status %s, retrying in %.3fs", resp.status_code, delay, extra={"attempt": attempt})
                    time.sleep(delay)
                    continue

                if 200 <= resp.status_code < 300:
                    self._circuit.on_success()
                    return resp

                # Неуспешный, не-ретраимый статус
                self._circuit.on_failure()
                self._raise_for_status(resp)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteError, httpx.RemoteProtocolError) as e:
                last_exc = e
                self._circuit.on_failure()
                if method.upper() in self.cfg.retry_methods and attempt < attempts:
                    delay = _compute_backoff(attempt, self.cfg.retry_backoff_base, self.cfg.retry_backoff_cap)
                    logger.warning("Network error, retrying in %.3fs: %s", delay, repr(e), extra={"attempt": attempt})
                    time.sleep(delay)
                    continue
                raise APIError(503, f"Network error: {e}") from e

        if last_exc:
            raise APIError(503, f"Exhausted retries: {last_exc}") from last_exc
        raise APIError(500, "Unknown error after retries")

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        message = payload.get("message") or payload.get("error") or resp.text
        code = payload.get("code")
        if resp.status_code == 429:
            raise RateLimitError(resp.status_code, message or "Too Many Requests", code=code, details=payload)
        raise APIError(resp.status_code, message or f"HTTP {resp.status_code}", code=code, details=payload)

    # ---------- CRUD ОПЕРАЦИИ ---------- #

    def create_entity(self, entity: Entity, *, validate_only: bool = False, idempotency_key: Optional[str] = None) -> Entity:
        params = {"validateOnly": str(validate_only).lower()} if validate_only else None
        resp = self._request("POST", PATHS["entities"], json_body=entity.to_json(), params=params, idempotency_key=idempotency_key or str(uuid.uuid4()))
        return Entity.from_json(resp.json())

    def get_entity(self, entity_id: str, *, view: Optional[str] = None) -> Entity:
        params = {"view": view} if view else None
        resp = self._request("GET", PATHS["entity"].format(id=entity_id), params=params)
        return Entity.from_json(resp.json())

    def update_entity(
        self,
        entity: Entity,
        *,
        update_mask: Optional[List[str]] = None,
        allow_missing: bool = False,
        validate_only: bool = False,
        expected_etag: Optional[str] = None,
    ) -> Entity:
        params: Dict[str, Any] = {}
        if update_mask:
            params["updateMask"] = ",".join(update_mask)
        if allow_missing:
            params["allowMissing"] = "true"
        if validate_only:
            params["validateOnly"] = "true"
        headers = {"If-Match": expected_etag} if expected_etag else None
        resp = self._request("PATCH", PATHS["entity"].format(id=entity.id), params=params, json_body=entity.to_json(), headers=headers)
        return Entity.from_json(resp.json())

    def delete_entity(self, entity_id: str, *, allow_missing: bool = False, expected_etag: Optional[str] = None, hard_delete: bool = False) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if allow_missing:
            params["allowMissing"] = "true"
        if hard_delete:
            params["hardDelete"] = "true"
        headers = {"If-Match": expected_etag} if expected_etag else None
        resp = self._request("DELETE", PATHS["entity"].format(id=entity_id), params=params, headers=headers)
        return resp.json()

    def list_entities(
        self,
        *,
        filter_expr: Optional[str] = None,
        filter_params: Optional[Mapping[str, str]] = None,
        sort: Optional[List[Tuple[str, str]]] = None,  # [(field, ASC|DESC)]
        page_size: int = 100,
        ids: Optional[List[str]] = None,
        kind: Optional[str] = None,
        namespace: Optional[str] = None,
        owner: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        tags: Optional[List[str]] = None,
    ) -> Generator[Entity, None, None]:
        """
        Итеративная пагинация.
        """
        next_token: Optional[str] = None
        while True:
            body: Dict[str, Any] = {
                "page": {"page_size": page_size, "page_token": next_token or ""},
            }
            if filter_expr:
                body["filter"] = {"expr": filter_expr, "params": dict(filter_params or {})}
            if sort:
                body["sort"] = [{"field": f, "direction": d} for f, d in sort]
            if ids:
                body["ids"] = ids
            if kind:
                body["kind"] = kind
            if namespace:
                body["namespace"] = namespace
            if owner:
                body["owner"] = owner
            if labels:
                body["labels"] = dict(labels)
            if tags:
                body["tags"] = tags

            resp = self._request("POST", PATHS["entities"] + ":list", json_body=body)
            payload = resp.json()
            for item in payload.get("entities", []):
                yield Entity.from_json(item)
            next_token = (payload.get("page") or {}).get("next_page_token")
            if not next_token:
                break

    def batch_upsert_entities(self, entities: Iterable[Entity], *, validate_only: bool = False, idempotency_key: Optional[str] = None) -> List[Dict[str, Any]]:
        body = {
            "entities": [e.to_json() for e in entities],
            "validate_only": validate_only,
        }
        resp = self._request("POST", PATHS["batch_upsert"], json_body=body, idempotency_key=idempotency_key or str(uuid.uuid4()))
        data = resp.json()
        return list(data.get("results", []))

    def search_entities(
        self,
        query: str,
        *,
        filter_expr: Optional[str] = None,
        filter_params: Optional[Mapping[str, str]] = None,
        sort: Optional[List[Tuple[str, str]]] = None,
        page_size: int = 50,
    ) -> Generator[Entity, None, None]:
        next_token: Optional[str] = None
        while True:
            body: Dict[str, Any] = {
                "query": query,
                "page": {"page_size": page_size, "page_token": next_token or ""},
            }
            if filter_expr:
                body["filter"] = {"expr": filter_expr, "params": dict(filter_params or {})}
            if sort:
                body["sort"] = [{"field": f, "direction": d} for f, d in sort]

            resp = self._request("POST", PATHS["search"], json_body=body)
            payload = resp.json()
            for item in payload.get("entities", []):
                yield Entity.from_json(item)
            next_token = (payload.get("page") or {}).get("next_page_token")
            if not next_token:
                break

    # ---------- SSE WATCH ---------- #

    def watch_entities(self, *, filter_expr: Optional[str] = None, since: Optional[str] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Синхронное чтение событий через SSE.
        Возвращает dict { "type": str, "entity": Entity, "occurred_at": ISO8601, ... }
        """
        params: Dict[str, Any] = {}
        if filter_expr:
            params["filter"] = filter_expr
        if since:
            params["since"] = since

        headers = {"Accept": "text/event-stream"}
        with self._client.stream("GET", PATHS["watch"], params=params, headers=headers, timeout=self.cfg.sse_read_timeout) as resp:
            if resp.status_code != 200:
                self._raise_for_status(resp)
            for line in resp.iter_lines():
                if not line:
                    continue
                # Ожидаем формат: "data: {...json...}"
                if line.startswith(b"data:"):
                    try:
                        payload = json.loads(line[5:].decode("utf-8").strip())
                        if "entity" in payload and isinstance(payload["entity"], dict):
                            payload["entity"] = Entity.from_json(payload["entity"])
                        yield payload
                    except Exception as e:  # pragma: no cover
                        logger.warning("Failed to parse SSE line: %s", e)


# =========================== АСИНХРОННЫЙ КЛИЕНТ =========================== #

class AsyncMythosClient:
    """
    Асинхронный клиент Mythos Core.

    Использование:
        cfg = ClientConfig(base_url="https://api.mythos.example", token="...")
        async with AsyncMythosClient(cfg) as cli:
            ent = await cli.get_entity("123")
            async for e in cli.list_entities(kind="dataset"):
                ...
    """

    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            timeout=_default_timeout(cfg),
            verify=cfg.verify_ssl,
            proxies=cfg.proxies,
            headers=_make_headers(cfg),
        )
        self._bucket = _TokenBucket(cfg.rate_limit_rps, cfg.rate_limit_burst) if cfg.rate_limit_rps else None
        self._circuit = _CircuitBreaker(cfg.circuit_fail_threshold, cfg.circuit_reset_timeout)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncMythosClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def _await_bucket(self) -> None:
        if not self._bucket:
            return
        wait = self._bucket.consume()
        if wait > 0:
            await asyncio.sleep(wait)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotency_key: Optional[str] = None,
        stream: bool = False,
    ) -> httpx.Response:
        await self._await_bucket()

        if not self._circuit.can_pass():
            raise APIError(503, "Circuit breaker open")

        req_headers = _make_headers(self.cfg, idempotency_key)
        if headers:
            req_headers.update(headers)
        req_headers.setdefault("X-Request-Id", str(uuid.uuid4()))

        attempts = max(0, self.cfg.retry_attempts)
        last_exc: Optional[Exception] = None

        for attempt in range(attempts + 1):
            try:
                resp = await self._client.request(
                    method, path, params=params, json=json_body, headers=req_headers, stream=stream
                )
                if resp.status_code in self.cfg.retry_statuses and method.upper() in self.cfg.retry_methods:
                    if resp.status_code == 429:
                        ra = resp.headers.get("Retry-After")
                        delay = float(ra) if ra and ra.isdigit() else _compute_backoff(attempt, self.cfg.retry_backoff_base, self.cfg.retry_backoff_cap)
                        logger.warning("429 received, retrying in %.3fs", delay, extra={"attempt": attempt, "status": resp.status_code})
                        await asyncio.sleep(delay)
                        continue
                    delay = _compute_backoff(attempt, self.cfg.retry_backoff_base, self.cfg.retry_backoff_cap)
                    logger.warning("Retryable status %s, retrying in %.3fs", resp.status_code, delay, extra={"attempt": attempt})
                    await asyncio.sleep(delay)
                    continue

                if 200 <= resp.status_code < 300:
                    self._circuit.on_success()
                    return resp

                self._circuit.on_failure()
                self._raise_for_status(resp)
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteError, httpx.RemoteProtocolError) as e:
                last_exc = e
                self._circuit.on_failure()
                if method.upper() in self.cfg.retry_methods and attempt < attempts:
                    delay = _compute_backoff(attempt, self.cfg.retry_backoff_base, self.cfg.retry_backoff_cap)
                    logger.warning("Network error, retrying in %.3fs: %s", delay, repr(e), extra={"attempt": attempt})
                    await asyncio.sleep(delay)
                    continue
                raise APIError(503, f"Network error: {e}") from e

        if last_exc:
            raise APIError(503, f"Exhausted retries: {last_exc}") from last_exc
        raise APIError(500, "Unknown error after retries")

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        try:
            payload = resp.json()
        except Exception:
            payload = {}
        message = payload.get("message") or payload.get("error") or resp.text
        code = payload.get("code")
        if resp.status_code == 429:
            raise RateLimitError(resp.status_code, message or "Too Many Requests", code=code, details=payload)
        raise APIError(resp.status_code, message or f"HTTP {resp.status_code}", code=code, details=payload)

    # ---------- CRUD ---------- #

    async def create_entity(self, entity: Entity, *, validate_only: bool = False, idempotency_key: Optional[str] = None) -> Entity:
        params = {"validateOnly": str(validate_only).lower()} if validate_only else None
        resp = await self._request("POST", PATHS["entities"], json_body=entity.to_json(), params=params, idempotency_key=idempotency_key or str(uuid.uuid4()))
        return Entity.from_json(resp.json())

    async def get_entity(self, entity_id: str, *, view: Optional[str] = None) -> Entity:
        params = {"view": view} if view else None
        resp = await self._request("GET", PATHS["entity"].format(id=entity_id), params=params)
        return Entity.from_json(resp.json())

    async def update_entity(
        self,
        entity: Entity,
        *,
        update_mask: Optional[List[str]] = None,
        allow_missing: bool = False,
        validate_only: bool = False,
        expected_etag: Optional[str] = None,
    ) -> Entity:
        params: Dict[str, Any] = {}
        if update_mask:
            params["updateMask"] = ",".join(update_mask)
        if allow_missing:
            params["allowMissing"] = "true"
        if validate_only:
            params["validateOnly"] = "true"
        headers = {"If-Match": expected_etag} if expected_etag else None
        resp = await self._request("PATCH", PATHS["entity"].format(id=entity.id), params=params, json_body=entity.to_json(), headers=headers)
        return Entity.from_json(resp.json())

    async def delete_entity(self, entity_id: str, *, allow_missing: bool = False, expected_etag: Optional[str] = None, hard_delete: bool = False) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if allow_missing:
            params["allowMissing"] = "true"
        if hard_delete:
            params["hardDelete"] = "true"
        headers = {"If-Match": expected_etag} if expected_etag else None
        resp = await self._request("DELETE", PATHS["entity"].format(id=entity_id), params=params, headers=headers)
        return resp.json()

    async def list_entities(
        self,
        *,
        filter_expr: Optional[str] = None,
        filter_params: Optional[Mapping[str, str]] = None,
        sort: Optional[List[Tuple[str, str]]] = None,
        page_size: int = 100,
        ids: Optional[List[str]] = None,
        kind: Optional[str] = None,
        namespace: Optional[str] = None,
        owner: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
        tags: Optional[List[str]] = None,
    ) -> AsyncIterator[Entity]:
        next_token: Optional[str] = None
        while True:
            body: Dict[str, Any] = {
                "page": {"page_size": page_size, "page_token": next_token or ""},
            }
            if filter_expr:
                body["filter"] = {"expr": filter_expr, "params": dict(filter_params or {})}
            if sort:
                body["sort"] = [{"field": f, "direction": d} for f, d in sort]
            if ids:
                body["ids"] = ids
            if kind:
                body["kind"] = kind
            if namespace:
                body["namespace"] = namespace
            if owner:
                body["owner"] = owner
            if labels:
                body["labels"] = dict(labels)
            if tags:
                body["tags"] = tags

            resp = await self._request("POST", PATHS["entities"] + ":list", json_body=body)
            payload = resp.json()
            for item in payload.get("entities", []):
                yield Entity.from_json(item)
            next_token = (payload.get("page") or {}).get("next_page_token")
            if not next_token:
                break

    async def batch_upsert_entities(self, entities: Iterable[Entity], *, validate_only: bool = False, idempotency_key: Optional[str] = None) -> List[Dict[str, Any]]:
        body = {
            "entities": [e.to_json() for e in entities],
            "validate_only": validate_only,
        }
        resp = await self._request("POST", PATHS["batch_upsert"], json_body=body, idempotency_key=idempotency_key or str(uuid.uuid4()))
        data = resp.json()
        return list(data.get("results", []))

    async def search_entities(
        self,
        query: str,
        *,
        filter_expr: Optional[str] = None,
        filter_params: Optional[Mapping[str, str]] = None,
        sort: Optional[List[Tuple[str, str]]] = None,
        page_size: int = 50,
    ) -> AsyncIterator[Entity]:
        next_token: Optional[str] = None
        while True:
            body: Dict[str, Any] = {
                "query": query,
                "page": {"page_size": page_size, "page_token": next_token or ""},
            }
            if filter_expr:
                body["filter"] = {"expr": filter_expr, "params": dict(filter_params or {})}
            if sort:
                body["sort"] = [{"field": f, "direction": d} for f, d in sort]

            resp = await self._request("POST", PATHS["search"], json_body=body)
            payload = resp.json()
            for item in payload.get("entities", []):
                yield Entity.from_json(item)
            next_token = (payload.get("page") or {}).get("next_page_token")
            if not next_token:
                break

    # ---------- SSE WATCH ---------- #

    async def watch_entities(self, *, filter_expr: Optional[str] = None, since: Optional[str] = None) -> AsyncIterator[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if filter_expr:
            params["filter"] = filter_expr
        if since:
            params["since"] = since
        headers = {"Accept": "text/event-stream"}

        # httpx.AsyncClient.stream возвращает async context manager
        async with self._client.stream("GET", PATHS["watch"], params=params, headers=headers, timeout=self.cfg.sse_read_timeout) as resp:
            if resp.status_code != 200:
                self._raise_for_status(resp)
            async for line in resp.aiter_lines():
                if not line:
                    continue
                if line.startswith("data:"):
                    try:
                        payload = json.loads(line[5:].strip())
                        if "entity" in payload and isinstance(payload["entity"], dict):
                            payload["entity"] = Entity.from_json(payload["entity"])
                        yield payload
                    except Exception as e:  # pragma: no cover
                        logger.warning("Failed to parse SSE line: %s", e)


# --------------------------- Вспомогательные фабрики --------------------------- #

def build_sync_client(
    base_url: str,
    token: Optional[str] = None,
    *,
    auth_type: AuthType = "bearer",
    **kwargs: Any,
) -> MythosClient:
    cfg = ClientConfig(base_url=base_url, token=token, auth_type=auth_type, **kwargs)
    return MythosClient(cfg)


async def build_async_client(
    base_url: str,
    token: Optional[str] = None,
    *,
    auth_type: AuthType = "bearer",
    **kwargs: Any,
) -> AsyncMythosClient:
    cfg = ClientConfig(base_url=base_url, token=token, auth_type=auth_type, **kwargs)
    return AsyncMythosClient(cfg)


# --------------------------- Пример использования --------------------------- #

if __name__ == "__main__":  # Демонстрация синхронного сценария
    logging.basicConfig(level=logging.INFO)
    cfg = ClientConfig(
        base_url="http://localhost:8080",
        token=None,
        auth_type="none",
        retry_attempts=2,
        rate_limit_rps=20.0,
    )
    with MythosClient(cfg) as cli:
        try:
            # Пример листинга (при наличии сервера)
            for e in cli.list_entities(kind="dataset"):
                print(e)
        except APIError as e:
            logger.error("APIError: %s", e)
