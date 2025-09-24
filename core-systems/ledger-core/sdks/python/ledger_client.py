# ledger-core/sdks/python/ledger_client.py
"""
Индустриальный Python SDK для Ledger Core API.

Особенности:
- Синхронный и асинхронный клиент (httpx).
- Строгая типизация, dataclass-конфиг, явные исключения.
- Повторы с экспоненциальным бэкоффом + джиттер (идемпотентные методы).
- Идемпотентность (Idempotency-Key) и детерминированная генерация ключа.
- Пагинация (итераторы) и фильтры.
- Загрузка файлов (multipart) и стриминг событий (SSE/NDJSON).
- Валидация ответов по JSON Schema (опционально, если доступен jsonschema).
- Хуки before_request/after_response, интеграция с OpenTelemetry (если установлен).
- Безопасные дефолты таймаутов, ограничение размеров, поддержка прокси/кастомного транспорта.

Зависимости:
- httpx>=0.24 (sync/async HTTP клиент)
- (опционально) jsonschema>=4.0 для валидации
- (опционально) opentelemetry-api/opentelemetry-instrumentation-httpx для автотрейсинга

Пример:
    from ledger_client import LedgerClient, LedgerAsyncClient, TxCreate

    client = LedgerClient(base_url="https://api.ledger.example.com", api_key="secret")
    tx = client.create_transaction(TxCreate(...))
    for item in client.list_transactions(limit=100):
        ...

Лицензия: MIT/Apache-2.0 (на выбор вашего репозитория).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Literal,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    TypedDict,
    Union,
)

# Внешние зависимости
try:
    import httpx
except ImportError as e:  # pragma: no cover
    raise RuntimeError("Требуется зависимость httpx (pip install httpx)") from e

# Опциональная валидация JSON Schema
with contextlib.suppress(Exception):
    import jsonschema  # type: ignore

    _HAS_JSONSCHEMA = True
else:
    _HAS_JSONSCHEMA = False

# Опциональный OpenTelemetry (необязателен)
with contextlib.suppress(Exception):
    from opentelemetry import trace  # type: ignore

    _TRACER = trace.get_tracer("ledger-client")
except Exception:  # type: ignore
    _TRACER = None  # type: ignore


# ----------------------------- Исключения -----------------------------


class LedgerError(Exception):
    """Базовое исключение SDK."""


class NetworkError(LedgerError):
    """Сетевые ошибки и таймауты."""


class AuthError(LedgerError):
    """Проблемы аутентификации/авторизации (401/403)."""


class NotFoundError(LedgerError):
    """Ресурс не найден (404)."""


class RateLimitError(LedgerError):
    """Превышение лимитов (429)."""

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class ValidationError(LedgerError):
    """Ошибка валидации данных (422/400)."""


class ServerError(LedgerError):
    """Серверные ошибки (>=500)."""


class RetryExhausted(LedgerError):
    """Исчерпаны попытки повтора."""


# ----------------------------- Типы данных -----------------------------


# Публичные типы для пользователей SDK (минимально необходимые)
class TxParty(TypedDict, total=False):
    id: str
    type: Literal["customer", "merchant", "internal_account", "provider", "bank"]
    name: Optional[str]


class TxCreate(TypedDict, total=False):
    schemaVersion: str
    id: Optional[str]  # если не задан — будет сгенерирован UUIDv4 на стороне SDK
    type: Literal["charge", "refund", "transfer", "payout", "fee", "adjustment"]
    status: Literal["pending", "authorized", "posted", "reversed", "failed", "cancelled"]
    occurredAt: str
    recordedAt: Optional[str]
    currency: str
    amount: str
    amountNet: str
    payer: TxParty
    payee: TxParty
    externalId: Optional[str]
    metadata: Dict[str, Any]


class Tx(TypedDict, total=False):
    # Представление ответа API. Детализируйте под свой контракт.
    id: str
    schemaVersion: str
    type: str
    status: str
    occurredAt: str
    recordedAt: str
    currency: str
    amount: str
    amountNet: str
    payer: TxParty
    payee: TxParty
    metadata: Dict[str, Any]


class Page(TypedDict, total=False):
    items: List[Tx]
    next: Optional[str]  # токен/курсор
    total: Optional[int]


# ----------------------------- Конфигурация клиента -----------------------------


@dataclass(frozen=True)
class RetryConfig:
    max_attempts: int = 5
    base_delay: float = 0.25  # секунд
    max_delay: float = 5.0
    # Повторяем только безопасные/идемпотентные методы + определённые коды
    retry_on_status: Tuple[int, ...] = (408, 409, 425, 429, 500, 502, 503, 504)
    retry_on_methods: Tuple[str, ...] = ("GET", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "POST")
    # POST повторяем только при наличии Idempotency-Key или при явно установленном флаге idempotent=True
    jitter: float = 0.2  # +/- 20% случайный разброс задержки


@dataclass(frozen=True)
class ClientConfig:
    base_url: str
    api_key: Optional[str] = None
    timeout: float = 10.0
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    pool_limits: httpx.Limits = field(default_factory=lambda: httpx.Limits(max_keepalive_connections=20, max_connections=100))
    proxies: Optional[Union[str, Dict[str, str]]] = None
    headers: Mapping[str, str] = field(default_factory=dict)
    user_agent: str = "ledger-core-python-sdk/1.0"
    validate_responses: bool = True
    retry: RetryConfig = field(default_factory=RetryConfig)
    # Ограничение на размер тела ответа (байты); None = без ограничения
    max_response_bytes: Optional[int] = 20 * 1024 * 1024  # 20 MiB
    # Ключи для идемпотентности можно генерировать автоматически
    auto_idempotency_for_post: bool = True


BeforeRequestHook = Callable[[httpx.Request], None]
AfterResponseHook = Callable[[httpx.Response], None]


# ----------------------------- Утилиты -----------------------------


def _now_ms() -> int:
    return int(time.time() * 1000)


def _compute_idempotency_key(method: str, url: str, body: Optional[Union[str, bytes]]) -> str:
    """
    Детерминированная генерация Idempotency-Key: sha256(method|url|body).
    """
    h = hashlib.sha256()
    h.update(method.encode("utf-8"))
    h.update(b"|")
    h.update(url.encode("utf-8"))
    if body is not None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        h.update(b"|")
        h.update(body)
    return h.hexdigest()


def _should_retry(
    method: str,
    status_code: Optional[int],
    exc: Optional[Exception],
    retry_cfg: RetryConfig,
    idempotent: bool,
) -> bool:
    if exc is not None:
        return True  # сетевые/таймаутные — пробуем повторить
    if status_code is None:
        return False
    if status_code in retry_cfg.retry_on_status:
        # POST повторяем только если запрос идемпотентный
        if method.upper() == "POST" and not idempotent:
            return False
        return True
    return False


def _backoff_sleep(attempt: int, cfg: RetryConfig) -> float:
    d = min(cfg.max_delay, cfg.base_delay * (2 ** (attempt - 1)))
    # джиттер +/- jitter%
    j = d * cfg.jitter
    return max(0.0, d + (os.urandom(1)[0] / 255.0 * 2 * j - j))


def _ensure_status(resp: httpx.Response) -> None:
    if 200 <= resp.status_code < 300:
        return
    if resp.status_code in (401, 403):
        raise AuthError(f"Auth error: {resp.status_code} {resp.text[:500]}")
    if resp.status_code == 404:
        raise NotFoundError(f"Not found: {resp.request.url}")
    if resp.status_code == 429:
        ra = None
        try:
            ra_hdr = resp.headers.get("Retry-After")
            if ra_hdr:
                ra = float(ra_hdr)
        except Exception:
            ra = None
        raise RateLimitError(f"Rate limited: {resp.text[:500]}", retry_after=ra)
    if resp.status_code in (400, 409, 422):
        raise ValidationError(f"Validation error: {resp.text[:1000]}")
    if resp.status_code >= 500:
        raise ServerError(f"Server error: {resp.status_code} {resp.text[:1000]}")
    raise LedgerError(f"Unexpected status: {resp.status_code} {resp.text[:500]}")


def _enforce_response_size(resp: httpx.Response, max_bytes: Optional[int]) -> None:
    if max_bytes is None:
        return
    # Попытаемся оценить по Content-Length, иначе по фактическим байтам
    cl = resp.headers.get("Content-Length")
    if cl and cl.isdigit() and int(cl) > max_bytes:
        raise LedgerError(f"Response too large: {cl} bytes > {max_bytes}")
    if resp.content is not None and len(resp.content) > max_bytes:
        raise LedgerError(f"Response too large: {len(resp.content)} bytes > {max_bytes}")


# ----------------------------- Базовый клиент -----------------------------


class _Base:
    def __init__(
        self,
        cfg: ClientConfig,
        before_request: Optional[BeforeRequestHook] = None,
        after_response: Optional[AfterResponseHook] = None,
        schema: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self._cfg = cfg
        self._before = before_request
        self._after = after_response
        self._schema = schema  # JSON Schema транзакции (опционально)

    # ----------------- публичные методы высокого уровня -----------------

    # Транзакции
    def _tx_path(self) -> str:
        return "/api/v1/transactions"

    # Health
    def _health_path(self) -> str:
        return "/health/ready"

    # События (SSE/NDJSON)
    def _events_path(self) -> str:
        return "/api/v1/events"

    # ----------------- сериализация/валидация -----------------

    def _serialize_json(self, obj: Any) -> str:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    def _validate_tx(self, data: Mapping[str, Any]) -> None:
        if not self._cfg.validate_responses or not _HAS_JSONSCHEMA or self._schema is None:
            return
        try:
            jsonschema.validate(data, self._schema)  # type: ignore
        except Exception as e:  # pragma: no cover
            raise ValidationError(f"JSONSchema validation failed: {e}") from e

    # ----------------- заголовки и авторизация -----------------

    def _default_headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": self._cfg.user_agent,
        }
        if self._cfg.api_key:
            h["Authorization"] = f"Bearer {self._cfg.api_key}"
        # Корреляционный ID для трассинга
        h.setdefault("X-Request-Id", str(uuid.uuid4()))
        return {**h, **dict(self._cfg.headers)}

    # ----------------- формирование параметров -----------------

    def _params_from_filters(self, **filters: Any) -> Dict[str, Any]:
        return {k: v for k, v in filters.items() if v is not None}


# ----------------------------- Синхронный клиент -----------------------------


class LedgerClient(_Base):
    """
    Синхронный клиент. Управляет собственным httpx.Client (context manager).
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        *,
        timeout: float = 10.0,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        write_timeout: float = 10.0,
        headers: Optional[Mapping[str, str]] = None,
        proxies: Optional[Union[str, Dict[str, str]]] = None,
        pool_limits: Optional[httpx.Limits] = None,
        validate_responses: bool = True,
        retry: Optional[RetryConfig] = None,
        before_request: Optional[BeforeRequestHook] = None,
        after_response: Optional[AfterResponseHook] = None,
        schema: Optional[Mapping[str, Any]] = None,
        auto_idempotency_for_post: bool = True,
        max_response_bytes: Optional[int] = 20 * 1024 * 1024,
        user_agent: str = "ledger-core-python-sdk/1.0",
    ) -> None:
        cfg = ClientConfig(
            base_url=base_url.rstrip("/"),
            api_key=api_key,
            timeout=timeout,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
            headers=headers or {},
            proxies=proxies,
            pool_limits=pool_limits or httpx.Limits(max_keepalive_connections=20, max_connections=100),
            validate_responses=validate_responses,
            retry=retry or RetryConfig(),
            auto_idempotency_for_post=auto_idempotency_for_post,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
        )
        super().__init__(cfg, before_request, after_response, schema)
        self._client = httpx.Client(
            base_url=self._cfg.base_url,
            headers=self._default_headers(),
            timeout=httpx.Timeout(self._cfg.timeout, connect=self._cfg.connect_timeout, read=self._cfg.read_timeout, write=self._cfg.write_timeout),
            limits=self._cfg.pool_limits,
            proxies=self._cfg.proxies,
        )

    # ---------- контекстный менеджер ----------
    def __enter__(self) -> "LedgerClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # ---------- низкоуровневый запрос с повторами ----------
    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotent: bool = False,
        files: Optional[Mapping[str, Any]] = None,
        stream: bool = False,
    ) -> httpx.Response:
        url = path if path.startswith("http") else f"{self._cfg.base_url}{path}"
        req_headers: Dict[str, str] = dict(self._default_headers())
        if headers:
            req_headers.update(headers)

        body_str: Optional[str] = None
        data = None
        content = None

        if json_body is not None:
            body_str = self._serialize_json(json_body)
            content = body_str.encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json; charset=utf-8")

        if files:
            # httpx сам соберёт multipart
            data = json_body or {}
            content = None  # data/files mutually exclusive

        method_up = method.upper()
        # Автоидемпотентность для POST, если включена и есть тело
        if method_up == "POST" and self._cfg.auto_idempotency_for_post and not req_headers.get("Idempotency-Key"):
            key = _compute_idempotency_key(method_up, url, body_str)
            req_headers["Idempotency-Key"] = key
            idempotent = True

        attempt = 1
        last_exc: Optional[Exception] = None
        while True:
            try:
                req = self._client.build_request(method_up, url, params=params, content=content, headers=req_headers, files=files, data=data)
                if self._before:
                    self._before(req)
                if _TRACER:
                    with _TRACER.start_as_current_span(f"HTTP {method_up} {path}"):
                        resp = self._client.send(req, stream=stream)
                else:
                    resp = self._client.send(req, stream=stream)
                if self._after:
                    self._after(resp)
                if not stream:
                    _enforce_response_size(resp, self._cfg.max_response_bytes)
                if _should_retry(method_up, resp.status_code, None, self._cfg.retry, idempotent):
                    # 429 может вернуть Retry-After
                    delay = None
                    if resp.status_code == 429:
                        ra_hdr = resp.headers.get("Retry-After")
                        with contextlib.suppress(Exception):
                            delay = float(ra_hdr) if ra_hdr else None
                    resp.read()
                    resp.close()
                    if attempt >= self._cfg.retry.max_attempts:
                        raise RetryExhausted(f"Повторы исчерпаны (attempt={attempt})")
                    time.sleep(delay if delay is not None else _backoff_sleep(attempt, self._cfg.retry))
                    attempt += 1
                    continue
                return resp
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                last_exc = e
                if attempt >= self._cfg.retry.max_attempts or not _should_retry(method_up, None, e, self._cfg.retry, idempotent):
                    raise NetworkError(str(e)) from e
                time.sleep(_backoff_sleep(attempt, self._cfg.retry))
                attempt += 1

    # ---------- высокоуровневые операции ----------

    def health(self) -> bool:
        resp = self._request("GET", self._health_path())
        if resp.status_code // 100 == 2:
            return True
        return False

    def create_transaction(self, tx: TxCreate) -> Tx:
        # Генерируем UUID при необходимости
        if not tx.get("id"):
            tx = {**tx, "id": str(uuid.uuid4())}
        resp = self._request("POST", self._tx_path(), json_body=tx)
        _ensure_status(resp)
        data = resp.json()
        self._validate_tx(data)
        return data  # type: ignore[return-value]

    def get_transaction(self, tx_id: str) -> Tx:
        resp = self._request("GET", f"{self._tx_path()}/{tx_id}")
        _ensure_status(resp)
        data = resp.json()
        self._validate_tx(data)
        return data  # type: ignore[return-value]

    def list_transactions(
        self,
        *,
        limit: int = 100,
        cursor: Optional[str] = None,
        status: Optional[str] = None,
        type: Optional[str] = None,
        occurred_from: Optional[str] = None,
        occurred_to: Optional[str] = None,
        payer_id: Optional[str] = None,
        payee_id: Optional[str] = None,
    ) -> Iterator[Tx]:
        """
        Итератор по всем транзакциям с автоматическим обходом страниц.
        """
        params = self._params_from_filters(
            limit=limit,
            cursor=cursor,
            status=status,
            type=type,
            occurred_from=occurred_from,
            occurred_to=occurred_to,
            payer_id=payer_id,
            payee_id=payee_id,
        )
        while True:
            resp = self._request("GET", self._tx_path(), params=params)
            _ensure_status(resp)
            page: Page = resp.json()  # type: ignore[assignment]
            items = page.get("items") or []
            for it in items:
                self._validate_tx(it)
                yield it  # type: ignore[misc]
            nxt = page.get("next")
            if not nxt:
                break
            params = {"cursor": nxt, "limit": limit}

    def refund_transaction(self, original_tx_id: str, amount: Optional[str] = None, *, reason: Optional[str] = None) -> Tx:
        payload: Dict[str, Any] = {"originalTxId": original_tx_id}
        if amount is not None:
            payload["amount"] = amount
        if reason:
            payload["reason"] = reason
        resp = self._request("POST", f"{self._tx_path()}/refunds", json_body=payload)
        _ensure_status(resp)
        data = resp.json()
        self._validate_tx(data)
        return data  # type: ignore[return-value]

    def upload_attachment(self, tx_id: str, file_path: str, *, content_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Загрузка файла как вложения к транзакции.
        """
        name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            files = {
                "file": (name, f, content_type or "application/octet-stream"),
            }
            resp = self._request("POST", f"{self._tx_path()}/{tx_id}/attachments", files=files)
        _ensure_status(resp)
        return resp.json()

    def stream_events(self, *, since: Optional[str] = None, event_types: Optional[Sequence[str]] = None) -> Iterator[Dict[str, Any]]:
        """
        Поток событий (SSE/NDJSON). Автоматически восстанавливает соединение с курсором last_event_id.
        """
        params: Dict[str, Any] = {}
        if since:
            params["since"] = since
        if event_types:
            params["types"] = ",".join(event_types)

        last_id: Optional[str] = None
        while True:
            headers = {}
            if last_id:
                headers["Last-Event-Id"] = last_id
            try:
                resp = self._request("GET", self._events_path(), params=params, headers=headers, stream=True)
                _ensure_status(resp)
                # Поддержка двух форматов: SSE "data:" строки и NDJSON (по строкам)
                for line in resp.iter_lines():
                    if not line:
                        continue
                    s = line.decode("utf-8", errors="ignore")
                    if s.startswith("id:"):
                        last_id = s[3:].strip()
                        continue
                    if s.startswith("data:"):
                        payload = s[5:].strip()
                    else:
                        payload = s
                    try:
                        ev = json.loads(payload)
                        if "id" in ev:
                            last_id = str(ev["id"])
                        yield ev
                    except json.JSONDecodeError:
                        continue
            except NetworkError:
                time.sleep(1.0)
                continue
            finally:
                with contextlib.suppress(Exception):
                    resp.close()  # type: ignore[name-defined]


# ----------------------------- Асинхронный клиент -----------------------------


class LedgerAsyncClient(_Base):
    """
    Асинхронный клиент. Использует httpx.AsyncClient.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        *,
        timeout: float = 10.0,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        write_timeout: float = 10.0,
        headers: Optional[Mapping[str, str]] = None,
        proxies: Optional[Union[str, Dict[str, str]]] = None,
        pool_limits: Optional[httpx.Limits] = None,
        validate_responses: bool = True,
        retry: Optional[RetryConfig] = None,
        before_request: Optional[BeforeRequestHook] = None,
        after_response: Optional[AfterResponseHook] = None,
        schema: Optional[Mapping[str, Any]] = None,
        auto_idempotency_for_post: bool = True,
        max_response_bytes: Optional[int] = 20 * 1024 * 1024,
        user_agent: str = "ledger-core-python-sdk/1.0",
    ) -> None:
        cfg = ClientConfig(
            base_url=base_url.rstrip("/"),
            api_key=api_key,
            timeout=timeout,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
            headers=headers or {},
            proxies=proxies,
            pool_limits=pool_limits or httpx.Limits(max_keepalive_connections=20, max_connections=100),
            validate_responses=validate_responses,
            retry=retry or RetryConfig(),
            auto_idempotency_for_post=auto_idempotency_for_post,
            max_response_bytes=max_response_bytes,
            user_agent=user_agent,
        )
        super().__init__(cfg, before_request, after_response, schema)
        self._client = httpx.AsyncClient(
            base_url=self._cfg.base_url,
            headers=self._default_headers(),
            timeout=httpx.Timeout(self._cfg.timeout, connect=self._cfg.connect_timeout, read=self._cfg.read_timeout, write=self._cfg.write_timeout),
            limits=self._cfg.pool_limits,
            proxies=self._cfg.proxies,
        )

    # ---------- контекстный менеджер ----------
    async def __aenter__(self) -> "LedgerAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---------- низкоуровневый запрос с повторами ----------
    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        idempotent: bool = False,
        files: Optional[Mapping[str, Any]] = None,
        stream: bool = False,
    ) -> httpx.Response:
        url = path if path.startswith("http") else f"{self._cfg.base_url}{path}"
        req_headers: Dict[str, str] = dict(self._default_headers())
        if headers:
            req_headers.update(headers)

        body_str: Optional[str] = None
        data = None
        content = None
        if json_body is not None:
            body_str = self._serialize_json(json_body)
            content = body_str.encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json; charset=utf-8")

        if files:
            data = json_body or {}
            content = None

        method_up = method.upper()
        if method_up == "POST" and self._cfg.auto_idempotency_for_post and not req_headers.get("Idempotency-Key"):
            key = _compute_idempotency_key(method_up, url, body_str)
            req_headers["Idempotency-Key"] = key
            idempotent = True

        attempt = 1
        last_exc: Optional[Exception] = None
        while True:
            try:
                req = self._client.build_request(method_up, url, params=params, content=content, headers=req_headers, files=files, data=data)
                if self._before:
                    self._before(req)
                if _TRACER:
                    with _TRACER.start_as_current_span(f"HTTP {method_up} {path}"):
                        resp = await self._client.send(req, stream=stream)
                else:
                    resp = await self._client.send(req, stream=stream)
                if self._after:
                    self._after(resp)
                if not stream:
                    _enforce_response_size(resp, self._cfg.max_response_bytes)
                if _should_retry(method_up, resp.status_code, None, self._cfg.retry, idempotent):
                    delay = None
                    if resp.status_code == 429:
                        ra_hdr = resp.headers.get("Retry-After")
                        with contextlib.suppress(Exception):
                            delay = float(ra_hdr) if ra_hdr else None
                    await resp.aread()
                    await resp.aclose()
                    if attempt >= self._cfg.retry.max_attempts:
                        raise RetryExhausted(f"Повторы исчерпаны (attempt={attempt})")
                    await asyncio_sleep(delay if delay is not None else _backoff_sleep(attempt, self._cfg.retry))
                    attempt += 1
                    continue
                return resp
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                last_exc = e
                if attempt >= self._cfg.retry.max_attempts or not _should_retry(method_up, None, e, self._cfg.retry, idempotent):
                    raise NetworkError(str(e)) from e
                await asyncio_sleep(_backoff_sleep(attempt, self._cfg.retry))
                attempt += 1


# Неблокирующий sleep (без импортов asyncio на верхнем уровне)
async def asyncio_sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)


# ---------- Асинхронные высокоуровневые операции ----------


    async def health(self) -> bool:
        resp = await self._request("GET", self._health_path())
        return resp.status_code // 100 == 2

    async def create_transaction(self, tx: TxCreate) -> Tx:
        if not tx.get("id"):
            tx = {**tx, "id": str(uuid.uuid4())}
        resp = await self._request("POST", self._tx_path(), json_body=tx)
        _ensure_status(resp)
        data = resp.json()
        self._validate_tx(data)
        return data  # type: ignore[return-value]

    async def get_transaction(self, tx_id: str) -> Tx:
        resp = await self._request("GET", f"{self._tx_path()}/{tx_id}")
        _ensure_status(resp)
        data = resp.json()
        self._validate_tx(data)
        return data  # type: ignore[return-value]

    async def list_transactions(
        self,
        *,
        limit: int = 100,
        cursor: Optional[str] = None,
        status: Optional[str] = None,
        type: Optional[str] = None,
        occurred_from: Optional[str] = None,
        occurred_to: Optional[str] = None,
        payer_id: Optional[str] = None,
        payee_id: Optional[str] = None,
    ) -> AsyncIterator[Tx]:
        params = self._params_from_filters(
            limit=limit,
            cursor=cursor,
            status=status,
            type=type,
            occurred_from=occurred_from,
            occurred_to=occurred_to,
            payer_id=payer_id,
            payee_id=payee_id,
        )
        while True:
            resp = await self._request("GET", self._tx_path(), params=params)
            _ensure_status(resp)
            page: Page = resp.json()  # type: ignore[assignment]
            items = page.get("items") or []
            for it in items:
                self._validate_tx(it)
                yield it  # type: ignore[misc]
            nxt = page.get("next")
            if not nxt:
                break
            params = {"cursor": nxt, "limit": limit}

    async def refund_transaction(self, original_tx_id: str, amount: Optional[str] = None, *, reason: Optional[str] = None) -> Tx:
        payload: Dict[str, Any] = {"originalTxId": original_tx_id}
        if amount is not None:
            payload["amount"] = amount
        if reason:
            payload["reason"] = reason
        resp = await self._request("POST", f"{self._tx_path()}/refunds", json_body=payload)
        _ensure_status(resp)
        data = resp.json()
        self._validate_tx(data)
        return data  # type: ignore[return-value]

    async def upload_attachment(self, tx_id: str, file_path: str, *, content_type: Optional[str] = None) -> Dict[str, Any]:
        name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            files = {
                "file": (name, f, content_type or "application/octet-stream"),
            }
            resp = await self._request("POST", f"{self._tx_path()}/{tx_id}/attachments", files=files)
        _ensure_status(resp)
        return resp.json()

    async def stream_events(self, *, since: Optional[str] = None, event_types: Optional[Sequence[str]] = None) -> AsyncIterator[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if since:
            params["since"] = since
        if event_types:
            params["types"] = ",".join(event_types)

        last_id: Optional[str] = None
        while True:
            headers = {}
            if last_id:
                headers["Last-Event-Id"] = last_id
            try:
                resp = await self._request("GET", self._events_path(), params=params, headers=headers, stream=True)
                _ensure_status(resp)
                async with resp.aiter_lines() as lines:  # type: ignore[attr-defined]
                    async for line in lines:
                        if not line:
                            continue
                        s = line
                        if s.startswith("id:"):
                            last_id = s[3:].strip()
                            continue
                        if s.startswith("data:"):
                            payload = s[5:].strip()
                        else:
                            payload = s
                        with contextlib.suppress(Exception):
                            ev = json.loads(payload)
                            if "id" in ev:
                                last_id = str(ev["id"])
                            yield ev
            except NetworkError:
                await asyncio_sleep(1.0)
                continue
            finally:
                with contextlib.suppress(Exception):
                    await resp.aclose()  # type: ignore[name-defined]


# ----------------------------- Экспорт API модуля -----------------------------

__all__ = [
    "LedgerClient",
    "LedgerAsyncClient",
    "ClientConfig",
    "RetryConfig",
    "LedgerError",
    "NetworkError",
    "AuthError",
    "NotFoundError",
    "RateLimitError",
    "ValidationError",
    "ServerError",
    "RetryExhausted",
    "TxCreate",
    "Tx",
    "TxParty",
]
