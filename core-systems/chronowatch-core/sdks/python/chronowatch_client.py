# chronowatch-core/sdks/python/chronowatch_client.py
# -*- coding: utf-8 -*-
"""
Промышленный Python SDK для ChronoWatch Core.

Зависимости:
    - httpx>=0.27  (sync/async HTTP/2 клиент)
    - python>=3.9

Функциональность:
    - Синхронный и асинхронный клиенты (ChronoWatchClient, ChronoWatchAsyncClient)
    - Авторизация Bearer (строка или callables для ротации токена)
    - Повторные попытки с экспоненциальным бэккофом и джиттером
    - Идемпотентность POST через заголовок Idempotency-Key (опционально)
    - Пагинация генераторами (iter_*)
    - Утилиты сериализации RFC3339/Duration
    - Watch через Server-Sent Events (если включено на шлюзе)

Совместимо с HTTP-маппингами gRPC из calendar.proto:
    GET    /v1/calendars
    GET    /v1/calendars/{id}
    POST   /v1/calendars
    PATCH  /v1/calendars/{id}
    DELETE /v1/calendars/{id}
    ... и т.д. для composites, slas, serviceBindings,
    а также:
    POST   /v1/availability:resolve
    POST   /v1/sla:compute
"""

from __future__ import annotations

import abc
import asyncio
import json
import logging
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    Generator,
    Iterable,
    Iterator,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "The 'httpx' package is required for chronowatch_client. Install via: pip install httpx>=0.27"
    ) from e


__all__ = [
    "ChronoWatchClient",
    "ChronoWatchAsyncClient",
    "ClientConfig",
    "ChronoWatchError",
    "ApiError",
    "AuthError",
    "RetryError",
    "ValidationError",
    "to_rfc3339",
    "from_rfc3339",
    "to_duration",
    "from_duration",
    "TimeInterval",
]

SDK_VERSION = "0.1.0"
LOGGER = logging.getLogger("chronowatch.sdk")


# ============================
# Исключения
# ============================

class ChronoWatchError(Exception):
    """Базовое исключение SDK."""


class ApiError(ChronoWatchError):
    """HTTP-ошибка API."""

    def __init__(self, status_code: int, message: str, payload: Optional[dict] = None):
        super().__init__(f"API error {status_code}: {message}")
        self.status_code = status_code
        self.payload = payload or {}


class AuthError(ApiError):
    """401/403."""


class RetryError(ChronoWatchError):
    """Превышен лимит повторных попыток."""


class ValidationError(ChronoWatchError):
    """Неверные параметры запроса."""


# ============================
# Конфиг и модели
# ============================

TokenProvider = Union[str, Callable[[], str], Callable[[], Optional[str]], Callable[[], "Awaitable[str]"]]

@dataclass
class ClientConfig:
    base_url: str
    token: Optional[TokenProvider] = None
    timeout: float = 10.0
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    retries: int = 3
    backoff_factor: float = 0.5
    max_backoff: float = 8.0
    verify_ssl: bool = True
    http2: bool = True
    user_agent: str = field(default_factory=lambda: f"ChronoWatchSDK/{SDK_VERSION} (+https://aethernova.example)")
    default_headers: Mapping[str, str] = field(default_factory=dict)

    @staticmethod
    def from_env(prefix: str = "CHRONO_") -> "ClientConfig":
        return ClientConfig(
            base_url=os.getenv(f"{prefix}BASE_URL", "http://localhost:8080"),
            token=os.getenv(f"{prefix}TOKEN"),
            timeout=float(os.getenv(f"{prefix}TIMEOUT", "10")),
            verify_ssl=os.getenv(f"{prefix}VERIFY_SSL", "true").lower() in ("1", "true", "yes"),
            http2=os.getenv(f"{prefix}HTTP2", "true").lower() in ("1", "true", "yes"),
        )


@dataclass
class TimeInterval:
    start: datetime
    end: datetime

    def to_json(self) -> Dict[str, str]:
        if self.end <= self.start:
            raise ValidationError("TimeInterval.end must be greater than start")
        return {"start": to_rfc3339(self.start), "end": to_rfc3339(self.end)}


# ============================
# Утилиты времени
# ============================

_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)

def to_rfc3339(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def from_rfc3339(value: str) -> datetime:
    if not _RFC3339_RE.match(value):
        raise ValidationError(f"Invalid RFC3339 timestamp: {value}")
    if value.endswith("Z"):
        value = value.replace("Z", "+00:00")
    return datetime.fromisoformat(value)


def to_duration(td: Union[timedelta, int, float]) -> str:
    """
    Преобразует timedelta/секунды в ISO 8601 duration (пример: PT90S, PT2H, P1DT3H).
    Упрощённая запись: секунды -> PT{S}S.
    """
    if isinstance(td, (int, float)):
        seconds = float(td)
    else:
        seconds = td.total_seconds()
    if seconds < 0:
        raise ValidationError("Duration must be non-negative")
    # Простая форма: только секунды
    return f"PT{int(seconds)}S"


def from_duration(value: str) -> timedelta:
    """
    Минимально необходимый парсер ISO8601 duration PTxxS/PTxxM/PTxxH.
    Для расширенных форматов используйте полноценные парсеры по необходимости.
    """
    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", value)
    if not m:
        raise ValidationError(f"Unsupported duration format: {value}")
    hours = int(m.group(1) or 0)
    mins = int(m.group(2) or 0)
    secs = int(m.group(3) or 0)
    return timedelta(hours=hours, minutes=mins, seconds=secs)


# ============================
# Базовый миксин
# ============================

class _BaseClient(abc.ABC):
    def __init__(self, cfg: ClientConfig):
        if not cfg.base_url:
            raise ValidationError("base_url is required")
        self._cfg = cfg
        self._base = cfg.base_url.rstrip("/")
        self._default_headers = {
            "User-Agent": cfg.user_agent,
            "Accept": "application/json",
            **(cfg.default_headers or {}),
        }

    # ------- токен --------
    async def _aget_token(self) -> Optional[str]:
        token = self._cfg.token
        if token is None:
            return None
        if callable(token):
            res = token()
            if asyncio.iscoroutine(res):
                return await res  # type: ignore[func-returns-value]
            return res  # type: ignore[return-value]
        return token  # type: ignore[return-value]

    def _get_token(self) -> Optional[str]:
        token = self._cfg.token
        if token is None:
            return None
        if callable(token):
            return token()  # type: ignore[return-value]
        return token  # type: ignore[return-value]

    # ------- заголовки -----
    def _auth_headers(self, token: Optional[str]) -> Dict[str, str]:
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    # ------- URL helper ----
    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self._base}{path}"

    # ------- правила ретраев ----
    @staticmethod
    def _should_retry(method: str, status: int) -> bool:
        # Идемпотентные + управляемо для 429/5xx
        if status in (408, 429) or 500 <= status < 600:
            return True
        return False

    @staticmethod
    def _sleep_with_backoff(attempt: int, factor: float, max_backoff: float) -> None:
        sleep = min((2 ** attempt) * factor, max_backoff)
        # небольшой джиттер
        sleep = sleep * (0.8 + 0.4 * (uuid.uuid4().int % 1000) / 1000.0)
        time.sleep(sleep)

    @staticmethod
    async def _asleep_with_backoff(attempt: int, factor: float, max_backoff: float) -> None:
        sleep = min((2 ** attempt) * factor, max_backoff)
        sleep = sleep * (0.8 + 0.4 * (uuid.uuid4().int % 1000) / 1000.0)
        await asyncio.sleep(sleep)

    # ------- формат update_mask ----
    @staticmethod
    def _mask_to_str(update_mask: Optional[Union[str, Sequence[str]]]) -> Optional[str]:
        if update_mask is None:
            return None
        if isinstance(update_mask, str):
            return update_mask
        return ",".join(update_mask)


# ============================
# Синхронный клиент
# ============================

class ChronoWatchClient(_BaseClient):
    """
    Синхронный клиент ChronoWatch.

    Пример:
        cfg = ClientConfig.from_env()
        with ChronoWatchClient(cfg) as cli:
            for c in cli.iter_calendars(page_size=200):
                ...
    """

    def __init__(self, cfg: ClientConfig):
        super().__init__(cfg)
        self._client = httpx.Client(
            http2=cfg.http2,
            verify=cfg.verify_ssl,
            headers=self._default_headers,
            timeout=httpx.Timeout(
                cfg.timeout, connect=cfg.connect_timeout, read=cfg.read_timeout, write=cfg.write_timeout
            ),
        )

    # ---- контекстный менеджер ----
    def __enter__(self) -> "ChronoWatchClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: D401
        self.close()

    def close(self) -> None:
        self._client.close()

    # ---- низкоуровневый запрос с ретраями ----
    def _request(
        self,
        method: Literal["GET", "POST", "PATCH", "DELETE"],
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        expected_status: Iterable[int] = (200, 201, 204),
    ) -> httpx.Response:
        token = self._get_token()
        headers = {**self._auth_headers(token)}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        url = self._url(path)
        cfg = self._cfg

        last_exc: Optional[Exception] = None
        for attempt in range(0, cfg.retries + 1):
            try:
                resp = self._client.request(method, url, params=params, json=json_body, headers=headers)
                if resp.status_code in expected_status:
                    return resp
                if self._should_retry(method, resp.status_code) and attempt < cfg.retries:
                    LOGGER.debug("Retryable status=%s attempt=%s url=%s", resp.status_code, attempt, url)
                    self._sleep_with_backoff(attempt, cfg.backoff_factor, cfg.max_backoff)
                    continue
                # Ошибки 401/403
                if resp.status_code in (401, 403):
                    raise AuthError(resp.status_code, resp.text, _safe_json(resp))
                raise ApiError(resp.status_code, resp.text, _safe_json(resp))
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteError, httpx.RemoteProtocolError) as e:
                last_exc = e
                if attempt < cfg.retries:
                    LOGGER.debug("Retryable network error attempt=%s url=%s err=%r", attempt, url, e)
                    self._sleep_with_backoff(attempt, cfg.backoff_factor, cfg.max_backoff)
                    continue
                break
        raise RetryError(f"Exceeded retries ({cfg.retries}) for {method} {url}. Last error: {last_exc!r}")

    # -------------------------
    # Calendars
    # -------------------------
    def list_calendars(
        self,
        *,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        resp = self._request(
            "GET",
            "/v1/calendars",
            params={"page_size": page_size, "page_token": page_token, "filter": filter, "order_by": order_by},
        )
        return resp.json()

    def iter_calendars(
        self, *, page_size: int = 200, filter: Optional[str] = None, order_by: Optional[str] = None
    ) -> Iterator[Dict[str, Any]]:
        token = None
        while True:
            page = self.list_calendars(page_size=page_size, page_token=token, filter=filter, order_by=order_by)
            for item in page.get("calendars", []):
                yield item
            token = page.get("next_page_token")
            if not token:
                break

    def get_calendar(self, name: str) -> Dict[str, Any]:
        resp = self._request("GET", f"/v1/{name}")
        return resp.json()

    def create_calendar(self, calendar: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        resp = self._request("POST", "/v1/calendars", json_body={"calendar": dict(calendar)}, idempotency_key=idempotency_key)
        return resp.json()

    def update_calendar(
        self,
        calendar: Mapping[str, Any],
        *,
        update_mask: Optional[Union[str, Sequence[str]]] = None,
        etag: Optional[str] = None,
    ) -> Dict[str, Any]:
        name = _require_name(calendar, "calendar")
        params = {"update_mask": self._mask_to_str(update_mask), "etag": etag}
        resp = self._request("PATCH", f"/v1/{name}", params=_compact(params), json_body={"calendar": dict(calendar)})
        return resp.json()

    def delete_calendar(self, name: str, *, etag: Optional[str] = None) -> Dict[str, Any]:
        resp = self._request("DELETE", f"/v1/{name}", params=_compact({"etag": etag}))
        return resp.json() if resp.content else {}

    # -------------------------
    # Composite Calendars
    # -------------------------
    def list_composites(
        self,
        *,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "GET",
            "/v1/composites",
            params={"page_size": page_size, "page_token": page_token, "filter": filter, "order_by": order_by},
        ).json()

    def get_composite(self, name: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/{name}").json()

    def create_composite(self, composite: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self._request(
            "POST", "/v1/composites", json_body={"composite": dict(composite)}, idempotency_key=idempotency_key
        ).json()

    def update_composite(
        self,
        composite: Mapping[str, Any],
        *,
        update_mask: Optional[Union[str, Sequence[str]]] = None,
        etag: Optional[str] = None,
    ) -> Dict[str, Any]:
        name = _require_name(composite, "composite")
        return self._request(
            "PATCH",
            f"/v1/{name}",
            params=_compact({"update_mask": self._mask_to_str(update_mask), "etag": etag}),
            json_body={"composite": dict(composite)},
        ).json()

    def delete_composite(self, name: str, *, etag: Optional[str] = None) -> Dict[str, Any]:
        resp = self._request("DELETE", f"/v1/{name}", params=_compact({"etag": etag}))
        return resp.json() if resp.content else {}

    # -------------------------
    # SLA Profiles
    # -------------------------
    def list_slas(
        self,
        *,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "GET",
            "/v1/slas",
            params={"page_size": page_size, "page_token": page_token, "filter": filter, "order_by": order_by},
        ).json()

    def get_sla(self, name: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/{name}").json()

    def create_sla(self, profile: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self._request(
            "POST", "/v1/slas", json_body={"profile": dict(profile)}, idempotency_key=idempotency_key
        ).json()

    def update_sla(
        self,
        profile: Mapping[str, Any],
        *,
        update_mask: Optional[Union[str, Sequence[str]]] = None,
        etag: Optional[str] = None,
    ) -> Dict[str, Any]:
        name = _require_name(profile, "profile")
        return self._request(
            "PATCH",
            f"/v1/{name}",
            params=_compact({"update_mask": self._mask_to_str(update_mask), "etag": etag}),
            json_body={"profile": dict(profile)},
        ).json()

    def delete_sla(self, name: str, *, etag: Optional[str] = None) -> Dict[str, Any]:
        resp = self._request("DELETE", f"/v1/{name}", params=_compact({"etag": etag}))
        return resp.json() if resp.content else {}

    # -------------------------
    # Service Bindings
    # -------------------------
    def list_service_bindings(
        self,
        *,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "GET",
            "/v1/serviceBindings",
            params={"page_size": page_size, "page_token": page_token, "filter": filter, "order_by": order_by},
        ).json()

    def get_service_binding(self, name: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/{name}").json()

    def create_service_binding(self, binding: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self._request(
            "POST", "/v1/serviceBindings", json_body={"binding": dict(binding)}, idempotency_key=idempotency_key
        ).json()

    def update_service_binding(
        self,
        binding: Mapping[str, Any],
        *,
        update_mask: Optional[Union[str, Sequence[str]]] = None,
        etag: Optional[str] = None,
    ) -> Dict[str, Any]:
        name = _require_name(binding, "binding")
        return self._request(
            "PATCH",
            f"/v1/{name}",
            params=_compact({"update_mask": self._mask_to_str(update_mask), "etag": etag}),
            json_body={"binding": dict(binding)},
        ).json()

    def delete_service_binding(self, name: str, *, etag: Optional[str] = None) -> Dict[str, Any]:
        resp = self._request("DELETE", f"/v1/{name}", params=_compact({"etag": etag}))
        return resp.json() if resp.content else {}

    # -------------------------
    # Compute
    # -------------------------
    def resolve_availability(
        self,
        *,
        calendar_refs: Sequence[str],
        interval: TimeInterval,
        return_busy: bool = False,
        timezone_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        body = {
            "calendar_refs": list(calendar_refs),
            "interval": interval.to_json(),
            "return_busy": return_busy,
            "timezone": timezone_override,
        }
        return self._request("POST", "/v1/availability:resolve", json_body=_compact(body)).json()

    def compute_sla(self, *, sla_profile_ref: str, interval: TimeInterval) -> Dict[str, Any]:
        body = {"sla_profile_ref": sla_profile_ref, "interval": interval.to_json()}
        return self._request("POST", "/v1/sla:compute", json_body=body).json()

    # -------------------------
    # Watch (SSE)
    # -------------------------
    def watch_calendars(
        self, *, filter: Optional[str] = None, etag: Optional[str] = None, heartbeat: int = 30
    ) -> Iterator[Dict[str, Any]]:
        """
        Подписка на события через SSE (если шлюз поддерживает).
        Возвращает генератор dict-сообщений.
        """
        headers = {
            **self._default_headers,
            **self._auth_headers(self._get_token()),
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
        params = _compact({"filter": filter, "etag": etag, "heartbeat": heartbeat})
        url = self._url("/v1/watch/calendars")  # маршрут шлюза (пример)

        with self._client.stream("GET", url, params=params, headers=headers) as r:
            if r.status_code != 200:
                raise ApiError(r.status_code, r.text, _safe_json(r))
            buf = ""
            for chunk in r.iter_text():
                if not chunk:
                    continue
                buf += chunk
                # SSE события разделяются пустой строкой
                while "\n\n" in buf:
                    raw, buf = buf.split("\n\n", 1)
                    data_lines = [ln[5:] for ln in raw.splitlines() if ln.startswith("data:")]
                    if not data_lines:
                        continue
                    data = "\n".join(data_lines)
                    try:
                        yield json.loads(data)
                    except json.JSONDecodeError:
                        yield {"raw": data}


# ============================
# Асинхронный клиент
# ============================

class ChronoWatchAsyncClient(_BaseClient):
    """
    Асинхронный клиент ChronoWatch.

    Пример:
        cfg = ClientConfig.from_env()
        async with ChronoWatchAsyncClient(cfg) as cli:
            async for c in cli.aiter_calendars(page_size=200):
                ...
    """

    def __init__(self, cfg: ClientConfig):
        super().__init__(cfg)
        self._client = httpx.AsyncClient(
            http2=cfg.http2,
            verify=cfg.verify_ssl,
            headers=self._default_headers,
            timeout=httpx.Timeout(
                cfg.timeout, connect=cfg.connect_timeout, read=cfg.read_timeout, write=cfg.write_timeout
            ),
        )

    async def __aenter__(self) -> "ChronoWatchAsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: D401
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _arequest(
        self,
        method: Literal["GET", "POST", "PATCH", "DELETE"],
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        expected_status: Iterable[int] = (200, 201, 204),
    ) -> httpx.Response:
        token = await self._aget_token()
        headers = {**self._auth_headers(token)}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        url = self._url(path)
        cfg = self._cfg

        last_exc: Optional[Exception] = None
        for attempt in range(0, cfg.retries + 1):
            try:
                resp = await self._client.request(method, url, params=params, json=json_body, headers=headers)
                if resp.status_code in expected_status:
                    return resp
                if self._should_retry(method, resp.status_code) and attempt < cfg.retries:
                    LOGGER.debug("Async retryable status=%s attempt=%s url=%s", resp.status_code, attempt, url)
                    await self._asleep_with_backoff(attempt, cfg.backoff_factor, cfg.max_backoff)
                    continue
                if resp.status_code in (401, 403):
                    raise AuthError(resp.status_code, resp.text, _safe_json(resp))
                raise ApiError(resp.status_code, resp.text, _safe_json(resp))
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteError, httpx.RemoteProtocolError) as e:
                last_exc = e
                if attempt < cfg.retries:
                    LOGGER.debug("Async retryable network error attempt=%s url=%s err=%r", attempt, url, e)
                    await self._asleep_with_backoff(attempt, cfg.backoff_factor, cfg.max_backoff)
                    continue
                break
        raise RetryError(f"Exceeded retries ({cfg.retries}) for {method} {url}. Last error: {last_exc!r}")

    # ---- Calendars ----
    async def list_calendars(
        self,
        *,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        resp = await self._arequest(
            "GET",
            "/v1/calendars",
            params={"page_size": page_size, "page_token": page_token, "filter": filter, "order_by": order_by},
        )
        return resp.json()

    async def aiter_calendars(
        self, *, page_size: int = 200, filter: Optional[str] = None, order_by: Optional[str] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        token = None
        while True:
            page = await self.list_calendars(page_size=page_size, page_token=token, filter=filter, order_by=order_by)
            for item in page.get("calendars", []):
                yield item
            token = page.get("next_page_token")
            if not token:
                break

    async def get_calendar(self, name: str) -> Dict[str, Any]:
        return (await self._arequest("GET", f"/v1/{name}")).json()

    async def create_calendar(self, calendar: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return (
            await self._arequest("POST", "/v1/calendars", json_body={"calendar": dict(calendar)}, idempotency_key=idempotency_key)
        ).json()

    async def update_calendar(
        self,
        calendar: Mapping[str, Any],
        *,
        update_mask: Optional[Union[str, Sequence[str]]] = None,
        etag: Optional[str] = None,
    ) -> Dict[str, Any]:
        name = _require_name(calendar, "calendar")
        return (
            await self._arequest(
                "PATCH",
                f"/v1/{name}",
                params=_compact({"update_mask": self._mask_to_str(update_mask), "etag": etag}),
                json_body={"calendar": dict(calendar)},
            )
        ).json()

    async def delete_calendar(self, name: str, *, etag: Optional[str] = None) -> Dict[str, Any]:
        resp = await self._arequest("DELETE", f"/v1/{name}", params=_compact({"etag": etag}))
        return resp.json() if resp.content else {}

    # ---- Composites ----
    async def list_composites(
        self,
        *,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        return (
            await self._arequest(
                "GET",
                "/v1/composites",
                params={"page_size": page_size, "page_token": page_token, "filter": filter, "order_by": order_by},
            )
        ).json()

    async def get_composite(self, name: str) -> Dict[str, Any]:
        return (await self._arequest("GET", f"/v1/{name}")).json()

    async def create_composite(self, composite: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return (
            await self._arequest(
                "POST", "/v1/composites", json_body={"composite": dict(composite)}, idempotency_key=idempotency_key
            )
        ).json()

    async def update_composite(
        self,
        composite: Mapping[str, Any],
        *,
        update_mask: Optional[Union[str, Sequence[str]]] = None,
        etag: Optional[str] = None,
    ) -> Dict[str, Any]:
        name = _require_name(composite, "composite")
        return (
            await self._arequest(
                "PATCH",
                f"/v1/{name}",
                params=_compact({"update_mask": self._mask_to_str(update_mask), "etag": etag}),
                json_body={"composite": dict(composite)},
            )
        ).json()

    async def delete_composite(self, name: str, *, etag: Optional[str] = None) -> Dict[str, Any]:
        resp = await self._arequest("DELETE", f"/v1/{name}", params=_compact({"etag": etag}))
        return resp.json() if resp.content else {}

    # ---- SLA ----
    async def list_slas(
        self,
        *,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        return (
            await self._arequest(
                "GET", "/v1/slas", params={"page_size": page_size, "page_token": page_token, "filter": filter, "order_by": order_by}
            )
        ).json()

    async def get_sla(self, name: str) -> Dict[str, Any]:
        return (await self._arequest("GET", f"/v1/{name}")).json()

    async def create_sla(self, profile: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return (
            await self._arequest("POST", "/v1/slas", json_body={"profile": dict(profile)}, idempotency_key=idempotency_key)
        ).json()

    async def update_sla(
        self,
        profile: Mapping[str, Any],
        *,
        update_mask: Optional[Union[str, Sequence[str]]] = None,
        etag: Optional[str] = None,
    ) -> Dict[str, Any]:
        name = _require_name(profile, "profile")
        return (
            await self._arequest(
                "PATCH",
                f"/v1/{name}",
                params=_compact({"update_mask": self._mask_to_str(update_mask), "etag": etag}),
                json_body={"profile": dict(profile)},
            )
        ).json()

    async def delete_sla(self, name: str, *, etag: Optional[str] = None) -> Dict[str, Any]:
        resp = await self._arequest("DELETE", f"/v1/{name}", params=_compact({"etag": etag}))
        return resp.json() if resp.content else {}

    # ---- Service Bindings ----
    async def list_service_bindings(
        self,
        *,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        return (
            await self._arequest(
                "GET",
                "/v1/serviceBindings",
                params={"page_size": page_size, "page_token": page_token, "filter": filter, "order_by": order_by},
            )
        ).json()

    async def get_service_binding(self, name: str) -> Dict[str, Any]:
        return (await self._arequest("GET", f"/v1/{name}")).json()

    async def create_service_binding(self, binding: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return (
            await self._arequest(
                "POST", "/v1/serviceBindings", json_body={"binding": dict(binding)}, idempotency_key=idempotency_key
            )
        ).json()

    async def update_service_binding(
        self,
        binding: Mapping[str, Any],
        *,
        update_mask: Optional[Union[str, Sequence[str]]] = None,
        etag: Optional[str] = None,
    ) -> Dict[str, Any]:
        name = _require_name(binding, "binding")
        return (
            await self._arequest(
                "PATCH",
                f"/v1/{name}",
                params=_compact({"update_mask": self._mask_to_str(update_mask), "etag": etag}),
                json_body={"binding": dict(binding)},
            )
        ).json()

    async def delete_service_binding(self, name: str, *, etag: Optional[str] = None) -> Dict[str, Any]:
        resp = await self._arequest("DELETE", f"/v1/{name}", params=_compact({"etag": etag}))
        return resp.json() if resp.content else {}

    # ---- Compute ----
    async def resolve_availability(
        self,
        *,
        calendar_refs: Sequence[str],
        interval: TimeInterval,
        return_busy: bool = False,
        timezone_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        body = {
            "calendar_refs": list(calendar_refs),
            "interval": interval.to_json(),
            "return_busy": return_busy,
            "timezone": timezone_override,
        }
        return (await self._arequest("POST", "/v1/availability:resolve", json_body=_compact(body))).json()

    async def compute_sla(self, *, sla_profile_ref: str, interval: TimeInterval) -> Dict[str, Any]:
        body = {"sla_profile_ref": sla_profile_ref, "interval": interval.to_json()}
        return (await self._arequest("POST", "/v1/sla:compute", json_body=body)).json()

    # ---- Watch (SSE) ----
    async def watch_calendars(
        self, *, filter: Optional[str] = None, etag: Optional[str] = None, heartbeat: int = 30
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Асинхронная подписка SSE.
        """
        headers = {
            **self._default_headers,
            **self._auth_headers(await self._aget_token()),
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
        params = _compact({"filter": filter, "etag": etag, "heartbeat": heartbeat})
        url = self._url("/v1/watch/calendars")  # маршрут шлюза

        async with self._client.stream("GET", url, params=params, headers=headers) as r:
            if r.status_code != 200:
                raise ApiError(r.status_code, await r.aread(), _safe_json(r))
            buf = ""
            async for chunk in r.aiter_text():
                if not chunk:
                    continue
                buf += chunk
                while "\n\n" in buf:
                    raw, buf = buf.split("\n\n", 1)
                    data_lines = [ln[5:] for ln in raw.splitlines() if ln.startswith("data:")]
                    if not data_lines:
                        continue
                    data = "\n".join(data_lines)
                    try:
                        yield json.loads(data)
                    except json.JSONDecodeError:
                        yield {"raw": data}


# ============================
# Вспомогательные функции
# ============================

def _safe_json(resp: httpx.Response) -> Optional[dict]:
    try:
        return resp.json()
    except Exception:
        return None


def _compact(d: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


def _require_name(obj: Mapping[str, Any], field_name: str) -> str:
    """
    В protobuf HTTP-маппингах PATCH использует путь /v1/{X.name=*}.
    Поэтому в теле обязательно наличие obj['name'] вида 'calendars/{id}' / 'composites/{id}' и т.п.
    """
    name = obj.get("name")
    if not name or not isinstance(name, str):
        raise ValidationError(f"Field '{field_name}.name' is required and must be a string")
    return name


# ============================
# Логирование по умолчанию (не навязываем конфиг)
# ============================
if os.getenv("CHRONO_LOG", "").lower() in ("1", "true", "yes"):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s:%(lineno)d - %(message)s",
        stream=sys.stderr,
    )
