# engine/adapters/datafabric_adapter.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

# Опциональные зависимости
try:
    import httpx  # type: ignore
    _HAS_HTTPX = True
except Exception:
    _HAS_HTTPX = False

try:
    from pydantic import BaseModel, ValidationError as PydanticValidationError  # type: ignore
    _HAS_PYDANTIC = True
except Exception:
    _HAS_PYDANTIC = False

# Интеграция с телеметрией (необязательна, модуль может отсутствовать)
with contextlib.suppress(Exception):
    from engine.telemetry.profiling import profile_block  # type: ignore
    _HAS_PROFILING = True
if not locals().get("_HAS_PROFILING"):
    def profile_block(name: Optional[str] = None, config: Optional[Any] = None):
        @contextlib.contextmanager
        def _noop():
            yield
        return _noop()

LOG = logging.getLogger(__name__)
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    LOG.addHandler(_h)
    LOG.setLevel(logging.INFO)

# ==============================
# Исключения адаптера
# ==============================

class DataFabricError(RuntimeError):
    pass

class DataFabricAuthError(DataFabricError):
    pass

class DataFabricRateLimitError(DataFabricError):
    pass

class DataFabricTemporaryError(DataFabricError):
    pass

class DataFabricNotFoundError(DataFabricError):
    pass

class DataFabricCircuitOpenError(DataFabricError):
    pass

class DataFabricValidationError(DataFabricError):
    pass


# ==============================
# Конфигурация и утилиты
# ==============================

@dataclass(frozen=True)
class DataFabricConfig:
    base_url: str
    api_key: str
    tenant: Optional[str] = None
    project: Optional[str] = None

    # Таймауты/повторы
    timeout_seconds: float = 20.0
    connect_timeout_seconds: float = 5.0
    retries: int = 3
    backoff_base: float = 0.25  # секунды
    backoff_cap: float = 3.0
    backoff_jitter: float = 0.2

    # Circuit breaker
    cb_failure_threshold: int = 5
    cb_reset_timeout_seconds: float = 30.0
    cb_half_open_max_calls: int = 2

    # Безопасность/сеть
    verify_ssl: bool = True
    user_agent: str = "engine-core/datafabric-adapter/1.0"
    extra_headers: Mapping[str, str] = field(default_factory=dict)

    # Поведение
    redact_secrets_in_logs: bool = True
    default_page_size: int = 1000
    max_page_size: int = 10000
    idempotency_prefix: str = "eng-"

    @staticmethod
    def from_env(prefix: str = "DF") -> "DataFabricConfig":
        def _get(k: str, default: Optional[str] = None) -> str:
            v = os.getenv(f"{prefix}_{k}")
            if v is None:
                if default is None:
                    raise KeyError(f"Missing env: {prefix}_{k}")
                return default
            return v

        def _get_float(k: str, default: float) -> float:
            v = os.getenv(f"{prefix}_{k}")
            return float(v) if v is not None else default

        def _get_int(k: str, default: int) -> int:
            v = os.getenv(f"{prefix}_{k}")
            return int(v) if v is not None else default

        return DataFabricConfig(
            base_url=_get("BASE_URL"),
            api_key=_get("API_KEY"),
            tenant=os.getenv(f"{prefix}_TENANT"),
            project=os.getenv(f"{prefix}_PROJECT"),
            timeout_seconds=_get_float("TIMEOUT", 20.0),
            connect_timeout_seconds=_get_float("CONNECT_TIMEOUT", 5.0),
            retries=_get_int("RETRIES", 3),
            backoff_base=_get_float("BACKOFF_BASE", 0.25),
            backoff_cap=_get_float("BACKOFF_CAP", 3.0),
            backoff_jitter=_get_float("BACKOFF_JITTER", 0.2),
            cb_failure_threshold=_get_int("CB_FAILURES", 5),
            cb_reset_timeout_seconds=_get_float("CB_RESET", 30.0),
            cb_half_open_max_calls=_get_int("CB_HALF_OPEN", 2),
            verify_ssl=(os.getenv(f"{prefix}_VERIFY_SSL", "1") not in ("0", "false", "False")),
            user_agent=os.getenv(f"{prefix}_UA", "engine-core/datafabric-adapter/1.0"),
        )

def _redact(s: str) -> str:
    if not s:
        return s
    if len(s) <= 6:
        return "***"
    return s[:3] + "***" + s[-3:]

def _iso_now() -> str:
    return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"

def _rand_idempotency_key(prefix: str) -> str:
    rand = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    return f"{prefix}{rand}"

def _stable_hash(payload: Any) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()[:32]


# ==============================
# Circuit Breaker
# ==============================

class CircuitBreakerState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int,
        reset_timeout_seconds: float,
        half_open_max_calls: int,
        time_func: Callable[[], float] = time.monotonic,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout_seconds = reset_timeout_seconds
        self.half_open_max_calls = half_open_max_calls
        self._time = time_func

        self._state = CircuitBreakerState.CLOSED
        self._fail_count = 0
        self._opened_at = 0.0
        self._half_open_calls = 0

    def on_success(self) -> None:
        if self._state != CircuitBreakerState.CLOSED:
            self._state = CircuitBreakerState.CLOSED
            self._fail_count = 0
            self._half_open_calls = 0

    def on_failure(self) -> None:
        if self._state == CircuitBreakerState.CLOSED:
            self._fail_count += 1
            if self._fail_count >= self.failure_threshold:
                self._state = CircuitBreakerState.OPEN
                self._opened_at = self._time()
        elif self._state == CircuitBreakerState.HALF_OPEN:
            # Любая ошибка в half-open — снова OPEN
            self._state = CircuitBreakerState.OPEN
            self._opened_at = self._time()
            self._half_open_calls = 0

    def allow(self) -> bool:
        now = self._time()
        if self._state == CircuitBreakerState.CLOSED:
            return True
        if self._state == CircuitBreakerState.OPEN:
            if now - self._opened_at >= self.reset_timeout_seconds:
                self._state = CircuitBreakerState.HALF_OPEN
                self._half_open_calls = 0
                return True
            return False
        if self._state == CircuitBreakerState.HALF_OPEN:
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False
        return True

    @property
    def state(self) -> str:
        return self._state


# ==============================
# Базовый интерфейс
# ==============================

class BaseDataFabricAdapter(abc.ABC):
    @abc.abstractmethod
    def health_check(self) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    async def health_check_async(self) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    def query(self, *, sql: Optional[str] = None, dsl: Optional[Mapping[str, Any]] = None,
              params: Optional[Mapping[str, Any]] = None, page: int = 1, page_size: int = 1000) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    async def query_async(self, *, sql: Optional[str] = None, dsl: Optional[Mapping[str, Any]] = None,
                          params: Optional[Mapping[str, Any]] = None, page: int = 1, page_size: int = 1000) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    def write_rows(self, dataset: str, rows: Sequence[Mapping[str, Any]], mode: str = "upsert",
                   idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    async def write_rows_async(self, dataset: str, rows: Sequence[Mapping[str, Any]], mode: str = "upsert",
                               idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    def read_rows(self, dataset: str, *, page: int = 1, page_size: int = 1000,
                  filters: Optional[Mapping[str, Any]] = None, fields: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        ...

    @abc.abstractmethod
    async def read_rows_async(self, dataset: str, *, page: int = 1, page_size: int = 1000,
                              filters: Optional[Mapping[str, Any]] = None, fields: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        ...


# ==============================
# Адаптер
# ==============================

class DataFabricAdapter(BaseDataDataFabricAdapter:=BaseDataFabricAdapter):  # type: ignore
    """
    Промышленный адаптер к абстрактной платформе DataFabric (HTTP API).
    Поддерживает sync/async, автоповторы, circuit breaker, идемпотентность, health-check.
    """

    def __init__(self, config: DataFabricConfig) -> None:
        self.cfg = config
        self._cb = CircuitBreaker(
            failure_threshold=config.cb_failure_threshold,
            reset_timeout_seconds=config.cb_reset_timeout_seconds,
            half_open_max_calls=config.cb_half_open_max_calls,
        )
        self._client: Optional[Any] = None  # httpx.Client / urllib
        self._aclient: Optional[Any] = None # httpx.AsyncClient

        # Заголовки
        self._headers = {
            "Authorization": f"Bearer {self.cfg.api_key}",
            "User-Agent": self.cfg.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        for k, v in self.cfg.extra_headers.items():
            self._headers[k] = v

        # Базовый путь
        self._base = self.cfg.base_url.rstrip("/")

        # Контекстные атрибуты
        self._closed = False

        LOG.info(
            "DataFabricAdapter init base=%s tenant=%s project=%s verify_ssl=%s",
            self._base,
            self.cfg.tenant,
            self.cfg.project,
            self.cfg.verify_ssl,
        )

    # ------- Контекст-менеджеры -------

    def __enter__(self) -> "DataFabricAdapter":
        self._ensure_sync_client()
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        self.close()

    async def __aenter__(self) -> "DataFabricAdapter":
        await self._ensure_async_client()
        return self

    async def __aexit__(self, exc_type: Optional[Type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        await self.aclose()

    def close(self) -> None:
        self._closed = True
        if _HAS_HTTPX and isinstance(self._client, httpx.Client):
            with contextlib.suppress(Exception):
                self._client.close()
        self._client = None

    async def aclose(self) -> None:
        self._closed = True
        if _HAS_HTTPX and isinstance(self._aclient, httpx.AsyncClient):
            with contextlib.suppress(Exception):
                await self._aclient.aclose()
        self._aclient = None

    # ------- Публичные методы -------

    def health_check(self) -> Dict[str, Any]:
        with profile_block("df.health_check"):
            return self._do_request(
                method="GET",
                path="/health",
                timeout=self.cfg.connect_timeout_seconds,
            )

    async def health_check_async(self) -> Dict[str, Any]:
        async with profile_block("df.health_check_async"):  # type: ignore
            return await self._do_request_async(
                method="GET",
                path="/health",
                timeout=self.cfg.connect_timeout_seconds,
            )

    def query(
        self, *,
        sql: Optional[str] = None,
        dsl: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Any]] = None,
        page: int = 1,
        page_size: int = 1000,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"page": page, "page_size": self._clamp_page_size(page_size)}
        if sql:
            payload["sql"] = sql
            if params:
                payload["params"] = params
        elif dsl:
            payload["dsl"] = dsl
        else:
            raise ValueError("Either sql or dsl must be provided")
        with profile_block("df.query"):
            return self._do_request("POST", "/query", json=payload)

    async def query_async(
        self, *,
        sql: Optional[str] = None,
        dsl: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Any]] = None,
        page: int = 1,
        page_size: int = 1000,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"page": page, "page_size": self._clamp_page_size(page_size)}
        if sql:
            payload["sql"] = sql
            if params:
                payload["params"] = params
        elif dsl:
            payload["dsl"] = dsl
        else:
            raise ValueError("Either sql or dsl must be provided")
        async with profile_block("df.query_async"):  # type: ignore
            return await self._do_request_async("POST", "/query", json=payload)

    def write_rows(
        self,
        dataset: str,
        rows: Sequence[Mapping[str, Any]],
        mode: str = "upsert",
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not rows:
            return {"status": "no-op", "written": 0}
        key = idempotency_key or self._make_idempotency_key(dataset, rows, mode)
        payload = {"dataset": dataset, "mode": mode, "rows": list(rows)}
        with profile_block("df.write_rows"):
            return self._do_request("POST", "/datasets/write", json=payload, idempotency_key=key)

    async def write_rows_async(
        self,
        dataset: str,
        rows: Sequence[Mapping[str, Any]],
        mode: str = "upsert",
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not rows:
            return {"status": "no-op", "written": 0}
        key = idempotency_key or self._make_idempotency_key(dataset, rows, mode)
        payload = {"dataset": dataset, "mode": mode, "rows": list(rows)}
        async with profile_block("df.write_rows_async"):  # type: ignore
            return await self._do_request_async("POST", "/datasets/write", json=payload, idempotency_key=key)

    def read_rows(
        self,
        dataset: str,
        *,
        page: int = 1,
        page_size: int = 1000,
        filters: Optional[Mapping[str, Any]] = None,
        fields: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "dataset": dataset,
            "page": page,
            "page_size": self._clamp_page_size(page_size),
        }
        if filters:
            payload["filters"] = filters
        if fields:
            payload["fields"] = list(fields)
        with profile_block("df.read_rows"):
            return self._do_request("POST", "/datasets/read", json=payload)

    async def read_rows_async(
        self,
        dataset: str,
        *,
        page: int = 1,
        page_size: int = 1000,
        filters: Optional[Mapping[str, Any]] = None,
        fields: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "dataset": dataset,
            "page": page,
            "page_size": self._clamp_page_size(page_size),
        }
        if filters:
            payload["filters"] = filters
        if fields:
            payload["fields"] = list(fields)
        async with profile_block("df.read_rows_async"):  # type: ignore
            return await self._do_request_async("POST", "/datasets/read", json=payload)

    # ------- Вспомогательное -------

    def _make_idempotency_key(self, dataset: str, rows: Sequence[Mapping[str, Any]], mode: str) -> str:
        h = _stable_hash({"ds": dataset, "mode": mode, "rows": rows})
        return f"{self.cfg.idempotency_prefix}{h}"

    def _clamp_page_size(self, ps: int) -> int:
        if ps <= 0:
            return self.cfg.default_page_size
        return min(ps, self.cfg.max_page_size)

    # ------- Транспорт -------

    def _ensure_sync_client(self) -> None:
        if self._client is not None:
            return
        if _HAS_HTTPX:
            self._client = httpx.Client(
                base_url=self._base,
                timeout=self.cfg.timeout_seconds,
                verify=self.cfg.verify_ssl,
                headers=self._headers,
            )
        else:
            # Отложенное использование urllib (простая реализация ниже)
            self._client = _UrllibTransport(base_url=self._base, verify=self.cfg.verify_ssl, headers=self._headers)

    async def _ensure_async_client(self) -> None:
        if self._aclient is not None:
            return
        if not _HAS_HTTPX:
            raise RuntimeError("Async mode requires httpx to be installed")
        self._aclient = httpx.AsyncClient(
            base_url=self._base,
            timeout=self.cfg.timeout_seconds,
            verify=self.cfg.verify_ssl,
            headers=self._headers,
        )

    # ------- HTTP запросы с ретраями и Circuit Breaker -------

    def _do_request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_sync_client()
        if not self._cb.allow():
            raise DataFabricCircuitOpenError("Circuit breaker is open")
        headers = dict(self._headers)
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        attempt = 0
        while True:
            attempt += 1
            try:
                start = time.perf_counter()
                resp = self._client.request(  # type: ignore[attr-defined]
                    method,
                    path,
                    json=json,
                    params=params,
                    headers=headers,
                    timeout=timeout or self.cfg.timeout_seconds,
                )
                dur = time.perf_counter() - start
                self._log_req(method, path, json, params, resp.status_code, dur)
                data = self._handle_response(resp.status_code, resp.text)
                self._cb.on_success()
                return data
            except DataFabricTemporaryError as e:
                self._cb.on_failure()
                if attempt > self.cfg.retries:
                    raise
                self._sleep_backoff(attempt)
            except (DataFabricRateLimitError,) as e:
                self._cb.on_failure()
                if attempt > self.cfg.retries:
                    raise
                self._sleep_backoff(attempt, rate_limited=True)
            except (DataFabricAuthError, DataFabricNotFoundError, DataFabricValidationError):
                self._cb.on_failure()
                raise
            except Exception as e:
                self._cb.on_failure()
                if attempt > self.cfg.retries:
                    raise DataFabricTemporaryError(str(e)) from e
                self._sleep_backoff(attempt)

    async def _do_request_async(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        await self._ensure_async_client()
        if not self._cb.allow():
            raise DataFabricCircuitOpenError("Circuit breaker is open")
        headers = dict(self._headers)
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        attempt = 0
        while True:
            attempt += 1
            try:
                start = time.perf_counter()
                assert _HAS_HTTPX
                resp = await self._aclient.request(  # type: ignore[attr-defined]
                    method,
                    path,
                    json=json,
                    params=params,
                    headers=headers,
                    timeout=timeout or self.cfg.timeout_seconds,
                )
                dur = time.perf_counter() - start
                self._log_req(method, path, json, params, resp.status_code, dur)
                data = self._handle_response(resp.status_code, resp.text)
                self._cb.on_success()
                return data
            except DataFabricTemporaryError:
                self._cb.on_failure()
                if attempt > self.cfg.retries:
                    raise
                await self._asleep_backoff(attempt)
            except (DataFabricRateLimitError,):
                self._cb.on_failure()
                if attempt > self.cfg.retries:
                    raise
                await self._asleep_backoff(attempt, rate_limited=True)
            except (DataFabricAuthError, DataFabricNotFoundError, DataFabricValidationError):
                self._cb.on_failure()
                raise
            except Exception as e:
                self._cb.on_failure()
                if attempt > self.cfg.retries:
                    raise DataFabricTemporaryError(str(e)) from e
                await self._asleep_backoff(attempt)

    # ------- Обработка ответа -------

    def _handle_response(self, status_code: int, text: str) -> Dict[str, Any]:
        try:
            data = json.loads(text) if text else {}
        except Exception:
            data = {"raw": text}

        if 200 <= status_code < 300:
            # Optional: валидация схемы при наличии pydantic
            if _HAS_PYDANTIC and isinstance(data, dict) and "data" in data:
                # Пример простейшей валидации результата
                class _ResultModel(BaseModel):  # type: ignore
                    status: Optional[str] = None
                    data: Any
                try:
                    _ = _ResultModel(**data)
                except PydanticValidationError as e:
                    raise DataFabricValidationError(str(e))
            return data

        # Классификация ошибок
        if status_code in (401, 403):
            raise DataFabricAuthError(data.get("error") or "Unauthorized")
        if status_code == 404:
            raise DataFabricNotFoundError(data.get("error") or "Not Found")
        if status_code == 409:
            raise DataFabricValidationError(data.get("error") or "Conflict")
        if status_code == 429:
            raise DataFabricRateLimitError(data.get("error") or "Rate limited")
        if 500 <= status_code < 600:
            raise DataFabricTemporaryError(data.get("error") or f"Server error {status_code}")

        raise DataFabricError(data.get("error") or f"HTTP {status_code}")

    # ------- Backoff -------

    def _sleep_backoff(self, attempt: int, *, rate_limited: bool = False) -> None:
        base = self.cfg.backoff_base * (2 ** (attempt - 1))
        if rate_limited:
            base *= 1.5
        base = min(base, self.cfg.backoff_cap)
        jitter = random.uniform(-self.cfg.backoff_jitter, self.cfg.backoff_jitter)
        time.sleep(max(0.0, base + jitter))

    async def _asleep_backoff(self, attempt: int, *, rate_limited: bool = False) -> None:
        base = self.cfg.backoff_base * (2 ** (attempt - 1))
        if rate_limited:
            base *= 1.5
        base = min(base, self.cfg.backoff_cap)
        jitter = random.uniform(-self.cfg.backoff_jitter, self.cfg.backoff_jitter)
        await asyncio.sleep(max(0.0, base + jitter))

    # ------- Логирование -------

    def _log_req(
        self,
        method: str,
        path: str,
        json_payload: Optional[Mapping[str, Any]],
        params: Optional[Mapping[str, Any]],
        status: int,
        dur: float,
    ) -> None:
        if self.cfg.redact_secrets_in_logs:
            hdr = {**self._headers}
            if "Authorization" in hdr:
                hdr["Authorization"] = f"Bearer {_redact(self.cfg.api_key)}"
        else:
            hdr = self._headers
        LOG.info(
            "DF %s %s status=%s dur=%.3fs params=%s payload_size=%s headers=%s",
            method, path, status, dur,
            list((params or {}).keys()) if params else None,
            len(json.dumps(json_payload, sort_keys=True).encode("utf-8")) if json_payload else 0,
            hdr,
        )


# ==============================
# Простой транспорт на urllib (fallback, sync)
# ==============================

class _UrllibTransport:
    def __init__(self, *, base_url: str, verify: bool, headers: Mapping[str, str]) -> None:
        import urllib.request
        self._base = base_url.rstrip("/")
        self._verify = verify
        self._headers = dict(headers)
        self._u = urllib.request

        if not verify:
            import ssl
            self._sslctx = ssl.create_default_context()
            self._sslctx.check_hostname = False
            self._sslctx.verify_mode = ssl.CERT_NONE
        else:
            self._sslctx = None

    def request(
        self,
        method: str,
        path: str,
        json: Optional[Mapping[str, Any]] = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: float = 20.0,
    ):
        import urllib.parse
        url = self._base + path
        if params:
            q = urllib.parse.urlencode(params, doseq=True)
            url = f"{url}?{q}"

        body_bytes = None
        req_headers = dict(self._headers)
        if headers:
            req_headers.update(headers)
        if json is not None:
            body_bytes = json_dumps_bytes(json)
            req_headers["Content-Type"] = "application/json"

        req = self._u.Request(url, data=body_bytes, headers=req_headers, method=method)
        ctx = self._sslctx
        with contextlib.closing(self._u.urlopen(req, timeout=timeout, context=ctx)) as resp:  # type: ignore[arg-type]
            code = resp.getcode()
            text = resp.read().decode("utf-8", errors="replace")
            return _SimpleResponse(code, text)


class _SimpleResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


def json_dumps_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


# ==============================
# Пример опциональной модели ответа (Pydantic)
# ==============================

if _HAS_PYDANTIC:
    class QueryResult(BaseModel):  # type: ignore
        status: Optional[str]
        data: Any
        page: Optional[int] = None
        page_size: Optional[int] = None
        total: Optional[int] = None

    class WriteResult(BaseModel):  # type: ignore
        status: Optional[str]
        written: int
        idempotency_key: Optional[str] = None

else:
    QueryResult = Dict[str, Any]  # type: ignore
    WriteResult = Dict[str, Any]  # type: ignore
