"""
Chronowatch Core — Data Fabric Adapter (industrial grade)

Назначение
---------
Единый адаптер для работы с "данными инфраструктуры":
  • события (event stream)
  • точки таймсерий (metrics/tsdb)
  • объекты/блоб-хранилище (object storage)

Особенности
-----------
  • Асинхронный Protocol с строгими типами
  • Экспоненциальный retry с полный/частичный джиттер
  • Мини circuit-breaker (open/half-open/closed)
  • Идемпотентность с TTL (на уровне adapter'a)
  • Таймауты, корректная отмена корутины
  • Опциональный OpenTelemetry-трейсинг (если установлен)
  • Полностью рабочий InMemory backend (без внешних зависимостей)
  • Заглушки S3/Redis/Kafka для безопасной компиляции без SDK
  • Никаких синхронных I/O; только async

Совместимость
-------------
Python 3.10+
Pydantic v2 (при отсутствии — корректно сообщит об ошибке при импорте)

Автор: Chronowatch Platform
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Tuple

# -------- Pydantic (v2) --------
try:
    from pydantic import BaseModel, Field, RootModel, ValidationError
except Exception as e:  # pragma: no cover
    raise RuntimeError("pydantic v2 is required for chronowatch.adapters.datafabric_adapter") from e

# -------- OpenTelemetry (optional) --------
try:  # pragma: no cover
    from opentelemetry import trace
    _OTEL_TRACER = trace.get_tracer("chronowatch.datafabric")
except Exception:  # pragma: no cover
    _OTEL_TRACER = None  # type: ignore


UTC = timezone.utc
__all__ = [
    "DataFabricError",
    "BackendNotConfigured",
    "IdempotencyViolation",
    "CircuitOpenError",
    "TimeoutExceeded",
    "DataEvent",
    "TimeSeriesPoint",
    "DataObjectRef",
    "DataFabric",
    "InMemoryDataFabric",
    "build_data_fabric",
]


# =========================
# Исключения
# =========================

class DataFabricError(Exception):
    """Базовая ошибка адаптера."""


class BackendNotConfigured(DataFabricError):
    """Бэкенд не сконфигурирован/не поддерживается на этой сборке."""


class IdempotencyViolation(DataFabricError):
    """Нарушение идемпотентности (дубликат с отличающимися данными)."""


class CircuitOpenError(DataFabricError):
    """Circuit breaker: цепь открыта — запросы временно отклоняются."""


class TimeoutExceeded(DataFabricError):
    """Истек таймаут операции."""


# =========================
# Модели
# =========================

class DataEvent(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: uuid.UUID
    type: str = Field(min_length=1, max_length=128)
    ts: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    source: str = Field(default="", max_length=128)
    payload: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = Field(default=None, max_length=256)

    class Config:
        extra = "forbid"


class TimeSeriesPoint(BaseModel):
    metric: str = Field(min_length=1, max_length=150)
    ts: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    value: float
    tags: Dict[str, str] = Field(default_factory=dict)

    class Config:
        extra = "forbid"


class DataObjectRef(BaseModel):
    key: str = Field(min_length=1, max_length=512)
    size: int
    etag: str
    content_type: str = "application/octet-stream"
    metadata: Dict[str, str] = Field(default_factory=dict)

    class Config:
        extra = "forbid"


# =========================
# Надёжность: Retry + CircuitBreaker
# =========================

@dataclass
class _BreakerState:
    failures: int = 0
    opened_at: float = 0.0
    state: Literal["closed", "open", "half_open"] = "closed"


class _CircuitBreaker:
    """
    Мини circuit-breaker: открывается после N ошибок, удерживает интервал cooldown,
    потом пол-открытое окно допускает один пробный вызов.
    """

    def __init__(self, max_failures: int = 5, cooldown: float = 5.0) -> None:
        self._max_failures = max_failures
        self._cooldown = cooldown
        self._st = _BreakerState()
        self._lock = asyncio.Lock()

    async def before_call(self) -> None:
        async with self._lock:
            now = time.time()
            if self._st.state == "open":
                if now - self._st.opened_at >= self._cooldown:
                    self._st.state = "half_open"
                else:
                    raise CircuitOpenError("circuit open (cooldown)")
            # closed/half_open — допускаем

    async def on_success(self) -> None:
        async with self._lock:
            self._st = _BreakerState()  # reset -> closed

    async def on_failure(self) -> None:
        async with self._lock:
            if self._st.state == "half_open":
                # пробный вызов неудачен — снова открываем
                self._st.state = "open"
                self._st.opened_at = time.time()
                self._st.failures = self._max_failures
                return
            self._st.failures += 1
            if self._st.failures >= self._max_failures:
                self._st.state = "open"
                self._st.opened_at = time.time()


async def _async_retry(
    func,
    *args,
    attempts: int = 5,
    base_delay: float = 0.05,
    max_delay: float = 1.0,
    timeout: Optional[float] = None,
    breaker: Optional[_CircuitBreaker] = None,
    **kwargs,
):
    """
    Унифицированный retry с экспоненциальным ростом и полным джиттером.
    """
    last_exc: Optional[Exception] = None
    for i in range(1, attempts + 1):
        if breaker is not None:
            await breaker.before_call()
        try:
            coro = func(*args, **kwargs)
            if timeout is not None:
                return await asyncio.wait_for(coro, timeout=timeout)
            return await coro
        except asyncio.TimeoutError as e:
            last_exc = TimeoutExceeded(str(e))
            if breaker is not None:
                await breaker.on_failure()
        except CircuitOpenError as e:
            # проносим дальше, retry не поможет
            raise e
        except Exception as e:
            last_exc = e
            if breaker is not None:
                await breaker.on_failure()
        else:  # pragma: no cover
            last_exc = None

        # если это был последний заход — выбрасываем
        if i >= attempts:
            assert last_exc is not None
            raise last_exc

        # экспоненциальный бэк-офф с полным джиттером
        delay = min(max_delay, base_delay * (2 ** (i - 1)))
        await asyncio.sleep(random.uniform(0, delay))
    # недостижимо
    assert False  # pragma: no cover


def _otel_span(name: str):
    """Контекстный менеджер для OTel span (если доступен)."""
    if _OTEL_TRACER is None:  # pragma: no cover
        from contextlib import nullcontext
        return nullcontext()
    return _OTEL_TRACER.start_as_current_span(name)


# =========================
# Протокол Data Fabric
# =========================

class DataFabric(Protocol):
    # EVENTS
    async def put_event(self, ev: DataEvent) -> None: ...
    async def get_events(
        self,
        tenant_id: uuid.UUID,
        type: Optional[str],
        since: Optional[datetime],
        limit: int = 100,
    ) -> List[DataEvent]: ...

    # TIMESERIES
    async def write_points(self, tenant_id: uuid.UUID, points: List[TimeSeriesPoint]) -> None: ...
    async def query_points(
        self,
        tenant_id: uuid.UUID,
        metric: str,
        start: datetime,
        end: datetime,
        tags: Optional[Dict[str, str]] = None,
        limit: int = 1000,
    ) -> List[TimeSeriesPoint]: ...

    # OBJECTS
    async def put_object(
        self,
        tenant_id: uuid.UUID,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> DataObjectRef: ...

    async def get_object(self, tenant_id: uuid.UUID, key: str) -> Optional[Tuple[bytes, DataObjectRef]]: ...

    # HEALTH
    async def health(self) -> bool: ...


# =========================
# In-Memory реализация
# =========================

class InMemoryDataFabric(DataFabric):
    """
    Производственный уровень для dev/test:
      • потокобезопасные структуры
      • идемпотентность put_object по idempotency_key
      • простая фильтрация по типу/времени/тегам
      • "холодное" хранилище объектов в памяти
    """

    def __init__(
        self,
        *,
        idem_ttl: float = 600.0,
        retry_attempts: int = 3,
        breaker_failures: int = 6,
        breaker_cooldown: float = 2.0,
        op_timeout: float = 2.5,
    ) -> None:
        self._lock = asyncio.Lock()
        self._events: Dict[uuid.UUID, List[DataEvent]] = {}
        self._ts: Dict[uuid.UUID, Dict[str, List[TimeSeriesPoint]]] = {}
        self._objects: Dict[Tuple[uuid.UUID, str], Tuple[bytes, DataObjectRef]] = {}
        self._idem: Dict[Tuple[uuid.UUID, str], Tuple[str, float]] = {}
        self._idem_ttl = idem_ttl

        self._retry_attempts = retry_attempts
        self._breaker = _CircuitBreaker(max_failures=breaker_failures, cooldown=breaker_cooldown)
        self._op_timeout = op_timeout

    # ---------- helpers ----------

    @staticmethod
    def _etag(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _purge_idem(self) -> None:
        now = time.time()
        dead_keys = [k for k, (_, exp) in self._idem.items() if exp <= now]
        for k in dead_keys:
            self._idem.pop(k, None)

    # ---------- EVENTS ----------

    async def put_event(self, ev: DataEvent) -> None:
        async def _op():
            async with self._lock:
                arr = self._events.setdefault(ev.tenant_id, [])
                # идемпотентность событий опционально по key
                if ev.idempotency_key:
                    self._purge_idem()
                    key = (ev.tenant_id, ev.idempotency_key)
                    v = self._idem.get(key)
                    if v:
                        stored_hash, _ = v
                        cur_hash = hashlib.sha256(ev.model_dump_json().encode("utf-8")).hexdigest()
                        if stored_hash != cur_hash:
                            raise IdempotencyViolation("same idempotency_key but different payload")
                        return
                    payload_hash = hashlib.sha256(ev.model_dump_json().encode("utf-8")).hexdigest()
                    self._idem[key] = (payload_hash, time.time() + self._idem_ttl)
                arr.append(ev)

        with _otel_span("df.put_event"):
            return await _async_retry(
                _op,
                attempts=self._retry_attempts,
                breaker=self._breaker,
                timeout=self._op_timeout,
            )

    async def get_events(
        self,
        tenant_id: uuid.UUID,
        type: Optional[str],
        since: Optional[datetime],
        limit: int = 100,
    ) -> List[DataEvent]:
        async def _op():
            async with self._lock:
                items = list(self._events.get(tenant_id, []))
                if type:
                    items = [e for e in items if e.type == type]
                if since:
                    s = since.astimezone(UTC)
                    items = [e for e in items if e.ts.astimezone(UTC) >= s]
                items.sort(key=lambda e: e.ts)
                return items[: max(1, min(5000, limit))]

        with _otel_span("df.get_events"):
            return await _async_retry(
                _op,
                attempts=self._retry_attempts,
                breaker=self._breaker,
                timeout=self._op_timeout,
            )

    # ---------- TIMESERIES ----------

    async def write_points(self, tenant_id: uuid.UUID, points: List[TimeSeriesPoint]) -> None:
        if not points:
            return

        async def _op():
            async with self._lock:
                bucket = self._ts.setdefault(tenant_id, {})
                for p in points:
                    arr = bucket.setdefault(p.metric, [])
                    arr.append(p)

        with _otel_span("df.write_points"):
            return await _async_retry(
                _op,
                attempts=self._retry_attempts,
                breaker=self._breaker,
                timeout=self._op_timeout,
            )

    async def query_points(
        self,
        tenant_id: uuid.UUID,
        metric: str,
        start: datetime,
        end: datetime,
        tags: Optional[Dict[str, str]] = None,
        limit: int = 1000,
    ) -> List[TimeSeriesPoint]:
        assert end > start, "end must be greater than start"
        tags = tags or {}

        async def _op():
            async with self._lock:
                arr = list(self._ts.get(tenant_id, {}).get(metric, []))
                s = start.astimezone(UTC)
                e = end.astimezone(UTC)
                if tags:
                    def match(tsp: TimeSeriesPoint) -> bool:
                        for k, v in tags.items():
                            if tsp.tags.get(k) != v:
                                return False
                        return True
                    arr = [p for p in arr if match(p)]
                arr = [p for p in arr if s <= p.ts.astimezone(UTC) <= e]
                arr.sort(key=lambda p: p.ts)
                return arr[: max(1, min(100_000, limit))]

        with _otel_span("df.query_points"):
            return await _async_retry(
                _op,
                attempts=self._retry_attempts,
                breaker=self._breaker,
                timeout=self._op_timeout,
            )

    # ---------- OBJECTS ----------

    async def put_object(
        self,
        tenant_id: uuid.UUID,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> DataObjectRef:
        metadata = metadata or {}

        async def _op():
            async with self._lock:
                etag = self._etag(data)
                ref = DataObjectRef(
                    key=key,
                    size=len(data),
                    etag=etag,
                    content_type=content_type,
                    metadata=metadata,
                )
                # идемпотентность на объектном слое
                if idempotency_key:
                    self._purge_idem()
                    idem_key = (tenant_id, idempotency_key)
                    v = self._idem.get(idem_key)
                    if v:
                        stored_hash, _ = v
                        if stored_hash != etag:
                            raise IdempotencyViolation("same idempotency_key but different blob content")
                        # возвращаем текущую ссылку из хранилища (если есть)
                        prev = self._objects.get((tenant_id, key))
                        if prev:
                            return prev[1]
                    self._idem[idem_key] = (etag, time.time() + self._idem_ttl)

                self._objects[(tenant_id, key)] = (data, ref)
                return ref

        with _otel_span("df.put_object"):
            return await _async_retry(
                _op,
                attempts=self._retry_attempts,
                breaker=self._breaker,
                timeout=self._op_timeout,
            )

    async def get_object(self, tenant_id: uuid.UUID, key: str) -> Optional[Tuple[bytes, DataObjectRef]]:
        async def _op():
            async with self._lock:
                return self._objects.get((tenant_id, key))

        with _otel_span("df.get_object"):
            return await _async_retry(
                _op,
                attempts=self._retry_attempts,
                breaker=self._breaker,
                timeout=self._op_timeout,
            )

    # ---------- HEALTH ----------

    async def health(self) -> bool:
        # In-memory всегда готов, но проводим микрозадержку для единообразия
        async def _op():
            await asyncio.sleep(0)
            return True

        with _otel_span("df.health"):
            return await _async_retry(
                _op,
                attempts=1,
                breaker=None,
                timeout=0.25,
            )


# =========================
# Заглушки реальных бэкендов (без SDK)
# =========================

class _S3DataFabric(DataFabric):
    def __init__(self) -> None:
        raise BackendNotConfigured("S3 backend not bundled in this build")

    async def put_event(self, ev: DataEvent) -> None: ...
    async def get_events(self, tenant_id: uuid.UUID, type: Optional[str], since: Optional[datetime], limit: int = 100) -> List[DataEvent]: ...
    async def write_points(self, tenant_id: uuid.UUID, points: List[TimeSeriesPoint]) -> None: ...
    async def query_points(self, tenant_id: uuid.UUID, metric: str, start: datetime, end: datetime, tags: Optional[Dict[str, str]] = None, limit: int = 1000) -> List[TimeSeriesPoint]: ...
    async def put_object(self, tenant_id: uuid.UUID, key: str, data: bytes, content_type: str = "application/octet-stream", metadata: Optional[Dict[str, str]] = None, idempotency_key: Optional[str] = None) -> DataObjectRef: ...
    async def get_object(self, tenant_id: uuid.UUID, key: str) -> Optional[Tuple[bytes, DataObjectRef]]: ...
    async def health(self) -> bool: ...


class _RedisKafkaDataFabric(DataFabric):
    def __init__(self) -> None:
        raise BackendNotConfigured("Redis/Kafka backend not bundled in this build")

    async def put_event(self, ev: DataEvent) -> None: ...
    async def get_events(self, tenant_id: uuid.UUID, type: Optional[str], since: Optional[datetime], limit: int = 100) -> List[DataEvent]: ...
    async def write_points(self, tenant_id: uuid.UUID, points: List[TimeSeriesPoint]) -> None: ...
    async def query_points(self, tenant_id: uuid.UUID, metric: str, start: datetime, end: datetime, tags: Optional[Dict[str, str]] = None, limit: int = 1000) -> List[TimeSeriesPoint]: ...
    async def put_object(self, tenant_id: uuid.UUID, key: str, data: bytes, content_type: str = "application/octet-stream", metadata: Optional[Dict[str, str]] = None, idempotency_key: Optional[str] = None) -> DataObjectRef: ...
    async def get_object(self, tenant_id: uuid.UUID, key: str) -> Optional[Tuple[bytes, DataObjectRef]]: ...
    async def health(self) -> bool: ...


# =========================
# Фабрика
# =========================

def build_data_fabric() -> DataFabric:
    """
    Выбор бэкенда по переменным окружения:

      DATAFABRIC_BACKEND = memory | s3 | redis_kafka
      DATAFABRIC_IDEM_TTL = <секунды> (по умолчанию 600)

    Для prod подключите ваши реализации вместо заглушек.
    """
    backend = (os.getenv("DATAFABRIC_BACKEND") or "memory").lower()
    idem_ttl = float(os.getenv("DATAFABRIC_IDEM_TTL", "600"))
    if backend == "memory":
        return InMemoryDataFabric(idem_ttl=idem_ttl)
    if backend == "s3":
        return _S3DataFabric()  # raises NotConfigured
    if backend in ("redis_kafka", "redis+kafka"):
        return _RedisKafkaDataFabric()  # raises NotConfigured
    raise BackendNotConfigured(f"Unknown backend: {backend}")


# =========================
# Примитивный self-test
# =========================

async def _selftest():  # pragma: no cover
    df = InMemoryDataFabric()
    tenant = uuid.uuid4()

    # event
    ev = DataEvent(tenant_id=tenant, type="heartbeat", payload={"status": "ok"}, idempotency_key="hb:svcA:1")
    await df.put_event(ev)
    await df.put_event(ev)  # idem
    got = await df.get_events(tenant, "heartbeat", since=datetime.now(tz=UTC) - timedelta(days=1))
    assert len(got) == 1

    # ts
    pts = [
        TimeSeriesPoint(metric="cpu", value=0.5, tags={"host": "a"}),
        TimeSeriesPoint(metric="cpu", value=0.6, tags={"host": "a"}),
    ]
    await df.write_points(tenant, pts)
    res = await df.query_points(tenant, "cpu", datetime.now(tz=UTC) - timedelta(minutes=1), datetime.now(tz=UTC) + timedelta(minutes=1), tags={"host": "a"})
    assert len(res) == 2

    # object
    data = b"hello"
    ref = await df.put_object(tenant, "greet.txt", data, idempotency_key="obj:greet")
    blob = await df.get_object(tenant, "greet.txt")
    assert blob and blob[0] == data and blob[1].etag == hashlib.sha256(data).hexdigest()

if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_selftest())
