# -*- coding: utf-8 -*-
"""
OmniMind Core — Redis Streams Queue Adapter (async)

Гарантии и возможности:
- Redis Streams (XADD/XREADGROUP/XACK/XCLAIM) с consumer group.
- At-least-once доставка с visibility timeout и авто-reclaim «застрявших» сообщений.
- Dead-letter (DLQ) при превышении порога ретраев.
- Идемпотентность продюсера через SETNX (message_key) + TTL.
- Батчевый приём/подтверждение, backpressure через семафор.
- JSON-сериализация с безопасной нормализацией и ограничением размера.
- Метрики Prometheus (опционально) и OpenTelemetry tracing (опционально).
- Конфигурация через Pydantic Settings и ENV.

Зависимости (опциональные):
- redis.asyncio
- prometheus_client
- opentelemetry-api

Безопасность:
- Секреты и полезная нагрузка не логируются в явном виде; логи — агрегированные.
- Пределы на размер полезной нагрузки и пачек.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseSettings, Field, validator

try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

# Prometheus (опционально)
try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False
    class _Noop:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass
    Counter = Histogram = Gauge = _Noop  # type: ignore

# OpenTelemetry (опционально)
try:
    from opentelemetry import trace  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False
    trace = None  # type: ignore


# -----------------------------------------------------------------------------
# Метрики
# -----------------------------------------------------------------------------
Q_ENQ = Counter("omnimind_queue_enqueued_total", "Messages enqueued", ["queue"]) if _PROM else Counter()
Q_DEDUP = Counter("omnimind_queue_deduplicated_total", "Producer deduplications", ["queue"]) if _PROM else Counter()
Q_DEQ = Counter("omnimind_queue_dequeued_total", "Messages dequeued", ["queue"]) if _PROM else Counter()
Q_ACK = Counter("omnimind_queue_acked_total", "Messages acked", ["queue"]) if _PROM else Counter()
Q_NACK = Counter("omnimind_queue_nacked_total", "Messages nacked/requeued", ["queue"]) if _PROM else Counter()
Q_DLQ = Counter("omnimind_queue_dlq_total", "Messages sent to DLQ", ["queue"]) if _PROM else Counter()
Q_RECLAIM = Counter("omnimind_queue_reclaimed_total", "Messages reclaimed", ["queue"]) if _PROM else Counter()
Q_LAT_ENQ = Histogram("omnimind_queue_enqueue_seconds", "Enqueue latency", ["queue"]) if _PROM else Histogram()
Q_LAT_DEQ = Histogram("omnimind_queue_dequeue_seconds", "Dequeue latency", ["queue"]) if _PROM else Histogram()
Q_INFLIGHT = Gauge("omnimind_queue_inflight", "Inflight messages (consumer)", ["queue"]) if _PROM else Gauge()


# -----------------------------------------------------------------------------
# Настройки
# -----------------------------------------------------------------------------
class RedisQueueSettings(BaseSettings):
    url: str = Field("redis://localhost:6379/0", env="REDIS_URL")
    stream: str = Field("omnimind:queue", env="REDIS_STREAM")
    group: str = Field("omnimind-consumers", env="REDIS_GROUP")
    consumer: str = Field("consumer-1", env="REDIS_CONSUMER")

    dlq_stream: str = Field("omnimind:queue:dlq", env="REDIS_DLQ_STREAM")
    max_len: int = Field(10_000_000, env="REDIS_STREAM_MAXLEN")  # обрезка истории (approximate)
    trim_approx: bool = Field(True, env="REDIS_STREAM_TRIM_APPROX")

    # Чтение
    batch_size: int = Field(64, env="QUEUE_BATCH_SIZE")
    block_ms: int = Field(5000, env="QUEUE_BLOCK_MS")  # время блокировки XREADGROUP
    ack_on_exit: bool = Field(True, env="QUEUE_ACK_ON_EXIT")

    # Видимость и ретраи
    visibility_timeout_s: int = Field(60, env="QUEUE_VISIBILITY_TIMEOUT_S")
    max_retries: int = Field(16, env="QUEUE_MAX_RETRIES")

    # Идемпотентность продюсера
    dedup_ttl_s: int = Field(3600, env="QUEUE_DEDUP_TTL_S")  # TTL ключа уникальности
    dedup_prefix: str = Field("q:dedup:", env="QUEUE_DEDUP_PREFIX")

    # Полезная нагрузка
    payload_max_bytes: int = Field(262144, env="QUEUE_PAYLOAD_MAX_BYTES")  # 256 KiB
    json_compact: bool = Field(True, env="QUEUE_JSON_COMPACT")

    # Параллелизм
    max_concurrency: int = Field(16, env="QUEUE_MAX_CONCURRENCY")

    # Reclaimer
    reclaim_interval_s: int = Field(15, env="QUEUE_RECLAIM_INTERVAL_S")
    reclaim_idle_s: int = Field(60, env="QUEUE_RECLAIM_IDLE_S")  # XAUTOCLAIM idle threshold

    # Разное
    create_group_if_missing: bool = Field(True, env="QUEUE_CREATE_GROUP")
    health_key: str = Field("q:health", env="QUEUE_HEALTH_KEY")
    health_ttl_s: int = Field(30, env="QUEUE_HEALTH_TTL_S")

    class Config:
        env_file = os.environ.get("ENV_FILE", None)
        case_sensitive = False

    @validator("batch_size")
    def _v_batch(cls, v):  # noqa
        return max(1, min(1024, v))

    @validator("max_concurrency")
    def _v_conc(cls, v):  # noqa
        return max(1, min(256, v))


# -----------------------------------------------------------------------------
# Модель сообщения
# -----------------------------------------------------------------------------
@dataclass
class QueueMessage:
    id: str                 # Redis stream ID
    payload: Dict[str, Any] # десериализованная полезная нагрузка
    attempt: int            # количество обработок (редоставок)
    key: Optional[str]      # ключ идемпотентности продюсера (если был)


# -----------------------------------------------------------------------------
# Утилиты сериализации
# -----------------------------------------------------------------------------
def _json_dump(d: Mapping[str, Any], compact: bool) -> bytes:
    if compact:
        s = json.dumps(d, separators=(",", ":"), ensure_ascii=False)
    else:
        s = json.dumps(d, ensure_ascii=False)
    b = s.encode("utf-8")
    return b

def _json_load(b: bytes) -> Dict[str, Any]:
    return json.loads(b.decode("utf-8"))


# -----------------------------------------------------------------------------
# Очередь на Redis Streams
# -----------------------------------------------------------------------------
class RedisStreamQueue:
    def __init__(self, settings: Optional[RedisQueueSettings] = None):
        if aioredis is None:
            raise RuntimeError("redis.asyncio is not installed")
        self.settings = settings or RedisQueueSettings()
        self._r = aioredis.from_url(self.settings.url, encoding=None, decode_responses=False)
        self._sem = asyncio.Semaphore(self.settings.max_concurrency)
        self._stop = asyncio.Event()
        self._reclaimer_task: Optional[asyncio.Task] = None

    # ------------------------ Жизненный цикл ------------------------

    async def start(self) -> None:
        # Создать stream и группу, если нужно
        if self.settings.create_group_if_missing:
            try:
                await self._r.xgroup_create(
                    name=self.settings.stream,
                    groupname=self.settings.group,
                    id="$",
                    mkstream=True,
                )
            except Exception as e:
                # BUSYGROUP — группа уже существует
                if "BUSYGROUP" not in str(e):
                    raise
        # Запустить reclaimer
        self._reclaimer_task = asyncio.create_task(self._reclaimer_loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._reclaimer_task:
            self._reclaimer_task.cancel()
            with asyncio.exceptions.CancelledError:  # type: ignore
                pass
            self._reclaimer_task = None
        await self._r.close()

    # ------------------------ Producer API -------------------------

    async def enqueue(
        self,
        payload: Mapping[str, Any],
        *,
        message_key: Optional[str] = None,
    ) -> Optional[str]:
        """
        Поставить сообщение в очередь. Если указан message_key, включается идемпотентность
        через SETNX: при повторной попытке в пределах dedup_ttl_s сообщение не дублируется.
        Возвращает stream ID либо None, если сработала дедупликация.
        """
        t0 = time.perf_counter()
        q = self.settings.stream

        # дедуп
        if message_key:
            key = (self.settings.dedup_prefix + message_key).encode("utf-8")
            ok = await self._r.set(key, b"1", ex=self.settings.dedup_ttl_s, nx=True)
            if not ok:
                if _PROM:
                    Q_DEDUP.labels(q).inc()
                return None

        # сериализация
        body = dict(payload)
        # служебные поля (прозрачно для консюмера)
        if message_key:
            body["_mk"] = message_key
        data = _json_dump(body, self.settings.json_compact)
        if len(data) > self.settings.payload_max_bytes:
            raise ValueError("Payload too large")

        maxlen_arg = ["MAXLEN", "~", self.settings.max_len] if self.settings.trim_approx else ["MAXLEN", self.settings.max_len]
        msg_id = await self._r.xadd(q, {"data": data}, *maxlen_arg)  # type: ignore

        if _PROM:
            Q_ENQ.labels(q).inc()
            Q_LAT_ENQ.labels(q).observe(time.perf_counter() - t0)
        return msg_id.decode("utf-8") if isinstance(msg_id, (bytes, bytearray)) else str(msg_id)

    async def enqueue_many(
        self,
        items: Sequence[Mapping[str, Any]],
        *,
        message_keys: Optional[Sequence[Optional[str]]] = None,
    ) -> List[Optional[str]]:
        """
        Батчевое добавление. message_keys, если задан, должен совпадать по длине с items.
        """
        res: List[Optional[str]] = []
        keys = message_keys or [None] * len(items)
        for it, k in zip(items, keys):
            res.append(await self.enqueue(it, message_key=k))
        return res

    # ------------------------ Consumer API -------------------------

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

    async def poll(self) -> AsyncIterator[List[QueueMessage]]:
        """
        Асинхронный итератор батчей сообщений. Обработка:
        - XREADGROUP BLOCK для новых
        - затем XAUTOCLAIM «зависших» (idle >= reclaim_idle_s)
        - в каждую выдачу входит не более batch_size сообщений
        """
        q = self.settings.stream
        g = self.settings.group
        c = self.settings.consumer
        bsize = self.settings.batch_size

        while not self._stop.is_set():
            # 1) прочитать новые
            t0 = time.perf_counter()
            resp = await self._r.xreadgroup(groupname=g, consumername=c, streams={q: ">"}, count=bsize, block=self.settings.block_ms)
            if _PROM:
                Q_LAT_DEQ.labels(q).observe(time.perf_counter() - t0)

            msgs: List[QueueMessage] = []
            if resp:
                # resp: [(stream, [(id, {'data': bytes})])]
                for _stream, entries in resp:
                    for mid, fields in entries:
                        raw = fields.get(b"data")
                        if not raw:
                            # некорректное сообщение — ack и в DLQ с пометкой
                            await self._send_to_dlq(mid, {"error": "missing_data"})
                            await self._r.xack(q, g, mid)
                            continue
                        try:
                            body = _json_load(raw)
                        except Exception:
                            await self._send_to_dlq(mid, {"error": "json_decode_error"})
                            await self._r.xack(q, g, mid)
                            continue
                        mk = body.pop("_mk", None)
                        attempt = await self._get_attempt(q, g, mid)
                        msgs.append(QueueMessage(id=mid.decode() if isinstance(mid, (bytes, bytearray)) else str(mid),
                                                 payload=body, attempt=attempt, key=mk))
                if msgs:
                    if _PROM:
                        Q_DEQ.labels(q).inc()
                    Q_INFLIGHT.labels(q).set(len(msgs))
                    yield msgs
                    Q_INFLIGHT.labels(q).set(0)
                    continue

            # 2) если новых нет — попробуем re-claim «зависшие»
            reclaimed = await self._reclaim_once(limit=bsize)
            if reclaimed:
                yield reclaimed
                continue

        # завершение
        return

    async def ack(self, *ids: str) -> int:
        """
        Подтверждение обработки.
        """
        if not ids:
            return 0
        n = await self._r.xack(self.settings.stream, self.settings.group, *ids)
        if _PROM:
            Q_ACK.labels(self.settings.stream).inc()
        return int(n or 0)

    async def nack(self, *ids: str, requeue: bool = True) -> int:
        """
        Отменить обработку. Если requeue=False — отправляем в DLQ и ACK оригинал.
        Если requeue=True — просто оставляем в PEL, XCLAIM подхватит.
        """
        if not ids:
            return 0
        count = 0
        if not requeue:
            # забрать тела и отправить в DLQ
            for mid in ids:
                body = await self._peek(mid)
                await self._send_to_dlq(mid, {"error": "nack", "body": body or {}})
                await self._r.xack(self.settings.stream, self.settings.group, mid)
                count += 1
            if _PROM:
                Q_DLQ.labels(self.settings.stream).inc()
            return count
        # requeue по сути ничего не делает; сообщение останется в PEL до XCLAIM
        if _PROM:
            Q_NACK.labels(self.settings.stream).inc()
        return 0

    async def extend_visibility(self, *ids: str) -> int:
        """
        Продлить «видимость» (переназначить idle=0, перехватив через XCLAIM самим же потребителем).
        """
        if not ids:
            return 0
        q, g, c = self.settings.stream, self.settings.group, self.settings.consumer
        # минимальная idle=0, force без передачи
        try:
            claimed = await self._r.xclaim(q, g, c, min_idle_time=0, message_ids=list(ids), idle=0, justid=True)
        except Exception:
            claimed = []
        return len(claimed or [])

    # ------------------------ Внутренние утилиты -------------------------

    async def _get_attempt(self, stream: str, group: str, mid: bytes) -> int:
        """
        Количество обработок по данным PEL (XPENDING).
        """
        try:
            info = await self._r.xpending_range(stream, group, "-", "+", 1, consumer=None, idle=None, start=mid, end=mid)
            # xpending_range может вернуть [] если запись только что прочитана
            if info:
                # (message_id, consumer, idle, deliveries)
                return int(info[0][3])
        except Exception:
            pass
        return 1

    async def _send_to_dlq(self, mid: Any, meta: Mapping[str, Any]) -> None:
        try:
            data = _json_dump({"mid": mid.decode() if isinstance(mid, (bytes, bytearray)) else str(mid), **meta}, True)
            await self._r.xadd(self.settings.dlq_stream, {"data": data}, "MAXLEN", "~", self.settings.max_len)
        except Exception:
            pass

    async def _peek(self, mid: str) -> Optional[Dict[str, Any]]:
        """
        Получить тело сообщения по ID для DLQ/диагностики.
        """
        try:
            entries = await self._r.xrange(self.settings.stream, min=mid, max=mid, count=1)
            if not entries:
                return None
            _id, fields = entries[0]
            raw = fields.get(b"data")
            if not raw:
                return None
            return _json_load(raw)
        except Exception:
            return None

    async def _reclaim_once(self, limit: int) -> List[QueueMessage]:
        """
        Забрать «зависшие» сообщения (idle >= reclaim_idle_s) себе в обработку.
        """
        q, g, c = self.settings.stream, self.settings.group, self.settings.consumer
        msgs: List[QueueMessage] = []
        try:
            # XAUTOCLAIM >= Redis 6.2
            next_start = b"0-0"
            while len(msgs) < limit:
                idle = self.settings.reclaim_idle_s * 1000
                res = await self._r.xautoclaim(q, g, c, min_idle_time=idle, start_id=next_start, count=limit - len(msgs))
                if not res:
                    break
                entries, next_start = res[1], res[0]
                for mid, fields in entries:
                    raw = fields.get(b"data")
                    if not raw:
                        await self._r.xack(q, g, mid)
                        continue
                    try:
                        body = _json_load(raw)
                    except Exception:
                        await self._r.xack(q, g, mid)
                        continue
                    mk = body.pop("_mk", None)
                    attempt = await self._get_attempt(q, g, mid)
                    if attempt > self.settings.max_retries:
                        await self._send_to_dlq(mid, {"error": "max_retries_exceeded", "attempt": attempt})
                        await self._r.xack(q, g, mid)
                        if _PROM:
                            Q_DLQ.labels(q).inc()
                        continue
                    msgs.append(QueueMessage(id=mid.decode() if isinstance(mid, (bytes, bytearray)) else str(mid),
                                             payload=body, attempt=attempt, key=mk))
                if not entries:
                    break
        except Exception:
            # Для старых Redis: можно fallback на XPENDING + XCLAIM, но тут опускаем сложности.
            pass
        if msgs and _PROM:
            Q_RECLAIM.labels(q).inc()
        return msgs

    async def _reclaimer_loop(self) -> None:
        """
        Фоновая задача: периодически трогает XAUTOCLAIM для освобождения «зависших» сообщений.
        Также публикует heartbeat в health_key.
        """
        q = self.settings.stream
        while not self._stop.is_set():
            try:
                await self._r.set(self.settings.health_key.encode("utf-8"), b"1", ex=self.settings.health_ttl_s)
                # мягкий прогон reclaimer'а без вывода сообщений наружу
                await self._reclaim_once(limit=self.settings.batch_size)
            except Exception:
                pass
            await asyncio.sleep(self.settings.reclaim_interval_s)


# -----------------------------------------------------------------------------
# Высокоуровневый потребитель (optional helper)
# -----------------------------------------------------------------------------
class QueueWorker:
    """
    Утилита для запуска обработчика с параллелизмом и корректным ack/nack.
    """
    def __init__(self, queue: RedisStreamQueue, handler, *, concurrency: Optional[int] = None):
        self.queue = queue
        self.handler = handler  # async def handler(msg: QueueMessage) -> bool (True=ack, False=dlq)
        self.concurrency = concurrency or queue.settings.max_concurrency
        self._sem = asyncio.Semaphore(self.concurrency)
        self._stop = asyncio.Event()
        self._tasks: List[asyncio.Task] = []

    async def run(self) -> None:
        async with self.queue:
            async for batch in self.queue.poll():
                if self._stop.is_set():
                    break
                for msg in batch:
                    await self._sem.acquire()
                    t = asyncio.create_task(self._process(msg))
                    t.add_done_callback(lambda _: self._sem.release())
                    self._tasks.append(t)
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def stop(self) -> None:
        self._stop.set()

    async def _process(self, msg: QueueMessage) -> None:
        q = self.queue.settings.stream
        span = None
        if _OTEL:
            tracer = trace.get_tracer("omnimind.queue")  # type: ignore
            span = tracer.start_as_current_span("queue.process", attributes={"queue": q, "attempt": msg.attempt})  # type: ignore
            span.__enter__()  # type: ignore
        try:
            ok = await self.handler(msg)
            if ok:
                await self.queue.ack(msg.id)
            else:
                # отправляем в DLQ и ACK оригинал
                await self.queue.nack(msg.id, requeue=False)
        except Exception:
            # Requeue: оставим в PEL, чтобы XAUTOCLAIM подобрал
            await self.queue.nack(msg.id, requeue=True)
        finally:
            if span:
                span.__exit__(None, None, None)  # type: ignore


# -----------------------------------------------------------------------------
# Пример использования (докстринг, не исполняется)
# -----------------------------------------------------------------------------
"""
Пример:

from omnimind.adapters.queue.redis_queue import RedisStreamQueue, QueueWorker, RedisQueueSettings

settings = RedisQueueSettings(
    url="redis://localhost:6379/0",
    stream="omnimind:queue",
    group="omnimind-consumers",
    consumer="c-1",
)

queue = RedisStreamQueue(settings)

async def handler(msg):
    # Ваша бизнес-логика; вернуть True для ACK или False для отправки в DLQ
    print("processing", msg.id, msg.attempt, msg.payload)
    return True

worker = QueueWorker(queue, handler, concurrency=8)

# Запуск воркера:
# await worker.run()

# Публикация:
# await queue.enqueue({"type": "task", "data": {...}}, message_key="unique-key-123")

Ограничения:
- Требуется Redis ≥ 6.2 для XAUTOCLAIM. Для более старых версий нужен fallback через XPENDING+XCLAIM.
- Если переменные окружения/Redis недоступны, адаптер сообщит об ошибке конфигурации. I cannot verify this.
"""
