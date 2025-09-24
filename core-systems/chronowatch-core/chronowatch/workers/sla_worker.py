# chronowatch-core/chronowatch/workers/sla_worker.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Protocol,
    Tuple,
)

# Зависимость на внутренний модуль с расчётом SLO/Error Budget
from ..sla.budget import (
    SLOBudgetTracker,
    BurnAlertSpec,
    BurnAlertEvent,
    BudgetSnapshot,
    build_tracker,
)

__all__ = [
    "SlaWorkerConfig",
    "SlaEvent",
    "EventSource",
    "EventSink",
    "InMemoryEventSource",
    "NDJSONEventSource",
    "KafkaEventSource",
    "RedisStreamEventSource",
    "LogSink",
    "WebhookSink",
    "SlaWorker",
    "run_sla_worker_cli",
]

# ------------------------------------------------------------------------------
# Конфигурация
# ------------------------------------------------------------------------------

@dataclass(slots=True)
class SlaWorkerConfig:
    name: str = "default-slo"
    objective: float = 0.999
    window_seconds: int = 28 * 24 * 60 * 60
    bucket_seconds: int = 60

    # Очередь/потоки
    queue_maxsize: int = 10000
    consumer_batch: int = 500
    update_flush_interval_sec: float = 0.2

    # Периодика
    snapshot_period_sec: float = 15.0
    alert_check_period_sec: float = 5.0

    # Исключения и дедуп
    exclude_label_keys: Tuple[str, ...] = ("exclude_from_slo",)
    maintenance_windows: List[Tuple[float, float]] = field(default_factory=list)  # списки [start_ts, end_ts)
    dedup_capacity: int = 100_000
    dedup_ttl_seconds: int = 3600

    # Логирование
    log_level: int = logging.INFO

    # Вебхук (если нужен)
    webhook_url: Optional[str] = None
    webhook_timeout_sec: float = 2.0
    webhook_retry: int = 2
    webhook_backoff_sec: float = 0.5


@dataclass(slots=True)
class SlaEvent:
    """
    Универсальное событие качества. Минимум: good/total (+ опционально ts/id/labels).
    good/total должны быть неотрицательными и good <= total.
    """
    good: int
    total: int
    ts: Optional[float] = None               # секунды UNIX; если None, берём текущее время воркера
    labels: Dict[str, str] = field(default_factory=dict)
    id: Optional[str] = None                 # для дедупликации (идемпотентность)


# ------------------------------------------------------------------------------
# Источники событий
# ------------------------------------------------------------------------------

class EventSource(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def __aiter__(self) -> AsyncIterator[SlaEvent]: ...


class InMemoryEventSource:
    """Программный источник для тестов/интеграции."""
    def __init__(self) -> None:
        self._q: asyncio.Queue[SlaEvent] = asyncio.Queue()
        self._closed = False

    async def start(self) -> None:
        self._closed = False

    async def stop(self) -> None:
        self._closed = True
        # Разбудим ожидателя
        await self._q.put(SlaEvent(good=0, total=0, id="__stop__"))

    async def push(self, ev: SlaEvent) -> None:
        if self._closed:
            raise RuntimeError("source closed")
        await self._q.put(ev)

    def __aiter__(self) -> AsyncIterator[SlaEvent]:
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[SlaEvent]:
        while True:
            ev = await self._q.get()
            if ev.id == "__stop__":
                break
            yield ev


class NDJSONEventSource:
    """
    Источник NDJSON: одна JSON-строка на событие.
    Поля: good, total, optional ts|id|labels.
    Можно читать из stdin (path=None) или из файла (path=...).
    """
    def __init__(self, path: Optional[str] = None) -> None:
        self._path = path
        self._fd = None
        self._loop_task: Optional[asyncio.Task] = None
        self._q: asyncio.Queue[SlaEvent] = asyncio.Queue(maxsize=10000)
        self._stopped = asyncio.Event()

    async def start(self) -> None:
        if self._path:
            self._fd = open(self._path, "r", buffering=1)
        else:
            self._fd = sys.stdin
        self._loop_task = asyncio.create_task(self._reader_loop())

    async def stop(self) -> None:
        self._stopped.set()
        if self._loop_task:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass
        if self._fd and self._fd is not sys.stdin:
            try:
                self._fd.close()
            except Exception:
                pass

    async def _reader_loop(self) -> None:
        assert self._fd is not None
        loop = asyncio.get_running_loop()
        try:
            while not self._stopped.is_set():
                line = await loop.run_in_executor(None, self._fd.readline)
                if not line:
                    await asyncio.sleep(0.05)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    ev = SlaEvent(
                        good=int(obj["good"]),
                        total=int(obj["total"]),
                        ts=float(obj.get("ts", time.time())),
                        labels=dict(obj.get("labels", {})),
                        id=str(obj.get("id")) if obj.get("id") is not None else None,
                    )
                    await self._q.put(ev)
                except Exception:
                    # пропускаем битые записи
                    continue
        except asyncio.CancelledError:
            return

    def __aiter__(self) -> AsyncIterator[SlaEvent]:
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[SlaEvent]:
        while not self._stopped.is_set():
            ev = await self._q.get()
            yield ev


class KafkaEventSource:
    """
    Опциональный источник из Kafka (требуется aiokafka).
    Сообщение — JSON с полями SlaEvent.
    """
    def __init__(self, bootstrap_servers: str, topic: str, group_id: str = "sla-worker") -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self._consumer = None
        self._running = False

    async def start(self) -> None:
        try:
            from aiokafka import AIOKafkaConsumer  # type: ignore
        except Exception as e:
            raise RuntimeError("aiokafka is required for KafkaEventSource") from e
        self._consumer = AIOKafkaConsumer(
            self.topic,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            enable_auto_commit=True,
            auto_offset_reset="latest",
            value_deserializer=lambda v: v.decode("utf-8"),
        )
        await self._consumer.start()
        self._running = True

    async def stop(self) -> None:
        self._running = False
        if self._consumer:
            await self._consumer.stop()

    def __aiter__(self) -> AsyncIterator[SlaEvent]:
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[SlaEvent]:
        assert self._consumer is not None
        while self._running:
            msg = await self._consumer.getone()
            try:
                obj = json.loads(msg.value)
                yield SlaEvent(
                    good=int(obj["good"]),
                    total=int(obj["total"]),
                    ts=float(obj.get("ts", time.time())),
                    labels=dict(obj.get("labels", {})),
                    id=str(obj.get("id")) if obj.get("id") is not None else None,
                )
            except Exception:
                # пропускаем битые записи
                continue


class RedisStreamEventSource:
    """
    Опциональный источник из Redis Streams (требуется redis.asyncio).
    Стрим XREAD BLOCK 1000 STREAMS <key> $; запись — JSON.
    """
    def __init__(self, dsn: str, stream_key: str, group: Optional[str] = None, consumer: Optional[str] = None) -> None:
        self.dsn = dsn
        self.stream_key = stream_key
        self.group = group
        self.consumer = consumer or f"sla-{os.getpid()}"
        self._client = None
        self._running = False

    async def start(self) -> None:
        try:
            import redis.asyncio as redis  # type: ignore
        except Exception as e:
            raise RuntimeError("redis.asyncio is required for RedisStreamEventSource") from e

        self._client = redis.from_url(self.dsn)
        if self.group:
            try:
                await self._client.xgroup_create(self.stream_key, self.group, id="$", mkstream=True)
            except Exception:
                pass
        self._running = True

    async def stop(self) -> None:
        self._running = False
        if self._client:
            try:
                await self._client.aclose()
            except Exception:
                pass

    def __aiter__(self) -> AsyncIterator[SlaEvent]:
        return self._aiter()

    async def _aiter(self) -> AsyncIterator[SlaEvent]:
        assert self._client is not None
        while self._running:
            try:
                if self.group:
                    resp = await self._client.xreadgroup(self.group, self.consumer, streams={self.stream_key: ">"}, count=100, block=1000)
                else:
                    resp = await self._client.xread({self.stream_key: "$"}, count=100, block=1000)
                for _stream, entries in (resp or []):
                    for entry_id, fields in entries:
                        raw = fields.get("data") if isinstance(fields, dict) else None
                        try:
                            obj = json.loads(raw if isinstance(raw, (bytes, str)) else "{}")
                            yield SlaEvent(
                                good=int(obj["good"]),
                                total=int(obj["total"]),
                                ts=float(obj.get("ts", time.time())),
                                labels=dict(obj.get("labels", {})),
                                id=str(obj.get("id")) if obj.get("id") is not None else None,
                            )
                        except Exception:
                            continue
                        finally:
                            if self.group:
                                # подтверждаем обработку
                                try:
                                    await self._client.xack(self.stream_key, self.group, entry_id)
                                except Exception:
                                    pass
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.2)


# ------------------------------------------------------------------------------
# Синки
# ------------------------------------------------------------------------------

class EventSink(Protocol):
    async def emit_snapshot(self, snap: BudgetSnapshot) -> None: ...
    async def emit_alert(self, alert: BurnAlertEvent) -> None: ...


class LogSink:
    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.log = logger or logging.getLogger("sla.worker.sink.log")

    async def emit_snapshot(self, snap: BudgetSnapshot) -> None:
        self.log.info(
            "SLO[%s] total=%d good=%d bad=%d comp=%.6f err=%.6f rem=%.3f burns=%s",
            snap.slo_name, snap.total, snap.good, snap.bad,
            snap.compliance, snap.error_rate, snap.budget_remaining_ratio,
            {k: round(v, 3) for k, v in snap.burn_rates.items()},
        )

    async def emit_alert(self, alert: BurnAlertEvent) -> None:
        lvl = logging.WARNING if alert.active else logging.INFO
        self.log.log(
            lvl,
            "ALERT[%s] active=%s short=%.2f long=%.2f reason=%s",
            alert.name, alert.active, alert.short_burn_rate, alert.long_burn_rate, alert.reason,
        )


class WebhookSink:
    """
    Минимальный вебхук без внешних зависимостей (urllib в thread-pool).
    """
    def __init__(self, url: str, timeout: float = 2.0, retries: int = 2, backoff: float = 0.5) -> None:
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self._log = logging.getLogger("sla.worker.sink.webhook")

    async def emit_snapshot(self, snap: BudgetSnapshot) -> None:
        await self._post_json({"type": "snapshot", "data": dataclass_to_dict(snap)})

    async def emit_alert(self, alert: BurnAlertEvent) -> None:
        await self._post_json({"type": "alert", "data": dataclass_to_dict(alert)})

    async def _post_json(self, payload: Dict[str, Any]) -> None:
        import urllib.request
        import urllib.error

        data = json.dumps(payload).encode("utf-8")
        attempt = 0
        while True:
            try:
                req = urllib.request.Request(self.url, data=data, headers={"Content-Type": "application/json"})
                await asyncio.to_thread(urllib.request.urlopen, req, timeout=self.timeout)
                return
            except urllib.error.URLError as e:
                attempt += 1
                if attempt > self.retries:
                    self._log.warning("webhook failed after %d tries: %s", attempt - 1, e)
                    return
                await asyncio.sleep(self.backoff * attempt)


# ------------------------------------------------------------------------------
# Воркер
# ------------------------------------------------------------------------------

def dataclass_to_dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "__dict__"):
        try:
            from dataclasses import asdict
            return asdict(obj)
        except Exception:
            pass
    # fallback
    return json.loads(json.dumps(obj, default=lambda o: getattr(o, "__dict__", str(o))))


class _LRUDedup:
    """
    Простой LRU для дедуплификации событий по id с TTL.
    Не использует внешние библиотеки.
    """
    def __init__(self, capacity: int, ttl: int) -> None:
        self.capacity = capacity
        self.ttl = ttl
        self._store: OrderedDict[str, float] = OrderedDict()

    def seen(self, key: Optional[str], now: float) -> bool:
        if not key:
            return False
        # очистка устаревших примерно раз на 1024 операций — можно улучшить при желании
        if len(self._store) > self.capacity * 2:
            self._gc(now)
        if key in self._store:
            ts = self._store.pop(key)
            if now - ts <= self.ttl:
                # уже видели
                self._store[key] = ts
                return True
        # новое
        self._store[key] = now
        if len(self._store) > self.capacity:
            self._store.popitem(last=False)
        return False

    def _gc(self, now: float) -> None:
        keys = list(self._store.keys())
        for k in keys:
            ts = self._store[k]
            if now - ts > self.ttl:
                self._store.pop(k, None)


class SlaWorker:
    """
    Асинхронный воркер SLO/Error Budget.
    """
    def __init__(
        self,
        source: EventSource,
        *,
        sinks: Iterable[EventSink] = (),
        config: Optional[SlaWorkerConfig] = None,
        tracker: Optional[SLOBudgetTracker] = None,
        burn_alerts: Iterable[BurnAlertSpec] = (),
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.cfg = config or SlaWorkerConfig()
        self.log = logger or logging.getLogger("sla.worker")
        self.log.setLevel(self.cfg.log_level)

        self.source = source
        self.sinks = list(sinks) or [LogSink()]

        self.tracker = tracker or build_tracker(
            name=self.cfg.name,
            objective=self.cfg.objective,
            window_seconds=self.cfg.window_seconds,
            bucket_seconds=self.cfg.bucket_seconds,
            burn_alerts=list(burn_alerts) if burn_alerts else None,
        )

        # Подписка на события трекера (опционально)
        # self.tracker._on_snapshot = lambda snap: ...
        # self.tracker._on_alert = lambda evt: ...

        self._queue: asyncio.Queue[SlaEvent] = asyncio.Queue(maxsize=self.cfg.queue_maxsize)
        self._stop = asyncio.Event()
        self._tasks: List[asyncio.Task] = []

        self._dedup = _LRUDedup(self.cfg.dedup_capacity, self.cfg.dedup_ttl_seconds)

    # ---------- lifecycle ----------

    async def start(self) -> None:
        self._stop.clear()
        await self.source.start()
        self._tasks.append(asyncio.create_task(self._producer()))
        self._tasks.append(asyncio.create_task(self._consumer()))
        self._tasks.append(asyncio.create_task(self._periodic_snapshots()))
        self._tasks.append(asyncio.create_task(self._periodic_alerts()))
        self.log.info(
            "SLA worker started: SLO=%s obj=%.6f window=%ds",
            self.cfg.name, self.cfg.objective, self.cfg.window_seconds
        )

    async def stop(self) -> None:
        self._stop.set()
        try:
            await self.source.stop()
        except Exception:
            pass
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        self.log.info("SLA worker stopped")

    # ---------- loops ----------

    async def _producer(self) -> None:
        """
        Читает события из источника и кладёт их в очередь с backpressure.
        """
        try:
            async for ev in self.source:
                if self._stop.is_set():
                    break
                await self._queue.put(ev)
        except asyncio.CancelledError:
            return
        except Exception as e:
            self.log.exception("producer error: %s", e)

    async def _consumer(self) -> None:
        """
        Забирает события из очереди, применяет исключения и дедуп, агрегирует батчами.
        """
        batch: List[SlaEvent] = []
        last_flush = time.time()
        try:
            while not self._stop.is_set():
                try:
                    ev = await asyncio.wait_for(self._queue.get(), timeout=self.cfg.update_flush_interval_sec)
                    batch.append(ev)
                except asyncio.TimeoutError:
                    pass

                now = time.time()
                if batch and (len(batch) >= self.cfg.consumer_batch or (now - last_flush) >= self.cfg.update_flush_interval_sec):
                    self._flush_batch(batch, now)
                    batch.clear()
                    last_flush = now
        except asyncio.CancelledError:
            # финальный слив
            if batch:
                self._flush_batch(batch, time.time())
            return
        except Exception as e:
            self.log.exception("consumer error: %s", e)

    def _flush_batch(self, events: List[SlaEvent], now: float) -> None:
        good_sum = total_sum = 0
        for ev in events:
            if self._dedup.seen(ev.id, now):
                continue
            if self._excluded(ev, now):
                continue
            ts = ev.ts if ev.ts is not None else now
            # защищаемся от некорректных значений
            g = max(0, int(ev.good))
            t = max(0, int(ev.total))
            if g > t:
                g = t
            self.tracker.update(good=g, total=t, labels=ev.labels, ts=ts)
            good_sum += g
            total_sum += t
        if total_sum:
            self.log.debug("batch applied: total=%d good=%d", total_sum, good_sum)

    def _excluded(self, ev: SlaEvent, now: float) -> bool:
        # По лейблам
        for k in self.cfg.exclude_label_keys:
            if ev.labels.get(k, "").lower() in ("1", "true", "yes"):
                return True
        # По плановым окнам
        t = ev.ts if ev.ts is not None else now
        for start, end in self.cfg.maintenance_windows:
            if start <= t < end:
                return True
        return False

    async def _periodic_snapshots(self) -> None:
        try:
            while not self._stop.is_set():
                snap = self.tracker.snapshot()
                await self._fanout_snapshot(snap)
                await asyncio.sleep(self.cfg.snapshot_period_sec)
        except asyncio.CancelledError:
            return

    async def _periodic_alerts(self) -> None:
        try:
            while not self._stop.is_set():
                events = self.tracker.check_alerts()
                for e in events:
                    await self._fanout_alert(e)
                await asyncio.sleep(self.cfg.alert_check_period_sec)
        except asyncio.CancelledError:
            return

    async def _fanout_snapshot(self, snap: BudgetSnapshot) -> None:
        await asyncio.gather(*(sink.emit_snapshot(snap) for sink in self.sinks), return_exceptions=True)

    async def _fanout_alert(self, evt: BurnAlertEvent) -> None:
        await asyncio.gather(*(sink.emit_alert(evt) for sink in self.sinks), return_exceptions=True)


# ------------------------------------------------------------------------------
# CLI (опционально, для самостоятельного процесса)
# ------------------------------------------------------------------------------

async def _run_cli_from_env() -> None:
    """
    Пример самостоятельного запуска воркера из переменных окружения:
      SLO_NAME, SLO_OBJECTIVE, SLO_WINDOW_SECONDS
      NDJSON_PATH (если не задан — читаем stdin)
      WEBHOOK_URL (опционально)
    """
    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    cfg = SlaWorkerConfig(
        name=os.getenv("SLO_NAME", "default-slo"),
        objective=float(os.getenv("SLO_OBJECTIVE", "0.999")),
        window_seconds=int(os.getenv("SLO_WINDOW_SECONDS", str(28 * 24 * 60 * 60))),
        webhook_url=os.getenv("WEBHOOK_URL"),
    )

    source = NDJSONEventSource(path=os.getenv("NDJSON_PATH") or None)
    sinks: List[EventSink] = [LogSink()]
    if cfg.webhook_url:
        sinks.append(WebhookSink(cfg.webhook_url, timeout=cfg.webhook_timeout_sec, retries=cfg.webhook_retry, backoff=cfg.webhook_backoff_sec))

    worker = SlaWorker(source, sinks=sinks, config=cfg)

    stop = asyncio.Event()

    def _signal_handler() -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows
            signal.signal(sig, lambda *_: _signal_handler())

    await worker.start()
    await stop.wait()
    await worker.stop()


def run_sla_worker_cli() -> None:
    try:
        asyncio.run(_run_cli_from_env())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":  # pragma: no cover
    run_sla_worker_cli()
