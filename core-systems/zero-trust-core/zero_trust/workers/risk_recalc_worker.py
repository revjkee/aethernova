# -*- coding: utf-8 -*-
"""
Risk Recalc Worker — промышленный асинхронный воркер пересчёта рисков для Zero-Trust Core.

Функции:
- Потребление событий риска из очереди (Kafka/RabbitMQ/Redis Streams — опционально; fallback: InMemory).
- Идемпотентность по event_id, лимиты скорости, батч‑переработка с параллелизмом.
- Хранение профилей риска и агрегатов (Redis/SQLite; fallback выбирается автоматически).
- Модель расчёта риска 0..100 c уровнями LOW/MEDIUM/HIGH/CRITICAL и причинами.
- Экспоненциальное затухание сигналов, эскалация при повторных инцидентах.
- Метрики Prometheus (опционально), структурированные JSON‑логи.
- Грациозное завершение, DLQ для «ядовитых» сообщений.
- Конфиг через ENV (без внешних зависимостей), CLI-интерфейс.

Автор: Aethernova / NeuroCity Zero-Trust Core
Лицензия: Apache-2.0
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import enum
import functools
import json
import logging
import os
import random
import signal
import sys
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

# --------------------------- Опциональные зависимости ---------------------------

_HAS_PROM = False
try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server  # type: ignore

    _HAS_PROM = True
except Exception:
    # Заглушки метрик
    class _Nop:
        def __init__(self, *_, **__): ...
        def labels(self, *_, **__): return self
        def inc(self, *_: Any, **__: Any): ...
        def observe(self, *_: Any, **__: Any): ...
        def set(self, *_: Any, **__: Any): ...
    Counter = Histogram = Gauge = _Nop  # type: ignore
    def start_http_server(*_, **__): ...  # type: ignore

_HAS_REDIS = False
try:
    # redis-py 4.x: redis.asyncio
    import redis.asyncio as aioredis  # type: ignore
    _HAS_REDIS = True
except Exception:
    aioredis = None

_HAS_SQLITE = False
try:
    import aiosqlite  # type: ignore
    _HAS_SQLITE = True
except Exception:
    aiosqlite = None

_HAS_KAFKA = False
try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer  # type: ignore
    _HAS_KAFKA = True
except Exception:
    AIOKafkaConsumer = AIOKafkaProducer = None

_HAS_RABBIT = False
try:
    import aio_pika  # type: ignore
    _HAS_RABBIT = True
except Exception:
    aio_pika = None

# --------------------------- Логирование ---------------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("risk_worker")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(_JsonFormatter())
        logger.addHandler(h)
    logger.setLevel(getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO))
    logger.propagate = False
    return logger

log = _setup_logger()

# --------------------------- Конфигурация через ENV ---------------------------

@dataclasses.dataclass(frozen=True)
class Settings:
    queue_backend: str = os.getenv("RISK_QUEUE_BACKEND", "memory")  # memory|redis|kafka|rabbit
    queue_topic: str = os.getenv("RISK_QUEUE_TOPIC", "risk.events")
    queue_group: str = os.getenv("RISK_QUEUE_GROUP", "risk-worker")
    queue_dlx: str = os.getenv("RISK_DLQ", "risk.dlq")

    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    sqlite_path: str = os.getenv("SQLITE_PATH", "./risk_state.db")

    kafka_bootstrap: str = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
    rabbit_url: str = os.getenv("RABBIT_URL", "amqp://guest:guest@localhost/")

    max_parallel: int = int(os.getenv("RISK_MAX_PARALLEL", "16"))
    batch_size: int = int(os.getenv("RISK_BATCH_SIZE", "64"))
    vis_window_sec: int = int(os.getenv("RISK_VIS_WINDOW_SEC", "3600"))
    exp_decay: float = float(os.getenv("RISK_EXP_DECAY", "0.94"))  # за окно

    # веса и пороги риска
    w_auth_fail: float = float(os.getenv("RISK_W_AUTH_FAIL", "14.0"))
    w_anomaly: float = float(os.getenv("RISK_W_ANOMALY", "18.0"))
    w_geo_mismatch: float = float(os.getenv("RISK_W_GEO", "10.0"))
    w_device_posture: float = float(os.getenv("RISK_W_POSTURE", "16.0"))
    w_privilege: float = float(os.getenv("RISK_W_PRIV", "12.0"))
    w_mfa_pass: float = float(os.getenv("RISK_W_MFA_PASS", "-8.0"))  # снижение
    w_replay: float = float(os.getenv("RISK_W_REPLAY", "20.0"))
    w_dlp: float = float(os.getenv("RISK_W_DLP", "22.0"))

    thr_medium: float = float(os.getenv("RISK_THR_MEDIUM", "30.0"))
    thr_high: float = float(os.getenv("RISK_THR_HIGH", "60.0"))
    thr_critical: float = float(os.getenv("RISK_THR_CRIT", "80.0"))

    prometheus_port: int = int(os.getenv("PROM_PORT", "9109"))
    enable_metrics: bool = os.getenv("ENABLE_METRICS", "1") == "1"

    rate_bucket: int = int(os.getenv("RISK_RATE_BUCKET", "200"))
    rate_refill_per_sec: float = float(os.getenv("RISK_RATE_REFILL", "80"))

    dlq_max_retries: int = int(os.getenv("DLQ_MAX_RETRIES", "5"))
    shutdown_timeout: int = int(os.getenv("SHUTDOWN_TIMEOUT", "30"))

    @property
    def storage_backend(self) -> str:
        # предпочитаем Redis; иначе SQLite; иначе — memory
        if _HAS_REDIS:
            return "redis"
        if _HAS_SQLITE:
            return "sqlite"
        return "memory"

CFG = Settings()

# --------------------------- Метрики ---------------------------

MET_CONSUMED = Counter("risk_events_consumed_total", "Считанные события", ["backend"])  # type: ignore
MET_PROCESSED = Counter("risk_events_processed_total", "Успешно обработанные события")  # type: ignore
MET_FAILED = Counter("risk_events_failed_total", "События с ошибкой")  # type: ignore
MET_RETRIES = Counter("risk_event_retries_total", "Ретраи обработки")  # type: ignore
MET_LATENCY = Histogram("risk_processing_latency_seconds", "Латентность обработки события")  # type: ignore
MET_SCORE = Histogram("risk_score_distribution", "Распределение итогового риска", buckets=[0,10,20,30,40,50,60,70,80,90,100])  # type: ignore
GAUGE_INFLIGHT = Gauge("risk_inflight_tasks", "В обработке сейчас")  # type: ignore

if CFG.enable_metrics and _HAS_PROM:
    start_http_server(CFG.prometheus_port)
    log.info("Prometheus metrics enabled", extra={"extra": {"port": CFG.prometheus_port}})

# --------------------------- Доменные модели ---------------------------

class EntityType(enum.Enum):
    USER = "user"
    SERVICE = "service"
    NODE = "node"

class RiskLevel(enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclasses.dataclass
class RiskEvent:
    event_id: str
    ts: float
    entity_id: str
    entity_type: str  # из EntityType
    signals: Dict[str, Any]  # произвольные признаки (auth_failures, anomaly_score, geo, device, privilege, replay, dlp, mfa_pass)
    correlation_id: Optional[str] = None

@dataclasses.dataclass
class RiskProfile:
    entity_id: str
    entity_type: str
    score: float
    level: RiskLevel
    reasons: List[str]
    updated_at: float

# --------------------------- Утилиты ---------------------------

def _now() -> float:
    return time.time()

def _sleep_jitter(base: float, attempt: int, cap: float) -> float:
    # экспоненциальный с джиттером
    v = min(cap, base * (2 ** (attempt - 1)))
    return random.uniform(v * 0.5, v)

# --------------------------- Абстракции очереди ---------------------------

class QueueMessage:
    __slots__ = ("payload", "meta")
    def __init__(self, payload: Dict[str, Any], meta: Dict[str, Any]):
        self.payload = payload
        self.meta = meta  # например, offset/delivery_tag/retry_count

class AbstractConsumer:
    async def start(self): ...
    async def stop(self): ...
    async def fetch_batch(self, max_items: int, timeout: float = 1.0) -> List[QueueMessage]:
        return []
    async def ack(self, msg: QueueMessage): ...
    async def reject(self, msg: QueueMessage, *, requeue: bool): ...

class AbstractProducer:
    async def start(self): ...
    async def stop(self): ...
    async def publish(self, topic: str, payload: Dict[str, Any]): ...

# -------- InMemory (fallback) --------

class InMemoryQueue(AbstractConsumer, AbstractProducer):
    def __init__(self):
        self._q: asyncio.Queue = asyncio.Queue()
        self._running = False

    async def start(self): self._running = True
    async def stop(self):
        self._running = False
        with contextlib.suppress(asyncio.QueueEmpty):
            while True:
                self._q.get_nowait()

    async def publish(self, topic: str, payload: Dict[str, Any]):
        await self._q.put(QueueMessage(payload, {"topic": topic}))

    async def fetch_batch(self, max_items: int, timeout: float = 1.0) -> List[QueueMessage]:
        items: List[QueueMessage] = []
        try:
            first = await asyncio.wait_for(self._q.get(), timeout=timeout)
            items.append(first)
        except asyncio.TimeoutError:
            return []
        for _ in range(max_items - 1):
            try:
                items.append(self._q.get_nowait())
            except asyncio.QueueEmpty:
                break
        return items

    async def ack(self, msg: QueueMessage): ...
    async def reject(self, msg: QueueMessage, *, requeue: bool):
        if requeue:
            await self._q.put(msg)

# -------- Redis Streams (если доступен) --------

class RedisStreamsConsumer(AbstractConsumer):
    def __init__(self, url: str, stream: str, group: str):
        if not _HAS_REDIS:
            raise RuntimeError("Redis backend недоступен")
        self._r = aioredis.from_url(url, decode_responses=True)
        self.stream = stream
        self.group = group
        self._consumer = f"c-{os.getpid()}-{random.randint(1000,9999)}"
        self._running = False

    async def start(self):
        self._running = True
        # создаём group, если нет
        try:
            await self._r.xgroup_create(name=self.stream, groupname=self.group, id="$", mkstream=True)
        except Exception:
            # возможно, уже создана
            pass

    async def stop(self):
        self._running = False
        await self._r.close()

    async def fetch_batch(self, max_items: int, timeout: float = 1.0) -> List[QueueMessage]:
        res = await self._r.xreadgroup(groupname=self.group, consumername=self._consumer,
                                       streams={self.stream: ">"}, count=max_items, latest_ids=None, block=int(timeout*1000))
        out: List[QueueMessage] = []
        for _, messages in res or []:
            for msg_id, fields in messages:
                try:
                    payload = json.loads(fields.get("payload", "{}"))
                except Exception:
                    payload = {}
                out.append(QueueMessage(payload, {"redis_id": msg_id}))
        return out

    async def ack(self, msg: QueueMessage):
        msg_id = msg.meta.get("redis_id")
        if msg_id:
            await self._r.xack(self.stream, self.group, msg_id)
            await self._r.xdel(self.stream, msg_id)

    async def reject(self, msg: QueueMessage, *, requeue: bool):
        # В Redis Streams «reject» не обязателен; можно просто не ack — попадёт в PEL.
        # Для DLQ — публикуем в отдельный stream.
        if not requeue:
            await self._r.xadd(name=f"{self.stream}.dlq", fields={"payload": json.dumps(msg.payload)})

class RedisStreamsProducer(AbstractProducer):
    def __init__(self, url: str):
        if not _HAS_REDIS:
            raise RuntimeError("Redis backend недоступен")
        self._r = aioredis.from_url(url, decode_responses=True)

    async def start(self): ...
    async def stop(self): await self._r.close()

    async def publish(self, topic: str, payload: Dict[str, Any]):
        await self._r.xadd(name=topic, fields={"payload": json.dumps(payload)})

# -------- Kafka (опционально) --------

class KafkaConsumer(AbstractConsumer):
    def __init__(self, bootstrap: str, topic: str, group: str):
        if not _HAS_KAFKA:
            raise RuntimeError("Kafka backend недоступен")
        self._c = AIOKafkaConsumer(topic, bootstrap_servers=bootstrap, group_id=group, enable_auto_commit=False)
        self._topic = topic

    async def start(self): await self._c.start()
    async def stop(self): await self._c.stop()

    async def fetch_batch(self, max_items: int, timeout: float = 1.0) -> List[QueueMessage]:
        out: List[QueueMessage] = []
        try:
            msg = await asyncio.wait_for(self._c.getone(), timeout=timeout)
        except asyncio.TimeoutError:
            return []
        out.append(QueueMessage(json.loads(msg.value.decode("utf-8")), {"tp": (msg.topic, msg.partition), "offset": msg.offset}))
        for _ in range(max_items - 1):
            m = await self._c.getmany(timeout_ms=1)
            for tp, batch in m.items():
                for rec in batch:
                    out.append(QueueMessage(json.loads(rec.value.decode("utf-8")),
                                            {"tp": (rec.topic, rec.partition), "offset": rec.offset}))
        return out

    async def ack(self, msg: QueueMessage):
        # В aiokafka коммитим смещения пачками; для простоты — коммитим сразу.
        await self._c.commit()

    async def reject(self, msg: QueueMessage, *, requeue: bool):
        # Для DLQ нужна отдельная продюсер‑логика; пропускаем здесь.
        ...

class KafkaProducer(AbstractProducer):
    def __init__(self, bootstrap: str):
        if not _HAS_KAFKA:
            raise RuntimeError("Kafka backend недоступен")
        self._p = AIOKafkaProducer(bootstrap_servers=bootstrap)

    async def start(self): await self._p.start()
    async def stop(self): await self._p.stop()

    async def publish(self, topic: str, payload: Dict[str, Any]):
        await self._p.send_and_wait(topic, json.dumps(payload).encode("utf-8"))

# -------- RabbitMQ (опционально) --------

class RabbitConsumer(AbstractConsumer):
    def __init__(self, url: str, queue: str):
        if not _HAS_RABBIT:
            raise RuntimeError("Rabbit backend недоступен")
        self.url = url
        self.queue = queue
        self._conn = None
        self._ch = None
        self._q = None

    async def start(self):
        self._conn = await aio_pika.connect_robust(self.url)
        self._ch = await self._conn.channel()
        self._q = await self._ch.declare_queue(self.queue, durable=True)

    async def stop(self):
        if self._conn:
            await self._conn.close()

    async def fetch_batch(self, max_items: int, timeout: float = 1.0) -> List[QueueMessage]:
        out: List[QueueMessage] = []
        for _ in range(max_items):
            with contextlib.suppress(asyncio.TimeoutError):
                msg = await asyncio.wait_for(self._q.get(no_ack=False), timeout=timeout)  # type: ignore
                payload = json.loads(msg.body.decode("utf-8"))
                out.append(QueueMessage(payload, {"delivery": msg}))
        return out

    async def ack(self, msg: QueueMessage):
        delivery = msg.meta.get("delivery")
        if delivery:
            await delivery.ack()

    async def reject(self, msg: QueueMessage, *, requeue: bool):
        delivery = msg.meta.get("delivery")
        if delivery:
            await delivery.reject(requeue=requeue)

class RabbitProducer(AbstractProducer):
    def __init__(self, url: str):
        if not _HAS_RABBIT:
            raise RuntimeError("Rabbit backend недоступен")
        self.url = url
        self._conn = None
        self._ch = None

    async def start(self):
        self._conn = await aio_pika.connect_robust(self.url)
        self._ch = await self._conn.channel()

    async def stop(self):
        if self._conn:
            await self._conn.close()

    async def publish(self, topic: str, payload: Dict[str, Any]):
        await self._ch.default_exchange.publish(  # type: ignore
            aio_pika.Message(body=json.dumps(payload).encode("utf-8")),
            routing_key=topic,
        )

# --------------------------- Хранилище ---------------------------

class AbstractStorage:
    async def start(self): ...
    async def stop(self): ...
    async def is_duplicate_event(self, event_id: str, ttl_sec: int = 3600) -> bool: return False
    async def get_profile(self, entity_id: str, entity_type: str) -> Optional[RiskProfile]: ...
    async def put_profile(self, profile: RiskProfile): ...
    async def incr_counter(self, key: str, window_sec: int, decay: float) -> float: ...
    async def get_counter(self, key: str) -> float: return 0.0

# Redis‑хранилище
class RedisStorage(AbstractStorage):
    def __init__(self, url: str):
        self._r = aioredis.from_url(url, decode_responses=True)  # type: ignore

    async def start(self): ...
    async def stop(self): await self._r.close()

    async def is_duplicate_event(self, event_id: str, ttl_sec: int = 3600) -> bool:
        # SETNX+EX
        ok = await self._r.set(name=f"risk:evt:{event_id}", value="1", ex=ttl_sec, nx=True)
        return not bool(ok)

    async def get_profile(self, entity_id: str, entity_type: str) -> Optional[RiskProfile]:
        raw = await self._r.get(f"risk:profile:{entity_type}:{entity_id}")
        if not raw:
            return None
        d = json.loads(raw)
        return RiskProfile(**d)

    async def put_profile(self, profile: RiskProfile):
        key = f"risk:profile:{profile.entity_type}:{profile.entity_id}"
        await self._r.set(key, json.dumps(dataclasses.asdict(profile)), ex=24 * 3600)

    async def incr_counter(self, key: str, window_sec: int, decay: float) -> float:
        # простая модель: храним текущее значение и timestamp, применяем затухание
        now = _now()
        meta_key = f"{key}:meta"
        pipe = self._r.pipeline()
        pipe.get(key)
        pipe.get(meta_key)
        cur, meta = await pipe.execute()
        cur = float(cur) if cur else 0.0
        last_ts = float(meta) if meta else now
        elapsed = max(0.0, now - last_ts)
        windows = elapsed / float(window_sec) if window_sec > 0 else 0.0
        decayed = cur * (decay ** windows)
        decayed += 1.0
        pipe = self._r.pipeline()
        pipe.set(key, decayed)
        pipe.set(meta_key, now)
        await pipe.execute()
        return decayed

    async def get_counter(self, key: str) -> float:
        v = await self._r.get(key)
        return float(v) if v else 0.0

# SQLite‑хранилище
class SQLiteStorage(AbstractStorage):
    def __init__(self, path: str):
        self._path = path
        self._db = None

    async def start(self):
        self._db = await aiosqlite.connect(self._path)  # type: ignore
        await self._db.execute("""
        CREATE TABLE IF NOT EXISTS events_dedup (
            event_id TEXT PRIMARY KEY,
            ts REAL
        )""")
        await self._db.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            entity_type TEXT, entity_id TEXT, score REAL, level TEXT, reasons TEXT, updated_at REAL,
            PRIMARY KEY (entity_type, entity_id)
        )""")
        await self._db.execute("""
        CREATE TABLE IF NOT EXISTS counters (
            key TEXT PRIMARY KEY,
            value REAL,
            updated REAL
        )""")
        await self._db.commit()

    async def stop(self):
        if self._db:
            await self._db.close()

    async def is_duplicate_event(self, event_id: str, ttl_sec: int = 3600) -> bool:
        now = _now()
        try:
            await self._db.execute("INSERT INTO events_dedup(event_id, ts) VALUES (?, ?)", (event_id, now))  # type: ignore
            await self._db.commit()
            # чистка
            await self._db.execute("DELETE FROM events_dedup WHERE ts < ?", (now - ttl_sec,))  # type: ignore
            return False
        except Exception:
            return True

    async def get_profile(self, entity_id: str, entity_type: str) -> Optional[RiskProfile]:
        cur = await self._db.execute("SELECT score, level, reasons, updated_at FROM profiles WHERE entity_type=? AND entity_id=?",  # type: ignore
                                     (entity_type, entity_id))
        row = await cur.fetchone()
        if not row:
            return None
        score, level, reasons, updated_at = row
        return RiskProfile(entity_id=entity_id, entity_type=entity_type, score=score,
                           level=RiskLevel(level), reasons=json.loads(reasons), updated_at=updated_at)

    async def put_profile(self, profile: RiskProfile):
        await self._db.execute(
            "INSERT INTO profiles(entity_type, entity_id, score, level, reasons, updated_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(entity_type, entity_id) DO UPDATE SET "
            "score=excluded.score, level=excluded.level, reasons=excluded.reasons, updated_at=excluded.updated_at",
            (profile.entity_type, profile.entity_id, profile.score, profile.level.value,
             json.dumps(profile.reasons), profile.updated_at),
        )
        await self._db.commit()

    async def incr_counter(self, key: str, window_sec: int, decay: float) -> float:
        now = _now()
        cur = await self._db.execute("SELECT value, updated FROM counters WHERE key=?", (key,))  # type: ignore
        row = await cur.fetchone()
        if not row:
            value, updated = 0.0, now
        else:
            value, updated = float(row[0]), float(row[1])
        elapsed = max(0.0, now - updated)
        windows = elapsed / float(window_sec) if window_sec > 0 else 0.0
        decayed = value * (decay ** windows)
        decayed += 1.0
        await self._db.execute("INSERT INTO counters(key, value, updated) VALUES (?,?,?) "
                               "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
                               (key, decayed, now))  # type: ignore
        await self._db.commit()
        return decayed

    async def get_counter(self, key: str) -> float:
        cur = await self._db.execute("SELECT value FROM counters WHERE key=?", (key,))  # type: ignore
        row = await cur.fetchone()
        return float(row[0]) if row else 0.0

# In‑Memory storage (на крайний случай)
class MemoryStorage(AbstractStorage):
    def __init__(self):
        self._dedup: Dict[str, float] = {}
        self._profiles: Dict[Tuple[str, str], RiskProfile] = {}
        self._counters: Dict[str, Tuple[float, float]] = {}  # key -> (value, updated)

    async def start(self): ...
    async def stop(self): ...

    async def is_duplicate_event(self, event_id: str, ttl_sec: int = 3600) -> bool:
        now = _now()
        # очистка старых
        for k, ts in list(self._dedup.items()):
            if ts < now - ttl_sec:
                self._dedup.pop(k, None)
        if event_id in self._dedup:
            return True
        self._dedup[event_id] = now
        return False

    async def get_profile(self, entity_id: str, entity_type: str) -> Optional[RiskProfile]:
        return self._profiles.get((entity_type, entity_id))

    async def put_profile(self, profile: RiskProfile):
        self._profiles[(profile.entity_type, profile.entity_id)] = profile

    async def incr_counter(self, key: str, window_sec: int, decay: float) -> float:
        now = _now()
        value, updated = self._counters.get(key, (0.0, now))
        elapsed = max(0.0, now - updated)
        windows = elapsed / float(window_sec) if window_sec > 0 else 0.0
        value = value * (decay ** windows) + 1.0
        self._counters[key] = (value, now)
        return value

    async def get_counter(self, key: str) -> float:
        value, _ = self._counters.get(key, (0.0, _now()))
        return value

# --------------------------- Лимитер и идемпотентность ---------------------------

class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = capacity
        self.refill = refill_per_sec
        self.tokens = capacity
        self.last = _now()
        self._lock = asyncio.Lock()

    async def take(self, n: int = 1) -> bool:
        async with self._lock:
            now = _now()
            delta = now - self.last
            self.tokens = min(self.capacity, self.tokens + delta * self.refill)
            self.last = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False

# --------------------------- Модель вычисления риска ---------------------------

class RiskEngine:
    def __init__(self, cfg: Settings, storage: AbstractStorage):
        self.cfg = cfg
        self.storage = storage

    async def compute(self, ev: RiskEvent) -> RiskProfile:
        t0 = _now()
        reasons: List[str] = []

        # Извлекаем признаки
        s = ev.signals
        auth_fail = int(s.get("auth_failures", 0))
        anomaly = float(s.get("anomaly_score", 0.0))  # 0..1
        geo_mismatch = bool(s.get("geo_mismatch", False))
        device_bad = float(s.get("device_posture_score", 0.0))  # 0..1 (1=плохо)
        privilege = float(s.get("privilege_sensitivity", 0.0))  # 0..1
        mfa_pass = bool(s.get("mfa_passed", False))
        replay = bool(s.get("replay_detected", False))
        dlp_hit = int(s.get("dlp_hits", 0))

        # Динамика: счётчик failure по окну
        fail_key = f"risk:c:fail:{ev.entity_type}:{ev.entity_id}"
        fail_dyn = 0.0
        for _ in range(auth_fail):
            fail_dyn = await self.storage.incr_counter(fail_key, self.cfg.vis_window_sec, self.cfg.exp_decay)

        # Базовая линия (если уже был профиль)
        prev = await self.storage.get_profile(ev.entity_id, ev.entity_type)
        baseline = prev.score if prev else 0.0

        # Веса
        score = 0.0
        if auth_fail > 0 or fail_dyn > 0.0:
            contrib = self.cfg.w_auth_fail * min(1.0, (auth_fail + fail_dyn) / 5.0)
            score += contrib
            reasons.append(f"auth_fail:{auth_fail}+dyn≈{round(fail_dyn,2)} → {round(contrib,1)}")

        if anomaly > 0.0:
            contrib = self.cfg.w_anomaly * anomaly
            score += contrib
            reasons.append(f"anomaly:{anomaly:.2f} → {round(contrib,1)}")

        if geo_mismatch:
            score += self.cfg.w_geo_mismatch
            reasons.append(f"geo_mismatch → {self.cfg.w_geo_mismatch}")

        if device_bad > 0.0:
            contrib = self.cfg.w_device_posture * device_bad
            score += contrib
            reasons.append(f"device_posture:{device_bad:.2f} → {round(contrib,1)}")

        if privilege > 0.0:
            contrib = self.cfg.w_privilege * privilege
            score += contrib
            reasons.append(f"privilege:{privilege:.2f} → {round(contrib,1)}")

        if mfa_pass:
            score += self.cfg.w_mfa_pass
            reasons.append(f"mfa_pass → {self.cfg.w_mfa_pass}")

        if replay:
            score += self.cfg.w_replay
            reasons.append(f"replay_detected → {self.cfg.w_replay}")

        if dlp_hit > 0:
            contrib = self.cfg.w_dlp * min(1.0, dlp_hit / 3.0)
            score += contrib
            reasons.append(f"dlp_hits:{dlp_hit} → {round(contrib,1)}")

        # Смешивание с базовой линией (легкое «залипание» риска)
        if baseline > 0.0:
            mix = 0.15
            score = (1 - mix) * score + mix * baseline
            reasons.append(f"baseline:{baseline:.1f} mix={mix}")

        # Нормализация 0..100
        score = max(0.0, min(100.0, score))

        # Уровень
        if score >= self.cfg.thr_critical:
            level = RiskLevel.CRITICAL
        elif score >= self.cfg.thr_high:
            level = RiskLevel.HIGH
        elif score >= self.cfg.thr_medium:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        profile = RiskProfile(
            entity_id=ev.entity_id,
            entity_type=ev.entity_type,
            score=score,
            level=level,
            reasons=reasons,
            updated_at=_now(),
        )

        MET_SCORE.observe(score)  # type: ignore
        MET_LATENCY.observe(max(0.0, _now() - t0))  # type: ignore
        return profile

# --------------------------- Воркер ---------------------------

class RiskRecalcWorker:
    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.consumer: AbstractConsumer
        self.producer: AbstractProducer
        self.storage: AbstractStorage
        self.bucket = TokenBucket(cfg.rate_bucket, cfg.rate_refill_per_sec)
        self.engine: Optional[RiskEngine] = None
        self._stop = asyncio.Event()
        self._sema = asyncio.Semaphore(cfg.max_parallel)

    async def start(self):
        # Очередь
        if self.cfg.queue_backend == "redis" and _HAS_REDIS:
            self.consumer = RedisStreamsConsumer(self.cfg.redis_url, self.cfg.queue_topic, self.cfg.queue_group)
            self.producer = RedisStreamsProducer(self.cfg.redis_url)
            backend = "redis"
        elif self.cfg.queue_backend == "kafka" and _HAS_KAFKA:
            self.consumer = KafkaConsumer(self.cfg.kafka_bootstrap, self.cfg.queue_topic, self.cfg.queue_group)
            self.producer = KafkaProducer(self.cfg.kafka_bootstrap)
            backend = "kafka"
        elif self.cfg.queue_backend == "rabbit" and _HAS_RABBIT:
            self.consumer = RabbitConsumer(self.cfg.rabbit_url, self.cfg.queue_topic)
            self.producer = RabbitProducer(self.cfg.rabbit_url)
            backend = "rabbit"
        else:
            q = InMemoryQueue()
            self.consumer = q
            self.producer = q
            backend = "memory"

        # Хранилище
        if CFG.storage_backend == "redis":
            self.storage = RedisStorage(self.cfg.redis_url)
        elif CFG.storage_backend == "sqlite":
            self.storage = SQLiteStorage(self.cfg.sqlite_path)
        else:
            self.storage = MemoryStorage()

        await self.consumer.start()
        await self.producer.start()
        await self.storage.start()
        self.engine = RiskEngine(self.cfg, self.storage)
        log.info("RiskRecalcWorker started", extra={"extra": {"queue": backend, "storage": CFG.storage_backend}})

    async def stop(self):
        self._stop.set()
        await self.consumer.stop()
        await self.producer.stop()
        await self.storage.stop()
        log.info("RiskRecalcWorker stopped")

    async def _handle_one(self, msg: QueueMessage):
        async with self._sema:
            if not await self.bucket.take():
                # перегруз — мягко отложим
                await asyncio.sleep(0.02)
            MET_CONSUMED.labels(CFG.queue_backend).inc()  # type: ignore

            # идемпотентность
            ev_json = msg.payload
            try:
                ev = RiskEvent(**ev_json)
                if await self.storage.is_duplicate_event(ev.event_id):
                    await self.consumer.ack(msg)
                    return

                t0 = _now()
                profile = await self.engine.compute(ev)  # type: ignore
                await self.storage.put_profile(profile)
                # Публикуем обновление для downstream (policy engine и т.п.)
                upd = dataclasses.asdict(profile)
                upd["type"] = "risk_profile_update"
                upd["correlation_id"] = ev.correlation_id
                await self.producer.publish(topic="risk.updates", payload=upd)

                MET_PROCESSED.inc()  # type: ignore
                GAUGE_INFLIGHT.set(max(0, self.cfg.max_parallel - self._sema._value))  # type: ignore
                await self.consumer.ack(msg)

                log.info("risk_update",
                         extra={"extra": {"entity": f"{profile.entity_type}/{profile.entity_id}",
                                          "score": round(profile.score, 1),
                                          "level": profile.level.value,
                                          "latency_ms": int((_now()-t0)*1000)}})
            except Exception as e:
                MET_FAILED.inc()  # type: ignore
                # DLQ/повтор
                retry = int(msg.meta.get("retry", 0))
                if retry >= self.cfg.dlq_max_retries:
                    # отправим в DLQ
                    await self.producer.publish(self.cfg.queue_dlx,
                                                {"error": str(e), "payload": ev_json, "ts": _now()})
                    await self.consumer.ack(msg)
                    log.error("dlq", extra={"extra": {"retries": retry, "reason": str(e)}})
                else:
                    MET_RETRIES.inc()  # type: ignore
                    # мягкий requeue
                    msg.meta["retry"] = retry + 1
                    await self.consumer.reject(msg, requeue=True)
                    log.warning("requeue", extra={"extra": {"retry": retry + 1, "reason": str(e)}})

    async def run(self):
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        while not self._stop.is_set():
            try:
                batch = await self.consumer.fetch_batch(self.cfg.batch_size, timeout=1.0)
                if not batch:
                    continue
                tasks = [asyncio.create_task(self._handle_one(m)) for m in batch]
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("run_loop_error", extra={"extra": {"err": str(e)}})
                await asyncio.sleep(0.2)

        # период на мягкое завершение
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._drain(), timeout=self.cfg.shutdown_timeout)

    async def shutdown(self):
        if not self._stop.is_set():
            log.info("shutdown_signal")
            self._stop.set()

    async def _drain(self):
        # ожидание завершения текущих задач
        while self._sema._value != self.cfg.max_parallel:
            await asyncio.sleep(0.05)

# --------------------------- CLI ---------------------------

def _print_help():
    print("Usage: python -m zero_trust.workers.risk_recalc_worker [run|oneshot]", file=sys.stderr)

async def _seed_inmemory(worker: RiskRecalcWorker):
    # тестовые события для In‑Memory режима
    if isinstance(worker.consumer, InMemoryQueue):
        now = _now()
        evs = [
            RiskEvent(event_id="e1", ts=now, entity_id="u-1", entity_type=EntityType.USER.value,
                      signals={"auth_failures": 3, "anomaly_score": 0.6, "geo_mismatch": True,
                               "device_posture_score": 0.2, "mfa_passed": False, "dlp_hits": 0}),
            RiskEvent(event_id="e2", ts=now, entity_id="u-1", entity_type=EntityType.USER.value,
                      signals={"auth_failures": 1, "anomaly_score": 0.2, "mfa_passed": True}),
            RiskEvent(event_id="e3", ts=now, entity_id="svc-pay", entity_type=EntityType.SERVICE.value,
                      signals={"privilege_sensitivity": 0.9, "replay_detected": True}),
        ]
        for ev in evs:
            await worker.producer.publish(CFG.queue_topic, dataclasses.asdict(ev))
        log.info("seeded_inmemory", extra={"extra": {"count": len(evs)}})

async def main():
    args = sys.argv[1:]
    if not args:
        _print_help()
        return
    cmd = args[0]

    worker = RiskRecalcWorker(CFG)
    await worker.start()
    try:
        if cmd == "run":
            # Если InMemory — посеем тестовые события
            await _seed_inmemory(worker)
            await worker.run()
        elif cmd == "oneshot":
            # единичный прогон одного события из stdin
            raw = sys.stdin.read()
            payload = json.loads(raw)
            msg = QueueMessage(payload, {})
            await worker._handle_one(msg)
        else:
            _print_help()
    finally:
        await worker.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
