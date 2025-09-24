from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Awaitable, Callable, Deque, Dict, Optional, Tuple, List

# =========================
# Опциональные метрики Prometheus
# =========================
_PROM = os.getenv("INGEST_PROMETHEUS", "true").lower() == "true"
_prom = None
if _PROM:
    try:
        from prometheus_client import Counter, Histogram, Gauge  # type: ignore

        class _Prom:
            def __init__(self):
                self.incoming = Counter("ingest_incoming_total", "Incoming envelopes", ["name"])
                self.accepted = Counter("ingest_accepted_total", "Accepted events", ["name"])
                self.rejected = Counter("ingest_rejected_total", "Rejected envelopes", ["name", "reason"])
                self.deduped = Counter("ingest_deduped_total", "Dropped as duplicate", ["name"])
                self.dispatched = Counter("ingest_dispatched_total", "Dispatched events", ["name"])
                self.failed = Counter("ingest_failed_total", "Sink failures", ["name", "kind"])
                self.dlq = Counter("ingest_dlq_total", "Dead-lettered events", ["name", "reason"])
                self.latency = Histogram("ingest_latency_seconds", "End-to-end latency (recv -> sink)", ["name"],
                                         buckets=[0.001,0.002,0.005,0.01,0.02,0.05,0.1,0.2,0.5,1,2,5])
                self.rate_tokens = Gauge("ingest_rate_tokens", "Available tokens per partition", ["name", "partition"])
                self.queue_depth = Gauge("ingest_queue_depth", "Queue depth per partition", ["name", "partition"])
        _prom = _Prom()
    except Exception:
        _prom = None


# =========================
# Исключения
# =========================
class IngestError(Exception): ...
class SignatureError(IngestError): ...
class ValidationError(IngestError): ...
class RateLimited(IngestError): ...
class DuplicateEvent(IngestError): ...
class SinkFailed(IngestError): ...


# =========================
# Модель события
# =========================
@dataclass
class EventMeta:
    source: str                   # система-источник (например, "game-gateway", "admin")
    tenant: Optional[str] = None  # сегментация по арендаторам
    partition_key: Optional[str] = None  # ключ партиции (player_id, world_id и т.п.)
    correlation_id: Optional[str] = None # сквозной id запроса/трассы
    request_id: Optional[str] = None     # id http/grpc запроса на границе
    ip: Optional[str] = None
    user_agent: Optional[str] = None

@dataclass
class WorldEvent:
    kind: str                     # тип события, например "player.move" / "quest.complete"
    payload: Dict[str, Any]       # произвольные данные события
    meta: EventMeta               # метаданные
    recv_ts: float                # время приёма на границе (client->ingest)
    server_ts: float              # время серверной обработки (ingest->sink)
    seq: Optional[int] = None     # монотонный номер источника (если есть)
    event_id: Optional[str] = None  # идемпотентный id, если задан клиентом

    def to_json(self) -> Dict[str, Any]:
        d = asdict(self)
        # dataclass EventMeta уже сериализуется через asdict
        return d

# =========================
# Сырой конверт и безопасность
# =========================
@dataclass
class EventEnvelope:
    """
    Сырой JSON конверт, приходящий на ingest‑границу.
    Обязательные поля:
      - kind: str
      - payload: dict
      - meta: dict (минимум source)
      - ts: float (unix seconds, клиентский)
      - sig: опциональная HMAC подпись: base64(hmac_sha256(secret, "{kind}.{ts}.{sha256(payload_json)}"))
    """
    data: Dict[str, Any]

    @staticmethod
    def from_bytes(blob: bytes, *, max_bytes: int = 256 * 1024) -> "EventEnvelope":
        if len(blob) > max_bytes:
            raise ValidationError("envelope too large")
        try:
            obj = json.loads(blob.decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValidationError("envelope must be JSON object")
            return EventEnvelope(obj)
        except json.JSONDecodeError as e:
            raise ValidationError(f"bad json: {e}") from e

    def validate_and_normalize(
        self,
        *,
        secret_provider: Optional[Callable[[str], Optional[bytes]]] = None,
        max_skew_sec: float = 120.0,
        require_sig: bool = False,
    ) -> Tuple[WorldEvent, str]:
        d = self.data
        # базовая схема
        kind = d.get("kind")
        payload = d.get("payload")
        meta = d.get("meta") or {}
        ts = d.get("ts")
        sig = d.get("sig")

        if not isinstance(kind, str) or not kind:
            raise ValidationError("kind required")
        if not isinstance(payload, dict):
            raise ValidationError("payload must be object")
        if not isinstance(meta, dict) or not meta.get("source"):
            raise ValidationError("meta.source required")
        if not isinstance(ts, (int, float)):
            raise ValidationError("ts (client timestamp) required")

        # защита по времени (анти‑replay)
        now = time.time()
        if abs(now - float(ts)) > max_skew_sec:
            raise ValidationError("timestamp skew too large")

        # проверка подписи (опционально)
        if require_sig or sig is not None:
            src = str(meta.get("source"))
            secret = secret_provider(src) if secret_provider else None
            if not secret:
                raise SignatureError("secret not found for source")
            payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            digest = hashlib.sha256(payload_json).hexdigest()
            msg = f"{kind}.{int(ts)}.{digest}".encode("utf-8")
            try:
                sig_bytes = base64.b64decode(sig or "", validate=True)
            except Exception:
                raise SignatureError("bad signature encoding")
            if not hmac.compare_digest(hmac.new(secret, msg, hashlib.sha256).digest(), sig_bytes):
                raise SignatureError("signature mismatch")

        # нормализация meta
        em = EventMeta(
            source=str(meta["source"]),
            tenant=meta.get("tenant"),
            partition_key=meta.get("partition_key"),
            correlation_id=meta.get("correlation_id") or str(uuid.uuid4()),
            request_id=meta.get("request_id"),
            ip=meta.get("ip"),
            user_agent=meta.get("user_agent"),
        )

        event = WorldEvent(
            kind=kind,
            payload=payload,
            meta=em,
            recv_ts=float(ts),
            server_ts=now,
            seq=d.get("seq"),
            event_id=d.get("event_id"),
        )
        # вычисление ключа партиции по умолчанию
        partition = em.partition_key or _default_partition(kind, payload, em)
        return event, partition

def _default_partition(kind: str, payload: Dict[str, Any], meta: EventMeta) -> str:
    # приоритет: явный ключ из meta > player_id > world_id > tenant > source
    for k in ("player_id", "actor_id", "wallet_id", "world_id", "room_id"):
        v = payload.get(k)
        if isinstance(v, (str, int)):
            return str(v)
    if meta.tenant:
        return f"tenant:{meta.tenant}"
    return f"source:{meta.source}"


# =========================
# Дедупликация (идемпотентность)
# =========================
class IdempotencyStore:
    """
    Абстракция внешнего хранилища идемпотентных event_id.
    Ожидаемый контракт: set_if_absent(key, ttl_sec) -> bool (True если записали; False если уже было).
    """
    async def set_if_absent(self, key: str, ttl_sec: int) -> bool:  # pragma: no cover - интерфейс
        raise NotImplementedError

class _InMemoryIdemp(IdempotencyStore):
    def __init__(self, capacity: int = 200_000) -> None:
        self._set: set[str] = set()
        self._lru: Deque[str] = deque(maxlen=capacity)

    async def set_if_absent(self, key: str, ttl_sec: int) -> bool:
        # ttl игнорируется в in‑memory; достаточно LRU
        if key in self._set:
            return False
        self._set.add(key)
        self._lru.append(key)
        if len(self._lru) == self._lru.maxlen:
            old = self._lru.popleft()
            self._set.discard(old)
        return True


# =========================
# Token-bucket лимитирование
# =========================
@dataclass
class _Bucket:
    tokens: float
    last: float

class RateLimiter:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = max(0.001, float(rate_per_sec))
        self.burst = max(1, int(burst))
        self._buckets: Dict[str, _Bucket] = {}

    def allow(self, key: str, *, now: Optional[float] = None) -> bool:
        t = now or time.time()
        b = self._buckets.get(key)
        if not b:
            b = _Bucket(tokens=float(self.burst), last=t)
            self._buckets[key] = b
        # накапливаем токены
        delta = t - b.last
        b.tokens = min(self.burst, b.tokens + delta * self.rate)
        b.last = t
        if b.tokens >= 1.0:
            b.tokens -= 1.0
            return True
        return False

    def tokens(self, key: str) -> float:
        b = self._buckets.get(key)
        return b.tokens if b else float(self.burst)


# =========================
# Маршрутизатор/синкапы
# =========================
SinkFn = Callable[[str, WorldEvent], Awaitable[None]]
BatchSinkFn = Callable[[str, List[WorldEvent]], Awaitable[None]]

class Router:
    """Обёртка над пользовательскими sink‑функциями."""
    def __init__(self, sink: Optional[SinkFn] = None, batch_sink: Optional[BatchSinkFn] = None) -> None:
        self.sink = sink
        self.batch_sink = batch_sink

    async def dispatch(self, partition: str, evs: List[WorldEvent]) -> None:
        if not evs:
            return
        if self.batch_sink:
            await self.batch_sink(partition, evs)
        elif self.sink:
            for e in evs:
                await self.sink(partition, e)
        else:
            raise SinkFailed("no sink configured")


# =========================
# DLQ интерфейс
# =========================
DLQFn = Callable[[Dict[str, Any], str], Awaitable[None]]  # (envelope_json, reason)

async def _noop_dlq(envelope: Dict[str, Any], reason: str) -> None:
    return


# =========================
# Ingest‑пайплайн
# =========================
@dataclass
class IngestConfig:
    name: str = "world-ingest"
    queue_capacity: int = 100_000
    max_batch: int = 256
    max_batch_bytes: int = 256 * 1024
    max_interval: float = 0.050
    require_signature: bool = False
    skew_sec: float = 120.0
    idemp_ttl_sec: int = 3600
    rate_per_sec: float = 2_000.0   # по умолчанию 2k событий/сек на партицию
    rate_burst: int = 2_000
    retry_max: int = 5
    retry_base_delay: float = 0.01
    retry_multiplier: float = 2.0
    retry_max_delay: float = 0.250
    # функции окружения
    secret_provider: Optional[Callable[[str], Optional[bytes]]] = None
    partition_of: Optional[Callable[[WorldEvent], str]] = None

class WorldEventIngest:
    """
    Асинхронный ingestion‑конвейер:
      submit(bytes) -> очередь -> нормализация/валидация -> дедуп/лимиты -> батч‑доставка в sink/DLQ.
    """
    def __init__(
        self,
        config: IngestConfig,
        router: Router,
        *,
        idempotency_store: Optional[IdempotencyStore] = None,
        dlq: DLQFn = _noop_dlq,
    ) -> None:
        self.cfg = config
        self.router = router
        self.idemp = idempotency_store or _InMemoryIdemp()
        self.dlq = dlq
        self._limiter = RateLimiter(self.cfg.rate_per_sec, self.cfg.rate_burst)
        self._queue: asyncio.Queue[Tuple[bytes, float]] = asyncio.Queue(self.cfg.queue_capacity)
        self._closed = False
        self._task: Optional[asyncio.Task] = None
        # очереди по партициям
        self._by_part: Dict[str, Deque[Tuple[WorldEvent, int]]] = defaultdict(deque)  # (event, size_bytes)

    async def __aenter__(self) -> "WorldEventIngest":
        self._task = asyncio.create_task(self._run_loop(), name=f"{self.cfg.name}-loop")
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    # ----- Публичный вход -----
    async def submit(self, raw: bytes) -> None:
        if self._closed:
            raise IngestError("ingest closed")
        if _prom:
            _prom.incoming.labels(self.cfg.name).inc()
        try:
            self._queue.put_nowait((raw, time.time()))
        except asyncio.QueueFull:
            # backpressure: в DLQ причину дадим "backpressure"
            if _prom:
                _prom.rejected.labels(self.cfg.name, "backpressure").inc()
            env = self._parse_unsafe(raw)
            await self._safe_dlq(env, "backpressure")

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # финальный флаш
        await self._flush_all(force=True)

    # ----- Основной цикл -----
    async def _run_loop(self) -> None:
        try:
            last_flush = time.time()
            while not self._closed:
                timeout = self.cfg.max_interval
                try:
                    raw, recv_wall = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    # по таймеру — флаш
                    await self._flush_all()
                    last_flush = time.time()
                    continue

                # обработка одного конверта
                await self._process_one(raw, recv_wall)

                # периодический флаш по интервалу
                now = time.time()
                if (now - last_flush) >= self.cfg.max_interval:
                    await self._flush_all()
                    last_flush = now
        except asyncio.CancelledError:
            return

    async def _process_one(self, raw: bytes, recv_wall: float) -> None:
        try:
            env = EventEnvelope.from_bytes(raw, max_bytes=self.cfg.max_batch_bytes)
            event, partition = env.validate_and_normalize(
                secret_provider=self.cfg.secret_provider,
                max_skew_sec=self.cfg.skew_sec,
                require_sig=self.cfg.require_signature,
            )
        except SignatureError as e:
            if _prom:
                _prom.rejected.labels(self.cfg.name, "signature").inc()
            await self._safe_dlq(self._parse_unsafe(raw), f"signature:{e}")
            return
        except ValidationError as e:
            if _prom:
                _prom.rejected.labels(self.cfg.name, "validation").inc()
            await self._safe_dlq(self._parse_unsafe(raw), f"validation:{e}")
            return
        except Exception as e:
            if _prom:
                _prom.rejected.labels(self.cfg.name, "parse").inc()
            await self._safe_dlq(self._parse_unsafe(raw), f"parse:{e}")
            return

        # кастомный ключ партиции при необходимости
        if self.cfg.partition_of:
            try:
                partition = self.cfg.partition_of(event) or partition
            except Exception:
                pass

        # дедуп по event_id, если есть
        if event.event_id:
            ok = await self.idemp.set_if_absent(self._idemp_key(event), self.cfg.idemp_ttl_sec)
            if not ok:
                if _prom:
                    _prom.deduped.labels(self.cfg.name).inc()
                return

        # rate‑limit
        if not self._limiter.allow(partition):
            if _prom:
                _prom.rejected.labels(self.cfg.name, "rate_limit").inc()
                _prom.rate_tokens.labels(self.cfg.name, partition).set(self._limiter.tokens(partition))
            await self._safe_dlq(event.to_json(), "rate_limit")
            return

        # постановка в партиционную очередь
        body = json.dumps(event.to_json(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self._by_part[partition].append((event, len(body)))
        if _prom:
            _prom.accepted.labels(self.cfg.name).inc()
            _prom.queue_depth.labels(self.cfg.name, partition).set(len(self._by_part[partition]))

        # условия немедленного флаша по размеру
        await self._maybe_flush_partition(partition)

        # латентность от границы до «ingest принят»
        if _prom:
            _prom.latency.labels(self.cfg.name).observe(max(0.0, event.server_ts - event.recv_ts))

    async def _maybe_flush_partition(self, partition: str) -> None:
        q = self._by_part[partition]
        if not q:
            return
        # размер батча и байт
        total_n = min(len(q), self.cfg.max_batch)
        total_b = 0
        for i in range(total_n):
            total_b += q[i][1]
            if total_b >= self.cfg.max_batch_bytes or (i + 1) >= self.cfg.max_batch:
                await self._flush_partition(partition, i + 1)
                return

    async def _flush_all(self, *, force: bool = False) -> None:
        tasks: List[asyncio.Task] = []
        for pk, q in list(self._by_part.items()):
            if not q:
                continue
            if force or len(q) >= 1:
                tasks.append(asyncio.create_task(self._flush_partition(pk)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=False)

    async def _flush_partition(self, pk: str, take: Optional[int] = None) -> None:
        q = self._by_part[pk]
        if not q:
            return
        evs: List[WorldEvent] = []
        bytes_size = 0
        limit = take if take is not None else min(len(q), self.cfg.max_batch)
        while q and len(evs) < limit:
            ev, size = q.popleft()
            evs.append(ev); bytes_size += size
        if _prom:
            _prom.queue_depth.labels(self.cfg.name, pk).set(len(q))
        # ретраи доставки
        attempt = 0
        base = self.cfg.retry_base_delay
        mult = self.cfg.retry_multiplier
        maxd = self.cfg.retry_max_delay
        while True:
            try:
                await self.router.dispatch(pk, evs)
                if _prom:
                    _prom.dispatched.labels(self.cfg.name).inc(len(evs))
                return
            except Exception as e:
                attempt += 1
                if _prom:
                    _prom.failed.labels(self.cfg.name, type(e).__name__).inc()
                if attempt > self.cfg.retry_max:
                    # DLQ на невосстановимые ошибки
                    for ev in evs:
                        await self._safe_dlq(ev.to_json(), f"sink:{type(e).__name__}")
                    return
                delay = min(maxd, base * (mult ** (attempt - 1)))
                # небольшой джиттер
                jitter = 0.8 + 0.4 * (os.urandom(1)[0] / 255.0)
                await asyncio.sleep(delay * jitter)

    # ----- Вспомогательное -----
    def _idemp_key(self, ev: WorldEvent) -> str:
        # составной ключ: имя пайплайна + источник + event_id
        return f"{self.cfg.name}:{ev.meta.source}:{ev.event_id}"

    async def _safe_dlq(self, envelope_json: Dict[str, Any], reason: str) -> None:
        try:
            await self.dlq(envelope_json, reason)
            if _prom:
                _prom.dlq.labels(self.cfg.name, reason.split(":")[0]).inc()
        except Exception:
            # DLQ не должен ломать ingest
            pass

    @staticmethod
    def _parse_unsafe(raw: bytes) -> Dict[str, Any]:
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {"_raw": "<unparseable>"}
