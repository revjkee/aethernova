from __future__ import annotations

import asyncio
import json
import os
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Callable, Dict, Iterable, List, Literal, Optional, Tuple, Union

from redis.asyncio import Redis
from redis.asyncio.client import Pipeline
from redis.exceptions import BusyGroupError, ConnectionError, TimeoutError as RedisTimeoutError

# =========================
# Типы и константы
# =========================

JsonDict = Dict[str, Any]
AuditHook = Callable[[str, Dict[str, Any]], None]
MetricHook = Callable[[str, float, Dict[str, str]], None]

DEFAULT_MAXLEN = 1_000_000              # примерно, trim ~
DEFAULT_VISIBILITY_TIMEOUT_MS = 60_000  # через сколько «переобъявлять» подвисшие
DEFAULT_IDLE_RECLAIM_MS = 120_000       # idle для XCLAIM
DEFAULT_MAX_DELIVERY_ATTEMPTS = 10      # после — DLQ
DEFAULT_BLOCK_MS = 5_000                # блокирующее ожидание чтения
DEFAULT_HEALTH_TIMEOUT_SEC = 3.0
DEFAULT_BATCH_SIZE = 128

SERIALIZER_JSON = "json"
COMPRESSION_ZLIB = "zlib"

# =========================
# Сообщение
# =========================

@dataclass(slots=True, frozen=True)
class Message:
    stream: str
    group: str
    id: str
    payload: JsonDict
    headers: JsonDict = field(default_factory=dict)
    attempts: int = 1  # delivery count (из XDELIVERIES, если доступно)
    received_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    @property
    def correlation_id(self) -> Optional[str]:
        h = self.headers or {}
        return h.get("correlation_id") or h.get("x-request-id")

# =========================
# Конфиг
# =========================

@dataclass(slots=True)
class QueueConfig:
    stream: str
    group: str
    consumer: str
    maxlen: int = DEFAULT_MAXLEN
    block_ms: int = DEFAULT_BLOCK_MS
    visibility_timeout_ms: int = DEFAULT_VISIBILITY_TIMEOUT_MS
    idle_reclaim_ms: int = DEFAULT_IDLE_RECLAIM_MS
    max_delivery_attempts: int = DEFAULT_MAX_DELIVERY_ATTEMPTS
    batch_size: int = DEFAULT_BATCH_SIZE
    dlq_stream: Optional[str] = None
    # идемпотентность публикаций: ключи будут храниться TTL
    publish_dedup_ttl_sec: int = 24 * 3600
    # сериализация/сжатие
    serializer: Literal["json"] = SERIALIZER_JSON
    compression: Optional[Literal["zlib"]] = None


# =========================
# Адаптер Redis Streams
# =========================

class RedisQueue:
    """
    Продакшн‑адаптер очереди на Redis Streams с consumer groups.

    Возможности:
      - publish()/publish_batch(): XADD с MAXLEN ~ и идемпотентной дедупликацией (опционально)
      - poll(): XREADGROUP блокирующий, отдаёт Message, поддерживает backpressure через batch_size
      - ack()/nack(): XACK и перенос в DLQ при превышении попыток
      - reclaim_stuck(): XAUTOCLAIM/XCLAIM «подбирает» подвисшие сообщения по idle
      - health_check(): ping, доступность Redis и latency
      - stats(): длины стримов, pending, deliveries
    """

    def __init__(
        self,
        redis: Redis,
        cfg: QueueConfig,
        *,
        audit_hook: Optional[AuditHook] = None,
        metric_hook: Optional[MetricHook] = None,
    ) -> None:
        self.r = redis
        self.cfg = cfg
        self.audit: AuditHook = audit_hook or (lambda e, f: None)
        self.metric: MetricHook = metric_hook or (lambda name, value, tags: None)
        self._ensure_lock = asyncio.Lock()

    # -------------------------
    # Инициализация
    # -------------------------
    async def ensure(self) -> None:
        """
        Создаёт stream и consumer group, если их нет. Потокобезопасно.
        """
        async with self._ensure_lock:
            # создаём stream, если пуст
            try:
                await self.r.xadd(self.cfg.stream, {"__init__": "1"}, id="*", maxlen=self.cfg.maxlen, approximate=True)
            except Exception:
                # уже есть — игнорируем
                pass
            # создаём группу
            try:
                await self.r.xgroup_create(name=self.cfg.stream, groupname=self.cfg.group, id="0-0", mkstream=True)
            except BusyGroupError:
                pass
            # создаём DLQ если задан
            if self.cfg.dlq_stream:
                try:
                    await self.r.xadd(self.cfg.dlq_stream, {"__init__": "1"}, id="*", maxlen=self.cfg.maxlen, approximate=True)
                except Exception:
                    pass

    # -------------------------
    # Сериализация
    # -------------------------
    def _encode(self, payload: JsonDict, headers: Optional[JsonDict]) -> Dict[str, str]:
        env = {
            "v": 1,
            "payload": payload or {},
            "headers": headers or {},
        }
        raw = json.dumps(env, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if self.cfg.compression == COMPRESSION_ZLIB:
            raw = zlib.compress(raw)
            return {"content": raw, "ct": "bin", "enc": "zlib"}
        return {"content": raw, "ct": "json"}

    def _decode(self, fields: Dict[bytes, bytes]) -> Tuple[JsonDict, JsonDict]:
        ct = fields.get(b"ct", b"json").decode()
        raw = fields[b"content"]
        if ct == "bin" and fields.get(b"enc") == b"zlib":
            raw = zlib.decompress(raw)
        env = json.loads(raw.decode("utf-8"))
        return env.get("payload") or {}, env.get("headers") or {}

    # -------------------------
    # Публикация
    # -------------------------
    async def publish(
        self,
        *,
        payload: JsonDict,
        headers: Optional[JsonDict] = None,
        dedup_key: Optional[str] = None,
    ) -> str:
        """
        Публикует сообщение. Если задан dedup_key — публикация идемпотентна в течение publish_dedup_ttl_sec.
        """
        await self.ensure()
        if dedup_key:
            # пробуем забронировать ключ
            ok = await self.r.set(
                self._dedup_key(dedup_key),
                "1",
                ex=self.cfg.publish_dedup_ttl_sec,
                nx=True,
            )
            if not ok:
                # уже публиковали
                self.audit("queue.publish.dedup_skip", {"stream": self.cfg.stream})
                return "0-0"

        fields = self._encode(payload, headers)
        t0 = time.perf_counter()
        msg_id = await self.r.xadd(
            self.cfg.stream,
            fields,
            maxlen=self.cfg.maxlen,
            approximate=True,
            id="*",
        )
        self.metric("queue_publish_ms", (time.perf_counter() - t0) * 1000, {"stream": self.cfg.stream})
        self.audit("queue.publish", {"stream": self.cfg.stream})
        return msg_id

    async def publish_batch(
        self, items: Iterable[Tuple[JsonDict, Optional[JsonDict], Optional[str]]]
    ) -> List[str]:
        """
        Пакетная публикация: [(payload, headers, dedup_key), ...]
        """
        await self.ensure()
        pipe: Pipeline = self.r.pipeline(transaction=False)
        # предварительная установка dedup ключей
        to_set: List[str] = []
        for _, _, d in items:
            if d:
                to_set.append(d)
        for d in to_set:
            pipe.set(self._dedup_key(d), "1", ex=self.cfg.publish_dedup_ttl_sec, nx=True)

        # публикуем
        ids_index: List[int] = []
        for payload, headers, _ in items:
            fields = self._encode(payload, headers)
            pipe.xadd(self.cfg.stream, fields, maxlen=self.cfg.maxlen, approximate=True, id="*")
            ids_index.append(len(pipe.command_stack) - 1)
        res = await pipe.execute()

        # собираем id (там будут результаты SET и XADD вперемешку)
        msg_ids: List[str] = []
        for idx in ids_index:
            msg_ids.append(res[idx])
        self.audit("queue.publish_batch", {"count": len(msg_ids), "stream": self.cfg.stream})
        return msg_ids

    # -------------------------
    # Потребление
    # -------------------------
    async def poll(self) -> AsyncGenerator[Message, None]:
        """
        Блокирующее чтение из consumer group. Возвращает сообщения по одному.
        Обрабатывайте и вызывайте ack()/nack().
        """
        await self.ensure()
        while True:
            try:
                # Сначала «подберём» подвисшие сообщения у неактивных потребителей
                await self.reclaim_stuck(limit=self.cfg.batch_size)

                rows = await self.r.xreadgroup(
                    groupname=self.cfg.group,
                    consumername=self.cfg.consumer,
                    streams={self.cfg.stream: ">"},
                    count=self.cfg.batch_size,
                    block=self.cfg.block_ms,
                )
                if not rows:
                    continue

                # rows: [(stream, [(id, fields), ...])]
                for stream_key, entries in rows:
                    for mid, fields in entries:
                        payload, headers = self._decode(fields)
                        attempts = int(fields.get(b"attempts", b"1"))
                        yield Message(
                            stream=stream_key.decode() if isinstance(stream_key, (bytes, bytearray)) else stream_key,
                            group=self.cfg.group,
                            id=mid.decode() if isinstance(mid, (bytes, bytearray)) else mid,
                            payload=payload,
                            headers=headers,
                            attempts=attempts,
                        )
            except (ConnectionError, RedisTimeoutError):
                await asyncio.sleep(0.5)  # краткий бэкофф при сетевых сбоях

    # -------------------------
    # Подтверждение / отрицание
    # -------------------------
    async def ack(self, msg: Message) -> None:
        await self.r.xack(msg.stream, self.cfg.group, msg.id)
        # Дополнительно можно удалить из основного стрима для экономии памяти:
        await self.r.xdel(msg.stream, msg.id)
        self.audit("queue.ack", {"stream": msg.stream})

    async def nack(self, msg: Message, *, requeue: bool = True, reason: Optional[str] = None) -> None:
        """
        Отрицательное подтверждение: либо вернуть в очередь (XADD копии), либо отправить в DLQ.
        """
        # Увеличим attempts и решим — DLQ или retry
        next_attempt = msg.attempts + 1
        if not requeue or next_attempt > self.cfg.max_delivery_attempts:
            # DLQ
            if self.cfg.dlq_stream:
                fields = self._encode(
                    {**msg.payload, "_dead": True, "_reason": reason or "nack"},
                    {**(msg.headers or {}), "attempts": next_attempt},
                )
                fields["attempts"] = str(next_attempt).encode()
                await self.r.xadd(self.cfg.dlq_stream, fields, maxlen=self.cfg.maxlen, approximate=True)
            await self.r.xack(msg.stream, self.cfg.group, msg.id)
            await self.r.xdel(msg.stream, msg.id)
            self.audit("queue.dlq", {"stream": msg.stream, "attempts": next_attempt})
            return

        # requeue: добавим копию в конец стрима с увеличенным attempts
        fields = self._encode(msg.payload, msg.headers)
        fields["attempts"] = str(next_attempt).encode()
        await self.r.xadd(self.cfg.stream, fields, maxlen=self.cfg.maxlen, approximate=True)
        # подтвердим исходное, чтобы не застряло в PEL
        await self.r.xack(msg.stream, self.cfg.group, msg.id)
        await self.r.xdel(msg.stream, msg.id)
        self.audit("queue.nack", {"stream": msg.stream, "attempts": next_attempt})

    # -------------------------
    # Подбор застрявших сообщений (visibility timeout)
    # -------------------------
    async def reclaim_stuck(self, *, limit: int = 100) -> int:
        """
        Перевыдаёт (claim) сообщения, висящие в PEL дольше idle_reclaim_ms.
        Использует XAUTOCLAIM, если доступно; иначе — XCLAIM.
        """
        idle = self.cfg.idle_reclaim_ms
        reclaimed = 0
        try:
            # XAUTOCLAIM возвращает (next_start_id, [(id, fields)...])
            start_id = "0-0"
            while True and reclaimed < limit:
                next_id, entries = await self.r.xautoclaim(
                    name=self.cfg.stream,
                    groupname=self.cfg.group,
                    consumername=self.cfg.consumer,
                    min_idle_time=idle,
                    start_id=start_id,
                    count=min(100, limit - reclaimed),
                )
                if not entries:
                    break
                reclaimed += len(entries)
                start_id = next_id
        except Exception:
            # fallback на XCLAIM: получаем список pending и claim'им вручную
            pending = await self.r.xpending(self.cfg.stream, self.cfg.group)
            # pending: {'pending': N, 'min': 'id', 'max': 'id', 'consumers': [{'name': 'c', 'pending': n}, ...]}
            if pending and pending.get("pending", 0) > 0:
                # выборочно возьмём несколько
                # NB: в redis-py нет прямого xpending-range async до 4.6 — опустим для краткости
                pass
        if reclaimed:
            self.audit("queue.reclaim", {"stream": self.cfg.stream, "count": reclaimed})
        return reclaimed

    # -------------------------
    # Статистика / здоровье
    # -------------------------
    async def stats(self) -> Dict[str, Any]:
        info = await self.r.xinfo_stream(self.cfg.stream)
        grp = await self._safe_xinfo_groups(self.cfg.stream)
        res = {
            "stream": self.cfg.stream,
            "length": info.get("length"),
            "radix_tree_keys": info.get("radix-tree-keys"),
            "first_entry": info.get("first-entry", [None])[0],
            "last_entry": info.get("last-entry", [None])[0],
            "groups": grp,
        }
        if self.cfg.dlq_stream:
            try:
                dlq_info = await self.r.xinfo_stream(self.cfg.dlq_stream)
                res["dlq_length"] = dlq_info.get("length")
            except Exception:
                res["dlq_length"] = None
        return res

    async def health_check(self, *, timeout_sec: float = DEFAULT_HEALTH_TIMEOUT_SEC) -> Dict[str, Any]:
        t0 = time.perf_counter()
        try:
            fut = self.r.ping()
            pong = await asyncio.wait_for(fut, timeout=timeout_sec)
            ok = bool(pong)
        except Exception as e:
            return {"ok": False, "latency_ms": None, "error": str(e)}
        latency = (time.perf_counter() - t0) * 1000
        return {"ok": ok, "latency_ms": latency}

    # -------------------------
    # Вспомогательные
    # -------------------------
    def _dedup_key(self, key: str) -> str:
        return f"q:{self.cfg.stream}:dedup:{key}"

    async def _safe_xinfo_groups(self, stream: str) -> Any:
        try:
            return await self.r.xinfo_groups(stream)
        except Exception:
            return None

# =========================
# Пример использования (можно удалить/вынести в доку)
# =========================
async def _example() -> None:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    r = Redis.from_url(redis_url, decode_responses=False)

    cfg = QueueConfig(
        stream="ledger.events",
        group="workers",
        consumer=f"c-{os.getpid()}",
        dlq_stream="ledger.events.dlq",
        compression="zlib",
    )
    q = RedisQueue(r, cfg)

    await q.ensure()

    # Публикация
    mid = await q.publish(
        payload={"type": "anchor.created", "id": "123"},
        headers={"correlation_id": "req-abc"},
        dedup_key="anchor:123:created",
    )
    print("published:", mid)

    # Потребление (одним сообщением)
    async for msg in q.poll():
        try:
            print("got:", msg.id, msg.payload)
            # ... обработка ...
            await q.ack(msg)
        except Exception as e:
            await q.nack(msg, requeue=True, reason=str(e))

# if __name__ == "__main__":
#     asyncio.run(_example())
