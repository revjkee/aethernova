# -*- coding: utf-8 -*-
"""
physical_integration/protocols/amqp_client.py

Промышленный AMQP-клиент для RabbitMQ (AMQP 0-9-1) на базе aio-pika.

Зависимости:
  aio-pika>=9.4
  pamqp>=3.2 (транзитивно)
  prometheus-client>=0.16 (опционально)
  opentelemetry-api/opentelemetry-sdk (опционально для трейсов)

Основные возможности:
- Robust-подключение с TLS, экспоненциальный бэкофф + джиттер.
- Publisher confirms, mandatory publish, обработка returned messages.
- Декларация топологии: exchanges/queues/bindings, DLX + retry-очереди по TTL.
- Потребление: QoS, пул воркеров, идемпотентность (x-idempotency-key), backoff и DLQ.
- Метрики Prometheus и OTel-трейсинг (если установлены).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

import aio_pika
from aio_pika import Message, DeliveryMode, ExchangeType, IncomingMessage, RobustConnection, RobustChannel

# ------------------------------------------------------------------------------
# Опциональные зависимости
# ------------------------------------------------------------------------------
try:
    from prometheus_client import Counter, Histogram, Gauge
except Exception:  # pragma: no cover
    class _Noop:
        def __init__(self, *a, **k): ...
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): ...
        def observe(self, *a, **k): ...
        def set(self, *a, **k): ...
    Counter = Histogram = Gauge = _Noop  # type: ignore

try:
    from opentelemetry import trace
    _TRACER = trace.get_tracer(__name__)
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False
    _TRACER = None  # type: ignore

# ------------------------------------------------------------------------------
# Метрики
# ------------------------------------------------------------------------------
AMQP_PUBLISHED = Counter("amqp_published_total", "Published messages", ["exchange", "outcome"])
AMQP_CONSUMED = Counter("amqp_consumed_total", "Consumed messages", ["queue", "outcome"])
AMQP_PROCESS_LAT = Histogram("amqp_consume_latency_seconds", "Handler latency", ["queue", "outcome"],
                             buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5))
AMQP_RECONNECTS = Counter("amqp_reconnects_total", "Reconnect attempts", ["outcome"])
AMQP_INFLIGHT = Gauge("amqp_inflight_handlers", "In-flight handlers", ["queue"])

# ------------------------------------------------------------------------------
# Конфигурация
# ------------------------------------------------------------------------------
@dataclass
class AMQPSettings:
    uri: str = field(default_factory=lambda: os.getenv("AMQP_URL", "amqps://guest:guest@localhost:5671/"))
    client_name: str = "physical-integration-core"
    heartbeat: int = 30
    timeout: int = 10
    prefetch_count: int = 32
    publisher_confirms: bool = True
    reconnect_min_s: float = 0.5
    reconnect_max_s: float = 10.0
    reconnect_factor: float = 2.0
    reconnect_jitter_s: float = 0.333
    ssl_enable: bool = True
    ssl_verify: bool = True
    ssl_cafile: Optional[str] = None
    ssl_certfile: Optional[str] = None
    ssl_keyfile: Optional[str] = None
    name_prefix: str = field(default_factory=lambda: os.getenv("AMQP_NAME_PREFIX", "pic"))
    enable_metrics: bool = True


@dataclass
class ExchangeCfg:
    name: str
    type: ExchangeType = ExchangeType.TOPIC
    durable: bool = True
    auto_delete: bool = False
    internal: bool = False
    passive: bool = False
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QueueCfg:
    name: str
    durable: bool = True
    exclusive: bool = False
    auto_delete: bool = False
    passive: bool = False
    arguments: Dict[str, Any] = field(default_factory=dict)  # x-*, например DLX/TTL
    # Автоматическая настройка DLQ и retry
    with_retry: bool = True
    retry_ttl_ms: int = 15000
    max_retries: int = 5


@dataclass
class BindingCfg:
    exchange: str
    queue: str
    routing_key: str = "#"
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TopologyConfig:
    exchanges: List[ExchangeCfg] = field(default_factory=list)
    queues: List[QueueCfg] = field(default_factory=list)
    bindings: List[BindingCfg] = field(default_factory=list)


@dataclass
class PublishOptions:
    routing_key: str
    message: Union[bytes, str, Dict[str, Any]]
    headers: Dict[str, Any] = field(default_factory=dict)
    content_type: Optional[str] = None
    persistent: bool = True
    expiration_ms: Optional[int] = None
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None
    mandatory: bool = True
    idempotency_key: Optional[str] = None


# ------------------------------------------------------------------------------
# Идемпотентность
# ------------------------------------------------------------------------------
class IdempotencyStore:
    async def seen(self, key: str) -> bool:
        raise NotImplementedError
    async def mark(self, key: str, ttl_s: int = 900) -> None:
        raise NotImplementedError


class InMemoryIdempotencyStore(IdempotencyStore):
    def __init__(self) -> None:
        self._data: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def seen(self, key: str) -> bool:
        now = time.time()
        async with self._lock:
            exp = self._data.get(key)
            if not exp:
                return False
            if exp < now:
                self._data.pop(key, None)
                return False
            return True

    async def mark(self, key: str, ttl_s: int = 900) -> None:
        async with self._lock:
            self._data[key] = time.time() + ttl_s


# ------------------------------------------------------------------------------
# Результат обработки
# ------------------------------------------------------------------------------
class HandleResult:
    __slots__ = ("_kind", "requeue", "delay_ms", "detail")

    def __init__(self, kind: str, requeue: bool = False, delay_ms: Optional[int] = None, detail: str = ""):
        self._kind = kind
        self.requeue = requeue
        self.delay_ms = delay_ms
        self.detail = detail

    @staticmethod
    def ack(detail: str = "") -> "HandleResult":
        return HandleResult("ack", detail=detail)

    @staticmethod
    def nack(requeue: bool = False, detail: str = "") -> "HandleResult":
        return HandleResult("nack", requeue=requeue, detail=detail)

    @staticmethod
    def retry(delay_ms: int) -> "HandleResult":
        return HandleResult("retry", requeue=False, delay_ms=delay_ms)


# ------------------------------------------------------------------------------
# Вспомогательные функции
# ------------------------------------------------------------------------------
def _build_ssl_context(s: AMQPSettings) -> Optional[ssl.SSLContext]:
    if not s.ssl_enable:
        return None
    ctx = ssl.create_default_context(cafile=s.ssl_cafile)
    if not s.ssl_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if s.ssl_certfile and s.ssl_keyfile:
        ctx.load_cert_chain(certfile=s.ssl_certfile, keyfile=s.ssl_keyfile)
    return ctx


def _exp_backoff_gen(min_s: float, max_s: float, factor: float, jitter_s: float):
    delay = min_s
    while True:
        yield delay + random.uniform(0, jitter_s)
        delay = min(delay * factor, max_s)


def _json_dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _now_ms() -> int:
    return int(time.time() * 1000)


# ------------------------------------------------------------------------------
# Основной клиент
# ------------------------------------------------------------------------------
class AMQPClient:
    def __init__(
        self,
        settings: AMQPSettings,
        topology: Optional[TopologyConfig] = None,
        idem_store: Optional[IdempotencyStore] = None,
        logger_name: str = "amqp",
    ) -> None:
        self.s = settings
        self.top = topology or TopologyConfig()
        self.idem = idem_store or InMemoryIdempotencyStore()
        self.log = logging.getLogger(logger_name)
        self._conn: Optional[RobustConnection] = None
        self._chan: Optional[RobustChannel] = None
        self._exchanges: Dict[str, aio_pika.exchange.Exchange] = {}
        self._queues: Dict[str, aio_pika.queue.Queue] = {}
        self._return_lock = asyncio.Lock()
        self._closed = asyncio.Event()
        self._consumers: List[asyncio.Task] = []

    # ------------------------ Connection lifecycle -------------------------

    async def connect(self) -> None:
        ssl_ctx = _build_ssl_context(self.s)
        backoff = _exp_backoff_gen(self.s.reconnect_min_s, self.s.reconnect_max_s, self.s.reconnect_factor, self.s.reconnect_jitter_s)
        while True:
            try:
                self.log.info("AMQP connecting to %s", self.s.uri)
                self._conn = await aio_pika.connect_robust(
                    self.s.uri,
                    client_properties={"connection_name": self.s.client_name},
                    timeout=self.s.timeout,
                    heartbeat=self.s.heartbeat,
                    ssl=ssl_ctx is not None,
                    ssl_context=ssl_ctx,
                )
                self._chan = await self._conn.channel(publisher_confirms=self.s.publisher_confirms)
                await self._chan.set_qos(prefetch_count=self.s.prefetch_count)
                self._chan.add_on_return_callback(self._on_returned_message)
                AMQP_RECONNECTS.labels("ok").inc()
                self.log.info("AMQP connected")
                return
            except Exception as e:
                AMQP_RECONNECTS.labels("fail").inc()
                delay = next(backoff)
                self.log.warning("AMQP connect failed: %s. Retry in %.2fs", e, delay)
                await asyncio.sleep(delay)

    async def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        for t in self._consumers:
            t.cancel()
        await asyncio.gather(*self._consumers, return_exceptions=True)
        try:
            if self._chan:
                await self._chan.close()
        finally:
            if self._conn:
                await self._conn.close()
        self.log.info("AMQP closed")

    # ---------------------------- Topology ---------------------------------

    def _full_name(self, name: str) -> str:
        return f"{self.s.name_prefix}.{name}" if self.s.name_prefix else name

    async def declare_topology(self) -> None:
        assert self._chan is not None, "Channel not ready"
        # Авто-DLX/Retry для очередей
        for q in self.top.queues:
            if q.with_retry:
                dlx_name = self._full_name(f"{q.name}.dlx")
                retry_name = self._full_name(f"{q.name}.retry")
                main_x_name = self._full_name(f"{q.name}.x")
                # Главный обменник для простоты
                if main_x_name not in [self._full_name(x.name) for x in self.top.exchanges]:
                    self.top.exchanges.append(ExchangeCfg(name=f"{q.name}.x", type=ExchangeType.TOPIC))
                # DLX
                if dlx_name not in [self._full_name(x.name) for x in self.top.exchanges]:
                    self.top.exchanges.append(ExchangeCfg(name=f"{q.name}.dlx", type=ExchangeType.TOPIC))
                # Retry
                if retry_name not in [self._full_name(x.name) for x in self.top.exchanges]:
                    self.top.exchanges.append(ExchangeCfg(name=f"{q.name}.retry", type=ExchangeType.TOPIC))

        # Обменники
        for x in self.top.exchanges:
            ex = await self._chan.declare_exchange(
                self._full_name(x.name), x.type, durable=x.durable, auto_delete=x.auto_delete,
                internal=x.internal, passive=x.passive, arguments=x.arguments
            )
            self._exchanges[x.name] = ex

        # Очереди
        for q in self.top.queues:
            args = dict(q.arguments)
            if q.with_retry:
                args.setdefault("x-dead-letter-exchange", self._full_name(f"{q.name}.dlx"))
                # retry очередь получит TTL и вернет в основной exchange
                retry_q_name = self._full_name(f"{q.name}.retry.q")
                await self._declare_retry(q, retry_q_name)
            queue = await self._chan.declare_queue(
                self._full_name(q.name), durable=q.durable, exclusive=q.exclusive,
                auto_delete=q.auto_delete, passive=q.passive, arguments=args
            )
            self._queues[q.name] = queue

        # Биндинги
        for b in self.top.bindings:
            ex = self._exchanges[b.exchange]
            q = self._queues[b.queue]
            await q.bind(ex, routing_key=b.routing_key, arguments=b.arguments)

        # Биндим DLX на основную очередь и retry на основной обменник
        for q in self.top.queues:
            if q.with_retry:
                # Все недоставленные/некорректные попадают в DLX с ключом "<rk>.dead"
                dlx = self._exchanges[f"{q.name}.dlx"]
                main_q = self._queues[q.name]
                await main_q.bind(self._exchanges[f"{q.name}.x"], routing_key="#")
                # Retry-очередь уже создана и вернет сообщение через TTL в основной exchange
        self.log.info("AMQP topology declared")

    async def _declare_retry(self, q: QueueCfg, retry_q_name: str) -> None:
        # Retry exchange и очередь
        retry_x = await self._chan.declare_exchange(self._full_name(f"{q.name}.retry"), ExchangeType.TOPIC, durable=True)
        self._exchanges[f"{q.name}.retry"] = retry_x
        await self._chan.declare_queue(
            retry_q_name,
            durable=True,
            arguments={
                "x-message-ttl": q.retry_ttl_ms,
                "x-dead-letter-exchange": self._full_name(f"{q.name}.x"),
            },
        )
        # Биндим retry очередь на retry exchange
        await self._queues_bind_runtime(retry_q_name, retry_x)

    async def _queues_bind_runtime(self, queue_name_full: str, ex: aio_pika.Exchange) -> None:
        q = await self._chan.get_queue(queue_name_full, ensure=True)
        await q.bind(ex, "#")

    # ---------------------------- Publishing --------------------------------

    async def publish(self, exchange: str, opts: PublishOptions) -> None:
        assert self._chan is not None, "Channel not ready"
        ex = self._exchanges.get(exchange)
        if not ex:
            ex = await self._chan.get_exchange(self._full_name(exchange), ensure=True)
            self._exchanges[exchange] = ex

        body: bytes
        content_type = opts.content_type
        if isinstance(opts.message, bytes):
            body = opts.message
            content_type = content_type or "application/octet-stream"
        elif isinstance(opts.message, str):
            body = opts.message.encode("utf-8")
            content_type = content_type or "text/plain; charset=utf-8"
        else:
            body = _json_dumps(opts.message)
            content_type = content_type or "application/json"

        headers = dict(opts.headers)
        if opts.idempotency_key:
            headers.setdefault("x-idempotency-key", opts.idempotency_key)

        msg = Message(
            body=body,
            delivery_mode=DeliveryMode.PERSISTENT if opts.persistent else DeliveryMode.NOT_PERSISTENT,
            content_type=content_type,
            headers=headers,
            correlation_id=opts.correlation_id,
            reply_to=opts.reply_to,
            expiration=opts.expiration_ms / 1000 if opts.expiration_ms else None,
            timestamp=time.time(),
            app_id=self.s.client_name,
        )

        span_ctx = None
        if _OTEL:
            span_ctx = _TRACER.start_as_current_span("amqp.publish", attributes={
                "messaging.system": "rabbitmq",
                "messaging.destination": self._full_name(exchange),
                "messaging.rabbitmq.routing_key": opts.routing_key,
                "messaging.message_payload_size_bytes": len(body),
            })
        try:
            if span_ctx:
                with span_ctx:
                    await ex.publish(msg, routing_key=opts.routing_key, mandatory=opts.mandatory)
            else:
                await ex.publish(msg, routing_key=opts.routing_key, mandatory=opts.mandatory)
            AMQP_PUBLISHED.labels(exchange=exchange, outcome="ok").inc()
        except aio_pika.exceptions.DeliveryError as e:
            AMQP_PUBLISHED.labels(exchange=exchange, outcome="returned").inc()
            raise e
        except Exception:
            AMQP_PUBLISHED.labels(exchange=exchange, outcome="error").inc()
            raise

    async def _on_returned_message(self, message: IncomingMessage) -> None:
        async with self._return_lock:
            self.log.error("Returned message: rk=%s, headers=%s, reply_code=%s, reply_text=%s",
                           message.routing_key, message.headers, message.reply_code, message.reply_text)
            try:
                await message.ack()  # это Returned, не доставлено никуда; фиктивный ack
            except Exception:
                pass

    # ---------------------------- Consuming ---------------------------------

    async def consume(
        self,
        queue: str,
        handler: Callable[[IncomingMessage], Awaitable[HandleResult]],
        concurrency: int = 8,
        dlq_exchange: Optional[str] = None,
        max_retries: Optional[int] = None,
    ) -> None:
        """
        Запускает воркеров-читателей очереди. Блокирует до cancel() или close().
        """
        assert self._chan is not None, "Channel not ready"
        q = self._queues.get(queue)
        if not q:
            q = await self._chan.get_queue(self._full_name(queue), ensure=True)
            self._queues[queue] = q

        if max_retries is None:
            # По умолчанию: берем из конфигурации очереди
            qcfg = next((qq for qq in self.top.queues if qq.name == queue), None)
            max_retries = qcfg.max_retries if qcfg else 5

        dlx = dlq_exchange or f"{queue}.dlx"

        async def _worker(idx: int):
            AMQP_INFLIGHT.labels(queue=queue).set(0)
            async with q.iterator() as it:
                async for m in it:
                    AMQP_INFLIGHT.labels(queue=queue).inc()
                    start = time.perf_counter()
                    try:
                        # Идемпотентность
                        idem_key = m.headers.get("x-idempotency-key") or m.message_id
                        if idem_key and await self.idem.seen(str(idem_key)):
                            await m.ack()
                            AMQP_CONSUMED.labels(queue=queue, outcome="dup").inc()
                            continue

                        # Обработка
                        res = await handler(m)

                        if res._kind == "ack":
                            await m.ack()
                            if idem_key:
                                await self.idem.mark(str(idem_key))
                            AMQP_CONSUMED.labels(queue=queue, outcome="ack").inc()
                            AMQP_PROCESS_LAT.labels(queue=queue, outcome="ack").observe(time.perf_counter() - start)

                        elif res._kind == "retry":
                            # Увеличим счетчик ретраев и отправим в retry exchange с TTL
                            retry_count = int(m.headers.get("x-retry-count", 0)) + 1
                            if retry_count > max_retries:
                                await self._to_dlq(queue, m, dlx, reason="max_retries_exceeded")
                                await m.ack()
                                AMQP_CONSUMED.labels(queue=queue, outcome="dlq").inc()
                            else:
                                await self._to_retry(queue, m, delay_ms=res.delay_ms or 1000, retry_count=retry_count)
                                await m.ack()
                                AMQP_CONSUMED.labels(queue=queue, outcome="retry").inc()
                            AMQP_PROCESS_LAT.labels(queue=queue, outcome="retry").observe(time.perf_counter() - start)

                        else:  # nack
                            await m.nack(requeue=res.requeue)
                            AMQP_CONSUMED.labels(queue=queue, outcome="nack_requeue" if res.requeue else "nack_drop").inc()
                            AMQP_PROCESS_LAT.labels(queue=queue, outcome="nack").observe(time.perf_counter() - start)

                    except Exception as e:  # жесткий пад обработки -> DLQ
                        self.log.exception("Handler error, routing to DLQ")
                        try:
                            await self._to_dlq(queue, m, dlx, reason=str(e))
                            await m.ack()
                            AMQP_CONSUMED.labels(queue=queue, outcome="dlq").inc()
                        except Exception:
                            await m.reject(requeue=False)
                            AMQP_CONSUMED.labels(queue=queue, outcome="reject").inc()
                    finally:
                        AMQP_INFLIGHT.labels(queue=queue).dec()

        # Запуск пула
        workers = [asyncio.create_task(_worker(i), name=f"amqp-consumer-{queue}-{i}") for i in range(concurrency)]
        self._consumers.extend(workers)
        await asyncio.gather(*workers)

    async def _to_retry(self, queue: str, m: IncomingMessage, delay_ms: int, retry_count: int) -> None:
        # Публикуем в retry exchange с TTL на уровне очереди
        ex = self._exchanges.get(f"{queue}.retry")
        if not ex:
            ex = await self._chan.get_exchange(self._full_name(f"{queue}.retry"), ensure=True)
            self._exchanges[f"{queue}.retry"] = ex
        headers = dict(m.headers or {})
        headers["x-retry-count"] = retry_count
        body = m.body
        msg = Message(
            body=body,
            headers=headers,
            delivery_mode=m.delivery_mode or DeliveryMode.PERSISTENT,
            content_type=m.content_type,
            correlation_id=m.correlation_id,
            reply_to=m.reply_to,
            app_id=self.s.client_name,
            timestamp=time.time(),
        )
        await ex.publish(msg, routing_key=m.routing_key or "")

    async def _to_dlq(self, queue: str, m: IncomingMessage, dlx: str, reason: str) -> None:
        ex = self._exchanges.get(dlx)
        if not ex:
            ex = await self._chan.get_exchange(self._full_name(dlx), ensure=True)
            self._exchanges[dlx] = ex
        headers = dict(m.headers or {})
        headers["x-dead-letter-reason"] = reason
        headers["x-dead-letter-ts"] = _now_ms()
        msg = Message(
            body=m.body,
            headers=headers,
            delivery_mode=m.delivery_mode or DeliveryMode.PERSISTENT,
            content_type=m.content_type,
            correlation_id=m.correlation_id,
            reply_to=m.reply_to,
            app_id=self.s.client_name,
            timestamp=time.time(),
        )
        await ex.publish(msg, routing_key=(m.routing_key or "") + ".dead")

# ------------------------------------------------------------------------------
# Пример минимальной инициализации (справочно; не исполняется при импорте)
# ------------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    settings = AMQPSettings(
        uri=os.getenv("AMQP_URL", "amqps://guest:guest@localhost:5671/"),
        ssl_cafile=os.getenv("AMQP_CA"),
        ssl_certfile=os.getenv("AMQP_CERT"),
        ssl_keyfile=os.getenv("AMQP_KEY"),
        name_prefix=os.getenv("AMQP_NAME_PREFIX", "pic"),
    )

    topology = TopologyConfig(
        exchanges=[
            ExchangeCfg(name="telemetry.x", type=ExchangeType.TOPIC),
            ExchangeCfg(name="telemetry.dlx", type=ExchangeType.TOPIC),
        ],
        queues=[
            QueueCfg(name="telemetry.q", with_retry=True, retry_ttl_ms=10000, max_retries=5),
        ],
        bindings=[
            BindingCfg(exchange="telemetry.x", queue="telemetry.q", routing_key="sites.*.plc.#"),
        ],
    )

    client = AMQPClient(settings, topology)

    async def handler(msg: IncomingMessage) -> HandleResult:
        try:
            payload = json.loads(msg.body)
            # Ваша бизнес-логика...
            return HandleResult.ack()
        except json.JSONDecodeError:
            return HandleResult.nack(requeue=False)
        except Exception:
            return HandleResult.retry(delay_ms=5000)

    async def main():
        await client.connect()
        await client.declare_topology()
        # Пример публикации
        await client.publish(
            "telemetry.x",
            PublishOptions(routing_key="sites.edge-01.plc.energy", message={"k": "v"}, idempotency_key="demo-1"),
        )
        # Потребление
        consume_task = asyncio.create_task(client.consume("telemetry.q", handler, concurrency=8))
        await asyncio.sleep(5)
        consume_task.cancel()
        await client.close()

    asyncio.run(main())
