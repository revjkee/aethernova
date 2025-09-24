# -*- coding: utf-8 -*-
"""
physical_integration/edge/gateway.py

Промышленный Edge Gateway для physical-integration-core.
Функции:
- Жизненный цикл: start/stop, устойчивые переподключения к AMQP.
- Конфигурация YAML: загрузка, валидация ключевых полей, hot-reload (watcher).
- Шина: AMQP (publisher confirms, mandatory, retry/DLQ), команда-подписки из очереди.
- Обработка: плагинная модель Processor (start/stop/handle), bounded asyncio.Queue (backpressure).
- Наблюдаемость: /health/live, /health/ready, /metrics (Prometheus), heartbeat, OTel-трейсы (опц).
- Надёжность: идемпотентность на публикациях, аккуратный shutdown (SIGINT/SIGTERM), тайм-ауты.

Зависимости:
  aio-pika>=9.4
  PyYAML>=6.0
  fastapi>=0.103, uvicorn>=0.23
  prometheus-client>=0.16 (опц.), opentelemetry-api/opentelemetry-sdk (опц.)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

# --- Опциональные библиотеки и полифилы ---
try:
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover
    class BaseModel:  # type: ignore
        def __init__(self, **kw): [setattr(self, k, v) for k, v in kw.items()]
        def model_dump(self): return self.__dict__
    def Field(default=None, **kw): return default

try:
    import yaml
except Exception as e:  # pragma: no cover
    raise RuntimeError("PyYAML не установлен: pip install pyyaml") from e

try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse, PlainTextResponse
    import uvicorn
except Exception as e:  # pragma: no cover
    raise RuntimeError("FastAPI/uvicorn не установлены: pip install fastapi uvicorn") from e

try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception:  # pragma: no cover
    class _Noop:
        def __init__(self, *a, **k): ...
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): ...
        def observe(self, *a, **k): ...
        def set(self, *a, **k): ...
    Counter = Gauge = Histogram = _Noop  # type: ignore
    def generate_latest(): return b""
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"

# OTel (опционально)
try:
    from opentelemetry import trace
    _TRACER = trace.get_tracer(__name__)
    _OTEL = True
except Exception:  # pragma: no cover
    _TRACER = None
    _OTEL = False

# AMQP клиент из протоколов
from physical_integration.protocols.amqp_client import (
    AMQPClient, AMQPSettings, TopologyConfig, ExchangeCfg, QueueCfg, BindingCfg,
    PublishOptions, HandleResult,
)

# -----------------------------------------------------------------------------
# Метрики
# -----------------------------------------------------------------------------
GW_HEARTBEAT = Counter("edge_heartbeat_total", "Heartbeats sent", ["site", "node"])
GW_EVENTS_PUB = Counter("edge_events_published_total", "Published events", ["topic", "outcome"])
GW_CMD_CONSUMED = Counter("edge_commands_total", "Commands handled", ["cmd", "outcome"])
GW_UP = Gauge("edge_gateway_up", "1 if gateway running, 0 otherwise", ["site", "node"])
GW_PROC_LAT = Histogram("edge_processor_latency_seconds", "Processor handle latency", ["name", "outcome"],
                        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5))

# -----------------------------------------------------------------------------
# Конфигурация
# -----------------------------------------------------------------------------
class GatewaySettings(BaseModel):
    env: str = Field(default=os.getenv("ENVIRONMENT", "prod"))
    site_id: str = Field(default=os.getenv("SITE_ID", "default-site"))
    node_id: str = Field(default=os.getenv("NODE_ID", "edge-01"))
    config_path: str = Field(default=os.getenv("EDGE_CONFIG", "/etc/physical-integration/edge.yaml"))
    http_bind: str = Field(default=os.getenv("EDGE_HTTP_BIND", "0.0.0.0"))
    http_port: int = Field(default=int(os.getenv("EDGE_HTTP_PORT", "8480")))
    # AMQP
    amqp_url: str = Field(default=os.getenv("AMQP_URL", "amqps://guest:guest@localhost:5671/"))
    amqp_name_prefix: str = Field(default=os.getenv("AMQP_NAME_PREFIX", "pic"))
    amqp_prefetch: int = Field(default=int(os.getenv("AMQP_PREFETCH", "32")))
    # Очереди/обменники
    x_events: str = Field(default=os.getenv("EDGE_X_EVENTS", "edge.events.x"))
    q_commands: str = Field(default=os.getenv("EDGE_Q_COMMANDS", "edge.commands.q"))
    # Поведение
    heartbeat_interval_s: int = Field(default=int(os.getenv("EDGE_HEARTBEAT_INTERVAL", "15")))
    reload_debounce_ms: int = Field(default=int(os.getenv("EDGE_RELOAD_DEBOUNCE_MS", "300")))
    processor_queue_size: int = Field(default=int(os.getenv("EDGE_PROC_QUEUE", "1000")))
    processor_concurrency: int = Field(default=int(os.getenv("EDGE_PROC_CONCURRENCY", "4")))
    enable_metrics: bool = Field(default=bool(int(os.getenv("EDGE_METRICS", "1"))))
    enable_graphiql: bool = Field(default=False)  # зарезервировано
    # TLS для AMQP подтягивается из AMQPSettings через переменные среды


@dataclass
class Config:
    """Минимальная модель пользовательской конфигурации шлюза."""
    version: int
    processors: List[Dict[str, Any]] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def load(path: Path) -> "Config":
        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        version = int(raw.get("version", 1))
        processors = raw.get("processors", []) or []
        routes = raw.get("routes", []) or []
        # Базовая валидация
        if version < 1:
            raise ValueError("config.version must be >= 1")
        for p in processors:
            if "name" not in p or "type" not in p:
                raise ValueError("processor requires fields: name, type")
        return Config(version=version, processors=processors, routes=routes)

# -----------------------------------------------------------------------------
# Плагинная модель процессоров
# -----------------------------------------------------------------------------
class Processor:
    """Базовый процессор данных. Реализации должны быть идемпотентны и быстры."""
    def __init__(self, name: str, cfg: Dict[str, Any], enqueue: Callable[[str, Dict[str, Any]], Awaitable[None]]):
        self.name = name
        self.cfg = cfg
        self.enqueue = enqueue
        self._closed = asyncio.Event()

    async def start(self) -> None:
        """Поднять ресурсы, запустить фоновые задачи."""
        return None

    async def handle(self, item: Dict[str, Any]) -> None:
        """Обработка входного события. Может вызывать self.enqueue для публикации."""
        return None

    async def stop(self) -> None:
        """Корректно завершить работу."""
        self._closed.set()

# Пример встроенного процессора: passthrough с аннотациями и фильтрацией
class PassthroughProcessor(Processor):
    async def handle(self, item: Dict[str, Any]) -> None:
        # Простая фильтрация по ключам, добавление тегов
        allow = self.cfg.get("allow", {})
        tags = self.cfg.get("tags", {})
        for k, v in allow.items():
            if item.get(k) != v:
                return
        enriched = dict(item)
        enriched.setdefault("tags", {}).update(tags)
        await self.enqueue(self.cfg.get("topic", "edge.events.passthrough"), enriched)

# Реестр типов процессоров
PROCESSOR_TYPES: Dict[str, Callable[[str, Dict[str, Any], Callable[[str, Dict[str, Any]], Awaitable[None]]], Processor]] = {
    "passthrough": PassthroughProcessor,
    # сюда можно зарегистрировать дополнительные реализации
}

# -----------------------------------------------------------------------------
# Edge Gateway
# -----------------------------------------------------------------------------
class EdgeGateway:
    def __init__(self, settings: GatewaySettings) -> None:
        self.s = settings
        self.log = logging.getLogger("edge-gateway")
        self.cfg_path = Path(settings.config_path)
        self.cfg: Optional[Config] = None
        self._cfg_mtime = 0.0
        self._amqp = self._make_amqp()
        self._http: Optional[FastAPI] = None
        self._http_server: Optional[uvicorn.Server] = None
        self._tasks: List[asyncio.Task] = []
        self._closed = asyncio.Event()
        self._ready = asyncio.Event()
        self._proc_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=self.s.processor_queue_size)
        self._processors: List[Processor] = []

    def _make_amqp(self) -> AMQPClient:
        amqp_settings = AMQPSettings(
            uri=self.s.amqp_url,
            name_prefix=self.s.amqp_name_prefix,
            prefetch_count=self.s.amqp_prefetch,
        )
        topology = TopologyConfig(
            exchanges=[
                ExchangeCfg(name=self.s.x_events),
                ExchangeCfg(name=f"{self.s.q_commands}.x"),
                ExchangeCfg(name=f"{self.s.q_commands}.dlx"),
            ],
            queues=[
                QueueCfg(name=self.s.q_commands, with_retry=True, retry_ttl_ms=5000, max_retries=10),
            ],
            bindings=[
                BindingCfg(exchange=f"{self.s.q_commands}.x", queue=self.s.q_commands, routing_key="#"),
            ],
        )
        return AMQPClient(amqp_settings, topology)

    # ------------------------------ HTTP/Health -----------------------------
    def _build_http(self) -> FastAPI:
        app = FastAPI(title="physical-integration-core edge", version="1.0")

        @app.get("/health/live")
        async def live() -> JSONResponse:
            return JSONResponse({"status": "ok", "site": self.s.site_id, "node": self.s.node_id})

        @app.get("/health/ready")
        async def ready() -> JSONResponse:
            return JSONResponse({"status": "ready" if self._ready.is_set() else "starting"})

        @app.get("/metrics")
        async def metrics() -> PlainTextResponse:
            body = generate_latest()
            return PlainTextResponse(body, media_type=CONTENT_TYPE_LATEST)

        return app

    async def _run_http(self) -> None:
        assert self._http is not None
        config = uvicorn.Config(self._http, host=self.s.http_bind, port=self.s.http_port, log_config=None, access_log=False)
        server = uvicorn.Server(config)
        self._http_server = server
        await server.serve()

    # ------------------------------ Lifecycle ------------------------------
    async def start(self) -> None:
        self.log.info("Gateway starting: site=%s node=%s", self.s.site_id, self.s.node_id)
        GW_UP.labels(site=self.s.site_id, node=self.s.node_id).set(0)
        # HTTP
        self._http = self._build_http()
        self._tasks.append(asyncio.create_task(self._run_http(), name="http-server"))
        # AMQP connect & topology
        await self._amqp.connect()
        await self._amqp.declare_topology()
        # Load config
        await self._load_config(force=True)
        # Start processors workers
        for i in range(self.s.processor_concurrency):
            self._tasks.append(asyncio.create_task(self._processor_worker(i), name=f"proc-worker-{i}"))
        # Start consumers for commands
        self._tasks.append(asyncio.create_task(self._consume_commands(), name="commands-consumer"))
        # Start watcher & heartbeat & supervisor
        self._tasks.append(asyncio.create_task(self._watch_config_loop(), name="config-watcher"))
        self._tasks.append(asyncio.create_task(self._heartbeat_loop(), name="heartbeat"))
        self._tasks.append(asyncio.create_task(self._supervisor_loop(), name="supervisor"))
        self._ready.set()
        GW_UP.labels(site=self.s.site_id, node=self.s.node_id).set(1)
        self.log.info("Gateway started")

    async def stop(self) -> None:
        if self._closed.is_set():
            return
        self.log.info("Gateway stopping...")
        self._closed.set()
        # Остановка процессоров
        for p in self._processors:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(p.stop(), timeout=5)
        # Остановка задач
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        # Закрытие AMQP
        with contextlib.suppress(Exception):
            await self._amqp.close()
        # Остановка HTTP
        if self._http_server:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._http_server.shutdown(), timeout=5)
        GW_UP.labels(site=self.s.site_id, node=self.s.node_id).set(0)
        self.log.info("Gateway stopped")

    # ------------------------------ Config ---------------------------------
    async def _load_config(self, force: bool = False) -> None:
        try:
            stat = self.cfg_path.stat()
        except FileNotFoundError:
            self.log.error("Config not found: %s", self.cfg_path)
            return
        if not force and stat.st_mtime <= self._cfg_mtime:
            return
        cfg = Config.load(self.cfg_path)
        self._cfg_mtime = stat.st_mtime
        await self._apply_config(cfg)

    async def _apply_config(self, cfg: Config) -> None:
        self.log.info("Applying config v%s with %d processors", cfg.version, len(cfg.processors))
        # Остановить старые процессоры
        for p in self._processors:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(p.stop(), timeout=5)
        self._processors.clear()
        # Создать новые процессоры
        for p_cfg in cfg.processors:
            name = p_cfg["name"]
            typ = p_cfg["type"].lower()
            factory = PROCESSOR_TYPES.get(typ)
            if not factory:
                self.log.warning("Unknown processor type: %s (skip)", typ)
                continue
            proc = factory(name, p_cfg, self.publish_event)
            await proc.start()
            self._processors.append(proc)
        self.cfg = cfg
        self.log.info("Config applied: processors=%s", [p.name for p in self._processors])

    async def _watch_config_loop(self) -> None:
        debounce = self.s.reload_debounce_ms / 1000.0
        last = 0.0
        while not self._closed.is_set():
            try:
                await self._load_config(force=False)
            except Exception:
                self.log.exception("Config reload error")
            await asyncio.sleep(max(0.5, debounce))
            # Простая периодическая проверка mtime; для watchfiles можно заменить реализацией

    # --------------------------- Heartbeat/Supervisor -----------------------
    async def _heartbeat_loop(self) -> None:
        while not self._closed.is_set():
            try:
                payload = {
                    "type": "edge.heartbeat",
                    "site": self.s.site_id,
                    "node": self.s.node_id,
                    "ts": time.time(),
                }
                await self._publish(self.s.x_events, PublishOptions(
                    routing_key=f"sites.{self.s.site_id}.{self.s.node_id}.heartbeat",
                    message=payload,
                    idempotency_key=f"hb:{int(time.time() // self.s.heartbeat_interval_s)}"
                ))
                GW_HEARTBEAT.labels(site=self.s.site_id, node=self.s.node_id).inc()
            except Exception:
                self.log.exception("Heartbeat publish failed")
            await asyncio.sleep(self.s.heartbeat_interval_s)

    async def _supervisor_loop(self) -> None:
        while not self._closed.is_set():
            # Здесь можно проверять очереди, лаги, ресурсы, температуру и т.д.
            await asyncio.sleep(5)

    # ------------------------------- Queue/Backpressure ---------------------
    async def enqueue(self, item: Dict[str, Any]) -> None:
        """Внешняя точка ввода событий (если нужно пушить в общий конвейер)."""
        await self._proc_queue.put(item)

    async def _processor_worker(self, idx: int) -> None:
        while not self._closed.is_set():
            try:
                item = await self._proc_queue.get()
                for proc in self._processors:
                    start = time.perf_counter()
                    try:
                        await proc.handle(dict(item))  # копия на каждый процессор
                        GW_PROC_LAT.labels(name=proc.name, outcome="ok").observe(time.perf_counter() - start)
                    except Exception:
                        GW_PROC_LAT.labels(name=proc.name, outcome="error").observe(time.perf_counter() - start)
                        self.log.exception("Processor %s failed", proc.name)
                self._proc_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception:
                self.log.exception("Processor worker error")

    # ----------------------------- AMQP Publish -----------------------------
    async def publish_event(self, topic: str, payload: Dict[str, Any], headers: Optional[Dict[str, Any]] = None) -> None:
        rk = topic.replace("/", ".")
        msg = dict(payload)
        msg.setdefault("site", self.s.site_id)
        msg.setdefault("node", self.s.node_id)
        await self._publish(self.s.x_events, PublishOptions(
            routing_key=rk,
            message=msg,
            headers=headers or {},
            idempotency_key=payload.get("id") or payload.get("key"),
        ))

    async def _publish(self, exchange: str, opts: PublishOptions) -> None:
        # Обертка c метриками/трейсами
        span_ctx = None
        if _OTEL and _TRACER:
            span_ctx = _TRACER.start_as_current_span("edge.publish", attributes={
                "messaging.destination": exchange,
                "messaging.route": opts.routing_key,
            })
        try:
            if span_ctx:
                with span_ctx:
                    await self._amqp.publish(exchange, opts)
            else:
                await self._amqp.publish(exchange, opts)
            GW_EVENTS_PUB.labels(topic=opts.routing_key, outcome="ok").inc()
        except Exception:
            GW_EVENTS_PUB.labels(topic=opts.routing_key, outcome="error").inc()
            raise

    # ----------------------------- Commands consume -------------------------
    async def _consume_commands(self) -> None:
        queue = self.s.q_commands

        async def handler(m) -> HandleResult:
            try:
                payload = json.loads(m.body)
            except Exception:
                return HandleResult.nack(requeue=False, detail="bad-json")

            cmd = payload.get("cmd")
            if not cmd:
                return HandleResult.nack(requeue=False, detail="no-cmd")

            try:
                if cmd == "ping":
                    await self.publish_event("edge.events.pong", {"ts": time.time(), "ref": payload.get("ref")})
                    GW_CMD_CONSUMED.labels(cmd=cmd, outcome="ok").inc()
                    return HandleResult.ack()
                elif cmd == "reload_config":
                    await self._load_config(force=True)
                    GW_CMD_CONSUMED.labels(cmd=cmd, outcome="ok").inc()
                    return HandleResult.ack()
                elif cmd == "emit":
                    # Произвольная публикация в конвейер
                    data = payload.get("data") or {}
                    await self.enqueue(data)
                    GW_CMD_CONSUMED.labels(cmd=cmd, outcome="ok").inc()
                    return HandleResult.ack()
                else:
                    GW_CMD_CONSUMED.labels(cmd=cmd, outcome="unknown").inc()
                    return HandleResult.nack(requeue=False, detail="unknown-cmd")
            except Exception:
                GW_CMD_CONSUMED.labels(cmd=cmd, outcome="error").inc()
                return HandleResult.retry(delay_ms=5000)

        await self._amqp.consume(queue, handler, concurrency=4)

# -----------------------------------------------------------------------------
# Bootstrap
# -----------------------------------------------------------------------------
def _setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

async def _main() -> None:
    _setup_logging()
    s = GatewaySettings()
    gw = EdgeGateway(s)

    loop = asyncio.get_running_loop()
    stop_ev = asyncio.Event()

    def _graceful(*_):
        if not stop_ev.is_set():
            stop_ev.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _graceful)

    await gw.start()

    await stop_ev.wait()
    await gw.stop()

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
