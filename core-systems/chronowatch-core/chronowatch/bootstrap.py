# chronowatch-core/chronowatch/bootstrap.py
# -*- coding: utf-8 -*-
"""
ChronoWatch Core — Bootstrap module.

Возможности:
- Загрузка конфигурации из YAML + ENV-переопределения (dotted path).
- Структурное JSON-логирование (ISO8601) с trace/span (если доступен OpenTelemetry).
- ASGI-приложение с фолбэком: FastAPI -> Starlette -> минимальный ASGI.
- Health эндпоинты: /health/live, /health/ready, /health/startup, /health/check.
- Грациозное завершение по SIGTERM/SIGINT; горячая перезагрузка конфигурации по SIGHUP.
- Опционально: OTLP (traces/metrics) и интеграция с RateLimitMiddleware (если установлен).
- Единый вход: main() с CLI аргументами.

Зависимости (необязательные, используются при наличии):
- fastapi, starlette, uvicorn
- pyyaml
- opentelemetry-sdk, opentelemetry-exporter-otlp, opentelemetry-instrumentation-asgi

Безопасность:
- Секреты — только через ENV; файл конфигурации — без секретов.
- X-Forwarded-For учитывается на уровне middleware (если подключите), здесь только базовая обработка.

Автор: Aethernova / ChronoWatch Core.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import importlib
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Mapping, MutableMapping, Optional, Tuple

# ---------- Опциональные импорты ----------
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
except Exception:  # pragma: no cover
    FastAPI = None  # type: ignore
    JSONResponse = None  # type: ignore

try:
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse as StarletteJSONResponse
    from starlette.routing import Route as StarletteRoute
    from starlette.middleware import Middleware as StarletteMiddleware
except Exception:  # pragma: no cover
    Starlette = None  # type: ignore
    StarletteJSONResponse = None  # type: ignore
    StarletteRoute = None  # type: ignore
    StarletteMiddleware = None  # type: ignore

try:
    import uvicorn  # type: ignore
except Exception:  # pragma: no cover
    uvicorn = None  # type: ignore

# OpenTelemetry (строго опционально)
try:
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware as OTelASGIMiddleware
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    metrics = None  # type: ignore
    TracerProvider = None  # type: ignore
    BatchSpanProcessor = None  # type: ignore
    OTLPSpanExporter = None  # type: ignore
    Resource = None  # type: ignore
    MeterProvider = None  # type: ignore
    PeriodicExportingMetricReader = None  # type: ignore
    OTLPMetricExporter = None  # type: ignore
    OTelASGIMiddleware = None  # type: ignore


# ---------- Утилиты конфигурации ----------

def _read_yaml_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    if yaml is None:
        raise RuntimeError("pyyaml не установлен, а конфигурация задана в YAML")
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("Корень YAML должен быть мапой (dict)")
    return data


def _deep_get(d: Mapping[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, Mapping) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _deep_set(d: MutableMapping[str, Any], path: str, value: Any) -> None:
    cur: MutableMapping[str, Any] = d
    parts = path.split(".")
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, MutableMapping):
            nxt = {}
            cur[p] = nxt  # type: ignore[index]
        cur = nxt  # type: ignore[assignment]
    cur[parts[-1]] = value


def _apply_env_overrides(cfg: MutableMapping[str, Any], mapping: List[Mapping[str, str]]) -> None:
    """
    mapping: список {name: ENV_NAME, path: dotted.path.in.config}
    Если переменная окружения присутствует — перекрывает соответствующее значение.
    """
    for rule in mapping:
        env_name = rule.get("name")
        conf_path = rule.get("path")
        if not env_name or not conf_path:
            continue
        if env_name in os.environ:
            _deep_set(cfg, conf_path, os.environ[env_name])


@dataclasses.dataclass
class AppConfig:
    service_name: str = "chronowatch-core"
    environment: str = os.getenv("ENVIRONMENT", "production")
    version: str = os.getenv("CHRONO_VERSION", "v0.1.0")

    host: str = os.getenv("CHRONO_HOST", "0.0.0.0")
    port: int = int(os.getenv("CHRONO_PORT", "8080"))
    log_level: str = os.getenv("CHRONO_LOG_LEVEL", "INFO")
    json_logs: bool = True

    # OTEL
    otel_enabled: bool = os.getenv("OTEL_ENABLED", "true").lower() == "true"
    otlp_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
    otlp_protocol: str = os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")  # grpc|http/protobuf
    otel_sample_ratio: float = float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.2"))

    # RateLimit: включится автоматически, если модуль доступен и включён в конфиг
    ratelimit_enabled: bool = True

    # Проброс конфигов приложения (для эндпоинтов/клиентов/фичей)
    raw: Dict[str, Any] = dataclasses.field(default_factory=dict)

    @classmethod
    def from_sources(cls, config_path: Optional[str]) -> "AppConfig":
        base: Dict[str, Any] = {}
        if config_path:
            base = _read_yaml_file(Path(config_path))
        # Общие поля
        service_name = _deep_get(base, "app.name", "chronowatch-core")
        environment = _deep_get(base, "app.environment", os.getenv("ENVIRONMENT", "production"))
        version = _deep_get(base, "telemetry.opentelemetry.resource.attributes.service.version", os.getenv("CHRONO_VERSION", "v0.1.0"))

        # Порт
        port = int(_deep_get(base, "server.http.port", os.getenv("CHRONO_PORT", "8080")))
        host = os.getenv("CHRONO_HOST", "0.0.0.0")

        # Логи
        json_logs = bool(_deep_get(base, "telemetry.logging.json", True))
        log_level = str(_deep_get(base, "telemetry.logging.level.root", os.getenv("CHRONO_LOG_LEVEL", "INFO"))).upper()

        # OTEL
        otel_enabled = bool(_deep_get(base, "telemetry.opentelemetry.enabled", os.getenv("OTEL_ENABLED", "true").lower() == "true"))
        otlp_endpoint = str(_deep_get(base, "telemetry.opentelemetry.endpoint", os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")))
        otlp_protocol = str(_deep_get(base, "telemetry.opentelemetry.protocol", os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")))
        sample_ratio = float(_deep_get(base, "telemetry.opentelemetry.sampling.probability", float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.2"))))

        # ENV overrides, если в файле задана карта envOverrides
        env_map = _deep_get(base, "envOverrides", [])
        if isinstance(env_map, list):
            _apply_env_overrides(base, env_map)

        return cls(
            service_name=service_name,
            environment=environment,
            version=str(version),
            host=host,
            port=port,
            log_level=log_level,
            json_logs=json_logs,
            otel_enabled=otel_enabled,
            otlp_endpoint=otlp_endpoint,
            otlp_protocol=otlp_protocol,
            otel_sample_ratio=sample_ratio,
            raw=base,
        )


# ---------- Логирование ----------

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "file": record.pathname,
            "line": record.lineno,
            "thread": record.threadName,
            "pid": record.process,
        }
        # Trace/Span — если есть OpenTelemetry
        if trace is not None:
            try:
                span = trace.get_current_span()
                ctx = span.get_span_context()
                if ctx and ctx.is_valid:
                    payload["trace_id"] = format(ctx.trace_id, "032x")
                    payload["span_id"] = format(ctx.span_id, "016x")
            except Exception:
                pass
        # Доп. поля из record.extra
        for k in ("service", "env", "version"):
            v = getattr(record, k, None)
            if v is not None:
                payload[k] = v
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(cfg: AppConfig) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    root.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    if cfg.json_logs:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter(fmt="%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)

    # Базовые атрибуты на корневом логгере
    logging.LoggerAdapter(root, {"service": cfg.service_name, "env": cfg.environment, "version": cfg.version})


# ---------- OpenTelemetry ----------

class _OTelController:
    def __init__(self) -> None:
        self._tp = None
        self._mp = None

    def init(self, cfg: AppConfig) -> None:
        if not cfg.otel_enabled or TracerProvider is None:
            return
        res = Resource.create({
            "service.name": cfg.service_name,
            "service.version": cfg.version,
            "deployment.environment": cfg.environment,
        })

        # Traces
        tp = TracerProvider(resource=res)
        span_exporter = OTLPSpanExporter(endpoint=cfg.otlp_endpoint)
        tp.add_span_processor(BatchSpanProcessor(span_exporter))
        trace.set_tracer_provider(tp)

        # Metrics
        mp = MeterProvider(
            resource=res,
            metric_readers=[
                PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=cfg.otlp_endpoint))
            ],
        )
        metrics.set_meter_provider(mp)

        self._tp = tp
        self._mp = mp
        logging.getLogger(__name__).info("OpenTelemetry initialized", extra={"service": cfg.service_name})

    def shutdown(self) -> None:
        with contextlib.suppress(Exception):
            if self._tp:
                self._tp.shutdown()
        with contextlib.suppress(Exception):
            if self._mp:
                self._mp.shutdown()


otel_ctl = _OTelController()


# ---------- Состояние здоровья сервиса ----------

class _HealthState:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.ready = asyncio.Event()

    def mark_started(self) -> None:
        if not self.started.is_set():
            self.started.set()

    def mark_ready(self) -> None:
        if not self.ready.is_set():
            self.ready.set()


health_state = _HealthState()


# ---------- Инициализация ASGI приложения ----------

def _try_import_rate_limit_middleware() -> Optional[Callable]:
    """
    Возвращает класс middleware, если модуль установлен.
    Ожидается: chronowatch.api.http.middleware.ratelimit.RateLimitMiddleware
    """
    try:
        m = importlib.import_module("chronowatch.api.http.middleware.ratelimit")
        return getattr(m, "RateLimitMiddleware", None)
    except Exception:
        return None


def _build_app(cfg: AppConfig):
    """
    Возвращает ASGI-приложение. Порядок проб: FastAPI -> Starlette -> минимальный ASGI.
    """
    limiter_cls = _try_import_rate_limit_middleware() if cfg.ratelimit_enabled else None

    # ---------- FastAPI ----------
    if FastAPI is not None:
        app = FastAPI(title=cfg.service_name, version=cfg.version)

        @app.on_event("startup")
        async def _on_startup() -> None:
            health_state.mark_started()
            # Переход в ready — допустите позднее, если есть внешние зависимости
            health_state.mark_ready()
            logging.getLogger(__name__).info("Service startup complete")

        @app.on_event("shutdown")
        async def _on_shutdown() -> None:
            logging.getLogger(__name__).info("Service shutdown")

        # Health endpoints
        @app.get("/health/live")
        async def live() -> Any:
            return {"status": "SERVING", "service": cfg.service_name, "ts": _now_iso()}

        @app.get("/health/ready")
        async def ready() -> Any:
            return (
                {"status": "SERVING", "service": cfg.service_name, "ts": _now_iso()}
                if health_state.ready.is_set()
                else JSONResponse({"status": "NOT_SERVING", "service": cfg.service_name, "ts": _now_iso()}, status_code=503)  # type: ignore
            )

        @app.get("/health/startup")
        async def startup() -> Any:
            return (
                {"status": "SERVING", "service": cfg.service_name, "ts": _now_iso()}
                if health_state.started.is_set()
                else JSONResponse({"status": "NOT_SERVING", "service": cfg.service_name, "ts": _now_iso()}, status_code=503)  # type: ignore
            )

        @app.get("/health/check")
        async def check() -> Any:
            # Здесь может быть проверка БД/кэша/брокера
            return {
                "status": "SERVING" if health_state.ready.is_set() else "DEGRADED",
                "service": cfg.service_name,
                "version": cfg.version,
                "env": cfg.environment,
                "ts": _now_iso(),
            }

        # OpenTelemetry ASGI middleware
        if OTelASGIMiddleware is not None and cfg.otel_enabled:
            app.add_middleware(OTelASGIMiddleware)

        # Rate limit middleware (если доступен)
        if limiter_cls is not None:
            # Минимальная демонстрационная политика: щадящее ограничение GETов
            from chronowatch.api.http.middleware.ratelimit import (  # type: ignore
                RateLimitRule, Strategy, RuleMatch, IdentityPolicy, MemoryBackend,
            )

            rules = [
                RateLimitRule(
                    name="public_get",
                    limit=100,
                    window=60.0,
                    strategy=Strategy.SLIDING_WINDOW,
                    match=RuleMatch(path=r"^/.*", methods={"GET"}),
                    identity=IdentityPolicy(by_ip=True),
                ),
            ]
            app.add_middleware(limiter_cls, backend=MemoryBackend(), rules=rules)  # type: ignore

        return app

    # ---------- Starlette ----------
    if Starlette is not None:
        async def live(_req) -> Any:
            return StarletteJSONResponse({"status": "SERVING", "service": cfg.service_name, "ts": _now_iso()})

        async def ready(_req) -> Any:
            if health_state.ready.is_set():
                return StarletteJSONResponse({"status": "SERVING", "service": cfg.service_name, "ts": _now_iso()})
            return StarletteJSONResponse({"status": "NOT_SERVING", "service": cfg.service_name, "ts": _now_iso()}, status_code=503)

        async def startup(_req) -> Any:
            if health_state.started.is_set():
                return StarletteJSONResponse({"status": "SERVING", "service": cfg.service_name, "ts": _now_iso()})
            return StarletteJSONResponse({"status": "NOT_SERVING", "service": cfg.service_name, "ts": _now_iso()}, status_code=503)

        async def check(_req) -> Any:
            return StarletteJSONResponse({
                "status": "SERVING" if health_state.ready.is_set() else "DEGRADED",
                "service": cfg.service_name,
                "version": cfg.version,
                "env": cfg.environment,
                "ts": _now_iso(),
            })

        routes = [
            StarletteRoute("/health/live", live),
            StarletteRoute("/health/ready", ready),
            StarletteRoute("/health/startup", startup),
            StarletteRoute("/health/check", check),
        ]
        middleware = []
        if OTelASGIMiddleware is not None and cfg.otel_enabled:
            middleware.append(StarletteMiddleware(OTelASGIMiddleware))
        app = Starlette(routes=routes, middleware=middleware)

        return app

    # ---------- Минимальный ASGI ----------
    async def simple_app(scope, receive, send):
        if scope["type"] != "http":
            await _asgi_plain_text(send, 404, b"Unsupported")
            return
        path = scope.get("path", "/")
        if path == "/health/live":
            body = json.dumps({"status": "SERVING", "service": cfg.service_name, "ts": _now_iso()}).encode("utf-8")
            await _asgi_json(send, 200, body)
            return
        if path == "/health/ready":
            status = 200 if health_state.ready.is_set() else 503
            body = json.dumps(
                {"status": "SERVING" if status == 200 else "NOT_SERVING", "service": cfg.service_name, "ts": _now_iso()}
            ).encode("utf-8")
            await _asgi_json(send, status, body)
            return
        if path == "/health/startup":
            status = 200 if health_state.started.is_set() else 503
            body = json.dumps(
                {"status": "SERVING" if status == 200 else "NOT_SERVING", "service": cfg.service_name, "ts": _now_iso()}
            ).encode("utf-8")
            await _asgi_json(send, status, body)
            return
        if path == "/health/check":
            body = json.dumps({
                "status": "SERVING" if health_state.ready.is_set() else "DEGRADED",
                "service": cfg.service_name,
                "version": cfg.version,
                "env": cfg.environment,
                "ts": _now_iso(),
            }).encode("utf-8")
            await _asgi_json(send, 200, body)
            return
        await _asgi_plain_text(send, 404, b"Not Found")

    return simple_app


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


async def _asgi_json(send, status: int, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json; charset=utf-8")]})
    await send({"type": "http.response.body", "body": body})


async def _asgi_plain_text(send, status: int, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
    await send({"type": "http.response.body", "body": body})


# ---------- Сервер / сигналы ----------

def install_signal_handlers(reload_cb: Callable[[], None], shutdown_cb: Callable[[], Awaitable[None]]) -> None:
    loop = asyncio.get_event_loop()
    # SIGTERM/SIGINT — грациозное завершение
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(_on_shutdown_signal(s, shutdown_cb)))
    # SIGHUP — горячая перезагрузка конфигурации
    with contextlib.suppress(NotImplementedError):
        loop.add_signal_handler(signal.SIGHUP, reload_cb)


async def _on_shutdown_signal(sig: signal.Signals, shutdown_cb: Callable[[], Awaitable[None]]) -> None:
    logging.getLogger(__name__).warning("Received signal, shutting down", extra={"signal": str(sig)})
    await shutdown_cb()


async def run_uvicorn(app, cfg: AppConfig) -> None:
    if uvicorn is None:
        raise RuntimeError("uvicorn не установлен")
    config = uvicorn.Config(
        app=app,
        host=cfg.host,
        port=cfg.port,
        log_level=cfg.log_level.lower(),
        reload=False,
        proxy_headers=True,
        forwarded_allow_ips="*",
        timeout_keep_alive=65,
        use_colors=False,
        server_header=False,
    )
    server = uvicorn.Server(config)

    async def _shutdown() -> None:
        server.should_exit = True

    def _reload() -> None:
        logging.getLogger(__name__).info("SIGHUP received — config reload requested")

    install_signal_handlers(_reload, _shutdown)

    # Старт, фиксация started/ready на событиях приложения
    health_state.mark_started()
    health_state.mark_ready()
    await server.serve()


# ---------- CLI ----------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="chronowatch-bootstrap", description="ChronoWatch Core Bootstrap")
    p.add_argument("--config", "-c", default=os.getenv("CHRONO_CONFIG", ""), help="Путь к YAML конфигурации")
    p.add_argument("--host", default=os.getenv("CHRONO_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.getenv("CHRONO_PORT", "8080")))
    p.add_argument("--log-level", default=os.getenv("CHRONO_LOG_LEVEL", "INFO"))
    p.add_argument("--no-otel", action="store_true", help="Отключить OpenTelemetry")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    cfg = AppConfig.from_sources(args.config if args.config else None)
    # Параметры CLI имеют приоритет
    cfg.host = args.host
    cfg.port = args.port
    cfg.log_level = args.log_level
    if args.no_otel:
        cfg.otel_enabled = False

    setup_logging(cfg)

    # Init OpenTelemetry
    otel_ctl.init(cfg)

    app = _build_app(cfg)

    # Запуск цикла
    try:
        asyncio.run(run_uvicorn(app, cfg))
    finally:
        otel_ctl.shutdown()


if __name__ == "__main__":
    main()
