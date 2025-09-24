# ops/omnimind/bootstrap.py
from __future__ import annotations

import contextlib
import dataclasses
import importlib
import importlib.metadata as md
import json
import logging
import logging.handlers
import os
import queue
import re
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union

# ----------------------------- Optional deps ---------------------------------
with contextlib.suppress(Exception):
    import yaml  # type: ignore

with contextlib.suppress(Exception):
    from jsonschema import validate as jsonschema_validate  # type: ignore

with contextlib.suppress(Exception):
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST  # type: ignore
    from prometheus_client import start_http_server as prom_start_http_server  # type: ignore

with contextlib.suppress(Exception):
    # OpenTelemetry — опционально
    from opentelemetry import trace  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
    from opentelemetry.sdk.resources import Resource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore

# ------------------------------ Types & Config -------------------------------

JSON = Union[dict, list, str, int, float, bool, None]

ENV_CONFIG_PATH = "OMNIMIND_CONFIG"
ENV_CONFIG_SCHEMA = "OMNIMIND_CONFIG_SCHEMA"
ENV_CONFIG_ENV_PREFIX = "OMNI__"  # OMNI__section__key=val → config.section.key = val

DEFAULT_CONFIG_PATHS = (
    "./config.yaml",
    "./config.yml",
    "./config.json",
    "/etc/omnimind/config.yaml",
)

# ------------------------------ Logging --------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        base = {
            "ts": ts,
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "pid": record.process,
            "tid": record.thread,
        }
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        for k, v in getattr(record, "__dict__", {}).items():
            if k.startswith("_") or k in ("args", "msg", "levelno", "levelname", "name", "process", "processName",
                                          "thread", "threadName", "created", "msecs", "relativeCreated", "pathname",
                                          "filename", "module", "lineno", "funcName", "exc_info", "exc_text",
                                          "stack_info", "stack", "ts", "lvl"):
                continue
            if k not in base:
                base[k] = v
        return json.dumps(base, ensure_ascii=False)

def setup_logging(cfg: Mapping[str, Any]) -> logging.Logger:
    log_cfg = cfg.get("logging", {}) if isinstance(cfg, Mapping) else {}
    level = (log_cfg.get("level") or "INFO").upper()
    as_json = bool(log_cfg.get("json", True))
    fmt = log_cfg.get("format") or "%(asctime)s %(levelname)s %(name)s %(message)s"
    log_dir = Path(cfg.get("paths", {}).get("logs", "/var/log/omnimind")) if isinstance(cfg, Mapping) else Path("/var/log/omnimind")
    log_file = log_dir / "app.log"

    root = logging.getLogger()
    # идемпотентно
    for h in list(root.handlers):
        root.removeHandler(h)
    root.setLevel(getattr(logging, level, logging.INFO))

    # stdout
    sh = logging.StreamHandler(stream=sys.stdout)
    sh.setLevel(root.level)
    sh.setFormatter(JsonFormatter() if as_json else logging.Formatter(fmt))
    root.addHandler(sh)

    # file with rotation
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=int(log_cfg.get("rotation", {}).get("max_size_mb", 50)) * 1024 * 1024,
            backupCount=int(log_cfg.get("rotation", {}).get("max_backups", 5)), encoding="utf-8"
        )
        fh.setLevel(root.level)
        fh.setFormatter(JsonFormatter() if as_json else logging.Formatter(fmt))
        root.addHandler(fh)
    except Exception as e:
        root.warning("log_file_setup_failed", extra={"error": str(e), "path": str(log_file)})

    root.info("logging_initialized", extra={"level": level, "json": as_json})
    return root

# ------------------------------ Config ---------------------------------------

def _read_file(path: Path) -> JSON:
    data = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        if "yaml" not in sys.modules:
            raise RuntimeError("PyYAML is not installed but YAML config provided")
        return yaml.safe_load(data)  # type: ignore
    return json.loads(data)

_env_pat = re.compile(r"\$\{(?P<key>[A-Za-z_][A-Za-z0-9_]*)(?::(?P<default>[^}]*))?\}")

def _expand_env(obj: JSON) -> JSON:
    if isinstance(obj, str):
        def rep(m: re.Match) -> str:
            k = m.group("key")
            d = m.group("default") or ""
            return os.getenv(k, d)
        return _env_pat.sub(rep, obj)
    if isinstance(obj, list):
        return [_expand_env(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _expand_env(v) for k, v in obj.items()}
    return obj

def _deep_merge(dst: MutableMapping[str, Any], src: Mapping[str, Any]) -> MutableMapping[str, Any]:
    for k, v in src.items():
        if isinstance(v, Mapping) and isinstance(dst.get(k), Mapping):
            _deep_merge(dst[k], v)  # type: ignore
        else:
            dst[k] = v  # type: ignore
    return dst

def _apply_env_overrides(cfg: MutableMapping[str, Any], prefix: str = ENV_CONFIG_ENV_PREFIX) -> None:
    # OMNI__a__b__c=value → cfg[a][b][c] = parsed(value)
    for k, v in os.environ.items():
        if not k.startswith(prefix):
            continue
        path = k[len(prefix):].split("__")
        cur: MutableMapping[str, Any] = cfg
        for part in path[:-1]:
            cur = cur.setdefault(part, {})  # type: ignore
        # try JSON parse, else string
        try:
            cur[path[-1]] = json.loads(v)
        except Exception:
            cur[path[-1]] = v

def load_config(explicit_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    paths: List[Path] = []
    if explicit_path:
        paths.append(Path(str(explicit_path)))
    elif os.getenv(ENV_CONFIG_PATH):
        paths.append(Path(os.environ[ENV_CONFIG_PATH]))
    else:
        paths.extend(Path(p) for p in DEFAULT_CONFIG_PATHS)

    for p in paths:
        if p.exists():
            cfg = _read_file(p)
            if not isinstance(cfg, Mapping):
                raise RuntimeError("Config root must be an object")
            cfg = dict(cfg)  # shallow copy
            cfg = _expand_env(cfg)  # ${VAR:default}
            _apply_env_overrides(cfg)  # OMNI__*
            return cfg  # type: ignore
    # fallback to minimal defaults
    cfg = {
        "app": {"name": "omnimind-core", "env": os.getenv("APP_ENV", "staging")},
        "server": {"port": int(os.getenv("PORT", "8080"))},
        "logging": {"level": "INFO", "json": True},
        "paths": {
            "logs": os.getenv("LOG_DIR", "/var/log/omnimind"),
            "data": os.getenv("DATA_DIR", "/var/lib/omnimind"),
        },
        "metrics": {"enabled": True, "port": int(os.getenv("METRICS_PORT", "8080"))},
        "tls": {"enabled": False},
    }
    _apply_env_overrides(cfg)
    return cfg

def validate_config(cfg: Mapping[str, Any]) -> None:
    schema_path = os.getenv(ENV_CONFIG_SCHEMA)
    if schema_path and "jsonschema_validate" in globals():
        sp = Path(schema_path)
        if not sp.exists():
            raise RuntimeError(f"Config schema not found: {sp}")
        schema = _read_file(sp)
        jsonschema_validate(cfg, schema)  # type: ignore

# ------------------------------ Secrets --------------------------------------

def resolve_secrets(obj: JSON) -> JSON:
    """
    Рекурсивно разворачивает нотацию {"$secret": "ENV:NAME"} | "file:/path" | "literal:..".
    """
    if isinstance(obj, dict) and "$secret" in obj and len(obj) == 1:
        spec = str(obj["$secret"])
        if spec.startswith("ENV:"):
            name = spec[4:]
            val = os.getenv(name)
            if val is None:
                raise RuntimeError(f"Secret ENV:{name} is not set")
            return val
        if spec.startswith("file:"):
            path = Path(spec[5:])
            return path.read_text(encoding="utf-8").strip()
        if spec.startswith("literal:"):
            return spec[len("literal:") :]
        raise RuntimeError(f"Unsupported secret spec: {spec}")
    if isinstance(obj, list):
        return [resolve_secrets(x) for x in obj]
    if isinstance(obj, dict):
        return {k: resolve_secrets(v) for k, v in obj.items()}
    return obj

# ------------------------------ Metrics --------------------------------------

@dataclass
class Metrics:
    registry: Optional["CollectorRegistry"] = None
    started_thread: Optional[threading.Thread] = None
    up_gauge: Optional["Gauge"] = None
    request_counter: Optional["Counter"] = None
    request_latency: Optional["Histogram"] = None

def setup_metrics(cfg: Mapping[str, Any], log: logging.Logger) -> Metrics:
    if "CollectorRegistry" not in globals():
        log.info("metrics_disabled_no_prometheus")
        return Metrics()
    mcfg = cfg.get("metrics", {}) if isinstance(cfg, Mapping) else {}
    if not mcfg or not mcfg.get("enabled", True):
        log.info("metrics_disabled_config")
        return Metrics()
    port = int(mcfg.get("port", cfg.get("server", {}).get("port", 8080)))
    reg = CollectorRegistry(auto_describe=True)
    # Use default start_http_server (separate thread). It uses global REGISTRY by default; pass registry explicitly.
    # To keep it simple and avoid WSGI, use builtin server with global registry; acceptable for ops metrics.
    thr = prom_start_http_server(port, addr="0.0.0.0")  # type: ignore
    up = Gauge("omnimind_up", "Service availability gauge", registry=reg)  # not exported via custom reg with start_http_server
    rc = Counter("omnimind_requests_total", "Total processed requests", ["path", "code"])  # global REGISTRY
    rl = Histogram("omnimind_request_latency_seconds", "Request latency", ["path"])  # global REGISTRY
    up.set(1)
    log.info("metrics_started", extra={"port": port})
    return Metrics(registry=reg, started_thread=thr, up_gauge=up, request_counter=rc, request_latency=rl)

# ------------------------------ Tracing --------------------------------------

@dataclass
class Tracing:
    provider: Optional["TracerProvider"] = None
    processor: Optional["BatchSpanProcessor"] = None

def setup_tracing(cfg: Mapping[str, Any], log: logging.Logger) -> Tracing:
    if "trace" not in globals():
        log.info("tracing_disabled_no_otel")
        return Tracing()
    tcfg = cfg.get("tracing", {}) if isinstance(cfg, Mapping) else {}
    if not tcfg or not tcfg.get("enabled", False):
        log.info("tracing_disabled_config")
        return Tracing()
    endpoint = tcfg.get("endpoint", os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"))
    res = Resource.create({
        "service.name": cfg.get("app", {}).get("name", "omnimind-core"),
        "service.version": cfg.get("app", {}).get("version", "0.0.0"),
        "service.namespace": cfg.get("app", {}).get("env", "staging"),
    })
    provider = TracerProvider(resource=res)
    exporter = OTLPSpanExporter(endpoint=endpoint)
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)
    log.info("tracing_started", extra={"endpoint": endpoint})
    return Tracing(provider=provider, processor=processor)

# ------------------------------ Health server --------------------------------

class _HealthState:
    live = True
    ready = False

class _HealthHandler(BaseHTTPRequestHandler):
    server_version = "omnimind-health/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/healthz/live"):
            self._send(HTTPStatus.OK if _HealthState.live else HTTPStatus.SERVICE_UNAVAILABLE, {"status": "live"})
            return
        if self.path.startswith("/healthz/ready"):
            self._send(HTTPStatus.OK if _HealthState.ready else HTTPStatus.SERVICE_UNAVAILABLE, {"status": "ready"})
            return
        if self.path == "/ping":
            self._send(HTTPStatus.OK, {"pong": True})
            return
        self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def log_message(self, format: str, *args: Any) -> None:  # silence
        return

    def _send(self, status: HTTPStatus, body: Dict[str, Any]):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

@dataclass
class HealthServer:
    server: Optional[ThreadingHTTPServer] = None
    thread: Optional[threading.Thread] = None
    port: int = 0

def setup_health(cfg: Mapping[str, Any], log: logging.Logger) -> HealthServer:
    scfg = cfg.get("server", {}) if isinstance(cfg, Mapping) else {}
    port = int(scfg.get("port", 8080))
    host = scfg.get("bind_host", "0.0.0.0")
    try:
        httpd = ThreadingHTTPServer((host, port), _HealthHandler)
        t = threading.Thread(target=httpd.serve_forever, name="health-http", daemon=True)
        t.start()
        log.info("health_server_started", extra={"host": host, "port": port})
        return HealthServer(server=httpd, thread=t, port=port)
    except OSError as e:
        log.error("health_server_failed", extra={"error": str(e), "port": port})
        return HealthServer()

# ------------------------------ Plugins --------------------------------------

def load_plugins(entry_point_group: str, ctx: "BootstrapContext", log: logging.Logger) -> List[str]:
    loaded: List[str] = []
    with contextlib.suppress(Exception):
        for ep in md.entry_points().select(group=entry_point_group):  # type: ignore[attr-defined]
            try:
                fn = ep.load()
                if callable(fn):
                    fn(ctx)  # type: ignore
                    loaded.append(ep.name)
            except Exception as e:
                log.error("plugin_load_failed", extra={"name": ep.name, "error": str(e)})
    return loaded

# ------------------------------ BootstrapContext -----------------------------

@dataclass
class BootstrapContext:
    config: Dict[str, Any]
    logger: logging.Logger
    metrics: Metrics
    tracing: Tracing
    health: HealthServer
    started_at: float = field(default_factory=time.time)
    _shutdown_hooks: List[Callable[[], None]] = field(default_factory=list)

    def ready(self) -> None:
        _HealthState.ready = True
        self.logger.info("service_ready")

    def not_ready(self) -> None:
        _HealthState.ready = False
        self.logger.warning("service_not_ready")

    def on_shutdown(self, hook: Callable[[], None]) -> None:
        self._shutdown_hooks.append(hook)

    def shutdown(self) -> None:
        self.logger.info("shutdown_initiated")
        _HealthState.live = False
        _HealthState.ready = False
        for hook in reversed(self._shutdown_hooks):
            with contextlib.suppress(Exception):
                hook()
        # stop health server
        if self.health.server:
            with contextlib.suppress(Exception):
                self.health.server.shutdown()
                self.health.server.server_close()
        # flush logging
        for h in list(self.logger.handlers):
            with contextlib.suppress(Exception):
                h.flush()
        # shutdown tracing
        if self.tracing.provider and self.tracing.processor:
            with contextlib.suppress(Exception):
                self.tracing.processor.shutdown()
                self.tracing.provider.shutdown()
        self.logger.info("shutdown_completed", extra={"uptime_sec": round(time.time() - self.started_at, 3)})

# ------------------------------ uvloop (optional) ----------------------------

def maybe_setup_uvloop(log: logging.Logger) -> None:
    try:
        import uvloop  # type: ignore
        uvloop.install()
        log.info("uvloop_installed")
    except Exception:
        log.info("uvloop_not_available")

# ------------------------------ Main bootstrap -------------------------------

def bootstrap(
    *,
    config_path: Optional[Union[str, Path]] = None,
    service_name: Optional[str] = None,
    validate: bool = True,
    load_plugins_group: str = "omnimind.plugins",
) -> BootstrapContext:
    """
    Выполняет полный цикл инициализации.
    Возвращает BootstrapContext и не блокирует поток.
    """
    cfg = load_config(config_path)
    # безопасно разрешаем секреты
    cfg = resolve_secrets(cfg)  # type: ignore
    if validate:
        validate_config(cfg)

    log = setup_logging(cfg)
    maybe_setup_uvloop(log)

    # Проставим имя сервиса в конфиг, если задано
    if service_name:
        cfg.setdefault("app", {})["name"] = service_name

    metrics = setup_metrics(cfg, log)
    tracing = setup_tracing(cfg, log)
    health = setup_health(cfg, log)

    ctx = BootstrapContext(config=cfg, logger=log, metrics=metrics, tracing=tracing, health=health)

    # Обработка сигналов
    def _make_handler(signame: str):
        def _h(_sig: int, _frm: Any):
            log.info("signal_received", extra={"signal": signame})
            ctx.shutdown()
            # немедленный выход, если вне ASGI/uvicorn
            os._exit(0)
        return _h

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(Exception):
            signal.signal(sig, _make_handler(sig.name))

    # Загрузка плагинов
    loaded = load_plugins(load_plugins_group, ctx, log)
    if loaded:
        log.info("plugins_loaded", extra={"count": len(loaded), "names": loaded})

    log.info("bootstrap_complete", extra={"env": cfg.get("app", {}).get("env", "staging")})
    return ctx

# ------------------------------ Example usage --------------------------------
if __name__ == "__main__":
    """
    Пример локального запуска bootstrap для smoke-теста.
    PYTHONPATH=. python ops/omnimind/bootstrap.py
    """
    ctx = bootstrap()
    ctx.ready()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        ctx.shutdown()
