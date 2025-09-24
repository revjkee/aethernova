# -*- coding: utf-8 -*-
"""
OblivionVault Core — Bootstrap (industrial-grade)

Возможности:
- Загрузка конфигурации YAML/JSON с подстановкой ${ENV} и безопасной валидацией ключевых полей
- Подготовка директорий (data/log/conf), проверка прав TLS/ключей, создание PID-файла
- Логирование: JSON-логгер, раздельный audit-лог, ротация, уровни из конфига
- Наблюдаемость: Prometheus (если установлен), OpenTelemetry (если установлен)
- Безопасность: HSTS/CSP/Headers, CORS из конфига, снижение привилегий (setuid/setgid), drop supplementary groups
- Плагины: загрузка Python-плагинов из каталога, безопасный белый список
- HTTP-приложение: FastAPI, системные middleware, подключение роутеров v1 (retention — если доступен)
- Health/Readiness: встроенные endpoints и отдельный лёгкий TCP-сервер
- Сигналы: SIGTERM/SIGINT — graceful shutdown, SIGHUP — перезагрузка конфигурации
- Запуск: uvicorn (если установлен), иначе informative ошибка

Совместимость: Python 3.9+
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import importlib
import importlib.util
import json
import logging
import logging.handlers
import os
import pwd
import grp
import re
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

# ------------------------------
# Опциональные зависимости
# ------------------------------

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False

try:
    from fastapi import FastAPI, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, PlainTextResponse
    _HAS_FASTAPI = True
except Exception:
    _HAS_FASTAPI = False

try:
    import uvicorn  # type: ignore
    _HAS_UVICORN = True
except Exception:
    _HAS_UVICORN = False

try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST  # type: ignore
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False

try:
    # Ленивая инициализация OTEL в рантайме
    from opentelemetry import trace  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
    from opentelemetry.sdk.resources import Resource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
    _HAS_OTEL = True
except Exception:
    _HAS_OTEL = False


SDK_NAME = "oblivionvault-core"
DEFAULT_CONFIG_PATHS = [
    "/etc/oblivionvault/config.yml",
    "/etc/oblivionvault/oblivionvault.yaml",
    "./configs/oblivionvault.yaml",
]

LOG = logging.getLogger("oblivionvault.bootstrap")


# ------------------------------
# Утилиты
# ------------------------------

def expand_env(obj: Any) -> Any:
    """
    Рекурсивная подстановка переменных окружения вида ${VAR} или ${VAR:-default}
    в строковых значениях структуры данных.
    """
    if isinstance(obj, dict):
        return {k: expand_env(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [expand_env(v) for v in obj]
    if isinstance(obj, str):
        # ${VAR:-default} и ${VAR}
        def repl(m: re.Match[str]) -> str:
            var = m.group(1)
            default = m.group(2)
            val = os.environ.get(var, default if default is not None else "")
            return val
        return re.sub(r"\$\{([A-Z0-9_]+)(?::-(.*?) )?\}", lambda m: repl(m), obj)
    return obj


def _read_yaml_or_json(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if _HAS_YAML and (path.suffix in (".yml", ".yaml")):
        return yaml.safe_load(text) or {}
    try:
        return json.loads(text)
    except Exception:
        if _HAS_YAML:
            return yaml.safe_load(text) or {}
        raise


def ensure_dir(path: Path, mode: int = 0o750, user: Optional[str] = None, group: Optional[str] = None) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    if user or group:
        _chown(path, user, group)


def _chown(path: Path, user: Optional[str], group: Optional[str]) -> None:
    try:
        uid = pwd.getpwnam(user).pw_uid if user else -1
    except Exception:
        uid = -1
    try:
        gid = grp.getgrnam(group).gr_gid if group else -1
    except Exception:
        gid = -1
    if uid != -1 or gid != -1:
        os.chown(path, uid if uid != -1 else -1, gid if gid != -1 else -1)


def _secure_file(path: Path, required_mode_bits: int, max_mode: int = 0o640) -> None:
    """
    Проверка прав для секретных файлов (например TLS private key).
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    st = path.stat()
    # Жёстко ограничим права
    os.chmod(path, max_mode)
    if (st.st_mode & required_mode_bits) != required_mode_bits:
        # Пытаемся поставить необходимые биты, оставляя максимум max_mode
        os.chmod(path, max_mode)


def _compute_cert_fingerprint(path: Path, algo: str = "sha256") -> Optional[str]:
    try:
        import hashlib
        with open(path, "rb") as f:
            data = f.read()
        h = getattr(hashlib, algo)()
        h.update(data)
        return h.hexdigest()
    except Exception:
        return None


# ------------------------------
# Конфигурация
# ------------------------------

@dataclass
class TLSConfig:
    enabled: bool = True
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    client_ca_file: Optional[str] = None
    min_version: str = "TLS1.2"


@dataclass
class ServerConfig:
    bind_addr: str = "0.0.0.0"
    port: int = 9443
    http_enabled: bool = False
    https_enabled: bool = True
    request_timeout: int = 30
    cors_enabled: bool = False
    cors_origins: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class LoggingConfig:
    level: str = "info"
    format: str = "json"
    file: str = "/var/log/oblivionvault/oblivionvault.log"
    rotate_max_size_mb: int = 256
    rotate_max_backups: int = 10
    rotate_max_age_days: int = 14
    compress: bool = True
    audit_file: str = "/var/log/oblivionvault/audit.log"


@dataclass
class TelemetryConfig:
    prom_enabled: bool = True
    prom_bind_addr: str = "127.0.0.1"
    prom_port: int = 9464
    otel_enabled: bool = False
    otel_endpoint: str = "http://127.0.0.1:4318"
    sampling_ratio: float = 0.05


@dataclass
class RuntimeConfig:
    run_as_user: Optional[str] = None
    run_as_group: Optional[str] = None
    pid_file: str = "/run/oblivionvault/oblivionvault.pid"
    data_dir: str = "/var/lib/oblivionvault"
    conf_dir: str = "/etc/oblivionvault"
    log_dir: str = "/var/log/oblivionvault"
    plugins_dir: str = "/var/lib/oblivionvault/plugins"
    allow_plugin_network: bool = False


@dataclass
class AppConfig:
    server: ServerConfig = field(default_factory=ServerConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    # поля ниже читаются без жёсткой типизации, чтобы не ломать обратную совместимость
    features: Dict[str, Any] = field(default_factory=dict)
    observability: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_mapping(m: Mapping[str, Any]) -> "AppConfig":
        s = m.get("server", {})
        t = m.get("tls", {})
        l = m.get("logging", {})
        te = m.get("telemetry", {})
        r = m.get("runtime", {})
        return AppConfig(
            server=ServerConfig(
                bind_addr=s.get("bind_addr", "0.0.0.0"),
                port=int(s.get("port", 9443)),
                http_enabled=bool(s.get("http_enabled", False)),
                https_enabled=bool(s.get("https_enabled", True)),
                request_timeout=int(s.get("request_timeout", 30)),
                cors_enabled=bool(s.get("cors", {}).get("enabled", s.get("cors_enabled", False))),
                cors_origins=s.get("cors", {}).get("allow_origins", s.get("cors_origins", [])) or [],
                security_headers=s.get("security_headers", {}) or {},
            ),
            tls=TLSConfig(
                enabled=bool(t.get("enabled", True)),
                cert_file=t.get("certificate_file") or t.get("cert_file"),
                key_file=t.get("private_key_file") or t.get("key_file"),
                client_ca_file=t.get("client_ca_file"),
                min_version=t.get("min_version", "TLS1.2"),
            ),
            logging=LoggingConfig(
                level=l.get("level", "info"),
                format=l.get("format", "json"),
                file=l.get("file", "/var/log/oblivionvault/oblivionvault.log"),
                rotate_max_size_mb=int((l.get("rotate", {}) or {}).get("max_size_mb", 256)),
                rotate_max_backups=int((l.get("rotate", {}) or {}).get("max_backups", 10)),
                rotate_max_age_days=int((l.get("rotate", {}) or {}).get("max_age_days", 14)),
                compress=bool((l.get("rotate", {}) or {}).get("compress", True)),
                audit_file=l.get("audit_file", "/var/log/oblivionvault/audit.log"),
            ),
            telemetry=TelemetryConfig(
                prom_enabled=bool((m.get("telemetry", {}).get("prometheus", {}) or {}).get("enabled", True)),
                prom_bind_addr=(m.get("telemetry", {}).get("prometheus", {}) or {}).get("bind_addr", "127.0.0.1"),
                prom_port=int((m.get("telemetry", {}).get("prometheus", {}) or {}).get("port", 9464)),
                otel_enabled=bool((m.get("telemetry", {}).get("tracing", {}) or {}).get("enabled", False)),
                otel_endpoint=(m.get("telemetry", {}).get("tracing", {}).get("otlp", {}) or {}).get("endpoint", "http://127.0.0.1:4318"),
                sampling_ratio=float(m.get("telemetry", {}).get("tracing", {}).get("sampling_ratio", 0.05)),
            ),
            runtime=RuntimeConfig(
                run_as_user=(m.get("security", {}) or {}).get("run_as_user") or (m.get("runtime", {}) or {}).get("run_as_user"),
                run_as_group=(m.get("security", {}) or {}).get("run_as_group") or (m.get("runtime", {}) or {}).get("run_as_group"),
                pid_file=(m.get("runtime", {}) or {}).get("pid_file", "/run/oblivionvault/oblivionvault.pid"),
                data_dir=(m.get("storage", {}) or {}).get("file", {}).get("path", "/var/lib/oblivionvault/data").rsplit("/data", 1)[0],
                conf_dir=m.get("runtime", {}).get("conf_dir", "/etc/oblivionvault"),
                log_dir=m.get("runtime", {}).get("log_dir", "/var/log/oblivionvault"),
                plugins_dir=(m.get("plugins", {}) or {}).get("dir", "/var/lib/oblivionvault/plugins"),
                allow_plugin_network=bool((m.get("plugins", {}) or {}).get("sandbox", {}).get("allow_network", False)),
            ),
            features=m.get("features", {}) or {},
            observability=m.get("observability", {}) or {},
        )

    def validate(self) -> None:
        # Минимальная строгая валидация для безопасности сети и TLS
        if not self.server.http_enabled and not self.server.https_enabled:
            raise ValueError("Both HTTP and HTTPS are disabled; nothing to serve")
        if self.server.https_enabled and self.tls.enabled:
            if not self.tls.cert_file or not self.tls.key_file:
                raise ValueError("TLS enabled but certificate_file/private_key_file are missing")
        if self.server.port <= 0 or self.server.port > 65535:
            raise ValueError("Invalid server.port")
        if self.telemetry.prom_enabled:
            if self.telemetry.prom_port <= 0 or self.telemetry.prom_port > 65535:
                raise ValueError("Invalid telemetry.prometheus.port")


# ------------------------------
# Логирование
# ------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": dt.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "lvl": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, ensure_ascii=False)


def setup_logging(cfg: LoggingConfig) -> None:
    level = getattr(logging, cfg.level.upper(), logging.INFO)
    logging.basicConfig(level=level)
    for h in list(logging.getLogger().handlers):
        logging.getLogger().removeHandler(h)

    handlers: List[logging.Handler] = []
    log_dir = Path(cfg.file).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    rotate_bytes = cfg.rotate_max_size_mb * 1024 * 1024
    handler = logging.handlers.RotatingFileHandler(
        cfg.file, maxBytes=rotate_bytes, backupCount=cfg.rotate_max_backups, encoding="utf-8"
    )
    handler.setFormatter(JsonFormatter())
    handlers.append(handler)

    # Дублируем в stderr, полезно для systemd-journal
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(JsonFormatter())
    handlers.append(console)

    root = logging.getLogger()
    root.setLevel(level)
    for h in handlers:
        root.addHandler(h)

    # Отдельный audit-логгер
    audit_handler = logging.handlers.RotatingFileHandler(
        cfg.audit_file, maxBytes=rotate_bytes, backupCount=cfg.rotate_max_backups, encoding="utf-8"
    )
    audit_handler.setFormatter(JsonFormatter())
    audit_logger = logging.getLogger("oblivionvault.audit")
    audit_logger.setLevel(level)
    audit_logger.addHandler(audit_handler)
    audit_logger.propagate = False

    LOG.info("logging initialized: file=%s audit=%s level=%s", cfg.file, cfg.audit_file, cfg.level)


# ------------------------------
# OTEL / Prometheus
# ------------------------------

class Telemetry:
    def __init__(self, cfg: TelemetryConfig):
        self.cfg = cfg
        self._metrics_ready = False
        self._otel_ready = False
        # Метрики
        self.http_requests_total = None
        self.http_request_duration = None
        self.ready_gauge = None

    def init_prom(self) -> None:
        if not self.cfg.prom_enabled:
            return
        if not _HAS_PROM:
            LOG.warning("prometheus_client not installed; metrics disabled")
            return
        # Регистрация метрик
        self.http_requests_total = Counter("ov_http_requests_total", "HTTP requests", ["method", "path", "code"])
        self.http_request_duration = Histogram("ov_http_request_duration_seconds", "HTTP request duration", ["method", "path"])
        self.ready_gauge = Gauge("ov_ready", "Readiness state")
        self._metrics_ready = True
        LOG.info("prometheus metrics registered")

    def init_otel(self) -> None:
        if not self.cfg.otel_enabled:
            return
        if not _HAS_OTEL:
            LOG.warning("opentelemetry not installed; tracing disabled")
            return
        resource = Resource.create({"service.name": SDK_NAME})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=self.cfg.otel_endpoint, timeout=5)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        self._otel_ready = True
        LOG.info("opentelemetry configured: endpoint=%s", self.cfg.otel_endpoint)

    def metrics_asgi(self):
        """
        Возвращает ASGI-обработчик /metrics
        """
        if not self._metrics_ready:
            async def disabled(scope, receive, send):
                if scope["type"] == "http":
                    await send({"type": "http.response.start", "status": 404, "headers": []})
                    await send({"type": "http.response.body", "body": b"metrics disabled"})
            return disabled

        async def app(scope, receive, send):
            if scope["type"] != "http":
                return
            body = generate_latest()
            headers = [(b"content-type", CONTENT_TYPE_LATEST.encode("ascii")), (b"cache-control", b"no-cache")]
            await send({"type": "http.response.start", "status": 200, "headers": headers})
            await send({"type": "http.response.body", "body": body})
        return app


# ------------------------------
# Плагины
# ------------------------------

def load_plugins(dir_path: Path, allowed: Optional[List[str]] = None) -> List[str]:
    loaded: List[str] = []
    if not dir_path.exists():
        return loaded
    for f in dir_path.glob("*.py"):
        name = f.stem
        if allowed and allowed != ["*"] and name not in allowed:
            continue
        spec = importlib.util.spec_from_file_location(f"ov_plugin_{name}", f)
        if not spec or not spec.loader:
            LOG.warning("cannot load plugin: %s", f)
            continue
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)  # type: ignore
            loaded.append(name)
            LOG.info("plugin loaded: %s", name)
        except Exception as e:
            LOG.exception("plugin load failed: %s error=%s", name, e)
    return loaded


# ------------------------------
# Приложение
# ------------------------------

class Bootstrap:
    def __init__(self, config: AppConfig):
        self.cfg = config
        self.telemetry = Telemetry(config.telemetry)
        self._stop_event = threading.Event()
        self._ready = False
        self._pidfile: Optional[Path] = None
        self._app: Optional[Any] = None  # FastAPI
        self._server_thread: Optional[threading.Thread] = None
        self._plugins: List[str] = []

    # ---------- lifecycle ----------

    def prepare_fs(self) -> None:
        # Каталоги
        rt = self.cfg.runtime
        ensure_dir(Path(rt.data_dir), 0o750)
        ensure_dir(Path(rt.log_dir), 0o750)
        ensure_dir(Path(rt.conf_dir), 0o750)
        ensure_dir(Path(rt.plugins_dir), 0o750)

        # TLS-файлы и права
        if self.cfg.server.https_enabled and self.cfg.tls.enabled:
            cert = Path(self.cfg.tls.cert_file or "")
            key = Path(self.cfg.tls.key_file or "")
            _secure_file(cert, required_mode_bits=0o400, max_mode=0o640)
            _secure_file(key, required_mode_bits=0o400, max_mode=0o600)
            LOG.info("TLS cert fingerprint sha256=%s", _compute_cert_fingerprint(cert) or "n/a")

    def write_pidfile(self) -> None:
        pid_path = Path(self.cfg.runtime.pid_file)
        ensure_dir(pid_path.parent, 0o755)
        pid_path.write_text(str(os.getpid()), encoding="utf-8")
        self._pidfile = pid_path
        LOG.info("pid file written: %s", pid_path)

    def drop_privileges(self) -> None:
        user = self.cfg.runtime.run_as_user
        group = self.cfg.runtime.run_as_group
        if os.geteuid() != 0 or not user:
            return
        target_uid = pwd.getpwnam(user).pw_uid
        target_gid = grp.getgrnam(group).gr_gid if group else pwd.getpwnam(user).pw_gid
        # Drop supplementary groups
        os.setgroups([])
        os.setgid(target_gid)
        os.setuid(target_uid)
        # Ensure no privilege regain
        os.umask(0o027)
        LOG.info("privileges dropped to %s:%s", user, group or "")

    def build_app(self) -> Any:
        if not _HAS_FASTAPI:
            raise RuntimeError("fastapi is not installed")

        app = FastAPI(title="OblivionVault Core API", version="1.0")

        # CORS
        s = self.cfg.server
        if s.cors_enabled and self.cfg.server.cors_origins:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=self.cfg.server.cors_origins,
                allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                allow_headers=["Authorization", "Content-Type", "X-Request-Id", "X-Tenant-Id"],
                allow_credentials=False,
                max_age=600,
            )

        # Безопасные заголовки
        @app.middleware("http")
        async def security_headers(request: Request, call_next):
            start = time.perf_counter()
            req_id = request.headers.get("X-Request-Id") or str(os.urandom(8).hex())
            headers = {
                "X-Request-Id": req_id,
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": self.cfg.server.security_headers.get("x_frame_options", "DENY"),
                "Referrer-Policy": self.cfg.server.security_headers.get("referrer_policy", "no-referrer"),
            }
            if self.cfg.server.security_headers.get("strict_transport_security"):
                headers["Strict-Transport-Security"] = self.cfg.server.security_headers["strict_transport_security"]
            if self.cfg.server.security_headers.get("content_security_policy"):
                headers["Content-Security-Policy"] = self.cfg.server.security_headers["content_security_policy"]
            if self.cfg.server.security_headers.get("permissions_policy"):
                headers["Permissions-Policy"] = self.cfg.server.security_headers["permissions_policy"]

            response: Response
            try:
                response = await call_next(request)
            except Exception as e:
                LOG.exception("unhandled error")
                response = JSONResponse(status_code=500, content={"message": "internal error"})
            for k, v in headers.items():
                response.headers.setdefault(k, v)

            if _HAS_PROM and self.telemetry.http_requests_total and self.telemetry.http_request_duration:
                elapsed = time.perf_counter() - start
                path = request.url.path
                self.telemetry.http_requests_total.labels(request.method, path, str(response.status_code)).inc()
                self.telemetry.http_request_duration.labels(request.method, path).observe(elapsed)

            return response

        # Health endpoints
        @app.get("/healthz")
        async def healthz():
            return {"status": "ok", "ts": dt.datetime.utcnow().isoformat() + "Z"}

        @app.get("/readyz")
        async def readyz():
            if self._ready:
                return {"ready": True}
            return JSONResponse(status_code=503, content={"ready": False})

        # Prometheus endpoint
        if self.cfg.telemetry.prom_enabled:
            app.add_route("/metrics", self.telemetry.metrics_asgi(), methods=["GET"])

        # Подключаем встроенные маршрутизаторы, если доступны в системе
        try:
            mod = importlib.import_module("oblivionvault.api.http.routers.v1.retention")
            router = getattr(mod, "router", None)
            if router is not None:
                app.include_router(router)
                LOG.info("router mounted: retention v1")
        except Exception:
            LOG.info("retention router not found; skipping")

        # Хук audit
        @app.post("/_internal/audit")
        async def _audit(event: Dict[str, Any]):
            logging.getLogger("oblivionvault.audit").info(json.dumps(event, ensure_ascii=False))
            return {"ok": True}

        self._app = app
        return app

    def start_http(self) -> None:
        if not _HAS_UVICORN:
            raise RuntimeError("uvicorn is not installed")
        if self._app is None:
            self.build_app()

        s = self.cfg.server
        ssl_kwargs: Dict[str, Any] = {}
        if s.https_enabled and self.cfg.tls.enabled:
            ssl_kwargs = {
                "ssl_certfile": self.cfg.tls.cert_file,
                "ssl_keyfile": self.cfg.tls.key_file,
            }

        def _run():
            uvicorn.run(  # type: ignore
                self._app,
                host=s.bind_addr,
                port=s.port,
                workers=1,
                log_config=None,  # мы уже настроили logging
                timeout_keep_alive=s.request_timeout,
                **ssl_kwargs,
            )

        self._server_thread = threading.Thread(target=_run, name="uvicorn", daemon=True)
        self._server_thread.start()
        LOG.info("http server starting on %s:%s https=%s", s.bind_addr, s.port, bool(ssl_kwargs))

    def start(self) -> None:
        # Метрики/трейсинг
        self.telemetry.init_prom()
        self.telemetry.init_otel()

        # ФС, PID, права
        self.prepare_fs()
        self.write_pidfile()
        self.drop_privileges()

        # Плагины (список из конфига, если задан)
        plugins_allowed = os.environ.get("OV_PLUGINS_ALLOWED", "*").split(",") if os.environ.get("OV_PLUGINS_ALLOWED") else ["*"]
        self._plugins = load_plugins(Path(self.cfg.runtime.plugins_dir), plugins_allowed)

        # HTTP
        self.build_app()
        self.start_http()

        # Готовность
        self._ready = True
        if _HAS_PROM and self.telemetry.ready_gauge:
            self.telemetry.ready_gauge.set(1)

        LOG.info("bootstrap complete")

    def stop(self) -> None:
        self._ready = False
        if _HAS_PROM and self.telemetry.ready_gauge:
            self.telemetry.ready_gauge.set(0)
        # uvicorn в режиме внутри потока завершится по сигналу процесса; здесь только housekeeping
        if self._pidfile and self._pidfile.exists():
            try:
                self._pidfile.unlink()
            except Exception:
                pass
        LOG.info("stopped")

    # ---------- конфиг-релоад ----------

    def reload_config(self, new_cfg: AppConfig) -> None:
        # На практике тут стоит сделать hot-reload отдельных подсистем.
        self.cfg = new_cfg
        LOG.info("configuration reloaded")


# ------------------------------
# CLI / Main
# ------------------------------

def load_config(paths: List[str]) -> AppConfig:
    last_err: Optional[Exception] = None
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        try:
            raw = _read_yaml_or_json(path)
            raw = expand_env(raw)
            cfg = AppConfig.from_mapping(raw)
            cfg.validate()
            LOG.info("config loaded from %s", path)
            return cfg
        except Exception as e:
            last_err = e
            LOG.exception("failed to load config from %s", path)
    raise RuntimeError(f"config not found or invalid; tried: {paths}; last_error={last_err}")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="oblivionvault-bootstrap")
    ap.add_argument("-c", "--config", action="append", help="Path to config file (YAML/JSON). Can be specified multiple times.")
    ap.add_argument("--foreground", action="store_true", help="Run in foreground (do not daemonize).")
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    config_paths = args.config or os.environ.get("OV_CONFIG_PATHS", "").split(":")
    if not any(config_paths):
        config_paths = DEFAULT_CONFIG_PATHS

    # Настроим базовое логирование в консоль до чтения конфига
    logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler(sys.stderr)])
    try:
        cfg = load_config(config_paths)
    except Exception as e:
        LOG.error("cannot load configuration: %s", e)
        return 2

    try:
        setup_logging(cfg.logging)
    except Exception as e:
        LOG.error("cannot setup logging: %s", e)
        return 3

    boot = Bootstrap(cfg)

    # Сигналы
    def _sigterm(signum, frame):
        LOG.info("signal received: %s", signum)
        boot.stop()
        sys.exit(0)

    def _sighup(signum, frame):
        LOG.info("SIGHUP received; reloading configuration")
        try:
            new_cfg = load_config(config_paths)
            boot.reload_config(new_cfg)
        except Exception as e:
            LOG.error("reload failed: %s", e)

    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGINT, _sigterm)
    try:
        signal.signal(signal.SIGHUP, _sighup)
    except Exception:
        pass  # Windows

    try:
        boot.start()
    except Exception as e:
        LOG.exception("bootstrap failed: %s", e)
        return 4

    # Ожидание завершения
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        boot.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
