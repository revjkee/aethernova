# ledger-core/examples/quickstart/run.py
from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import signal
import socket
import sys
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

# ====================== Мягкие импорты (всё опционально) ======================

with contextlib.suppress(Exception):
    from dotenv import load_dotenv  # type: ignore
    _HAS_DOTENV = True
else:
    _HAS_DOTENV = False

with contextlib.suppress(Exception):
    import uvloop  # type: ignore
    _HAS_UVLOOP = True
else:
    _HAS_UVLOOP = False

with contextlib.suppress(Exception):
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine  # type: ignore
    from sqlalchemy import text as sa_text  # type: ignore
    _HAS_SA = True
else:
    _HAS_SA = False

with contextlib.suppress(Exception):
    from ledger.adapters.db.repository import create_session_factory  # type: ignore
    _HAS_REPO = True
else:
    _HAS_REPO = False

with contextlib.suppress(Exception):
    from ledger.crypto.signer import load_signer_from_pem, HashAlgorithm  # type: ignore
    _HAS_SIGNER = True
else:
    _HAS_SIGNER = False

with contextlib.suppress(Exception):
    from ledger.security.self_inhibitor_integration import (
        InMemoryStore,
        SelfInhibitor,
        EvaluationInput,
        env_policy_loader,
    )  # type: ignore
    _HAS_INHIBITOR = True
else:
    _HAS_INHIBITOR = False

with contextlib.suppress(Exception):
    from adapters.legacy_migration_adapter import (  # type: ignore
        LegacyMigrationAdapter,
        LoadMode,
        MigrationSourceSpec,
        MigrationTargetSpec,
        FileStateStore,
        TransformRegistry,
        MigrationPolicy,
    )
    _HAS_MIGRATION = True
else:
    _HAS_MIGRATION = False

with contextlib.suppress(Exception):
    from opentelemetry import trace  # type: ignore
    from opentelemetry.sdk.resources import Resource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter  # type: ignore
    _HAS_OTEL = True
else:
    _HAS_OTEL = False


# ====================== Конфигурация ======================

@dataclass(slots=True)
class AppConfig:
    env: str = "dev"
    service_name: str = "ledger-quickstart"
    log_json: bool = True
    log_level: str = "INFO"
    # HTTP пробы
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    # База данных
    db_dsn: Optional[str] = None  # "postgresql+asyncpg://user:pass@host:5432/db"
    db_connect_timeout_s: float = 5.0
    db_max_retries: int = 10
    db_backoff_base_s: float = 0.2
    db_backoff_max_s: float = 3.0
    # Подписант (демо)
    pem_path: Optional[str] = None
    # Telemetry
    otel_console: bool = False
    # Демо‑миграция
    demo_csv_path: Optional[str] = None
    demo_table: str = "demo"

    @staticmethod
    def from_env() -> "AppConfig":
        if _HAS_DOTENV:
            load_dotenv(override=False)
        return AppConfig(
            env=os.getenv("APP_ENV", "dev"),
            service_name=os.getenv("SERVICE_NAME", "ledger-quickstart"),
            log_json=os.getenv("LOG_JSON", "1") == "1",
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            http_host=os.getenv("HTTP_HOST", "0.0.0.0"),
            http_port=int(os.getenv("HTTP_PORT", "8080")),
            db_dsn=os.getenv("DB_DSN") or None,
            db_connect_timeout_s=float(os.getenv("DB_CONNECT_TIMEOUT", "5.0")),
            db_max_retries=int(os.getenv("DB_MAX_RETRIES", "10")),
            db_backoff_base_s=float(os.getenv("DB_BACKOFF_BASE", "0.2")),
            db_backoff_max_s=float(os.getenv("DB_BACKOFF_MAX", "3.0")),
            pem_path=os.getenv("SIGNING_KEY_PEM") or None,
            otel_console=os.getenv("OTEL_CONSOLE", "0") == "1",
            demo_csv_path=os.getenv("DEMO_CSV_PATH") or None,
            demo_table=os.getenv("DEMO_TABLE", "demo"),
        )


# ====================== Логирование ======================

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def setup_logging(cfg: AppConfig) -> None:
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    h = logging.StreamHandler(sys.stdout)
    h.setLevel(level)
    h.setFormatter(JsonFormatter() if cfg.log_json else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.handlers.clear()
    root.addHandler(h)


# ====================== OpenTelemetry (опционально) ======================

def setup_otel(cfg: AppConfig) -> None:
    if not _HAS_OTEL or not cfg.otel_console:
        return
    resource = Resource.create({"service.name": cfg.service_name, "service.env": cfg.env})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)


# ====================== Мини‑HTTP сервер для health/ready ======================

class MiniHTTPServer:
    """
    Простейший HTTP‑сервер на asyncio без зависимостей.
    Обслуживает только GET /health и GET /ready.
    """
    def __init__(self, host: str, port: int, readiness_flag: asyncio.Event) -> None:
        self._host = host
        self._port = port
        self._server: Optional[asyncio.AbstractServer] = None
        self._ready = readiness_flag
        self._log = logging.getLogger("http")

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)
        sock = next(iter(self._server.sockets or []), None)
        addr = sock.getsockname() if sock else (self._host, self._port)
        self._log.info("HTTP server started", extra={"extra": {"addr": str(addr)}})

    async def stop(self) -> None:
        if not self._server:
            return
        self._server.close()
        await self._server.wait_closed()
        self._log.info("HTTP server stopped")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        except asyncio.TimeoutError:
            writer.close()
            return
        req = data.decode(errors="ignore")
        # очень упрощённый разбор первой строки
        line = req.split("\r\n", 1)[0]
        method, path, _ = (line.split(" ") + ["", ""])[:3]
        if method != "GET":
            await self._respond(writer, 405, {"error": "method not allowed"})
            return
        if path.startswith("/health"):
            await self._respond(writer, 200, {"status": "ok", "ts": _utc()})
            return
        if path.startswith("/ready"):
            if self._ready.is_set():
                await self._respond(writer, 200, {"ready": True, "ts": _utc()})
            else:
                await self._respond(writer, 503, {"ready": False})
            return
        await self._respond(writer, 404, {"error": "not found"})

    async def _respond(self, writer: asyncio.StreamWriter, code: int, body: Dict[str, Any]) -> None:
        payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
        headers = [
            f"HTTP/1.1 {code} {'OK' if code==200 else 'ERR'}",
            "Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(payload)}",
            "Connection: close",
            "",
            "",
        ]
        writer.write("\r\n".join(headers).encode() + payload)
        with contextlib.suppress(Exception):
            await writer.drain()
        writer.close()


# ====================== Утилиты ======================

def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _exp_backoff(attempt: int, base: float, maxv: float) -> float:
    d = min(maxv, base * (2 ** (attempt - 1)))
    # небольшой джиттер
    rnd = (time.perf_counter_ns() % 10_000) / 10_000.0
    return max(0.0, d * (0.8 + 0.4 * rnd))


# ====================== Приложение и жизненный цикл ======================

class Application:
    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        self.log = logging.getLogger("app")
        self.ready = asyncio.Event()
        self._bg_tasks: List[asyncio.Task] = []
        self._http = MiniHTTPServer(cfg.http_host, cfg.http_port, self.ready)
        self.engine: Optional["AsyncEngine"] = None  # SQLAlchemy engine

    # -------- старт/останов --------

    async def start(self) -> None:
        # HTTP сервер — стартуем сразу (для /health), /ready поднимем после инициализации
        await self._http.start()

        # Инициализация БД с ретраями (если настроена)
        if _HAS_SA and self.cfg.db_dsn:
            await self._init_db_with_retries()
        else:
            self.log.info("DB not configured or SQLAlchemy missing — skipping DB init")

        # Готово к работе
        self.ready.set()
        self.log.info("Application started", extra={"extra": {"env": self.cfg.env, "service": self.cfg.service_name}})

    async def stop(self, timeout: float = 10.0) -> None:
        self.ready.clear()
        # Остановить фоновые задачи
        await self._cancel_bg(timeout=timeout)
        # Закрыть БД
        if self.engine:
            with contextlib.suppress(Exception):
                await self.engine.dispose()
        # Остановить HTTP
        await self._http.stop()
        self.log.info("Application stopped")

    # -------- DB init --------

    async def _init_db_with_retries(self) -> None:
        assert _HAS_SA
        last_err: Optional[Exception] = None
        for attempt in range(1, self.cfg.db_max_retries + 1):
            try:
                self.engine = create_async_engine(self.cfg.db_dsn, echo=False, pool_pre_ping=True)  # type: ignore[arg-type]
                async with self.engine.connect() as conn:
                    await asyncio.wait_for(conn.execute(sa_text("SELECT 1")), timeout=self.cfg.db_connect_timeout_s)
                self.log.info("DB connected")
                return
            except Exception as e:
                last_err = e
                delay = _exp_backoff(attempt, self.cfg.db_backoff_base_s, self.cfg.db_backoff_max_s)
                self.log.warning("DB connect failed, retrying", extra={"extra": {"attempt": attempt, "delay_s": round(delay, 3), "error": str(e)}})
                await asyncio.sleep(delay)
        # не удалось
        self.log.error("DB connect failed permanently", extra={"extra": {"error": str(last_err)}})
        raise SystemExit(2)

    # -------- фоновые задачи --------

    def spawn_bg(self, coro: Awaitable[Any], name: str) -> None:
        t = asyncio.create_task(self._guard(coro, name), name=name)
        self._bg_tasks.append(t)

    async def _guard(self, coro: Awaitable[Any], name: str) -> None:
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.log.error("Background task crashed", extra={"extra": {"task": name, "error": str(e)}})

    async def _cancel_bg(self, timeout: float) -> None:
        if not self._bg_tasks:
            return
        for t in self._bg_tasks:
            t.cancel()
        with contextlib.suppress(Exception):
            await asyncio.wait(self._bg_tasks, timeout=timeout)


# ====================== Демонстрационные сценарии ======================

async def demo_sign(cfg: AppConfig) -> None:
    if not (_HAS_SIGNER and cfg.pem_path):
        logging.getLogger("demo.sign").info("Signer disabled (no PEM or dependency)")
        return
    pem = open(cfg.pem_path, "rb").read()
    signer = load_signer_from_pem(private_key_pem=pem)
    payload = {"hello": "ledger", "ts": int(time.time())}
    res = signer.sign_message(payload, as_jws=True, detached_payload=False, hash_alg=HashAlgorithm.SHA256)
    logging.getLogger("demo.sign").info("Signed", extra={"extra": {"kid": signer.kid, "alg": signer.alg.value, "hash": res.hash_alg.value, "jws": bool(res.jws_compact)}})

async def demo_inhibitor() -> None:
    if not _HAS_INHIBITOR:
        logging.getLogger("demo.inhibitor").info("Self-inhibitor disabled")
        return
    store = InMemoryStore()
    inh = SelfInhibitor(store=store, policy_loader=env_policy_loader)
    inp = EvaluationInput(action="transfer.create", actor="user:42", risk_score=0.3, context={"amount": "10.00"}, scopes=("payments",))
    res = await inh.evaluate(inp)
    logging.getLogger("demo.inhibitor").info("Evaluation", extra={"extra": {"decision": res.decision.value, "reason": res.reason}})

async def demo_migration(cfg: AppConfig, engine: Optional["AsyncEngine"]) -> None:
    if not _HAS_MIGRATION:
        logging.getLogger("demo.migrate").info("Migration adapter missing — skip")
        return
    if not (engine and _HAS_SA and cfg.demo_csv_path):
        logging.getLogger("demo.migrate").info("No DB or DEMO_CSV_PATH — skip")
        return
    src = MigrationSourceSpec(name="legacy_demo", path=cfg.demo_csv_path, fmt="csv")
    tgt = MigrationTargetSpec(name="demo_table", sql_dsn=cfg.db_dsn, table=cfg.demo_table, unique_keys=("id",))
    state = FileStateStore("./.quickstart_state.json")
    reg = TransformRegistry()
    reg.add("legacy_demo", lambda r: {**r, "email": (r.get("email") or "").strip().lower()})
    policy = MigrationPolicy(batch_size=500, dry_run=False)
    adapter = LegacyMigrationAdapter(source=src, target=tgt, state=state, transforms=reg, policy=policy)
    stats = await adapter.run(LoadMode.INCREMENTAL)
    logging.getLogger("demo.migrate").info("Migration finished", extra={"extra": stats.as_dict()})


# ====================== Команды ======================

async def cmd_health(app: Application) -> int:
    db_ok = False
    if app.engine:
        try:
            async with app.engine.connect() as conn:
                res = await conn.execute(sa_text("SELECT 1"))
                db_ok = int(res.scalar_one()) == 1
        except Exception:
            db_ok = False
    payload = {"db": db_ok, "env": app.cfg.env, "service": app.cfg.service_name}
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0 if db_ok else 2

async def cmd_seed(cfg: AppConfig) -> int:
    await demo_sign(cfg)
    await demo_inhibitor()
    return 0

async def cmd_migrate(cfg: AppConfig, engine: Optional["AsyncEngine"]) -> int:
    await demo_migration(cfg, engine)
    return 0

async def cmd_serve(app: Application) -> int:
    # graceful shutdown по сигналам
    stop = asyncio.Event()
    log = logging.getLogger("serve")

    def _on_signal() -> None:
        log.info("Signal received, shutting down")
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _on_signal)

    await app.start()
    await stop.wait()
    await app.stop(timeout=15.0)
    return 0


# ====================== CLI и main ======================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ledger-quickstart", description="Quickstart runner for ledger-core")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="запустить сервис (HTTP /health и /ready)")
    sub.add_parser("health", help="проверить зависимость БД и вывести состояние в JSON")
    sub.add_parser("seed", help="демо: подпись и self-inhibitor")
    sub.add_parser("migrate", help="демо миграции CSV → БД")

    p.add_argument("--db-dsn", default=None, help="DSN БД (перекрывает DB_DSN)")
    p.add_argument("--pem", default=None, help="Путь к PEM для демо‑подписи")
    p.add_argument("--csv", default=None, help="Путь к CSV для демо‑миграции")
    p.add_argument("--http-port", type=int, default=None, help="Порт HTTP для /health,/ready")
    p.add_argument("--log-json", action=argparse.BooleanOptionalAction, default=None)
    p.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--otel-console", action=argparse.BooleanOptionalAction, default=None)
    return p

def apply_overrides(cfg: AppConfig, args: argparse.Namespace) -> AppConfig:
    if args.db_dsn:
        cfg.db_dsn = args.db_dsn
    if args.pem:
        cfg.pem_path = args.pem
    if args.csv:
        cfg.demo_csv_path = args.csv
    if args.http_port is not None:
        cfg.http_port = int(args.http_port)
    if args.log_json is not None:
        cfg.log_json = bool(args.log_json)
    if args.log_level:
        cfg.log_level = args.log_level
    if args.otel_console is not None:
        cfg.otel_console = bool(args.otel_console)
    return cfg

async def amain() -> int:
    if _HAS_UVLOOP:
        uvloop.install()

    cfg = AppConfig.from_env()
    parser = build_parser()
    args = parser.parse_args()
    cfg = apply_overrides(cfg, args)
    setup_logging(cfg)
    setup_otel(cfg)

    app = Application(cfg)

    # Если нужна БД для отдельных команд — проинициализируем частично
    if _HAS_SA and cfg.db_dsn and args.cmd in ("health", "migrate"):
        try:
            await app._init_db_with_retries()
        except SystemExit:
            # health должен уметь упасть с кодом 2; для migrate — тоже
            if args.cmd == "health":
                print(json.dumps({"db": False, "env": cfg.env}, separators=(",", ":"), ensure_ascii=False))
                return 2
            raise

    if args.cmd == "health":
        return await cmd_health(app)
    if args.cmd == "seed":
        return await cmd_seed(cfg)
    if args.cmd == "migrate":
        return await cmd_migrate(cfg, app.engine)
    if args.cmd == "serve":
        return await cmd_serve(app)

    parser.print_help()
    return 2

def main() -> None:
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
