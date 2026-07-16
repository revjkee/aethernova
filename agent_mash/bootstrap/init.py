# agent_mash/bootstrap/init.py
from __future__ import annotations

import atexit
import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import platform
import signal
import sys
import threading
import time
import traceback
import uuid
from typing import Any, Awaitable, Callable, Mapping, MutableMapping, Optional

_BOOTSTRAP_LOCK = threading.RLock()
_BOOTSTRAP_STATE: dict[str, Any] = {
    "done": False,
    "ts": None,
    "run_id": None,
    "pid": os.getpid(),
    "errors": [],
}


class BootstrapError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True, slots=True)
class BootstrapConfig:
    app_name: str = "agent_mash"
    environment: str = "dev"  # dev|test|staging|prod
    log_level: str = "INFO"  # DEBUG|INFO|WARNING|ERROR|CRITICAL
    log_format: str = "json"  # json|text
    timezone: str = "UTC"
    enable_uvloop: bool = True
    strict_env: bool = True
    install_signal_handlers: bool = True
    graceful_shutdown_timeout_s: float = 20.0
    allow_root_in_prod: bool = False
    require_utf8_io: bool = True
    fail_fast: bool = True
    extra: Mapping[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class BootstrapContext:
    run_id: str
    started_at_unix: float
    config: BootstrapConfig
    python: str
    platform: str
    pid: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at_unix": self.started_at_unix,
            "app_name": self.config.app_name,
            "environment": self.config.environment,
            "pid": self.pid,
            "python": self.python,
            "platform": self.platform,
            "log_level": self.config.log_level,
            "log_format": self.config.log_format,
            "timezone": self.config.timezone,
        }


def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(key)
    if v is None:
        return default
    v = v.strip()
    return v if v else default


def _parse_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    v = value.strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


def load_config_from_env(prefix: str = "AGENT_MASH_") -> BootstrapConfig:
    """
    Читает конфиг bootstrap из окружения.
    Никаких догадок: только явные значения или дефолты.
    """
    app_name = _env(f"{prefix}APP_NAME", "agent_mash") or "agent_mash"
    environment = (_env(f"{prefix}ENV", "dev") or "dev").lower()
    log_level = (_env(f"{prefix}LOG_LEVEL", "INFO") or "INFO").upper()
    log_format = (_env(f"{prefix}LOG_FORMAT", "json") or "json").lower()
    timezone = _env(f"{prefix}TZ", "UTC") or "UTC"

    enable_uvloop = _parse_bool(_env(f"{prefix}UVLOOP"), True)
    strict_env = _parse_bool(_env(f"{prefix}STRICT_ENV"), True)
    install_signal_handlers = _parse_bool(_env(f"{prefix}SIGNALS"), True)

    graceful_shutdown_timeout_s = float(_env(f"{prefix}SHUTDOWN_TIMEOUT_S", "20") or "20")
    allow_root_in_prod = _parse_bool(_env(f"{prefix}ALLOW_ROOT_IN_PROD"), False)
    require_utf8_io = _parse_bool(_env(f"{prefix}REQUIRE_UTF8_IO"), True)
    fail_fast = _parse_bool(_env(f"{prefix}FAIL_FAST"), True)

    extras: dict[str, str] = {}
    extras_prefix = f"{prefix}EXTRA_"
    for k, v in os.environ.items():
        if k.startswith(extras_prefix):
            extras[k[len(extras_prefix):].lower()] = v

    return BootstrapConfig(
        app_name=app_name,
        environment=environment,
        log_level=log_level,
        log_format=log_format,
        timezone=timezone,
        enable_uvloop=enable_uvloop,
        strict_env=strict_env,
        install_signal_handlers=install_signal_handlers,
        graceful_shutdown_timeout_s=graceful_shutdown_timeout_s,
        allow_root_in_prod=allow_root_in_prod,
        require_utf8_io=require_utf8_io,
        fail_fast=fail_fast,
        extra=extras,
    )


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: dict[str, Any] = {
            "ts": time.time(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        ctx = get_bootstrap_context(silent=True)
        if ctx is not None:
            base["run_id"] = ctx.run_id
            base["env"] = ctx.config.environment
            base["app"] = ctx.config.app_name
            base["pid"] = ctx.pid

        if record.exc_info:
            base["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            base["exc"] = "".join(traceback.format_exception(*record.exc_info))

        # переносим "extra" поля
        for k, v in record.__dict__.items():
            if k in {
                "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread", "threadName",
                "processName", "process",
            }:
                continue
            if k.startswith("_"):
                continue
            if k not in base:
                base[k] = v

        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))


def _configure_logging(cfg: BootstrapConfig) -> None:
    level = getattr(logging, cfg.log_level.upper(), None)
    if not isinstance(level, int):
        raise BootstrapError(f"Invalid log level: {cfg.log_level}")

    root = logging.getLogger()
    root.setLevel(level)

    # чистим старые хендлеры (важно для тестов и повторного запуска)
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(stream=sys.stdout)
    if cfg.log_format == "json":
        handler.setFormatter(_JsonFormatter())
    elif cfg.log_format == "text":
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
        handler.setFormatter(logging.Formatter(fmt=fmt))
    else:
        raise BootstrapError(f"Invalid log format: {cfg.log_format}")

    root.addHandler(handler)

    # шумные логгеры понижаем до WARNING
    for noisy in ("asyncio", "urllib3", "httpx", "uvicorn", "gunicorn", "sqlalchemy"):
        logging.getLogger(noisy).setLevel(max(level, logging.WARNING))


def _require_utf8_io() -> None:
    # Python 3.7+ поддерживает reconfigure для stdio в большинстве случаев
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        raise BootstrapError(f"Failed to enforce UTF-8 stdio: {e}") from e


def _validate_environment(cfg: BootstrapConfig) -> None:
    allowed_env = {"dev", "test", "staging", "prod"}
    if cfg.environment not in allowed_env:
        raise BootstrapError(f"Invalid environment: {cfg.environment}. Allowed: {sorted(allowed_env)}")

    if cfg.environment == "prod":
        # запрет запуска от root, если явно не разрешено
        if not cfg.allow_root_in_prod:
            if os.name != "nt":
                try:
                    if os.geteuid() == 0:
                        raise BootstrapError("Refusing to run as root in prod (set ALLOW_ROOT_IN_PROD=true to override)")
                except AttributeError:
                    # платформа без geteuid
                    pass

        # в проде stricter defaults
        if cfg.strict_env:
            # минимальный набор критичных переменных, которые часто забывают
            critical = [
                "TZ",
            ]
            missing = [k for k in critical if not _env(k)]
            if missing:
                raise BootstrapError(f"Missing critical env vars in prod: {missing}")

    if cfg.graceful_shutdown_timeout_s <= 0:
        raise BootstrapError("graceful_shutdown_timeout_s must be > 0")


def _install_uvloop_if_possible() -> None:
    # uvloop опциональный, без принуждения и без догадок
    with contextlib.suppress(Exception):
        import uvloop  # type: ignore

        uvloop.install()


def _set_timezone(tz: str) -> None:
    # POSIX: влияет на time.localtime и подобное
    os.environ["TZ"] = tz
    with contextlib.suppress(Exception):
        time.tzset()


def _make_context(cfg: BootstrapConfig) -> BootstrapContext:
    run_id = str(uuid.uuid4())
    started_at = time.time()
    return BootstrapContext(
        run_id=run_id,
        started_at_unix=started_at,
        config=cfg,
        python=sys.version.replace("\n", " "),
        platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
        pid=os.getpid(),
    )


def get_bootstrap_context(*, silent: bool = False) -> Optional[BootstrapContext]:
    ctx = _BOOTSTRAP_STATE.get("context")
    if isinstance(ctx, BootstrapContext):
        return ctx
    if silent:
        return None
    raise BootstrapError("Bootstrap context is not initialized")


def is_bootstrapped() -> bool:
    return bool(_BOOTSTRAP_STATE.get("done") is True)


def _record_error(err: BaseException) -> None:
    try:
        _BOOTSTRAP_STATE["errors"].append(
            {
                "type": type(err).__name__,
                "msg": str(err),
                "trace": traceback.format_exc(),
                "ts": time.time(),
            }
        )
    except Exception:
        # не допускаем вторичных ошибок в обработке ошибок
        pass


def _maybe_fail_fast(cfg: BootstrapConfig, err: BaseException) -> None:
    if cfg.fail_fast:
        raise err


def bootstrap(config: Optional[BootstrapConfig] = None) -> BootstrapContext:
    """
    Синхронный bootstrap: можно вызывать многократно, фактически выполнится один раз.
    """
    with _BOOTSTRAP_LOCK:
        if is_bootstrapped():
            return get_bootstrap_context()

        cfg = config or load_config_from_env()
        try:
            if cfg.require_utf8_io:
                _require_utf8_io()
            _set_timezone(cfg.timezone)
            _validate_environment(cfg)
            _configure_logging(cfg)
            if cfg.enable_uvloop:
                _install_uvloop_if_possible()

            ctx = _make_context(cfg)
            _BOOTSTRAP_STATE["context"] = ctx
            _BOOTSTRAP_STATE["run_id"] = ctx.run_id
            _BOOTSTRAP_STATE["ts"] = ctx.started_at_unix

            logger = logging.getLogger(f"{cfg.app_name}.bootstrap")
            logger.info("bootstrap_initialized", extra={"bootstrap": ctx.as_dict()})

            if cfg.install_signal_handlers:
                _install_signal_handlers(cfg)

            atexit.register(_on_exit)

            _BOOTSTRAP_STATE["done"] = True
            return ctx
        except BaseException as e:  # noqa: BLE001
            _record_error(e)
            # попытка поднять логирование хотя бы текстом, если ещё не успели
            with contextlib.suppress(Exception):
                logging.basicConfig(level=logging.INFO)
                logging.getLogger("bootstrap").exception("bootstrap_failed")
            if config is None:
                # если конфиг был из env, попытка прочитать fail_fast ещё раз бессмысленна
                raise
            _maybe_fail_fast(cfg, e)
            raise


async def bootstrap_async(
    config: Optional[BootstrapConfig] = None,
    *,
    async_init: Optional[Callable[[BootstrapContext], Awaitable[None]]] = None,
) -> BootstrapContext:
    """
    Асинхронный bootstrap: сначала выполняет sync bootstrap, затем опциональную async-инициализацию.
    """
    ctx = bootstrap(config)
    if async_init is None:
        return ctx

    # защита от повторного вызова async_init
    key = "async_init_done"
    with _BOOTSTRAP_LOCK:
        if _BOOTSTRAP_STATE.get(key) is True:
            return ctx
        _BOOTSTRAP_STATE[key] = "in_progress"

    logger = logging.getLogger(f"{ctx.config.app_name}.bootstrap")
    try:
        await async_init(ctx)
        with _BOOTSTRAP_LOCK:
            _BOOTSTRAP_STATE[key] = True
        logger.info("bootstrap_async_initialized")
        return ctx
    except BaseException as e:  # noqa: BLE001
        _record_error(e)
        with _BOOTSTRAP_LOCK:
            _BOOTSTRAP_STATE[key] = False
        logger.exception("bootstrap_async_failed")
        _maybe_fail_fast(ctx.config, e)
        raise


def _install_signal_handlers(cfg: BootstrapConfig) -> None:
    logger = logging.getLogger(f"{cfg.app_name}.bootstrap")

    def _handler(signum: int, _frame: Any) -> None:
        sig = signal.Signals(signum).name if signum in signal.Signals.__members__.values() else str(signum)
        logger.warning("signal_received", extra={"signal": sig})
        _BOOTSTRAP_STATE["shutdown_requested"] = True
        _BOOTSTRAP_STATE["shutdown_signal"] = sig

    # SIGTERM/SIGINT: стандартные для остановки сервисов
    for s in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(Exception):
            signal.signal(s, _handler)

    # SIGHUP: если есть, логируем как запрос перезагрузки
    if hasattr(signal, "SIGHUP"):
        with contextlib.suppress(Exception):
            signal.signal(signal.SIGHUP, _handler)


def shutdown_requested() -> bool:
    return bool(_BOOTSTRAP_STATE.get("shutdown_requested") is True)


async def wait_for_shutdown(*, poll_interval_s: float = 0.2) -> None:
    while not shutdown_requested():
        await asyncio.sleep(poll_interval_s)


def _on_exit() -> None:
    ctx = get_bootstrap_context(silent=True)
    logger = logging.getLogger("bootstrap")
    if ctx is None:
        return
    logger.info(
        "process_exit",
        extra={
            "run_id": ctx.run_id,
            "pid": ctx.pid,
            "errors_count": len(_BOOTSTRAP_STATE.get("errors") or []),
        },
    )


def bootstrap_state() -> Mapping[str, Any]:
    """
    Возвращает read-only снимок состояния bootstrap (без мутаций).
    """
    with _BOOTSTRAP_LOCK:
        out: dict[str, Any] = dict(_BOOTSTRAP_STATE)
        ctx = out.get("context")
        if isinstance(ctx, BootstrapContext):
            out["context"] = ctx.as_dict()
        return out


def require_bootstrap() -> BootstrapContext:
    """
    Явная гарантия, что bootstrap был вызван: иначе исключение.
    """
    return get_bootstrap_context()


def safe_main(
    main_fn: Callable[[], int],
    *,
    config: Optional[BootstrapConfig] = None,
) -> int:
    """
    Обёртка для entrypoint: поднимает bootstrap и даёт единый формат падений.
    """
    try:
        bootstrap(config)
        return int(main_fn())
    except SystemExit as e:
        return int(e.code or 0)
    except BaseException as e:  # noqa: BLE001
        _record_error(e)
        logging.getLogger("bootstrap").exception("fatal_error")
        return 1


async def safe_main_async(
    main_fn: Callable[[], Awaitable[int]],
    *,
    config: Optional[BootstrapConfig] = None,
    async_init: Optional[Callable[[BootstrapContext], Awaitable[None]]] = None,
) -> int:
    """
    Асинхронный entrypoint: bootstrap_async + единый формат падений.
    """
    try:
        await bootstrap_async(config, async_init=async_init)
        return int(await main_fn())
    except SystemExit as e:
        return int(e.code or 0)
    except BaseException as e:  # noqa: BLE001
        _record_error(e)
        logging.getLogger("bootstrap").exception("fatal_error")
        return 1


__all__ = [
    "BootstrapConfig",
    "BootstrapContext",
    "BootstrapError",
    "bootstrap",
    "bootstrap_async",
    "bootstrap_state",
    "get_bootstrap_context",
    "is_bootstrapped",
    "load_config_from_env",
    "require_bootstrap",
    "safe_main",
    "safe_main_async",
    "shutdown_requested",
    "wait_for_shutdown",
]
