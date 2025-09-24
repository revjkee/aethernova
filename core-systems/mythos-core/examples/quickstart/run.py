#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mythos-core/examples/quickstart/run.py

Промышленный quickstart-раннер для Mythos Core:
- Без внешних зависимостей (stdlib only)
- Конфиги: TOML/JSON + ENV override (префикс MYTHOS_)
- Асинхронное исполнение, таймауты, корректное завершение по сигналам
- Логирование (текст/JSON), метрики времени, heartbeat-файл
- Команды: run | healthcheck | version | gen-config
- Fallback-движок, если пакет mythos_core не установлен

Python >= 3.11
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import datetime as dt
import importlib
import inspect
import io
import json
import logging
import logging.config
import os
import random
import signal
import sys
import time
import traceback
import types
import typing as t
from dataclasses import dataclass, field
from pathlib import Path

# tomllib доступен в стандартной библиотеке Python 3.11+
try:
    import tomllib  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    tomllib = None  # Для старых интерпретаторов; JSON всё равно доступен.


__APP_NAME__ = "mythos-quickstart"
__VERSION__ = "1.0.0"
__DEFAULT_LOG_FORMAT__ = "text"  # text | json
__ENV_PREFIX__ = "MYTHOS_"


# ------------------------------- УТИЛИТЫ ------------------------------------ #
def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(dt_obj: dt.datetime | None = None) -> str:
    return (dt_obj or utcnow()).isoformat()


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, obj: t.Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def append_jsonl(path: Path, obj: t.Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False))
        f.write("\n")


def env_get(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


def clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))


# --------------------------- КОНФИГУРАЦИЯ ----------------------------------- #
@dataclass(slots=True)
class AppConfig:
    # Основные параметры
    output_dir: Path = field(default_factory=lambda: Path("artifacts") / utcnow().strftime("%Y%m%d_%H%M%S"))
    log_level: str = "INFO"
    log_format: str = __DEFAULT_LOG_FORMAT__  # "text" | "json"
    seed: int | None = None

    # Исполнение
    max_steps: int = 10
    timeout_sec: float | None = 60.0
    profile: bool = False
    dry_run: bool = False

    # Доменно-специфичные параметры движка (пример)
    story_title: str = "Genesis of Aethernova"
    temperature: float = 0.2  # 0..1
    model_path: str | None = None  # путь к локальной модели, если есть

    # Служебные пути
    logs_filename: str = "run.log"
    heartbeat_sec: float = 5.0

    @staticmethod
    def from_mapping(d: dict[str, t.Any]) -> "AppConfig":
        # Преобразуем строки в Path и приводим типы
        cfg = AppConfig()
        for f in dataclasses.fields(AppConfig):
            name = f.name
            if name in d and d[name] is not None:
                val = d[name]
                if f.type is Path:
                    val = Path(val)
                elif f.type is bool:
                    val = bool(val)
                elif f.type in (int, float) or t.get_origin(f.type) in {t.Union, t.Optional}:
                    # Попробуем привести штатно
                    # (нам хватает базового кейса; сложные union-ы тут не нужны)
                    pass
                setattr(cfg, name, val)
        return cfg


def _lower_keys(d: dict[str, t.Any]) -> dict[str, t.Any]:
    return {str(k).lower(): v for k, v in d.items()}


def load_config_file(path: Path) -> dict[str, t.Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    suffix = path.suffix.lower()
    raw = read_text_file(path)
    if suffix in (".toml", ".tml", ".toml.txt"):
        if tomllib is None:
            raise RuntimeError("TOML config is not supported on this Python. Use JSON or upgrade to 3.11+.")
        data = tomllib.loads(raw)
        return _lower_keys(data)
    elif suffix in (".json", ".jsonc"):
        # Простая поддержка "//" комментариев для JSONC
        cleaned = "\n".join(line for line in raw.splitlines() if not line.strip().startswith("//"))
        data = json.loads(cleaned or "{}")
        return _lower_keys(data)
    else:
        raise ValueError(f"Unsupported config format: {suffix}")


def env_overrides(prefix: str = __ENV_PREFIX__) -> dict[str, t.Any]:
    """
    Переменные окружения с префиксом MYTHOS_ перекрывают файл.
    Примеры:
      MYTHOS_LOG_LEVEL=DEBUG
      MYTHOS_MAX_STEPS=50
      MYTHOS_OUTPUT_DIR=out/run1
      MYTHOS_DRY_RUN=1
    """
    out: dict[str, t.Any] = {}
    p = prefix.upper()
    for k, v in os.environ.items():
        if not k.startswith(p):
            continue
        key = k[len(p) :].lower()
        # Приведение типов для простых случаев
        if v.isdigit():
            out[key] = int(v)
        elif v.lower() in ("true", "false", "1", "0", "yes", "no"):
            out[key] = v.lower() in ("true", "1", "yes")
        else:
            try:
                out[key] = float(v) if "." in v else v
            except Exception:
                out[key] = v
    return out


def build_config(args: argparse.Namespace) -> AppConfig:
    base: dict[str, t.Any] = {}
    if args.config:
        base.update(load_config_file(Path(args.config)))
    base.update(env_overrides())
    cli = {
        "output_dir": args.output_dir,
        "log_level": args.log_level,
        "log_format": args.log_format,
        "seed": args.seed,
        "max_steps": args.max_steps,
        "timeout_sec": args.timeout_sec,
        "profile": args.profile,
        "dry_run": args.dry_run,
        "story_title": args.story_title,
        "temperature": args.temperature,
        "model_path": args.model_path,
        "heartbeat_sec": args.heartbeat_sec,
    }
    # Удалим None, чтобы не затирать файл/ENV
    cli = {k: v for k, v in cli.items() if v is not None}
    base.update(_lower_keys(cli))
    return AppConfig.from_mapping(base)


# ----------------------------- ЛОГИРОВАНИЕ ---------------------------------- #
class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": iso(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(cfg: AppConfig) -> None:
    level = getattr(logging, str(cfg.log_level).upper(), logging.INFO)
    handlers: dict[str, dict[str, t.Any]] = {}
    formatters: dict[str, dict[str, t.Any]] = {}
    root_handlers: list[str] = []

    # Console
    if cfg.log_format == "json":
        formatters["json"] = {"()": _JsonFormatter}
        handlers["console"] = {
            "class": "logging.StreamHandler",
            "level": level,
            "formatter": "json",
            "stream": "ext://sys.stdout",
        }
    else:
        formatters["text"] = {
            "format": "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S%z",
        }
        handlers["console"] = {
            "class": "logging.StreamHandler",
            "level": level,
            "formatter": "text",
            "stream": "ext://sys.stdout",
        }
    root_handlers.append("console")

    # File (в artifacts/output_dir/run.log)
    log_file = cfg.output_dir / cfg.logs_filename
    format_key = "json" if cfg.log_format == "json" else "text"
    handlers["file"] = {
        "class": "logging.handlers.RotatingFileHandler",
        "level": level,
        "formatter": format_key,
        "filename": str(log_file),
        "maxBytes": 5 * 1024 * 1024,
        "backupCount": 3,
        "encoding": "utf-8",
    }
    root_handlers.append("file")

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": formatters,
            "handlers": handlers,
            "root": {"level": level, "handlers": root_handlers},
        }
    )


# ------------------------------ ДВИЖОК -------------------------------------- #
class BaseMythosEngine:
    """
    Базовый интерфейс движка Mythos для quickstart. Реальный движок можно
    предоставить из пакета `mythos_core.engine.MythosEngine`.
    """

    def __init__(self, cfg: AppConfig, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.log = logger

    async def initialize(self) -> None:
        self.log.debug("Engine initialize started")
        await asyncio.sleep(0)  # yield
        self.log.debug("Engine initialize completed")

    async def step(self, i: int) -> dict[str, t.Any]:
        """
        Выполняет один шаг генерации/логики.
        Возвращает словарь с результатом шага (будет записан в JSONL).
        """
        raise NotImplementedError

    async def finalize(self) -> dict[str, t.Any]:
        self.log.debug("Engine finalize started")
        await asyncio.sleep(0)  # yield
        self.log.debug("Engine finalize completed")
        return {"status": "ok"}


class FallbackMythosEngine(BaseMythosEngine):
    """
    Безопасный встроенный движок. Синтетически генерирует сюжетные "кадры"
    для демонстрации пайплайна без внешних зависимостей.
    """

    async def step(self, i: int) -> dict[str, t.Any]:
        # Имитация генерации "кадра" истории
        await asyncio.sleep(0.01)
        entropy = random.random() * self.cfg.temperature
        return {
            "ts": iso(),
            "idx": i,
            "title": self.cfg.story_title,
            "fragment": f"Frame {i}: entropy={entropy:.4f}",
            "meta": {"temperature": self.cfg.temperature},
        }


def try_import_engine(cfg: AppConfig, logger: logging.Logger) -> BaseMythosEngine:
    """
    Пытаемся импортировать реальный движок из mythos_core.engine.MythosEngine.
    Если не получается — используем FallbackMythosEngine.
    """
    try:
        mod = importlib.import_module("mythos_core.engine")
        engine_cls: t.Any = getattr(mod, "MythosEngine", None)
        if engine_cls and inspect.isclass(engine_cls):
            logger.info("Using external engine: mythos_core.engine.MythosEngine")
            return engine_cls(cfg, logger)  # type: ignore[call-arg]
        logger.warning("mythos_core.engine.MythosEngine not found; using fallback engine")
    except Exception as e:
        logger.warning("Could not import mythos_core.engine; using fallback engine; %s", e)
    return FallbackMythosEngine(cfg, logger)


# -------------------------- ИСПОЛНЕНИЕ PIPELINE ------------------------------ #
class GracefulExit(SystemExit):
    pass


class CancelScope:
    """
    Управление отменой задач через общий Event.
    """
    def __init__(self) -> None:
        self._event = asyncio.Event()

    def cancel(self) -> None:
        self._event.set()

    def cancelled(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()


async def heartbeat_task(path: Path, period_sec: float, cancel: CancelScope, logger: logging.Logger) -> None:
    """
    Периодически записывает heartbeat-файл с текущим временем.
    """
    try:
        while not cancel.cancelled():
            write_text_file(path, iso())
            await asyncio.wait_for(cancel.wait(), timeout=period_sec)
    except asyncio.TimeoutError:
        # таймаут — нормальный режим "пинга", продолжаем
        await heartbeat_task(path, period_sec, cancel, logger)
    except Exception as e:
        logger.error("Heartbeat error: %s", e)


async def run_pipeline(cfg: AppConfig) -> int:
    log = logging.getLogger(__APP_NAME__)
    t_start = time.perf_counter()

    if cfg.seed is not None:
        random.seed(cfg.seed)
        log.info("Seed set: %s", cfg.seed)

    # Создаём директории/пути артефактов
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    results_jsonl = cfg.output_dir / "results.jsonl"
    summary_json = cfg.output_dir / "summary.json"
    heartbeat_file = cfg.output_dir / "heartbeat.txt"
    meta_json = cfg.output_dir / "meta.json"

    write_json(
        meta_json,
        {
            "app": __APP_NAME__,
            "version": __VERSION__,
            "started_at": iso(),
            "config": dataclasses.asdict(cfg),
        },
    )

    # Инициализация движка
    engine = try_import_engine(cfg, log)
    await engine.initialize()

    cancel = CancelScope()
    loop = asyncio.get_running_loop()

    # Обработка сигналов
    def _signal_handler(sig: int, _frame: t.Any) -> None:
        log.warning("Signal %s received. Cancelling...", sig)
        cancel.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal_handler, sig, None)

    # Heartbeat
    hb_task = asyncio.create_task(heartbeat_task(heartbeat_file, cfg.heartbeat_sec, cancel, log), name="heartbeat")

    # Основной цикл
    steps = int(cfg.max_steps)
    steps = max(0, steps)
    if cfg.dry_run:
        log.info("Dry-run mode: no steps executed. Planned steps: %d", steps)
        write_json(
            summary_json,
            {
                "status": "dry-run",
                "planned_steps": steps,
                "finished_at": iso(),
                "duration_sec": round(time.perf_counter() - t_start, 6),
            },
        )
        cancel.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await hb_task
        return 0

    try:
        async def _run_steps() -> None:
            for i in range(steps):
                if cancel.cancelled():
                    log.warning("Cancelled before step %d", i)
                    break
                frame = await engine.step(i)
                frame["runtime"] = {"step": i, "ts": iso()}
                append_jsonl(results_jsonl, frame)

        if cfg.timeout_sec and cfg.timeout_sec > 0:
            await asyncio.wait_for(_run_steps(), timeout=cfg.timeout_sec)
        else:
            await _run_steps()

        # finalize
        if not cancel.cancelled():
            final = await engine.finalize()
        else:
            final = {"status": "cancelled"}

        # summary
        write_json(
            summary_json,
            {
                "status": final.get("status", "ok"),
                "finished_at": iso(),
                "duration_sec": round(time.perf_counter() - t_start, 6),
                "steps": steps,
            },
        )
        return 0 if final.get("status") in {"ok", "success"} else 2

    except asyncio.TimeoutError:
        log.error("Run timed out after %.3f sec", cfg.timeout_sec)
        write_json(
            summary_json,
            {
                "status": "timeout",
                "finished_at": iso(),
                "duration_sec": round(time.perf_counter() - t_start, 6),
                "steps": steps,
            },
        )
        return 3
    except Exception as e:
        log.exception("Run failed: %s", e)
        write_json(
            summary_json,
            {
                "status": "error",
                "error": str(e),
                "finished_at": iso(),
                "duration_sec": round(time.perf_counter() - t_start, 6),
                "steps": steps,
            },
        )
        return 1
    finally:
        cancel.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await hb_task


# ------------------------------ CLI КОМАНДЫ --------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=__APP_NAME__,
        description="Quickstart runner for Mythos Core (industrial-ready, stdlib-only).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # Общие флаги, которые логично иметь у основной run-команды
    def add_common_flags(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", type=str, help="Path to TOML/JSON config file")
        sp.add_argument("--output-dir", type=Path, help="Artifacts output directory")
        sp.add_argument("--log-level", type=str, choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log level")
        sp.add_argument("--log-format", type=str, choices=["text", "json"], help="Log format")
        sp.add_argument("--seed", type=int, help="Random seed for reproducibility")
        sp.add_argument("--max-steps", type=int, help="Max steps to execute")
        sp.add_argument("--timeout-sec", type=float, help="Global timeout in seconds")
        sp.add_argument("--profile", action="store_true", help="Enable lightweight timing info")
        sp.add_argument("--dry-run", action="store_true", help="Plan execution without running steps")
        sp.add_argument("--story-title", type=str, help="Story title")
        sp.add_argument("--temperature", type=float, help="Temperature [0..1]")
        sp.add_argument("--model-path", type=str, help="Optional model path")
        sp.add_argument("--heartbeat-sec", type=float, help="Heartbeat period seconds")

    # run
    sp_run = sub.add_parser("run", help="Execute pipeline")
    add_common_flags(sp_run)

    # healthcheck
    sub.add_parser("healthcheck", help="Basic self-check without executing steps")

    # version
    sub.add_parser("version", help="Print version and environment")

    # gen-config
    sp_gc = sub.add_parser("gen-config", help="Generate a minimal TOML config to stdout")
    sp_gc.add_argument("--with-comments", action="store_true", help="Include helpful comments in TOML")

    return p


def gen_default_toml(include_comments: bool = False) -> str:
    cfg = AppConfig()
    # Не используем tomli-w; собираем TOML вручную (достаточно для примера).
    lines = []
    c = lines.append
    header = "# mythos-core quickstart config (TOML)\n"
    c(header)
    if include_comments:
        c('# Override via env: MYTHOS_<KEY>, e.g., MYTHOS_LOG_LEVEL="DEBUG"\n')
    c(f'output_dir = "{cfg.output_dir.as_posix()}"')
    c(f'log_level = "{cfg.log_level}"')
    c(f'log_format = "{cfg.log_format}"')
    c("seed = 1234")
    c(f"max_steps = {cfg.max_steps}")
    c(f"timeout_sec = {cfg.timeout_sec if cfg.timeout_sec is not None else 0}")
    c(f"profile = {str(cfg.profile).lower()}")
    c(f"dry_run = {str(cfg.dry_run).lower()}")
    c(f'story_title = "{cfg.story_title}"')
    c(f"temperature = {cfg.temperature}")
    c('model_path = ""')
    c(f'logs_filename = "{cfg.logs_filename}"')
    c(f"heartbeat_sec = {cfg.heartbeat_sec}")
    return "\n".join(lines) + "\n"


def do_healthcheck() -> int:
    print(json.dumps({"status": "ok", "time": iso(), "app": __APP_NAME__, "version": __VERSION__}, ensure_ascii=False))
    return 0


def do_version() -> int:
    info = {
        "app": __APP_NAME__,
        "version": __VERSION__,
        "python": sys.version.split()[0],
        "time": iso(),
    }
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


async def do_run(args: argparse.Namespace) -> int:
    cfg = build_config(args)
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(cfg)
    log = logging.getLogger(__APP_NAME__)

    if cfg.profile:
        t0 = time.perf_counter()
        rc = await run_pipeline(cfg)
        dt_sec = time.perf_counter() - t0
        log.info("Total runtime: %.6f sec", dt_sec)
        return rc
    else:
        return await run_pipeline(cfg)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.cmd == "healthcheck":
        return do_healthcheck()
    if args.cmd == "version":
        return do_version()
    if args.cmd == "gen-config":
        print(gen_default_toml(include_comments=getattr(args, "with_comments", False)))
        return 0
    if args.cmd == "run":
        try:
            return asyncio.run(do_run(args))
        except KeyboardInterrupt:
            return 130
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
