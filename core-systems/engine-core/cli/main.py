# engine/cli/main.py
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
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any, Callable, Dict, Optional

# -----------------------------
# Безопасный логгер (текст/JSON)
# -----------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created)),
            "lvl": record.levelname,
            "name": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def setup_logging(level: str, fmt: str) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)

LOG = logging.getLogger("engine.cli")

# -----------------------------
# Опциональные модули платформы
# -----------------------------

# Профилирование
with contextlib.suppress(Exception):
    from engine.telemetry.profiling import profile_block, TelemetryConfig  # type: ignore
    _HAS_PROF = True
if not "profile_block" in globals():
    def profile_block(name: Optional[str] = None, config: Optional[Any] = None):
        @contextlib.contextmanager
        def _noop():
            yield
        return _noop()
    _HAS_PROF = False

# Кэш
with contextlib.suppress(Exception):
    from engine.adapters.cache_adapter import CacheAdapter, CacheConfig  # type: ignore
    _HAS_CACHE = True
else:
    _HAS_CACHE = False

# DataFabric
with contextlib.suppress(Exception):
    from engine.adapters.datafabric_adapter import DataFabricAdapter, DataFabricConfig  # type: ignore
    _HAS_DF = True
else:
    _HAS_DF = False

# -----------------------------
# Конфигурация CLI
# -----------------------------

@dataclass
class CliConfig:
    log_level: str = "INFO"
    log_format: str = "text"             # text|json
    config_file: Optional[str] = None
    plugin_dir: Optional[str] = None

def load_file_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")
    text = p.read_text(encoding="utf-8")
    # YAML если установлен, иначе JSON
    try:
        import yaml  # type: ignore
        return dict(yaml.safe_load(text) or {})
    except Exception:
        return json.loads(text)

def merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge_dicts(out[k], v)  # type: ignore
        else:
            out[k] = v
    return out

# -----------------------------
# Плагины
# -----------------------------

def load_plugins(plugin_dir: Optional[str]) -> Dict[str, Callable[[argparse.Namespace], int]]:
    """
    Плагины: любой файл *.py в каталоге может объявить функцию:
      def register(cli: 'Cli'):  # cli.add_command("name", func, help="...")
          ...
    """
    commands: Dict[str, Callable] = {}
    if not plugin_dir:
        return commands
    p = Path(plugin_dir)
    if not p.exists() or not p.is_dir():
        return commands
    sys.path.insert(0, str(p))
    for py in p.glob("*.py"):
        modname = py.stem
        try:
            mod = importlib.import_module(modname)
            if hasattr(mod, "register"):
                # модуль сам зарегистрирует подкоманды через Cli.add_command
                pass
        except Exception as e:
            LOG.warning("Plugin load failed: %s (%s)", modname, e)
    return commands

# -----------------------------
# CLI каркас
# -----------------------------

class Cli:
    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            prog="engine",
            description="Engine Core CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(
                """\
                Примеры:
                  engine version
                  engine health
                  engine run --duration 10
                  engine profile --block "heavy_task" -- dump ./telemetry
                """
            ),
        )
        self.sub = self.parser.add_subparsers(dest="cmd", required=True)
        self._register_builtin()

    def _register_builtin(self) -> None:
        # Глобальные флаги
        self.parser.add_argument("--log-level", default=os.getenv("ENGINE_LOG_LEVEL", "INFO"),
                                 choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Уровень логирования")
        self.parser.add_argument("--log-format", default=os.getenv("ENGINE_LOG_FORMAT", "text"),
                                 choices=["text", "json"], help="Формат логов")
        self.parser.add_argument("--config", help="Путь к конфигурационному файлу (YAML/JSON)")
        self.parser.add_argument("--plugins", help="Каталог плагинов")

        # version
        p_ver = self.sub.add_parser("version", help="Показать версию")
        p_ver.set_defaults(_handler=self.cmd_version)

        # health
        p_health = self.sub.add_parser("health", help="Проверка здоровья подсистем")
        p_health.add_argument("--deep", action="store_true", help="Глубокая проверка")
        p_health.set_defaults(_handler=self.cmd_health)

        # run (демо-задача/воркер)
        p_run = self.sub.add_parser("run", help="Запустить демонстрационную задачу/воркер")
        p_run.add_argument("--duration", type=int, default=5, help="Секунды работы до мягкого завершения")
        p_run.add_argument("--grace", type=float, default=3.0, help="Таймаут мягкого завершения")
        p_run.set_defaults(_handler=self.cmd_run)

        # profile
        p_prof = self.sub.add_parser("profile", help="Запустить блок с профилированием")
        p_prof.add_argument("--block", required=True, help="Имя профилируемого блока")
        p_prof.add_argument("--out-dir", default=os.getenv("ENGINE_PROFILE_DIR", "telemetry/profiles"))
        p_prof.add_argument("--duration", type=float, default=1.0, help="Искусственная нагрузка (сек)")
        p_prof.set_defaults(_handler=self.cmd_profile)

        # cache (опционально)
        p_cache = self.sub.add_parser("cache", help="Операции с кэшем")
        p_cache.add_argument("op", choices=["get", "set", "del", "tag-invalidate"])
        p_cache.add_argument("--key")
        p_cache.add_argument("--value")
        p_cache.add_argument("--ttl", type=int, default=None)
        p_cache.add_argument("--tag", action="append")
        p_cache.set_defaults(_handler=self.cmd_cache)

        # adapters (опционально DataFabric демо)
        p_ad = self.sub.add_parser("adapters", help="Диагностика адаптеров")
        p_ad.add_argument("target", choices=["datafabric"])
        p_ad.add_argument("--sql", help="SQL запрос")
        p_ad.add_argument("--page", type=int, default=1)
        p_ad.add_argument("--page-size", type=int, default=5)
        p_ad.set_defaults(_handler=self.cmd_adapters)

    # -------------------------
    # Точки входа команд
    # -------------------------

    def run(self, argv: Optional[list[str]] = None) -> int:
        args = self.parser.parse_args(argv)
        # Логирование
        setup_logging(args.log_level, args.log_format)

        # Конфиг
        base_cfg: Dict[str, Any] = {"log_level": args.log_level, "log_format": args.log_format}
        file_cfg = {}
        if args.config:
            try:
                file_cfg = load_file_config(args.config)
            except Exception as e:
                LOG.error("Failed to load config: %s", e)
                return 2
        cfg = merge_dicts(base_cfg, file_cfg)
        LOG.debug("Effective config: %s", cfg)

        # Плагины (плагины могут добавлять свои subparser до parse_args — для простоты грузим здесь)
        if args.plugins:
            load_plugins(args.plugins)

        # Вызов обработчика
        handler: Callable[[argparse.Namespace], int] = getattr(args, "_handler", None)
        if not handler:
            self.parser.print_help()
            return 2
        try:
            return handler(args)
        except KeyboardInterrupt:
            LOG.warning("Interrupted by user")
            return 130
        except Exception as e:
            LOG.error("Unhandled error: %s", e, exc_info=True)
            return 1

    # --- version ---
    def cmd_version(self, args: argparse.Namespace) -> int:
        ver = os.getenv("ENGINE_VERSION", "0.1.0")
        build = os.getenv("ENGINE_BUILD", "dev")
        print(json.dumps({"version": ver, "build": build}, ensure_ascii=False))
        return 0

    # --- health ---
    def cmd_health(self, args: argparse.Namespace) -> int:
        ok = True
        details: Dict[str, Any] = {"time": time.time(), "profiler": _HAS_PROF, "cache": _HAS_CACHE, "datafabric": _HAS_DF}

        # Cache health
        if _HAS_CACHE:
            try:
                from engine.adapters.cache_adapter import CacheAdapter, CacheConfig  # type: ignore
                c = CacheAdapter(CacheConfig.from_env("CACHE"))
                details["cache_healthy"] = c.healthy()
                ok = ok and details["cache_healthy"]
            except Exception as e:
                details["cache_error"] = str(e)
                ok = False

        # DataFabric health
        if args.deep and _HAS_DF:
            try:
                from engine.adapters.datafabric_adapter import DataFabricAdapter, DataFabricConfig  # type: ignore
                df = DataFabricAdapter(DataFabricConfig.from_env("DF"))
                with profile_block("cli.df.health"):
                    res = df.health_check()
                details["datafabric_health"] = res
            except Exception as e:
                details["datafabric_error"] = str(e)
                ok = False

        print(json.dumps({"status": "ok" if ok else "degraded", "details": details}, ensure_ascii=False, indent=2))
        return 0 if ok else 1

    # --- run ---
    def cmd_run(self, args: argparse.Namespace) -> int:
        async def _run_main() -> int:
            # Грациозное завершение
            stop = asyncio.Event()

            def _handler(signame: str):
                LOG.warning("Received signal %s, shutting down...", signame)
                stop.set()

            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                with contextlib.suppress(NotImplementedError):
                    loop.add_signal_handler(sig, _handler, sig.name)

            start = time.time()
            LOG.info("Worker started (duration=%ss, grace=%ss)", args.duration, args.grace)

            # Демонстрационная периодическая задача
            async def tick():
                i = 0
                while not stop.is_set():
                    with profile_block("cli.run.tick"):
                        LOG.info("tick %s", i)
                        await asyncio.sleep(1.0)
                        i += 1

            t = asyncio.create_task(tick())

            # Тормоз по времени
            try:
                await asyncio.wait_for(stop.wait(), timeout=args.duration)
            except asyncio.TimeoutError:
                LOG.info("Duration elapsed, stopping...")

            # Грациозное завершение
            stop.set()
            try:
                await asyncio.wait_for(t, timeout=args.grace)
            except asyncio.TimeoutError:
                LOG.warning("Grace timeout, cancel task")
                t.cancel()
                with contextlib.suppress(Exception):
                    await t

            LOG.info("Worker finished in %.3fs", time.time() - start)
            return 0

        return asyncio.run(_run_main())

    # --- profile ---
    def cmd_profile(self, args: argparse.Namespace) -> int:
        if not _HAS_PROF:
            LOG.error("Telemetry profiling is not available (engine.telemetry.profiling not found)")
            return 1
        cfg = TelemetryConfig().with_overrides(
            output_dir=args.out_dir,
            dump_pstats=True,
            dump_json=True,
            dump_chrome_trace=True,
            enabled=True,
            auto_dump_on_atexit=False,
            default_span_name=args.block,
        )
        from engine.telemetry.profiling import Profiler  # type: ignore
        prof = Profiler(name=args.block, config=cfg)
        with prof:
            # Имитируем нагрузку
            LOG.info("Profiling block '%s' for %.2fs", args.block, args.duration)
            x = 0
            t0 = time.perf_counter()
            while time.perf_counter() - t0 < args.duration:
                # Небольшая CPU‑нагрузка
                for n in range(10000):
                    x += (n * n) % 97
            LOG.debug("work result=%s", x)
        prof.dump()
        print(json.dumps({"status": "ok", "out_dir": args.out_dir, "block": args.block}, ensure_ascii=False))
        return 0

    # --- cache ---
    def cmd_cache(self, args: argparse.Namespace) -> int:
        if not _HAS_CACHE:
            LOG.error("Cache adapter not available")
            return 1
        from engine.adapters.cache_adapter import CacheAdapter, CacheConfig  # type: ignore
        c = CacheAdapter(CacheConfig.from_env("CACHE"))

        op: str = args.op
        if op == "get":
            if not args.key:
                LOG.error("--key is required")
                return 2
            v = c.get(args.key)
            print(json.dumps({"key": args.key, "value": v}, ensure_ascii=False))
            return 0
        if op == "set":
            if not args.key:
                LOG.error("--key is required")
                return 2
            v: Any = args.value
            # Попытка распарсить как JSON
            with contextlib.suppress(Exception):
                v = json.loads(args.value)
            c.set(args.key, v, ttl=args.ttl, tags=args.tag)
            print(json.dumps({"status": "ok"}, ensure_ascii=False))
            return 0
        if op == "del":
            if not args.key:
                LOG.error("--key is required")
                return 2
            c.delete(args.key)
            print(json.dumps({"status": "ok"}, ensure_ascii=False))
            return 0
        if op == "tag-invalidate":
            if not args.tag:
                LOG.error("--tag is required (repeatable)")
                return 2
            removed_sum = 0
            for t in args.tag:
                removed_sum += c.invalidate_tag(t)
            print(json.dumps({"status": "ok", "removed": removed_sum}, ensure_ascii=False))
            return 0
        LOG.error("Unknown op")
        return 2

    # --- adapters (DataFabric демо) ---
    def cmd_adapters(self, args: argparse.Namespace) -> int:
        if args.target == "datafabric":
            if not _HAS_DF:
                LOG.error("DataFabric adapter not available")
                return 1
            from engine.adapters.datafabric_adapter import DataFabricAdapter, DataFabricConfig  # type: ignore
            cfg = DataFabricConfig.from_env("DF")
            df = DataFabricAdapter(cfg)
            if args.sql:
                with profile_block("cli.df.query"):
                    res = df.query(sql=args.sql, page=args.page, page_size=args.page_size)
            else:
                with profile_block("cli.df.health"):
                    res = df.health_check()
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0
        LOG.error("Unknown target")
        return 2


# -----------------------------
# Точка входа
# -----------------------------

def main(argv: Optional[list[str]] = None) -> int:
    cli = Cli()
    return cli.run(argv)

if __name__ == "__main__":
    sys.exit(main())
