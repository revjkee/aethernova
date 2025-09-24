# engine-core/engine/cli/admin.py
"""
Engine Admin CLI — промышленный административный инструмент.

Возможности:
- status                 : быстрый свод состояния окружения и интеграций
- config show / set      : просмотр/изменение конфигурации (ENV/.env)
- trace selftest         : инициализация и проверка OpenTelemetry-трейсинга
- mock seed-data         : загрузка начальных данных в DataFabricMock из JSON/NDJSON
- ai chat                : вызов AIMock для smoke-тестов LLM-обвязки
- health                 : базовая проверка доступности и метрик

Зависимости:
- Только стандартная библиотека Python. Опциональные модули подключаются мягко:
  - engine.telemetry.tracing
  - engine.adapters.observability_adapter
  - engine.mocks.datafabric_mock
  - engine.mocks.ai_mock

Формат вывода:
  По умолчанию "text". Переключить можно флагом --output json.
  Уровень логирования регулируется --verbose/-v / --quiet/-q.

Коды выхода:
  0  — OK
  2  — пользовательская ошибка (аргументы/валидация/подтверждение)
  3  — недоступно (фича/модуль)
  4  — таймаут
  5  — внутренняя ошибка

SPDX-License-Identifier: Apache-2.0 OR MIT
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import signal
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# -------------------------- Логирование и вывод --------------------------

LOG = logging.getLogger("engine.cli")

def setup_logging(verbosity: int, quiet: bool) -> None:
    """Настройка уровня логирования."""
    if quiet:
        level = logging.ERROR
    else:
        # verbosity: 0=INFO, 1=DEBUG, >=2=DEBUG с более подробными сообщениями
        level = logging.INFO if verbosity == 0 else logging.DEBUG
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    handler.setFormatter(logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%SZ"))
    root.addHandler(handler)
    root.setLevel(level)

def _print(data: Any, output: str = "text") -> None:
    """Унифицированный вывод."""
    if output == "json":
        sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    else:
        if isinstance(data, (dict, list, tuple)):
            sys.stdout.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        else:
            sys.stdout.write(str(data) + "\n")

# ------------------------------ Утилиты ----------------------------------

def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}

def _load_env_file(path: Path) -> Dict[str, str]:
    """Простая загрузка .env (KEY=VALUE), без зависимостей."""
    if not path.exists():
        return {}
    out: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def _save_env_file(path: Path, values: Dict[str, str]) -> None:
    """Сохранение .env с простым форматированием и бэкапом."""
    if path.exists():
        backup = path.with_suffix(path.suffix + ".bak")
        path.replace(backup)
    lines = [f"{k}={v}" for k, v in sorted(values.items())]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

@contextlib.contextmanager
def _time_block() -> Iterable[None]:
    t0 = time.perf_counter()
    try:
        yield
    finally:
        dt = time.perf_counter() - t0
        LOG.debug("done in %.3fs", dt)

# --------------------- Мягкие импорты интеграций ------------------------

# Observability
try:
    from engine.adapters.observability_adapter import get_observability as _get_obs  # type: ignore
except Exception:  # pragma: no cover
    _get_obs = None  # type: ignore

# Tracing
try:
    from engine.telemetry import tracing as _tracing  # type: ignore
except Exception:  # pragma: no cover
    _tracing = None  # type: ignore

# DataFabricMock
try:
    from engine.mocks.datafabric_mock import DataFabricMock, TableSchema, Column, Query  # type: ignore
except Exception:  # pragma: no cover
    DataFabricMock = None  # type: ignore
    TableSchema = None  # type: ignore
    Column = None  # type: ignore
    Query = None  # type: ignore

# AIMock
try:
    from engine.mocks.ai_mock import AIMock, AIMockConfig  # type: ignore
except Exception:  # pragma: no cover
    AIMock = None  # type: ignore
    AIMockConfig = None  # type: ignore

# ------------------------------- Команды --------------------------------

@dataclass
class CLIContext:
    output: str = "text"
    yes: bool = False
    timeout: float = 30.0

# ---- status ----
def cmd_status(ctx: CLIContext, args: argparse.Namespace) -> int:
    data = {
        "service_name": os.getenv("ENGINE_OBS_SERVICE_NAME", "engine-core"),
        "service_version": os.getenv("ENGINE_OBS_SERVICE_VERSION", "0.0.0"),
        "deploy_env": os.getenv("ENGINE_OBS_DEPLOY_ENV", "dev"),
        "observability": bool(_get_obs),
        "tracing": bool(_tracing),
        "datafabric_mock": bool(DataFabricMock),
        "ai_mock": bool(AIMock),
        "python": sys.version.split()[0],
        "cwd": str(Path.cwd()),
    }
    _print(data, ctx.output)
    return 0

# ---- config show/set ----
def cmd_config_show(ctx: CLIContext, args: argparse.Namespace) -> int:
    env_path = Path(args.file) if args.file else Path(".env")
    vals = _load_env_file(env_path)
    _print({"path": str(env_path), "values": vals}, ctx.output)
    return 0

def cmd_config_set(ctx: CLIContext, args: argparse.Namespace) -> int:
    env_path = Path(args.file) if args.file else Path(".env")
    vals = _load_env_file(env_path)
    for pair in args.pairs:
        if "=" not in pair:
            LOG.error("invalid pair (expected KEY=VALUE): %s", pair)
            return 2
        k, v = pair.split("=", 1)
        vals[k.strip()] = v.strip()
    if not ctx.yes:
        _print({"path": str(env_path), "preview": vals}, ctx.output)
        LOG.warning("Pass --yes to write the file")
        return 2
    _save_env_file(env_path, vals)
    _print({"path": str(env_path), "written": True, "count": len(vals)}, ctx.output)
    return 0

# ---- trace selftest ----
def cmd_trace_selftest(ctx: CLIContext, args: argparse.Namespace) -> int:
    if not _tracing:
        LOG.error("tracing module not available")
        return 3
    with _time_block():
        # respect env; allow override via flags
        if args.exporter:
            os.environ["ENGINE_TRACING_EXPORTER"] = args.exporter
        if args.endpoint:
            os.environ["ENGINE_TRACING_OTLP_ENDPOINT"] = args.endpoint
        os.environ.setdefault("ENGINE_TRACING_ENABLED", "true")
        os.environ.setdefault("ENGINE_TRACING_SERVICE_NAME", "engine-core")
        os.environ.setdefault("ENGINE_TRACING_SERVICE_VERSION", os.getenv("ENGINE_OBS_SERVICE_VERSION", "0.0.0"))
        _tracing.setup_tracing()
        tracer = _tracing.get_tracer("engine.cli")
        with tracer.start_as_current_span("selftest") as span:
            span.set_attribute("cli.command", "trace selftest")
            span.set_attribute("exporter", os.getenv("ENGINE_TRACING_EXPORTER", "otlp_grpc"))
            time.sleep(0.02)
        _tracing.shutdown_tracing()
    _print({"ok": True, "exporter": os.getenv("ENGINE_TRACING_EXPORTER", "otlp_grpc")}, ctx.output)
    return 0

# ---- mock seed-data ----
async def _seed_data_async(table: str, schema_path: Optional[str], data_path: str, batch: int) -> Dict[str, Any]:
    if not DataFabricMock or not TableSchema or not Column:
        raise RuntimeError("DataFabricMock not available")
    # Схема: либо из JSON, либо дефолтная (попытка вывода из данных)
    schema: Optional[TableSchema] = None  # type: ignore
    if schema_path:
        schema_json = json.loads(Path(schema_path).read_text(encoding="utf-8"))
        cols = tuple(Column(c["name"], eval(c.get("type","str")), c.get("required", False)) for c in schema_json["columns"])  # type: ignore
        schema = TableSchema(  # type: ignore
            name=table,
            primary_key=schema_json["primary_key"],
            columns=cols,
            ttl_seconds=schema_json.get("ttl_seconds"),
            unique=tuple(schema_json.get("unique", ())),
            soft_delete=bool(schema_json.get("soft_delete", True)),
        )
    # Загрузка данных
    p = Path(data_path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    rows: List[Dict[str, Any]] = []
    if p.suffix.lower() in {".ndjson", ".jsonl"}:
        for line in p.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s:
                rows.append(json.loads(s))
    else:
        loaded = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(loaded, list):
            rows = list(loaded)
        else:
            raise ValueError("expected JSON array or NDJSON")

    # Засев
    total = 0
    async with DataFabricMock.session() as df:  # type: ignore
        if schema is None:
            # авто-схема: берём типы из первой строки и выбираем PK: id|key|uuid
            first = rows[0]
            pk = "id" if "id" in first else ("key" if "key" in first else next(iter(first.keys())))
            cols = tuple(Column(k, type(v) if v is not None else str, k == pk) for k, v in first.items())  # type: ignore
            schema = TableSchema(name=table, primary_key=pk, columns=cols)  # type: ignore
        await df.create_table(schema)
        for i in range(0, len(rows), batch):
            chunk = rows[i:i+batch]
            total += await df.upsert(table, chunk)  # idempotent
    return {"table": table, "rows": len(rows), "inserted": total}

def cmd_mock_seed(ctx: CLIContext, args: argparse.Namespace) -> int:
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(Exception):
                loop.add_signal_handler(sig, loop.stop)
        with _time_block():
            result = loop.run_until_complete(asyncio.wait_for(
                _seed_data_async(args.table, args.schema, args.data, args.batch), timeout=ctx.timeout))
        _print({"ok": True, **result}, ctx.output)
        return 0
    except asyncio.TimeoutError:
        LOG.error("seed-data timed out after %.1fs", ctx.timeout)
        return 4
    except Exception as e:
        LOG.exception("seed-data failed: %s", e)
        return 5
    finally:
        try:
            asyncio.get_event_loop().close()
        except Exception:
            pass

# ---- ai chat (AIMock) ----
async def _ai_chat_async(prompt: str, temperature: float, max_tokens: int) -> Dict[str, Any]:
    if not AIMock or not AIMockConfig:
        raise RuntimeError("AIMock not available")
    mock = AIMock(AIMockConfig())  # type: ignore
    resp = await mock.chat_complete([{"role": "user", "content": prompt}], temperature=temperature, max_tokens=max_tokens)
    txt = resp["choices"][0]["message"]["content"]
    return {"model": resp["model"], "text": txt, "usage": resp["usage"]}

def cmd_ai_chat(ctx: CLIContext, args: argparse.Namespace) -> int:
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        with _time_block():
            result = loop.run_until_complete(asyncio.wait_for(
                _ai_chat_async(args.prompt, args.temperature, args.max_tokens), timeout=ctx.timeout))
        _print(result, ctx.output)
        return 0
    except asyncio.TimeoutError:
        LOG.error("ai chat timed out after %.1fs", ctx.timeout)
        return 4
    except Exception as e:
        LOG.exception("ai chat failed: %s", e)
        return 5
    finally:
        with contextlib.suppress(Exception):
            asyncio.get_event_loop().close()

# ---- health ----
def cmd_health(ctx: CLIContext, args: argparse.Namespace) -> int:
    # Минимальный набор проверок
    checks = []
    checks.append(("python", True, sys.version.split()[0]))
    checks.append(("observability", bool(_get_obs), "available" if _get_obs else "missing"))
    checks.append(("tracing", bool(_tracing), "available" if _tracing else "missing"))
    checks.append(("datafabric_mock", bool(DataFabricMock), "available" if DataFabricMock else "missing"))
    checks.append(("ai_mock", bool(AIMock), "available" if AIMock else "missing"))
    ok = all(flag for _, flag, _ in checks)
    _print({"ok": ok, "checks": [{"name": n, "ok": f, "info": i} for (n, f, i) in checks]}, ctx.output)
    return 0 if ok else 3

# ------------------------------ Парсер CLI -------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="engine-admin",
        description="Engine Admin CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              engine-admin status --output json
              engine-admin config show --file .env
              engine-admin config set ENGINE_TRACING_EXPORTER=otlp_grpc --yes
              engine-admin trace selftest --exporter console
              engine-admin mock seed-data --table users --data ./users.ndjson --batch 1000
              engine-admin ai chat --prompt "ping"
        """).strip(),
    )
    p.add_argument("--output", choices=["text", "json"], default="text", help="output format")
    p.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress non-error logs")
    p.add_argument("--yes", action="store_true", help="assume 'yes' for prompts/changes")
    p.add_argument("--timeout", type=float, default=float(os.getenv("ENGINE_CLI_TIMEOUT", "30")), help="global timeout seconds")

    sub = p.add_subparsers(dest="cmd", required=True)

    # status
    sp = sub.add_parser("status", help="show environment status")
    sp.set_defaults(func=cmd_status)

    # config
    sp_cfg = sub.add_parser("config", help="configuration ops")
    sub_cfg = sp_cfg.add_subparsers(dest="subcmd", required=True)

    sp_cfg_show = sub_cfg.add_parser("show", help="show .env")
    sp_cfg_show.add_argument("--file", help="path to .env (default ./.env)")
    sp_cfg_show.set_defaults(func=cmd_config_show)

    sp_cfg_set = sub_cfg.add_parser("set", help="set KEY=VALUE pairs to .env")
    sp_cfg_set.add_argument("pairs", nargs="+", help="KEY=VALUE")
    sp_cfg_set.add_argument("--file", help="path to .env (default ./.env)")
    sp_cfg_set.set_defaults(func=cmd_config_set)

    # trace
    sp_tr = sub.add_parser("trace", help="tracing operations")
    sub_tr = sp_tr.add_subparsers(dest="subcmd", required=True)
    sp_tr_self = sub_tr.add_parser("selftest", help="initialize tracing and emit a test span")
    sp_tr_self.add_argument("--exporter", choices=["otlp_grpc", "otlp_http", "jaeger", "console"], help="override exporter")
    sp_tr_self.add_argument("--endpoint", help="exporter endpoint")
    sp_tr_self.set_defaults(func=cmd_trace_selftest)

    # mock
    sp_mock = sub.add_parser("mock", help="mock operations")
    sub_mock = sp_mock.add_subparsers(dest="subcmd", required=True)
    sp_seed = sub_mock.add_parser("seed-data", help="seed DataFabricMock with JSON/NDJSON")
    sp_seed.add_argument("--table", required=True, help="table name")
    sp_seed.add_argument("--schema", help="path to schema json (optional)")
    sp_seed.add_argument("--data", required=True, help="path to data .json/.ndjson")
    sp_seed.add_argument("--batch", type=int, default=1000, help="batch size")
    sp_seed.set_defaults(func=cmd_mock_seed)

    # ai
    sp_ai = sub.add_parser("ai", help="ai mock operations")
    sub_ai = sp_ai.add_subparsers(dest="subcmd", required=True)
    sp_ai_chat = sub_ai.add_parser("chat", help="AIMock chat completion")
    sp_ai_chat.add_argument("--prompt", required=True, help="user prompt")
    sp_ai_chat.add_argument("--temperature", type=float, default=0.2, help="sampling temperature")
    sp_ai_chat.add_argument("--max-tokens", type=int, default=256, help="max output tokens")
    sp_ai_chat.set_defaults(func=cmd_ai_chat)

    # health
    sp_health = sub.add_parser("health", help="basic health check")
    sp_health.set_defaults(func=cmd_health)

    return p

# -------------------------------- main ----------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    ctx = CLIContext(output=args.output, yes=args.yes, timeout=args.timeout)
    setup_logging(args.verbose, args.quiet)

    # Привязка сигнального обработчика для корректного завершения
    with contextlib.suppress(Exception):
        signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))

    # Переадресуем в соответствующую функцию
    func = getattr(args, "func", None)
    if not func:
        parser.print_help()
        return 2

    try:
        return func(ctx, args)
    except KeyboardInterrupt:
        LOG.error("interrupted")
        return 130
    except SystemExit as e:
        return int(e.code)
    except Exception as e:
        LOG.exception("unhandled error: %s", e)
        return 5

if __name__ == "__main__":
    sys.exit(main())
