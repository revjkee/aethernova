# -*- coding: utf-8 -*-
"""
ledger-core/cli/main.py
Промышленный CLI для управления сервисом Ledger Core.

Возможности:
- Единая инициализация логирования и окружения (см. ledger.telemetry.logging).
- Async Bootstrap (БД, миграции по флагу, health).
- Команды:
    version                       — печать версии и окружения
    health                        — проверка доступности БД
    db create-schema              — создать схему (если отсутствует)
    db migrate [--to REV]         — alembic upgrade (по умолчанию head)
    db rollback --to REV          — alembic downgrade до REV
    db exec-sql --file/--sql      — выполнить SQL с защитой по умолчанию
    gen secret [--bytes N]        — генерация криптосекрета в base64
    gen idem-key                  — генерация безопасного Idempotency-Key
- Грейсфул завершение, корректные exit codes, детерминированные JSON‑выводы для машинной обработки.

Зависимости: Python 3.10+, httpx (опционально для внешних проверок не используется), alembic (опционально для миграций), typer (опционально, fallback на argparse).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import secrets
import signal
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Внутренние модули
try:
    from ledger.bootstrap import create_app_resources, BootstrapSettings
except Exception as e:
    print(json.dumps({"error": "bootstrap_import_error", "detail": str(e)}), file=sys.stderr)
    sys.exit(2)

try:
    from ledger.telemetry.logging import setup_logging, bind_context, get_logger
except Exception as e:
    print(json.dumps({"error": "logging_import_error", "detail": str(e)}), file=sys.stderr)
    sys.exit(2)

# Опциональные зависимости
try:
    import typer  # type: ignore
    _HAS_TYPER = True
except Exception:
    _HAS_TYPER = False

# Alembic — опционально
try:
    from alembic import command as alembic_command  # type: ignore
    from alembic.config import Config as AlembicConfig  # type: ignore
    _HAS_ALEMBIC = True
except Exception:
    _HAS_ALEMBIC = False


# ============================ Утилиты ============================

APP_ROOT = Path(__file__).resolve().parents[1]  # ledger-core/ledger
REPO_ROOT = Path(__file__).resolve().parents[2]  # ledger-core/

def _find_alembic_ini() -> Optional[Path]:
    # По умолчанию ожидаем alembic.ini в корне репозитория
    ini = REPO_ROOT / "alembic.ini"
    return ini if ini.exists() else None

def _alembic_cfg(settings: BootstrapSettings, ini: Optional[Path]) -> AlembicConfig:
    if not _HAS_ALEMBIC:
        raise RuntimeError("alembic is not installed")
    if not ini:
        raise RuntimeError("alembic.ini not found")
    cfg = AlembicConfig(str(ini))
    # sqlalchemy.url читается из env; приводим к sync‑URL (без +asyncpg)
    os.environ.setdefault("SQLALCHEMY_URL", settings.db.url.replace("+asyncpg", ""))
    return cfg

def _print_json(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))

def _setup_global_logging(level: str, env: Optional[str], service: Optional[str], version: Optional[str]) -> None:
    setup_logging(level=level)
    bind_context(env=env or os.getenv("APP_ENV", "staging"),
                 service=service or os.getenv("APP_NAME", "ledger-core"),
                 version=version or os.getenv("APP_VERSION", "0.0.0"))

# ============================ Реализация команд ============================

async def cmd_version(args: argparse.Namespace) -> int:
    settings = BootstrapSettings()
    version = Path(settings.version_file).read_text(encoding="utf-8").strip() if Path(settings.version_file).exists() else "0.0.0+unknown"
    _print_json({
        "version": version,
        "env": settings.app_env,
        "db": {"url": settings.db.url.split("@")[-1].split("?")[0]},  # без чувствительных данных
    })
    return 0

async def cmd_health(args: argparse.Namespace) -> int:
    log = get_logger(__name__)
    async with (await create_app_resources()) as bs:
        health = await bs.resources.health()
        status = health.get("status", "degraded")
        _print_json(health)
        if status != "ok":
            log.warning("health degraded", extra=health)
            return 1
        return 0

async def cmd_db_create_schema(args: argparse.Namespace) -> int:
    from sqlalchemy import text
    async with (await create_app_resources()) as bs:
        schema = bs.resources.settings.db.url  # берем имя схемы из моделей, но безопаснее из env
        # Схема объявлена в моделях как LEDGER_DB_SCHEMA, читаем env с дефолтом ledger
        schema_name = os.getenv("LEDGER_DB_SCHEMA", "ledger")
        async with bs.resources.engine.begin() as conn:
            await conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name};"))
        _print_json({"status": "ok", "schema": schema_name})
        return 0

async def cmd_db_migrate(args: argparse.Namespace) -> int:
    if not _HAS_ALEMBIC:
        _print_json({"error": "alembic_not_installed"})
        return 2
    settings = BootstrapSettings()
    cfg = _alembic_cfg(settings, _find_alembic_ini())
    rev = args.to if args.to else "head"
    alembic_command.upgrade(cfg, rev)
    _print_json({"status": "ok", "action": "upgrade", "to": rev})
    return 0

async def cmd_db_rollback(args: argparse.Namespace) -> int:
    if not _HAS_ALEMBIC:
        _print_json({"error": "alembic_not_installed"})
        return 2
    settings = BootstrapSettings()
    cfg = _alembic_cfg(settings, _find_alembic_ini())
    if not args.to:
        _print_json({"error": "missing_required", "detail": "--to REV is required"})
        return 2
    alembic_command.downgrade(cfg, args.to)
    _print_json({"status": "ok", "action": "downgrade", "to": args.to})
    return 0

async def cmd_db_exec_sql(args: argparse.Namespace) -> int:
    from sqlalchemy import text
    sql_text: Optional[str] = None
    if args.file:
        p = Path(args.file)
        if not p.exists():
            _print_json({"error": "file_not_found", "path": str(p)})
            return 2
        sql_text = p.read_text(encoding="utf-8")
    elif args.sql:
        sql_text = args.sql
    else:
        _print_json({"error": "missing_required", "detail": "--file or --sql is required"})
        return 2

    if not args.unsafe:
        # Простая защита: запретим потенциально опасные операторы без явного разрешения
        dangerous = ("drop ", "truncate ", "alter ", "delete ")
        low = sql_text.lower()
        if any(tok in low for tok in dangerous):
            _print_json({"error": "potentially_unsafe_sql", "detail": "use --unsafe to allow"})
            return 2

    async with (await create_app_resources()) as bs:
        rows_affected = 0
        first_row: Optional[Dict[str, Any]] = None
        async with bs.resources.engine.begin() as conn:
            result = await conn.execute(text(sql_text))
            try:
                fetched = result.mappings().all()
                # Выведем первую строку для подтверждения структуры
                if fetched:
                    first_row = dict(fetched[0])
            except Exception:
                # Не выборка — возьмем счетчик
                rows_affected = result.rowcount or 0

        _print_json({"status": "ok", "rows_affected": rows_affected, "first_row": first_row})
        return 0

def cmd_gen_secret(args: argparse.Namespace) -> int:
    n = int(args.bytes or 32)
    token = base64.urlsafe_b64encode(secrets.token_bytes(n)).rstrip(b"=").decode()
    _print_json({"secret": token, "bytes": n})
    return 0

def cmd_gen_idem_key(args: argparse.Namespace) -> int:
    # Idempotency-Key: 32 байта энтропии в base32 (без паддинга), удобочитаемый
    raw = secrets.token_bytes(32)
    key = base64.b32encode(raw).decode().rstrip("=")
    _print_json({"idempotency_key": key})
    return 0


# ============================ Typer CLI (если доступен) ============================

if _HAS_TYPER:
    app = typer.Typer(add_completion=False, help="Ledger Core CLI")

    @app.callback()
    def _global(
        log_level: str = typer.Option("INFO", "--log-level", envvar="LOG_LEVEL", help="Глобальный уровень логирования"),
        app_env: Optional[str] = typer.Option(None, "--env", envvar="APP_ENV", help="Окружение"),
        app_name: Optional[str] = typer.Option(None, "--service", envvar="APP_NAME", help="Имя сервиса"),
        app_version: Optional[str] = typer.Option(None, "--version-str", envvar="APP_VERSION", help="Версия сервиса"),
    ):
        _setup_global_logging(log_level, app_env, app_name, app_version)

    @app.command()
    def version() -> None:
        sys.exit(asyncio.run(cmd_version(argparse.Namespace())))

    @app.command()
    def health() -> None:
        sys.exit(asyncio.run(cmd_health(argparse.Namespace())))

    db_app = typer.Typer(help="Операции с БД")
    app.add_typer(db_app, name="db")

    @db_app.command("create-schema")
    def db_create_schema() -> None:
        sys.exit(asyncio.run(cmd_db_create_schema(argparse.Namespace())))

    @db_app.command("migrate")
    def db_migrate(to: Optional[str] = typer.Option(None, "--to", help="Ревизия Alembic, по умолчанию head")) -> None:
        sys.exit(asyncio.run(cmd_db_migrate(argparse.Namespace(to=to))))

    @db_app.command("rollback")
    def db_rollback(to: str = typer.Option(..., "--to", help="Ревизия Alembic для отката")) -> None:
        sys.exit(asyncio.run(cmd_db_rollback(argparse.Namespace(to=to))))

    @db_app.command("exec-sql")
    def db_exec_sql(
        file: Optional[str] = typer.Option(None, "--file", "-f", help="SQL файл"),
        sql: Optional[str] = typer.Option(None, "--sql", help="SQL строка"),
        unsafe: bool = typer.Option(False, "--unsafe", help="Разрешить опасные операторы"),
    ) -> None:
        ns = argparse.Namespace(file=file, sql=sql, unsafe=unsafe)
        sys.exit(asyncio.run(cmd_db_exec_sql(ns)))

    gen_app = typer.Typer(help="Генераторы")
    app.add_typer(gen_app, name="gen")

    @gen_app.command("secret")
    def gen_secret(bytes: int = typer.Option(32, "--bytes", min=16, max=128)) -> None:
        sys.exit(cmd_gen_secret(argparse.Namespace(bytes=bytes)))

    @gen_app.command("idem-key")
    def gen_idem_key() -> None:
        sys.exit(cmd_gen_idem_key(argparse.Namespace()))

    def main() -> None:
        # Грейсфул SIGINT/SIGTERM для корректного выхода из asyncio.run
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda s, f: sys.exit(130 if s == signal.SIGINT else 143))
        app()

# ============================ Argparse fallback (если Typer недоступен) ============================

else:
    def _build_parser() -> argparse.ArgumentParser:
        p = argparse.ArgumentParser(prog="ledger-core", description="Ledger Core CLI")
        p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
        p.add_argument("--env", default=os.getenv("APP_ENV", "staging"))
        p.add_argument("--service", default=os.getenv("APP_NAME", "ledger-core"))
        p.add_argument("--version-str", default=os.getenv("APP_VERSION", "0.0.0"))

        sub = p.add_subparsers(dest="cmd", required=True)

        sub.add_parser("version")
        sub.add_parser("health")

        db = sub.add_parser("db", help="DB operations")
        db_sub = db.add_subparsers(dest="db_cmd", required=True)
        db_sub.add_parser("create-schema")

        m = db_sub.add_parser("migrate")
        m.add_argument("--to", default=None)

        r = db_sub.add_parser("rollback")
        r.add_argument("--to", required=True)

        e = db_sub.add_parser("exec-sql")
        e.add_argument("--file", "-f", default=None)
        e.add_argument("--sql", default=None)
        e.add_argument("--unsafe", action="store_true")

        gen = sub.add_parser("gen", help="Generators")
        gen_sub = gen.add_subparsers(dest="gen_cmd", required=True)
        s = gen_sub.add_parser("secret")
        s.add_argument("--bytes", type=int, default=32)
        gen_sub.add_parser("idem-key")

        return p

    async def _dispatch(ns: argparse.Namespace) -> int:
        if ns.cmd == "version":
            return await cmd_version(ns)
        if ns.cmd == "health":
            return await cmd_health(ns)
        if ns.cmd == "db":
            if ns.db_cmd == "create-schema":
                return await cmd_db_create_schema(ns)
            if ns.db_cmd == "migrate":
                return await cmd_db_migrate(ns)
            if ns.db_cmd == "rollback":
                return await cmd_db_rollback(ns)
            if ns.db_cmd == "exec-sql":
                return await cmd_db_exec_sql(ns)
        if ns.cmd == "gen":
            if ns.gen_cmd == "secret":
                return cmd_gen_secret(ns)
            if ns.gen_cmd == "idem-key":
                return cmd_gen_idem_key(ns)
        _print_json({"error": "unknown_command"})
        return 2

    def main() -> None:
        parser = _build_parser()
        ns = parser.parse_args()
        _setup_global_logging(ns.log_level, ns.env, ns.service, ns.version_str)
        # Грейсфул на SIGINT/SIGTERM
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda s, f: sys.exit(130 if s == signal.SIGINT else 143))
        rc = asyncio.run(_dispatch(ns))
        sys.exit(rc)

# ============================ Entry point ============================

if __name__ == "__main__":
    main()
