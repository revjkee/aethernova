# cli/tools/migrate_db.py
# Industrial-grade CLI for managing Alembic migrations in ledger-core.
# Python: 3.11+
#
# External deps (typical for project):
#   alembic>=1.13
#   SQLAlchemy[asyncio]>=2.0
# Optional:
#   python-dotenv>=1.0  (if you want to load .env automatically)
#
# Environment variables:
#   LEDGER_DB_URL     - database URL (overridable via --db-url)
#   ALEMBIC_INI       - path to alembic.ini (overridable via --alembic-ini)
#   LEDGER_LOG_LEVEL  - logging level (INFO by default)
#
# Usage examples:
#   python -m cli.tools.migrate_db status
#   python -m cli.tools.migrate_db upgrade head
#   python -m cli.tools.migrate_db downgrade -1 --force
#   python -m cli.tools.migrate_db revision -m "add users table"
#   python -m cli.tools.migrate_db upgrade head --sql > upgrade.sql   # offline
#   python -m cli.tools.migrate_db check                               # connectivity & heads
#
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Optional, Iterable

# Optional .env
with contextlib.suppress(Exception):
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()

try:
    from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
    from sqlalchemy import text
except Exception as e:  # pragma: no cover
    print("SQLAlchemy[asyncio] is required: pip install 'SQLAlchemy[asyncio]'", file=sys.stderr)
    raise

try:
    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory
except Exception as e:  # pragma: no cover
    print("Alembic is required: pip install alembic", file=sys.stderr)
    raise

LOG = logging.getLogger("ledger.cli.migrate_db")
if not LOG.handlers:
    _h = logging.StreamHandler()
    _f = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    _h.setFormatter(_f)
    LOG.addHandler(_h)
LOG.setLevel(os.getenv("LEDGER_LOG_LEVEL", "INFO").upper())

DEFAULT_ALEMBIC_INI = os.getenv("ALEMBIC_INI", os.path.join(os.getcwd(), "alembic.ini"))
DEFAULT_DB_URL = os.getenv("LEDGER_DB_URL", "")

# -----------------------------
# Utilities
# -----------------------------
def _fatal(msg: str, code: int = 2) -> None:
    LOG.error(msg)
    sys.exit(code)

def _info(msg: str) -> None:
    LOG.info(msg)

def _warn(msg: str) -> None:
    LOG.warning(msg)

def _confirm(prompt: str) -> bool:
    sys.stdout.write(f"{prompt} [y/N]: ")
    sys.stdout.flush()
    ans = sys.stdin.readline().strip().lower()
    return ans in ("y", "yes")

def _derive_backend(db_url: str) -> str:
    # rough scheme detection
    lower = db_url.lower()
    if lower.startswith(("postgresql+asyncpg://", "postgresql://", "postgres://")):
        return "postgresql"
    if lower.startswith(("sqlite+aiosqlite://", "sqlite://")):
        return "sqlite"
    if lower.startswith(("mysql+aiomysql://", "mysql://", "mariadb://")):
        return "mysql"
    return "unknown"

def _alembic_config(alembic_ini: str, db_url: str, x_args: Optional[Iterable[str]] = None) -> Config:
    if not os.path.exists(alembic_ini):
        _fatal(f"alembic.ini not found: {alembic_ini}")
    cfg = Config(alembic_ini)
    # Allow override via CLI/env
    if db_url:
        cfg.set_main_option("sqlalchemy.url", db_url)
    # Propagate x arguments (alembic -x)
    if x_args:
        for x in x_args:
            cfg.set_main_option(f"x_{x}", "1")
    return cfg

async def _test_connectivity(db_url: str, timeout_sec: float = 10.0) -> None:
    backend = _derive_backend(db_url)
    # Normalize async URL for SQLAlchemy if missing driver for common backends
    url = db_url
    if backend == "postgresql" and "+asyncpg" not in db_url:
        url = db_url.replace("postgresql://", "postgresql+asyncpg://").replace("postgres://", "postgresql+asyncpg://")
    if backend == "sqlite" and "+aiosqlite" not in db_url:
        url = db_url.replace("sqlite://", "sqlite+aiosqlite://")
    engine: AsyncEngine = create_async_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)
    try:
        async with asyncio.timeout(timeout_sec):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
                # Check alembic_version existence (non-fatal if missing)
                with contextlib.suppress(Exception):
                    await conn.execute(text("SELECT 1 FROM alembic_version"))
        _info(f"DB connectivity OK ({backend})")
    finally:
        await engine.dispose()

@contextlib.asynccontextmanager
async def _advisory_lock(db_url: str, lock_name: str = "ledger_migration_lock"):
    """
    Prevent concurrent migration runs. For PostgreSQL uses pg_advisory_lock.
    For others: best-effort no-op.
    """
    backend = _derive_backend(db_url)
    if backend != "postgresql":
        yield
        return

    url = db_url if "+asyncpg" in db_url else db_url.replace("postgresql://", "postgresql+asyncpg://").replace("postgres://", "postgresql+asyncpg://")
    engine: AsyncEngine = create_async_engine(url, pool_pre_ping=True)
    # 64-bit key from lock_name
    key = int.from_bytes(hashlib.sha256(lock_name.encode("utf-8")).digest()[:8], byteorder="big", signed=False)
    try:
        async with engine.begin() as conn:
            # Try immediate lock acquisition
            rv = await conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key})
            got = rv.scalar()
            if not got:
                _fatal("Another migration process holds the advisory lock. Abort.")
            _info("Advisory lock acquired")
        try:
            yield
        finally:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
                _info("Advisory lock released")
    finally:
        await engine.dispose()

def _ensure_force_or_confirm(args: argparse.Namespace, action: str) -> None:
    if args.force:
        return
    if not _confirm(f"Confirm '{action}' on database {args.db_url}?"):
        _fatal("Action cancelled by user", code=1)

def _require_db_url(url: str) -> str:
    if not url:
        _fatal("Database URL is required. Set LEDGER_DB_URL or pass --db-url.")
    return url

# -----------------------------
# Commands
# -----------------------------
def cmd_status(args: argparse.Namespace) -> None:
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    script = ScriptDirectory.from_config(cfg)
    head = ",".join(script.get_heads())
    current = None
    with contextlib.suppress(Exception):
        # Alembic's current() prints to stdout; we need programmatic state:
        # Use the environment to read current rev; fallback prints if needed.
        pass
    print(f"Heads: {head}")
    # Use 'command.current' to print; less ideal but acceptable for CLI:
    command.current(cfg, verbose=True)

def cmd_history(args: argparse.Namespace) -> None:
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    rev_range = f"{args.range}" if args.range else None
    command.history(cfg, rev_range=rev_range, verbose=args.verbose)

def cmd_heads(args: argparse.Namespace) -> None:
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    command.heads(cfg, verbose=args.verbose)

def cmd_current(args: argparse.Namespace) -> None:
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    command.current(cfg, verbose=True)

def cmd_upgrade(args: argparse.Namespace) -> None:
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    if args.sql:
        command.upgrade(cfg, args.revision, sql=True, tag=args.tag)
        return
    # online: advisory lock + connectivity
    async def _run():
        await _test_connectivity(args.db_url)
        async with _advisory_lock(args.db_url):
            command.upgrade(cfg, args.revision, tag=args.tag)
    asyncio.run(_run())

def cmd_downgrade(args: argparse.Namespace) -> None:
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    if not args.sql:
        _ensure_force_or_confirm(args, f"downgrade to {args.revision}")
    if args.sql:
        command.downgrade(cfg, args.revision, sql=True, tag=args.tag)
        return
    async def _run():
        await _test_connectivity(args.db_url)
        async with _advisory_lock(args.db_url):
            command.downgrade(cfg, args.revision, tag=args.tag)
    asyncio.run(_run())

def cmd_stamp(args: argparse.Namespace) -> None:
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    _ensure_force_or_confirm(args, f"stamp {args.revision}")
    if args.sql:
        command.stamp(cfg, args.revision, sql=True, tag=args.tag)
        return
    async def _run():
        await _test_connectivity(args.db_url)
        async with _advisory_lock(args.db_url):
            command.stamp(cfg, args.revision, tag=args.tag)
    asyncio.run(_run())

def cmd_revision(args: argparse.Namespace) -> None:
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    command.revision(
        cfg,
        message=args.message,
        autogenerate=args.autogenerate,
        rev_id=args.rev_id,
        branch_label=args.branch_label,
        splice=args.splice,
        head=args.head,
        depends_on=args.depends_on,
    )

def cmd_check(args: argparse.Namespace) -> None:
    # Connectivity + multiple heads detection
    cfg = _alembic_config(args.alembic_ini, args.db_url)
    async def _run():
        await _test_connectivity(args.db_url)
    asyncio.run(_run())
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    if len(heads) > 1:
        _warn(f"Multiple heads detected: {heads}")
        if not args.allow_multiple_heads:
            _fatal("Multiple heads are not allowed (merge required).")
    print("Check OK")

# -----------------------------
# Parser
# -----------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="migrate_db", description="Ledger-core Alembic migration tool")
    p.add_argument("--db-url", default=DEFAULT_DB_URL, help="Database URL (env LEDGER_DB_URL)")
    p.add_argument("--alembic-ini", default=DEFAULT_ALEMBIC_INI, help="Path to alembic.ini (env ALEMBIC_INI)")
    p.add_argument("--tag", default=None, help="Alembic tag for upgrade/downgrade/stamp")
    p.add_argument("--sql", action="store_true", help="Offline mode: emit SQL to stdout")
    p.add_argument("--force", action="store_true", help="Do not prompt for confirmation on destructive actions")
    p.add_argument("--dry-run", action="store_true", help="Parse args and show what would be executed, then exit")

    sub = p.add_subparsers(dest="cmd", required=True)

    s_status = sub.add_parser("status", help="Show current revision and heads")
    s_status.set_defaults(func=cmd_status)

    s_hist = sub.add_parser("history", help="Show revision history")
    s_hist.add_argument("--range", default=None, help="Revision range, e.g. base:head or <rev1>:<rev2>")
    s_hist.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    s_hist.set_defaults(func=cmd_history)

    s_heads = sub.add_parser("heads", help="Show heads")
    s_heads.add_argument("-v", "--verbose", action="store_true")
    s_heads.set_defaults(func=cmd_heads)

    s_current = sub.add_parser("current", help="Show current DB revision")
    s_current.set_defaults(func=cmd_current)

    s_up = sub.add_parser("upgrade", help="Upgrade to a later revision")
    s_up.add_argument("revision", help="Target revision (e.g., head, +1, <rev>)")
    s_up.set_defaults(func=cmd_upgrade)

    s_down = sub.add_parser("downgrade", help="Revert to a previous revision")
    s_down.add_argument("revision", help="Target revision (e.g., -1, base, <rev>)")
    s_down.set_defaults(func=cmd_downgrade)

    s_stamp = sub.add_parser("stamp", help="Set DB revision without running migrations")
    s_stamp.add_argument("revision", help="Revision (e.g., head, base, <rev>)")
    s_stamp.set_defaults(func=cmd_stamp)

    s_rev = sub.add_parser("revision", help="Create a new revision file")
    s_rev.add_argument("-m", "--message", required=True, help="Revision message")
    s_rev.add_argument("--autogenerate", action="store_true", help="Autogenerate from models")
    s_rev.add_argument("--rev-id", default=None, help="Manual revision id")
    s_rev.add_argument("--branch-label", default=None, help="Branch label")
    s_rev.add_argument("--splice", action="store_true", help="Create a splice branch")
    s_rev.add_argument("--head", default="head", help="Base head for new revision")
    s_rev.add_argument("--depends-on", default=None, help="Revision(s) this depends on")
    s_rev.set_defaults(func=cmd_revision)

    s_check = sub.add_parser("check", help="Connectivity and heads check")
    s_check.add_argument("--allow-multiple-heads", action="store_true", help="Do not fail on multiple heads")
    s_check.set_defaults(func=cmd_check)

    return p

# -----------------------------
# Entry
# -----------------------------
def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Dry-run summary
    if args.dry_run:
        print("Dry-run mode. Parsed arguments:")
        for k, v in sorted(vars(args).items()):
            if k in ("func",):
                continue
            print(f"  {k} = {v}")
        sys.exit(0)

    args.db_url = _require_db_url(args.db_url)

    t0 = time.perf_counter()
    try:
        args.func(args)
    except KeyboardInterrupt:
        _fatal("Interrupted by user", code=130)
    except SystemExit:
        raise
    except Exception as e:
        _fatal(f"Migration command failed: {e}", code=1)
    finally:
        dt = (time.perf_counter() - t0) * 1000.0
        _info(f"Done in {dt:.1f} ms")

if __name__ == "__main__":
    main()
