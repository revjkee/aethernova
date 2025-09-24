# datafabric-core/cli/tools/seed_demo_data.py
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import string
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# -------- Optional tracing (no-op if unavailable) --------
try:
    from datafabric.observability.tracing import start_span, add_event, set_attributes, trace_function
except Exception:
    from contextlib import contextmanager
    @contextmanager
    def start_span(*args, **kwargs):
        yield
    def add_event(*args, **kwargs): ...
    def set_attributes(*args, **kwargs): ...
    def trace_function(*dargs, **dkwargs):
        def deco(fn): return fn
        return deco

# -------- Time utils (fallback to stdlib if missing) -----
try:
    from datafabric.utils.time import now_utc, to_iso8601, parse_duration
except Exception:
    def now_utc() -> datetime:
        return datetime.now(timezone.utc)
    def to_iso8601(dt: datetime, with_ms: bool = True) -> str:
        s = dt.astimezone(timezone.utc).isoformat()
        return s.replace("+00:00", "Z")
    def parse_duration(value) -> timedelta:
        if isinstance(value, timedelta): return value
        if isinstance(value, (int, float)): return timedelta(seconds=float(value))
        s = str(value).strip().lower()
        units = {"s":1, "m":60, "h":3600, "d":86400}
        num = ""
        total = 0.0
        for ch in s:
            if ch.isdigit() or ch == ".":
                num += ch
            else:
                if ch not in units or not num:
                    raise ValueError(f"bad duration: {value!r}")
                total += float(num) * units[ch]
                num = ""
        if num:
            total += float(num)
        return timedelta(seconds=total)

# -------- SQLAlchemy (required) --------------------------
try:
    from sqlalchemy import (
        BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer, Numeric, String, Text, text,
        MetaData, Table, select, insert, UniqueConstraint
    )
    from sqlalchemy.dialects.postgresql import UUID as PGUUID
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
    from sqlalchemy.sql import func
except Exception as exc:
    raise RuntimeError("SQLAlchemy (async) is required for seeding") from exc

# =========================================================
# Configuration dataclasses
# =========================================================

@dataclass
class SeedConfig:
    db_url: str
    init_schema: bool = False
    truncate: bool = False
    users: int = 1_000
    accounts_per_user_min: int = 1
    accounts_per_user_max: int = 3
    tx_per_account_min: int = 10
    tx_per_account_max: int = 50
    tx_amount_min: float = -200.0
    tx_amount_max: float =  500.0
    currencies: Tuple[str, ...] = ("USD", "EUR", "SEK")
    seed: int = 42
    batch_size: int = 2_000
    upsert: bool = True                 # emulate ON CONFLICT DO NOTHING
    quiet: bool = False
    yaml_path: Optional[str] = None     # optional external YAML for overrides

# =========================================================
# Helpers: random deterministic data
# =========================================================

ALPHA = string.ascii_lowercase
DIGITS = string.digits

def _rand_str(n: int) -> str:
    return "".join(random.choice(ALPHA) for _ in range(n))

def _rand_email(name: str) -> str:
    domain = random.choice(["example.com", "mail.test", "aethernova.dev"])
    return f"{name}.{_rand_str(4)}@{domain}"

def _uuid4_hex() -> str:
    # hex with hyphens to be compatible across PG/SQLite
    import uuid
    return str(uuid.uuid4())

def _rand_name() -> str:
    first = random.choice(["Alex", "Maria", "John", "Eva", "Liam", "Olivia", "Noah", "Mia", "Emma", "Lucas"])
    last  = random.choice(["Ivanov", "Smith", "Johnson", "Lindberg", "Andersson", "Kuznetsov", "Brown", "Garcia"])
    return f"{first} {last}"

def _rand_datetime(start: datetime, end: datetime) -> datetime:
    delta = (end - start).total_seconds()
    t = start + timedelta(seconds=random.random() * max(delta, 1))
    return t.replace(tzinfo=timezone.utc)

def _now_minus(days: int) -> datetime:
    return now_utc() - timedelta(days=days)

# =========================================================
# Schema (portable PG/SQLite)
# =========================================================

def _uuid_column(name: str, metadata: MetaData, pg: bool) -> Column:
    if pg:
        return Column(name, PGUUID(as_uuid=False), primary_key=True)
    return Column(name, String(36), primary_key=True)

def build_metadata(db_url: str) -> MetaData:
    metadata = MetaData(naming_convention={
        "pk": "pk_%(table_name)s",
        "ix": "ix_%(table_name)s_%(column_0_name)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    })
    pg = db_url.startswith("postgresql+asyncpg://") or db_url.startswith("postgresql+psycopg")

    users = Table(
        "users", metadata,
        _uuid_column("id", metadata, pg),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Column("email", String(255), nullable=False, unique=True),
        Column("name", String(255), nullable=False),
    )

    accounts = Table(
        "accounts", metadata,
        _uuid_column("id", metadata, pg),
        Column("user_id", users.c.id.type, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        Column("currency", String(8), nullable=False),
        Column("balance", Numeric(18, 2), nullable=False, server_default="0"),
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        UniqueConstraint("user_id", "currency", name="uq_accounts_user_currency"),
    )

    transactions = Table(
        "transactions", metadata,
        _uuid_column("id", metadata, pg),
        Column("account_id", accounts.c.id.type, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False),
        Column("amount", Numeric(18, 2), nullable=False),
        Column("currency", String(8), nullable=False),
        Column("kind", String(16), nullable=False),  # debit|credit|fee|refund
        Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
        Index("ix_transactions_account_created", "account_id", "created_at"),
    )

    return metadata

# =========================================================
# Seed logic
# =========================================================

@dataclass
class SeedState:
    user_ids: List[str]
    account_ids: List[Tuple[str, str]]  # (account_id, currency)

async def init_schema(engine: AsyncEngine, metadata: MetaData) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)

async def truncate_all(engine: AsyncEngine, metadata: MetaData) -> None:
    tables = list(reversed(metadata.sorted_tables))
    async with engine.begin() as conn:
        url = str(engine.url)
        if url.startswith("postgresql"):
            for t in tables:
                await conn.execute(text(f'TRUNCATE TABLE "{t.name}" RESTART IDENTITY CASCADE'))
        else:
            for t in tables:
                await conn.execute(text(f'DELETE FROM "{t.name}"'))

def _chunk(iterable: List[Dict[str, Any]], size: int) -> Iterable[List[Dict[str, Any]]]:
    for i in range(0, len(iterable), size):
        yield iterable[i:i+size]

@trace_function("seed.generate.users")
def gen_users(n: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    start = _now_minus(365)
    end   = now_utc()
    for _ in range(n):
        name = _rand_name()
        out.append({
            "id": _uuid4_hex(),
            "created_at": _rand_datetime(start, end),
            "email": _rand_email(name.replace(" ", ".").lower()),
            "name": name,
        })
    return out

@trace_function("seed.generate.accounts")
def gen_accounts(user_ids: List[str], cur: Tuple[str, ...], per_user: Tuple[int, int]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    start = _now_minus(300)
    end   = now_utc()
    lo, hi = per_user
    for uid in user_ids:
        k = random.randint(lo, hi)
        used = set()
        for _ in range(k):
            ccy = random.choice(cur)
            # avoid duplicate currency per user
            attempts = 0
            while ccy in used and attempts < 10:
                ccy = random.choice(cur); attempts += 1
            used.add(ccy)
            out.append({
                "id": _uuid4_hex(),
                "user_id": uid,
                "currency": ccy,
                "balance": round(random.uniform(0, 10_000), 2),
                "created_at": _rand_datetime(start, end),
            })
    return out

@trace_function("seed.generate.transactions")
def gen_transactions(accounts: List[Dict[str, Any]], per_acc: Tuple[int, int], amount_range: Tuple[float, float]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    kinds = ["debit", "credit", "fee", "refund"]
    start = _now_minus(180)
    end   = now_utc()
    lo, hi = per_acc
    lo = max(0, lo)
    for acc in accounts:
        n = random.randint(lo, hi)
        for _ in range(n):
            amt = round(random.uniform(amount_range[0], amount_range[1]), 2)
            out.append({
                "id": _uuid4_hex(),
                "account_id": acc["id"],
                "amount": amt,
                "currency": acc["currency"],
                "kind": random.choice(kinds),
                "created_at": _rand_datetime(start, end),
            })
    return out

async def _insert_batches(engine: AsyncEngine, table: Table, rows: List[Dict[str, Any]], batch_size: int, upsert: bool) -> int:
    total = 0
    if not rows:
        return 0
    async with engine.begin() as conn:
        url = str(engine.url)
        for batch in _chunk(rows, batch_size):
            if upsert:
                if url.startswith("postgresql"):
                    # PG: ON CONFLICT DO NOTHING by PK
                    cols = list(batch[0].keys())
                    stmt = insert(table).values(batch).on_conflict_do_nothing(index_elements=[list(table.primary_key.columns)[0].name])
                else:
                    # SQLite: INSERT OR IGNORE
                    stmt = insert(table).prefix_with("OR IGNORE").values(batch)
            else:
                stmt = insert(table).values(batch)
            res = await conn.execute(stmt)
            if res.rowcount is not None:
                total += res.rowcount
            else:
                total += len(batch)
    return total

# =========================================================
# YAML overrides (optional)
# =========================================================

def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1","true","yes","y","on")

def _load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml
    except Exception as exc:
        raise RuntimeError("PyYAML not installed, remove --config or install PyYAML") from exc
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def load_config(args: argparse.Namespace) -> SeedConfig:
    url = args.db_url or os.getenv("DF_DB_URL") or "sqlite+aiosqlite:///./demo.db"
    cfg = SeedConfig(
        db_url=url,
        init_schema=args.init_schema or _env_bool("DF_SEED_INIT_SCHEMA", False),
        truncate=args.truncate or _env_bool("DF_SEED_TRUNCATE", False),
        users=int(os.getenv("DF_SEED_USERS", args.users)),
        accounts_per_user_min=int(os.getenv("DF_SEED_ACC_MIN", args.accounts_min)),
        accounts_per_user_max=int(os.getenv("DF_SEED_ACC_MAX", args.accounts_max)),
        tx_per_account_min=int(os.getenv("DF_SEED_TX_MIN", args.txs_min)),
        tx_per_account_max=int(os.getenv("DF_SEED_TX_MAX", args.txs_max)),
        tx_amount_min=float(os.getenv("DF_SEED_AMT_MIN", args.amount_min)),
        tx_amount_max=float(os.getenv("DF_SEED_AMT_MAX", args.amount_max)),
        currencies=tuple((os.getenv("DF_SEED_CCY", ",".join(args.currencies))).split(",")),
        seed=int(os.getenv("DF_SEED_SEED", args.seed)),
        batch_size=int(os.getenv("DF_SEED_BATCH", args.batch)),
        upsert=_env_bool("DF_SEED_UPSERT", not args.no_upsert),
        quiet=args.quiet,
        yaml_path=args.config,
    )
    # YAML overrides
    if cfg.yaml_path:
        data = _load_yaml(cfg.yaml_path)
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    return cfg

# =========================================================
# CLI and runner
# =========================================================

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Seed demo data for DataFabric (async, PG/SQLite)")
    p.add_argument("--db-url", type=str, default=None, help="SQLAlchemy async URL (DF_DB_URL if absent)")
    p.add_argument("--init-schema", action="store_true", help="Create tables if not exist")
    p.add_argument("--truncate", action="store_true", help="Truncate tables before seeding")
    p.add_argument("--users", type=int, default=1000, help="Number of users")
    p.add_argument("--accounts-min", type=int, default=1, help="Min accounts per user")
    p.add_argument("--accounts-max", type=int, default=3, help="Max accounts per user")
    p.add_argument("--txs-min", type=int, default=10, help="Min tx per account")
    p.add_argument("--txs-max", type=int, default=50, help="Max tx per account")
    p.add_argument("--amount-min", type=float, default=-200.0, help="Min tx amount")
    p.add_argument("--amount-max", type=float, default=500.0, help="Max tx amount")
    p.add_argument("--currencies", nargs="+", default=["USD", "EUR", "SEK"], help="List of currencies")
    p.add_argument("--seed", type=int, default=42, help="PRNG seed for reproducibility")
    p.add_argument("--batch", type=int, default=2000, help="Insert batch size")
    p.add_argument("--no-upsert", action="store_true", help="Disable upsert/ignore on conflicts")
    p.add_argument("--quiet", action="store_true", help="Less verbose output")
    p.add_argument("--config", type=str, default=None, help="YAML path to override settings")
    return p

async def run(cfg: SeedConfig) -> Dict[str, Any]:
    random.seed(cfg.seed)

    engine = create_async_engine(cfg.db_url, pool_pre_ping=True, pool_size=5, max_overflow=5)

    metadata = build_metadata(cfg.db_url)
    result: Dict[str, Any] = {
        "started_at": to_iso8601(now_utc()),
        "db": cfg.db_url,
        "seed": cfg.seed,
        "rows": {"users": 0, "accounts": 0, "transactions": 0},
    }

    try:
        if cfg.init_schema:
            with start_span("seed.init_schema"):
                await init_schema(engine, metadata)

        if cfg.truncate:
            with start_span("seed.truncate"):
                await truncate_all(engine, metadata)

        # Generate data
        with start_span("seed.generate"):
            users = gen_users(cfg.users)
            user_ids = [u["id"] for u in users]

            accounts = gen_accounts(
                user_ids=user_ids,
                cur=cfg.currencies,
                per_user=(cfg.accounts_per_user_min, cfg.accounts_per_user_max)
            )
            transactions = gen_transactions(
                accounts=accounts,
                per_acc=(cfg.tx_per_account_min, cfg.tx_per_account_max),
                amount_range=(cfg.tx_amount_min, cfg.tx_amount_max),
            )

        # Insert in order: users -> accounts -> transactions
        users_t = metadata.tables["users"]
        accounts_t = metadata.tables["accounts"]
        tx_t = metadata.tables["transactions"]

        with start_span("seed.insert.users", {"count": len(users)}):
            n = await _insert_batches(engine, users_t, users, cfg.batch_size, cfg.upsert)
            result["rows"]["users"] = n
            if not cfg.quiet:
                print(f"Inserted users: {n}")

        with start_span("seed.insert.accounts", {"count": len(accounts)}):
            n = await _insert_batches(engine, accounts_t, accounts, cfg.batch_size, cfg.upsert)
            result["rows"]["accounts"] = n
            if not cfg.quiet:
                print(f"Inserted accounts: {n}")

        with start_span("seed.insert.transactions", {"count": len(transactions)}):
            n = await _insert_batches(engine, tx_t, transactions, cfg.batch_size, cfg.upsert)
            result["rows"]["transactions"] = n
            if not cfg.quiet:
                print(f"Inserted transactions: {n}")

        result["finished_at"] = to_iso8601(now_utc())
        add_event("seed.done", {"total": json.dumps(result["rows"])})
        return result
    finally:
        await engine.dispose()

def main() -> None:
    args = _build_parser().parse_args()
    cfg = load_config(args)
    with start_span("seed.run", {"db": cfg.db_url, "seed": cfg.seed}):
        out = asyncio.run(run(cfg))
        print(json.dumps(out, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
