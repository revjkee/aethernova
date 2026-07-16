# agent_mash/tests/integration/database/test_persistence.py
from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import pytest

try:
    from sqlalchemy import (
        Column,
        DateTime,
        MetaData,
        String,
        Table,
        Text,
        UniqueConstraint,
        func,
        insert,
        select,
        text as sql_text,
    )
    from sqlalchemy.exc import IntegrityError, OperationalError
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
    from sqlalchemy.orm import sessionmaker
except Exception as e:  # pragma: no cover
    pytest.skip(f"SQLAlchemy is required for integration DB tests: {type(e).__name__}: {e}", allow_module_level=True)


@dataclass(frozen=True)
class _DbConfig:
    url: str
    dialect: str


def _read_database_url() -> Optional[str]:
    # Prefer explicit integration DSN
    for key in ("AETHERNOVA_DATABASE_URL", "DATABASE_URL"):
        v = os.getenv(key, "").strip()
        if v:
            return v
    return None


def _detect_dialect(url: str) -> str:
    # Very small deterministic detection; no claims about your infrastructure.
    if url.startswith("postgresql+"):
        return "postgresql"
    if url.startswith("postgresql://"):
        return "postgresql"
    if url.startswith("sqlite+"):
        return "sqlite"
    if url.startswith("sqlite://"):
        return "sqlite"
    # Unknown: still try to use it, but label dialect as unknown
    return "unknown"


def _db_config_or_skip() -> _DbConfig:
    url = _read_database_url()
    if not url:
        pytest.skip(
            "Integration DB not configured. "
            "Set AETHERNOVA_DATABASE_URL (preferred) or DATABASE_URL to run these tests."
        )
    return _DbConfig(url=url, dialect=_detect_dialect(url))


@pytest.fixture(scope="session")
def db_config() -> _DbConfig:
    return _db_config_or_skip()


@pytest.fixture(scope="session")
async def engine(db_config: _DbConfig) -> AsyncEngine:
    # Conservative defaults for CI stability
    connect_args: dict[str, Any] = {}
    if db_config.dialect == "sqlite":
        # sqlite async: allow multi-task access in tests
        connect_args = {"check_same_thread": False}

    eng = create_async_engine(
        db_config.url,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    # Validate connectivity early
    try:
        async with eng.connect() as conn:
            await conn.execute(sql_text("SELECT 1"))
    except OperationalError as e:
        pytest.skip(f"DB connection failed: {type(e).__name__}: {e}")

    yield eng

    await eng.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncSession:
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with maker() as s:
        yield s


@pytest.fixture(scope="session")
def metadata() -> MetaData:
    return MetaData()


@pytest.fixture(scope="session")
def persistence_table(metadata: MetaData) -> Table:
    # Isolated integration test table; name randomized per run to avoid collisions
    # and to avoid touching any production schema.
    tbl_name = f"it_persistence_{uuid.uuid4().hex[:10]}"
    return Table(
        tbl_name,
        metadata,
        Column("id", String(64), primary_key=True),
        Column("bucket", String(64), nullable=False),
        Column("payload", Text, nullable=False),
        Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
        UniqueConstraint("bucket", "id", name=f"uq_{tbl_name}_bucket_id"),
    )


@pytest.fixture(scope="session", autouse=True)
async def create_schema(engine: AsyncEngine, metadata: MetaData, persistence_table: Table) -> None:
    # Create and drop schema around the entire test session
    try:
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
    except Exception as e:
        pytest.skip(f"Failed to create integration schema: {type(e).__name__}: {e}")

    yield

    # Drop at end (best-effort)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(metadata.drop_all)
    except Exception:
        pass


def _row_id() -> str:
    return uuid.uuid4().hex


def _payload(i: int) -> str:
    return f'{{"i": {i}, "ts": {time.time()}}}'


@pytest.mark.asyncio
async def test_persistence_commit_and_readback(session: AsyncSession, persistence_table: Table) -> None:
    rid = _row_id()
    bucket = "commit-readback"
    payload = _payload(1)

    await session.execute(
        insert(persistence_table).values(id=rid, bucket=bucket, payload=payload)
    )
    await session.commit()

    res = await session.execute(
        select(persistence_table.c.id, persistence_table.c.bucket, persistence_table.c.payload).where(
            persistence_table.c.id == rid, persistence_table.c.bucket == bucket
        )
    )
    row = res.first()
    assert row is not None
    assert row.id == rid
    assert row.bucket == bucket
    assert row.payload == payload


@pytest.mark.asyncio
async def test_persistence_rollback_discards_changes(session: AsyncSession, persistence_table: Table) -> None:
    rid = _row_id()
    bucket = "rollback"
    payload = _payload(2)

    await session.execute(
        insert(persistence_table).values(id=rid, bucket=bucket, payload=payload)
    )
    await session.rollback()

    res = await session.execute(
        select(persistence_table.c.id).where(persistence_table.c.id == rid, persistence_table.c.bucket == bucket)
    )
    assert res.first() is None


@pytest.mark.asyncio
async def test_persistence_unique_constraint(session: AsyncSession, persistence_table: Table) -> None:
    rid = _row_id()
    bucket = "unique"
    payload1 = _payload(3)
    payload2 = _payload(4)

    await session.execute(insert(persistence_table).values(id=rid, bucket=bucket, payload=payload1))
    await session.commit()

    # Second insert with same (bucket, id) must fail or be prevented
    try:
        await session.execute(insert(persistence_table).values(id=rid, bucket=bucket, payload=payload2))
        await session.commit()
        # If commit succeeded, then the backend did not enforce uniqueness as expected.
        # That is a valid test failure because the table declares UniqueConstraint.
        pytest.fail("Expected IntegrityError on duplicate (bucket, id), but commit succeeded.")
    except IntegrityError:
        await session.rollback()


@pytest.mark.asyncio
async def test_persistence_upsert_like_behavior_optional(session: AsyncSession, persistence_table: Table) -> None:
    """
    Optional behavior check: if your DB supports ON CONFLICT DO NOTHING, ensure it works.
    If not supported (e.g., older SQLite or unknown dialect), test is skipped.
    """
    # Only run for known supporting dialects
    # PostgreSQL supports it; SQLite supports it in modern versions.
    url = str(session.bind.url) if session.bind is not None else ""
    dialect = "postgresql" if "postgresql" in url else ("sqlite" if "sqlite" in url else "unknown")
    if dialect not in ("postgresql", "sqlite"):
        pytest.skip("Upsert behavior test skipped for unknown dialect.")

    rid = _row_id()
    bucket = "upsert"
    payload = _payload(5)

    stmt = insert(persistence_table).values(id=rid, bucket=bucket, payload=payload)
    try:
        # SQLAlchemy dialect-specific
        if dialect == "postgresql":
            stmt = stmt.on_conflict_do_nothing(index_elements=["bucket", "id"])
        elif dialect == "sqlite":
            stmt = stmt.prefix_with("OR IGNORE")
    except Exception:
        pytest.skip("Upsert syntax not available in current SQLAlchemy/dialect setup.")

    await session.execute(stmt)
    await session.commit()

    # Re-run same statement, should not error
    await session.execute(stmt)
    await session.commit()

    res = await session.execute(
        select(func.count()).select_from(persistence_table).where(
            persistence_table.c.id == rid, persistence_table.c.bucket == bucket
        )
    )
    count = res.scalar_one()
    assert int(count) == 1


@pytest.mark.asyncio
async def test_persistence_concurrent_inserts(engine: AsyncEngine, persistence_table: Table) -> None:
    """
    Concurrency smoke test with isolated sessions.
    Validates that the database handles parallel commits without deadlock.
    """
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    bucket = f"concurrent-{uuid.uuid4().hex[:8]}"

    async def _worker(i: int) -> None:
        async with maker() as s:
            await s.execute(
                insert(persistence_table).values(id=_row_id(), bucket=bucket, payload=_payload(i))
            )
            await s.commit()

    await asyncio.gather(*(_worker(i) for i in range(20)))

    async with maker() as s:
        res = await s.execute(
            select(func.count()).select_from(persistence_table).where(persistence_table.c.bucket == bucket)
        )
        count = int(res.scalar_one())
        assert count == 20


@pytest.mark.asyncio
async def test_persistence_repeatable_read_same_txn(session: AsyncSession, persistence_table: Table) -> None:
    """
    Within the same transaction, a read after insert (before commit) should see the row.
    This is a basic transactional invariant for a single session.
    """
    rid = _row_id()
    bucket = "txn-visibility"
    payload = _payload(6)

    await session.execute(insert(persistence_table).values(id=rid, bucket=bucket, payload=payload))

    res1 = await session.execute(
        select(persistence_table.c.payload).where(persistence_table.c.id == rid, persistence_table.c.bucket == bucket)
    )
    v1 = res1.scalar_one_or_none()
    assert v1 == payload

    res2 = await session.execute(
        select(persistence_table.c.payload).where(persistence_table.c.id == rid, persistence_table.c.bucket == bucket)
    )
    v2 = res2.scalar_one_or_none()
    assert v2 == payload

    await session.rollback()
