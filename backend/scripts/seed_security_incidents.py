# backend/scripts/seed_security_incidents.py
# Industrial-grade async seeder for security incidents (PostgreSQL + SQLAlchemy async).
# Requirements: Python 3.10+, SQLAlchemy 2.x, asyncpg driver available via DATABASE_URL.

from __future__ import annotations

import asyncio
import csv
import json
import os
import sys
import signal
import argparse
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Iterable, Tuple

from sqlalchemy import (
    MetaData,
    Table,
    Column,
    String,
    Text,
    DateTime,
    Index,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID, insert
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, AsyncConnection
from sqlalchemy.sql import select
import uuid
import logging

# ---------------------------
# Structured JSON Logger
# ---------------------------
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if record.args and isinstance(record.args, dict):
            payload.update(record.args)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

logger = logging.getLogger("seed_security_incidents")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonFormatter())
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False

# ---------------------------
# Data model & validation
# ---------------------------
SEVERITIES = {"critical", "high", "medium", "low", "info"}
STATUSES = {"open", "triage", "in_progress", "mitigated", "closed", "false_positive"}

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _uuid4() -> str:
    return str(uuid.uuid4())

@dataclass
class Incident:
    # Primary identifiers
    id: str = field(default_factory=_uuid4)
    correlation_id: str = field(default_factory=_uuid4)

    # Business fields
    title: str = ""
    description: str = ""
    severity: str = "medium"
    status: str = "open"
    detected_at: datetime = field(default_factory=now_utc)
    resolved_at: Optional[datetime] = None

    source: str = "seed_script"
    assignee: Optional[str] = None

    # Rich context
    tags: List[str] = field(default_factory=list)
    assets: List[Dict[str, Any]] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Auditing
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)

    def validate(self) -> None:
        if not self.title or not isinstance(self.title, str):
            raise ValueError("title is required and must be a non-empty string")
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(SEVERITIES)}")
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {sorted(STATUSES)}")
        if not isinstance(self.detected_at, datetime):
            raise ValueError("detected_at must be a datetime")
        if self.resolved_at is not None and not isinstance(self.resolved_at, datetime):
            raise ValueError("resolved_at must be a datetime or None")
        if not self.correlation_id:
            raise ValueError("correlation_id is required")
        # Normalize tz
        if self.detected_at.tzinfo is None:
            self.detected_at = self.detected_at.replace(tzinfo=timezone.utc)
        if self.resolved_at and self.resolved_at.tzinfo is None:
            self.resolved_at = self.resolved_at.replace(tzinfo=timezone.utc)
        if self.created_at.tzinfo is None:
            self.created_at = self.created_at.replace(tzinfo=timezone.utc)
        if self.updated_at.tzinfo is None:
            self.updated_at = self.updated_at.replace(tzinfo=timezone.utc)

    def to_row(self) -> Dict[str, Any]:
        self.validate()
        return {
            "id": self.id,
            "correlation_id": self.correlation_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "detected_at": self.detected_at,
            "resolved_at": self.resolved_at,
            "source": self.source,
            "assignee": self.assignee,
            "tags": self.tags,
            "assets": self.assets,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

# ---------------------------
# DB schema (SQLAlchemy Core)
# ---------------------------
metadata = MetaData(schema=None)  # use default schema; adjust if needed

security_incidents = Table(
    "security_incidents",
    metadata,
    Column("id", UUID(as_uuid=False), primary_key=True),
    Column("correlation_id", String(64), nullable=False),
    Column("title", String(512), nullable=False),
    Column("description", Text, nullable=False, default=""),
    Column("severity", String(16), nullable=False, default="medium"),
    Column("status", String(32), nullable=False, default="open"),
    Column("detected_at", DateTime(timezone=True), nullable=False),
    Column("resolved_at", DateTime(timezone=True), nullable=True),
    Column("source", String(128), nullable=False, default="seed_script"),
    Column("assignee", String(128), nullable=True),
    Column("tags", JSONB, nullable=False, server_default="[]"),
    Column("assets", JSONB, nullable=False, server_default="[]"),
    Column("mitre_tactics", JSONB, nullable=False, server_default="[]"),
    Column("mitre_techniques", JSONB, nullable=False, server_default="[]"),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint("correlation_id", name="uq_security_incidents_correlation_id"),
    Index("ix_security_incidents_detected_at", "detected_at"),
    Index("ix_security_incidents_severity", "severity"),
    Index("ix_security_incidents_status", "status"),
    Index("ix_security_incidents_source", "source"),
)

# ---------------------------
# IO helpers
# ---------------------------
def parse_datetime(value: str) -> datetime:
    # Accept ISO 8601, fallback to unix seconds
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            raise ValueError(f"Invalid datetime: {value}")

def normalize_incident_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(d)
    if "id" in out and out["id"] in (None, "", "auto"):
        out["id"] = _uuid4()
    if "detected_at" in out and isinstance(out["detected_at"], str):
        out["detected_at"] = parse_datetime(out["detected_at"])
    if "resolved_at" in out and isinstance(out["resolved_at"], str):
        out["resolved_at"] = parse_datetime(out["resolved_at"])
    # Defaults
    out.setdefault("id", _uuid4())
    out.setdefault("correlation_id", _uuid4())
    out.setdefault("severity", "medium")
    out.setdefault("status", "open")
    out.setdefault("source", "seed_script")
    out.setdefault("description", "")
    out.setdefault("tags", [])
    out.setdefault("assets", [])
    out.setdefault("mitre_tactics", [])
    out.setdefault("mitre_techniques", [])
    out.setdefault("detected_at", now_utc())
    out.setdefault("created_at", now_utc())
    out.setdefault("updated_at", now_utc())
    return out

def load_from_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
        # NDJSON support
        if "\n" in content and content.lstrip().startswith("{") and "\n{" in content:
            records = []
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))
            return records
        data = json.loads(content)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError("Unsupported JSON structure. Expect object or array.")

def load_from_csv(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            # Convert comma-separated lists for tags, tactics, techniques, assets(optional JSON)
            for key in ("tags", "mitre_tactics", "mitre_techniques"):
                if r.get(key):
                    r[key] = [x.strip() for x in r[key].split(",") if x.strip()]
                else:
                    r[key] = []
            if r.get("assets"):
                try:
                    r["assets"] = json.loads(r["assets"])
                except Exception:
                    r["assets"] = []
            rows.append(r)
    return rows

def load_input_records(path: Optional[str]) -> List[Incident]:
    if not path:
        # Built-in sample dataset (idempotent by correlation_id)
        base_ts = now_utc()
        samples = [
            {
                "title": "Suspicious admin login from unknown IP",
                "description": "Multiple failed logins followed by success on admin account.",
                "severity": "high",
                "status": "triage",
                "detected_at": base_ts.isoformat(),
                "source": "siem",
                "tags": ["auth", "account_takeover", "siem"],
                "assets": [{"type": "service", "name": "auth-api"}],
                "mitre_tactics": ["TA0006"],
                "mitre_techniques": ["T1110"],
                "correlation_id": "seed-si-0001",
            },
            {
                "title": "Outbound data spike to unknown domain",
                "description": "Egress anomaly detected on gateway.",
                "severity": "critical",
                "status": "in_progress",
                "detected_at": base_ts.isoformat(),
                "source": "ids",
                "tags": ["egress", "exfiltration"],
                "assets": [{"type": "gateway", "name": "edge-gw-1"}],
                "mitre_tactics": ["TA0010"],
                "mitre_techniques": ["T1041"],
                "correlation_id": "seed-si-0002",
            },
            {
                "title": "K8s pod privilege escalation blocked",
                "description": "OPA/Gatekeeper denied privileged pod.",
                "severity": "medium",
                "status": "mitigated",
                "detected_at": base_ts.isoformat(),
                "source": "policy",
                "tags": ["k8s", "gatekeeper", "policy"],
                "assets": [{"type": "cluster", "name": "prod-cluster"}],
                "mitre_tactics": ["TA0004"],
                "mitre_techniques": ["T1068"],
                "correlation_id": "seed-si-0003",
            },
            {
                "title": "Unusual wallet activity",
                "description": "Burst of micro-transactions detected.",
                "severity": "low",
                "status": "open",
                "detected_at": base_ts.isoformat(),
                "source": "onchain-analytics",
                "tags": ["web3", "wallet", "anomaly"],
                "assets": [{"type": "wallet", "name": "treasury"}],
                "mitre_tactics": [],
                "mitre_techniques": [],
                "correlation_id": "seed-si-0004",
            },
        ]
        return [Incident(**normalize_incident_dict(s)) for s in samples]

    ext = os.path.splitext(path)[1].lower()
    if ext in (".json", ".ndjson"):
        raw = load_from_json(path)
    elif ext in (".csv",):
        raw = load_from_csv(path)
    else:
        raise ValueError("Unsupported file format. Use JSON/NDJSON/CSV.")
    return [Incident(**normalize_incident_dict(r)) for r in raw]

# ---------------------------
# DB helpers
# ---------------------------
async def create_engine(db_url: str) -> AsyncEngine:
    return create_async_engine(db_url, future=True, pool_pre_ping=True)

async def ensure_schema(conn: AsyncConnection, create_table: bool) -> None:
    if not create_table:
        return
    await conn.run_sync(metadata.create_all)
    logger.info("schema_ensured", extra={"action": "create_all", "tables": ["security_incidents"]})

async def upsert_chunk(
    conn: AsyncConnection, rows: List[Dict[str, Any]]
) -> Tuple[int, int]:
    if not rows:
        return 0, 0
    stmt = insert(security_incidents).values(rows)
    update_cols = {
        "title": stmt.excluded.title,
        "description": stmt.excluded.description,
        "severity": stmt.excluded.severity,
        "status": stmt.excluded.status,
        "detected_at": stmt.excluded.detected_at,
        "resolved_at": stmt.excluded.resolved_at,
        "source": stmt.excluded.source,
        "assignee": stmt.excluded.assignee,
        "tags": stmt.excluded.tags,
        "assets": stmt.excluded.assets,
        "mitre_tactics": stmt.excluded.mitre_tactics,
        "mitre_techniques": stmt.excluded.mitre_techniques,
        "updated_at": stmt.excluded.updated_at,
    }
    stmt = stmt.on_conflict_do_update(
        index_elements=[security_incidents.c.correlation_id],
        set_=update_cols,
    )
    res = await conn.execute(stmt)
    # SQLAlchemy returns rowcount for DML; with upsert it can be 1 per row in many cases
    return len(rows), res.rowcount or 0

async def seed_incidents(
    engine: AsyncEngine,
    incidents: List[Incident],
    chunk_size: int = 500,
    dry_run: bool = False,
    create_table: bool = False,
) -> Tuple[int, int]:
    created = 0
    upserted_effect = 0
    async with engine.begin() as conn:
        await ensure_schema(conn, create_table=create_table)
        if dry_run:
            logger.info("dry_run", extra={"count": len(incidents)})
            return 0, 0

        # Process in chunks
        for i in range(0, len(incidents), chunk_size):
            chunk = incidents[i : i + chunk_size]
            rows = [inc.to_row() for inc in chunk]
            c, u = await upsert_chunk(conn, rows)
            created += c
            upserted_effect += u
            logger.info(
                "chunk_upserted",
                extra={
                    "chunk_start": i,
                    "chunk_end": i + len(chunk) - 1,
                    "chunk_size": len(chunk),
                    "upsert_effect": u,
                },
            )
    return created, upserted_effect

# ---------------------------
# CLI / Orchestration
# ---------------------------
def with_timeout(coro, timeout_s: int):
    return asyncio.wait_for(coro, timeout=timeout_s)

def install_signal_handlers(loop: asyncio.AbstractEventLoop):
    def _shutdown():
        for task in asyncio.all_tasks(loop=loop):
            task.cancel()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            # On Windows, signals might not be fully supported
            pass

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Seed security incidents into PostgreSQL.")
    p.add_argument("--db", dest="db_url", default=os.getenv("DATABASE_URL", ""), help="Async DB URL (postgresql+asyncpg://user:pass@host/db)")
    p.add_argument("--from-file", dest="from_file", default=None, help="Path to JSON/NDJSON/CSV file")
    p.add_argument("--limit", type=int, default=None, help="Limit number of records to seed")
    p.add_argument("--chunk-size", type=int, default=500, help="Bulk upsert chunk size")
    p.add_argument("--create-table", action="store_true", help="Create table if not exists")
    p.add_argument("--dry-run", action="store_true", help="Validate inputs and exit without writing")
    p.add_argument("--timeout", type=int, default=300, help="Overall timeout in seconds")
    return p.parse_args(argv)

async def main_async(args: argparse.Namespace) -> int:
    if not args.db_url:
        logger.error("missing_db_url", extra={"hint": "Provide --db or set DATABASE_URL env (postgresql+asyncpg://...)"})
        return 2

    try:
        records = load_input_records(args.from_file)
    except Exception as e:
        logger.error("load_input_error", extra={"from_file": args.from_file, "error": str(e)})
        return 3

    if args.limit is not None:
        records = records[: max(args.limit, 0)]

    # Validation pass
    valid: List[Incident] = []
    for r in records:
        try:
            r.validate()
            valid.append(r)
        except Exception as e:
            logger.error("validation_error", extra={"title": r.title, "correlation_id": r.correlation_id, "error": str(e)})
    if not valid:
        logger.error("no_valid_records", extra={"total_loaded": len(records)})
        return 4

    engine = await create_engine(args.db_url)

    # Simple connection retry
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            async with engine.connect() as conn:
                await conn.execute(select(1))
            break
        except Exception as e:
            if attempt == max_attempts:
                logger.error("db_connect_failed", extra={"attempt": attempt, "error": str(e)})
                await engine.dispose()
                return 5
            backoff = min(2 ** attempt, 16)
            logger.info("db_connect_retry", extra={"attempt": attempt, "backoff_s": backoff})
            await asyncio.sleep(backoff)

    try:
        created, upserted = await seed_incidents(
            engine=engine,
            incidents=valid,
            chunk_size=args.chunk_size,
            dry_run=args.dry_run,
            create_table=args.create_table,
        )
        logger.info("seed_complete", extra={"input": len(records), "valid": len(valid), "created": created, "upsert_effect": upserted, "dry_run": args.dry_run})
        return 0
    finally:
        await engine.dispose()

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    install_signal_handlers(loop)
    try:
        return loop.run_until_complete(with_timeout(main_async(args), args.timeout))
    except asyncio.TimeoutError:
        logger.error("timeout", extra={"timeout_s": args.timeout})
        return 9
    except asyncio.CancelledError:
        logger.error("cancelled")
        return 10
    except Exception as e:
        logger.error("fatal_error", extra={"error": str(e)})
        return 11
    finally:
        try:
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            loop.close()

if __name__ == "__main__":
    sys.exit(main())
