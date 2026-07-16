#!/usr/bin/env python3
"""
migrate_payments_legacy.py

Industrial-grade migration script for legacy payments data.

Properties:
- Idempotent (safe to re-run)
- Transactional
- Batched processing
- Dry-run support
- Explicit logging and audit
- No assumptions about business logic beyond schema mapping

Environment variables:
- LEGACY_DATABASE_URL      source database DSN
- TARGET_DATABASE_URL      target database DSN
- MIGRATION_BATCH_SIZE     optional, default 500
- MIGRATION_DRY_RUN        optional, "true"/"false", default false
"""

from __future__ import annotations

import os
import sys
import logging
from typing import Any, Iterable, List, Dict

from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    select,
    insert,
    and_,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

LEGACY_DATABASE_URL = os.getenv("LEGACY_DATABASE_URL")
TARGET_DATABASE_URL = os.getenv("TARGET_DATABASE_URL")

if not LEGACY_DATABASE_URL or not TARGET_DATABASE_URL:
    raise RuntimeError(
        "LEGACY_DATABASE_URL and TARGET_DATABASE_URL must be set"
    )

BATCH_SIZE = int(os.getenv("MIGRATION_BATCH_SIZE", "500"))
DRY_RUN = os.getenv("MIGRATION_DRY_RUN", "false").lower() == "true"


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("migrate_payments_legacy")


# -----------------------------------------------------------------------------
# Database setup
# -----------------------------------------------------------------------------

def _create_engine(url: str) -> Engine:
    return create_engine(
        url,
        future=True,
        pool_pre_ping=True,
    )


legacy_engine = _create_engine(LEGACY_DATABASE_URL)
target_engine = _create_engine(TARGET_DATABASE_URL)

legacy_meta = MetaData()
target_meta = MetaData()


# -----------------------------------------------------------------------------
# Table definitions (reflected, not invented)
# -----------------------------------------------------------------------------

legacy_payments = Table(
    "payments",
    legacy_meta,
    autoload_with=legacy_engine,
)

target_payments = Table(
    "payments",
    target_meta,
    autoload_with=target_engine,
)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _batched(rows: Iterable[Dict[str, Any]], size: int) -> Iterable[List[Dict[str, Any]]]:
    batch: List[Dict[str, Any]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def _map_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Explicit field mapping.
    Adjust only if schemas differ.
    """
    return dict(row)


# -----------------------------------------------------------------------------
# Migration logic
# -----------------------------------------------------------------------------

def migrate() -> None:
    logger.info("Starting legacy payments migration")
    logger.info("Dry-run mode: %s", DRY_RUN)
    logger.info("Batch size: %d", BATCH_SIZE)

    with legacy_engine.connect() as legacy_conn, target_engine.connect() as target_conn:
        legacy_session = Session(bind=legacy_conn)
        target_session = Session(bind=target_conn)

        try:
            stmt = select(legacy_payments)
            result = legacy_session.execute(stmt)

            total = 0
            migrated = 0

            rows = [dict(row._mapping) for row in result]

            for batch in _batched(rows, BATCH_SIZE):
                total += len(batch)

                mapped = [_map_row(r) for r in batch]

                if DRY_RUN:
                    logger.info(
                        "Dry-run: would migrate %d payments (total processed %d)",
                        len(mapped),
                        total,
                    )
                    continue

                for item in mapped:
                    # Idempotency check based on primary key
                    pk_conditions = [
                        target_payments.c[col.name] == item[col.name]
                        for col in target_payments.primary_key.columns
                    ]

                    exists_stmt = select(target_payments.c[list(target_payments.primary_key.columns)[0].name]).where(
                        and_(*pk_conditions)
                    )

                    exists = target_session.execute(exists_stmt).first()
                    if exists:
                        continue

                    target_session.execute(insert(target_payments).values(**item))
                    migrated += 1

                target_session.commit()
                logger.info(
                    "Batch committed: %d records, total processed %d, migrated %d",
                    len(batch),
                    total,
                    migrated,
                )

            logger.info(
                "Migration completed. Processed %d rows, migrated %d rows",
                total,
                migrated,
            )

        except SQLAlchemyError as e:
            target_session.rollback()
            logger.error("Migration failed, transaction rolled back")
            logger.error(str(e))
            raise
        finally:
            legacy_session.close()
            target_session.close()


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        migrate()
    except Exception as exc:
        logger.error("Fatal migration error")
        logger.error(str(exc))
        sys.exit(1)
    sys.exit(0)
