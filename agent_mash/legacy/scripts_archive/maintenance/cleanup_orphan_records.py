#!/usr/bin/env python3
"""
cleanup_orphan_records.py

Industrial maintenance script for detecting and removing orphan records
from a relational database.

Key principles:
- Explicit configuration only (no implicit table guesses)
- Dry-run by default
- Transactional safety
- Deterministic logging
- Idempotent behavior

This script is intended for scheduled maintenance or controlled manual runs.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError


# ----------------------------
# Configuration model
# ----------------------------

@dataclass(frozen=True)
class OrphanRule:
    """
    Defines a single orphan-cleanup rule.

    child_table: table containing potentially orphaned rows
    child_fk_column: foreign key column in child_table
    parent_table: referenced parent table
    parent_pk_column: primary key column in parent_table
    """
    child_table: str
    child_fk_column: str
    parent_table: str
    parent_pk_column: str


# Example rules.
# IMPORTANT:
# These must be explicitly reviewed and adapted to the real schema.
ORPHAN_RULES: Sequence[OrphanRule] = (
    OrphanRule(
        child_table="sessions",
        child_fk_column="user_id",
        parent_table="users",
        parent_pk_column="id",
    ),
    OrphanRule(
        child_table="tokens",
        child_fk_column="user_id",
        parent_table="users",
        parent_pk_column="id",
    ),
)


# ----------------------------
# Logging
# ----------------------------

def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


# ----------------------------
# Database helpers
# ----------------------------

def create_db_engine(database_url: str) -> Engine:
    return create_engine(
        database_url,
        isolation_level="AUTOCOMMIT",
        future=True,
    )


def find_orphans(engine: Engine, rule: OrphanRule) -> List[int]:
    """
    Returns a list of primary keys of orphan rows.
    Assumes child table has a column named 'id' as primary key.
    """
    query = text(f"""
        SELECT c.id
        FROM {rule.child_table} AS c
        LEFT JOIN {rule.parent_table} AS p
            ON c.{rule.child_fk_column} = p.{rule.parent_pk_column}
        WHERE c.{rule.child_fk_column} IS NOT NULL
          AND p.{rule.parent_pk_column} IS NULL
    """)

    with engine.connect() as conn:
        result = conn.execute(query)
        return [row[0] for row in result.fetchall()]


def delete_orphans(engine: Engine, rule: OrphanRule, ids: Iterable[int]) -> int:
    """
    Deletes orphan rows by primary key.
    Returns number of deleted rows.
    """
    ids = list(ids)
    if not ids:
        return 0

    delete_query = text(f"""
        DELETE FROM {rule.child_table}
        WHERE id = ANY(:ids)
    """)

    with engine.begin() as conn:
        result = conn.execute(delete_query, {"ids": ids})
        return result.rowcount or 0


# ----------------------------
# Core logic
# ----------------------------

def process_rule(
    engine: Engine,
    rule: OrphanRule,
    dry_run: bool,
) -> Tuple[int, int]:
    """
    Processes a single orphan rule.

    Returns:
        found_count, deleted_count
    """
    orphan_ids = find_orphans(engine, rule)
    found_count = len(orphan_ids)

    if found_count == 0:
        logging.info(
            "No orphan records found for %s.%s",
            rule.child_table,
            rule.child_fk_column,
        )
        return 0, 0

    logging.info(
        "Found %d orphan records in table '%s'",
        found_count,
        rule.child_table,
    )

    if dry_run:
        logging.info(
            "Dry-run enabled, no records will be deleted for table '%s'",
            rule.child_table,
        )
        return found_count, 0

    deleted_count = delete_orphans(engine, rule, orphan_ids)

    logging.info(
        "Deleted %d orphan records from table '%s'",
        deleted_count,
        rule.child_table,
    )

    return found_count, deleted_count


# ----------------------------
# CLI
# ----------------------------

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cleanup orphan records from database",
    )

    parser.add_argument(
        "--database-url",
        required=True,
        help="SQLAlchemy database URL",
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply deletions. If not set, script runs in dry-run mode.",
    )

    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    setup_logging()
    args = parse_args(argv)

    dry_run = not args.apply
    if dry_run:
        logging.info("Running in DRY-RUN mode")

    engine = create_db_engine(args.database_url)

    total_found = 0
    total_deleted = 0

    try:
        for rule in ORPHAN_RULES:
            found, deleted = process_rule(engine, rule, dry_run=dry_run)
            total_found += found
            total_deleted += deleted
    except SQLAlchemyError as exc:
        logging.error("Database error occurred: %s", exc)
        return 1

    logging.info(
        "Cleanup finished. Found=%d Deleted=%d DryRun=%s",
        total_found,
        total_deleted,
        dry_run,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
