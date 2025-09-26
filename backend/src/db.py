"""Asynchronous database module.

This module provides a `database` object (an instance of `databases.Database`)
and an `init_db()` coroutine that performs light-weight initialization
(creates a simple `users` table if it does not exist).

Configuration:
- Reads `DATABASE_URL` from environment. If not set, defaults to
  a local SQLite file `./dev.db` using the aiosqlite driver.

Notes:
- For production use replace the simple `init_db` with proper migrations
  (Alembic or another migration tool). This module is written to be
  dependency-light while remaining production-amenable.
"""
from __future__ import annotations

import os
import sqlalchemy
from typing import Optional
from databases import Database
from .models import metadata


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///app/data/dev.db")

# Primary database instance used by the application
database = Database(DATABASE_URL)


async def init_db() -> None:
    """Perform minimal initialization (create tables if missing).

    This is intentionally lightweight. Use Alembic for real migrations.
    """
    # If using sqlite, ensure parent directory exists so the file can be created
    if DATABASE_URL.startswith("sqlite"):
        # extract file path after prefix like sqlite+aiosqlite:///app/data/dev.db
        parts = DATABASE_URL.split("///", 1)
        if len(parts) == 2:
            path = parts[1]
            parent = os.path.dirname(path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

    # Ensure database is connected temporarily if not already
    connected_here = False
    if not getattr(database, "is_connected", False):
        await database.connect()
        connected_here = True

    try:
        # Prefer migrations (Alembic) for production databases. As a
        # development convenience, if using the local sqlite file we will
        # create tables from SQLAlchemy metadata so the dev experience is
        # smooth without requiring running migrations.
        if DATABASE_URL.startswith("sqlite"):
            sync_url = DATABASE_URL
            if "+aiosqlite" in sync_url:
                sync_url = sync_url.replace("+aiosqlite", "")
            engine = sqlalchemy.create_engine(sync_url)
            metadata.create_all(engine)
        else:
            # For non-sqlite databases rely on Alembic migrations. Do not
            # attempt to create tables automatically in production.
            pass
    finally:
        if connected_here:
            await database.disconnect()

