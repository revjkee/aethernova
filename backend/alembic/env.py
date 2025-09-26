from __future__ import with_statement
import os
from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging. Wrap in try/except because
# some minimal alembic.ini files may omit expected keys and fileConfig will
# raise KeyError which would prevent migrations from running.
try:
    if config.config_file_name:
        fileConfig(config.config_file_name)
except Exception:
    # Logging config is optional for migration runtime; proceed without it.
    pass

# add your model's MetaData object here
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.models import metadata as target_metadata


def run_migrations_offline():
    url = os.getenv('DATABASE_URL') or config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    database_url = os.getenv('DATABASE_URL') or config.get_main_option("sqlalchemy.url")
    # Alembic should use a synchronous engine for DDL. If an async driver
    # (e.g. +asyncpg or +aiosqlite) is present in DATABASE_URL, strip it.
    sync_url = database_url
    if "+asyncpg" in sync_url:
        sync_url = sync_url.replace("+asyncpg", "")
    if "+aiosqlite" in sync_url:
        sync_url = sync_url.replace("+aiosqlite", "")

    connectable = engine_from_config(
        {
            'sqlalchemy.url': sync_url
        },
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
