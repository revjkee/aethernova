# agent_mash/legacy/scripts_archive/maintenance/README.md

# Maintenance Scripts (Legacy Archive)

This directory contains archived maintenance utilities kept for backward compatibility and incident response.
They are not part of the primary runtime and must be executed manually by an operator.

Files:
- rebuild_indexes_legacy.py
  Rebuilds or optimizes indexes depending on the database engine behind DATABASE_URL.

## Safety Model

This script is safe by default:
- Runs in dry-run mode unless `--apply` is provided.
- Requires explicit targeting (`--schema`, `--table`) for some engines where full rebuild may be disruptive.
- Logs every action and returns non-zero exit codes on failure.

## Requirements

- Python 3.10+
- SQLAlchemy 2.x

The script expects a database URL in one of the following:
- `--database-url ...`
- `DATABASE_URL` environment variable

## Examples

Dry-run (default):
- python rebuild_indexes_legacy.py

Apply changes:
- python rebuild_indexes_legacy.py --apply

PostgreSQL, rebuild everything in schema:
- python rebuild_indexes_legacy.py --apply --schema public

PostgreSQL, rebuild only specific tables:
- python rebuild_indexes_legacy.py --apply --schema public --table users --table orders

SQLite file:
- DATABASE_URL=sqlite:////absolute/path/to/db.sqlite3 python rebuild_indexes_legacy.py --apply

MySQL/MariaDB, optimize tables:
- python rebuild_indexes_legacy.py --apply --schema your_db --table users --table orders

## Exit Codes

- 0: success
- 2: invalid arguments / configuration
- 3: database connection error
- 4: execution error
