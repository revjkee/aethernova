#!/usr/bin/env bash
set -euo pipefail

cd /app || exit 1

# Wait for Postgres to be ready (if DATABASE_URL points to Postgres)
DB_URL=${DATABASE_URL:-}
if [[ -n "$DB_URL" && "$DB_URL" == postgresql* ]]; then
  echo "Waiting for Postgres to be ready..."
  # parse user:pass@host:port/db from DATABASE_URL
  # fall back to service name 'db' if not present
  host=$(echo "$DB_URL" | sed -E 's#.*@([^:/]+).*#\1#' || echo db)
  port=$(echo "$DB_URL" | sed -E 's#.*:([0-9]+)/.*#\1#' || echo 5432)
  attempts=0
  until pg_isready -h "$host" -p "$port" >/dev/null 2>&1; do
    attempts=$((attempts+1))
    echo "Postgres not ready yet (attempt $attempts), sleeping 2s..."
    sleep 2
    if [ "$attempts" -gt 30 ]; then
      echo "Postgres did not become ready in time" >&2
      break
    fi
  done
fi

# Run migrations
if command -v alembic >/dev/null 2>&1; then
  echo "Running alembic upgrade head..."
  alembic -c backend/alembic.ini upgrade head || echo "alembic failed, continuing"
fi

# Start production server with Gunicorn + Uvicorn workers
exec gunicorn -k uvicorn.workers.UvicornWorker "src.main:app" -b 0.0.0.0:8000 --workers 2
