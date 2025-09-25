#!/usr/bin/env bash
set -euo pipefail

cd /app || exit 1

# Wait for Postgres to be ready (if DATABASE_URL points to Postgres)
DB_URL=${DATABASE_URL:-}
# If DATABASE_URL is not provided via compose interpolation, try to build it
# from POSTGRES_* env vars that are loaded via env_file. This makes the
# container robust when compose variable substitution didn't occur.
if [[ -z "$DB_URL" && -n "${POSTGRES_USER:-}" ]]; then
  POSTGRES_HOST=${POSTGRES_HOST:-db}
  POSTGRES_PORT=${POSTGRES_PORT:-5432}
  DB_URL="postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}/${POSTGRES_DB}"
  export DATABASE_URL="$DB_URL"
  echo "Constructed DATABASE_URL from POSTGRES_*: $DB_URL"
fi

if [[ -z "$DB_URL" ]]; then
  echo "DATABASE_URL not set and POSTGRES_USER missing; falling back to db:5432 for readiness checks"
  host=db
  port=5432
  check_db=true
else
  check_db=false
fi

if [[ "$DB_URL" != "" && "$DB_URL" == postgresql* ]]; then
  echo "Waiting for Postgres to be ready..."
  # Extract host and port robustly from URL like user:pass@host:port/db
  tail=${DB_URL#*@}
  host_port=${tail%%/*}
  host=${host_port%%:*}
  if [[ "$host_port" == *":"* ]]; then
    port=${host_port#*:}
  else
    port=5432
  fi
  # sanity: default host if empty
  host=${host:-db}
  attempts=0
  max_attempts=120
  until pg_isready -h "$host" -p "$port" >/dev/null 2>&1; do
    attempts=$((attempts+1))
    echo "Postgres not ready yet (attempt $attempts/$max_attempts), sleeping 2s..."
    sleep 2
    if [ "$attempts" -gt "$max_attempts" ]; then
      echo "Postgres did not become ready in time" >&2
      break
    fi
  done
  echo "Postgres readiness check finished (host=$host port=$port)"
fi

if [ "${check_db}" = true ]; then
  echo "Waiting for Postgres to be ready (fallback db:5432)..."
  attempts=0
  max_attempts=120
  until pg_isready -h "db" -p "5432" >/dev/null 2>&1; do
    attempts=$((attempts+1))
    echo "Postgres (db:5432) not ready yet (attempt $attempts/$max_attempts), sleeping 2s..."
    sleep 2
    if [ "$attempts" -gt "$max_attempts" ]; then
      echo "Postgres did not become ready in time" >&2
      break
    fi
  done
fi

# Diagnostic listing to help debug mounted files inside the container
echo "Contents of /app:" 
ls -la /app || true

# Run migrations (use absolute path to config inside container)
ALEMBIC_CONFIG=/app/alembic.ini
if command -v alembic >/dev/null 2>&1; then
  echo "Running alembic upgrade head with config $ALEMBIC_CONFIG..."
  alembic -c "$ALEMBIC_CONFIG" upgrade head || echo "alembic failed, continuing"
fi

# Start production server with Gunicorn + Uvicorn workers
exec gunicorn -k uvicorn.workers.UvicornWorker "src.main:app" -b 0.0.0.0:8000 --workers 2
