#!/usr/bin/env bash
set -euo pipefail

# Run migrations (alembic) if available, then start the app
cd /app || exit 1
if command -v alembic >/dev/null 2>&1; then
  echo "Running alembic upgrade head..."
  alembic -c backend/alembic.ini upgrade head || true
fi

exec python -m uvicorn src.main:app --host 0.0.0.0 --port 8000
