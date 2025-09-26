#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export PYTHONPATH="$(pwd)"
echo "Running alembic with config backend/alembic.ini"
alembic -c backend/alembic.ini upgrade head
