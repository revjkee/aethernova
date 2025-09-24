#!/usr/bin/env bash
set -euo pipefail
cd /workspaces/zero-trust-core

# Обновим venv на случай смены lock-файла
if [ -f "poetry.lock" ]; then
  poetry install --sync --with dev,test,audit,docs -n || true
fi

# Печать сведений об окружении
python --version
poetry --version
ruff --version || true
mypy --version || true

echo "[post_start] environment ready."
