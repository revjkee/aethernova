#!/usr/bin/env bash
set -euo pipefail

cd /workspaces/zero-trust-core

# Poetry уже установлен feature'ом, но страхуемся.
if ! command -v poetry >/dev/null 2>&1; then
  curl -sSL https://install.python-poetry.org | python3 - --version 1.8.3
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/vscode/.bashrc
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/vscode/.zshrc
fi

# Локальные git-настройки
git config --global --add safe.directory /workspaces/zero-trust-core
git config --global pull.rebase false

# Установка зависимостей проекта (включая группы разработки/тестов/аудита/доков)
poetry install --with dev,test,audit,docs --no-root -n

# Преднастройка pre-commit, ruff, mypy
if [ -f ".pre-commit-config.yaml" ]; then
  pre-commit install --install-hooks || true
fi

# Кэш mypy для ускорения
mkdir -p .mypy_cache .ruff_cache

echo "[post_create] done."
