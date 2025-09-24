# datafabric-core — промышленный Makefile
# Требования (опционально, автоматически используются, если доступны в venv):
#   python>=3.10, pip, venv, pytest, coverage, ruff, black, mypy, bandit, pip-audit, build, twine, mkdocs
# Кросс‑платформенная поддержка: Linux/macOS/Windows (PowerShell/WSL) через универсальные пути .venv

# ----------------------------
# ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ
# ----------------------------
SHELL := /bin/sh

PY ?= python3
PIP ?= $(PY) -m pip

# Каталог виртуального окружения
VENV_DIR := .venv
# Активированный интерпретатор внутри venv (кросс‑платформенно)
PY_VENV := $(VENV_DIR)/bin/python
PIP_VENV := $(VENV_DIR)/bin/pip

# Windows (Git Bash/PowerShell) поддержка путей:
ifeq ($(OS),Windows_NT)
	PY_VENV := $(VENV_DIR)/Scripts/python.exe
	PIP_VENV := $(VENV_DIR)/Scripts/pip.exe
endif

# Основные директории проекта
SRC_DIR ?= src
PKG_NAME ?= datafabric_core
TESTS_DIR ?= tests

# Параметры по умолчанию
COV_THRESHOLD ?= 85
DOCKER_IMAGE ?= datafabric-core:dev
DOCKERFILE ?= Dockerfile
PYPI_REPO ?= pypi
VERSION ?= $(shell $(PY_VENV) -c "import importlib.metadata,sys; \
  print(importlib.metadata.version('$(PKG_NAME)'))" 2>/dev/null || echo "0.0.0-dev")

# ----------------------------
# УТИЛИТЫ
# ----------------------------
.DEFAULT_GOAL := help
.PHONY: help venv sync install dev tools fmt fmt-check lint type test cov \
        build dist wheel sdist clean distclean docker-build docker-test \
        sec audit docs docs-serve release tag verify env print-vars

## help: Показать список целей и описание
help:
	@awk 'BEGIN {FS":.*##"; printf "\n\033[1mДоступные цели:\033[0m\n"} \
	/^[a-zA-Z0-9_\-]+:.*##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ----------------------------
# ОКРУЖЕНИЕ И ЗАВИСИМОСТИ
# ----------------------------

## venv: Создать локальное виртуальное окружение .venv (если нет)
venv:
	@test -d $(VENV_DIR) || $(PY) -m venv $(VENV_DIR)
	@$(PIP_VENV) -q install --upgrade pip wheel

## tools: Установить/обновить базовые инструменты разработчика
tools: venv
	@$(PIP_VENV) -q install --upgrade \
		build twine pytest pytest-cov coverage ruff black mypy bandit pip-audit

## install: Установить проект и runtime-зависимости (PEP 517/518)
install: venv
	@if [ -f "pyproject.toml" ]; then \
		echo "-> Installing from pyproject.toml"; \
		$(PIP_VENV) -q install -e . ; \
	elif [ -f "requirements.txt" ]; then \
		echo "-> Installing from requirements.txt"; \
		$(PIP_VENV) -q install -r requirements.txt ; \
	else \
		echo "No pyproject.toml or requirements.txt found."; \
	fi

## dev: Установить dev‑зависимости (если определены extras)
dev: install tools
	@if $(PIP_VENV) show $(PKG_NAME) >/dev/null 2>&1; then \
		echo "-> Ensuring dev extras"; \
		$(PIP_VENV) -q install -e .[dev] 2>/dev/null || true; \
	fi

## sync: Полная синхронизация окружения (venv+install+tools)
sync: venv install tools

## env: Показать версии инструментов в окружении
env: venv
	@echo "Python:       $$($(PY_VENV) --version)"
	@echo "Pip:          $$($(PIP_VENV) --version)"
	@echo "Pytest:       $$($(PY_VENV) -m pytest --version | head -1)"
	@echo "Black:        $$($(PY_VENV) -m black --version)"
	@echo "Ruff:         $$($(PY_VENV) -m ruff --version)"
	@echo "Mypy:         $$($(PY_VENV) -m mypy --version)"
	@echo "Bandit:       $$($(PY_VENV) -m bandit --version || true)"
	@echo "pip-audit:    $$($(PY_VENV) -m pip_audit --version || true)"

# ----------------------------
# КАЧЕСТВО КОДА
# ----------------------------

## fmt: Автоформатирование (Black + Ruff)
fmt: venv
	@$(PY_VENV) -m black $(SRC_DIR) $(TESTS_DIR) || true
	@$(PY_VENV) -m ruff format $(SRC_DIR) $(TESTS_DIR) || true
	@$(PY_VENV) -m ruff check --fix $(SRC_DIR) $(TESTS_DIR) || true

## fmt-check: Проверить форматирование без изменений
fmt-check: venv
	@$(PY_VENV) -m black --check $(SRC_DIR) $(TESTS_DIR)
	@$(PY_VENV) -m ruff format --check $(SRC_DIR) $(TESTS_DIR)
	@$(PY_VENV) -m ruff check $(SRC_DIR) $(TESTS_DIR)

## lint: Статический анализ (Ruff)
lint: venv
	@$(PY_VENV) -m ruff check $(SRC_DIR) $(TESTS_DIR)

## type: Проверка типов (Mypy)
type: venv
	@$(PY_VENV) -m mypy $(SRC_DIR)

# ----------------------------
# ТЕСТЫ И ПОКРЫТИЕ
# ----------------------------

## test: Запуск тестов (pytest)
test: venv
	@$(PY_VENV) -m pytest -q

## cov: Тесты с покрытием и порогом ($(COV_THRESHOLD)%)
cov: venv
	@$(PY_VENV) -m pytest --cov=$(PKG_NAME) --cov-report=term-missing:skip-covered \
		--cov-report=xml --cov-fail-under=$(COV_THRESHOLD)

# ----------------------------
# СБОРКА И ДИСТРИБУЦИЯ
# ----------------------------

## build: Сборка sdist+wheel (PEP 517)
build: venv
	@$(PY_VENV) -m build

## wheel: Сборка только wheel
wheel: venv
	@$(PY_VENV) -m build --wheel

## sdist: Сборка только sdist
sdist: venv
	@$(PY_VENV) -m build --sdist

# ----------------------------
# БЕЗОПАСНОСТЬ
# ----------------------------

## sec: Быстрая проверка безопасности (Bandit) по src
sec: venv
	@$(PY_VENV) -m bandit -q -r $(SRC_DIR) -x $(TESTS_DIR) || true

## audit: Аудит зависимостей (pip-audit)
audit: venv
	@$(PY_VENV) -m pip_audit || true

# ----------------------------
# ДОКУМЕНТАЦИЯ (опционально, если присутствует mkdocs.yml)
# ----------------------------

## docs: Сборка документации (mkdocs build)
docs: venv
	@if [ -f "mkdocs.yml" ]; then \
		$(PY_VENV) -m pip -q install mkdocs mkdocs-material; \
		$(PY_VENV) -m mkdocs build --clean; \
	else \
		echo "mkdocs.yml not found; skip docs"; \
	fi

## docs-serve: Локальный сервер документации
docs-serve: venv
	@if [ -f "mkdocs.yml" ]; then \
		$(PY_VENV) -m pip -q install mkdocs mkdocs-material; \
		$(PY_VENV) -m mkdocs serve -a 0.0.0.0:8000; \
	else \
		echo "mkdocs.yml not found; skip docs-serve"; \
	fi

# ----------------------------
# DOCKER
# ----------------------------

## docker-build: Сборка Docker‑образа ($(DOCKER_IMAGE))
docker-build:
	@docker build -t $(DOCKER_IMAGE) -f $(DOCKERFILE) .

## docker-test: Тесты внутри контейнера
docker-test:
	@docker run --rm -t $(DOCKER_IMAGE) /bin/sh -lc "pytest -q || pytest -q -x"

# ----------------------------
# РЕЛИЗ И ТЕГИ (ручной контроль)
# ----------------------------

## tag: Создать аннотированный git‑тег v$(VERSION)
tag:
	@git diff --quiet || (echo "Working tree not clean"; exit 1)
	@git tag -a v$(VERSION) -m "datafabric-core v$(VERSION)"
	@echo "Tagged v$(VERSION)"

## release: Публикация на PyPI (требуется настроенный .pypirc)
release: build
	@$(PY_VENV) -m twine upload --repository $(PYPI_REPO) dist/*

## verify: Комплексная проверка (fmt-check, lint, type, cov)
verify: fmt-check lint type cov

# ----------------------------
# ОЧИСТКА
# ----------------------------

## clean: Удалить временные файлы и кэш
clean:
	@find . -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf .mypy_cache .pytest_cache .ruff_cache coverage.xml htmlcov || true

## distclean: Полная очистка (включая .venv и dist)
distclean: clean
	@rm -rf $(VENV_DIR) build dist *.egg-info || true

# ----------------------------
# ОТЛАДОЧНЫЕ
# ----------------------------

## print-vars: Печать ключевых переменных окружения Makefile
print-vars:
	@echo "PY=$(PY)"
	@echo "PIP=$(PIP)"
	@echo "VENV_DIR=$(VENV_DIR)"
	@echo "PY_VENV=$(PY_VENV)"
	@echo "SRC_DIR=$(SRC_DIR)"
	@echo "PKG_NAME=$(PKG_NAME)"
	@echo "TESTS_DIR=$(TESTS_DIR)"
	@echo "VERSION=$(VERSION)"
	@echo "DOCKER_IMAGE=$(DOCKER_IMAGE)"
