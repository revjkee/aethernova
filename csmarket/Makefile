# csmarket/Makefile
# Industrial Makefile for Python (FastAPI + async SQLAlchemy) monorepo core.
# Goals:
# - Single entrypoint for dev, quality, tests, migrations, and containers
# - Cross-platform (Linux/macOS/Windows) behavior with predictable defaults
# - Override-friendly via environment variables
#
# Usage:
#   make help
#   make venv install
#   make run
#   make lint test
#   make docker-up

SHELL := /bin/sh

.DEFAULT_GOAL := help

# Project layout
ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
APP_DIR  ?= $(ROOT_DIR)/app
SCRIPTS_DIR ?= $(ROOT_DIR)/scripts

# Virtual environment
VENV_DIR ?= $(ROOT_DIR)/.venv

# Tools (override if needed)
PYTHON ?= python3
PIP ?= $(VENV_DIR)/bin/pip
PY ?= $(VENV_DIR)/bin/python

# If venv binaries do not exist (Windows), use Scripts/
ifeq ($(wildcard $(VENV_DIR)/bin/python),)
	PIP := $(VENV_DIR)/Scripts/pip.exe
	PY  := $(VENV_DIR)/Scripts/python.exe
endif

# Application defaults
APP_MODULE ?= app.main:app
HOST ?= 0.0.0.0
PORT ?= 8000
LOG_LEVEL ?= info
WORKERS ?= 1

# Database and migrations
ALEMBIC ?= $(PY) -m alembic
ALEMBIC_INI ?= $(ROOT_DIR)/alembic.ini

# Quality tools
RUFF ?= $(PY) -m ruff
MYPY ?= $(PY) -m mypy
PYTEST ?= $(PY) -m pytest

# Containers
DOCKER ?= docker
DOCKER_COMPOSE ?= docker compose
COMPOSE_FILE ?= $(ROOT_DIR)/docker-compose.yml

# Utilities
RM ?= rm -rf
MKDIR_P ?= mkdir -p

# Make behavior
.SILENT:
.ONESHELL:
MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --warn-undefined-variables

.PHONY: help
help:
	printf "%s\n" \
	"csmarket Makefile targets:" \
	"" \
	"Core:" \
	"  make venv              Create virtual environment in .venv" \
	"  make install           Install dependencies (default group)" \
	"  make install-dev       Install dependencies with dev extras (if supported)" \
	"  make sync              Reinstall deps cleanly (pip cache respected)" \
	"" \
	"Run:" \
	"  make run               Run API with uvicorn (no reload)" \
	"  make dev               Run API with reload (development)" \
	"" \
	"Quality:" \
	"  make format            Format code (ruff format if available)" \
	"  make lint              Lint code (ruff)" \
	"  make typecheck         Typecheck (mypy)" \
	"  make test              Run tests (pytest)" \
	"  make ci                Run full CI-like pipeline locally" \
	"" \
	"DB:" \
	"  make db-upgrade        Apply migrations (alembic upgrade head)" \
	"  make db-downgrade      Downgrade one revision (alembic downgrade -1)" \
	"  make db-revision MSG=  Create new migration (autogenerate)" \
	"" \
	"Containers:" \
	"  make docker-build      Build images" \
	"  make docker-up         Start services (docker compose up -d)" \
	"  make docker-down       Stop services" \
	"  make docker-logs       Follow logs" \
	"" \
	"Security:" \
	"  make audit             Dependency audit (pip-audit if installed)" \
	"" \
	"Cleaning:" \
	"  make clean             Remove caches and build artifacts" \
	"  make distclean         Remove venv too" \
	""

# Internal helper: check command exists
define require_cmd
	command -v $(1) >/dev/null 2>&1 || { echo "Missing required command: $(1)"; exit 1; }
endef

# Internal helper: ensure venv exists
.PHONY: _ensure_venv
_ensure_venv:
	if [ ! -d "$(VENV_DIR)" ]; then \
		echo "Virtualenv not found at $(VENV_DIR). Run: make venv"; \
		exit 1; \
	fi
	if [ ! -f "$(PY)" ]; then \
		echo "Python not found in venv. Run: make venv"; \
		exit 1; \
	fi

.PHONY: venv
venv:
	$(call require_cmd,$(PYTHON))
	$(PYTHON) -m venv "$(VENV_DIR)"
	$(PIP) --version >/dev/null 2>&1 || true
	$(PY) -m pip install --upgrade pip setuptools wheel

# Install dependencies
# This Makefile supports both:
# - pyproject.toml (PEP 517/518) workflows
# - requirements*.txt workflows
#
# If you rely on a tool like uv/poetry/pdm, override INSTALL_CMD accordingly.
INSTALL_CMD ?= $(PIP) install -e .

# Optional dev install command; override for your packaging tool if needed.
INSTALL_DEV_CMD ?= $(PIP) install -e ".[dev]"

.PHONY: install
install: _ensure_venv
	$(call require_cmd,$(PIP))
	$(INSTALL_CMD)

.PHONY: install-dev
install-dev: _ensure_venv
	$(call require_cmd,$(PIP))
	$(INSTALL_DEV_CMD)

.PHONY: sync
sync: _ensure_venv
	$(call require_cmd,$(PIP))
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) uninstall -y csmarket >/dev/null 2>&1 || true
	$(INSTALL_CMD)

# Run targets
.PHONY: run
run: _ensure_venv
	$(PY) -m uvicorn "$(APP_MODULE)" --host "$(HOST)" --port "$(PORT)" --log-level "$(LOG_LEVEL)" --workers "$(WORKERS)"

.PHONY: dev
dev: _ensure_venv
	$(PY) -m uvicorn "$(APP_MODULE)" --host "$(HOST)" --port "$(PORT)" --log-level "$(LOG_LEVEL)" --reload

# Quality targets
.PHONY: format
format: _ensure_venv
	# Prefer ruff format when available
	if $(PY) -c "import ruff" >/dev/null 2>&1; then \
		$(RUFF) format "$(ROOT_DIR)"; \
	else \
		echo "ruff is not installed in venv. Install dev deps: make install-dev"; \
		exit 1; \
	fi

.PHONY: lint
lint: _ensure_venv
	if $(PY) -c "import ruff" >/dev/null 2>&1; then \
		$(RUFF) check "$(ROOT_DIR)"; \
	else \
		echo "ruff is not installed in venv. Install dev deps: make install-dev"; \
		exit 1; \
	fi

.PHONY: typecheck
typecheck: _ensure_venv
	if $(PY) -c "import mypy" >/dev/null 2>&1; then \
		$(MYPY) "$(ROOT_DIR)"; \
	else \
		echo "mypy is not installed in venv. Install dev deps: make install-dev"; \
		exit 1; \
	fi

.PHONY: test
test: _ensure_venv
	if $(PY) -c "import pytest" >/dev/null 2>&1; then \
		$(PYTEST) -q; \
	else \
		echo "pytest is not installed in venv. Install dev deps: make install-dev"; \
		exit 1; \
	fi

.PHONY: ci
ci: lint typecheck test

# Database / Alembic targets
.PHONY: db-upgrade
db-upgrade: _ensure_venv
	if [ ! -f "$(ALEMBIC_INI)" ]; then \
		echo "Missing alembic.ini at $(ALEMBIC_INI)"; \
		exit 1; \
	fi
	$(ALEMBIC) -c "$(ALEMBIC_INI)" upgrade head

.PHONY: db-downgrade
db-downgrade: _ensure_venv
	if [ ! -f "$(ALEMBIC_INI)" ]; then \
		echo "Missing alembic.ini at $(ALEMBIC_INI)"; \
		exit 1; \
	fi
	$(ALEMBIC) -c "$(ALEMBIC_INI)" downgrade -1

.PHONY: db-revision
db-revision: _ensure_venv
	if [ ! -f "$(ALEMBIC_INI)" ]; then \
		echo "Missing alembic.ini at $(ALEMBIC_INI)"; \
		exit 1; \
	fi
	if [ -z "$(MSG)" ]; then \
		echo "MSG is required. Example: make db-revision MSG='add users table'"; \
		exit 1; \
	fi
	$(ALEMBIC) -c "$(ALEMBIC_INI)" revision --autogenerate -m "$(MSG)"

# Containers
.PHONY: docker-build
docker-build:
	$(call require_cmd,$(DOCKER))
	if [ ! -f "$(COMPOSE_FILE)" ]; then \
		echo "Missing docker-compose.yml at $(COMPOSE_FILE)"; \
		exit 1; \
	fi
	$(DOCKER_COMPOSE) -f "$(COMPOSE_FILE)" build

.PHONY: docker-up
docker-up:
	$(call require_cmd,$(DOCKER))
	if [ ! -f "$(COMPOSE_FILE)" ]; then \
		echo "Missing docker-compose.yml at $(COMPOSE_FILE)"; \
		exit 1; \
	fi
	$(DOCKER_COMPOSE) -f "$(COMPOSE_FILE)" up -d

.PHONY: docker-down
docker-down:
	$(call require_cmd,$(DOCKER))
	if [ ! -f "$(COMPOSE_FILE)" ]; then \
		echo "Missing docker-compose.yml at $(COMPOSE_FILE)"; \
		exit 1; \
	fi
	$(DOCKER_COMPOSE) -f "$(COMPOSE_FILE)" down

.PHONY: docker-logs
docker-logs:
	$(call require_cmd,$(DOCKER))
	if [ ! -f "$(COMPOSE_FILE)" ]; then \
		echo "Missing docker-compose.yml at $(COMPOSE_FILE)"; \
		exit 1; \
	fi
	$(DOCKER_COMPOSE) -f "$(COMPOSE_FILE)" logs -f --tail=200

# Security: dependency audit
.PHONY: audit
audit: _ensure_venv
	# Uses pip-audit if installed
	if $(PY) -c "import pip_audit" >/dev/null 2>&1; then \
		$(PY) -m pip_audit; \
	else \
		echo "pip-audit is not installed in venv. Install it: $(PIP) install pip-audit"; \
		exit 1; \
	fi

# Cleaning
.PHONY: clean
clean:
	$(RM) "$(ROOT_DIR)/.pytest_cache"
	$(RM) "$(ROOT_DIR)/.ruff_cache"
	$(RM) "$(ROOT_DIR)/.mypy_cache"
	$(RM) "$(ROOT_DIR)/**/__pycache__"
	$(RM) "$(ROOT_DIR)/**/*.pyc"
	$(RM) "$(ROOT_DIR)/**/*.pyo"
	$(RM) "$(ROOT_DIR)/build"
	$(RM) "$(ROOT_DIR)/dist"
	$(RM) "$(ROOT_DIR)/*.egg-info"

.PHONY: distclean
distclean: clean
	$(RM) "$(VENV_DIR)"
