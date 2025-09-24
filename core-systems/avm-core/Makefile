# Makefile — промышленная сборка для avm-core
# Требования: Python >= 3.11, make, bash, git
# Основные цели:
#   make bootstrap    — создать .venv и установить зависимости проекта
#   make lint         — ruff lint + форматирование проверки
#   make typecheck    — mypy
#   make test         — pytest с покрытием
#   make check        — полный прогон качества (lint+types+tests)
#   make build        — сборка wheel+sdist
#   make release      — релиз: check+build+tag
#   make publish      — публикация в PyPI (использует twine, нужен PYPI_TOKEN)
#   make clean        — очистка артефактов

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

PYTHON ?= python3.11
PIP := $(VENV)/bin/pip
PY := $(VENV)/bin/python
HATCH := $(VENV)/bin/hatch
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
PYTEST := $(VENV)/bin/pytest
TWINE := $(VENV)/bin/twine
COVERAGE := $(VENV)/bin/coverage

VENV ?= .venv
PIP_CACHE_DIR ?= $(HOME)/.cache/pip
SRC_DIR := avm_core

# Версию читаем из pyproject.toml
PROJECT_VERSION := $(shell awk -F'= ' '/^version *=/ {gsub(/"/,""); print $$2; exit}' pyproject.toml 2>/dev/null || echo "0.0.0")

.PHONY: help
help:
	@echo "Available targets:"
	@egrep -h '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(PIP) install -U pip wheel

.PHONY: bootstrap ## Create venv and install dev dependencies
bootstrap: $(VENV)
	$(PIP) install -U pip wheel
	$(PIP) install -e .[dev]

.PHONY: sync ## Reinstall dependencies from scratch (idempotent)
sync:
	rm -rf $(VENV)
	$(MAKE) bootstrap

.PHONY: fmt ## Auto-format with ruff (imports + fixes)
fmt: $(VENV)
	$(RUFF) check --select I --fix .
	$(RUFF) format .

.PHONY: lint ## Lint with ruff (no changes)
lint: $(VENV)
	$(RUFF) check .
	$(RUFF) format --check .

.PHONY: typecheck ## Static type checking with mypy
typecheck: $(VENV)
	$(MYPY) $(SRC_DIR)

.PHONY: test ## Run tests with coverage
test: $(VENV)
	$(PYTEST) -q --cov=$(SRC_DIR) --cov-report=term-missing --cov-report=xml:.coverage.xml

.PHONY: check ## Run all quality gates
check: lint typecheck test

.PHONY: build ## Build sdist and wheel
build: $(VENV)
	$(HATCH) build

.PHONY: clean ## Clean build/test artifacts
clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage .coverage.* .coverage.xml
	rm -rf build dist *.egg-info
	find . -name "__pycache__" -type d -exec rm -rf {} +

.PHONY: dist-clean ## Clean everything including venv
dist-clean: clean
	rm -rf $(VENV)

.PHONY: version ## Show current project version
version:
	@echo "$(PROJECT_VERSION)"

# Примитивный bump (minor/patch); меняет версию в pyproject.toml
.PHONY: bump-patch
bump-patch:
	@old=$$(awk -F'= ' '/^version *=/ {gsub(/"/,""); print $$2; exit}' pyproject.toml); \
	IFS=.; set -- $$old; printf "old=%s\n" "$$old"; \
	new="$$1.$$(( $$2 )).$$(( $$3 + 1 ))"; \
	sed -i.bak "s/^version *= *.*/version = \"$$new\"/" pyproject.toml && rm -f pyproject.toml.bak; \
	echo "new=$$new"

.PHONY: bump-minor
bump-minor:
	@old=$$(awk -F'= ' '/^version *=/ {gsub(/"/,""); print $$2; exit}' pyproject.toml); \
	IFS=.; set -- $$old; printf "old=%s\n" "$$old"; \
	new="$$1.$$(( $$2 + 1 )).0"; \
	sed -i.bak "s/^version *= *.*/version = \"$$new\"/" pyproject.toml && rm -f pyproject.toml.bak; \
	echo "new=$$new"

.PHONY: tag ## Create git tag vX.Y.Z from pyproject version
tag:
	git diff --quiet || { echo "Working tree is dirty"; exit 1; }
	git tag -s "v$(PROJECT_VERSION)" -m "avm-core $(PROJECT_VERSION)"
	git push --tags

.PHONY: release ## Full release pipeline (quality gates + build + tag)
release: check build tag

.PHONY: publish ## Publish to PyPI (requires PYPI_TOKEN)
publish:
	@[ -n "$$PYPI_TOKEN" ] || { echo "PYPI_TOKEN is not set"; exit 1; }
	$(PIP) install -U twine
	$(TWINE) upload --non-interactive -u __token__ -p "$$PYPI_TOKEN" dist/*

.PHONY: docker-build ## Build runtime image (expects Dockerfile)
docker-build:
	docker build --pull --no-cache -t avm-core:$(PROJECT_VERSION) .

.PHONY: docker-run ## Run container (override CMD with ARGS=...)
docker-run:
	docker run --rm -it -e PYTHONUNBUFFERED=1 avm-core:$(PROJECT_VERSION) $(ARGS)
