# Industrial Makefile for neuroforge-core

SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

.DEFAULT_GOAL := help

# -------------------- Project variables --------------------
PKG_NAME        ?= neuroforge_core
SRC_DIR         ?= src
TESTS_DIR       ?= tests
VENV            ?= .venv
PYTHON_BIN      ?= python3
PYTHON          := $(VENV)/bin/python
PIP             := $(VENV)/bin/pip

# CPU cores (Linux/macOS/other)
CORES := $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Git derived version
GIT_TAG   := $(shell git describe --tags --abbrev=0 2>/dev/null || echo 0.0.0)
GIT_SHA   := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo "-dirty" || echo "")
VERSION   ?= $(GIT_TAG)+$(GIT_SHA)$(GIT_DIRTY)

# Docker
IMAGE         ?= neuroforge-core
REGISTRY      ?=
IMAGE_TAG     ?= $(VERSION)
PLATFORM      ?= linux/amd64
DOCKERFILE    ?= ./Dockerfile
BUILD_CONTEXT ?= .
DOCKER_LABELS ?= \
	--label org.opencontainers.image.title=$(IMAGE) \
	--label org.opencontainers.image.version=$(IMAGE_TAG) \
	--label org.opencontainers.image.revision=$(GIT_SHA) \
	--label org.opencontainers.image.source=$$(git config --get remote.origin.url 2>/dev/null || echo unknown)

# Load .env if present (non-fatal)
ifneq (,$(wildcard .env))
include .env
export $(shell sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' .env)
endif

# Colors (optional, will degrade to plain if tput missing)
COLOR := $(shell command -v tput >/dev/null 2>&1 && tput setaf 6 || echo "")
NC    := $(shell command -v tput >/dev/null 2>&1 && tput sgr0   || echo "")

# -------------------- Helpers --------------------
.PHONY: help
help: ## Показать справку по целям
	@printf "\n$(COLOR)neuroforge-core Make targets$(NC)\n\n"
	@awk 'BEGIN {FS = ":.*##"; printf "  %-28s %s\n", "target", "description"; printf "  %-28s %s\n", "------", "-----------"} \
		/^[a-zA-Z0-9_.-]+:.*##/ { printf "  %-28s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf "\n"

# -------------------- Environment setup --------------------
$(VENV)/.ok:  ## Внутренний маркер готовности venv
	@$(PYTHON_BIN) -m venv $(VENV)
	@$(PIP) install --upgrade pip setuptools wheel
	@touch $@

.PHONY: venv
venv: $(VENV)/.ok ## Создать venv и обновить базовые инструменты

.PHONY: install-dev
install-dev: venv ## Установить dev-зависимости (ruff, black, mypy, pytest, build и т.д.)
	@$(PIP) install -U \
		pytest pytest-cov \
		ruff black isort mypy types-setuptools \
		build twine \
		bandit pip-audit \
		cyclonedx-bom || true
	@# cyclonedx-bom пакет может быть cyclonedx-bom или cyclonedx-python-lib; команда будет проверена в sbom
	@echo "Dev dependencies installed."

# -------------------- Code quality --------------------
.PHONY: fmt
fmt: venv ## Автоформатирование (ruff fix + black + isort)
	@$(VENV)/bin/ruff --version >/dev/null 2>&1 && $(VENV)/bin/ruff check --fix $(SRC_DIR) $(TESTS_DIR) || echo "ruff not installed"
	@$(VENV)/bin/black --version >/dev/null 2>&1 && $(VENV)/bin/black $(SRC_DIR) $(TESTS_DIR) || echo "black not installed"
	@$(VENV)/bin/isort --version >/dev/null 2>&1 && $(VENV)/bin/isort $(SRC_DIR) $(TESTS_DIR) || echo "isort not installed"

.PHONY: fmt-check
fmt-check: venv ## Проверка форматирования без исправления
	@$(VENV)/bin/ruff check $(SRC_DIR) $(TESTS_DIR)
	@$(VENV)/bin:black --check $(SRC_DIR) $(TESTS_DIR)
	@$(VENV)/bin:isort --check-only $(SRC_DIR) $(TESTS_DIR)

.PHONY: lint
lint: venv ## Статический анализ (ruff)
	@$(VENV)/bin/ruff check $(SRC_DIR) $(TESTS_DIR)

.PHONY: typecheck
typecheck: venv ## Проверка типов (mypy)
	@$(VENV)/bin/mypy --python-version 3.10 $(SRC_DIR)

# -------------------- Testing --------------------
PYTEST_ARGS ?= -q
COV_MODULES ?= $(PKG_NAME)

.PHONY: test
test: venv ## Юнит-тесты с покрытием
	@$(VENV)/bin/pytest $(TESTS_DIR) $(PYTEST_ARGS) --cov=$(COV_MODULES) --cov-report=term-missing

.PHONY: test-integration
test-integration: venv ## Интеграционные тесты (маркер integration)
	@$(VENV)/bin/pytest $(TESTS_DIR)/integration -m "not slow" $(PYTEST_ARGS) --cov=$(COV_MODULES) --cov-append

.PHONY: coverage-html
coverage-html: venv ## HTML-отчет покрытия
	@$(VENV)/bin/pytest $(TESTS_DIR) -q --cov=$(COV_MODULES) --cov-report=html
	@echo "Report: file://$(CURDIR)/htmlcov/index.html"

# -------------------- Security --------------------
.PHONY: audit
audit: venv ## Аудит зависимостей (pip-audit)
	@$(VENV)/bin/pip-audit -r requirements.txt 2>/dev/null || $(VENV)/bin/pip-audit || true

.PHONY: bandit
bandit: venv ## Статический анализ безопасности (bandit)
	@$(VENV)/bin/bandit -q -r $(SRC_DIR) || true

.PHONY: sbom
sbom: venv ## Генерация SBOM (CycloneDX или Syft если доступен)
	@mkdir -p sbom
	@{ command -v cyclonedx-py >/dev/null 2>&1 && cyclonedx-py -o sbom/cyclonedx.json -r .; } \
	 || { command -v cyclonedx-bom >/dev/null 2>&1 && cyclonedx-bom -o sbom/cyclonedx.json; } \
	 || { command -v syft >/dev/null 2>&1 && syft packages dir:$(CURDIR) -o cyclonedx-json > sbom/cyclonedx.json; } \
	 || { echo "No SBOM tool found (cyclonedx-py, cyclonedx-bom or syft)"; exit 0; }
	@echo "SBOM written to sbom/cyclonedx.json"

# -------------------- Build & publish --------------------
DIST_DIR ?= dist

.PHONY: build
build: venv ## Сборка wheel+sdist
	@$(PYTHON) -m build
	@ls -lh $(DIST_DIR) || true

.PHONY: publish
publish: ## Публикация в PyPI через twine (использует TWINE_USERNAME/TWINE_PASSWORD или токен)
	@$(VENV)/bin/twine upload dist/*

# -------------------- Docker --------------------
.PHONY: docker-build
docker-build: ## Локальная сборка docker образа
	@docker build -f $(DOCKERFILE) $(BUILD_CONTEXT) \
		--build-arg VERSION=$(IMAGE_TAG) \
		--build-arg VCS_REF=$(GIT_SHA) \
		$(DOCKER_LABELS) \
		-t $(REGISTRY)$(if $(REGISTRY),/,)$(IMAGE):$(IMAGE_TAG)

.PHONY: docker-buildx
docker-buildx: ## Кроссплатформенная сборка (buildx)
	@docker buildx build --platform $(PLATFORM) -f $(DOCKERFILE) $(BUILD_CONTEXT) \
		--build-arg VERSION=$(IMAGE_TAG) \
		--build-arg VCS_REF=$(GIT_SHA) \
		$(DOCKER_LABELS) \
		-t $(REGISTRY)$(if $(REGISTRY),/,)$(IMAGE):$(IMAGE_TAG) --load

.PHONY: docker-push
docker-push: ## Публикация docker образа
	@docker push $(REGISTRY)$(if $(REGISTRY),/,)$(IMAGE):$(IMAGE_TAG)

.PHONY: docker-run
docker-run: ## Запуск контейнера (переменные окружения из .env)
	@docker run --rm -it --env-file .env -p 8000:8000 $(REGISTRY)$(if $(REGISTRY),/,)$(IMAGE):$(IMAGE_TAG)

# -------------------- Aggregates --------------------
.PHONY: ci-check
ci-check: fmt-check lint typecheck test audit bandit ## Полный набор проверок для CI

# -------------------- Cleaning --------------------
.PHONY: clean
clean: ## Очистить кеши/сборки
	@rm -rf $(DIST_DIR) build *.egg-info .pytest_cache .mypy_cache htmlcov sbom || true

.PHONY: clean-pyc
clean-pyc: ## Удалить байткод Python
	@find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.py[co]' -delete 2>/dev/null || true

.PHONY: clean-venv
clean-venv: ## Удалить виртуальное окружение
	@rm -rf $(VENV) || true

# -------------------- Utilities --------------------
.PHONY: print-%  # пример: make print-VERSION
print-%: ## Вывести значение переменной
	@echo $* = $($*)
