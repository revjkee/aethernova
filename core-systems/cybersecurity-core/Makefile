# --------- Makefile (cybersecurity-core) ----------
# Универсальный DevSecOps-пайплайн: uv → poetry → python -m
# Цели: help, setup, install, lock, fmt, fmt-check, lint, typecheck,
#       test, coverage, coverage-html, security, sbom, docker-build,
#       docker-scan, clean, distclean, version-sync, tag, release, ci

SHELL := /bin/bash

# --------- Настраиваемые параметры ----------
PYTHON          ?= python3
PACKAGE_NAME    ?= cybersecurity_core
SRC             ?= src
TESTS           ?= tests
COV_FAIL_UNDER  ?= 85
DOCKER_IMAGE    ?= cybersecurity-core:local
DOCKER_CONTEXT  ?= .
VERSION_FILE    ?= VERSION
PYPROJECT_FILE  ?= pyproject.toml

# Автовыбор раннера: uv → poetry → python -m
RUNNER := $(shell if command -v uv >/dev/null 2>&1; then echo "uv run"; \
                 elif command -v poetry >/dev/null 2>&1; then echo "poetry run"; \
                 else echo "$(PYTHON) -m"; fi)

PIP_RUN := $(shell if command -v uv >/dev/null 2>&1; then echo "uv pip"; \
                elif command -v poetry >/dev/null 2>&1; then echo "poetry run pip"; \
                else echo "$(PYTHON) -m pip"; fi)

# Опции Python для строгого режима в одноразовых скриптах
PYSTRICT := -X dev -W error

# --------- Вспомогательные макросы ----------
define _hr
	@printf "\n\033[1;36m%s\033[0m\n" "------------------------------------------------------------"
endef

# --------- Цели по умолчанию ----------
.DEFAULT_GOAL := help

.PHONY: help
help: ## Показать список целей
	@echo "Make targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# --------- Инициализация окружения ----------
.PHONY: setup
setup: ## Установка pre-commit hooks (если установлен pre-commit)
	$(_hr)
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install --install-hooks; \
	else \
		echo "pre-commit не найден, пропускаю"; \
	fi

.PHONY: install
install: ## Установка зависимостей (uv/poetry/pip)
	$(_hr)
	@if command -v uv >/dev/null 2>&1; then \
		uv sync; \
	elif command -v poetry >/dev/null 2>&1; then \
		poetry install --no-interaction --no-ansi; \
	else \
		$(PIP_RUN) install --upgrade pip; \
		$(PIP_RUN) install -r requirements.txt || true; \
	fi

.PHONY: lock
lock: ## Обновить/заблокировать зависимости (uv/poetry)
	$(_hr)
	@if command -v uv >/dev/null 2>&1; then \
		uv lock; \
	elif command -v poetry >/dev/null 2>&1; then \
		poetry lock --no-interaction --no-ansi; \
	else \
		echo "Нет менеджера зависимостей uv/poetry: пропускаю lock"; \
	fi

# --------- Качество кода ----------
.PHONY: fmt
fmt: ## Форматирование (ruff + black, если есть)
	$(_hr)
	@($(RUNNER) ruff format $(SRC) $(TESTS) || echo "ruff format недоступен")
	@($(RUNNER) black $(SRC) $(TESTS) 2>/dev/null || echo "black недоступен")
	@($(RUNNER) ruff check --fix $(SRC) $(TESTS) || echo "ruff check недоступен")

.PHONY: fmt-check
fmt-check: ## Проверка форматирования (без изменений)
	$(_hr)
	@($(RUNNER) ruff format --check $(SRC) $(TESTS) || (echo "ruff format check провалился"; exit 1))
	@($(RUNNER) black --check $(SRC) $(TESTS) 2>/dev/null || echo "black недоступен, пропускаю")

.PHONY: lint
lint: ## Линтинг (ruff)
	$(_hr)
	@($(RUNNER) ruff check $(SRC) $(TESTS))

.PHONY: typecheck
typecheck: ## Статическая типизация (mypy)
	$(_hr)
	@($(RUNNER) mypy $(SRC) || (echo "mypy проверка провалена"; exit 1))

# --------- Тесты и покрытие ----------
.PHONY: test
test: ## Тесты (pytest)
	$(_hr)
	@($(RUNNER) pytest -q $(TESTS))

.PHONY: coverage
coverage: ## Покрытие (coverage + threshold)
	$(_hr)
	@($(RUNNER) coverage run -m pytest $(TESTS))
	@($(RUNNER) coverage report --fail-under=$(COV_FAIL_UNDER))

.PHONY: coverage-html
coverage-html: ## HTML-отчет покрытия (./htmlcov/index.html)
	$(_hr)
	@($(RUNNER) coverage html)
	@echo "HTML-отчет: htmlcov/index.html"

# --------- Безопасность ----------
.PHONY: security
security: ## Security-аудит: bandit, pip-audit, safety (если установлены)
	$(_hr)
	@echo "Bandit:"
	@command -v bandit >/dev/null 2>&1 && $(RUNNER) bandit -q -r $(SRC) -ll -ii || echo "bandit не установлен, пропускаю"
	@echo "pip-audit:"
	@command -v pip-audit >/dev/null 2>&1 && $(RUNNER) pip_audit || $(RUNNER) pip-audit || echo "pip-audit не установлен, пропускаю"
	@echo "Safety:"
	@command -v safety >/dev/null 2>&1 && $(RUNNER) safety check -q || echo "safety не установлен, пропускаю"

.PHONY: sbom
sbom: ## Генерация SBOM (CycloneDX / Syft) в ./sbom/
	$(_hr)
	@mkdir -p sbom
	@if command -v cyclonedx-py >/dev/null 2>&1; then \
		$(RUNNER) cyclonedx-py --format json --output sbom/cyclonedx-python.json; \
	elif command -v cyclonedx-bom >/dev/null 2>&1; then \
		$(RUNNER) cyclonedx-bom -o sbom/cyclonedx-python.json; \
	else \
		echo "CycloneDX для Python не найден, пропускаю"; \
	fi
	@if command -v syft >/dev/null 2>&1; then \
		syft dir:$(DOCKER_CONTEXT) -o cyclonedx-json=sbom/syft-repo.json; \
	else \
		echo "Syft не установлен, пропускаю анализ репозитория"; \
	fi

# --------- Docker ----------
.PHONY: docker-build
docker-build: ## Сборка Docker-образа (DOCKER_IMAGE)
	$(_hr)
	@docker build --pull --rm -t $(DOCKER_IMAGE) $(DOCKER_CONTEXT)

.PHONY: docker-scan
docker-scan: ## Скан контейнерного образа (trivy, если установлен)
	$(_hr)
	@if command -v trivy >/dev/null 2>&1; then \
		trivy image --exit-code 0 --severity HIGH,CRITICAL $(DOCKER_IMAGE); \
	else \
		echo "trivy не установлен, пропускаю"; \
	fi

# --------- Релизы и версии ----------
.PHONY: version-sync
version-sync: ## Синхронизация версии из VERSION в pyproject.toml
	$(_hr)
	@if [ -f "$(VERSION_FILE)" ] && [ -f "$(PYPROJECT_FILE)" ]; then \
		V="$$(tr -d ' \t\n\r' < $(VERSION_FILE))"; \
		echo "Синхронизирую версию $$V в $(PYPROJECT_FILE)"; \
		grep -qE '^version\s*=\s*".*"' $(PYPROJECT_FILE) && \
			sed -E -i.bak 's/^version\s*=\s*".*"/version = "'$$V'"/' $(PYPROJECT_FILE) || \
			echo 'version = "'$$V'"' >> $(PYPROJECT_FILE); \
	else \
		echo "VERSION или pyproject.toml не найдены — пропускаю"; \
	fi

.PHONY: tag
tag: ## Создать git-тег из VERSION
	$(_hr)
	@if [ -f "$(VERSION_FILE)" ]; then \
		V="$$(tr -d ' \t\n\r' < $(VERSION_FILE))"; \
		git tag -a "v$$V" -m "Release v$$V"; \
		echo "Создан тег v$$V"; \
	else \
		echo "VERSION не найден — пропускаю"; \
	fi

.PHONY: release
release: version-sync tag ## Локальный релиз: sync версии + тег
	@echo "Релизная процедура завершена (локально)."

# --------- Композитные цели ----------
.PHONY: ci
ci: fmt-check lint typecheck test coverage security ## Полный CI-профиль локально

# --------- Уборка ----------
.PHONY: clean
clean: ## Очистить временные файлы
	$(_hr)
	@rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage \
		dist build sbom *.egg-info __pycache__ */__pycache__

.PHONY: distclean
distclean: clean ## Полная очистка (включая виртуальные окружения uv/poetry)
	$(_hr)
	@rm -rf .venv .uv
