# Строгий Makefile для automation-core
# - Строгий Bash с pipefail; однопроцессная оболочка для каждой цели (.ONESHELL)
# - Явные .PHONY цели
# - Автодетект Poetry; без Poetry используются python3/pip
# Документация: GNU Make (.PHONY/.ONESHELL), Bash (-o pipefail), Poetry CLI. 
# См. ссылки в сопроводительном ответе.

SHELL := /usr/bin/env bash
.SHELLFLAGS := -Eeuo pipefail -c
.ONESHELL:

# Предупреждать об использовании неинициализированных переменных Make
MAKEFLAGS += --warn-undefined-variables

.DEFAULT_GOAL := help

# -------------------------------------------------------------------
# Переменные окружения (можно переопределять: `make test PYTHON=python3.12`)
# -------------------------------------------------------------------
PYTHON       ?= python3
POETRY       ?= $(shell command -v poetry 2>/dev/null)
RUN          := $(if $(POETRY),poetry run,)
PIP          := $(if $(POETRY),poetry run pip,$(PYTHON) -m pip)
PROJECT_DIR  := $(shell git rev-parse --show-toplevel 2>/dev/null || pwd)
COV_REPORT   ?= term-missing
COV_HTMLDIR  ?= htmlcov

# Группы инструментов; при необходимости установите их в среду разработки/Poetry
LINTER       ?= ruff
TYPER        ?= mypy
TESTER       ?= pytest
SECCHECK     ?= bandit

# -------------------------------------------------------------------
# Вспомогательная функция печати (цвета опциональны)
# -------------------------------------------------------------------
define log
	@printf "[%s] %s\n" "$(1)" "$(2)"
endef

# -------------------------------------------------------------------
# Цели
# -------------------------------------------------------------------
.PHONY: help
help: ## Показать список целей
	@awk 'BEGIN{FS=":.*##"; printf "\nДоступные цели:\n\n"} /^[a-zA-Z0-9_.-]+:.*##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: install
install: ## Установка зависимостей (Poetry при наличии; иначе pip/requirements*)
	$(call log,INFO,"Установка зависимостей")
ifneq ($(POETRY),)
	poetry install --no-interaction --sync
else
	$(PYTHON) -m pip install -U pip
	@if [ -f requirements.txt ]; then $(PIP) install -r requirements.txt; fi
	@if [ -f requirements-dev.txt ]; then $(PIP) install -r requirements-dev.txt; fi
endif

.PHONY: format
format: ## Автоформатирование (ruff format)
	$(call log,INFO,"Форматирование")
	$(RUN) $(LINTER) format .

.PHONY: lint
lint: ## Линтинг (ruff check)
	$(call log,INFO,"Линтинг")
	$(RUN) $(LINTER) check .

.PHONY: typecheck
typecheck: ## Статическая типизация (mypy)
	$(call log,INFO,"Проверка типов")
	$(RUN) $(TYPER) .

.PHONY: test
test: ## Тесты (pytest, без покрытия)
	$(call log,INFO,"Запуск тестов")
	$(RUN) $(TESTER) -q

.PHONY: coverage
coverage: ## Тесты с покрытием (pytest-cov; отчеты: терминал + HTML)
	$(call log,INFO,"Тесты с покрытием")
	$(RUN) $(TESTER) --maxfail=1 --cov=. --cov-report=$(COV_REPORT) --cov-report=html:$(COV_HTMLDIR)

.PHONY: sec
sec: ## Базовая проверка безопасности (bandit по проекту)
	$(call log,INFO,"Проверка безопасности")
	$(RUN) $(SECCHECK) -r . -x .venv,venv,.git,__pycache__,.mypy_cache,.ruff_cache

.PHONY: check
check: lint typecheck test ## Композитная цель: линтер + типы + тесты

.PHONY: clean
clean: ## Очистка артефактов сборки и кэшей
	$(call log,INFO,"Очистка")
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage $(COV_HTMLDIR)

.PHONY: ci
ci: install check coverage ## CI-профиль: установка, проверки, покрытие
	$(call log,INFO,"CI-профиль завершен")

# -------------------------------------------------------------------
# Примеры дополнительных целей (раскомментируйте при необходимости)
# -------------------------------------------------------------------
#.PHONY: tools
#tools: ## Установка базовых dev-инструментов (вне Poetry)
#	$(PIP) install -U ruff mypy pytest pytest-cov bandit
#
#.PHONY: sbom
#sbom: ## Генерация SBOM (если установлен cyclonedx-bom в среде)
#	$(call log,INFO,"Генерация SBOM (CycloneDX)")
#	@if command -v cyclonedx-bom >/dev/null 2>&1; then \
#		cyclonedx-bom -o sbom.json -e ; \
#	else \
#		echo "cyclonedx-bom не найден"; exit 1; \
#	fi
