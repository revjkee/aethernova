SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PROJECT_NAME ?= reva-studio
PYTHON ?= python
UV ?= uv
COMPOSE ?= docker compose

APP_MODULE ?= src.main:app
BOT_MODULE ?= src.bot.main
HOST ?= 0.0.0.0
PORT ?= 8000

ENV_FILE ?= .env
ENV_TEST_FILE ?= .env.test

ALEMBIC ?= alembic
PYTEST ?= pytest
RUFF ?= ruff
MYPY ?= mypy

DC_FILE_BASE ?= docker-compose.yml
DC_FILE_DEV ?= docker-compose.dev.yml
DC_FILE_PROD ?= docker-compose.prod.yml
DC_FILE_OBS ?= docker-compose.observability.yml

UNIT_TEST_PATH ?= tests/unit
INTEGRATION_TEST_PATH ?= tests/integration
E2E_TEST_PATH ?= tests/e2e
SRC_PATH ?= src
TESTS_PATH ?= tests

COV_TARGET ?= src
REV_MSG ?= auto_revision

define PRINT_HEADER
	@printf "\n[%s] %s\n" "$(PROJECT_NAME)" "$(1)"
endef

.PHONY: help
help: ## Показать список доступных команд
	@awk 'BEGIN {FS = ":.*## "}; /^[a-zA-Z0-9_.-]+:.*## / {printf "%-28s %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

.PHONY: doctor
doctor: ## Проверить наличие базовых инструментов
	$(call PRINT_HEADER,checking toolchain)
	@command -v $(PYTHON) >/dev/null 2>&1 || { echo "$(PYTHON) not found"; exit 1; }
	@command -v $(UV) >/dev/null 2>&1 || { echo "$(UV) not found"; exit 1; }
	@command -v $(COMPOSE) >/dev/null 2>&1 || { echo "docker compose not found"; exit 1; }
	@echo "toolchain OK"

.PHONY: env-check
env-check: ## Проверить наличие .env файлов
	$(call PRINT_HEADER,checking env files)
	@test -f $(ENV_FILE) || { echo "$(ENV_FILE) not found"; exit 1; }
	@echo "$(ENV_FILE) OK"
	@if [ -f "$(ENV_TEST_FILE)" ]; then echo "$(ENV_TEST_FILE) OK"; else echo "$(ENV_TEST_FILE) not found, skipping"; fi

.PHONY: install
install: ## Установить зависимости из lock-файла
	$(call PRINT_HEADER,installing dependencies)
	$(UV) sync --frozen

.PHONY: install-dev
install-dev: ## Установить зависимости для разработки
	$(call PRINT_HEADER,installing dev dependencies)
	$(UV) sync --all-extras

.PHONY: lock
lock: ## Обновить lock-файл зависимостей
	$(call PRINT_HEADER,locking dependencies)
	$(UV) lock

.PHONY: sync
sync: ## Синхронизировать окружение по lock-файлу
	$(call PRINT_HEADER,syncing environment)
	$(UV) sync

.PHONY: update
update: ## Обновить зависимости и lock-файл
	$(call PRINT_HEADER,updating dependencies)
	$(UV) lock --upgrade
	$(UV) sync

.PHONY: format
format: ## Форматирование кода
	$(call PRINT_HEADER,formatting code)
	$(UV) run $(RUFF) format $(SRC_PATH) $(TESTS_PATH)
	$(UV) run $(RUFF) check $(SRC_PATH) $(TESTS_PATH) --fix

.PHONY: lint
lint: ## Проверка линтером
	$(call PRINT_HEADER,linting code)
	$(UV) run $(RUFF) check $(SRC_PATH) $(TESTS_PATH)

.PHONY: typecheck
typecheck: ## Проверка типов
	$(call PRINT_HEADER,type checking)
	$(UV) run $(MYPY) $(SRC_PATH)

.PHONY: check
check: lint typecheck ## Полная статическая проверка

.PHONY: test
test: ## Запустить все тесты
	$(call PRINT_HEADER,running tests)
	$(UV) run $(PYTEST) -q

.PHONY: test-unit
test-unit: ## Запустить unit-тесты
	$(call PRINT_HEADER,running unit tests)
	$(UV) run $(PYTEST) -q $(UNIT_TEST_PATH)

.PHONY: test-integration
test-integration: ## Запустить integration-тесты
	$(call PRINT_HEADER,running integration tests)
	$(UV) run $(PYTEST) -q $(INTEGRATION_TEST_PATH)

.PHONY: test-e2e
test-e2e: ## Запустить e2e-тесты
	$(call PRINT_HEADER,running e2e tests)
	$(UV) run $(PYTEST) -q $(E2E_TEST_PATH)

.PHONY: test-cov
test-cov: ## Запустить тесты с покрытием
	$(call PRINT_HEADER,running tests with coverage)
	$(UV) run $(PYTEST) --cov=$(COV_TARGET) --cov-report=term-missing --cov-report=html

.PHONY: test-watch
test-watch: ## Запустить тесты в режиме watch
	$(call PRINT_HEADER,running tests in watch mode)
	$(UV) run $(PYTEST) -f

.PHONY: ci
ci: env-check check test ## Локальный CI-прогон

.PHONY: run-api
run-api: ## Запустить FastAPI через uvicorn
	$(call PRINT_HEADER,starting api)
	$(UV) run uvicorn $(APP_MODULE) --host $(HOST) --port $(PORT) --reload

.PHONY: run-bot
run-bot: ## Запустить Telegram-бота
	$(call PRINT_HEADER,starting bot)
	$(UV) run $(PYTHON) -m $(BOT_MODULE)

.PHONY: shell
shell: ## Открыть shell внутри uv-окружения
	$(call PRINT_HEADER,starting project shell)
	$(UV) run bash

.PHONY: python
python: ## Открыть Python внутри uv-окружения
	$(call PRINT_HEADER,starting python)
	$(UV) run $(PYTHON)

.PHONY: routes
routes: ## Показать роуты FastAPI
	$(call PRINT_HEADER,listing api routes)
	$(UV) run $(PYTHON) - <<'PY'
from importlib import import_module
module_name, app_name = "$(APP_MODULE)".split(":")
app = getattr(import_module(module_name), app_name)
for route in app.routes:
    methods = ",".join(sorted(getattr(route, "methods", []) or []))
    print(f"{methods:20} {route.path}")
PY

.PHONY: db-upgrade
db-upgrade: ## Применить все миграции Alembic
	$(call PRINT_HEADER,applying migrations)
	$(UV) run $(ALEMBIC) upgrade head

.PHONY: db-downgrade
db-downgrade: ## Откатить миграции на 1 шаг вниз
	$(call PRINT_HEADER,downgrading migration)
	$(UV) run $(ALEMBIC) downgrade -1

.PHONY: db-history
db-history: ## Показать историю миграций
	$(call PRINT_HEADER,showing migration history)
	$(UV) run $(ALEMBIC) history

.PHONY: db-current
db-current: ## Показать текущую миграцию в БД
	$(call PRINT_HEADER,showing current migration)
	$(UV) run $(ALEMBIC) current

.PHONY: db-revision
db-revision: ## Создать пустую миграцию: make db-revision REV_MSG="create_users"
	$(call PRINT_HEADER,creating revision)
	$(UV) run $(ALEMBIC) revision -m "$(REV_MSG)"

.PHONY: db-autorevision
db-autorevision: ## Создать autogenerate миграцию: make db-autorevision REV_MSG="create_users"
	$(call PRINT_HEADER,creating autogenerated revision)
	$(UV) run $(ALEMBIC) revision --autogenerate -m "$(REV_MSG)"

.PHONY: db-stamp
db-stamp: ## Проставить head без выполнения миграций
	$(call PRINT_HEADER,stamping database)
	$(UV) run $(ALEMBIC) stamp head

.PHONY: compose-config
compose-config: ## Проверить итоговую конфигурацию docker compose
	$(call PRINT_HEADER,validating compose config)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) config

.PHONY: up
up: ## Поднять базовый dev-стек
	$(call PRINT_HEADER,starting containers)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) up -d

.PHONY: up-build
up-build: ## Поднять dev-стек с пересборкой
	$(call PRINT_HEADER,starting containers with build)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) up -d --build

.PHONY: down
down: ## Остановить dev-стек
	$(call PRINT_HEADER,stopping containers)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) down

.PHONY: restart
restart: down up ## Перезапустить dev-стек

.PHONY: logs
logs: ## Показать логи dev-стека
	$(call PRINT_HEADER,showing logs)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) logs -f --tail=200

.PHONY: ps
ps: ## Показать список контейнеров
	$(call PRINT_HEADER,showing containers)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) ps

.PHONY: prod-up
prod-up: ## Поднять prod-стек
	$(call PRINT_HEADER,starting production stack)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_PROD) up -d

.PHONY: prod-down
prod-down: ## Остановить prod-стек
	$(call PRINT_HEADER,stopping production stack)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_PROD) down

.PHONY: obs-up
obs-up: ## Поднять observability-стек
	$(call PRINT_HEADER,starting observability stack)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_OBS) up -d

.PHONY: obs-down
obs-down: ## Остановить observability-стек
	$(call PRINT_HEADER,stopping observability stack)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_OBS) down

.PHONY: obs-logs
obs-logs: ## Показать логи observability-стека
	$(call PRINT_HEADER,showing observability logs)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_OBS) logs -f --tail=200

.PHONY: app-logs
app-logs: ## Показать логи app-сервиса
	$(call PRINT_HEADER,showing app logs)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) logs -f --tail=200 app

.PHONY: bot-logs
bot-logs: ## Показать логи bot-сервиса
	$(call PRINT_HEADER,showing bot logs)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) logs -f --tail=200 bot

.PHONY: db-logs
db-logs: ## Показать логи postgres-сервиса
	$(call PRINT_HEADER,showing database logs)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) logs -f --tail=200 postgres

.PHONY: redis-logs
redis-logs: ## Показать логи redis-сервиса
	$(call PRINT_HEADER,showing redis logs)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) logs -f --tail=200 redis

.PHONY: app-sh
app-sh: ## Открыть shell внутри app-контейнера
	$(call PRINT_HEADER,opening shell in app container)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) exec app sh

.PHONY: bot-sh
bot-sh: ## Открыть shell внутри bot-контейнера
	$(call PRINT_HEADER,opening shell in bot container)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) exec bot sh

.PHONY: db-shell
db-shell: ## Подключиться к postgres через psql
	$(call PRINT_HEADER,opening psql session)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) exec postgres psql -U $$POSTGRES_USER -d $$POSTGRES_DB

.PHONY: redis-shell
redis-shell: ## Подключиться к redis-cli
	$(call PRINT_HEADER,opening redis shell)
	$(COMPOSE) -f $(DC_FILE_BASE) -f $(DC_FILE_DEV) exec redis redis-cli

.PHONY: migrate
migrate: db-upgrade ## Алиас для применения миграций

.PHONY: bootstrap
bootstrap: doctor env-check install db-upgrade ## Первичная инициализация проекта

.PHONY: dev
dev: install format check test ## Полный локальный цикл разработки

.PHONY: clean
clean: ## Очистить временные файлы
	$(call PRINT_HEADER,cleaning project artifacts)
	find . -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".mypy_cache" -o -name ".ruff_cache" -o -name ".coverage" -o -name "htmlcov" \) -prune -exec rm -rf {} +
	find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete

.PHONY: clean-venv
clean-venv: ## Удалить локальное виртуальное окружение
	$(call PRINT_HEADER,removing virtual environment)
	rm -rf .venv

.PHONY: clean-all
clean-all: clean clean-venv ## Полная очистка проекта