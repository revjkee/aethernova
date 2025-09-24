# Makefile — industrial grade for engine-core
# Usage: `make help` to list commands

# --------------------------------------------------------------------------------------
# Variables (override via CLI: make build DOCKER_IMAGE=my/engine-core VERSION=1.2.3)
# --------------------------------------------------------------------------------------
PROJECT            ?= engine-core
PYTHON             ?= python3.11
POETRY             ?= poetry
PACKAGE            ?= engine_core
SRC_DIR            ?= src/$(PACKAGE)
TEST_DIR           ?= tests
CONFIG_DIR         ?= configs
VERSION_FILE       ?= VERSION
GIT_SHA            := $(shell git rev-parse --short HEAD 2>/dev/null || echo "nogit")
GIT_BRANCH         := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "nogit")
VERSION            ?= $(shell test -f $(VERSION_FILE) && cat $(VERSION_FILE) || echo "0.0.0-dev")
BUILD_DATE         := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
DOCKER_IMAGE       ?= ghcr.io/aethernova/engine-core
DOCKER_TAG         ?= $(VERSION)
DOCKER_PLATFORM    ?= linux/amd64
OTEL_SERVICE_NAME  ?= $(PROJECT)
PROM_NAMESPACE     ?= engine_core
# Tools (optional, detected at runtime)
SYFT               ?= syft
GRYPE              ?= grype

# Colors
BLUE=\033[1;34m
GREEN=\033[1;32m
YELLOW=\033[1;33m
RESET=\033[0m

# Default target
.DEFAULT_GOAL := help
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

define print_target
	@printf "$(BLUE)%-28s$(RESET) %s\n" "$(1)" "$(2)"
endef

help: ## Показать список целей
	@echo "$(GREEN)$(PROJECT) — Make targets$(RESET)"
	@echo
	$(call print_target,setup,Установка окружения (Poetry, pre-commit))
	$(call print_target,install,Poetry install с виртуальным окружением .venv)
	$(call print_target,lock,Сгенерировать poetry.lock без обновлений)
	$(call print_target,update,Обновить зависимости (poetry update))
	$(call print_target,lint,Линт и авто-фикс Ruff)
	$(call print_target,format,Форматирование Ruff)
	$(call print_target,typecheck,Статическая типизация mypy)
	$(call print_target,test,Тесты с покрытием)
	$(call print_target,coverage-html,HTML-отчет покрытия)
	$(call print_target,run,Локальный запуск API (uvicorn))
	$(call print_target,cli-serve,Запуск через Typer CLI)
	$(call print_target,docker-build,Сборка Docker-образа)
	$(call print_target,docker-push,Публикация Docker-образа)
	$(call print_target,docker-run,Запуск контейнера локально)
	$(call print_target,sbom,SBOM (syft) для образа/репо)
	$(call print_target,scan,Скан уязвимостей (grype + pip-audit))
	$(call print_target,pre-commit-install,Установка pre-commit хуков)
	$(call print_target,pre-commit,Запуск всех pre-commit хуков)
	$(call print_target,clean,Очистка артефактов)
	$(call print_target,release,Создание git-тега v$(VERSION) и пуш)
	@echo

# --------------------------------------------------------------------------------------
# Environment / Install
# --------------------------------------------------------------------------------------

setup: ## Установка Poetry, зависимости, pre-commit
	@$(MAKE) install
	@$(MAKE) pre-commit-install

install: ## Poetry install c локальным .venv
	@$(PYTHON) -m pip -q install --upgrade pip
	@$(PYTHON) -m pip -q install pipx || true
	@pipx ensurepath || true
	@$(POETRY) --version >/dev/null 2>&1 || pipx install poetry==1.8.3
	@$(POETRY) config virtualenvs.in-project true
	@$(POETRY) env use $(PYTHON) || true
	@POETRY_VIRTUALENVS_IN_PROJECT=true $(POETRY) install --no-interaction --no-ansi

lock: ## Сгенерировать poetry.lock без обновлений
	@$(POETRY) lock --no-update

update: ## Обновить зависимости (poetry update)
	@$(POETRY) update

# --------------------------------------------------------------------------------------
# Quality gates
# --------------------------------------------------------------------------------------

lint: ## Ruff lint + авто-фикс
	@$(POETRY) run ruff check --fix .

format: ## Ruff форматирование
	@$(POETRY) run ruff format .

typecheck: ## mypy строгий режим
	@$(POETRY) run mypy --config-file mypy.ini $(SRC_DIR) $(TEST_DIR)

test: ## pytest + coverage.xml
	@$(POETRY) run pytest -q --maxfail=1 --disable-warnings \
		--cov=$(PACKAGE) --cov-report=term-missing --cov-report=xml $(TEST_DIR)

coverage-html: ## Генерация HTML-отчёта покрытия
	@$(POETRY) run coverage html
	@echo "$(GREEN)HTML coverage report at: htmlcov/index.html$(RESET)"

pre-commit-install: ## Установка git-хуков pre-commit
	@$(POETRY) run pre-commit install -t pre-commit -t commit-msg

pre-commit: ## Запустить pre-commit на всех файлах
	@$(POETRY) run pre-commit run --all-files

scan: ## Скан уязвимостей: grype (Docker образ) + pip-audit (deps)
	@echo "$(YELLOW)pip-audit (deps)…$(RESET)"
	@$(POETRY) export -f requirements.txt --with dev --without-hashes -o /tmp/req.txt
	@$(POETRY) run pip-audit -r /tmp/req.txt || true
	@echo "$(YELLOW)grype (image $(DOCKER_IMAGE):$(DOCKER_TAG))…$(RESET)"
	@command -v $(GRYPE) >/dev/null 2>&1 && $(GRYPE) $(DOCKER_IMAGE):$(DOCKER_TAG) || echo "grype not found, skip"

sbom: ## SBOM: syft dir и/или образ
	@command -v $(SYFT) >/dev/null 2>&1 && $(SYFT) packages dir:. -o json > sbom.repo.json || echo "syft not found, skip repo SBOM"
	@command -v $(SYFT) >/dev/null 2>&1 && $(SYFT) $(DOCKER_IMAGE):$(DOCKER_TAG) -o json > sbom.image.json || echo "syft not found, skip image SBOM"
	@ls -1 sbom*.json 2>/dev/null || true

# --------------------------------------------------------------------------------------
# Run / Serve
# --------------------------------------------------------------------------------------

run: ## Локальный запуск API (uvicorn) на 0.0.0.0:8000
	@APP_CONFIG=$(CONFIG_DIR)/application.yaml \
	$(POETRY) run uvicorn $(PACKAGE).app:app --host 0.0.0.0 --port 8000 --reload

cli-serve: ## Запуск через Typer CLI (engine-core serve)
	@$(POETRY) run engine-core serve --host 0.0.0.0 --port 8000

# --------------------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------------------

docker-build: ## Сборка Docker-образа с метаданными
	@docker buildx build --platform $(DOCKER_PLATFORM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg VCS_REF=$(GIT_SHA) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-f ops/docker/Dockerfile .

docker-push: ## Публикация Docker-образа
	@docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-run: ## Запуск контейнера локально (порт 8000)
	@docker run --rm -it -p 8000:8000 \
		-e APP_CONFIG=$(CONFIG_DIR)/application.yaml \
		--name $(PROJECT) $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-stop: ## Остановка контейнера
	@docker stop $(PROJECT) || true

docker-clean: ## Удалить dangling-образы/кэши
	@docker image prune -f
	@docker builder prune -f || true

# --------------------------------------------------------------------------------------
# Release flow
# --------------------------------------------------------------------------------------

release: ## Создать и запушить git-тег v$(VERSION)
	@git add -A
	@git commit -m "chore(release): v$(VERSION)" || true
	@git tag -s v$(VERSION) -m "$(PROJECT) v$(VERSION)"
	@git push --follow-tags

# --------------------------------------------------------------------------------------
# Clean
# --------------------------------------------------------------------------------------

clean: ## Очистить кэши/артефакты
	@find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	@rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov coverage.xml dist build wheels
	@echo "$(GREEN)Clean done.$(RESET)"
