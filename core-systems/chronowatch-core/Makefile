# Makefile для chronowatch-core — промышленная версия
# Безопасный bash, отказ при ошибках и незаданых переменных
SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# Загружаем переменные из .env, если файл существует
ENV_FILE ?= .env
ifneq (,$(wildcard $(ENV_FILE)))
include $(ENV_FILE)
export
endif

# Основные переменные проекта
PROJECT_NAME ?= chronowatch-core
REGISTRY     ?= ghcr.io/aethernova
IMAGE        ?= $(REGISTRY)/$(PROJECT_NAME)
DATE         := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "nogit")
GIT_BRANCH   := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "nogit")
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")

# Автоопределение наличия стеков
HAS_PY       := $(shell test -f pyproject.toml -o -f requirements.txt && echo 1 || echo 0)
HAS_NODE     := $(shell test -f package.json && echo 1 || echo 0)
HAS_GO       := $(shell test -f go.mod && echo 1 || echo 0)
HAS_PROTO    := $(shell test -d proto && ls -1 proto/*.proto >/dev/null 2>&1 && echo 1 || echo 0)
HAS_DOCKER   := $(shell test -f Dockerfile && echo 1 || echo 0)
HAS_COMPOSE  := $(shell ls -1 docker-compose*.y*ml >/dev/null 2>&1 && echo 1 || echo 0)

# Кросс-платформенные команды
PYTHON       ?= python3
PIP          ?= pip3
NPM          ?= npm
NODE         ?= node
GO           ?= go
DOCKER       ?= docker

BUILD_DIR    ?= build
DIST_DIR     ?= dist

# Универсальная проверка инструментов
define require_tool
	@if ! command -v $(1) >/dev/null 2>&1; then \
		echo "Отсутствует требуемый инструмент: $(1)"; \
		exit 1; \
	fi
endef

# Печать переменных
print-vars: ## Показать ключевые переменные окружения
	@echo "PROJECT_NAME=$(PROJECT_NAME)"
	@echo "REGISTRY=$(REGISTRY)"
	@echo "IMAGE=$(IMAGE)"
	@echo "DATE=$(DATE)"
	@echo "GIT_COMMIT=$(GIT_COMMIT)"
	@echo "GIT_BRANCH=$(GIT_BRANCH)"
	@echo "VERSION=$(VERSION)"
	@echo "HAS_PY=$(HAS_PY) HAS_NODE=$(HAS_NODE) HAS_GO=$(HAS_GO) HAS_PROTO=$(HAS_PROTO) HAS_DOCKER=$(HAS_DOCKER) HAS_COMPOSE=$(HAS_COMPOSE)"

# ------------------------------------------------------------------------------
# Инициализация и зависимости
# ------------------------------------------------------------------------------
init: ## Инициализация проекта, pre-commit, директории build/dist
	@mkdir -p $(BUILD_DIR) $(DIST_DIR)
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install -t pre-commit -t commit-msg || true; \
	fi
	@if [ "$(HAS_PY)" = "1" ]; then \
		if command -v uv >/dev/null 2>&1; then \
			uv venv .venv && . .venv/bin/activate && uv pip install -U pip; \
			if [ -f pyproject.toml ]; then . .venv/bin/activate && uv pip install -e .; \
			elif [ -f requirements.txt ]; then . .venv/bin/activate && uv pip install -r requirements.txt; fi; \
		else \
			$(PYTHON) -m venv .venv && . .venv/bin/activate && python -m pip install -U pip; \
			if [ -f pyproject.toml ] && command -v poetry >/dev/null 2>&1; then . .venv/bin/activate && poetry install; \
			elif [ -f requirements.txt ]; then . .venv/bin/activate && pip install -r requirements.txt; fi; \
		fi \
	fi
	@if [ "$(HAS_NODE)" = "1" ]; then \
		$(call require_tool,$(NPM)); \
		$(NPM) ci || $(NPM) install; \
	fi
	@if [ "$(HAS_GO)" = "1" ]; then \
		$(call require_tool,$(GO)); \
		$(GO) mod download; \
	fi

deps: init ## Синоним init
	@true

# ------------------------------------------------------------------------------
# Качество кода
# ------------------------------------------------------------------------------
fmt: ## Форматирование кода для доступных стеков
	@if [ "$(HAS_PY)" = "1" ]; then \
		. .venv/bin/activate 2>/dev/null || true; \
		command -v ruff >/dev/null 2>&1 && ruff format . || true; \
		command -v black >/dev/null 2>&1 && black . || true; \
		command -v isort >/dev/null 2>&1 && isort . || true; \
	fi
	@if [ "$(HAS_NODE)" = "1" ]; then \
		if $(NPM) run | grep -q "format"; then $(NPM) run format; else \
			command -v npx >/dev/null 2>&1 && npx prettier -w . || true; fi; \
	fi
	@if [ "$(HAS_GO)" = "1" ]; then \
		$(GO) fmt ./...; \
	fi

lint: ## Линтеры для доступных стеков
	@if [ "$(HAS_PY)" = "1" ]; then \
		. .venv/bin/activate 2>/dev/null || true; \
		command -v ruff >/dev/null 2>&1 && ruff check . || true; \
		command -v flake8 >/dev/null 2>&1 && flake8 || true; \
		command -v bandit >/dev/null 2>&1 && bandit -q -r . || true; \
	fi
	@if [ "$(HAS_NODE)" = "1" ]; then \
		if $(NPM) run | grep -q "lint"; then $(NPM) run lint; else \
			command -v npx >/dev/null 2>&1 && npx eslint . || true; fi; \
	fi
	@if [ "$(HAS_GO)" = "1" ]; then \
		if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; else $(GO) vet ./...; fi; \
	fi

typecheck: ## Статическая типизация, если доступна
	@if [ "$(HAS_PY)" = "1" ]; then \
		. .venv/bin/activate 2>/dev/null || true; \
		command -v mypy >/dev/null 2>&1 && mypy . || true; \
	fi
	@if [ "$(HAS_NODE)" = "1" ]; then \
		if [ -f tsconfig.json ]; then \
			if $(NPM) run | grep -q "typecheck"; then $(NPM) run typecheck; else npx tsc -p tsconfig.json --noEmit; fi; \
		fi \
	fi

# ------------------------------------------------------------------------------
# Тесты и покрытие
# ------------------------------------------------------------------------------
test: ## Запуск тестов для доступных стеков
	@if [ "$(HAS_PY)" = "1" ]; then \
		. .venv/bin/activate 2>/dev/null || true; \
		if command -v pytest >/dev/null 2>&1; then pytest -q; fi; \
	fi
	@if [ "$(HAS_NODE)" = "1" ]; then \
		if $(NPM) run | grep -q "test"; then $(NPM) run test --silent; fi; \
	fi
	@if [ "$(HAS_GO)" = "1" ]; then \
		$(GO) test ./...; \
	fi

coverage: ## Отчеты покрытия, если инструменты доступны
	@mkdir -p $(BUILD_DIR)/coverage
	@if [ "$(HAS_PY)" = "1" ]; then \
		. .venv/bin/activate 2>/dev/null || true; \
		if command -v coverage >/dev/null 2>&1; then \
			coverage run -m pytest && coverage xml -o $(BUILD_DIR)/coverage/python.xml && coverage html -d $(BUILD_DIR)/coverage/python_html; \
		fi \
	fi
	@if [ "$(HAS_NODE)" = "1" ]; then \
		if $(NPM) run | grep -qi "coverage"; then $(NPM) run coverage; fi; \
	fi
	@if [ "$(HAS_GO)" = "1" ]; then \
		$(GO) test ./... -coverprofile=$(BUILD_DIR)/coverage/go.out && \
		$(GO) tool cover -html=$(BUILD_DIR)/coverage/go.out -o $(BUILD_DIR)/coverage/go.html; \
	fi

# ------------------------------------------------------------------------------
# Протоколы и генерация кода
# ------------------------------------------------------------------------------
proto: ## Компиляция .proto, если есть
	@if [ "$(HAS_PROTO)" = "1" ]; then \
		if command -v buf >/dev/null 2>&1; then \
			buf generate; \
		elif command -v protoc >/dev/null 2>&1; then \
			find proto -name '*.proto' -print0 | xargs -0 -I{} protoc -I proto --python_out=./ --go_out=./ --go-grpc_out=./ --grpc-python_out=./ {}; \
		else \
			echo "buf или protoc не найдены"; exit 1; \
		fi \
	else \
		echo "Нет proto файлов"; \
	fi

# ------------------------------------------------------------------------------
# Сборка, контейнеры, поставка
# ------------------------------------------------------------------------------
build: ## Сборка проекта без Docker, если стек поддерживает явную сборку
	@if [ "$(HAS_GO)" = "1" ]; then \
		mkdir -p $(DIST_DIR); \
		$(GO) build -ldflags "-X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.date=$(DATE)" -o $(DIST_DIR)/$(PROJECT_NAME) ./...; \
	elif [ "$(HAS_NODE)" = "1" ]; then \
		if $(NPM) run | grep -q "build"; then $(NPM) run build; else echo "Нет команды build в package.json"; fi; \
	elif [ "$(HAS_PY)" = "1" ]; then \
		. .venv/bin/activate 2>/dev/null || true; \
		if command -v python -m build >/dev/null 2>&1; then python -m build; else echo "Для Python сборки установите пакет build"; fi; \
	else \
		echo "Явный шаг сборки не определен для текущего стека"; \
	fi

docker-build: ## Сборка Docker образа, если есть Dockerfile
	@if [ "$(HAS_DOCKER)" = "1" ]; then \
		$(call require_tool,$(DOCKER)); \
		DOCKER_BUILDKIT=1 $(DOCKER) build --pull \
			--build-arg VCS_REF=$(GIT_COMMIT) --build-arg BUILD_DATE=$(DATE) \
			-t $(IMAGE):$(VERSION) -t $(IMAGE):latest . ; \
	else \
		echo "Dockerfile не найден"; \
	fi

docker-push: ## Публикация Docker образа
	@$(call require_tool,$(DOCKER))
	@$(DOCKER) push $(IMAGE):$(VERSION) || true
	@$(DOCKER) push $(IMAGE):latest || true

compose-up: ## Запуск сервисов через docker compose
	@if [ "$(HAS_COMPOSE)" = "1" ]; then \
		$(call require_tool,$(DOCKER)); \
		docker compose up -d --build; \
	else \
		echo "Файл docker-compose не найден"; \
	fi

compose-down: ## Остановка сервисов docker compose
	@if [ "$(HAS_COMPOSE)" = "1" ]; then \
		docker compose down -v; \
	else \
		echo "Файл docker-compose не найден"; \
	fi

# ------------------------------------------------------------------------------
# Безопасность и соответствие
# ------------------------------------------------------------------------------
sbom: ## Генерация SBOM в SPDX и CycloneDX, если доступен syft
	@mkdir -p $(BUILD_DIR)/sbom
	@if command -v syft >/dev/null 2>&1; then \
		if [ "$(HAS_DOCKER)" = "1" ]; then \
			syft $(IMAGE):$(VERSION) -o spdx-json > $(BUILD_DIR)/sbom/sbom.spdx.json || true; \
			syft $(IMAGE):$(VERSION) -o cyclonedx-json > $(BUILD_DIR)/sbom/sbom.cdx.json || true; \
		else \
			syft dir:. -o spdx-json > $(BUILD_DIR)/sbom/sbom.spdx.json || true; \
			syft dir:. -o cyclonedx-json > $(BUILD_DIR)/sbom/sbom.cdx.json || true; \
		fi \
	else \
		echo "syft не найден"; \
	fi

scan: ## Security-скан кода и образа, если доступен trivy
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --scanners vuln,secret,misconfig --exit-code 0 --format table . || true; \
		if [ "$(HAS_DOCKER)" = "1" ]; then trivy image --exit-code 0 $(IMAGE):$(VERSION) || true; fi; \
	else \
		echo "trivy не найден"; \
	fi

# ------------------------------------------------------------------------------
# Релизы и версии
# ------------------------------------------------------------------------------
tag-release: ## Создать git-тег релиза vX.Y.Z и запушить
	@if [ -z "$$V" ]; then echo "Укажите версию: make tag-release V=1.2.3"; exit 1; fi
	@git tag -a "v$$V" -m "release: v$$V"
	@git push --tags

# ------------------------------------------------------------------------------
# Документация
# ------------------------------------------------------------------------------
docs: ## Сборка документации, если доступен генератор
	@if [ -f mkdocs.yml ] && command -v mkdocs >/dev/null 2>&1; then \
		mkdocs build -d $(BUILD_DIR)/site; \
	elif [ -f typedoc.json ] && [ "$(HAS_NODE)" = "1" ]; then \
		npx typedoc; \
	else \
		echo "Генератор документации не найден"; \
	fi

# ------------------------------------------------------------------------------
# Служебные цели
# ------------------------------------------------------------------------------
ci: ## Полный цикл для CI: deps, fmt, lint, typecheck, test, build
	$(MAKE) deps
	$(MAKE) fmt
	$(MAKE) lint
	$(MAKE) typecheck
	$(MAKE) test
	$(MAKE) build

clean: ## Очистка артефактов сборки и кэшей
	@rm -rf $(BUILD_DIR) $(DIST_DIR) .pytest_cache .ruff_cache .mypy_cache coverage htmlcov
	@find . -name "__pycache__" -type d -prune -exec rm -rf {} +
	@find . -name "*.pyc" -delete
	@find . -name "*.pyo" -delete

help: ## Показать список целей и описание
	@echo "Цели Makefile для $(PROJECT_NAME):"
	@grep -E '^[a-zA-Z0-9_.-]+:.*?## ' $(firstword $(MAKEFILE_LIST)) | awk 'BEGIN {FS=":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'
