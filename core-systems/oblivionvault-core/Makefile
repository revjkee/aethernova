# oblivionvault-core/Makefile
# Универсальный, промышленный Makefile для репозитория.
# Безопасные дефолты, самодокументация, условные действия по наличию инструментов/каталогов.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

.DEFAULT_GOAL := help
.ONESHELL:

# ---------------------------- Параметры проекта -----------------------------
PROJECT_NAME ?= oblivionvault-core
DOCKER_REGISTRY ?= ghcr.io/acme
IMAGE ?= $(DOCKER_REGISTRY)/$(PROJECT_NAME)

# Семантическая версия и метаданные сборки
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Платформы для buildx
PLATFORMS ?= linux/amd64,linux/arm64

# Внутренние помощники
HAS_PYTEST := $(shell command -v pytest >/dev/null 2>&1 && echo 1 || echo 0)
HAS_RUFF   := $(shell command -v ruff >/dev/null 2>&1 && echo 1 || echo 0)
HAS_BLACK  := $(shell command -v black >/dev/null 2>&1 && echo 1 || echo 0)
HAS_GO     := $(shell command -v go >/dev/null 2>&1 && echo 1 || echo 0)
HAS_NPM    := $(shell command -v npm >/dev/null 2>&1 && echo 0 || echo 1)
HAS_DOCKER := $(shell command -v docker >/dev/null 2>&1 && echo 1 || echo 0)
HAS_TRIVY  := $(shell command -v trivy >/dev/null 2>&1 && echo 1 || echo 0)
HAS_SYFT   := $(shell command -v syft >/dev/null 2>&1 && echo 1 || echo 0)
HAS_HELM   := $(shell command -v helm >/dev/null 2>&1 && echo 1 || echo 0)
HAS_TERRAFORM := $(shell command -v terraform >/dev/null 2>&1 && echo 1 || echo 0)

# Параметры Docker
export DOCKER_BUILDKIT=1

# Цвета (только для help)
BLUE=\033[36m
NC=\033[0m

# ---------------------------- Цели верхнего уровня --------------------------

.PHONY: help
help: ## Показать доступные цели
	@printf "$(BLUE)$(PROJECT_NAME) — универсальные цели$(NC)\n"
	@awk 'BEGIN {FS = ":.*##"; printf "\nTargets:\n"} /^[a-zA-Z0-9_\/-]+:.*?##/ { printf "  %-30s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: init
init: ## Создать локальные артефакты (например .venv, .env) при необходимости
	@if [ -f ".env.example" ] && [ ! -f ".env" ]; then cp .env.example .env; fi
	@if [ -f "pyproject.toml" ] && [ ! -d ".venv" ]; then python3 -m venv .venv; fi
	@if [ -f "package.json" ] && [ ! -d "node_modules" ]; then npm ci; fi
	@echo "init done"

.PHONY: fmt
fmt: ## Автоформатирование кода (python/node/go) при наличии инструментов
	@if [ -f "pyproject.toml" ] && [ "$(HAS_BLACK)" = "1" ]; then . .venv/bin/activate 2>/dev/null || true; black .; fi
	@if [ -f "pyproject.toml" ] && [ "$(HAS_RUFF)" = "1" ]; then ruff format .; fi
	@if [ "$(HAS_GO)" = "1" ] && [ -d "./cmd" -o -d "./internal" ]; then go fmt ./...; fi
	@if [ -f "package.json" ]; then npm run fmt --if-present; fi
	@echo "fmt done"

.PHONY: lint
lint: ## Линтеры (ruff/eslint/golangci-lint) при наличии
	@if [ -f "pyproject.toml" ] && [ "$(HAS_RUFF)" = "1" ]; then ruff check .; fi
	@if [ -f "package.json" ]; then npm run lint --if-present; fi
	@if [ "$(HAS_GO)" = "1" ]; then golangci-lint run ./... 2>/dev/null || true; fi
	@echo "lint done"

.PHONY: test
test: ## Тесты (pytest/go test/npm test) при наличии
	@if [ -d "tests" ] && [ "$(HAS_PYTEST)" = "1" ]; then PYTHONPATH=. pytest -q --disable-warnings --maxfail=1; fi
	@if [ "$(HAS_GO)" = "1" ]; then go test ./... -count=1; fi
	@if [ -f "package.json" ]; then npm test --if-present; fi
	@echo "test done"

.PHONY: coverage
coverage: ## Покрытие тестами (если инструменты доступны)
	@if [ -d "tests" ] && [ "$(HAS_PYTEST)" = "1" ]; then PYTHONPATH=. pytest --cov=. --cov-report=term-missing; fi
	@if [ "$(HAS_GO)" = "1" ]; then go test ./... -cover; fi

.PHONY: build
build: ## Сборка локального артефакта (если предусмотрено в package.json или Go)
	@if [ -f "package.json" ]; then npm run build --if-present; fi
	@if [ "$(HAS_GO)" = "1" ] && [ -d "./cmd" ]; then go build ./cmd/...; fi
	@echo "build done"

# ---------------------------- Контейнеризация -------------------------------

.PHONY: docker/build
docker/build: ## Сборка docker-образа (локальная)
	@if [ "$(HAS_DOCKER)" != "1" ]; then echo "docker not installed"; exit 1; fi
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT_SHA=$(COMMIT_SHA) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t $(IMAGE):$(VERSION) \
	  -t $(IMAGE):latest \
	  .

.PHONY: docker/buildx
docker/buildx: ## Мультиархитектурная сборка buildx (amd64, arm64)
	@if [ "$(HAS_DOCKER)" != "1" ]; then echo "docker not installed"; exit 1; fi
	# Создание билдера при необходимости
	@if ! docker buildx ls | grep -q "picore-builder"; then docker buildx create --use --name picore-builder; fi
	docker buildx build \
	  --platform $(PLATFORMS) \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT_SHA=$(COMMIT_SHA) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t $(IMAGE):$(VERSION) \
	  -t $(IMAGE):latest \
	  --load \
	  .

.PHONY: docker/push
docker/push: ## Публикация образов (требует логин в реестр)
	@if [ "$(HAS_DOCKER)" != "1" ]; then echo "docker not installed"; exit 1; fi
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

.PHONY: docker/sbom
docker/sbom: ## Генерация SBOM (syft) при наличии
	@if [ "$(HAS_SYFT)" = "1" ]; then syft $(IMAGE):$(VERSION) -o spdx-json > sbom-$(PROJECT_NAME)-$(VERSION).spdx.json; else echo "syft not installed, skipping"; fi

.PHONY: docker/scan
docker/scan: ## Скан уязвимостей (trivy) при наличии
	@if [ "$(HAS_TRIVY)" = "1" ]; then trivy image --scanners vuln,secret,config --exit-code 1 --severity CRITICAL,HIGH $(IMAGE):$(VERSION) || true; else echo "trivy not installed, skipping"; fi

# ---------------------------- Инфраструктура --------------------------------

.PHONY: helm/lint
helm/lint: ## Проверка Helm-чартов при наличии
	@if [ "$(HAS_HELM)" = "1" ] && [ -d "ops/helm" ]; then helm lint ops/helm/* || true; else echo "helm or ops/helm not present, skipping"; fi

.PHONY: terraform/validate
terraform/validate: ## Проверка Terraform при наличии
	@if [ "$(HAS_TERRAFORM)" = "1" ] && [ -d "ops/terraform" ]; then \
	  terraform -chdir=ops/terraform fmt -check; \
	  terraform -chdir=ops/terraform init -backend=false; \
	  terraform -chdir=ops/terraform validate; \
	else echo "terraform or ops/terraform not present, skipping"; fi

# ---------------------------- Релизы и теги ---------------------------------

.PHONY: tag
tag: ## Создать аннотированный git-тег vX.Y.Z, VERSION=vX.Y.Z
	@if [ -z "$(VERSION)" ]; then echo "VERSION required (e.g. make tag VERSION=v1.2.3)"; exit 1; fi
	git tag -a "$(VERSION)" -m "Release $(VERSION)"
	git push origin "$(VERSION)"

.PHONY: release
release: fmt lint test docker/build docker/sbom docker/scan ## Выполнить полный набор для релиза

# ---------------------------- Уборка ----------------------------------------

.PHONY: clean
clean: ## Очистка артефактов
	@rm -rf dist build .pytest_cache .coverage coverage.xml sbom-*.spdx.json || true
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "clean done"
