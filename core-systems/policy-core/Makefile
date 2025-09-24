# policy-core/Makefile
# Промышленный конвейер для Policy-as-Code (OPA/Rego) и сопутствующего кода.
# Краткая помощь: `make help`

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

# -------- Параметры проекта --------
PROJECT            := policy-core
POL_DIR            := policies
TEST_DIR           := tests
DIST_DIR           := dist
BUNDLE_NAME        := $(PROJECT)-bundle.tar.gz
BUNDLE_PATH        := $(DIST_DIR)/$(BUNDLE_NAME)
SBOM_PATH          := $(DIST_DIR)/sbom.cdx.json
COVERAGE_XML       := $(DIST_DIR)/coverage.xml
COVERAGE_HTML_DIR  := $(DIST_DIR)/htmlcov

# -------- Инструменты (локальные/через Docker) --------
PYTHON ?= python3
PIP    ?= pip3
VENV   ?= .venv

# OPA: если локально нет, будет использоваться Docker
OPA            ?= opa
OPA_DOCKER_IMG ?= openpolicyagent/opa:latest
OPA_RUN        := $(OPA)
# Проверка наличия opa в PATH
OPA_EXISTS     := $(shell command -v $(OPA) >/dev/null 2>&1 && echo yes || echo no)
ifeq ($(OPA_EXISTS),no)
OPA_RUN = docker run --rm -u $$(id -u):$$(id -g) -v $$PWD:/src -w /src $(OPA_DOCKER_IMG)
endif

CONTEST        ?= conftest
CONTEST_EXISTS := $(shell command -v $(CONTEST) >/dev/null 2>&1 && echo yes || echo no)
YAMLLINT       ?= yamllint
MDL            ?= markdownlint
SEMGR          ?= semgrep
BANDIT         ?= bandit
TRIVY          ?= trivy
SYFT           ?= syft
COSIGN         ?= cosign
PRECOMMIT      ?= pre-commit
PYTEST         ?= pytest
BLACK          ?= black
ISORT          ?= isort

# -------- Переключатели безопасности/CI --------
CI        ?= 0
SIGN_BUNDLE ?= 0                  # включить подпись cosign (1/0)
COSIGN_KEY  ?= ./cosign.key       # путь к ключу, если SIGN_BUNDLE=1

# -------- Утилиты --------
UNAME_S := $(shell uname -s)
SHA256  := sha256sum
ifeq ($(UNAME_S),Darwin)
	SHA256 := shasum -a 256
endif

# -------- Справка --------
.PHONY: help
help: ## Показать доступные цели
	@awk 'BEGIN {FS ":.*##"; printf "\n%s\n\n","Доступные цели:"} /^[a-zA-Z0-9_\-]+:.*##/ { printf "  %-24s %s\n", $$1, $$2 }' $(MAKEFILE_LIST); echo

# -------- Виртуальное окружение / зависимости --------
.PHONY: venv
venv: ## Создать venv и обновить pip
	@test -d "$(VENV)" || $(PYTHON) -m venv "$(VENV)"
	. "$(VENV)/bin/activate"; pip install --upgrade pip

.PHONY: install
install: venv ## Установить зависимости (prod+dev при наличии)
	. "$(VENV)/bin/activate"; \
	if [ -f requirements.txt ]; then pip install -r requirements.txt; fi; \
	if [ -f requirements-dev.txt ]; then pip install -r requirements-dev.txt; fi; \
	if command -v $(PRECOMMIT) >/dev/null 2>&1; then $(PRECOMMIT) install; fi

# -------- Форматирование --------
.PHONY: fmt
fmt: ## Автоформатирование (Python/OPA/Markdown)
	@if [ -d "$(POL_DIR)" ]; then $(OPA_RUN) fmt -w $(POL_DIR); fi
	@if [ -d "$(TEST_DIR)" ]; then $(OPA_RUN) fmt -w $(TEST_DIR); fi
	@if command -v $(BLACK) >/dev/null 2>&1; then $(BLACK) .; fi
	@if command -v $(ISORT) >/dev/null 2>&1; then $(ISORT) .; fi
	@if command -v $(MDL) >/dev/null 2>&1; then $(MDL) -f json . || true; fi

# -------- Линтинг --------
.PHONY: lint
lint: ## Линт всех артефактов (rego/yaml/md/python)
	@if [ -d "$(POL_DIR)" ]; then $(OPA_RUN) fmt -d $(POL_DIR); fi
	@if [ -d "$(TEST_DIR)" ]; then $(OPA_RUN) fmt -d $(TEST_DIR); fi
	@if command -v $(CONTEST) >/dev/null 2>&1 && [ -d "$(POL_DIR)" ]; then $(CONTEST) verify $(POL_DIR); fi
	@if command -v $(YAMLLINT) >/dev/null 2>&1; then $(YAMLLINT) .; fi
	@if command -v $(MDL) >/dev/null 2>&1; then $(MDL) .; fi
	@if command -v $(SEMGR) >/dev/null 2>&1; then $(SEMGR) ci --error || [ "$(CI)" = "0" ]; fi
	@if command -v $(BANDIT) >/dev/null 2>&1; then $(BANDIT) -q -r . || [ "$(CI)" = "0" ]; fi

# -------- Тесты кода --------
.PHONY: test
test: ## Тесты Python (если есть)
	@if command -v $(PYTEST) >/dev/null 2>&1; then $(PYTEST) -q || exit 1; else echo "pytest не найден, пропуск"; fi

.PHONY: coverage
coverage: ## Покрытие кода (XML/HTML если возможно)
	@mkdir -p $(DIST_DIR)
	@if command -v $(PYTEST) >/dev/null 2>&1; then \
	    $(PYTEST) --cov=. --cov-report=xml:$(COVERAGE_XML) --cov-report=html:$(COVERAGE_HTML_DIR); \
	else echo "pytest не найден, пропуск покрытия"; fi

# -------- Тесты политик (OPA/Rego) --------
.PHONY: policy-test
policy-test: ## Тесты политик OPA (opa test)
	@[ -d "$(POL_DIR)" ] || { echo "Нет каталога $(POL_DIR)"; exit 1; }
	@$(OPA_RUN) test $(POL_DIR) $(TEST_DIR) -v

# -------- Сборка бандла политик --------
.PHONY: policy-bundle
policy-bundle: ## Сборка бандла политик (tar.gz) + SHA256 + опциональная подпись
	@[ -d "$(POL_DIR)" ] || { echo "Нет каталога $(POL_DIR)"; exit 1; }
	@mkdir -p $(DIST_DIR)
	# Сборка через OPA build (bundle формат)
/bin/echo "Building bundle via OPA"
	@$(OPA_RUN) build -b $(POL_DIR) -o $(BUNDLE_PATH)
	# Хеш-сумма
	@cd $(DIST_DIR); $(SHA256) $(BUNDLE_NAME) > $(BUNDLE_NAME).sha256
	# Подпись (опционально)
ifneq ($(SIGN_BUNDLE),0)
	@if [ -f "$(COSIGN_KEY)" ]; then \
		$(COSIGN) sign-blob --key "$(COSIGN_KEY)" --output-signature "$(BUNDLE_PATH).sig" "$(BUNDLE_PATH)"; \
	else echo "COSIGN_KEY не найден: $(COSIGN_KEY)"; exit 1; fi
endif
	@echo "Bundle: $(BUNDLE_PATH)"
	@echo "SHA256: $(BUNDLE_PATH).sha256"
ifneq ($(SIGN_BUNDLE),0)
	@echo "Signature: $(BUNDLE_PATH).sig"
endif

# -------- Артефакты безопасности --------
.PHONY: sbom
sbom: ## Сгенерировать SBOM (CycloneDX JSON)
	@mkdir -p $(DIST_DIR)
	@if command -v $(SYFT) >/dev/null 2>&1; then \
		$(SYFT) . -o cyclonedx-json=$(SBOM_PATH); \
	else echo "syft не найден, пропуск SBOM"; fi
	@echo "SBOM: $(SBOM_PATH)"

.PHONY: scan
scan: ## Скан зависимостей/ФС (Trivy), правила кода (Semgrep)
	@if command -v $(TRIVY) >/dev/null 2>&1; then $(TRIVY) fs --no-progress --exit-code 1 . || [ "$(CI)" = "0" ]; else echo "trivy не найден, пропуск"; fi
	@if command -v $(SEMGR) >/dev/null 2>&1; then $(SEMGR) ci --error || [ "$(CI)" = "0" ]; else echo "semgrep не найден, пропуск"; fi

# -------- Docker --------
IMG ?= $(PROJECT):local
.PHONY: docker-build
docker-build: ## Сборка docker-образа
	docker build -t $(IMG) .

# -------- Композитные цели --------
.PHONY: all
all: lint test policy-test policy-bundle ## Полный локальный цикл

.PHONY: ci
ci: ## CI-конвейер: формат/линт/тесты/бандл/SBOM/скан
	$(MAKE) fmt
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) policy-test
	$(MAKE) policy-bundle
	$(MAKE) sbom
	$(MAKE) scan

# -------- Утилиты --------
.PHONY: print-vars
print-vars: ## Вывести ключевые переменные
	@echo "OPA_EXISTS=$(OPA_EXISTS)"
	@echo "OPA_RUN=$(OPA_RUN)"
	@echo "BUNDLE_PATH=$(BUNDLE_PATH)"
	@echo "DIST_DIR=$(DIST_DIR)"
	@echo "CI=$(CI)"
	@echo "SIGN_BUNDLE=$(SIGN_BUNDLE)"
	@echo "COSIGN_KEY=$(COSIGN_KEY)"

# -------- Очистка --------
.PHONY: clean
clean: ## Очистить временные артефакты
	@rm -rf $(DIST_DIR) || true
	@find . -name '__pycache__' -o -name '.pytest_cache' -o -name '*.pyc' | xargs -I{} rm -rf {}

.PHONY: distclean
distclean: clean ## Полная очистка (включая venv)
	@rm -rf "$(VENV)" || true
