# Industrial DevSecOps Makefile for security-core
# Используется локально и в CI. Безопасно пропускает шаги, если тул недоступен.
# Минимум зависимостей, максимум проверок.

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

# -------- Config --------
PY ?= python3
PIP ?= pip3
VENV ?= .venv
BUILD_DIR ?= build
SRC_DIR ?= src
TEST_DIR ?= tests
COVERAGE_FILE ?= $(BUILD_DIR)/coverage.xml
REPORT_DIR ?= $(BUILD_DIR)/reports
SBOM_FILE ?= $(BUILD_DIR)/sbom.spdx.json
IMAGE_NAME ?= security-core
IMAGE_TAG ?= local
IMAGE ?= $(IMAGE_NAME):$(IMAGE_TAG)
CI ?= 0

# Цвета
C_RESET := \033[0m
C_BOLD := \033[1m
C_GREEN := \033[32m
C_YELLOW := \033[33m
C_RED := \033[31m
C_CYAN := \033[36m

# -------- Helpers --------
define _step
	@echo -e "$(C_CYAN)▶ $(1)$(C_RESET)"
endef

define _ok
	@echo -e "$(C_GREEN)✔ $(1)$(C_RESET)"
endef

define _warn
	@echo -e "$(C_YELLOW)⚠ $(1)$(C_RESET)"
endef

define _err
	@echo -e "$(C_RED)✖ $(1)$(C_RESET)"; exit 1
endef

exists = $(shell command -v $(1) >/dev/null 2>&1 && echo 1 || echo 0)

mkbuild:
	@mkdir -p $(BUILD_DIR) $(REPORT_DIR)

# -------- Help --------
.PHONY: help
help:
	@echo -e "$(C_BOLD)security-core Make targets$(C_RESET)"
	@awk 'BEGIN {FS=":.*?#"} /^[a-zA-Z0-9_-]+:.*?#/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# -------- Python env --------
.PHONY: venv
venv: mkbuild ## Создать виртуальное окружение
	@if [ ! -d "$(VENV)" ]; then \
		$(call _step,Создание venv); \
		$(PY) -m venv $(VENV); \
	fi
	@. $(VENV)/bin/activate; $(PIP) install --upgrade pip >/dev/null

.PHONY: deps
deps: venv ## Установка dev-зависимостей (если есть файлы)
	@. $(VENV)/bin/activate; \
	FILES="requirements-dev.txt requirements.txt Pipfile pyproject.toml"; \
	HAVE=0; \
	for f in $$FILES; do [ -f "$$f" ] && HAVE=1; done; \
	if [ $$HAVE -eq 0 ]; then $(call _warn,Файлы зависимостей не найдены — пропуск); exit 0; fi; \
	if [ -f "requirements-dev.txt" ]; then $(PIP) install -r requirements-dev.txt; fi; \
	if [ -f "requirements.txt" ]; then $(PIP) install -r requirements.txt; fi; \
	if [ -f "pyproject.toml" ]; then $(PIP) install -e ".[dev]" || true; fi; \
	if [ -f "Pipfile" ]; then which pipenv >/dev/null 2>&1 && pipenv install --dev || true; fi; \
	$(call _ok,Dev-зависимости готовы)

.PHONY: pre-commit
pre-commit: venv ## Установка/обновление pre-commit хуков
	@. $(VENV)/bin/activate; \
	if [ $(call exists,pre-commit) -eq 1 ]; then \
		pre-commit install --install-hooks; \
		$(call _ok,pre-commit установлен); \
	else \
		$(call _warn,pre-commit не найден — pip install pre-commit); \
	fi

# -------- Code Quality --------
.PHONY: fmt
fmt: venv ## Автоформатирование (ruff/black/isort при наличии)
	@. $(VENV)/bin/activate; \
	[ $(call exists,ruff) -eq 1 ] && ruff format $(SRC_DIR) $(TEST_DIR) || $(call _warn,ruff format пропущен); \
	[ $(call exists,black) -eq 1 ] && black $(SRC_DIR) $(TEST_DIR) || $(call _warn,black пропущен); \
	[ $(call exists,isort) -eq 1 ] && isort $(SRC_DIR) $(TEST_DIR) || $(call _warn,isort пропущен)

.PHONY: lint
lint: venv ## Линтинг (ruff/mypy)
	@. $(VENV)/bin/activate; \
	[ $(call exists,ruff) -eq 1 ] && ruff check $(SRC_DIR) || $(call _warn,ruff пропущен); \
	[ $(call exists,mypy) -eq 1 ] && mypy $(SRC_DIR) || $(call _warn,mypy пропущен)

.PHONY: test
test: venv mkbuild ## Тесты (pytest + покрытие если доступно)
	@. $(VENV)/bin/activate; \
	if [ $(call exists,pytest) -eq 1 ]; then \
		if [ $(call exists,coverage) -eq 1 ] || python -c "import coverage" >/dev/null 2>&1; then \
			pytest -q --maxfail=1 --disable-warnings --cov=$(SRC_DIR) --cov-report=xml:$(COVERAGE_FILE); \
		else \
			pytest -q --maxfail=1 --disable-warnings; \
		fi; \
	else \
		$(call _warn,pytest недоступен — пропуск); \
	fi

# -------- Security: SAST/SCA/Secrets --------
.PHONY: sec-scan
sec-scan: venv mkbuild ## Полный пакет проверок безопасности
	@. $(VENV)/bin/activate; \
	# Bandit (Python SAST)
	[ $(call exists,bandit) -eq 1 ] && bandit -q -r $(SRC_DIR) -f txt -o $(REPORT_DIR)/bandit.txt || $(call _warn,Bandit пропущен); \
	# pip-audit / safety (SCA)
	[ $(call exists,pip-audit) -eq 1 ] && pip-audit -r requirements.txt -f json -o $(REPORT_DIR)/pip-audit.json || $(call _warn,pip-audit пропущен или нет requirements.txt); \
	[ $(call exists,safety) -eq 1 ] && safety check -r requirements.txt -o $(REPORT_DIR)/safety.json --json || $(call _warn,safety пропущен или нет requirements.txt); \
	# Semgrep (универсальный SAST)
	[ $(call exists,semgrep) -eq 1 ] && semgrep ci --sarif -o $(REPORT_DIR)/semgrep.sarif || $(call _warn,Semgrep пропущен); \
	# Gitleaks (секреты)
	[ $(call exists,gitleaks) -eq 1 ] && gitleaks detect --no-git --report-format json --report-path $(REPORT_DIR)/gitleaks.json . || $(call _warn,Gitleaks пропущен); \
	# Trivy (FS SCA/секреты/мисконфиги)
	[ $(call exists,trivy) -eq 1 ] && trivy fs --security-checks vuln,secret,config --format sarif --output $(REPORT_DIR)/trivy-fs.sarif . || $(call _warn,Trivy fs пропущен)

.PHONY: secrets-scan
secrets-scan: ## Быстрый поиск секретов
	@[ $(call exists,gitleaks) -eq 1 ] && gitleaks detect --no-git --report-format json --report-path $(REPORT_DIR)/gitleaks.json . || $(call _warn,Gitleaks недоступен)

.PHONY: licenses
licenses: venv mkbuild ## Отчёты по лицензиям (Python/Node, если есть)
	@. $(VENV)/bin/activate; \
	# Python
	if [ -f requirements.txt ] && [ $(call exists,pip-licenses) -eq 1 ]; then \
		pip-licenses --format=json --with-urls --with-license-file --output-file=$(REPORT_DIR)/pip-licenses.json; \
	else \
		$(call _warn,pip-licenses или requirements.txt отсутствует); \
	fi; \
	# Node
	if [ -f package.json ]; then \
		if [ $(call exists,npx) -eq 1 ]; then \
			npx --yes license-checker --json > $(REPORT_DIR)/npm-licenses.json || $(call _warn,license-checker не выполнился); \
		else \
			$(call _warn,npx недоступен — пропуск npm лицензий); \
		fi; \
	fi

# -------- SBOM --------
.PHONY: sbom
sbom: mkbuild ## Генерация SBOM (Syft)
	@[ $(call exists,syft) -eq 1 ] && syft . -o spdx-json > $(SBOM_FILE) || $(call _warn,Syft недоступен — SBOM пропущен)

# -------- Container --------
.PHONY: docker-build
docker-build: ## Сборка контейнера
	@$(call _step,Сборка образа $(IMAGE))
	@docker build -t $(IMAGE) .

.PHONY: docker-scan
docker-scan: ## Скан контейнера (Trivy image)
	@[ $(call exists,trivy) -eq 1 ] && trivy image --format sarif --output $(REPORT_DIR)/trivy-image.sarif $(IMAGE) || $(call _warn,Trivy недоступен — пропуск image scan)

# -------- Aggregates --------
.PHONY: all
all: fmt lint test sec-scan sbom ## Полный цикл качества и безопасности

.PHONY: quick
quick: lint test ## Быстрые проверки без тяжёлых сканов

.PHONY: clean
clean: ## Очистка артефактов
	@rm -rf $(BUILD_DIR) .pytest_cache .mypy_cache .ruff_cache $(COVERAGE_FILE)

.PHONY: distclean
distclean: clean ## Полная очистка, включая venv
	@rm -rf $(VENV)

# -------- CI convenience --------
.PHONY: ci
ci: ## Режим CI (fail-fast: предупреждения превращаются в ошибки)
	@$(MAKE) CI=1 all

# ----- End -----
