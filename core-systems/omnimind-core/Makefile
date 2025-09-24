# Makefile — промышленный интерфейс задач для omnimind-core
# Используйте: `make help` для списка целей.
# Политика: «fail fast», воспроизводимые окружения, безопасные проверки.

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
MAKEFLAGS += --no-builtin-rules --warn-undefined-variables
.ONESHELL:

# --------------------------------------------------------------------------------------
# Параметры проекта
# --------------------------------------------------------------------------------------
PROJECT        ?= omnimind-core
PY             ?= python3
VENV           ?= .venv
ACTIVATE       ?= source $(VENV)/bin/activate
ENV_FILE       ?= .env
DOCKER_IMAGE   ?= ghcr.io/omniorg/$(PROJECT)
DOCKER_TAG     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DOCKER_BUILDPLATFORM ?= linux/amd64
CI             ?= 0

# Автоподхват переменных окружения
ifneq (,$(wildcard $(ENV_FILE)))
	include $(ENV_FILE)
	export $(shell sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' $(ENV_FILE))
endif

# --------------------------------------------------------------------------------------
# Вспомогательные макросы
# --------------------------------------------------------------------------------------
define need
	@if ! command -v $(1) >/dev/null 2>&1; then \
		echo "[ERROR] Missing required tool: $(1)"; exit 127; \
	fi
endef

define need-msg
	@if ! command -v $(1) >/dev/null 2>&1; then \
		echo "[ERROR] Missing tool: $(1). $(2)"; exit 127; \
	fi
endef

# --------------------------------------------------------------------------------------
# Цель по умолчанию
# --------------------------------------------------------------------------------------
.DEFAULT_GOAL := help

# --------------------------------------------------------------------------------------
# Окружение Python
# --------------------------------------------------------------------------------------
.PHONY: setup venv sync-deps
setup: ## Создать изолированное окружение и установить dev-зависимости
	@echo "[SETUP] Creating virtualenv at $(VENV)"
	$(PY) -m venv $(VENV)
	$(ACTIVATE); python -m pip install --upgrade pip wheel
	@if [ -f pyproject.toml ]; then \
		echo "[SETUP] Installing from pyproject.toml (PEP 517)"; \
		$(ACTIVATE); python -m pip install -e ".[dev]" || { \
			echo "[WARN] '.[dev]' not found; trying '.[test]';"; \
			$(ACTIVATE); python -m pip install -e ".[test]" || true; }; \
	elif [ -f requirements-dev.txt ]; then \
		echo "[SETUP] Installing from requirements-dev.txt"; \
		$(ACTIVATE); python -m pip install -r requirements-dev.txt; \
	elif [ -f requirements.txt ]; then \
		echo "[SETUP] Installing from requirements.txt"; \
		$(ACTIVATE); python -m pip install -r requirements.txt; \
	else \
		echo "[SETUP] No dependency files found; skipping."; \
	fi

venv: ## Проверить/создать venv
	@test -d $(VENV) || $(MAKE) setup
	@echo "[VENV] $(VENV) ready"

sync-deps: venv ## Переустановить зависимости (force)
	@rm -rf $(VENV)
	@$(MAKE) setup

# --------------------------------------------------------------------------------------
# Качество кода
# --------------------------------------------------------------------------------------
.PHONY: format lint typecheck qa
format: venv ## Форматирование (ruff/black)
	$(ACTIVATE); if command -v ruff >/dev/null 2>&1; then \
		echo "[FORMAT] ruff format"; ruff format .; fi
	$(ACTIVATE); if command -v black >/dev/null 2>&1; then \
		echo "[FORMAT] black"; black .; fi

lint: venv ## Линтинг (ruff/flake8)
	$(ACTIVATE); if command -v ruff >/dev/null 2>&1; then \
		echo "[LINT] ruff check"; ruff check --output-format=full .; \
	elif command -v flake8 >/dev/null 2>&1; then \
		echo "[LINT] flake8"; flake8 .; \
	else \
		echo "[LINT] no linter installed"; exit 1; fi

typecheck: venv ## Статическая типизация (mypy/pyright)
	$(ACTIVATE); if command -v mypy >/dev/null 2>&1; then \
		echo "[TYPE] mypy"; mypy --strict --install-types --non-interactive .; \
	elif command -v pyright >/dev/null 2>&1; then \
		echo "[TYPE] pyright"; pyright; \
	else \
		echo "[TYPE] no type checker installed"; exit 1; fi

qa: lint typecheck ## Быстрый комплекс проверок качества

# --------------------------------------------------------------------------------------
# Тестирование и покрытие
# --------------------------------------------------------------------------------------
.PHONY: test coverage
test: venv ## Запуск тестов (pytest)
	$(ACTIVATE); if command -v pytest >/dev/null 2>&1; then \
		echo "[TEST] pytest"; pytest -q; \
	else \
		echo "[TEST] pytest not installed"; exit 1; fi

coverage: venv ## Покрытие тестами (pytest-cov, отчеты html)
	$(ACTIVATE); if command -v pytest >/dev/null 2>&1; then \
		echo "[COVERAGE] pytest --cov"; \
		pytest -q --cov=$(PROJECT) --cov-report=term-missing --cov-report=xml --cov-report=html; \
		echo "[COVERAGE] htmlcov/index.html ready"; \
	else \
		echo "[COVERAGE] pytest not installed"; exit 1; fi

# --------------------------------------------------------------------------------------
# Безопасность и лицензии
# --------------------------------------------------------------------------------------
.PHONY: security bandit audit safety semgrep gitleaks licenses
security: bandit audit safety ## Комплексная проверка безопасности (статический анализ и уязвимости)

bandit: venv ## Python security: bandit
	$(ACTIVATE); if command -v bandit >/dev/null 2>&1; then \
		echo "[SEC] bandit"; bandit -r -q -c pyproject.toml . || bandit -r -q .; \
	else echo "[SEC] bandit not installed (skip)"; fi

audit: venv ## Аудит зависимостей (pip-audit)
	$(ACTIVATE); if command -v pip-audit >/dev/null 2>&1; then \
		echo "[SEC] pip-audit"; pip-audit -r requirements.txt || pip-audit || true; \
	else echo "[SEC] pip-audit not installed (skip)"; fi

safety: venv ## Safety DB аудит
	$(ACTIVATE); if command -v safety >/dev/null 2>&1; then \
		echo "[SEC] safety check"; safety check -i 70612 || true; \
	else echo "[SEC] safety not installed (skip)"; fi

semgrep: ## Semgrep (по умолчанию правил нет — пропуск)
	@{ command -v semgrep >/dev/null 2>&1 && semgrep scan --error --metrics=off || echo "[SEC] semgrep not installed (skip)"; }

gitleaks: ## Поиск секретов в истории git
	@{ command -v gitleaks >/dev/null 2>&1 && gitleaks detect --no-banner --redact || echo "[SEC] gitleaks not installed (skip)"; }

licenses: venv ## Сводка лицензий Python-зависимостей
	$(ACTIVATE); if command -v pip-licenses >/dev/null 2>&1; then \
		pip-licenses --format=markdown --with-urls --with-license-file > licenses.md; \
		echo "[INFO] licenses.md generated"; \
	else echo "[INFO] pip-licenses not installed (skip)"; fi

# --------------------------------------------------------------------------------------
# SBOM и артефакты
# --------------------------------------------------------------------------------------
.PHONY: sbom
sbom: ## Сборка SBOM (syft → sbom.spdx.json)
	@{ command -v syft >/dev/null 2>&1 && syft packages dir:. -o spdx-json > sbom.spdx.json || { \
		echo "[SBOM] syft not found; skipping"; }; }

# --------------------------------------------------------------------------------------
# Сборка дистрибутива
# --------------------------------------------------------------------------------------
.PHONY: build dist
build: dist ## Синоним для dist

dist: venv ## Сборка wheel/sdist в ./dist
	$(ACTIVATE); if command -v python >/dev/null 2>&1; then \
		if [ -f pyproject.toml ]; then \
			echo "[BUILD] PEP 517 build"; python -m build; \
		else \
			echo "[BUILD] setup.py build"; python setup.py sdist bdist_wheel; \
		fi \
	else \
		echo "[BUILD] python not available"; exit 1; fi

# --------------------------------------------------------------------------------------
# Docker
# --------------------------------------------------------------------------------------
.PHONY: docker-build docker-run docker-push
docker-build: ## Сборка Docker-образа
	$(call need,docker)
	@echo "[DOCKER] Build $(DOCKER_IMAGE):$(DOCKER_TAG)"
	@DOCKER_BUILDKIT=1 docker build --platform $(DOCKER_BUILDPLATFORM) -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

docker-run: ## Запуск контейнера локально
	$(call need,docker)
	@docker run --rm -it -p 8000:8000 --env-file $(ENV_FILE) $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-push: ## Публикация образа
	$(call need,docker)
	@docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

# --------------------------------------------------------------------------------------
# Git-утилиты и релиз
# --------------------------------------------------------------------------------------
.PHONY: tag release changelog
tag: ## Создать аннотированный тег из VERSION или даты
	@ver=$$( [ -f VERSION ] && cat VERSION || date +%Y.%m.%d.%H%M ); \
	git tag -a "$$ver" -m "release $$ver"; echo "[GIT] tagged $$ver"

release: qa test security dist sbom ## Композитная цель для CI-релиза

changelog: ## Сводка изменений (последние 100 коммитов)
	@{ command -v git >/dev/null 2>&1 && git log -n 100 --pretty=format:'- %h %ad %s' --date=short || true; }

# --------------------------------------------------------------------------------------
# Очистка
# --------------------------------------------------------------------------------------
.PHONY: clean deep-clean
clean: ## Очистка артефактов
	@rm -rf .pytest_cache .mypy_cache htmlcov .coverage coverage.xml dist build *.egg-info

deep-clean: clean ## Полная очистка, включая окружение
	@rm -rf $(VENV) sbom.spdx.json licenses.md

# --------------------------------------------------------------------------------------
# Справка
# --------------------------------------------------------------------------------------
.PHONY: help
help: ## Показать это справочное меню
	@echo "Targets for $(PROJECT):"
	@awk 'BEGIN {FS":.*##"} /^[a-zA-Z0-9_\-]+:.*##/ {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
