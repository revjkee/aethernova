# mythos-core/Makefile
# Самодокументируемый промышленный Makefile для проекта Mythos Core.
# Поддерживает: venv, зависимости, линт, типизацию, тесты, покрытие, билд wheel, docker buildx, релизные артефакты.

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

# -------------------------------
# Конфигурация (можно переопределять: make VAR=value)
# -------------------------------
PY              ?= python3
PIP             ?= pip3
VENV            ?= .venv
ACTIVATE        := . $(VENV)/bin/activate
SRC_DIR         ?= src
PKG             ?= mythos_core
TESTS_DIR       ?= tests
DIST_DIR        ?= dist
BUILD_DIR       ?= build
COVER_HTML_DIR  ?= htmlcov
COV_FAIL_UNDER  ?= 80
UV              ?= uv

# Docker
REGISTRY        ?=
IMAGE_NAME      ?= mythos-core
GIT_VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0)
IMAGE_TAG       ?= $(GIT_VERSION)
IMAGE           := $(if $(REGISTRY),$(REGISTRY)/,)$(IMAGE_NAME):$(IMAGE_TAG)

# Цвета
GREEN := \033[1;32m
BLUE  := \033[1;34m
RED   := \033[1;31m
NC    := \033[0m

# Подхватываем .env, если есть
ifneq (,$(wildcard .env))
include .env
export
endif

# Значение по умолчанию
.DEFAULT_GOAL := help

# -------------------------------
# Вспомогательные макросы/шаблоны
# -------------------------------
define _print_step
	@printf "$(BLUE)>>$(NC) %s\n" "$(1)"
endef

define _ensure_venv
	@if [ ! -d "$(VENV)" ]; then \
		$(call _print_step,Создаётся виртуальное окружение $(VENV)); \
		$(PY) -m venv "$(VENV)"; \
	fi
endef

define _pip_install
	$(ACTIVATE); \
	$(PIP) install -U pip wheel; \
	if [ -f requirements-dev.txt ]; then \
		$(PIP) install -r requirements-dev.txt; \
	elif [ -f requirements.txt ]; then \
		$(PIP) install -r requirements.txt; \
	elif [ -f pyproject.toml ]; then \
		# pyproject без менеджера — пробуем PEP 517/518
		$(PIP) install -e .; \
	else \
		echo "Не найдены requirements*.txt или pyproject.toml"; \
	fi
endef

define _cmd_or_skip
	if command -v $(1) >/dev/null 2>&1; then $(2); else echo "$(1) не установлен — пропуск"; fi
endef

# -------------------------------
# Цели
# -------------------------------

## help: Показать справку по целям
.PHONY: help
help:
	@echo "Цели Makefile (mythos-core):"
	@grep -E '^[a-zA-Z0-9_\-]+:.*?## ' $(lastword $(MAKEFILE_LIST)) | \
		awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

## setup: Создать venv и установить зависимости (requirements* или pyproject)
.PHONY: setup
setup:
	$(call _ensure_venv)
	$(call _print_step,Установка зависимостей)
	$(call _pip_install)
	@printf "$(GREEN)OK$(NC)\n"

## uv-setup: Создать venv через uv и установить зависимости быстрее (если доступен uv)
.PHONY: uv-setup
uv-setup:
	$(call _print_step,Проверка uv)
	@if command -v $(UV) >/dev/null 2>&1; then \
		$(UV) venv $(VENV); \
		. $(VENV)/bin/activate; \
		if [ -f requirements-dev.txt ]; then $(UV) pip install -r requirements-dev.txt; \
		elif [ -f requirements.txt ]; then $(UV) pip install -r requirements.txt; \
		elif [ -f pyproject.toml ]; then $(UV) pip install -e .; \
		fi; \
	else echo "uv не найден — используйте make setup"; exit 1; fi
	@printf "$(GREEN)OK$(NC)\n"

## fmt: Форматирование кода (ruff format) и сортировка импортов
.PHONY: fmt
fmt:
	$(call _ensure_venv)
	$(call _print_step,Форматирование кода)
	$(ACTIVATE); $(call _cmd_or_skip,ruff,ruff format $(SRC_DIR) $(TESTS_DIR))
	$(ACTIVATE); $(call _cmd_or_skip,ruff,ruff check --select I --fix $(SRC_DIR) $(TESTS_DIR))
	@printf "$(GREEN)OK$(NC)\n"

## lint: Линтинг (ruff) и статический анализ (опционально bandit)
.PHONY: lint
lint:
	$(call _ensure_venv)
	$(call _print_step,Линтинг)
	$(ACTIVATE); $(call _cmd_or_skip,ruff,ruff check $(SRC_DIR) $(TESTS_DIR))
	$(ACTIVATE); $(call _cmd_or_skip,bandit,bandit -q -r $(SRC_DIR) || true)
	@printf "$(GREEN)OK$(NC)\n"

## type: Проверка типов (mypy)
.PHONY: type
type:
	$(call _ensure_venv)
	$(call _print_step,Проверка типов)
	$(ACTIVATE); $(call _cmd_or_skip,mypy,mypy $(SRC_DIR) --install-types --non-interactive)
	@printf "$(GREEN)OK$(NC)\n"

## test: Юнит-тесты с покрытием (pytest + coverage XML/HTML)
.PHONY: test
test:
	$(call _ensure_venv)
	$(call _print_step,Запуск тестов)
	$(ACTIVATE); $(call _cmd_or_skip,pytest,pytest -q --maxfail=1 --disable-warnings --cov=$(PKG) --cov-report=term-missing --cov-report=xml --cov-report=html:$(COVER_HTML_DIR) $(TESTS_DIR))
	@if [ -f coverage.xml ]; then \
		$(call _print_step,Порог покрытия: $(COV_FAIL_UNDER)%); \
		python3 - <<'PY' ; \
import sys, xml.etree.ElementTree as ET; \
root=ET.parse('coverage.xml').getroot(); \
rate=float(root.get('line-rate','0')); \
pct=int(rate*100+0.5); \
print(f"Coverage: {pct}%"); \
sys.exit(0 if pct>=$(COV_FAIL_UNDER) else 1) \
PY \
	; fi

## clean: Очистить артефакты сборки/кэши
.PHONY: clean
clean:
	$(call _print_step,Очистка артефактов)
	rm -rf $(BUILD_DIR) $(DIST_DIR) $(COVER_HTML_DIR) .pytest_cache .mypy_cache *.egg-info coverage.xml .ruff_cache
	@find $(SRC_DIR) -name '__pycache__' -type d -prune -exec rm -rf {} +
	@printf "$(GREEN)OK$(NC)\n"

## dist: Сборка wheel/sdist (PEP 517)
.PHONY: dist
dist:
	$(call _ensure_venv)
	$(call _print_step,Сборка пакета)
	$(ACTIVATE); $(PY) -m pip install -U build
	$(ACTIVATE); $(PY) -m build --outdir $(DIST_DIR)
	@ls -l $(DIST_DIR)
	@printf "$(GREEN)OK$(NC)\n"

## run: Запуск основного модуля (если определён)
.PHONY: run
run:
	$(call _ensure_venv)
	$(call _print_step,Запуск $(PKG) как модуля)
	$(ACTIVATE); $(PY) -m $(PKG)

## ci: Полный цикл для CI (setup → fmt → lint → type → test → dist)
.PHONY: ci
ci: setup fmt lint type test dist

## docker-build: Сборка Docker-образа (buildx, многоарх при наличии)
.PHONY: docker-build
docker-build:
	$(call _print_step,Docker build $(IMAGE))
	@if command -v docker >/dev/null 2>&1; then \
		if docker buildx inspect >/dev/null 2>&1; then \
			docker buildx build --load -t $(IMAGE) . ; \
		else \
			docker build -t $(IMAGE) . ; \
		fi \
	else echo "docker не установлен"; exit 1; fi
	@printf "$(GREEN)OK$(NC)\n"

## docker-run: Запуск контейнера (локально)
.PHONY: docker-run
docker-run:
	$(call _print_step,Docker run $(IMAGE))
	@if command -v docker >/dev/null 2>&1; then \
		docker run --rm -it -p 8000:8000 $(IMAGE); \
	else echo "docker не установлен"; exit 1; fi

## docker-push: Публикация образа в реестр (требует REGISTRY)
.PHONY: docker-push
docker-push:
	@if [ -z "$(REGISTRY)" ]; then echo "REGISTRY не задан"; exit 1; fi
	$(call _print_step,Push $(IMAGE))
	@if command -v docker >/dev/null 2>&1; then docker push $(IMAGE); else echo "docker не установлен"; exit 1; fi

## venv: Только создание venv (без установки зависимостей)
.PHONY: venv
venv:
	$(call _ensure_venv)
	@printf "$(GREEN)OK$(NC)\n"

## freeze: Зафиксировать текущие зависимости в requirements.txt
.PHONY: freeze
freeze:
	$(call _ensure_venv)
	$(ACTIVATE); $(PIP) freeze | sed '/^pkg-resources==/d' > requirements.txt
	@printf "$(GREEN)OK$(NC)\n"
