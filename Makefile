.PHONY: help setup-dev install-deps install-frontend audit test test-unit test-integration \
	lint format format-check type-check security-scan run migrate build docker-up docker-down \
	monitoring-start clean pre-commit ci-local

PYTHON ?= python
COMPOSE ?= docker compose
BACKEND_PATHS := backend/src backend/tests

help:
	@echo "Aethernova development commands"
	@echo "  setup-dev         Install Python and frontend dependencies"
	@echo "  audit             Run repository contract checks"
	@echo "  test              Run backend and repository tests"
	@echo "  lint              Run flake8 on maintained Python paths"
	@echo "  format-check      Check Black formatting"
	@echo "  type-check        Run mypy on the backend"
	@echo "  build             Build backend and frontend containers"
	@echo "  docker-up         Start the local stack"
	@echo "  monitoring-start  Start Prometheus and Grafana"

setup-dev: install-deps install-frontend
	$(PYTHON) -m pre_commit install

install-deps:
	$(PYTHON) -m pip install -r requirements-dev.txt

install-frontend:
	npm --prefix frontend ci

audit:
	$(PYTHON) tools/repository_audit.py
	$(COMPOSE) config --quiet

test:
	$(PYTHON) -m pytest tests backend/tests

test-unit:
	$(PYTHON) -m pytest backend/tests/unit

test-integration:
	$(PYTHON) -m pytest tests/integration backend/tests/integration

lint:
	$(PYTHON) -m flake8 $(BACKEND_PATHS)

format:
	$(PYTHON) -m black $(BACKEND_PATHS) tools tests

format-check:
	$(PYTHON) -m black --check $(BACKEND_PATHS) tools tests

type-check:
	$(PYTHON) -m mypy backend/src --ignore-missing-imports

security-scan:
	$(PYTHON) -m bandit -q -r backend/src

run:
	$(PYTHON) -m uvicorn backend.src.main:app --reload --host 0.0.0.0 --port 8000

migrate:
	$(PYTHON) -m alembic -c backend/alembic.ini upgrade head

build:
	$(COMPOSE) build backend frontend

docker-up:
	$(COMPOSE) up -d

docker-down:
	$(COMPOSE) down

monitoring-start:
	$(COMPOSE) up -d prometheus grafana

pre-commit:
	$(PYTHON) -m pre_commit run --all-files

ci-local: audit format-check lint type-check test-unit

clean:
	$(PYTHON) -c "import pathlib,shutil; [shutil.rmtree(p,ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]; [p.unlink(missing_ok=True) for p in pathlib.Path('.').rglob('*.pyc')]; [shutil.rmtree(pathlib.Path(p),ignore_errors=True) for p in ('.pytest_cache','.mypy_cache','.ruff_cache','htmlcov','reports')]"
