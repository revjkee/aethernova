# Makefile для проекта TeslaAI

.PHONY: help build test lint format clean run docker-up docker-down migrate

help:
	@echo "Makefile commands:"
	@echo "  build        - Собрать Docker образы"
	@echo "  test         - Запустить тесты проекта"
	@echo "  lint         - Запустить проверку стиля кода (flake8)"
	@echo "  format       - Отформатировать код (black)"
	@echo "  clean        - Очистить временные файлы и кэши"
	@echo "  run          - Запустить приложение локально"
	@echo "  docker-up    - Запустить контейнеры Docker"
	@echo "  docker-down  - Остановить контейнеры Docker"
	@echo "  migrate      - Применить миграции базы данных"

build:
	docker-compose build

test:
	pytest --maxfail=1 --disable-warnings -q

lint:
	flake8 src tests

format:
	black src tests

clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete

run:
	uvicorn src.main:app --reload

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

migrate:
	alembic upgrade head
