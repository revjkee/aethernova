# Makefile для проекта my_telegram_bot
# Управление сборкой, запуском, миграциями, тестами и деплоем

.PHONY: help build up down migrate test lint clean

# Переменные
DOCKER_COMPOSE=docker-compose
API_SERVICE=api
BOT_SERVICE=bot
WORKER_SERVICE=worker

help:
	@echo "Доступные команды:"
	@echo "  build           - Собрать все Docker-образы"
	@echo "  up              - Запустить все контейнеры (api, bot, worker, БД и сервисы)"
	@echo "  down            - Остановить и удалить все контейнеры"
	@echo "  migrate         - Выполнить миграции базы данных"
	@echo "  test            - Запустить тесты pytest"
	@echo "  lint            - Проверить код линтерами (flake8, mypy)"
	@echo "  clean           - Очистить кэш и временные файлы"

build:
	@$(DOCKER_COMPOSE) build

up:
	@$(DOCKER_COMPOSE) up -d

down:
	@$(DOCKER_COMPOSE) down

migrate:
	@$(DOCKER_COMPOSE) run --rm $(API_SERVICE) alembic upgrade head

test:
	@$(DOCKER_COMPOSE) run --rm $(API_SERVICE) pytest --cov=backend tests/

lint:
	@$(DOCKER_COMPOSE) run --rm $(API_SERVICE) flake8 backend tests
	@$(DOCKER_COMPOSE) run --rm $(API_SERVICE) mypy backend

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf .mypy_cache
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info

