# Makefile для orchestrator

.PHONY: all build test lint clean deploy help

# Переменные
APP_NAME := teslaai-orchestrator
BUILD_DIR := build
SRC_DIR := src

# Основная задача — сборка
all: build

# Сборка проекта (предполагается, что используется Docker)
build:
	@echo "Сборка Docker образа $(APP_NAME)..."
	docker build -t $(APP_NAME):latest .

# Запуск линтинга кода (например, flake8 для Python)
lint:
	@echo "Запуск линтинга кода..."
	flake8 $(SRC_DIR)

# Запуск тестов (pytest)
test:
	@echo "Запуск тестов..."
	pytest $(SRC_DIR)/tests

# Очистка временных и билд-артефактов
clean:
	@echo "Очистка проекта..."
	rm -rf $(BUILD_DIR)
	docker rmi -f $(APP_NAME):latest || true

# Деплой (примитивный, можно расширить под CI/CD)
deploy: build
	@echo "Деплой образа $(APP_NAME) на сервер..."
	docker tag $(APP_NAME):latest registry.example.com/$(APP_NAME):latest
	docker push registry.example.com/$(APP_NAME):latest

# Помощь — описание доступных команд
help:
	@echo "Доступные команды Makefile:"
	@echo "  make build   - Сборка Docker образа"
	@echo "  make lint    - Проверка кода линтером"
	@echo "  make test    - Запуск тестов"
	@echo "  make clean   - Очистка артефактов и образов"
	@echo "  make deploy  - Сборка и отправка образа в registry"
	@echo "  make help    - Показать это сообщение"
