# Makefile для управления системой улучшенных AI агентов

# Переменные
PYTHON = python3
VENV = venv
VENV_BIN = $(VENV)/bin
CONFIG_FILE = agent_mash/config/enhanced_agents_config.json
LOG_LEVEL = INFO

# Цвета для вывода
BLUE = \033[0;34m
GREEN = \033[0;32m
YELLOW = \033[0;33m
RED = \033[0;31m
NC = \033[0m # No Color

.PHONY: help install setup test demo clean lint format run-* benchmark

help: ## Показать справку
	@echo "$(BLUE)Система управления улучшенными AI агентами$(NC)"
	@echo ""
	@echo "$(GREEN)Доступные команды:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Установка зависимостей
	@echo "$(BLUE)Установка зависимостей...$(NC)"
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -r requirements-dev.txt
	@echo "$(GREEN)✅ Зависимости установлены$(NC)"

setup: install ## Полная настройка проекта
	@echo "$(BLUE)Настройка проекта...$(NC)"
	mkdir -p logs
	mkdir -p agent_mash/config
	mkdir -p agent_mash/tests
	mkdir -p agent_mash/examples
	mkdir -p agent_mash/scripts
	@echo "$(GREEN)✅ Проект настроен$(NC)"

test: ## Запуск всех тестов
	@echo "$(BLUE)Запуск тестов...$(NC)"
	$(PYTHON) -m pytest agent_mash/tests/ -v --tb=short --color=yes
	@echo "$(GREEN)✅ Тесты завершены$(NC)"

test-unit: ## Запуск только unit тестов
	@echo "$(BLUE)Запуск unit тестов...$(NC)"
	$(PYTHON) -m pytest agent_mash/tests/test_enhanced_agents.py::TestAdvancedDataProcessor -v
	$(PYTHON) -m pytest agent_mash/tests/test_enhanced_agents.py::TestDecisionEngine -v
	$(PYTHON) -m pytest agent_mash/tests/test_enhanced_agents.py::TestExternalAPIIntegration -v

test-integration: ## Запуск интеграционных тестов
	@echo "$(BLUE)Запуск интеграционных тестов...$(NC)"
	$(PYTHON) -m pytest agent_mash/tests/test_enhanced_agents.py::TestIntegration -v

test-agents: ## Тестирование агентов
	@echo "$(BLUE)Тестирование агентов...$(NC)"
	$(PYTHON) -m pytest agent_mash/tests/test_enhanced_agents.py::TestEnhancedBaseAgent -v
	$(PYTHON) -m pytest agent_mash/tests/test_enhanced_agents.py::TestAgentOrchestra -v

demo: ## Запуск полной демонстрации
	@echo "$(BLUE)Запуск демонстрации системы...$(NC)"
	cd agent_mash && $(PYTHON) -m examples.enhanced_agents_demo
	@echo "$(GREEN)✅ Демонстрация завершена$(NC)"

run-demo: ## Запуск через скрипт управления (demo режим)
	@echo "$(BLUE)Запуск demo режима...$(NC)"
	$(PYTHON) agent_mash/scripts/run_enhanced_agents.py demo --log-level $(LOG_LEVEL)

run-interactive: ## Интерактивный режим
	@echo "$(BLUE)Запуск интерактивного режима...$(NC)"
	$(PYTHON) agent_mash/scripts/run_enhanced_agents.py interactive \
		--config $(CONFIG_FILE) --log-level $(LOG_LEVEL)

run-production: ## Продакшн режим
	@echo "$(BLUE)Запуск продакшн режима...$(NC)"
	$(PYTHON) agent_mash/scripts/run_enhanced_agents.py production \
		--config $(CONFIG_FILE) --log-level $(LOG_LEVEL) --log-file logs/production.log

run-distributed: ## Распределенный режим
	@echo "$(BLUE)Запуск в распределенном режиме...$(NC)"
	$(PYTHON) agent_mash/scripts/run_enhanced_agents.py production \
		--config $(CONFIG_FILE) --distributed --log-level $(LOG_LEVEL)

benchmark: ## Запуск бенчмарка производительности
	@echo "$(BLUE)Запуск бенчмарка...$(NC)"
	$(PYTHON) agent_mash/scripts/run_enhanced_agents.py benchmark \
		--config $(CONFIG_FILE) --log-level INFO --log-file logs/benchmark.log
	@echo "$(GREEN)✅ Бенчмарк завершен$(NC)"

quick-test-data: ## Быстрый тест обработки данных
	@echo "$(BLUE)Быстрый тест обработки данных...$(NC)"
	cd agent_mash && $(PYTHON) -c "
import asyncio
from examples.enhanced_agents_demo import quick_data_processing_demo
asyncio.run(quick_data_processing_demo())
"

quick-test-decisions: ## Быстрый тест принятия решений
	@echo "$(BLUE)Быстрый тест принятия решений...$(NC)"
	cd agent_mash && $(PYTHON) -c "
import asyncio
from examples.enhanced_agents_demo import quick_decision_demo
asyncio.run(quick_decision_demo())
"

lint: ## Проверка кода линтерами
	@echo "$(BLUE)Проверка кода линтерами...$(NC)"
	$(PYTHON) -m flake8 agent_mash/ --max-line-length=120 --ignore=E501,W503,E203
	$(PYTHON) -m pylint agent_mash/ --disable=C0114,C0115,C0116,R0903,R0902,R0801 || true
	@echo "$(GREEN)✅ Проверка линтерами завершена$(NC)"

format: ## Форматирование кода
	@echo "$(BLUE)Форматирование кода...$(NC)"
	$(PYTHON) -m black agent_mash/ --line-length=120
	$(PYTHON) -m isort agent_mash/ --profile black
	@echo "$(GREEN)✅ Код отформатирован$(NC)"

check-deps: ## Проверка зависимостей
	@echo "$(BLUE)Проверка зависимостей...$(NC)"
	$(PYTHON) -m pip check
	$(PYTHON) -m pip list --outdated
	@echo "$(GREEN)✅ Проверка зависимостей завершена$(NC)"

logs: ## Просмотр последних логов
	@echo "$(BLUE)Последние логи системы:$(NC)"
	@if [ -f logs/production.log ]; then \
		tail -n 50 logs/production.log; \
	else \
		echo "$(YELLOW)Логи не найдены. Запустите систему в продакшн режиме.$(NC)"; \
	fi

logs-follow: ## Мониторинг логов в реальном времени
	@echo "$(BLUE)Мониторинг логов (Ctrl+C для выхода):$(NC)"
	@if [ -f logs/production.log ]; then \
		tail -f logs/production.log; \
	else \
		echo "$(YELLOW)Логи не найдены. Запустите систему в продакшн режиме.$(NC)"; \
	fi

status: ## Статус системы (проверка процессов)
	@echo "$(BLUE)Статус системы:$(NC)"
	@ps aux | grep -E "(enhanced_agents|agent_mash)" | grep -v grep || echo "$(YELLOW)Процессы агентов не найдены$(NC)"
	@echo ""
	@echo "$(BLUE)Размер логов:$(NC)"
	@du -h logs/ 2>/dev/null || echo "$(YELLOW)Директория логов не найдена$(NC)"

clean: ## Очистка временных файлов
	@echo "$(BLUE)Очистка временных файлов...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.log" -size +100M -delete 2>/dev/null || true
	rm -rf .pytest_cache/
	rm -rf .coverage
	@echo "$(GREEN)✅ Очистка завершена$(NC)"

clean-logs: ## Очистка всех логов
	@echo "$(BLUE)Очистка логов...$(NC)"
	rm -rf logs/*.log
	@echo "$(GREEN)✅ Логи очищены$(NC)"

install-dev: ## Установка в dev режиме
	@echo "$(BLUE)Установка в режиме разработки...$(NC)"
	$(PYTHON) -m pip install -e .
	@echo "$(GREEN)✅ Установка в dev режиме завершена$(NC)"

docker-build: ## Сборка Docker образа
	@echo "$(BLUE)Сборка Docker образа...$(NC)"
	docker build -t enhanced-agents .
	@echo "$(GREEN)✅ Docker образ собран$(NC)"

docker-run: ## Запуск в Docker контейнере
	@echo "$(BLUE)Запуск в Docker...$(NC)"
	docker run --rm -it \
		-v $(PWD)/logs:/app/logs \
		-v $(PWD)/agent_mash/config:/app/agent_mash/config \
		enhanced-agents demo
	@echo "$(GREEN)✅ Docker контейнер завершен$(NC)"

# Цели для CI/CD
ci-test: install test lint ## CI: полная проверка кода
	@echo "$(GREEN)✅ CI тесты пройдены$(NC)"

ci-build: install test benchmark ## CI: сборка и тестирование производительности
	@echo "$(GREEN)✅ CI сборка завершена$(NC)"

# Мониторинг и отладка
monitor: ## Мониторинг системных ресурсов
	@echo "$(BLUE)Мониторинг системы (Ctrl+C для выхода):$(NC)"
	@while true; do \
		echo "$(YELLOW)$(shell date): CPU: $(shell ps -eo pcpu | awk '{sum += $$1} END {print sum}')% | RAM: $(shell free -m | awk '/^Mem:/{printf "%.1f%%", $$3/$$2*100}')$(NC)"; \
		sleep 5; \
	done

debug-config: ## Проверка конфигурации
	@echo "$(BLUE)Проверка конфигурации:$(NC)"
	@if [ -f $(CONFIG_FILE) ]; then \
		$(PYTHON) -m json.tool $(CONFIG_FILE) > /dev/null && echo "$(GREEN)✅ Конфигурация валидна$(NC)" || echo "$(RED)❌ Ошибка в конфигурации$(NC)"; \
	else \
		echo "$(YELLOW)⚠️  Файл конфигурации не найден: $(CONFIG_FILE)$(NC)"; \
	fi

debug-imports: ## Проверка импортов
	@echo "$(BLUE)Проверка импортов...$(NC)"
	$(PYTHON) -c "
try:
    from agent_mash.core.enhanced_base_agent import create_chatbot_agent
    from agent_mash.core.agent_orchestra import create_simple_orchestra
    from agent_mash.core.advanced_data_processor import AdvancedDataProcessor
    from agent_mash.core.decision_engine import AdvancedDecisionEngine
    from agent_mash.core.external_api_integration import ExternalAPIManager
    print('$(GREEN)✅ Все модули импортируются успешно$(NC)')
except Exception as e:
    print('$(RED)❌ Ошибка импорта:$(NC)', e)
"

# Документация
docs: ## Генерация документации
	@echo "$(BLUE)Генерация документации...$(NC)"
	$(PYTHON) -c "
import agent_mash.core.enhanced_base_agent as eba
import agent_mash.core.agent_orchestra as ao
print('=== ENHANCED BASE AGENT ===')
print(eba.EnhancedBaseAgent.__doc__)
print('\n=== AGENT ORCHESTRA ===') 
print(ao.AgentOrchestra.__doc__)
"
	@echo "$(GREEN)✅ Документация сгенерирована$(NC)"

example-config: ## Создание примера конфигурации
	@echo "$(BLUE)Создание примера конфигурации...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "$(YELLOW)Создаю пример конфигурации в $(CONFIG_FILE)$(NC)"; \
		cp agent_mash/config/enhanced_agents_config.json $(CONFIG_FILE); \
	else \
		echo "$(GREEN)Конфигурация уже существует: $(CONFIG_FILE)$(NC)"; \
	fi

# Информация о системе
info: ## Информация о системе и проекте
	@echo "$(BLUE)=== ИНФОРМАЦИЯ О СИСТЕМЕ ===$(NC)"
	@echo "$(YELLOW)Python версия:$(NC) $(shell $(PYTHON) --version)"
	@echo "$(YELLOW)Рабочая директория:$(NC) $(PWD)"
	@echo "$(YELLOW)Конфигурация:$(NC) $(CONFIG_FILE)"
	@echo "$(YELLOW)Логи:$(NC) logs/"
	@echo ""
	@echo "$(BLUE)=== СТРУКТУРА ПРОЕКТА ===$(NC)"
	@tree agent_mash/ -L 2 2>/dev/null || find agent_mash/ -type d | head -20
	@echo ""
	@echo "$(BLUE)=== СТАТИСТИКА КОДА ===$(NC)"
	@echo "$(YELLOW)Python файлов:$(NC) $(shell find agent_mash/ -name '*.py' | wc -l)"
	@echo "$(YELLOW)Строк кода:$(NC) $(shell find agent_mash/ -name '*.py' -exec wc -l {} + | tail -1 | awk '{print $$1}')"

# Режимы разработки
dev-setup: setup install-dev ## Настройка среды разработки
	@echo "$(GREEN)✅ Среда разработки настроена$(NC)"

dev-test: format lint test ## Полная проверка для разработки
	@echo "$(GREEN)✅ Проверка разработки завершена$(NC)"

# По умолчанию показываем help
all: help