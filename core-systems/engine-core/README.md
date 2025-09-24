# engine-core

Core‑движок сервисной платформы: FastAPI + Typer CLI, структурированные логи, health/ready/metrics, конфигурация через Pydantic Settings и YAML, минимальная монетизация модулем `passive_revenue_core`.

- Язык: Python 3.11
- Лицензия: Apache‑2.0 (`LICENSE`)
- Версия: см. файл `VERSION` и `CHANGELOG.md`

## Содержание
- [Возможности](#возможности)
- [Быстрый старт](#быстрый-старт)
- [Запуск](#запуск)
- [Конфигурация](#конфигурация)
- [Качество и безопасность](#качество-и-безопасность)
- [Наблюдаемость](#наблюдаемость)
- [Контейнеры и DevContainer](#контейнеры-и-devcontainer)
- [CI/CD и релизы](#cicd-и-релизы)
- [API](#api)
- [Модуль пассивной монетизации](#модуль-пассивной-монетизации)
- [Структура репозитория](#структура-репозитория)
- [FAQ](#faq)

## Возможности
- HTTP‑приложение на FastAPI: `/healthz`, `/readyz`, `/metrics`.
- CLI (Typer): `engine-core serve|check|version`.
- Конфиги: `.env` + `configs/application.yaml` (+ `configs/passive_revenue.yaml`).
- Логи: `structlog` (JSON), корреляция trace/request id.
- Метрики: `prometheus-client`.
- Линт/формат: Ruff; типизация: mypy (strict); тесты: pytest + coverage.
- DevContainer и VS Code профили (запуск/отладка/тесты).
- Docker‑образ, k8s‑манифесты (шаблоны).
- Пассивные доходы (минимальная реклама, маркетплейс ассетов, перепродажа API‑лимитов, NFT‑пасс, ликвидность — интерфейсы и заглушки).

## Быстрый старт
```bash
# Требуется Python 3.11 и Poetry 1.8.x
python3.11 -m pip install --upgrade pip pipx
pipx install poetry==1.8.3

# Установка зависимостей (локальное .venv в корне)
poetry config virtualenvs.in-project true
poetry env use 3.11
poetry install

# Проверка и запуск
poetry run engine-core version
poetry run engine-core serve --host 0.0.0.0 --port 8000
# затем откройте http://localhost:8000/healthz
