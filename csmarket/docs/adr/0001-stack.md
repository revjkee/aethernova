# 0001-stack
# ADR-0001: Stack (csmarket)

Status: Accepted
Date: 2026-02-13
Owners: csmarket core team

## Context

csmarket требует серверный стек, который одновременно:
- поддерживает высокую параллельность ввода-вывода и сетевые интеграции
- обеспечивает строгую типизацию и предсказуемость контрактов API
- имеет зрелую экосистему для миграций схемы, тестирования и статического анализа
- разворачивается воспроизводимо (локально, CI, staging, production)
- допускает разделение API и фоновых задач (worker) с общей кодовой базой

Проверяемые первичные источники по ключевым требованиям и компонентам:
- ASGI и модель асинхронных приложений в Starlette (базовый слой FastAPI): https://www.starlette.io/
- FastAPI (архитектура, зависимостная инъекция, ASGI): https://fastapi.tiangolo.com/
- SQLAlchemy AsyncIO (официальная документация): https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- asyncpg (драйвер PostgreSQL для asyncio): https://magicstack.github.io/asyncpg/current/
- Alembic (миграции SQLAlchemy): https://alembic.sqlalchemy.org/
- PostgreSQL (официальная документация): https://www.postgresql.org/docs/
- Redis (официальная документация): https://redis.io/docs/
- Docker Compose Specification: https://compose-spec.io/
- Nginx (официальная документация): https://nginx.org/en/docs/
- OpenTelemetry (спецификации и SDK): https://opentelemetry.io/docs/
- Prometheus (экспозиция метрик и модель мониторинга): https://prometheus.io/docs/introduction/overview/

## Decision

Выбираем следующий промышленный стек для csmarket:

### Runtime и API
- Python 3.12 (runtime)
- FastAPI как web framework (ASGI)
- Uvicorn как ASGI server

Sources:
- FastAPI docs: https://fastapi.tiangolo.com/
- Uvicorn docs: https://www.uvicorn.org/
- Python 3.12 docs: https://docs.python.org/3.12/

### Data layer
- PostgreSQL как основная реляционная база данных
- SQLAlchemy 2.x (AsyncIO) как ORM и слой доступа к данным
- asyncpg как драйвер PostgreSQL
- Alembic для миграций схемы

Sources:
- PostgreSQL docs: https://www.postgresql.org/docs/
- SQLAlchemy AsyncIO docs: https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- asyncpg docs: https://magicstack.github.io/asyncpg/current/
- Alembic docs: https://alembic.sqlalchemy.org/

### Cache и очереди
- Redis как кеш и инфраструктурный брокер для фоновых задач (по потребности проекта)

Sources:
- Redis docs: https://redis.io/docs/

### Reverse proxy и edge
- Nginx как reverse proxy перед API (TLS termination, buffering, rate limiting по мере необходимости)

Sources:
- Nginx docs: https://nginx.org/en/docs/

### Observability
- OpenTelemetry для трассировки и метрик
- Prometheus модель для сбора метрик (экспонирование /metrics)

Sources:
- OpenTelemetry docs: https://opentelemetry.io/docs/
- Prometheus docs: https://prometheus.io/docs/introduction/overview/

### Quality gates
- pytest для тестирования
- ruff для линтинга и автоформата
- mypy для статической типизации

Sources:
- pytest docs: https://docs.pytest.org/
- ruff docs: https://docs.astral.sh/ruff/
- mypy docs: https://mypy.readthedocs.io/

### Packaging и delivery
- Docker для контейнеризации
- Docker Compose для локального/CI оркестрирования сервисов

Sources:
- Docker docs: https://docs.docker.com/
- Compose spec: https://compose-spec.io/

### Non-goals (явные границы)
- Kubernetes не является обязательным для MVP и не фиксируется в данном ADR
- Выделенный сервисный mesh не фиксируется в данном ADR
- Мульти-региональная репликация БД не фиксируется в данном ADR

Не могу подтвердить это для конкретного репозитория без просмотра ваших файлов инфраструктуры и окружений, поэтому границы выше заданы как решение данного ADR, а не как утверждение о текущем состоянии проекта.

## Consequences

### Positive
- ASGI и async stack масштабируются под I/O-нагрузку без увеличения числа процессов пропорционально запросам
- SQLAlchemy AsyncIO и Alembic дают единый контроль схемы и транзакций
- PostgreSQL обеспечивает зрелые транзакции и индексацию под торговые и маркетплейсные сценарии
- Compose позволяет воспроизводимо поднимать одинаковое окружение локально и в CI
- OpenTelemetry и Prometheus задают стандарт наблюдаемости, переносимый между средами

Источники по базовым возможностям:
- ASGI ecosystem (Starlette): https://www.starlette.io/
- SQLAlchemy AsyncIO: https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- Alembic migrations: https://alembic.sqlalchemy.org/
- Compose spec: https://compose-spec.io/
- OpenTelemetry: https://opentelemetry.io/docs/
- Prometheus: https://prometheus.io/docs/introduction/overview/

### Negative
- Async требует дисциплины в работе с блокирующими операциями и библиотеками
- ORM добавляет абстракцию, которую нужно контролировать профилированием запросов
- Redis как компонент добавляет операционные риски (память, persistence режимы)
- Nginx конфигурация требует явного сопровождения и тестирования

Не могу подтвердить это в контексте ваших конкретных нагрузочных профилей без замеров и профилирования в вашем окружении.

## Alternatives Considered

1) Django + DRF
- Отклонено для данного ADR как базовый API-стек, так как принято решение фиксировать ASGI-ориентированную архитектуру вокруг FastAPI.
Source:
- Django docs: https://docs.djangoproject.com/

2) Flask
- Отклонено как базовый стек, так как принято решение фиксировать ASGI-стек и встроенную типизацию контрактов FastAPI.
Source:
- Flask docs: https://flask.palletsprojects.com/

3) MongoDB как primary storage
- Отклонено как primary storage в базовом ADR; csmarket фиксирует PostgreSQL как основное транзакционное хранилище.
Sources:
- PostgreSQL docs: https://www.postgresql.org/docs/
- MongoDB docs: https://www.mongodb.com/docs/

## Decision Record

We standardize csmarket on:
- FastAPI (ASGI) + Uvicorn
- PostgreSQL + SQLAlchemy AsyncIO + asyncpg + Alembic
- Redis (cache / infra)
- Nginx (edge)
- OpenTelemetry + Prometheus (observability)
- pytest + ruff + mypy (quality)
- Docker + Compose (delivery)

## References

All links in this ADR point to official primary documentation:
- https://fastapi.tiangolo.com/
- https://www.starlette.io/
- https://www.uvicorn.org/
- https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- https://magicstack.github.io/asyncpg/current/
- https://alembic.sqlalchemy.org/
- https://www.postgresql.org/docs/
- https://redis.io/docs/
- https://nginx.org/en/docs/
- https://compose-spec.io/
- https://docs.docker.com/
- https://opentelemetry.io/docs/
- https://prometheus.io/docs/introduction/overview/
- https://docs.pytest.org/
- https://docs.astral.sh/ruff/
- https://mypy.readthedocs.io/
- https://docs.djangoproject.com/
- https://flask.palletsprojects.com/
- https://www.mongodb.com/docs/
