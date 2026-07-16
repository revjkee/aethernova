# Reva Studio

Production-grade backend platform for beauty studio operations: bookings, staff scheduling, services catalog, loyalty, notifications, analytics, and Telegram bot automation.

## Overview

Reva Studio is a backend-centric platform designed for a beauty business with future SaaS scaling in mind. The repository is intended to support:

- appointment booking and rescheduling
- staff and schedule management
- services and pricing catalog
- loyalty and bonus logic
- notifications and reminders
- admin/API integration
- analytics and operational reporting
- Telegram bot workflows

The project is designed around a modular Python backend with clear separation of domain logic, application services, infrastructure adapters, and external interfaces.

## Status

Current status: active development

Repository maturity target:

- production-ready architecture
- reproducible local environment
- strict CI checks
- typed Python codebase
- controlled database migrations
- container-based development and deployment

## Core principles

- explicit boundaries between domain and infrastructure
- reproducible environments
- deterministic startup
- migration-first database changes
- configuration through environment variables
- observability by default
- secure defaults
- scalable repository structure

## Suggested stack

This README is prepared for the following production-oriented stack:

- Python 3.12+
- FastAPI for HTTP API
- aiogram 3 for Telegram bot
- PostgreSQL as the primary relational database
- Redis for caching, ephemeral state, throttling, and background coordination
- Alembic for schema migrations
- Docker Compose for local orchestration
- Pydantic v2 for settings and validation

## Repository structure

```text
reva-studio/
├── README.md
├── .env.example
├── .gitignore
├── pyproject.toml
├── uv.lock
├── docker-compose.yml
├── docker-compose.override.yml
├── Makefile
├── alembic.ini
├── alembic/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
├── app/
│   ├── main.py
│   ├── config/
│   │   ├── settings.py
│   │   └── logging.py
│   ├── api/
│   │   ├── deps.py
│   │   ├── errors.py
│   │   └── v1/
│   │       ├── router.py
│   │       ├── health.py
│   │       ├── bookings.py
│   │       ├── staff.py
│   │       ├── services.py
│   │       ├── loyalty.py
│   │       └── users.py
│   ├── bot/
│   │   ├── main.py
│   │   ├── routers/
│   │   ├── middlewares/
│   │   ├── filters/
│   │   ├── keyboards/
│   │   └── handlers/
│   ├── domain/
│   │   ├── bookings/
│   │   ├── staff/
│   │   ├── services/
│   │   ├── loyalty/
│   │   └── users/
│   ├── application/
│   │   ├── commands/
│   │   ├── queries/
│   │   ├── services/
│   │   └── dto/
│   ├── infrastructure/
│   │   ├── db/
│   │   │   ├── base.py
│   │   │   ├── models/
│   │   │   ├── repositories/
│   │   │   └── session.py
│   │   ├── redis/
│   │   ├── repositories/
│   │   ├── integrations/
│   │   └── tasks/
│   ├── schemas/
│   ├── common/
│   └── telemetry/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── scripts/
│   ├── dev/
│   ├── db/
│   └── ops/
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── bot.md
│   ├── deployment.md
│   └── adr/
└── deploy/
    ├── docker/
    ├── nginx/
    └── systemd/