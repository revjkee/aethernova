# Local Development Runbook

- Status: Active
- Last Updated: 2026-03-23
- Owners: Reva Studio Engineering
- Audience: Backend, Infra, QA, Product Engineering
- Scope: Local development environment for Reva Studio

## 1. Purpose

This runbook defines the standard local development workflow for Reva Studio.

It exists to ensure that every engineer uses the same baseline process for:

- bootstrapping the project;
- starting local dependencies;
- running the application in development mode;
- applying database migrations;
- executing tests;
- inspecting logs;
- recovering from common local failures.

This runbook is intentionally operational. It does not replace architecture ADRs or deployment documentation.

## 2. Source of truth

This runbook is aligned with official documentation for the main tooling used by the project:

- Docker Compose is used to define and run the local service stack.
- FastAPI application code is served through an ASGI server in development.
- Alembic is used to manage schema migrations.
- pytest is used to execute automated tests.

References:
- Docker Compose docs: https://docs.docker.com/compose/
- Docker Compose quickstart: https://docs.docker.com/compose/gettingstarted/
- Docker Compose startup order and healthchecks: https://docs.docker.com/compose/how-tos/startup-order/
- Compose file reference: https://docs.docker.com/reference/compose-file/
- FastAPI first steps: https://fastapi.tiangolo.com/tutorial/first-steps/
- FastAPI deployment manual server run: https://fastapi.tiangolo.com/deployment/manually/
- FastAPI deployment concepts: https://fastapi.tiangolo.com/deployment/concepts/
- Alembic tutorial: https://alembic.sqlalchemy.org/en/latest/tutorial.html
- Alembic autogenerate: https://alembic.sqlalchemy.org/en/latest/autogenerate.html
- Alembic commands API: https://alembic.sqlalchemy.org/en/latest/api/commands.html
- pytest usage: https://docs.pytest.org/en/stable/how-to/usage.html
- pytest getting started: https://docs.pytest.org/en/stable/getting-started.html

## 3. Local environment contract

The local development environment must satisfy these rules:

1. Application code runs in development mode.
2. Infrastructure dependencies run through Docker Compose unless explicitly documented otherwise.
3. Database schema changes are applied only through Alembic migrations.
4. Tests are executed with pytest.
5. Startup order for dependent services must rely on healthchecks where required.
6. Local changes must not depend on undocumented machine-specific state.

Rationale:
- Docker documents Compose as the tool for defining and running multi-container applications.
- Docker documents healthchecks and dependency ordering for startup sequencing.
- FastAPI documents local development server usage.
- Alembic documents migration-based schema management.
- pytest documents standard invocation and test discovery.

## 4. Repository assumptions

This runbook assumes the repository contains, at minimum, the following kinds of artifacts:

```text
reva-studio/
├── apps/
├── docs/
├── alembic/
├── tests/
├── docker-compose.yml
├── .env.example
├── pyproject.toml
└── alembic.ini