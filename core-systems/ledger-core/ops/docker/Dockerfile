# syntax=docker/dockerfile:1.7

#############################
# Builder stage: wheels/venv
#############################
FROM --platform=$BUILDPLATFORM python:3.11-slim AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG PIP_DISABLE_PIP_VERSION_CHECK=1
ARG PIP_ROOT_USER_ACTION=ignore
ARG UV_INDEX_URL
ARG UV_EXTRA_INDEX_URL

# Опциональные build-аргументы для детального контроля
ARG PROJECT_DIR=/app
ARG VENV_DIR=/opt/venv
ARG PIP_CACHE_DIR=/root/.cache/pip
ARG POETRY_VERSION=1.8.3

WORKDIR ${PROJECT_DIR}

# Базовые пакеты для сборки нативных колёс (минимум)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Создаём изолированный venv
RUN python -m venv ${VENV_DIR} && \
    ${VENV_DIR}/bin/python -m pip install -U pip wheel setuptools

# Поддержка альтернативного индекс‑репозитория через uv/pip (необязательно)
# При желании можно uncomment и установить uv:
# RUN ${VENV_DIR}/bin/python -m pip install uv

# Подготовка зависимостей:
# 1) Если есть requirements*.txt — используем их (стабильнее в CI).
# 2) Иначе — если есть poetry.lock/pyproject.toml — собираем export и ставим.
# 3) Иначе — если есть только pyproject.toml (PEP 621) — pip install .
# Все операции кэшируем.
RUN --mount=type=cache,target=${PIP_CACHE_DIR},sharing=locked \
    --mount=type=bind,source=requirements.txt,target=requirements.txt,ro \
    if [ -f requirements.txt ]; then \
      ${VENV_DIR}/bin/pip install -r requirements.txt; \
    else \
      echo "no requirements.txt" > /dev/null; \
    fi || true

RUN --mount=type=cache,target=${PIP_CACHE_DIR},sharing=locked \
    --mount=type=bind,source=requirements-dev.txt,target=requirements-dev.txt,ro \
    if [ -f requirements-dev.txt ]; then \
      ${VENV_DIR}/bin/pip install -r requirements-dev.txt; \
    else \
      echo "no requirements-dev.txt" > /dev/null; \
    fi || true

# Poetry path (если проект управляется Poetry)
RUN --mount=type=cache,target=${PIP_CACHE_DIR},sharing=locked \
    --mount=type=bind,source=poetry.lock,target=poetry.lock,ro \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml,ro \
    if [ -f poetry.lock ] && [ -f pyproject.toml ]; then \
      ${VENV_DIR}/bin/pip install "poetry==${POETRY_VERSION}" && \
      poetry export --without-hashes -o /tmp/requirements-export.txt && \
      ${VENV_DIR}/bin/pip install -r /tmp/requirements-export.txt; \
    else \
      echo "poetry not used" > /dev/null; \
    fi || true

# Если нет requirements*, но есть pyproject.toml — установим пакет в editable (для сервисов/CLI)
# На стадии builder удобно иметь исходники: монтируем весь контекст и ставим .[all] при наличии.
COPY pyproject.toml ./
# Если setup.cfg/setup.py присутствуют — также копируем
COPY setup.cfg setup.py* ./
# Копируем исходники для сборки (минимум)
COPY ledger_core ./ledger_core

RUN --mount=type=cache,target=${PIP_CACHE_DIR},sharing=locked \
    if [ -f pyproject.toml ]; then \
      ${VENV_DIR}/bin/pip install -e . ; \
    fi

# Предкомпилируем байткод для ускорения cold start
RUN ${VENV_DIR}/bin/python -m compileall -q ${PROJECT_DIR}

# Печать зависимостей для аудита
RUN ${VENV_DIR}/bin/python -m pip freeze > /tmp/pip-freeze.txt


#############################
# Runtime stage: minimal
#############################
FROM python:3.11-slim AS runtime

ARG PROJECT_DIR=/app
ARG VENV_DIR=/opt/venv
ARG APP_USER=app
ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PATH="${VENV_DIR}/bin:${PATH}" \
    APP_HOME=${PROJECT_DIR} \
    UMASK=027

WORKDIR ${PROJECT_DIR}

# Создаём непривилегированного пользователя и рабочие директории
RUN groupadd --gid ${APP_GID} ${APP_USER} \
    && useradd --uid ${APP_UID} --gid ${APP_GID} --shell /usr/sbin/nologin --home-dir ${PROJECT_DIR} ${APP_USER} \
    && mkdir -p ${PROJECT_DIR} \
    && chown -R ${APP_USER}:${APP_USER} ${PROJECT_DIR}

# Устанавливаем минимальные системные зависимости для работы (если нужны certs/locale)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

# Копируем venv и артефакты из builder
COPY --from=builder --chown=${APP_USER}:${APP_USER} ${VENV_DIR} ${VENV_DIR}
COPY --from=builder --chown=${APP_USER}:${APP_USER} /tmp/pip-freeze.txt /opt/pip-freeze.txt

# Копируем только необходимые исходники (runtime‑минимум)
COPY --chown=${APP_USER}:${APP_USER} ledger_core ./ledger_core

# Дополнительно компилируем байткод (с учётом рантайм‑окружения)
RUN python -m compileall -q ${PROJECT_DIR}

# Безопасные права
RUN chmod -R go=rX ${PROJECT_DIR} ${VENV_DIR}

USER ${APP_USER}:${APP_USER}

# Healthcheck (пример: CLI команда ledger_core.health:main должна возвращать 0)
# При необходимости замените на актуальную команду.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import importlib,sys; \
m=importlib.util.find_spec('ledger_core'); \
sys.exit(0 if m else 1)" || exit 1

# Перекрываемые переменные среды приложения
ENV LEDGER_CORE_ENV=production \
    LEDGER_CORE_LOG_LEVEL=INFO

# Стандартный entrypoint (замените при необходимости на gunicorn/uvicorn для web)
# Например, если есть консольный скрипт `ledger-core` в pyproject — используйте его.
ENTRYPOINT ["python", "-m", "ledger_core"]
CMD ["--help"]

#############################
# Notes
#############################
# Сборка:
#   docker buildx build -f ops/docker/Dockerfile -t ledger-core:latest --load .
#
# Multi-arch (пример):
#   docker buildx build --platform linux/amd64,linux/arm64 -f ops/docker/Dockerfile -t org/ledger-core:latest --push .
#
# Артефакты аудита:
#   docker run --rm ledger-core:latest cat /opt/pip-freeze.txt
