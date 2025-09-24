# syntax=docker/dockerfile:1.7
############################################
# physical-integration-core — Dockerfile
# Production-grade, Python 3.12, multi-stage
############################################

ARG PYTHON_VERSION=3.12-slim
ARG DEBIAN_FRONTEND=noninteractive

# ========== BASE (общие слои) ==========
FROM python:${PYTHON_VERSION} AS base
ARG DEBIAN_FRONTEND
ENV \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  UV_THREADPOOL_SIZE=64 \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  TZ=Etc/UTC \
  # изолированная venv
  VIRTUAL_ENV=/opt/venv \
  PATH="/opt/venv/bin:${PATH}"

# Минимальный набор пакетов + tini как init-процесс
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends tini ca-certificates netcat-traditional && \
    update-ca-certificates && \
    apt-get purge -y --auto-remove && \
    rm -rf /var/lib/apt/lists/*

# Создаем виртуальное окружение заранее (кэшируется)
RUN python -m venv "$VIRTUAL_ENV" && \
    "${VIRTUAL_ENV}/bin/python" -m pip install --upgrade pip setuptools wheel

# ========== BUILDER (зависимости) ==========
FROM base AS builder
WORKDIR /app

# Воспользуемся BuildKit кэшом для pip
# Поддержка двух сценариев:
# 1) requirements*.txt — быстрый путь
# 2) pyproject.toml/SETUP.cfg — editable install проекта
#
# Копируем только файлы зависимостей для максимального кэша:
COPY requirements*.txt* /app/ 2>/dev/null || true
COPY pyproject.toml poetry.lock setup.cfg setup.py /app/ 2>/dev/null || true

# Устанавливаем зависимости
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    if [ -f requirements.txt ]; then \
        pip install -r requirements.txt; \
        if [ -f requirements.prod.txt ]; then pip install -r requirements.prod.txt; fi; \
    elif [ -f pyproject.toml ] || [ -f setup.cfg ] || [ -f setup.py ]; then \
        # Базовые runtime-зависимости проекта (без dev)
        pip install .; \
    else \
        echo "No dependency manifest found, skipping deps layer"; \
    fi

# ========== RUNTIME (минимальный образ) ==========
FROM base AS runtime
WORKDIR /app

# Метаданные сборки (OCI)
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="physical-integration-core" \
      org.opencontainers.image.description="Industrial runtime image for physical-integration-core" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://example.com/physical-integration-core" \
      org.opencontainers.image.licenses="Apache-2.0"

# Создаем непривилегированного пользователя
RUN set -eux; \
    groupadd -g 10001 app && useradd -u 10001 -g 10001 -s /usr/sbin/nologin -m app && \
    install -d -o app -g app /app && \
    # Ужесточаем umask по умолчанию
    echo "umask 027" >> /etc/profile

# Копируем установленную venv из builder (меньше слоя)
COPY --from=builder /opt/venv /opt/venv

# Копируем исходники проекта (минимально необходимое)
# Предполагается запуск из корня репозитория:
#   docker build -f ops/docker/Dockerfile .
COPY --chown=app:app . /app

# Опционально: удаляем dev/тест директории из образа (уменьшаем размер)
RUN rm -rf tests .git .github .vscode 2>/dev/null || true

# Права
RUN find /app -type d -exec chmod 0750 {} \; && \
    find /app -type f -exec chmod 0640 {} \; && \
    chmod 0755 /app && \
    # Скрипты запуска, если есть
    if [ -d "/app/ops/bin" ]; then chmod -R 0755 /app/ops/bin; fi

# Переходим на пользователя app
USER app:app

# Порт по умолчанию для сервисов (переопределите при необходимости)
EXPOSE 8000

# HEALTHCHECK без curl: проверяем TCP-порт, если задан HEALTHCHECK_PORT (по умолчанию 8000)
ENV HEALTHCHECK_PORT=8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD nc -z 127.0.0.1 "$HEALTHCHECK_PORT" || exit 1

# Команда запуска:
# Переопределите переменной START_CMD на свой модуль/сервер, например:
#   -e START_CMD="gunicorn physical_integration_core.api:app -b 0.0.0.0:8000 --workers 2"
# По умолчанию пытаемся запустить как модуль Python.
ENV START_CMD="python -m physical_integration_core"
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["sh","-lc","${START_CMD}"]
