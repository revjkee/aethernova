# cybersecurity-core/ops/docker/Dockerfile
# syntax=docker/dockerfile:1.7-labs

############################
#      Build arguments     #
############################
ARG PYTHON_VERSION=3.12
ARG DISTRO_VARIANT=slim
ARG APP_NAME=cybersecurity-core

# OCI/metadata
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=0.0.0
ARG VCS_URL
ARG VENDOR="Aethernova"

############################
#          Base            #
############################
FROM python:${PYTHON_VERSION}-${DISTRO_VARIANT} AS base

ENV \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  # Опциональная локаль/часовой пояс
  TZ=UTC \
  LC_ALL=C.UTF-8 \
  LANG=C.UTF-8

# Общий рабочий каталог для сборки
WORKDIR /src

############################
#         Builder          #
############################
FROM base AS builder

ARG DEBIAN_FRONTEND=noninteractive

# Пакеты для сборки криптографических/сетевых зависимостей
# (openssl/ffi/rust для cryptography/ruff/uvloop и т.п.)
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      gcc \
      libffi-dev \
      libssl-dev \
      pkg-config \
      rustc \
      cargo \
      git && \
    rm -rf /var/lib/apt/lists/*

# Кэш pip
RUN python -m pip install --upgrade pip wheel setuptools

# Poetry для проектов на pyproject.toml
ARG POETRY_VERSION=1.8.3
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "poetry==${POETRY_VERSION}"

# Копируем весь контекст (для универсальности и кэширования)
# Рекомендуется иметь .dockerignore в корне репозитория
COPY . /src

# Подготовим артефакты для runtime
RUN mkdir -p /artifacts/wheels

# Экспорт зависимостей и сборка колеса, если есть Poetry-проект.
# Фолбэк: если только requirements.txt — используем его.
RUN set -eux; \
    if [ -f "pyproject.toml" ]; then \
      poetry export --without-hashes --only main -f requirements.txt -o /artifacts/requirements.txt; \
      poetry build -f wheel -n; \
      cp -f dist/*.whl /artifacts/wheels/ || true; \
    elif [ -f "requirements.txt" ]; then \
      cp -f requirements.txt /artifacts/requirements.txt; \
    else \
      # Нет явных зависимостей — создаём пустой файл
      : > /artifacts/requirements.txt; \
    fi

############################
#         Runtime          #
############################
FROM python:${PYTHON_VERSION}-${DISTRO_VARIANT} AS runtime

ARG DEBIAN_FRONTEND=noninteractive
ARG APP_NAME
ARG VENDOR
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION
ARG VCS_URL

# Метаданные OCI
LABEL org.opencontainers.image.title="${APP_NAME}" \
      org.opencontainers.image.description="Hardened ${APP_NAME} service image" \
      org.opencontainers.image.vendor="${VENDOR}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="${VCS_URL}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Proprietary"

ENV \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  TZ=UTC \
  LC_ALL=C.UTF-8 \
  LANG=C.UTF-8 \
  # Создадим изолированное окружение и сделаем его дефолтным
  VENV_PATH=/opt/venv \
  PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  # Значения по умолчанию для запуска приложения и healthcheck
  APP_CMD="python -m cybersecurity_core" \
  HEALTHCHECK_HOST="127.0.0.1" \
  HEALTHCHECK_PORT="8080"

# Минимум системных пакетов + tini для корректного reaping процессов
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      tini \
      ca-certificates \
      curl && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Создаём непривилегированного пользователя
ARG UID=65532
ARG GID=65532
RUN set -eux; \
    groupadd -g "${GID}" app && \
    useradd --no-log-init -r -u "${UID}" -g app -d /home/app -s /usr/sbin/nologin app && \
    mkdir -p /home/app && chown -R app:app /home/app

# Копируем артефакты из builder
COPY --from=builder /artifacts /artifacts

# Создаём виртуальное окружение и устанавливаем зависимости/пакет
RUN set -eux; \
    python -m venv "${VENV_PATH}"; \
    "${VENV_PATH}/bin/python" -m pip install --upgrade pip; \
    if [ -s "/artifacts/requirements.txt" ]; then \
      --mount=type=cache,target=/root/.cache/pip \
      "${VENV_PATH}/bin/pip" install -r /artifacts/requirements.txt; \
    fi; \
    if [ "$(ls -A /artifacts/wheels || true)" ]; then \
      --mount=type=cache,target=/root/.cache/pip \
      "${VENV_PATH}/bin/pip" install /artifacts/wheels/*.whl; \
    fi; \
    rm -rf /root/.cache/pip /artifacts

# Рабочие каталоги под данные/логи (единственные пишущие)
WORKDIR /app
RUN mkdir -p /data /var/log/app && chown -R app:app /data /var/log/app

# Жёстче права на системные пути (уменьшаем поверхность атаки)
RUN set -eux; \
    chmod -R a-wX /usr/local /usr/lib/python* || true; \
    find /opt/venv -type d -exec chmod 755 {} \; ; \
    find /opt/venv -type f -exec chmod 644 {} \; || true

# Стартовый скрипт (поддерживает APP_CMD и дефолт "python -m cybersecurity_core")
RUN set -eux; \
    printf '%s\n' '#!/bin/sh' \
      'set -euo pipefail' \
      'umask 027' \
      'if [ -z "${APP_CMD:-}" ]; then' \
      '  APP_CMD="python -m cybersecurity_core"' \
      'fi' \
      'exec sh -c "$APP_CMD"' \
    > /usr/local/bin/entrypoint && \
    chmod +x /usr/local/bin/entrypoint

# Порт по умолчанию (не привилегированный)
EXPOSE 8080

# HEALTHCHECK: проверка TCP-порта (без curl-зависимости по HTTP)
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD python - <<'PY' || exit 1
import os, socket
host = os.environ.get("HEALTHCHECK_HOST","127.0.0.1")
port = int(os.environ.get("HEALTHCHECK_PORT","8080"))
s = socket.socket()
s.settimeout(2)
try:
    s.connect((host, port))
finally:
    s.close()
PY

# Tini как init-процесс
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/entrypoint"]

# Запуск по умолчанию — можно переопределить APP_CMD во время docker run
CMD []
# Примеры:
#   docker run --rm -e APP_CMD="uvicorn app.main:app --host 0.0.0.0 --port 8080" image:tag
#   docker run --rm -e APP_CMD="python -m cybersecurity_core" image:tag

# Рекомендации по запуску (безопаснее) — настраиваются на уровне orchestrator:
#   --read-only --cap-drop=ALL --pids-limit=256 --memory=512m --cpus=1 \
#   -v data:/data -v logs:/var/log/app \
#   --health-cmd (используется из Dockerfile)
