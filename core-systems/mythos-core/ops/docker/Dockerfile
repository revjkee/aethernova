# mythos-core/ops/docker/Dockerfile
# syntax=docker/dockerfile:1.7-labs

#############################
# Стандартные аргументы
#############################
ARG PYTHON_VERSION=3.12
ARG DEBIAN_SUITE=bookworm

#############################
# Стадия: builder
#############################
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_SUITE} AS builder

# Важные ENV для reproducible сборок и производительности
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Обновляем сертификаты и ставим инструменты для сборки колёс
RUN --mount=type=cache,target=/var/cache/apt \
    set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        git \
        ca-certificates \
        curl; \
    rm -rf /var/lib/apt/lists/*

# Создаём изолированный виртуальный env
ENV VENV=/opt/venv
RUN python -m venv "${VENV}"
ENV PATH="${VENV}/bin:${PATH}"

# Подготовим директорию с исходниками
WORKDIR /src

# 1) Устанавливаем зависимости, если есть requirements-файлы (лучший кеш)
# 2) Иначе перейдём к сборке из pyproject/setup.*
# Используем BuildKit-кэш для pip
COPY --link requirements*.txt pyproject.toml setup.cfg setup.py README.* LICENSE* ./ 2>/dev/null || true
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    python -m pip install -U pip wheel; \
    if [ -f requirements.txt ]; then \
        pip install --no-deps --prefer-binary -r requirements.txt; \
    fi; \
    if [ -f requirements-prod.txt ]; then \
        pip install --no-deps --prefer-binary -r requirements-prod.txt; \
    fi

# Копируем остальной код и собираем wheel
COPY --link . /src
# Собираем wheel в /tmp/wheels и ставим его во venv (без исходников)
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    mkdir -p /tmp/wheels; \
    pip wheel --no-deps --prefer-binary -w /tmp/wheels /src; \
    pip install --no-deps --no-index --find-links=/tmp/wheels /tmp/wheels/*.whl; \
    # sanity-check
    python -c "import importlib, sys; importlib.import_module('mythos_core'); print('Installed:', sys.version)"

#############################
# Стадия: runtime
#############################
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_SUITE} AS runtime

# Метаданные образа (можно переопределять через --build-arg)
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="mythos-core" \
      org.opencontainers.image.description="Production image for Mythos Core (Python ${PYTHON_VERSION})" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://example.com/mythos-core" \
      org.opencontainers.image.licenses="Apache-2.0"

# Базовые ENV
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    APP_HOME=/app \
    APP_MODULE="mythos_core.api.app:app" \
    PORT=8000 \
    HEALTHCHECK_PATH="/healthz"

# Устанавливаем только минимальные системные зависимости для runtime
RUN --mount=type=cache,target=/var/cache/apt \
    set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        tini; \
    rm -rf /var/lib/apt/lists/*

# Создаём непривилегированного пользователя
ARG UID=10001
ARG GID=10001
RUN set -eux; \
    groupadd -g "${GID}" app; \
    useradd --no-log-init -m -u "${UID}" -g "${GID}" -s /usr/sbin/nologin app

# Копируем готовое виртуальное окружение из builder
COPY --from=builder --chown=app:app /opt/venv /opt/venv

# Рабочая директория приложения (по умолчанию пустая — пакет уже в venv)
WORKDIR ${APP_HOME}
RUN chown -R app:app ${APP_HOME}

USER app:app

# Экспортируем порт приложения
EXPOSE ${PORT}

# Healthcheck для API (если эндпоинт реализован)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}${HEALTHCHECK_PATH}" || exit 1

# Запускаем через tini (init) и оболочку, чтобы подставить APP_MODULE и PORT
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["sh", "-c", "exec uvicorn ${APP_MODULE} --host 0.0.0.0 --port ${PORT} --proxy-headers"]
