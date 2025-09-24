# oblivionvault-core/ops/docker/Dockerfile
# Промышленный многостадийный Dockerfile для Python-сервиса.
# Совместим и с requirements*.txt, и с pyproject.toml/poetry.lock.

# -------------------------
# 1) Базовый слой с Python
# -------------------------
ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim AS base

# Жесткие, безопасные дефолты для Python и pip
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    # ускорение и повторяемость сборок
    PIP_DEFAULT_TIMEOUT=100 \
    # предсказуемые пути
    APP_HOME=/app

WORKDIR ${APP_HOME}

# Общие утилиты и сертификаты (в обоих слоях)
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl tini && \
    rm -rf /var/lib/apt/lists/*

# -------------------------
# 2) Сборка wheel-зависимостей
# -------------------------
FROM base AS builder

# Инструменты для сборки бинарных пакетов Python (минимальный набор)
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
      build-essential gcc pkg-config \
      libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Копируем только манифесты зависимостей для лучшего кэширования
# Поддерживаем оба подхода: requirements*.txt и/или pyproject.toml + poetry.lock
COPY requirements*.txt ./ 
COPY pyproject.toml poetry.lock* ./

# Создаем wheelhouse со всеми зависимостями
# 1) Если есть requirements*.txt — используем их
# 2) Если есть pyproject.toml — собираем проект и его зависимости через pip wheel
# Примечание: без внешних менеджеров (poetry/pdm); стандартный pip + build backend.
RUN python -m pip install --upgrade pip setuptools wheel && \
    mkdir -p /wheels && \
    if ls requirements*.txt >/dev/null 2>&1; then \
        echo "[builder] Detected requirements*.txt"; \
        for req in $(ls requirements*.txt); do \
          python -m pip wheel --wheel-dir=/wheels -r "$req"; \
        done; \
    fi && \
    if [ -f pyproject.toml ]; then \
        echo "[builder] Detected pyproject.toml"; \
        # соберем сам проект в wheel (без исходников) для последующей установки
        python -m pip wheel --wheel-dir=/wheels . || true; \
        # если есть poetry.lock, зависимости должны быть в pyproject;
        # в противном случае их подтянет команда выше.
    fi && \
    ls -l /wheels

# Слой с исходниками для опциональной сборки колеса проекта (если не попало выше)
# Копируем после генерации базовых wheels, чтобы не ломать кэш зависимостей
COPY . ${APP_HOME}

# На случай, если проектное wheel не было собрано ранее (pyproject есть, но wheel не собран)
RUN if [ ! -e /wheels/*.whl ]; then \
      echo "[builder] Building project wheel fallback"; \
      python -m pip wheel --wheel-dir=/wheels . || true; \
    fi

# -------------------------
# 3) Рантайм-слой (тонкий)
# -------------------------
FROM base AS runtime

# Метаданные образа (OCI)
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="oblivionvault-core" \
      org.opencontainers.image.description="Production-grade container for oblivionvault-core" \
      org.opencontainers.image.source="https://example.com/oblivionvault-core" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# Создаем непривилегированного пользователя
RUN groupadd --system app && useradd --system --home-dir ${APP_HOME} --gid app --shell /sbin/nologin app && \
    chown -R app:app ${APP_HOME}

# Устанавливаем только runtime-зависимости из wheelhouse
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels /wheels/* && \
    rm -rf /wheels

# Копируем код приложения (файлы уже отфильтрованы .dockerignore)
COPY --chown=app:app . ${APP_HOME}

# Предкомпилируем байткод для ускорения старта
RUN python -m compileall -q ${APP_HOME}

# ------------- 
# Запуск/сервис
# -------------
# Tini как PID 1 для корректной обработки сигналов
ENTRYPOINT ["/usr/bin/tini", "--"]

# Конфигурация сервера приложений через ENV
ENV HOST=0.0.0.0 \
    PORT=8080 \
    WORKERS=4 \
    TIMEOUT=60 \
    LOG_LEVEL=info \
    # Модуль приложения определяется внешне; дефолт для ASGI:
    APP_MODULE=oblivionvault_core.api.app:app \
    # Попытка предпочесть gunicorn; если отсутствует — fallback на uvicorn
    RUNNER=gunicorn \
    # Путь healthcheck
    HEALTHCHECK_PATH=/health

# Порт сервиса
EXPOSE 8080

# Простой entrypoint-скрипт выбора раннера (gunicorn -> uvicorn -> python -m)
# Без внешних файлов: создаём в образе
RUN printf '%s\n' \
'#!/bin/sh' \
'set -eu' \
'CMD="$1"; shift || true' \
'# Если первый аргумент - опции, запуск через сервер приложений' \
'if [ "${CMD#-}" != "$CMD" ]; then' \
'  set -- "$CMD" "$@"' \
'  CMD=""' \
'fi' \
'# Выбор раннера' \
'if [ -z "${CMD:-}" ]; then' \
'  if python -c "import gunicorn" >/dev/null 2>&1 && [ "${RUNNER:-}" = "gunicorn" ]; then' \
'    exec gunicorn "$APP_MODULE" \\' \
'      -k uvicorn.workers.UvicornWorker \\' \
'      --bind "${HOST}:${PORT}" \\' \
'      --workers "${WORKERS}" \\' \
'      --timeout "${TIMEOUT}" \\' \
'      --log-level "${LOG_LEVEL}"' \
'  elif python -c "import uvicorn" >/dev/null 2>&1; then' \
'    exec python -m uvicorn "$APP_MODULE" --host "${HOST}" --port "${PORT}" --workers "${WORKERS}" --log-level "${LOG_LEVEL}"' \
'  else' \
'    echo "Neither gunicorn nor uvicorn found; trying python -m ${APP_MODULE}" >&2' \
'    exec python -m "${APP_MODULE%:*}"' \
'  fi' \
'else' \
'  exec "$CMD" "$@"' \
'fi' \
> /usr/local/bin/start && chmod +x /usr/local/bin/start

USER app

# HEALTHCHECK использует curl из базового слоя
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT}${HEALTHCHECK_PATH}" || exit 1

# Команда по умолчанию: автоподбор раннера
CMD ["/usr/local/bin/start"]
