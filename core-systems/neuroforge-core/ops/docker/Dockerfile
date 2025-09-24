# syntax=docker/dockerfile:1.7-labs
##
## neuroforge-core — промышленный Dockerfile (Python 3.11, Debian bookworm-slim)
## Многостадийная сборка: builder -> runtime
##

ARG PYTHON_VERSION=3.11
ARG DEBIAN_FRONTEND=noninteractive

########################
# 1) Builder stage
########################
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

# Включаем строгую оболочку и кэш pip/apt (BuildKit required)
SHELL ["/bin/sh", "-eux", "-c"]

# Базовые ENV для воспроизводимости и корректного поведения Python/pip
ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_DEFAULT_TIMEOUT=60 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=0

# Опциональные аргументы для системных зависимостей (минимальные дефолты)
# Добавьте нужные dev-пакеты в BUILD_DEPS, а рантайм-библиотеки — в RUNTIME_DEPS
ARG BUILD_DEPS="build-essential gcc g++ pkg-config git"
ARG BUILD_LIB_DEPS="libffi-dev libssl-dev libpq-dev zlib1g-dev libjpeg-dev libmagic-dev"
ARG RUNTIME_DEPS="ca-certificates libffi8 libssl3 libpq5 libmagic1"

# Обновляем apt, ставим зависимости (dev только в builder), чистим кэш
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update -y && \
    apt-get install -y --no-install-recommends ${BUILD_DEPS} ${BUILD_LIB_DEPS} ${RUNTIME_DEPS} && \
    rm -rf /var/lib/apt/lists/*

# Заводим изолированное venv, обновляем инструменты сборки
ENV VENV_PATH=/opt/venv
RUN python -m venv "${VENV_PATH}" && \
    "${VENV_PATH}/bin/pip" install --upgrade pip setuptools wheel

# Рабочий каталог исходников
WORKDIR /src

# Копируем репозиторий целиком (универсально; если хотите — оптимизируйте под свой layout)
# Используйте .dockerignore для исключения ненужного
COPY . /src

# Установка зависимостей:
# Приоритет: requirements.lock -> requirements.txt -> pyproject.toml (PEP 517)
# Если есть hashes в requirements.lock — применим --require-hashes.
# Кешируем директорию pip для ускорения повторных сборок.
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked <<'EOF'
set -eux
PIP="${VENV_PATH}/bin/pip"
if [ -f requirements.lock ]; then
  # Если lock содержит hashes, используем строгую установку; иначе без флага
  if grep -E '^[a-zA-Z0-9_\-]+[=><!~]=.*--hash=sha' -q requirements.lock; then
    "$PIP" install --require-hashes -r requirements.lock
  else
    "$PIP" install -r requirements.lock
  fi
elif [ -f requirements.txt ]; then
  "$PIP" install -r requirements.txt
elif [ -f pyproject.toml ]; then
  # Установка как дистрибутива (можно заменить на .[prod] при наличии)
  "$PIP" install .
fi
# Валидация конфликтов зависимостей
"$PIP" check || true
EOF

# Предсобираем байткод (опционально). Закомментируйте, если хотите исключить __pycache__.
# RUN "${VENV_PATH}/bin/python" -m compileall -q /src

########################
# 2) Runtime stage
########################
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

SHELL ["/bin/sh", "-eux", "-c"]

# Базовые ENV для рантайма
ENV \
  PIP_DISABLE_PIP_VERSION_CHECK=1 \
  PIP_NO_CACHE_DIR=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  VENV_PATH=/opt/venv \
  APP_HOME=/app

# Устанавливаем только необходимые рантайм-библиотеки
ARG RUNTIME_DEPS="ca-certificates libffi8 libssl3 libpq5 libmagic1"
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update -y && \
    apt-get install -y --no-install-recommends ${RUNTIME_DEPS} && \
    rm -rf /var/lib/apt/lists/*

# Копируем подготовленное виртуальное окружение из builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="${VENV_PATH}/bin:${PATH}"

# Создаём непривилегированного пользователя и рабочую директорию
ARG APP_USER=app
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd -g "${APP_GID}" "${APP_USER}" && \
    useradd -m -d "${APP_HOME}" -u "${APP_UID}" -g "${APP_GID}" -s /usr/sbin/nologin "${APP_USER}" && \
    install -d -o "${APP_UID}" -g "${APP_GID}" "${APP_HOME}"

WORKDIR /app

# Копируем исходники приложения (после venv, чтобы не инвалидировать кэш зависимостей)
COPY --chown=${APP_UID}:${APP_GID} . /app

# Минимальная проверка импортов (не обязательна; безопасно игнорируется при отсутствии пакета)
# RUN python -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('neuroforge_core') else 0)"

# Пользователь без привилегий
USER ${APP_UID}:${APP_GID}

# OCI метаданные (подставьте свои значения через --build-arg)
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="neuroforge-core" \
      org.opencontainers.image.description="Production-grade runtime image for neuroforge-core" \
      org.opencontainers.image.source="https://example.org/neuroforge-core" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Apache-2.0"

# Healthcheck-заготовка (адаптируйте под ваше приложение; по умолчанию выключено)
# HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
#   CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 8080)); s.close()"

# По умолчанию не задаём CMD/ENTRYPOINT, чтобы не навязывать точку входа.
# Пример (раскомментируйте, если у вас есть модуль запуска приложения):
# ENTRYPOINT ["python", "-m", "neuroforge_core"]

# Безопасное значение по умолчанию: показать версию Python/пакетов — контейнер завершится успешно.
CMD ["python", "-V"]
