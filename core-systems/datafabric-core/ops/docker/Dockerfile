# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.12
ARG POETRY_VERSION=1.8.3

############################
# Base image (common setup)
############################
FROM python:${PYTHON_VERSION}-slim AS base

ENV \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_NO_CACHE_DIR=on \
  POETRY_VIRTUALENVS_CREATE=false \
  POETRY_NO_INTERACTION=1 \
  # Безопасные дефолты
  UMASK=0022 \
  LANG=C.UTF-8 \
  LC_ALL=C.UTF-8

# Часто нужные системные библиотеки для рантайма
# (openssl/ffi/tzdata; без компиляторов)
RUN set -Eeux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates tzdata libffi8 libssl3 curl; \
    rm -rf /var/lib/apt/lists/*

############################
# Builder (full toolchain)
############################
FROM base AS builder

# Инструменты сборки: компиляторы, заголовки, Rust (для cryptography и др.), git
RUN set -Eeux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential gcc g++ libffi-dev libssl-dev pkg-config git \
      rustc cargo; \
    rm -rf /var/lib/apt/lists/*

# Poetry (через pip во избежание внешних скачиваний исполняемых файлов)
RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}"

# Рабочая директория для сборки
WORKDIR /build

# Сначала копируем только манифесты для кешируемой установки зависимостей
# ПОМНИТЕ: корректный кеш работает, если poetry.lock меняется при изменении зависимостей
COPY pyproject.toml poetry.lock ./

# Создаём отдельный venv, в который установим зависимости и пакет
ENV VENV_DIR=/opt/venv
RUN python -m venv "${VENV_DIR}" && \
    "${VENV_DIR}/bin/pip" --version && \
    # Устанавливаем только runtime‑зависимости
    poetry export --only main --format=requirements.txt --without-hashes -o /tmp/requirements.txt && \
    "${VENV_DIR}/bin/pip" install --no-cache-dir -r /tmp/requirements.txt

# Теперь копируем исходники проекта для установки самого пакета
# Поддержим распространённые раскладки (скорректируйте при необходимости)
#   - datafabric_core/… (основной пакет)
#   - engine/… (если требуется как зависимость)
#   - любые скрипты/ресурсы, на которые ссылается пакет
COPY datafabric_core/ ./datafabric_core/
COPY engine/ ./engine/ 2>/dev/null || true
COPY README* LICENSE NOTICE ./

# Устанавливаем сам проект во venv (editable не используем для продакшена)
RUN "${VENV_DIR}/bin/pip" install --no-cache-dir .

# Дополнительно: сборка bytecode для ускорения cold‑start (опционально)
RUN "${VENV_DIR}/bin/python" -m compileall -q "${VENV_DIR}/lib/python"*"/site-packages"

############################
# Runtime (slim, non-root)
############################
FROM base AS runtime

# Создаём непривилегированного пользователя
ARG APP_USER=app
ARG APP_UID=10001
ARG APP_GID=10001
RUN set -Eeux; \
    groupadd --gid "${APP_GID}" "${APP_USER}"; \
    useradd  --uid "${APP_UID}" --gid "${APP_GID}" --create-home --shell /usr/sbin/nologin "${APP_USER}"

# Копируем готовое виртуальное окружение из builder'а
ENV VENV_DIR=/opt/venv
ENV PATH="${VENV_DIR}/bin:${PATH}"
COPY --from=builder "${VENV_DIR}" "${VENV_DIR}"

# Рабочая директория приложения (папка для конфигов/монтируемых данных)
WORKDIR /app

# По желанию можно скопировать только runtime‑артефакты (конфиги, статические файлы)
# COPY config/ ./config/ 2>/dev/null || true

# Жёсткая политика прав и безопасности контейнера
# - Запуск под непривилегированным пользователем
# - Сброс лишних capabilities
USER ${APP_UID}:${APP_GID}
# hadolint ignore=DL3025
ENTRYPOINT ["/opt/venv/bin/python", "-m", "datafabric_core"]
CMD []

# Порт и healthcheck — подстройте под приложение
EXPOSE 8080
HEALTHCHECK --interval=20s --timeout=3s --start-period=20s --retries=5 \
  CMD curl -fsS "http://127.0.0.1:8080/health" || exit 1

# Защита на уровне контейнера (для сред, где поддерживается Security Options)
# Эти инструкции — декларативны; реальное применение зависит от оркестратора
# com.docker.cap-drop убирает все cap'ы; no-new-privileges запрещает повышать привилегии
LABEL \
  org.opencontainers.image.title="datafabric-core" \
  org.opencontainers.image.description="DataFabric Core runtime image (Poetry, non-root, secure defaults)" \
  org.opencontainers.image.vendor="Your Org" \
  org.opencontainers.image.source="https://example.com/your-repo" \
  org.opencontainers.image.licenses="Apache-2.0" \
  io.container.capabilities="drop=ALL" \
  io.kubernetes.cri-o.TrySkipVolumeSELinuxLabel="true"

# Финал: печатаем версии для отладки на этапе сборки
RUN python --version && pip --version
