# chronowatch-core/ops/docker/Dockerfile
# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.11-slim

# ------------------------------
# Base layer
# ------------------------------
FROM python:${PYTHON_VERSION} AS base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PATH="/usr/local/bin:${PATH}"

# Minimal base OS deps
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      git \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------
# Builder layer
# ------------------------------
FROM base AS builder
WORKDIR /src

# Build-time toolchain only in builder
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      gcc \
      g++ \
      libpq-dev \
      libssl-dev \
      pkg-config \
      curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project sources; при необходимости уточните .dockerignore
COPY . /src

# Обновляем pip и собираем колеса зависимостей и самого проекта.
# Если есть requirements.txt, сначала колесим зависимости.
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --upgrade pip wheel build && \
    if [[ -f "requirements.txt" ]]; then \
      pip wheel --no-deps -w /wheels -r requirements.txt ; \
    fi && \
    python -m build --wheel --outdir /wheels

# ------------------------------
# Runtime layer
# ------------------------------
FROM base AS runtime
ARG APP_USER=app
ARG APP_UID=10001
ARG APP_GID=10001

# Только рантайм-библиотеки
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      tini \
      libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Non-root пользователь
RUN groupadd --system --gid ${APP_GID} ${APP_USER} && \
    useradd  --system --create-home --uid ${APP_UID} --gid ${APP_GID} ${APP_USER}

WORKDIR /app

# Устанавливаем только предварительно собранные колеса
COPY --from=builder /wheels /wheels
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --upgrade pip && \
    pip install --no-index --find-links=/wheels /wheels/* && \
    rm -rf /wheels

# OCI метки для трассируемости сборки
ARG VCS_REF=""
ARG BUILD_DATE=""
ARG VERSION=""
LABEL org.opencontainers.image.title="chronowatch-core" \
      org.opencontainers.image.description="Industrial Python runtime for chronowatch-core" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Proprietary"

USER ${APP_UID}:${APP_GID}

# Tini как init; команда задается оркестратором
ENTRYPOINT ["/usr/bin/tini","--"]

# Внимание: намеренно не задаем CMD, чтобы не предполагать структуру приложения.
# Определите команду запуска на этапе docker run/compose/k8s.
