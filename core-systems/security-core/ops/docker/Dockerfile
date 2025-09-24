# syntax = docker/dockerfile:1.7-labs

############################
#      Build arguments     #
############################
ARG PYTHON_VERSION=3.12
ARG APP_NAME=security-core
ARG APP_USER=svc
ARG APP_UID=10001
ARG APP_GID=10001

############################
#        Builder           #
############################
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

# Безопасные и воспроизводимые настройки
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOURCE_DATE_EPOCH=1704067200

# Необязательные системные зависимости для сборки нативных колёс (оставляем тонко)
# Устанавливаем только на стадии builder
RUN --mount=type=cache,target=/var/cache/apt \
    set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
    ; \
    rm -rf /var/lib/apt/lists/*

# Создаём изолированное окружение
ENV VENV=/opt/venv
RUN python -m venv "${VENV}"
ENV PATH="${VENV}/bin:${PATH}"

WORKDIR /app

# 1) Сначала подтягиваем манифесты зависимостей для максимального кеширования
# Поддерживаем оба сценария: requirements* и PEP 621 (pyproject.toml)
COPY ./requirements.txt ./requirements.txt
COPY ./requirements-dev.txt ./requirements-dev.txt
COPY ./pyproject.toml ./pyproject.toml
COPY ./poetry.lock ./poetry.lock

# 2) Устанавливаем зависимости (с кешем pip через BuildKit)
# Приоритет:
#   - если есть requirements*.txt -> используем их
#   - иначе если есть pyproject.toml -> соберём editable/pep517
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    if [ -f requirements.txt ]; then \
        pip install --upgrade pip wheel; \
        pip install -r requirements.txt; \
    elif [ -f pyproject.toml ]; then \
        pip install --upgrade pip build; \
        python -m build --wheel --no-isolation; \
        pip install dist/*.whl; \
    else \
        echo "No dependency manifest found; proceeding without deps"; \
    fi

# 3) Копируем исходники последним слоем для лучшего кеша
COPY . /app

# Если используем pyproject и нужен editable-инсталл (по желанию проекта)
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    if [ -f pyproject.toml ] && [ ! -f requirements.txt ]; then \
        pip install -e .; \
    fi

# Предкомпиляция байткода для быстрого старта
RUN python -m compileall -q /app || true

# Отдельный каталог с артефактами для копирования в рантайм
RUN mkdir -p /runtime && \
    cp -a "${VENV}" /runtime/venv && \
    mkdir -p /runtime/app && \
    cp -a /app /runtime/app

############################
#     Runtime (Distroless) #
############################
FROM gcr.io/distroless/python3-debian12:nonroot AS runtime

# OCI‑метаданные
ARG APP_NAME \
    PYTHON_VERSION
ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"
LABEL org.opencontainers.image.title="${APP_NAME}" \
      org.opencontainers.image.description="NeuroCity ${APP_NAME} service (distroless, nonroot)" \
      org.opencontainers.image.source="https://example.com/repo" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      org.opencontainers.image.vendor="NeuroCity"

# Окружение рантайма
ENV PATH="/opt/venv/bin:/usr/bin:/usr/local/bin" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Для некоторых библиотек снижает потребление потоков
    OMP_NUM_THREADS=1 \
    # Параметры healthcheck (порт сервиса можно переопределить)
    HEALTHCHECK_HOST=127.0.0.1 \
    HEALTHCHECK_PORT=8000

# Копируем только то, что нужно
COPY --from=builder /runtime/venv /opt/venv
COPY --from=builder /runtime/app /app

WORKDIR /app

# Пользователь nonroot предоставляется дистролессом (uid 65532). Дополнительно фиксируем права.
USER 65532:65532

# Опциональная декларация порта приложения
EXPOSE 8000

# Healthcheck без сторонних утилит (используем python)
# Возвращает 0 при успешном TCP‑подключении к HEALTHCHECK_HOST:HEALTHCHECK_PORT
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 CMD \
  python - <<'PY' || exit 1
import os, socket
host = os.environ.get("HEALTHCHECK_HOST","127.0.0.1")
port = int(os.environ.get("HEALTHCHECK_PORT","8000"))
s = socket.socket()
s.settimeout(2.0)
try:
    s.connect((host, port))
    s.close()
    raise SystemExit(0)
except Exception:
    raise SystemExit(1)
PY

# По умолчанию не навязываем конкретный ранкоманд — это безопасный базовый образ.
# Переопределяйте CMD/ENTRYPOINT в оркестраторе: например,
#   CMD ["-m","security_core.api"]
ENTRYPOINT ["python"]
CMD ["-c","print('security-core runtime ready. Set CMD to your module, e.g. -m security_core')"]

############################
#   Optional debug runtime #
############################
# Удобная цель с shell и tini для локальной отладки.
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime-debug

ARG APP_NAME \
    APP_USER \
    APP_UID \
    APP_GID \
    VCS_REF="unknown" \
    BUILD_DATE="unknown"

LABEL org.opencontainers.image.title="${APP_NAME}-debug" \
      org.opencontainers.image.description="Debug runtime (slim + shell + tini), not for prod" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Минимум утилит для отладки и корректного PID 1
RUN --mount=type=cache,target=/var/cache/apt \
    set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      tini ca-certificates tzdata dumb-init \
    ; \
    rm -rf /var/lib/apt/lists/*

# Пользователь
RUN set -eux; \
    groupadd -g "${APP_GID}" "${APP_USER}"; \
    useradd -u "${APP_UID}" -g "${APP_GID}" -m -s /usr/sbin/nologin "${APP_USER}"

COPY --from=builder /runtime/venv /opt/venv
COPY --from=builder /runtime/app /app

WORKDIR /app
USER ${APP_UID}:${APP_GID}
EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini","-g","--"]
CMD ["python","-m","http.server","8000"]

############################
#     Default export       #
############################
# По умолчанию итоговая цель — безопасный distroless runtime.
# Для отладки можно собирать: `--target runtime-debug`
FROM runtime AS final
