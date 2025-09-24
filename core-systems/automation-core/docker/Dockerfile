# automation-core/docker/Dockerfile
# Многоэтапная сборка: builder (создание wheel по PEP 517) -> runtime (минимальный образ).
# Основано на официальных рекомендациях Docker (multi-stage, минимальная база) и PyPA build/PEP 517. 
# Docs: Docker best practices; Dockerfile reference; Python official image; PyPA build; poetry-core. 
# https://docs.docker.com/build/building/best-practices/
# https://docs.docker.com/reference/dockerfile/
# https://hub.docker.com/_/python
# https://build.pypa.io/en/stable/api.html
# https://github.com/python-poetry/poetry-core

# -------- Builder stage --------
ARG PYTHON_VERSION=3.12-slim
FROM python:${PYTHON_VERSION} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Системные пакеты для сборки (оставляются только в builder-слое).
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Копируем только метаданные и исходники (src-layout предполагается):
# pyproject.toml (poetry-core как PEP 517 backend) и исходники проекта.
COPY pyproject.toml README.md ./
COPY src ./src

# Обновляем pip и ставим PyPA build; сборка дистрибутива (wheel).
# «python -m build» — фронтенд PyPA для PEP 517 (wheel/source). 
# Источник: https://build.pypa.io/en/stable/api.html
RUN python -m pip install --upgrade pip && \
    python -m pip install --no-cache-dir build && \
    python -m build --wheel --outdir /dist

# -------- Runtime stage --------
FROM python:${PYTHON_VERSION} AS runtime

# Создаём изолированную среду выполнения и non-root пользователя.
ENV VENV=/opt/venv
RUN python -m venv ${VENV} && \
    ${VENV}/bin/pip install --upgrade pip && \
    groupadd -g 10001 app && useradd -m -u 10001 -g 10001 app
ENV PATH="${VENV}/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Устанавливаем собранное колесо (зависимости подтянутся из PyPI).
# Билд-зависимости не попадают в финальный образ благодаря multi-stage. 
COPY --from=builder /dist/*.whl /tmp/dist/
RUN pip install --no-cache-dir /tmp/dist/*.whl && rm -rf /tmp/dist

# HEALTHCHECK согласно справочнику Dockerfile.
# Проверка: импорт пакета automation_core (замените при необходимости).
# Docs: https://docs.docker.com/reference/dockerfile/
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import importlib, sys; importlib.import_module('automation_core'); sys.exit(0)"

# Опционально скопируйте конфиги/ресурсы, если они нужны рантайму:
# COPY configs/ /app/configs/

# По умолчанию запускаем модуль (при необходимости поменяйте на ваш CLI/entrypoint).
# Если в вашем проекте задан console_script, замените CMD на бинарь.
USER app
CMD ["python", "-m", "automation_core"]
