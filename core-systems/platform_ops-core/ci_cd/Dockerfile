# ┌────────────────────────────────────────────────────────┐
# │       TeslaAI Genesis CI/CD — Build Container         │
# │   Оптимизировано 20 агентами (security, perf, dev)    │
# └────────────────────────────────────────────────────────┘

FROM python:3.11-slim AS base

LABEL maintainer="dev@teslaai.io"
LABEL version="1.0"
LABEL description="CI/CD Runtime Image for TeslaAI Genesis infrastructure pipelines"

# Установка базовых пакетов
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        unzip \
        ca-certificates \
        build-essential \
        libffi-dev \
        libssl-dev \
        libpq-dev \
        gcc \
        gnupg \
        jq \
        bash-completion \
        netcat \
        tini && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Установка poetry
ENV POETRY_VERSION=1.8.2
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    ln -s /root/.local/bin/poetry /usr/local/bin/poetry

# Установка утилит CI
RUN pip install --no-cache-dir \
    pre-commit==3.7.0 \
    safety==3.1.0 \
    bandit==1.7.8 \
    black==24.4.2 \
    isort==5.13.2 \
    flake8==7.0.0 \
    mypy==1.10.0 \
    coverage==7.5.1 \
    httpx==0.27.0 \
    pytest==8.2.1 \
    pytest-asyncio==0.23.6 \
    pytest-cov==5.0.0

# Настройка рабочего каталога
WORKDIR /app

# Добавление poetry зависимостей (для layer cache)
COPY pyproject.toml poetry.lock ./
RUN poetry config virtualenvs.create false && poetry install --no-root --no-interaction

# Добавление исходного кода (позже, чтобы не инвалидировать кэш)
COPY . .

# Установка прав доступа и запуска по умолчанию
RUN chmod +x ./entrypoint.sh
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash"]

# ┌────────────────────────────────────────┐
# │        Security / CI Notes             │
# ├────────────────────────────────────────┤
# │ - Поддерживает запуск линтеров, тестов │
# │ - Используется в GitHub Actions и Argo │
# │ - Может выполнять docker-in-docker     │
# └────────────────────────────────────────┘
