# syntax=docker/dockerfile:1.4

# 1. Stage: Build environment
FROM python:3.11-bullseye-slim AS builder



RUN apt-get install -y tzdata && \
    ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata
RUN useradd -m appuser
USER appuser
RUN apt-get update && apt-get install -y --no-install-recommends \
    debian-archive-keyring ca-certificates \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    build-essential \
  && rm -rf /var/lib/apt/lists/*


# Обновляем и устанавливаем сборочные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    build-essential \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем файлы с зависимостями
COPY requirements.txt pyproject.toml ./

# Обновляем pip и устанавливаем зависимости в изолированное окружение
RUN python -m venv /opt/venv \
  && . /opt/venv/bin/activate \
  && pip install --upgrade pip setuptools wheel \
  && pip install -r requirements.txt

# Копируем исходный код
COPY src/ ./src/

# 2. Stage: Runtime environment
FROM python:3.11-bullseye-slim


# Копируем виртуальное окружение из build stage
COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Копируем исходный код из build stage
COPY --from=builder /app/src ./src

ENV PATH="/opt/venv/bin:$PATH"

# Минимизируем слои и очищаем кэш
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 \
  && rm -rf /var/lib/apt/lists/*

# Устанавливаем переменную окружения для Python буферизации вывода
ENV PYTHONUNBUFFERED=1

# Стандартная команда запуска (можно адаптировать под конкретный entrypoint)
CMD ["python", "-m", "src.main"]
