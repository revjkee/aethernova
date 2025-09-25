FROM python:3.11-slim

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    postgresql-client \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем requirements и устанавливаем зависимости
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код и миграции
COPY backend/src/ ./src/
COPY backend/alembic/ ./alembic/
COPY backend/entrypoint.sh /entrypoint.sh

# Копируем security-core (локальная разработческая интеграция)
COPY ../core-systems/security-core/security /opt/security
ENV PYTHONPATH=/opt:/app

# Создадим непривилегированного пользователя для запуска
RUN groupadd -r app && useradd -r -g app app || true
RUN chown -R app:app /app /opt/security || true

EXPOSE 8000

USER app
ENTRYPOINT ["/entrypoint.sh"]
# Dockerfile для backend (FastAPI/Uvicorn)
FROM python:3.11-slim

WORKDIR /app

# Установим зависимости (используем requirements из папки backend, а не корня репозитория)
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY backend/src/ ./src/

# Копируем alembic и скрипты миграций
COPY backend/alembic/ ./alembic/
COPY backend/scripts/ ./scripts/
COPY backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /alembic/env.py || true

# Копируем security-core (локальная разработческая интеграция)
COPY ../core-systems/security-core/security /opt/security
# Добавим в PYTHONPATH, чтобы import security работал (родительский каталог /opt содержит папку security)
ENV PYTHONPATH=/opt:/app

# Открываем порт
EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
