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
COPY backend/requirements.txt ./requirements.txt
COPY backend/requirements-dev.txt ./requirements-dev.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "${BUILD_DEV:-0}" = "1" ]; then pip install --no-cache-dir -r requirements-dev.txt; fi

# Копируем исходный код, alembic и скрипты миграций
COPY backend/src/ ./src/
COPY backend/alembic/ ./alembic/
COPY backend/alembic.ini ./alembic.ini
COPY backend/scripts/ ./scripts/
COPY backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /alembic/env.py || true

# Копируем security-core (локальная разработческая интеграция)
COPY ../core-systems/security-core/security /opt/security
# Добавим в PYTHONPATH, чтобы import security работал (родительский каталог /opt содержит папку security)
ENV PYTHONPATH=/opt:/app

# Создадим непривилегированного пользователя для запуска
RUN groupadd -r app && useradd -r -g app app || true
RUN chown -R app:app /app /opt/security || true

EXPOSE 8000

USER app
ENTRYPOINT ["/entrypoint.sh"]
