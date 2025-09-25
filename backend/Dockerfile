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
