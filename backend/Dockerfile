# Dockerfile для backend (FastAPI/Uvicorn)
FROM python:3.11-slim

WORKDIR /app

# Установим зависимости (используем requirements из папки backend, а не корня репозитория)
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY backend/src/ ./src/

# Копируем security-core (локальная разработческая интеграция)
COPY ../core-systems/security-core/security /opt/security
# Добавим в PYTHONPATH, чтобы import security работал (родительский каталог /opt содержит папку security)
ENV PYTHONPATH=/opt:/app

# Открываем порт
EXPOSE 8000

# Запуск приложения
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
