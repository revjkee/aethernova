# Dockerfile для blackvault-ui
FROM python:3.11-slim

WORKDIR /app

# Установить зависимости для Flask
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Установить зависимости Flask
RUN pip install --no-cache-dir flask gunicorn

# Скопировать исходный код UI
COPY . .

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8000/health || exit 1

# Запуск приложения
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--worker-class", "sync", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
