# Dockerfile для backend (FastAPI/Uvicorn)
FROM python:3.10-slim

WORKDIR /app

# Установим зависимости
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY src/ ./src/

# Открываем порт
EXPOSE 8000

# Запуск приложения
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
