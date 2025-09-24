FROM python:3.11-slim

# Установка системных зависимостей
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Рабочая директория
WORKDIR /app

# Копируем зависимости
COPY requirements.txt pyproject.toml ./

# Установка Python-зависимостей
RUN pip install --upgrade pip && pip install -r requirements.txt

# Копируем backend и .env
COPY ./backend /app/backend
COPY .env /app/.env
COPY ./entrypoints /app/entrypoints

# Команда запуска — БОТ
CMD ["python", "entrypoints/run_bot.py"]
