#!/bin/bash
# Скрипт инициализации TimescaleDB для проекта TeslaAI
# Проверка, установка и настройка TimescaleDB с расширением для временных рядов

set -e

echo "Проверка наличия psql..."
if ! command -v psql &> /dev/null
then
    echo "Ошибка: psql не установлен. Установите PostgreSQL client."
    exit 1
fi

DB_NAME="tesla_ai"
DB_USER="tesla_user"
DB_PASS="secure_password_here" # Заменить на безопасный пароль
DB_PORT=5432

echo "Создаем базу данных $DB_NAME, если ее нет..."
psql -U postgres -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
psql -U postgres -c "CREATE DATABASE $DB_NAME;"

echo "Создаем пользователя $DB_USER, если его нет..."
psql -U postgres -tc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | grep -q 1 || \
psql -U postgres -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"

echo "Выдача привилегий пользователю $DB_USER на базу $DB_NAME..."
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"

echo "Подключаемся к базе и включаем расширение TimescaleDB..."
psql -U postgres -d $DB_NAME -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"

echo "Создаем схему для временных рядов..."
psql -U $DB_USER -d $DB_NAME <<EOSQL
CREATE SCHEMA IF NOT EXISTS timeseries;
EOSQL

echo "Настройка завершена успешно."
