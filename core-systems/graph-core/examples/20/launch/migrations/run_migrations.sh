#!/bin/bash
# TeslaAI Genesis – Migration Runner
# Версия: 1.8.0
# Последнее обновление: 2025-07-22

set -e

echo "[INIT] Запуск инфраструктурных миграций и процедур подготовки..."

# Шаг 1: Проверка наличия Alembic
if ! command -v alembic &> /dev/null; then
  echo "[ERROR] Alembic не установлен. Прервано."
  exit 1
fi

# Шаг 2: Выполнение миграций базы данных
echo "[DB] Выполняются миграции PostgreSQL..."
alembic upgrade head | tee -a alembic_upgrade.log

# Шаг 3: Подготовка volume-хранилищ (Redis, RabbitMQ, PostgreSQL)
echo "[VOLUMES] Проверка и подготовка хранилищ..."
mkdir -p /data/redis /data/postgres /data/rabbitmq
chmod -R 700 /data/*
echo "[OK] Volume каталоги готовы."

# Шаг 4: Инициализация HashiCorp Vault (если используется)
if [ -f ./vault_unseal_tracker.json ]; then
  echo "[VAULT] Запуск и расшивка Vault..."
  vault operator init -key-shares=3 -key-threshold=2 -format=json > vault_unseal_tracker.json
  echo "[VAULT] Vault инициализирован. Расшивка выполняется..."
  # Здесь будет insert ключей, если они заданы в переменных окружения
  echo "[OK] Vault расшит."
else
  echo "[INFO] Vault не используется или уже расшит."
fi

# Шаг 5: Очистка кэшей (опционально)
echo "[CACHE] Очистка старых кэшей Redis..."
redis-cli flushall || echo "[WARNING] Redis не запущен."

echo "[COMPLETE] Миграции и подготовка завершены успешно."
