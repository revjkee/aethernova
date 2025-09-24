#!/bin/bash
# Скрипт для безопасного восстановления базы данных PostgreSQL из зашифрованного бэкапа

set -euo pipefail

# Переменные (настраиваются через окружение или в файле .env)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-mydatabase}"
DB_USER="${DB_USER:-postgres}"
BACKUP_FILE_ENC="${1:-}"
ENCRYPTION_KEY="${ENCRYPTION_KEY:-}"  # Должен быть установлен в окружении

if [ -z "$BACKUP_FILE_ENC" ]; then
  echo "ERROR: Укажите путь к зашифрованному файлу бэкапа в аргументе скрипта."
  exit 1
fi

if [ ! -f "$BACKUP_FILE_ENC" ]; then
  echo "ERROR: Файл $BACKUP_FILE_ENC не найден."
  exit 1
fi

if [ -z "$ENCRYPTION_KEY" ]; then
  echo "ERROR: ENCRYPTION_KEY не установлен в окружении."
  exit 1
fi

DECRYPTED_BACKUP="/tmp/$(basename "$BACKUP_FILE_ENC" .gpg).sql"

echo "Расшифровка бэкапа $BACKUP_FILE_ENC..."

echo "$ENCRYPTION_KEY" | gpg --batch --yes --passphrase-fd 0 -o "$DECRYPTED_BACKUP" -d "$BACKUP_FILE_ENC"

echo "Восстановление базы данных ${DB_NAME} из $DECRYPTED_BACKUP..."

PGPASSWORD="${DB_PASSWORD:-}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$DECRYPTED_BACKUP"

echo "Очистка временных файлов..."
rm -f "$DECRYPTED_BACKUP"

echo "Восстановление базы данных ${DB_NAME} завершено успешно."
