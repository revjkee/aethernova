#!/bin/bash
# Скрипт для безопасного бэкапа базы данных PostgreSQL с шифрованием и выгрузкой в защищённое хранилище

set -euo pipefail

# Переменные (настраиваются через окружение или в файле .env)
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-mydatabase}"
DB_USER="${DB_USER:-postgres}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/postgres}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
ENCRYPTION_KEY="${ENCRYPTION_KEY:-}"  # Должен быть установлен в окружении

DATE=$(date +'%Y-%m-%d_%H-%M-%S')
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_backup_${DATE}.sql"
ENCRYPTED_BACKUP_FILE="${BACKUP_FILE}.gpg"

# Проверка наличия GPG ключа
if [ -z "$ENCRYPTION_KEY" ]; then
  echo "ERROR: ENCRYPTION_KEY не установлен в окружении."
  exit 1
fi

mkdir -p "$BACKUP_DIR"

echo "Запуск бэкапа базы данных ${DB_NAME}..."

# Выполнение дампа базы данных
PGPASSWORD="${DB_PASSWORD:-}" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -F p "$DB_NAME" > "$BACKUP_FILE"

echo "Бэкап выполнен: $BACKUP_FILE"

# Шифрование бэкапа с помощью GPG
echo "$ENCRYPTION_KEY" | gpg --batch --yes --passphrase-fd 0 -c "$BACKUP_FILE"
mv "${BACKUP_FILE}.gpg" "$ENCRYPTED_BACKUP_FILE"
rm "$BACKUP_FILE"

echo "Бэкап зашифрован: $ENCRYPTED_BACKUP_FILE"

# Удаление старых бэкапов
find "$BACKUP_DIR" -type f -name "*.gpg" -mtime +"$BACKUP_RETENTION_DAYS" -exec rm -f {} \;

echo "Удалены бэкапы старше ${BACKUP_RETENTION_DAYS} дней."

echo "Бэкап базы данных ${DB_NAME} завершён успешно."
