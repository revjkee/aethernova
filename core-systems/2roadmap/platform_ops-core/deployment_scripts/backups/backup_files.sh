#!/bin/bash
# Скрипт для инкрементального бэкапа важных файлов и директорий с шифрованием и ротацией

set -euo pipefail

# Конфигурация
BACKUP_SRC="${BACKUP_SRC:-/var/www /etc /home}"
BACKUP_DEST="${BACKUP_DEST:-/backups/files}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
ENCRYPTION_PASSPHRASE="${ENCRYPTION_PASSPHRASE:-}"

TIMESTAMP=$(date +'%Y%m%d_%H%M%S')
ARCHIVE_NAME="files_backup_${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="${BACKUP_DEST}/${ARCHIVE_NAME}"
ENCRYPTED_ARCHIVE_PATH="${ARCHIVE_PATH}.gpg"

# Проверка директории назначения
mkdir -p "$BACKUP_DEST"

# Создание архива с указанными источниками
tar -czf "$ARCHIVE_PATH" $BACKUP_SRC

# Шифрование архива с использованием GPG и пароля из переменной окружения
if [ -z "$ENCRYPTION_PASSPHRASE" ]; then
  echo "ERROR: ENCRYPTION_PASSPHRASE не установлен в окружении."
  exit 1
fi

echo "$ENCRYPTION_PASSPHRASE" | gpg --batch --yes --passphrase-fd 0 -c --output "$ENCRYPTED_ARCHIVE_PATH" "$ARCHIVE_PATH"

# Удаление незашифрованного архива
rm -f "$ARCHIVE_PATH"

# Очистка старых бэкапов
find "$BACKUP_DEST" -type f -name "files_backup_*.tar.gz.gpg" -mtime +$RETENTION_DAYS -exec rm -f {} \;

echo "Резервное копирование файлов завершено успешно. Архив: $ENCRYPTED_ARCHIVE_PATH"
