#!/bin/bash
# Скрипт автоматического резервного копирования базы данных PostgreSQL с ротацией и логированием
# Назначение: TeslaAI project backup solution

set -euo pipefail

# Конфигурация
PG_USER="tesla_user"
PG_DB="tesla_ai"
BACKUP_DIR="/var/backups/tesla_ai"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
BACKUP_FILE="${BACKUP_DIR}/backup_${DATE}.sql.gz"
LOG_FILE="${BACKUP_DIR}/backup.log"
RETENTION_DAYS=7

# Создаем директорию бэкапов, если не существует
mkdir -p "${BACKUP_DIR}"

# Функция логирования с таймстампом
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $1" | tee -a "${LOG_FILE}"
}

log "Начало резервного копирования базы ${PG_DB}."

# Выполнение дампа базы и сжатие
if pg_dump -U "${PG_USER}" "${PG_DB}" | gzip > "${BACKUP_FILE}"; then
    log "Резервная копия успешно сохранена в ${BACKUP_FILE}."
else
    log "Ошибка при создании резервной копии."
    exit 1
fi

# Удаляем бэкапы старше RETENTION_DAYS
find "${BACKUP_DIR}" -type f -name "backup_*.sql.gz" -mtime +${RETENTION_DAYS} -exec rm -f {} \;
log "Удалены резервные копии старше ${RETENTION_DAYS} дней."

log "Резервное копирование завершено."

exit 0
