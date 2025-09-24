#!/bin/bash
# Скрипт для отката базы данных к предыдущему состоянию из резервной копии
# Обеспечивает безопасность, логи и контроль ошибок

set -euo pipefail

# Конфигурация
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-mydatabase}"
DB_USER="${DB_USER:-postgres}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/db}"
LOG_FILE="${LOG_FILE:-/var/log/rollback_db.log}"

# Функция логирования с меткой времени
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# Проверка наличия pg_restore и psql
if ! command -v pg_restore &> /dev/null; then
    log "Ошибка: pg_restore не найден в PATH."
    exit 1
fi

if ! command -v psql &> /dev/null; then
    log "Ошибка: psql не найден в PATH."
    exit 1
fi

# Поиск последней резервной копии для отката
LAST_BACKUP=$(ls -1t "$BACKUP_DIR"/*.dump 2>/dev/null | head -n 1 || true)

if [[ -z "$LAST_BACKUP" ]]; then
    log "Нет резервных копий для отката в директории $BACKUP_DIR."
    exit 1
fi

log "Начинается откат базы данных '$DB_NAME' с использованием резервной копии: $LAST_BACKUP"

# Отключение подключения к базе перед восстановлением
log "Отключаем активные подключения к базе '$DB_NAME'"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "
    REVOKE CONNECT ON DATABASE \"$DB_NAME\" FROM PUBLIC;
    SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();
"

# Восстановление базы из резервной копии
log "Восстановление базы данных..."
pg_restore --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" --dbname="$DB_NAME" --clean --no-owner "$LAST_BACKUP"

# Восстановление прав на подключение
log "Восстанавливаем права подключения к базе '$DB_NAME'"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "
    GRANT CONNECT ON DATABASE \"$DB_NAME\" TO PUBLIC;
"

log "Откат базы данных завершен успешно."

exit 0
