#!/usr/bin/env bash
# restore.sh — безопасное восстановление из зашифрованных бэкапов TeslaAI Genesis
# Поддержка восстановления PostgreSQL, MySQL, Redis
# Требуется наличие GPG ключа для дешифровки

set -euo pipefail
IFS=$'\n\t'

### === НАСТРОЙКИ === ###
BACKUP_DIR="/var/backups/teslaai"
GPG_KEY_ID="A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0"

# PostgreSQL
PG_USER="postgres"
PG_DB="tesla_ai_core"
PG_HOST="localhost"
PG_PORT="5432"

# MySQL
MYSQL_USER="root"
MYSQL_DB="tesla_metadata"
MYSQL_HOST="localhost"

# Redis
REDIS_DIR="/var/lib/redis"

### === ФУНКЦИИ === ###
function usage() {
  echo "Использование: $0 <service> <backup_file>"
  echo "  service: postgres | mysql | redis"
  echo "  backup_file: полный путь к зашифрованному backup файлу"
  exit 1
}

function check_file() {
  if [[ ! -f "$1" ]]; then
    echo "Ошибка: файл $1 не найден"
    exit 2
  fi
}

function restore_postgres() {
  local backup_file="$1"
  echo "Восстановление PostgreSQL из $backup_file..."
  gpg --decrypt "$backup_file" | gunzip | psql -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" "$PG_DB"
  echo "PostgreSQL восстановлен успешно."
}

function restore_mysql() {
  local backup_file="$1"
  echo "Восстановление MySQL из $backup_file..."
  gpg --decrypt "$backup_file" | gunzip | mysql -u "$MYSQL_USER" -h "$MYSQL_HOST" "$MYSQL_DB"
  echo "MySQL восстановлен успешно."
}

function restore_redis() {
  local backup_file="$1"
  echo "Восстановление Redis из $backup_file..."
  local tmpfile=$(mktemp)
  gpg --decrypt "$backup_file" | gunzip > "$tmpfile"
  systemctl stop redis.service
  cp "$tmpfile" "$REDIS_DIR/dump.rdb"
  chown redis:redis "$REDIS_DIR/dump.rdb"
  systemctl start redis.service
  rm -f "$tmpfile"
  echo "Redis восстановлен успешно."
}

### === MAIN === ###
if [[ $# -ne 2 ]]; then
  usage
fi

SERVICE="$1"
BACKUP_FILE="$2"
check_file "$BACKUP_FILE"

case "$SERVICE" in
  postgres)
    restore_postgres "$BACKUP_FILE"
    ;;
  mysql)
    restore_mysql "$BACKUP_FILE"
    ;;
  redis)
    restore_redis "$BACKUP_FILE"
    ;;
  *)
    echo "Ошибка: неизвестный сервис '$SERVICE'. Допустимо: postgres, mysql, redis"
    usage
    ;;
esac
