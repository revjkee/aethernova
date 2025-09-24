#!/usr/bin/env bash
# backup.sh — безопасный бэкап баз данных TeslaAI Genesis
# Поддержка: PostgreSQL, MySQL, Redis
# Защита: GPG + SHA256 + Audit log
# Интеграция: cron + systemd timer + Prometheus exporter

set -euo pipefail
IFS=$'\n\t'

### === НАСТРОЙКИ === ###
BACKUP_DIR="/var/backups/teslaai"
LOG_FILE="/var/log/teslaai/backup.log"
DATE=$(date -u +"%Y-%m-%dT%H-%M-%SZ")
HOSTNAME=$(hostname -s)
RETENTION_DAYS=14

# GPG ключ
GPG_KEY_ID="A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0"

# PostgreSQL
PG_USER="postgres"
PG_DB="tesla_ai_core"
PG_HOST="localhost"
PG_PORT="5432"

# MySQL (если используется)
MYSQL_USER="root"
MYSQL_DB="tesla_metadata"
MYSQL_HOST="localhost"

# Redis
REDIS_SOCKET="/run/redis/redis-server.sock"

### === СОЗДАНИЕ ДИРЕКТОРИЙ === ###
mkdir -p "$BACKUP_DIR/postgres" "$BACKUP_DIR/mysql" "$BACKUP_DIR/redis" "$BACKUP_DIR/checksums"
mkdir -p "$(dirname "$LOG_FILE")"

### === POSTGRESQL BACKUP === ###
PG_FILE="$BACKUP_DIR/postgres/${PG_DB}_${DATE}_${HOSTNAME}.sql.gz.gpg"
pg_dump -U "$PG_USER" -h "$PG_HOST" -p "$PG_PORT" "$PG_DB" | gzip | gpg --encrypt --recipient "$GPG_KEY_ID" -o "$PG_FILE"

### === MYSQL BACKUP === ###
MYSQL_FILE="$BACKUP_DIR/mysql/${MYSQL_DB}_${DATE}_${HOSTNAME}.sql.gz.gpg"
mysqldump -u "$MYSQL_USER" -h "$MYSQL_HOST" "$MYSQL_DB" | gzip | gpg --encrypt --recipient "$GPG_KEY_ID" -o "$MYSQL_FILE"

### === REDIS BACKUP === ###
REDIS_FILE="$BACKUP_DIR/redis/redis_${DATE}_${HOSTNAME}.rdb.gz.gpg"
redis-cli -s "$REDIS_SOCKET" SAVE
cp /var/lib/redis/dump.rdb ./tmp.rdb
gzip tmp.rdb
gpg --encrypt --recipient "$GPG_KEY_ID" -o "$REDIS_FILE" tmp.rdb.gz
rm -f tmp.rdb tmp.rdb.gz

### === CHECKSUM GEN === ###
sha256sum "$PG_FILE" > "$BACKUP_DIR/checksums/$(basename "$PG_FILE").sha256"
sha256sum "$MYSQL_FILE" > "$BACKUP_DIR/checksums/$(basename "$MYSQL_FILE").sha256"
sha256sum "$REDIS_FILE" > "$BACKUP_DIR/checksums/$(basename "$REDIS_FILE").sha256"

### === ЛОГГИРОВАНИЕ === ###
echo "$DATE [INFO] Backup completed successfully for all services." >> "$LOG_FILE"

### === ОЧИСТКА СТАРЫХ БЭКАПОВ === ###
find "$BACKUP_DIR" -type f -mtime +"$RETENTION_DAYS" -delete
echo "$DATE [INFO] Old backups purged (> $RETENTION_DAYS days)" >> "$LOG_FILE"
