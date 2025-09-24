#!/bin/bash

# TeslaAI Genesis — Snapshot Restore Tool
# Автор: AI Platform DevOps Team

set -e

echo "🚨 [TeslaAI] ИНИЦИАЛИЗАЦИЯ ВОССТАНОВЛЕНИЯ ИЗ SNAPSHOT"
RESTORE_DATE=$(date +"%Y-%m-%d_%H-%M")
LOG_FILE="restore_log_$RESTORE_DATE.log"
mkdir -p logs && touch logs/$LOG_FILE

echo "🔍 Проверка наличия snapshot-файлов..."
SNAPSHOT_DIR="./volumes/backup"
REQUIRED_FILES=("redis.rdb" "postgres_dump.sql" "rabbitmq_definitions.json" "graph.json" "ai_state_log.json")

for FILE in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$SNAPSHOT_DIR/$FILE" ]; then
    echo "❌ Отсутствует файл: $FILE" | tee -a logs/$LOG_FILE
    exit 1
  fi
done

echo "✅ Все файлы найдены. Начинаем восстановление..." | tee -a logs/$LOG_FILE

# --- Redis ---
echo "🔁 Восстановление Redis..." | tee -a logs/$LOG_FILE
docker cp "$SNAPSHOT_DIR/redis.rdb" redis:/data/dump.rdb
docker exec redis redis-cli shutdown nosave
docker start redis
echo "✅ Redis восстановлен." | tee -a logs/$LOG_FILE

# --- PostgreSQL ---
echo "🔁 Восстановление PostgreSQL..." | tee -a logs/$LOG_FILE
cat "$SNAPSHOT_DIR/postgres_dump.sql" | docker exec -i postgres psql -U postgres
echo "✅ PostgreSQL восстановлен." | tee -a logs/$LOG_FILE

# --- RabbitMQ ---
echo "🔁 Восстановление RabbitMQ..." | tee -a logs/$LOG_FILE
docker cp "$SNAPSHOT_DIR/rabbitmq_definitions.json" rabbitmq:/etc/rabbitmq/definitions.json
docker restart rabbitmq
echo "✅ RabbitMQ восстановлен." | tee -a logs/$LOG_FILE

# --- Knowledge Graph ---
echo "🔁 Восстановление Knowledge Graph..." | tee -a logs/$LOG_FILE
cp "$SNAPSHOT_DIR/graph.json" ./genius-core/graph-core/snapshot/graph.json
echo "✅ Graph восстановлен." | tee -a logs/$LOG_FILE

# --- AI-State ---
echo "🔁 Восстановление AI-состояния..." | tee -a logs/$LOG_FILE
cp "$SNAPSHOT_DIR/ai_state_log.json" ./launch/self_state/ai_state_log.json
echo "✅ AI-состояние восстановлено." | tee -a logs/$LOG_FILE

# --- Integrity Check ---
echo "🔎 Проверка целостности после восстановления..." | tee -a logs/$LOG_FILE
python3 launch/recovery/integrity_verifier.py >> logs/$LOG_FILE

echo "🎉 Восстановление завершено успешно: $RESTORE_DATE" | tee -a logs/$LOG_FILE
