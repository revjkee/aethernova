#!/bin/bash
# path: platform-security/code-protection/intrusion_response/quarantine_repo.sh

# TeslaAI Quarantine System v2.4
# Назначение: изоляция подозрительного git-репозитория от внешнего доступа и разработчиков.
# Используется при обнаружении инцидентов, утечек или саботажа. Полностью автоматизирован.

set -euo pipefail

REPO_PATH=${1:-"/opt/genesis/core"}
QUARANTINE_ROOT="/var/quarantine"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%S")
QUARANTINE_PATH="${QUARANTINE_ROOT}/$(basename "$REPO_PATH")_$TIMESTAMP"
LOGFILE="/var/log/teslaai/quarantine_repo.log"
GUARD_ENDPOINT="http://localhost:8181/api/incident/ingest"

mkdir -p "$QUARANTINE_ROOT"

# === Шаг 1: Проверка наличия репозитория
if [ ! -d "$REPO_PATH/.git" ]; then
    echo "[ERROR] Не найден git-репозиторий в $REPO_PATH" | tee -a "$LOGFILE"
    exit 1
fi

# === Шаг 2: Изоляция
echo "[INFO] Изоляция репозитория $REPO_PATH..." | tee -a "$LOGFILE"
mv "$REPO_PATH" "$QUARANTINE_PATH"

# === Шаг 3: Удаление прав доступа (опционально)
chmod -R 000 "$QUARANTINE_PATH"
chattr -R +i "$QUARANTINE_PATH" || echo "[WARN] Не удалось установить immutable-флаг"

# === Шаг 4: Уведомление AI Guard
read -r -d '' PAYLOAD <<EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "host": "$(hostname -f)",
  "incident_type": "repository_quarantine",
  "severity": "critical",
  "quarantine_path": "${QUARANTINE_PATH}",
  "original_path": "${REPO_PATH}",
  "tags": ["repo_isolation", "security_event", "immutable"]
}
EOF

curl -s -X POST -H "Content-Type: application/json" \
     -d "${PAYLOAD}" "${GUARD_ENDPOINT}" >> "$LOGFILE" 2>&1

# === Шаг 5: Логирование
echo "[SUCCESS] Репозиторий изолирован: $QUARANTINE_PATH" | tee -a "$LOGFILE"
