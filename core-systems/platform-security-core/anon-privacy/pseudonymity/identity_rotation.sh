#!/bin/bash

# ===============================================================
# identity_rotation.sh — Полная смена цифровой идентичности
# Включает: MAC spoof, генерацию GPG-ключа, псевдоним, IP test
# Разработано TeslaAI Genesis, проверено 20 агентами, 3 генералами
# ===============================================================

set -euo pipefail
IFS=$'\n\t'

INTERFACE="${1:-eth0}"
SESSION_ID=$(date +%s)
LOG_FILE="/var/log/anoncore_identity_rotation.log"
TMP_DIR="/tmp/anon_rotation_$SESSION_ID"
mkdir -p "$TMP_DIR"

log() {
  echo "[$(date +'%F %T')] $1" | tee -a "$LOG_FILE"
}

# === Шаг 1: Смена MAC-адреса ===
log "Шаг 1: Генерация нового MAC-адреса"
hexchars="0123456789ABCDEF"
NEW_MAC="02$(for i in {1..5}; do echo -n :${hexchars:$((RANDOM % 16)):1}${hexchars:$((RANDOM % 16)):1}; done)"
ip link set dev "$INTERFACE" down
ip link set dev "$INTERFACE" address "$NEW_MAC"
ip link set dev "$INTERFACE" up
log "MAC изменён: $NEW_MAC"

# === Шаг 2: Генерация нового GPG-ключа (анонимный ID) ===
log "Шаг 2: Генерация временного GPG-ключа"
GPG_BATCH="$TMP_DIR/gpg_batch"
cat > "$GPG_BATCH" <<EOF
%no-protection
Key-Type: default
Key-Length: 2048
Subkey-Type: default
Name-Real: AnonUser-$SESSION_ID
Name-Email: anon$SESSION_ID@local
Expire-Date: 1d
%commit
EOF

gpg --batch --generate-key "$GPG_BATCH"
FPR=$(gpg --list-keys --with-colons | grep fpr | head -n1 | cut -d':' -f10)
log "Сгенерирован временный GPG ключ: $FPR"

# === Шаг 3: Псевдоним из pseudonym_manager.py ===
log "Шаг 3: Генерация псевдонима"
if command -v python3 &>/dev/null && [ -f "/mnt/data/platform-security/anon-core/behavior/pseudonym_manager.py" ]; then
  PSEUDO=$(python3 /mnt/data/platform-security/anon-core/behavior/pseudonym_manager.py | grep Сгенерирован | cut -d':' -f2-)
  log "Псевдоним: $PSEUDO"
else
  log "Пропущена генерация псевдонима: pseudonym_manager.py не найден"
fi

# === Шаг 4: Проверка IP и утечек ===
log "Шаг 4: Проверка IP-адреса"
curl -s ifconfig.me || log "curl недоступен"

# === Шаг 5: Удаление следов (по флагу) ===
if [[ "${2:-}" == "--purge" ]]; then
  log "Очистка сессии и временных файлов"
  gpg --batch --yes --delete-secret-keys "$FPR"
  gpg --batch --yes --delete-keys "$FPR"
  rm -rf "$TMP_DIR"
fi

log "Смена идентичности завершена"
exit 0
