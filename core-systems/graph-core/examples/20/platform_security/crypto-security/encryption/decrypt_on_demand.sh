#!/bin/bash
# decrypt_on_demand.sh — Промышленный скрипт расшифровки исходного кода по требованию
# TeslaAI Genesis · 20-кратная усиленная защита
# Раздел: platform-security/code-protection/encryption/

set -euo pipefail

# === Конфигурация ===
AUTHORIZED_USERS=("root" "devops" "aiops")
GPG_PASSPHRASE_ENV="TESLAAI_GPG_PASSPHRASE"
LOG_FILE="/var/log/teslaai_gpg_decrypt.log"
INPUT_FILE="$1"
OUTPUT_FILE="${2:-$(basename "$INPUT_FILE" .gpg)}"
CHECKSUM_FILE="${INPUT_FILE}.sha256"

# === Проверка прав пользователя ===
CURRENT_USER=$(whoami)
if [[ ! " ${AUTHORIZED_USERS[*]} " =~ " ${CURRENT_USER} " ]]; then
    echo "[DENIED] Пользователь $CURRENT_USER не авторизован." | tee -a "$LOG_FILE"
    exit 1
fi

# === Проверка переменной с паролем ===
if [[ -z "${!GPG_PASSPHRASE_ENV:-}" ]]; then
    echo "[ERROR] Пароль GPG не найден в переменной окружения $GPG_PASSPHRASE_ENV." | tee -a "$LOG_FILE"
    exit 1
fi

# === Проверка контрольной суммы ===
if [[ -f "$CHECKSUM_FILE" ]]; then
    echo "[INFO] Проверка контрольной суммы..." >> "$LOG_FILE"
    sha256sum -c "$CHECKSUM_FILE" >> "$LOG_FILE" 2>&1 || {
        echo "[FAIL] Контрольная сумма не совпадает. Расшифровка прервана." | tee -a "$LOG_FILE"
        exit 1
    }
fi

# === Расшифровка файла ===
echo "[START] Расшифровка файла $INPUT_FILE пользователем $CURRENT_USER..." >> "$LOG_FILE"

gpg --batch --yes --passphrase "${!GPG_PASSPHRASE_ENV}" \
    --output "$OUTPUT_FILE" --decrypt "$INPUT_FILE" && \
    echo "[OK] Расшифровка завершена: $OUTPUT_FILE" >> "$LOG_FILE"

# === Проверка успешного вывода ===
if [[ -f "$OUTPUT_FILE" ]]; then
    echo "[SUCCESS] Файл расшифрован: $(realpath "$OUTPUT_FILE")" >> "$LOG_FILE"
else
    echo "[ERROR] Файл $OUTPUT_FILE не был создан." | tee -a "$LOG_FILE"
    exit 1
fi
