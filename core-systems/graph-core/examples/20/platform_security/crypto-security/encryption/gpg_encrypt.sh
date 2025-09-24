#!/bin/bash
# gpg_encrypt.sh — Промышленный скрипт для шифрования исходного кода через GPG
# TeslaAI Genesis · 20x усиление защиты
# Раздел: platform-security/code-protection/encryption/

set -euo pipefail

# === Конфигурация ===
GPG_KEY_ID="teslaai-secure@example.com"      # Получатель/владелец ключа
INPUT_DIR="$1"                               # Папка или файл для шифрования
LOG_FILE="/var/log/teslaai_gpg_encrypt.log"  # Журнал действий
ENCRYPTED_DIR="encrypted_output"             # Каталог с зашифрованным выводом

# === Проверка ключа ===
if ! gpg --list-keys "$GPG_KEY_ID" >/dev/null 2>&1; then
    echo "[ERROR] Ключ GPG $GPG_KEY_ID не найден." | tee -a "$LOG_FILE"
    exit 1
fi

# === Подготовка вывода ===
mkdir -p "$ENCRYPTED_DIR"

encrypt_file() {
    local file="$1"
    local rel_path="${file#$INPUT_DIR/}"
    local enc_file="$ENCRYPTED_DIR/$rel_path.gpg"

    mkdir -p "$(dirname "$enc_file")"

    gpg --batch --yes --recipient "$GPG_KEY_ID" --output "$enc_file" --encrypt "$file" && \
    echo "[OK] Encrypted $file to $enc_file" >> "$LOG_FILE"
}

# === Основная логика ===
if [ -d "$INPUT_DIR" ]; then
    find "$INPUT_DIR" -type f ! -name "*.gpg" | while read -r file; do
        encrypt_file "$file"
    done
elif [ -f "$INPUT_DIR" ]; then
    encrypt_file "$INPUT_DIR"
else
    echo "[ERROR] Файл или папка $INPUT_DIR не найдены." | tee -a "$LOG_FILE"
    exit 1
fi

echo "[FINISHED] Шифрование завершено: $(date)" >> "$LOG_FILE"
