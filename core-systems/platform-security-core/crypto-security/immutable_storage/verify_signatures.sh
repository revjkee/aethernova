#!/bin/bash
# path: platform-security/code-protection/immutable_storage/verify_signatures.sh

# TeslaAI Genesis — Digital Signature Verifier (enhanced x20)
# Проверка цифровых подписей всех файлов репозитория для защиты от подмены, саботажа и внедрения вредоносного кода

set -e

TRUSTED_KEYS_DIR=".gpg/trusted"
FILES_LIST=$(git ls-files)
LOG_FILE="/var/log/teslaai_signature_audit.log"
VERBOSE=true

echo "[✓] Starting digital signature verification..."
echo "-----------------------------" >> "$LOG_FILE"
echo "[SIGNATURE AUDIT] $(date)" >> "$LOG_FILE"

if [ ! -d "$TRUSTED_KEYS_DIR" ]; then
    echo "[ERROR] Директория с доверенными ключами не найдена: $TRUSTED_KEYS_DIR"
    exit 1
fi

# Импорт всех доверенных GPG-ключей
for keyfile in "$TRUSTED_KEYS_DIR"/*.asc; do
    gpg --import "$keyfile" >/dev/null 2>&1 || {
        echo "[ERROR] Не удалось импортировать ключ $keyfile"
        exit 1
    }
done

# Проверка подписей файлов
for file in $FILES_LIST; do
    if [[ "$file" == *.sig ]]; then
        continue
    fi

    if [ -f "${file}.sig" ]; then
        if gpg --verify "${file}.sig" "$file" &>/dev/null; then
            $VERBOSE && echo "[OK] $file — подпись действительна"
            echo "[OK] $file" >> "$LOG_FILE"
        else
            echo "[FAIL] $file — НЕ ПРОЙДЕНА проверка подписи"
            echo "[FAIL] $file" >> "$LOG_FILE"
            exit 1
        fi
    else
        echo "[WARN] $file — подпись не найдена"
        echo "[WARN] $file" >> "$LOG_FILE"
    fi
done

echo "[✓] Проверка подписей завершена успешно."
