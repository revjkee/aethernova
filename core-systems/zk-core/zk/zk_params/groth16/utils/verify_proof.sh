#!/bin/bash
# Скрипт проверки доказательства для Groth16 через CLI

set -e

if [ "$#" -ne 4 ]; then
    echo "Использование: $0 <verification_key.json> <public.json> <proof.json> <output.txt>"
    exit 1
fi

VERIFICATION_KEY=$1
PUBLIC_JSON=$2
PROOF_JSON=$3
OUTPUT_FILE=$4

# Проверка доказательства с помощью snarkjs CLI
snarkjs groth16 verify $VERIFICATION_KEY $PUBLIC_JSON $PROOF_JSON > $OUTPUT_FILE 2>&1

if grep -q "Verification OK" $OUTPUT_FILE; then
    echo "Доказательство успешно проверено."
else
    echo "Ошибка проверки доказательства. Подробности в $OUTPUT_FILE"
    exit 1
fi
