#!/bin/bash
# Скрипт генерации доказательства для Groth16 через CLI

set -e

if [ "$#" -ne 4 ]; then
    echo "Использование: $0 <circuit.wasm> <input.json> <circuit_final.zkey> <proof.json>"
    exit 1
fi

CIRCUIT_WASM=$1
INPUT_JSON=$2
ZKEY=$3
PROOF_JSON=$4

# Генерация proof и public signals
# Предполагается, что используется snarkjs CLI, он должен быть установлен

snarkjs groth16 prove $ZKEY $INPUT_JSON $PROOF_JSON

echo "Доказательство успешно сгенерировано и сохранено в $PROOF_JSON"
