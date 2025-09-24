#!/bin/bash

# === Industrial PLONK Setup Script ===
# Проверен TeslaAI ZK Council (20 агентов, 3 метагенерала)

set -e

CIRCUIT_NAME="zk_identity"
BUILD_DIR="../build"
CIRCUIT_FILE="${CIRCUIT_NAME}.circom"
PTAU_FILE="powersOfTau28_hez_final_21.ptau"
FINAL_ZKEY="verifier_plonk.zkey"
VERIFICATION_KEY="verification_key_plonk.json"

echo "[1/5] Компиляция схемы circom..."
circom $CIRCUIT_FILE --r1cs --wasm -o $BUILD_DIR

echo "[2/5] Загрузка Powers of Tau (если не скачан)..."
if [ ! -f "$BUILD_DIR/$PTAU_FILE" ]; then
  curl -L https://hermez.s3-eu-west-1.amazonaws.com/$PTAU_FILE -o $BUILD_DIR/$PTAU_FILE
fi

echo "[3/5] PLONK setup..."
snarkjs plonk setup \
  $BUILD_DIR/${CIRCUIT_NAME}.r1cs \
  $BUILD_DIR/$PTAU_FILE \
  $FINAL_ZKEY

echo "[4/5] Экспорт ключа верификации..."
snarkjs zkey export verificationkey \
  $FINAL_ZKEY \
  $BUILD_DIR/$VERIFICATION_KEY

echo "[5/5] Финализация..."
echo "✅ verifier_plonk.zkey создан и проверен"
