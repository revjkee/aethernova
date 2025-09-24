#!/bin/bash
set -euo pipefail

CIRCUIT_NAME="zk_identity"
BUILD_DIR="../build"
PTAU_FILE="powersOfTau28_hez_final_21.ptau"
PTAU_URL="https://hermez.s3-eu-west-1.amazonaws.com/$PTAU_FILE"
ZKEY_FINAL="${CIRCUIT_NAME}_final.zkey"
ZKEY_INITIAL="${CIRCUIT_NAME}_init.zkey"
BEACON_HEX="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
BEACON_DESC="NeuroCity Genesis Ceremony Beacon"

mkdir -p "$BUILD_DIR"

echo "[1] Проверка PTAU-файла..."
if [ ! -f "$BUILD_DIR/$PTAU_FILE" ]; then
  echo "[1.1] PTAU-файл отсутствует, загружаю..."
  curl -L "$PTAU_URL" -o "$BUILD_DIR/$PTAU_FILE"
else
  echo "[1.2] PTAU-файл найден: $PTAU_FILE"
fi

echo "[2] Инициализация zKey..."
snarkjs groth16 setup \
  "$BUILD_DIR/${CIRCUIT_NAME}.r1cs" \
  "$BUILD_DIR/$PTAU_FILE" \
  "$BUILD_DIR/$ZKEY_INITIAL"

echo "[3] Внесение энтропии через beacon..."
snarkjs zkey beacon \
  "$BUILD_DIR/$ZKEY_INITIAL" \
  "$BUILD_DIR/$ZKEY_FINAL" \
  "$BEACON_HEX" \
  "$BEACON_DESC"

echo "[4] Проверка финального zKey..."
snarkjs zkey verify \
  "$BUILD_DIR/${CIRCUIT_NAME}.r1cs" \
  "$BUILD_DIR/$PTAU_FILE" \
  "$BUILD_DIR/$ZKEY_FINAL"

echo "[5] Экспорт структуры схемы..."
snarkjs zkey export verificationkey "$BUILD_DIR/$ZKEY_FINAL" "$BUILD_DIR/verification_key.json"

echo "[✔] Trusted setup завершён: zKey готов, ключ верификации экспортирован"
