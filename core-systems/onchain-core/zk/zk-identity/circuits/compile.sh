#!/bin/bash
set -euo pipefail

CIRCUIT_NAME="zk_identity"
BUILD_DIR="../build"
CIRCUIT_PATH="./${CIRCUIT_NAME}.circom"
PTAU_FILE="powersOfTau28_hez_final_21.ptau"

echo "[+] Создание папки сборки: ${BUILD_DIR}"
mkdir -p "$BUILD_DIR"

echo "[1] Компиляция Circom схемы..."
circom "$CIRCUIT_PATH" --r1cs --wasm --sym -o "$BUILD_DIR"

echo "[2] Проверка наличия PTAU-файла..."
if [ ! -f "$BUILD_DIR/$PTAU_FILE" ]; then
    echo "[2.1] Скачивание PTAU-файла..."
    curl -o "$BUILD_DIR/$PTAU_FILE" https://hermez.s3-eu-west-1.amazonaws.com/${PTAU_FILE}
fi

echo "[3] Генерация zkey (Groth16)..."
snarkjs groth16 setup "$BUILD_DIR/${CIRCUIT_NAME}.r1cs" "$BUILD_DIR/$PTAU_FILE" "$BUILD_DIR/${CIRCUIT_NAME}_groth16.zkey"

echo "[3.1] Экспорт верификатора (Groth16)..."
snarkjs zkey export verifier "$BUILD_DIR/${CIRCUIT_NAME}_groth16.zkey" "../contracts/VerifierGroth16.sol"

echo "[4] Генерация zkey (PLONK)..."
snarkjs plonk setup "$BUILD_DIR/${CIRCUIT_NAME}.r1cs" "$BUILD_DIR/$PTAU_FILE" "$BUILD_DIR/${CIRCUIT_NAME}_plonk.zkey"

echo "[4.1] Экспорт верификатора (PLONK)..."
snarkjs zkey export verifier "$BUILD_DIR/${CIRCUIT_NAME}_plonk.zkey" "../contracts/VerifierPlonk.sol"

echo "[5] Генерация метаданных схемы..."
snarkjs r1cs info "$BUILD_DIR/${CIRCUIT_NAME}.r1cs"

echo "[✔] Сборка завершена. Файлы:"
ls -lh "$BUILD_DIR"
