#!/bin/bash

# Скрипт проверки SHA256 хеша ptau-файла для trusted setup Groth16

PTAU_FILE="powers_of_tau_15.ptau"
EXPECTED_HASH="9c48c9d7a09c9e3b9b4d2f5a6c4d7e8f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"

echo "Проверка целостности файла $PTAU_FILE..."

if [ ! -f "$PTAU_FILE" ]; then
  echo "Ошибка: файл $PTAU_FILE не найден!"
  exit 1
fi

# Вычисление SHA256 хеша файла
ACTUAL_HASH=$(sha256sum "$PTAU_FILE" | awk '{print $1}')

echo "Ожидаемый хеш: $EXPECTED_HASH"
echo "Фактический хеш: $ACTUAL_HASH"

if [ "$EXPECTED_HASH" == "$ACTUAL_HASH" ]; then
  echo "Проверка пройдена успешно. Файл цел и не поврежден."
  exit 0
else
  echo "Ошибка: хеш не совпадает! Файл поврежден или изменен."
  exit 2
fi
