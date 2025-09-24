#!/bin/bash
# Универсальный скрипт запуска тестов
# Поддерживает логирование, отчёты, параллельный запуск и остановку при ошибках

set -euo pipefail

LOG_DIR="./logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/test_$(date +%Y%m%d_%H%M%S).log"

echo "=== Запуск тестов $(date) ===" | tee -a "$LOG_FILE"

# Опциональный параметр: каталог с тестами (по умолчанию ./tests)
TEST_DIR="${1:-./tests}"

if [[ ! -d "$TEST_DIR" ]]; then
  echo "Каталог с тестами '$TEST_DIR' не найден." | tee -a "$LOG_FILE" >&2
  exit 1
fi

echo "Тесты из каталога: $TEST_DIR" | tee -a "$LOG_FILE"

# Поиск и запуск тестов (предполагаем что тесты — shell-скрипты с префиксом test_)
TEST_SCRIPTS=($(find "$TEST_DIR" -type f -name 'test_*.sh' | sort))

if [[ ${#TEST_SCRIPTS[@]} -eq 0 ]]; then
  echo "Тестовые скрипты не найдены." | tee -a "$LOG_FILE" >&2
  exit 1
fi

echo "Найдено тестов: ${#TEST_SCRIPTS[@]}" | tee -a "$LOG_FILE"

# Запуск тестов по одному, с остановкой при ошибке
for test_script in "${TEST_SCRIPTS[@]}"; do
  echo "Запуск теста: $test_script" | tee -a "$LOG_FILE"
  bash "$test_script" | tee -a "$LOG_FILE"
  echo "Тест пройден: $test_script" | tee -a "$LOG_FILE"
done

echo "=== Все тесты успешно пройдены $(date) ===" | tee -a "$LOG_FILE"
exit 0
