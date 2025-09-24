#!/bin/bash
# Скрипт запуска комплексной проверки безопасности кода и инфраструктуры
# Запускает статический анализ, проверку зависимостей, сканирование уязвимостей и отчетность

set -euo pipefail

LOG_DIR="./security_logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$LOG_DIR/security_report_$TIMESTAMP.txt"

echo "=== Запуск проверки безопасности: $TIMESTAMP ===" | tee -a "$REPORT_FILE"

# 1. Статический анализ кода с помощью SonarQube Scanner
if command -v sonar-scanner &> /dev/null; then
  echo "Запуск SonarQube Scanner..." | tee -a "$REPORT_FILE"
  sonar-scanner >> "$REPORT_FILE" 2>&1
else
  echo "SonarQube Scanner не установлен, пропуск..." | tee -a "$REPORT_FILE"
fi

# 2. Проверка зависимостей на известные уязвимости (для Python - Safety)
if command -v safety &> /dev/null; then
  echo "Проверка зависимостей Safety..." | tee -a "$REPORT_FILE"
  safety check >> "$REPORT_FILE" 2>&1
else
  echo "Safety не установлен, пропуск проверки зависимостей..." | tee -a "$REPORT_FILE"
fi

# 3. Запуск Snyk для проверки контейнеров и инфраструктуры (если настроено)
if command -v snyk &> /dev/null; then
  echo "Запуск Snyk тестирования..." | tee -a "$REPORT_FILE"
  snyk test >> "$REPORT_FILE" 2>&1 || echo "Snyk обнаружил уязвимости." | tee -a "$REPORT_FILE"
else
  echo "Snyk не установлен, пропуск..." | tee -a "$REPORT_FILE"
fi

# 4. Скрипт проверки прав доступа и конфигураций (custom check)
echo "Проверка прав доступа и конфигураций..." | tee -a "$REPORT_FILE"
find . -type f -perm /o+w -exec ls -l {} \; >> "$REPORT_FILE" || true

# 5. Итоговый отчет
echo "=== Проверка безопасности завершена ===" | tee -a "$REPORT_FILE"
echo "Отчет сохранён в $REPORT_FILE"

exit 0
