#!/bin/bash
#
# Скрипт для триггера запуска CI/CD пайплайна.
# Поддерживает интеграцию с Jenkins, GitHub Actions и другими системами с REST API.
# Обеспечивает безопасность, валидацию параметров и логирование.
#

set -euo pipefail

# Обязательные переменные окружения
: "${PIPELINE_URL:?Необходимо установить PIPELINE_URL}"
: "${API_TOKEN:?Необходимо установить API_TOKEN}"

# Опциональные параметры
BRANCH="${BRANCH:-main}"
BUILD_PARAMS="${BUILD_PARAMS:-}"

LOG_FILE="${LOG_FILE:-/var/log/ci_cd_trigger.log}"

timestamp() {
  date +"%Y-%m-%d %H:%M:%S"
}

log() {
  echo "$(timestamp) - $*" | tee -a "$LOG_FILE"
}

trigger_build() {
  local payload

  if [[ -z "$BUILD_PARAMS" ]]; then
    payload="{\"branch\":\"$BRANCH\"}"
  else
    payload="{\"branch\":\"$BRANCH\", \"params\":$BUILD_PARAMS}"
  fi

  log "Отправка запроса на запуск сборки: $payload"

  response=$(curl -s -w "%{http_code}" -o /tmp/ci_response.txt -X POST "$PIPELINE_URL" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$payload")

  http_code="${response: -3}"
  body=$(cat /tmp/ci_response.txt)

  if [[ "$http_code" =~ ^2 ]]; then
    log "Сборка успешно запущена: $body"
  else
    log "Ошибка запуска сборки. HTTP код: $http_code, ответ: $body"
    exit 1
  fi
}

main() {
  log "=== Запуск триггера CI/C
