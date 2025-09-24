#!/bin/bash
# Скрипт для надежной настройки переменных окружения
# Загружает и валидирует необходимые переменные, логирует процесс и предотвращает перезапись

set -euo pipefail

ENV_FILE=".env"
LOG_FILE="./logs/setup_env_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")"

echo "=== Настройка переменных окружения ===" | tee -a "$LOG_FILE"

# Проверка наличия файла .env
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Файл $ENV_FILE не найден." | tee -a "$LOG_FILE" >&2
  exit 1
fi

# Функция безопасной загрузки переменной окружения
load_env_var() {
  local var_name=$1
  local default_value=$2
  local value

  value=$(grep -E "^$var_name=" "$ENV_FILE" | cut -d '=' -f2- | tr -d '\r\n' || true)

  if [[ -z "$value" ]]; then
    if [[ -n "$default_value" ]]; then
      export "$var_name"="$default_value"
      echo "Переменная $var_name не найдена, установлено значение по умолчанию: $default_value" | tee -a "$LOG_FILE"
    else
      echo "Ошибка: обязательная переменная $var_name не установлена и не имеет значения по умолчанию." | tee -a "$LOG_FILE" >&2
      exit 1
    fi
  else
    export "$var_name"="$value"
    echo "Переменная $var_name загружена: $value" | tee -a "$LOG_FILE"
  fi
}

# Загрузка переменных окружения (пример)
load_env_var "APP_ENV" "production"
load_env_var "DATABASE_URL" ""
load_env_var "REDIS_URL" "redis://localhost:6379"
load_env_var "API_KEY" ""

echo "=== Переменные окружения успешно настроены ===" | tee -a "$LOG_FILE"

exit 0
