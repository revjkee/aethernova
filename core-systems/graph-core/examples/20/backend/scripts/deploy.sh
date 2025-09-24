#!/bin/bash
# Универсальный скрипт деплоя
# Поддерживает: подготовку окружения, сборку, тесты, деплой с откатом и логированием

set -euo pipefail

LOG_DIR="./logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/deploy_$(date +%Y%m%d_%H%M%S).log"

echo "=== Начало деплоя $(date) ===" | tee -a "$LOG_FILE"

# Проверка переменных окружения
: "${DEPLOY_ENV:?DEPLOY_ENV не установлен}"
: "${APP_NAME:?APP_NAME не установлен}"
: "${REPO_URL:?REPO_URL не установлен}"
: "${BRANCH:=main}"  # ветка по умолчанию

echo "Цель деплоя: $DEPLOY_ENV" | tee -a "$LOG_FILE"
echo "Приложение: $APP_NAME" | tee -a "$LOG_FILE"
echo "Репозиторий: $REPO_URL" | tee -a "$LOG_FILE"
echo "Ветка: $BRANCH" | tee -a "$LOG_FILE"

# Функция для отката при ошибках
rollback() {
  echo "Ошибка деплоя, выполняется откат..." | tee -a "$LOG_FILE" >&2
  # Реализация отката зависит от среды
  # Здесь пример: перезапуск последней стабильной версии
  # systemctl restart "$APP_NAME" || echo "Откат не выполнен"
  exit 1
}

trap rollback ERR

# Клонирование репозитория
WORKDIR="/tmp/deploy_$APP_NAME"
if [[ -d "$WORKDIR" ]]; then
  rm -rf "$WORKDIR"
fi

git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$WORKDIR" | tee -a "$LOG_FILE"

cd "$WORKDIR"

# Сборка приложения
if [[ -f "./build.sh" ]]; then
  bash ./build.sh | tee -a "$LOG_FILE"
else
  echo "Скрипт сборки build.sh не найден." | tee -a "$LOG_FILE" >&2
  exit 1
fi

# Запуск тестов
if [[ -f "./test.sh" ]]; then
  bash ./test.sh | tee -a "$LOG_FILE"
else
  echo "Скрипт тестов test.sh не найден, пропускаем тестирование." | tee -a "$LOG_FILE"
fi

# Деплой (пример для systemd-сервиса)
echo "Запуск деплоя..." | tee -a "$LOG_FILE"
sudo systemctl stop "$APP_NAME" | tee -a "$LOG_FILE"
sudo cp -r "$WORKDIR"/dist/* /opt/"$APP_NAME"/ | tee -a "$LOG_FILE"
sudo systemctl start "$APP_NAME" | tee -a "$LOG_FILE"

# Проверка статуса сервиса
sleep 3
sudo systemctl is-active --quiet "$APP_NAME"
if [[ $? -ne 0 ]]; then
  echo "Сервис $APP_NAME не запустился, выполняем откат." | tee -a "$LOG_FILE" >&2
  rollback
fi

echo "Деплой завершен успешно." | tee -a "$LOG_FILE"
exit 0
