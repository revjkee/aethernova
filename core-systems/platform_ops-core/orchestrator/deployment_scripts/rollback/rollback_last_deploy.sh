#!/bin/bash
# Скрипт для безопасного отката последнего деплоя в Kubernetes кластере с логированием и проверками

set -euo pipefail

# Конфигурация
NAMESPACE="${NAMESPACE:-default}"
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-my-app}"
KUBECTL="${KUBECTL:-kubectl}"
LOG_FILE="${LOG_FILE:-/var/log/rollback_last_deploy.log}"

# Функция логирования с меткой времени
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# Проверка наличия kubectl
if ! command -v $KUBECTL &> /dev/null; then
    echo "Ошибка: kubectl не установлен или не доступен в PATH."
    exit 1
fi

log "Начинаем откат последнего деплоя для деплоймента '$DEPLOYMENT_NAME' в namespace '$NAMESPACE'"

# Получение истории ревизий деплоймента
REVISIONS=$($KUBECTL rollout history deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" --no-headers | awk '{print $1}' | sort -r)
CURRENT_REVISION=$($KUBECTL rollout status deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" | grep -oE 'revision: [0-9]+' | awk '{print $2}')

if [[ -z "$CURRENT_REVISION" ]]; then
    log "Не удалось определить текущую ревизию. Откат невозможен."
    exit 1
fi

log "Текущая ревизия: $CURRENT_REVISION"

# Определение ревизии для отката (предыдущая)
PREV_REVISION=$(echo "$REVISIONS" | grep -v "^$CURRENT_REVISION$" | head -n 1)

if [[ -z "$PREV_REVISION" ]]; then
    log "Нет предыдущей ревизии для отката."
    exit 1
fi

log "Откат на ревизию: $PREV_REVISION"

# Выполнение отката
$KUBECTL rollout undo deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE" --to-revision="$PREV_REVISION"

log "Запуск проверки статуса деплоймента после отката..."
$KUBECTL rollout status deployment "$DEPLOYMENT_NAME" -n "$NAMESPACE"

log "Откат успешно завершен."

exit 0
