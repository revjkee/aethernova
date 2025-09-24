#!/bin/bash
set -euo pipefail

# Логируем время запуска
echo "Deploy started at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Проверка обязательных переменных окружения
: "${DEPLOY_ENV:?DEPLOY_ENV is not set}"
: "${APP_NAME:?APP_NAME is not set}"

echo "Deploying application: $APP_NAME to environment: $DEPLOY_ENV"

# Настройка kubeconfig (пример для Kubernetes)
if [[ -n "${KUBECONFIG_PATH:-}" ]]; then
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo "Using KUBECONFIG at $KUBECONFIG"
else
    echo "KUBECONFIG_PATH not set, assuming default kubeconfig location"
fi

# Подтягиваем последние изменения (если применимо)
if [[ -d "./deployment" ]]; then
    echo "Updating deployment manifests..."
    git -C ./deployment pull origin main
fi

# Применяем конфигурацию Kubernetes с проверкой
echo "Applying Kubernetes manifests..."
kubectl apply --dry-run=client -f ./deployment/manifests/
kubectl apply -f ./deployment/manifests/

# Проверка статуса деплоя с таймаутом
echo "Waiting for deployment rollout to complete..."
kubectl rollout status deployment/$APP_NAME -n $DEPLOY_ENV --timeout=120s

echo "Deployment successful."

# Очистка старых образов и логов, если нужно (пример)
if [[ -n "${CLEANUP_OLD_IMAGES:-}" && "$CLEANUP_OLD_IMAGES" == "true" ]]; then
    echo "Cleaning up old Docker images..."
    docker image prune -af
fi

# Логируем время окончания
echo "Deploy finished at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

exit 0
