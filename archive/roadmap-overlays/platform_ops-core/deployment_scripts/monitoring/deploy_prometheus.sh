#!/bin/bash

set -euo pipefail

NAMESPACE="monitoring"
RELEASE_NAME="prometheus"
CHART_REPO="https://prometheus-community.github.io/helm-charts"
CHART_NAME="prometheus-community/prometheus"
VALUES_FILE="./prometheus-values.yaml"

echo "[1/5] Проверка наличия Helm..."
if ! command -v helm &> /dev/null; then
  echo "Helm не установлен. Установите Helm и повторите попытку."
  exit 1
fi

echo "[2/5] Создание namespace '${NAMESPACE}' если он не существует..."
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"

echo "[3/5] Добавление репозитория Helm-чартов Prometheus..."
helm repo add prometheus-community "${CHART_REPO}" || true
helm repo update

echo "[4/5] Установка или обновление Prometheus с пользовательскими параметрами..."
helm upgrade --install "${RELEASE_NAME}" "${CHART_NAME}" \
  --namespace "${NAMESPACE}" \
  --values "${VALUES_FILE}" \
  --atomic \
  --create-namespace

echo "[5/5] Prometheus успешно развернут в namespace '${NAMESPACE}'"
