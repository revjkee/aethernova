#!/bin/bash

set -euo pipefail

NAMESPACE="monitoring"
RELEASE_NAME="grafana"
CHART_REPO="https://grafana.github.io/helm-charts"
CHART_NAME="grafana/grafana"
VALUES_FILE="./grafana-values.yaml"

echo "[1/6] Проверка наличия Helm..."
if ! command -v helm &> /dev/null; then
  echo "Helm не установлен. Установите Helm и повторите."
  exit 1
fi

echo "[2/6] Создание namespace '${NAMESPACE}' если он не существует..."
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"

echo "[3/6] Добавление репозитория Helm-чартов Grafana..."
helm repo add grafana "${CHART_REPO}" || true
helm repo update

echo "[4/6] Проверка наличия файла значений Grafana..."
if [[ ! -f "${VALUES_FILE}" ]]; then
  echo "Файл ${VALUES_FILE} не найден. Создайте его перед деплоем."
  exit 1
fi

echo "[5/6] Установка или обновление Grafana..."
helm upgrade --install "${RELEASE_NAME}" "${CHART_NAME}" \
  --namespace "${NAMESPACE}" \
  --values "${VALUES_FILE}" \
  --atomic \
  --create-namespace

echo "[6/6] Grafana успешно развернута в namespace '${NAMESPACE}'"
