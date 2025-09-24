#!/usr/bin/env bash
# Filename: report_count_metric.sh
# Purpose : Export Prometheus metric with number of extracted post-exploitation reports

set -euo pipefail

METRIC_NAME="autopwn_generated_reports"
HELP_MSG="# HELP ${METRIC_NAME} Number of generated post-exploitation reports by autopwn"
TYPE_MSG="# TYPE ${METRIC_NAME} gauge"
EXPORT_PATH="/var/lib/node_exporter/textfile_collector/autopwn.prom"
REPORT_DIR="/tmp/reports"
TIMESTAMP="$(date +%s)"
LABELS="source=\"metasploit\",stage=\"post_exploitation\""

# Подсчёт валидных JSON-отчётов
COUNT=$(find "$REPORT_DIR" -type f -name "*.json" -exec jq empty {} \; -print 2>/dev/null | wc -l)

# Создание метрики
{
  echo "${HELP_MSG}"
  echo "${TYPE_MSG}"
  echo "${METRIC_NAME}{${LABELS}} ${COUNT}"
  echo "# TIMESTAMP ${TIMESTAMP}"
} > "$EXPORT_PATH"

# Логирование
logger -t autopwn-metric "Exported metric ${METRIC_NAME}=${COUNT} to ${EXPORT_PATH}"
