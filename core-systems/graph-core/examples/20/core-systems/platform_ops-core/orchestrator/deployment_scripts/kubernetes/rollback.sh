#!/bin/bash

# ================================
# Kubernetes Rollback Script
# TeslaAI Genesis Platform
# ================================

set -euo pipefail

# ==== Configuration ====
NAMESPACE="genesis"
HELM_RELEASES=("webserver" "database" "backend" "frontend" "auth" "observer")
ROLLBACK_REVISION="${1:-}"

# ==== Functions ====

check_tools() {
  for tool in helm kubectl; do
    if ! command -v $tool &>/dev/null; then
      echo "[ERROR] '$tool' is not installed or not in PATH"
      exit 1
    fi
  done
}

rollback_release() {
  local release=$1
  local revision=$2

  if [[ -z "$revision" ]]; then
    echo "[INFO] Rolling back $release to previous revision..."
    helm rollback "$release" --namespace "$NAMESPACE"
  else
    echo "[INFO] Rolling back $release to revision $revision..."
    helm rollback "$release" "$revision" --namespace "$NAMESPACE"
  fi
}

print_current_revisions() {
  echo "[INFO] Listing current Helm revisions in namespace '$NAMESPACE'..."
  for release in "${HELM_RELEASES[@]}"; do
    echo "== $release =="
    helm history "$release" --namespace "$NAMESPACE" || echo "No history found"
    echo
  done
}

validate_status() {
  echo "[INFO] Verifying pod status after rollback..."
  kubectl get pods -n "$NAMESPACE"
  kubectl get events -n "$NAMESPACE" --sort-by=.metadata.creationTimestamp | tail -n 20
}

# ==== Main ====

echo "====================================="
echo "⏪ Starting Rollback Process"
echo "====================================="

check_tools
print_current_revisions

for release in "${HELM_RELEASES[@]}"; do
  rollback_release "$release" "$ROLLBACK_REVISION"
done

validate_status

echo "====================================="
echo "✅ Rollback completed"
echo "====================================="
