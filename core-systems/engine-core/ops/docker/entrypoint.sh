#!/usr/bin/env bash

# ==============================================================================
# Industrial Entrypoint Script for engine-core containers
# Location: engine-core/ops/docker/entrypoint.sh
# Purpose : Secure initialization and lifecycle control
# ==============================================================================

set -euo pipefail

APP_NAME="engine-core"
VENV_PATH="/opt/venv"
LOG_DIR="/var/log/$APP_NAME"
DEFAULT_CMD="python -m engine_core.app"
MIGRATION_CMD="poetry run alembic upgrade head"
PRESTART_HOOK="./scripts/prestart.sh"
POSTSTART_HOOK="./scripts/poststart.sh"

# === Trap shutdown signals ===
function shutdown_handler() {
  echo "[entrypoint] Caught termination signal. Shutting down $APP_NAME..."
  exit 0
}
trap shutdown_handler SIGINT SIGTERM

# === Ensure log directory exists ===
mkdir -p "$LOG_DIR"
touch "$LOG_DIR/runtime.log"

# === Activate virtualenv if exists ===
if [[ -d "$VENV_PATH" ]]; then
  echo "[entrypoint] Activating virtualenv at $VENV_PATH"
  source "$VENV_PATH/bin/activate"
fi

# === Load env if present ===
if [[ -f ".env" ]]; then
  echo "[entrypoint] Loading .env file"
  set -o allexport
  source .env
  set +o allexport
fi

# === Run prestart hook if exists ===
if [[ -x "$PRESTART_HOOK" ]]; then
  echo "[entrypoint] Executing prestart hook: $PRESTART_HOOK"
  "$PRESTART_HOOK"
fi

# === Run database migrations (optional) ===
if [[ "${RUN_MIGRATIONS:-true}" == "true" ]]; then
  echo "[entrypoint] Running DB migrations..."
  eval "$MIGRATION_CMD"
fi

# === Poststart hook ===
if [[ -x "$POSTSTART_HOOK" ]]; then
  echo "[entrypoint] Executing poststart hook: $POSTSTART_HOOK"
  "$POSTSTART_HOOK"
fi

# === Launch application ===
echo "[entrypoint] Starting: ${*:-$DEFAULT_CMD}"
exec "${@:-$DEFAULT_CMD}"
