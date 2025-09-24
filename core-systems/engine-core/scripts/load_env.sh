#!/usr/bin/env bash

# ============================================================================
# Industrial-grade .env loader for local and CI use
# Location: engine-core/scripts/load_env.sh
# ============================================================================

set -euo pipefail

ENV_FILE=".env"
EXAMPLE_FILE=".env.example"
REQUIRED_KEYS=("PORT" "DATABASE_URL" "SECRET_KEY")
ALLOW_OVERRIDE=false

# === FUNCTION: Log ===
log() {
  echo "[load_env] $*"
}

# === FUNCTION: Check .env exists ===
check_env_file() {
  if [[ ! -f "$ENV_FILE" ]]; then
    log "Error: $ENV_FILE not found."
    if [[ -f "$EXAMPLE_FILE" ]]; then
      log "Hint: You can create it from $EXAMPLE_FILE"
    fi
    exit 1
  fi
}

# === FUNCTION: Export vars without override ===
export_env_vars() {
  log "Exporting variables from $ENV_FILE"
  while IFS='=' read -r key value; do
    [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue

    # Trim whitespace
    key="$(echo "$key" | xargs)"
    value="$(echo "$value" | xargs)"

    # Skip already set vars unless override allowed
    if [[ -z "${!key-}" || "$ALLOW_OVERRIDE" == true ]]; then
      export "$key=$value"
    else
      log "Skipping already set variable: $key"
    fi
  done < "$ENV_FILE"
}

# === FUNCTION: Validate required vars ===
validate_keys() {
  log "Validating required variables..."
  for key in "${REQUIRED_KEYS[@]}"; do
    if [[ -z "${!key-}" ]]; then
      log "Error: Required variable $key is not set"
      exit 2
    fi
  done
}

# === FUNCTION: Diff against .env.example ===
check_missing_keys() {
  if [[ -f "$EXAMPLE_FILE" ]]; then
    log "Checking for missing keys from $EXAMPLE_FILE"
    while IFS='=' read -r key _; do
      [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
      key="$(echo "$key" | xargs)"
      if ! grep -q "^$key=" "$ENV_FILE"; then
        log "Warning: $key present in $EXAMPLE_FILE but missing in $ENV_FILE"
      fi
    done < "$EXAMPLE_FILE"
  fi
}

# === MAIN ===
check_env_file
export_env_vars
check_missing_keys
validate_keys

log "Environment loaded successfully."
