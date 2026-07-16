#!/usr/bin/env bash
# datafabric-core Docker entrypoint
# Features:
#  - Strict shell, clear logging, deterministic env
#  - .env ingestion (safe), runtime dirs, umask
#  - Dependency waits: Postgres, Redis, Kafka, S3
#  - Optional migrations before start
#  - Roles: web, worker, oneoff, shell, custom CMD
#  - Proper signal handling, exec, non-root via gosu or su-exec
#  - Health preflight and graceful timeouts

set -Eeuo pipefail

# ----------------------------- logging -----------------------------------------
log()  { printf "[entrypoint] %s\n" "$*" >&2; }
die()  { printf "[entrypoint][ERROR] %s\n" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------- tini wrapper ------------------------------------
# Ensure PID 1 reaps children and forwards signals
if [[ "${TINI_ENABLED:-1}" = "1" && "$$" -eq 1 ]]; then
  if have tini; then
    exec tini -- "$0" "$@"
  elif have dumb-init; then
    exec dumb-init -- "$0" "$@"
  fi
fi

# ----------------------------- env ingestion -----------------------------------
ROOT_DIR="${APP_ROOT_DIR:-/app}"
cd "$ROOT_DIR" || die "Cannot cd to $ROOT_DIR"

# Safe load .env if present (non-exported secrets must be provided via Docker/K8s secrets)
if [[ -f ".env" ]]; then
  # shellcheck disable=SC2046
  set -a
  # Allow only non-secret dev vars by pattern if needed; here we source as is.
  . ".env"
  set +a
  log "Loaded .env"
fi

# Defaults
APP_NAME="${APP_NAME:-datafabric-core}"
APP_ENV="${APP_ENV:-prod}"
TZ="${TZ:-UTC}"
LANG="${LANG:-C.UTF-8}"
PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
UMASK="${UMASK:-0027}"
GRACEFUL_TIMEOUT="${GRACEFUL_TIMEOUT:-20}"

export TZ LANG PYTHONUNBUFFERED

umask "$UMASK" || true

# ----------------------------- drop privileges ---------------------------------
drop_priv() {
  # Prefer gosu, then su-exec, else run as current user
  if [[ "$(id -u)" -eq 0 ]]; then
    local tgt_user="${APP_USER:-app}"
    local tgt_uid="${APP_UID:-1000}"
    local tgt_gid="${APP_GID:-1000}"

    if ! id -u "$tgt_user" >/dev/null 2>&1; then
      groupadd -g "$tgt_gid" -o "$tgt_user" >/dev/null 2>&1 || true
      useradd -m -u "$tgt_uid" -g "$tgt_gid" -o -s /usr/sbin/nologin "$tgt_user" >/dev/null 2>&1 || true
    fi

    chown -R "$tgt_user:$tgt_user" "$ROOT_DIR" 2>/dev/null || true
    mkdir -p /var/log/$APP_NAME /var/run/$APP_NAME
    chown -R "$tgt_user:$tgt_user" /var/log/$APP_NAME /var/run/$APP_NAME

    if have gosu; then
      exec gosu "$tgt_user" "$@"
    elif have su-exec; then
      exec su-exec "$tgt_user" "$@"
    else
      log "gosu/su-exec not found, running as root"
      exec "$@"
    fi
  else
    exec "$@"
  fi
}

# ----------------------------- waiters -----------------------------------------
wait_tcp() {
  # wait_tcp host port timeout_seconds
  local host="$1" port="$2" timeout="${3:-30}" start t
  start="$(date +%s)"
  log "Waiting for tcp://${host}:${port} up to ${timeout}s"
  while true; do
    if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      log "tcp://${host}:${port} is available"
      return 0
    fi
    t="$(($(date +%s) - start))"
    if (( t >= timeout )); then
      die "Timeout waiting for tcp://${host}:${port}"
    fi
    sleep 1
  done
}

wait_http() {
  # wait_http url timeout_seconds
  local url="$1" timeout="${2:-30}" start rc
  start="$(date +%s)"
  log "Waiting for HTTP ${url} up to ${timeout}s"
  while true; do
    if have curl; then
      rc="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 2 "$url" || true)"
      if [[ "$rc" =~ ^2|3 ]]; then
        log "HTTP ${url} is available"
        return 0
      fi
    fi
    if (( $(date +%s) - start >= timeout )); then
      die "Timeout waiting for ${url}"
    fi
    sleep 1
  done
}

wait_dependencies() {
  # Postgres
  if [[ -n "${PG_HOST:-}" && -n "${PG_PORT:-}" ]]; then
    wait_tcp "$PG_HOST" "$PG_PORT" "${PG_WAIT_TIMEOUT:-60}"
  fi
  # Redis
  if [[ -n "${REDIS_URL:-}" ]]; then
    # parse host:port
    local host port
    host="$(echo "$REDIS_URL" | sed -E 's#redis://([^:/]+):([0-9]+)/?.*#\1#')"
    port="$(echo "$REDIS_URL" | sed -E 's#redis://([^:/]+):([0-9]+)/?.*#\2#')"
    if [[ -n "$host" && -n "$port" ]]; then
      wait_tcp "$host" "$port" "${REDIS_WAIT_TIMEOUT:-30}"
    fi
  fi
  # Kafka
  if [[ -n "${KAFKA_BROKERS:-}" ]]; then
    IFS=',' read -r -a brokers <<< "$KAFKA_BROKERS"
    for b in "${brokers[@]}"; do
      local host port
      host="${b%%:*}"; port="${b##*:}"
      [[ -n "$host" && -n "$port" ]] && wait_tcp "$host" "$port" "${KAFKA_WAIT_TIMEOUT:-60}"
    done
  fi
  # S3
  if [[ -n "${S3_ENDPOINT:-}" ]]; then
    local url="${S3_ENDPOINT%/}"
    wait_http "$url/minio/health/ready" "${S3_WAIT_TIMEOUT:-30}" || true
  fi
}

# ----------------------------- migrations hook ---------------------------------
run_migrations() {
  if [[ "${RUN_MIGRATIONS:-0}" = "1" ]]; then
    log "Running migrations"
    if [[ -f "scripts/migrate.sh" ]]; then
      bash scripts/migrate.sh || die "scripts/migrate.sh failed"
    elif have alembic; then
      alembic upgrade head || die "alembic failed"
    else
      log "No migration tool detected, skipping"
    fi
  fi
}

# ----------------------------- roles -------------------------------------------
run_web() {
  local host="${UVICORN_HOST:-0.0.0.0}"
  local port="${UVICORN_PORT:-8080}"
  local workers="${UVICORN_WORKERS:-2}"
  local app="${UVICORN_APP:-datafabric_core.api.app:app}"

  [[ -z "${SKIP_WAITS:-}" ]] && wait_dependencies
  run_migrations

  local cmd
  if have uvicorn; then
    cmd=(uvicorn "$app" --host "$host" --port "$port" --workers "$workers" --timeout-keep-alive 30)
    if [[ "${LOG_FORMAT:-json}" = "json" ]]; then
      cmd+=(--log-config ./ops/logging/uvicorn_json.yaml)
      [[ -f ./ops/logging/uvicorn_json.yaml ]] || cmd=("${cmd[@]::${#cmd[@]}-2}")
    fi
  elif have gunicorn; then
    local wsgi="${GUNICORN_APP:-datafabric_core.api.app:app}"
    cmd=(gunicorn "$wsgi" --bind "${host}:${port}" --workers "$workers" --access-logfile - --error-logfile - --timeout "$GRACEFUL_TIMEOUT")
  else
    die "Neither uvicorn nor gunicorn found"
  fi

  drop_priv "${cmd[@]}"
}

run_worker() {
  [[ -z "${SKIP_WAITS:-}" ]] && wait_dependencies
  run_migrations
  local cmd

  if have rq; then
    cmd=(rq worker --with-scheduler)
  elif have celery; then
    local app="${CELERY_APP:-datafabric_core.worker.app}"
    cmd=(celery -A "$app" worker --loglevel="${CELERY_LOGLEVEL:-INFO}")
  else
    # Fallback to a demo worker if implemented
    if [[ -f "src/datafabric_core/worker.py" ]]; then
      cmd=(python -m datafabric_core.worker)
    else
      die "No worker runtime found (rq/celery/module)"
    fi
  fi

  drop_priv "${cmd[@]}"
}

run_oneoff() {
  [[ -z "${SKIP_WAITS:-}" ]] && wait_dependencies
  run_migrations
  shift 1 || true
  if [[ $# -eq 0 ]]; then
    die "oneoff requires a command, e.g. oneoff python -m datafabric_core.tools.task"
  fi
  drop_priv "$@"
}

run_shell() {
  drop_priv "${SHELL_BIN:-bash}"
}

# ----------------------------- main dispatch -----------------------------------
case "${1:-web}" in
  web)    log "Role: web";    run_web ;;
  worker) log "Role: worker"; run_worker ;;
  oneoff) log "Role: oneoff"; run_oneoff "$@" ;;
  shell)  log "Role: shell";  run_shell ;;
  help|-h|--help)
    cat <<'USAGE'
Usage: entrypoint.sh [web|worker|oneoff <cmd...>|shell]
Env:
  APP_ROOT_DIR=/app
  APP_ENV=prod
  RUN_MIGRATIONS=0
  SKIP_WAITS=
  UVICORN_APP, UVICORN_HOST, UVICORN_PORT, UVICORN_WORKERS
  PG_HOST, PG_PORT, REDIS_URL, KAFKA_BROKERS, S3_ENDPOINT
  APP_USER, APP_UID, APP_GID
USAGE
    ;;
  *)
    log "Custom command: $*"
    drop_priv "$@"
    ;;
esac
