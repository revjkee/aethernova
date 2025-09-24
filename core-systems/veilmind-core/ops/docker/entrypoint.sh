#!/usr/bin/env bash
# veilmind-core/ops/docker/entrypoint.sh
# Industrial Zero-Trust Entrypoint for containers
# Shell: bash 5.x

set -Eeuo pipefail
shopt -s lastpipe

# ----------- Constants / Defaults -----------
APP_NAME="${APP_NAME:-veilmind-core}"
APP_ENV="${APP_ENV:-prod}"
APP_MODE="${1:-api}"                 # api|worker|migrate|shell|selftest
APP_HOST="${APP_HOST:-0.0.0.0}"
APP_PORT="${APP_PORT:-8000}"
APP_MODULE="${APP_MODULE:-veilmind_core.app:app}"     # ASGI target for uvicorn
WORKERS="${WORKERS:-$(nproc)}"
UVICORN_EXTRA="${UVICORN_EXTRA:-}"   # e.g. "--proxy-headers --forwarded-allow-ips='*'"
GRACEFUL_TIMEOUT="${GRACEFUL_TIMEOUT:-30}"
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-60}"
ULIMIT_NOFILE="${ULIMIT_NOFILE:-262144}"
NON_ROOT_USER="${NON_ROOT_USER:-veilmind}"
NON_ROOT_UID="${NON_ROOT_UID:-10001}"
NON_ROOT_GID="${NON_ROOT_GID:-10001}"

DB_URL="${DB_URL:-}"
DB_WAIT_HOST="${DB_WAIT_HOST:-}"
DB_WAIT_PORT="${DB_WAIT_PORT:-}"
BROKER_WAIT_HOST="${BROKER_WAIT_HOST:-}"
BROKER_WAIT_PORT="${BROKER_WAIT_PORT:-}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-45}"
WAIT_INTERVAL="${WAIT_INTERVAL:-2}"

# OpenTelemetry defaults (safe off by default)
export OTEL_TRACES_EXPORTER="${OTEL_TRACES_EXPORTER:-none}"
export OTEL_METRICS_EXPORTER="${OTEL_METRICS_EXPORTER:-none}"
export OTEL_LOGS_EXPORTER="${OTEL_LOGS_EXPORTER:-none}"
export OTEL_RESOURCE_ATTRIBUTES="${OTEL_RESOURCE_ATTRIBUTES:-service.name=${APP_NAME},deployment.environment=${APP_ENV}}"

# ----------- Redacting Logger -----------
REDACT_MASK="[REDACTED]"
# keys and regex patterns to redact from logs
declare -a REDACT_KEYS=("password" "passwd" "secret" "token" "access_token" "refresh_token" "id_token" "authorization" "api_key" "apikey" "cookie" "set-cookie" "session" "private_key" "client_secret" "db_password" "jwt" "otp")
RE_JWT='eyJ[[:alnum:]_\-]+\.[[:alnum:]_\-]+\.[[:alnum:]_\-]+'
RE_BEARER='[Bb]earer[[:space:]]+[A-Za-z0-9._-]+'
RE_PAN='(^|[^0-9])([0-9]{13,19})([^0-9]|$)'

redact() {
  local msg="$*"
  for k in "${REDACT_KEYS[@]}"; do
    msg="$(sed -E "s/(${k}[[:space:]]*[:=][[:space:]]*)([^ ,;]+)/(\\1${REDACT_MASK})/Ig" <<< "$msg")"
  done
  msg="$(sed -E "s/${RE_JWT}/${REDACT_MASK}/g" <<< "$msg")"
  msg="$(sed -E "s/${RE_BEARER}/${REDACT_MASK}/g" <<< "$msg")"
  msg="$(sed -E "s/${RE_PAN}/${REDACT_MASK}/g" <<< "$msg")"
  # hard cap to avoid log flooding
  if [ "${#msg}" -gt 2048 ]; then
    msg="${msg:0:2048}...(truncated)"
  fi
  printf "%s" "$msg"
}

log() {
  local level="$1"; shift
  printf "[%s] %s\n" "$level" "$(redact "$*")" >&2
}

info() { log INFO "$@"; }
warn() { log WARN "$@"; }
err()  { log ERROR "$@"; }

# ----------- Signal handling -----------
PID_CHILD=""

cleanup() {
  local code=$?
  if [ -n "${PID_CHILD}" ] && kill -0 "${PID_CHILD}" 2>/dev/null; then
    warn "Forwarding SIGTERM to child pid=${PID_CHILD}"
    kill -TERM "${PID_CHILD}" 2>/dev/null || true
    # wait with timeout
    local waited=0
    while kill -0 "${PID_CHILD}" 2>/dev/null; do
      sleep 1
      waited=$((waited+1))
      if [ "${waited}" -ge "${GRACEFUL_TIMEOUT}" ]; then
        err "Child did not stop within ${GRACEFUL_TIMEOUT}s, sending SIGKILL"
        kill -KILL "${PID_CHILD}" 2>/dev/null || true
        break
      fi
    done
  fi
  exit "${code}"
}
trap cleanup EXIT
trap 'warn "SIGTERM received"; exit 143' TERM
trap 'warn "SIGINT received"; exit 130' INT

# ----------- Utilities -----------
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Required command not found: $1"; exit 127; }
}

wait_tcp() {
  local host="$1" port="$2" label="${3:-dep}"
  [ -z "$host" ] || [ -z "$port" ] && return 0
  local start=$(date +%s)
  info "Waiting for ${label} at ${host}:${port} (timeout=${WAIT_TIMEOUT}s)"
  while true; do
    (exec 3<>"/dev/tcp/${host}/${port}") >/dev/null 2>&1 && { info "${label} is reachable"; return 0; }
    sleep "${WAIT_INTERVAL}"
    if (( $(date +%s) - start >= WAIT_TIMEOUT )); then
      err "Timeout waiting for ${label} at ${host}:${port}"
      return 1
    fi
  done
}

lower_privileges() {
  # Switch to non-root if running as root and user exists or can be created
  if [ "$(id -u)" -eq 0 ]; then
    if ! id -u "${NON_ROOT_USER}" >/dev/null 2>&1; then
      info "Creating non-root user ${NON_ROOT_USER} (${NON_ROOT_UID}:${NON_ROOT_GID})"
      groupadd -g "${NON_ROOT_GID}" -f "${NON_ROOT_USER}" || true
      useradd -m -u "${NON_ROOT_UID}" -g "${NON_ROOT_GID}" -s /bin/bash "${NON_ROOT_USER}" || true
    fi
    chown -R "${NON_ROOT_USER}:${NON_ROOT_USER}" /workspaces 2>/dev/null || true
    exec gosu "${NON_ROOT_USER}" "$0" "$APP_MODE" "$@"
  fi
}

apply_ulimits() {
  if command -v ulimit >/dev/null 2>&1; then
    ulimit -n "${ULIMIT_NOFILE}" || warn "Cannot raise nofile to ${ULIMIT_NOFILE}"
  fi
}

check_readonly_fs() {
  # warn if root is not read-only (good to know in prod)
  if mount | grep -E " on / " | grep -q "(ro,"; then
    info "Root filesystem is read-only"
  else
    warn "Root filesystem is writable; recommend read-only rootfs in prod"
  fi
}

validate_env() {
  # minimal validations
  if [ "${APP_MODE}" = "api" ] || [ "${APP_MODE}" = "worker" ]; then
    [ -n "${APP_MODULE}" ] || { err "APP_MODULE must be set"; exit 64; }
  fi
  # basic DB sanity if URL provided
  if [ -n "${DB_URL}" ]; then
    case "${DB_URL}" in
      postgres://*|postgresql://*|mysql://*|mysql+pymysql://*|sqlite://* ) : ;;
      * ) warn "DB_URL has unexpected scheme";;
    esac
  fi
}

run_migrations() {
  if command -v alembic >/dev/null 2>&1 && [ -f "alembic.ini" ]; then
    info "Running Alembic migrations"
    alembic upgrade head || { err "Migrations failed"; exit 65; }
  elif command -v poetry >/dev/null 2>&1 && poetry run alembic --help >/dev/null 2>&1; then
    info "Running Alembic migrations via Poetry"
    poetry run alembic upgrade head || { err "Migrations failed"; exit 65; }
  else
    info "No migrations detected; skipping"
  fi
}

run_selftest() {
  info "Running selftest"
  if python -c "import zero_trust.telemetry.tracing as t; t.init_tracing(); t.trace_health(status='ok'); t.shutdown_tracing(); print('telemetry:ok')" ; then
    info "Telemetry selftest passed"
  else
    warn "Telemetry selftest failed"
  fi
  if pytest -k "smoke or quick" -q >/dev/null 2>&1; then
    info "Pytest quick suite passed"
  else
    warn "Pytest quick suite not available or failed"
  fi
}

start_api() {
  require_cmd python
  require_cmd uvicorn
  apply_ulimits
  # optional waits
  wait_tcp "${DB_WAIT_HOST}" "${DB_WAIT_PORT}" "database" || exit 75
  wait_tcp "${BROKER_WAIT_HOST}" "${BROKER_WAIT_PORT}" "broker" || exit 76

  # run migrations if requested
  if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    run_migrations
  fi

  info "Starting API: ${APP_MODULE} on ${APP_HOST}:${APP_PORT}, workers=${WORKERS}"
  # start and exec as PID 1
  exec uvicorn "${APP_MODULE}" \
      --host "${APP_HOST}" \
      --port "${APP_PORT}" \
      --workers "${WORKERS}" \
      --timeout-keep-alive 20 \
      ${UVICORN_EXTRA}
}

start_worker() {
  require_cmd python
  apply_ulimits
  wait_tcp "${DB_WAIT_HOST}" "${DB_WAIT_PORT}" "database" || exit 75
  # Example: celery/rq/your worker
  if command -v celery >/dev/null 2>&1; then
    info "Starting Celery worker"
    exec celery -A veilmind_core.worker.app worker --loglevel=INFO
  elif command -v rq >/dev/null 2>&1; then
    info "Starting RQ worker"
    exec rq worker
  else
    err "No worker runtime found (celery/rq). Provide start command."
    exit 69
  fi
}

start_shell() {
  info "Opening debug shell"
  exec /bin/bash
}

# ----------- Bootstrap -----------
main() {
  check_readonly_fs
  validate_env

  # Optional privilege drop (requires gosu/su-exec if root)
  if [ "$(id -u)" -eq 0 ] && command -v gosu >/dev/null 2>&1; then
    lower_privileges "$@"
  fi

  case "${APP_MODE}" in
    api)       start_api ;;
    worker)    start_worker ;;
    migrate)   run_migrations ;;
    shell)     start_shell ;;
    selftest)  run_selftest ;;
    *)
      err "Unknown APP_MODE='${APP_MODE}'. Use: api|worker|migrate|shell|selftest"
      exit 64
      ;;
  esac
}

main "$@"
