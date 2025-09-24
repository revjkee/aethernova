#!/usr/bin/env bash
# chronowatch-core/ops/docker/entrypoint.sh
# Industrial-grade entrypoint for ChronoWatch Core containers.

set -Eeuo pipefail

# -----------------------------
# Global defaults (override via ENV)
# -----------------------------
: "${APP_NAME:=chronowatch-core}"
: "${APP_DIR:=/app}"
: "${APP_USER:=app}"
: "${APP_GROUP:=app}"
: "${APP_UID:=10001}"
: "${APP_GID:=10001}"
: "${UMASK:=027}"

# Runtime
: "${PYTHONPATH:=${APP_DIR}}"
: "${ENV_FILE:=/app/.env}"
: "${LOG_LEVEL:=INFO}"
: "${TZ:=UTC}"

# Network / Dependencies
: "${WAIT_FOR:=}"               # Comma-separated host:port list, e.g. "db:5432,redis:6379"
: "${WAIT_FOR_TIMEOUT:=60}"     # Seconds per endpoint
: "${WAIT_SLEEP:=1}"            # Backoff step between checks

# Web server
: "${WEB_CMD:=gunicorn}"        # gunicorn|uvicorn
: "${APP_MODULE:=chronowatch_core.api.main:app}"  # ASGI app path
: "${HOST:=0.0.0.0}"
: "${PORT:=8000}"
: "${WORKERS:=2}"
: "${WORKER_CLASS:=uvicorn.workers.UvicornWorker}"
: "${GUNICORN_EXTRA:=}"         # extra args string
: "${UVICORN_EXTRA:=}"          # extra args string
: "${RELOAD:=false}"            # dev reload for uvicorn

# DB migrations
: "${ENABLE_MIGRATIONS:=true}"  # true|false
: "${ALEMBIC_INI:=/app/alembic.ini}"
: "${MIGRATION_CMD:=alembic -c ${ALEMBIC_INI} upgrade head}"

# Celery / RQ / custom worker
: "${WORKER_CMD:=celery -A chronowatch_core.worker.app worker --loglevel=${LOG_LEVEL}}"
: "${SCHEDULER_CMD:=celery -A chronowatch_core.worker.app beat --loglevel=${LOG_LEVEL}}"

# Healthcheck
: "${HEALTHCHECK_FILE:=/tmp/.healthcheck}"
: "${HEALTHCHECK_TTL:=30}"      # seconds to consider health "fresh"

# Limits
: "${NOFILE:=65536}"

export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

# -----------------------------
# Logging helpers
# -----------------------------
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { echo "$(ts) [$APP_NAME] [$1] ${*:2}"; }
log_info() { log INFO "$@"; }
log_warn() { log WARN "$@"; }
log_err() { log ERROR "$@"; }

# -----------------------------
# Trap & PID1 signal handling
# -----------------------------
children=()

_reap() {
  # Reap any zombie children
  while true; do
    local pid
    pid=$(pgrep -P 1 || true)
    [[ -z "${pid}" ]] && break
    wait "${pid}" || true
  done
}

_term() {
  local sig="${1:-TERM}"
  log_warn "Received signal ${sig}, forwarding to children: ${children[*]:-none}"
  for pid in "${children[@]:-}"; do
    kill -s "${sig}" "${pid}" 2>/dev/null || true
  done
}

trap '_term TERM' TERM
trap '_term INT'  INT
trap '_reap'      CHLD

# -----------------------------
# Privilege management
# -----------------------------
create_user_group() {
  if ! getent group "${APP_GROUP}" >/dev/null 2>&1; then
    addgroup --gid "${APP_GID}" "${APP_GROUP}" >/dev/null 2>&1 || groupadd -g "${APP_GID}" "${APP_GROUP}"
  fi
  if ! id "${APP_USER}" >/dev/null 2>&1; then
    adduser -D -H -G "${APP_GROUP}" -u "${APP_UID}" "${APP_USER}" >/dev/null 2>&1 || useradd -M -U -g "${APP_GROUP}" -u "${APP_UID}" "${APP_USER}"
  fi
}

drop_privs_exec() {
  local user="${APP_USER}:${APP_GROUP}"
  if command -v gosu >/dev/null 2>&1; then
    exec gosu "${user}" "$@"
  elif command -v su-exec >/dev/null 2>&1; then
    exec su-exec "${user}" "$@"
  else
    # Fallback to runuser; note: no TTY allocation in containers
    exec runuser -u "${APP_USER}" -- "$@"
  fi
}

maybe_chown() {
  local targets=("$@")
  for p in "${targets[@]}"; do
    [[ -e "$p" ]] && chown -R "${APP_USER}:${APP_GROUP}" "$p" || true
  done
}

# -----------------------------
# Env loading
# -----------------------------
load_env_file() {
  if [[ -f "${ENV_FILE}" ]]; then
    log_info "Loading environment from ${ENV_FILE}"
    # shellcheck disable=SC1090
    set -a
    . "${ENV_FILE}"
    set +a
  fi
}

# -----------------------------
# Wait for dependencies (TCP)
# -----------------------------
wait_for_tcp() {
  local endpoint="$1"
  local host="${endpoint%%:*}"
  local port="${endpoint##*:}"
  local deadline=$((SECONDS + WAIT_FOR_TIMEOUT))

  log_info "Waiting for ${host}:${port} (timeout ${WAIT_FOR_TIMEOUT}s)"
  while (( SECONDS < deadline )); do
    if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      log_info "Dependency ${host}:${port} is available"
      return 0
    fi
    sleep "${WAIT_SLEEP}"
  done
  log_err "Timeout waiting for ${host}:${port}"
  return 1
}

wait_dependencies() {
  [[ -z "${WAIT_FOR}" ]] && return 0
  IFS=',' read -r -a deps <<< "${WAIT_FOR}"
  for dep in "${deps[@]}"; do
    wait_for_tcp "$(echo "$dep" | xargs)"
  done
}

# -----------------------------
# Healthcheck
# -----------------------------
touch_health() {
  printf "%s" "$(ts)" > "${HEALTHCHECK_FILE}"
}

health_probe() {
  if [[ ! -f "${HEALTHCHECK_FILE}" ]]; then
    log_err "Healthcheck file not found"
    return 1
  fi
  local last ts_last now
  ts_last=$(cat "${HEALTHCHECK_FILE}" || true)
  now=$(date -u +%s)
  last=$(date -u -d "${ts_last}" +%s 2>/dev/null || echo 0)
  if (( now - last <= HEALTHCHECK_TTL )); then
    log_info "Health OK (fresh within ${HEALTHCHECK_TTL}s)"
    return 0
  else
    log_err "Health STALE (older than ${HEALTHCHECK_TTL}s)"
    return 1
  fi
}

# -----------------------------
# Migrations
# -----------------------------
run_migrations() {
  if [[ "${ENABLE_MIGRATIONS}" == "true" ]]; then
    if [[ -f "${ALEMBIC_INI}" ]]; then
      log_info "Running DB migrations: ${MIGRATION_CMD}"
      eval "${MIGRATION_CMD}"
      log_info "Migrations completed"
    else
      log_warn "Alembic config not found: ${ALEMBIC_INI}, skipping migrations"
    fi
  else
    log_info "Migrations disabled (ENABLE_MIGRATIONS=${ENABLE_MIGRATIONS})"
  fi
}

# -----------------------------
# ulimit / system
# -----------------------------
tune_limits() {
  umask "${UMASK}" || true
  ulimit -n "${NOFILE}" 2>/dev/null || log_warn "Cannot set nofile=${NOFILE}"
  ln -snf "/usr/share/zoneinfo/${TZ}" /etc/localtime 2>/dev/null || true
  echo "${TZ}" >/etc/timezone 2>/dev/null || true
}

# -----------------------------
# Commands
# -----------------------------
cmd_web() {
  run_migrations
  touch_health

  case "${WEB_CMD}" in
    gunicorn)
      local bind="--bind ${HOST}:${PORT}"
      local workers="--workers ${WORKERS}"
      local worker_class="--worker-class ${WORKER_CLASS}"
      local access="--access-logfile -"
      local error="--error-logfile -"
      local loglvl="--log-level ${LOG_LEVEL}"
      set -- gunicorn ${bind} ${workers} ${worker_class} ${access} ${error} ${loglvl} ${GUNICORN_EXTRA} "${APP_MODULE}"
      ;;
    uvicorn)
      local rl=()
      [[ "${RELOAD}" == "true" ]] && rl=(--reload)
      set -- uvicorn "${APP_MODULE}" --host "${HOST}" --port "${PORT}" --log-level "$(echo "${LOG_LEVEL}" | tr '[:upper:]' '[:lower:]')" "${rl[@]}" ${UVICORN_EXTRA}
      ;;
    *)
      log_err "Unsupported WEB_CMD=${WEB_CMD} (expected gunicorn|uvicorn)"
      exit 64
      ;;
  esac

  log_info "Starting web: $*"
  exec "$@"
}

cmd_worker() {
  run_migrations
  touch_health
  log_info "Starting worker: ${WORKER_CMD}"
  eval "exec ${WORKER_CMD}"
}

cmd_scheduler() {
  touch_health
  log_info "Starting scheduler: ${SCHEDULER_CMD}"
  eval "exec ${SCHEDULER_CMD}"
}

cmd_migrate_only() {
  run_migrations
  log_info "Migrate-only mode finished"
}

cmd_shell() {
  log_info "Starting shell"
  exec /bin/sh -l
}

cmd_health() {
  health_probe
}

cmd_printenv() {
  env | sort
}

# -----------------------------
# Main
# -----------------------------
main() {
  tune_limits
  load_env_file
  create_user_group

  # Ensure ownership for common writable paths
  maybe_chown "${APP_DIR}" /var/log /var/run /tmp

  wait_dependencies

  # If first arg is an option, treat as web
  if [[ "${#}" -eq 0 ]]; then
    set -- web
  fi

  # If user passes a binary directly, just exec it as-is under drop-privs
  case "$1" in
    web|worker|scheduler|migrate-only|shell|health|printenv)
      subcmd="$1"; shift || true
      ;;
    *)
      # Arbitrary command, exec as-is
      log_info "Executing custom command: $*"
      if [[ "$(id -u)" -eq 0 ]]; then
        drop_privs_exec "$@"
      else
        exec "$@"
      fi
      return
      ;;
  esac

  # Drop privileges for known subcommands
  if [[ "$(id -u)" -eq 0 ]]; then
    case "${subcmd}" in
      web)
        drop_privs_exec bash -lc "$(declare -f run_migrations cmd_web touch_health log_info log_err); cmd_web \"$@\""
        ;;
      worker)
        drop_privs_exec bash -lc "$(declare -f run_migrations cmd_worker touch_health log_info log_err); cmd_worker \"$@\""
        ;;
      scheduler)
        drop_privs_exec bash -lc "$(declare -f cmd_scheduler touch_health log_info); cmd_scheduler \"$@\""
        ;;
      migrate-only)
        drop_privs_exec bash -lc "$(declare -f run_migrations log_info); cmd_migrate_only \"$@\""
        ;;
      shell)
        drop_privs_exec /bin/sh -l
        ;;
      health)
        # health should run as root is fine; but we can drop too
        drop_privs_exec bash -lc "$(declare -f health_probe log_info log_err); cmd_health \"$@\""
        ;;
      printenv)
        drop_privs_exec bash -lc "$(declare -f cmd_printenv); cmd_printenv \"$@\""
        ;;
    esac
  else
    case "${subcmd}" in
      web)          cmd_web "$@";;
      worker)       cmd_worker "$@";;
      scheduler)    cmd_scheduler "$@";;
      migrate-only) cmd_migrate_only "$@";;
      shell)        cmd_shell "$@";;
      health)       cmd_health "$@";;
      printenv)     cmd_printenv "$@";;
    esac
  fi
}

main "$@"
