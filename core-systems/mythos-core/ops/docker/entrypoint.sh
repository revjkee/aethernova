#!/usr/bin/env sh
# Mythos Core - Industrial Docker Entrypoint
# Shell: POSIX sh (BusyBox ash / dash compatible)

# -------- Strict-ish mode (portable) --------
set -eu
# pipefail is not POSIX; try enable if shell supports it
( set -o pipefail ) 2>/dev/null && set -o pipefail || true
IFS='
 	'

# -------- Defaults (override by env) --------
APP_NAME="${APP_NAME:-mythos}"
APP_HOME="${APP_HOME:-/app}"
APP_DATA_DIR="${APP_DATA_DIR:-/data}"
APP_LOG_DIR="${APP_LOG_DIR:-/var/log/${APP_NAME}}"

APP_USER="${APP_USER:-app}"
APP_GROUP="${APP_GROUP:-app}"
APP_UID="${APP_UID:-10001}"
APP_GID="${APP_GID:-10001}"
RUN_AS_ROOT="${RUN_AS_ROOT:-0}"            # 1 — не дропать привилегии
UMASK_VAL="${UMASK:-0027}"                 # безопасный умаск по умолчанию
TZ="${TZ:-UTC}"

ENV_FILE="${ENV_FILE:-}"                   # путь к .env (опц.)
LOAD_ENV_FROM_APP="${LOAD_ENV_FROM_APP:-1}"# 1 — пробовать $APP_HOME/.env

WAIT_FOR="${WAIT_FOR:-}"                   # "host1:port1,host2:port2 ..."
WAIT_FOR_TIMEOUT="${WAIT_FOR_TIMEOUT:-30}" # сек на каждый endpoint

PRESTART_HOOK="${PRESTART_HOOK:-}"         # явный путь к prestart (опц.)
RUN_MIGRATIONS="${RUN_MIGRATIONS:-0}"      # 1 — запускать миграции
MIGRATE_CMD="${MIGRATE_CMD:-${APP_NAME} migrate}"

DEFAULT_CMD="${DEFAULT_CMD:-${APP_NAME}}"  # дефолтная команда, если аргументы не переданы

# -------- Logging helpers --------
ts_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log()    { printf "%s [%s] %s\n" "$(ts_utc)" "$1" "$2" >&2; }
die()    { log "FATAL" "$1"; exit 1; }

# -------- Env loading --------
maybe_source_env() {
  # Load explicit ENV_FILE first
  if [ -n "${ENV_FILE}" ] && [ -f "${ENV_FILE}" ]; then
    log "INFO" "Loading environment from ${ENV_FILE}"
    # export all vars while sourcing
    set -a; . "${ENV_FILE}"; set +a
  fi

  # Then try $APP_HOME/.env if allowed
  if [ "${LOAD_ENV_FROM_APP}" = "1" ] && [ -f "${APP_HOME}/.env" ]; then
    log "INFO" "Loading environment from ${APP_HOME}/.env"
    set -a; . "${APP_HOME}/.env"; set +a
  fi
}

# -------- Timezone / umask --------
maybe_set_timezone() {
  if [ -n "${TZ}" ] && [ -e "/usr/share/zoneinfo/${TZ}" ]; then
    # best-effort; may require privileges
    if [ "$(id -u)" = "0" ]; then
      ln -sf "/usr/share/zoneinfo/${TZ}" /etc/localtime 2>/dev/null || true
      echo "${TZ}" > /etc/timezone 2>/dev/null || true
      log "INFO" "Timezone set to ${TZ}"
    else
      log "WARN" "Cannot set timezone without root; continuing with ${TZ}"
    fi
  else
    log "INFO" "Using timezone: ${TZ} (link not adjusted)"
  fi

  # set umask
  umask "${UMASK_VAL}" 2>/dev/null || log "WARN" "Invalid UMASK=${UMASK_VAL}, keeping default"
  log "INFO" "umask=$(umask)"
}

# -------- User / group / dirs --------
ensure_group() {
  # If group exists, reuse GID or adjust
  if getent group "${APP_GROUP}" >/dev/null 2>&1; then
    return 0
  fi
  addgroup -g "${APP_GID}" "${APP_GROUP}" 2>/dev/null \
    || groupadd -g "${APP_GID}" "${APP_GROUP}" 2>/dev/null \
    || addgroup "${APP_GROUP}" 2>/dev/null \
    || true
}

ensure_user() {
  if id -u "${APP_USER}" >/dev/null 2>&1; then
    return 0
  fi
  ensure_group
  # Try BusyBox adduser, then useradd
  adduser -D -H -s /sbin/nologin -G "${APP_GROUP}" -u "${APP_UID}" "${APP_USER}" 2>/dev/null \
    || useradd -m -s /usr/sbin/nologin -g "${APP_GROUP}" -u "${APP_UID}" "${APP_USER}" 2>/dev/null \
    || true
}

chown_safe() {
  # Only root can chown
  if [ "$(id -u)" != "0" ]; then
    return 0
  fi
  path="$1"
  [ -e "${path}" ] || return 0
  chown -R "${APP_UID}:${APP_GID}" "${path}" 2>/dev/null || true
}

setup_user_and_dirs() {
  if [ "${RUN_AS_ROOT}" = "1" ]; then
    log "INFO" "RUN_AS_ROOT=1 — running as root (no privilege drop)"
  else
    ensure_user
  fi

  # Ensure directories exist
  mkdir -p "${APP_HOME}" "${APP_DATA_DIR}" "${APP_LOG_DIR}" 2>/dev/null || true
  chown_safe "${APP_HOME}"
  chown_safe "${APP_DATA_DIR}"
  chown_safe "${APP_LOG_DIR}"
}

# -------- Wait for TCP deps --------
_has_cmd() { command -v "$1" >/dev/null 2>&1; }

_wait_one_nc() {
  host="$1"; port="$2"; timeout="$3"
  end=$(( $(date +%s) + timeout ))
  while :; do
    if _has_cmd nc; then
      nc -z -w 2 "${host}" "${port}" >/dev/null 2>&1 && return 0
    elif _has_cmd telnet; then
      # non-interactive telnet check
      ( echo quit | telnet "${host}" "${port}" ) >/dev/null 2>&1 && return 0
    else
      log "WARN" "Neither nc nor telnet available; skipping wait for ${host}:${port}"
      return 0
    fi
    if [ "$(date +%s)" -ge "${end}" ]; then
      return 1
    fi
    sleep 1
  done
}

wait_for_endpoints() {
  [ -n "${WAIT_FOR}" ] || return 0
  log "INFO" "Waiting for dependencies: ${WAIT_FOR} (timeout ${WAIT_FOR_TIMEOUT}s each)"

  # split by comma/space/newline
  OLD_IFS="${IFS}"
  IFS=', 	
'
  for ep in ${WAIT_FOR}; do
    IFS="${OLD_IFS}"
    ep_trim=$(printf "%s" "${ep}" | tr -d ' ')
    host=$(printf "%s" "${ep_trim}" | cut -d: -f1)
    port=$(printf "%s" "${ep_trim}" | cut -d: -f2)
    [ -n "${host}" ] && [ -n "${port}" ] || die "Invalid WAIT_FOR endpoint: '${ep_trim}' (expected host:port)"
    log "INFO" "Waiting ${host}:${port} ..."
    if _wait_one_nc "${host}" "${port}" "${WAIT_FOR_TIMEOUT}"; then
      log "INFO" "Ready: ${host}:${port}"
    else
      die "Timeout waiting for ${host}:${port}"
    fi
    IFS=', 	
'
  done
  IFS="${OLD_IFS}"
}

# -------- Hooks / migrations --------
run_hook() {
  # Priority: explicit -> /usr/local/bin/prestart.sh -> ${APP_HOME}/ops/docker/prestart.sh
  if [ -n "${PRESTART_HOOK}" ] && [ -x "${PRESTART_HOOK}" ]; then
    log "INFO" "Running prestart hook: ${PRESTART_HOOK}"
    "${PRESTART_HOOK}" || die "Prestart hook failed"
    return 0
  fi

  if [ -x "/usr/local/bin/prestart.sh" ]; then
    log "INFO" "Running prestart hook: /usr/local/bin/prestart.sh"
    /usr/local/bin/prestart.sh || die "Prestart hook failed"
    return 0
  fi

  if [ -x "${APP_HOME}/ops/docker/prestart.sh" ]; then
    log "INFO" "Running prestart hook: ${APP_HOME}/ops/docker/prestart.sh"
    "${APP_HOME}/ops/docker/prestart.sh" || die "Prestart hook failed"
    return 0
  fi

  log "INFO" "No prestart hook found (skipping)"
}

run_migrations() {
  [ "${RUN_MIGRATIONS}" = "1" ] || return 0
  log "INFO" "Running migrations: ${MIGRATE_CMD}"
  # Run migrations as app user if applicable
  if [ "${RUN_AS_ROOT}" = "0" ] && id -u "${APP_USER}" >/dev/null 2>&1; then
    if _has_cmd su-exec; then
      su-exec "${APP_USER}:${APP_GROUP}" sh -c "${MIGRATE_CMD}" || die "Migrations failed"
      return 0
    elif _has_cmd gosu; then
      gosu "${APP_USER}:${APP_GROUP}" sh -c "${MIGRATE_CMD}" || die "Migrations failed"
      return 0
    fi
  fi
  # Fallback (root or no su-exec/gosu)
  sh -c "${MIGRATE_CMD}" || die "Migrations failed"
}

# -------- Exec chain (init + drop privs) --------
exec_with_init_and_drop_privs() {
  # Decide final command
  if [ "$#" -gt 0 ]; then
    CMD="$*"
  else
    CMD="${DEFAULT_CMD}"
  fi

  log "INFO" "Command: ${CMD}"

  # Build drop-privs wrapper if needed
  RUNNER=""
  if [ "${RUN_AS_ROOT}" = "0" ] && id -u "${APP_USER}" >/dev/null 2>&1; then
    if _has_cmd su-exec; then
      RUNNER="su-exec ${APP_USER}:${APP_GROUP}"
    elif _has_cmd gosu; then
      RUNNER="gosu ${APP_USER}:${APP_GROUP}"
    elif _has_cmd su; then
      # su variant (no exec passthrough on all distros, so wrap)
      RUNNER="su -s /bin/sh -c"
      CMD="exec ${CMD}"
      CMD_USER="${APP_USER}"
      # su path: su -s /bin/sh -c "exec ${CMD}" ${APP_USER}
      if _has_cmd tini; then
        exec tini -g -- sh -c "${RUNNER} \"${CMD}\" ${CMD_USER}"
      elif _has_cmd dumb-init; then
        exec dumb-init -- sh -c "${RUNNER} \"${CMD}\" ${CMD_USER}"
      else
        # bare fallback
        exec sh -c "${RUNNER} \"${CMD}\" ${CMD_USER}"
      fi
    else
      log "WARN" "No su-exec/gosu/su available; running as current user"
    fi
  fi

  # Prefer proper init as PID 1 to reap zombies
  if _has_cmd tini; then
    if [ -n "${RUNNER}" ]; then
      exec tini -g -- ${RUNNER} sh -c "exec ${CMD}"
    else
      exec tini -g -- sh -c "exec ${CMD}"
    fi
  elif _has_cmd dumb-init; then
    if [ -n "${RUNNER}" ]; then
      exec dumb-init -- ${RUNNER} sh -c "exec ${CMD}"
    else
      exec dumb-init -- sh -c "exec ${CMD}"
    fi
  else
    # Last-resort: no init – run and forward signals as best effort
    # Use exec to replace shell (PID 1). Signal forwarding will be handled by kernel to child.
    if [ -n "${RUNNER}" ]; then
      exec ${RUNNER} sh -c "exec ${CMD}"
    else
      exec sh -c "exec ${CMD}"
    fi
  fi
}

# -------- Main --------
main() {
  log "INFO" "Starting ${APP_NAME} entrypoint (UID=$(id -u), GID=$(id -g))"
  maybe_source_env
  maybe_set_timezone
  setup_user_and_dirs
  wait_for_endpoints
  run_hook
  run_migrations
  if [ "$#" -gt 0 ]; then
    exec_with_init_and_drop_privs "$@"
  else
    exec_with_init_and_drop_privs
  fi
}

main "$@"
