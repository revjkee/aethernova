#!/usr/bin/env bash
# OblivionVault Core — Industrial Docker Entrypoint
# Safe-by-default, dependency-aware, secrets-aware, signal-friendly.

set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------
# Re-exec via tini (PID1)
# -----------------------
if [[ -z "${OV_TINI_CHILD:-}" ]]; then
  for TINI_CAND in /sbin/tini /usr/bin/tini /bin/tini; do
    if [[ -x "${TINI_CAND}" ]]; then
      export OV_TINI_CHILD=1
      exec "${TINI_CAND}" -g -- "$0" "$@"
    fi
  done
fi

# -----------------------
# Defaults
# -----------------------
APP_NAME="${APP_NAME:-oblivionvault-core}"
APP_HOME="${APP_HOME:-/app}"
APP_DATA_DIR="${APP_DATA_DIR:-/data}"
APP_LOG_DIR="${APP_LOG_DIR:-/var/log/${APP_NAME}}"

LOG_LEVEL="${LOG_LEVEL:-INFO}"          # DEBUG|INFO|WARN|ERROR
UMASK_VALUE="${UMASK_VALUE:-0022}"      # 0022 by default
TZ="${TZ:-UTC}"

# Wait configuration
WAIT_FOR_TCP="${WAIT_FOR_TCP:-}"        # "host1:5432,host2:6379"
WAIT_FOR_HTTP="${WAIT_FOR_HTTP:-}"      # "http://host:8080/health,https://svc/readyz"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-60}"      # seconds

# Hooks
HOOKS_PRESTART_DIR="${HOOKS_PRESTART_DIR:-/opt/${APP_NAME}/hooks/prestart.d}"
HOOKS_POSTSTART_DIR="${HOOKS_POSTSTART_DIR:-/opt/${APP_NAME}/hooks/poststart.d}"

# Migrations
MIGRATIONS_CMD="${MIGRATIONS_CMD:-}"
SEED_CMD="${SEED_CMD:-}"

# User management
RUN_AS_UID="${RUN_AS_UID:-}"
RUN_AS_GID="${RUN_AS_GID:-}"
RUN_AS_USER="${RUN_AS_USER:-app}"
CREATE_USER_SHELL="${CREATE_USER_SHELL:-/usr/sbin/nologin}"

# Ownership fixes
FIX_OWNERSHIP="${FIX_OWNERSHIP:-0}"     # 1 to chown APP_DATA_DIR and APP_LOG_DIR

# Filesystem sync
FSYNC_ON_STOP="${FSYNC_ON_STOP:-1}"

# -----------------------
# Logging helpers
# -----------------------
_color() { [[ -t 1 ]] || return 0; case "$1" in DEBUG) printf '\033[36m';; INFO) printf '\033[32m';; WARN) printf '\033[33m';; ERROR) printf '\033[31m';; *) :;; esac; }
_nocolor() { [[ -t 1 ]] || return 0; printf '\033[0m'; }
_level_num() { case "$1" in DEBUG) echo 10;; INFO) echo 20;; WARN) echo 30;; ERROR) echo 40;; *) echo 20;; esac; }
_should_log() { local want have; want=$(_level_num "$LOG_LEVEL"); have=$(_level_num "${1:-INFO}"); [[ "$have" -ge "$want" ]]; }
log() {
  local lvl="${1:-INFO}"; shift || true
  _should_log "$lvl" || return 0
  local ts; ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  local c; c="$(_color "$lvl")"
  local n; n="$(_nocolor)"
  printf '%s[%s] %s%s%s %s\n' "" "$ts" "$c" "$lvl" "$n" "${*:-}" 1>&2
}
die() { log ERROR "$*"; exit 1; }

# -----------------------
# Utilities
# -----------------------
require_binary() { command -v "$1" >/dev/null 2>&1 || die "Required binary not found: $1"; }
join_by() { local IFS="$1"; shift; echo "$*"; }

# Secrets loader: FOO_FILE overrides FOO
load_secrets() {
  local var file
  while IFS='=' read -r var _; do
    [[ "$var" == *_FILE ]] || continue
    local base="${var%_FILE}"
    file="${!var:-}"
    if [[ -n "$file" && -r "$file" ]]; then
      export "$base"="$(<"$file")"
      log DEBUG "Loaded secret for $base from $file"
      unset "$var"
    fi
  done < <(env)
}

# Safe env sanity
set_timezone() {
  export TZ
  if [[ -w /etc/timezone && -w /etc/localtime && -e /usr/share/zoneinfo/$TZ ]]; then
    echo "$TZ" >/etc/timezone || true
    ln -sf "/usr/share/zoneinfo/$TZ" /etc/localtime || true
  fi
}
set_umask() { umask "$UMASK_VALUE" || die "Invalid UMASK_VALUE=$UMASK_VALUE"; }

# Waiters
wait_tcp_target() {
  local hostport="$1" timeout="${2:-$WAIT_TIMEOUT}" start now host port
  host="${hostport%%:*}"; port="${hostport##*:}"
  log INFO "Waiting TCP $host:$port up to ${timeout}s"
  start=$(date +%s)
  while true; do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then exec 3<&- 3>&-; log INFO "TCP ready: $host:$port"; return 0; fi
    now=$(date +%s); (( now - start >= timeout )) && die "Timeout waiting TCP $host:$port"
    sleep 1
  done
}
wait_http_target() {
  local url="$1" timeout="${2:-$WAIT_TIMEOUT}"
  if command -v curl >/dev/null 2>&1; then
    log INFO "Waiting HTTP ${url} up to ${timeout}s"
    local start; start=$(date +%s)
    while true; do
      if curl -fsS -m 5 -o /dev/null "$url"; then log INFO "HTTP ready: $url"; return 0; fi
      local now; now=$(date +%s); (( now - start >= timeout )) && die "Timeout waiting HTTP $url"
      sleep 1
    done
  elif command -v wget >/dev/null 2>&1; then
    log INFO "Waiting HTTP ${url} up to ${timeout}s (wget)"
    local start; start=$(date +%s)
    while true; do
      if wget -q -T 5 -O /dev/null "$url"; then log INFO "HTTP ready: $url"; return 0; fi
      local now; now=$(date +%s); (( now - start >= timeout )) && die "Timeout waiting HTTP $url"
      sleep 1
    done
  else
    log WARN "curl/wget not found, skipping HTTP wait for ${url}"
  fi
}
wait_dependencies() {
  local tcp="${WAIT_FOR_TCP:-}" http="${WAIT_FOR_HTTP:-}"
  if [[ -n "$tcp" ]]; then
    IFS=',' read -r -a a <<< "$tcp"
    for t in "${a[@]}"; do [[ -n "$t" ]] && wait_tcp_target "$t" "$WAIT_TIMEOUT"; done
  fi
  if [[ -n "$http" ]]; then
    IFS=',' read -r -a b <<< "$http"
    for u in "${b[@]}"; do [[ -n "$u" ]] && wait_http_target "$u" "$WAIT_TIMEOUT"; done
  fi
}

# Hooks runner
run_hooks() {
  local dir="$1" name; name="$(basename "$dir" || true)"
  [[ -d "$dir" ]] || { log DEBUG "No hooks in $dir"; return 0; }
  log INFO "Running hooks in $dir"
  local f
  # shellcheck disable=SC2045
  for f in $(ls -1 "$dir" 2>/dev/null | sort); do
    [[ -x "$dir/$f" ]] || { log DEBUG "Skip non-executable $dir/$f"; continue; }
    log INFO "Hook: $dir/$f"
    "$dir/$f"
  done
}

# Permission fixes
fix_permissions() {
  [[ "$FIX_OWNERSHIP" == "1" ]] || return 0
  [[ -n "$RUN_AS_UID" && -n "$RUN_AS_GID" ]] || { log WARN "FIX_OWNERSHIP=1 but RUN_AS_UID/GID not set"; return 0; }
  local dirs=("$APP_DATA_DIR" "$APP_LOG_DIR")
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] || { mkdir -p "$d"; }
    chown -R "${RUN_AS_UID}:${RUN_AS_GID}" "$d" || log WARN "chown failed for $d"
  done
}

# User switcher
maybe_switch_user() {
  [[ -n "$RUN_AS_UID" && -n "$RUN_AS_GID" ]] || return 0
  if ! getent group "$RUN_AS_GID" >/dev/null 2>&1; then
    groupadd -g "$RUN_AS_GID" "$RUN_AS_USER" || true
  fi
  if ! id -u "$RUN_AS_USER" >/dev/null 2>&1; then
    useradd -u "$RUN_AS_UID" -g "$RUN_AS_GID" -M -s "$CREATE_USER_SHELL" "$RUN_AS_USER" || true
  fi
}

# Graceful shutdown
child_pid=""
forward_signals() {
  local sig="$1"
  if [[ -n "${child_pid}" ]]; then
    log WARN "Forwarding ${sig} to PID ${child_pid}"
    kill "-${sig}" "${child_pid}" 2>/dev/null || true
  fi
}
flush_fs() {
  [[ "$FSYNC_ON_STOP" == "1" ]] || return 0
  command -v sync >/dev/null 2>&1 && sync || true
}

# -----------------------
# Subcommands
# -----------------------
cmd_web() {
  [[ -z "${MIGRATIONS_CMD:-}" ]] || { log INFO "Running migrations"; eval "$MIGRATIONS_CMD"; }
  [[ -z "${SEED_CMD:-}" ]] || { log INFO "Running seed"; eval "$SEED_CMD"; }
  run_hooks "$HOOKS_PRESTART_DIR"

  local cmd=()
  if [[ -n "${APP_WEB_CMD:-}" ]]; then
    IFS=' ' read -r -a cmd <<< "${APP_WEB_CMD}"
  else
    cmd=(python -m app.run)
  fi

  if [[ -n "$RUN_AS_UID" && -n "$RUN_AS_GID" ]]; then
    if command -v gosu >/dev/null 2>&1; then
      gosu "${RUN_AS_UID}:${RUN_AS_GID}" "${cmd[@]}" &
    elif command -v su-exec >/dev/null 2>&1; then
      su-exec "${RUN_AS_UID}:${RUN_AS_GID}" "${cmd[@]}" &
    else
      # Fallback: run as current user
      "${cmd[@]}" &
    fi
  else
    "${cmd[@]}" &
  fi

  child_pid="$!"
  log INFO "Web started with PID ${child_pid}"

  run_hooks "$HOOKS_POSTSTART_DIR"

  wait "$child_pid"
  local rc=$?
  log INFO "Web process exited rc=${rc}"
  return "${rc}"
}

cmd_worker() {
  run_hooks "$HOOKS_PRESTART_DIR"
  local cmd=()
  if [[ -n "${APP_WORKER_CMD:-}" ]]; then
    IFS=' ' read -r -a cmd <<< "${APP_WORKER_CMD}"
  else
    cmd=(python -m app.worker)
  fi

  if [[ -n "$RUN_AS_UID" && -n "$RUN_AS_GID" ]]; then
    if command -v gosu >/dev/null 2>&1; then
      gosu "${RUN_AS_UID}:${RUN_AS_GID}" "${cmd[@]}" &
    elif command -v su-exec >/dev/null 2>&1; then
      su-exec "${RUN_AS_UID}:${RUN_AS_GID}" "${cmd[@]}" &
    else
      "${cmd[@]}" &
    fi
  else
    "${cmd[@]}" &
  fi

  child_pid="$!"
  log INFO "Worker started with PID ${child_pid}"

  run_hooks "$HOOKS_POSTSTART_DIR"

  wait "$child_pid"
  local rc=$?
  log INFO "Worker process exited rc=${rc}"
  return "${rc}"
}

cmd_migrate() {
  [[ -n "${MIGRATIONS_CMD:-}" ]] || die "MIGRATIONS_CMD not set"
  eval "$MIGRATIONS_CMD"
}

cmd_shell() {
  exec /bin/sh -lc "${*:-bash}" || exec /bin/bash || exec /bin/sh
}

cmd_healthcheck() {
  # Lightweight probe. Customize via APP_HEALTH_CMD or HTTP/TCP env.
  if [[ -n "${APP_HEALTH_CMD:-}" ]]; then
    eval "$APP_HEALTH_CMD"
    exit $?
  fi
  if [[ -n "$WAIT_FOR_HTTP" ]]; then
    IFS=',' read -r -a a <<< "$WAIT_FOR_HTTP"
    wait_http_target "${a[0]}" 5
    exit $?
  fi
  if [[ -n "$WAIT_FOR_TCP" ]]; then
    IFS=',' read -r -a b <<< "$WAIT_FOR_TCP"
    wait_tcp_target "${b[0]}" 5
    exit $?
  fi
  # Default: ok
  exit 0
}

# -----------------------
# Main
# -----------------------
main() {
  trap 'forward_signals TERM; flush_fs' TERM
  trap 'forward_signals INT;  flush_fs' INT
  trap 'forward_signals HUP;  flush_fs' HUP
  trap 'flush_fs' EXIT

  log INFO "Starting ${APP_NAME} entrypoint"
  set_timezone
  set_umask
  load_secrets
  maybe_switch_user
  fix_permissions
  wait_dependencies

  local subcmd="${1:-web}"; shift || true
  case "$subcmd" in
    web)     cmd_web "$@";;
    worker)  cmd_worker "$@";;
    migrate) cmd_migrate "$@";;
    shell)   cmd_shell "$@";;
    healthcheck) cmd_healthcheck "$@";;
    *) log WARN "Unknown subcommand: ${subcmd}. Executing raw: $subcmd $*"; exec "$subcmd" "$@";;
  esac
}

main "$@"
