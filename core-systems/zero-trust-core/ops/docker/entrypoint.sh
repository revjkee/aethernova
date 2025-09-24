#!/usr/bin/env bash
# Production-grade entrypoint for zero-trust-core
# Features:
#  - strict bash flags and safe defaults
#  - load secrets from *_FILE environment variables
#  - wait-for dependencies (tcp host:port or unix:/path.sock)
#  - render config templates via envsubst
#  - drop privileges using gosu / su-exec or fallback to su -c
#  - graceful shutdown: SIGTERM -> SIGTERM to child -> SIGKILL after timeout
#  - readiness/liveness files for k8s probes
#  - structured logging with timestamps
#
# Environment variables (defaults provided):
#  APP_BIN              -> main binary to run (default /usr/local/bin/zero-trust-core)
#  APP_USER             -> user to run as (default appuser)
#  APP_GROUP            -> group to run as (default appuser)
#  WAIT_FOR             -> comma-separated list of host:port or unix:/path.sock to wait for
#  WAIT_TIMEOUT         -> seconds to wait for dependencies (default 60)
#  CONFIG_TEMPLATE      -> path to template file (optional)
#  CONFIG_OUT           -> rendered config path (optional)
#  SECRET_FILE_VARS     -> comma-separated env var names that point to secret files (optional)
#  GRACEFUL_TIMEOUT     -> seconds to wait after SIGTERM before SIGKILL (default 30)
#  READY_FILE           -> path for readiness file (default /tmp/ready)
#  LOG_LEVEL            -> INFO|DEBUG (default INFO)
#
set -euo pipefail

# -----------------------
# Defaults and utils
# -----------------------
: "${APP_BIN:=/usr/local/bin/zero-trust-core}"
: "${APP_USER:=appuser}"
: "${APP_GROUP:=appuser}"
: "${WAIT_FOR:=}"
: "${WAIT_TIMEOUT:=60}"
: "${CONFIG_TEMPLATE:=}"
: "${CONFIG_OUT:=}"
: "${SECRET_FILE_VARS:=}"
: "${GRACEFUL_TIMEOUT:=30}"
: "${READY_FILE:=/tmp/ready}"
: "${LOG_LEVEL:=INFO}"
: "${DEBUG:=false}"

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() {
  level="$1"; shift
  printf '%s %s [%s] %s\n' "$(timestamp)" "$HOSTNAME" "$level" "$*" >&2
}
log_info() { [ "$LOG_LEVEL" = "DEBUG" ] && log "DEBUG" "$@" || log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_err()  { log "ERROR" "$@"; }

# Strict: ensure APP_BIN exists
if [ ! -x "$APP_BIN" ]; then
  log_err "Application binary not found or not executable: $APP_BIN"
  exit 2
fi

# -----------------------
# Secret loader
# -----------------------
load_secrets_from_env_files() {
  # If SECRET_FILE_VARS specified, only process those, else process all *_FILE env vars
  local vars="$SECRET_FILE_VARS"
  if [ -z "$vars" ]; then
    # generate list like VAR_NAME_FILE entries present in env
    # Use "env" builtin to list environment; portable-ish
    vars="$(env | awk -F= '/_FILE=/ {print $1}' | paste -sd, - 2>/dev/null || true)"
  fi
  IFS=',' read -r -a arr <<< "$vars"
  for v in "${arr[@]}"; do
    v="$(echo "$v" | xargs)"  # trim
    [ -z "$v" ] && continue
    # actual file env var must exist
    if [ -n "${!v-}" ]; then
      file="${!v}"
      if [ -f "$file" ]; then
        target_var="${v%_FILE}"
        # read safely
        val="$(sed -n '1h;1!H;${x;p}' "$file" 2>/dev/null || cat "$file" 2>/dev/null)"
        # export into environment
        export "$target_var"="$val"
        # optional: unset *_FILE to reduce accidental leakage
        unset "$v"
        log_info "Loaded secret from $file into env var $target_var"
      else
        log_warn "Secret file for $v not found: $file"
      fi
    fi
  done
}

# -----------------------
# Wait for dependencies
# -----------------------
wait_for_target() {
  target="$1"
  timeout="$2"
  start_time=$(date +%s)
  log_info "Waiting for $target (timeout ${timeout}s)"
  while true; do
    now=$(date +%s)
    elapsed=$((now - start_time))
    if [ "$elapsed" -ge "$timeout" ]; then
      log_err "Timeout waiting for $target after ${timeout}s"
      return 1
    fi

    if [[ "$target" =~ ^unix: ]]; then
      sock="${target#unix:}"
      if [ -S "$sock" ]; then
        log_info "Found unix socket $sock"
        return 0
      fi
    else
      # host:port
      host="${target%%:*}"
      port="${target##*:}"
      # try /dev/tcp if available
      if (exec 3<>"/dev/tcp/$host/$port") >/dev/null 2>&1; then
        exec 3>&- 3<&-
        log_info "$host:$port is reachable"
        return 0
      fi
      # fallback: try nc
      if command -v nc >/dev/null 2>&1; then
        if nc -z "$host" "$port" >/dev/null 2>&1; then
          log_info "$host:$port is reachable (nc)"
          return 0
        fi
      fi
    fi
    sleep 0.5
  done
}

wait_for_dependencies() {
  if [ -z "$WAIT_FOR" ]; then
    log_info "No external dependencies configured (WAIT_FOR empty)"
    return 0
  fi
  IFS=',' read -r -a targets <<< "$WAIT_FOR"
  for t in "${targets[@]}"; do
    t="$(echo "$t" | xargs)" || true
    [ -z "$t" ] && continue
    if ! wait_for_target "$t" "$WAIT_TIMEOUT"; then
      return 1
    fi
  done
  return 0
}

# -----------------------
# Config rendering
# -----------------------
render_config_template() {
  if [ -z "$CONFIG_TEMPLATE" ] || [ -z "$CONFIG_OUT" ]; then
    return 0
  fi
  if [ ! -f "$CONFIG_TEMPLATE" ]; then
    log_err "Config template not found: $CONFIG_TEMPLATE"
    return 1
  fi
  if command -v envsubst >/dev/null 2>&1; then
    log_info "Rendering config template $CONFIG_TEMPLATE -> $CONFIG_OUT using envsubst"
    envsubst < "$CONFIG_TEMPLATE" > "$CONFIG_OUT"
    chmod 600 "$CONFIG_OUT" || true
    return 0
  else
    log_warn "envsubst not available; copying template without substitution"
    cp "$CONFIG_TEMPLATE" "$CONFIG_OUT"
    chmod 600 "$CONFIG_OUT" || true
    return 0
  fi
}

# -----------------------
# Privilege drop helper
# -----------------------
run_as_user() {
  # args: command...
  if [ "$(id -u)" -eq 0 ]; then
    # try gosu
    if command -v gosu >/dev/null 2>&1; then
      exec gosu "${APP_USER}:${APP_GROUP}" "$@"
    fi
    if command -v su-exec >/dev/null 2>&1; then
      exec su-exec "${APP_USER}:${APP_GROUP}" "$@"
    fi
    # fallback to su -c (less ideal)
    if command -v su >/dev/null 2>&1; then
      su -s /bin/bash -c "exec \"$*\"" "${APP_USER}"
    fi
    log_warn "No privilege drop helper (gosu/su-exec) found; running as root (not recommended)"
    exec "$@"
  else
    exec "$@"
  fi
}

# -----------------------
# Cleanup and signal handling
# -----------------------
_child_pid=0
_graceful_timeout="$GRACEFUL_TIMEOUT"

on_shutdown() {
  sig="$1"
  log_warn "Entrypoint received signal $sig, forwarding to child pid=${_child_pid:-unknown}"
  if [ "${_child_pid:-0}" -ne 0 ]; then
    kill -s TERM "${_child_pid}" >/dev/null 2>&1 || true
    # wait for graceful shutdown
    SECONDS_WAITED=0
    while kill -0 "${_child_pid}" >/dev/null 2>&1; do
      if [ "$SECONDS_WAITED" -ge "$_graceful_timeout" ]; then
        log_warn "Child did not exit after ${_graceful_timeout}s, sending SIGKILL"
        kill -s KILL "${_child_pid}" >/dev/null 2>&1 || true
        break
      fi
      sleep 1
      SECONDS_WAITED=$((SECONDS_WAITED+1))
    done
  fi
  # remove readiness file
  if [ -f "$READY_FILE" ]; then
    rm -f "$READY_FILE" || true
  fi
  log_info "Shutdown complete"
  exit 0
}

trap 'on_shutdown SIGTERM' SIGTERM
trap 'on_shutdown SIGINT'  SIGINT

# -----------------------
# Prepare runtime directories and permissions
# -----------------------
prepare_runtime_dirs() {
  # ensure /var/run and /var/log owned by APP_USER if running as root
  for d in /var/run/zero-trust /var/log/zero-trust /var/lib/zero-trust; do
    mkdir -p "$d" || true
    if id "$APP_USER" >/dev/null 2>&1; then
      chown -R "${APP_USER}:${APP_GROUP}" "$d" || true
      chmod 750 "$d" || true
    fi
  done
}

# -----------------------
# Main startup sequence
# -----------------------
main() {
  log_info "Entrypoint starting (APP_BIN=$APP_BIN) LOG_LEVEL=$LOG_LEVEL"

  # load secrets from files into environment
  load_secrets_from_env_files

  # render config template if provided
  if ! render_config_template; then
    log_err "Config rendering failed"
    exit 3
  fi

  # prepare directories
  prepare_runtime_dirs

  # wait for dependencies
  if ! wait_for_dependencies; then
    log_err "Dependency wait failed"
    exit 4
  fi

  # start application as child process
  # support args: if container passed explicit command, use it; else use APP_BIN
  if [ "$#" -gt 0 ]; then
    CMD=( "$@" )
  else
    CMD=( "$APP_BIN" )
  fi

  log_info "Starting application: ${CMD[*]}"
  # run as specified user (drop privileges if running as root)
  if [ "$(id -u)" -eq 0 ]; then
    # ensure user exists; if not, try to create with minimal privileges (best-effort)
    if ! id "$APP_USER" >/dev/null 2>&1; then
      log_warn "User $APP_USER does not exist; creating with UID/GID from env if provided"
      # create group/user only if adduser is present (best-effort)
      if command -v useradd >/dev/null 2>&1; then
        useradd --system --no-create-home --group "$APP_GROUP" "$APP_USER" >/dev/null 2>&1 || true
      fi
    fi
  fi

  # spawn child in background to allow signal trapping
  if [ "$(id -u)" -eq 0 ]; then
    # use run_as_user to exec keeping child as backgrounded process
    if command -v gosu >/dev/null 2>&1; then
      gosu "${APP_USER}:${APP_GROUP}" "${CMD[@]}" &
    elif command -v su-exec >/dev/null 2>&1; then
      su-exec "${APP_USER}:${APP_GROUP}" "${CMD[@]}" &
    else
      # last resort: run directly (still background)
      "${CMD[@]}" &
    fi
  else
    "${CMD[@]}" &
  fi

  _child_pid=$!
  log_info "Spawned child pid=${_child_pid}"

  # create readiness file (indicates process started; readiness probe can check more advanced conditions)
  touch "$READY_FILE" || true
  log_info "Readiness file created at $READY_FILE"

  # wait for child to exit
  wait "${_child_pid}"
  exit_code=$?
  log_warn "Child pid=${_child_pid} exited with code ${exit_code}"
  # cleanup readiness
  [ -f "$READY_FILE" ] && rm -f "$READY_FILE" || true
  # propagate exit code
  exit "$exit_code"
}

# -----------------------
# Run main with passed args
# -----------------------
main "$@"
