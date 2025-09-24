#!/usr/bin/env bash
# shellcheck shell=bash
# cybersecurity-core :: industrial Docker entrypoint
# Features: strict mode, secrets *_FILE, non-root drop, wait-for deps, hooks, signals, exec under init

set -Eeuo pipefail

#######################################
# Logging
#######################################
LOG_LEVEL="${LOG_LEVEL:-info}"  # debug|info|warn|error
TS() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

_log_level_to_int() {
  case "${1,,}" in
    debug) echo 10 ;;
    info)  echo 20 ;;
    warn)  echo 30 ;;
    error) echo 40 ;;
    *)     echo 20 ;;
  esac
}
LOG_LEVEL_INT="$(_log_level_to_int "$LOG_LEVEL")"

_log() {
  local level="$1"; shift || true
  local level_int="$(_log_level_to_int "$level")"
  if (( level_int >= LOG_LEVEL_INT )); then
    printf '%s [%s] %s\n' "$(TS)" "${level^^}" "$*" 1>&2
  fi
}
debug(){ _log debug "$@"; }
info(){  _log info  "$@"; }
warn(){  _log warn  "$@"; }
error(){ _log error "$@"; }

die() {
  error "$*"
  exit 1
}

#######################################
# Trap & diagnostics
#######################################
on_err() {
  local ec=$?
  error "Unhandled error (exit=$ec). Aborting."
  exit "$ec"
}
on_exit() {
  local ec=$?
  debug "Entrypoint exit with code $ec."
}
trap on_err ERR
trap on_exit EXIT

#######################################
# Env defaults
#######################################
APP_HOME="${APP_HOME:-/app}"
DATA_DIR="${DATA_DIR:-/data}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/cyber}"
UMASK="${UMASK:-0022}"

# Privilege/env settings
PUID="${PUID:-}"
PGID="${PGID:-}"
RUN_AS_USER="${RUN_AS_USER:-}"
RUN_AS_GROUP="${RUN_AS_GROUP:-}"
CHOWN_DIRS="${CHOWN_DIRS:-$APP_HOME,$DATA_DIR,$RUNTIME_DIR}"

# Dependency wait
WAIT_FOR="${WAIT_FOR:-}"               # "host:port,host2:port2"
WAIT_FOR_TIMEOUT="${WAIT_FOR_TIMEOUT:-60}"  # seconds per endpoint
WAIT_FOR_INTERVAL="${WAIT_FOR_INTERVAL:-2}" # seconds between attempts

# Hooks/commands
PRE_START_CMD="${PRE_START_CMD:-}"
MIGRATIONS_CMD="${MIGRATIONS_CMD:-}"

#######################################
# Utilities
#######################################
has_cmd() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }
tighten_perms_if_secret() {
  # If file is world/group-readable, fix it (600)
  local f="$1"
  if [ -f "$f" ]; then
    chmod go-rwx "$f" || true
  fi
}

#######################################
# Secrets loader (VAR_FILE -> VAR)
#######################################
load_env_from_files() {
  debug "Loading secrets from *_FILE if present..."
  # Iterate exported env names that end with _FILE
  while IFS='=' read -r name value; do
    # Strip export and quotes
    name="${name#export }"
    name="${name%%=*}"
    case "$name" in
      *_FILE)
        local var="${name%_FILE}"
        local path="${!name:-}"
        if [ -n "$path" ]; then
          [ -r "$path" ] || die "Secret file not readable: $path"
          tighten_perms_if_secret "$path"
          local val
          val="$(<"$path")"
          export "$var"="$val"
          unset "$name"
          debug "Loaded secret into $var from $path"
        fi
      ;;
    esac
  done < <(env | sort)
}

#######################################
# Wait for a single host:port
#######################################
wait_for_one() {
  local hostport="$1"
  local timeout="${2:-$WAIT_FOR_TIMEOUT}"
  local interval="${3:-$WAIT_FOR_INTERVAL}"

  local host="${hostport%%:*}"
  local port="${hostport##*:}"
  [ -n "$host" ] && [ -n "$port" ] || die "Invalid WAIT_FOR target: '$hostport'"

  info "Waiting for $host:$port (timeout=${timeout}s, interval=${interval}s)..."
  local start epoch_now
  start="$(date +%s)"

  while true; do
    if has_cmd nc; then
      if nc -z "$host" "$port" >/dev/null 2>&1; then
        info "Dependency reachable: $host:$port"
        return 0
      fi
    else
      # /dev/tcp fallback (bash-specific)
      if (exec 3<>"/dev/tcp/$host/$port") >/dev/null 2>&1; then
        exec 3>&- 3<&-
        info "Dependency reachable: $host:$port"
        return 0
      fi
    fi

    epoch_now="$(date +%s)"
    if (( epoch_now - start >= timeout )); then
      die "Timeout waiting for $host:$port after ${timeout}s"
    fi
    sleep "$interval"
  done
}

wait_for_all() {
  [ -z "$WAIT_FOR" ] && return 0
  IFS=',' read -r -a targets <<< "$WAIT_FOR"
  for t in "${targets[@]}"; do
    t="${t//[[:space:]]/}"
    [ -z "$t" ] || wait_for_one "$t" "$WAIT_FOR_TIMEOUT" "$WAIT_FOR_INTERVAL"
  done
}

#######################################
# User & group management / privilege drop
#######################################
detect_suexec() {
  if has_cmd su-exec; then echo "su-exec"; return 0; fi
  if has_cmd gosu;   then echo "gosu";   return 0; fi
  echo ""
}

create_group_if_needed() {
  local gid="$1" name="${2:-cyber}"
  if has_cmd getent; then
    if getent group "$gid" >/dev/null 2>&1; then return 0; fi
  fi
  if has_cmd addgroup; then
    addgroup -g "$gid" -S "$name" >/dev/null 2>&1 || true
  elif has_cmd groupadd; then
    groupadd -g "$gid" -r "$name" >/dev/null 2>&1 || true
  fi
}

create_user_if_needed() {
  local uid="$1" gid="$2" name="${3:-cyber}"
  if has_cmd getent; then
    if getent passwd "$uid" >/dev/null 2>&1; then return 0; fi
  fi
  if has_cmd adduser; then
    adduser -S -D -H -u "$uid" -G "$name" "$name" >/dev/null 2>&1 || true
  elif has_cmd useradd; then
    useradd -r -M -N -u "$uid" -g "$gid" -s /usr/sbin/nologin "$name" >/dev/null 2>&1 || true
  fi
}

resolve_user_group() {
  local uid gid u g
  if [ -n "$PUID" ] && [ -n "$PGID" ]; then
    uid="$PUID"; gid="$PGID"
    u="${RUN_AS_USER:-cyber}"
    g="${RUN_AS_GROUP:-cyber}"
  elif [ -n "$RUN_AS_USER" ] || [ -n "$RUN_AS_GROUP" ]; then
    # If names provided, try to fetch ids; fallback to 1000
    u="${RUN_AS_USER:-cyber}"
    g="${RUN_AS_GROUP:-cyber}"
    uid="$(id -u "$u" 2>/dev/null || echo 1000)"
    gid="$(id -g "$g" 2>/dev/null || echo 1000)"
  else
    # No override; if root, we still drop to 1000:1000 by default
    uid=1000; gid=1000; u=cyber; g=cyber
  fi

  echo "$uid:$gid:$u:$g"
}

ensure_runtime_dirs() {
  umask "$UMASK"
  for d in "$APP_HOME" "$DATA_DIR" "$RUNTIME_DIR"; do
    ensure_dir "$d"
  done

  # chown requested directories if running as root
  if [ "$(id -u)" -eq 0 ] && [ -n "$CHOWN_DIRS" ]; then
    IFS=',' read -r -a dirs <<< "$CHOWN_DIRS"
    local d
    for d in "${dirs[@]}"; do
      d="${d//[[:space:]]/}"
      [ -z "$d" ] && continue
      if [ -d "$d" ] || [ -f "$d" ]; then
        chown -R "${TARGET_UID}:${TARGET_GID}" "$d" || warn "Failed to chown $d"
      fi
    done
  fi
}

#######################################
# Hooks
#######################################
run_hooks() {
  local hook_dir="/docker-entrypoint.d"
  if [ -d "$hook_dir" ]; then
    info "Running hooks in $hook_dir..."
    # Only *.sh, ignore non-exec
    find "$hook_dir" -maxdepth 1 -type f -name "*.sh" | sort | while read -r f; do
      if [ -x "$f" ]; then
        info "Executing hook: $(basename "$f")"
        "$f"
      else
        info "Sourcing hook: $(basename "$f")"
        # shellcheck disable=SC1090
        . "$f"
      fi
    done
  fi
}

run_optional_cmd() {
  local title="$1"; shift || true
  local cmd="$*"
  [ -z "$cmd" ] && return 0
  info "$title: $cmd"
  # Run as target user if we have suexec tool and need to drop from root
  if [ "$(id -u)" -eq 0 ] && [ -n "$SUEXEC" ]; then
    $SUEXEC "${TARGET_UID}:${TARGET_GID}" bash -lc "$cmd"
  else
    bash -lc "$cmd"
  fi
}

#######################################
# Init wrapper detection (PID1 reaping)
#######################################
detect_init() {
  if has_cmd dumb-init; then
    echo "dumb-init --"
    return 0
  fi
  if has_cmd tini; then
    echo "tini --"
    return 0
  fi
  echo ""
}

#######################################
# Main
#######################################
main() {
  load_env_from_files

  # Resolve target user/group
  IFS=':' read -r TARGET_UID TARGET_GID TARGET_USER TARGET_GROUP < <(resolve_user_group)
  debug "Target user: ${TARGET_USER} (${TARGET_UID}); group: ${TARGET_GROUP} (${TARGET_GID})"

  # Create user/group if root and required
  if [ "$(id -u)" -eq 0 ]; then
    create_group_if_needed "$TARGET_GID" "$TARGET_GROUP"
    create_user_if_needed  "$TARGET_UID" "$TARGET_GID" "$TARGET_USER"
  fi

  ensure_runtime_dirs

  # Prepare suexec & init tools
  SUEXEC="$(detect_suexec)"
  INIT_BIN="$(detect_init)"

  # Wait dependencies
  wait_for_all

  # Hooks and optional commands
  run_hooks
  run_optional_cmd "Pre-start command" $PRE_START_CMD
  run_optional_cmd "Migrations command" $MIGRATIONS_CMD

  # Final exec: preserve CMD/args
  if [ "$#" -eq 0 ]; then
    die "No command provided to entrypoint. Define CMD in Dockerfile or pass it in 'docker run ...'."
  fi

  info "Starting service: $*"
  if [ "$(id -u)" -eq 0 ]; then
    if [ -n "$SUEXEC" ]; then
      # Drop privileges + init reaper if available
      if [ -n "$INIT_BIN" ]; then
        exec $INIT_BIN $SUEXEC "${TARGET_UID}:${TARGET_GID}" "$@"
      else
        exec $SUEXEC "${TARGET_UID}:${TARGET_GID}" "$@"
      fi
    else
      warn "su-exec/gosu not found; running as root. It is recommended to install 'su-exec' or 'gosu'."
      if [ -n "$INIT_BIN" ]; then
        exec $INIT_BIN "$@"
      else
        exec "$@"
      fi
    fi
  else
    # Already non-root
    if [ -n "$INIT_BIN" ]; then
      exec $INIT_BIN "$@"
    else
      exec "$@"
    fi
  fi
}

main "$@"
