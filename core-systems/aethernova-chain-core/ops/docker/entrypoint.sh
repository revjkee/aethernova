#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Industrial Entrypoint for Aethernova Chain Core
# Features:
#  - POSIX sh, strict mode, deterministic logs
#  - Proper PID 1 signal forwarding & zombie reaping (optionally via tini)
#  - Secure *_FILE env loading for secrets
#  - Wait-for-dependencies (HOST:PORT with timeout)
#  - Drop privileges to non-root via gosu/su-exec; optional dynamic user by PUID/PGID
#  - Safe exec of the target process

# ========== Strict mode ==========
# Portable strict flags (no pipefail in pure /bin/sh)
set -eu
IFS='
	 '

# ========== Logging helpers ==========
log()  { printf '%s [INFO ] %s\n'  "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&1; }
warn() { printf '%s [WARN ] %s\n'  "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
err()  { printf '%s [ERROR] %s\n'  "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }

# ========== Env helpers ==========
# file_env VAR [default] — load VAR from VAR or VAR_FILE (like docker-library/*)
file_env() {
  # shellcheck disable=SC2039
  var="$1"; def="${2:-}"
  file_var="${var}_FILE"
  if [ "${!var-}" ] && [ "${!file_var-}" ]; then
    err "Both $var and $file_var are set (exclusive)."
    exit 1
  fi
  val="$def"
  if [ "${!var-}" ]; then
    val="${!var}"
  elif [ "${!file_var-}" ]; then
    if [ ! -r "$(printf %s "${!file_var}")" ]; then
      err "$file_var points to unreadable file: ${!file_var}"
      exit 1
    fi
    # shellcheck disable=SC2002
    val="$(cat -- "$(printf %s "${!file_var}")")"
  fi
  export "$var"="$val"
  unset "$file_var"
}

# require_env VAR — ensure env var is non-empty
require_env() {
  var="$1"
  if [ -z "${!var-}" ]; then
    err "Required environment variable '$var' is not set."
    exit 1
  fi
}

# ========== Dependency wait (HOST:PORT, TIMEOUT seconds) ==========
wait_for() {
  host="$1"; port="$2"; timeout_s="${3:-30}"
  start_ts=$(date +%s)
  while :; do
    if command -v nc >/dev/null 2>&1; then
      if nc -z "${host}" "${port}" 2>/dev/null; then
        log "Dependency ${host}:${port} is available."
        return 0
      fi
    elif [ -e "/dev/tcp/${host}/${port}" ] 2>/dev/null; then
      # Some shells support /dev/tcp
      : >/dev/tcp/"${host}"/"${port}" && {
        log "Dependency ${host}:${port} is available."
        return 0
      } || true
    else
      warn "Neither 'nc' nor /dev/tcp available; skipping check for ${host}:${port}."
      return 0
    fi
    now=$(date +%s)
    elapsed=$(( now - start_ts ))
    if [ "$elapsed" -ge "$timeout_s" ]; then
      err "Timeout waiting for ${host}:${port} (${timeout_s}s)."
      return 1
    fi
    sleep 1
  done
}

# Parse comma-separated WAIT_FOR="host1:port1,host2:port2"
maybe_wait_for_deps() {
  if [ -n "${WAIT_FOR-}" ]; then
    IFS=','; set -- $WAIT_FOR; IFS='
	 '
    for hp in "$@"; do
      host=$(printf %s "$hp" | awk -F: '{print $1}')
      port=$(printf %s "$hp" | awk -F: '{print $2}')
      [ -n "$host" ] && [ -n "$port" ] || { err "Invalid WAIT_FOR token: '$hp'"; exit 1; }
      wait_for "$host" "$port" "${WAIT_TIMEOUT:-60}"
    done
  fi
}

# ========== User/Group management ==========
# Create or adjust runtime user based on PUID/PGID; works on BusyBox/Alpine and Debian/Ubuntu
ensure_user() {
  desired_uid="${PUID:-1000}"
  desired_gid="${PGID:-1000}"
  user_name="${APP_USER:-app}"
  group_name="${APP_GROUP:-app}"

  # If running as non-root, skip
  if [ "$(id -u)" != "0" ]; then
    log "Container not running as root; skipping user management."
    return 0
  fi

  addgroup_cmd="addgroup -g"; adduser_cmd="adduser -D -H -s /sbin/nologin -G"
  if command -v groupadd >/dev/null 2>&1; then
    addgroup_cmd="groupadd -g"
  fi
  if command -v useradd >/dev/null 2>&1; then
    adduser_cmd="useradd -M -s /usr/sbin/nologin -g"
  fi

  # Create/ensure group
  if ! getent group "$group_name" >/dev/null 2>&1; then
    $addgroup_cmd "$desired_gid" "$group_name" >/dev/null 2>&1 || true
  fi

  # Create/ensure user
  if ! id -u "$user_name" >/dev/null 2>&1; then
    $adduser_cmd "$group_name" -u "$desired_uid" "$user_name" >/dev/null 2>&1 || true
  fi

  # Optional chown of app dirs
  for d in ${APP_OWN_DIRS:-}; do
    if [ -e "$d" ]; then
      chown -R "${user_name}:${group_name}" "$d" || warn "Cannot chown $d"
    fi
  done
}

# Drop privileges using gosu or su-exec if available
drop_privs_exec() {
  target_user="${APP_USER:-app}"
  target_group="${APP_GROUP:-app}"
  if [ "$(id -u)" = "0" ]; then
    if command -v gosu >/dev/null 2>&1; then
      exec gosu "${target_user}:${target_group}" "$@"
    elif command -v su-exec >/dev/null 2>&1; then
      exec su-exec "${target_user}:${target_group}" "$@"
    else
      warn "gosu/su-exec not found; continuing as root."
      exec "$@"
    fi
  else
    exec "$@"
  fi
}

# ========== Tini integration (optional) ==========
maybe_wrap_with_tini() {
  if [ "${USE_TINI:-auto}" = "never" ]; then
    exec "$@"
  fi
  # If docker run --init used, PID1 already is docker-init (tini); just exec.
  if grep -qa docker-init /proc/1/comm 2>/dev/null; then
    exec "$@"
  fi
  # Local tini binary
  if command -v tini >/dev/null 2>&1; then
    exec tini -- "$@"
  fi
  # Fallback: run without tini, but still exec to forward signals
  warn "tini not found and --init not used; proceeding without dedicated init."
  exec "$@"
}

# ========== Signal handling for wrapper sub-process ==========
child_pid=""
term_handler() {
  if [ -n "$child_pid" ] && kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "$child_pid" 2>/dev/null || true
    wait "$child_pid" 2>/dev/null || true
  fi
  exit 143
}

trap term_handler INT TERM

# ========== Main ==========
main() {
  # Load secrets via *_FILE (declare needed keys here)
  for k in ${FILE_ENV_VARS:-}; do
    # example: FILE_ENV_VARS="DB_PASSWORD API_KEY"
    file_env "$k"
  done

  # Validate required env vars
  for k in ${REQUIRED_ENV_VARS:-}; do
    require_env "$k"
  done

  # Optional wait for deps
  maybe_wait_for_deps

  # Optional dynamic user creation/chown
  if [ "${ENABLE_DYNAMIC_USER:-1}" = "1" ]; then
    ensure_user
  fi

  # If WRAP_WITH_TINI is set to 1/true/auto, let maybe_wrap_with_tini decide
  if [ "${WRAP_WITH_TINI:-auto}" != "never" ]; then
    # When wrapping with tini, we do not need our own traps; tini reaps/forwards.
    maybe_wrap_with_tini "$@"
    # never returns
  fi

  # Otherwise run child directly (and forward signals via exec/drop_privs_exec)
  # Start as background only if we need our own trap supervision
  set +e
  if [ "$(id -u)" = "0" ] && { command -v gosu >/dev/null 2>&1 || command -v su-exec >/dev/null 2>&1; }; then
    drop_privs_exec "$@"
  else
    exec "$@"
  fi
}

# If no args provided, use default command from image
if [ "$#" -eq 0 ]; then
  err "No command provided to entrypoint."
  exit 127
fi

main "$@"
