# automation-core/docker/entrypoint.sh
#!/usr/bin/env bash
# Industrial container entrypoint
# - Safe bash: -e (errexit), -u (nounset), -o pipefail
# - Proper signal handling (via tini if present or Docker --init)
# - Privilege drop: su-exec / gosu
# - Dependency wait: WAIT_FOR=host1:port1,host2:port2
# - Optional prestart/migrations hooks
# - Exec form to hand PID 1 to the app

set -euo pipefail
IFS=$'\n\t'

# -------- logging --------
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf "%s INFO  %s\n"  "$(ts)" "$*"; }
warn(){ printf "%s WARN  %s\n"  "$(ts)" "$*" >&2; }
err() { printf "%s ERROR %s\n"  "$(ts)" "$*" >&2; }
die() { err "$*"; exit 1; }

# -------- debug --------
if [[ "${DEBUG:-0}" == "1" ]]; then set -x; fi

# -------- helpers --------
have() { command -v "$1" >/dev/null 2>&1; }
# shellcheck disable=SC2120
redact() {
  # redact common secret-like envs in logs
  sed -E 's/(PASSWORD|PASS|TOKEN|SECRET|KEY)=([^ ]+)/\1=*******/g'
}

# -------- configuration (env) --------
APP_NAME="${APP_NAME:-automation-core}"
USE_TINI="${USE_TINI:-auto}"                # auto|1|0
RUN_AS_USER="${RUN_AS_USER:-}"               # e.g. app or 1000
RUN_AS_GROUP="${RUN_AS_GROUP:-}"             # e.g. app or 1000
APP_WRITABLE_DIRS="${APP_WRITABLE_DIRS:-}"   # comma-separated list to mkdir -p and chown
WAIT_FOR="${WAIT_FOR:-}"                     # "host1:port1,host2:port2"
WAIT_FOR_TIMEOUT="${WAIT_FOR_TIMEOUT:-30}"   # seconds per endpoint
WAIT_FOR_INTERVAL="${WAIT_FOR_INTERVAL:-2}"  # seconds between retries
PRESTART_CMD="${PRESTART_CMD:-}"             # optional prestart shell command
MIGRATIONS_CMD="${MIGRATIONS_CMD:-}"         # optional migrations command
RUN_DB_MIGRATIONS="${RUN_DB_MIGRATIONS:-}"   # if "1" -> run MIGRATIONS_CMD
HEALTHCHECK_TOUCH="${HEALTHCHECK_TOUCH:-}"   # file to touch on readiness

# -------- sanity checks --------
[[ "$#" -ge 1 ]] || die "No command provided to entrypoint"

# -------- directories --------
prepare_dirs() {
  [[ -z "${APP_WRITABLE_DIRS}" ]] && return 0
  IFS=',' read -r -a dirs <<< "${APP_WRITABLE_DIRS}"
  for d in "${dirs[@]}"; do
    [[ -z "$d" ]] && continue
    mkdir -p "$d"
    if [[ -n "${RUN_AS_USER}" ]]; then
      chown -R "${RUN_AS_USER}:${RUN_AS_GROUP:-$RUN_AS_USER}" "$d" || warn "chown failed for $d"
    fi
    log "prepared dir: $d"
  done
}

# -------- wait for deps --------
probe_tcp() {
  local host="$1" port="$2" timeout="${3:-$WAIT_FOR_TIMEOUT}"
  if have nc; then
    nc -z -w "${timeout}" "$host" "$port" </dev/null
    return $?
  fi
  # Bash /dev/tcp fallback
  local start end=$((SECONDS + timeout))
  while (( SECONDS < end )); do
    if exec 3<>"/dev/tcp/${host}/${port}"; then
      exec 3>&- 3<&-
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_all() {
  [[ -z "${WAIT_FOR}" ]] && return 0
  IFS=',' read -r -a deps <<< "${WAIT_FOR}"
  for dep in "${deps[@]}"; do
    [[ -z "$dep" ]] && continue
    local host port
    host="${dep%%:*}"; port="${dep##*:}"
    [[ -z "$host" || -z "$port" ]] && die "Invalid WAIT_FOR endpoint: $dep"
    log "waiting for $host:$port (timeout ${WAIT_FOR_TIMEOUT}s)"
    if ! probe_tcp "$host" "$port" "$WAIT_FOR_TIMEOUT"; then
      die "dependency $host:$port not reachable within ${WAIT_FOR_TIMEOUT}s"
    fi
    log "dependency ready: $host:$port"
  done
}

# -------- hooks --------
run_hook() {
  local name="$1" cmd="$2"
  [[ -z "$cmd" ]] && return 0
  log "running ${name}: $(printf "%q " $cmd | redact)"
  bash -ceu "$cmd"
  log "${name} finished"
}

# -------- privilege drop --------
wrap_privdrop() {
  # returns wrapper command array via echo (used with eval-safe array expansion)
  if [[ -n "${RUN_AS_USER}" && "$(id -u)" -eq 0 ]]; then
    if have su-exec; then
      echo "su-exec ${RUN_AS_USER}:${RUN_AS_GROUP:-$RUN_AS_USER}"
      return 0
    elif have gosu; then
      echo "gosu ${RUN_AS_USER}:${RUN_AS_GROUP:-$RUN_AS_USER}"
      return 0
    else
      warn "su-exec/gosu not found; running as root"
    fi
  fi
  echo ""  # no wrapper
}

# -------- tini wrapper --------
find_tini() {
  if [[ "${USE_TINI}" == "0" ]]; then
    echo ""; return 0
  fi
  if [[ "${USE_TINI}" == "1" || "${USE_TINI}" == "auto" ]]; then
    if have tini; then echo "tini -g --"; return 0; fi
    [[ -x /sbin/tini ]] && { echo "/sbin/tini -g --"; return 0; }
    [[ -x /usr/bin/tini ]] && { echo "/usr/bin/tini -g --"; return 0; }
  fi
  echo ""
}

# -------- main --------
main() {
  log "entrypoint start: $(printf "%q " "$@" | redact)"

  prepare_dirs
  wait_for_all
  run_hook "prestart" "${PRESTART_CMD}"

  if [[ "${RUN_DB_MIGRATIONS}" == "1" ]]; then
    run_hook "migrations" "${MIGRATIONS_CMD}"
  fi

  local tini_wrap priv_wrap
  tini_wrap="$(find_tini)"
  priv_wrap="$(wrap_privdrop)"

  if [[ -n "${HEALTHCHECK_TOUCH}" ]]; then
    mkdir -p "$(dirname "${HEALTHCHECK_TOUCH}")"
    : > "${HEALTHCHECK_TOUCH}" || warn "healthcheck touch failed"
  fi

  # Build final exec line
  if [[ -n "$tini_wrap" && -n "$priv_wrap" ]]; then
    log "exec via tini + ${priv_wrap%% *}"
    exec $tini_wrap $priv_wrap "$@"
  elif [[ -n "$tini_wrap" ]]; then
    log "exec via tini"
    exec $tini_wrap "$@"
  elif [[ -n "$priv_wrap" ]]; then
    log "exec via ${priv_wrap%% *}"
    exec $priv_wrap "$@"
  else
    log "exec app (no wrappers)"
    exec "$@"
  fi
}

main "$@"
