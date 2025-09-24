#!/usr/bin/env bash
# Industrial entrypoint for core-systems/security-core
# Safe by default: strict shell, least privilege, soft-fail for optional tools.

set -Eeuo pipefail

############################
# Defaults and environment #
############################

APP_NAME="${APP_NAME:-security-core}"
APP_USER="${APP_USER:-app}"
APP_GROUP="${APP_GROUP:-app}"
APP_UID="${APP_UID:-10001}"
APP_GID="${APP_GID:-10001}"

APP_HOME="${APP_HOME:-/app}"
APP_WORKDIR="${APP_WORKDIR:-$APP_HOME}"
APP_LOG_DIR="${APP_LOG_DIR:-/var/log/$APP_NAME}"
APP_DATA_DIR="${APP_DATA_DIR:-/var/lib/$APP_NAME}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/$APP_NAME}"
HEALTHCHECK_FILE="${HEALTHCHECK_FILE:-/healthz}"
UMASK_VALUE="${UMASK_VALUE:-027}"
TZ="${TZ:-}"

# Execution modes: web | worker | migrate | task | auto
APP_MODE="${APP_MODE:-auto}"

# Network waits: comma-separated host:port entries
WAIT_FOR="${WAIT_FOR:-}"

# Directories to chown (space-separated)
CHOWN_DIRS_DEFAULT="$APP_HOME $APP_WORKDIR $APP_LOG_DIR $APP_DATA_DIR $RUNTIME_DIR"
CHOWN_DIRS="${CHOWN_DIRS:-$CHOWN_DIRS_DEFAULT}"

# Hooks
HOOKS_PRE_DIR="${HOOKS_PRE_DIR:-/docker-entrypoint.d/pre.d}"
HOOKS_POST_DIR="${HOOKS_POST_DIR:-/docker-entrypoint.d/post.d}"

# Low ports capability
SETCAP_NETBIND="${SETCAP_NETBIND:-false}"
SETCAP_TARGET="${SETCAP_TARGET:-}"

# TLS trust
EXTRA_CA_DIR="${EXTRA_CA_DIR:-/usr/local/share/ca-certificates}"

# Health update interval (seconds). If 0, one-shot touch.
HEALTH_INTERVAL="${HEALTH_INTERVAL:-0}"

# Python defaults (soft)
PY_APP_MODULE="${PY_APP_MODULE:-security_core.app:app}"   # for uvicorn/gunicorn
PY_WORKER_APP="${PY_WORKER_APP:-security_core.worker}"     # for celery or custom
PY_MIGRATE_CMD="${PY_MIGRATE_CMD:-alembic upgrade head}"   # if alembic present

################################
# Utils: log, warn, error, die #
################################
log()  { printf '[%s] %s\n' "$APP_NAME" "$*"; }
warn() { printf '[%s][warn] %s\n' "$APP_NAME" "$*" >&2; }
err()  { printf '[%s][error] %s\n' "$APP_NAME" "$*" >&2; }
die()  { err "$*"; exit 1; }

########################################
# file_env: load VAR or VAR_FILE safely #
########################################
file_env() {
  # usage: file_env VAR [DEFAULT]
  local var="$1"
  local fileVar="${var}_FILE"
  local def="${2:-}"
  if [ "${!var:-}" ] && [ "${!fileVar:-}" ]; then
    die "Both $var and $fileVar are set. Only one is allowed."
  fi
  local val="$def"
  if [ "${!var:-}" ]; then
    val="${!var}"
  elif [ "${!fileVar:-}" ]; then
    val="$(< "${!fileVar}")"
  fi
  export "$var"="$val"
  unset "$fileVar"
}

##############################
# Minimal command existence  #
##############################
have() { command -v "$1" >/dev/null 2>&1; }

##############################
# User and permissions setup #
##############################
create_group_if_missing() {
  local group="$1" gid="$2"
  if getent group "$group" >/dev/null 2>&1; then
    return 0
  fi
  if have addgroup; then
    addgroup -g "$gid" "$group" >/dev/null 2>&1 || addgroup "$group" >/dev/null 2>&1 || true
  elif have groupadd; then
    groupadd -g "$gid" -o "$group" >/dev/null 2>&1 || groupadd "$group" >/dev/null 2>&1 || true
  else
    warn "No groupadd/addgroup; skipping group creation."
  fi
}

create_user_if_missing() {
  local user="$1" uid="$2" group="$3"
  if id -u "$user" >/dev/null 2>&1; then
    return 0
  fi
  if have adduser; then
    adduser -D -H -G "$group" -u "$uid" "$user" >/dev/null 2>&1 || true
  elif have useradd; then
    useradd -M -N -s /usr/sbin/nologin -u "$uid" -g "$group" "$user" >/dev/null 2>&1 || true
  else
    warn "No useradd/adduser; skipping user creation."
  fi
}

ensure_user() {
  # Create or reconcile UID/GID
  create_group_if_missing "$APP_GROUP" "$APP_GID"
  create_user_if_missing "$APP_USER" "$APP_UID" "$APP_GROUP"
  # Try to adjust uid/gid if mismatch
  if [ "$(id -g "$APP_USER" 2>/dev/null || echo)" != "$APP_GID" ] && have usermod; then
    usermod -g "$APP_GID" "$APP_USER" || warn "Failed to update primary group for $APP_USER"
  fi
  if [ "$(id -u "$APP_USER" 2>/dev/null || echo)" != "$APP_UID" ] && have usermod; then
    usermod -u "$APP_UID" "$APP_USER" || warn "Failed to set UID for $APP_USER"
  fi
}

chown_dirs() {
  for d in $CHOWN_DIRS; do
    mkdir -p "$d" || true
    chown -R "$APP_UID:$APP_GID" "$d" || warn "chown failed for $d"
    chmod -R u=rwX,g=rX,o= "$d" || true
  done
}

############################
# Hooks and pre-run stages #
############################
run_hooks() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  # shellcheck disable=SC2045
  for f in $(ls -1 "$dir"/*.sh 2>/dev/null || true); do
    [ -f "$f" ] || continue
    log "Running hook: $f"
    # shellcheck disable=SC1090
    . "$f"
  done
}

#############################
# Wait for TCP dependencies #
#############################
wait_for() {
  # WAIT_FOR="host1:5432,host2:6379"
  local list="$1"
  [ -n "$list" ] || return 0
  IFS=',' read -r -a items <<< "$list"
  for item in "${items[@]}"; do
    local host="${item%%:*}"
    local port="${item##*:}"
    log "Waiting for $host:$port"
    for i in $(seq 1 60); do
      if (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
        log "$host:$port is ready"
        break
      fi
      sleep 1
      [ "$i" -eq 60 ] && die "Timeout waiting for $host:$port"
    done
  done
}

#########################
# Healthcheck handling  #
#########################
start_health_updater() {
  local interval="$1"
  [ "$interval" -gt 0 ] || { : > "$HEALTHCHECK_FILE" 2>/dev/null || true; return 0; }
  ( while true; do date +%s > "$HEALTHCHECK_FILE" 2>/dev/null || true; sleep "$interval"; done ) &
}

#########################
# CA trust augmentation #
#########################
update_ca_trust() {
  if [ -d "$EXTRA_CA_DIR" ] && ls -1 "$EXTRA_CA_DIR"/*.crt >/dev/null 2>&1; then
    if have update-ca-certificates; then
      update-ca-certificates >/dev/null 2>&1 || warn "update-ca-certificates failed"
    elif have trust; then
      for c in "$EXTRA_CA_DIR"/*.crt; do trust anchor "$c" >/dev/null 2>&1 || true; done
    else
      warn "No CA update tool available; skipping extra CAs"
    fi
  fi
}

#########################
# Capabilities handling #
#########################
maybe_setcap() {
  [ "$SETCAP_NETBIND" = "true" ] || return 0
  [ -n "$SETCAP_TARGET" ] || { warn "SETCAP_NETBIND=true but SETCAP_TARGET is empty"; return 0; }
  if have setcap; then
    setcap 'cap_net_bind_service=+ep' "$SETCAP_TARGET" || warn "setcap failed for $SETCAP_TARGET"
  else
    warn "setcap not found; cannot allow low ports"
  fi
}

#########################
# Timezone and umask    #
#########################
apply_tz_umask() {
  umask "$UMASK_VALUE" || warn "umask set failed"
  if [ -n "$TZ" ]; then
    if [ -f "/usr/share/zoneinfo/$TZ" ]; then
      ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime && echo "$TZ" > /etc/timezone || warn "TZ apply failed"
    else
      warn "TZ '$TZ' not found in /usr/share/zoneinfo"
    fi
  fi
}

#######################################
# Privilege drop with multiple fallbacks
#######################################
drop_privs_exec() {
  local user="$1"; shift
  if [ "$(id -u)" -ne 0 ]; then
    exec "$@"
  fi
  if have gosu; then
    exec gosu "$user" "$@"
  elif have su-exec; then
    exec su-exec "$user" "$@"
  elif have runuser; then
    exec runuser -u "$user" -- "$@"
  else
    exec su -s /bin/sh -c "$*"
  fi
}

#########################
# Migration helpers     #
#########################
run_migrations_soft() {
  # Try alembic first, then python module
  if have alembic; then
    log "Running migrations via alembic"
    alembic upgrade head || warn "alembic failed"
    return 0
  fi
  if have python; then
    if python -c "import ${PY_WORKER_APP%.*}" >/dev/null 2>&1; then
      log "Running python migrate module (best-effort)"
      python -m "${PY_WORKER_APP%.*}.migrate" || warn "python migrate failed"
    else
      warn "No migration module found"
    fi
  fi
}

#########################
# Command resolvers     #
#########################
resolve_web_cmd() {
  # prefer gunicorn, fallback to uvicorn
  if have gunicorn; then
    echo "gunicorn -b 0.0.0.0:${PORT:-8080} --workers ${WEB_CONCURRENCY:-2} --timeout ${WEB_TIMEOUT:-60} ${PY_APP_MODULE}"
    return
  fi
  if have uvicorn; then
    echo "uvicorn ${PY_APP_MODULE} --host 0.0.0.0 --port ${PORT:-8080} --workers ${WEB_CONCURRENCY:-2}"
    return
  fi
  # last resort: python -m
  if have python; then
    echo "python -m ${PY_APP_MODULE%%:*}"
    return
  fi
  die "No web runner found (gunicorn/uvicorn/python)"
}

resolve_worker_cmd() {
  # prefer celery
  if have celery; then
    echo "celery -A ${PY_WORKER_APP} worker --loglevel=${CELERY_LOGLEVEL:-INFO} --concurrency=${CELERY_CONCURRENCY:-2}"
    return
  fi
  if have python; then
    echo "python -m ${PY_WORKER_APP}"
    return
  fi
  die "No worker runner found (celery/python)"
}

#########################
# Main                  #
#########################
main() {
  # Load secrets via *_FILE
  for v in DB_URL API_TOKEN SENTRY_DSN REDIS_URL; do file_env "$v" || true; done

  apply_tz_umask
  update_ca_trust
  maybe_setcap

  # Prepare filesystem and user
  if [ "$(id -u)" -eq 0 ]; then
    ensure_user
    chown_dirs
    mkdir -p "$(dirname "$HEALTHCHECK_FILE")" || true
    : > "$HEALTHCHECK_FILE" 2>/dev/null || true
  fi

  run_hooks "$HOOKS_PRE_DIR"

  # Wait for dependencies
  [ -n "$WAIT_FOR" ] && wait_for "$WAIT_FOR"

  # Migrations if requested
  if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
    run_migrations_soft
  fi

  start_health_updater "${HEALTH_INTERVAL:-0}"

  # Determine command
  local cmd=()
  if [ "$#" -gt 0 ]; then
    cmd=( "$@" )
  else
    case "$APP_MODE" in
      web|auto)
        cmd=( bash -lc "$(resolve_web_cmd)" )
        ;;
      worker)
        cmd=( bash -lc "$(resolve_worker_cmd)" )
        ;;
      migrate)
        cmd=( bash -lc "run_migrations_soft" )
        ;;
      task)
        # one-shot user-defined task (e.g., APP_TASK_CMD="python -m ...")
        [ -n "${APP_TASK_CMD:-}" ] || die "APP_TASK_CMD is empty for APP_MODE=task"
        cmd=( bash -lc "${APP_TASK_CMD}" )
        ;;
      *)
        die "Unknown APP_MODE: $APP_MODE"
        ;;
    esac
  fi

  log "Starting: ${cmd[*]}"
  # Drop privileges and exec
  drop_privs_exec "$APP_USER" "${cmd[@]}"
}

main "$@"
