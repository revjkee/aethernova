#!/usr/bin/env bash
# policy-core :: production entrypoint
# shellcheck shell=bash disable=SC2155

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

# --------- Constants ----------
readonly SCRIPT_NAME="${0##*/}"
readonly WORKDIR="${WORKDIR:-/workspaces/policy-core}"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --------- Logging ----------
log()  { printf '[%s] [INFO]  %s\n'  "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&1; }
warn() { printf '[%s] [WARN]  %s\n'  "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
err()  { printf '[%s] [ERROR] %s\n'  "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { err "$*"; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

# --------- Environment (tunable) ----------
export POLICYCORE_APP_MODULE="${POLICYCORE_APP_MODULE:-policy_core.api:app}"
export POLICYCORE_HOST="${POLICYCORE_HOST:-0.0.0.0}"
export POLICYCORE_PORT="${POLICYCORE_PORT:-8000}"
export POLICYCORE_LOG_LEVEL="${POLICYCORE_LOG_LEVEL:-info}"
export POLICYCORE_RELOAD="${POLICYCORE_RELOAD:-false}"             # dev only
export POLICYCORE_WORKERS="${POLICYCORE_WORKERS:-}"
export POLICYCORE_VENV="${POLICYCORE_VENV:-$WORKDIR/.venv}"
export POLICYCORE_USER="${POLICYCORE_USER:-app}"
export POLICYCORE_UID="${POLICYCORE_UID:-1000}"
export POLICYCORE_GID="${POLICYCORE_GID:-1000}"
export POLICYCORE_PRESTART="${POLICYCORE_PRESTART:-}"               # optional hook script
export POLICYCORE_EXTRA_UVICORN_ARGS="${POLICYCORE_EXTRA_UVICORN_ARGS:-}"  # extra opts

# --------- Helpers ----------
cpu_workers() {
  if [[ -n "${POLICYCORE_WORKERS}" ]]; then
    echo "${POLICYCORE_WORKERS}"
    return
  fi
  if command -v nproc >/dev/null 2>&1; then
    local n="$(nproc)"
    # не более 8 воркеров по умолчанию
    (( n > 8 )) && n=8
    (( n < 1 )) && n=1
    echo "${n}"
  else
    echo 2
  fi
}

activate_venv() {
  if [[ -d "${POLICYCORE_VENV}" ]]; then
    # shellcheck source=/dev/null
    . "${POLICYCORE_VENV}/bin/activate"
    log "Activated venv: ${POLICYCORE_VENV}"
  else
    warn "Virtualenv not found at ${POLICYCORE_VENV} (skipping activation)"
  fi
}

ensure_user() {
  # Создаем системного пользователя при запуске под root
  if [[ "$(id -u)" -ne 0 ]]; then
    return
  fi

  local gid_exists user_exists
  if ! getent group "${POLICYCORE_GID}" >/dev/null 2>&1; then
    groupadd -g "${POLICYCORE_GID}" "${POLICYCORE_USER}" >/dev/null 2>&1 || true
  fi
  if ! id -u "${POLICYCORE_USER}" >/dev/null 2>&1; then
    useradd -m -u "${POLICYCORE_UID}" -g "${POLICYCORE_GID}" -s /bin/bash "${POLICYCORE_USER}" >/dev/null 2>&1 || true
  fi

  mkdir -p "${WORKDIR}"
  chown -R "${POLICYCORE_UID}:${POLICYCORE_GID}" "${WORKDIR}" || true
}

# Выполнение команды от имени непривилегированного пользователя, если сейчас root
exec_as_app() {
  if [[ "$(id -u)" -ne 0 ]]; then
    exec "$@"
    return
  fi

  if command -v gosu >/dev/null 2>&1; then
    exec gosu "${POLICYCORE_UID}:${POLICYCORE_GID}" "$@"
  elif command -v su-exec >/dev/null 2>&1; then
    exec su-exec "${POLICYCORE_UID}:${POLICYCORE_GID}" "$@"
  elif command -v runuser >/dev/null 2>&1; then
    exec runuser -u "${POLICYCORE_USER}" -- "$@"
  else
    warn "Neither gosu/su-exec/runuser found; continuing as root"
    exec "$@"
  fi
}

prestart_hook() {
  if [[ -n "${POLICYCORE_PRESTART}" ]]; then
    if [[ -x "${POLICYCORE_PRESTART}" ]]; then
      log "Running prestart hook: ${POLICYCORE_PRESTART}"
      "${POLICYCORE_PRESTART}"
    elif [[ -f "${POLICYCORE_PRESTART}" ]]; then
      log "Sourcing prestart script: ${POLICYCORE_PRESTART}"
      # shellcheck source=/dev/null
      . "${POLICYCORE_PRESTART}"
    else
      warn "Prestart hook not found or not executable: ${POLICYCORE_PRESTART}"
    fi
  fi
}

# --------- Signal handling (for non-exec runs) ----------
forward_signals() {
  # Если запущено "в фоне", форвардим сигналы дочернему процессу
  local pid="$1"
  trap "kill -TERM ${pid} 2>/dev/null || true" TERM
  trap "kill -INT  ${pid} 2>/dev/null || true" INT
}

# --------- Main modes ----------
serve_api() {
  need_cmd python
  need_cmd bash
  activate_venv

  if ! python -c "import uvicorn" 2>/dev/null; then
    die "uvicorn is not installed in the environment. Install web extras or ensure dependency availability."
  fi

  local workers
  workers="$(cpu_workers)"

  local reload_flag=()
  [[ "${POLICYCORE_RELOAD}" == "true" ]] && reload_flag=(--reload)

  prestart_hook

  local cmd=(uvicorn "${POLICYCORE_APP_MODULE}" --host "${POLICYCORE_HOST}" --port "${POLICYCORE_PORT}" --log-level "${POLICYCORE_LOG_LEVEL}" --proxy-headers --workers "${workers}")
  if [[ -n "${POLICYCORE_EXTRA_UVICORN_ARGS}" ]]; then
    # shellcheck disable=SC2206
    cmd+=(${POLICYCORE_EXTRA_UVICORN_ARGS})
  fi
  cmd+=("${reload_flag[@]}")

  log "Starting API: ${cmd[*]}"
  exec_as_app "${cmd[@]}"
}

run_cli() {
  activate_venv
  if ! command -v policyctl >/dev/null 2>&1; then
    die "policyctl entry point not found. Ensure project is installed with console script."
  fi
  exec_as_app policyctl "$@"
}

run_pytest() {
  activate_venv
  if ! command -v pytest >/dev/null 2>&1; then
    die "pytest not found in environment."
  fi
  prestart_hook
  exec_as_app pytest -q "$@"
}

run_worker() {
  activate_venv
  if ! command -v policyctl >/dev/null 2>&1; then
    die "policyctl entry point not found for worker mode."
  fi
  prestart_hook
  exec_as_app policyctl worker "$@"
}

# --------- Bootstrap ----------
cd "${WORKDIR}" 2>/dev/null || true
ensure_user

mode="${1:-serve}"
case "${mode}" in
  serve|api)
    shift || true
    # если переданы дополнительные аргументы, присоединим их к uvicorn
    [[ $# -gt 0 ]] && export POLICYCORE_EXTRA_UVICORN_ARGS="${POLICYCORE_EXTRA_UVICORN_ARGS} $*"
    serve_api
    ;;
  cli)
    shift || true
    run_cli "$@"
    ;;
  test|pytest)
    shift || true
    run_pytest "$@"
    ;;
  worker)
    shift || true
    run_worker "$@"
    ;;
  exec)
    shift || true
    activate_venv
    prestart_hook
    exec_as_app "${@:-/bin/bash}"
    ;;
  bash|sh)
    shift || true
    activate_venv
    exec_as_app "${mode}" "$@"
    ;;
  -*)
    # Переданы только опции uvicorn
    export POLICYCORE_EXTRA_UVICORN_ARGS="${POLICYCORE_EXTRA_UVICORN_ARGS} $*"
    serve_api
    ;;
  *)
    # Любая произвольная команда
    shift || true
    activate_venv
    exec_as_app "${mode}" "$@"
    ;;
esac
