#!/usr/bin/env bash
# Omnimind industrial Docker entrypoint
# shellcheck shell=bash

set -Eeuo pipefail

#######################################
# Logging
#######################################
TS() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
LOG() { printf "%s [ENTRYPOINT] %s\n" "$(TS)" "$*" >&2; }
WARN() { printf "%s [ENTRYPOINT][WARN] %s\n" "$(TS)" "$*" >&2; }
ERR() { printf "%s [ENTRYPOINT][ERROR] %s\n" "$(TS)" "$*" >&2; }
die() { ERR "$*"; exit 1; }

#######################################
# Defaults (overridable via ENV)
#######################################
: "${APP_NAME:=omnimind-core}"
: "${APP_MODULE:=omnimind_core.app:app}"      # для ASGI (uvicorn)
: "${GUNICORN_APP:=omnimind_core.wsgi:app}"   # для WSGI (gunicorn)
: "${SERVER:=uvicorn}"                        # uvicorn|gunicorn|custom
: "${CUSTOM_CMD:=}"                           # например: "python -m omnimind_core.cli serve"
: "${HOST:=0.0.0.0}"
: "${PORT:=8000}"
: "${LOG_LEVEL:=info}"                        # debug|info|warning|error
: "${WORKERS:=}"                              # автодетект, если пусто
: "${GRACEFUL_TIMEOUT:=30}"                   # сек, timeout на graceful shutdown
: "${PRESTART_PATH:=}"                        # скрипт подготовки (bash)
: "${RUN_MIGRATIONS:=false}"                  # true/false
: "${MIGRATIONS_CMD:=}"                       # кастомная команда миграций
: "${WAIT_FOR:=}"                             # CSV список host:port зависимостей
: "${WAIT_TIMEOUT:=60}"                       # общий таймаут ожидания зависимостей
: "${HEALTHCHECK_CMD:=}"                      # произвольная команда до старта (dry check)
: "${ENABLE_TINI:=true}"                      # использовать tini при наличии
: "${UMASK:=0027}"                            # по умолчанию ограниченный доступ
: "${NOFILE:=65536}"                          # ulimit -n
: "${DROP_PRIVILEGES:=true}"                  # понижение привилегий
: "${APP_USER:=app}"                          # пользователь внутри контейнера
: "${APP_GROUP:=app}"                         # группа внутри контейнера
: "${CHOWN_DIRS:=/data}"                      # директории для chown (через запятую)
: "${ENV_FILE:=/app/.env}"                    # путь до .env

#######################################
# Signal handling for PID 1
#######################################
_child_pid=""
on_signal() {
  local sig="$1"
  WARN "Caught signal ${sig}, forwarding to child ${_child_pid:-N/A} and waiting up to ${GRACEFUL_TIMEOUT}s"
  if [[ -n "${_child_pid}" && "${_child_pid}" =~ ^[0-9]+$ ]]; then
    kill -s "${sig}" "${_child_pid}" 2>/dev/null || true
    # ждём graceful
    local waited=0
    while kill -0 "${_child_pid}" 2>/dev/null; do
      sleep 1
      waited=$((waited+1))
      if (( waited >= GRACEFUL_TIMEOUT )); then
        WARN "Graceful timeout exceeded, sending SIGKILL to ${_child_pid}"
        kill -9 "${_child_pid}" 2>/dev/null || true
        break
      fi
    done
  fi
  exit 0
}
trap 'on_signal TERM' TERM
trap 'on_signal INT'  INT
trap 'on_signal HUP'  HUP

#######################################
# Helpers
#######################################
load_env_file() {
  if [[ -f "${ENV_FILE}" ]]; then
    LOG "Loading environment from ${ENV_FILE}"
    # Игнорируем комментарии и пустые строки, поддерживаем KEY=VALUE
    set -o allexport
    # shellcheck disable=SC2046
    source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "${ENV_FILE}" | sed 's/\r$//')
    set +o allexport
  fi
}

calc_workers() {
  if [[ -n "${WORKERS}" ]]; then
    echo "${WORKERS}"
    return
  fi
  local cpu
  cpu=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
  # классическая формула для uvicorn/gunicorn
  echo $(( (cpu * 2) + 1 ))
}

ulimit_setup() {
  umask "${UMASK}" || WARN "Failed to set umask=${UMASK}"
  ulimit -n "${NOFILE}" 2>/dev/null || WARN "Failed to raise NOFILE to ${NOFILE}"
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

wait_for_one() {
  local hostport="$1"
  local host port start_ts now elapsed
  IFS=':' read -r host port <<<"${hostport}"
  [[ -z "${host}" || -z "${port}" ]] && die "WAIT_FOR entry '${hostport}' must be host:port"

  LOG "Waiting for ${host}:${port} up to ${WAIT_TIMEOUT}s..."
  start_ts=$(date +%s)
  while true; do
    if (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
      LOG "Dependency ${host}:${port} is reachable"
      return 0
    fi
    now=$(date +%s)
    elapsed=$((now - start_ts))
    if (( elapsed >= WAIT_TIMEOUT )); then
      die "Timeout waiting for ${host}:${port} after ${WAIT_TIMEOUT}s"
    fi
    sleep 1
  done
}

wait_dependencies() {
  [[ -z "${WAIT_FOR}" ]] && return 0
  IFS=',' read -ra deps <<<"${WAIT_FOR}"
  for d in "${deps[@]}"; do
    wait_for_one "$(echo "$d" | xargs)"
  done
}

prestart() {
  # Предварительный healthcheck до старта (например, локальные миграции, schema check)
  if [[ -n "${HEALTHCHECK_CMD}" ]]; then
    LOG "Running prestart healthcheck: ${HEALTHCHECK_CMD}"
    bash -c "${HEALTHCHECK_CMD}" || die "Healthcheck failed"
  fi

  if [[ -n "${PRESTART_PATH}" ]]; then
    [[ -x "${PRESTART_PATH}" ]] || WARN "PRESTART_PATH=${PRESTART_PATH} is not executable; trying with bash"
    LOG "Running prestart script: ${PRESTART_PATH}"
    bash "${PRESTART_PATH}" || die "Prestart script failed"
  fi
}

migrations() {
  [[ "${RUN_MIGRATIONS}" == "true" ]] || return 0
  if [[ -n "${MIGRATIONS_CMD}" ]]; then
    LOG "Running migrations: ${MIGRATIONS_CMD}"
    bash -c "${MIGRATIONS_CMD}" || die "Migrations failed"
  else
    # Авто-эвристики: alembic/django/psql миграции
    if has_cmd alembic && [[ -f "./alembic.ini" ]]; then
      LOG "Running Alembic migrations"
      alembic upgrade head || die "Alembic migrations failed"
    elif has_cmd python && [[ -f "manage.py" ]]; then
      LOG "Running Django migrations"
      python manage.py migrate --noinput || die "Django migrations failed"
    else
      WARN "RUN_MIGRATIONS=true, but no known migration command found; set MIGRATIONS_CMD"
    fi
  fi
}

ensure_user() {
  [[ "${DROP_PRIVILEGES}" == "true" ]] || return 0

  if [[ "$(id -u)" -ne 0 ]]; then
    LOG "Container not running as root; skipping privilege drop"
    return 0
  fi

  # Создаём пользователя/группу, если их нет
  if ! getent group "${APP_GROUP}" >/dev/null 2>&1; then
    groupadd -r "${APP_GROUP}" >/dev/null 2>&1 || true
  fi
  if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    useradd -r -g "${APP_GROUP}" -d /nonexistent -s /usr/sbin/nologin "${APP_USER}" >/dev/null 2>&1 || true
  fi

  IFS=',' read -ra dirs <<<"${CHOWN_DIRS}"
  for d in "${dirs[@]}"; do
    d="$(echo "$d" | xargs)"
    [[ -z "${d}" ]] && continue
    if [[ -e "${d}" ]]; then
      chown -R "${APP_USER}:${APP_GROUP}" "${d}" 2>/dev/null || WARN "Cannot chown ${d}"
    fi
  done

  # Если tini есть — используем его от non-root
  if [[ "${ENABLE_TINI}" == "true" && -x "/sbin/tini" ]]; then
    export USE_TINI=1
  fi

  # Перезапускаем сам entrypoint под пользователем
  LOG "Dropping privileges to ${APP_USER}:${APP_GROUP}"
  exec gosu "${APP_USER}:${APP_GROUP}" "$0" "$@"
}

build_server_cmd() {
  local workers
  workers="$(calc_workers)"

  case "${SERVER,,}" in
    uvicorn)
      if ! has_cmd uvicorn; then
        die "uvicorn not found, install it or set SERVER=gunicorn/custom"
      fi
      printf "uvicorn %s --host %s --port %s --workers %s --log-level %s --timeout-keep-alive %s" \
        "${APP_MODULE}" "${HOST}" "${PORT}" "${workers}" "${LOG_LEVEL}" "${GRACEFUL_TIMEOUT}"
      ;;
    gunicorn)
      if ! has_cmd gunicorn; then
        die "gunicorn not found, install it or set SERVER=uvicorn/custom"
      fi
      # Для ASGI можно использовать gunicorn с uvicorn.workers.UvicornWorker
      printf "gunicorn %s --bind %s:%s --workers %s --timeout %s --log-level %s --worker-class uvicorn.workers.UvicornWorker" \
        "${GUNICORN_APP}" "${HOST}" "${PORT}" "${workers}" "${GRACEFUL_TIMEOUT}" "${LOG_LEVEL}"
      ;;
    custom)
      [[ -n "${CUSTOM_CMD}" ]] || die "SERVER=custom requires CUSTOM_CMD"
      printf "%s" "${CUSTOM_CMD}"
      ;;
    *)
      die "Unsupported SERVER='${SERVER}'. Use uvicorn|gunicorn|custom"
      ;;
  esac
}

maybe_wrap_tini() {
  if [[ "${ENABLE_TINI}" == "true" && -x "/sbin/tini" ]]; then
    echo "/sbin/tini -g --"
  else
    echo ""
  fi
}

#######################################
# Main
#######################################
main() {
  LOG "Starting ${APP_NAME} entrypoint"
  load_env_file
  ulimit_setup
  ensure_user "$@"

  wait_dependencies
  prestart
  migrations

  local cmd server_cmd tini_prefix
  server_cmd="$(build_server_cmd)"
  tini_prefix="$(maybe_wrap_tini)"

  LOG "Server command: ${server_cmd}"
  if [[ -n "${tini_prefix}" ]]; then
    LOG "Using tini as PID 1"
  fi

  # Запускаем как PID 1: корректная обработка сигналов
  if [[ -n "${tini_prefix}" ]]; then
    # shellcheck disable=SC2086
    ${tini_prefix} bash -lc "${server_cmd}" &
  else
    bash -lc "${server_cmd}" &
  fi

  _child_pid=$!
  LOG "Spawned child process PID=${_child_pid}"

  # Ожидаем завершения дочернего процесса
  wait "${_child_pid}"
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    ERR "Child process exited with code ${rc}"
  else
    LOG "Child process exited cleanly"
  fi
  exit "${rc}"
}

main "$@"
