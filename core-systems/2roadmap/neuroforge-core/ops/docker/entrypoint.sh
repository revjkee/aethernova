#!/usr/bin/env bash
# neuroforge-core/ops/docker/entrypoint.sh
# Надежный entrypoint для контейнера neuroforge-core.

set -Eeuo pipefail
IFS=$'\n\t'

#######################################
# Логирование
#######################################
log()  { printf '%s [%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "${1:-INFO}" "${*:2}"; }
die()  { log ERROR "$*"; exit 1; }

#######################################
# Настройки по умолчанию (можно переопределить через ENV)
#######################################
: "${APP_USER:=app}"
: "${APP_GROUP:=app}"
: "${APP_UID:=10100}"
: "${APP_GID:=10100}"
: "${APP_HOME:=/app}"
: "${APP_DATA_DIR:=/var/lib/neuroforge}"
: "${APP_RUN_DIR:=/var/run/neuroforge}"
: "${APP_LOG_DIR:=/var/log/neuroforge}"
: "${APP_READINESS_TIMEOUT:=60}"          # сек, ожидание зависимостей
: "${APP_HTTP_WAIT:=}"                    # пример: http://localhost:8080/healthz
: "${APP_TCP_WAIT:=}"                     # пример: host:port[,host:port]
: "${APP_AUTO_MIGRATE:=true}"             # выполнять миграции перед стартом
: "${APP_STRICT_ENV:=true}"               # падать, если переменные не заданы
: "${APP_DOTENV_PATH:=/run/secrets/.env}" # безопасная точка для dotenv (если существует)
: "${APP_USE_TINI:=true}"                 # подключить tini, если доступен
: "${APP_DROP_PRIVS:=true}"               # понижать привилегии на запуске
: "${APP_HEALTH_CMD:=}"                   # опциональная команда проверки готовности приложения

# Примеры обязательных переменных (раскомментируйте под свой сервис)
REQUIRED_ENV_VARS=( )
# REQUIRED_ENV_VARS=( "DB_DSN" "SECRET_KEY" )

#######################################
# Подхват .env (безопасно)
#######################################
load_env_file() {
  local f="${1:-$APP_DOTENV_PATH}"
  if [[ -f "$f" ]]; then
    log INFO "Loading dotenv from $f"
    # shellcheck disable=SC1090
    set -a; source "$f"; set +a
  fi
}

#######################################
# Проверка обязательных переменных окружения
#######################################
require_env() {
  [[ "${APP_STRICT_ENV}" != "true" ]] && return 0
  local missing=()
  for v in "${REQUIRED_ENV_VARS[@]}"; do
    if [[ -z "${!v:-}" ]]; then
      missing+=("$v")
    fi
  done
  if ((${#missing[@]} > 0)); then
    die "Missing required env vars: ${missing[*]}"
  fi
}

#######################################
# Ожидание TCP-эндпоинтов: host:port[,host:port]
#######################################
wait_for_tcp() {
  local endpoints="${1:-}"
  [[ -z "$endpoints" ]] && return 0
  local deadline shell_has_timeout=false
  deadline=$((SECONDS + APP_READINESS_TIMEOUT))
  log INFO "Waiting for TCP endpoints: $endpoints (timeout ${APP_READINESS_TIMEOUT}s)"
  IFS=',' read -r -a eps <<< "$endpoints"
  for ep in "${eps[@]}"; do
    local host="${ep%:*}" port="${ep##*:}"
    while ! (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1; do
      if (( SECONDS >= deadline )); then
        die "Timeout waiting for $host:$port"
      fi
      sleep 0.5
    done
    log INFO "TCP ready: $host:$port"
  done
}

#######################################
# Ожидание HTTP healthcheck (2xx/3xx)
#######################################
wait_for_http() {
  local url="${1:-}"
  [[ -z "$url" ]] && return 0
  local deadline=$((SECONDS + APP_READINESS_TIMEOUT))
  log INFO "Waiting for HTTP: $url (timeout ${APP_READINESS_TIMEOUT}s)"
  while true; do
    if curl -fsS -o /dev/null "$url"; then
      log INFO "HTTP ready: $url"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      die "Timeout waiting for $url"
    fi
    sleep 0.5
  done
}

#######################################
# Подготовка пользователей/каталогов для read-only rootfs
#######################################
ensure_user_and_dirs() {
  # Создаём группу/пользователя, если их нет
  if ! getent group  "$APP_GROUP" >/dev/null 2>&1; then
    addgroup --system --gid "$APP_GID" "$APP_GROUP" >/dev/null 2>&1 || groupadd -g "$APP_GID" -r "$APP_GROUP"
  fi
  if ! id -u "$APP_USER" >/dev/null 2>&1; then
    adduser --system --home "$APP_HOME" --uid "$APP_UID" --ingroup "$APP_GROUP" "$APP_USER" >/dev/null 2>&1 \
      || useradd -r -u "$APP_UID" -g "$APP_GID" -d "$APP_HOME" -s /sbin/nologin "$APP_USER"
  fi

  # Каталоги для данных/логов/сокетов
  for d in "$APP_DATA_DIR" "$APP_RUN_DIR" "$APP_LOG_DIR"; do
    mkdir -p "$d"
    chown -R "$APP_UID:$APP_GID" "$d"
    chmod 0750 "$d" || true
  done
}

#######################################
# Понижение привилегий
#######################################
drop_privs_exec() {
  if [[ "${APP_DROP_PRIVS}" != "true" || "$(id -u)" -ne 0 ]]; then
    exec "$@"
  fi
  if command -v gosu >/dev/null 2>&1; then
    exec gosu "$APP_USER:$APP_GROUP" "$@"
  elif command -v su-exec >/dev/null 2>&1; then
    exec su-exec "$APP_USER:$APP_GROUP" "$@"
  else
    # Fallback: chroot-run as user
    exec runuser -u "$APP_USER" -- "$@" 2>/dev/null || exec su -s /bin/sh -c "$*"
  fi
}

#######################################
# Миграции (переопределите под свой фреймворк)
#######################################
run_migrations() {
  if [[ "${APP_AUTO_MIGRATE}" != "true" ]]; then
    log INFO "Auto-migrate disabled"
    return 0
  fi
  if command -v neuroforge-admin >/dev/null 2>&1; then
    log INFO "Running migrations via neuroforge-admin migrate"
    neuroforge-admin migrate
  elif [[ -x "$APP_HOME/manage.py" ]]; then
    log INFO "Running migrations via manage.py"
    python "$APP_HOME/manage.py" migrate --no-input
  else
    log INFO "No migration tool detected; skipping"
  fi
}

#######################################
# tini (PID 1 reaper)
#######################################
maybe_wrap_tini() {
  if [[ "${APP_USE_TINI}" == "true" ]] && command -v /sbin/tini >/dev/null 2>&1; then
    exec /sbin/tini -- "$@"
  elif [[ "${APP_USE_TINI}" == "true" ]] && command -v tini >/dev/null 2>&1; then
    exec tini -- "$@"
  else
    exec "$@"
  fi
}

#######################################
# Основная маршрутизация команд
#######################################
cmd_api() {
  require_env
  wait_for_tcp "$APP_TCP_WAIT"
  wait_for_http "$APP_HTTP_WAIT"
  run_migrations
  # Пример запуска uvicorn/gunicorn — адаптируйте под ваш app
  local host="${APP_HOST:-0.0.0.0}" port="${APP_PORT:-8080}" workers="${APP_WORKERS:-$(nproc)}"
  local bind="${host}:${port}"

  if command -v gunicorn >/dev/null 2>&1; then
    log INFO "Starting gunicorn on ${bind} workers=${workers}"
    drop_privs_exec gunicorn "neuroforge_core.app:app" \
      --bind "$bind" --workers "$workers" --worker-class uvicorn.workers.UvicornWorker \
      --access-logfile '-' --error-logfile '-' --graceful-timeout 30 --timeout 120
  elif command -v uvicorn >/dev/null 2>&1; then
    log INFO "Starting uvicorn on ${bind}"
    drop_privs_exec uvicorn "neuroforge_core.app:app" --host "$host" --port "$port" --workers "$workers"
  else
    die "No ASGI server found (gunicorn/uvicorn)"
  fi
}

cmd_worker() {
  require_env
  wait_for_tcp "$APP_TCP_WAIT"
  run_migrations
  # Пример Celery/Arq/RQ — адаптируйте
  if command -v neuroforge-worker >/dev/null 2>&1; then
    log INFO "Starting neuroforge-worker"
    drop_privs_exec neuroforge-worker
  elif command -v celery >/dev/null 2>&1; then
    log INFO "Starting celery worker"
    drop_privs_exec celery -A neuroforge_core.worker:app worker --loglevel=INFO
  else
    die "No worker command found"
  fi
}

cmd_migrate() {
  require_env
  wait_for_tcp "$APP_TCP_WAIT"
  run_migrations
  log INFO "Migrations finished"
}

cmd_shell() {
  ensure_user_and_dirs
  drop_privs_exec bash -l
}

cmd_exec() {
  shift 1 || true
  [[ $# -gt 0 ]] || die "usage: exec <command...>"
  drop_privs_exec "$@"
}

#######################################
# Bootstrap
#######################################
main() {
  load_env_file
  ensure_user_and_dirs

  case "${1:-api}" in
    api)      maybe_wrap_tini "$0" _api "$@";;
    worker)   maybe_wrap_tini "$0" _worker "$@";;
    migrate)  maybe_wrap_tini "$0" _migrate "$@";;
    shell)    maybe_wrap_tini "$0" _shell "$@";;
    exec)     maybe_wrap_tini "$0" _exec "$@";;
    *)        # если передан исполняемый бинарник — запускаем как есть
              log INFO "Delegating to command: $*"
              maybe_wrap_tini "$@"
              ;;
  esac
}

# Внутренние обёртки для правильного exec/tini
_api()     { shift 1; cmd_api   "$@"; }
_worker()  { shift 1; cmd_worker "$@"; }
_migrate() { shift 1; cmd_migrate "$@"; }
_shell()   { shift 1; cmd_shell  "$@"; }
_exec()    { shift 1; cmd_exec   "$@"; }

main "$@"
