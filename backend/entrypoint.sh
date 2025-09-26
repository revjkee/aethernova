#!/usr/bin/env bash
# backend/entrypoint.sh
#
# Промышленная обертка для контейнера backend:
# - Безопасные флаги bash: немедленный выход на ошибках
# - Ожидание зависимостей: PostgreSQL, Redis, RabbitMQ (опционально)
# - Prestart hook: scripts/prestart.sh (если существует и исполняемый)
# - Миграции БД через Alembic (включаются флагом)
# - Запуск API (gunicorn с uvicorn worker) или uvicorn в DEV
# - Запуск фоновых воркеров/планировщиков (пример на Celery — опционально)
# - Корректное завершение по сигналам SIGTERM/SIGINT
#
# Требуемые/опциональные переменные окружения (с дефолтами):
#   APP_MODULE="app.main:app"     # путь к ASGI приложению
#   HOST="0.0.0.0"
#   PORT="8000"
#   WORKERS="2"                   # кол-во воркеров gunicorn
#   LOG_LEVEL="info"              # debug|info|warning|error|critical
#   DEV_MODE="0"                  # 1 => uvicorn --reload
#   RUN_DB_MIGRATIONS="1"         # 1 => alembic upgrade head при запуске API
#   WAIT_FOR_DB="1"               # ждать ли БД (Postgres)
#   DB_HOST, DB_PORT              # например: DB_HOST=postgres, DB_PORT=5432
#   WAIT_FOR_REDIS="0"            # ждать ли Redis
#   REDIS_HOST, REDIS_PORT
#   WAIT_FOR_RABBIT="0"           # ждать ли RabbitMQ
#   RABBIT_HOST, RABBIT_PORT
#   ALEMBIC_CONFIG="alembic.ini"  # путь к ini
#   CELERY_APP="app.worker:celery_app"  # модуль Celery (если используется)
#   CELERY_CONCURRENCY="1"
#   PRESTART_HOOK="scripts/prestart.sh" # путь к хук-скрипту
#
# Примеры:
#   ./entrypoint.sh api
#   ./entrypoint.sh migrate
#   ./entrypoint.sh worker
#   ./entrypoint.sh scheduler
#   ./entrypoint.sh healthcheck

set -Eeuo pipefail

#####################################
# Логи и сигналы
#####################################
log()  { printf '%s [%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "${1}" "${*:2}"; }
info() { log "INFO" "$@"; }
warn() { log "WARN" "$@"; }
err()  { log "ERROR" "$@" >&2; }

child_pid=""

graceful_shutdown() {
  warn "Получен сигнал. Корректное завершение (PID=${child_pid:-none})..."
  if [[ -n "${child_pid}" ]] && ps -p "${child_pid}" >/dev/null 2>&1; then
    kill -TERM "${child_pid}" || true
    # Даем времени завершиться дочерним процессам:
    for i in {1..30}; do
      if ! ps -p "${child_pid}" >/dev/null 2>&1; then
        info "Дочерний процесс завершен."
        break
      fi
      sleep 1
    done
    # Форс, если не завершился:
    if ps -p "${child_pid}" >/dev/null 2>&1; then
      warn "Форс-завершение дочернего процесса..."
      kill -KILL "${child_pid}" || true
    fi
  fi
  exit 0
}

trap graceful_shutdown SIGINT SIGTERM

#####################################
# Конфигурация по умолчанию
#####################################
APP_MODULE="${APP_MODULE:-app.main:app}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
WORKERS="${WORKERS:-2}"
LOG_LEVEL="${LOG_LEVEL:-info}"
DEV_MODE="${DEV_MODE:-0}"

RUN_DB_MIGRATIONS="${RUN_DB_MIGRATIONS:-1}"
WAIT_FOR_DB="${WAIT_FOR_DB:-1}"
DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"

WAIT_FOR_REDIS="${WAIT_FOR_REDIS:-0}"
REDIS_HOST="${REDIS_HOST:-redis}"
REDIS_PORT="${REDIS_PORT:-6379}"

WAIT_FOR_RABBIT="${WAIT_FOR_RABBIT:-0}"
RABBIT_HOST="${RABBIT_HOST:-rabbitmq}"
RABBIT_PORT="${RABBIT_PORT:-5672}"

ALEMBIC_CONFIG="${ALEMBIC_CONFIG:-alembic.ini}"

CELERY_APP="${CELERY_APP:-app.worker:celery_app}"
CELERY_CONCURRENCY="${CELERY_CONCURRENCY:-1}"

PRESTART_HOOK="${PRESTART_HOOK:-scripts/prestart.sh}"

#####################################
# Утилиты
#####################################
have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Ожидание TCP-порта (nc или bash /dev/tcp)
wait_for_host_port() {
  local host="$1"
  local port="$2"
  local timeout="${3:-60}"
  local start_ts
  start_ts=$(date +%s)

  info "Ожидание ${host}:${port} (таймаут ${timeout}s)..."
  while true; do
    if have_cmd nc; then
      if nc -z "${host}" "${port}" >/dev/null 2>&1; then
        info "Доступен ${host}:${port}"
        return 0
      fi
    else
      # fallback через bash tcp
      if (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
        info "Доступен ${host}:${port}"
        return 0
      fi
    fi
    sleep 1
    local now_ts
    now_ts=$(date +%s)
    if (( now_ts - start_ts >= timeout )); then
      err "Таймаут ожидания ${host}:${port} (${timeout}s)."
      return 1
    fi
  done
}

wait_dependencies() {
  local timeout="${1:-90}"

  if [[ "${WAIT_FOR_DB}" == "1" ]]; then
    wait_for_host_port "${DB_HOST}" "${DB_PORT}" "${timeout}"
  fi

  if [[ "${WAIT_FOR_REDIS}" == "1" ]]; then
    wait_for_host_port "${REDIS_HOST}" "${REDIS_PORT}" "${timeout}"
  fi

  if [[ "${WAIT_FOR_RABBIT}" == "1" ]]; then
    wait_for_host_port "${RABBIT_HOST}" "${RABBIT_PORT}" "${timeout}"
  fi
}

run_prestart_hook() {
  if [[ -f "${PRESTART_HOOK}" ]]; then
    if [[ -x "${PRESTART_HOOK}" ]]; then
      info "Выполняю prestart hook: ${PRESTART_HOOK}"
      "${PRESTART_HOOK}"
    else
      warn "Prestart hook найден, но не исполняемый. Запуск через интерпретатор bash."
      bash "${PRESTART_HOOK}"
    fi
  else
    info "Prestart hook не найден (${PRESTART_HOOK}), пропускаю."
  fi
}

alembic_upgrade() {
  if [[ -f "${ALEMBIC_CONFIG}" ]]; then
    info "Выполняю миграции: alembic upgrade head"
    alembic -c "${ALEMBIC_CONFIG}" upgrade head
  else
    warn "Файл Alembic не найден (${ALEMBIC_CONFIG}). Пропускаю миграции."
  fi
}

#####################################
# Команды запуска
#####################################
cmd_api() {
  wait_dependencies "120"
  run_prestart_hook
  if [[ "${RUN_DB_MIGRATIONS}" == "1" ]]; then
    alembic_upgrade
  fi

  if [[ "${DEV_MODE}" == "1" ]]; then
    info "DEV_MODE=1 — запускаю uvicorn с авто-перезагрузкой."
    uvicorn "${APP_MODULE}" --host "${HOST}" --port "${PORT}" --log-level "${LOG_LEVEL}" --reload &
    child_pid=$!
  else
    info "Запускаю gunicorn (uvicorn workers)."
    # Примечание: при необходимости добавьте --graceful-timeout/--timeout по вашим SLO/SLA.
    gunicorn "${APP_MODULE}" \
      --worker-class uvicorn.workers.UvicornWorker \
      --bind "${HOST}:${PORT}" \
      --workers "${WORKERS}" \
      --log-level "${LOG_LEVEL}" \
      --access-logfile "-" \
      --error-logfile "-" &
    child_pid=$!
  fi

  wait "${child_pid}"
}

cmd_migrate() {
  wait_dependencies "120"
  alembic_upgrade
}

cmd_worker() {
  wait_dependencies "120"
  run_prestart_hook

  if ! have_cmd celery; then
    err "Celery не установлен, команда worker недоступна."
    exit 1
  fi

  info "Запускаю Celery worker (app=${CELERY_APP}, concurrency=${CELERY_CONCURRENCY})"
  celery -A "${CELERY_APP}" worker \
    --concurrency "${CELERY_CONCURRENCY}" \
    --loglevel "${LOG_LEVEL}" &
  child_pid=$!
  wait "${child_pid}"
}

cmd_scheduler() {
  wait_dependencies "120"
  run_prestart_hook

  if ! have_cmd celery; then
    err "Celery не установлен, команда scheduler недоступна."
    exit 1
  fi

  info "Запускаю Celery beat (app=${CELERY_APP})"
  celery -A "${CELERY_APP}" beat --loglevel "${LOG_LEVEL}" &
  child_pid=$!
  wait "${child_pid}"
}

cmd_healthcheck() {
  # Простой healthcheck: наличие процесса python/gunicorn не проверяем — скрипт вызывается самостоятельной командой.
  # Здесь можно дополнить проверку доступности зависимостей/миграций/версий.
  info "HEALTHCHECK OK"
}

cmd_shell() {
  info "Открываю интерактивную оболочку bash."
  exec bash
}

#####################################
# Разбор аргумента
#####################################
main() {
  local cmd="${1:-api}"

  case "${cmd}" in
    api)
      cmd_api
      ;;
    migrate|migration|migrations)
      cmd_migrate
      ;;
    worker)
      cmd_worker
      ;;
    scheduler|beat)
      cmd_scheduler
      ;;
    healthcheck)
      cmd_healthcheck
      ;;
    shell)
      cmd_shell
      ;;
    *)
      err "Неизвестная команда: ${cmd}
Доступные команды: api | migrate | worker | scheduler | healthcheck | shell"
      exit 2
      ;;
  esac
}

main "$@"
