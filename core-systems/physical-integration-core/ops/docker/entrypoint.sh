#!/bin/sh
# path: physical-integration-core/ops/docker/entrypoint.sh
# POSIX‑совместимый, безопасный entrypoint для runtime контейнера.

set -eu

# ------------- Конфиг через ENV (с дефолтами) -------------
APP_USER="${APP_USER:-app}"
APP_GROUP="${APP_GROUP:-app}"
APP_UID="${APP_UID:-10001}"
APP_GID="${APP_GID:-10001}"

APP_HOME="${APP_HOME:-/app}"
APP_DATA_DIR="${APP_DATA_DIR:-/data}"
APP_LOG_DIR="${APP_LOG_DIR:-/var/log/physical-integration-core}"
APP_TMP_DIR="${APP_TMP_DIR:-/tmp/physical-integration-core}"

# Формат "host:port,host2:port2"
WAIT_FOR_TARGETS="${WAIT_FOR_TARGETS:-}"
WAIT_FOR_TIMEOUT="${WAIT_FOR_TIMEOUT:-25}"

# Health‑probe файл (пишется при успешной инициализации и удаляется при стопе)
HEALTH_FILE="${HEALTH_FILE:-/tmp/.healthy}"

# Tini (если присутствует) — надёжный reaper PID1
TINI_BIN="${TINI_BIN:-/sbin/tini}"

# Лог‑уровень: INFO/DEBUG
LOG_LEVEL="${LOG_LEVEL:-INFO}"

# ------------- Утилиты -------------
log() {
  # ts level msg...
  # Пример: log INFO "message" key=value
  ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  lvl="${1:-INFO}"; shift || true
  if [ "${LOG_LEVEL}" != "DEBUG" ] && [ "${lvl}" = "DEBUG" ]; then
    return 0
  fi
  printf '%s %-5s %s\n' "${ts}" "${lvl}" "$*" >&2
}

die() {
  log ERROR "$*"
  exit 1
}

# Проверка наличия бинаря
has() {
  command -v "$1" >/dev/null 2>&1
}

# Ретраи команды: retry <n> <sleep_s> -- cmd args...
retry() {
  n="$1"; shift
  sl="$1"; shift
  i=0
  while :; do
    if "$@"; then
      return 0
    fi
    i=$((i+1))
    if [ "${i}" -ge "${n}" ]; then
      return 1
    fi
    sleep "${sl}"
  done
}

# Ожидание TCP‑сокетов: WAIT_FOR_TARGETS="host:port,host2:port2"
wait_for_targets() {
  [ -z "${WAIT_FOR_TARGETS}" ] && return 0
  IFS=',' 
  set -- ${WAIT_FOR_TARGETS}
  unset IFS
  for target in "$@"; do
    host="$(printf '%s' "${target}" | cut -d: -f1)"
    port="$(printf '%s' "${target}" | cut -d: -f2)"
    [ -z "${host}" ] && die "WAIT_FOR_TARGETS: пустой host в '${target}'"
    [ -z "${port}" ] && die "WAIT_FOR_TARGETS: пустой port в '${target}'"
    log INFO "Ожидание ${host}:${port} (timeout=${WAIT_FOR_TIMEOUT}s)"
    t0="$(date +%s)"
    while :; do
      if (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
        log INFO "Готово: ${host}:${port}"
        break
      fi
      now="$(date +%s)"
      if [ $((now - t0)) -ge "${WAIT_FOR_TIMEOUT}" ]; then
        die "Таймаут ожидания ${host}:${port}"
      fi
      sleep 1
    done
  done
}

# Создание каталогов с корректными правами
ensure_dirs() {
  for d in "${APP_DATA_DIR}" "${APP_LOG_DIR}" "${APP_TMP_DIR}"; do
    [ -d "${d}" ] || mkdir -p "${d}"
  done
  chown -R "${APP_UID}:${APP_GID}" "${APP_DATA_DIR}" "${APP_LOG_DIR}" "${APP_TMP_DIR}" 2>/dev/null || true
}

# Понижение привилегий, если мы root
drop_privs_exec() {
  if [ "$(id -u)" -eq 0 ]; then
    # Создадим пользователя/группу, если их нет
    if ! getent group "${APP_GROUP}" >/dev/null 2>&1; then
      addgroup -g "${APP_GID}" -S "${APP_GROUP}" 2>/dev/null || addgroup -g "${APP_GID}" "${APP_GROUP}" || true
    fi
    if ! getent passwd "${APP_USER}" >/dev/null 2>&1; then
      adduser -S -D -H -s /sbin/nologin -G "${APP_GROUP}" -u "${APP_UID}" "${APP_USER}" 2>/dev/null \
        || useradd -l -M -s /usr/sbin/nologin -g "${APP_GROUP}" -u "${APP_UID}" "${APP_USER}" || true
    fi
    chown -R "${APP_UID}:${APP_GID}" "${APP_HOME}" 2>/dev/null || true

    if has gosu; then
      exec gosu "${APP_USER}:${APP_GROUP}" "$@"
    elif has su-exec; then
      exec su-exec "${APP_USER}:${APP_GROUP}" "$@"
    else
      log WARN "gosu/su-exec не найдены, продолжаю под root"
      exec "$@"
    fi
  else
    exec "$@"
  fi
}

# Graceful‑shutdown: удалим health‑файл
graceful() {
  log INFO "Получен сигнал, завершаю..."
  rm -f "${HEALTH_FILE}" 2>/dev/null || true
  # даём дочернему процессу время
  sleep 0.2
  exit 0
}

trap graceful INT TERM

# ------------- Pre‑hooks -------------
run_pre_hooks() {
  # 1) Скрипт /docker-prestart.sh, если присутствует
  if [ -x "/docker-prestart.sh" ]; then
    log INFO "Запуск /docker-prestart.sh"
    /docker-prestart.sh || die "docker-prestart завершился с ошибкой"
  fi
  # 2) Каталог хуков /docker-prestart.d/*
  if [ -d "/docker-prestart.d" ]; then
    for f in /docker-prestart.d/*; do
      [ -e "$f" ] || continue
      if [ -x "$f" ]; then
        log INFO "Запуск хука: $f"
        "$f" || die "Хук $f завершился с ошибкой"
      else
        log DEBUG "Пропуск неисполняемого файла: $f"
      fi
    done
  fi
}

# ------------- Основные режимы -------------
cmd_help() {
  cat <<'EOF'
Доступные режимы:
  web            — запуск веб‑API (uvicorn/gunicorn, если сконфигурировано)
  worker         — запуск воркера (например, rq/celery/custom)
  migrate        — выполнить миграции БД (alembic/скрипт)
  shell          — интерактивная оболочка (sh)
  eval <cmd...>  — выполнить произвольную команду
  help           — показать это сообщение
Без аргументов выполняется 'web'.
EOF
}

run_web() {
  # По умолчанию: uvicorn physical_integration_core.api:app
  # Можно переопределить через APP_WEB_CMD
  CMD="${APP_WEB_CMD:-uvicorn physical_integration_core.api:app --host 0.0.0.0 --port 8080}"
  log INFO "Старт режима web: ${CMD}"
  touch "${HEALTH_FILE}" 2>/dev/null || true
  # tini, если есть
  if [ -x "${TINI_BIN}" ]; then
    drop_privs_exec "${TINI_BIN}" -- sh -c "${CMD}"
  else
    drop_privs_exec sh -c "${CMD}"
  fi
}

run_worker() {
  # По умолчанию запускаем модуль воркера проекта
  CMD="${APP_WORKER_CMD:-python -m physical_integration_core.workers.default}"
  log INFO "Старт режима worker: ${CMD}"
  touch "${HEALTH_FILE}" 2>/dev/null || true
  if [ -x "${TINI_BIN}" ]; then
    drop_privs_exec "${TINI_BIN}" -- sh -c "${CMD}"
  else
    drop_privs_exec sh -c "${CMD}"
  fi
}

run_migrate() {
  # Алгоритм: выполнить пользовательскую команду миграций или попытаться alembic
  if [ -n "${APP_MIGRATE_CMD:-}" ]; then
    CMD="${APP_MIGRATE_CMD}"
  elif has alembic; then
    CMD="alembic upgrade head"
  else
    die "Не задан APP_MIGRATE_CMD и не найден alembic"
  fi
  log INFO "Выполняю миграции: ${CMD}"
  if [ -x "${TINI_BIN}" ]; then
    drop_privs_exec "${TINI_BIN}" -- sh -c "${CMD}"
  else
    drop_privs_exec sh -c "${CMD}"
  fi
  log INFO "Миграции применены"
}

run_shell() {
  drop_privs_exec sh
}

run_eval() {
  shift 1 || true
  [ $# -gt 0 ] || die "Нужно указать команду для eval"
  log INFO "Выполняю: $*"
  if [ -x "${TINI_BIN}" ]; then
    drop_privs_exec "${TINI_BIN}" -- "$@"
  else
    drop_privs_exec "$@"
  fi
}

# ------------- Main -------------
main() {
  mode="${1:-web}"

  log INFO "Старт entrypoint (mode=${mode})"
  ensure_dirs
  run_pre_hooks

  # Ожидаем внешние зависимости (если заданы)
  wait_for_targets

  case "${mode}" in
    web)
      run_web
      ;;
    worker)
      run_worker
      ;;
    migrate)
      run_migrate
      ;;
    shell)
      run_shell
      ;;
    eval)
      run_eval "$@"
      ;;
    help|-h|--help)
      cmd_help
      ;;
    *)
      # Неизвестный режим — трактуем как явную команду
      log INFO "Неизвестный режим '${mode}', исполняю как команду"
      run_eval "$@"
      ;;
  esac
}

main "$@"
