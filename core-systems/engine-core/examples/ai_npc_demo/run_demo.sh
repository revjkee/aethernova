#!/usr/bin/env bash
# engine/examples/ai_npc_demo/run_demo.sh
# Промышленный запуск демо AI NPC: инфраструктура, здоровье, нагрузка, профили, логи.

set -Eeuo pipefail

# ---------------------------
# Логирование и утилиты
# ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." >/dev/null 2>&1 && pwd)"
cd "${REPO_ROOT}"

_red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
_green() { printf '\033[32m%s\033[0m\n' "$*"; }
_yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
_blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

log() { _blue "[demo] $*"; }
warn(){ _yellow "[demo] $*"; }
err() { _red "[demo] $*"; }
die() { err "$*"; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Не найдено: $1"; }

on_exit() {
  local ec=$?
  if [[ "${AUTO_DOWN:-0}" == "1" ]]; then
    # Мягкая остановка инфраструктуры, если запускали автоматически
    _stop_redis || true
  fi
  exit "$ec"
}
trap on_exit EXIT

# ---------------------------
# Загрузка .env (если есть)
# ---------------------------
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "${SCRIPT_DIR}/.env" | sed 's/#.*//g' | xargs -I{} echo {})
fi

# ---------------------------
# Конфигурация по умолчанию (переопределяйте через ENV/.env)
# ---------------------------
ENGINE_LOG_LEVEL="${ENGINE_LOG_LEVEL:-INFO}"
ENGINE_LOG_FORMAT="${ENGINE_LOG_FORMAT:-text}"

PYTHON_BIN="${PYTHON_BIN:-python3}"
PY_MIN_MAJOR="${PY_MIN_MAJOR:-3}"
PY_MIN_MINOR="${PY_MIN_MINOR:-10}"
VENV_DIR="${VENV_DIR:-${REPO_ROOT}/.venv}"
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-}"

USE_DOCKER_REDIS="${USE_DOCKER_REDIS:-1}"       # 1=использовать docker redis при наличии
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
REDIS_NAME="${REDIS_NAME:-ai-npc-demo-redis}"
REDIS_PORT="${REDIS_PORT:-6379}"

# Переменные для модулей движка
export ENGINE_VERSION="${ENGINE_VERSION:-0.1.0}"
export ENGINE_BUILD="${ENGINE_BUILD:-demo}"

# Конфиг кэша (совместим с CacheConfig.from_env("CACHE"))
export CACHE_REDIS_URL="${CACHE_REDIS_URL:-redis://127.0.0.1:${REDIS_PORT}/0}"
export CACHE_TAGS="${CACHE_TAGS:-1}"
export CACHE_VER="${CACHE_VER:-1}"

# Конфиг профилирования
export ENGINE_PROFILING="${ENGINE_PROFILING:-1}"
export ENGINE_PROFILE_DIR="${ENGINE_PROFILE_DIR:-${REPO_ROOT}/telemetry/profiles}"

# Конфиг генератора нагрузки (совместим с LoadGenConfig.from_env)
export LOADGEN_NAME="${LOADGEN_NAME:-ai-npc}"
export LOADGEN_DURATION="${LOADGEN_DURATION:-15}"
export LOADGEN_WARMUP="${LOADGEN_WARMUP:-2}"
export LOADGEN_RPS="${LOADGEN_RPS:-50}"
export LOADGEN_MODEL="${LOADGEN_MODEL:-open}"
export LOADGEN_SINK="${LOADGEN_SINK:-memory}"         # memory|http|ws
export LOADGEN_ENDPOINT="${LOADGEN_ENDPOINT:-}"        # требуется для http/ws
export LOADGEN_EXPORT_JSON="${LOADGEN_EXPORT_JSON:-${REPO_ROOT}/telemetry/reports/ai_npc_load.json}"
export LOADGEN_TAG="${LOADGEN_TAG:-npc}"

# ---------------------------
# Проверки окружения
# ---------------------------
_check_python() {
  need_cmd "${PYTHON_BIN}"
  local ver
  ver="$("${PYTHON_BIN}" -c 'import sys;print(".".join(map(str,sys.version_info[:3])))')"
  local major minor
  major="$(echo "${ver}" | cut -d. -f1)"
  minor="$(echo "${ver}" | cut -d. -f2)"
  if (( major < PY_MIN_MAJOR || (major == PY_MIN_MAJOR && minor < PY_MIN_MINOR) )); then
    die "Требуется Python >= ${PY_MIN_MAJOR}.${PY_MIN_MINOR}, найдено ${ver}"
  fi
  _green "Python ${ver} ок"
}

_ensure_venv() {
  if [[ ! -d "${VENV_DIR}" ]]; then
    log "Создаю виртуальное окружение: ${VENV_DIR}"
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  fi
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  pip install --upgrade pip >/dev/null
  # Локальная установка пакета (editable), если pyproject.toml/setup.* присутствуют
  if [[ -f "${REPO_ROOT}/pyproject.toml" || -f "${REPO_ROOT}/setup.py" ]]; then
    log "Устанавливаю текущий пакет (editable)"
    pip install -e ".[dev]" >/dev/null || pip install -e . >/dev/null
  fi
  if [[ -n "${REQUIREMENTS_FILE}" && -f "${REQUIREMENTS_FILE}" ]]; then
    log "Устанавливаю зависимости из ${REQUIREMENTS_FILE}"
    pip install -r "${REQUIREMENTS_FILE}" >/dev/null
  fi
}

_wait_port() {
  local host="${1:-127.0.0.1}" port="${2:?port}" timeout="${3:-10}"
  local start
  start="$(date +%s)"
  while :; do
    if (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    if (( $(date +%s) - start > timeout )); then
      return 1
    fi
    sleep 0.2
  done
}

# ---------------------------
# Redis через Docker (опционально)
# ---------------------------
_start_redis() {
  if [[ "${USE_DOCKER_REDIS}" != "1" ]]; then
    warn "USE_DOCKER_REDIS=0 — пропускаю запуск Redis"
    return 0
  fi
  if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' | grep -q "^${REDIS_NAME}\$"; then
      log "Redis контейнер уже запущен (${REDIS_NAME})"
    else
      log "Запускаю Redis: ${REDIS_IMAGE} на порту ${REDIS_PORT} (имя ${REDIS_NAME})"
      docker run -d --rm --name "${REDIS_NAME}" -p "${REDIS_PORT}:6379" "${REDIS_IMAGE}" >/dev/null
    fi
    if _wait_port "127.0.0.1" "${REDIS_PORT}" 10; then
      _green "Redis доступен на 127.0.0.1:${REDIS_PORT}"
    else
      die "Redis не поднялся за таймаут"
    fi
  else
    warn "Docker недоступен; ожидаю локальный redis на 127.0.0.1:${REDIS_PORT}"
    _wait_port "127.0.0.1" "${REDIS_PORT}" 1 || warn "Порт ${REDIS_PORT} не слушается"
  fi
}

_stop_redis() {
  if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' | grep -q "^${REDIS_NAME}\$"; then
      log "Останавливаю Redis контейнер (${REDIS_NAME})"
      docker stop "${REDIS_NAME}" >/dev/null
    fi
  fi
}

_redis_logs() {
  if command -v docker >/dev/null 2>&1; then
    docker logs --tail 200 "${REDIS_NAME}" 2>/dev/null || true
  else
    warn "Docker недоступен — логи Redis недоступны"
  fi
}

# ---------------------------
# Команды демо
# ---------------------------
_cmd_health() {
  _ensure_venv
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  export ENGINE_LOG_LEVEL ENGINE_LOG_FORMAT
  python - <<'PY'
import json, os
from engine.cli.main import main as eng_main
# Проверка версии и здоровья
print("== version ==")
eng_main(["--log-level", os.getenv("ENGINE_LOG_LEVEL","INFO"), "version"])
print("== health ==")
eng_main(["--log-level", os.getenv("ENGINE_LOG_LEVEL","INFO"), "health", "--deep"])
PY
}

_cmd_profile() {
  local block="${1:-ai_npc_block}"
  local dur="${2:-2.0}"
  _ensure_venv
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  export ENGINE_LOG_LEVEL ENGINE_LOG_FORMAT ENGINE_PROFILE_DIR ENGINE_PROFILING
  python - <<PY
import os
from engine.cli.main import main as eng_main
print("== profiling ==")
eng_main(["--log-level", os.getenv("ENGINE_LOG_LEVEL","INFO"),
          "profile", "--block", "${block}", "--out-dir", os.getenv("ENGINE_PROFILE_DIR","telemetry/profiles"),
          "--duration", "${dur}"])
PY
  _green "Профили сохранены в ${ENGINE_PROFILE_DIR}"
}

_cmd_loadgen() {
  _ensure_venv
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  export LOADGEN_NAME LOADGEN_DURATION LOADGEN_WARMUP LOADGEN_RPS LOADGEN_MODEL \
         LOADGEN_SINK LOADGEN_ENDPOINT LOADGEN_EXPORT_JSON LOADGEN_TAG
  export ENGINE_LOG_LEVEL ENGINE_LOG_FORMAT
  log "Запуск генератора нагрузки: name=${LOADGEN_NAME} rps=${LOADGEN_RPS} model=${LOADGEN_MODEL} sink=${LOADGEN_SINK}"
  python -m engine.cli.tools.loadgen \
    --duration "${LOADGEN_DURATION}" \
    --warmup "${LOADGEN_WARMUP}" \
    --rps "${LOADGEN_RPS}" \
    --model "${LOADGEN_MODEL}" \
    --sink "${LOADGEN_SINK}" \
    ${LOADGEN_ENDPOINT:+--endpoint "${LOADGEN_ENDPOINT}"} \
    --export "${LOADGEN_EXPORT_JSON}" \
    --tag "${LOADGEN_TAG}" || die "Loadgen завершился с ошибкой"
  _green "Отчет нагрузки: ${LOADGEN_EXPORT_JSON}"
}

_cmd_demo() {
  AUTO_DOWN=1
  _check_python
  _start_redis
  _cmd_health
  _cmd_loadgen
  _cmd_profile "ai_npc_demo" "1.5"
  _green "Демо завершено успешно."
}

_cmd_up() {
  _check_python
  _start_redis
  _ensure_venv
  _green "Инфраструктура готова."
}

_cmd_down() {
  _stop_redis
  _green "Инфраструктура остановлена."
}

_cmd_status() {
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "^${REDIS_NAME}\$"; then
    _green "Redis (docker) запущен на :${REDIS_PORT}"
  else
    warn "Redis контейнер не найден. Если вы используете локальный redis — проверьте порт :${REDIS_PORT}"
  fi
  if [[ -d "${VENV_DIR}" ]]; then
    _green "VENV существует: ${VENV_DIR}"
  else
    warn "VENV отсутствует: ${VENV_DIR}"
  fi
}

_cmd_logs() {
  _redis_logs
}

_cmd_env() {
  cat <<EOF
ENGINE_LOG_LEVEL=${ENGINE_LOG_LEVEL}
ENGINE_LOG_FORMAT=${ENGINE_LOG_FORMAT}
PYTHON_BIN=${PYTHON_BIN}
VENV_DIR=${VENV_DIR}
USE_DOCKER_REDIS=${USE_DOCKER_REDIS}
REDIS_IMAGE=${REDIS_IMAGE}
REDIS_NAME=${REDIS_NAME}
REDIS_PORT=${REDIS_PORT}
CACHE_REDIS_URL=${CACHE_REDIS_URL}
ENGINE_PROFILING=${ENGINE_PROFILING}
ENGINE_PROFILE_DIR=${ENGINE_PROFILE_DIR}
LOADGEN_NAME=${LOADGEN_NAME}
LOADGEN_DURATION=${LOADGEN_DURATION}
LOADGEN_WARMUP=${LOADGEN_WARMUP}
LOADGEN_RPS=${LOADGEN_RPS}
LOADGEN_MODEL=${LOADGEN_MODEL}
LOADGEN_SINK=${LOADGEN_SINK}
LOADGEN_ENDPOINT=${LOADGEN_ENDPOINT}
LOADGEN_EXPORT_JSON=${LOADGEN_EXPORT_JSON}
LOADGEN_TAG=${LOADGEN_TAG}
EOF
}

_usage() {
  cat <<'USAGE'
Использование: run_demo.sh <команда>

Команды:
  up            — подготовить окружение (Python venv) и запустить Redis (docker, если доступен)
  down          — остановить инфраструктуру (Redis docker)
  status        — показать состояние (Redis/venv)
  logs          — показать логи Redis (docker)
  env           — вывести эффективные переменные окружения
  health        — выполнить health/version через engine CLI
  loadgen       — запустить генератор нагрузки (параметры через ENV/.env)
  profile       — снять профили демо: profile <BLOCK> <DURATION_SEC>
  demo          — полный сценарий: up -> health -> loadgen -> profile -> down(авто)

ENV‑переменные можно определить в .env рядом со скриптом или экспортировать заранее.
Примеры:
  ENGINE_LOG_LEVEL=DEBUG ./run_demo.sh health
  LOADGEN_RPS=200 LOADGEN_DURATION=30 ./run_demo.sh loadgen
  USE_DOCKER_REDIS=0 ./run_demo.sh up
USAGE
}

# ---------------------------
# Разбор команды
# ---------------------------
CMD="${1:-}"
case "${CMD}" in
  up)       _cmd_up ;;
  down)     _cmd_down ;;
  status)   _cmd_status ;;
  logs)     _cmd_logs ;;
  env)      _cmd_env ;;
  health)   _cmd_health ;;
  loadgen)  _cmd_loadgen ;;
  profile)  shift || true; _cmd_profile "${1:-ai_npc_block}" "${2:-2.0}" ;;
  demo)     _cmd_demo ;;
  ""|help|-h|--help) _usage ;;
  *) die "Неизвестная команда: ${CMD}. Запустите: run_demo.sh help" ;;
esac
