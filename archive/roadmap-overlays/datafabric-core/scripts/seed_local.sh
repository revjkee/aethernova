#!/usr/bin/env bash
# datafabric-core / scripts / seed_local.sh
# Локальный детерминированный бутстрап окружения разработчика.
# Особенности:
#  - Безопасные опции bash, строгие проверки и ловушка ошибок.
#  - Авто‑поиск Docker Compose файла, ожидание готовности сервисов.
#  - Построение .venv, установка зависимостей, проверка инструментов.
#  - Инициализация Postgres (БД/пользователь/расширения), Kafka (топики), Redis (ключи), MinIO (бакет).
#  - Идемпотентность (складывает отметки в ./seeds/.stamp-*).
#
# Использование:
#   ./scripts/seed_local.sh [--no-docker] [--reset] [--with-kafka] [--with-redis] [--with-minio] [--with-migrate]
#                           [--sample N] [--env .env.local] [--python python3.12]
#
# Примеры:
#   ./scripts/seed_local.sh --with-kafka --with-redis --with-minio --with-migrate --sample 500
#   ./scripts/seed_local.sh --no-docker --with-migrate --sample 100
#
# Требования: bash, docker(+compose) при использовании контейнеров, psql, python3, pip, awk, sed.

set -Eeuo pipefail
IFS=$'\n\t'

# ------------------------------
# Логирование и удобства
# ------------------------------
COLOR_GRAY='\033[0;37m'
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_RESET='\033[0m'

log()   { printf "${COLOR_BLUE}[seed]${COLOR_RESET} %s\n" "$*"; }
ok()    { printf "${COLOR_GREEN}[ ok ]${COLOR_RESET} %s\n" "$*"; }
warn()  { printf "${COLOR_YELLOW}[warn]${COLOR_RESET} %s\n" "$*"; }
err()   { printf "${COLOR_RED}[fail]${COLOR_RESET} %s\n" "$*" 1>&2; }
die()   { err "$*"; exit 1; }

trap 'err "Произошла ошибка на строке $LINENO"; exit 1' ERR

need() {
  command -v "$1" >/dev/null 2>&1 || die "Не найден инструмент: $1"
}

retry() {
  local tries=$1; shift
  local delay=${1:-2}; shift || true
  local i=0
  until "$@"; do
    i=$((i+1))
    if (( i >= tries )); then
      return 1
    fi
    sleep "$delay"
  done
}

wait_for_tcp() {
  local host=$1 port=$2 timeout=${3:-60}
  log "Ожидание ${host}:${port} (timeout ${timeout}s)"
  local start=$(date +%s)
  until (echo > /dev/tcp/"$host"/"$port") >/dev/null 2>&1; do
    sleep 1
    local now=$(date +%s)
    (( now - start > timeout )) && return 1
  done
  ok "Порт ${host}:${port} доступен"
}

abspath() {
  python3 - <<'PY'
import os,sys
print(os.path.abspath(sys.argv[1]))
PY
}

# ------------------------------
# Параметры/флаги
# ------------------------------
NO_DOCKER=0
DO_KAFKA=0
DO_REDIS=0
DO_MINIO=0
DO_MIGRATE=0
SAMPLE=200
ENV_FILE=".env"
PY_CMD="python3"

# Разбор аргументов
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-docker) NO_DOCKER=1; shift ;;
    --with-kafka) DO_KAFKA=1; shift ;;
    --with-redis) DO_REDIS=1; shift ;;
    --with-minio) DO_MINIO=1; shift ;;
    --with-migrate) DO_MIGRATE=1; shift ;;
    --sample) SAMPLE="${2:?}"; shift 2 ;;
    --env) ENV_FILE="${2:?}"; shift 2 ;;
    --python) PY_CMD="${2:?}"; shift 2 ;;
    --reset) RESET=1; shift ;;
    -h|--help)
      sed -n '1,100p' "$0" | sed -n '1,60p'
      exit 0
      ;;
    *) die "Неизвестный аргумент: $1" ;;
  esac
done

# ------------------------------
# Директории/штампы
# ------------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED_DIR="${ROOT_DIR}/seeds"
mkdir -p "${SEED_DIR}"

STAMP_VENV="${SEED_DIR}/.stamp-venv"
STAMP_DB="${SEED_DIR}/.stamp-db"
STAMP_DATA="${SEED_DIR}/.stamp-sample-${SAMPLE}"
STAMP_KAFKA="${SEED_DIR}/.stamp-kafka"
STAMP_REDIS="${SEED_DIR}/.stamp-redis"
STAMP_MINIO="${SEED_DIR}/.stamp-minio"
STAMP_MIGR="${SEED_DIR}/.stamp-migrate"

# ------------------------------
# Загрузка .env или генерация дефолтов
# ------------------------------
ENV_PATH="${ROOT_DIR}/${ENV_FILE}"
if [[ -f "${ENV_PATH}" ]]; then
  log "Загрузка переменных из ${ENV_FILE}"
  # shellcheck disable=SC1090
  set -a; source "${ENV_PATH}"; set +a
else
  warn "Файл ${ENV_FILE} не найден — используются безопасные дефолты и будет создан шаблон"
  cat > "${ENV_PATH}" <<'EOF'
# datafabric-core local env (generated)
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=datafabric
POSTGRES_USER=datafabric
POSTGRES_PASSWORD=changeme

REDIS_HOST=127.0.0.1
REDIS_PORT=6379

KAFKA_BROKER=127.0.0.1:9092
KAFKA_TOPICS=df.events,df.commands

MINIO_ENDPOINT=http://127.0.0.1:9000
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin
MINIO_BUCKET=datafabric

PYTHON_VENV=.venv
EOF
  ok "Сгенерирован ${ENV_FILE} — проверьте секреты"
  # shellcheck disable=SC1090
  set -a; source "${ENV_PATH}"; set +a
fi

# ------------------------------
# Проверки инструментов
# ------------------------------
need awk
need sed
need "${PY_CMD}"
need psql || die "Требуется psql (PostgreSQL client)"

if (( NO_DOCKER == 0 )); then
  need docker
  # docker compose vs docker-compose
  if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
  else
    die "Не найден ни 'docker compose', ни 'docker-compose'"
  fi
else
  COMPOSE=""
fi

# ------------------------------
# Определение compose файла (если docker разрешён)
# ------------------------------
COMPOSE_FILE=""
if (( NO_DOCKER == 0 )); then
  for f in "${ROOT_DIR}/compose.yaml" "${ROOT_DIR}/docker-compose.yml" "${ROOT_DIR}/docker/compose.yaml"; do
    if [[ -f "$f" ]]; then
      COMPOSE_FILE="$f"
      break
    fi
  done
  if [[ -z "${COMPOSE_FILE}" ]]; then
    warn "Compose файл не найден — пропускаю запуск контейнеров (параметр --no-docker мог бы быть уместен)"
    NO_DOCKER=1
  else
    log "Compose файл: ${COMPOSE_FILE}"
  fi
fi

# ------------------------------
# Поднятие контейнеров
# ------------------------------
if (( NO_DOCKER == 0 )); then
  log "Запуск контейнеров через Docker Compose (detached)"
  ${COMPOSE} -f "${COMPOSE_FILE}" up -d
fi

# ------------------------------
# Ожидание сервисов
# ------------------------------
wait_for_tcp "${POSTGRES_HOST}" "${POSTGRES_PORT}" 90 || die "Postgres не доступен"
if (( DO_REDIS == 1 )); then
  wait_for_tcp "${REDIS_HOST}" "${REDIS_PORT}" 60 || die "Redis не доступен"
fi
if (( DO_KAFKA == 1 )); then
  # Kafka может подниматься дольше — увеличим таймаут
  wait_for_tcp "$(echo "${KAFKA_BROKER}" | cut -d: -f1)" "$(echo "${KAFKA_BROKER}" | cut -d: -f2)" 180 \
    || die "Kafka брокер не доступен: ${KAFKA_BROKER}"
fi
if (( DO_MINIO == 1 )); then
  # Вытащим хост/порт из URL
  MINIO_HOSTPORT=$(echo "${MINIO_ENDPOINT}" | sed -E 's#^https?://##')
  wait_for_tcp "$(echo "${MINIO_HOSTPORT}" | cut -d: -f1)" "$(echo "${MINIO_HOSTPORT}" | cut -d: -f2)" 90 \
    || die "MinIO не доступен: ${MINIO_ENDPOINT}"
fi

# ------------------------------
# Python venv и зависимости
# ------------------------------
cd "${ROOT_DIR}"
VENV_DIR="${PYTHON_VENV:-.venv}"
if [[ -n "${RESET:-}" ]]; then
  warn "Сброс venv по флагу --reset"
  rm -rf "${VENV_DIR}" || true
  rm -f "${STAMP_VENV}"
fi

if [[ ! -f "${STAMP_VENV}" ]]; then
  log "Подготовка виртуального окружения: ${VENV_DIR}"
  "${PY_CMD}" -m venv "${VENV_DIR}"
  # shellcheck disable=SC1090
  source "${VENV_DIR}/bin/activate"
  python -m pip install --upgrade pip wheel
  if [[ -f "pyproject.toml" ]]; then
    pip install -e .[dev] || pip install -e .
  elif [[ -f "requirements.txt" ]]; then
    pip install -r requirements.txt
  fi
  touch "${STAMP_VENV}"
  ok "Venv готов"
else
  # shellcheck disable=SC1090
  source "${VENV_DIR}/bin/activate"
  ok "Venv уже подготовлен"
fi

# ------------------------------
# Инициализация Postgres (БД/пользователь/расширения)
# ------------------------------
PG_URI="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
if [[ ! -f "${STAMP_DB}" ]]; then
  log "Инициализация Postgres: ${POSTGRES_DB}@${POSTGRES_HOST}:${POSTGRES_PORT}"
  export PGPASSWORD="${POSTGRES_PASSWORD}"
  # Создание пользователя/БД (idempotent) и расширений
  psql -h "${POSTGRES_HOST}" -p "${POSTGRES_PORT}" -U "${POSTGRES_USER}" -d postgres -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${POSTGRES_USER}') THEN
    CREATE ROLE ${POSTGRES_USER} LOGIN PASSWORD '${POSTGRES_PASSWORD}';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname='${POSTGRES_DB}') THEN
    CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};
  END IF;
END
\$\$;
SQL

  psql "${PG_URI}" -v ON_ERROR_STOP=1 <<'SQL'
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;
SQL
  touch "${STAMP_DB}"
  ok "Postgres инициализирован"
else
  ok "Postgres уже инициализирован"
fi

# ------------------------------
# Миграции (опционально)
# ------------------------------
if (( DO_MIGRATE == 1 )); then
  if [[ ! -f "${STAMP_MIGR}" ]]; then
    if python -c "import importlib.util,sys; sys.exit(0) if importlib.util.find_spec('alembic') else sys.exit(1)"; then
      log "Выполнение Alembic миграций"
      ALEM_CONF="${ROOT_DIR}/alembic.ini"
      if [[ -f "${ALEM_CONF}" ]]; then
        ALEMBIC_CONFIG="${ALEM_CONF}" alembic upgrade head || die "Провал миграций Alembic"
      else
        warn "alembic.ini не найден — пропуск миграций"
      fi
    else
      warn "Alembic не установлен — пропуск миграций"
    fi
    touch "${STAMP_MIGR}"
    ok "Миграции отмечены как применённые"
  else
    ok "Миграции уже применены"
  fi
fi

# ------------------------------
# Примерные данные (идемпотентно)
# ------------------------------
if [[ ! -f "${STAMP_DATA}" ]]; then
  log "Загрузка примерных данных (${SAMPLE} записей)"
  psql "${PG_URI}" -v ON_ERROR_STOP=1 <<SQL
CREATE SCHEMA IF NOT EXISTS demo;
CREATE TABLE IF NOT EXISTS demo_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind TEXT NOT NULL,
  payload JSONB NOT NULL
);
-- Вставка SAMPLE записей, пропуская при повторном запуске (по idempotency-ключу kind='seed')
INSERT INTO demo_events(kind, payload)
SELECT 'seed', json_build_object('n', gs)
FROM generate_series(1, ${SAMPLE}) AS gs
WHERE NOT EXISTS (SELECT 1 FROM demo_events WHERE kind = 'seed' LIMIT 1);
SQL
  touch "${STAMP_DATA}"
  ok "Данные загружены"
else
  ok "Примерные данные уже загружены"
fi

# ------------------------------
# Kafka (опционально)
# ------------------------------
if (( DO_KAFKA == 1 )); then
  if [[ ! -f "${STAMP_KAFKA}" ]]; then
    log "Инициализация Kafka топиков"
    IFS=',' read -r -a TOPICS <<< "${KAFKA_TOPICS}"
    CREATED=0

    # Попытка: kafka-topics в PATH
    if command -v kafka-topics.sh >/dev/null 2>&1 || command -v kafka-topics >/dev/null 2>&1; then
      KT=$(command -v kafka-topics.sh || command -v kafka-topics)
      for t in "${TOPICS[@]}"; do
        ${KT} --bootstrap-server "${KAFKA_BROKER}" --create --if-not-exists --topic "$t" --partitions 3 --replication-factor 1 || true
        CREATED=$((CREATED+1))
      done
    elif [[ -n "${COMPOSE_FILE:-}" ]]; then
      # Попытка через docker compose exec (имя сервиса 'kafka' может отличаться; скорректируйте при необходимости)
      if ${COMPOSE} -f "${COMPOSE_FILE}" ps kafka >/dev/null 2>&1; then
        for t in "${TOPICS[@]}"; do
          ${COMPOSE} -f "${COMPOSE_FILE}" exec -T kafka bash -lc \
            "kafka-topics.sh --bootstrap-server ${KAFKA_BROKER} --create --if-not-exists --topic ${t} --partitions 3 --replication-factor 1" || true
          CREATED=$((CREATED+1))
        done
      else
        warn "Сервис 'kafka' в compose не найден — пропуск инициализации топиков"
      fi
    else
      warn "Не найден kafka-topics и отсутствует compose‑доступ — пропуск Kafka‑инициализации"
    fi

    touch "${STAMP_KAFKA}"
    ok "Kafka инициализирована (${CREATED} операций)"
  else
    ok "Kafka уже инициализирована"
  fi
fi

# ------------------------------
# Redis (опционально)
# ------------------------------
if (( DO_REDIS == 1 )); then
  if [[ ! -f "${STAMP_REDIS}" ]]; then
    log "Инициализация Redis ключей"
    if command -v redis-cli >/dev/null 2>&1; then
      redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" SET df:seed:ts "$(date -u +%FT%TZ)" >/dev/null
      redis-cli -h "${REDIS_HOST}" -p "${REDIS_PORT}" HSET df:config mode "dev" version "local" >/dev/null
      touch "${STAMP_REDIS}"
      ok "Redis ключи установлены"
    else
      warn "redis-cli не найден — пропуск Redis инициализации"
    fi
  else
    ok "Redis уже инициализирован"
  fi
fi

# ------------------------------
# MinIO (опционально)
# ------------------------------
if (( DO_MINIO == 1 )); then
  if [[ ! -f "${STAMP_MINIO}" ]]; then
    log "Инициализация MinIO бакета: ${MINIO_BUCKET}"
    # Предпочтительно: mc (MinIO client)
    if command -v mc >/dev/null 2>&1; then
      mc alias set local "${MINIO_ENDPOINT}" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null
      mc mb -p "local/${MINIO_BUCKET}" 2>/dev/null || true
      mc policy set download "local/${MINIO_BUCKET}" >/dev/null || true
      touch "${STAMP_MINIO}"
      ok "MinIO бакет готов"
    elif command -v aws >/dev/null 2>&1; then
      # Альтернатива: AWS CLI v2 в S3‑совместимом режиме
      AWS_EARGS="--endpoint-url ${MINIO_ENDPOINT} --no-verify-ssl"
      aws ${AWS_EARGS} s3 mb "s3://${MINIO_BUCKET}" 2>/dev/null || true
      touch "${STAMP_MINIO}"
      ok "MinIO бакет готов (через aws cli)"
    else
      warn "Не найден ни 'mc', ни 'aws' — пропуск инициализации MinIO"
    fi
  else
    ok "MinIO уже инициализирован"
  fi
fi

# ------------------------------
# Дополнительные user‑hooks (опционально)
# ------------------------------
if python - <<'PY'
import importlib.util
exit(0 if importlib.util.find_spec("datafabric_core") else 1)
PY
then
  # Если в проекте есть модульный сеедер, запустим его (идемпотентно).
  if python -c "import importlib; import sys; sys.exit(0) if importlib.util.find_spec('datafabric_core.scripts.seed') else sys.exit(1)"; then
    log "Запуск модульного сидера: python -m datafabric_core.scripts.seed"
    python -m datafabric_core.scripts.seed || warn "Модульный сидер завершился с предупреждением"
  fi
fi

ok "Локальное окружение подготовлено"
log "PG: ${PG_URI}"
(( DO_KAFKA == 1 )) && log "Kafka: ${KAFKA_BROKER}"
(( DO_REDIS == 1 )) && log "Redis: ${REDIS_HOST}:${REDIS_PORT}"
(( DO_MINIO == 1 )) && log "MinIO: ${MINIO_ENDPOINT} / bucket=${MINIO_BUCKET}"
