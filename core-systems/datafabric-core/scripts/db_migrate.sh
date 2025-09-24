#!/usr/bin/env bash
# datafabric-core/scripts/db_migrate.sh
# Унифицированный запуск миграций БД (Alembic или SQL-файлы), с бэкапом, блокировкой и верификацией.

set -Eeuo pipefail

# ---------------------------
# ЛОГИРОВАНИЕ И УТИЛИТЫ
# ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
cd "${REPO_ROOT}"

_red(){ printf '\033[31m%s\033[0m\n' "$*" >&2; }
_green(){ printf '\033[32m%s\033[0m\n' "$*"; }
_yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
_blue(){ printf '\033[34m%s\033[0m\n' "$*"; }
log(){ _blue "[migrate] $*"; }
warn(){ _yellow "[migrate] $*"; }
die(){ _red "[migrate] $*"; exit 1; }

need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "Не найдено: $1"; }

# ---------------------------
# ОКРУЖЕНИЕ / .env
# ---------------------------
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "${ENV_FILE}" | sed 's/#.*//g' | xargs -I{} echo {})
fi

# Базовые переменные (можно задать в .env)
DB_URL="${DATABASE_URL:-${DB_URL:-}}"
DB_KIND="${DB_KIND:-auto}"             # auto|postgres|mysql
DB_SCHEMA="${DB_SCHEMA:-public}"
DB_BACKUP_DIR="${DB_BACKUP_DIR:-${REPO_ROOT}/telemetry/db_backups}"
DB_LOCK_KEY="${DB_LOCK_KEY:-732145}"   # advisory lock для Postgres
DB_RETRIES="${DB_RETRIES:-30}"
DB_RETRY_DELAY="${DB_RETRY_DELAY:-2}"

ALEMBIC_INI="${ALEMBIC_INI:-${REPO_ROOT}/alembic.ini}"
SQL_DIR="${SQL_DIR:-${REPO_ROOT}/migrations/sql}"     # пути вида 0001_init.up.sql / 0001_init.down.sql
STATE_FILE="${STATE_FILE:-${REPO_ROOT}/migrations/.state.json}"
DRY_SQL="${DRY_SQL:-0}"               # 1 = не применять, а выводить SQL (если поддерживается)
AUTO_BACKUP="${AUTO_BACKUP:-1}"
STRICT_HASH="${STRICT_HASH:-0}"       # 1 = строго сверять хэши SQL для уже применённых миграций

mkdir -p "${DB_BACKUP_DIR}" "$(dirname "${STATE_FILE}")"

# ---------------------------
# ДЕТЕКТ РЕЖИМА
# ---------------------------
MODE="sql"
if [[ -f "${ALEMBIC_INI}" ]]; then
  MODE="alembic"
fi

if [[ -z "${DB_URL}" ]]; then
  # Попытаемся собрать из отдельных переменных
  # Postgres: PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE
  if [[ -n "${PGHOST:-}" && -n "${PGDATABASE:-}" ]]; then
    DB_URL="postgresql://${PGUSER:-postgres}:${PGPASSWORD:-}${PGPASSWORD:+@}${PGHOST}:${PGPORT:-5432}/${PGDATABASE}"
  elif [[ -n "${MYSQL_HOST:-}" && -n "${MYSQL_DB:-}" ]]; then
    DB_URL="mysql://${MYSQL_USER:-root}:${MYSQL_PASSWORD:-}${MYSQL_PASSWORD:+@}${MYSQL_HOST}:${MYSQL_PORT:-3306}/${MYSQL_DB}"
  else
    die "DATABASE_URL не задан и не удалось собрать из переменных. Пример: export DATABASE_URL='postgresql://user:pass@host:5432/db'"
  fi
fi

if [[ "${DB_KIND}" == "auto" ]]; then
  case "${DB_URL}" in
    postgres://*|postgresql://*) DB_KIND="postgres" ;;
    mysql://*|mariadb://*)       DB_KIND="mysql" ;;
    *) die "Не удалось определить DB_KIND из DATABASE_URL: ${DB_URL}" ;;
  esac
fi

# ---------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ---------------------------
wait_db(){
  local tries="${DB_RETRIES}" delay="${DB_RETRY_DELAY}"
  log "Ожидание доступности БД (${DB_KIND})..."
  case "${DB_KIND}" in
    postgres)
      need_cmd psql
      until PGPASSWORD="" psql "${DB_URL}" -c "select 1" >/dev/null 2>&1; do
        ((tries--)) || die "БД не доступна"
        sleep "${delay}"
      done
      ;;
    mysql)
      need_cmd mysql
      until mysql --protocol=TCP "${DB_URL#mysql://}" -e "SELECT 1" >/dev/null 2>&1; do
        ((tries--)) || die "БД не доступна"
        sleep "${delay}"
      done
      ;;
  esac
  _green "БД доступна"
}

backup_db(){
  [[ "${AUTO_BACKUP}" != "1" ]] && { warn "AUTO_BACKUP=0 — пропускаю бэкап"; return 0; }
  local ts; ts="$(date -u +'%Y%m%dT%H%M%SZ')"
  case "${DB_KIND}" in
    postgres)
      need_cmd pg_dump
      local out="${DB_BACKUP_DIR}/pg_${ts}.sql.gz"
      log "Бэкап БД в ${out}"
      pg_dump "${DB_URL}" | gzip -9 > "${out}"
      ;;
    mysql)
      need_cmd mysqldump
      local out="${DB_BACKUP_DIR}/mysql_${ts}.sql.gz"
      log "Бэкап БД в ${out}"
      mysqldump "${DB_URL#mysql://}" | gzip -9 > "${out}"
      ;;
  esac
  _green "Бэкап выполнен"
}

pg_lock(){
  # Advisory lock для предотвращения конкурентных миграций
  [[ "${DB_KIND}" != "postgres" ]] && return 0
  need_cmd psql
  log "Получение advisory-lock (${DB_LOCK_KEY})"
  psql "${DB_URL}" -v "ON_ERROR_STOP=1" -c "SELECT pg_advisory_lock(${DB_LOCK_KEY});" >/dev/null
}
pg_unlock(){
  [[ "${DB_KIND}" != "postgres" ]] && return 0
  psql "${DB_URL}" -v "ON_ERROR_STOP=1" -c "SELECT pg_advisory_unlock(${DB_LOCK_KEY});" >/dev/null || true
}

calc_sha256(){
  need_cmd shasum || true
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

jq_get(){
  local key="$1"
  if [[ -f "${STATE_FILE}" ]]; then
    python - <<PY 2>/dev/null || true
import json,sys
try:
  s=json.load(open("${STATE_FILE}"))
  v=s.get("${key}")
  print(v if v is not None else "")
except Exception:
  sys.exit(0)
PY
  fi
}

jq_put(){
  local key="$1" val="$2"
  python - <<PY
import json,sys,os
p="${STATE_FILE}"
os.makedirs(os.path.dirname(p), exist_ok=True)
try:
  s=json.load(open(p))
except Exception:
  s={}
s["${key}"]="${val}"
json.dump(s, open(p,"w"), indent=2)
print("ok")
PY
}

# ---------------------------
# ALEMBIC-МОД РЕАЛИЗАЦИЯ
# ---------------------------
alembic_cmd(){
  need_cmd python
  if ! python -c "import alembic" >/dev/null 2>&1; then
    die "Alembic не установлен в среде Python"
  fi
  ALEM_FLAGS=(-x "db_url=${DB_URL}" )
  [[ "${DRY_SQL}" == "1" ]] && ALEM_FLAGS+=(--sql)
  ALEM_CMD=(alembic -c "${ALEMBIC_INI}" "${ALEMBIC_OP[@]}" "${ALEMBIC_ARGS[@]}" "${ALEM_FLAGS[@]}")
  # shellcheck disable=SC2068
  "${ALEM_CMD[@]}"
}

alembic_up(){
  ALEMBIC_OP=(upgrade)
  ALEMBIC_ARGS=(head)
  alembic_cmd
}
alembic_down(){
  ALEMBIC_OP=(downgrade)
  ALEMBIC_ARGS=(-1)
  alembic_cmd
}
alembic_to(){
  local rev="${1:?Укажите ревизию}"
  ALEMBIC_OP=(upgrade)
  ALEMBIC_ARGS=("${rev}")
  alembic_cmd
}
alembic_stamp(){
  local rev="${1:?Укажите ревизию}"
  ALEMBIC_OP=(stamp)
  ALEMBIC_ARGS=("${rev}")
  alembic_cmd
}
alembic_current(){
  ALEMBIC_OP=(current)
  ALEMBIC_ARGS=(--verbose)
  alembic_cmd
}
alembic_history(){
  ALEMBIC_OP=(history)
  ALEMBIC_ARGS=(--verbose)
  alembic_cmd
}
alembic_revision(){
  local msg="${1:-manual}"
  ALEMBIC_OP=(revision)
  ALEMBIC_ARGS=(-m "${msg}" --autogenerate)
  alembic_cmd
}

# ---------------------------
# SQL-МОД РЕАЛИЗАЦИЯ
# ---------------------------
sql_list(){
  # возвращает упорядоченный список .up.sql
  find "${SQL_DIR}" -type f -name "*.up.sql" | sort
}

sql_current_rev(){
  # читаем текущую ревизию из таблицы служебных миграций (создадим если нет)
  case "${DB_KIND}" in
    postgres)
      psql "${DB_URL}" -v "ON_ERROR_STOP=1" -c "CREATE TABLE IF NOT EXISTS ${DB_SCHEMA}.schema_migrations (rev text primary key, applied_at timestamptz not null default now(), sha256 text);" >/dev/null
      psql "${DB_URL}" -t -A -F',' -c "SELECT rev FROM ${DB_SCHEMA}.schema_migrations ORDER BY applied_at DESC LIMIT 1" 2>/dev/null | head -n1
      ;;
    mysql)
      mysql "${DB_URL#mysql://}" -e "CREATE TABLE IF NOT EXISTS schema_migrations (rev varchar(191) PRIMARY KEY, applied_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, sha256 varchar(64));" >/dev/null 2>&1 || true
      mysql "${DB_URL#mysql://}" -N -e "SELECT rev FROM schema_migrations ORDER BY applied_at DESC LIMIT 1" 2>/dev/null | head -n1
      ;;
  esac
}

sql_apply(){
  local file="$1"
  [[ -f "${file}" ]] || die "Файл не найден: ${file}"
  local base; base="$(basename "${file}")"
  local rev="${base%%.*}"             # 0001_init.up.sql -> 0001_init
  rev="${rev%.up}"                    # на случай 0001.up.sql
  local sha; sha="$(calc_sha256 "${file}")"
  log "Применение ${base} (rev=${rev})"
  if [[ "${DRY_SQL}" == "1" ]]; then
    cat "${file}"
    return 0
  fi
  case "${DB_KIND}" in
    postgres)
      psql "${DB_URL}" -v "ON_ERROR_STOP=1" -f "${file}"
      psql "${DB_URL}" -v "ON_ERROR_STOP=1" -c "INSERT INTO ${DB_SCHEMA}.schema_migrations(rev,sha256) VALUES ('${rev}','${sha}')" >/dev/null
      ;;
    mysql)
      mysql "${DB_URL#mysql://}" < "${file}" >/dev/null
      mysql "${DB_URL#mysql://}" -e "INSERT INTO schema_migrations(rev,sha256) VALUES ('${rev}','${sha}')" >/dev/null 2>&1 || true
      ;;
  esac
}

sql_verify_hashes(){
  [[ "${STRICT_HASH}" != "1" ]] && return 0
  log "Строгая проверка sha256 применённых миграций"
  case "${DB_KIND}" in
    postgres)
      while IFS=$'\t' read -r rev sha_db; do
        local f="${SQL_DIR}/${rev}.up.sql"
        [[ -f "${f}" ]] || { warn "Нет файла для ревизии ${rev}"; continue; }
        local sha_fs; sha_fs="$(calc_sha256 "${f}")"
        [[ "${sha_db}" == "${sha_fs}" ]] || die "SHA mismatch для ${rev}: db=${sha_db} fs=${sha_fs}"
      done < <(psql "${DB_URL}" -t -A -F $'\t' -c "SELECT rev, sha256 FROM ${DB_SCHEMA}.schema_migrations ORDER BY applied_at")
      ;;
    mysql)
      warn "STRICT_HASH для MySQL best-effort"
      ;;
  esac
  _green "Проверка sha256 пройдена"
}

sql_up(){
  wait_db
  [[ "${AUTO_BACKUP}" == "1" ]] && backup_db
  [[ "${DB_KIND}" == "postgres" ]] && pg_lock
  sql_verify_hashes || { pg_unlock; return 1; }

  local curr; curr="$(sql_current_rev || true)"
  local applied=0
  for f in $(sql_list); do
    local base; base="$(basename "${f}")"
    local rev="${base%%.*}"; rev="${rev%.up}"
    if [[ -n "${curr}" ]]; then
      # если текущая ревизия совпадает — начнем после неё
      if [[ "${rev}" == "${curr}" ]]; then curr=""; continue; fi
      [[ -n "${curr}" ]] && continue
    fi
    sql_apply "${f}"
    applied=$((applied+1))
  done
  pg_unlock
  _green "Готово. Применено миграций: ${applied}"
}

sql_down(){
  # Откат последней миграции, если есть *.down.sql
  wait_db
  [[ "${DB_KIND}" == "postgres" ]] && pg_lock
  local curr; curr="$(sql_current_rev || true)"
  [[ -z "${curr}" ]] && { warn "Нет применённых миграций"; pg_unlock; return 0; }
  local f="${SQL_DIR}/${curr}.down.sql"
  [[ -f "${f}" ]] || { die "Для ревизии ${curr} отсутствует down-скрипт: ${f}"; }
  log "Откат ${curr}"
  if [[ "${DRY_SQL}" == "1" ]]; then
    cat "${f}"
    pg_unlock
    return 0
  fi
  case "${DB_KIND}" in
    postgres)
      psql "${DB_URL}" -v "ON_ERROR_STOP=1" -f "${f}"
      psql "${DB_URL}" -v "ON_ERROR_STOP=1" -c "DELETE FROM ${DB_SCHEMA}.schema_migrations WHERE rev='${curr}'" >/dev/null
      ;;
    mysql)
      mysql "${DB_URL#mysql://}" < "${f}" >/dev/null
      mysql "${DB_URL#mysql://}" -e "DELETE FROM schema_migrations WHERE rev='${curr}'" >/dev/null 2>&1 || true
      ;;
  esac
  pg_unlock
  _green "Откат выполнен: ${curr}"
}

sql_status(){
  wait_db
  local curr; curr="$(sql_current_rev || true)"
  _green "Текущая ревизия: ${curr:-<нет>}"
  log "Доступные миграции:"
  sql_list | sed 's|.*/||g' | nl -w2 -s'. '
}

sql_to(){
  # Применить до указанной ревизии включительно
  local target="${1:?Укажите ревизию (например, 0005_add_index)}"
  wait_db
  [[ "${AUTO_BACKUP}" == "1" ]] && backup_db
  [[ "${DB_KIND}" == "postgres" ]] && pg_lock

  local reached=0
  for f in $(sql_list); do
    local base; base="$(basename "${f}")"
    local rev="${base%%.*}"; rev="${rev%.up}"
    sql_apply "${f}"
    if [[ "${rev}" == "${target}" ]]; then
      reached=1; break
    fi
  done
  pg_unlock
  [[ "${reached}" -eq 1 ]] || die "Ревизия ${target} не найдена среди .up.sql"
  _green "БД приведена к ревизии ${target}"
}

# ---------------------------
# ОБЩИЕ КОМАНДЫ
# ---------------------------
usage(){
  cat <<'USAGE'
Использование: db_migrate.sh <команда> [аргументы]

Глобальные ENV:
  DATABASE_URL / DB_URL            URL подключения (postgresql://... | mysql://...)
  DB_KIND                          auto|postgres|mysql (по умолчанию auto)
  ALEMBIC_INI                      путь к alembic.ini (по умолчанию ./alembic.ini)
  SQL_DIR                          каталог SQL миграций (по умолчанию migrations/sql)
  DRY_SQL                          1 = выводить SQL вместо применения (если поддерживается)
  AUTO_BACKUP                      1 = делать бэкап перед апдейтом (по умолчанию 1)
  DB_LOCK_KEY                      целое для advisory lock Postgres
  STRICT_HASH                      1 = сверять sha256 уже применённых SQL миграций

Команды (режим Alembic):
  up                 — alembic upgrade head
  down               — alembic downgrade -1
  to <rev>           — alembic upgrade <rev>
  stamp <rev>        — alembic stamp <rev>
  current            — alembic current --verbose
  history            — alembic history --verbose
  revision [-m msg]  — alembic revision --autogenerate -m "msg"

Команды (режим SQL):
  up                 — применить все *.up.sql по возрастанию
  down               — откат последней ревизии *.down.sql
  to <rev>           — применить up до ревизии <rev> включительно
  status             — текущая ревизия и список доступных миграций
  verify             — (STRICT_HASH=1) проверить sha256 у применённых миграций

Флаги:
  --sql              — то же, что DRY_SQL=1 (сухой прогон)

Примеры:
  DATABASE_URL=postgresql://user:pass@127.0.0.1:5432/db ./scripts/db_migrate.sh up
  ./scripts/db_migrate.sh --sql to 0007_add_orders
  STRICT_HASH=1 ./scripts/db_migrate.sh verify
USAGE
}

trap '[[ "${DB_KIND}" == "postgres" ]] && pg_unlock || true' EXIT

# разбор аргументов
DRY_FLAG=0
if [[ "${1:-}" == "--sql" ]]; then
  DRY_SQL=1; DRY_FLAG=1; shift
fi
CMD="${1:-}"
shift || true

[[ -n "${CMD}" ]] || { usage; exit 1; }

case "${MODE}:${CMD}" in
  alembic:up)        wait_db; [[ "${AUTO_BACKUP}" == "1" ]] && backup_db; alembic_up ;;
  alembic:down)      wait_db; alembic_down ;;
  alembic:to)        wait_db; [[ "${AUTO_BACKUP}" == "1" ]] && backup_db; alembic_to "${1:-}";;
  alembic:stamp)     wait_db; alembic_stamp "${1:-}";;
  alembic:current)   wait_db; alembic_current ;;
  alembic:history)   wait_db; alembic_history ;;
  alembic:revision)  wait_db; alembic_revision "${1:-manual}";;

  sql:up)            sql_up ;;
  sql:down)          sql_down ;;
  sql:to)            sql_to "${1:-}";;
  sql:status)        sql_status ;;
  sql:verify)        STRICT_HASH=1 sql_verify_hashes ;;

  *:help|*:--help|-h) usage ;;
  *) die "Неизвестная команда: ${CMD} (режим ${MODE}). Запустите: db_migrate.sh -h" ;;
esac
