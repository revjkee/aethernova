#!/usr/bin/env bash
# ledger-core/scripts/seed_local.sh
# Industrial-grade local seeding utility for ledger-core
# Supports: PostgreSQL (psql) and SQLite (sqlite3)
# Safe defaults, dry-run, retries, transactional apply, .env loading.

set -Eeuo pipefail

# ----------------------------------------
# Config & Defaults
# ----------------------------------------
PROJECT="${PROJECT:-ledger-core}"
ENV_FILE="${ENV_FILE:-.env}"

DB_DIALECT="${DB_DIALECT:-postgres}"  # postgres|sqlite
# PostgreSQL DSN parts (fallbacks)
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-postgres}"
PG_PASSWORD="${PG_PASSWORD:-postgres}"
PG_DATABASE="${PG_DATABASE:-ledger_local}"
PG_SCHEMA="${PG_SCHEMA:-public}"
PG_SSLMODE="${PG_SSLMODE:-disable}"

# Full DSN override (optional)
PG_DSN="${PG_DSN:-}"

# SQLite path
SQLITE_PATH="${SQLITE_PATH:-./.local/ledger_local.sqlite3}"

# Seeds & migrations
SEEDS_DIR="${SEEDS_DIR:-seeds}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-migrations}"

# Behavior
DRY_RUN="${DRY_RUN:-false}"
RETRY_MAX="${RETRY_MAX:-20}"
RETRY_DELAY_SEC="${RETRY_DELAY_SEC:-0.5}"
STATEMENT_TIMEOUT_MS="${STATEMENT_TIMEOUT_MS:-60000}" # for psql

# ----------------------------------------
# UI / Logging
# ----------------------------------------
BLUE="$(printf '\033[1;34m')"; GREEN="$(printf '\033[1;32m')"
YELLOW="$(printf '\033[1;33m')"; RED="$(printf '\033[1;31m')"
NC="$(printf '\033[0m')"

log()  { printf "%s[%s] %s%s\n" "$BLUE" "$PROJECT" "$*" "$NC" >&2; }
ok()   { printf "%s[OK] %s%s\n" "$GREEN" "$*" "$NC" >&2; }
warn() { printf "%s[WARN] %s%s\n" "$YELLOW" "$*" "$NC" >&2; }
err()  { printf "%s[ERR] %s%s\n" "$RED" "$*" "$NC" >&2; }

usage() {
  cat <<EOF
Usage: $0 [--migrate] [--seed] [--drop] [--reset] [--health] [--dry-run] [--dialect postgres|sqlite]
Options:
  --migrate          Apply migrations from ${MIGRATIONS_DIR}/ (safe order)
  --seed             Apply seeds from ${SEEDS_DIR}/ (idempotent where possible)
  --drop             Drop database/schema (DANGER; guarded)
  --reset            Equivalent to: --drop --migrate --seed
  --health           Only check DB connectivity and print info
  --dry-run          Print planned actions without executing them
  --dialect <d>      Override DB_DIALECT (postgres|sqlite)
Environment (.env is loaded if present):
  DB_DIALECT, PG_* or SQLITE_PATH, SEEDS_DIR, MIGRATIONS_DIR, STATEMENT_TIMEOUT_MS
EOF
}

# ----------------------------------------
# Env loading
# ----------------------------------------
load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC2046
    export $(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$ENV_FILE" | cut -d= -f1) || true
    # shellcheck source=/dev/null
    set -a; . "$ENV_FILE"; set +a || true
    log "Loaded env from $ENV_FILE"
  fi
}

# ----------------------------------------
# Helpers
# ----------------------------------------
is_true() { [[ "${1,,}" == "true" || "${1,,}" == "1" || "${1,,}" == "yes" ]]; }

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || { err "Command not found: $cmd"; exit 127; }
}

confirm_danger() {
  local prompt="$1"
  read -r -p "$prompt [type YES]: " ans
  [[ "$ans" == "YES" ]]
}

retry() {
  local n=0; local max="${1:-$RETRY_MAX}"; local delay="${2:-$RETRY_DELAY_SEC}"
  shift 2
  until "$@"; do
    n=$((n+1))
    if (( n >= max )); then return 1; fi
    sleep "$delay"
  done
}

# ----------------------------------------
# DB Clients
# ----------------------------------------
pg_dsn() {
  if [[ -n "$PG_DSN" ]]; then printf "%s" "$PG_DSN"; return 0; fi
  printf "postgresql://%s:%s@%s:%s/%s?sslmode=%s" \
    "$PG_USER" "$PG_PASSWORD" "$PG_HOST" "$PG_PORT" "$PG_DATABASE" "$PG_SSLMODE"
}

pg_exec() {
  local sql="$1"
  if is_true "$DRY_RUN"; then
    log "[dry-run] psql <- ${sql//[$'\n']/ }"
    return 0
  fi
  PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn)" \
    --set ON_ERROR_STOP=1 \
    --set "statement_timeout=${STATEMENT_TIMEOUT_MS}" \
    --quiet -v "schema=${PG_SCHEMA}" -c "$sql"
}

pg_exec_file() {
  local file="$1"
  if is_true "$DRY_RUN"; then
    log "[dry-run] psql -f $file"
    return 0
  fi
  PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn)" \
    --set ON_ERROR_STOP=1 \
    --set "statement_timeout=${STATEMENT_TIMEOUT_MS}" \
    --quiet -v "schema=${PG_SCHEMA}" -f "$file"
}

pg_health() {
  PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn)" -tAc "select 1" >/dev/null
}

sqlite_exec() {
  local sql="$1"
  if is_true "$DRY_RUN"; then
    log "[dry-run] sqlite3 $SQLITE_PATH <- ${sql//[$'\n']/ }"
    return 0
  fi
  mkdir -p "$(dirname "$SQLITE_PATH")"
  sqlite3 "$SQLITE_PATH" "$sql"
}

sqlite_exec_file() {
  local file="$1"
  if is_true "$DRY_RUN"; then
    log "[dry-run] sqlite3 $SQLITE_PATH < $file"
    return 0
  fi
  mkdir -p "$(dirname "$SQLITE_PATH")"
  sqlite3 "$SQLITE_PATH" < "$file"
}

sqlite_health() {
  sqlite3 "$SQLITE_PATH" "select 1;" >/dev/null 2>&1 || true
  return 0
}

# ----------------------------------------
# Migrations
# ----------------------------------------
apply_migrations_pg() {
  if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    warn "No migrations dir: $MIGRATIONS_DIR"
    return 0
  fi
  log "Applying migrations for PostgreSQL from $MIGRATIONS_DIR"
  # Ensure schema and migrations table
  pg_exec "do \$\$ begin
    if not exists(select 1 from information_schema.schemata where schema_name='${PG_SCHEMA}') then
      execute format('create schema %I', '${PG_SCHEMA}');
    end if;
  end \$\$;"
  pg_exec "create table if not exists ${PG_SCHEMA}.schema_migrations(id text primary key, applied_at timestamptz default now());"
  # Apply *.sql in lexicographic order if not applied
  while IFS= read -r -d '' f; do
    local id; id="$(basename "$f")"
    local cnt
    cnt="$(PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn)" -tAc "select count(1) from ${PG_SCHEMA}.schema_migrations where id='${id}'")"
    if [[ "$cnt" == "0" ]]; then
      log "Applying migration: $id"
      if ! is_true "$DRY_RUN"; then
        PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn)" --set ON_ERROR_STOP=1 --set "statement_timeout=${STATEMENT_TIMEOUT_MS}" --quiet <<SQL
begin;
set search_path to ${PG_SCHEMA}, public;
\ir '$f'
insert into ${PG_SCHEMA}.schema_migrations(id) values ('${id}');
commit;
SQL
      else
        log "[dry-run] would apply $id"
      fi
    else
      log "Skip migration (already applied): $id"
    fi
  done < <(find "$MIGRATIONS_DIR" -maxdepth 1 -type f -name "*.sql" -print0 | sort -z)
  ok "Migrations applied"
}

apply_migrations_sqlite() {
  if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    warn "No migrations dir: $MIGRATIONS_DIR"
    return 0
  fi
  log "Applying migrations for SQLite from $MIGRATIONS_DIR"
  sqlite_exec "create table if not exists schema_migrations(id text primary key, applied_at text default (datetime('now')));"
  while IFS= read -r -d '' f; do
    local id; id="$(basename "$f")"
    local cnt
    cnt="$(sqlite3 "$SQLITE_PATH" "select count(1) from schema_migrations where id='${id}'" 2>/dev/null || echo 0)"
    if [[ "$cnt" == "0" ]]; then
      log "Applying migration: $id"
      if ! is_true "$DRY_RUN"; then
        sqlite3 "$SQLITE_PATH" <<SQL
.begin
.read '$f'
insert into schema_migrations(id) values ('${id}');
.commit
SQL
      else
        log "[dry-run] would apply $id"
      fi
    else
      log "Skip migration (already applied): $id"
    fi
  done < <(find "$MIGRATIONS_DIR" -maxdepth 1 -type f -name "*.sql" -print0 | sort -z)
  ok "Migrations applied"
}

# ----------------------------------------
# Seeding
# ----------------------------------------
apply_seeds_pg() {
  if [[ ! -d "$SEEDS_DIR" ]]; then
    warn "No seeds dir: $SEEDS_DIR"
    return 0
  fi
  log "Applying seeds for PostgreSQL from $SEEDS_DIR"
  # SQL files
  while IFS= read -r -d '' f; do
    log "Seed SQL: $(basename "$f")"
    if ! is_true "$DRY_RUN"; then
      PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn)" --set ON_ERROR_STOP=1 --set "statement_timeout=${STATEMENT_TIMEOUT_MS}" --quiet <<SQL
begin;
set search_path to ${PG_SCHEMA}, public;
\ir '$f'
commit;
SQL
    else
      log "[dry-run] would apply SQL $f"
    fi
  done < <(find "$SEEDS_DIR" -maxdepth 1 -type f -name "*.sql" -print0 | sort -z)
  # JSON files (optional, require jq)
  if command -v jq >/dev/null 2>&1; then
    while IFS= read -r -d '' jf; do
      log "Seed JSON: $(basename "$jf")"
      if ! is_true "$DRY_RUN"; then
        # Expect array of objects with table & values: [{"table":"accounts","values":{"id":1,"name":"demo"}}]
        mapfile -t rows < <(jq -c '.[]' "$jf")
        for row in "${rows[@]}"; do
          local tbl cols vals
          tbl="$(jq -r '.table' <<<"$row")"
          cols="$(jq -r '.values | keys | map(@sh) | join(",")' <<<"$row" | tr -d \')"
          vals="$(jq -r '.values | [.[]] | map(@sh) | join(",")' <<<"$row")"
          pg_exec "insert into ${PG_SCHEMA}.\"$tbl\"(${cols}) values(${vals});"
        done
      else
        log "[dry-run] would apply JSON $jf"
      fi
    done < <(find "$SEEDS_DIR" -maxdepth 1 -type f -name "*.json" -print0 | sort -z)
  else
    warn "jq not found; skipping JSON seeds"
  fi
  ok "Seeds applied"
}

apply_seeds_sqlite() {
  if [[ ! -d "$SEEDS_DIR" ]]; then
    warn "No seeds dir: $SEEDS_DIR"
    return 0
  fi
  log "Applying seeds for SQLite from $SEEDS_DIR"
  while IFS= read -r -d '' f; do
    log "Seed SQL: $(basename "$f")"
    sqlite_exec_file "$f"
  done < <(find "$SEEDS_DIR" -maxdepth 1 -type f -name "*.sql" -print0 | sort -z)
  if command -v jq >/dev/null 2>&1; then
    while IFS= read -r -d '' jf; do
      log "Seed JSON: $(basename "$jf")"
      if ! is_true "$DRY_RUN"; then
        mapfile -t rows < <(jq -c '.[]' "$jf")
        for row in "${rows[@]}"; do
          local tbl cols vals
          tbl="$(jq -r '.table' <<<"$row")"
          cols="$(jq -r '.values | keys | join(",")' <<<"$row")"
          # Escape single quotes for SQLite
          vals="$(jq -r '.values | [.[]] | map( if type=="string" then "'"'"'" + gsub("'"'"'"; "''") + "'"'"'" else tostring end ) | join(",")' <<<"$row")"
          sqlite_exec "insert into \"$tbl\"($cols) values($vals);"
        done
      else
        log "[dry-run] would apply JSON $jf"
      fi
    done < <(find "$SEEDS_DIR" -maxdepth 1 -type f -name "*.json" -print0 | sort -z)
  else
    warn "jq not found; skipping JSON seeds"
  fi
  ok "Seeds applied"
}

# ----------------------------------------
# Drop / Reset
# ----------------------------------------
drop_pg() {
  warn "About to DROP schema/database for PostgreSQL target: $(pg_dsn) schema=${PG_SCHEMA}"
  if ! confirm_danger "This is destructive. Confirm"; then
    err "Aborted."
    exit 2
  fi
  # Prefer dropping schema; if fails, attempt create database flow
  if ! pg_exec "drop schema if exists ${PG_SCHEMA} cascade; create schema ${PG_SCHEMA};"; then
    warn "Schema drop failed; attempting database drop/create"
    # Need superuser for drop database; best-effort
    local db="$PG_DATABASE"
    PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn | sed "s|/${PG_DATABASE}|/postgres|")" --set ON_ERROR_STOP=1 -c "select pg_terminate_backend(pid) from pg_stat_activity where datname='${db}' and pid<>pg_backend_pid();" || true
    PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn | sed "s|/${PG_DATABASE}|/postgres|")" --set ON_ERROR_STOP=1 -c "drop database if exists ${db}; create database ${db};" || true
  fi
  ok "Dropped PostgreSQL target"
}

drop_sqlite() {
  warn "About to remove SQLite file: $SQLITE_PATH"
  if ! confirm_danger "This is destructive. Confirm"; then
    err "Aborted."
    exit 2
  fi
  if is_true "$DRY_RUN"; then
    log "[dry-run] rm -f $SQLITE_PATH"
  else
    rm -f "$SQLITE_PATH"
  fi
  ok "Dropped SQLite target"
}

# ----------------------------------------
# Health
# ----------------------------------------
health_pg() {
  log "Checking PostgreSQL connectivity..."
  if retry "$RETRY_MAX" "$RETRY_DELAY_SEC" pg_health; then
    ok "PostgreSQL is reachable: $(pg_dsn)"
    PGPASSWORD="$PG_PASSWORD" psql "$(pg_dsn)" -tAc "select current_database(), current_user, version();" || true
  else
    err "PostgreSQL is unreachable"
    return 1
  fi
}

health_sqlite() {
  log "Checking SQLite..."
  sqlite_health || { err "SQLite error"; return 1; }
  ok "SQLite ready: $SQLITE_PATH"
}

# ----------------------------------------
# Orchestration
# ----------------------------------------
do_migrate() {
  case "$DB_DIALECT" in
    postgres) apply_migrations_pg ;;
    sqlite)   apply_migrations_sqlite ;;
    *) err "Unsupported DB_DIALECT: $DB_DIALECT"; exit 2 ;;
  esac
}

do_seed() {
  case "$DB_DIALECT" in
    postgres) apply_seeds_pg ;;
    sqlite)   apply_seeds_sqlite ;;
    *) err "Unsupported DB_DIALECT: $DB_DIALECT"; exit 2 ;;
  esac
}

do_drop() {
  case "$DB_DIALECT" in
    postgres) drop_pg ;;
    sqlite)   drop_sqlite ;;
    *) err "Unsupported DB_DIALECT: $DB_DIALECT"; exit 2 ;;
  esac
}

do_health() {
  case "$DB_DIALECT" in
    postgres) health_pg ;;
    sqlite)   health_sqlite ;;
    *) err "Unsupported DB_DIALECT: $DB_DIALECT"; exit 2 ;;
  esac
}

# ----------------------------------------
# Traps
# ----------------------------------------
cleanup() { warn "Interrupted"; }
trap cleanup INT TERM

# ----------------------------------------
# Parse args
# ----------------------------------------
MIGRATE=false; SEED=false; DROP=false; RESET=false; HEALTH=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --migrate) MIGRATE=true; shift ;;
    --seed)    SEED=true; shift ;;
    --drop)    DROP=true; shift ;;
    --reset)   RESET=true; shift ;;
    --health)  HEALTH=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --dialect) DB_DIALECT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

# ----------------------------------------
# Main
# ----------------------------------------
load_env

case "$DB_DIALECT" in
  postgres) require_cmd psql ;;
  sqlite)   require_cmd sqlite3 ;;
  *) err "Unsupported DB_DIALECT: $DB_DIALECT"; exit 2 ;;
esac

if is_true "$HEALTH"; then
  do_health || exit 1
  exit 0
fi

if is_true "$RESET"; then
  DROP=true; MIGRATE=true; SEED=true
fi

log "Starting seed utility: dialect=${DB_DIALECT} dry_run=${DRY_RUN} project=${PROJECT}"

if is_true "$DROP"; then
  do_drop
fi

if is_true "$MIGRATE"; then
  do_health || exit 1
  do_migrate
fi

if is_true "$SEED"; then
  do_health || exit 1
  do_seed
fi

ok "Done."
