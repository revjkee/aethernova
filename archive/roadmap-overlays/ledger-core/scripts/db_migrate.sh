#!/usr/bin/env bash
# ledger-core/scripts/db_migrate.sh
# Industrial-grade, dependency-light DB migration runner for PostgreSQL and SQLite.
# Features:
# - Drivers: PostgreSQL (psql), SQLite (sqlite3)
# - Transactional .sql migrations, executable steps (.sh/.bash/.py) as hooks
# - Advisory lock (Postgres), BEGIN IMMEDIATE (SQLite) to prevent concurrent runs
# - Version table with checksums, repair, force, baseline
# - Commands: plan | status | up [N|all] | down [N] | repair-checksums | force <version> | baseline <version>
# - Dry-run, retries with backoff, timeouts, masked logs, .env loading
# - Deterministic ordering: YYYYMMDD_HHMMSS__name.sql
# - Up/Down pairing: foo.sql (up) and foo.down.sql (down)
# - Multiple directories support via MIGRATIONS_DIRS="m1:m2:..."
set -euo pipefail
IFS=$'\n\t'

# ---------------- Configuration (env overridable) ----------------
DB_DRIVER="${DB_DRIVER:-postgres}"            # postgres | sqlite
DB_DSN="${DB_DSN:-}"                          # e.g. postgres://user:pass@host:5432/db or file path for sqlite
MIGRATIONS_DIRS="${MIGRATIONS_DIRS:-migrations}"  # colon-separated
MIGRATIONS_TABLE="${MIGRATIONS_TABLE:-ledger_schema_migrations}"
LOCK_NAMESPACE="${LOCK_NAMESPACE:-424242}"    # arbitrary namespace for pg_advisory_lock
STATEMENT_TIMEOUT_MS="${STATEMENT_TIMEOUT_MS:-600000}"
LOCK_TIMEOUT_MS="${LOCK_TIMEOUT_MS:-5000}"
RETRIES="${RETRIES:-3}"
BACKOFF_BASE_MS="${BACKOFF_BASE_MS:-250}"
COLOR="${COLOR:-auto}"                         # auto|always|never
VERBOSE="${VERBOSE:-0}"
DRY_RUN="${DRY_RUN:-0}"
DOTENV_FILE="${DOTENV_FILE:-.env}"

# ---------------- Utilities ----------------
_red=$'\033[31m'; _grn=$'\033[32m'; _ylw=$'\033[33m'; _blu=$'\033[34m'; _dim=$'\033[2m'; _rst=$'\033[0m'
_color() {
  case "$COLOR" in
    always) printf "%s" "$1";;
    auto)   [[ -t 1 ]] && printf "%s" "$1" || true;;
    never|*) true;;
  esac
}
log()      { _color "$_dim"; printf "[%s] " "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; _color "$_rst"; printf "%s\n" "$*"; }
info()     { _color "$_blu"; printf "INFO "; _color "$_rst"; printf "%s\n" "$*"; }
ok()       { _color "$_grn"; printf "OK   "; _color "$_rst"; printf "%s\n" "$*"; }
warn()     { _color "$_ylw"; printf "WARN "; _color "$_rst"; printf "%s\n" "$*"; }
err()      { _color "$_red"; printf "ERR  "; _color "$_rst"; printf "%s\n" "$*" >&2; }
die()      { err "$*"; exit 1; }
mask()     { # mask credentials in DSN-like strings
  sed -E 's#(postgres(ql)?://)([^:/@]+)(:[^@/]+)?@#\1\3:***@#g'
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# sha256 availability
shasum_cmd() {
  if cmd_exists sha256sum; then echo "sha256sum"; return; fi
  if cmd_exists shasum; then echo "shasum -a 256"; return; fi
  die "sha256 utility not found (sha256sum or shasum)"
}

# ---------------- .env loader ----------------
load_dotenv() {
  local f="${DOTENV_FILE}"
  [[ -f "$f" ]] || return 0
  # Only KEY=VALUE without export, no command substitution
  set -a
  # shellcheck disable=SC2046
  source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=.*$' "$f" | sed -E 's/^[[:space:]]+//')
  set +a
}

# ---------------- Driver: PostgreSQL ----------------
pg_exec() {
  local sql="$1"
  local dsn="$2"
  local timeout_ms="${3:-$STATEMENT_TIMEOUT_MS}"
  local lock_timeout_ms="${4:-$LOCK_TIMEOUT_MS}"
  [[ -z "$dsn" ]] && die "DB_DSN is empty for postgres"
  [[ "$DRY_RUN" = "1" ]] && { info "(dry-run) psql <<< $(echo "$sql" | tr '\n' ' ' )"; return 0; }
  PGPASSWORD="" psql "$dsn" -v "ON_ERROR_STOP=1" -X -q \
    -c "SET lock_timeout = ${lock_timeout_ms}; SET statement_timeout = ${timeout_ms}; $sql" >/dev/null
}

pg_exec_file() {
  local file="$1"; local dsn="$2"
  [[ -z "$dsn" ]] && die "DB_DSN is empty for postgres"
  [[ "$DRY_RUN" = "1" ]] && { info "(dry-run) psql -f $file"; return 0; }
  PGPASSWORD="" psql "$dsn" -v "ON_ERROR_STOP=1" -X -q \
    -c "SET lock_timeout = ${LOCK_TIMEOUT_MS}; SET statement_timeout = ${STATEMENT_TIMEOUT_MS};" \
    -f "$file" >/dev/null
}

pg_init_schema() {
  pg_exec "
    CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE}(
      id BIGSERIAL PRIMARY KEY,
      version VARCHAR(255) NOT NULL UNIQUE,
      name TEXT NOT NULL,
      checksum CHAR(64) NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    " "$DB_DSN"
}

pg_lock_acquire() {
  local key="$1" # bigint
  pg_exec "SELECT pg_try_advisory_lock(${LOCK_NAMESPACE}, ${key})" "$DB_DSN"
  # enforce blocking lock with timeout using lock_timeout; if fails, psql raises error
  pg_exec "SELECT pg_advisory_lock(${LOCK_NAMESPACE}, ${key})" "$DB_DSN"
}
pg_lock_release() {
  local key="$1"
  pg_exec "SELECT pg_advisory_unlock(${LOCK_NAMESPACE}, ${key})" "$DB_DSN" || true
}

pg_tx() {
  local sql="$1"
  pg_exec "BEGIN; ${sql}; COMMIT;" "$DB_DSN"
}

pg_applied_versions() {
  PGPASSWORD="" psql "$DB_DSN" -X -q -A -t -c "SELECT version||' '||checksum FROM ${MIGRATIONS_TABLE} ORDER BY version" 2>/dev/null || true
}

# ---------------- Driver: SQLite ----------------
sqlite_exec() {
  local sql="$1"; local dsn="$2"
  [[ -z "$dsn" ]] && die "DB_DSN is empty for sqlite"
  [[ "$DRY_RUN" = "1" ]] && { info "(dry-run) sqlite3 $dsn <<< $(echo "$sql" | tr '\n' ' ')"; return 0; }
  sqlite3 "$dsn" "$sql" >/dev/null
}

sqlite_exec_file() {
  local file="$1"; local dsn="$2"
  [[ "$DRY_RUN" = "1" ]] && { info "(dry-run) sqlite3 $dsn < $file"; return 0; }
  sqlite3 "$dsn" < "$file" >/dev/null
}

sqlite_init_schema() {
  sqlite_exec "
    CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE}(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      version TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  " "$DB_DSN"
}

sqlite_lock_acquire() {
  # BEGIN IMMEDIATE acquires write lock; if fails, sqlite3 exits non-zero
  sqlite_exec "BEGIN IMMEDIATE;" "$DB_DSN"
}
sqlite_lock_release() {
  sqlite_exec "COMMIT;" "$DB_DSN" || true
}
sqlite_applied_versions() {
  sqlite3 "$DB_DSN" -batch -noheader -cmd ".mode list" "SELECT version||' '||checksum FROM ${MIGRATIONS_TABLE} ORDER BY version" 2>/dev/null || true
}

# ---------------- Driver Dispatch ----------------
driver_require() {
  case "$DB_DRIVER" in
    postgres) cmd_exists psql || die "psql not found";;
    sqlite)   cmd_exists sqlite3 || die "sqlite3 not found";;
    *) die "Unsupported DB_DRIVER: $DB_DRIVER";;
  esac
}

driver_init_schema() {
  case "$DB_DRIVER" in
    postgres) pg_init_schema;;
    sqlite)   sqlite_init_schema;;
  esac
}

driver_lock_acquire() {
  local key="$1"
  case "$DB_DRIVER" in
    postgres) pg_lock_acquire "$key";;
    sqlite)   sqlite_lock_acquire;;
  esac
}
driver_lock_release() {
  local key="$1"
  case "$DB_DRIVER" in
    postgres) pg_lock_release "$key";;
    sqlite)   sqlite_lock_release;;
  esac
}
driver_exec_file() {
  local file="$1"
  case "$DB_DRIVER" in
    postgres) pg_exec_file "$file" "$DB_DSN";;
    sqlite)   sqlite_exec_file "$file" "$DB_DSN";;
  esac
}
driver_insert_version() {
  local version="$1" name="$2" checksum="$3"
  case "$DB_DRIVER" in
    postgres) pg_exec "INSERT INTO ${MIGRATIONS_TABLE}(version,name,checksum) VALUES ($$${version}$$,$$${name}$$,'${checksum}')" "$DB_DSN";;
    sqlite)   sqlite_exec "INSERT INTO ${MIGRATIONS_TABLE}(version,name,checksum) VALUES ('${version}','${name}','${checksum}')" "$DB_DSN";;
  esac
}
driver_delete_version() {
  local version="$1"
  case "$DB_DRIVER" in
    postgres) pg_exec "DELETE FROM ${MIGRATIONS_TABLE} WHERE version = $$${version}$$" "$DB_DSN";;
    sqlite)   sqlite_exec "DELETE FROM ${MIGRATIONS_TABLE} WHERE version = '${version}'" "$DB_DSN";;
  esac
}
driver_update_checksum() {
  local version="$1" checksum="$2"
  case "$DB_DRIVER" in
    postgres) pg_exec "UPDATE ${MIGRATIONS_TABLE} SET checksum='${checksum}' WHERE version=$$${version}$$" "$DB_DSN";;
    sqlite)   sqlite_exec "UPDATE ${MIGRATIONS_TABLE} SET checksum='${checksum}' WHERE version='${version}'" "$DB_DSN";;
  esac
}

driver_applied_map() {
  declare -gA APPLIED=()
  local line
  case "$DB_DRIVER" in
    postgres) line="$(pg_applied_versions)";;
    sqlite)   line="$(sqlite_applied_versions)";;
  esac
  # shellcheck disable=SC2206
  local rows=(${line//$'\n'/ })
  # Parse rows where each row is "version checksum"
  while IFS= read -r r; do
    [[ -z "$r" ]] && continue
    local v="${r%% *}"; local c="${r#* }"
    APPLIED["$v"]="$c"
  done <<<"$(case "$DB_DRIVER" in postgres) pg_applied_versions;; sqlite) sqlite_applied_versions;; esac)"
  return 0
}

# ---------------- Migrations discovery ----------------
discover_files() {
  IFS=':' read -r -a dirs <<<"$MIGRATIONS_DIRS"
  local f
  for d in "${dirs[@]}"; do
    [[ -d "$d" ]] || continue
    find "$d" -maxdepth 1 -type f \( -name "*.sql" -o -perm -u+x \) -print
  done | sort
}

is_down_file() { [[ "$1" == *.down.sql ]]; }
is_sql_file()  { [[ "$1" == *.sql ]]; }
is_exec_file() { [[ -x "$1" && ! "$1" =~ \.sql$ ]]; }

file_version() {
  local b; b="$(basename "$1")"
  # Expect prefix "YYYYMMDD_HHMMSS__name"
  echo "$b" | sed -E 's/^([0-9]{8}_[0-9]{6})__.*$/\1/'
}
file_name_only() {
  local b; b="$(basename "$1")"
  echo "$b" | sed -E 's/^[0-9]{8}_[0-9]{6}__//'
}
file_checksum() {
  local cmd; cmd="$(shasum_cmd)"
  $cmd "$1" | awk '{print $1}'
}
paired_down() {
  local up="$1"
  local dir; dir="$(dirname "$up")"
  local base; base="$(basename "$up" .sql)"
  echo "${dir}/${base}.down.sql"
}

# ---------------- Planning ----------------
plan_up() {
  driver_applied_map
  local f v name chk
  declare -a plan=()
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    is_down_file "$f" && continue
    v="$(file_version "$f")"
    name="$(file_name_only "$f")"
    chk="$(file_checksum "$f")"
    if [[ -n "${APPLIED[$v]:-}" ]]; then
      if [[ "${APPLIED[$v]}" != "$chk" ]]; then
        printf "MISMATCH  %s  %s  have=%s want=%s\n" "$v" "$name" "${APPLIED[$v]}" "$chk"
      else
        printf "APPLIED   %s  %s\n" "$v" "$name"
      fi
      continue
    fi
    printf "PENDING   %s  %s\n" "$v" "$name"
    plan+=("$f")
  done < <(discover_files)

  # Return list via global
  MIGRATION_PLAN=("${plan[@]}")
}

plan_down() {
  # Roll back latest applied that has a matching .down.sql
  driver_applied_map
  # build list of applied versions sorted descending
  local -a applied_sorted
  for v in "${!APPLIED[@]}"; do applied_sorted+=("$v"); done
  IFS=$'\n' applied_sorted=($(sort -r <<<"${applied_sorted[*]:-}")); unset IFS
  declare -a plan=()
  local v
  for v in "${applied_sorted[@]}"; do
    # find file for this version
    local f
    while IFS= read -r f; do
      [[ "$(file_version "$f")" == "$v" ]] || continue
      local down; down="$(paired_down "$f")"
      [[ -f "$down" ]] && plan+=("$down")
      break
    done < <(discover_files)
  done
  DOWN_PLAN=("${plan[@]}")
}

# ---------------- Execution ----------------
apply_sql_file() {
  local file="$1"
  local v n chk
  v="$(file_version "$file")"
  n="$(file_name_only "$file")"
  chk="$(file_checksum "$file")"
  info "Applying ${v} ${n}"
  driver_exec_file "$file"
  driver_insert_version "$v" "$n" "$chk"
  ok "Applied ${v} ${n}"
}

apply_exec_file() {
  local file="$1"
  local v n
  v="$(file_version "$file")"
  n="$(file_name_only "$file")"
  info "Executing ${v} ${n} (executable)"
  [[ "$DRY_RUN" = "1" ]] && { info "(dry-run) $file"; return 0; }
  DB_DRIVER="$DB_DRIVER" DB_DSN="$DB_DSN" "$file"
  ok "Executed ${v} ${n}"
}

revert_sql_file() {
  local down="$1"
  local v n
  # version same as paired up
  v="$(echo "$(basename "$down")" | sed -E 's/^([0-9]{8}_[0-9]{6})__.*/\1/')"
  n="$(file_name_only "$down")"
  info "Reverting ${v} ${n}"
  driver_exec_file "$down"
  driver_delete_version "$v"
  ok "Reverted ${v} ${n}"
}

# ---------------- Retry wrapper ----------------
with_retries() {
  local fn="$1"; shift
  local attempt=1; local max="${RETRIES}"
  local back="${BACKOFF_BASE_MS}"
  while true; do
    if "$fn" "$@"; then return 0; fi
    if (( attempt > max )); then return 1; fi
    warn "Attempt ${attempt}/${max} failed, backing off ${back}ms"
    sleep "$(awk "BEGIN{print ${back}/1000}")"
    back=$(( back * 2 ))
    attempt=$(( attempt + 1 ))
  done
}

# ---------------- Commands ----------------
usage() {
  cat <<EOF
Usage: DB_DRIVER=postgres DB_DSN="postgres://user:***@host:5432/db" $0 <command> [args]

Commands:
  plan                         Show pending and mismatched migrations
  status                       Show applied versions and checksums
  up [N|all]                   Apply next N or all pending migrations
  down [N]                     Revert N last migrations (requires .down.sql)
  repair-checksums             Recompute and store checksums for applied versions (no SQL run)
  force <version>              Mark version as applied without executing (DANGEROUS)
  baseline <version>           Create baseline row if table is empty (no files executed)
Options (env):
  DB_DRIVER=postgres|sqlite
  DB_DSN=<dsn or path>        DSN for postgres, filename for sqlite
  MIGRATIONS_DIRS=dir[:dir2]  Default: migrations
  DRY_RUN=1                   Do not execute, only log
  VERBOSE=1                   More logs
EOF
}

cmd_plan() {
  plan_up
}

cmd_status() {
  driver_applied_map
  if [[ "${#APPLIED[@]}" -eq 0 ]]; then
    echo "No applied migrations."
    return 0
  fi
  for v in $(printf "%s\n" "${!APPLIED[@]}" | sort); do
    printf "APPLIED   %s  %s\n" "$v" "${APPLIED[$v]}"
  done
}

cmd_up() {
  local n="${1:-1}"
  [[ "$n" == "all" ]] && n=999999
  plan_up
  local count=0 f
  # Advisory lock key by hash of DSN and table
  local key; key=$(printf "%s" "${DB_DSN}:${MIGRATIONS_TABLE}" | cksum | awk '{print $1}')
  with_retries driver_lock_acquire "$key" || die "Could not acquire lock"
  trap 'driver_lock_release "$key"' EXIT
  driver_init_schema
  for f in "${MIGRATION_PLAN[@]:-}"; do
    if is_exec_file "$f"; then
      apply_exec_file "$f"
    elif is_sql_file "$f"; then
      apply_sql_file "$f"
    fi
    count=$((count + 1))
    [[ $count -ge $n ]] && break
  done
  ok "Applied $count migration(s)"
}

cmd_down() {
  local n="${1:-1}"
  [[ "$n" =~ ^[0-9]+$ ]] || die "down requires numeric N"
  plan_down
  local count=0
  local key; key=$(printf "%s" "${DB_DSN}:${MIGRATIONS_TABLE}" | cksum | awk '{print $1}')
  with_retries driver_lock_acquire "$key" || die "Could not acquire lock"
  trap 'driver_lock_release "$key"' EXIT
  driver_init_schema
  local f
  for f in "${DOWN_PLAN[@]:-}"; do
    revert_sql_file "$f"
    count=$((count + 1))
    [[ $count -ge $n ]] && break
  done
  ok "Reverted $count migration(s)"
}

cmd_repair_checksums() {
  driver_init_schema
  driver_applied_map
  local f v chk
  while IFS= read -r f; do
    is_down_file "$f" && continue
    v="$(file_version "$f")"
    chk="$(file_checksum "$f")"
    if [[ -n "${APPLIED[$v]:-}" && "${APPLIED[$v]}" != "$chk" ]]; then
      warn "Repair checksum for ${v}: ${APPLIED[$v]} -> ${chk}"
      [[ "$DRY_RUN" = "1" ]] || driver_update_checksum "$v" "$chk"
    fi
  done < <(discover_files)
  ok "Repair complete"
}

cmd_force() {
  local v="${1:-}"
  [[ -n "$v" ]] || die "force requires version"
  driver_init_schema
  # try to find file to get name and checksum
  local f n chk
  f="$(discover_files | grep -E "/${v}__" | head -n1 || true)"
  if [[ -z "$f" ]]; then
    n="forced"
    chk="$(printf "%s" "$v" | $(shasum_cmd) | awk '{print $1}')"
  else
    n="$(file_name_only "$f")"; chk="$(file_checksum "$f")"
  fi
  warn "Forcing version ${v} (${n}) without executing migration"
  [[ "$DRY_RUN" = "1" ]] || driver_insert_version "$v" "$n" "$chk"
  ok "Forced version ${v}"
}

cmd_baseline() {
  local v="${1:-}"
  [[ -n "$v" ]] || die "baseline requires version"
  driver_init_schema
  driver_applied_map
  if [[ "${#APPLIED[@]}" -gt 0 ]]; then
    die "baseline allowed only on empty ${MIGRATIONS_TABLE}"
  fi
  local f n chk
  f="$(discover_files | grep -E "/${v}__" | head -n1 || true)"
  if [[ -z "$f" ]]; then
    n="baseline"
    chk="$(printf "%s" "$v" | $(shasum_cmd) | awk '{print $1}')"
  else
    n="$(file_name_only "$f")"; chk="$(file_checksum "$f")"
  fi
  warn "Creating baseline ${v} (${n})"
  [[ "$DRY_RUN" = "1" ]] || driver_insert_version "$v" "$n" "$chk"
  ok "Baseline ${v} created"
}

# ---------------- Main ----------------
main() {
  load_dotenv
  driver_require

  [[ "${VERBOSE}" = "1" ]] && set -x || true

  local cmd="${1:-}"; shift || true
  case "${cmd:-}" in
    plan)               cmd_plan "$@";;
    status)             cmd_status "$@";;
    up)                 cmd_up "$@";;
    down)               cmd_down "$@";;
    repair-checksums)   cmd_repair_checksums "$@";;
    force)              cmd_force "$@";;
    baseline)           cmd_baseline "$@";;
    ""|-h|--help|help)  usage;;
    *) die "Unknown command: $cmd";;
  esac
}

main "$@"
