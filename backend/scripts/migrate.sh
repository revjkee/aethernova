#!/usr/bin/env bash
# backend/scripts/migrate.sh
# Industrial-grade Alembic migration helper for FastAPI/SQLAlchemy projects.
# Features:
# - Safe .env loading (optional), strict bash flags, timestamped logs
# - Postgres readiness probe (pg_isready or TCP fallback)
# - Autodetect alembic.ini location with overrides
# - Commands: up, down, stamp, heads, current, history, dry-run, make, wait-db
# - Non-interactive, CI-friendly, deterministic exit codes

set -Eeuo pipefail

#######################################
# Logging helpers
#######################################
log()   { printf '[%s] %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*"; }
info()  { log "INFO  $*"; }
warn()  { log "WARN  $*"; }
error() { log "ERROR $*" >&2; }
die()   { error "$*"; exit 1; }

#######################################
# Path discovery
#######################################
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# Default search order for alembic.ini (can be overridden via env ALEMBIC_INI)
ALEMBIC_INI="${ALEMBIC_INI:-}"
if [[ -z "${ALEMBIC_INI}" ]]; then
  for cand in \
      "${REPO_ROOT}/alembic.ini" \
      "${REPO_ROOT}/src/alembic.ini" \
      "${REPO_ROOT}/backend/alembic.ini" \
      "${REPO_ROOT}/app/alembic.ini"
  do
    if [[ -f "$cand" ]]; then
      ALEMBIC_INI="$cand"
      break
    fi
  done
fi
[[ -n "${ALEMBIC_INI}" && -f "${ALEMBIC_INI}" ]] || die "alembic.ini not found. Set ALEMBIC_INI or place it in repo root."

# Optional working directory for Alembic (where env.py lives)
ALEMBIC_CWD="${ALEMBIC_CWD:-$(dirname "${ALEMBIC_INI}")}"

#######################################
# Load .env if present (safe)
#######################################
load_env() {
  local env_file="${1:-${REPO_ROOT}/.env}"
  if [[ -f "${env_file}" ]]; then
    info "Loading environment from ${env_file}"
    set -a
    # shellcheck disable=SC1090
    source "${env_file}"
    set +a
  else
    info "No .env file found at ${env_file} (skipping)"
  fi
}

#######################################
# Check dependencies
#######################################
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

#######################################
# Database readiness
#######################################
parse_db_host_port() {
  # Accepts DATABASE_URL in form postgresql://user:pass@host:port/db?opts
  # Extract host and port using parameter expansion / sed (best-effort)
  local url="$1"
  local host port
  host="$(printf '%s' "${url}" | sed -E 's#^[a-zA-Z0-9+.-]+://([^:@/]+)(:([0-9]+))?.*$#\1#')"
  port="$(printf '%s' "${url}" | sed -nE 's#^[a-zA-Z0-9+.-]+://[^:@/]+:([0-9]+).*$#\1#p')"
  [[ -n "${host}" ]] || host="127.0.0.1"
  [[ -n "${port}" ]] || port="5432"
  printf '%s %s\n' "${host}" "${port}"
}

wait_for_db() {
  local url="${DATABASE_URL:-}"
  local timeout="${1:-60}"
  [[ -n "${url}" ]] || die "DATABASE_URL is not set."
  info "Waiting for database readiness (timeout=${timeout}s)"

  if command -v pg_isready >/dev/null 2>&1; then
    # Prefer pg_isready
    local host port
    read -r host port < <(parse_db_host_port "${url}")
    local start end
    start="$(date +%s)"
    while true; do
      if pg_isready -h "${host}" -p "${port}" >/dev/null 2>&1; then
        info "Database is ready (${host}:${port})"
        return 0
      fi
      end="$(date +%s)"
      if (( end - start >= timeout )); then
        die "Database not ready after ${timeout}s."
      fi
      sleep 1
    done
  else
    # Fallback: TCP connect via /dev/tcp (bash) best-effort
    local host port
    read -r host port < <(parse_db_host_port "${url}")
    local start end
    start="$(date +%s)"
    while true; do
      if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
        info "Database TCP port is open (${host}:${port})"
        return 0
      fi
      end="$(date +%s)"
      if (( end - start >= timeout )); then
        die "Database TCP port not open after ${timeout}s."
      fi
      sleep 1
    done
  fi
}

#######################################
# Alembic wrapper
#######################################
alembic() {
  # Run alembic with pinned ini and cwd; pass through args
  ( cd "${ALEMBIC_CWD}" && command alembic -c "${ALEMBIC_INI}" "$@" )
}

#######################################
# Commands
#######################################
cmd_up() {
  local rev="${1:-head}"
  info "Upgrading database to ${rev}"
  alembic upgrade "${rev}"
}

cmd_down() {
  local rev="${1:--1}" # step by default
  info "Downgrading database to ${rev}"
  alembic downgrade "${rev}"
}

cmd_stamp() {
  local rev="${1:?usage: migrate.sh stamp <revision>}"
  info "Stamp database to ${rev} (no migration run)"
  alembic stamp "${rev}"
}

cmd_heads()   { info "Listing heads"; alembic heads; }
cmd_current() { info "Current revision"; alembic current; }
cmd_history() {
  if [[ "${1:-}" == "--verbose" ]]; then
    info "History (verbose)"
    alembic history --verbose
  else
    info "History"
    alembic history
  fi
}

cmd_dry_run() {
  local rev="${1:-head}"
  info "Generating offline SQL for upgrade to ${rev}"
  alembic upgrade "${rev}" --sql
}

cmd_make() {
  local msg="${1:-}"
  local flag="${2:-}"
  [[ -n "${msg}" ]] || die "usage: migrate.sh make \"message\" [--autogenerate]"
  if [[ "${flag}" == "--autogenerate" ]]; then
    info "Creating autogenerate revision: ${msg}"
    alembic revision --autogenerate -m "${msg}"
  else
    info "Creating empty revision: ${msg}"
    alembic revision -m "${msg}"
  fi
}

cmd_wait_db() {
  local t="${1:-60}"
  wait_for_db "${t}"
}

#######################################
# Usage
#######################################
usage() {
  cat <<'USAGE'
Usage: migrate.sh <command> [args]

Commands:
  wait-db [TIMEOUT]       Wait for DATABASE_URL to become ready (default 60s)
  up [REV]                Upgrade to revision (default: head)
  down [REV|STEPS]        Downgrade to revision or by steps (default: -1)
  stamp <REV>             Set DB to revision without running migrations
  heads                   Show available heads
  current                 Show current DB revision
  history [--verbose]     Show migration history
  dry-run [REV]           Generate SQL for upgrade (offline mode)
  make "message" [--autogenerate]
                          Create new revision (optionally autogenerate)

Environment:
  ALEMBIC_INI             Path to alembic.ini (auto-discovered if not set)
  ALEMBIC_CWD             Alembic working dir (defaults to ini directory)
  DATABASE_URL            SQLAlchemy URL to target database (required for run)
  DOTENV_PATH             Optional path to .env (default: <repo>/.env)

Examples:
  ./migrate.sh wait-db 90
  ./migrate.sh up
  ./migrate.sh dry-run head > upgrade.sql
  ./migrate.sh make "add_users_table" --autogenerate
USAGE
}

#######################################
# Traps
#######################################
cleanup() { :; }
trap cleanup EXIT

#######################################
# Entry
#######################################
main() {
  require_cmd python
  require_cmd bash
  require_cmd alembic

  # Load .env if present (override path via DOTENV_PATH)
  load_env "${DOTENV_PATH:-${REPO_ROOT}/.env}"

  local cmd="${1:-}"
  shift || true

  case "${cmd}" in
    up)         cmd_up "$@";;
    down)       cmd_down "$@";;
    stamp)      cmd_stamp "$@";;
    heads)      cmd_heads "$@";;
    current)    cmd_current "$@";;
    history)    cmd_history "$@";;
    dry-run)    cmd_dry_run "$@";;
    make)       cmd_make "$@";;
    wait-db)    cmd_wait_db "$@";;
    ""|help|-h|--help) usage;;
    *) die "Unknown command: ${cmd}. See: migrate.sh help";;
  esac
}

main "$@"
