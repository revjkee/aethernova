#!/usr/bin/env bash
# omnimind-core/scripts/seed_local.sh
# Industrial-grade local seeding script for OmniMind Core.
# Safe-by-default, idempotent, multi-backend (PostgreSQL, Redis, Kafka, MinIO).
# Usage: bash scripts/seed_local.sh [options]
#
# Options:
#   --env-file <path>      Path to .env file (default: .env or .env.local if exists)
#   --db-url <url>         Override DATABASE_URL (postgres://...)
#   --redis-url <url>      Override REDIS_URL (redis://...)
#   --kafka-brokers <str>  Comma-separated Kafka brokers (e.g. localhost:9092)
#   --minio-url <url>      MinIO endpoint (http://localhost:9000)
#   --minio-key <key>      MinIO access key
#   --minio-secret <sec>   MinIO secret key
#   --fixtures-dir <dir>   Directory with fixtures (*.sql, *.ndjson) [default: seeds/fixtures]
#   --migrate-cmd <cmd>    Migration command [default: "alembic upgrade head" if found, else skipped]
#   --admin-email <email>  Admin email [default: admin@omnimind.local]
#   --admin-pass <pass>    Admin password [default: admin12345]
#   --tenant <name>        Tenant/org name [default: default]
#   --reset                Drop seed checkpoint to re-apply seed (keeps data)
#   --dry-run              Print actions without executing mutating steps
#   --yes                  Non-interactive (assume yes)
#   -h|--help              Show help
#
# Environment:
#   DATABASE_URL, REDIS_URL, KAFKA_BROKERS, MINIO_URL, MINIO_ACCESS_KEY, MINIO_SECRET_KEY
#   PSQL, REDIS_CLI, KAFKA_TOPICS, MC (override binaries)
#
# Exit codes: non-zero on error.

set -Eeuo pipefail

### --------------- Logging & traps ---------------

ts() { date -u +"%Y-%m-%dT%H:%M:%S%z"; }
log() { printf "%s [%s] %s\n" "$(ts)" "$1" "$2"; }
info() { log "INFO" "$*"; }
warn() { log "WARN" "$*"; }
err() { log "ERROR" "$*" >&2; }
ok() { log "OK" "$*"; }
die() { err "$*"; exit 1; }

cleanup() {
  local ec=$?
  if [[ $ec -ne 0 ]]; then err "Seed failed with code $ec"; fi
}
trap cleanup EXIT

### --------------- Defaults ---------------

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE=""
DB_URL="${DATABASE_URL:-}"
REDIS_URL="${REDIS_URL:-}"
KAFKA_BROKERS="${KAFKA_BROKERS:-}"
MINIO_URL="${MINIO_URL:-${MINIO_ENDPOINT:-}}"
MINIO_KEY="${MINIO_ACCESS_KEY:-}"
MINIO_SECRET="${MINIO_SECRET_KEY:-}"
FIXTURES_DIR="${ROOT_DIR}/seeds/fixtures"
MIGRATE_CMD_DEFAULT=""
ADMIN_EMAIL="admin@omnimind.local"
ADMIN_PASS="admin12345"
TENANT_NAME="default"
RESET_FLAG="false"
DRY_RUN="false"
ASSUME_YES="false"

PSQL="${PSQL:-psql}"
REDIS_CLI="${REDIS_CLI:-redis-cli}"
KAFKA_TOPICS="${KAFKA_TOPICS:-kafka-topics}"
MC="${MC:-mc}"

### --------------- Helpers ---------------

print_help() {
  sed -n '1,100p' "$0" | sed -n '/^# Usage:/,$p' | sed 's/^# //'
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

confirm() {
  if [[ "$ASSUME_YES" == "true" ]]; then return 0; fi
  read -r -p "$1 [y/N]: " yn
  [[ "${yn,,}" == "y" || "${yn,,}" == "yes" ]]
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env-file) ENV_FILE="$2"; shift 2;;
      --db-url) DB_URL="$2"; shift 2;;
      --redis-url) REDIS_URL="$2"; shift 2;;
      --kafka-brokers) KAFKA_BROKERS="$2"; shift 2;;
      --minio-url) MINIO_URL="$2"; shift 2;;
      --minio-key) MINIO_KEY="$2"; shift 2;;
      --minio-secret) MINIO_SECRET="$2"; shift 2;;
      --fixtures-dir) FIXTURES_DIR="$2"; shift 2;;
      --migrate-cmd) MIGRATE_CMD_DEFAULT="$2"; shift 2;;
      --admin-email) ADMIN_EMAIL="$2"; shift 2;;
      --admin-pass) ADMIN_PASS="$2"; shift 2;;
      --tenant) TENANT_NAME="$2"; shift 2;;
      --reset) RESET_FLAG="true"; shift;;
      --dry-run) DRY_RUN="true"; shift;;
      --yes) ASSUME_YES="true"; shift;;
      -h|--help) print_help; exit 0;;
      *) die "Unknown argument: $1";;
    esac
  done
}

load_env() {
  if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
    info "Loading env from $ENV_FILE"
    set -a; # export
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
  else
    if [[ -f "${ROOT_DIR}/.env.local" ]]; then
      info "Loading env from .env.local"
      set -a; source "${ROOT_DIR}/.env.local"; set +a
    elif [[ -f "${ROOT_DIR}/.env" ]]; then
      info "Loading env from .env"
      set -a; source "${ROOT_DIR}/.env"; set +a
    fi
  fi
  DB_URL="${DB_URL:-${DATABASE_URL:-}}"
  REDIS_URL="${REDIS_URL:-${REDIS_URL:-}}"
  KAFKA_BROKERS="${KAFKA_BROKERS:-${KAFKA_BROKERS:-}}"
  MINIO_URL="${MINIO_URL:-${MINIO_ENDPOINT:-}}"
  MINIO_KEY="${MINIO_KEY:-${MINIO_ACCESS_KEY:-}}"
  MINIO_SECRET="${MINIO_SECRET:-${MINIO_SECRET_KEY:-}}"
}

url_host() {
  # Extract host:port from URL using python for reliability
  python3 - <<'PY' "$1"
import sys, urllib.parse as u
p=u.urlparse(sys.argv[1]); h=p.hostname or ""; port=p.port or (6379 if p.scheme.startswith("redis") else 5432)
print(f"{h}:{port}")
PY
}

wait_for_tcp() {
  local hostport="$1" name="$2" timeout=${3:-60}
  info "Waiting for $name at $hostport (timeout ${timeout}s)"
  local start=$(date +%s)
  while true; do
    if (echo >"/dev/tcp/${hostport/:/ /}" >/dev/null 2>&1); then
      ok "$name is ready"
      return 0
    fi
    sleep 1
    local now=$(date +%s)
    if (( now - start > timeout )); then
      die "Timeout waiting for $name at $hostport"
    fi
  done
}

run_if() {
  local msg="$1"; shift
  if [[ "$DRY_RUN" == "true" ]]; then
    info "[dry-run] $msg: $*"
  else
    info "$msg: $*"
    "$@"
  fi
}

psql_tx() {
  local sql="$1"
  if [[ -z "$DB_URL" ]]; then return 0; fi
  if [[ "$DRY_RUN" == "true" ]]; then
    info "[dry-run] psql transaction"
    printf "%s\n" "$sql" | sed 's/^/  | /'
    return 0
  fi
  PGPASSWORD="" \
  "$PSQL" "$DB_URL" -v ON_ERROR_STOP=1 -X -q <<SQL
BEGIN;
${sql}
COMMIT;
SQL
}

### --------------- Capability detection ---------------

detect_migrate_cmd() {
  if [[ -n "$MIGRATE_CMD_DEFAULT" ]]; then
    echo "$MIGRATE_CMD_DEFAULT"; return
  fi
  if command -v alembic >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/alembic.ini" ]]; then
    echo "alembic upgrade head"; return
  fi
  if command -v poetry >/dev/null 2>&1 && poetry run alembic --version >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/alembic.ini" ]]; then
    echo "poetry run alembic upgrade head"; return
  fi
  if command -v uv >/dev/null 2>&1 && uv run alembic --version >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/alembic.ini" ]]; then
    echo "uv run alembic upgrade head"; return
  fi
  echo ""
}

### --------------- Seed steps ---------------

ensure_requirements() {
  info "Checking required commands"
  [[ -n "$DB_URL" ]] && need_cmd "$PSQL"
  [[ -n "$REDIS_URL" ]] && need_cmd "$REDIS_CLI"
  [[ -n "$KAFKA_BROKERS" ]] && need_cmd "$KAFKA_TOPICS"
  if [[ -n "$MINIO_URL" ]]; then
    need_cmd "$MC"
  fi
  need_cmd python3
}

await_services() {
  [[ -n "$DB_URL" ]] && wait_for_tcp "$(url_host "$DB_URL")" "PostgreSQL" 90
  [[ -n "$REDIS_URL" ]] && wait_for_tcp "$(url_host "$REDIS_URL")" "Redis" 60
  if [[ -n "$KAFKA_BROKERS" ]]; then
    IFS=',' read -r -a brokers <<<"$KAFKA_BROKERS"
    for b in "${brokers[@]}"; do wait_for_tcp "$b" "Kafka broker $b" 120; done
  fi
  if [[ -n "$MINIO_URL" ]]; then
    wait_for_tcp "$(url_host "$MINIO_URL")" "MinIO" 60
  fi
}

apply_migrations() {
  local cmd
  cmd="$(detect_migrate_cmd)"
  if [[ -z "$cmd" ]]; then
    warn "No migration command detected; skipping migrations"
    return
  fi
  run_if "Applying database migrations" bash -lc "$cmd"
}

ensure_seed_schema() {
  [[ -z "$DB_URL" ]] && return 0
  psql_tx "
    CREATE SCHEMA IF NOT EXISTS meta;
    CREATE TABLE IF NOT EXISTS meta.seed_history (
      id SERIAL PRIMARY KEY,
      seed_name TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      details JSONB NOT NULL DEFAULT '{}'
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ux_seed_history_name_ck
      ON meta.seed_history (seed_name, checksum);
  "
}

seed_checkpoint() {
  local action="$1" name="$2" checksum="$3" details_json="$4"
  case "$action" in
    exists)
      [[ -z "$DB_URL" ]] && return 1
      "$PSQL" "$DB_URL" -At -q -X <<SQL | grep -q 1 || return 1
SELECT 1 FROM meta.seed_history WHERE seed_name='${name}' AND checksum='${checksum}' LIMIT 1;
SQL
      return 0
      ;;
    record)
      psql_tx "
        INSERT INTO meta.seed_history (seed_name, checksum, details)
        VALUES ('${name}', '${checksum}', '${details_json}'::jsonb)
        ON CONFLICT DO NOTHING;
      "
      ;;
    clear)
      psql_tx "DELETE FROM meta.seed_history WHERE seed_name='${name}';"
      ;;
    *) die "Unknown checkpoint action: $action";;
  esac
}

hash_payload() {
  printf "%s" "$1" | sha256sum | awk '{print $1}'
}

seed_core_sql() {
  [[ -z "$DB_URL" ]] && return 0
  local payload
  payload=$(cat <<'SQL'
-- Core seed: extensions, roles, tenant, admin user, api key
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Tenants
CREATE TABLE IF NOT EXISTS public.tenants(
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Roles
CREATE TABLE IF NOT EXISTS public.roles(
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users
CREATE TABLE IF NOT EXISTS public.users(
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  email CITEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- UserRoles
CREATE TABLE IF NOT EXISTS public.user_roles(
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, role_id)
);

-- API Keys
CREATE TABLE IF NOT EXISTS public.api_keys(
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
  key_hash TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

-- Idempotent inserts
INSERT INTO public.tenants(name) VALUES ($$__TENANT_NAME__$$)
ON CONFLICT (name) DO NOTHING;

INSERT INTO public.roles(name) VALUES ('admin'), ('developer'), ('viewer')
ON CONFLICT (name) DO NOTHING;

-- Ensure admin user exists
WITH t AS (
  SELECT id FROM public.tenants WHERE name=$$__TENANT_NAME__$$
),
u AS (
  SELECT id FROM public.users WHERE email=$$__ADMIN_EMAIL__$$
)
INSERT INTO public.users(tenant_id, email, password_hash)
SELECT t.id, $$__ADMIN_EMAIL__$$, crypt($$__ADMIN_PASS__$$, gen_salt('bf', 10))
FROM t
WHERE NOT EXISTS (SELECT 1 FROM u);

-- Grant admin role
WITH u AS (SELECT id FROM public.users WHERE email=$$__ADMIN_EMAIL__$$),
r AS (SELECT id FROM public.roles WHERE name='admin')
INSERT INTO public.user_roles(user_id, role_id)
SELECT u.id, r.id FROM u, r
ON CONFLICT DO NOTHING;

-- Ensure API key exists (label 'local-admin')
WITH t AS (SELECT id FROM public.tenants WHERE name=$$__TENANT_NAME__$$),
k AS (SELECT 1 FROM public.api_keys WHERE label='local-admin' LIMIT 1)
INSERT INTO public.api_keys(tenant_id, key_hash, label)
SELECT t.id, encode(digest($$__ADMIN_EMAIL__$$ || ':' || $$__ADMIN_PASS__$$, 'sha256'), 'hex'), 'local-admin'
FROM t
WHERE NOT EXISTS (SELECT 1 FROM k);
SQL
)
  local sql="${payload//\$\$__TENANT_NAME__\$\$/$TENANT_NAME}"
  sql="${sql//\$\$__ADMIN_EMAIL__\$\$/$ADMIN_EMAIL}"
  sql="${sql//\$\$__ADMIN_PASS__\$\$/$ADMIN_PASS}"

  local ck
  ck="$(hash_payload "$sql")"
  if seed_checkpoint exists "core-sql" "$ck" "{}"; then
    ok "Core SQL seed already applied (checksum=$ck)"
    return 0
  fi

  info "Applying core SQL seed..."
  psql_tx "$sql"
  seed_checkpoint record "core-sql" "$ck" "{\"tenant\":\"$TENANT_NAME\",\"admin\":\"$ADMIN_EMAIL\"}"
  ok "Core SQL seed applied"
}

seed_redis() {
  [[ -z "$REDIS_URL" ]] && return 0
  local hp; hp="$(url_host "$REDIS_URL")"
  local host="${hp%:*}" port="${hp#*:}"
  local flags_key="omnimind:flags:default"
  local json='{"feature_x":true,"rate_limit":"100r/s","beta_users":["admin@omnimind.local"]}'

  if [[ "$DRY_RUN" == "true" ]]; then
    info "[dry-run] redis set $flags_key $json"
    return 0
  fi
  info "Seeding Redis feature flags..."
  "$REDIS_CLI" -h "$host" -p "$port" SET "$flags_key" "$json" >/dev/null
  ok "Redis flags set at $flags_key"
}

seed_kafka() {
  [[ -z "$KAFKA_BROKERS" ]] && return 0
  local topics=("omnimind.events" "omnimind.audit" "omnimind.errors")
  IFS=',' read -r -a brokers <<<"$KAFKA_BROKERS"
  local bstr="${brokers[*]}"
  for t in "${topics[@]}"; do
    if "$KAFKA_TOPICS" --bootstrap-server "${bstr// /,}" --list 2>/dev/null | grep -q "^${t}$"; then
      ok "Kafka topic exists: $t"
      continue
    fi
    run_if "Creating Kafka topic" "$KAFKA_TOPICS" --bootstrap-server "${bstr// /,}" --create --if-not-exists --topic "$t" --partitions 1 --replication-factor 1
  done
}

seed_minio() {
  [[ -z "$MINIO_URL" ]] && return 0
  local alias="localminio"
  local bucket="omnimind"
  if [[ "$DRY_RUN" == "true" ]]; then
    info "[dry-run] mc alias set $alias $MINIO_URL *** ***"
    info "[dry-run] mc mb --ignore-existing $alias/$bucket"
    return 0
  fi
  info "Configuring MinIO client alias..."
  "$MC" alias set "$alias" "$MINIO_URL" "$MINIO_KEY" "$MINIO_SECRET" >/dev/null
  info "Ensuring bucket $bucket exists..."
  "$MC" mb --ignore-existing "$alias/$bucket" >/dev/null || true
  ok "MinIO bucket ready: $bucket"
}

apply_fixtures() {
  local dir="$FIXTURES_DIR"
  [[ -d "$dir" ]] || { warn "Fixtures dir not found: $dir (skipping)"; return 0; }
  info "Applying fixtures from $dir"
  shopt -s nullglob
  local applied=0
  for f in "$dir"/*.sql; do
    local ck; ck="$(hash_payload "$(sha256sum "$f" | awk '{print $1}')")"
    if seed_checkpoint exists "fixture-sql:${f}" "$ck" "{}"; then
      ok "Fixture already applied: $f"
      continue
    fi
    if [[ -z "$DB_URL" ]]; then
      warn "Skipping SQL fixture without DATABASE_URL: $f"
      continue
    fi
    if [[ "$DRY_RUN" == "true" ]]; then
      info "[dry-run] psql -f $f"
    else
      info "Applying SQL fixture: $f"
      "$PSQL" "$DB_URL" -v ON_ERROR_STOP=1 -X -q -f "$f"
      seed_checkpoint record "fixture-sql:${f}" "$ck" "{\"path\":\"$f\"}"
      applied=$((applied+1))
    fi
  done
  for f in "$dir"/*.ndjson; do
    # Generic NDJSON loader is app-specific; log presence.
    warn "NDJSON fixture detected (no generic loader): $f (skipped)"
  done
  ok "Fixtures processed (applied: $applied)"
}

print_summary() {
  cat <<EOF
------------------------------------------------------------
Seed summary:
  Project root   : $ROOT_DIR
  DB_URL         : ${DB_URL:-<none>}
  REDIS_URL      : ${REDIS_URL:-<none>}
  Kafka brokers  : ${KAFKA_BROKERS:-<none>}
  MinIO          : ${MINIO_URL:-<none>}
  Tenant         : $TENANT_NAME
  Admin email    : $ADMIN_EMAIL
  Fixtures dir   : $FIXTURES_DIR
  Dry-run        : $DRY_RUN
------------------------------------------------------------
EOF
}

### --------------- Main ---------------

main() {
  parse_args "$@"
  load_env
  ensure_requirements
  print_summary

  if [[ "$DRY_RUN" != "true" ]]; then
    confirm "Proceed with seeding the local environment?" || die "Aborted by user"
  fi

  await_services

  if [[ "$RESET_FLAG" == "true" && -n "$DB_URL" ]]; then
    info "Reset flag set: clearing seed checkpoints"
    seed_checkpoint clear "core-sql" "" "{}" || true
    # Remove fixture checkpoints
    psql_tx "DELETE FROM meta.seed_history WHERE seed_name LIKE 'fixture-sql:%';" || true
  fi

  apply_migrations
  ensure_seed_schema
  seed_core_sql
  seed_redis
  seed_kafka
  seed_minio
  apply_fixtures

  ok "Local seed completed successfully."
}

main "$@"
