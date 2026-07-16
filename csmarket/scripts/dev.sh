#!/usr/bin/env bash
# csmarket/scripts/dev.sh
# Industrial-grade local dev orchestration for Docker Compose.
# Requirements: bash, docker, docker compose plugin.

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"

log()  { printf '%s\n' "$*"; }
err()  { printf '%s\n' "ERROR: $*" >&2; }
die()  { err "$*"; exit 1; }

on_err() {
  local exit_code="$?"
  local line_no="${1:-unknown}"
  err "Command failed (exit=${exit_code}) at line ${line_no}."
  exit "${exit_code}"
}
trap 'on_err "$LINENO"' ERR

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

need_docker() {
  need_cmd docker
  docker info >/dev/null 2>&1 || die "Docker daemon is not reachable. Start Docker and retry."
  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is not available. Install docker compose and retry."
}

resolve_project_root() {
  local start_dir="${1:-$PWD}"
  local d="$start_dir"
  while [[ "$d" != "/" ]]; do
    if [[ -f "$d/docker-compose.yml" ]] || [[ -f "$d/docker-compose.yaml" ]]; then
      printf '%s\n' "$d"
      return 0
    fi
    d="$(dirname "$d")"
  done
  return 1
}

PROJECT_ROOT="$(resolve_project_root "$PWD" 2>/dev/null || true)"
[[ -n "${PROJECT_ROOT:-}" ]] || die "Project root not found (docker-compose.yml/.yaml not found in parent directories)."

cd "$PROJECT_ROOT"

COMPOSE_FILE=""
if [[ -f "$PROJECT_ROOT/docker-compose.yml" ]]; then
  COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"
elif [[ -f "$PROJECT_ROOT/docker-compose.yaml" ]]; then
  COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yaml"
else
  die "docker-compose.yml/.yaml not found in project root."
fi

# Optional compose additions (applied if exist).
EXTRA_FILES=()
[[ -f "$PROJECT_ROOT/docker-compose.override.yml" ]] && EXTRA_FILES+=("$PROJECT_ROOT/docker-compose.override.yml")
[[ -f "$PROJECT_ROOT/docker-compose.override.yaml" ]] && EXTRA_FILES+=("$PROJECT_ROOT/docker-compose.override.yaml")
[[ -f "$PROJECT_ROOT/docker-compose.dev.yml" ]] && EXTRA_FILES+=("$PROJECT_ROOT/docker-compose.dev.yml")
[[ -f "$PROJECT_ROOT/docker-compose.dev.yaml" ]] && EXTRA_FILES+=("$PROJECT_ROOT/docker-compose.dev.yaml")

# Safe .env loader: only KEY=VALUE lines, no command execution.
load_env_file() {
  local env_path="$1"
  [[ -f "$env_path" ]] || return 0

  # Export variables defined as KEY=VALUE without spaces around '=' and valid shell identifier KEY.
  # Ignores comments and empty lines.
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    # Trim leading/trailing spaces.
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    # Strict KEY=VALUE
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      local key="${BASH_REMATCH[1]}"
      local val="${BASH_REMATCH[2]}"

      # Remove optional surrounding quotes for basic compatibility.
      if [[ "$val" =~ ^\"(.*)\"$ ]]; then
        val="${BASH_REMATCH[1]}"
      elif [[ "$val" =~ ^\'(.*)\'$ ]]; then
        val="${BASH_REMATCH[1]}"
      fi

      export "${key}=${val}"
    else
      die "Invalid line in env file: ${env_path}: ${line}"
    fi
  done < "$env_path"
}

# Prefer .env in project root if present.
load_env_file "$PROJECT_ROOT/.env" || true

compose() {
  local args=()
  args+=(--project-directory "$PROJECT_ROOT")
  args+=(-f "$COMPOSE_FILE")
  local f
  for f in "${EXTRA_FILES[@]:-}"; do
    args+=(-f "$f")
  done
  docker compose "${args[@]}" "$@"
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/dev.sh <command> [options]

Commands:
  up                Start services (default: detached)
  down              Stop and remove containers, networks (keeps volumes by default)
  restart           Restart services
  logs              Show logs (follow by default)
  ps                Show status
  build             Build images
  pull              Pull images
  exec              Exec into a running service (requires --service)
  sh                Open shell in a running service (requires --service; tries sh then bash)
  clean             Danger: down -v --remove-orphans (removes volumes)

Options:
  --attach           Run in attached mode for 'up' (default is detached)
  --detach           Force detached mode for 'up'
  --build            For 'up': build before start
  --pull             For 'up': pull before start
  --no-cache         For 'build': disable build cache
  --service <name>   Service name for exec/sh
  --                 Pass remaining args to docker compose (for logs/exec/etc)

Examples:
  scripts/dev.sh up --build
  scripts/dev.sh logs --
  scripts/dev.sh sh --service api
  scripts/dev.sh exec --service db -- psql -U postgres
USAGE
}

COMMAND="${1:-}"
[[ -n "$COMMAND" ]] || { usage; exit 2; }
shift || true

# Defaults
UP_DETACHED=1
UP_BUILD=0
UP_PULL=0
BUILD_NO_CACHE=0
SERVICE_NAME=""
PASSTHROUGH=()

# Parse options until '--'
while [[ "${1:-}" != "" ]]; do
  case "$1" in
    --attach) UP_DETACHED=0; shift ;;
    --detach) UP_DETACHED=1; shift ;;
    --build)  UP_BUILD=1; shift ;;
    --pull)   UP_PULL=1; shift ;;
    --no-cache) BUILD_NO_CACHE=1; shift ;;
    --service)
      shift
      SERVICE_NAME="${1:-}"
      [[ -n "$SERVICE_NAME" ]] || die "--service requires a value"
      shift
      ;;
    --)
      shift
      while [[ "${1:-}" != "" ]]; do
        PASSTHROUGH+=("$1")
        shift
      done
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1 (use --help)"
      ;;
  esac
done

need_docker

case "$COMMAND" in
  up)
    log "Project: $PROJECT_ROOT"
    log "Compose:  $COMPOSE_FILE"

    if [[ "$UP_PULL" -eq 1 ]]; then
      log "Pulling images..."
      compose pull
    fi

    if [[ "$UP_BUILD" -eq 1 ]]; then
      log "Building images..."
      compose build
    fi

    if [[ "$UP_DETACHED" -eq 1 ]]; then
      log "Starting services (detached)..."
      compose up -d
      compose ps
    else
      log "Starting services (attached)..."
      compose up
    fi
    ;;
  down)
    log "Stopping services..."
    compose down --remove-orphans
    ;;
  restart)
    log "Restarting services..."
    compose restart
    compose ps
    ;;
  logs)
    log "Showing logs..."
    if [[ "${#PASSTHROUGH[@]}" -gt 0 ]]; then
      compose logs "${PASSTHROUGH[@]}"
    else
      compose logs -f --tail=200
    fi
    ;;
  ps)
    compose ps
    ;;
  build)
    if [[ "$BUILD_NO_CACHE" -eq 1 ]]; then
      compose build --no-cache
    else
      compose build
    fi
    ;;
  pull)
    compose pull
    ;;
  exec)
    [[ -n "$SERVICE_NAME" ]] || die "exec requires --service <name>"
    [[ "${#PASSTHROUGH[@]}" -gt 0 ]] || die "exec requires command after --"
    compose exec "$SERVICE_NAME" "${PASSTHROUGH[@]}"
    ;;
  sh)
    [[ -n "$SERVICE_NAME" ]] || die "sh requires --service <name>"
    # Try sh first, then bash.
    if compose exec "$SERVICE_NAME" sh -lc 'exit 0' >/dev/null 2>&1; then
      compose exec "$SERVICE_NAME" sh
    else
      compose exec "$SERVICE_NAME" bash
    fi
    ;;
  clean)
    log "Removing containers, networks, and volumes..."
    compose down -v --remove-orphans
    ;;
  *)
    usage
    die "Unknown command: $COMMAND"
    ;;
esac
