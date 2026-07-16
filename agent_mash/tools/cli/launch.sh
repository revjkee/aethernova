#!/usr/bin/env bash
# agent_mash/tools/cli/launch.sh
#
# Industrial launcher for Docker Compose stacks.
# Supports Docker Compose v2 ("docker compose") and v1 ("docker-compose").
#
# Security and reliability goals:
# - Strict mode (set -Eeuo pipefail)
# - Deterministic project root discovery
# - Safe argument handling
# - Clear logs, consistent exit codes
# - Compose file auto-detection with override options

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_PATH=""
SCRIPT_DIR=""
PROJECT_ROOT=""
COMPOSE_FILE=""
ENV_FILE=""
COMPOSE_BIN=()

LOG_LEVEL="${LOG_LEVEL:-info}"     # debug|info|warn|error
NO_COLOR="${NO_COLOR:-0}"          # 1 disables colors
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-}"  # optional override
COMPOSE_PROFILES="${COMPOSE_PROFILES:-}"          # optional override (comma-separated)
COMPOSE_PARALLEL_LIMIT="${COMPOSE_PARALLEL_LIMIT:-}" # optional override

# ---------- logging ----------

_is_tty() { [[ -t 1 ]]; }

_color() {
  local code="$1"
  if [[ "${NO_COLOR}" == "1" ]] || ! _is_tty; then
    printf "%s" ""
    return 0
  fi
  printf "\033[%sm" "${code}"
}

c_reset="$(_color 0)"
c_dim="$(_color 2)"
c_red="$(_color 31)"
c_yellow="$(_color 33)"
c_green="$(_color 32)"
c_blue="$(_color 34)"

_now() {
  # ISO-8601 without timezone ambiguity, keeps it consistent in logs
  date +"%Y-%m-%dT%H:%M:%S"
}

_log() {
  local level="$1"; shift
  local msg="$*"

  local ts="$(_now)"
  local prefix="[${ts}] [${level}]"

  case "${level}" in
    debug)
      [[ "${LOG_LEVEL}" == "debug" ]] || return 0
      printf "%s %s%s%s\n" "${prefix}" "${c_dim}" "${msg}" "${c_reset}" >&2
      ;;
    info)
      printf "%s %s%s%s\n" "${prefix}" "${c_green}" "${msg}" "${c_reset}" >&2
      ;;
    warn)
      printf "%s %s%s%s\n" "${prefix}" "${c_yellow}" "${msg}" "${c_reset}" >&2
      ;;
    error)
      printf "%s %s%s%s\n" "${prefix}" "${c_red}" "${msg}" "${c_reset}" >&2
      ;;
    *)
      printf "%s %s\n" "${prefix}" "${msg}" >&2
      ;;
  esac
}

die() {
  local code="$1"; shift
  _log error "$*"
  exit "${code}"
}

# ---------- traps & errors ----------

_on_error() {
  local exit_code="$?"
  local line_no="${1:-unknown}"
  local cmd="${2:-unknown}"
  _log error "Command failed (exit=${exit_code}) at line ${line_no}: ${cmd}"
  exit "${exit_code}"
}

_on_int() {
  _log warn "Interrupted"
  exit 130
}

trap '_on_error "${LINENO}" "${BASH_COMMAND}"' ERR
trap _on_int INT

# ---------- utils ----------

require_cmd() {
  local name="$1"
  command -v "${name}" >/dev/null 2>&1 || die 127 "Missing required command: ${name}"
}

realpath_fallback() {
  # Best-effort absolute path resolver.
  # Uses realpath if available; otherwise uses Python if available; otherwise uses pwd/cd.
  local p="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "${p}"
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    python - <<'PY' "${p}"
import os, sys
print(os.path.abspath(sys.argv[1]))
PY
    return 0
  fi
  # Shell fallback
  (
    cd "$(dirname "${p}")" >/dev/null 2>&1
    printf "%s/%s\n" "$(pwd -P)" "$(basename "${p}")"
  )
}

script_init_paths() {
  # shellcheck disable=SC2128
  if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_PATH="$(realpath_fallback "${BASH_SOURCE[0]}")"
  else
    SCRIPT_PATH="$(realpath_fallback "$0")"
  fi
  SCRIPT_DIR="$(dirname "${SCRIPT_PATH}")"
}

find_project_root() {
  # Start from script dir and walk up until we find a marker
  # Markers: .git, docker-compose.yml, compose.yml, pyproject.toml, package.json
  local dir="${SCRIPT_DIR}"
  while [[ "${dir}" != "/" ]]; do
    if [[ -d "${dir}/.git" ]] \
      || [[ -f "${dir}/docker-compose.yml" ]] \
      || [[ -f "${dir}/docker-compose.yaml" ]] \
      || [[ -f "${dir}/compose.yml" ]] \
      || [[ -f "${dir}/compose.yaml" ]] \
      || [[ -f "${dir}/pyproject.toml" ]] \
      || [[ -f "${dir}/package.json" ]]; then
      PROJECT_ROOT="${dir}"
      return 0
    fi
    dir="$(dirname "${dir}")"
  done
  return 1
}

detect_compose_file() {
  # Priority: user override -> compose.yml -> docker-compose.yml -> compose.yaml -> docker-compose.yaml
  local override="${1:-}"
  if [[ -n "${override}" ]]; then
    if [[ -f "${override}" ]]; then
      COMPOSE_FILE="$(realpath_fallback "${override}")"
      return 0
    fi
    die 2 "Compose file not found: ${override}"
  fi

  local candidates=(
    "${PROJECT_ROOT}/compose.yml"
    "${PROJECT_ROOT}/docker-compose.yml"
    "${PROJECT_ROOT}/compose.yaml"
    "${PROJECT_ROOT}/docker-compose.yaml"
  )

  local f=""
  for f in "${candidates[@]}"; do
    if [[ -f "${f}" ]]; then
      COMPOSE_FILE="$(realpath_fallback "${f}")"
      return 0
    fi
  done

  die 2 "No compose file found in project root: ${PROJECT_ROOT}"
}

detect_env_file() {
  local override="${1:-}"
  if [[ -n "${override}" ]]; then
    if [[ -f "${override}" ]]; then
      ENV_FILE="$(realpath_fallback "${override}")"
      return 0
    fi
    die 2 "Env file not found: ${override}"
  fi

  if [[ -f "${PROJECT_ROOT}/.env" ]]; then
    ENV_FILE="$(realpath_fallback "${PROJECT_ROOT}/.env")"
    return 0
  fi

  ENV_FILE=""
  return 0
}

detect_compose_bin() {
  require_cmd docker

  # Prefer v2
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_BIN=(docker compose)
    return 0
  fi

  # Fallback v1
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_BIN=(docker-compose)
    return 0
  fi

  die 127 "Docker Compose not found. Install Docker Compose v2 or docker-compose v1."
}

compose_base_args() {
  # Builds base args for compose invocation.
  # We must not echo arrays with spaces incorrectly; use printf with NUL separation? Here we output lines and mapfile.
  local -a args=()

  args+=(-f "${COMPOSE_FILE}")

  if [[ -n "${ENV_FILE}" ]]; then
    args+=(--env-file "${ENV_FILE}")
  fi

  if [[ -n "${COMPOSE_PROJECT_NAME}" ]]; then
    args+=(-p "${COMPOSE_PROJECT_NAME}")
  fi

  if [[ -n "${COMPOSE_PROFILES}" ]]; then
    # Compose accepts multiple --profile
    local IFS=',' read -r -a profiles <<<"${COMPOSE_PROFILES}"
    local pr=""
    for pr in "${profiles[@]}"; do
      if [[ -n "${pr}" ]]; then
        args+=(--profile "${pr}")
      fi
    done
  fi

  if [[ -n "${COMPOSE_PARALLEL_LIMIT}" ]]; then
    args+=(--parallel "${COMPOSE_PARALLEL_LIMIT}")
  fi

  printf "%s\n" "${args[@]}"
}

run_compose() {
  local -a base=()
  mapfile -t base < <(compose_base_args)

  _log debug "Compose bin: ${COMPOSE_BIN[*]}"
  _log debug "Compose file: ${COMPOSE_FILE}"
  _log debug "Env file: ${ENV_FILE:-<none>}"
  _log debug "Project root: ${PROJECT_ROOT}"

  # shellcheck disable=SC2145
  _log debug "Compose args: ${base[*]} $*"

  (
    cd "${PROJECT_ROOT}"
    "${COMPOSE_BIN[@]}" "${base[@]}" "$@"
  )
}

usage() {
  cat <<'USAGE'
Usage:
  launch.sh [global options] <command> [command args...]

Global options:
  --root <path>          Override project root (default: auto-detect from script location)
  --file <compose.yml>   Override compose file path
  --env <.env>           Override env file path (default: <root>/.env if exists)
  --project <name>       Override compose project name (-p)
  --profiles <a,b>       Set compose profiles (comma-separated)
  --log-level <level>    debug|info|warn|error (default: info)
  --no-color             Disable colored logs

Commands:
  up [--build] [--detach] [services...]
  down [--volumes] [--remove-orphans]
  restart [services...]
  status
  ps
  logs [--follow] [services...]
  build [services...]
  pull [services...]
  exec <service> <cmd...>
  shell <service>

Examples:
  ./launch.sh up --detach
  ./launch.sh logs --follow api
  ./launch.sh exec api python -V
USAGE
}

# ---------- argument parsing ----------

ROOT_OVERRIDE=""
FILE_OVERRIDE=""
ENV_OVERRIDE=""

parse_global_opts() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --root)
        [[ $# -ge 2 ]] || die 2 "Missing value for --root"
        ROOT_OVERRIDE="$(realpath_fallback "$2")"
        shift 2
        ;;
      --file)
        [[ $# -ge 2 ]] || die 2 "Missing value for --file"
        FILE_OVERRIDE="$(realpath_fallback "$2")"
        shift 2
        ;;
      --env)
        [[ $# -ge 2 ]] || die 2 "Missing value for --env"
        ENV_OVERRIDE="$(realpath_fallback "$2")"
        shift 2
        ;;
      --project)
        [[ $# -ge 2 ]] || die 2 "Missing value for --project"
        COMPOSE_PROJECT_NAME="$2"
        shift 2
        ;;
      --profiles)
        [[ $# -ge 2 ]] || die 2 "Missing value for --profiles"
        COMPOSE_PROFILES="$2"
        shift 2
        ;;
      --log-level)
        [[ $# -ge 2 ]] || die 2 "Missing value for --log-level"
        LOG_LEVEL="$2"
        shift 2
        ;;
      --no-color)
        NO_COLOR="1"
        shift 1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        # stop at first non-global arg (command)
        break
        ;;
    esac
  done

  # return remaining args
  printf "%s\n" "$@"
}

# ---------- commands ----------

cmd_up() {
  local build="0"
  local detach="0"
  local -a services=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --build) build="1"; shift ;;
      --detach|-d) detach="1"; shift ;;
      --) shift; services+=("$@"); break ;;
      *) services+=("$1"); shift ;;
    esac
  done

  local -a args=(up)
  [[ "${detach}" == "1" ]] && args+=(-d)
  [[ "${build}" == "1" ]] && args+=(--build)
  args+=(--remove-orphans)

  if [[ ${#services[@]} -gt 0 ]]; then
    args+=("${services[@]}")
  fi

  _log info "Starting stack"
  run_compose "${args[@]}"
}

cmd_down() {
  local volumes="0"
  local remove_orphans="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --volumes|-v) volumes="1"; shift ;;
      --remove-orphans) remove_orphans="1"; shift ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die 2 "Unknown argument for down: $1"
        ;;
    esac
  done

  local -a args=(down)
  [[ "${volumes}" == "1" ]] && args+=(-v)
  [[ "${remove_orphans}" == "1" ]] && args+=(--remove-orphans)

  _log info "Stopping stack"
  run_compose "${args[@]}"
}

cmd_restart() {
  local -a services=()
  while [[ $# -gt 0 ]]; do
    services+=("$1"); shift
  done
  _log info "Restarting services"
  if [[ ${#services[@]} -gt 0 ]]; then
    run_compose restart "${services[@]}"
  else
    run_compose restart
  fi
}

cmd_status() {
  _log info "Stack status"
  run_compose ps
}

cmd_ps() {
  run_compose ps
}

cmd_logs() {
  local follow="0"
  local -a services=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --follow|-f) follow="1"; shift ;;
      --) shift; services+=("$@"); break ;;
      *) services+=("$1"); shift ;;
    esac
  done

  local -a args=(logs --timestamps)
  [[ "${follow}" == "1" ]] && args+=(-f)

  if [[ ${#services[@]} -gt 0 ]]; then
    args+=("${services[@]}")
  fi

  run_compose "${args[@]}"
}

cmd_build() {
  local -a services=()
  while [[ $# -gt 0 ]]; do
    services+=("$1"); shift
  done
  _log info "Building images"
  if [[ ${#services[@]} -gt 0 ]]; then
    run_compose build "${services[@]}"
  else
    run_compose build
  fi
}

cmd_pull() {
  local -a services=()
  while [[ $# -gt 0 ]]; do
    services+=("$1"); shift
  done
  _log info "Pulling images"
  if [[ ${#services[@]} -gt 0 ]]; then
    run_compose pull "${services[@]}"
  else
    run_compose pull
  fi
}

cmd_exec() {
  [[ $# -ge 2 ]] || die 2 "exec requires: <service> <cmd...>"
  local service="$1"; shift
  run_compose exec -T "${service}" "$@"
}

cmd_shell() {
  [[ $# -ge 1 ]] || die 2 "shell requires: <service>"
  local service="$1"; shift

  # prefer bash, fallback sh
  run_compose exec "${service}" bash -lc 'command -v bash >/dev/null 2>&1 && exec bash || exec sh'
}

# ---------- main ----------

main() {
  script_init_paths

  local -a remaining=()
  mapfile -t remaining < <(parse_global_opts "$@")

  if [[ ${#remaining[@]} -eq 0 ]]; then
    usage
    exit 2
  fi

  local cmd="${remaining[0]}"
  shift || true

  # Rebuild the rest of args excluding cmd
  local -a cmd_args=()
  if [[ ${#remaining[@]} -gt 1 ]]; then
    cmd_args=("${remaining[@]:1}")
  fi

  if [[ -n "${ROOT_OVERRIDE}" ]]; then
    [[ -d "${ROOT_OVERRIDE}" ]] || die 2 "Project root not found: ${ROOT_OVERRIDE}"
    PROJECT_ROOT="${ROOT_OVERRIDE}"
  else
    find_project_root || die 2 "Unable to detect project root from: ${SCRIPT_DIR}"
  fi

  detect_compose_file "${FILE_OVERRIDE}"
  detect_env_file "${ENV_OVERRIDE}"
  detect_compose_bin

  case "${cmd}" in
    up)       cmd_up "${cmd_args[@]}" ;;
    down)     cmd_down "${cmd_args[@]}" ;;
    restart)  cmd_restart "${cmd_args[@]}" ;;
    status)   cmd_status ;;
    ps)       cmd_ps ;;
    logs)     cmd_logs "${cmd_args[@]}" ;;
    build)    cmd_build "${cmd_args[@]}" ;;
    pull)     cmd_pull "${cmd_args[@]}" ;;
    exec)     cmd_exec "${cmd_args[@]}" ;;
    shell)    cmd_shell "${cmd_args[@]}" ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      die 2 "Unknown command: ${cmd}"
      ;;
  esac
}

main "$@"
