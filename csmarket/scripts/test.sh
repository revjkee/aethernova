#!/usr/bin/env bash
# File: csmarket/scripts/test.sh
# Purpose: Industrial-grade test runner for csmarket (local + CI).
# Requirements (auto-detected):
#   - Preferred: uv (https://github.com/astral-sh/uv)
#   - Fallback: python3 + pip
# Optional:
#   - pytest, pytest-cov, coverage (installed via project deps)
#   - docker / docker compose (only if using --docker)

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SCRIPT_NAME="$(basename "$0")"

log()  { printf '%s\n' "$*"; }
err()  { printf '%s\n' "$*" 1>&2; }
die()  { err "ERROR: $*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

on_err() {
  local code="$?"
  err "ERROR: ${SCRIPT_NAME} failed (exit code: ${code})"
  exit "$code"
}
trap on_err ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT_DIR"

export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_NO_PYTHON_VERSION_WARNING=1
export PIP_DEFAULT_TIMEOUT="${PIP_DEFAULT_TIMEOUT:-60}"

MODE="all"                 # unit|integration|all
COVERAGE="0"               # 1 enables coverage
COV_HTML="0"               # 1 generates htmlcov/
COV_XML="0"                # 1 generates coverage.xml
JUNIT_XML="0"              # 1 generates junit.xml
DOCKER="0"                 # 1 runs tests in docker compose
DOCKER_SERVICE="${DOCKER_SERVICE:-api}"
PYTEST_PATHS=()            # default: tests
PYTEST_EXTRA_ARGS=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/test.sh [options] [-- <extra pytest args>]

Options:
  --unit               Run unit tests only
  --integration        Run integration tests only
  --all                Run all tests (default)

  --cov                Enable coverage
  --cov-html           Enable coverage + generate htmlcov/
  --cov-xml            Enable coverage + generate coverage.xml
  --junit              Generate junit.xml (useful for CI)

  --docker             Run tests inside docker compose service
  --service NAME       Docker compose service name (default: api)

  --path PATH          Add pytest path (can be specified multiple times)
  -h, --help           Show help

Examples:
  scripts/test.sh
  scripts/test.sh --unit --cov
  scripts/test.sh --integration --junit
  scripts/test.sh -- --maxfail=1 -q
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --unit) MODE="unit"; shift ;;
    --integration) MODE="integration"; shift ;;
    --all) MODE="all"; shift ;;

    --cov) COVERAGE="1"; shift ;;
    --cov-html) COVERAGE="1"; COV_HTML="1"; shift ;;
    --cov-xml) COVERAGE="1"; COV_XML="1"; shift ;;
    --junit) JUNIT_XML="1"; shift ;;

    --docker) DOCKER="1"; shift ;;
    --service)
      [[ $# -ge 2 ]] || die "--service requires a value"
      DOCKER_SERVICE="$2"
      shift 2
      ;;
    --path)
      [[ $# -ge 2 ]] || die "--path requires a value"
      PYTEST_PATHS+=("$2")
      shift 2
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        PYTEST_EXTRA_ARGS+=("$1")
        shift
      done
      ;;
    -h|--help) usage; exit 0 ;;
    *)
      die "Unknown option: $1 (use --help)"
      ;;
  esac
done

if [[ ${#PYTEST_PATHS[@]} -eq 0 ]]; then
  PYTEST_PATHS=("tests")
fi

# Load .env if present (non-fatal). This is intentionally conservative.
# Only exports lines of form KEY=VALUE, ignores comments and blanks.
if [[ -f ".env" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      export "$line"
    fi
  done < ".env"
fi

compose_cmd() {
  if have docker && docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return 0
  fi
  if have docker-compose; then
    echo "docker-compose"
    return 0
  fi
  return 1
}

resolve_python() {
  if have python3; then echo "python3"; return 0; fi
  if have python; then echo "python"; return 0; fi
  return 1
}

run_local() {
  local python_bin
  python_bin="$(resolve_python)" || die "python3/python not found in PATH"

  local -a pytest_args
  pytest_args=()

  case "$MODE" in
    unit) pytest_args+=("-m" "not integration") ;;
    integration) pytest_args+=("-m" "integration") ;;
    all) : ;;
    *) die "Invalid MODE: $MODE" ;;
  esac

  # Coverage configuration (only if enabled)
  if [[ "$COVERAGE" == "1" ]]; then
    pytest_args+=("--cov" "--cov-report=term-missing")
    [[ "$COV_XML" == "1" ]] && pytest_args+=("--cov-report=xml:coverage.xml")
    [[ "$COV_HTML" == "1" ]] && pytest_args+=("--cov-report=html:htmlcov")
  fi

  # JUnit for CI
  if [[ "$JUNIT_XML" == "1" ]]; then
    pytest_args+=("--junitxml=junit.xml")
  fi

  # Prefer uv if available for fast, locked, isolated execution.
  if have uv; then
    # If project provides a lock, uv will use it; otherwise it still runs in an isolated env.
    # We do not force a lock filename because repository layouts may differ.
    uv run -- python -m pytest "${PYTEST_PATHS[@]}" "${pytest_args[@]}" "${PYTEST_EXTRA_ARGS[@]}"
    return 0
  fi

  # Fallback to python -m pytest (assumes deps already installed in current env/venv).
  "$python_bin" -m pytest "${PYTEST_PATHS[@]}" "${pytest_args[@]}" "${PYTEST_EXTRA_ARGS[@]}"
}

run_docker() {
  local dc
  dc="$(compose_cmd)" || die "docker compose / docker-compose not found"

  # Ensure compose files exist
  if [[ ! -f "docker-compose.yml" && ! -f "compose.yml" ]]; then
    die "docker compose file not found (docker-compose.yml/compose.yml)"
  fi

  # Pass through env variables already loaded, do not mount secrets explicitly here.
  # Service must have project code mounted or baked in image.
  $dc run --rm \
    -e PYTHONUNBUFFERED="${PYTHONUNBUFFERED}" \
    -e PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE}" \
    -e PYTHONHASHSEED="${PYTHONHASHSEED}" \
    "${DOCKER_SERVICE}" \
    bash -lc "./scripts/test.sh $( [[ "$MODE" != "all" ]] && echo "--$MODE" ) \
      $( [[ "$COVERAGE" == "1" ]] && echo "--cov" ) \
      $( [[ "$COV_HTML" == "1" ]] && echo "--cov-html" ) \
      $( [[ "$COV_XML" == "1" ]] && echo "--cov-xml" ) \
      $( [[ "$JUNIT_XML" == "1" ]] && echo "--junit" ) \
      $( for p in "${PYTEST_PATHS[@]}"; do printf '%q ' "--path" "$p"; done ) \
      -- ${PYTEST_EXTRA_ARGS[*]-}"
}

main() {
  log "Running tests from: $ROOT_DIR"
  log "Mode: $MODE"
  log "Coverage: $COVERAGE (html=$COV_HTML, xml=$COV_XML)"
  log "JUnit: $JUNIT_XML"
  log "Docker: $DOCKER (service=$DOCKER_SERVICE)"
  log "Pytest paths: ${PYTEST_PATHS[*]}"

  if [[ "$DOCKER" == "1" ]]; then
    run_docker
  else
    run_local
  fi

  # If coverage enabled and coverage package is present, also generate XML/HTML via coverage tool (optional).
  # This is intentionally not required because pytest-cov already produces reports when configured above.
  if [[ "$COVERAGE" == "1" && "$COV_XML" == "1" && -f ".coverage" && have coverage ]]; then
    coverage xml -o coverage.xml >/dev/null 2>&1 || true
  fi
  if [[ "$COVERAGE" == "1" && "$COV_HTML" == "1" && -f ".coverage" && have coverage ]]; then
    coverage html -d htmlcov >/dev/null 2>&1 || true
  fi

  log "OK"
}

main "$@"
