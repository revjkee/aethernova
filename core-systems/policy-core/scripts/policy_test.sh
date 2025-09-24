#!/usr/bin/env bash
# Industrial test runner for policy-core
# Cross-platform: Linux/macOS
# Shell requirements: bash 4+, coreutils
# Safe-mode
set -Eeuo pipefail

#---------------------------------------
# Global defaults (can be overridden by env)
#---------------------------------------
: "${PYTHON:=python3}"
: "${PIP:=pip3}"
: "${CI:=false}"
: "${PC_ROOT:=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
: "${REPORT_DIR:=${PC_ROOT}/.reports}"
: "${JUNIT_DIR:=${REPORT_DIR}/junit}"
: "${COV_DIR:=${REPORT_DIR}/coverage}"
: "${HTMLCOV_DIR:=${COV_DIR}/html}"
: "${COV_XML:=${COV_DIR}/coverage.xml}"
: "${COV_FAIL_UNDER:=0}"                 # override in CI (e.g. 80)
: "${PYTEST_ARGS:=}"                     # extra args passthrough
: "${PYTEST_MAXFAIL:=1}"
: "${PYTEST_TIMEOUT:=300}"               # global test timeout seconds
: "${PYTEST_PARALLEL:=auto}"             # 'auto' | '0' (disabled) | integer
: "${PYTEST_RETRY:=0}"                   # retries for flaky tests if plugin present
: "${LINT_ENABLE:=true}"                 # ruff if available
: "${TYPECHECK_ENABLE:=false}"           # mypy optional
: "${SECURITY_ENABLE:=false}"            # bandit optional
: "${COVERAGE_ENABLE:=true}"
: "${COLOR:=true}"
: "${FAIL_FAST:=false}"
: "${VERBOSE:=false}"

#---------------------------------------
# Colors
#---------------------------------------
if [[ "${COLOR}" == "true" ]] && [[ -t 2 ]]; then
  c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_cya=$'\033[36m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
else
  c_red=""; c_grn=""; c_yel=""; c_cya=""; c_dim=""; c_off=""
fi

log()   { printf "%s[policy-test]%s %s\n" "${c_cya}" "${c_off}" "$*" >&2; }
ok()    { printf "%s[ok]%s %s\n"          "${c_grn}" "${c_off}" "$*" >&2; }
warn()  { printf "%s[warn]%s %s\n"        "${c_yel}" "${c_off}" "$*" >&2; }
err()   { printf "%s[err]%s %s\n"         "${c_red}" "${c_off}" "$*" >&2; }

#---------------------------------------
# Help
#---------------------------------------
usage() {
  cat <<'EOF'
policy_test.sh - Industrial test runner for policy-core

USAGE:
  scripts/policy_test.sh [options] [-- [extra pytest args]]

OPTIONS:
  -h, --help                Show help
  -q, --quiet               Reduce verbosity
  -v, --verbose             Verbose mode
      --no-color            Disable colored logs
      --fail-fast           Stop on first failure (pytest -x)
      --no-lint             Disable ruff even if installed
      --typecheck           Enable mypy if installed
      --security            Enable bandit if installed
      --no-cov              Disable coverage collection
      --cov-threshold N     Set coverage fail-under to N (default env COV_FAIL_UNDER)
      --parallel [N|auto]   Enable pytest-xdist with workers (default: auto). 0 disables.
      --retry N             Retries for flaky tests (requires pytest-rerunfailures)
      --timeout SEC         Global test timeout (default: 300)
      --maxfail N           Stop after N failures (default: 1)
      --reports DIR         Reports root directory (default: .reports)
      --junit DIR           JUnit XML dir (default: .reports/junit)
      --covdir DIR          Coverage dir (default: .reports/coverage)
      --python PATH         Python interpreter (default: python3)
      --pip PATH            pip executable (default: pip3)

ENV OVERRIDES:
  CI, PC_ROOT, REPORT_DIR, JUNIT_DIR, COV_DIR, HTMLCOV_DIR, COV_XML,
  COV_FAIL_UNDER, PYTEST_ARGS, PYTEST_MAXFAIL, PYTEST_TIMEOUT,
  PYTEST_PARALLEL, PYTEST_RETRY, LINT_ENABLE, TYPECHECK_ENABLE,
  SECURITY_ENABLE, COVERAGE_ENABLE, COLOR, FAIL_FAST, VERBOSE.

EXAMPLES:
  scripts/policy_test.sh
  scripts/policy_test.sh --parallel auto --cov-threshold 80 --retry 2
  scripts/policy_test.sh --no-lint --typecheck --security -- --k "not slow"
EOF
}

#---------------------------------------
# Trap for diagnostics
#---------------------------------------
on_exit() {
  local ec=$?
  if (( ec != 0 )); then
    err "Exited with code ${ec}"
  fi
}
trap on_exit EXIT

#---------------------------------------
# Parse args
#---------------------------------------
args=()
while (( "$#" )); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -q|--quiet) VERBOSE=false; PYTEST_ARGS+=" -q"; shift ;;
    -v|--verbose) VERBOSE=true; shift ;;
    --no-color) COLOR=false; shift ;;
    --fail-fast) FAIL_FAST=true; shift ;;
    --no-lint) LINT_ENABLE=false; shift ;;
    --typecheck) TYPECHECK_ENABLE=true; shift ;;
    --security) SECURITY_ENABLE=true; shift ;;
    --no-cov) COVERAGE_ENABLE=false; shift ;;
    --cov-threshold) COV_FAIL_UNDER="${2}"; shift 2 ;;
    --parallel) PYTEST_PARALLEL="${2}"; shift 2 ;;
    --retry) PYTEST_RETRY="${2}"; shift 2 ;;
    --timeout) PYTEST_TIMEOUT="${2}"; shift 2 ;;
    --maxfail) PYTEST_MAXFAIL="${2}"; shift 2 ;;
    --reports) REPORT_DIR="${2}"; shift 2 ;;
    --junit) JUNIT_DIR="${2}"; shift 2 ;;
    --covdir) COV_DIR="${2}"; shift 2 ;;
    --python) PYTHON="${2}"; shift 2 ;;
    --pip) PIP="${2}"; shift 2 ;;
    --) shift; args+=("$@"); break ;;
    *) args+=("$1"); shift ;;
  esac
done

# Recompute derived paths after overrides
JUNIT_DIR="${JUNIT_DIR}"
COV_DIR="${COV_DIR}"
HTMLCOV_DIR="${HTMLCOV_DIR}"
COV_XML="${COV_XML}"

#---------------------------------------
# Sanity checks
#---------------------------------------
require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Required command not found: $1"
    exit 2
  fi
}
require_cmd "${PYTHON}"
require_cmd "${PIP}"

mkdir -p "${REPORT_DIR}" "${JUNIT_DIR}" "${COV_DIR}" "${HTMLCOV_DIR}"

#---------------------------------------
# Python environment detection (venv / Poetry / plain)
#---------------------------------------
activate_env() {
  if [[ -f "${PC_ROOT}/poetry.lock" ]] && command -v poetry >/dev/null 2>&1; then
    ok "Using Poetry environment"
    # shellcheck disable=SC1090
    poetry run true || { err "Poetry environment not ready"; exit 3; }
    export USE_POETRY=1
  elif [[ -f "${PC_ROOT}/.venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "${PC_ROOT}/.venv/bin/activate"
    ok "Using project .venv"
  elif [[ -n "${VIRTUAL_ENV:-}" ]]; then
    ok "Using existing virtualenv: ${VIRTUAL_ENV}"
  else
    warn "No virtualenv detected; using system interpreter ${PYTHON}"
  fi
}
activate_env

#---------------------------------------
# Tool availability
#---------------------------------------
has_py_module() {
  if [[ -n "${USE_POETRY:-}" ]]; then
    poetry run "${PYTHON}" - <<'PY' "$1" >/dev/null 2>&1 || return 1
import importlib, sys
sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 1)
PY
  else
    "${PYTHON}" - <<'PY' "$1" >/dev/null 2>&1 || return 1
import importlib, sys
sys.exit(0 if importlib.util.find_spec(sys.argv[1]) else 1)
PY
  fi
}

pyexec() {
  if [[ -n "${USE_POETRY:-}" ]]; then
    poetry run "${PYTHON}" "$@"
  else
    "${PYTHON}" "$@"
  fi
}
pytest_cmd() {
  if [[ -n "${USE_POETRY:-}" ]]; then
    poetry run pytest "$@"
  else
    pytest "$@"
  fi
}

#---------------------------------------
# Assemble pytest arguments
#---------------------------------------
build_pytest_args() {
  local -a pa
  pa+=("-ra" "--maxfail=${PYTEST_MAXFAIL}" "--durations=10")
  pa+=("--timeout=${PYTEST_TIMEOUT}") # requires pytest-timeout if present; otherwise ignored by pytest
  if [[ "${FAIL_FAST}" == "true" ]]; then
    pa+=("-x")
  fi

  # Parallelization if pytest-xdist present
  if has_py_module "xdist"; then
    if [[ "${PYTEST_PARALLEL}" == "auto" ]]; then
      pa+=("-n" "auto")
    elif [[ "${PYTEST_PARALLEL}" != "0" ]]; then
      pa+=("-n" "${PYTEST_PARALLEL}")
    fi
  else
    [[ "${PYTEST_PARALLEL}" != "0" ]] && warn "pytest-xdist not available; running serial"
  fi

  # Retries for flaky tests if plugin present
  if (( PYTEST_RETRY > 0 )); then
    if has_py_module "pytest_rerunfailures"; then
      pa+=("--reruns" "${PYTEST_RETRY}" "--reruns-delay" "2")
    else
      warn "pytest-rerunfailures not available; ignoring --retry"
    fi
  fi

  # Coverage
  if [[ "${COVERAGE_ENABLE}" == "true" ]]; then
    if has_py_module "coverage"; then
      pa+=("--cov=policy_core" "--cov-report=term-missing" "--cov-report=xml:${COV_XML}" "--cov-report=html:${HTMLCOV_DIR}")
      if (( COV_FAIL_UNDER > 0 )); then
        pa+=("--cov-fail-under=${COV_FAIL_UNDER}")
      fi
    else
      warn "coverage/pytest-cov not available; skipping coverage"
    fi
  fi

  # JUnit XML
  pa+=("--junitxml=${JUNIT_DIR}/junit.xml")

  # Human-friendly defaults
  pa+=("policy-core/tests")

  # Extra user args
  if [[ -n "${PYTEST_ARGS}" ]]; then
    # shellcheck disable=SC2206
    pa+=(${PYTEST_ARGS})
  fi
  if [[ "${#args[@]}" -gt 0 ]]; then
    pa+=("${args[@]}")
  fi

  printf '%s\n' "${pa[@]}"
}

#---------------------------------------
# Lint / Type / Security
#---------------------------------------
run_ruff() {
  if [[ "${LINT_ENABLE}" != "true" ]]; then
    warn "Lint disabled by flag"
    return 0
  fi
  if has_py_module "ruff"; then
    ok "Running ruff"
    if [[ -n "${USE_POETRY:-}" ]]; then
      poetry run ruff check policy-core
    else
      ruff check policy-core
    fi
  else
    warn "ruff not available; skipping lint"
  fi
}
run_mypy() {
  if [[ "${TYPECHECK_ENABLE}" != "true" ]]; then
    return 0
  fi
  if has_py_module "mypy"; then
    ok "Running mypy"
    if [[ -n "${USE_POETRY:-}" ]]; then
      poetry run mypy policy-core
    else
      mypy policy-core
    fi
  else
    warn "mypy not available; skipping typecheck"
  fi
}
run_bandit() {
  if [[ "${SECURITY_ENABLE}" != "true" ]]; then
    return 0
  fi
  if has_py_module "bandit"; then
    ok "Running bandit"
    if [[ -n "${USE_POETRY:-}" ]]; then
      poetry run bandit -q -r policy-core -f junit -o "${JUNIT_DIR}/bandit.xml" || {
        err "bandit found issues"
        return 5
      }
    else
      bandit -q -r policy-core -f junit -o "${JUNIT_DIR}/bandit.xml" || {
        err "bandit found issues"
        return 5
      }
    fi
  else
    warn "bandit not available; skipping security scan"
  fi
}

#---------------------------------------
# Main
#---------------------------------------
main() {
  log "Root: ${PC_ROOT}"
  log "Reports: ${REPORT_DIR}"
  [[ "${VERBOSE}" == "true" ]] && set -x

  run_ruff
  run_mypy
  run_bandit

  mapfile -t PA < <(build_pytest_args)
  ok "pytest args: ${PA[*]}"

  if [[ -n "${USE_POETRY:-}" ]]; then
    poetry run pytest "${PA[@]}"
  else
    pytest "${PA[@]}"
  fi

  ok "Reports:"
  printf "  JUnit: %s\n  Coverage XML: %s\n  Coverage HTML: %s\n" "${JUNIT_DIR}/junit.xml" "${COV_XML}" "${HTMLCOV_DIR}"
}

main "$@"
