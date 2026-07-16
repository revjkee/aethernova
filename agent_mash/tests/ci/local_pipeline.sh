#!/usr/bin/env bash
# agent_mash/tests/ci/local_pipeline.sh
#
# Local CI pipeline for agent_mash project.
# This script is intended to mirror CI behavior as closely as possible.
#
# Requirements:
#   - bash 4+
#   - python 3.10+
#   - pip
#
# Usage:
#   ./local_pipeline.sh
#
# Exit codes:
#   0  success
#   >0 failure at some pipeline stage

set -Eeuo pipefail
IFS=$'\n\t'

#######################################
# Configuration
#######################################

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR=".venv-ci"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

REQ_MAIN="requirements.txt"
REQ_DEV="requirements-dev.txt"

#######################################
# Helpers
#######################################

log() {
  printf '[CI] %s\n' "$1"
}

fail() {
  printf '[CI][ERROR] %s\n' "$1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

#######################################
# Preflight checks
#######################################

log "Starting local CI pipeline"
log "Project root: ${PROJECT_ROOT}"

require_cmd "${PYTHON_BIN}"
require_cmd pip

"${PYTHON_BIN}" --version || fail "Python is not available"

#######################################
# Virtual environment
#######################################

log "Preparing virtual environment: ${VENV_DIR}"

if [ -d "${VENV_DIR}" ]; then
  log "Removing existing virtual environment"
  rm -rf "${VENV_DIR}"
fi

"${PYTHON_BIN}" -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

pip install --upgrade pip setuptools wheel

#######################################
# Dependency installation
#######################################

if [ -f "${PROJECT_ROOT}/${REQ_MAIN}" ]; then
  log "Installing main dependencies"
  pip install -r "${PROJECT_ROOT}/${REQ_MAIN}"
else
  log "Main requirements file not found, skipping"
fi

if [ -f "${PROJECT_ROOT}/${REQ_DEV}" ]; then
  log "Installing development dependencies"
  pip install -r "${PROJECT_ROOT}/${REQ_DEV}"
else
  log "Development requirements file not found, skipping"
fi

#######################################
# Formatting and linting
#######################################

if command -v black >/dev/null 2>&1; then
  log "Running black (check mode)"
  black --check "${PROJECT_ROOT}" || fail "Black formatting check failed"
else
  log "Black not installed, skipping"
fi

if command -v ruff >/dev/null 2>&1; then
  log "Running ruff"
  ruff check "${PROJECT_ROOT}" || fail "Ruff linting failed"
else
  log "Ruff not installed, skipping"
fi

#######################################
# Static type checking
#######################################

if command -v mypy >/dev/null 2>&1; then
  log "Running mypy"
  mypy "${PROJECT_ROOT}" || fail "Mypy type checking failed"
else
  log "Mypy not installed, skipping"
fi

#######################################
# Tests
#######################################

require_cmd pytest

log "Running unit tests"
pytest "${PROJECT_ROOT}/agent_mash/tests/unit" || fail "Unit tests failed"

log "Running compliance tests"
pytest "${PROJECT_ROOT}/agent_mash/tests/compliance" || fail "Compliance tests failed"

#######################################
# Test data validation
#######################################

log "Validating test_data directory integrity"

TEST_DATA_DIR="${PROJECT_ROOT}/agent_mash/tests/test_data"

if [ ! -d "${TEST_DATA_DIR}" ]; then
  fail "test_data directory not found"
fi

# Check that all referenced input_json files exist
if command -v yq >/dev/null 2>&1; then
  log "Checking YAML meta files with yq"
  while IFS= read -r meta; do
    yq '.cases[].input_json' "${meta}" | while IFS= read -r path; do
      [ -z "${path}" ] && continue
      full_path="$(cd "$(dirname "${meta}")" && realpath "${path}")"
      [ -f "${full_path}" ] || fail "Referenced input JSON not found: ${full_path}"
    done
  done < <(find "${TEST_DATA_DIR}" -name "cases.yaml")
else
  log "yq not installed, skipping deep meta validation"
fi

#######################################
# Cleanup
#######################################

log "Local CI pipeline completed successfully"
exit 0
