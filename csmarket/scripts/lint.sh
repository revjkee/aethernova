#!/usr/bin/env bash
# csmarket/scripts/lint.sh
# Industrial lint pipeline for Python monorepo/module.
# Runs fast, deterministic checks with strict error handling.

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SCRIPT_NAME="lint.sh"

die() {
  printf '%s\n' "ERROR: $*" >&2
  exit 1
}

note() {
  printf '%s\n' "INFO: $*"
}

warn() {
  printf '%s\n' "WARN: $*" >&2
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Best-effort project root resolution:
# 1) git root if available
# 2) parent of scripts directory
resolve_root() {
  local script_dir
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  if has_cmd git; then
    if git -C "$script_dir" rev-parse --show-toplevel >/dev/null 2>&1; then
      git -C "$script_dir" rev-parse --show-toplevel
      return 0
    fi
  fi
  # Fallback: assume scripts/ is under project root
  cd -- "$script_dir/.." && pwd -P
}

ROOT_DIR="$(resolve_root)"
cd -- "$ROOT_DIR"

# Defaults (override via env):
# LINT_TARGETS: what to lint (space-separated)
# LINT_FAIL_FAST: if "1" stop at first failure, else run all and summarize
# LINT_MYPY: "1" enable mypy if installed (default: 1)
# LINT_BANDIT: "1" enable bandit if installed (default: 0)
# LINT_PIP_AUDIT: "1" enable pip-audit if installed (default: 0)
# LINT_RUFF: "1" enable ruff if installed (default: 1)
# LINT_RUFF_FORMAT: "1" enable ruff format check (default: 1)

LINT_TARGETS="${LINT_TARGETS:-app tests}"
LINT_FAIL_FAST="${LINT_FAIL_FAST:-0}"

LINT_RUFF="${LINT_RUFF:-1}"
LINT_RUFF_FORMAT="${LINT_RUFF_FORMAT:-1}"
LINT_MYPY="${LINT_MYPY:-1}"
LINT_BANDIT="${LINT_BANDIT:-0}"
LINT_PIP_AUDIT="${LINT_PIP_AUDIT:-0}"

# Ensure targets exist; if not, shrink list to existing paths to avoid false negatives.
filter_existing_targets() {
  local out=()
  local t
  for t in $LINT_TARGETS; do
    if [[ -e "$t" ]]; then
      out+=("$t")
    fi
  done
  if [[ ${#out[@]} -eq 0 ]]; then
    # Fallback: current directory
    out=(".")
  fi
  printf '%s\n' "${out[@]}"
}

mapfile -t TARGETS < <(filter_existing_targets)

note "Project root: $ROOT_DIR"
note "Targets: ${TARGETS[*]}"

# Track failures without losing full output
FAILURES=0

run_step() {
  local name="$1"
  shift
  note "Running: $name"
  if "$@"; then
    note "OK: $name"
    return 0
  fi
  warn "FAILED: $name"
  FAILURES=$((FAILURES + 1))
  if [[ "$LINT_FAIL_FAST" == "1" ]]; then
    exit 1
  fi
  return 1
}

# Prefer python -m for tools when possible to ensure venv resolution.
PYTHON_BIN="${PYTHON_BIN:-python}"

if ! has_cmd "$PYTHON_BIN"; then
  die "python not found in PATH. Set PYTHON_BIN to a valid python executable."
fi

# ruff (lint + format)
if [[ "$LINT_RUFF" == "1" ]]; then
  if has_cmd ruff; then
    run_step "ruff check" ruff check --config ruff.toml "${TARGETS[@]}" || true
  else
    # If ruff is available as module but not command
    if "$PYTHON_BIN" -c "import ruff" >/dev/null 2>&1; then
      run_step "python -m ruff check" "$PYTHON_BIN" -m ruff check --config ruff.toml "${TARGETS[@]}" || true
    else
      warn "ruff not installed; skipping ruff checks."
      FAILURES=$((FAILURES + 1))
      if [[ "$LINT_FAIL_FAST" == "1" ]]; then
        exit 1
      fi
    fi
  fi

  if [[ "$LINT_RUFF_FORMAT" == "1" ]]; then
    if has_cmd ruff; then
      run_step "ruff format --check" ruff format --config ruff.toml --check "${TARGETS[@]}" || true
    else
      if "$PYTHON_BIN" -c "import ruff" >/dev/null 2>&1; then
        run_step "python -m ruff format --check" "$PYTHON_BIN" -m ruff format --config ruff.toml --check "${TARGETS[@]}" || true
      else
        warn "ruff not installed; skipping format check."
        FAILURES=$((FAILURES + 1))
        if [[ "$LINT_FAIL_FAST" == "1" ]]; then
          exit 1
        fi
      fi
    fi
  fi
fi

# mypy
if [[ "$LINT_MYPY" == "1" ]]; then
  if has_cmd mypy; then
    run_step "mypy" mypy --config-file mypy.ini "${TARGETS[@]}" || true
  else
    if "$PYTHON_BIN" -c "import mypy" >/dev/null 2>&1; then
      run_step "python -m mypy" "$PYTHON_BIN" -m mypy --config-file mypy.ini "${TARGETS[@]}" || true
    else
      warn "mypy not installed; skipping mypy."
    fi
  fi
fi

# bandit (optional, off by default)
if [[ "$LINT_BANDIT" == "1" ]]; then
  if has_cmd bandit; then
    # -q reduces noise; -r recursive; -ll low confidence included can be too noisy, so default to medium/high
    run_step "bandit" bandit -q -r "${TARGETS[@]}" || true
  else
    if "$PYTHON_BIN" -c "import bandit" >/dev/null 2>&1; then
      run_step "python -m bandit" "$PYTHON_BIN" -m bandit -q -r "${TARGETS[@]}" || true
    else
      warn "bandit not installed; skipping bandit."
    fi
  fi
fi

# pip-audit (optional, off by default)
if [[ "$LINT_PIP_AUDIT" == "1" ]]; then
  if has_cmd pip-audit; then
    # If requirements are managed by pyproject, pip-audit still works in installed environment.
    run_step "pip-audit" pip-audit || true
  else
    if "$PYTHON_BIN" -c "import pip_audit" >/dev/null 2>&1; then
      run_step "python -m pip_audit" "$PYTHON_BIN" -m pip_audit || true
    else
      warn "pip-audit not installed; skipping pip-audit."
    fi
  fi
fi

if [[ "$FAILURES" -eq 0 ]]; then
  note "Lint: success"
  exit 0
fi

warn "Lint: failed steps: $FAILURES"
exit 1
