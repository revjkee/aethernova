#!/usr/bin/env bash
# filepath: automation-core/scripts/typecheck.sh
# Purpose : Industrial-grade Python type-check entrypoint for CI and local runs.
# Features: mypy + (optional) pyright, git-changed mode, uvx/npx isolation, caching, strict flags.
#
# Usage:
#   ./scripts/typecheck.sh [--paths "src tests"] [--no-mypy] [--pyright] [--no-pyright] \
#       [--changed] [--base-ref origin/main] [--install-types] [--max-workers N] [--strict]
#
# Env (examples):
#   USE_UV=1                # prefer uvx for Python tools
#   PYRIGHT_ENABLE=1        # enable pyright (default off; set --pyright to force)
#   MYPY_CACHE_DIR=.mypy_cache
#   TYPECHECK_EXCLUDE='(^|/)(\.venv|\.tox|dist|build|node_modules|__pycache__|.*/generated/)'
#   GIT_DIFF_FILTER=ACMRTUXB
#
# References (authoritative):
# - mypy reads config from mypy.ini/.mypy.ini/pyproject.toml/setup.cfg; --config-file overrides. :contentReference[oaicite:1]{index=1}
# - mypy and installed packages / PEP 561 type stubs; --install-types for missing stubs. :contentReference[oaicite:2]{index=2}
# - PEP 561 distributing & packaging type information. :contentReference[oaicite:3]{index=3}
# - Pyright CLI & config file (pyrightconfig.json). :contentReference[oaicite:4]{index=4}
# - Getting started with Pyright (include/commit config). :contentReference[oaicite:5]{index=5}
# - uvx runs tools in disposable envs (alias of `uv tool run`). :contentReference[oaicite:6]{index=6}
# - npx runs package binaries one-off. :contentReference[oaicite:7]{index=7}

set -Eeuo pipefail

# ---------- logging ----------
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf '%s [%s] %s\n' "$(ts)" "$1" "${*:2}"; }
die() { log "ERROR" "$*"; exit 1; }
on_exit() { rc=$?; if [[ $rc -ne 0 ]]; then log "ERROR" "typecheck failed with code $rc"; else log "INFO" "typecheck OK"; fi; }
trap on_exit EXIT

# ---------- defaults ----------
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[[ -z "${ROOT}" ]] && ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PATHS_DEFAULT="src tests"
PATHS="$PATHS_DEFAULT"
RUN_MYPY=1
RUN_PYRIGHT=${PYRIGHT_ENABLE:-0}
CHANGED_ONLY=0
BASE_REF="origin/main"
INSTALL_TYPES=0
STRICT_MODE=0
MAX_WORKERS=""
EXCLUDE_REGEX="${TYPECHECK_EXCLUDE:-'(^|/)(\.venv|\.tox|dist|build|node_modules|__pycache__|.*/generated/)'}"
MYPY_CACHE="${MYPY_CACHE_DIR:-.mypy_cache}"

# ---------- args ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --paths)           PATHS="$2"; shift 2;;
    --no-mypy)         RUN_MYPY=0; shift;;
    --pyright)         RUN_PYRIGHT=1; shift;;
    --no-pyright)      RUN_PYRIGHT=0; shift;;
    --changed)         CHANGED_ONLY=1; shift;;
    --base-ref)        BASE_REF="$2"; shift 2;;
    --install-types)   INSTALL_TYPES=1; shift;;
    --strict)          STRICT_MODE=1; shift;;
    --max-workers)     MAX_WORKERS="$2"; shift 2;;
    -h|--help)
      cat <<EOF
Usage: $0 [options]
  --paths "src tests"     Space-separated include roots (default: "$PATHS_DEFAULT")
  --no-mypy               Disable mypy
  --pyright|--no-pyright  Enable/disable pyright (default: disabled)
  --changed               Check only changed *.py files vs --base-ref (git)
  --base-ref BRANCH       Git base (default: origin/main)
  --install-types         Allow mypy to auto-install missing PEP 561 stubs (network)
  --strict                Add stricter defaults for mypy/pyright
  --max-workers N         Hint worker parallelism for tools that support it
EOF
      exit 0;;
    *) die "Unknown arg: $1";;
  esac
done

# ---------- tool runners ----------
have() { command -v "$1" >/dev/null 2>&1; }

# Prefer uvx for Python tools (isolated, cached env)
run_mypy_cmd() {
  if [[ "${USE_UV:-1}" -eq 1 ]] && have uvx; then
    printf 'uvx mypy@latest'
  elif have mypy; then
    printf 'mypy'
  else
    # fallback: python -m mypy if installed in venv
    printf 'python -m mypy'
  fi
}

# Pyright (Node tool). Prefer native 'pyright', then 'npx pyright'.
run_pyright_cmd() {
  if have pyright; then
    printf 'pyright'
  elif have npx; then
    printf 'npx --yes pyright'
  else
    printf ''  # not available
  fi
}

# ---------- discover targets ----------
collect_changed_py() {
  local base="${1:-$BASE_REF}"
  local filter="${GIT_DIFF_FILTER:-ACMRTUXB}"
  git fetch --quiet --all || true
  git diff --name-only --diff-filter="$filter" "$base"... -- '*.py' \
    | grep -E '\.py$' || true
}

if [[ $CHANGED_ONLY -eq 1 ]]; then
  mapfile -t FILES < <(collect_changed_py "$BASE_REF")
  if [[ ${#FILES[@]} -eq 0 ]]; then
    log "INFO" "no changed Python files vs $BASE_REF; nothing to check"
    exit 0
  fi
  TARGETS=("${FILES[@]}")
else
  # Expand provided paths into file globs for mypy/pyright
  read -r -a TARGETS <<<"$PATHS"
fi

# ---------- mypy ----------
run_mypy() {
  [[ $RUN_MYPY -eq 1 ]] || { log "INFO" "mypy disabled"; return 0; }

  local cmd; cmd="$(run_mypy_cmd)" || true
  [[ -z "$cmd" ]] && die "mypy not found (try installing or set USE_UV=1 with uvx)"

  local args=()
  args+=(--pretty --show-error-codes --cache-dir "$MYPY_CACHE" --exclude "$EXCLUDE_REGEX")
  [[ $STRICT_MODE -eq 1 ]] && args+=(--strict)
  [[ -n "$MAX_WORKERS" ]] && args+=(--threads "$MAX_WORKERS")

  # Respect existing config in mypy.ini/.mypy.ini/pyproject.toml/setup.cfg by default (mypy does this).
  # Optionally allow auto-install missing types (network).
  if [[ $INSTALL_TYPES -eq 1 ]]; then
    args+=(--install-types --non-interactive)
  fi

  log "INFO" "Running: $cmd ${args[*]} ${TARGETS[*]}"
  # shellcheck disable=SC2086
  eval "$cmd" "${args[@]}" "${TARGETS[@]}"
}

# ---------- pyright ----------
run_pyright() {
  [[ $RUN_PYRIGHT -eq 1 ]] || { log "INFO" "pyright disabled"; return 0; }

  local cmd; cmd="$(run_pyright_cmd)" || true
  [[ -z "$cmd" ]] && die "pyright not found (install or enable npx)"

  local args=()
  # If pyrightconfig.json exists, pyright will use it; otherwise pass target paths explicitly.
  [[ $STRICT_MODE -eq 1 ]] && args+=(--level error)

  # pyright doesn't support a cache-dir flag; it's fast by design.
  log "INFO" "Running: $cmd ${args[*]} ${TARGETS[*]}"
  # shellcheck disable=SC2086
  eval "$cmd" "${args[@]}" "${TARGETS[@]}"
}

# ---------- main ----------
log "INFO" "project root: $ROOT"
log "INFO" "targets: ${TARGETS[*]:-<empty>}"
log "INFO" "mypy: ${RUN_MYPY}, pyright: ${RUN_PYRIGHT}, changed-only: ${CHANGED_ONLY}, strict: ${STRICT_MODE}"

rc=0
if ! run_mypy;   then rc=1; fi
if ! run_pyright; then rc=1; fi
exit "$rc"
