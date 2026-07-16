#!/usr/bin/env bash
# scripts/fmt.sh
#
# Industrial formatter for Python repo:
# - Deterministic, strict bash
# - Uses Ruff formatter + autofix for lint rules
# - Optional mypy run
#
# Exit codes:
#   0  success
#   2  usage / arguments
#  10  missing required tool(s)
#  11  repo root not found
#  12  no Python files found (nothing to do)
#  20  formatting failed
#  21  autofix failed
#  22  mypy failed

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# ---------- logging ----------
log()  { printf '%s\n' "$*"; }
err()  { printf '%s\n' "$*" >&2; }
die()  { err "$1"; exit "${2:-1}"; }

# ---------- helpers ----------
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<'USAGE'
Usage:
  scripts/fmt.sh [--check] [--mypy] [--path PATH] [--no-fix] [--quiet]

Options:
  --check        Do not modify files; fail if changes would be made.
  --mypy         Run mypy after formatting (if installed).
  --path PATH    Format only a subpath (default: repo root).
  --no-fix       Do not run ruff autofix (only formatting).
  --quiet        Reduce output.
  -h, --help     Show help.

Examples:
  scripts/fmt.sh
  scripts/fmt.sh --check
  scripts/fmt.sh --path app
  scripts/fmt.sh --mypy
USAGE
}

# ---------- repo root detection ----------
# Priority:
# 1) git root if inside a git repo
# 2) climb up looking for pyproject.toml
detect_root() {
  local root=""
  if have git; then
    if root="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
      printf '%s\n' "$root"
      return 0
    fi
  fi

  local d="$SCRIPT_DIR"
  while [[ "$d" != "/" ]]; do
    if [[ -f "$d/pyproject.toml" ]]; then
      printf '%s\n' "$d"
      return 0
    fi
    d="$(dirname "$d")"
  done
  return 1
}

# ---------- arguments ----------
CHECK_MODE="0"
RUN_MYPY="0"
TARGET_PATH=""
NO_FIX="0"
QUIET="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK_MODE="1"; shift ;;
    --mypy) RUN_MYPY="1"; shift ;;
    --path)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      TARGET_PATH="$2"; shift 2
      ;;
    --no-fix) NO_FIX="1"; shift ;;
    --quiet) QUIET="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      err "Unknown argument: $1"
      usage >&2
      exit 2
      ;;
  esac
done

# ---------- locate repo ----------
REPO_ROOT="$(detect_root || true)"
[[ -n "$REPO_ROOT" ]] || die "Repo root not found (no git root and no pyproject.toml upward from scripts/)." 11

if [[ -z "$TARGET_PATH" ]]; then
  TARGET_ABS="$REPO_ROOT"
else
  # Allow relative to repo root, or absolute path
  if [[ "$TARGET_PATH" = /* ]]; then
    TARGET_ABS="$TARGET_PATH"
  else
    TARGET_ABS="$REPO_ROOT/$TARGET_PATH"
  fi
fi

[[ -e "$TARGET_ABS" ]] || die "Target path does not exist: $TARGET_ABS" 2

# ---------- tools ----------
# Ruff is the single required tool. Everything else is optional.
have ruff || die "Missing required tool: ruff. Install it in your environment before running this script." 10

# ---------- discover python files (fast fail for empty targets) ----------
# This avoids "success" doing nothing in CI when path is wrong.
PY_COUNT="0"
if [[ -d "$TARGET_ABS" ]]; then
  # Find .py and also consider pyproject-driven formatting. We count .py for safety.
  # Exclude common heavy dirs.
  while IFS= read -r -d '' _; do
    PY_COUNT="$((PY_COUNT + 1))"
    # Early stop after 1 file
    [[ "$PY_COUNT" -ge 1 ]] && break
  done < <(find "$TARGET_ABS" \
      -type d \( -name .git -o -name .venv -o -name venv -o -name __pycache__ -o -name .mypy_cache -o -name .ruff_cache -o -name node_modules -o -name dist -o -name build \) -prune -false \
      -o -type f -name "*.py" -print0 2>/dev/null)
else
  # Single file
  if [[ "$TARGET_ABS" == *.py ]]; then PY_COUNT="1"; fi
fi

if [[ "$PY_COUNT" -eq 0 ]]; then
  die "No Python files found under: $TARGET_ABS" 12
fi

# ---------- run ----------
cd -- "$REPO_ROOT"

# Respect --quiet
if [[ "$QUIET" -eq 1 ]]; then
  RUFF_QUIET=(--quiet)
else
  RUFF_QUIET=()
fi

# Ruff format
# In check mode: --check
if [[ "$CHECK_MODE" -eq 1 ]]; then
  if ! ruff format "${RUFF_QUIET[@]}" --check -- "$TARGET_ABS"; then
    die "Formatting check failed (ruff format --check)." 20
  fi
else
  if ! ruff format "${RUFF_QUIET[@]}" -- "$TARGET_ABS"; then
    die "Formatting failed (ruff format)." 20
  fi
fi

# Ruff autofix lint (optional)
if [[ "$NO_FIX" -eq 0 ]]; then
  # In check mode: do not apply fixes; just verify lint is clean per configured rules.
  if [[ "$CHECK_MODE" -eq 1 ]]; then
    if ! ruff check "${RUFF_QUIET[@]}" -- "$TARGET_ABS"; then
      die "Lint check failed (ruff check)." 21
    fi
  else
    # Apply safe fixes. If your config enables unsafe fixes, control it in ruff config.
    if ! ruff check "${RUFF_QUIET[@]}" --fix -- "$TARGET_ABS"; then
      die "Autofix failed (ruff check --fix)." 21
    fi
  fi
fi

# Optional mypy
if [[ "$RUN_MYPY" -eq 1 ]]; then
  if have mypy; then
    # mypy configuration is expected in mypy.ini / pyproject.toml
    if ! mypy -- "$TARGET_ABS"; then
      die "mypy failed." 22
    fi
  else
    die "Requested --mypy, but mypy is not installed." 10
  fi
fi

exit 0
