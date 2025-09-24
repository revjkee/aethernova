#!/usr/bin/env bash
# automation-core/scripts/format.sh
# Industrial-grade multi-language formatter orchestrator.
# Safe-by-default: uses git to select files; only runs tools that are available.

set -Eeuo pipefail
IFS=$'\n\t'

# ---------------------------
# Utilities
# ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# Find git root or fallback to repo root guess (two levels up from automation-core/scripts)
find_git_root() {
  if git_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    printf '%s\n' "$git_root"
  else
    printf '%s\n' "$(cd "$SCRIPT_DIR/../.." && pwd)"
  fi
}
ROOT="$(find_git_root)"
cd "$ROOT"

readonly RESET=$'\033[0m'
readonly DIM=$'\033[2m'
readonly BOLD=$'\033[1m'
readonly RED=$'\033[31m'
readonly GREEN=$'\033[32m'
readonly YELLOW=$'\033[33m'
readonly BLUE=$'\033[34m'

log() { printf '%s[%s]%s %s\n' "$DIM" "${1}" "$RESET" "${*:2}"; }
ok()  { printf '%s[OK]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn(){ printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*"; }
err() { printf '%s[ERR]%s %s\n' "$RED" "$RESET" "$*" >&2; }
die(){ err "$*"; exit 1; }

have() { command -v "$1" &>/dev/null; }
jobs_default() {
  if have nproc; then nproc; elif have sysctl; then sysctl -n hw.ncpu 2>/dev/null || echo 4; else echo 4; fi
}

trap 'err "Interrupted"; exit 130' INT

# ---------------------------
# Defaults & CLI
# ---------------------------
MODE="changed"   # changed|staged|all|since
CHECK=0          # 1 to check-only
SINCE_REF=""     # e.g. origin/main
JOBS="$(jobs_default)"
VERBOSE=0
RESTAGE=0        # restage modified files when --staged
GIT_SELECT=1     # set to 0 to scan filesystem (rarely needed)

usage() {
  cat <<EOF
Usage: $0 [options] [-- <path>...]
  Selection (mutually exclusive):
    --all                  Format all tracked files
    --staged               Format only staged files; re-stage updated files
    --since <ref>          Format files changed since <ref> (e.g., origin/main)
    --changed              Format modified & untracked files (default)

  Behavior:
    --check                Check only (no writes); exit non-zero on diffs
    --jobs <N>             Parallel jobs for per-file tools (default: $JOBS)
    --no-git               Do not use git to select files (scan tree)
    --verbose              Verbose logging

Examples:
  $0 --all
  $0 --staged --check
  $0 --since origin/main
  $0 --changed -- --packages/app
EOF
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) MODE="all";;
    --staged) MODE="staged"; RESTAGE=1;;
    --since) MODE="since"; SINCE_REF="${2:-}"; shift;;
    --changed) MODE="changed";;
    --check) CHECK=1;;
    --jobs) JOBS="${2:-}"; shift;;
    --no-git) GIT_SELECT=0;;
    --verbose) VERBOSE=1;;
    -h|--help) usage; exit 0;;
    --) shift; ARGS+=("$@"); break;;
    *) ARGS+=("$1");;
  esac
  shift
done

[[ "$MODE" == "since" && -z "$SINCE_REF" ]] && die "--since requires a ref (e.g., --since origin/main)"

# ---------------------------
# File selection (git-aware)
# ---------------------------
git_ls() {
  local spec="$1"
  shift || true
  # Always produce NUL-delimited, respect .gitignore
  case "$spec" in
    all)
      git ls-files -z --cached --others --exclude-standard -- "${@:-.}"
      ;;
    changed)
      {
        git ls-files -z --modified --others --exclude-standard -- "${@:-.}" || true
      }
      ;;
    staged)
      git diff --name-only -z --cached -- "${@:-.}"
      ;;
    since)
      git diff --name-only -z "$SINCE_REF"... -- "${@:-.}"
      ;;
  esac
}

scan_fs() {
  # Fallback: find under provided paths or repo root; filter via extensions later
  local roots=("${@:-.}")
  find "${roots[@]}" -type f -print0
}

select_files() {
  local mode="$1"; shift || true
  local paths=("$@")
  if [[ "$GIT_SELECT" -eq 1 ]] && have git && git rev-parse --is-inside-work-tree &>/dev/null; then
    git_ls "$mode" "${paths[@]}"
  else
    scan_fs "${paths[@]}"
  fi
}

# ---------------------------
# Buckets by extension
# ---------------------------
# Use associative arrays for buckets: ext -> files
declare -A BUCKET
add_to_bucket() {
  local key="$1"; local file="$2"
  BUCKET["$key"]+="$file"$'\0'
}

EXT_MATCH() {
  # map extensions to logical keys
  local f="$1"
  case "${f,,}" in
    *.sh) echo "sh";;
    *.bash) echo "sh";;
    *.zsh) echo "sh";;
    *.py) echo "py";;
    *.ts) echo "ts";;
    *.tsx) echo "ts";;
    *.js) echo "js";;
    *.jsx) echo "js";;
    *.json) echo "json";;
    *.md) echo "md";;
    *.go) echo "go";;
    *.tf) echo "tf";;
    *.proto) echo "proto";;
    *.yml|*.yaml) echo "yaml";;
    *.sql) echo "sql";;
    *.rs) echo "rust";;
    *.c|*.h|*.cc|*.cpp|*.hpp|*.hh) echo "cxx";;
    *.java) echo "java";;
    *.kt) echo "kotlin";;
    *.dart) echo "dart";;
    *.swift) echo "swift";;
    *.lua) echo "lua";;
    *.rb) echo "ruby";;
    *.php) echo "php";;
    *.dockerfile|dockerfile|*/*dockerfile) echo "docker";;
    *) echo ""; return 1;;
  esac
}

BUILD_BUCKETS() {
  while IFS= read -r -d '' f; do
    # Skip generated common dirs
    case "$f" in
      */node_modules/*|*/dist/*|*/build/*|*/out/*|*/.turbo/*|*/.next/*|*/.cache/*|*/vendor/*|*/.venv/*|*/venv/*|*/__pycache__/*|*/target/*|*/.git/*) continue;;
    esac
    key="$(EXT_MATCH "$f" || true)" || continue
    add_to_bucket "$key" "$f"
  done < <(select_files "$MODE" "${ARGS[@]}")
}

# ---------------------------
# Runner helpers
# ---------------------------
run_xargs() {
  local cmd=("$@")
  if [[ -z "$FILES" ]]; then return 0; fi
  if [[ "$VERBOSE" -eq 1 ]]; then
    log RUN "${cmd[*]}"
  fi
  # shellcheck disable=SC2086
  printf '%s\0' $FILES | xargs -0 -P "$JOBS" -n 50 "${cmd[@]}"
}

run_list() {
  local label="$1"; shift
  local need="$1"; shift
  if [[ -z "$FILES" ]]; then return 0; fi
  if [[ "$need" -eq 0 ]]; then
    warn "$label: tool not found; skipping"
    return 0
  fi
  "$@"
}

# ---------------------------
# Formatters per bucket
# ---------------------------
format_shell() {
  FILES="${BUCKET[sh]}"
  # shfmt
  if have shfmt; then
    local mode=("-w")
    [[ "$CHECK" -eq 1 ]] && mode=("-d")
    run_list "shfmt" 1 run_xargs shfmt -s -i 2 -ci "${mode[@]}"
  else
    warn "shfmt not found"
  fi
  # shellcheck (check-only)
  if have shellcheck; then
    run_list "shellcheck" 1 run_xargs shellcheck -x
  fi
}

format_python() {
  FILES="${BUCKET[py]}"
  if [[ -n "$FILES" ]]; then
    # Ruff (formatter + linter) preferred
    if have ruff; then
      if [[ "$CHECK" -eq 1 ]]; then
        run_xargs ruff format --check
        run_xargs ruff check
      else
        run_xargs ruff format
        run_xargs ruff check --fix
      fi
    else
      warn "ruff not found"
      if have black; then
        if [[ "$CHECK" -eq 1 ]]; then run_xargs black --check; else run_xargs black; fi
      fi
      if have isort; then
        if [[ "$CHECK" -eq 1 ]]; then run_xargs isort --check-only; else run_xargs isort; fi
      fi
    fi
  fi
}

format_js_ts() {
  local ts_files="${BUCKET[ts]}"
  local js_files="${BUCKET[js]}"
  local json_files="${BUCKET[json]}"
  local md_files="${BUCKET[md]}"
  local yaml_files="${BUCKET[yaml]}"

  FILES="$ts_files$js_files$json_files$md_files$yaml_files"
  if [[ -z "$FILES" ]]; then return 0; fi

  # Prefer Biome if available
  if have biome; then
    if [[ "$CHECK" -eq 1 ]]; then
      run_xargs biome check --diagnostic-format=github --no-errors-on-unmatched
    else
      run_xargs biome check --write --no-errors-on-unmatched
    fi
  else
    # Prettier
    if have prettier; then
      if [[ "$CHECK" -eq 1 ]]; then
        run_xargs prettier --check
      else
        run_xargs prettier --write
      fi
    fi
    # ESLint for JS/TS
    if have eslint; then
      FILES="$ts_files$js_files"
      if [[ -n "$FILES" ]]; then
        if [[ "$CHECK" -eq 1 ]]; then
          run_xargs eslint --max-warnings=0
        else
          run_xargs eslint --fix --max-warnings=0
        fi
      fi
    fi
  fi
}

format_go() {
  FILES="${BUCKET[go]}"
  if [[ -z "$FILES" ]]; then return 0; fi
  if have gofmt; then
    if [[ "$CHECK" -eq 1 ]]; then
      # gofmt: prints filenames on diff; normalize to non-zero exit if any
      if ! run_xargs gofmt -l -s >/dev/null; then true; fi
      diff_out="$(printf '%s\0' $FILES | xargs -0 -P "$JOBS" -n 50 gofmt -l -s)"
      if [[ -n "$diff_out" ]]; then
        printf '%s\n' "$diff_out" >&2
        return 1
      fi
    else
      run_xargs gofmt -w -s
    fi
  fi
  if have goimports; then
    if [[ "$CHECK" -eq 1 ]]; then
      diff_out="$(printf '%s\0' $FILES | xargs -0 -P "$JOBS" -n 50 goimports -l)"
      if [[ -n "$diff_out" ]]; then
        printf '%s\n' "$diff_out" >&2
        return 1
      fi
    else
      run_xargs goimports -w
    fi
  fi
}

format_cxx() {
  FILES="${BUCKET[cxx]}"
  if [[ -z "$FILES" ]]; then return 0; fi
  if have clang-format; then
    if [[ "$CHECK" -eq 1 ]]; then
      run_xargs clang-format --Werror --dry-run
    else
      run_xargs clang-format -i
    fi
  else
    warn "clang-format not found"
  fi
}

format_rust() {
  FILES="${BUCKET[rust]}"
  if [[ -z "$FILES" ]]; then return 0; fi
  if have cargo; then
    if [[ "$CHECK" -eq 1 ]]; then cargo fmt --all -- --check; else cargo fmt --all; fi
  elif have rustfmt; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs rustfmt --check; else run_xargs rustfmt; fi
  fi
}

format_tf() {
  FILES="${BUCKET[tf]}"
  if [[ -z "$FILES" ]]; then return 0; fi
  if have terraform; then
    if [[ "$CHECK" -eq 1 ]]; then
      terraform fmt -recursive -check
    else
      terraform fmt -recursive
    fi
  else
    warn "terraform not found"
  fi
}

format_proto() {
  FILES="${BUCKET[proto]}"
  if [[ -z "$FILES" ]]; then return 0; fi
  if have buf; then
    if [[ "$CHECK" -eq 1 ]]; then buf format --diff --exit-code; else buf format -w; fi
  elif have clang-format; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs clang-format --Werror --dry-run; else run_xargs clang-format -i; fi
  else
    warn "buf/clang-format not found for .proto"
  fi
}

format_yaml_md_misc() {
  # YAML lint/format (optional)
  FILES="${BUCKET[yaml]}"
  if [[ -n "$FILES" ]]; then
    if have yamlfmt; then
      if [[ "$CHECK" -eq 1 ]]; then run_xargs yamlfmt -lint; else run_xargs yamlfmt -w; fi
    fi
    if have yamllint; then
      run_xargs yamllint -f standard
    fi
  fi

  # Markdown lint (optional)
  FILES="${BUCKET[md]}"
  if [[ -n "$FILES" && "$CHECK" -eq 1 && have markdownlint ]] ; then
    run_xargs markdownlint
  elif [[ -n "$FILES" && have markdownlint ]] ; then
    run_xargs markdownlint --fix
  fi
}

format_sql() {
  FILES="${BUCKET[sql]}"
  if [[ -z "$FILES" ]]; then return 0; fi
  if have sqlfluff; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs sqlfluff lint; else run_xargs sqlfluff fix -f; fi
  elif have pg_format; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs pg_format --inplace --nogit 2>/dev/null || true; else run_xargs pg_format --inplace; fi
  else
    warn "sqlfluff/pg_format not found"
  fi
}

format_java_kotlin() {
  FILES="${BUCKET[java]}"
  if [[ -n "$FILES" && have google-java-format ]]; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs google-java-format --dry-run --set-exit-if-changed; else run_xargs google-java-format -i; fi
  fi
  FILES="${BUCKET[kotlin]}"
  if [[ -n "$FILES" && have ktlint ]]; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs ktlint --relative .; else run_xargs ktlint -F --relative .; fi
  fi
}

format_dart_swift_lua_ruby_php() {
  FILES="${BUCKET[dart]}"
  if [[ -n "$FILES" && have dart ]]; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs dart format -o none --set-exit-if-changed; else run_xargs dart format -o write; fi
  fi
  FILES="${BUCKET[swift]}"
  if [[ -n "$FILES" && have swiftformat ]]; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs swiftformat --lint; else run_xargs swiftformat --quiet; fi
  fi
  FILES="${BUCKET[lua]}"
  if [[ -n "$FILES" && have stylua ]]; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs stylua --check; else run_xargs stylua; fi
  fi
  FILES="${BUCKET[ruby]}"
  if [[ -n "$FILES" ]]; then
    if have standardrb; then
      if [[ "$CHECK" -eq 1 ]]; then run_xargs standardrb --lint; else run_xargs standardrb --fix; fi
    elif have rubocop; then
      if [[ "$CHECK" -eq 1 ]]; then run_xargs rubocop --parallel; else run_xargs rubocop -A --parallel; fi
    fi
  fi
  FILES="${BUCKET[php]}"
  if [[ -n "$FILES" && have php-cs-fixer ]]; then
    if [[ "$CHECK" -eq 1 ]]; then run_xargs php-cs-fixer fix --using-cache=no --dry-run --diff; else run_xargs php-cs-fixer fix --using-cache=no; fi
  fi
}

format_docker() {
  FILES="${BUCKET[docker]}"
  if [[ -z "$FILES" ]]; then return 0; fi
  if have hadolint; then
    run_xargs hadolint
  fi
  # No ubiquitous formatter; rely on Prettier for Dockerfile if configured by plugin, otherwise noop
}

# ---------------------------
# Build & run
# ---------------------------
BUILD_BUCKETS

RC=0
run_stage() {
  local name="$1"
  shift
  log "RUN" "$name"
  if ! "$@"; then
    RC=1
    err "$name failed"
  else
    ok "$name done"
  fi
}

run_stage "shell"          format_shell
run_stage "python"         format_python
run_stage "js/ts/json/md"  format_js_ts
run_stage "go"             format_go
run_stage "c/c++"          format_cxx
run_stage "rust"           format_rust
run_stage "terraform"      format_tf
run_stage "proto"          format_proto
run_stage "yaml/md lint"   format_yaml_md_misc
run_stage "sql"            format_sql
run_stage "java/kotlin"    format_java_kotlin
run_stage "dart/swift/lua/ruby/php" format_dart_swift_lua_ruby_php
run_stage "dockerfile"     format_docker

# Re-stage updated files if requested
if [[ "$RESTAGE" -eq 1 && "$CHECK" -eq 0 && have git && -n "$(git rev-parse --git-dir 2>/dev/null)" ]]; then
  log "GIT" "restaging updated files"
  git add -A
fi

if [[ "$RC" -eq 0 ]]; then
  ok "Formatting complete"
else
  err "Formatting completed with issues"
fi

exit "$RC"
