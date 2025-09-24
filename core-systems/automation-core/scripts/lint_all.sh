#!/usr/bin/env bash
# automation-core/scripts/lint_all.sh
# Industrial-grade multi-language lint runner with parallel execution and safe fallbacks.

set -Eeuo pipefail
IFS=$'\n\t'

# --------------------------------------------
# Defaults
# --------------------------------------------
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

MODE="all"              # all|changed|staged|since
SINCE_REF="origin/main" # used when MODE=since
FIX="false"             # --fix to auto-format where supported
FAIL_FAST="false"       # stop on first failure
CONCURRENCY="${CONCURRENCY:-$(command -v nproc >/dev/null 2>&1 && nproc || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
TIMEOUT_SECS="${TIMEOUT_SECS:-0}" # 0 = no timeout
FORMAT="rich"           # rich|plain|json
SELECT_TOOLS="auto"     # auto or comma-separated: python,js,yaml,json,md,shell,docker,tf,toml,gha
USE_DOCKER="false"      # optional dockerized runners if local tools missing

# --------------------------------------------
# CLI parse
# --------------------------------------------
usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Modes (choose one):
  --all                      Lint entire repository (default)
  --changed                  Lint files changed vs HEAD (unstaged)
  --staged                   Lint files staged in index
  --since <ref>              Lint files changed since <ref> (default: origin/main)

Behavior:
  --fix                      Auto-fix where supported
  --no-fix                   Disable any formatting
  --fail-fast                Stop on first failing tool
  --concurrency <N>          Parallelism for per-file checks (default: ${CONCURRENCY})
  --timeout <secs>           Global soft timeout (0 = no timeout)
  --format <rich|plain|json> Output style for summary (default: rich)
  --select <list|auto>       Comma list of tools: python,js,yaml,json,md,shell,docker,tf,toml,gha
  --docker                   Try docker images if local tool missing
  --no-docker                Do not use docker fallback

Examples:
  $0 --changed
  $0 --staged --fix
  $0 --since origin/develop --select python,js,yaml --concurrency 8
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) MODE="all"; shift;;
    --changed) MODE="changed"; shift;;
    --staged) MODE="staged"; shift;;
    --since) MODE="since"; SINCE_REF="${2:?}"; shift 2;;
    --fix) FIX="true"; shift;;
    --no-fix) FIX="false"; shift;;
    --fail-fast) FAIL_FAST="true"; shift;;
    --concurrency) CONCURRENCY="${2:?}"; shift 2;;
    --timeout) TIMEOUT_SECS="${2:?}"; shift 2;;
    --format) FORMAT="${2:?}"; shift 2;;
    --select) SELECT_TOOLS="${2:?}"; shift 2;;
    --docker) USE_DOCKER="true"; shift;;
    --no-docker) USE_DOCKER="false"; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2;;
  esac
done

# --------------------------------------------
# Logging & helpers
# --------------------------------------------
COLOR="true"
if [[ -t 1 ]]; then
  if [[ "${NO_COLOR:-}" == "1" ]]; then COLOR="false"; fi
else
  COLOR="false"
fi

color() { [[ "$COLOR" == "true" ]] || { shift; echo "$*"; return; }
  case "$1" in
    red) printf "\033[31m%s\033[0m" "$2";;
    green) printf "\033[32m%s\033[0m" "$2";;
    yellow) printf "\033[33m%s\033[0m" "$2";;
    blue) printf "\033[34m%s\033[0m" "$2";;
    *) printf "%s" "$2";;
  esac
}

log()      { printf "%s %s\n" "$(color blue "[lint]")" "$*"; }
log_warn() { printf "%s %s\n" "$(color yellow "[warn]")" "$*"; }
log_err()  { printf "%s %s\n" "$(color red "[fail]")" "$*"; }

die() { log_err "$*"; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Docker fallback runner (very conservative; only used if --docker and image present locally)
dockerrun() {
  local image="$1"; shift
  if [[ "$USE_DOCKER" != "true" ]]; then return 127; fi
  if ! docker image inspect "$image" >/dev/null 2>&1; then return 127; fi
  docker run --rm -v "$REPO_ROOT":"$REPO_ROOT" -w "$REPO_ROOT" "$image" "$@"
}

# Safe timeout wrapper if /usr/bin/timeout exists
run_with_timeout() {
  local secs="$1"; shift
  if [[ "$secs" -gt 0 && -x "/usr/bin/timeout" ]]; then
    /usr/bin/timeout --preserve-status "$secs" "$@"
  else
    "$@"
  fi
}

join_by() { local IFS="$1"; shift; echo "$*"; }

# --------------------------------------------
# File discovery
# --------------------------------------------
git_files_all()       { git ls-files -z | tr -d '\r' | xargs -0 -I{} echo "{}"; }
git_files_changed()   { git diff --name-only --diff-filter=ACMRTUXB HEAD -- . || true; }
git_files_staged()    { git diff --cached --name-only --diff-filter=ACMRTUXB -- . || true; }
git_files_since()     { git diff --name-only --diff-filter=ACMRTUXB "$SINCE_REF"...HEAD -- . || true; }

collect_files() {
  case "$MODE" in
    all) git_files_all;;
    changed) git_files_changed;;
    staged) git_files_staged;;
    since) git_files_since;;
  esac | awk 'NF' | sort -u
}

FILES="$(collect_files)"

# --------------------------------------------
# Buckets by type
# --------------------------------------------
bucket() { grep -E "$1" <<<"$FILES" || true; }

PY_FILES="$(bucket '\.py$')"
JS_FILES="$(bucket '\.(js|jsx|mjs|cjs|ts|tsx)$')"
YAML_FILES="$(bucket '\.(yml|yaml)$')"
JSON_FILES="$(bucket '\.json$')"
MD_FILES="$(bucket '\.(md|mdx)$')"
SH_FILES="$(bucket '\.(sh)$' && grep -vE '^vendor/|^node_modules/|^\.venv/|^\.tox/' <<<"$(bucket '\.sh$')" || true)"
DOCKERFILES="$(grep -E '(^|/)[Dd]ockerfile$' <<<"$FILES" || true)"
TF_FILES="$(bucket '\.tf$')"
TOML_FILES="$(bucket '\.toml$')"
GHA_FILES="$(grep -E '^\.github/workflows/.+\.ya?ml$' <<<"$FILES" || true)"

# --------------------------------------------
# Tool selection
# --------------------------------------------
tool_selected() {
  [[ "$SELECT_TOOLS" == "auto" ]] && return 0
  IFS=',' read -r -a sel <<<"$SELECT_TOOLS"
  local name="$1"
  for s in "${sel[@]}"; do [[ "$s" == "$name" ]] && return 0; done
  return 1
}

# --------------------------------------------
# Runners
# Each runner should return 0 on success, non-zero on failures.
# They must gracefully skip if no files or tool missing.
# --------------------------------------------

run_python() {
  tool_selected "python" || return 0
  [[ -n "$PY_FILES" ]] || { log "python: no files"; return 0; }

  local ok=0
  # ruff (lint)
  if have ruff; then
    log "python: ruff check"
    if ! run_with_timeout "$TIMEOUT_SECS" ruff check --exit-non-zero-on-fix ${FIX:+--fix} $(echo "$PY_FILES"); then ok=1; fi
  else
    log_warn "python: ruff not found; skipping lint"
  fi

  # format (ruff fmt or black)
  if [[ "$FIX" == "true" ]]; then
    if have ruff; then
      log "python: ruff format"
      if ! run_with_timeout "$TIMEOUT_SECS" ruff format $(echo "$PY_FILES"); then ok=1; fi
    elif have black; then
      log "python: black format"
      if ! run_with_timeout "$TIMEOUT_SECS" black $(echo "$PY_FILES"); then ok=1; fi
    fi
  else
    if have black; then
      log "python: black --check"
      if ! run_with_timeout "$TIMEOUT_SECS" black --check $(echo "$PY_FILES"); then ok=1; fi
    fi
  fi

  # isort (if not covered by ruff)
  if have isort; then
    if [[ "$FIX" == "true" ]]; then
      log "python: isort"
      if ! run_with_timeout "$TIMEOUT_SECS" isort $(echo "$PY_FILES"); then ok=1; fi
    else
      log "python: isort --check-only"
      if ! run_with_timeout "$TIMEOUT_SECS" isort --check-only $(echo "$PY_FILES"); then ok=1; fi
    fi
  fi

  # mypy (type checking)
  if have mypy; then
    log "python: mypy"
    if ! run_with_timeout "$TIMEOUT_SECS" mypy $(echo "$PY_FILES"); then ok=1; fi
  else
    log_warn "python: mypy not found; skipping types"
  fi

  return "$ok"
}

run_js() {
  tool_selected "js" || return 0
  [[ -n "$JS_FILES" ]] || { log "js: no files"; return 0; }

  local ok=0
  # eslint
  if [[ -f "package.json" ]] && jq -e '.scripts.lint' package.json >/dev/null 2>&1; then
    log "js: npm run lint"
    if ! run_with_timeout "$TIMEOUT_SECS" npm run lint --silent; then ok=1; fi
  elif have eslint; then
    log "js: eslint"
    if ! run_with_timeout "$TIMEOUT_SECS" eslint ${FIX:+--fix} $(echo "$JS_FILES"); then ok=1; fi
  elif have npx; then
    log "js: npx eslint"
    if ! run_with_timeout "$TIMEOUT_SECS" npx --yes eslint ${FIX:+--fix} $(echo "$JS_FILES"); then ok=1; fi
  else
    log_warn "js: eslint not found; skipping"
  fi

  # prettier formatting/check
  if have prettier; then
    if [[ "$FIX" == "true" ]]; then
      log "js: prettier --write"
      if ! run_with_timeout "$TIMEOUT_SECS" prettier --write $(echo "$JS_FILES"); then ok=1; fi
    else
      log "js: prettier --check"
      if ! run_with_timeout "$TIMEOUT_SECS" prettier --check $(echo "$JS_FILES"); then ok=1; fi
    fi
  elif have npx; then
    if [[ "$FIX" == "true" ]]; then
      log "js: npx prettier --write"
      if ! run_with_timeout "$TIMEOUT_SECS" npx --yes prettier --write $(echo "$JS_FILES"); then ok=1; fi
    else
      log "js: npx prettier --check"
      if ! run_with_timeout "$TIMEOUT_SECS" npx --yes prettier --check $(echo "$JS_FILES"); then ok=1; fi
    fi
  fi

  return "$ok"
}

run_yaml() {
  tool_selected "yaml" || return 0
  [[ -n "$YAML_FILES" ]] || { log "yaml: no files"; return 0; }
  local ok=0
  if have yamllint; then
    log "yaml: yamllint"
    if ! run_with_timeout "$TIMEOUT_SECS" yamllint -f parsable $(echo "$YAML_FILES"); then ok=1; fi
  else
    # docker fallback (image must already exist locally)
    if dockerrun "cytopia/yamllint" yamllint -f parsable $(echo "$YAML_FILES"); then
      :
    else
      log_warn "yaml: yamllint not found; basic syntax check via python -c"
      # minimal syntax check if python and pyyaml present
      if have python3 && python3 -c "import yaml" 2>/dev/null; then
        while read -r f; do
          [[ -z "$f" ]] && continue
          if ! python3 - <<PY 2>/dev/null
import sys, yaml, io
with open("$f", "r", encoding="utf-8") as fh:
    yaml.safe_load(fh)
PY
          then ok=1; echo "$f: invalid YAML" >&2; fi
        done <<<"$YAML_FILES"
      fi
    fi
  fi
  return "$ok"
}

run_json() {
  tool_selected "json" || return 0
  [[ -n "$JSON_FILES" ]] || { log "json: no files"; return 0; }
  local ok=0
  if have jq; then
    log "json: jq validation"
    # parallel validation
    while read -r f; do
      [[ -z "$f" ]] && continue
      {
        if jq -e . "$f" >/dev/null 2>&1; then
          :
        else
          echo "$f: invalid JSON" >&2
          exit 1
        fi
        if [[ "$FIX" == "true" ]]; then
          tmp="$f.tmp.$$"
          if jq -S . "$f" > "$tmp" 2>/dev/null && mv "$tmp" "$f"; then :; else rm -f "$tmp"; fi
        fi
      } &
      # limit background jobs
      while [[ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$CONCURRENCY" ]]; do wait -n || true; done
    done <<<"$JSON_FILES"
    wait || ok=1
  else
    log_warn "json: jq not found; skipping"
  fi
  return "$ok"
}

run_md() {
  tool_selected "md" || return 0
  [[ -n "$MD_FILES" ]] || { log "md: no files"; return 0; }
  local ok=0
  if have markdownlint; then
    log "md: markdownlint"
    if ! run_with_timeout "$TIMEOUT_SECS" markdownlint $(echo "$MD_FILES"); then ok=1; fi
  elif have markdownlint-cli2; then
    log "md: markdownlint-cli2"
    if ! run_with_timeout "$TIMEOUT_SECS" markdownlint-cli2 $(echo "$MD_FILES"); then ok=1; fi
  else
    log_warn "md: markdownlint not found; skipping"
  fi
  return "$ok"
}

run_shell() {
  tool_selected "shell" || return 0
  [[ -n "$SH_FILES" ]] || { log "shell: no files"; return 0; }
  local ok=0
  if have shellcheck; then
    log "shell: shellcheck"
    if ! run_with_timeout "$TIMEOUT_SECS" shellcheck -S style $(echo "$SH_FILES"); then ok=1; fi
  else
    log_warn "shell: shellcheck not found; skipping"
  fi
  if have shfmt; then
    if [[ "$FIX" == "true" ]]; then
      log "shell: shfmt -w"
      if ! run_with_timeout "$TIMEOUT_SECS" shfmt -i 2 -ci -bn -sr -w $(echo "$SH_FILES"); then ok=1; fi
    else
      log "shell: shfmt -d"
      if ! run_with_timeout "$TIMEOUT_SECS" shfmt -i 2 -ci -bn -sr -d $(echo "$SH_FILES"); then ok=1; fi
    fi
  fi
  return "$ok"
}

run_dockerfiles() {
  tool_selected "docker" || return 0
  [[ -n "$DOCKERFILES" ]] || { log "docker: no Dockerfiles"; return 0; }
  local ok=0
  if have hadolint; then
    log "docker: hadolint"
    if ! run_with_timeout "$TIMEOUT_SECS" hadolint $(echo "$DOCKERFILES"); then ok=1; fi
  else
    log_warn "docker: hadolint not found; skipping"
  fi
  return "$ok"
}

run_tf() {
  tool_selected "tf" || return 0
  [[ -n "$TF_FILES" ]] || { log "tf: no .tf files"; return 0; }
  local ok=0
  # Find unique module dirs
  mapfile -t dirs < <(echo "$TF_FILES" | xargs -n1 dirname | sort -u)
  for d in "${dirs[@]}"; do
    log "tf: check module $d"
    pushd "$d" >/dev/null
    if have terraform; then
      if [[ "$FIX" == "true" ]]; then
        terraform fmt -recursive
      else
        terraform fmt -recursive -check || ok=1
      fi
      terraform init -backend=false -input=false >/dev/null 2>&1 || true
      terraform validate || ok=1
    else
      log_warn "tf: terraform not found; skipping in $d"
    fi
    popd >/dev/null
    [[ "$ok" -ne 0 && "$FAIL_FAST" == "true" ]] && return "$ok"
  done
  return "$ok"
}

run_toml() {
  tool_selected "toml" || return 0
  [[ -n "$TOML_FILES" ]] || { log "toml: no files"; return 0; }
  local ok=0
  if have taplo; then
    if [[ "$FIX" == "true" ]]; then
      log "toml: taplo format"
      if ! run_with_timeout "$TIMEOUT_SECS" taplo format $(echo "$TOML_FILES"); then ok=1; fi
    else
      log "toml: taplo check"
      if ! run_with_timeout "$TIMEOUT_SECS" taplo check $(echo "$TOML_FILES"); then ok=1; fi
    fi
  else
    log_warn "toml: taplo not found; skipping"
  fi
  return "$ok"
}

run_gha() {
  tool_selected "gha" || return 0
  [[ -n "$GHA_FILES" ]] || { log "gha: no workflow files"; return 0; }
  local ok=0
  if have actionlint; then
    log "gha: actionlint"
    if ! run_with_timeout "$TIMEOUT_SECS" actionlint; then ok=1; fi
  else
    log_warn "gha: actionlint not found; skipping"
  fi
  return "$ok"
}

# --------------------------------------------
# Execution orchestration
# --------------------------------------------
overall_status=0
declare -A RESULTS=()

run_and_capture() {
  local name="$1"; shift
  local st=0
  if "$@"; then
    RESULTS["$name"]="ok"
  else
    st=$?
    RESULTS["$name"]="fail"
    overall_status=1
    [[ "$FAIL_FAST" == "true" ]] && die "fail-fast: $name failed"
  fi
  return "$st"
}

start_ts=$(date +%s)

# Optional global timeout guard
if [[ "$TIMEOUT_SECS" -gt 0 ]]; then
  log "global timeout: ${TIMEOUT_SECS}s"
fi

run_and_capture "python"       run_python
run_and_capture "js"           run_js
run_and_capture "yaml"         run_yaml
run_and_capture "json"         run_json
run_and_capture "md"           run_md
run_and_capture "shell"        run_shell
run_and_capture "dockerfiles"  run_dockerfiles
run_and_capture "terraform"    run_tf
run_and_capture "toml"         run_toml
run_and_capture "gha"          run_gha

elapsed=$(( $(date +%s) - start_ts ))

# --------------------------------------------
# Summary
# --------------------------------------------
summary_rich() {
  echo
  echo "Summary:"
  for k in python js yaml json md shell dockerfiles terraform toml gha; do
    v="${RESULTS[$k]:-skip}"
    case "$v" in
      ok)    printf "  %-12s %s\n" "$k" "$(color green OK)";;
      fail)  printf "  %-12s %s\n" "$k" "$(color red FAIL)";;
      *)     printf "  %-12s %s\n" "$k" "$(color yellow SKIP)";;
    esac
  done
  printf "Elapsed: %ss\n" "$elapsed"
  [[ "$overall_status" -eq 0 ]] && printf "%s All checks passed\n" "$(color green DONE)" || printf "%s Some checks failed\n" "$(color red DONE)"
}

summary_plain() {
  echo "summary,tool,status"
  for k in python js yaml json md shell dockerfiles terraform toml gha; do
    v="${RESULTS[$k]:-skip}"
    echo "lint,$k,$v"
  done
  echo "elapsed_seconds,$elapsed"
  echo "overall_status,$overall_status"
}

summary_json() {
  printf '{'
  printf '"elapsed_seconds": %d, "results": {' "$elapsed"
  local first=1
  for k in python js yaml json md shell dockerfiles terraform toml gha; do
    v="${RESULTS[$k]:-skip}"
    if [[ $first -eq 0 ]]; then printf ','; fi
    printf '"%s":"%s"' "$k" "$v"
    first=0
  done
  printf '}, "overall_status": %d}\n' "$overall_status"
}

case "$FORMAT" in
  rich) summary_rich;;
  plain) summary_plain;;
  json) summary_json;;
  *) summary_rich;;
esac

exit "$overall_status"
