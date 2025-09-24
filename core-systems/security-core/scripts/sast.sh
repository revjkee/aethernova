#!/usr/bin/env bash
# SAST pipeline for security-core
# Standards: OWASP, DevSecOps, Zero-Trust
# Outputs: SARIF/JSON summaries with severity gating for CI

set -Eeuo pipefail

# ========= Configuration =========
SAST_MODE="${SAST_MODE:-full}"                     # fast|full|ci
SAST_TARGETS="${SAST_TARGETS:-.}"                  # space-separated paths
SAST_EXCLUDE="${SAST_EXCLUDE:-.git .venv node_modules dist build vendor .tox .mypy_cache .ruff_cache .pytest_cache}"
SAST_OUTPUT_DIR="${SAST_OUTPUT_DIR:-.sast-reports}"
SAST_CACHE_DIR="${SAST_CACHE_DIR:-.sast-cache}"
SAST_PARALLEL="${SAST_PARALLEL:-$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)}"
SAST_TIMEOUT="${SAST_TIMEOUT:-600}"                # seconds per tool
SAST_FAIL_ON="${SAST_FAIL_ON:-high}"               # critical|high|medium|low|none
SAST_LOG_LEVEL="${SAST_LOG_LEVEL:-info}"           # debug|info|warn|error
SAST_TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SAST_TMP_DIR="$(mktemp -d -t sast-XXXXXX)"

mkdir -p "$SAST_OUTPUT_DIR" "$SAST_CACHE_DIR" "$SAST_TMP_DIR"

# ========= Logging helpers =========
log() {
  local level="$1"; shift
  local levels="debug info warn error"
  [[ " $levels " == *" $SAST_LOG_LEVEL "* ]] || true
  local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "[$ts] [$level] $*" >&2
}
debug(){ [[ "$SAST_LOG_LEVEL" == "debug" ]] && log debug "$@"; }
info(){ log info "$@"; }
warn(){ log warn "$@"; }
error(){ log error "$@"; }
die(){ error "$@"; exit 1; }

cleanup() { rm -rf "$SAST_TMP_DIR" || true; }
trap cleanup EXIT

# ========= Utilities =========
require() {
  local bin="$1" name="${2:-$1}"
  if ! command -v "$bin" >/dev/null 2>&1; then
    warn "Не найдено: $name ($bin). Шаг будет пропущен."
    return 1
  fi
  return 0
}

timeout_wrap() {
  local to="$1"; shift
  command -v timeout >/dev/null 2>&1 \
    && timeout --preserve-status --signal=INT "$to" "$@" \
    || "$@"
}

join_by_space() { local IFS=" "; echo "$*"; }

contains_path() {
  local p="$1"
  shift || true
  for x in "$@"; do [[ "$p" == *"/$x"* || "$p" == "$x" ]] && return 0; done
  return 1
}

# ========= Inputs & filters =========
mapfile -t TARGET_LIST < <(printf "%s\n" $SAST_TARGETS | sed 's#^./##' || true)

SHOULD_SCAN() {
  local p="$1"
  for ex in $SAST_EXCLUDE; do
    if [[ "$p" == "$ex" || "$p" == */"$ex"* ]]; then
      return 1
    fi
  done
  return 0
}

# ========= Severity mapping & gating =========
# normalize severities to: critical,high,medium,low,info
sev_rank() {
  case "${1,,}" in
    critical) echo 4 ;;
    high|error) echo 3 ;;
    medium|warning|moderate) echo 2 ;;
    low|note) echo 1 ;;
    info|informational) echo 0 ;;
    *) echo 0 ;;
  esac
}
threshold_rank="$(sev_rank "$SAST_FAIL_ON")"

should_fail() {
  local sev="$1"
  [[ "$(sev_rank "$sev")" -ge "$threshold_rank" ]]
}

# ========= Detection of stack presence =========
has_python(){ [[ -f "pyproject.toml" || -f "requirements.txt" || -d "src" && -n "$(ls -1 **/*.py 2>/dev/null | head -n1 || true)" ]]; }
has_node(){ [[ -f "package.json" ]]; }
has_go(){ [[ -f "go.mod" ]]; }
has_rust(){ [[ -f "Cargo.toml" ]]; }
has_shell(){ [[ -n "$(ls -1 **/*.sh 2>/dev/null | head -n1 || true)" ]]; }
has_tf(){ [[ -n "$(ls -1 **/*.tf 2>/dev/null | head -n1 || true)" ]]; }
has_iac_yaml(){ [[ -n "$(ls -1 **/*.{yaml,yml} 2>/dev/null | head -n1 || true)" ]]; }
has_docker(){ [[ -n "$(ls -1 **/Dockerfile* 2>/dev/null | head -n1 || true)" ]]; }

# ========= Reports registry =========
declare -a REPORTS_JSON=()
declare -a REPORTS_SARIF=()
add_json(){ REPORTS_JSON+=("$1"); }
add_sarif(){ REPORTS_SARIF+=("$1"); }

# ========= Tool runners =========

run_semgrep() {
  require semgrep "Semgrep" || return 0
  local out="$SAST_OUTPUT_DIR/semgrep-$SAST_TIMESTAMP.sarif"
  local cfg="p/ci"
  [[ "$SAST_MODE" == "fast" ]] && cfg="p/default"
  info "Semgrep запускается с конфигурацией: $cfg"
  # Respect excludes
  local excludes=()
  for e in $SAST_EXCLUDE; do excludes+=(--exclude "$e"); done
  timeout_wrap "$SAST_TIMEOUT" semgrep --quiet --error --metrics=off \
    --config "$cfg" "${TARGET_LIST[@]}" "${excludes[@]}" \
    --sarif -o "$out" || warn "Semgrep завершился с кодом ошибки"
  [[ -s "$out" ]] && add_sarif "$out"
}

run_bandit() {
  require bandit "Bandit" || return 0
  has_python || { debug "Python-код не обнаружен для Bandit"; return 0; }
  local out="$SAST_OUTPUT_DIR/bandit-$SAST_TIMESTAMP.json"
  info "Bandit сканирует Python-проекты"
  timeout_wrap "$SAST_TIMEOUT" bandit -r "$(join_by_space "${TARGET_LIST[@]}")" -f json -o "$out" -q || true
  [[ -s "$out" ]] && add_json "$out"
}

run_trivy_fs() {
  require trivy "Trivy" || return 0
  local out="$SAST_OUTPUT_DIR/trivy-fs-$SAST_TIMESTAMP.sarif"
  info "Trivy fs сканирует исходники"
  local excludes=()
  for e in $SAST_EXCLUDE; do excludes+=(--exclude "$e"); done
  timeout_wrap "$SAST_TIMEOUT" trivy fs --quiet --scanners vuln,secret,misconfig \
    --format sarif --output "$out" "${TARGET_LIST[@]}" "${excludes[@]}" || true
  [[ -s "$out" ]] && add_sarif "$out"
}

run_trivy_config() {
  require trivy "Trivy" || return 0
  if has_tf || has_iac_yaml; then
    local out="$SAST_OUTPUT_DIR/trivy-config-$SAST_TIMESTAMP.sarif"
    info "Trivy config сканирует IaC конфигурации"
    timeout_wrap "$SAST_TIMEOUT" trivy config --quiet \
      --format sarif --output "$out" "${TARGET_LIST[@]}" || true
    [[ -s "$out" ]] && add_sarif "$out"
  fi
}

run_gitleaks() {
  require gitleaks "Gitleaks" || return 0
  local out="$SAST_OUTPUT_DIR/gitleaks-$SAST_TIMESTAMP.json"
  info "Gitleaks поиск секретов"
  timeout_wrap "$SAST_TIMEOUT" gitleaks detect --no-git --redact --report-format json --report-path "$out" || true
  [[ -s "$out" ]] && add_json "$out"
}

run_safety() {
  # Prefer pip-audit, fallback to safety
  if require pip-audit "pip-audit"; then
    has_python || return 0
    local out="$SAST_OUTPUT_DIR/pip-audit-$SAST_TIMESTAMP.json"
    info "pip-audit проверка зависимостей Python"
    timeout_wrap "$SAST_TIMEOUT" pip-audit -f json -o "$out" || true
    [[ -s "$out" ]] && add_json "$out"
  elif require safety "Safety"; then
    has_python || return 0
    local out="$SAST_OUTPUT_DIR/safety-$SAST_TIMESTAMP.json"
    info "Safety проверка зависимостей Python"
    if [[ -f requirements.txt ]]; then
      timeout_wrap "$SAST_TIMEOUT" safety check -r requirements.txt --full-report --json >"$out" || true
      [[ -s "$out" ]] && add_json "$out"
    else
      warn "Safety пропущен: нет requirements.txt"
    fi
  fi
}

run_npm_audit() {
  require npm "npm" || return 0
  has_node || return 0
  local out="$SAST_OUTPUT_DIR/npm-audit-$SAST_TIMESTAMP.json"
  info "npm audit проверка зависимостей Node.js"
  # npm audit returns non-zero on vulns; capture but don't fail pipeline here
  (timeout_wrap "$SAST_TIMEOUT" npm audit --json >"$out") || true
  [[ -s "$out" ]] && add_json "$out"
}

run_gosec() {
  require gosec "gosec" || return 0
  has_go || return 0
  local out="$SAST_OUTPUT_DIR/gosec-$SAST_TIMESTAMP.json"
  info "gosec анализ Go-кода"
  timeout_wrap "$SAST_TIMEOUT" gosec -no-fail -fmt=json -out="$out" ./... || true
  [[ -s "$out" ]] && add_json "$out"
}

run_cargo_audit() {
  require cargo-audit "cargo-audit" || return 0
  has_rust || return 0
  local out="$SAST_OUTPUT_DIR/cargo-audit-$SAST_TIMESTAMP.json"
  info "cargo-audit аудит Rust-зависимостей"
  timeout_wrap "$SAST_TIMEOUT" cargo audit -q -F json >"$out" || true
  [[ -s "$out" ]] && add_json "$out"
}

run_shellcheck() {
  require shellcheck "ShellCheck" || return 0
  has_shell || return 0
  local out="$SAST_OUTPUT_DIR/shellcheck-$SAST_TIMESTAMP.json"
  info "ShellCheck анализ shell-скриптов"
  # Collect files
  mapfile -t shfiles < <(git ls-files '*.sh' 2>/dev/null || true)
  if [[ "${#shfiles[@]}" -eq 0 ]]; then
    mapfile -t shfiles < <(ls -1 **/*.sh 2>/dev/null || true)
  fi
  if [[ "${#shfiles[@]}" -gt 0 ]]; then
    timeout_wrap "$SAST_TIMEOUT" shellcheck --format json "${shfiles[@]}" >"$out" || true
    [[ -s "$out" ]] && add_json "$out"
  fi
}

run_tfsec() {
  require tfsec "tfsec" || return 0
  has_tf || return 0
  local out="$SAST_OUTPUT_DIR/tfsec-$SAST_TIMESTAMP.sarif"
  info "tfsec анализ Terraform"
  timeout_wrap "$SAST_TIMEOUT" tfsec . --format sarif --out "$out" || true
  [[ -s "$out" ]] && add_sarif "$out"
}

run_checkov() {
  require checkov "Checkov" || return 0
  if has_tf || has_iac_yaml; then
    local out="$SAST_OUTPUT_DIR/checkov-$SAST_TIMESTAMP.sarif"
    info "Checkov анализ IaC"
    timeout_wrap "$SAST_TIMEOUT" checkov -d . -o sarif --output-file-path "$out" || true
    [[ -s "$out" ]] && add_sarif "$out"
  fi
}

# ========= Aggregation =========
# Requires jq for summary & severity gating
require jq "jq" || die "jq обязателен для агрегации результатов"

summarize() {
  local summary_json="$SAST_OUTPUT_DIR/summary-$SAST_TIMESTAMP.json"
  local summary_txt="$SAST_OUTPUT_DIR/summary-$SAST_TIMESTAMP.txt"
  info "Агрегация результатов в $summary_json"

  # Initialize counters
  local total_crit=0 total_high=0 total_med=0 total_low=0 total_info=0

  # Parse SARIF files (Semgrep, Trivy, tfsec, Checkov)
  for f in "${REPORTS_SARIF[@]}"; do
    debug "Парсинг SARIF $f"
    # Try standard SARIF schema with result.level or properties.severity
    local crit high med low info_c
    crit=$(jq '[.runs[].results[]? | (.properties.severity // .level // "info") | ascii_downcase | select(.=="critical") ] | length' "$f" 2>/dev/null || echo 0)
    high=$(jq '[.runs[].results[]? | (.properties.severity // .level // "info") | ascii_downcase | select(.=="high" or .=="error") ] | length' "$f" 2>/dev/null || echo 0)
    med=$(jq '[.runs[].results[]? | (.properties.severity // .level // "info") | ascii_downcase | select(.=="medium" or .=="warning") ] | length' "$f" 2>/dev/null || echo 0)
    low=$(jq '[.runs[].results[]? | (.properties.severity // .level // "info") | ascii_downcase | select(.=="low" or .=="note") ] | length' "$f" 2>/dev/null || echo 0)
    info_c=$(jq '[.runs[].results[]? | (.properties.severity // .level // "info") | ascii_downcase | select(.=="info" or .=="informational") ] | length' "$f" 2>/dev/null || echo 0)
    total_crit=$((total_crit+crit))
    total_high=$((total_high+high))
    total_med=$((total_med+med))
    total_low=$((total_low+low))
    total_info=$((total_info+info_c))
  done

  # Parse JSON reports of specific tools
  for f in "${REPORTS_JSON[@]}"; do
    debug "Парсинг JSON $f"
    case "$f" in
      *bandit-*.json)
        local bc bh bm bl
        bc=0
        bh=$(jq '[.results[]? | select(.issue_severity=="HIGH") ] | length' "$f" 2>/dev/null || echo 0)
        bm=$(jq '[.results[]? | select(.issue_severity=="MEDIUM") ] | length' "$f" 2>/dev/null || echo 0)
        bl=$(jq '[.results[]? | select(.issue_severity=="LOW") ] | length' "$f" 2>/dev/null || echo 0)
        total_high=$((total_high+bh))
        total_med=$((total_med+bm))
        total_low=$((total_low+bl))
        ;;
      *gitleaks-*.json)
        # Treat any secret as high severity
        local gl
        gl=$(jq '[.[]?] | length' "$f" 2>/dev/null || echo 0)
        total_high=$((total_high+gl))
        ;;
      *pip-audit-*.json)
        local ph pm pl
        ph=$(jq '[.[]? | .severity? | ascii_downcase | select(.=="critical" or .=="high")] | length' "$f" 2>/dev/null || echo 0)
        pm=$(jq '[.[]? | .severity? | ascii_downcase | select(.=="medium" or .=="moderate")] | length' "$f" 2>/dev/null || echo 0)
        pl=$(jq '[.[]? | .severity? | ascii_downcase | select(.=="low")] | length' "$f" 2>/dev/null || echo 0)
        total_high=$((total_high+ph))
        total_med=$((total_med+pm))
        total_low=$((total_low+pl))
        ;;
      *safety-*.json)
        # Safety JSON not always contains severity; count as high
        local sc
        sc=$(jq 'length' "$f" 2>/dev/null || echo 0)
        total_high=$((total_high+sc))
        ;;
      *npm-audit-*.json)
        local nh nm nl
        nh=$(jq '.vulnerabilities? | .high // 0 + (.critical // 0)' "$f" 2>/dev/null || echo 0)
        nm=$(jq '.vulnerabilities? | .moderate // 0' "$f" 2>/dev/null || echo 0)
        nl=$(jq '.vulnerabilities? | .low // 0' "$f" 2>/dev/null || echo 0)
        total_high=$((total_high+nh))
        total_med=$((total_med+nm))
        total_low=$((total_low+nl))
        ;;
      *gosec-*.json)
        local gh gm gl
        gh=$(jq '[.Issues[]? | select(.severity=="HIGH")] | length' "$f" 2>/dev/null || echo 0)
        gm=$(jq '[.Issues[]? | select(.severity=="MEDIUM")] | length' "$f" 2>/dev/null || echo 0)
        gl=$(jq '[.Issues[]? | select(.severity=="LOW")] | length' "$f" 2>/dev/null || echo 0)
        total_high=$((total_high+gh))
        total_med=$((total_med+gm))
        total_low=$((total_low+gl))
        ;;
      *cargo-audit-*.json)
        local ch
        ch=$(jq '.vulnerabilities.count // 0' "$f" 2>/dev/null || echo 0)
        total_high=$((total_high+ch))
        ;;
      *shellcheck-*.json)
        local shh shm shl
        shh=$(jq '[.[]? | select(.level=="error")] | length' "$f" 2>/dev/null || echo 0)
        shm=$(jq '[.[]? | select(.level=="warning")] | length' "$f" 2>/dev/null || echo 0)
        shl=$(jq '[.[]? | select(.level=="info" or .level=="style")] | length' "$f" 2>/dev/null || echo 0)
        total_high=$((total_high+shh))
        total_med=$((total_med+shm))
        total_low=$((total_low+shl))
        ;;
    esac
  done

  jq -n --arg ts "$SAST_TIMESTAMP" \
    --arg mode "$SAST_MODE" \
    --arg fail_on "$SAST_FAIL_ON" \
    --argjson crit "$total_crit" \
    --argjson high "$total_high" \
    --argjson med "$total_med" \
    --argjson low "$total_low" \
    --argjson info "$total_info" \
    --argjson sarif "$(printf '%s\n' "${REPORTS_SARIF[@]}" | jq -R -s 'split("\n")[:-1]')" \
    --argjson json "$(printf '%s\n' "${REPORTS_JSON[@]}" | jq -R -s 'split("\n")[:-1]')" \
    '{
      timestamp: $ts,
      mode: $mode,
      fail_on: $fail_on,
      totals: {critical:$crit, high:$high, medium:$med, low:$low, info:$info},
      reports: {sarif:$sarif, json:$json}
    }' >"$summary_json"

  {
    echo "SAST summary ($SAST_TIMESTAMP)"
    echo "Mode: $SAST_MODE   Fail-on: $SAST_FAIL_ON"
    echo "Found: critical=$total_crit high=$total_high medium=$total_med low=$total_low info=$total_info"
    echo "SARIF reports:"
    for f in "${REPORTS_SARIF[@]}"; do echo " - $f"; done
    echo "JSON reports:"
    for f in "${REPORTS_JSON[@]}"; do echo " - $f"; done
  } >"$summary_txt"

  # Exit code by threshold
  local fail=0
  if should_fail "critical" && [[ $total_crit -gt 0 ]]; then fail=1; fi
  if should_fail "high" && [[ $total_high -gt 0 ]]; then fail=1; fi
  if should_fail "medium" && [[ $total_med -gt 0 ]]; then fail=1; fi
  if should_fail "low" && [[ $total_low -gt 0 ]]; then fail=1; fi

  if [[ $fail -eq 1 ]]; then
    error "Порог серьезности нарушен. Детали: $summary_txt"
    return 2
  else
    info "Порог серьезности не нарушен."
    return 0
  fi
}

# ========= Runner orchestration =========
usage() {
  cat <<EOF
Usage: $(basename "$0") [--mode fast|full|ci] [--fail-on SEV] [--targets "paths"] [--exclude "paths"] [--timeout SECONDS]
Env overrides: SAST_MODE, SAST_FAIL_ON, SAST_TARGETS, SAST_EXCLUDE, SAST_TIMEOUT, SAST_OUTPUT_DIR, SAST_PARALLEL
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) SAST_MODE="${2:-$SAST_MODE}"; shift 2 ;;
    --fail-on) SAST_FAIL_ON="${2:-$SAST_FAIL_ON}"; shift 2 ;;
    --targets) SAST_TARGETS="${2:-$SAST_TARGETS}"; shift 2 ;;
    --exclude) SAST_EXCLUDE="${2:-$SAST_EXCLUDE}"; shift 2 ;;
    --timeout) SAST_TIMEOUT="${2:-$SAST_TIMEOUT}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) warn "Неизвестный аргумент: $1"; shift ;;
  esac
done

info "SAST старт: mode=$SAST_MODE fail-on=$SAST_FAIL_ON targets=[$SAST_TARGETS]"

# Select toolset by mode
declare -a JOBS=()

# Always:
JOBS+=(run_semgrep)
JOBS+=(run_trivy_fs)
JOBS+=(run_gitleaks)
JOBS+=(run_shellcheck)

# Language/stack-specific:
has_python && JOBS+=(run_bandit run_safety)
has_node && JOBS+=(run_npm_audit)
has_go && JOBS+=(run_gosec)
has_rust && JOBS+=(run_cargo_audit)

# IaC:
(has_tf || has_iac_yaml) && JOBS+=(run_trivy_config run_tfsec run_checkov)

# Mode adjustments
if [[ "$SAST_MODE" == "fast" ]]; then
  SAST_TIMEOUT="${SAST_TIMEOUT:-300}"
  # keep essential tools only
  JOBS=(run_semgrep run_gitleaks)
fi

# Parallel execution with background jobs (bounded by SAST_PARALLEL)
running=0
pids=()
for job in "${JOBS[@]}"; do
  while [[ $running -ge $SAST_PARALLEL ]]; do
    wait -n || true
    running=$((running-1))
  done
  info "Запуск шага: $job"
  ( $job ) &
  pids+=($!)
  running=$((running+1))
done

# Wait all
for pid in "${pids[@]}"; do
  wait "$pid" || true
done

# Summarize and set exit code
if summarize; then
  info "SAST завершен успешно"
  exit 0
else
  error "SAST завершен с нарушением порога"
  exit 2
fi
