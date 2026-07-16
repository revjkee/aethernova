#!/usr/bin/env bash
# Industrial DAST runner for security-core
# Supports: OWASP ZAP Baseline, Nuclei, Nikto, testssl.sh
# Works with Docker (preferred) or local binaries.
# Exit policy: fails on high/critical (configurable).
# Usage:
#   export TARGET_URL="https://app.example.com"
#   ./dast.sh
#
# Key env vars (with defaults):
#   TARGET_URL              - required, e.g. https://app.example.com
#   ARTIFACTS_DIR           - default: ./artifacts/dast
#   ZAP_TIMEOUT             - default: 900 (seconds)
#   ZAP_IMAGE               - default: owasp/zap2docker-stable
#   ZAP_CONTEXT_FILE        - optional path to ZAP context (for auth/scope)
#   NUCLEI_IMAGE            - default: projectdiscovery/nuclei:latest
#   NUCLEI_SEVERITIES       - default: critical,high,medium
#   NUCLEI_TEMPLATES        - optional (path or comma-separated remote dirs)
#   NIKTO_IMAGE             - default: sullo/nikto:latest
#   TESTSSL_IMAGE           - default: drwetter/testssl.sh
#   HEADERS_FILE            - optional file with extra HTTP headers (one per line: 'Name: Value')
#   DAST_FAIL_ON            - default: high  (values: none, low, medium, high, critical)
#   DAST_BLOCK_PROD         - default: true (block non-allowed hosts)
#   DAST_ALLOWED_HOSTS_RE   - default: "localhost|127.0.0.1|\.local$|\.test$|\.dev$|staging|sandbox"
#   DAST_MAX_RUNTIME        - optional hard cap in seconds for the entire run
#
# Requirements:
#   - bash >= 4, jq
#   - docker (recommended) or local binaries: zap-baseline.py, nuclei, nikto, testssl.sh
#
# Exit codes:
#   0 - success, below threshold or no findings
#   1 - usage/config error
#   2 - findings >= threshold
#   3 - runtime/tooling error

set -Eeuo pipefail
IFS=$'\n\t'

#######################################
# Logging
#######################################
log()  { printf '[%(%Y-%m-%dT%H:%M:%S%z)T] %s\n' -1 "$*"; }
err()  { printf '[%(%Y-%m-%dT%H:%M:%S%z)T] ERROR: %s\n' -1 "$*" >&2; }
die()  { err "$*"; exit 1; }

#######################################
# Config and defaults
#######################################
TARGET_URL="${TARGET_URL:-}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-./artifacts/dast}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${ARTIFACTS_DIR}/${RUN_ID}"

ZAP_TIMEOUT="${ZAP_TIMEOUT:-900}"
ZAP_IMAGE="${ZAP_IMAGE:-owasp/zap2docker-stable}"
ZAP_CONTEXT_FILE="${ZAP_CONTEXT_FILE:-}"

NUCLEI_IMAGE="${NUCLEI_IMAGE:-projectdiscovery/nuclei:latest}"
NUCLEI_SEVERITIES="${NUCLEI_SEVERITIES:-critical,high,medium}"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-}"

NIKTO_IMAGE="${NIKTO_IMAGE:-sullo/nikto:latest}"
TESTSSL_IMAGE="${TESTSSL_IMAGE:-drwetter/testssl.sh}"

HEADERS_FILE="${HEADERS_FILE:-}"
DAST_FAIL_ON="${DAST_FAIL_ON:-high}"
DAST_BLOCK_PROD="${DAST_BLOCK_PROD:-true}"
DAST_ALLOWED_HOSTS_RE="${DAST_ALLOWED_HOSTS_RE:-localhost|127.0.0.1|\.local$|\.test$|\.dev$|staging|sandbox}"

DAST_MAX_RUNTIME="${DAST_MAX_RUNTIME:-}"

# Severity map
declare -A SEV_MAP=( [none]=0 [info]=0 [low]=1 [medium]=2 [high]=3 [critical]=4 )
FAIL_THRESH=${SEV_MAP[${DAST_FAIL_ON:-high}]:-3}

#######################################
# Global state
#######################################
ZAP_JSON="${OUT_DIR}/zap-baseline.json"
ZAP_HTML="${OUT_DIR}/zap-baseline.html"
ZAP_MD="${OUT_DIR}/zap-baseline.md"

NUCLEI_JSONL="${OUT_DIR}/nuclei-findings.jsonl"
NUCLEI_TXT="${OUT_DIR}/nuclei-findings.txt"

NIKTO_JSON="${OUT_DIR}/nikto.json"
NIKTO_TXT="${OUT_DIR}/nikto.txt"

TESTSSL_JSON="${OUT_DIR}/testssl.json"
TESTSSL_HTML="${OUT_DIR}/testssl.html"

SUMMARY_MD="${OUT_DIR}/summary.md"

# Findings snapshot (max severity observed from authoritative scanners)
AUTH_MAX_SEV=0

#######################################
# Traps and timer
#######################################
cleanup() { :; }
trap cleanup EXIT

if [[ -n "${DAST_MAX_RUNTIME}" ]]; then
  # enforce total wall-clock timeout by background watchdog
  (
    sleep "${DAST_MAX_RUNTIME}" || true
    err "DAST_MAX_RUNTIME exceeded (${DAST_MAX_RUNTIME}s). Aborting."
    pkill -P $$ || true
    kill -TERM $$ || true
  ) & disown
fi

#######################################
# Helpers
#######################################
have_cmd() { command -v "$1" >/dev/null 2>&1; }
have_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

ensure_dir() { mkdir -p "$1"; }

url_parse() {
  # prints: proto host port
  local url="$1"
  local proto hostport host port
  proto="$(sed -E 's#^([^:/?#]+)://.*#\1#' <<<"$url")"
  hostport="$(sed -E 's#^[^:/?#]+://([^/?#]+).*#\1#' <<<"$url")"
  host="${hostport%%:*}"
  port="${hostport#*:}"
  if [[ "$host" == "$port" ]]; then
    if [[ "$proto" == "https" ]]; then port="443"; else port="80"; fi
  fi
  printf '%s %s %s\n' "$proto" "$host" "$port"
}

headers_mount_args() {
  # For ZAP/Nikto/Nuclei we pass headers differently, so we just provide a temp file.
  local src="${HEADERS_FILE}"
  if [[ -n "$src" && -f "$src" ]]; then
    printf '--mount type=bind,src=%s,dst=/tmp/extra_headers.txt,ro ' "$(realpath "$src")"
  fi
}

zap_replacer_from_headers() {
  # Convert headers file into ZAP replacer CLI args (-z ...).
  # Each header: Name: Value
  local headers_file="$1"
  local idx=0
  local args=()
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local name="${line%%:*}"
    local val="${line#*:}"
    name="$(echo "$name" | xargs)"
    val="$(echo "$val" | xargs)"
    args+=("-z" "-config" "replacer.full_list(${idx}).description=${name}")
    args+=("-z" "-config" "replacer.full_list(${idx}).enabled=true")
    args+=("-z" "-config" "replacer.full_list(${idx}).matchtype=REQ_HEADER")
    args+=("-z" "-config" "replacer.full_list(${idx}).matchstr=${name}")
    args+=("-z" "-config" "replacer.full_list(${idx}).replacement=${val}")
    args+=("-z" "-config" "replacer.full_list(${idx}).regex=false")
    idx=$((idx+1))
  done < "$headers_file"
  printf '%s ' "${args[@]}"
}

sev_max() {
  local a="$1"; local b="$2"
  if (( a > b )); then echo "$a"; else echo "$b"; fi
}

json_safe_count() {
  local file="$1"; local jqexpr="$2"
  if [[ -s "$file" ]]; then
    jq -r "$jqexpr" "$file" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

#######################################
# Preconditions
#######################################
[[ -n "$TARGET_URL" ]] || die "TARGET_URL is required"
have_cmd jq || die "jq is required"

ensure_dir "$OUT_DIR"
log "Artifacts directory: $OUT_DIR"

read -r PROTO HOST PORT < <(url_parse "$TARGET_URL")
log "Parsed URL => proto=$PROTO host=$HOST port=$PORT"

if [[ "${DAST_BLOCK_PROD,,}" == "true" ]]; then
  if ! [[ "$HOST" =~ $DAST_ALLOWED_HOSTS_RE ]]; then
    die "Host '$HOST' does not match DAST_ALLOWED_HOSTS_RE. Set DAST_BLOCK_PROD=false to override or adjust regex."
  fi
fi

#######################################
# OWASP ZAP Baseline
#######################################
run_zap() {
  log "Running OWASP ZAP Baseline..."
  local zap_replacer_args=()
  if [[ -n "$HEADERS_FILE" && -f "$HEADERS_FILE" ]]; then
    mapfile -t zap_replacer_args < <(zap_replacer_from_headers "$HEADERS_FILE")
  fi

  if have_docker; then
    # shellcheck disable=SC2046
    docker run --rm \
      -u "$(id -u):$(id -g)" \
      -v "${OUT_DIR}:/zap/wrk:rw" \
      $(headers_mount_args) \
      "${ZAP_IMAGE}" \
      zap-baseline.py \
        -t "${TARGET_URL}" \
        -J "wrk/$(basename "$ZAP_JSON")" \
        -r "wrk/$(basename "$ZAP_HTML")" \
        -w "wrk/$(basename "$ZAP_MD")" \
        -m 5 \
        -d \
        -z "-config api.disablekey=true" \
        -z "-config spider.maxDuration=5" \
        -z "-config scanner.threadPerHost=4" \
        -z "-config connection.timeoutInSecs=30" \
        ${zap_replacer_args[*]} \
        ${ZAP_CONTEXT_FILE:+-c "wrk/$(basename "$ZAP_CONTEXT_FILE")"} \
      || true
  else
    # Fallback to local zap-baseline.py
    zap-baseline.py \
      -t "${TARGET_URL}" \
      -J "${ZAP_JSON}" \
      -r "${ZAP_HTML}" \
      -w "${ZAP_MD}" \
      -m 5 -d \
      -z "-config api.disablekey=true" \
      -z "-config spider.maxDuration=5" \
      -z "-config scanner.threadPerHost=4" \
      -z "-config connection.timeoutInSecs=30" \
      || true
  fi

  # Evaluate severity: High is the max in ZAP baseline
  local zap_high zap_medium zap_low
  zap_high=$(json_safe_count "$ZAP_JSON" '[.site[]?.alerts[]?|select(.risk=="High")]|length')
  zap_medium=$(json_safe_count "$ZAP_JSON" '[.site[]?.alerts[]?|select(.risk=="Medium")]|length')
  zap_low=$(json_safe_count "$ZAP_JSON" '[.site[]?.alerts[]?|select(.risk=="Low")]|length')
  log "ZAP findings: high=${zap_high} medium=${zap_medium} low=${zap_low}"

  if (( zap_high > 0 )); then AUTH_MAX_SEV=$(sev_max "$AUTH_MAX_SEV" "${SEV_MAP[high]}"); fi
  if (( zap_medium > 0 )); then AUTH_MAX_SEV=$(sev_max "$AUTH_MAX_SEV" "${SEV_MAP[medium]}"); fi
}

#######################################
# Nuclei
#######################################
run_nuclei() {
  log "Running Nuclei..."
  local base_cmd=(nuclei -u "$TARGET_URL" -ni -severity "$NUCLEI_SEVERITIES" -jsonl -o "$NUCLEI_JSONL")
  if [[ -n "$NUCLEI_TEMPLATES" ]]; then
    # Support comma-separated list
    IFS=',' read -r -a tpl <<< "$NUCLEI_TEMPLATES"
    for t in "${tpl[@]}"; do base_cmd+=(-t "$t"); done
  fi
  if [[ -n "$HEADERS_FILE" && -f "$HEADERS_FILE" ]]; then
    # Convert headers to -H form
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      base_cmd+=(-H "$line")
    done < "$HEADERS_FILE"
  fi

  if have_docker; then
    docker run --rm \
      -u "$(id -u):$(id -g)" \
      -v "${OUT_DIR}:/out" \
      "${NUCLEI_IMAGE}" \
      nuclei -u "$TARGET_URL" -ni -severity "$NUCLEI_SEVERITIES" \
      ${NUCLEI_TEMPLATES:+-t "$NUCLEI_TEMPLATES"} \
      ${HEADERS_FILE:+$(while read -r l; do printf -- ' -H %q' "$l"; done < "$HEADERS_FILE")} \
      -jsonl -o "/out/$(basename "$NUCLEI_JSONL")" \
      || true
  else
    "${base_cmd[@]}" || true
  fi

  # Pretty txt summary
  if [[ -s "$NUCLEI_JSONL" ]]; then
    jq -r '[.templateID, .severity, .info.name, .host] | @tsv' "$NUCLEI_JSONL" | column -t \
      > "$NUCLEI_TXT" || true
  fi

  # Severity tally
  local n_crit n_high n_med
  n_crit=$(grep -i '"severity":"critical"' "$NUCLEI_JSONL" 2>/dev/null | wc -l || echo 0)
  n_high=$(grep -i '"severity":"high"' "$NUCLEI_JSONL" 2>/dev/null | wc -l || echo 0)
  n_med=$(grep -i '"severity":"medium"' "$NUCLEI_JSONL" 2>/dev/null | wc -l || echo 0)
  log "Nuclei findings: critical=${n_crit} high=${n_high} medium=${n_med}"

  if (( n_crit > 0 )); then AUTH_MAX_SEV=$(sev_max "$AUTH_MAX_SEV" "${SEV_MAP[critical]}"); fi
  if (( n_high > 0 )); then AUTH_MAX_SEV=$(sev_max "$AUTH_MAX_SEV" "${SEV_MAP[high]}"); fi
  if (( n_med > 0 )); then AUTH_MAX_SEV=$(sev_max "$AUTH_MAX_SEV" "${SEV_MAP[medium]}"); fi
}

#######################################
# Nikto
#######################################
run_nikto() {
  log "Running Nikto..."
  if have_docker; then
    docker run --rm \
      -u "$(id -u):$(id -g)" \
      -v "${OUT_DIR}:/out" \
      "${NIKTO_IMAGE}" \
      nikto -host "${TARGET_URL}" -output "/out/$(basename "$NIKTO_JSON")" -Format json \
      || true
  else
    nikto -host "${TARGET_URL}" -output "${NIKTO_JSON}" -Format json || true
  fi

  # Simple text view if JSON present
  if [[ -s "$NIKTO_JSON" ]]; then
    jq -r '..|.description? // empty' "$NIKTO_JSON" > "$NIKTO_TXT" || true
  fi
}

#######################################
# testssl.sh
#######################################
run_testssl() {
  log "Running testssl.sh..."
  local target="${HOST}:${PORT}"
  if have_docker; then
    docker run --rm \
      -u "$(id -u):$(id -g)" \
      -v "${OUT_DIR}:/out" \
      "${TESTSSL_IMAGE}" \
      --warnings batch --fast --parallel --sneaky \
      --jsonfile-pretty "/out/$(basename "$TESTSSL_JSON")" \
      --htmlfile "/out/$(basename "$TESTSSL_HTML")" \
      "$target" || true
  else
    testssl.sh --warnings batch --fast --parallel --sneaky \
      --jsonfile-pretty "$TESTSSL_JSON" \
      --htmlfile "$TESTSSL_HTML" \
      "$target" || true
  fi
}

#######################################
# Summary
#######################################
generate_summary() {
  log "Generating summary..."
  local zap_high zap_med zap_low
  zap_high=$(json_safe_count "$ZAP_JSON" '[.site[]?.alerts[]?|select(.risk=="High")]|length')
  zap_med=$(json_safe_count "$ZAP_JSON"  '[.site[]?.alerts[]?|select(.risk=="Medium")]|length')
  zap_low=$(json_safe_count "$ZAP_JSON"  '[.site[]?.alerts[]?|select(.risk=="Low")]|length')

  local n_crit n_high n_med
  n_crit=$(grep -i '"severity":"critical"' "$NUCLEI_JSONL" 2>/dev/null | wc -l || echo 0)
  n_high=$(grep -i '"severity":"high"' "$NUCLEI_JSONL" 2>/dev/null | wc -l || echo 0)
  n_med=$(grep -i '"severity":"medium"' "$NUCLEI_JSONL" 2>/dev/null | wc -l || echo 0)

  cat > "$SUMMARY_MD" <<EOF
# DAST Summary
Run ID: ${RUN_ID}
Target: ${TARGET_URL}

## OWASP ZAP Baseline
High: ${zap_high}
Medium: ${zap_med}
Low: ${zap_low}
Reports: $(basename "$ZAP_HTML"), $(basename "$ZAP_JSON"), $(basename "$ZAP_MD")

## Nuclei
Critical: ${n_crit}
High: ${n_high}
Medium: ${n_med}
Reports: $(basename "$NUCLEI_JSONL"), $(basename "$NUCLEI_TXT")

## Nikto
Report: $(basename "$NIKTO_JSON"), $(basename "$NIKTO_TXT")

## testssl.sh
Report: $(basename "$TESTSSL_HTML"), $(basename "$TESTSSL_JSON")

## Policy
Fail-on-severity: ${DAST_FAIL_ON}
EOF

  log "Summary written: $SUMMARY_MD"
}

#######################################
# Main
#######################################
main() {
  log "Starting DAST run"
  run_zap
  run_nuclei
  run_nikto
  run_testssl
  generate_summary

  log "Authoritative max severity observed (ZAP/Nuclei): ${AUTH_MAX_SEV}"
  log "Fail threshold: ${FAIL_THRESH} (${DAST_FAIL_ON})"
  if (( AUTH_MAX_SEV >= FAIL_THRESH && FAIL_THRESH > 0 )); then
    err "Failing build due to findings meeting threshold ${DAST_FAIL_ON}"
    exit 2
  fi

  log "DAST completed successfully"
}

main "$@"
