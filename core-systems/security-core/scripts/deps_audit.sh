#!/usr/bin/env bash
# deps_audit.sh
# Unified dependency and artifact security audit for multi-language repos.
# Targets: Python, Node.js, Go, Rust, Java (Maven/Gradle), .NET, Docker/OCI
# Outputs: JSON, SARIF, SBOM (SPDX, CycloneDX), exit codes suitable for CI.
# License: Apache-2.0

set -euo pipefail
IFS=$'\n\t'

# ---------------------------
# Configuration (env overridable)
# ---------------------------
: "${ARTIFACTS_DIR:=artifacts/security}"
: "${LOG_DIR:=${ARTIFACTS_DIR}/logs}"
: "${REPORT_DIR:=${ARTIFACTS_DIR}/reports}"
: "${SBOM_DIR:=${ARTIFACTS_DIR}/sbom}"
: "${SEVERITY_THRESHOLD:=high}"            # none, low, medium, high, critical
: "${FAIL_ON:=vulnerabilities}"            # vulnerabilities|errors|never
: "${TIMEOUT:=600}"                        # per tool timeout in seconds
: "${ALLOWLIST:=.audit-allowlist.txt}"     # optional suppressions (CVE IDs, lines)
: "${CI:=false}"

# Tooling toggles (auto-detect by default)
: "${ENABLE_PYTHON:=auto}"
: "${ENABLE_NODE:=auto}"
: "${ENABLE_GO:=auto}"
: "${ENABLE_RUST:=auto}"
: "${ENABLE_JAVA:=auto}"
: "${ENABLE_DOTNET:=auto}"
: "${ENABLE_CONTAINER:=auto}"
: "${ENABLE_SBOM:=auto}"

# ---------------------------
# Utilities
# ---------------------------
have_cmd() { command -v "$1" >/dev/null 2>&1; }
ensure_dir() { mkdir -p "$1"; }
timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

log_info()  { printf "[%s] [INFO ] %s\n"  "$(timestamp)" "$*" | tee -a "${LOG_DIR}/audit.log" >&2; }
log_warn()  { printf "[%s] [WARN ] %s\n"  "$(timestamp)" "$*" | tee -a "${LOG_DIR}/audit.log" >&2; }
log_error() { printf "[%s] [ERROR] %s\n" "$(timestamp)" "$*" | tee -a "${LOG_DIR}/audit.log" >&2; }

# severity order for thresholding
severity_rank() {
  case "$1" in
    none) echo 0 ;;
    low) echo 1 ;;
    medium|moderate) echo 2 ;;
    high) echo 3 ;;
    critical) echo 4 ;;
    *) echo 0 ;;
  esac
}

THRESHOLD_RANK=$(severity_rank "$SEVERITY_THRESHOLD")

# Global counters
FOUND_VULNS=0
FOUND_ERRORS=0

# Apply allowlist filter to a JSON line stream (very simple grep-based CVE suppression)
# If $ALLOWLIST exists and contains lines like "CVE-2023-12345" or any token,
# matching lines are filtered out from the output stream copied to *_filtered.json.
filter_with_allowlist() {
  local in_file="$1"
  local out_file="$2"
  if [[ -f "$ALLOWLIST" ]]; then
    # Grep -v any token from allowlist
    local tmp="${out_file}.tmp"
    cp "$in_file" "$tmp"
    while IFS= read -r token; do
      [[ -z "$token" ]] && continue
      grep -v -- "$token" "$tmp" > "${tmp}.2" || true
      mv "${tmp}.2" "$tmp"
    done < "$ALLOWLIST"
    mv "$tmp" "$out_file"
    log_info "Applied allowlist from ${ALLOWLIST} to ${in_file}"
  else
    cp "$in_file" "$out_file"
  fi
}

# Decide if we should fail build based on findings and FAIL_ON
finalize_exit() {
  if [[ "$FAIL_ON" == "never" ]]; then
    exit 0
  fi

  local exit_code=0
  if [[ "$FAIL_ON" == "errors" ]]; then
    [[ "$FOUND_ERRORS" -gt 0 ]] && exit_code=2
  elif [[ "$FAIL_ON" == "vulnerabilities" ]]; then
    [[ "$FOUND_VULNS" -gt 0 ]] && exit_code=1
  fi

  if [[ "$exit_code" -ne 0 ]]; then
    log_error "Failing per policy FAIL_ON=${FAIL_ON}; vulns=${FOUND_VULNS}, errors=${FOUND_ERRORS}"
  else
    log_info "No blocking findings; vulns=${FOUND_VULNS}, errors=${FOUND_ERRORS}"
  fi
  exit "$exit_code"
}

# Safely run a command with timeout; capture both stdout and stderr to files.
run_tool() {
  local name="$1"; shift
  local out_json="$1"; shift
  local cmd=("$@")

  log_info "Running ${name}: ${cmd[*]}"
  set +e
  if have_cmd timeout; then
    timeout --preserve-status "${TIMEOUT}" "${cmd[@]}" >"${out_json}.raw" 2>"${out_json}.stderr"
  else
    "${cmd[@]}" >"${out_json}.raw" 2>"${out_json}.stderr"
  fi
  local rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    log_warn "${name} exited with code ${rc} (non-fatal unless policy enforces). See ${out_json}.stderr"
    FOUND_ERRORS=$((FOUND_ERRORS+1))
  fi
}

# Evaluate simple JSON outputs for severity to increase FOUND_VULNS if at/above threshold.
# This is a heuristic parser using jq if available; otherwise count raw hits.
evaluate_severity() {
  local name="$1"
  local json="$2"
  local field_path="$3"     # jq path to severity string(s), e.g., ".vulnerabilities[].severity"
  local count=0

  if have_cmd jq; then
    local severities
    severities=$(jq -r "${field_path} // empty" "$json" || true)
    while IFS= read -r sev; do
      [[ -z "$sev" ]] && continue
      local rank
      rank=$(severity_rank "$(echo "$sev" | tr '[:upper:]' '[:lower:]')")
      if [[ "$rank" -ge "$THRESHOLD_RANK" ]]; then
        count=$((count+1))
      fi
    done <<< "$severities"
  else
    # Fallback: count occurrences of severity words in file
    case "$SEVERITY_THRESHOLD" in
      critical) count=$(grep -ci "critical" "$json" || true) ;;
      high)     count=$(grep -Eci "critical|high" "$json" || true) ;;
      medium)   count=$(grep -Eci "critical|high|medium|moderate" "$json" || true) ;;
      low)      count=$(grep -Eci "critical|high|medium|moderate|low" "$json" || true) ;;
      none)     count=$(wc -l < "$json" || echo 0) ;;
    esac
  fi

  if [[ "$count" -gt 0 ]]; then
    FOUND_VULNS=$((FOUND_VULNS+count))
    log_warn "${name}: ${count} findings at/above threshold ${SEVERITY_THRESHOLD}"
  else
    log_info "${name}: no findings at/above threshold ${SEVERITY_THRESHOLD}"
  fi
}

# ---------------------------
# Detection of ecosystems
# ---------------------------
detect_enabled() {
  local mode="$1"    # variable name like ENABLE_PYTHON
  local auto="$2"    # auto if present
  local result="false"

  case "$mode" in
    ENABLE_PYTHON)
      [[ -f "requirements.txt" || -f "poetry.lock" || -f "Pipfile.lock" ]] && result="true"
      ;;
    ENABLE_NODE)
      [[ -f "package-lock.json" || -f "yarn.lock" || -f "pnpm-lock.yaml" ]] && result="true"
      ;;
    ENABLE_GO)
      [[ -f "go.mod" ]] && result="true"
      ;;
    ENABLE_RUST)
      [[ -f "Cargo.lock" ]] && result="true"
      ;;
    ENABLE_JAVA)
      [[ -f "pom.xml" || -f "build.gradle" || -f "build.gradle.kts" ]] && result="true"
      ;;
    ENABLE_DOTNET)
      [[ -n "$(ls -1 *.csproj 2>/dev/null || true)" ]] && result="true"
      ;;
    ENABLE_CONTAINER)
      [[ -f "Dockerfile" || -n "${IMAGES:-}" ]] && result="true"
      ;;
    ENABLE_SBOM)
      result="true"
      ;;
  esac
  echo "$result"
}

auto_or_value() {
  local val="$1"; local detect="$2"
  if [[ "$val" == "auto" ]]; then echo "$detect"; else echo "$val"; fi
}

# ---------------------------
# Per-ecosystem runners
# ---------------------------

run_python_audit() {
  local name="python:pip-audit"
  if ! have_cmd pip-audit; then
    log_warn "pip-audit not found; skipping. Install with: pipx install pip-audit"
    return
  fi
  local out="${REPORT_DIR}/python_pip_audit.json"
  run_tool "$name" "$out" pip-audit -r requirements.txt -f json || true

  # If poetry or pipenv locks present, attempt audits
  if [[ -f "poetry.lock" ]]; then
    local name2="python:poetry-export+pip-audit"
    if have_cmd poetry; then
      poetry export -f requirements.txt --without-hashes -o .audit-reqs.txt >/dev/null 2>&1 || true
      run_tool "$name2" "${REPORT_DIR}/python_poetry_pip_audit.json" pip-audit -r .audit-reqs.txt -f json || true
    fi
  fi

  if [[ -f "$out.raw" ]]; then
    filter_with_allowlist "$out.raw" "$out"
    evaluate_severity "$name" "$out" '.vulnerabilities[].severity'
  fi

  # Optional safety
  if have_cmd safety && [[ -f "requirements.txt" ]]; then
    local out2="${REPORT_DIR}/python_safety.json"
    run_tool "python:safety" "$out2" safety check -r requirements.txt --full-report --json || true
    if [[ -f "$out2.raw" ]]; then
      filter_with_allowlist "$out2.raw" "$out2"
      evaluate_severity "python:safety" "$out2" '.issues[].severity'
    fi
  fi

  # Static security (Bandit)
  if have_cmd bandit; then
    local out3="${REPORT_DIR}/python_bandit.sarif"
    run_tool "python:bandit" "$out3" bandit -r . -f sarif || true
    # Bandit SARIF parsing optional
  fi
}

run_node_audit() {
  local mgr=""
  if [[ -f "pnpm-lock.yaml" && "$(have_cmd pnpm && echo yes)" == "yes" ]]; then mgr="pnpm"
  elif [[ -f "yarn.lock" && "$(have_cmd yarn && echo yes)" == "yes" ]]; then mgr="yarn"
  elif [[ -f "package-lock.json" && "$(have_cmd npm && echo yes)" == "yes" ]]; then mgr="npm"
  fi

  if [[ -z "$mgr" ]]; then
    log_warn "Node.js lockfile found but no package manager available; skipping"
    return
  fi

  local out="${REPORT_DIR}/node_${mgr}_audit.json"
  case "$mgr" in
    npm)  run_tool "node:npm-audit" "$out" npm audit --audit-level=low --json || true ;;
    yarn) run_tool "node:yarn-audit" "$out" yarn audit --json || true ;;
    pnpm) run_tool "node:pnpm-audit" "$out" pnpm audit --json || true ;;
  esac

  if [[ -f "$out.raw" ]]; then
    filter_with_allowlist "$out.raw" "$out"
    # Try common paths; differ across managers. Heuristic:
    evaluate_severity "node:${mgr}-audit" "$out" '..|.severity? // empty'
  fi
}

run_go_audit() {
  if ! have_cmd govulncheck; then
    log_warn "govulncheck not found; skipping. Install: go install golang.org/x/vuln/cmd/govulncheck@latest"
    return
  fi
  local out="${REPORT_DIR}/go_govulncheck.json"
  run_tool "go:govulncheck" "$out" govulncheck -json ./... || true
  if [[ -f "$out.raw" ]]; then
    filter_with_allowlist "$out.raw" "$out"
    evaluate_severity "go:govulncheck" "$out" '.vulns[].modules[].vulns[].severity'
  fi
}

run_rust_audit() {
  if ! have_cmd cargo-audit && ! have_cmd cargo; then
    log_warn "cargo/cargo-audit not found; skipping"
    return
  fi
  local out="${REPORT_DIR}/rust_cargo_audit.json"
  if have_cmd cargo-audit; then
    run_tool "rust:cargo-audit" "$out" cargo audit --json || true
  else
    log_warn "cargo-audit not installed; try: cargo install cargo-audit"
    return
  fi
  if [[ -f "$out.raw" ]]; then
    filter_with_allowlist "$out.raw" "$out"
    evaluate_severity "rust:cargo-audit" "$out" '.vulnerabilities.list[].advisory.severity'
  fi
}

run_java_audit() {
  # OWASP Dependency-Check
  if have_cmd dependency-check; then
    local out_json="${REPORT_DIR}/java_dep_check.json"
    local out_sarif="${REPORT_DIR}/java_dep_check.sarif"
    run_tool "java:owasp-dep-check" "$out_json" dependency-check --format JSON --format SARIF --scan . --out "${REPORT_DIR}" || true
    # dependency-check writes files itself; normalize names if needed
    # Severity evaluation best-effort:
    if [[ -f "${REPORT_DIR}/dependency-check-report.json" ]]; then
      filter_with_allowlist "${REPORT_DIR}/dependency-check-report.json" "$out_json"
      evaluate_severity "java:dep-check" "$out_json" '.vulnerabilities[].severity'
    fi
  elif have_cmd mvn; then
    # Fallback: OWASP Dependency-Check Maven plugin if configured in POM
    log_warn "dependency-check CLI not found; consider installing for richer reports"
    run_tool "java:mvn-enforcer" "${REPORT_DIR}/java_mvn_enforcer.json" mvn -q -DskipTests enforcer:enforce || true
  else
    log_warn "No Java audit tool available; skipping"
  fi
}

run_dotnet_audit() {
  if ! have_cmd dotnet; then
    log_warn ".NET SDK not found; skipping"
    return
  fi
  # dotnet list package --vulnerable
  local out="${REPORT_DIR}/dotnet_vulnerable.txt"
  run_tool "dotnet:list-vulnerable" "$out" dotnet list package --vulnerable || true
  # Attempt to transform to JSON (simple)
  if have_cmd jq; then
    grep -E ">" "${out}.raw" || true >/dev/null
  fi
  # Heuristic severity evaluation by keywords:
  [[ -f "${out}.raw" ]] && cp "${out}.raw" "$out" && evaluate_severity "dotnet:list-vulnerable" "$out" '.severity'
}

run_container_audit() {
  # Targets: current project Dockerfile build context or IMAGES env (space-separated)
  local have_trivy=$(have_cmd trivy && echo yes || echo no)
  local have_grype=$(have_cmd grype && echo yes || echo no)

  if [[ "$have_trivy" != "yes" && "$have_grype" != "yes" ]]; then
    log_warn "No container scanners (trivy/grype); skipping container audit"
    return
  fi

  local images=()
  if [[ -n "${IMAGES:-}" ]]; then
    images=(${IMAGES})
  elif [[ -f "Dockerfile" ]]; then
    local tag="local/audit:latest"
    log_info "Building temporary image ${tag}"
    if have_cmd docker; then
      docker build -t "${tag}" . >/dev/null 2>&1 || { log_warn "Docker build failed; skipping image scan"; return; }
      images+=("${tag}")
    else
      log_warn "Docker not available; skipping Dockerfile build"
    fi
  fi

  for img in "${images[@]}"; do
    if [[ "$have_trivy" == "yes" ]]; then
      local out="${REPORT_DIR}/container_trivy_${img//[:\/]/_}.json"
      run_tool "container:trivy" "$out" trivy image --quiet --format json --severity LOW,MEDIUM,HIGH,CRITICAL "$img" || true
      [[ -f "$out.raw" ]] && filter_with_allowlist "$out.raw" "$out" && evaluate_severity "container:trivy" "$out" '.Results[].Vulnerabilities[].Severity'
    fi
    if [[ "$have_grype" == "yes" ]]; then
      local out2="${REPORT_DIR}/container_grype_${img//[:\/]/_}.json"
      run_tool "container:grype" "$out2" grype "$img" -o json || true
      [[ -f "$out2.raw" ]] && filter_with_allowlist "$out2.raw" "$out2" && evaluate_severity "container:grype" "$out2" '.matches[].vulnerability.severity'
    fi
  done
}

run_sbom() {
  if ! have_cmd syft; then
    log_warn "syft not found; skipping SBOM generation"
    return
  fi
  ensure_dir "$SBOM_DIR"
  # SBOM for source and optionally built image
  local out_spdx="${SBOM_DIR}/sbom.spdx.json"
  local out_cdx="${SBOM_DIR}/sbom.cdx.json"
  run_tool "sbom:syft-spdx" "$out_spdx" syft packages dir:. -o spdx-json || true
  run_tool "sbom:syft-cdx"  "$out_cdx"  syft dir:. -o cyclonedx-json || true
}

# ---------------------------
# Main
# ---------------------------
main() {
  ensure_dir "$ARTIFACTS_DIR"
  ensure_dir "$LOG_DIR"
  ensure_dir "$REPORT_DIR"

  log_info "Starting unified dependency audit"
  log_info "Severity threshold: ${SEVERITY_THRESHOLD} (rank ${THRESHOLD_RANK})"
  log_info "Fail policy: ${FAIL_ON}; Timeout per tool: ${TIMEOUT}s; CI=${CI}"

  local d_py d_node d_go d_rust d_java d_dotnet d_cont d_sbom
  d_py=$(detect_enabled ENABLE_PYTHON)
  d_node=$(detect_enabled ENABLE_NODE)
  d_go=$(detect_enabled ENABLE_GO)
  d_rust=$(detect_enabled ENABLE_RUST)
  d_java=$(detect_enabled ENABLE_JAVA)
  d_dotnet=$(detect_enabled ENABLE_DOTNET)
  d_cont=$(detect_enabled ENABLE_CONTAINER)
  d_sbom=$(detect_enabled ENABLE_SBOM)

  local en_py en_node en_go en_rust en_java en_dotnet en_cont en_sbom
  en_py=$(auto_or_value "$ENABLE_PYTHON" "$d_py")
  en_node=$(auto_or_value "$ENABLE_NODE" "$d_node")
  en_go=$(auto_or_value "$ENABLE_GO" "$d_go")
  en_rust=$(auto_or_value "$ENABLE_RUST" "$d_rust")
  en_java=$(auto_or_value "$ENABLE_JAVA" "$d_java")
  en_dotnet=$(auto_or_value "$ENABLE_DOTNET" "$d_dotnet")
  en_cont=$(auto_or_value "$ENABLE_CONTAINER" "$d_cont")
  en_sbom=$(auto_or_value "$ENABLE_SBOM" "$d_sbom")

  [[ "$en_py" == "true"    ]] && run_python_audit
  [[ "$en_node" == "true"  ]] && run_node_audit
  [[ "$en_go" == "true"    ]] && run_go_audit
  [[ "$en_rust" == "true"  ]] && run_rust_audit
  [[ "$en_java" == "true"  ]] && run_java_audit
  [[ "$en_dotnet" == "true"]] && run_dotnet_audit
  [[ "$en_cont" == "true"  ]] && run_container_audit
  [[ "$en_sbom" == "true"  ]] && run_sbom

  # Summaries
  log_info "Audit completed. Findings at/above threshold: ${FOUND_VULNS}, tool errors: ${FOUND_ERRORS}"
  finalize_exit
}

main "$@"
