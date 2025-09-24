#!/usr/bin/env bash
# cybersecurity-core/scripts/sbom.sh
# Industrial-grade SBOM generator for directories and container images.
# Features:
#  - Strict bash modes, safe temp handling, clear logging
#  - Syft-based SBOM in SPDX JSON, CycloneDX JSON/XML
#  - Works for filesystem paths and container images
#  - Parallel processing (-j), reproducible output names with timestamps
#  - SHA256 manifest and optional Cosign signing of SBOMs
#  - Optional auto-install of Syft if SYFT_AUTOINSTALL=1

set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"

# -------- Logging --------
log()  { printf "[INFO ] %s\n" "$*" >&2; }
warn() { printf "[WARN ] %s\n" "$*" >&2; }
err()  { printf "[ERROR] %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

# -------- Defaults --------
OUT_DIR="${OUT_DIR:-./artifacts/sbom}"
FORMATS_DEFAULT=("spdx-json" "cyclonedx-json")
FORMATS=()
PARALLEL="${PARALLEL:-2}"
COMPONENT_NAME="${COMPONENT_NAME:-cybersecurity-core}"
COMPONENT_VERSION="${COMPONENT_VERSION:-}"
TOOL="${TOOL:-syft}"  # syft only for now
SIGN="${SIGN:-0}"     # 1 to sign with cosign if available
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CREATE_INDEX=1

# -------- Helpers --------
is_cmd() { command -v "$1" >/dev/null 2>&1; }

sanitize() {
  # Convert an arbitrary string into a safe filename token
  printf "%s" "$1" | tr '/:@ ' '____' | tr -c 'A-Za-z0-9._-_' '_'
}

ext_for_format() {
  case "$1" in
    spdx-json) echo "spdx.json" ;;
    cyclonedx-json) echo "cdx.json" ;;
    cyclonedx-xml) echo "cdx.xml" ;;
    *) die "Unknown format: $1" ;;
  esac
}

syft_output_flag() {
  local fmt="$1"
  case "$fmt" in
    spdx-json) echo "spdx-json" ;;
    cyclonedx-json) echo "cyclonedx-json" ;;
    cyclonedx-xml) echo "cyclonedx-xml" ;;
    *) die "Unknown format: $fmt" ;;
  esac
}

sha256_file() {
  if is_cmd sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif is_cmd shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "No sha256 tool found (sha256sum or shasum)."
  fi
}

json_escape() {
  # naive escape for manifest values
  printf "%s" "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || \
  printf "\"%s\"" "$1" | sed 's/"/\\"/g'
}

# -------- Usage --------
usage() {
  cat <<EOF
${SCRIPT_NAME} v${VERSION}
Generate SBOMs (SPDX JSON, CycloneDX JSON/XML) for directories and container images using Syft.

USAGE:
  ${SCRIPT_NAME} [OPTIONS] -- [TARGET ...]
  ${SCRIPT_NAME} [OPTIONS] [TARGET ...]        # "--" optional

TARGET:
  Filesystem paths (dirs or files) and/or container images.
  For images, pass names as recognized by Syft (e.g. "alpine:3.19", "docker:nginx:1.27").

OPTIONS:
  -o, --out-dir DIR          Output directory (default: ${OUT_DIR})
  -f, --format FMT           SBOM format: spdx-json | cyclonedx-json | cyclonedx-xml
                             May be used multiple times. Default: spdx-json, cyclonedx-json
  -j, --jobs N               Parallel jobs (default: ${PARALLEL})
  -n, --name NAME            Component name for file naming (default: ${COMPONENT_NAME})
  -v, --version VER          Component/app version to include in filenames (optional)
  -s, --sign                 Sign SBOM files with Cosign if available (COSIGN_* env respected)
  --no-index                 Do not create index manifest JSON
  --tool syft                SBOM generator tool (only 'syft' supported)
  --fail-on-missing          Exit if required tools are missing (default behavior)
  --allow-autoinstall        Allow auto-install of Syft when SYFT_AUTOINSTALL=1
  -h, --help                 Show this help

ENV:
  OUT_DIR, PARALLEL, COMPONENT_NAME, COMPONENT_VERSION, SIGN, SYFT_AUTOINSTALL

EXAMPLES:
  ${SCRIPT_NAME} -f spdx-json -f cyclonedx-xml -o artifacts/sbom -- . docker:alpine:3.19
  ${SCRIPT_NAME} -j 4 service/ docker:ghcr.io/org/app:sha-1234
EOF
}

# -------- Parse args --------
ALLOW_AUTOINSTALL=0
FAIL_ON_MISSING=1
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    -f|--format)
      FORMATS+=("$2"); shift 2 ;;
    -j|--jobs) PARALLEL="${2:-}"; shift 2 ;;
    -n|--name) COMPONENT_NAME="${2:-}"; shift 2 ;;
    -v|--version) COMPONENT_VERSION="${2:-}"; shift 2 ;;
    -s|--sign) SIGN=1; shift 1 ;;
    --no-index) CREATE_INDEX=0; shift 1 ;;
    --tool) TOOL="${2:-}"; shift 2 ;;
    --allow-autoinstall) ALLOW_AUTOINSTALL=1; shift 1 ;;
    --fail-on-missing) FAIL_ON_MISSING=1; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; while [[ $# -gt 0 ]]; do TARGETS+=("$1"); shift; done ;;
    -*)
      die "Unknown option: $1 (use --help)"
      ;;
    *)
      TARGETS+=("$1"); shift ;;
  esac
done

if [[ ${#FORMATS[@]} -eq 0 ]]; then
  FORMATS=("${FORMATS_DEFAULT[@]}")
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=(".")
fi

# -------- Check deps --------
need_syft() {
  if ! is_cmd syft; then
    if [[ "${SYFT_AUTOINSTALL:-0}" == "1" && $ALLOW_AUTOINSTALL -eq 1 ]]; then
      warn "syft not found. Attempting auto-install..."
      curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
        sh -s -- -b "${SYFT_INSTALL_BIN:-/usr/local/bin}" "${SYFT_VERSION:-v1.17.0}" || \
        die "Failed to auto-install syft."
      log "syft installed."
    else
      die "Required tool 'syft' is not installed. Set SYFT_AUTOINSTALL=1 and pass --allow-autoinstall to auto-install."
    fi
  fi
}

need_cosign() {
  if [[ $SIGN -eq 1 ]] && ! is_cmd cosign; then
    warn "Signing requested but 'cosign' not found. Skipping signing."
    SIGN=0
  fi
}

case "$TOOL" in
  syft) need_syft ;;
  *) die "Unsupported tool: $TOOL" ;;
esac
need_cosign

# -------- Prep output --------
mkdir -p "$OUT_DIR"
TMPDIR_ROOT="$(mktemp -d 2>/dev/null || mktemp -d -t sbomtmp)"
cleanup() {
  rm -rf "$TMPDIR_ROOT" || true
}
trap cleanup EXIT

# -------- Core generation --------
gen_one() {
  local target="$1"
  local target_token
  target_token="$(sanitize "$target")"

  local comp="${COMPONENT_NAME}"
  local ver="${COMPONENT_VERSION}"
  local base="${comp}-${ver:+${ver}-}${target_token}-${TIMESTAMP}"
  local created=()
  local failed=0

  for fmt in "${FORMATS[@]}"; do
    local ext; ext="$(ext_for_format "$fmt")"
    local out="${OUT_DIR}/${base}.${ext}"
    local out_tmp="${TMPDIR_ROOT}/${base}.${ext}.tmp"

    # syft output mapping
    local syft_fmt; syft_fmt="$(syft_output_flag "$fmt")"

    # Generate SBOM with syft
    if ! syft "packages:${target}" -o "${syft_fmt}=${out_tmp}" >/dev/null 2>&1; then
      warn "Syft failed for ${target} (${fmt})"
      failed=1
      continue
    fi

    # Atomically move
    mv -f "$out_tmp" "$out"

    # Compute sha256
    local sha; sha="$(sha256_file "$out")"
    printf "%s  %s\n" "$sha" "$(basename "$out")" >> "${OUT_DIR}/SHA256SUMS.txt"

    created+=("$out")

    # Optional signing (detached)
    if [[ $SIGN -eq 1 ]]; then
      if cosign sign-blob --yes --output-signature "${out}.sig" --output-certificate "${out}.crt" "$out" >/dev/null 2>&1; then
        : # ok
      else
        warn "Cosign signing failed for ${out}"
      fi
    fi
  done

  # Per-target manifest line (append)
  if [[ $CREATE_INDEX -eq 1 ]]; then
    local idx="${OUT_DIR}/index-manifest.jsonl"
    local files_json="[]"
    if is_cmd jq; then
      # Build JSON array of files with hashes
      local arr="[]"
      for f in "${created[@]}"; do
        local sha; sha="$(sha256_file "$f")"
        arr=$(jq -c --arg f "$(basename "$f")" --arg sha "$sha" '. + [{file:$f, sha256:$sha}]' <<<"$arr")
      done
      files_json="$arr"
    else
      # Fallback minimal JSONish without jq
      local items=""
      for f in "${created[@]}"; do
        local sha; sha="$(sha256_file "$f")"
        items="${items}{\"file\":\"$(basename "$f")\",\"sha256\":\"${sha}\"},"
      done
      files_json="[${items%,}]"
    fi

    {
      printf "{"
      printf "\"timestamp\":\"%s\"," "$TIMESTAMP"
      printf "\"component_name\":%s," "$(json_escape "$comp")"
      printf "\"component_version\":%s," "$(json_escape "${ver:-unknown}")"
      printf "\"target\":%s," "$(json_escape "$target")"
      printf "\"files\":%s" "$files_json"
      printf "}\n"
    } >> "$idx"
  fi

  # Return result
  if [[ $failed -eq 1 ]]; then
    return 1
  else
    return 0
  fi
}

export -f gen_one sanitize ext_for_format syft_output_flag sha256_file json_escape
export OUT_DIR COMPONENT_NAME COMPONENT_VERSION TIMESTAMP SIGN CREATE_INDEX TMPDIR_ROOT
export -f log warn err die

# -------- Dispatch (parallel) --------
log "Starting SBOM generation"
log "Output: $(readlink -f "$OUT_DIR" 2>/dev/null || realpath "$OUT_DIR" 2>/dev/null || echo "$OUT_DIR")"
log "Formats: ${FORMATS[*]}"
log "Targets: ${TARGETS[*]}"
log "Parallel jobs: ${PARALLEL}"

# Use xargs -P for parallel processing
# Build a null-delimited list to safely handle spaces
tmp_targets="${TMPDIR_ROOT}/targets.txt"
: > "$tmp_targets"
for t in "${TARGETS[@]}"; do
  printf "%s\0" "$t" >> "$tmp_targets"
done

# shellcheck disable=SC2010
if ! xargs -0 -n1 -P "${PARALLEL}" bash -c 'gen_one "$0"' < "$tmp_targets"; then
  warn "One or more SBOM generations failed."
  exit 2
fi

# -------- Finalize --------
if [[ -f "${OUT_DIR}/SHA256SUMS.txt" ]]; then
  sort -o "${OUT_DIR}/SHA256SUMS.txt" "${OUT_DIR}/SHA256SUMS.txt" || true
fi

if [[ $CREATE_INDEX -eq 1 && -f "${OUT_DIR}/index-manifest.jsonl" ]]; then
  log "Index manifest: ${OUT_DIR}/index-manifest.jsonl"
fi

log "SBOM generation complete."
