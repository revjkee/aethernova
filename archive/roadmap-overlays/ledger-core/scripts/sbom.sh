#!/usr/bin/env bash
# ledger-core/scripts/sbom.sh
# Unified SBOM generator for source directories and container images.
# Features:
# - Formats: cyclonedx-json|cyclonedx-xml|spdx-json
# - Targets: directory path or container image (docker|podman)
# - Tooling: prefers Syft; falls back to Trivy or CycloneDX ecosystem tools
# - Deterministic metadata (SOURCE_DATE_EPOCH via git), project name/version overrides
# - Optional Cosign signing and in-toto attestation
# - Cache directory, strict error handling, quiet mode, JSON schema-friendly output
#
# Exit codes:
#  0 success
#  2 usage error
#  3 unsupported target/format
#  4 tooling missing
#  5 generation failed
#  6 signing/attestation failed

set -Eeuo pipefail

# -------------
# Defaults
# -------------
FORMAT="${FORMAT:-cyclonedx-json}"   # cyclonedx-json|cyclonedx-xml|spdx-json
TARGET=""                             # path or image
OUT="${OUT:-}"                        # output file path; default derived from target
PROJECT_NAME="${PROJECT_NAME:-}"      # override component name
PROJECT_VERSION="${PROJECT_VERSION:-}"# override component version
PROVIDER="${PROVIDER:-auto}"          # auto|syft|trivy|cyclonedx-bom
CACHE_DIR="${CACHE_DIR:-.sbom-cache}"
QUIET="${QUIET:-0}"
ATTACH_PROVENANCE="${ATTACH_PROVENANCE:-0}" # 1 -> emit .intoto attestation
COSIGN_SIGN="${COSIGN_SIGN:-0}"             # 1 -> cosign sign-blob attestation
COSIGN_KEY="${COSIGN_KEY:-}"                # path to cosign key (or env COSIGN_PASSWORD)
DOCKER_BIN="${DOCKER_BIN:-}"                # docker|podman autodetected if empty
COLOR="${COLOR:-auto}"                      # auto|always|never

# -------------
# Logging
# -------------
_is_tty() { [ -t 2 ]; }
_use_color() {
  case "$COLOR" in
    always) return 0;;
    never)  return 1;;
    auto)   _is_tty;;
    *)      _is_tty;;
  esac
}
if _use_color; then
  c_reset=$'\033[0m'; c_red=$'\033[31m'; c_yel=$'\033[33m'; c_grn=$'\033[32m'; c_cyn=$'\033[36m'
else
  c_reset=""; c_red=""; c_yel=""; c_grn=""; c_cyn=""
fi
log()  { [ "$QUIET" = "1" ] || printf "%s[SBOM]%s %s\n" "$c_cyn" "$c_reset" "$*" >&2; }
ok()   { [ "$QUIET" = "1" ] || printf "%s[OK]%s %s\n" "$c_grn" "$c_reset" "$*" >&2; }
warn() { printf "%s[WARN]%s %s\n" "$c_yel" "$c_reset" "$*" >&2; }
err()  { printf "%s[ERR ]%s %s\n" "$c_red" "$c_reset" "$*" >&2; }

# -------------
# Usage
# -------------
usage() {
  cat >&2 <<EOF
Usage:
  $(basename "$0") -t <target> [-f <format>] [-o <out>] [--name N] [--version V]
                   [--provider auto|syft|trivy|cyclonedx-bom]
                   [--cache DIR] [--quiet]
                   [--attest] [--cosign] [--cosign-key KEY]

Targets:
  - directory path (source tree root)
  - container image reference (e.g. ghcr.io/org/app:tag). Requires docker or podman.

Formats:
  cyclonedx-json (default), cyclonedx-xml, spdx-json

Examples:
  # Source tree to CycloneDX JSON with git-based version
  $(basename "$0") -t . -f cyclonedx-json -o build/sbom.cdx.json

  # Container image to SPDX JSON, sign attestation with cosign key
  $(basename "$0") -t ghcr.io/org/app:1.2.3 -f spdx-json --attest --cosign --cosign-key ./cosign.key

Environment overrides:
  FORMAT, OUT, PROJECT_NAME, PROJECT_VERSION, PROVIDER, CACHE_DIR, QUIET, COLOR
EOF
  exit 2
}

# -------------
# Parse args
# -------------
long_opts=$(getopt -o t:f:o:h --long target:,format:,out:,help,name:,version:,provider:,cache:,quiet,attest,cosign,cosign-key:,color: -n sbom -- "$@") || usage
eval set -- "$long_opts"
while true; do
  case "$1" in
    -t|--target) TARGET="$2"; shift 2;;
    -f|--format) FORMAT="$2"; shift 2;;
    -o|--out) OUT="$2"; shift 2;;
    --name) PROJECT_NAME="$2"; shift 2;;
    --version) PROJECT_VERSION="$2"; shift 2;;
    --provider) PROVIDER="$2"; shift 2;;
    --cache) CACHE_DIR="$2"; shift 2;;
    --quiet) QUIET="1"; shift;;
    --attest) ATTACH_PROVENANCE="1"; shift;;
    --cosign) COSIGN_SIGN="1"; shift;;
    --cosign-key) COSIGN_KEY="$2"; shift 2;;
    --color) COLOR="$2"; shift 2;;
    -h|--help) usage;;
    --) shift; break;;
    *) usage;;
  esac
done

[ -n "${TARGET:-}" ] || usage

# -------------
# Helpers
# -------------
die() { err "$*"; exit "${2:-1}"; }

is_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_docker() {
  if [ -n "$DOCKER_BIN" ]; then echo "$DOCKER_BIN"; return; fi
  if is_cmd docker; then echo docker; return; fi
  if is_cmd podman; then echo podman; return; fi
  echo ""
}

is_image_ref() {
  # Simple heuristic: contains ':' or '@' and not an existing path
  if [ -e "$1" ]; then return 1; fi
  case "$1" in
    *@*|*:*/*|*:* ) return 0;;
    * ) return 1;;
  esac
}

ext_for_format() {
  case "$1" in
    cyclonedx-json) echo "cdx.json";;
    cyclonedx-xml)  echo "cdx.xml";;
    spdx-json)      echo "spdx.json";;
    *) return 1;;
  esac
}

provider_available() {
  case "$1" in
    syft) is_cmd syft && return 0 || return 1;;
    trivy) is_cmd trivy && return 0 || return 1;;
    cyclonedx-bom) is_cmd cyclonedx-bom && return 0 || return 1;;
    *) return 1;;
  esac
}

pick_provider() {
  case "$PROVIDER" in
    auto)
      if provider_available syft; then echo syft; return; fi
      if provider_available trivy; then echo trivy; return; fi
      if provider_available cyclonedx-bom; then echo cyclonedx-bom; return; fi
      ;;
    syft|trivy|cyclonedx-bom)
      if provider_available "$PROVIDER"; then echo "$PROVIDER"; return; fi
      ;;
  esac
  return 1
}

# -------------
# Deterministic metadata (project name/version, timestamp)
# -------------
git_root() { git rev-parse --show-toplevel 2>/dev/null || true; }
git_describe() { git describe --tags --always --dirty 2>/dev/null || true; }
git_commit_date() { git log -1 --format=%ct 2>/dev/null || true; }

derive_project_name() {
  if [ -n "${PROJECT_NAME:-}" ]; then echo "$PROJECT_NAME"; return; fi
  if [ -e "$TARGET" ]; then
    basename "$(cd "$TARGET" && pwd)"
  else
    # image ref as name
    echo "${TARGET//@/at_}" | tr '/:' '__'
  fi
}

derive_project_version() {
  if [ -n "${PROJECT_VERSION:-}" ]; then echo "$PROJECT_VERSION"; return; fi
  if [ -e "$TARGET" ]; then
    local gr; gr="$(git_root)"
    if [ -n "$gr" ]; then git_describe; else echo "0.0.0-dev"; fi
  else
    # image tag portion
    case "$TARGET" in
      *@*) echo "${TARGET##*@}";;
      *:*) echo "${TARGET##*:}";;
      *)   echo "latest";;
    esac
  fi
}

export_deterministic_time() {
  if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    local ts; ts="$(git_commit_date)"; ts="${ts:-0}"
    if [ "$ts" -gt 0 ] 2>/dev/null; then
      export SOURCE_DATE_EPOCH="$ts"
    else
      export SOURCE_DATE_EPOCH=0
    fi
  fi
}

# -------------
# Output path
# -------------
prepare_out() {
  local name ver ext base
  name="$(derive_project_name)"
  ver="$(derive_project_version)"
  ext="$(ext_for_format "$FORMAT")" || die "Unsupported format: $FORMAT" 3
  if [ -z "$OUT" ]; then
    mkdir -p "build"
    OUT="build/sbom-${name}-${ver}.${ext}"
  fi
  mkdir -p "$(dirname "$OUT")" "$CACHE_DIR"
}

# -------------
# Tool invocations
# -------------
run_syft() {
  local subject="$1"
  local fmt="$2"
  local name ver
  name="$(derive_project_name)"
  ver="$(derive_project_version)"

  local syft_format=""
  case "$fmt" in
    cyclonedx-json) syft_format="cyclonedx-json";;
    cyclonedx-xml)  syft_format="cyclonedx-xml";;
    spdx-json)      syft_format="spdx-json";;
    *) die "Syft does not support format: $fmt" 3;;
  esac

  # For directories syft packages dir; for images it pulls via docker/podman if available
  if is_image_ref "$subject"; then
    local dk; dk="$(detect_docker)"
    [ -n "$dk" ] || log "No docker/podman found; syft may use registry auth helpers if configured."
  fi

  # Add component metadata via --catalogers-config if provided; otherwise rely on BOM metadata fields
  syft "$subject" -o "${syft_format}" --source-name "$name" --source-version "$ver"
}

run_trivy() {
  local subject="$1"
  local fmt="$2"
  local name ver
  name="$(derive_project_name)"; ver="$(derive_project_version)"

  local t_format=""
  case "$fmt" in
    cyclonedx-json) t_format="cyclonedx";;
    spdx-json)      t_format="spdx";;
    cyclonedx-xml)  die "Trivy does not emit CycloneDX XML via SBOM command" 3;;
  esac

  if is_image_ref "$subject"; then
    trivy image --quiet --format "$t_format" --output - "$subject" | sed '1!b;s/.*/&/;' # pass-through
  else
    trivy fs --quiet --format "$t_format" --output - "$subject"
  fi
}

run_cyclonedx_bom() {
  # Works well for Node/Java/Python projects with lockfiles; as a fallback only for directories
  local subject="$1"
  [ -e "$subject" ] || die "CycloneDX generator supports only directories" 3
  case "$FORMAT" in
    cyclonedx-json) cyclonedx-bom --output-format json --exclude-dev -o - "$subject";;
    cyclonedx-xml)  cyclonedx-bom --output-format xml  --exclude-dev -o - "$subject";;
    spdx-json)      die "cyclonedx-bom does not produce SPDX" 3;;
  esac
}

generate_bom() {
  local provider="$1" subject="$2" fmt="$3"
  case "$provider" in
    syft) run_syft "$subject" "$fmt";;
    trivy) run_trivy "$subject" "$fmt";;
    cyclonedx-bom) run_cyclonedx_bom "$subject";;
    *) die "Unknown provider: $provider" 4;;
  esac
}

# -------------
# Signing / Attestation
# -------------
emit_attestation() {
  # Create minimal in-toto statement referencing SBOM file digest
  local artifact="$1"; local att_out="${artifact}.intoto.jsonl"
  local sha; sha="$(sha256sum "$artifact" | awk '{print $1}')"
  cat >"$att_out" <<JSON
{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"$(basename "$artifact")","digest":{"sha256":"$sha"}}],"predicateType":"https://slsa.dev/provenance/1.0","predicate":{"buildType":"custom:sbom","builder":{"id":"ledger-core/scripts/sbom.sh"},"metadata":{"sourceUri":"${TARGET}","buildStartedOn":"$(date -u +%FT%TZ)","reproducible":true}}}
JSON
  echo "$att_out"
}

cosign_sign_blob() {
  local file="$1"
  [ "$COSIGN_SIGN" = "1" ] || return 0
  is_cmd cosign || die "cosign not found for signing" 6
  local key_args=()
  if [ -n "$COSIGN_KEY" ]; then key_args+=(--key "$COSIGN_KEY"); else key_args+=(--key env://COSIGN_PASSWORD); fi
  cosign sign-blob "${key_args[@]}" --yes "$file" >/dev/null 2>&1 || die "cosign sign-blob failed" 6
  ok "Signed $(basename "$file") with cosign"
}

# -------------
# Main
# -------------
main() {
  export_deterministic_time
  prepare_out
  local provider; provider="$(pick_provider)" || die "No supported SBOM tool found. Install syft or trivy or cyclonedx-bom." 4

  log "Provider: $provider"
  log "Format:   $FORMAT"
  log "Target:   $TARGET"
  log "Output:   $OUT"

  # Generate
  if ! generate_bom "$provider" "$TARGET" "$FORMAT" >"$OUT".tmp; then
    rm -f "$OUT".tmp || true
    die "SBOM generation failed" 5
  fi

  # Normalize JSON whitespace for json formats (determinism)
  case "$FORMAT" in
    *json)
      if is_cmd jq; then
        jq -S . <"$OUT".tmp >"$OUT"
      else
        mv "$OUT".tmp "$OUT"
      fi
      ;;
    *)
      mv "$OUT".tmp "$OUT"
      ;;
  endcase

  ok "SBOM saved to $OUT"

  # Attestation
  if [ "$ATTACH_PROVENANCE" = "1" ]; then
    local att; att="$(emit_attestation "$OUT")"
    ok "Attestation saved to $att"
    cosign_sign_blob "$att"
  fi
}

main "$@"
