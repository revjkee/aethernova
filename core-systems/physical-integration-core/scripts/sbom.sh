#!/usr/bin/env bash
# physical-integration-core/scripts/sbom.sh
# Industrial SBOM generator for source trees and container images.
# Features:
#  - CycloneDX JSON + SPDX JSON generation (one or both)
#  - Source dir or container image input
#  - Deterministic metadata (UTC, normalized)
#  - Provenance manifest with tool versions and environment
#  - Integrity checks (SHA256) and JSON validation
#  - Optional signing with cosign
#  - Fallback to Dockerized syft if local tools are absent
#  - Sensible defaults for CI, verbose logs, fail-fast
#
# Exit codes:
#  0  success
#  2  invalid usage
#  3  tools missing and cannot fallback
#  4  generation failed
#  5  validation failed
set -Eeuo pipefail

# ------------- Globals / Defaults -------------
SCRIPT_NAME="${0##*/}"
ROOT_DIR="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd)"
NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || gdate -u +%Y-%m-%dT%H:%M:%SZ)"
HOST_UNAME="$(uname -s || echo unknown)"
FORMAT="both"            # spdx|cyclonedx|both
INPUT_TYPE="dir"         # dir|image
INPUT_PATH="$ROOT_DIR"   # default to repo root
IMAGE_REF=""             # used when INPUT_TYPE=image
OUT_DIR="$ROOT_DIR/build/sbom"
NAME="$(basename "$ROOT_DIR")"
VERSION="${GIT_COMMIT:-}"
USE_DOCKER_FALLBACK="auto"   # auto|always|never
PROVENANCE="true"
SIGN="false"
COSIGN_KEY="${COSIGN_KEY:-}"  # path to cosign.key or KMS URI
VERBOSE="${VERBOSE:-false}"
TOOL_PREF="syft"              # syft|trivy (primary generator)

# ------------- Logging -------------
log()  { printf '[%s] %s\n' "$NOW_UTC" "$*" >&2; }
dbg()  { if [[ "$VERBOSE" == "true" ]]; then printf '[%s][DBG] %s\n' "$NOW_UTC" "$*" >&2; fi; }
die()  { printf '[%s][ERR] %s\n' "$NOW_UTC" "$*" >&2; exit 4; }
usage(){ cat <<EOF
$SCRIPT_NAME — Generate SBOM (CycloneDX/SPDX) for a directory or container image.

Usage:
  $SCRIPT_NAME [--path DIR | --image REF] [--format FMT] [--out DIR]
               [--name NAME] [--version VER] [--tool syft|trivy]
               [--provenance true|false] [--sign true|false] [--cosign-key KEY]
               [--docker-fallback auto|always|never] [--verbose]

Options:
  --path DIR               Source directory to scan (default: repo root)
  --image REF              Container image reference (e.g. ghcr.io/org/app:tag)
  --format FMT             spdx | cyclonedx | both (default: both)
  --out DIR                Output directory (default: build/sbom)
  --name NAME              Component name (default: repo folder name)
  --version VER            Component version (default: \$GIT_COMMIT or git SHA)
  --tool syft|trivy        Primary generator (default: syft)
  --provenance true|false  Emit provenance manifest (default: true)
  --sign true|false        Sign SBOMs with cosign if available (default: false)
  --cosign-key KEY         cosign private key path or KMS URI (optional)
  --docker-fallback MODE   auto|always|never (default: auto)
  --verbose                Verbose logs
  -h, --help               This help

Environment:
  GIT_COMMIT  Pre-set version string; otherwise current git commit is used.

Examples:
  $SCRIPT_NAME --path . --format both --out build/sbom
  $SCRIPT_NAME --image ghcr.io/acme/api:1.2.3 --format cyclonedx --sign true
EOF
}

# ------------- Args parsing -------------
git_rev() {
  (git -C "$ROOT_DIR" rev-parse --short=12 HEAD 2>/dev/null) || echo "unknown"
}
VERSION="${VERSION:-$(git_rev)}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --path) INPUT_TYPE="dir"; INPUT_PATH="${2:?}"; shift 2;;
    --image) INPUT_TYPE="image"; IMAGE_REF="${2:?}"; shift 2;;
    --format) FORMAT="${2:?}"; shift 2;;
    --out) OUT_DIR="${2:?}"; shift 2;;
    --name) NAME="${2:?}"; shift 2;;
    --version) VERSION="${2:?}"; shift 2;;
    --tool) TOOL_PREF="${2:?}"; shift 2;;
    --provenance) PROVENANCE="${2:?}"; shift 2;;
    --sign) SIGN="${2:?}"; shift 2;;
    --cosign-key) COSIGN_KEY="${2:?}"; shift 2;;
    --docker-fallback) USE_DOCKER_FALLBACK="${2:?}"; shift 2;;
    --verbose) VERBOSE="true"; shift;;
    -h|--help) usage; exit 0;;
    *) printf 'Unknown option: %s\n\n' "$1" >&2; usage; exit 2;;
  esac
done

# ------------- Preconditions -------------
require_cmd() { command -v "$1" >/dev/null 2>&1; }
need_or_docker() {
  local cmd="$1"
  if require_cmd "$cmd"; then
    echo "local"
  elif require_cmd docker && [[ "$USE_DOCKER_FALLBACK" != "never" ]]; then
    echo "docker"
  else
    echo "missing"
  fi
}

jq_safe() { if require_cmd jq; then jq "$@"; else cat; fi; }

mkdir -p "$OUT_DIR"

# Normalize format
case "$FORMAT" in
  spdx|cyclonedx|both) ;;
  *) printf 'Invalid --format: %s\n' "$FORMAT" >&2; usage; exit 2;;
esac

if [[ "$INPUT_TYPE" == "dir" ]]; then
  [[ -d "$INPUT_PATH" ]] || { printf 'Directory not found: %s\n' "$INPUT_PATH" >&2; exit 2; }
else
  [[ -n "$IMAGE_REF" ]] || { printf '--image REF is required for image mode\n' >&2; exit 2; }
fi

# ------------- Tool selection -------------
SYFT_MODE="$(need_or_docker syft)"      # local|docker|missing
TRIVY_MODE="$(need_or_docker trivy)"    # local|docker|missing
COSIGN_AVAILABLE="false"
if [[ "$SIGN" == "true" ]] && require_cmd cosign; then COSIGN_AVAILABLE="true"; fi

if [[ "$TOOL_PREF" == "syft" && "$SYFT_MODE" == "missing" && "$TRIVY_MODE" != "missing" ]]; then
  log "syft missing, switching to trivy"
  TOOL_PREF="trivy"
fi
if [[ "$TOOL_PREF" == "trivy" && "$TRIVY_MODE" == "missing" && "$SYFT_MODE" != "missing" ]]; then
  log "trivy missing, switching to syft"
  TOOL_PREF="syft"
fi

if [[ "$TOOL_PREF" == "syft" && "$SYFT_MODE" == "missing" && "$USE_DOCKER_FALLBACK" == "never" ]]; then
  printf 'syft not available and docker fallback disabled\n' >&2; exit 3
fi
if [[ "$TOOL_PREF" == "trivy" && "$TRIVY_MODE" == "missing" && "$USE_DOCKER_FALLBACK" == "never" ]]; then
  printf 'trivy not available and docker fallback disabled\n' >&2; exit 3
fi

# ------------- Helpers to run tools -------------
run_syft() {
  # $1: output file; $2: format (spdx-json|cyclonedx-json); $3: target (dir or image ref)
  local out="$1" fmt="$2" target="$3"
  local args=(packages "$target" --scope all-layers -o "$fmt" --source-name "$NAME" --source-version "$VERSION")
  if [[ "$SYFT_MODE" == "local" ]]; then
    dbg "Running local syft ${args[*]}"
    syft "${args[@]}" > "$out"
  elif [[ "$SYFT_MODE" == "docker" ]]; then
    dbg "Running docker syft ${args[*]}"
    docker run --rm -i \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$PWD":"$PWD" -w "$PWD" \
      anchore/syft:latest "${args[@]}" > "$out"
  else
    return 1
  fi
}

run_trivy() {
  # $1: output file; $2: format (spdx-json|cyclonedx); $3: target (dir or image ref)
  local out="$1" fmt="$2" target="$3"
  local args=(sbom --format "$fmt" --output -)
  if [[ "$INPUT_TYPE" == "dir" ]]; then
    args+=("$target")
  else
    args+=(--image "$target")
  fi
  if [[ "$TRIVY_MODE" == "local" ]]; then
    dbg "Running local trivy ${args[*]}"
    trivy "${args[@]}" > "$out"
  elif [[ "$TRIVY_MODE" == "docker" ]]; then
    dbg "Running docker trivy ${args[*]}"
    docker run --rm -i \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$PWD":"$PWD" -w "$PWD" \
      aquasec/trivy:latest "${args[@]}" > "$out"
  else
    return 1
  fi
}

sha256_file() {
  if require_cmd sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif require_cmd shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    openssl dgst -sha256 "$1" | awk '{print $2}'
  fi
}

validate_json() {
  local f="$1"
  if require_cmd jq; then
    jq -e type "$f" >/dev/null
  else
    # minimal check
    python - <<'PY' "$f" || exit 1
import sys, json
json.load(open(sys.argv[1]))
PY
  fi
}

# ------------- Generation -------------
TARGET_LABEL="$INPUT_PATH"
if [[ "$INPUT_TYPE" == "image" ]]; then
  TARGET_LABEL="$IMAGE_REF"
fi

CYCLONE_OUT=""
SPDX_OUT=""

gen_with() {
  local generator="$1" fmt="$2" out="$3" tgt="$4"
  if [[ "$generator" == "syft" ]]; then
    if [[ "$fmt" == "cyclonedx" ]]; then
      run_syft "$out" "cyclonedx-json" "$tgt"
    else
      run_syft "$out" "spdx-json" "$tgt"
    fi
  else
    if [[ "$fmt" == "cyclonedx" ]]; then
      run_trivy "$out" "cyclonedx" "$tgt"
    else
      run_trivy "$out" "spdx-json" "$tgt"
    fi
  fi
}

emit_provenance() {
  local prov="$1"
  local tool_v_syft="" tool_v_trivy=""
  if [[ "$SYFT_MODE" != "missing" ]]; then tool_v_syft="$( (syft version 2>/dev/null || docker run --rm anchore/syft:latest version) | tr -d '\r' | head -n1 )"; fi
  if [[ "$TRIVY_MODE" != "missing" ]]; then tool_v_trivy="$( (trivy --version 2>/dev/null || docker run --rm aquasec/trivy:latest --version) | tr -d '\r' | head -n1 )"; fi
  cat > "$prov" <<JSON
{
  "schema": "https://veilmind.example/provenance/v1",
  "generated_at": "$NOW_UTC",
  "host_uname": "$HOST_UNAME",
  "component": { "name": "$NAME", "version": "$VERSION" },
  "input": { "type": "$INPUT_TYPE", "target": "$TARGET_LABEL" },
  "formats": "$FORMAT",
  "generator_primary": "$TOOL_PREF",
  "tools": {
    "syft": $(printf '%s' "$(jq -Rn --arg v "$tool_v_syft" '{"version": $v}' )"),
    "trivy": $(printf '%s' "$(jq -Rn --arg v "$tool_v_trivy" '{"version": $v}' )")
  },
  "env": {
    "CI": "${CI:-}",
    "GITHUB_ACTIONS": "${GITHUB_ACTIONS:-}",
    "GIT_COMMIT": "${GIT_COMMIT:-}",
    "PATH": "${PATH}"
  }
}
JSON
}

sign_file() {
  local f="$1"
  if [[ "$SIGN" != "true" || "$COSIGN_AVAILABLE" != "true" ]]; then
    return 0
  fi
  local key_arg=()
  if [[ -n "$COSIGN_KEY" ]]; then key_arg=(--key "$COSIGN_KEY"); fi
  cosign sign-blob "${key_arg[@]}" --output-signature "$f.sig" --output-certificate "$f.cert" "$f" >/dev/null
}

# Decide outputs
base="${OUT_DIR%/}/${NAME}-${VERSION}"
if [[ "$FORMAT" == "cyclonedx" || "$FORMAT" == "both" ]]; then CYCLONE_OUT="${base}.cdx.json"; fi
if [[ "$FORMAT" == "spdx"      || "$FORMAT" == "both" ]]; then SPDX_OUT="${base}.spdx.json"; fi

log "Generating SBOM for $INPUT_TYPE: $TARGET_LABEL"
log "Primary tool: $TOOL_PREF (fallback via Docker: $USE_DOCKER_FALLBACK)"

# Generate CycloneDX
if [[ -n "$CYCLONE_OUT" ]]; then
  dbg "Emit CycloneDX -> $CYCLONE_OUT"
  gen_with "$TOOL_PREF" "cyclonedx" "$CYCLONE_OUT.tmp" "$TARGET_LABEL" || die "CycloneDX generation failed"
  validate_json "$CYCLONE_OUT.tmp" || { rm -f "$CYCLONE_OUT.tmp"; exit 5; }
  # Normalize: enforce top-level metadata if jq is present
  if require_cmd jq; then
    jq '
      .bomFormat="CycloneDX"
      | .specVersion= (.specVersion // "1.5")
      | .serialNumber = (.serialNumber // ("urn:uuid:" + (now|tostring)))
      | .metadata |= (.component.name="'$NAME'" | .component.version="'$VERSION'" | .timestamp="'$NOW_UTC'")
    ' "$CYCLONE_OUT.tmp" > "$CYCLONE_OUT"
    rm -f "$CYCLONE_OUT.tmp"
  else
    mv "$CYCLONE_OUT.tmp" "$CYCLONE_OUT"
  fi
  log "CycloneDX OK: $CYCLONE_OUT (sha256=$(sha256_file "$CYCLONE_OUT"))"
  sign_file "$CYCLONE_OUT" || true
fi

# Generate SPDX
if [[ -n "$SPDX_OUT" ]]; then
  dbg "Emit SPDX -> $SPDX_OUT"
  gen_with "$TOOL_PREF" "spdx" "$SPDX_OUT.tmp" "$TARGET_LABEL" || die "SPDX generation failed"
  validate_json "$SPDX_OUT.tmp" || { rm -f "$SPDX_OUT.tmp"; exit 5; }
  if require_cmd jq; then
    jq '
      .spdxVersion = (.spdxVersion // "SPDX-2.3")
      | .creationInfo |= (.created="'$NOW_UTC'" | .creators += ["Tool: sbom.sh"])
      | .name="'$NAME'" | .documentNamespace = (.documentNamespace // ("http://spdx.org/spdxdocs/'$NAME'-'$VERSION'-" + (now|tostring)))
    ' "$SPDX_OUT.tmp" > "$SPDX_OUT"
    rm -f "$SPDX_OUT.tmp"
  else
    mv "$SPDX_OUT.tmp" "$SPDX_OUT"
  fi
  log "SPDX OK: $SPDX_OUT (sha256=$(sha256_file "$SPDX_OUT"))"
  sign_file "$SPDX_OUT" || true
fi

# Provenance
if [[ "$PROVENANCE" == "true" ]]; then
  PROV_OUT="${base}.provenance.json"
  emit_provenance "$PROV_OUT"
  validate_json "$PROV_OUT" || { rm -f "$PROV_OUT"; exit 5; }
  log "Provenance: $PROV_OUT (sha256=$(sha256_file "$PROV_OUT"))"
  sign_file "$PROV_OUT" || true
fi

# Manifest
MANIFEST="${base}.manifest.txt"
{
  echo "name=$NAME"
  echo "version=$VERSION"
  echo "generated_at=$NOW_UTC"
  echo "input_type=$INPUT_TYPE"
  echo "target=$TARGET_LABEL"
  [[ -n "$CYCLONE_OUT" ]] && echo "cyclonedx=$(realpath "$CYCLONE_OUT" 2>/dev/null || echo "$CYCLONE_OUT")"
  [[ -n "$SPDX_OUT" ]] && echo "spdx=$(realpath "$SPDX_OUT" 2>/dev/null || echo "$SPDX_OUT")"
  [[ "$PROVENANCE" == "true" ]] && echo "provenance=$(realpath "$PROV_OUT" 2>/dev/null || echo "$PROV_OUT")"
} > "$MANIFEST"

log "Done. Manifest: $MANIFEST"
exit 0
