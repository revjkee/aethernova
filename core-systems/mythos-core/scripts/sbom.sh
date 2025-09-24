#!/usr/bin/env bash
# mythos-core/scripts/sbom.sh
# Industrial SBOM generator & signer for source trees and container images.
# Features:
#  - Generates CycloneDX (JSON/XML) and SPDX (JSON) via syft
#  - Works on a project directory and/or docker/oci image refs
#  - Module-aware (-r): scans submodules and produces per-module SBOMs + index
#  - Atomic writes, SHA-256 checksums, optional signing (cosign/openssl) & verification
#  - Optional in-toto style attestations for images via cosign attest
#  - Deterministic naming: <name>-<version>-<target>-<format>.{json|xml}
# Exit codes:
#  0 OK, 1 usage error, 2 missing deps, 3 generation error, 4 signing error, 5 verify error

set -euo pipefail
IFS=$'\n\t'

# ----------- Defaults -----------
PROJECT_PATH="."
OUTPUT_DIR="dist/sbom"
FORMATS="cdx-json,spdx-json"   # supported: cdx-json, cdx-xml, spdx-json
IMAGE_REFS=()                  # one or multiple -i
RECURSIVE=false
PROJECT_NAME=""
PROJECT_VERSION=""
SIGN_KEY=""                    # file path for cosign/openssl private key
PUB_KEY=""                     # public key for verify
DO_ATTEST=false                # cosign attest for images
DO_VERIFY=false
TIMESTAMP_FMT="%Y-%m-%dT%H:%M:%SZ"

# ----------- Logging -----------
log()  { printf "[%s] %s\n" "$(date -u +$TIMESTAMP_FMT)" "$*" >&2; }
die()  { log "ERROR: $*"; exit "${2:-1}"; }

# ----------- Helpers -----------
usage() {
  cat <<'USAGE' >&2
Usage: sbom.sh [options]

Targets:
  -p <path>           Project directory to scan (default: .)
  -i <image-ref>      Container image ref (repeatable), e.g. ghcr.io/org/app:1.2.3

Output:
  -o <dir>            Output directory (default: dist/sbom)
  -f <formats>        Comma list: cdx-json,cdx-xml,spdx-json (default: cdx-json,spdx-json)
  -r                  Recursive module scan (subdirectories with manifests)

Identity:
  -n <name>           Override project name (default: dirname of -p)
  -v <version>        Override version (default: VERSION file or git describe or 0.0.0)

Security:
  -S <privkey>        Sign artifacts (cosign if available, else openssl)
  -A                  Create attestations for images (cosign attest; requires -S or keyless env)
  -V                  Verify signatures of artifacts in output dir
  -K <pubkey>         Public key for verify (cosign or openssl)

Other:
  -h                  Help

Notes:
  Requires: syft. Optional: jq, cosign, openssl, git.
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }
sha256_file() { if have sha256sum; then sha256sum "$1" | awk '{print $1}'; else shasum -a256 "$1" | awk '{print $1}'; fi; }
mkdirs() { mkdir -p "$1"; }
sanitize() { tr '/:@ ' '_-' <<<"$1"; }
atomic_write() {
  local src="$1" dst="$2" tmp
  tmp="$(mktemp -p "$(dirname "$dst")" .sbom.XXXXXX)"
  cp -f "$src" "$tmp"
  mv -f "$tmp" "$dst"
}

# Detect name/version if not set
detect_identity() {
  if [[ -z "$PROJECT_NAME" ]]; then
    PROJECT_NAME="$(basename "$(cd "$PROJECT_PATH" && pwd)")"
  fi
  if [[ -z "$PROJECT_VERSION" ]]; then
    if [[ -f "$PROJECT_PATH/VERSION" ]]; then
      PROJECT_VERSION="$(tr -d '\r\n ' < "$PROJECT_PATH/VERSION")"
    elif have git && git -C "$PROJECT_PATH" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      set +e
      PROJECT_VERSION="$(git -C "$PROJECT_PATH" describe --tags --always --dirty 2>/dev/null)"
      rc=$?
      set -e
      [[ $rc -eq 0 && -n "$PROJECT_VERSION" ]] || PROJECT_VERSION="0.0.0"
    else
      PROJECT_VERSION="0.0.0"
    fi
  fi
}

# Parse args
while getopts ":p:i:o:f:n:v:S:AK:Vrth" opt; do
  case "$opt" in
    p) PROJECT_PATH="$OPTARG" ;;
    i) IMAGE_REFS+=("$OPTARG") ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    f) FORMATS="$OPTARG" ;;
    n) PROJECT_NAME="$OPTARG" ;;
    v) PROJECT_VERSION="$OPTARG" ;;
    S) SIGN_KEY="$OPTARG" ;;
    A) DO_ATTEST=true ;;
    V) DO_VERIFY=true ;;
    K) PUB_KEY="$OPTARG" ;;
    r) RECURSIVE=true ;;
    h) usage; exit 0 ;;
    \?) die "Unknown option: -$OPTARG" 1 ;;
    :)  die "Option -$OPTARG requires an argument" 1 ;;
  esac
done

# Validate deps
have syft || die "syft is required. Install: https://github.com/anchore/syft" 2
if $DO_VERIFY || [[ -n "$SIGN_KEY" ]] || $DO_ATTEST; then
  if ! have cosign && ! have openssl; then
    die "Signing/verification requested but neither cosign nor openssl is available" 2
  fi
fi

detect_identity
mkdirs "$OUTPUT_DIR"
log "Project: $PROJECT_NAME @ $PROJECT_VERSION"
log "Output : $OUTPUT_DIR"
log "Formats: $FORMATS"

# Normalize formats
IFS=',' read -r -a FMT_ARR <<<"$FORMATS"
valid_fmt() {
  case "$1" in
    cdx-json|cdx-xml|spdx-json) return 0 ;;
    *) return 1 ;;
  esac
}

for f in "${FMT_ARR[@]}"; do
  valid_fmt "$f" || die "Unsupported format: $f" 1
done

# ----------- Generators -----------
gen_for_dir() {
  local dir="$1" modname="$2"
  for fmt in "${FMT_ARR[@]}"; do
    local ext="json" syft_fmt=""
    case "$fmt" in
      cdx-json) syft_fmt="cyclonedx-json"; ext="json" ;;
      cdx-xml)  syft_fmt="cyclonedx-xml";  ext="xml"  ;;
      spdx-json) syft_fmt="spdx-json";     ext="json" ;;
    esac
    local base="${PROJECT_NAME}-${PROJECT_VERSION}-${modname}-${fmt}"
    local out_tmp="${OUTPUT_DIR}/.${base}.tmp.${ext}"
    local out="${OUTPUT_DIR}/${base}.${ext}"

    log "Generating SBOM ($fmt) for module: $modname"
    # syft dir scan
    if ! syft "dir:${dir}" -q -o "$syft_fmt" > "$out_tmp"; then
      rm -f "$out_tmp"
      die "SBOM generation failed for ${modname} ($fmt)" 3
    fi
    atomic_write "$out_tmp" "$out"
    rm -f "$out_tmp"

    # checksum
    local sum
    sum="$(sha256_file "$out")"
    echo "${sum}  $(basename "$out")" > "${out}.sha256"
    log "Wrote: $(basename "$out") (sha256=${sum})"

    # sign (optional)
    if [[ -n "$SIGN_KEY" ]]; then
      sign_artifact "$out" || die "Signing failed for $out" 4
    fi
  done
}

gen_for_image() {
  local image="$1"
  local imgkey
  imgkey="$(sanitize "$image")"
  for fmt in "${FMT_ARR[@]}"; do
    local ext="json" syft_fmt=""
    case "$fmt" in
      cdx-json) syft_fmt="cyclonedx-json"; ext="json" ;;
      cdx-xml)  syft_fmt="cyclonedx-xml";  ext="xml"  ;;
      spdx-json) syft_fmt="spdx-json";     ext="json" ;;
    esac
    local base="${PROJECT_NAME}-${PROJECT_VERSION}-image_${imgkey}-${fmt}"
    local out_tmp="${OUTPUT_DIR}/.${base}.tmp.${ext}"
    local out="${OUTPUT_DIR}/${base}.${ext}"

    log "Generating SBOM ($fmt) for image: $image"
    if ! syft "$image" -q -o "$syft_fmt" > "$out_tmp"; then
      rm -f "$out_tmp"
      die "SBOM generation failed for image ${image} ($fmt)" 3
    fi
    atomic_write "$out_tmp" "$out"
    rm -f "$out_tmp"

    local sum
    sum="$(sha256_file "$out")"
    echo "${sum}  $(basename "$out")" > "${out}.sha256"
    log "Wrote: $(basename "$out") (sha256=${sum})"

    if [[ -n "$SIGN_KEY" ]]; then
      sign_artifact "$out" || die "Signing failed for $out" 4
    fi

    if $DO_ATTEST; then
      attest_image_with_predicate "$image" "$out" "$fmt" || die "Attestation failed for $image" 4
    fi
  done
}

# ----------- Signing / Verification -----------
# Prefer cosign for detached signatures. Fallback to openssl CMS detached.
sign_artifact() {
  local file="$1"
  if have cosign; then
    # cosign sign-blob produces <file>.sig and cosign bundle if asked; keep simple
    local sig="${file}.sig"
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --key "$SIGN_KEY" --output-signature "$sig" "$file" >/dev/null
    log "Signed (cosign): $(basename "$sig")"
    return 0
  elif have openssl; then
    # Detached CMS signature (PEM) with SHA256
    local sig="${file}.pem"
    openssl cms -sign -binary -in "$file" -signer "$SIGN_KEY" -outform PEM -out "$sig" -nodetach -md sha256 >/dev/null 2>&1 || return 1
    log "Signed (openssl CMS): $(basename "$sig")"
    return 0
  fi
  return 1
}

verify_artifacts() {
  local status=0
  shopt -s nullglob
  for f in "$OUTPUT_DIR"/*.{json,xml}; do
    # checksum
    if [[ -f "${f}.sha256" ]]; then
      local expected actual
      expected="$(awk '{print $1}' < "${f}.sha256")"
      actual="$(sha256_file "$f")"
      if [[ "$expected" != "$actual" ]]; then
        log "Checksum mismatch: $(basename "$f")"
        status=5
      fi
    fi
    # signature
    if [[ -n "$PUB_KEY" ]]; then
      if have cosign && [[ -f "${f}.sig" ]]; then
        set +e
        COSIGN_EXPERIMENTAL=1 cosign verify-blob --key "$PUB_KEY" --signature "${f}.sig" "$f" >/dev/null 2>&1
        rc=$?
        set -e
        if [[ $rc -ne 0 ]]; then
          log "Signature verify failed (cosign): $(basename "$f")"
          status=5
        else
          log "Verified (cosign): $(basename "$f")"
        fi
      elif have openssl && [[ -f "${f}.pem" ]]; then
        set +e
        openssl cms -verify -binary -in "${f}.pem" -inform PEM -content "$f" -CAfile "$PUB_KEY" >/dev/null 2>&1
        rc=$?
        set -e
        if [[ $rc -ne 0 ]]; then
          log "Signature verify failed (openssl): $(basename "$f")"
          status=5
        else
          log "Verified (openssl): $(basename "$f")"
        fi
      fi
    fi
  done
  return $status
}

attest_image_with_predicate() {
  local image="$1" predicate="$2" fmt="$3"
  have cosign || { log "cosign required for attest; skipping"; return 0; }
  local ptype=""
  case "$fmt" in
    cdx-json|cdx-xml) ptype="https://cyclonedx.org/bom" ;;
    spdx-json)        ptype="https://spdx.dev/Document" ;;
    *) ptype="application/vnd.cyclonedx" ;;
  esac
  log "Creating attestation for ${image} (predicate=$(basename "$predicate"))"
  # Key can be keyless if environment supports OIDC; otherwise use --key
  if [[ -n "$SIGN_KEY" ]]; then
    COSIGN_EXPERIMENTAL=1 cosign attest --key "$SIGN_KEY" --predicate "$predicate" --type "$ptype" "$image" >/dev/null
  else
    COSIGN_EXPERIMENTAL=1 cosign attest --predicate "$predicate" --type "$ptype" "$image" >/dev/null
  fi
}

# ----------- Module discovery -----------
discover_modules() {
  # Emit list of module directories to stdout. Heuristics: presence of common manifests.
  local root="$1"
  local -a mods=()
  while IFS= read -r -d '' d; do mods+=("$d"); done < <(
    find "$root" -type d \( -name ".git" -o -name "node_modules" -o -name ".venv" -o -name "venv" -o -name "dist" -o -name "build" -o -name "target" \) -prune -false -o \
      \( -name "package.json" -o -name "pyproject.toml" -o -name "requirements.txt" -o -name "Pipfile" -o -name "go.mod" -o -name "Cargo.toml" -o -name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" \) \
      -printf '%h\0' | sort -zu | uniq -z
  )
  printf "%s\n" "${mods[@]}"
}

# ----------- Main flow -----------
INDEX_FILE="${OUTPUT_DIR}/index.json"
echo '{ "artifacts": [] }' > "${INDEX_FILE}.tmp"

add_index() {
  local path="$1" kind="$2" target="$3" sha="$(sha256_file "$1")"
  if have jq; then
    jq --arg p "$(basename "$path")" --arg k "$kind" --arg t "$target" --arg s "$sha" \
      '.artifacts += [{file:$p, kind:$k, target:$t, sha256:$s}]' \
      "${INDEX_FILE}.tmp" > "${INDEX_FILE}.tmp2"
    mv -f "${INDEX_FILE}.tmp2" "${INDEX_FILE}.tmp"
  else
    # Fallback: append line-based index next to JSON
    echo "$(basename "$path"))|$kind|$target|$sha" >> "${INDEX_FILE}.txt"
  fi
}

# Project dir
if [[ -d "$PROJECT_PATH" ]]; then
  if $RECURSIVE; then
    log "Discovering modules under: $PROJECT_PATH"
    mapfile -t MODULES < <(discover_modules "$PROJECT_PATH")
    if [[ ${#MODULES[@]} -eq 0 ]]; then
      log "No modules found; scanning root only."
      MODULES=("$PROJECT_PATH")
    fi
    for mdir in "${MODULES[@]}"; do
      rel="${mdir#$PROJECT_PATH/}"
      mod="${rel:-root}"
      gen_for_dir "$mdir" "$mod"
      for f in "$OUTPUT_DIR"/"${PROJECT_NAME}-${PROJECT_VERSION}-${mod}-"*; do
        [[ -f "$f" && ( "$f" == *.json || "$f" == *.xml ) ]] && add_index "$f" "directory" "$mod"
      done
    done
  else
    gen_for_dir "$PROJECT_PATH" "root"
    for f in "$OUTPUT_DIR"/"${PROJECT_NAME}-${PROJECT_VERSION}-root-"*; do
      [[ -f "$f" && ( "$f" == *.json || "$f" == *.xml ) ]] && add_index "$f" "directory" "root"
    done
  fi
fi

# Images
if [[ ${#IMAGE_REFS[@]} -gt 0 ]]; then
  for img in "${IMAGE_REFS[@]}"; do
    gen_for_image "$img"
    key="$(sanitize "$img")"
    for f in "$OUTPUT_DIR"/"${PROJECT_NAME}-${PROJECT_VERSION}-image_${key}-"*; do
      [[ -f "$f" && ( "$f" == *.json || "$f" == *.xml ) ]] && add_index "$f" "image" "$img"
    done
  done
fi

# Finalize index
if have jq; then
  mv -f "${INDEX_FILE}.tmp" "$INDEX_FILE"
else
  # Create simple JSON if jq missing
  echo '{ "artifacts": [] }' > "$INDEX_FILE"
  rm -f "${INDEX_FILE}.tmp"
fi

# Verify if requested
if $DO_VERIFY; then
  log "Verifying artifacts in $OUTPUT_DIR"
  verify_artifacts || exit $?
fi

log "SBOM generation completed."
exit 0
