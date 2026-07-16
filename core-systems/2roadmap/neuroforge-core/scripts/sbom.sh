# file: neuroforge-core/scripts/sbom.sh
#!/usr/bin/env bash
# SBOM generator for source directories and container images
# Features:
# - CycloneDX / SPDX (json/xml/tag)
# - syft local or containerized (docker/podman)
# - optional grype vulnerability report
# - metadata enrichment (name/version/VCS) if python3 available
# - SHA256 checksums, GPG or cosign signatures, optional cosign attest for images
# - strict error handling and deterministic outputs

set -Eeuo pipefail

readonly ME="${BASH_SOURCE[0]##*/}"
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------
# Defaults (override by env)
# ---------------------------
: "${SBOM_SOURCE:=.}"                          # path or image ref
: "${SBOM_OUT:=${ROOT}/out/sbom}"              # output directory
: "${SBOM_FORMAT:=cyclonedx}"                  # cyclonedx | spdx
: "${SBOM_ENCODING:=json}"                     # json | xml | tag (tag only for spdx)
: "${SBOM_NAME:=}"                             # component name override
: "${SBOM_VERSION:=}"                          # component version override
: "${SBOM_COMPONENT_TYPE:=application}"        # application | library
: "${SBOM_EXCLUDES:=}"                         # comma-separated glob patterns
: "${SBOM_WITH_VULNS:=false}"                  # true|false -> grype report
: "${SBOM_SIGN_GPG:=false}"                    # true|false
: "${SBOM_GPG_KEY:=}"                          # key id/email for gpg --local-user
: "${SBOM_SIGN_COSIGN:=false}"                 # true|false (cosign sign-blob)
: "${SBOM_ATTEST_IMAGE:=false}"                # true|false cosign attest (only when SBOM_SOURCE is image)
: "${SBOM_SYFT_IMAGE:=docker.io/anchore/syft:latest}"
: "${SBOM_GRYPE_IMAGE:=docker.io/anchore/grype:latest}"
: "${CONTAINER_RUNTIME:=}"                     # docker|podman (autodetect)
: "${FORCE_CONTAINER_TOOLS:=false}"            # true forces containerized syft/grype

# ---------------------------
# Helpers
# ---------------------------
log() { printf '%s %s %s\n' "${NOW_UTC}" "${ME}" "$*" >&2; }
die() { log "ERROR:" "$*"; exit 1; }

usage() {
  cat <<EOF
Usage: ${ME} [options]

Options:
  --source <path|image>        Source directory or container image ref (default: ${SBOM_SOURCE})
  --out <dir>                  Output directory (default: ${SBOM_OUT})
  --format <cyclonedx|spdx>    SBOM format (default: ${SBOM_FORMAT})
  --encoding <json|xml|tag>    Output encoding (default: ${SBOM_ENCODING})
  --name <component-name>      Override top-level component name
  --version <component-version>Override top-level component version
  --component-type <type>      application|library (default: ${SBOM_COMPONENT_TYPE})
  --exclude <glob>             Exclude pattern (repeatable, for directory scan only)
  --with-vulns                 Generate vulnerability report with grype (JSON)
  --sign-gpg [key]             Sign SBOM via GPG (detached .sig), optional key id/email
  --sign-cosign                Sign SBOM via cosign sign-blob (creates .sig)
  --attest-image               Cosign attest SBOM for image sources (predicate=SBOM)
  --force-container-tools      Force running syft/grype in container even if local binaries exist
  -h|--help                    Show this help

Environment overrides exist for all options (prefix SBOM_*). No external network access is performed beyond tool images if containerized.
EOF
}

hash_sha256() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}' || sha256sum "$1" | awk '{print $1}'; }

have() { command -v "$1" >/dev/null 2>&1; }

detect_container_runtime() {
  if [[ -n "${CONTAINER_RUNTIME}" ]]; then echo "${CONTAINER_RUNTIME}"; return; fi
  if have docker; then echo docker; return; fi
  if have podman; then echo podman; return; fi
  echo ""
}

is_image_source() {
  # heuristics: contains ":" or "/" and not a local path OR explicitly prefixed by docker:// etc.
  local src="$1"
  if [[ "$src" == docker://* || "$src" == registry://* ]]; then return 0; fi
  if [[ -e "$src" || "$src" == . || "$src" == .. || "$src" == /* ]]; then return 1; fi
  # looks like image ref (e.g., alpine:3.19 or ghcr.io/org/app:tag)
  if [[ "$src" == *:* || "$src" == *"/"* ]]; then return 0; fi
  return 1
}

require_path() {
  local p="$1"
  [[ -e "$p" ]] || die "Path not found: $p"
}

mkout() {
  mkdir -p "${SBOM_OUT}"
}

# ---------------------------
# Tool discovery
# ---------------------------
syft_cmd=""
grype_cmd=""

pick_syft() {
  if [[ "${FORCE_CONTAINER_TOOLS}" == "true" ]]; then
    : # force container path
  elif have syft; then
    syft_cmd="syft"
    return
  fi
  local rt
  rt="$(detect_container_runtime)"
  [[ -n "$rt" ]] || die "syft not found and no container runtime (docker/podman) available"
  syft_cmd="$rt run --rm -t \
    -v ${PWD}:/work:ro \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -w /work \
    ${SBOM_SYFT_IMAGE}"
}

pick_grype() {
  if [[ "${FORCE_CONTAINER_TOOLS}" != "true" && have grype ]]; then
    grype_cmd="grype"; return
  fi
  local rt
  rt="$(detect_container_runtime)"
  [[ -n "$rt" ]] || { log "WARN: grype not found and no container runtime; vulnerability report disabled"; grype_cmd=""; return; }
  grype_cmd="$rt run --rm -t \
    -v ${PWD}:/work:ro \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -w /work \
    ${SBOM_GRYPE_IMAGE}"
}

# ---------------------------
# SBOM generation
# ---------------------------
syft_output_flag() {
  local fmt="$1" enc="$2"
  case "${fmt}:${enc}" in
    cyclonedx:json) echo "cyclonedx-json" ;;
    cyclonedx:xml)  echo "cyclonedx-xml" ;;
    spdx:json)      echo "spdx-json" ;;
    spdx:tag)       echo "spdx-tag-value" ;;
    spdx:xml)       echo "spdx-xml" ;;
    *) die "Unsupported format/encoding: ${fmt}/${enc}" ;;
  esac
}

apply_excludes_args() {
  local src="$1"
  local args=()
  if ! is_image_source "$src"; then
    IFS=',' read -r -a pats <<<"${SBOM_EXCLUDES}"
    for p in "${pats[@]}"; do
      [[ -n "${p// }" ]] || continue
      args+=( "--exclude" "$p" )
    done
  fi
  printf '%s\n' "${args[@]}"
}

enrich_metadata_json() {
  # Enrich CycloneDX/SPDX JSON with top-level name/version/VCS url if python3 present
  local file="$1"
  [[ -s "$file" ]] || return 0
  if ! have python3; then log "INFO: python3 not found; skipping metadata enrichment"; return 0; fi

  local name="${SBOM_NAME}" version="${SBOM_VERSION}"
  # Try to auto-detect if not provided
  if [[ -z "$name" ]]; then
    if [[ -f "${ROOT}/pyproject.toml" ]]; then name="$(awk -F= '/^name *=/{gsub(/["\047 ]/,"",$2);print $2}' "${ROOT}/pyproject.toml" | head -n1 || true)"; fi
    [[ -n "$name" ]] || name="$(basename "${ROOT}")"
  fi
  if [[ -z "$version" ]]; then
    if [[ -f "${ROOT}/VERSION" ]]; then version="$(tr -d ' \t\r\n' < "${ROOT}/VERSION")"; fi
    [[ -n "$version" ]] || version="$(git -C "${ROOT}" describe --tags --always 2>/dev/null || echo "0.0.0")"
  fi
  local vcs="$(git -C "${ROOT}" config --get remote.origin.url 2>/dev/null || true)"

  python3 - "$file" <<PY || log "WARN: metadata enrichment failed (non-fatal)"
import json,sys
path=sys.argv[1]
with open(path,'r',encoding='utf-8') as f:
    data=json.load(f)
name="${name}"
version="${version}"
vcs="${vcs}"
def inject_cdx(d):
    meta=d.setdefault("metadata",{})
    comp=meta.setdefault("component",{})
    comp.setdefault("type","${SBOM_COMPONENT_TYPE}")
    comp["name"]=name or comp.get("name") or "${SBOM_COMPONENT_TYPE}"
    comp["version"]=version or comp.get("version") or "0.0.0"
    if vcs and isinstance(comp,dict):
        refs=comp.setdefault("externalReferences",[])
        if not any((r.get("url")==vcs and r.get("type")=="vcs") for r in refs if isinstance(r,dict)):
            refs.append({"type":"vcs","url":vcs})
def inject_spdx(d):
    docs=d.get("documents") or d.get("Document") or d
    # Best-effort for SPDX json; structure varies by tool
    if isinstance(docs,dict) and "name" in docs:
        docs["name"]=name or docs["name"]
if isinstance(data,dict) and data.get("bomFormat")=="CycloneDX":
    inject_cdx(data)
else:
    inject_spdx(data)
with open(path,'w',encoding='utf-8') as f:
    json.dump(data,f,ensure_ascii=False,indent=2)
PY
}

generate_vuln_report() {
  local src="$1" out_json="$2"
  [[ -n "$grype_cmd" ]] || return 0
  if is_image_source "$src"; then
    ${grype_cmd} "$src" -o json > "$out_json"
  else
    ${grype_cmd} dir:"$src" -o json > "$out_json"
  fi
}

sign_gpg() {
  local file="$1"
  [[ "${SBOM_SIGN_GPG}" == "true" ]] || return 0
  have gpg || die "gpg not found but --sign-gpg requested"
  local args=(--batch --yes --armor --detach-sign)
  [[ -n "${SBOM_GPG_KEY}" ]] && args+=(--local-user "${SBOM_GPG_KEY}")
  gpg "${args[@]}" "$file"
  log "INFO: GPG signature created: ${file}.asc"
}

sign_cosign() {
  local file="$1"
  [[ "${SBOM_SIGN_COSIGN}" == "true" ]] || return 0
  have cosign || die "cosign not found but --sign-cosign requested"
  cosign sign-blob --yes --output-signature "${file}.sig" "$file"
  log "INFO: cosign signature created: ${file}.sig"
}

attest_image() {
  local src="$1" sbom_file="$2"
  [[ "${SBOM_ATTEST_IMAGE}" == "true" ]] || return 0
  is_image_source "$src" || die "--attest-image requires image source"
  have cosign || die "cosign not found for attestation"
  cosign attest --yes --type cyclonedx --predicate "$sbom_file" "$src"
  log "INFO: cosign attestation pushed for ${src}"
}

# ---------------------------
# CLI args
# ---------------------------
parse_args() {
  local excl_args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --source) SBOM_SOURCE="$2"; shift 2;;
      --out) SBOM_OUT="$2"; shift 2;;
      --format) SBOM_FORMAT="$2"; shift 2;;
      --encoding) SBOM_ENCODING="$2"; shift 2;;
      --name) SBOM_NAME="$2"; shift 2;;
      --version) SBOM_VERSION="$2"; shift 2;;
      --component-type) SBOM_COMPONENT_TYPE="$2"; shift 2;;
      --exclude) excl_args+=("$2"); shift 2;;
      --with-vulns) SBOM_WITH_VULNS=true; shift;;
      --sign-gpg) SBOM_SIGN_GPG=true; SBOM_GPG_KEY="${2:-${SBOM_GPG_KEY}}"; [[ $# -gt 1 && "$2" != "--"* ]] && shift 2 || shift 1;;
      --sign-cosign) SBOM_SIGN_COSIGN=true; shift;;
      --attest-image) SBOM_ATTEST_IMAGE=true; shift;;
      --force-container-tools) FORCE_CONTAINER_TOOLS=true; shift;;
      -h|--help) usage; exit 0;;
      *) die "Unknown option: $1";;
    esac
  done
  if [[ "${#excl_args[@]}" -gt 0 ]]; then
    SBOM_EXCLUDES="$(IFS=','; echo "${excl_args[*]}")"
  fi
}

# ---------------------------
# Main
# ---------------------------
main() {
  parse_args "$@"
  mkout
  pick_syft
  pick_grype

  local src="${SBOM_SOURCE}"
  local out="${SBOM_OUT%/}"
  local ofmt
  ofmt="$(syft_output_flag "${SBOM_FORMAT}" "${SBOM_ENCODING}")"

  # Resolve paths
  if ! is_image_source "$src"; then
    src="$(cd "$src" && pwd)"
    require_path "$src"
  fi

  # Output filenames
  local base="sbom"
  [[ -n "$SBOM_NAME" ]] && base="${base}-$(echo "$SBOM_NAME" | tr ' /:@' '____' )"
  local ext="json"
  case "$SBOM_ENCODING" in
    json) ext="json";;
    xml) ext="xml";;
    tag) ext="spdx";;
  esac
  local sbom_file="${out}/${base}.${ext}"
  local meta_file="${out}/${base}.meta.json"
  local vuln_file="${out}/${base}.vulns.json"

  # Excludes
  mapfile -t excl_args < <(apply_excludes_args "$SBOM_SOURCE")

  log "INFO: Generating SBOM"
  log "INFO: source=${SBOM_SOURCE} format=${SBOM_FORMAT}/${SBOM_ENCODING} out=${sbom_file}"

  # syft invocation
  if is_image_source "${SBOM_SOURCE}"; then
    ${syft_cmd} "${SBOM_SOURCE}" -o "${ofmt}" > "${sbom_file}"
  else
    ${syft_cmd} dir:"${src}" -o "${ofmt}" "${excl_args[@]}" > "${sbom_file}"
  fi

  # Enrich metadata (best-effort)
  if [[ "${SBOM_ENCODING}" == "json" ]]; then
    enrich_metadata_json "${sbom_file}"
  fi

  # Meta info
  {
    printf '{\n'
    printf '  "generated_at":"%s",\n' "${NOW_UTC}"
    printf '  "tool":"%s",\n' "${syft_cmd%% *}"
    printf '  "format":"%s",\n' "${SBOM_FORMAT}"
    printf '  "encoding":"%s",\n' "${SBOM_ENCODING}"
    printf '  "source":"%s",\n' "${SBOM_SOURCE}"
    printf '  "sha256":"%s"\n' "$(hash_sha256 "${sbom_file}")"
    printf '}\n'
  } > "${meta_file}"

  # Optional vulnerabilities
  if [[ "${SBOM_WITH_VULNS}" == "true" ]]; then
    log "INFO: Generating vulnerability report"
    generate_vuln_report "${SBOM_SOURCE}" "${vuln_file}" || log "WARN: grype failed (continuing)"
  fi

  # Signatures / attestation
  sign_gpg "${sbom_file}"
  sign_cosign "${sbom_file}"
  if [[ "${SBOM_ATTEST_IMAGE}" == "true" ]]; then
    attest_image "${SBOM_SOURCE}" "${sbom_file}"
  fi

  log "INFO: Done: ${sbom_file}"
  printf '%s\n' "${sbom_file}"
}

main "$@"
