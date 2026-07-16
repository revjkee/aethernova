#!/usr/bin/env bash
# SBOM pipeline for chronowatch-core
# Generates SPDX/CycloneDX for source dir, Docker images, or docker-compose stacks.
# Adds vuln scan (trivy/grype), optional in-toto/cosign attestation, validation, and containerized fallbacks.
# Compatible: Linux/macOS. Requires bash 4+.

set -Eeuo pipefail

###############################################################################
# Defaults & metadata
###############################################################################
PROJECT_NAME="${PROJECT_NAME:-chronowatch-core}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/build/sbom}"
DATE_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GIT_COMMIT="$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || echo "nogit")"
GIT_BRANCH="$(git -C "${ROOT_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "nogit")"
VERSION="${VERSION:-$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo "0.0.0")}"

# Tool images for fallbacks
SYFT_IMG="${SYFT_IMG:-anchore/syft:latest}"
GRYPE_IMG="${GRYPE_IMG:-anchore/grype:latest}"
TRIVY_IMG="${TRIVY_IMG:-aquasec/trivy:latest}"

# CLI toggles
TARGET="dir"                 # dir|image|compose
TARGET_PATH="${ROOT_DIR}"    # for dir target
IMAGES=()                    # for image target
IMAGE_FILE=""                # file with image list
FORMATS="all"                # spdx-json|spdx-tag|cyclonedx-json|cyclonedx-xml|all
WITH_VULN="false"            # add vulnerability scan reports
WITH_ATTEST="false"          # cosign attest
COMPONENT_NAME="${COMPONENT_NAME:-$PROJECT_NAME}"
VERBOSE="false"
PARALLEL_JOBS="${PARALLEL_JOBS:-1}"   # set >1 to parallelize image processing

# Load .env if present
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi

###############################################################################
# Logging
###############################################################################
log()  { printf "[%s] %s\n" "${DATE_UTC}" "$*"; }
err()  { printf "[%s] ERROR: %s\n" "${DATE_UTC}" "$*" >&2; }
die()  { err "$*"; exit 1; }

verbose() {
  if [[ "${VERBOSE}" == "true" ]]; then
    log "$@"
  fi
}

###############################################################################
# Helpers & checks
###############################################################################
have() { command -v "$1" >/dev/null 2>&1; }
have_docker() { command -v docker >/dev/null 2>&1; }
mkdirp() { mkdir -p "$1"; }

usage() {
cat <<'USAGE'
Usage:
  sbom.sh [--target dir|image|compose]
          [--path <dir>] [--image <ref>]... [--image-file file]
          [--formats spdx-json|spdx-tag|cyclonedx-json|cyclonedx-xml|all]
          [--output-dir <dir>] [--component-name <name>] [--version <x.y.z>]
          [--vuln] [--attest] [--parallel N] [--verbose]

Targets:
  --target dir      Generate SBOM for source directory (default).
  --target image    Generate SBOM for one or more Docker images.
  --target compose  Generate SBOM for images referenced by docker-compose*.

Options:
  --path DIR            Directory to scan (dir target). Default: repo root.
  --image REF           Image reference (can be repeated).
  --image-file FILE     File with one image ref per line.
  --formats FMT         One of: spdx-json|spdx-tag|cyclonedx-json|cyclonedx-xml|all (default: all).
  --output-dir DIR      Where to put artifacts. Default: build/sbom.
  --component-name N    Component name (package/bomRef name).
  --version V           Component version (default: git describe or 0.0.0).
  --vuln                Also run vulnerability scans (fs/image) and export reports.
  --attest              Produce cosign attestations for SBOMs (requires cosign).
  --parallel N          Parallel jobs for image processing (default: 1).
  --verbose             Verbose logs.

Examples:
  ./scripts/sbom.sh --target dir --vuln
  ./scripts/sbom.sh --target image --image ghcr.io/acme/app:1.2.3 --attest
  ./scripts/sbom.sh --target compose --formats cyclonedx-json --vuln

Exit codes:
  0 success; non-zero indicates failure.
USAGE
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="${2:-}"; shift 2;;
    --path) TARGET_PATH="${2:-}"; shift 2;;
    --image) IMAGES+=("$2"); shift 2;;
    --image-file) IMAGE_FILE="${2:-}"; shift 2;;
    --formats) FORMATS="${2:-}"; shift 2;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2;;
    --component-name) COMPONENT_NAME="${2:-}"; shift 2;;
    --version) VERSION="${2:-}"; shift 2;;
    --vuln) WITH_VULN="true"; shift 1;;
    --attest) WITH_ATTEST="true"; shift 1;;
    --parallel) PARALLEL_JOBS="${2:-1}"; shift 2;;
    --verbose) VERBOSE="true"; shift 1;;
    -h|--help) usage; exit 0;;
    *) err "Unknown argument: $1"; usage; exit 2;;
  esac
done

# Validate target
case "${TARGET}" in
  dir|image|compose) ;;
  *) die "--target must be dir|image|compose";;
escase || true

# Validate formats
valid_fmt() {
  case "$1" in
    spdx-json|spdx-tag|cyclonedx-json|cyclonedx-xml|all) return 0;;
    *) return 1;;
  esac
}
valid_fmt "${FORMATS}" || die "--formats invalid"

# Resolve images from file if provided
if [[ -n "${IMAGE_FILE}" ]]; then
  while IFS= read -r line; do
    [[ -n "$line" ]] && IMAGES+=("$line")
  done < "${IMAGE_FILE}"
fi

# Compose images discovery
discover_compose_images() {
  have_docker || die "docker is required for compose target"
  if docker compose version >/dev/null 2>&1; then
    docker compose config | awk '/image:/ {print $2}'
  else
    # legacy docker-compose
    docker-compose config | awk '/image:/ {print $2}'
  fi
}

###############################################################################
# Runners: syft/cdxgen local or containerized
###############################################################################
run_syft() {
  # Args: <source> <output_format> ; source examples: "dir:/path" or "image:ref"
  local source="$1" fmt="$2"
  if have syft; then
    syft "${source}" -o "${fmt}"
  elif have_docker; then
    docker run --rm -i \
      -v "${ROOT_DIR}":"${ROOT_DIR}" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -w "${ROOT_DIR}" \
      "${SYFT_IMG}" "${source}" -o "${fmt}"
  else
    die "syft not found and docker unavailable"
  fi
}

run_grype() {
  # Args: <source> <output_path_json> ; source: "dir:/path" or "image:ref"
  local source="$1" out="$2"
  if have grype; then
    grype --add-cpes-if-none "${source}" -o json > "${out}" || true
  elif have_docker; then
    docker run --rm -i \
      -v "${ROOT_DIR}":"${ROOT_DIR}" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -w "${ROOT_DIR}" \
      "${GRYPE_IMG}" --add-cpes-if-none "${source}" -o json > "${out}" || true
  else
    err "grype not found and docker unavailable; skipping"
  fi
}

run_trivy_fs() {
  local path="$1" out="$2"
  if have trivy; then
    trivy fs --scanners vuln,secret,misconfig --quiet --format json "${path}" > "${out}" || true
  elif have_docker; then
    docker run --rm -i \
      -v "${path}":"${path}" \
      -w "${path}" "${TRIVY_IMG}" fs --scanners vuln,secret,misconfig --quiet --format json . > "${out}" || true
  else
    err "trivy not found and docker unavailable; skipping"
  fi
}

run_trivy_image() {
  local image="$1" out="$2"
  if have trivy; then
    trivy image --quiet --format json "${image}" > "${out}" || true
  elif have_docker; then
    docker run --rm -i \
      -v /var/run/docker.sock:/var/run/docker.sock \
      "${TRIVY_IMG}" image --quiet --format json "${image}" > "${out}" || true
  else
    err "trivy not found and docker unavailable; skipping"
  fi
}

###############################################################################
# Cosign attestation
###############################################################################
do_attest() {
  # Args: <subject-ref> <predicate-file> <predicate-type>
  local subject="$1" pred="$2" ptype="$3"
  if [[ "${WITH_ATTEST}" != "true" ]]; then return 0; fi
  if ! have cosign; then
    err "cosign not found; skipping attest"
    return 0
  fi
  COSIGN_EXPERIMENTAL=1 cosign attest --yes \
    --type "${ptype}" \
    --predicate "${pred}" \
    "${subject}" || err "cosign attest failed (subject=${subject})"
}

###############################################################################
# Validation
###############################################################################
validate_json() { have jq && jq empty "$1" 2>/dev/null || true; }
validate_xml()  { have xmllint && xmllint --noout "$1" 2>/dev/null || true; }

###############################################################################
# Generators
###############################################################################
gen_dir_sbom() {
  local dir="$1"
  local outbase="${OUTPUT_DIR}/${COMPONENT_NAME}-${VERSION}-${GIT_COMMIT}"

  mkdirp "${OUTPUT_DIR}"

  # SPDX JSON
  if [[ "${FORMATS}" == "spdx-json" || "${FORMATS}" == "all" ]]; then
    verbose "Generating SPDX JSON for dir:${dir}"
    run_syft "dir:${dir}" "spdx-json" > "${outbase}.spdx.json"
    validate_json "${outbase}.spdx.json"
  fi

  # SPDX tag-value
  if [[ "${FORMATS}" == "spdx-tag" || "${FORMATS}" == "all" ]]; then
    verbose "Generating SPDX Tag for dir:${dir}"
    run_syft "dir:${dir}" "spdx-tag-value" > "${outbase}.spdx.tag"
  fi

  # CycloneDX JSON
  if [[ "${FORMATS}" == "cyclonedx-json" || "${FORMATS}" == "all" ]]; then
    verbose "Generating CycloneDX JSON for dir:${dir}"
    run_syft "dir:${dir}" "cyclonedx-json" > "${outbase}.cdx.json"
    validate_json "${outbase}.cdx.json"
    do_attest "${COMPONENT_NAME}:${VERSION}" "${outbase}.cdx.json" "cyclonedx"
  fi

  # CycloneDX XML
  if [[ "${FORMATS}" == "cyclonedx-xml" || "${FORMATS}" == "all" ]]; then
    verbose "Generating CycloneDX XML for dir:${dir}"
    run_syft "dir:${dir}" "cyclonedx-xml" > "${outbase}.cdx.xml"
    validate_xml "${outbase}.cdx.xml"
  fi

  if [[ "${WITH_VULN}" == "true" ]]; then
    verbose "Running vuln scans for dir:${dir}"
    run_grype "dir:${dir}" "${outbase}.grype.json"
    validate_json "${outbase}.grype.json"
    run_trivy_fs "${dir}" "${outbase}.trivy-fs.json"
    validate_json "${outbase}.trivy-fs.json"
  fi

  log "SBOM artifacts (dir) at: ${OUTPUT_DIR}"
}

process_image() {
  local image="$1"
  # sanitize image for filename
  local img_sanitized
  img_sanitized="$(echo "${image}" | tr '/:@' '___')"
  local outbase="${OUTPUT_DIR}/${img_sanitized}-${VERSION}-${GIT_COMMIT}"

  mkdirp "${OUTPUT_DIR}"

  # Generate SBOMs
  if [[ "${FORMATS}" == "spdx-json" || "${FORMATS}" == "all" ]]; then
    verbose "Generating SPDX JSON for image:${image}"
    run_syft "${image}" "spdx-json" > "${outbase}.spdx.json"
    validate_json "${outbase}.spdx.json"
  fi

  if [[ "${FORMATS}" == "spdx-tag" || "${FORMATS}" == "all" ]]; then
    verbose "Generating SPDX Tag for image:${image}"
    run_syft "${image}" "spdx-tag-value" > "${outbase}.spdx.tag"
  fi

  if [[ "${FORMATS}" == "cyclonedx-json" || "${FORMATS}" == "all" ]]; then
    verbose "Generating CycloneDX JSON for image:${image}"
    run_syft "${image}" "cyclonedx-json" > "${outbase}.cdx.json"
    validate_json "${outbase}.cdx.json"
    do_attest "${image}" "${outbase}.cdx.json" "cyclonedx"
  fi

  if [[ "${FORMATS}" == "cyclonedx-xml" || "${FORMATS}" == "all" ]]; then
    verbose "Generating CycloneDX XML for image:${image}"
    run_syft "${image}" "cyclonedx-xml" > "${outbase}.cdx.xml"
    validate_xml "${outbase}.cdx.xml"
  fi

  if [[ "${WITH_VULN}" == "true" ]]; then
    verbose "Running vuln scans for image:${image}"
    run_grype "${image}" "${outbase}.grype.json"
    validate_json "${outbase}.grype.json"
    run_trivy_image "${image}" "${outbase}.trivy-image.json"
    validate_json "${outbase}.trivy-image.json"
  fi

  log "SBOM artifacts (image) at: ${OUTPUT_DIR} for ${image}"
}

gen_image_sbom() {
  if [[ "${#IMAGES[@]}" -eq 0 ]]; then
    die "No images specified. Use --image or --image-file."
  fi

  if [[ "${PARALLEL_JOBS}" -gt 1 ]] && have xargs; then
    printf "%s\n" "${IMAGES[@]}" | xargs -n1 -P "${PARALLEL_JOBS}" -I {} bash -c 'process_image "$@"' _ {}
  else
    for img in "${IMAGES[@]}"; do
      process_image "${img}"
    done
  fi
}

gen_compose_sbom() {
  mapfile -t IMAGES < <(discover_compose_images || true)
  if [[ "${#IMAGES[@]}" -eq 0 ]]; then
    die "No images found in docker-compose config"
  fi
  gen_image_sbom
}

###############################################################################
# Main
###############################################################################
main() {
  mkdirp "${OUTPUT_DIR}"
  log "SBOM pipeline start"
  log "Project=${PROJECT_NAME} Version=${VERSION} Commit=${GIT_COMMIT} Branch=${GIT_BRANCH}"
  log "Target=${TARGET} Formats=${FORMATS} Output=${OUTPUT_DIR}"

  case "${TARGET}" in
    dir) gen_dir_sbom "${TARGET_PATH}";;
    image) gen_image_sbom;;
    compose) gen_compose_sbom;;
  esac

  log "SBOM pipeline done"
}

trap 'err "Unexpected error on line $LINENO"; exit 1' ERR
main
