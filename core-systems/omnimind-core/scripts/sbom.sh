#!/usr/bin/env bash
# path: omnimind-core/scripts/sbom.sh
# Industrial SBOM generator for omnimind-core
# Features:
#  - Modes: python | dir | image | all
#  - Outputs: CycloneDX JSON, SPDX JSON
#  - Supports Poetry or requirements.txt
#  - Validates JSON via jq, computes SHA256, optional cosign signing
#  - Reproducible artifact naming and strict bash hygiene

set -Eeuo pipefail

#######################################
# Globals & defaults
#######################################
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${PROJECT_ROOT}/artifacts/sbom"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
PRODUCT_NAME="omnimind-core"
PRODUCT_VERSION="${PRODUCT_VERSION:-0.1.0}"
SOURCE_DIR="${PROJECT_ROOT}"
PY_SRC_DIR="${PROJECT_ROOT}/src"
COLOR=${COLOR:-1}

# Tools (can be overridden via env)
CMD_SYFT="${SYFT_BIN:-syft}"
CMD_JQ="${JQ_BIN:-jq}"
CMD_CDX_PY="${CYCLONEDX_PY_BIN:-cyclonedx-py}"
CMD_CDX_BOM="${CYCLONEDX_BOM_BIN:-cyclonedx-bom}"
CMD_PIPDEPTREE="${PIPDEPTREE_BIN:-pipdeptree}"
CMD_POETRY="${POETRY_BIN:-poetry}"
CMD_PIP="${PIP_BIN:-pip}"
CMD_COSIGN="${COSIGN_BIN:-cosign}"

# Cosign
COSIGN_SIGN="${COSIGN_SIGN:-0}"
COSIGN_KEY_REF="${COSIGN_KEY_REF:-}"   # e.g. cosign.key or keyref like azure-kv://...
COSIGN_ANNOTATIONS="${COSIGN_ANNOTATIONS:-}" # key=value,key2=value2

#######################################
# Pretty printing
#######################################
cecho() {
  local color="$1"; shift
  local msg="$*"
  if [[ "${COLOR}" -eq 1 ]]; then
    case "${color}" in
      red) echo -e "\033[31m${msg}\033[0m" ;;
      green) echo -e "\033[32m${msg}\033[0m" ;;
      yellow) echo -e "\033[33m${msg}\033[0m" ;;
      blue) echo -e "\033[34m${msg}\033[0m" ;;
      *) echo "${msg}" ;;
    esac
  else
    echo "${msg}"
  fi
}

abort() { cecho red "ERROR: $*"; exit 1; }

on_error() {
  cecho red "Trap caught error on line ${BASH_LINENO[0]} (command: ${BASH_COMMAND})"
}
trap on_error ERR

usage() {
  cat <<EOF
Usage:
  $(basename "$0") MODE [options]

Modes:
  python                Generate SBOMs from Python dependencies (Poetry/requirements).
  dir [PATH]            Scan directory (default: project root) with syft.
  image IMAGE[:TAG]     Scan container image with syft.
  all [IMAGE[:TAG]]     Python + dir + (optional) image.

Options (env vars):
  PRODUCT_VERSION         Override product version (default: ${PRODUCT_VERSION})
  ARTIFACT_DIR            Output directory (default: ${ARTIFACT_DIR})
  COLOR=0                 Disable colored output
  COSIGN_SIGN=1           Enable cosign signing for JSON outputs
  COSIGN_KEY_REF=...      cosign key or keyref (required if COSIGN_SIGN=1)
  COSIGN_ANNOTATIONS=...  comma-separated key=value list
  SYFT_BIN, CYCLONEDX_*   Override tool paths

Examples:
  scripts/sbom.sh python
  scripts/sbom.sh dir ./src
  scripts/sbom.sh image ghcr.io/org/omnimind-core:latest
  PRODUCT_VERSION=1.2.3 scripts/sbom.sh all ghcr.io/org/omnimind-core:1.2.3
EOF
}

#######################################
# Preconditions
#######################################
need() { command -v "$1" >/dev/null 2>&1 || abort "Missing tool: $1"; }

ensure_tools_python() {
  need "${CMD_JQ}"
  # Prefer cyclonedx-py (native Python), fallback to cyclonedx-bom if present
  if ! command -v "${CMD_CDX_PY}" >/dev/null 2>&1; then
    cecho yellow "cyclonedx-py not found, trying cyclonedx-bom..."
    need "${CMD_CDX_BOM}"
  fi
  # Optional
  if ! command -v "${CMD_PIPDEPTREE}" >/dev/null 2>&1; then
    cecho yellow "pipdeptree not found (optional, will skip dependency tree export)"
  fi
  # Poetry or pip is needed to export deps
  if [[ -f "${PROJECT_ROOT}/poetry.lock" ]]; then
    need "${CMD_POETRY}"
  else
    need "${CMD_PIP}"
  fi
}

ensure_tools_syft() {
  need "${CMD_SYFT}"
  need "${CMD_JQ}"
}

ensure_artifact_dir() {
  mkdir -p "${ARTIFACT_DIR}"
}

sha256_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${f}" | awk '{print $1}' > "${f}.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${f}" | awk '{print $1}' > "${f}.sha256"
  else
    cecho yellow "No sha256 utility found; skipping checksum for ${f}"
  fi
}

json_validate() {
  local f="$1"
  "${CMD_JQ}" -e . "${f}" >/dev/null
}

cosign_sign_if_enabled() {
  local f="$1"
  if [[ "${COSIGN_SIGN}" == "1" ]]; then
    [[ -n "${COSIGN_KEY_REF}" ]] || abort "COSIGN_SIGN=1 requires COSIGN_KEY_REF"
    need "${CMD_COSIGN}"
    local ann_args=()
    if [[ -n "${COSIGN_ANNOTATIONS}" ]]; then
      IFS=',' read -r -a parts <<<"${COSIGN_ANNOTATIONS}"
      for kv in "${parts[@]}"; do
        ann_args+=( "-a" "${kv}" )
      done
    fi
    cecho blue "Signing ${f} with cosign (key: ${COSIGN_KEY_REF})"
    "${CMD_COSIGN}" sign-blob \
      --yes \
      --key "${COSIGN_KEY_REF}" \
      "${ann_args[@]}" \
      --output-signature "${f}.sig" \
      --output-certificate "${f}.cert" \
      "${f}"
  fi
}

#######################################
# Python SBOM generation
#######################################
export_requirements_tmp() {
  local tmp_req="$1"
  if [[ -f "${PROJECT_ROOT}/poetry.lock" ]]; then
    cecho blue "Detected Poetry project; exporting requirements..."
    # deterministic export
    "${CMD_POETRY}" export --without-hashes -f requirements.txt -o "${tmp_req}" >/dev/null
  elif [[ -f "${PROJECT_ROOT}/requirements.txt" ]]; then
    cecho blue "Using existing requirements.txt"
    cp "${PROJECT_ROOT}/requirements.txt" "${tmp_req}"
  else
    abort "No poetry.lock or requirements.txt found"
  fi
}

python_bom() {
  ensure_tools_python
  ensure_tools_syft
  ensure_artifact_dir

  local base="${ARTIFACT_DIR}/${PRODUCT_NAME}-${PRODUCT_VERSION}-${TIMESTAMP}"

  # 1) CycloneDX via cyclonedx-py or cyclonedx-bom (source-based)
  local cdx_json="${base}-python-cyclonedx.json"
  local tmp_req
  tmp_req="$(mktemp)"
  export_requirements_tmp "${tmp_req}"

  if command -v "${CMD_CDX_PY}" >/dev/null 2>&1; then
    cecho blue "Generating CycloneDX (python) via cyclonedx-py"
    "${CMD_CDX_PY}" --project-name "${PRODUCT_NAME}" \
                    --project-version "${PRODUCT_VERSION}" \
                    --format json \
                    --spec-version 1.5 \
                    --no-license-scan \
                    --input-file "${tmp_req}" \
      > "${cdx_json}"
  else
    cecho blue "Generating CycloneDX (python) via cyclonedx-bom"
    "${CMD_CDX_BOM}" \
      -o "${cdx_json}" \
      -F json \
      -S 1.5 \
      -n "${PRODUCT_NAME}" \
      -v "${PRODUCT_VERSION}" \
      -i "${tmp_req}"
  fi
  rm -f "${tmp_req}"
  json_validate "${cdx_json}"
  sha256_file "${cdx_json}"
  cosign_sign_if_enabled "${cdx_json}"
  cecho green "OK: ${cdx_json}"

  # 2) SPDX via syft (environment/discovery based)
  local spdx_json="${base}-python-spdx.json"
  cecho blue "Generating SPDX (python, dir scan) via syft"
  "${CMD_SYFT}" \
    "dir:${PY_SRC_DIR}" \
    -o "spdx-json=${spdx_json}" \
    --name "${PRODUCT_NAME}" \
    --source-name "python-src" \
    --quiet
  json_validate "${spdx_json}"
  sha256_file "${spdx_json}"
  cosign_sign_if_enabled "${spdx_json}"
  cecho green "OK: ${spdx_json}"

  # 3) Optional dependency tree snapshot (human-readable)
  if command -v "${CMD_PIPDEPTREE}" >/dev/null 2>&1; then
    local tree_txt="${base}-pipdeptree.txt"
    cecho blue "Exporting pipdeptree (optional)"
    "${CMD_PIPDEPTREE}" --warn silence > "${tree_txt}" || true
    sha256_file "${tree_txt}"
  fi
}

#######################################
# Directory SBOM (generic)
#######################################
dir_bom() {
  ensure_tools_syft
  ensure_artifact_dir

  local target="${1:-${SOURCE_DIR}}"
  [[ -d "${target}" ]] || abort "Directory not found: ${target}"

  local base="${ARTIFACT_DIR}/${PRODUCT_NAME}-${PRODUCT_VERSION}-${TIMESTAMP}-dir"
  local cdx_json="${base}-cyclonedx.json"
  local spdx_json="${base}-spdx.json"

  cecho blue "syft dir scan -> CycloneDX"
  "${CMD_SYFT}" "dir:${target}" -o "cyclonedx-json=${cdx_json}" --name "${PRODUCT_NAME}" --quiet
  json_validate "${cdx_json}"
  sha256_file "${cdx_json}"
  cosign_sign_if_enabled "${cdx_json}"
  cecho green "OK: ${cdx_json}"

  cecho blue "syft dir scan -> SPDX"
  "${CMD_SYFT}" "dir:${target}" -o "spdx-json=${spdx_json}" --name "${PRODUCT_NAME}" --quiet
  json_validate "${spdx_json}"
  sha256_file "${spdx_json}"
  cosign_sign_if_enabled "${spdx_json}"
  cecho green "OK: ${spdx_json}"
}

#######################################
# Image SBOM (container)
#######################################
image_bom() {
  ensure_tools_syft
  ensure_artifact_dir

  local image_ref="${1:-}"
  [[ -n "${image_ref}" ]] || abort "Image reference is required: image_bom <image:tag>"

  local safe_ref
  safe_ref="$(echo -n "${image_ref}" | tr '/:@' '___')"
  local base="${ARTIFACT_DIR}/${PRODUCT_NAME}-${PRODUCT_VERSION}-${TIMESTAMP}-img-${safe_ref}"
  local cdx_json="${base}-cyclonedx.json"
  local spdx_json="${base}-spdx.json"

  cecho blue "syft image scan -> CycloneDX: ${image_ref}"
  "${CMD_SYFT}" "registry:${image_ref}" -o "cyclonedx-json=${cdx_json}" --name "${PRODUCT_NAME}" --quiet || \
  "${CMD_SYFT}" "image:${image_ref}"   -o "cyclonedx-json=${cdx_json}" --name "${PRODUCT_NAME}" --quiet
  json_validate "${cdx_json}"
  sha256_file "${cdx_json}"
  cosign_sign_if_enabled "${cdx_json}"
  cecho green "OK: ${cdx_json}"

  cecho blue "syft image scan -> SPDX: ${image_ref}"
  "${CMD_SYFT}" "registry:${image_ref}" -o "spdx-json=${spdx_json}" --name "${PRODUCT_NAME}" --quiet || \
  "${CMD_SYFT}" "image:${image_ref}"   -o "spdx-json=${spdx_json}" --name "${PRODUCT_NAME}" --quiet
  json_validate "${spdx_json}"
  sha256_file "${spdx_json}"
  cosign_sign_if_enabled "${spdx_json}"
  cecho green "OK: ${spdx_json}"
}

#######################################
# Dispatcher
#######################################
main() {
  local mode="${1:-}"
  case "${mode}" in
    python)
      python_bom
      ;;
    dir)
      shift || true
      dir_bom "${1:-${SOURCE_DIR}}"
      ;;
    image)
      shift || true
      image_bom "${1:-}"
      ;;
    all)
      shift || true
      local maybe_image="${1:-}"
      python_bom
      dir_bom "${SOURCE_DIR}"
      if [[ -n "${maybe_image}" ]]; then
        image_bom "${maybe_image}"
      else
        cecho yellow "No image reference passed to 'all'; skipping image scan"
      fi
      ;;
    ""|-h|--help)
      usage
      ;;
    *)
      usage
      abort "Unknown mode: ${mode}"
      ;;
  esac

  cecho green "SBOM generation complete. Artifacts in: ${ARTIFACT_DIR}"
}

main "$@"
