#!/usr/bin/env bash
# Security-Core SBOM generator (industrial-grade)
# Supports: directory and/or container image sources
# Primary tool: anchore/syft (CycloneDX JSON/XML, SPDX JSON/Tag)
# Fallback: aquasecurity/trivy (CycloneDX for fs/image)
# Post-processing: JSON validation (jq), SHA256, optional GPG signature
# Exit on error and handle traps.

set -Eeuo pipefail

# -------- Logging --------
LOG_LEVEL="${LOG_LEVEL:-INFO}"

log()  { printf '[%s] %s\n' "${1}" "${2:-}"; }
dbg()  { [ "${LOG_LEVEL}" = "DEBUG" ] && log "DBG" "$*"; true; }
inf()  { log "INF" "$*"; }
wrn()  { log "WRN" "$*"; }
err()  { log "ERR" "$*" >&2; }
die()  { err "$*"; exit 1; }

# -------- Trap --------
on_error() {
  local exit_code=$?
  err "Failed at line ${BASH_LINENO[0]} (command: ${BASH_COMMAND}) with exit code ${exit_code}"
  exit "${exit_code}"
}
trap on_error ERR

# -------- Defaults --------
OUT_DIR="${OUT_DIR:-./artifacts/sbom}"
FORMATS_DEFAULT="cyclonedx-json"      # Safe default; widely supported
FORMATS="${FORMATS:-${FORMATS_DEFAULT}}"
NAME="${NAME:-}"                      # Optional artifact basename
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CACHE_DIR="${CACHE_DIR:-}"
VERIFY_JSON="${VERIFY_JSON:-1}"       # 1=validate JSON outputs with jq
WRITE_SHA256="${WRITE_SHA256:-1}"
GPG_KEY_ID="${GPG_KEY_ID:-}"          # set to key id to enable signing
PARALLEL="${PARALLEL:-0}"             # 1 enables parallel runs for dual source

# Sources (one or both)
TARGET_DIR=""
TARGET_IMAGE=""
DOCKER_PULL="${DOCKER_PULL:-0}"       # 1 to docker pull before scanning image
SYFT_OPTS="${SYFT_OPTS:-}"
TRIVY_OPTS="${TRIVY_OPTS:-}"
JQ_BIN="${JQ_BIN:-jq}"                # allow custom jq path
SHA256_BIN=""

# -------- Usage --------
usage() {
  cat <<'USAGE'
Usage:
  sbom.sh [options]

Options:
  --dir PATH              Scan filesystem directory PATH
  --image NAME[:TAG]      Scan container image (local or from registry)
  --pull                  docker pull the image before scanning (with --image)
  -o, --outdir PATH       Output directory (default: ./artifacts/sbom)
  -n, --name NAME         Basename for artifacts (default: inferred)
  -f, --format LIST       Comma-separated formats (default: cyclonedx-json)
                          Supported (Syft): cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag-value
                          Fallback (Trivy): cyclonedx-json only
  --cache-dir PATH        Optional cache directory for tools
  --no-json-verify        Do not validate JSON outputs with jq
  --no-sha256             Do not emit .sha256 sums
  --gpg-key KEYID         GPG key ID for detached ASCII signatures (*.asc)
  --parallel              If both --dir and --image given, process in parallel
  --syft-opts "OPTS"      Extra args to syft
  --trivy-opts "OPTS"     Extra args to trivy
  --debug                 Set LOG_LEVEL=DEBUG
  -h, --help              Show this help

Examples:
  sbom.sh --dir . -f cyclonedx-json,spdx-json
  sbom.sh --image ubuntu:22.04 --pull
  sbom.sh --dir ./src --image myorg/app:1.2.3 --parallel -n security-core
USAGE
}

# -------- Argparse --------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)           TARGET_DIR="${2:?}"; shift 2 ;;
    --image)         TARGET_IMAGE="${2:?}"; shift 2 ;;
    --pull)          DOCKER_PULL=1; shift ;;
    -o|--outdir)     OUT_DIR="${2:?}"; shift 2 ;;
    -n|--name)       NAME="${2:?}"; shift 2 ;;
    -f|--format)     FORMATS="${2:?}"; shift 2 ;;
    --cache-dir)     CACHE_DIR="${2:?}"; shift 2 ;;
    --no-json-verify) VERIFY_JSON=0; shift ;;
    --no-sha256)     WRITE_SHA256=0; shift ;;
    --gpg-key)       GPG_KEY_ID="${2:?}"; shift 2 ;;
    --parallel)      PARALLEL=1; shift ;;
    --syft-opts)     SYFT_OPTS="${2:-}"; shift 2 ;;
    --trivy-opts)    TRIVY_OPTS="${2:-}"; shift 2 ;;
    --debug)         LOG_LEVEL="DEBUG"; shift ;;
    -h|--help)       usage; exit 0 ;;
    *)               err "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

# Validate sources
if [[ -z "${TARGET_DIR}" && -z "${TARGET_IMAGE}" ]]; then
  die "Provide at least one source: --dir PATH or --image NAME[:TAG]"
fi

# -------- Tooling detection --------
have_cmd() { command -v "$1" >/dev/null 2>&1; }
TOOL_PRIMARY=""
if have_cmd syft; then
  TOOL_PRIMARY="syft"
elif have_cmd trivy; then
  TOOL_PRIMARY="trivy"
else
  die "Neither 'syft' nor 'trivy' found in PATH. Install syft (preferred) or trivy."
fi

if have_cmd sha256sum; then
  SHA256_BIN="sha256sum"
elif have_cmd shasum; then
  SHA256_BIN="shasum -a 256"
else
  if [[ "${WRITE_SHA256}" -eq 1 ]]; then
    wrn "No sha256sum/shasum available; SHA256 files will not be created."
    WRITE_SHA256=0
  fi
fi

if [[ "${VERIFY_JSON}" -eq 1 && ! $(have_cmd "${JQ_BIN}") ]]; then
  wrn "jq not found; JSON validation disabled."
  VERIFY_JSON=0
fi

if [[ -n "${GPG_KEY_ID}" && ! $(have_cmd gpg) ]]; then
  wrn "gpg not found; GPG signing disabled."
  GPG_KEY_ID=""
fi

# -------- Helpers --------
mkdir -p "${OUT_DIR}"
if [[ -n "${CACHE_DIR}" ]]; then
  mkdir -p "${CACHE_DIR}"
fi

sanitize_name() {
  # Turn arbitrary string into safe filename token
  echo "$1" | tr '/:@ ' '____' | tr -cd '[:alnum:]_.-'
}

git_meta() {
  local kv
  if have_cmd git && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    kv="git_commit=$(git rev-parse --short HEAD 2>/dev/null || true),git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  else
    kv="git_commit=none,git_branch=none"
  fi
  echo "${kv}"
}

artifact_base_for_dir() {
  local base
  if [[ -n "${NAME}" ]]; then base="${NAME}"
  else base="$(basename "$(realpath "$1")")"; fi
  echo "$(sanitize_name "${base}")-dir-${TIMESTAMP}"
}

artifact_base_for_img() {
  local base
  if [[ -n "${NAME}" ]]; then base="${NAME}"
  else base="$(sanitize_name "$1")"; fi
  echo "${base}-img-${TIMESTAMP}"
}

ext_for_format() {
  # Map format to extension
  case "$1" in
    cyclonedx-json) echo "cdx.json" ;;
    cyclonedx-xml)  echo "cdx.xml" ;;
    spdx-json)      echo "spdx.json" ;;
    spdx-tag-value) echo "spdx.tag" ;;
    *)              echo "$1" ;; # fallback
  esac
}

validate_json_if_needed() {
  local file="$1"
  case "${file}" in
    *.json)
      if [[ "${VERIFY_JSON}" -eq 1 ]]; then
        ${JQ_BIN} -e . "${file}" >/dev/null
        inf "Validated JSON: ${file}"
      fi
      ;;
  esac
}

write_sha256_if_needed() {
  local file="$1"
  if [[ "${WRITE_SHA256}" -eq 1 && -n "${SHA256_BIN}" ]]; then
    # Write alongside as .sha256
    ${SHA256_BIN} "${file}" | awk '{print $1}' > "${file}.sha256"
    inf "SHA256: $(cat "${file}.sha256")  (${file})"
  fi
}

sign_gpg_if_needed() {
  local file="$1"
  if [[ -n "${GPG_KEY_ID}" ]]; then
    gpg --batch --yes --local-user "${GPG_KEY_ID}" --armor --detach-sign -o "${file}.asc" "${file}"
    inf "GPG signature created: ${file}.asc"
  fi
}

maybe_pull_image() {
  local img="$1"
  if [[ "${DOCKER_PULL}" -eq 1 ]]; then
    if have_cmd docker; then
      inf "docker pull ${img}"
      docker pull "${img}" >/dev/null
    else
      wrn "docker not available; cannot pull image."
    fi
  fi
}

# -------- SBOM generation backends --------

sbom_syft() {
  # Args: source_type(dir|image) source format outfile
  local st="$1" src="$2" fmt="$3" out="$4"
  local cache_flag=()
  [[ -n "${CACHE_DIR}" ]] && cache_flag+=( "--cache-dir" "${CACHE_DIR}" )

  local source_spec=""
  case "${st}" in
    dir)   source_spec="dir:${src}" ;;
    image) source_spec="${src}" ;;
    *)     die "syft: unsupported source_type: ${st}" ;;
  esac

  inf "syft -> ${fmt}: ${src} -> ${out}"
  # syft supports: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag-value, syft-json
  syft packages "${source_spec}" \
    -o "${fmt}" \
    "${cache_flag[@]}" \
    ${SYFT_OPTS} > "${out}"
}

sbom_trivy() {
  # Args: source_type(dir|image) source fmt out
  local st="$1" src="$2" fmt="$3" out="$4"
  local subcmd=""
  case "${st}" in
    dir)   subcmd="fs" ;;
    image) subcmd="image" ;;
    *)     die "trivy: unsupported source_type: ${st}" ;;
  esac

  if [[ "${fmt}" != "cyclonedx-json" ]]; then
    die "trivy fallback supports cyclonedx-json only (requested: ${fmt})"
  fi

  local cache_flag=()
  [[ -n "${CACHE_DIR}" ]] && cache_flag+=( "--cache-dir" "${CACHE_DIR}" )

  inf "trivy ${subcmd} -> ${fmt}: ${src} -> ${out}"
  trivy "${subcmd}" "${src}" \
    --format cyclonedx \
    --output "${out}" \
    "${cache_flag[@]}" \
    ${TRIVY_OPTS}
}

generate_sbom() {
  # Args: source_type(dir|image) source formats base_outname
  local st="$1" src="$2" formats_csv="$3" base="$4"
  IFS=',' read -r -a formats <<< "${formats_csv}"

  for fmt in "${formats[@]}"; do
    local ext; ext=$(ext_for_format "${fmt}")
    local out="${OUT_DIR}/${base}.${ext}"

    if have_cmd syft; then
      sbom_syft "${st}" "${src}" "${fmt}" "${out}"
    else
      sbom_trivy "${st}" "${src}" "${fmt}" "${out}"
    fi

    validate_json_if_needed "${out}"
    write_sha256_if_needed "${out}"
    sign_gpg_if_needed "${out}"
  done

  # Emit a small metadata file
  local meta="${OUT_DIR}/${base}.meta"
  {
    echo "generated_at=${TIMESTAMP}"
    echo "tool_primary=${TOOL_PRIMARY}"
    echo "source_type=${st}"
    echo "source=${src}"
    echo "formats=${formats_csv}"
    echo "git_meta=$(git_meta)"
  } > "${meta}"
  write_sha256_if_needed "${meta}"
}

# -------- Orchestration --------
jobs=()

if [[ -n "${TARGET_DIR}" ]]; then
  [[ -d "${TARGET_DIR}" ]] || die "--dir path not found: ${TARGET_DIR}"
  local_base="$(artifact_base_for_dir "${TARGET_DIR}")"
  if [[ "${PARALLEL}" -eq 1 && -n "${TARGET_IMAGE}" ]]; then
    generate_sbom dir "${TARGET_DIR}" "${FORMATS}" "${local_base}" &
    jobs+=($!)
  else
    generate_sbom dir "${TARGET_DIR}" "${FORMATS}" "${local_base}"
  fi
fi

if [[ -n "${TARGET_IMAGE}" ]]; then
  maybe_pull_image "${TARGET_IMAGE}"
  image_base="$(artifact_base_for_img "${TARGET_IMAGE}")"
  if [[ "${PARALLEL}" -eq 1 && -n "${TARGET_DIR}" ]]; then
    generate_sbom image "${TARGET_IMAGE}" "${FORMATS}" "${image_base}" &
    jobs+=($!)
  else
    generate_sbom image "${TARGET_IMAGE}" "${FORMATS}" "${image_base}"
  fi
fi

# Wait for parallel jobs
if [[ ${#jobs[@]} -gt 0 ]]; then
  inf "Waiting for ${#jobs[@]} background job(s)..."
  wait "${jobs[@]}"
fi

inf "SBOM artifacts stored in: ${OUT_DIR}"
