# path: policy-core/scripts/policy_bundle_build.sh
#!/usr/bin/env bash
# Industrial bundle builder for policy-core
# Reproducible, signed, and SBOM-attested bundles
# Dependencies: bash >= 4, coreutils, tar/zip, awk, sed
# Optional: git, gpg, openssl, jq, yq, sha256sum/sha512sum or shasum
set -Eeuo pipefail

# ----------------------------- Config & Defaults -----------------------------
SCRIPT_VERSION="1.1.0"
# Colors when TTY
if [[ -t 1 ]]; then
  _C_BOLD=$'\033[1m'; _C_DIM=$'\033[2m'; _C_RED=$'\033[31m'; _C_YEL=$'\033[33m'
  _C_GRN=$'\033[32m'; _C_CYN=$'\033[36m'; _C_RST=$'\033[0m'
else
  _C_BOLD=""; _C_DIM=""; _C_RED=""; _C_YEL=""; _C_GRN=""; _C_CYN=""; _C_RST=""
fi

# Resolve paths
__dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
POLICY_ROOT="$(cd -- "${__dir}/.." && pwd)"
VERSION_FILE="${POLICY_ROOT}/VERSION"

# Defaults (overridable via args/env)
POLICY_NAME="${POLICY_NAME:-policy-core}"
SRC_DIR="${SRC_DIR:-${POLICY_ROOT}}"
OUT_DIR="${OUT_DIR:-${POLICY_ROOT}/dist}"
FORMAT="${FORMAT:-tar.gz}"           # tar.gz | zip | dir
SIGN_METHOD="${SIGN_METHOD:-none}"   # none | gpg | openssl
SIGN_KEY="${SIGN_KEY:-}"             # gpg key id OR path to PEM private key (for openssl)
INCLUDE_GLOBS_DEFAULT=( "*.md" "*.yml" "*.yaml" "*.json" "*.rego" )
EXCLUDE_GLOBS_DEFAULT=( ".git/**" "dist/**" "**/.venv/**" "**/__pycache__/**" )
INCLUDE_GLOBS=("${INCLUDE_GLOBS_DEFAULT[@]}")
EXCLUDE_GLOBS=("${EXCLUDE_GLOBS_DEFAULT[@]}")
STRICT="${STRICT:-0}"                # 1 = treat warnings as errors
DRY_RUN="${DRY_RUN:-0}"
CLEAN_OUT="${CLEAN_OUT:-0}"

# ----------------------------- Utility Functions -----------------------------
log()   { printf "%s%s%s %s\n" "${_C_DIM}" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "${_C_RST}" "$*"; }
info()  { printf "%sℹ%s %s\n" "${_C_CYN}" "${_C_RST}" "$*"; }
ok()    { printf "%s✓%s %s\n" "${_C_GRN}" "${_C_RST}" "$*"; }
warn()  { printf "%s!%s %s\n" "${_C_YEL}" "${_C_RST}" "$*"; }
err()   { printf "%s✗%s %s\n" "${_C_RED}" "${_C_RST}" "$*" >&2; }
die()   { err "$*"; exit 1; }

have()  { command -v "$1" >/dev/null 2>&1; }

on_exit() {
  local ec=$?
  if [[ ${ec} -ne 0 ]]; then err "Build failed with code ${ec}"; fi
}
trap on_exit EXIT

# Realpath portable
realpath_p() { python3 -c 'import os,sys;print(os.path.realpath(sys.argv[1]))' "$1"; }

# sha256/512 portable
sha256() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
sha512() {
  if have sha512sum; then sha512sum "$1" | awk '{print $1}'; else shasum -a 512 "$1" | awk '{print $1}'; fi
}

# GNU date fallback
DATE_BIN="date"
if ! date --version >/dev/null 2>&1; then
  if have gdate; then DATE_BIN="gdate"; fi
fi

# Glob matcher (rsync-style) using find
collect_files() {
  local base="$1"; shift
  local -a includes=("$@")
  local -a find_args=( -type f )
  local path file rel
  # Include patterns
  local tmp_include
  for pat in "${includes[@]}"; do
    find_args+=( -name "${pat}" -o )
  done
  # Remove trailing -o
  unset 'find_args[${#find_args[@]}-1]'
  # Run find and post-filter excludes
  while IFS= read -r -d '' file; do
    rel="${file#${base}/}"
    if should_exclude "${rel}"; then continue; fi
    printf "%s\0" "${file}"
  done < <(find "${base}" \( "${find_args[@]}" \) -print0 2>/dev/null)
}

should_exclude() {
  local rel="$1"
  local pat
  for pat in "${EXCLUDE_GLOBS[@]}"; do
    # crude glob-to-regex: ** -> .*, * -> [^/]*, escape dots
    local rx="${pat//./\\.}"; rx="${rx//\*\*/.*}"; rx="${rx//\*/[^\/]*}"
    if [[ "${rel}" =~ ^${rx}$ ]]; then return 0; fi
  done
  return 1
}

# SemVer validator
semver_ok() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([-+].*)?$ ]]
}

# JSON encode key/value with jq or pure shell
json_kv() {
  local k="$1" v="$2"
  if have jq; then
    jq -cn --arg k "$k" --arg v "$v" '{($k):$v}'
  else
    # naive escaping
    v=${v//\"/\\\"}
    printf '{"%s":"%s"}' "$k" "$v"
  fi
}

# Merge many small JSON documents into one object with jq; fallback to simple concat text
json_merge_objs() {
  if have jq; then jq -s 'reduce .[] as $i ({}; . * $i)'; else cat; fi
}

# Deterministic tar flags (GNU tar); gracefully degrade on BSD tar
tar_create() {
  local archive="$1" src_dir="$2"
  if tar --version >/dev/null 2>&1; then
    # Try GNU tar features
    if tar --help 2>&1 | grep -q -- "--sort=name"; then
      tar --owner=0 --group=0 --numeric-owner \
          --sort=name --mtime="@${SOURCE_DATE_EPOCH}" \
          -C "${src_dir}" -czf "${archive}" .
      return
    fi
  fi
  # BSD tar fallback (no sort/mtime)
  warn "BSD tar detected; tarball may be less reproducible"
  tar -C "${src_dir}" -czf "${archive}" .
}

zip_create() {
  local archive="$1" src_dir="$2"
  if have zip; then
    (cd "${src_dir}" && zip -r -q -X -9 "${archive}" .)
  else
    die "zip not found; install 'zip' or use --format tar.gz"
  fi
}

# Sign file
sign_file() {
  local file="$1"
  case "${SIGN_METHOD}" in
    gpg)
      have gpg || die "gpg not found"
      local args=( --batch --yes --armor --output "${file}.asc" --detach-sign )
      [[ -n "${SIGN_KEY}" ]] && args+=( --local-user "${SIGN_KEY}" )
      gpg "${args[@]}" "${file}"
      ok "GPG signature: ${file}.asc"
      ;;
    openssl)
      have openssl || die "openssl not found"
      [[ -n "${SIGN_KEY}" ]] || die "--sign openssl requires --key path/to/private_key.pem"
      openssl dgst -sha256 -sign "${SIGN_KEY}" -out "${file}.sig" "${file}"
      ok "OpenSSL signature: ${file}.sig"
      ;;
    none|*)
      ;;
  esac
}

# ----------------------------- CLI Arguments ---------------------------------
usage() {
  cat <<EOF
${_C_BOLD}${POLICY_NAME} bundle builder${_C_RST} v${SCRIPT_VERSION}
Usage:
  $(basename "$0") [options]

Options:
  --src DIR              Source root to collect files (default: ${SRC_DIR})
  --out DIR              Output directory for artifacts (default: ${OUT_DIR})
  --format FMT           tar.gz | zip | dir (default: ${FORMAT})
  --name NAME            Bundle base name (default: ${POLICY_NAME})
  --version VER          Override version (default: read from VERSION)
  --include "p1,p2"      Comma-separated include globs (default: ${INCLUDE_GLOBS_DEFAULT[*]})
  --exclude "e1,e2"      Comma-separated exclude globs
  --sign METHOD          none | gpg | openssl (default: ${SIGN_METHOD})
  --key KEY              GPG key-id (gpg) or private key path (openssl)
  --strict               Treat warnings as errors
  --clean                Clean output directory before build
  --dry-run              Print planned actions only
  -h|--help              Show this help
EOF
}

VER_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --src) SRC_DIR="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --format) FORMAT="$2"; shift 2 ;;
    --name) POLICY_NAME="$2"; shift 2 ;;
    --version) VER_OVERRIDE="$2"; shift 2 ;;
    --include) IFS=',' read -r -a INCLUDE_GLOBS <<<"$2"; shift 2 ;;
    --exclude) IFS=',' read -r -a EXCLUDE_GLOBS <<<"$2"; shift 2 ;;
    --sign) SIGN_METHOD="$2"; shift 2 ;;
    --key) SIGN_KEY="$2"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --clean) CLEAN_OUT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ----------------------------- Preconditions ---------------------------------
[[ -d "${SRC_DIR}" ]] || die "Source directory not found: ${SRC_DIR}"
mkdir -p "${OUT_DIR}"

if [[ -f "${VERSION_FILE}" ]]; then
  VERSION="$(<"${VERSION_FILE}")"
  VERSION="${VER_OVERRIDE:-${VERSION}}"
else
  VERSION="${VER_OVERRIDE:-0.0.0}"
fi
VERSION="${VERSION#"${VERSION%%[![:space:]]*}"}"; VERSION="${VERSION%"${VERSION##*[![:space:]]}"}"
semver_ok "${VERSION}" || { [[ "${STRICT}" -eq 1 ]] && die "Invalid SemVer: ${VERSION}"; warn "Non-SemVer version: ${VERSION}"; }

GIT_COMMIT="unknown"
GIT_DIRTY="0"
if have git && git -C "${POLICY_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  GIT_COMMIT="$(git -C "${POLICY_ROOT}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  if [[ -n "$(git -C "${POLICY_ROOT}" status --porcelain 2>/dev/null)" ]]; then GIT_DIRTY="1"; fi
else
  warn "git not available; provenance will be limited"
fi

# Reproducible timestamp
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  if [[ "${GIT_COMMIT}" != "unknown" ]]; then
    SOURCE_DATE_EPOCH="$(git -C "${POLICY_ROOT}" log -1 --format=%ct 2>/dev/null || ${DATE_BIN} +%s)"
  else
    SOURCE_DATE_EPOCH="$(${DATE_BIN} +%s)"
  fi
  export SOURCE_DATE_EPOCH
fi

BUILD_DATE_ISO="$(${DATE_BIN} -u -d "@${SOURCE_DATE_EPOCH}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || ${DATE_BIN} -u +"%Y-%m-%dT%H:%M:%SZ")"
BASENAME="${POLICY_NAME}-${VERSION}"
[[ "${GIT_COMMIT}" != "unknown" ]] && BASENAME="${BASENAME}+${GIT_COMMIT}"

STAGE_DIR="$(mktemp -d -t policy-bundle.XXXXXXXX)"
trap 'rm -rf -- "${STAGE_DIR}"' INT TERM EXIT

info "Building ${_C_BOLD}${BASENAME}${_C_RST}"
log  "Policy root: ${POLICY_ROOT}"
log  "Source dir : ${SRC_DIR}"
log  "Output dir : ${OUT_DIR}"
log  "Format     : ${FORMAT}"
log  "Version    : ${VERSION}"
log  "Git commit : ${GIT_COMMIT} (dirty=${GIT_DIRTY})"
log  "Timestamp  : ${BUILD_DATE_ISO} (SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH})"

# Clean output if requested
if [[ "${CLEAN_OUT}" -eq 1 ]]; then
  warn "Cleaning output directory: ${OUT_DIR}"
  find "${OUT_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
fi

# ----------------------------- Collect & Stage --------------------------------
info "Collecting files…"
mapfile -d '' FILES < <(collect_files "${SRC_DIR}" "${INCLUDE_GLOBS[@]}")

if [[ "${#FILES[@]}" -eq 0 ]]; then
  [[ "${STRICT}" -eq 1 ]] && die "No files matched include globs in ${SRC_DIR}"
  warn "No files matched include globs; bundle will be metadata-only"
fi

# Copy files to stage preserving relative structure
for abs in "${FILES[@]:-}"; do
  rel="${abs#${SRC_DIR}/}"
  dst_dir="${STAGE_DIR}/payload/$(dirname -- "${rel}")"
  mkdir -p "${dst_dir}"
  cp -p "${abs}" "${STAGE_DIR}/payload/${rel}"
done

# ----------------------------- Manifest & SBOM --------------------------------
info "Generating manifest…"
mkdir -p "${STAGE_DIR}/meta"

MANIFEST="${STAGE_DIR}/meta/manifest.json"
{
  echo '{'
  echo '  "name": "'"${POLICY_NAME}"'",'
  echo '  "version": "'"${VERSION}"'",'
  echo '  "created": "'"${BUILD_DATE_ISO}"'",'
  echo '  "git_commit": "'"${GIT_COMMIT}"'",'
  echo '  "git_dirty": '"${GIT_DIRTY}"','
  echo '  "source_date_epoch": '"${SOURCE_DATE_EPOCH}"','
  echo '  "files": ['
  first=1
  while IFS= read -r -d '' f; do
    rel="${f#${STAGE_DIR}/payload/}"
    size=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
    h256=$(sha256 "$f")
    h512=$(sha512 "$f")
    [[ $first -eq 0 ]] && echo '    ,'
    printf '    {"path":"%s","size":%s,"sha256":"%s","sha512":"%s"}' "${rel}" "${size}" "${h256}" "${h512}"
    first=0
  done < <(find "${STAGE_DIR}/payload" -type f -print0 | sort -z)
  echo
  echo '  ]'
  echo '}'
} > "${MANIFEST}"

ok "Manifest: ${MANIFEST}"

info "Creating minimal SPDX SBOM…"
SBOM="${STAGE_DIR}/meta/sbom.spdx"
{
  echo "SPDXVersion: SPDX-2.2"
  echo "DataLicense: CC0-1.0"
  echo "SPDXID: SPDXRef-DOCUMENT"
  echo "DocumentName: ${POLICY_NAME}-${VERSION}"
  echo "DocumentNamespace: https://example.local/spdx/${POLICY_NAME}/${VERSION}/${GIT_COMMIT:-na}"
  echo "Creator: Tool: ${POLICY_NAME}-bundle-builder/${SCRIPT_VERSION}"
  echo "Created: ${BUILD_DATE_ISO}"
  echo "######## Files ########"
  while IFS= read -r -d '' f; do
    rel="${f#${STAGE_DIR}/payload/}"
    echo "FileName: ${rel}"
    echo "SPDXID: SPDXRef-File-$(echo "${rel}" | tr '/.' '__')"
    echo "FileChecksum: SHA256: $(sha256 "$f")"
    echo "LicenseConcluded: NOASSERTION"
    echo "LicenseInfoInFile: NOASSERTION"
    echo "FileCopyrightText: NOASSERTION"
    echo ""
  done < <(find "${STAGE_DIR}/payload" -type f -print0 | sort -z)
} > "${SBOM}"
ok "SBOM: ${SBOM}"

# Write bundle metadata
BUNDLE_META="${STAGE_DIR}/meta/bundle.json"
jq_present=0; have jq && jq_present=1 || true
if [[ ${jq_present} -eq 1 ]]; then
  jq -n \
    --arg name "${POLICY_NAME}" \
    --arg version "${VERSION}" \
    --arg created "${BUILD_DATE_ISO}" \
    --arg commit "${GIT_COMMIT}" \
    --argjson dirty "${GIT_DIRTY}" \
    --arg format "${FORMAT}" \
    '{name:$name,version:$version,created:$created,git_commit:$commit,git_dirty:$dirty,format:$format}' \
    > "${BUNDLE_META}"
else
  cat > "${BUNDLE_META}" <<EOF
{"name":"${POLICY_NAME}","version":"${VERSION}","created":"${BUILD_DATE_ISO}","git_commit":"${GIT_COMMIT}","git_dirty":${GIT_DIRTY},"format":"${FORMAT}"}
EOF
fi
ok "Bundle meta: ${BUNDLE_META}"

# ----------------------------- Archive/Emit -----------------------------------
ART_BASE="${OUT_DIR}/${BASENAME}"
mkdir -p "${OUT_DIR}"

if [[ "${DRY_RUN}" -eq 1 ]]; then
  warn "Dry-run enabled; no artifacts will be created"
  exit 0
fi

case "${FORMAT}" in
  tar.gz)
    ARCHIVE="${ART_BASE}.tar.gz"
    # Normalize stage root to deterministic structure
    PKG_ROOT="${STAGE_DIR}/package"
    mkdir -p "${PKG_ROOT}"
    # Copy meta and payload under a single root dir
    ROOT_DIR_NAME="${BASENAME}"
    mkdir -p "${PKG_ROOT}/${ROOT_DIR_NAME}"
    cp -a "${STAGE_DIR}/meta" "${PKG_ROOT}/${ROOT_DIR_NAME}/"
    cp -a "${STAGE_DIR}/payload" "${PKG_ROOT}/${ROOT_DIR_NAME}/"
    tar_create "${ARCHIVE}" "${PKG_ROOT}"
    ok "Archive: ${ARCHIVE}"
    ;;
  zip)
    ARCHIVE="${ART_BASE}.zip"
    PKG_ROOT="${STAGE_DIR}/package"
    mkdir -p "${PKG_ROOT}/${BASENAME}"
    cp -a "${STAGE_DIR}/meta" "${PKG_ROOT}/${BASENAME}/"
    cp -a "${STAGE_DIR}/payload" "${PKG_ROOT}/${BASENAME}/"
    zip_create "${ARCHIVE}" "${PKG_ROOT}"
    ok "Archive: ${ARCHIVE}"
    ;;
  dir)
    DEST_DIR="${ART_BASE}"
    rm -rf -- "${DEST_DIR}"
    mkdir -p "${DEST_DIR}"
    cp -a "${STAGE_DIR}/meta" "${DEST_DIR}/"
    cp -a "${STAGE_DIR}/payload" "${DEST_DIR}/"
    ok "Directory bundle: ${DEST_DIR}"
    ;;
  *)
    die "Unknown --format: ${FORMAT}"
    ;;
esac

# Checksums
info "Writing checksums…"
if [[ "${FORMAT}" == "dir" ]]; then
  TARGET_PATH="${DEST_DIR}"
  # produce checksums for all files inside directory
  SHA256_FILE="${DEST_DIR}/SHA256SUMS"
  SHA512_FILE="${DEST_DIR}/SHA512SUMS"
  : > "${SHA256_FILE}"
  : > "${SHA512_FILE}"
  while IFS= read -r -d '' f; do
    rel="${f#${DEST_DIR}/}"
    printf "%s  %s\n" "$(sha256 "$f")" "${rel}" >> "${SHA256_FILE}"
    printf "%s  %s\n" "$(sha512 "$f")" "${rel}" >> "${SHA512_FILE}"
  done < <(find "${DEST_DIR}" -type f -print0 | sort -z)
  ok "Checksums: ${SHA256_FILE}, ${SHA512_FILE}"
else
  TARGET_PATH="${ARCHIVE}"
  SHA256_FILE="${ARCHIVE}.sha256"
  SHA512_FILE="${ARCHIVE}.sha512"
  printf "%s  %s\n" "$(sha256 "${ARCHIVE}")" "$(basename -- "${ARCHIVE}")" > "${SHA256_FILE}"
  printf "%s  %s\n" "$(sha512 "${ARCHIVE}")" "$(basename -- "${ARCHIVE}")" > "${SHA512_FILE}"
  ok "Checksums: ${SHA256_FILE}, ${SHA512_FILE}"
fi

# Sign
if [[ "${SIGN_METHOD}" != "none" ]]; then
  info "Signing artifacts with ${SIGN_METHOD}…"
  sign_file "${SHA256_FILE}"
  sign_file "${SHA512_FILE}"
fi

ok "Build complete"

# Print summary JSON for CI
SUMMARY_JSON="${OUT_DIR}/${BASENAME}.build.json"
{
  json_kv "name" "${POLICY_NAME}"
  json_kv "version" "${VERSION}"
  json_kv "git_commit" "${GIT_COMMIT}"
  json_kv "created" "${BUILD_DATE_ISO}"
  json_kv "format" "${FORMAT}"
  json_kv "artifact" "${ARCHIVE:-$DEST_DIR}"
} | json_merge_objs > "${SUMMARY_JSON}"
ok "Summary: ${SUMMARY_JSON}"

exit 0
