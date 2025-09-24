#!/usr/bin/env bash
# neuroforge-core release signing utility
# Features:
#  - Prepare artifacts list and metadata (provenance)
#  - Calculate SHA256 & SHA512 checksums (deterministic order)
#  - GPG detached, armored signatures for each artifact and for checksum files
#  - Optional Git tag signing
#  - Verification of checksums and signatures
#  - Safe defaults, strict bash, clear diagnostics
#
# Requirements: bash, git, gpg, sha256sum|shasum, sha512sum|shasum, sort, awk, date, sed
# Optional: openssl (for extra fingerprint checks)
#
# Exit codes: 0 OK, 2 usage error, 3 dependency missing, 4 signing error, 5 verify error

set -Eeuo pipefail
shopt -s failglob nullglob
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR_DEFAULT="${ROOT_DIR}/.out/release"
ART_DIR_DEFAULT="${ROOT_DIR}/dist"

# -------- Logging --------
log()  { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { log "ERROR: $*"; exit "${2:-1}"; }
note() { log "INFO:  $*"; }
warn() { log "WARN:  $*"; }

# -------- Tooling detection --------
need() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required tool: $1" 3
}

SHA256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  else need shasum; shasum -a 256 "$@"
  fi
}
SHA512() {
  if command -v sha512sum >/dev/null 2>&1; then sha512sum "$@"
  else need shasum; shasum -a 512 "$@"
  fi
}

# -------- Defaults & ENV --------
RELEASE_VERSION="${RELEASE_VERSION:-}"                 # e.g. v1.0.0
ARTIFACTS_GLOB="${ARTIFACTS_GLOB:-${ART_DIR_DEFAULT}/*}"   # path or glob
OUT_DIR="${OUT_DIR:-$OUT_DIR_DEFAULT}"                 # output directory for signatures
GPG_KEY_ID="${GPG_KEY_ID:-}"                           # e.g. 0xDEADBEEF... or user@domain
GIT_SIGN_TAG="${GIT_SIGN_TAG:-true}"                   # true|false
PROVENANCE_EXTRA="${PROVENANCE_EXTRA:-}"               # additional JSON fields (compact), optional
ARMOR="${ARMOR:-true}"                                 # gpg --armor if true
PARANOID="${PARANOID:-false}"                          # verify each step

# -------- Usage --------
usage() {
  cat <<EOF
${SCRIPT_NAME} - sign and verify release artifacts

USAGE:
  # Full pipeline (prepare + sign + verify)
  RELEASE_VERSION=v1.2.3 GPG_KEY_ID=<key> ${SCRIPT_NAME} all [--artifacts "<glob>"] [--out <dir>] [--no-tag]

SUBCOMMANDS:
  prepare   Prepare metadata and checksums for artifacts.
  sign      Sign artifacts, checksum files and optional git tag.
  verify    Verify checksums and signatures.
  all       Run prepare -> sign -> verify.

OPTIONS (env or flags):
  --artifacts "<glob>"   Glob or path to artifacts (default: ${ARTIFACTS_GLOB})
  --out <dir>            Output directory (default: ${OUT_DIR})
  --no-tag               Do not sign/create git tag (env GIT_SIGN_TAG=false)
  --version <v>          Release version (e.g., v1.2.3) (env RELEASE_VERSION)
  --key <id>             GPG key id/email (env GPG_KEY_ID)
  --paranoid             Enable step-by-step verification (env PARANOID=true)

ENV EXAMPLES:
  RELEASE_VERSION=v1.2.3
  GPG_KEY_ID="release@neuroforge.local"
  ARTIFACTS_GLOB="dist/*"
  OUT_DIR=".out/release"

EXIT:
  0 OK, 2 usage, 3 deps, 4 signing, 5 verify
EOF
}

# -------- Args parsing --------
SUBCMD="${1:-}"
shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS_GLOB="$2"; shift 2;;
    --out)       OUT_DIR="$2"; shift 2;;
    --version)   RELEASE_VERSION="$2"; shift 2;;
    --key)       GPG_KEY_ID="$2"; shift 2;;
    --no-tag)    GIT_SIGN_TAG="false"; shift 1;;
    --paranoid)  PARANOID="true"; shift 1;;
    -h|--help)   usage; exit 0;;
    *)           die "Unknown argument: $1" 2;;
  esac
done

[[ -z "${SUBCMD}" ]] && { usage; exit 2; }

# -------- Preconditions --------
require_base_tools() {
  need git; need gpg; need awk; need sort; need sed; need date
  # one of sha256sum/shasum and sha512sum/shasum checked dynamically
}

ensure_dirs() {
  mkdir -p "${OUT_DIR}" || die "Cannot create OUT_DIR: ${OUT_DIR}"
}

ensure_version() {
  [[ -n "${RELEASE_VERSION}" ]] || die "RELEASE_VERSION must be set (e.g., v1.2.3)" 2
  [[ "${RELEASE_VERSION}" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z\.-]+)?$ ]] || \
    die "RELEASE_VERSION must look like vMAJOR.MINOR.PATCH[-PRERELEASE]" 2
}

ensure_gpg() {
  [[ -n "${GPG_KEY_ID}" ]] || die "GPG_KEY_ID must be provided" 2
  if ! gpg --batch --list-keys "${GPG_KEY_ID}" >/dev/null 2>&1; then
    die "GPG key not found in keyring: ${GPG_KEY_ID}" 3
  fi
}

list_artifacts() {
  # Resolve glob deterministically
  local -a files=()
  while IFS= read -r -d '' f; do files+=("$f"); done < <(printf '%s\0' ${ARTIFACTS_GLOB} | xargs -0 -I{} bash -c 'for p in {}; do [[ -e "$p" ]] && printf "%s\0" "$p"; done')
  if [[ ${#files[@]} -eq 0 ]]; then
    die "No artifacts match: ${ARTIFACTS_GLOB}" 2
  fi
  printf '%s\n' "${files[@]}" | awk 'NF' | sort
}

git_info_json() {
  local commit branch dirty ts
  commit="$(git rev-parse --verify HEAD 2>/dev/null || echo 'unknown')"
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
  ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  if [[ "$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')" != "0" ]]; then
    dirty="true"
  else
    dirty="false"
  fi
  jq -c -n \
    --arg version "${RELEASE_VERSION}" \
    --arg commit "${commit}" \
    --arg branch "${branch}" \
    --arg timestamp "${ts}" \
    --arg tool "${SCRIPT_NAME}" \
    --argjson dirty "${dirty}" \
    '{version:$version,commit:$commit,branch:$branch,timestamp:$timestamp,dirty:$dirty,tool:$tool}'
}

# -------- Commands --------
cmd_prepare() {
  require_base_tools
  ensure_version
  ensure_dirs
  note "Collecting artifacts..."
  mapfile -t ARTIFACTS < <(list_artifacts)

  local checksums256="${OUT_DIR}/CHECKSUMS-SHA256.txt"
  local checksums512="${OUT_DIR}/CHECKSUMS-SHA512.txt"

  : > "${checksums256}"
  : > "${checksums512}"

  note "Computing checksums..."
  for f in "${ARTIFACTS[@]}"; do
    # write relative paths for portability
    local rel
    rel="$(python3 - <<PY 2>/dev/null || echo "$f"
import os,sys
print(os.path.relpath(sys.argv[1], sys.argv[2]))
PY
"$f" "${ROOT_DIR}")"
    (cd "${ROOT_DIR}" && SHA256 "${rel}") >> "${checksums256}"
    (cd "${ROOT_DIR}" && SHA512 "${rel}") >> "${checksums512}"
  done

  # Canonicalize order
  sort -o "${checksums256}" "${checksums256}"
  sort -o "${checksums512}" "${checksums512}"

  # Provenance JSON (requires jq)
  if command -v jq >/dev/null 2>&1; then
    note "Writing provenance..."
    local prov="${OUT_DIR}/PROVENANCE.json"
    local files_json
    files_json="$(printf '%s\n' "${ARTIFACTS[@]}" | jq -R -s -c 'split("\n")|map(select(length>0))')"
    local base
    base="$(git_info_json)"
    if [[ -n "${PROVENANCE_EXTRA}" ]]; then
      echo "${base}" | jq -c --argjson files "${files_json}" --argjson extra "${PROVENANCE_EXTRA}" \
        '. + {artifacts:$files} + $extra' > "${prov}"
    else
      echo "${base}" | jq -c --argjson files "${files_json}" \
        '. + {artifacts:$files}' > "${prov}"
    fi
  else
    warn "jq not found; skipping PROVENANCE.json"
  fi

  note "Prepared: ${checksums256}, ${checksums512}"
}

gpg_sign_file() {
  local infile="$1"
  local armor_flag=()
  [[ "${ARMOR}" == "true" ]] && armor_flag+=(--armor)
  gpg --batch --yes --local-user "${GPG_KEY_ID}" --detach-sign "${armor_flag[@]}" --output "${infile}.asc" "${infile}" \
    || die "GPG sign failed: ${infile}" 4
}

cmd_sign() {
  require_base_tools
  ensure_version
  ensure_dirs
  ensure_gpg

  mapfile -t ARTIFACTS < <(list_artifacts)
  local checksums256="${OUT_DIR}/CHECKSUMS-SHA256.txt"
  local checksums512="${OUT_DIR}/CHECKSUMS-SHA512.txt"
  [[ -f "${checksums256}" && -f "${checksums512}" ]] || die "Run 'prepare' first (checksums not found in ${OUT_DIR})" 2

  note "Signing artifacts..."
  for f in "${ARTIFACTS[@]}"; do
    gpg_sign_file "${f}"
  done

  note "Signing checksum files..."
  gpg_sign_file "${checksums256}"
  gpg_sign_file "${checksums512}"

  if [[ -f "${OUT_DIR}/PROVENANCE.json" ]]; then
    note "Signing provenance..."
    gpg_sign_file "${OUT_DIR}/PROVENANCE.json"
  fi

  if [[ "${GIT_SIGN_TAG}" == "true" ]]; then
    note "Signing/creating git tag ${RELEASE_VERSION}..."
    if git rev-parse "${RELEASE_VERSION}" >/dev/null 2>&1; then
      note "Tag exists; re-signing annotated tag"
      git tag -s -f "${RELEASE_VERSION}" -m "Release ${RELEASE_VERSION}" || die "git tag sign failed" 4
    else
      git tag -s "${RELEASE_VERSION}" -m "Release ${RELEASE_VERSION}" || die "git tag create failed" 4
    fi
  else
    note "Git tag signing disabled"
  fi

  if [[ "${PARANOID}" == "true" ]]; then
    cmd_verify || die "Paranoid verify failed" 5
  fi

  note "Sign complete."
}

cmd_verify() {
  require_base_tools
  ensure_version
  ensure_dirs

  mapfile -t ARTIFACTS < <(list_artifacts)
  local checksums256="${OUT_DIR}/CHECKSUMS-SHA256.txt"
  local checksums512="${OUT_DIR}/CHECKSUMS-SHA512.txt"
  [[ -f "${checksums256}" && -f "${checksums512}" ]] || die "Checksum files not found; run prepare/sign first" 2

  note "Verifying checksums..."
  (cd "${ROOT_DIR}" && (sha256sum -c "${checksums256}" 2>/dev/null || shasum -a 256 -c "${checksums256}")) \
    || die "SHA256 mismatch" 5
  (cd "${ROOT_DIR}" && (sha512sum -c "${checksums512}" 2>/devnull || shasum -a 512 -c "${checksums512}")) \
    || die "SHA512 mismatch" 5

  note "Verifying artifact signatures..."
  for f in "${ARTIFACTS[@]}"; do
    [[ -f "${f}.asc" ]] || die "Missing signature: ${f}.asc" 5
    gpg --batch --verify "${f}.asc" "${f}" >/dev/null 2>&1 || die "GPG verify failed: ${f}" 5
  done

  for s in "${checksums256}" "${checksums512}" "${OUT_DIR}/PROVENANCE.json"; do
    [[ -f "${s}" && -f "${s}.asc" ]] || { warn "Skip verify: ${s} or ${s}.asc missing"; continue; }
    gpg --batch --verify "${s}.asc" "${s}" >/dev/null 2>&1 || die "GPG verify failed: ${s}" 5
  done

  if git rev-parse "${RELEASE_VERSION}" >/dev/null 2>&1; then
    note "Verifying git tag signature..."
    git tag -v "${RELEASE_VERSION}" >/dev/null 2>&1 || die "git tag signature verify failed" 5
  else
    warn "Git tag ${RELEASE_VERSION} not found; skip verify"
  fi

  note "Verify OK."
}

cmd_all() {
  cmd_prepare
  cmd_sign
  cmd_verify
}

# -------- Dispatch --------
case "${SUBCMD}" in
  prepare) cmd_prepare;;
  sign)    cmd_sign;;
  verify)  cmd_verify;;
  all)     cmd_all;;
  *)       usage; exit 2;;
esac
