#!/usr/bin/env bash
# File: aethernova-chain-core/scripts/build_release.sh
# Description: Industrial-grade release builder for Aethernova Chain Core.
# Creates reproducible source archives, computes checksums, optional SBOM (syft),
# optional GPG signatures, generates release notes, and git-tags the version.

set -euo pipefail

#############################################
# Logging / Trap
#############################################
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf "%s [%s] %s\n" "$(ts)" "$1" "$2"; }
die() { log "ERROR" "$*"; exit 1; }

cleanup() { :; }
trap cleanup EXIT

#############################################
# Defaults
#############################################
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"
VERSION_FILE="${PROJECT_ROOT}/VERSION"
CHANGELOG_FILE="${DIST_DIR}/RELEASE_NOTES.md"

RELEASE_TYPE=""          # major|minor|patch|none
PUSH_TAG="false"
SIGN_ARTIFACTS="auto"    # auto|true|false
MAKE_SBOM="auto"         # auto|true|false
PROVENANCE="false"       # reserved for future (cosign/slsa-generator)
GIT_REMOTE="origin"
TAG_PREFIX="v"
ARCHIVE_PREFIX="aethernova-chain-core"
ARCHIVE_FORMAT="tar.gz"  # tar.gz only (reproducible)

#############################################
# Helpers
#############################################
usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --type {major|minor|patch|none}   Version bump type (default: none; uses VERSION as-is).
  --push-tag {true|false}           Push created tag to remote (default: false).
  --sign {auto|true|false}          GPG sign artifacts if gpg available or force/disable (default: auto).
  --sbom {auto|true|false}          Generate SBOM with syft if available or force/disable (default: auto).
  --remote <name>                   Git remote to push tag (default: origin).
  --tag-prefix <prefix>             Tag prefix (default: v).
  -h, --help                        Show this help.

Environment:
  GPG_KEY_ID                        GPG key id/email to use for signing (optional).

Examples:
  $(basename "$0") --type patch --push-tag true
  $(basename "$0") --type none --sign auto --sbom auto
EOF
}

have() { command -v "$1" >/dev/null 2>&1; }

require_clean_git() {
  git -C "${PROJECT_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Not a git repository."
  local st
  st="$(git -C "${PROJECT_ROOT}" status --porcelain)"
  [ -z "${st}" ] || die "Working tree not clean. Commit or stash changes."
}

get_current_version() {
  if [ -f "${VERSION_FILE}" ]; then
    tr -d ' \t\n\r' < "${VERSION_FILE}"
  else
    # Fallback to latest tag (without prefix), if any
    if git -C "${PROJECT_ROOT}" describe --tags --abbrev=0 >/dev/null 2>&1; then
      git -C "${PROJECT_ROOT}" describe --tags --abbrev=0 | sed "s/^${TAG_PREFIX}//"
    else
      echo "0.1.0"
    fi
  fi
}

bump_version() {
  local ver="$1" kind="$2"
  IFS='.' read -r MA MI PA <<<"${ver}"
  case "${kind}" in
    major) MA=$((MA+1)); MI=0; PA=0 ;;
    minor) MI=$((MI+1)); PA=0 ;;
    patch) PA=$((PA+1)) ;;
    none)  ;;
    *) die "Unknown bump type: ${kind}" ;;
  esac
  echo "${MA}.${MI}.${PA}"
}

write_version() {
  echo "$1" > "${VERSION_FILE}"
  git -C "${PROJECT_ROOT}" add "${VERSION_FILE}"
  if [ -n "$(git -C "${PROJECT_ROOT}" status --porcelain "${VERSION_FILE}")" ]; then
    git -C "${PROJECT_ROOT}" commit -m "chore(release): set version $1"
  fi
}

last_tag_or_empty() {
  git -C "${PROJECT_ROOT}" describe --tags --abbrev=0 2>/dev/null || true
}

gen_release_notes() {
  local from_tag="$1" to_ref="$2"
  {
    echo "# Aethernova Chain Core – Release Notes"
    echo
    echo "- Date (UTC): $(ts)"
    echo "- Range: ${from_tag:-<initial>}..${to_ref}"
    echo
    echo "## Summary (Conventional Commits)"
    echo
    # Group by types if possible
    git -C "${PROJECT_ROOT}" log --pretty=format:'- %s (%h) – %an' \
      "${from_tag:+${from_tag}..}${to_ref}" \
      | grep -E '^(feat|fix|perf|refactor|docs|test|chore)(\(|:)' || true
    echo
    echo "## Full Changelog"
    git -C "${PROJECT_ROOT}" log --pretty=format:'- %h %ad %an: %s' --date=short \
      "${from_tag:+${from_tag}..}${to_ref}"
    echo
  } > "${CHANGELOG_FILE}"
}

reproducible_git_archive() {
  local version="$1"
  local out="${DIST_DIR}/${ARCHIVE_PREFIX}-${version}.tar.gz"
  # Use git archive to avoid untracked/cruft files; fix mtime for reproducibility.
  # mtime: commit time of HEAD; owner/group set to 0.
  local mtime
  mtime="$(git -C "${PROJECT_ROOT}" log -1 --format=%ct HEAD)"
  TZ=UTC \
  git -C "${PROJECT_ROOT}" archive --format=tar --prefix="${ARCHIVE_PREFIX}-${version}/" HEAD \
  | tar --mtime="@${mtime}" --owner=0 --group=0 --numeric-owner -cf - -C /dev/null . \
  | gzip -n > "${out}"
  echo "${out}"
}

sha256sum_portable() {
  if have sha256sum; then
    sha256sum "$@"
  elif have shasum; then
    shasum -a 256 "$@"
  else
    die "No sha256 tool (sha256sum or shasum)."
  fi
}

maybe_sign() {
  local path="$1"
  if [ "${SIGN_ARTIFACTS}" = "false" ]; then return 0; fi
  if [ "${SIGN_ARTIFACTS}" = "true" ] || { [ "${SIGN_ARTIFACTS}" = "auto" ] && have gpg; }; then
    local key="${GPG_KEY_ID:-}"
    if [ -n "${key}" ]; then
      gpg --batch --yes --local-user "${key}" --output "${path}.asc" --detach-sign "${path}"
    else
      gpg --batch --yes --output "${path}.asc" --detach-sign "${path}"
    fi
    log "INFO" "Signed ${path} -> ${path}.asc"
  else
    log "WARN" "Skipping GPG signing (not requested or gpg not available)."
  fi
}

maybe_sbom() {
  local path="$1" version="$2"
  if [ "${MAKE_SBOM}" = "false" ]; then return 0; fi
  if [ "${MAKE_SBOM}" = "true" ] || { [ "${MAKE_SBOM}" = "auto" ] && have syft; }; then
    local out="${DIST_DIR}/${ARCHIVE_PREFIX}-${version}-sbom.spdx.json"
    syft "#{file:${path}}" -o spdx-json > "${out}" || die "SBOM generation failed"
    log "INFO" "SBOM -> ${out}"
    echo "${out}"
  else
    log "WARN" "Skipping SBOM (not requested or syft not available)."
  fi
}

create_tag() {
  local version="$1"
  local tag="${TAG_PREFIX}${version}"
  git -C "${PROJECT_ROOT}" tag -a "${tag}" -m "release: ${tag}"
  log "INFO" "Created tag ${tag}"
  if [ "${PUSH_TAG}" = "true" ]; then
    git -C "${PROJECT_ROOT}" push "${GIT_REMOTE}" "${tag}"
    log "INFO" "Pushed tag ${tag} to ${GIT_REMOTE}"
  fi
}

#############################################
# Parse args
#############################################
while [ $# -gt 0 ]; do
  case "$1" in
    --type) shift; RELEASE_TYPE="${1:-}";;
    --push-tag) shift; PUSH_TAG="${1:-false}";;
    --sign) shift; SIGN_ARTIFACTS="${1:-auto}";;
    --sbom) shift; MAKE_SBOM="${1:-auto}";;
    --remote) shift; GIT_REMOTE="${1:-origin}";;
    --tag-prefix) shift; TAG_PREFIX="${1:-v}";;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
  shift || true
done

#############################################
# Preconditions
#############################################
cd "${PROJECT_ROOT}"
mkdir -p "${DIST_DIR}"

require_clean_git

[ -x "$(command -v git)" ] || die "git is required"

#############################################
# Versioning
#############################################
CURRENT_VER="$(get_current_version)"
NEW_VER="$(bump_version "${CURRENT_VER}" "${RELEASE_TYPE:-none}")"

log "INFO" "Current version: ${CURRENT_VER}; bump: ${RELEASE_TYPE:-none}; new: ${NEW_VER}"

if [ "${RELEASE_TYPE:-none}" != "none" ]; then
  write_version "${NEW_VER}"
else
  # Ensure VERSION reflects CURRENT_VER/NEW_VER consistency
  if [ ! -f "${VERSION_FILE}" ]; then
    echo "${NEW_VER}" > "${VERSION_FILE}"
    git add "${VERSION_FILE}"
    git commit -m "chore(release): create VERSION ${NEW_VER}"
  fi
fi

#############################################
# Release Notes
#############################################
LAST_TAG="$(last_tag_or_empty)"
gen_release_notes "${LAST_TAG}" "HEAD"
log "INFO" "Release notes -> ${CHANGELOG_FILE}"

#############################################
# Source Archive (reproducible)
#############################################
ARCHIVE_PATH="$(reproducible_git_archive "${NEW_VER}")"
log "INFO" "Archive -> ${ARCHIVE_PATH}"

#############################################
# Checksums
#############################################
CHECKSUMS_FILE="${DIST_DIR}/${ARCHIVE_PREFIX}-${NEW_VER}-SHA256SUMS.txt"
sha256sum_portable "${ARCHIVE_PATH}" > "${CHECKSUMS_FILE}"
log "INFO" "Checksums -> ${CHECKSUMS_FILE}"

#############################################
# Optional SBOM
#############################################
SBOM_PATH="$(maybe_sbom "${ARCHIVE_PATH}" "${NEW_VER}" || true)"

#############################################
# Sign artifacts (optional)
#############################################
maybe_sign "${ARCHIVE_PATH}"
maybe_sign "${CHECKSUMS_FILE}"
[ -n "${SBOM_PATH:-}" ] && maybe_sign "${SBOM_PATH}"

#############################################
# Tag
#############################################
create_tag "${NEW_VER}"

log "INFO" "Done. Artifacts in: ${DIST_DIR}"
log "INFO" "Files:"
ls -1 "${DIST_DIR}"

exit 0
