#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# omnimind-core: Industrial release signing utility
#
# Features:
#  - Strict mode, robust error handling, clear logs with timestamps
#  - Checksums: SHA256/SHA512 (*.sha256, *.sha512)
#  - GPG detached ASCII signatures (*.asc) with configurable GNUPGHOME
#  - Optional Cosign (keyful or keyless OIDC) signatures and attestations
#  - SBOM signing (if SBOM file(s) provided or autodetected)
#  - SLSA predicate attestation support (if provided via --slsa-predicate)
#  - Reproducible, idempotent runs; dry-run support
#  - Verify mode to validate checksums and signatures
#
# Usage:
#   scripts/sign_release.sh check [--dist dist]
#   scripts/sign_release.sh sign  [--dist dist] [--gpg-key KEYID] [--gnupg GNUPGHOME] \
#                                [--cosign] [--keyless] [--cosign-key PATH] \
#                                [--sbom path|auto] [--slsa-predicate path] [--dry-run]
#   scripts/sign_release.sh verify [--dist dist] [--sbom path|auto]
#
# Env:
#   GPG_TTY                 For pinentry in interactive shells (recommended)
#   COSIGN_PASSWORD         Password for cosign key (if --cosign-key used)
#   COSIGN_EXPERIMENTAL=1   For keyless OIDC flows if required
#
# Exit codes:
#   0 on success, non-zero on failure
# ------------------------------------------------------------------------------

set -euo pipefail

# --------------- Logging ----------------
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf "%s [INFO ] %s\n" "$(ts)" "$*" >&2; }
warn(){ printf "%s [WARN ] %s\n" "$(ts)" "$*" >&2; }
err() { printf "%s [ERROR] %s\n" "$(ts)" "$*" >&2; }
die() { err "$*"; exit 1; }

# --------------- Defaults ----------------
DIST_DIR="dist"
GNUPG_DIR=""
GPG_KEY_ID="${GPG_KEY_ID:-}"        # can be overridden via --gpg-key
USE_COSIGN=0
COSIGN_KEY=""
COSIGN_KEYLESS=0
DRY_RUN=0
SBOM_ARG=""
SLSA_PREDICATE=""

# --------------- Helpers -----------------
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] $*"
  else
    eval "$@"
  fi
}

abspath() {
  # Convert path to absolute without python/perl deps
  local p="$1"
  if [[ "$p" = /* ]]; then printf "%s\n" "$p"; else printf "%s/%s\n" "$(pwd)" "$p"; fi
}

list_artifacts() {
  local dir="$1"
  find "$dir" -maxdepth 1 -type f ! -name "*.sha256" ! -name "*.sha512" ! -name "*.asc" \
    ! -name "*.sig" ! -name "*.intoto.jsonl" ! -name "*.att" ! -name "*.att.json" \
    -print | sort
}

detect_sbom() {
  local dir="$1"
  # Autodetect CycloneDX or SPDX SBOMs commonly named
  local candidates
  candidates=$(find "$dir" -maxdepth 1 -type f \( \
      -name "*sbom*.json" -o -name "*sbom*.xml" -o -name "*cyclonedx*.json" \
      -o -name "*spdx*.json" -o -name "*.spdx.json" -o -name "*.cdx.json" \) -print | sort || true)
  printf "%s" "$candidates"
}

sha_file() {
  local file="$1" algo="$2"
  case "$algo" in
    256) echo "${file}.sha256" ;;
    512) echo "${file}.sha512" ;;
    *) die "Unsupported sha algo: $algo" ;;
  esac
}

# --------------- Usage -------------------
usage() {
  sed -n '1,120p' "$0" | sed -n '1,120p' | sed -n '1,120p' >/dev/null 2>&1 || true
  cat <<EOF
Usage:
  $0 check  [--dist DIST]
  $0 sign   [--dist DIST] [--gpg-key KEYID] [--gnupg GNUPGHOME] [--dry-run]
            [--cosign] [--keyless] [--cosign-key PATH]
            [--sbom PATH|auto] [--slsa-predicate PATH]
  $0 verify [--dist DIST] [--sbom PATH|auto]

Options:
  --dist DIR             Directory with artifacts (default: dist)
  --gpg-key KEYID        GPG key ID/email/fingerprint to use
  --gnupg DIR            Custom GNUPGHOME (isolated keyring)
  --cosign               Enable cosign signing of artifacts
  --keyless              Use keyless OIDC with cosign (implies --cosign)
  --cosign-key PATH      Path to cosign private key (PEM); passphrase via COSIGN_PASSWORD
  --sbom PATH|auto       SBOM file(s) to sign (space-separated quoted) or 'auto' to detect
  --slsa-predicate PATH  SLSA predicate JSON to attach as attestation (cosign)
  --dry-run              Print actions without executing
EOF
}

# --------------- Argparse ----------------
ACTION="${1:-}"
shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist) DIST_DIR="${2:?}"; shift 2 ;;
    --gpg-key) GPG_KEY_ID="${2:?}"; shift 2 ;;
    --gnupg) GNUPG_DIR="${2:?}"; shift 2 ;;
    --cosign) USE_COSIGN=1; shift ;;
    --keyless) USE_COSIGN=1; COSIGN_KEYLESS=1; shift ;;
    --cosign-key) USE_COSIGN=1; COSIGN_KEY="${2:?}"; shift 2 ;;
    --sbom) SBOM_ARG="${2:?}"; shift 2 ;;
    --slsa-predicate) SLSA_PREDICATE="${2:?}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ -n "$ACTION" ]] || { usage; exit 1; }

DIST_DIR="$(abspath "$DIST_DIR")"
[[ -d "$DIST_DIR" ]] || die "DIST directory not found: $DIST_DIR"

if [[ -n "$GNUPG_DIR" ]]; then
  export GNUPGHOME="$(abspath "$GNUPG_DIR")"
  mkdir -p "$GNUPGHOME"
fi

# --------------- Preflight checks --------
check_tools() {
  require_cmd shasum || require_cmd sha256sum
  require_cmd gpg
  if [[ "$USE_COSIGN" -eq 1 ]]; then
    require_cmd cosign
  fi
}

check_env() {
  if [[ "$ACTION" = "sign" ]]; then
    [[ -n "$GPG_KEY_ID" ]] || warn "GPG key not specified; gpg may prompt for default key."
    if [[ "$USE_COSIGN" -eq 1 && -n "$COSIGN_KEY" && -z "${COSIGN_PASSWORD:-}" ]]; then
      warn "COSIGN_PASSWORD not set; cosign may prompt for key password."
    fi
    if [[ "$USE_COSIGN" -eq 1 && "$COSIGN_KEYLESS" -eq 1 ]]; then
      export COSIGN_EXPERIMENTAL="${COSIGN_EXPERIMENTAL:-1}"
      log "Cosign keyless mode enabled (OIDC); ensure CI identity/ambient cred is configured."
    fi
  fi
}

# --------------- Checksums ---------------
do_checksums() {
  local file sha256f sha512f
  while IFS= read -r file; do
    [[ -s "$file" ]] || continue
    sha256f="$(sha_file "$file" 256)"
    sha512f="$(sha_file "$file" 512)"

    if command -v sha256sum >/dev/null 2>&1; then
      run "sha256sum  \"$file\" | awk '{print \$1\"  \"$file}' > \"$sha256f\""
      run "sha512sum  \"$file\" | awk '{print \$1\"  \"$file}' > \"$sha512f\""
    else
      run "shasum -a 256 \"$file\" | awk '{print \$1\"  \"$file}' > \"$sha256f\""
      run "shasum -a 512 \"$file\" | awk '{print \$1\"  \"$file}' > \"$sha512f\""
    fi
  done < <(list_artifacts "$DIST_DIR")
}

# --------------- GPG Sign ----------------
do_gpg_sign() {
  local file asc
  while IFS= read -r file; do
    [[ -s "$file" ]] || continue
    asc="${file}.asc"
    local keyopt=""
    [[ -n "$GPG_KEY_ID" ]] && keyopt="--local-user \"$GPG_KEY_ID\""
    run "gpg --batch --yes --armor --detach-sign $keyopt --output \"$asc\" \"$file\""
  done < <(list_artifacts "$DIST_DIR")
}

# --------------- Cosign Sign -------------
do_cosign_sign() {
  [[ "$USE_COSIGN" -eq 1 ]] || return 0
  local file cosign_cmd="cosign sign-blob"
  if [[ -n "$COSIGN_KEY" ]]; then
    cosign_cmd+=" --key \"${COSIGN_KEY}\""
  elif [[ "$COSIGN_KEYLESS" -eq 1 ]]; then
    cosign_cmd+=" --yes"
  fi

  while IFS= read -r file; do
    [[ -s "$file" ]] || continue
    local sig="${file}.sig"
    run "$cosign_cmd --output-signature \"$sig\" \"$file\""
  done < <(list_artifacts "$DIST_DIR")
}

# --------------- SBOM Sign ---------------
do_sbom_sign() {
  local sboms=""
  case "$SBOM_ARG" in
    "" ) return 0 ;;
    auto ) sboms="$(detect_sbom "$DIST_DIR")" ;;
    * ) sboms="$SBOM_ARG" ;;
  esac

  [[ -n "$sboms" ]] || { log "SBOM not found for signing"; return 0; }

  while IFS= read -r sbfile; do
    [[ -s "$sbfile" ]] || continue
    local asc="${sbfile}.asc"
    local keyopt=""
    [[ -n "$GPG_KEY_ID" ]] && keyopt="--local-user \"$GPG_KEY_ID\""
    run "gpg --batch --yes --armor --detach-sign $keyopt --output \"$asc\" \"$sbfile\""
  done < <(printf "%s\n" $sboms)
}

# --------- SLSA / in-toto Attestation ----
do_attestation() {
  [[ "$USE_COSIGN" -eq 1 ]] || return 0
  [[ -n "$SLSA_PREDICATE" ]] || return 0
  [[ -f "$SLSA_PREDICATE" ]] || die "SLSA predicate not found: $SLSA_PREDICATE"

  local file att_cmd="cosign attest-blob --predicate \"${SLSA_PREDICATE}\" --type slsaprovenance"
  if [[ -n "$COSIGN_KEY" ]]; then
    att_cmd+=" --key \"${COSIGN_KEY}\""
  elif [[ "$COSIGN_KEYLESS" -eq 1 ]]; then
    att_cmd+=" --yes"
  fi

  while IFS= read -r file; do
    [[ -s "$file" ]] || continue
    local att="${file}.att"
    run "$att_cmd --outfile \"$att\" \"$file\""
  done < <(list_artifacts "$DIST_DIR")
}

# --------------- Verify ------------------
verify_checksums() {
  local ok=0
  if command -v sha256sum >/dev/null 2>&1; then
    if ! (cd "$DIST_DIR" && run "sha256sum --check --quiet" *.sha256); then ok=1; fi
    if ! (cd "$DIST_DIR" && run "sha512sum --check --quiet" *.sha512); then ok=1; fi
  else
    # shasum fallback
    if ! (cd "$DIST_DIR" && run "shasum -a 256 -c" *.sha256); then ok=1; fi
    if ! (cd "$DIST_DIR" && run "shasum -a 512 -c" *.sha512); then ok=1; fi
  fi
  [[ $ok -eq 0 ]] || die "Checksum verification failed"
}

verify_gpg() {
  local file asc any_fail=0
  while IFS= read -r file; do
    asc="${file}.asc"
    [[ -f "$asc" ]] || continue
    if ! gpg --verify "$asc" "$file" >/dev/null 2>&1; then
      err "GPG verify failed for: $file"
      any_fail=1
    fi
  done < <(list_artifacts "$DIST_DIR")
  [[ $any_fail -eq 0 ]] || die "GPG verification failed"
}

verify_cosign() {
  [[ "$USE_COSIGN" -eq 1 ]] || return 0
  local file any_fail=0
  while IFS= read -r file; do
    local sig="${file}.sig"
    [[ -f "$sig" ]] || continue
    local vcmd="cosign verify-blob --signature \"$sig\" \"$file\""
    if [[ -n "$COSIGN_KEY" ]]; then
      vcmd+=" --key \"${COSIGN_KEY}\""
    fi
    if ! eval "$vcmd" >/dev/null 2>&1; then
      err "Cosign verify failed for: $file"
      any_fail=1
    fi
  done < <(list_artifacts "$DIST_DIR")
  [[ $any_fail -eq 0 ]] || die "Cosign verification failed"
}

# --------------- Actions -----------------
action_check() {
  log "Preflight: checking required tools…"
  check_tools
  log "Environment check…"
  check_env
  log "Artifacts in $DIST_DIR:"
  list_artifacts "$DIST_DIR" | sed 's/^/  - /'
  log "OK"
}

action_sign() {
  check_tools
  check_env

  log "Generating checksums…"
  do_checksums
  log "Checksums done."

  log "Signing all artifacts with GPG…"
  do_gpg_sign
  log "GPG signatures done."

  if [[ "$USE_COSIGN" -eq 1 ]]; then
    log "Signing with Cosign…"
    do_cosign_sign
    log "Cosign signatures done."
  fi

  if [[ -n "$SBOM_ARG" ]]; then
    log "Signing SBOM(s)…"
    do_sbom_sign
    log "SBOM signatures done."
  fi

  if [[ -n "$SLSA_PREDICATE" ]]; then
    log "Creating SLSA attestations with Cosign…"
    do_attestation
    log "Attestations done."
  fi

  log "Signing finished."
}

action_verify() {
  check_tools
  log "Verifying checksums…"
  verify_checksums
  log "Verifying GPG signatures…"
  verify_gpg
  if [[ "$USE_COSIGN" -eq 1 ]]; then
    log "Verifying Cosign signatures…"
    verify_cosign
  fi
  if [[ -n "$SBOM_ARG" && "$SBOM_ARG" = "auto" ]]; then
    local sboms
    sboms="$(detect_sbom "$DIST_DIR")"
    if [[ -n "$sboms" ]]; then
      log "Verifying SBOM GPG signatures…"
      local any_fail=0
      while IFS= read -r sb; do
        [[ -f "${sb}.asc" ]] || continue
        if ! gpg --verify "${sb}.asc" "$sb" >/dev/null 2>&1; then
          err "SBOM verify failed: $sb"
          any_fail=1
        fi
      done < <(printf "%s\n" $sboms)
      [[ $any_fail -eq 0 ]] || die "SBOM verification failed"
    fi
  fi
  log "Verification OK."
}

# --------------- Trap for cleanup --------
cleanup() { :; }
trap cleanup EXIT

# --------------- Dispatch ----------------
case "$ACTION" in
  check)  action_check ;;
  sign)   action_sign ;;
  verify) action_verify ;;
  *) usage; exit 1 ;;
esac
