#!/usr/bin/env bash
# path: veilmind-core/scripts/sign_release.sh
# Industrial release signing tool: checksums (SHA-256/512), GPG detached ASCII signatures,
# optional cosign image signing and attestations. Linux/macOS compatible.
# Usage examples:
#   ./scripts/sign_release.sh sign --artifacts "dist/*.whl dist/*.tar.gz sbom/sbom.json" --key-id ABCDEF123456
#   ./scripts/sign_release.sh verify --checksums release-signing/CHECKSUMS-sha256.txt --sig release-signing/CHECKSUMS-sha256.txt.asc
#   COSIGN_EXPERIMENTAL=1 ./scripts/sign_release.sh sign --cosign-ref ghcr.io/org/veilmind-core:1.2.3

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

# ------------------------------- color/logging -------------------------------
Y=$'\033[33m'; G=$'\033[32m'; R=$'\033[31m'; B=$'\033[34m'; RS=$'\033[0m'
log()   { echo "${B}[sign]${RS} $*"; }
warn()  { echo "${Y}[warn]${RS} $*" >&2; }
err()   { echo "${R}[error]${RS} $*" >&2; exit 1; }

# ------------------------------- defaults -----------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${PROJECT_ROOT}/release-signing"
ALGO="sha256"             # or sha512
ARMOR=1                   # ASCII armor for GPG
SIGN_EACH=1               # sign each artifact in addition to CHECKSUMS
GPG_PROGRAM="${GPG_PROGRAM:-gpg}"
GPG_KEY_ID="${GPG_KEY_ID:-}"
COSIGN_REF="${COSIGN_REF:-}"
COSIGN_KEY="${COSIGN_KEY:-}"   # optional: path to cosign.key (if not keyless)
COSIGN_FLAGS=("--yes")
ARTIFACT_PATTERNS=()
CHECKSUMS_FILE=""
CHECKSUMS_SIG=""
MODE="sign"
VERIFY_SIG=""
PACKAGE_FILTER=""         # reserved for future

# ------------------------------- helpers ------------------------------------
die_dep() {
  command -v "$1" >/dev/null 2>&1 || err "Required dependency not found: $1"
}

checksum_tool() {
  # returns command to compute sum for a single file on current platform
  case "$ALGO" in
    sha256)
      if command -v sha256sum >/dev/null 2>&1; then echo "sha256sum"; return; fi
      if command -v shasum >/dev/null 2>&1; then echo "shasum -a 256"; return; fi
      ;;
    sha512)
      if command -v sha512sum >/dev/null 2>&1; then echo "sha512sum"; return; fi
      if command -v shasum >/dev/null 2>&1; then echo "shasum -a 512"; return; fi
      ;;
    *) err "Unsupported ALGO: $ALGO";;
  esac
  err "No checksum tool found for $ALGO (need sha256sum/sha512sum or shasum)."
}

checksum_check_cmd() {
  # returns command prefix to verify sums with -c alike
  case "$ALGO" in
    sha256)
      if command -v sha256sum >/dev/null 2>&1; then echo "sha256sum -c"; return; fi
      if command -v shasum    >/dev/null 2>&1; then echo "shasum -a 256 -c"; return; fi
      ;;
    sha512)
      if command -v sha512sum >/dev/null 2>&1; then echo "sha512sum -c"; return; fi
      if command -v shasum    >/dev/null 2>&1; then echo "shasum -a 512 -c"; return; fi
      ;;
  esac
  err "No checksum verification tool found."
}

relpath() {
  python3 - "$PROJECT_ROOT" "$1" <<'PY'
import os,sys
root, p = sys.argv[1], sys.argv[2]
print(os.path.relpath(os.path.realpath(p), root))
PY
}

_array_from_patterns() {
  local -a acc=()
  shopt -s nullglob globstar
  for pat in "$@"; do
    for f in $pat; do
      [[ -f "$f" ]] && acc+=("$f")
    done
  done
  shopt -u nullglob globstar
  printf '%s\0' "${acc[@]:-}"
}

gpg_args_base() {
  local -a a=("--batch" "--yes")
  [[ -n "$GPG_KEY_ID" ]] && a+=("--local-user" "$GPG_KEY_ID")
  [[ "${ARMOR}" == "1" ]] && a+=("--armor")
  printf '%s\n' "${a[@]}"
}

gpg_check_key() {
  $GPG_PROGRAM --batch --yes --list-keys "${GPG_KEY_ID}" >/dev/null 2>&1 || err "GPG key not found: ${GPG_KEY_ID}"
}

# ------------------------------ usage/help -----------------------------------
usage() {
  cat <<EOF
Usage:
  $0 sign   --artifacts "dist/*.whl dist/*.tar.gz sbom/*.json" [--out DIR] [--algo sha256|sha512] [--key-id KEYID] [--armor 0|1] [--no-sign-each] [--cosign-ref IMAGE[:TAG]] [--cosign-key PATH]
  $0 verify --checksums PATH [--sig PATH] [--algo sha256|sha512]

Environment:
  GPG_PROGRAM, GPG_KEY_ID, COSIGN_REF, COSIGN_KEY

Notes:
  - CHECKSUMS file is canonical and signed; individual files can also be signed (default on).
  - On macOS, uses shasum; on Linux prefers sha256sum/sha512sum.
EOF
}

# ------------------------------ arg parsing ----------------------------------
[[ $# -eq 0 ]] && { usage; exit 1; }
MODE="$1"; shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts)            shift; ARTIFACT_PATTERNS+=($1);;
    --out)                  shift; OUT_DIR="$1";;
    --algo)                 shift; ALGO="$1";;
    --key-id)               shift; GPG_KEY_ID="$1";;
    --gpg-program)          shift; GPG_PROGRAM="$1";;
    --armor)                shift; ARMOR="$1";;
    --no-sign-each)         SIGN_EACH=0;;
    --cosign-ref)           shift; COSIGN_REF="$1";;
    --cosign-key)           shift; COSIGN_KEY="$1";;
    --checksums)            shift; CHECKSUMS_FILE="$1";;
    --sig|--signature)      shift; VERIFY_SIG="$1";;
    -h|--help)              usage; exit 0;;
    *)                      ARTIFACT_PATTERNS+=("$1");;
  esac
  shift || true
done

mkdir -p "$OUT_DIR"

# ------------------------------- operations ----------------------------------
compute_checksums() {
  local -a files=()
  mapfile -d '' -t files < <(_array_from_patterns "${ARTIFACT_PATTERNS[@]}")
  [[ ${#files[@]} -gt 0 ]] || err "No artifacts matched: ${ARTIFACT_PATTERNS[*]:-<empty>}"

  local TOOL; TOOL="$(checksum_tool)"
  local out="${OUT_DIR}/CHECKSUMS-${ALGO}.txt"
  CHECKSUMS_FILE="$out"
  log "Computing ${ALGO} for ${#files[@]} file(s) → $(relpath "$out")"

  : > "$out.tmp"
  # Canonical format: "<sum><2 spaces><relative path>"
  for f in "${files[@]}"; do
    local rp; rp="$(relpath "$f")"
    # shellcheck disable=SC2086
    local sum; sum="$($TOOL "$f" | awk '{print $1}')"
    [[ -n "$sum" ]] || err "Failed to compute $ALGO for $f"
    printf "%s  %s\n" "$sum" "$rp" >> "$out.tmp"
  done

  LC_ALL=C sort -o "$out" "$out.tmp"
  rm -f "$out.tmp"
  log "Checksums written: $out"
}

sign_file_gpg() {
  local target="$1"
  local sig="${target}.asc"
  [[ "${ARMOR}" == "1" ]] || sig="${target}.sig"
  local -a base; mapfile -t base < <(gpg_args_base)
  log "GPG sign: $(relpath "$target") → $(relpath "$sig")"
  "$GPG_PROGRAM" "${base[@]}" --detach-sign --output "$sig" -- "$target"
  echo "$sig"
}

sign_artifacts_gpg() {
  gpg_check_key
  if [[ "$SIGN_EACH" == "1" ]]; then
    local -a files=()
    mapfile -d '' -t files < <(_array_from_patterns "${ARTIFACT_PATTERNS[@]}")
    for f in "${files[@]}"; do sign_file_gpg "$f" >/dev/null; done
  fi
  CHECKSUMS_SIG="$(sign_file_gpg "$CHECKSUMS_FILE")"
}

cosign_sign_if_requested() {
  [[ -n "$COSIGN_REF" ]] || return 0
  command -v cosign >/dev/null 2>&1 || err "cosign not found in PATH"
  log "Cosign sign image: ${COSIGN_REF}"
  local -a cargs=("${COSIGN_FLAGS[@]}")
  if [[ -n "$COSIGN_KEY" ]]; then
    cargs+=("--key" "$COSIGN_KEY")
  fi
  cosign sign "${cargs[@]}" "$COSIGN_REF"
  # Attach attestation with the checksums as predicate (generic type)
  if [[ -f "$CHECKSUMS_FILE" ]]; then
    log "Cosign attest (predicate: CHECKSUMS)"
    cosign attest "${cargs[@]}" \
      --predicate "$CHECKSUMS_FILE" \
      --type "https://cosign.sigstore.dev/checksums/v2" \
      "$COSIGN_REF"
  fi
}

verify_checksums() {
  [[ -n "$CHECKSUMS_FILE" ]] || err "--checksums path is required"
  [[ -f "$CHECKSUMS_FILE" ]] || err "Checksums file not found: $CHECKSUMS_FILE"
  local CMD; CMD="$(checksum_check_cmd)"
  log "Verifying checksums via: $CMD"
  # tool's -c expects current working directory relative to file entries
  ( cd "$PROJECT_ROOT" && $CMD "$CHECKSUMS_FILE" )
  log "Checksums OK"
}

verify_signature() {
  [[ -n "$VERIFY_SIG" ]] || return 0
  [[ -f "$VERIFY_SIG" ]] || err "Signature not found: $VERIFY_SIG"
  log "Verifying GPG signature: $(relpath "$VERIFY_SIG")"
  "$GPG_PROGRAM" --verify "$VERIFY_SIG" >/dev/null 2>&1 || err "GPG signature invalid"
  log "GPG signature OK"
}

summary() {
  echo
  echo "${G}=== SIGNING SUMMARY ===${RS}"
  echo "Project root : $PROJECT_ROOT"
  echo "Output dir   : $OUT_DIR"
  echo "Algorithm    : $ALGO"
  [[ -n "$GPG_KEY_ID"    ]] && echo "GPG key      : $GPG_KEY_ID"
  [[ -n "$CHECKSUMS_FILE" ]] && echo "CHECKSUMS    : $(relpath "$CHECKSUMS_FILE")"
  [[ -n "$CHECKSUMS_SIG"  ]] && echo "CHECKSUMS sig: $(relpath "$CHECKSUMS_SIG")"
  [[ -n "$COSIGN_REF"     ]] && echo "Cosign ref   : $COSIGN_REF"
}

# ------------------------------- main flow -----------------------------------
trap 'err "Interrupted."' INT TERM

case "$MODE" in
  sign)
    [[ -n "${ARTIFACT_PATTERNS[*]:-}" ]] || err "Provide --artifacts patterns or paths"
    [[ -n "$GPG_KEY_ID" ]] || warn "No --key-id provided; will rely on gpg default keyring selection"
    die_dep "$GPG_PROGRAM"
    die_dep awk
    compute_checksums
    sign_artifacts_gpg
    cosign_sign_if_requested
    summary
    ;;
  verify)
    # Verification does not require the key id; uses embedded signer from sig
    die_dep awk
    verify_checksums
    verify_signature
    ;;
  *)
    usage; exit 1;;
esac
