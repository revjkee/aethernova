#!/usr/bin/env bash
# Sign/verify release artifacts: checksums + GPG detached signatures (+ optional cosign)
# Platform: Linux/macOS
# License: Apache-2.0

set -Eeuo pipefail

#####################################
# Defaults & ENV
#####################################
ALGO="${ALGO:-sha256}"                 # sha256 | sha512
GPG_KEY="${GPG_KEY:-}"                 # e.g. 0xDEADBEEF or email
GPG_PASSPHRASE="${GPG_PASSPHRASE:-}"   # optional; uses gpg-agent if empty
COSIGN="${COSIGN:-0}"                  # 1 to enable cosign signing
COSIGN_KEY="${COSIGN_KEY:-}"           # path to cosign private key (for sign-blob)
COSIGN_PUB="${COSIGN_PUB:-}"           # path to cosign public key (for verify-blob)
RELEASE="${RELEASE:-}"                 # release id/version string (used in output dir)
OUT_DIR="${OUT_DIR:-}"                 # output dir; default derived from artifacts
DRY_RUN="${DRY_RUN:-0}"                # 1 to print actions only
NO_ARTIFACT_SIGS="${NO_ARTIFACT_SIGS:-0}" # 1 to sign only the manifest, not each artifact
COLOR="${COLOR:-auto}"                 # auto|always|never

#####################################
# Logging
#####################################
is_tty() { [ -t 2 ]; }
use_color() {
  case "$COLOR" in
    always) return 0 ;;
    never)  return 1 ;;
    *) is_tty ;;
  esac
}
if use_color; then
  C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_CYN=$'\033[36m'
else
  C_RESET=""; C_RED=""; C_GRN=""; C_YLW=""; C_CYN=""
fi
log()  { printf '%s[%s]%s %s\n' "$C_CYN" "$(date -u +%FT%TZ)" "$C_RESET" "$*" >&2; }
ok()   { printf '%s[%s]%s %s\n' "$C_GRN" "$(date -u +%FT%TZ)" "$C_RESET" "$*" >&2; }
warn() { printf '%s[%s]%s %s\n' "$C_YLW" "$(date -u +%FT%TZ)" "$C_RESET" "$*" >&2; }
die()  { printf '%s[%s]%s ERROR: %s\n' "$C_RED" "$(date -u +%FT%TZ)" "$C_RESET" "$*" >&2; exit 1; }

#####################################
# Help
#####################################
usage() {
cat >&2 <<'EOF'
Usage:
  scripts/sign_release.sh [sign|verify] [options] -- <artifacts...>

Commands:
  sign      Compute checksums, sign manifest and (optionally) each artifact.
  verify    Verify checksums and signatures for manifest and artifacts.

Options:
  -a, --algo {sha256|sha512}     Hash algorithm (default: sha256)
  -k, --gpg-key KEYID            GPG key id/email to sign with (required for sign)
      --no-artifact-sigs         Do not sign each artifact, only the manifest
      --cosign                   Additionally sign artifacts with cosign sign-blob
  -o, --out-dir DIR              Output directory for signatures (default: alongside artifacts or dist/sign/<release>)
  -r, --release VERSION          Release id/version (used in output dir naming)
      --dry-run                  Print what would be done without changing files
  -h, --help                     Show this help

ENV:
  ALGO, GPG_KEY, GPG_PASSPHRASE, COSIGN (0/1), COSIGN_KEY, COSIGN_PUB, RELEASE, OUT_DIR, DRY_RUN (0/1), NO_ARTIFACT_SIGS (0/1)

Examples:
  # Sign two files with GPG (sha256), write signatures next to files
  GPG_KEY="builder@example.com" scripts/sign_release.sh sign -- file1.tar.gz file2.whl

  # Create versioned output dir, sign manifest and artifacts, plus cosign
  GPG_KEY=0xDEADBEEF COSIGN=1 COSIGN_KEY=cosign.key \
  scripts/sign_release.sh sign -r v1.2.3 -o dist/sign -- file1.tar.gz file2.tgz

  # Verify all signatures and checksums from manifest in output dir
  scripts/sign_release.sh verify -o dist/sign/v1.2.3 -- file1.tar.gz file2.tgz
EOF
}

#####################################
# Utils
#####################################
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

hash_line() {
  # Print "HASH  FILE" in GNU coreutils format for given file and algo
  local algo="$1" f="$2" h=""
  case "$algo" in
    sha256)
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -b -- "$f"
        return
      elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -b -- "$f" | awk '{print $1"  "$2}'
        return
      else
        require_cmd openssl
        h=$(openssl dgst -sha256 -r -- "$f" | awk '{print $1}'); printf '%s  %s\n' "$h" "$f"
        return
      fi
      ;;
    sha512)
      if command -v sha512sum >/dev/null 2>&1; then
        sha512sum -b -- "$f"; return
      elif command -v shasum >/dev/null 2>&1; then
        shasum -a 512 -b -- "$f" | awk '{print $1"  "$2}'; return
      else
        require_cmd openssl
        h=$(openssl dgst -sha512 -r -- "$f" | awk '{print $1}'); printf '%s  %s\n' "$h" "$f"
        return
      fi
      ;;
    *) die "Unsupported algo: $algo" ;;
  esac
}

verify_hashes_from_manifest() {
  # Validate all entries in a manifest file (GNU format)
  local algo="$1" manifest="$2"
  require_cmd awk
  local ok_cnt=0; local bad_cnt=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    local expect file actual
    expect=$(printf '%s\n' "$line" | awk '{print $1}')
    file=$(printf '%s\n' "$line" | awk '{print $2}')
    # Drop leading '*' format if present; normalize double-space
    file="${file#*}"
    if [ ! -f "$file" ]; then warn "Missing file for hash verify: $file"; bad_cnt=$((bad_cnt+1)); continue; fi
    actual=$(hash_line "$algo" "$file" | awk '{print $1}')
    if [ "$expect" = "$actual" ]; then ok_cnt=$((ok_cnt+1)); else
      bad_cnt=$((bad_cnt+1)); warn "Hash mismatch: $file"
    fi
  done < "$manifest"
  [ "$bad_cnt" -eq 0 ] || die "Checksum verification failed: $bad_cnt bad, $ok_cnt ok"
  ok "Checksums verified: $ok_cnt OK"
}

gpg_sign_detached() {
  local key="$1" input="$2" output="${3:-"$2.asc"}"
  require_cmd gpg
  local extra=(--batch --yes --armor --detach-sign)
  if [ -n "${GPG_PASSPHRASE:-}" ]; then
    extra+=(--pinentry-mode loopback --passphrase-fd 0)
    # shellcheck disable=SC2068
    if [ "$DRY_RUN" = "1" ]; then log "[DRY-RUN] gpg -u $key -o $output ${extra[*]} $input <<< '****'"; return; fi
    printf '%s' "$GPG_PASSPHRASE" | gpg -u "$key" -o "$output" "${extra[@]}" -- "$input"
  else
    if [ "$DRY_RUN" = "1" ]; then log "[DRY-RUN] gpg -u $key -o $output ${extra[*]} $input"; return; fi
    gpg -u "$key" -o "$output" "${extra[@]}" -- "$input"
  fi
}

gpg_verify_detached() {
  local input="$1" sig="${2:-"$1.asc"}"
  require_cmd gpg
  gpg --verify -- "$sig" "$input" >/dev/null 2>&1 || die "GPG verify failed for $input"
}

cosign_sign_blob() {
  local input="$1" sig_out="$2" crt_out="$3"
  [ "$COSIGN" = "1" ] || return 0
  require_cmd cosign
  [ -n "$COSIGN_KEY" ] || die "COSIGN_KEY is required when COSIGN=1"
  if [ "$DRY_RUN" = "1" ]; then log "[DRY-RUN] cosign sign-blob --key $COSIGN_KEY --yes --output-signature $sig_out --output-certificate $crt_out $input"; return; fi
  cosign sign-blob --key "$COSIGN_KEY" --yes --output-signature "$sig_out" --output-certificate "$crt_out" -- "$input" >/dev/null
}

cosign_verify_blob() {
  local input="$1" sig="$2" crt="$3"
  [ "$COSIGN" = "1" ] || return 0
  require_cmd cosign
  [ -n "$COSIGN_PUB" ] || die "COSIGN_PUB is required for cosign verify"
  cosign verify-blob --key "$COSIGN_PUB" --signature "$sig" ${crt:+--certificate "$crt"} -- "$input" >/dev/null \
    || die "Cosign verify failed for $input"
}

mk_outdir() {
  local base="$1" rel="$2"
  if [ -n "$OUT_DIR" ]; then
    if [ -n "$rel" ]; then echo "$OUT_DIR/$rel"; else echo "$OUT_DIR"; fi
    return
  fi
  if [ -n "$RELEASE" ]; then
    echo "${base%/}/sign/$RELEASE"
  else
    echo "${base%/}/sign"
  fi
}

#####################################
# Parse args
#####################################
ACTION="sign"
FILES=()

if [ "$#" -eq 0 ]; then usage; exit 2; fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    sign|verify) ACTION="$1"; shift ;;
    -a|--algo) ALGO="${2:?}"; shift 2 ;;
    -k|--gpg-key) GPG_KEY="${2:?}"; shift 2 ;;
    --no-artifact-sigs) NO_ARTIFACT_SIGS=1; shift ;;
    --cosign) COSIGN=1; shift ;;
    -o|--out-dir) OUT_DIR="${2:?}"; shift 2 ;;
    -r|--release) RELEASE="${2:?}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "Unknown option: $1" ;;
    *) FILES+=("$1"); shift ;;
  esac
done
# Remaining positional (after --) go into FILES too
while [ "$#" -gt 0 ]; do FILES+=("$1"); shift; done

[ "${#FILES[@]}" -gt 0 ] || die "No artifacts provided"

case "$ALGO" in sha256|sha512) : ;; *) die "Unsupported algo: $ALGO" ;; esac

#####################################
# Main
#####################################
main_sign() {
  [ -n "$GPG_KEY" ] || die "GPG key is required for sign"
  # Make output dir
  local first_dir
  first_dir=$(dirname -- "${FILES[0]}")
  local outdir
  outdir=$(mk_outdir "$first_dir" "")
  mkdir -p "$outdir"

  # Create manifest in output dir
  local manifest="$outdir/checksums-$ALGO.txt"
  : > "$manifest"
  ok "Manifest: $manifest"

  # Hash artifacts
  for f in "${FILES[@]}"; do
    [ -f "$f" ] || die "Artifact not found: $f"
    # Hash line format: "HASH  FILE"
    hash_line "$ALGO" "$f" >> "$manifest"
  done
  ok "Checksums computed for ${#FILES[@]} file(s)"

  # Sign manifest (always)
  gpg_sign_detached "$GPG_KEY" "$manifest" "$manifest.asc"
  ok "GPG signed manifest: $manifest.asc"

  # Optionally sign each artifact
  if [ "$NO_ARTIFACT_SIGS" != "1" ]; then
    for f in "${FILES[@]}"; do
      gpg_sign_detached "$GPG_KEY" "$f" "$f.asc"
      if [ "$COSIGN" = "1" ]; then
        cosign_sign_blob "$f" "$f.cosign.sig" "$f.cosign.pem"
      fi
    done
    ok "Signed ${#FILES[@]} artifact(s) (GPG${COSIGN:++cosign})"
  else
    warn "Skipping per-artifact signatures (--no-artifact-sigs)"
  fi

  # Embed minimal release metadata (optional)
  local meta="$outdir/release-meta.json"
  {
    printf '{\n'
    printf '  "generated_at_utc": "%s",\n' "$(date -u +%FT%TZ)"
    printf '  "algo": "%s",\n' "$ALGO"
    printf '  "release": "%s",\n' "${RELEASE:-""}"
    printf '  "artifacts": [\n'
    local i=0
    for f in "${FILES[@]}"; do
      i=$((i+1))
      printf '    {"path": "%s"}%s\n' "$f" $([ $i -lt ${#FILES[@]} ] && echo "," || echo "")
    done
    printf '  ]\n}\n'
  } > "$meta"
  ok "Wrote metadata: $meta"
  ok "Done."
}

main_verify() {
  # Determine manifest location
  local first_dir
  first_dir=$(dirname -- "${FILES[0]}")
  local outdir
  outdir=$(mk_outdir "$first_dir" "")
  local manifest="$outdir/checksums-$ALGO.txt"
  [ -f "$manifest" ] || die "Manifest not found: $manifest"

  # Verify manifest signature
  if [ -f "$manifest.asc" ]; then
    gpg_verify_detached "$manifest" "$manifest.asc"
    ok "GPG manifest signature OK"
  else
    warn "Manifest signature not found: $manifest.asc"
  fi

  # Verify checksums
  verify_hashes_from_manifest "$ALGO" "$manifest"

  # Verify artifact signatures (if present)
  local checked=0
  for f in "${FILES[@]}"; do
    [ -f "$f" ] || die "Artifact not found: $f"
    if [ -f "$f.asc" ]; then
      gpg_verify_detached "$f" "$f.asc"
      checked=$((checked+1))
    fi
    if [ "$COSIGN" = "1" ] && [ -f "$f.cosign.sig" ]; then
      cosign_verify_blob "$f" "$f.cosign.sig" "${f}.cosign.pem"
      checked=$((checked+1))
    fi
  done
  ok "Verified signatures: $checked file(s)"
  ok "Done."
}

trap 'die "Interrupted"' INT
trap 'die "Failed (unexpected error)"' ERR

case "$ACTION" in
  sign)   main_sign ;;
  verify) main_verify ;;
  *)      die "Unknown action: $ACTION" ;;
esac
