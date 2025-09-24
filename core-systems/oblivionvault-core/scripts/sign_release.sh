#!/usr/bin/env bash
# oblivionvault-core/scripts/sign_release.sh
# Industrial-grade release signer: checksums, GPG/minisign/cosign signatures, manifest, verify mode.
# Usage:
#   ./scripts/sign_release.sh sign   -i ./dist -o ./signout -k <GPG_KEYID> [--cosign-key cosign.key] [--minisign-key minisign.key] [--tsa-url URL] [--provenance]
#   ./scripts/sign_release.sh verify -i ./dist -o ./signout
#
# Notes:
# - Requires: bash >= 4, coreutils, gpg, awk, sed. Optional: minisign, cosign, openssl (for RFC3161).
# - On macOS uses 'shasum -a 256/512' if sha256sum/sha512sum absent.
# - GPG works with gpg-agent/YubiKey; no секреты в логах. Detatched ASCII armor .asc.
# - Manifest and checksums are deterministic: LC_ALL=C, sorted.

set -euo pipefail

VERSION="1.2.0"
umask 077
LC_ALL=C
export LC_ALL

# ----------------------------- logging ----------------------------------------
log()  { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
warn() { log "WARN: $*"; }
info() { log "INFO: $*"; }

# ----------------------------- defaults ---------------------------------------
CMD="${1:-}"
shift || true

INPUT_DIR=""
OUT_DIR=""
GPG_KEYID=""
COSIGN_KEY=""
MINISIGN_KEY=""
TSA_URL=""
DO_PROVENANCE=0
SKIP_GPG=0
SKIP_MINISIGN=0
SKIP_COSIGN=0
DRY_RUN=0
VERIFY_MODE=0

# ----------------------------- helpers ----------------------------------------
sha256_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then echo "sha256sum"; return; fi
  if command -v gsha256sum >/dev/null 2>&1; then echo "gsha256sum"; return; fi
  if command -v shasum >/dev/null 2>&1; then echo "shasum -a 256"; return; fi
  die "No sha256 implementation found (sha256sum/gsha256sum/shasum)."
}
sha512_cmd() {
  if command -v sha512sum >/dev/null 2>&1; then echo "sha512sum"; return; fi
  if command -v gsha512sum >/dev/null 2>&1; then echo "gsha512sum"; return; fi
  if command -v shasum >/dev/null 2>&1; then echo "shasum -a 512"; return; fi
  die "No sha512 implementation found (sha512sum/gsha512sum/shasum)."
}

json_escape() {
  # Escape for JSON string (no external jq dependency).
  local s; s="$1"
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}
  printf '%s' "$s"
}

check_regular_file() {
  local p="$1"
  [ -f "$p" ] || die "Not a regular file: $p"
  case "$p" in
    */..|*/../*|../*|*/./*|*/.|./* ) die "Path traversal detected: $p";;
  esac
}

make_outdir() { mkdir -p "$OUT_DIR"; }

ts_cleanup() { :
  # reserved for future temp artifacts cleanup
}
trap ts_cleanup EXIT INT TERM

# ----------------------------- args -------------------------------------------
print_help() {
cat <<EOF
sign_release.sh v${VERSION}

USAGE:
  sign   -i DIR -o DIR -k GPG_KEYID [--cosign-key PATH] [--minisign-key PATH] [--tsa-url URL] [--provenance] [--dry-run] [--no-gpg] [--no-minisign] [--no-cosign]
  verify -i DIR -o DIR

OPTIONS:
  -i, --input DIR          Directory with artifacts to sign (files only, recursive disabled).
  -o, --out DIR            Output directory for signatures & manifests.
  -k, --gpg-key KEYID      GPG key id/fingerprint/email to sign with (detached .asc).
      --cosign-key PATH    cosign private key (optional). If not set, cosign is skipped or uses keyless if configured.
      --minisign-key PATH  minisign secret key (optional).
      --tsa-url URL        RFC3161 TSA endpoint (optional, requires openssl). Attaches .tsr to checksum files.
      --provenance         Generate provenance.json (git/tag/env).
      --dry-run            Do not write any files, print planned actions.
      --no-gpg             Skip GPG signing.
      --no-minisign        Skip minisign signing.
      --no-cosign          Skip cosign signing.

MODES:
  sign     Generate CHECKSUMS, signatures, manifest.
  verify   Verify CHECKSUMS and signatures in OUT DIR against INPUT DIR.

Exit codes: 0 ok, 1 error, 2 verify failed.
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -i|--input) INPUT_DIR="${2:-}"; shift 2;;
      -o|--out) OUT_DIR="${2:-}"; shift 2;;
      -k|--gpg-key) GPG_KEYID="${2:-}"; shift 2;;
      --cosign-key) COSIGN_KEY="${2:-}"; shift 2;;
      --minisign-key) MINISIGN_KEY="${2:-}"; shift 2;;
      --tsa-url) TSA_URL="${2:-}"; shift 2;;
      --provenance) DO_PROVENANCE=1; shift;;
      --dry-run) DRY_RUN=1; shift;;
      --no-gpg) SKIP_GPG=1; shift;;
      --no-minisign) SKIP_MINISIGN=1; shift;;
      --no-cosign) SKIP_COSIGN=1; shift;;
      -h|--help) print_help; exit 0;;
      *) die "Unknown option: $1";;
    esac
  done
  [ -n "$INPUT_DIR" ] || die "--input is required"
  [ -d "$INPUT_DIR" ]  || die "Input dir not found: $INPUT_DIR"
  [ -n "$OUT_DIR" ]    || die "--out is required"
  [ "$CMD" = "sign" ] && [ $SKIP_GPG -eq 0 ] && [ -z "$GPG_KEYID" ] && warn "GPG key not specified: will try default key"
}

require_bin() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

# ----------------------------- signing ----------------------------------------
gpg_sign() {
  local file="$1"
  [ $SKIP_GPG -eq 1 ] && { info "GPG skipped for $file"; return; }
  require_bin gpg
  local asc="$OUT_DIR/$(basename "$file").asc"
  [ $DRY_RUN -eq 1 ] && { info "[dry-run] gpg --detach-sign --armor -u ${GPG_KEYID:-<default>} $file -> $asc"; return; }
  gpg --batch --yes --armor --detach-sign ${GPG_KEYID:+-u "$GPG_KEYID"} --output "$asc" "$file"
}

minisign_sign() {
  local file="$1"
  [ $SKIP_MINISIGN -eq 1 ] && { info "minisign skipped for $file"; return; }
  command -v minisign >/dev/null 2>&1 || { warn "minisign not found; skipping"; return; }
  if [ -z "$MINISIGN_KEY" ]; then warn "minisign key not provided; skipping"; return; fi
  local sig="$OUT_DIR/$(basename "$file").minisig"
  [ $DRY_RUN -eq 1 ] && { info "[dry-run] minisign -Sm -s <hidden> -m $file -x $sig"; return; }
  minisign -Sm -s "$MINISIGN_KEY" -m "$file" -x "$sig"
}

cosign_sign() {
  local file="$1"
  [ $SKIP_COSIGN -eq 1 ] && { info "cosign skipped for $file"; return; }
  command -v cosign >/dev/null 2>&1 || { warn "cosign not found; skipping"; return; }
  # cosign stores signatures externally; here we write a local .cosign.sig via 'blob sign'
  local sig="$OUT_DIR/$(basename "$file").cosign.sig"
  local kopt=()
  [ -n "$COSIGN_KEY" ] && kopt=( "--key" "$COSIGN_KEY" )
  [ $DRY_RUN -eq 1 ] && { info "[dry-run] cosign sign-blob ${kopt[*]:-} --output-signature $sig $file"; return; }
  COSIGN_EXPERIMENTAL=1 cosign sign-blob "${kopt[@]}" --output-signature "$sig" "$file" >/dev/null
}

tsa_timestamp() {
  local file="$1"
  [ -z "$TSA_URL" ] && return 0
  command -v openssl >/dev/null 2>&1 || { warn "openssl not found; skipping TSA"; return; }
  local tsr="$OUT_DIR/$(basename "$file").tsr"
  [ $DRY_RUN -eq 1 ] && { info "[dry-run] openssl ts -query -data $file | curl $TSA_URL -> $tsr"; return; }
  local tsq tmp
  tsq="$(mktemp)"
  tmp="$(mktemp)"
  openssl ts -query -data "$file" -sha256 -no_nonce -out "$tsq"
  if command -v curl >/dev/null 2>&1; then
    curl -sS -H "Content-Type: application/timestamp-query" --data-binary @"$tsq" "$TSA_URL" -o "$tmp"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --header="Content-Type: application/timestamp-query" --post-file="$tsq" -O "$tmp" "$TSA_URL"
  else
    warn "No curl/wget for TSA"; rm -f "$tsq" "$tmp"; return
  fi
  openssl ts -reply -in "$tmp" -token_out -out "$tsr" || warn "TSA reply validation failed for $file"
  rm -f "$tsq" "$tmp"
}

# ----------------------------- checksums --------------------------------------
generate_checksums() {
  local sha256="$(sha256_cmd)"
  local sha512="$(sha512_cmd)"
  local out256="$OUT_DIR/CHECKSUMS.sha256"
  local out512="$OUT_DIR/CHECKSUMS.sha512"
  [ $DRY_RUN -eq 1 ] && { info "[dry-run] generating $out256 and $out512"; return; }

  : >"$out256"
  : >"$out512"
  # list files (non-recursive), skip dotfiles in OUT_DIR
  local f
  while IFS= read -r -d '' f; do
    check_regular_file "$f"
    (cd "$INPUT_DIR" && $sha256 "$(basename "$f")") >>"$out256"
    (cd "$INPUT_DIR" && $sha512 "$(basename "$f")") >>"$out512"
  done < <(find "$INPUT_DIR" -maxdepth 1 -type f -print0 | LC_ALL=C sort -z)

  # Normalize format for shasum outputs to 'HASH  FILENAME'
  sed -Ei.bak 's/\s+\*/  /g' "$out256" "$out512" 2>/dev/null || true
  rm -f "$out256".bak "$out512".bak

  # RFC3161 timestamp for checksum files if configured
  tsa_timestamp "$out256"
  tsa_timestamp "$out512"
}

verify_checksums() {
  local sha256="$(sha256_cmd)"
  local sha512="$(sha512_cmd)"
  local out256="$OUT_DIR/CHECKSUMS.sha256"
  local out512="$OUT_DIR/CHECKSUMS.sha512"
  [ -f "$out256" ] || die "Missing $out256"
  [ -f "$out512" ] || die "Missing $out512"

  info "Verifying SHA256"
  (cd "$INPUT_DIR" && $sha256 -c <(sed 's/  */  /' "$out256") ) || return 2
  info "Verifying SHA512"
  (cd "$INPUT_DIR" && $sha512 -c <(sed 's/  */  /' "$out512") ) || return 2
  return 0
}

# ----------------------------- manifest ---------------------------------------
generate_manifest() {
  local manifest="$OUT_DIR/RELEASE_MANIFEST.json"
  [ $DRY_RUN -eq 1 ] && { info "[dry-run] write $manifest"; return; }
  local arr="[" first=1
  local f
  while IFS= read -r -d '' f; do
    check_regular_file "$f"
    local bn="$(basename "$f")"
    local size
    size="$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f")"
    local h256 h512
    h256="$((sha256_cmd))"
    h512="$((sha512_cmd))"
    h256="$($h256 "$f" | awk '{print $1}')"
    h512="$($h512 "$f" | awk '{print $1}')"

    local entry="{\"name\":\"$(json_escape "$bn")\",\"size\":$size,\"sha256\":\"$h256\",\"sha512\":\"$h512\""
    # Attach signature file names if exist
    for ext in asc minisig cosign.sig tsr; do
      local sigp="$OUT_DIR/$bn.$ext"
      [ -f "$sigp" ] && entry="$entry,\"$ext\":\"$(json_escape "$bn.$ext")\""
    done
    entry="$entry}"
    if [ $first -eq 1 ]; then arr="$arr$entry"; first=0; else arr="$arr,$entry"; fi
  done < <(find "$INPUT_DIR" -maxdepth 1 -type f -print0 | LC_ALL=C sort -z)

  # attach checksum objects
  local chk256="$OUT_DIR/CHECKSUMS.sha256"
  local chk512="$OUT_DIR/CHECKSUMS.sha512"
  [ -f "$chk256" ] && arr="$arr,{\"name\":\"CHECKSUMS.sha256\",\"size\":$((stat -c '%s' "$chk256" 2>/dev/null || stat -f '%z' "$chk256"))}"
  [ -f "$chk512" ] && arr="$arr,{\"name\":\"CHECKSUMS.sha512\",\"size\":$((stat -c '%s' "$chk512" 2>/dev/null || stat -f '%z' "$chk512"))}"
  arr="$arr]"

  # Top-level manifest
  local git_rev git_tag builder host
  git_rev="$(git rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")"
  git_tag="$(git describe --tags --exact-match 2>/dev/null || echo "")"
  builder="$(whoami 2>/dev/null || echo "")"
  host="$(hostname 2>/dev/null || echo "")"

  cat >"$manifest" <<JSON
{
  "tool": "sign_release.sh",
  "version": "${VERSION}",
  "created_utc": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "input_dir": "$(json_escape "$INPUT_DIR")",
  "git": {"rev": "$(json_escape "$git_rev")", "tag": "$(json_escape "$git_tag")"},
  "builder": {"user": "$(json_escape "$builder")", "host": "$(json_escape "$host")"},
  "artifacts": $arr
}
JSON
}

generate_provenance() {
  [ $DO_PROVENANCE -eq 1 ] || return 0
  local prov="$OUT_DIR/provenance.json"
  [ $DRY_RUN -eq 1 ] && { info "[dry-run] write $prov"; return; }
  local rev tag remote osname kernel
  rev="$(git rev-parse HEAD 2>/dev/null || echo "")"
  tag="$(git describe --tags --always 2>/dev/null || echo "")"
  remote="$(git config --get remote.origin.url 2>/dev/null || echo "")"
  osname="$(uname -s 2>/dev/null || echo "")"
  kernel="$(uname -r 2>/dev/null || echo "")"
  cat >"$prov" <<JSON
{
  "type": "https://slsa.dev/provenance/v0.2-compat",
  "builder": {"id": "oblivionvault-core/sign_release.sh"},
  "invocation": {
    "parameters": {"input_dir": "$(json_escape "$INPUT_DIR")"},
    "environment": {"os": "$(json_escape "$osname")", "kernel": "$(json_escape "$kernel")"}
  },
  "vcs": {"revision": "$(json_escape "$rev")", "tag": "$(json_escape "$tag")", "remote": "$(json_escape "$remote")"},
  "materials": []
}
JSON
}

# ----------------------------- main ops ---------------------------------------
run_sign() {
  make_outdir
  info "Signing release: input=$INPUT_DIR out=$OUT_DIR"
  # Generate checksums first
  generate_checksums

  # Sign checksum files (preferred trust root)
  gpg_sign "$OUT_DIR/CHECKSUMS.sha256" || true
  gpg_sign "$OUT_DIR/CHECKSUMS.sha512" || true
  minisign_sign "$OUT_DIR/CHECKSUMS.sha256" || true
  minisign_sign "$OUT_DIR/CHECKSUMS.sha512" || true
  cosign_sign "$OUT_DIR/CHECKSUMS.sha256" || true
  cosign_sign "$OUT_DIR/CHECKSUMS.sha512" || true

  # Sign each artifact
  local f
  while IFS= read -r -d '' f; do
    check_regular_file "$f"
    gpg_sign "$f" || true
    minisign_sign "$f" || true
    cosign_sign "$f" || true
  done < <(find "$INPUT_DIR" -maxdepth 1 -type f -print0 | LC_ALL=C sort -z)

  # Manifest & provenance
  generate_manifest
  generate_provenance

  info "Done."
}

run_verify() {
  info "Verifying release: input=$INPUT_DIR out=$OUT_DIR"
  verify_checksums || { warn "Checksum verification failed"; exit 2; }

  # Verify signatures if present
  local rc=0
  if command -v gpg >/dev/null 2>&1; then
    for f in "$OUT_DIR"/CHECKSUMS.sha{256,512}.asc; do
      [ -f "$f" ] || continue
      info "Verifying GPG: $f"
      if ! gpg --batch --verify "$f" >/dev/null 2>&1; then warn "GPG verify failed for $f"; rc=2; fi
    done
  fi
  if command -v minisign >/dev/null 2>&1; then
    for f in "$OUT_DIR"/CHECKSUMS.sha{256,512}; do
      [ -f "$f".minisig ] || continue
      info "Verifying minisign: $f.minisig"
      if ! minisign -Vm "$f" -x "$f.minisig" >/dev/null 2>&1; then warn "minisign verify failed for $f"; rc=2; fi
    done
  fi
  if command -v cosign >/div/null 2>&1; then
    : # cosign verify-blob requires pubkey; left to CI where policy is known.
  fi

  [ $rc -eq 0 ] && info "Verify OK" || warn "Verify completed with errors"
  exit $rc
}

# ----------------------------- dispatch ---------------------------------------
case "$CMD" in
  sign)
    parse_args "$@"
    run_sign
    ;;
  verify)
    VERIFY_MODE=1
    parse_args "$@"
    run_verify
    ;;
  ""|-h|--help)
    print_help
    ;;
  *)
    die "Unknown command: $CMD. Use sign|verify."
    ;;
esac
