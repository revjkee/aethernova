#!/usr/bin/env bash
# Chronowatch Core — Industrial release signing utility
#
# Features:
#  - GPG detached ASCII signatures (*.asc) for each artifact
#  - SHA256/512 per-file hashes (*.sha256, *.sha512) + aggregated CHECKSUMS files
#  - Optional signing of aggregated CHECKSUMS with GPG
#  - Verification of signatures and hash files after creation
#  - Optional minisign and cosign sign-blob if available
#  - CI-friendly: non-interactive, batch mode, predictable outputs
#  - Dry-run and verbose modes; safe bash settings; colored logs
#  - Parallel processing (-j) with bounded jobs
#
# Requirements:
#  - bash, gpg, coreutils (sha256sum, sha512sum), find, xargs
# Optional:
#  - minisign, cosign, syft (for SBOM hints; generation not enforced)
#
# Usage:
#  scripts/sign_release.sh [options] [FILE ...]
#
# Common options:
#  --in DIR                 Directory to scan for artifacts (default: none)
#  --pattern GLOB           Glob for artifacts under --in (e.g. "*.tar.gz")
#  --out DIR                Output directory for aggregate files (default: same as files or ./release-signing)
#  --gpg-key KEYID          GPG key ID/email/fingerprint (env: GPG_KEY_ID)
#  --armor / --no-armor     Create ASCII-armored .asc (default: --armor)
#  --hash sha256,sha512     Which hashes to compute (default: sha256,sha512)
#  --sign-checksums         Also GPG-sign aggregated CHECKSUMS files
#  --cosign MODE            cosign sign-blob mode: keyless|kms|key:<path> (optional)
#  --minisign KEY           minisign secret key file path (optional)
#  -j N                     Parallel jobs for per-file work (default: 1)
#  --dry-run                Plan only, no changes
#  --verify-only            Verify existing signatures and hashes, do not create
#  --force                  Overwrite existing outputs
#  --verbose                Verbose output
#  --help                   Print help
#
# Examples:
#  scripts/sign_release.sh --in dist --pattern "*.tar.gz" --gpg-key ABCDEF123456
#  scripts/sign_release.sh build/app.zip --gpg-key release@chronowatch.io --sign-checksums
#  scripts/sign_release.sh --in out --pattern "*" --cosign keyless --minisign ~/.keys/minisign.key

set -Eeuo pipefail
IFS=$'\n\t'

VERSION="1.1.0"
SELF="$(basename "$0")"

# Colors (disable if not TTY)
if [[ -t 1 ]]; then
  C_BOLD="$(printf '\033[1m')"
  C_DIM="$(printf '\033[2m')"
  C_RED="$(printf '\033[31m')"
  C_GRN="$(printf '\033[32m')"
  C_YLW="$(printf '\033[33m')"
  C_BLU="$(printf '\033[34m')"
  C_RST="$(printf '\033[0m')"
else
  C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_RST=""
fi

log()  { printf "%s[%s]%s %s\n" "$C_DIM" "$SELF" "$C_RST" "$*"; }
info() { printf "%s[%s]%s %s\n" "$C_BLU" "$SELF" "$C_RST" "$*"; }
ok()   { printf "%s[%s]%s %s\n" "$C_GRN" "$SELF" "$C_RST" "$*"; }
warn() { printf "%s[%s]%s %s\n" "$C_YLW" "$SELF" "$C_RST" "$*"; }
err()  { printf "%s[%s]%s %s\n" "$C_RED" "$SELF" "$C_RST" "$*" 1>&2; }

die() { err "$*"; exit 1; }

cleanup() {
  # Reserved for future temp cleanup
  :
}
trap cleanup EXIT

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "Missing required command: $c"
  done
}

# Defaults
IN_DIR=""
OUT_DIR=""
PATTERN=""
GPG_KEY_ID="${GPG_KEY_ID:-}"
ARMOR=1
HASH_ALGOS="sha256,sha512"
SIGN_CHECKSUMS=0
COSIGN_MODE=""
MINISIGN_KEY=""
PARALLEL_JOBS=1
DRY_RUN=0
VERIFY_ONLY=0
FORCE=0
VERBOSE=0

usage() {
  cat <<EOF
$SELF v$VERSION — industrial release signing

Usage:
  $SELF [options] [FILE ...]

Options:
  --in DIR                 Scan directory for artifacts
  --pattern GLOB           Glob relative to --in (e.g. "*.tar.gz")
  --out DIR                Output directory for aggregates (default: next to files or ./release-signing)
  --gpg-key KEYID          GPG key id/email/fpr (env: GPG_KEY_ID)
  --armor | --no-armor     Use ASCII armored signatures (default: --armor)
  --hash LIST              Comma-separated: sha256,sha512 (default)
  --sign-checksums         GPG-sign aggregated CHECKSUMS files
  --cosign MODE            cosign sign-blob: keyless|kms|key:<path> (optional)
  --minisign KEYFILE      minisign secret key file path (optional)
  -j N                     Parallel jobs (default: 1)
  --dry-run                Do not modify filesystem
  --verify-only            Only verify existing signatures and hashes
  --force                  Overwrite existing outputs
  --verbose                More logs
  --help                   Show this help

Examples:
  $SELF --in dist --pattern "*.tar.gz" --gpg-key ABCD1234 --sign-checksums
  $SELF artifact.zip --gpg-key release@chronowatch.io
EOF
}

contains_algo() {
  local list="$1" needle="$2"
  [[ ",$list," == *",$needle,"* ]]
}

parse_args() {
  local arg
  while [[ $# -gt 0 ]]; do
    arg="$1"; shift
    case "$arg" in
      --in) IN_DIR="${1:-}"; shift ;;
      --pattern) PATTERN="${1:-}"; shift ;;
      --out) OUT_DIR="${1:-}"; shift ;;
      --gpg-key) GPG_KEY_ID="${1:-}"; shift ;;
      --armor) ARMOR=1 ;;
      --no-armor) ARMOR=0 ;;
      --hash) HASH_ALGOS="${1:-}"; shift ;;
      --sign-checksums) SIGN_CHECKSUMS=1 ;;
      --cosign) COSIGN_MODE="${1:-}"; shift ;;
      --minisign) MINISIGN_KEY="${1:-}"; shift ;;
      -j) PARALLEL_JOBS="${1:-1}"; shift ;;
      --dry-run) DRY_RUN=1 ;;
      --verify-only) VERIFY_ONLY=1 ;;
      --force) FORCE=1 ;;
      --verbose) VERBOSE=1 ;;
      --help|-h) usage; exit 0 ;;
      --) break ;;
      -*) die "Unknown option: $arg" ;;
      *)  # positional file
          set -- "$@" "$arg"
          ;;
    esac
  done
  # Re-append positional files
  POSITIONAL_FILES=("$@")
}

# Resolve output directory strategy
resolve_out_dir() {
  if [[ -n "$OUT_DIR" ]]; then
    mkdir -p "$OUT_DIR"
    echo "$OUT_DIR"
    return
  fi
  if [[ ${#ARTIFACTS[@]} -gt 0 ]]; then
    # Use directory of first artifact
    local first="${ARTIFACTS[0]}"
    local dir
    dir="$(cd "$(dirname "$first")" && pwd)"
    echo "$dir"
    return
  fi
  echo "$(pwd)/release-signing"
}

discover_artifacts() {
  ARTIFACTS=()
  local f
  # Positional files take precedence
  if [[ ${#POSITIONAL_FILES[@]} -gt 0 ]]; then
    for f in "${POSITIONAL_FILES[@]}"; do
      [[ -e "$f" ]] || die "File not found: $f"
      ARTIFACTS+=("$(realpath "$f")")
    done
    return
  fi
  # Directory + pattern
  if [[ -n "$IN_DIR" && -n "$PATTERN" ]]; then
    [[ -d "$IN_DIR" ]] || die "--in not a directory: $IN_DIR"
    mapfile -t ARTIFACTS < <(find "$IN_DIR" -type f -name "$PATTERN" | sort)
    [[ ${#ARTIFACTS[@]} -gt 0 ]] || die "No artifacts matched in $IN_DIR with pattern $PATTERN"
    return
  fi
  die "No artifacts specified. Use positional files or --in with --pattern."
}

sha_file_for() {
  local path="$1" algo="$2"
  echo "$path.$algo"
}

sig_file_for() {
  local path="$1" armor="$2"
  if [[ "$armor" -eq 1 ]]; then
    echo "$path.asc"
  else
    echo "$path.sig"
  fi
}

cosign_sig_for() {
  local path="$1"
  echo "$path.cosign.sig"
}

minisign_sig_for() {
  local path="$1"
  echo "$path.minisig"
}

hash_compute() {
  local f="$1" algo="$2"
  case "$algo" in
    sha256) sha256sum "$f" ;;
    sha512) sha512sum "$f" ;;
    *) die "Unsupported hash algo: $algo" ;;
  esac
}

hash_verify_file() {
  local checksum_file="$1"
  sha256sum -c "$checksum_file" >/dev/null 2>&1 || \
  sha512sum -c "$checksum_file" >/dev/null 2>&1 || return 1
}

gpg_sign() {
  local src="$1" dst_sig="$2" key="$3" armor="$4"
  local armor_flag=()
  [[ "$armor" -eq 1 ]] && armor_flag=(--armor)
  gpg --batch --yes --local-user "$key" --pinentry-mode loopback \
      --output "$dst_sig" --detach-sign "${armor_flag[@]}" "$src"
}

gpg_verify() {
  local sig="$1" src="$2"
  gpg --verify "$sig" "$src" >/dev/null 2>&1
}

cosign_sign_blob() {
  local src="$1" dst_sig="$2"
  case "$COSIGN_MODE" in
    keyless)
      COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes --output-signature "$dst_sig" "$src" >/dev/null
      ;;
    kms:*)
      local uri="${COSIGN_MODE#kms:}"
      cosign sign-blob --kms "$uri" --output-signature "$dst_sig" "$src" >/dev/null
      ;;
    key:*)
      local keypath="${COSIGN_MODE#key:}"
      cosign sign-blob --key "$keypath" --output-signature "$dst_sig" "$src" >/dev/null
      ;;
    *)
      die "Unknown cosign mode: $COSIGN_MODE"
      ;;
  esac
}

minisign_sign_blob() {
  local src="$1" dst_sig="$2" keyfile="$3"
  minisign -S -s "$keyfile" -m "$src" -x "$dst_sig" >/dev/null
}

aggregate_file_for() {
  local algo="$1" outdir="$2"
  echo "$outdir/CHECKSUMS-$algo.txt"
}

process_one() {
  local f="$1"
  local armor="$2"
  local key="$3"
  local force="$4"
  local do_cosign="$5"
  local do_minisign="$6"
  local out_dir="$7"

  [[ "$VERBOSE" -eq 1 ]] && log "Processing: $f"

  # Hashes
  IFS=',' read -r -a algos <<< "$HASH_ALGOS"
  local algo line sha_file
  for algo in "${algos[@]}"; do
    sha_file="$(sha_file_for "$f" "$algo")"
    if [[ -e "$sha_file" && "$force" -ne 1 ]]; then
      warn "Exists, skip hash ($algo): $sha_file"
    else
      if [[ "$DRY_RUN" -eq 1 ]]; then
        info "[dry-run] would compute $algo for $f -> $sha_file"
      else
        line="$(hash_compute "$f" "$algo")"
        printf "%s\n" "$line" > "$sha_file"
        ok "Wrote $algo: $sha_file"
      fi
    fi
  done

  # GPG signature
  local sig_file
  sig_file="$(sig_file_for "$f" "$armor")"
  if [[ -e "$sig_file" && "$force" -ne 1 ]]; then
    warn "Exists, skip signature: $sig_file"
  else
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] would GPG-sign $f -> $sig_file"
    else
      gpg_sign "$f" "$sig_file" "$key" "$armor"
      ok "Signed: $sig_file"
      if gpg_verify "$sig_file" "$f"; then
        ok "Verified GPG signature for $(basename "$f")"
      else
        die "GPG verification failed for $f"
      fi
    fi
  fi

  # Optional cosign
  if [[ -n "$do_cosign" ]]; then
    local csig
    csig="$(cosign_sig_for "$f")"
    if [[ -e "$csig" && "$force" -ne 1 ]]; then
      warn "Exists, skip cosign: $csig"
    else
      if [[ "$DRY_RUN" -eq 1 ]]; then
        info "[dry-run] would cosign sign-blob $f -> $csig"
      else
        cosign_sign_blob "$f" "$csig"
        ok "Cosign signature: $csig"
      fi
    fi
  fi

  # Optional minisign
  if [[ -n "$do_minisign" ]]; then
    local msig
    msig="$(minisign_sig_for "$f")"
    if [[ -e "$msig" && "$force" -ne 1 ]]; then
      warn "Exists, skip minisign: $msig"
    else
      if [[ "$DRY_RUN" -eq 1 ]]; then
        info "[dry-run] would minisign $f -> $msig"
      else
        minisign_sign_blob "$f" "$msig" "$do_minisign"
        ok "Minisign signature: $msig"
      fi
    fi
  fi

  # Append to aggregates
  local agg
  for algo in "${algos[@]}"; do
    agg="$(aggregate_file_for "$algo" "$out_dir")"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      info "[dry-run] would append $algo of $(basename "$f") to $agg"
    else
      # normalize to "hash  filename"
      case "$algo" in
        sha256) awk '{print $1"  "$2}' "$(sha_file_for "$f" "$algo")" >> "$agg" ;;
        sha512) awk '{print $1"  "$2}' "$(sha_file_for "$f" "$algo")" >> "$agg" ;;
      esac
      ok "Aggregated $algo for $(basename "$f") -> $(basename "$agg")"
    fi
  done
}

verify_only_one() {
  local f="$1"
  local armor="$2"

  IFS=',' read -r -a algos <<< "$HASH_ALGOS"
  local algo sha_file
  for algo in "${algos[@]}"; do
    sha_file="$(sha_file_for "$f" "$algo")"
    [[ -f "$sha_file" ]] || die "Missing checksum for verify: $sha_file"
    if sha256sum -c "$sha_file" >/dev/null 2>&1 || sha512sum -c "$sha_file" >/dev/null 2>&1; then
      ok "Checksum OK for $(basename "$f") [$algo]"
    else
      die "Checksum FAILED for $f [$algo]"
    fi
  done

  local sig_file
  sig_file="$(sig_file_for "$f" "$armor")"
  [[ -f "$sig_file" ]] || die "Missing signature for verify: $sig_file"
  if gpg_verify "$sig_file" "$f"; then
    ok "GPG signature OK for $(basename "$f")"
  else
    die "GPG signature FAILED for $f"
  fi
}

sign_aggregates_and_verify() {
  local out_dir="$1" key="$2" armor="$3"
  IFS=',' read -r -a algos <<< "$HASH_ALGOS"

  local algo agg sig
  for algo in "${algos[@]}"; do
    agg="$(aggregate_file_for "$algo" "$out_dir")"
    [[ -s "$agg" ]] || { warn "Empty aggregate for $algo: $agg"; continue; }

    # Verify aggregate lines are valid
    if [[ "$DRY_RUN" -eq 0 ]]; then
      # Create a temp copy in sha*sum format for -c verification
      local tmp="$agg.tmp"
      cp "$agg" "$tmp"
      # Replace double-space with space for robustness
      sed -i 's/  / /g' "$tmp"
      if sha256sum -c "$tmp" >/dev/null 2>&1 || sha512sum -c "$tmp" >/dev/null 2>&1; then
        ok "Aggregated checksums syntactically valid: $(basename "$agg")"
      else
        warn "Aggregate verification not conclusive for $(basename "$agg") (mixed algos expected)"
      fi
      rm -f "$tmp"
    fi

    if [[ "$SIGN_CHECKSUMS" -eq 1 ]]; then
      sig="$(sig_file_for "$agg" "$armor")"
      if [[ -e "$sig" && "$FORCE" -ne 1 ]]; then
        warn "Exists, skip GPG-sign aggregate: $sig"
      else
        if [[ "$DRY_RUN" -eq 1 ]]; then
          info "[dry-run] would GPG-sign aggregate $agg -> $sig"
        else
          gpg_sign "$agg" "$sig" "$key" "$armor"
          ok "Signed aggregate: $(basename "$sig")"
          gpg_verify "$sig" "$agg" && ok "Verified aggregate signature: $(basename "$agg")"
        fi
      fi
    fi
  done
}

main() {
  parse_args "$@"

  require_cmd gpg sha256sum sha512sum find xargs

  if [[ -z "$GPG_KEY_ID" ]]; then
    # try git signing key as fallback
    if command -v git >/dev/null 2>&1; then
      GPG_KEY_ID="$(git config --get user.signingkey || true)"
    fi
  fi
  [[ -n "$GPG_KEY_ID" ]] || die "No --gpg-key provided and user.signingkey not set."

  if [[ -n "$COSIGN_MODE" ]]; then
    require_cmd cosign
  fi
  if [[ -n "$MINISIGN_KEY" ]]; then
    require_cmd minisign
    [[ -f "$MINISIGN_KEY" ]] || die "minisign key not found: $MINISIGN_KEY"
  fi

  discover_artifacts

  # Resolve OUT_DIR and ensure aggregates exist
  OUT_DIR="$(resolve_out_dir)"
  [[ "$DRY_RUN" -eq 1 ]] || mkdir -p "$OUT_DIR"
  [[ "$VERBOSE" -eq 1 ]] && info "Output directory: $OUT_DIR"

  IFS=',' read -r -a algos <<< "$HASH_ALGOS"
  local a
  for a in "${algos[@]}"; do
    case "$a" in
      sha256|sha512) : ;;
      *) die "Unsupported hash in --hash: $a" ;;
    esac
  done

  # Pre-create empty aggregates (for ordered appends)
  local agg
  for a in "${algos[@]}"; do
    agg="$(aggregate_file_for "$a" "$OUT_DIR")"
    if [[ "$FORCE" -eq 1 && "$DRY_RUN" -eq 0 ]]; then
      : > "$agg"
    else
      [[ -f "$agg" ]] || { [[ "$DRY_RUN" -eq 1 ]] || : > "$agg"; }
    fi
  done

  if [[ "$VERIFY_ONLY" -eq 1 ]]; then
    info "Verify-only mode enabled"
    for f in "${ARTIFACTS[@]}"; do
      verify_only_one "$f" "$ARMOR"
    done
    # Verify aggregates signatures if present
    if [[ "$SIGN_CHECKSUMS" -eq 1 ]]; then
      for a in "${algos[@]}"; do
        agg="$(aggregate_file_for "$a" "$OUT_DIR")"
        if [[ -f "$agg" ]]; then
          local sig="$(sig_file_for "$agg" "$ARMOR")"
          if [[ -f "$sig" ]]; then
            gpg_verify "$sig" "$agg" && ok "Aggregate signature OK: $(basename "$agg")" || die "Aggregate signature FAILED: $(basename "$agg")"
          fi
        fi
      done
    fi
    ok "Verification complete"
    exit 0
  fi

  info "Signing with GPG key: $GPG_KEY_ID"
  [[ "$ARMOR" -eq 1 ]] && info "ASCII armored signatures enabled"

  # Process with optional parallel jobs
  if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
    info "Parallel jobs: $PARALLEL_JOBS"
    # Simple job queue
    running=0
    pids=()
    for f in "${ARTIFACTS[@]}"; do
      (
        process_one "$f" "$ARMOR" "$GPG_KEY_ID" "$FORCE" "$COSIGN_MODE" "$MINISIGN_KEY" "$OUT_DIR"
      ) &
      pids+=("$!")
      ((running++))
      if (( running >= PARALLEL_JOBS )); then
        wait -n
        ((running--))
      fi
    done
    # Wait for remaining jobs
    for pid in "${pids[@]}"; do wait "$pid"; done
  else
    for f in "${ARTIFACTS[@]}"; do
      process_one "$f" "$ARMOR" "$GPG_KEY_ID" "$FORCE" "$COSIGN_MODE" "$MINISIGN_KEY" "$OUT_DIR"
    done
  fi

  # Sign and verify aggregates if requested
  sign_aggregates_and_verify "$OUT_DIR" "$GPG_KEY_ID" "$ARMOR"

  ok "All artifacts processed successfully"
  ok "Aggregates location: $OUT_DIR"
}

main "$@"
