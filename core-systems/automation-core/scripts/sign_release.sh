#!/usr/bin/env bash
# automation-core/scripts/sign_release.sh
#
# Industrial-grade release signing script.
#
# Features:
#  - SHA256 checksums (GNU coreutils sha256sum).
#  - GPG detached signatures (.asc) for checksum file and optional per-asset.
#    GnuPG --detach-sign reference: https://www.gnupg.org/gph/en/manual/x135.html
#  - Sigstore cosign (if available): sign-blob for each asset and for SHA256SUMS;
#    optional in-toto attestations for SBOM files.
#    Cosign docs: https://docs.sigstore.dev/cosign/
#    Quickstart:  https://docs.sigstore.dev/quickstart/quickstart-cosign/
#    Attestations: https://docs.sigstore.dev/cosign/verifying/attestation/
#  - Deterministic tar packing (optional) for reproducible archives:
#    GNU tar reproducibility: https://www.gnu.org/software/tar/manual/html_node/Reproducibility.html
#    Reproducible-builds guidance: https://reproducible-builds.org/docs/archives/
#
# Safety:
#  - set -Eeuo pipefail; strict error handling.
#  - No network is required; cosign can still sign blobs offline with key material.
#
# Usage:
#  ./sign_release.sh \
#     --release-dir dist \
#     --out-dir dist/signing \
#     [--gpg-key-id <KEYID>] \
#     [--cosign-key <PATH|KMS|\"\">] \
#     [--pack path:archive-name.tar.gz] \
#     [--sbom-glob \"**/*.spdx.json\"] \
#     [--attest-type \"https://slsa.dev/provenance/v1\"] \
#     [--stamp-epoch <UNIX_EPOCH>]
#
# Environment variables (override CLI):
#  RELEASE_DIR, OUT_DIR, GPG_KEY_ID, COSIGN_KEY, SBOM_GLOB, ATTEST_TYPE, STAMP_EPOCH
#
# Exit codes:
#  0 success; non-zero on any failure.

set -Eeuo pipefail
IFS=$'\n\t'

# ----------------------------- Defaults / CLI ------------------------------
RELEASE_DIR="${RELEASE_DIR:-dist}"
OUT_DIR="${OUT_DIR:-${RELEASE_DIR}/signing}"
GPG_KEY_ID="${GPG_KEY_ID:-}"
COSIGN_KEY="${COSIGN_KEY:-}"            # empty => cosign keyless (if configured) or keyless flow; blob signing supports --key "" for keyless OIDC
SBOM_GLOB="${SBOM_GLOB:-**/*.spdx.json}" # SPDX JSON by default
ATTEST_TYPE="${ATTEST_TYPE:-https://slsa.dev/provenance/v1}"
STAMP_EPOCH="${STAMP_EPOCH:-${SOURCE_DATE_EPOCH:-0}}"

PACK_SPECS=()  # each: "path:archive-name.tar.gz"

usage() {
  cat <<'USAGE'
sign_release.sh — sign release artifacts with SHA256, GPG, and (optionally) cosign.

Options:
  --release-dir DIR        Directory with artifacts (default: dist)
  --out-dir DIR            Output dir for signatures (default: dist/signing)
  --gpg-key-id KEYID       GPG key id (fingerprint/email). If omitted, gpg default key used.
  --cosign-key VAL         cosign key ref (file path, KMS URI, or empty for keyless/cosign defaults)
  --pack SRC:ARCHIVE.tar.gz
                           Deterministically pack SRC into ARCHIVE.tar.gz before signing (repeatable)
  --sbom-glob GLOB         Glob for SBOMs to attest (default: **/*.spdx.json)
  --attest-type TYPE       in-toto predicateType (default: https://slsa.dev/provenance/v1)
  --stamp-epoch EPOCH      Fixed timestamp for deterministic tar (default: SOURCE_DATE_EPOCH or 0)
  -h|--help                Show help

Docs:
  GPG detached-sign: https://www.gnupg.org/gph/en/manual/x135.html
  sha256sum:         https://man7.org/linux/man-pages/man1/sha256sum.1.html
  Cosign:            https://docs.sigstore.dev/cosign/
  Cosign Quickstart: https://docs.sigstore.dev/quickstart/quickstart-cosign/
  Cosign Attest:     https://docs.sigstore.dev/cosign/verifying/attestation/
  GNU tar reproducibility: https://www.gnu.org/software/tar/manual/html_node/Reproducibility.html
  Reproducible archives:   https://reproducible-builds.org/docs/archives/
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-dir) RELEASE_DIR="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    --gpg-key-id) GPG_KEY_ID="$2"; shift 2;;
    --cosign-key) COSIGN_KEY="$2"; shift 2;;
    --pack) PACK_SPECS+=("$2"); shift 2;;
    --sbom-glob) SBOM_GLOB="$2"; shift 2;;
    --attest-type) ATTEST_TYPE="$2"; shift 2;;
    --stamp-epoch) STAMP_EPOCH="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 2;;
  esac
done

# ------------------------------ Pre-flight --------------------------------
log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "Required tool not found: $1"; }

need "sha256sum"   # GNU coreutils: https://man7.org/linux/man-pages/man1/sha256sum.1.html
need "gpg"         # GnuPG for --detach-sign: https://www.gnupg.org/gph/en/manual/x135.html

COSIGN_AVAILABLE=0
if command -v cosign >/dev/null 2>&1; then
  COSIGN_AVAILABLE=1
fi

[[ -d "$RELEASE_DIR" ]] || die "Release dir not found: $RELEASE_DIR"
mkdir -p "$OUT_DIR"

# --------------------- Deterministic tar (optional) -----------------------
# GNU tar reproducibility guidance: use fixed timestamps, numeric owners,
# sort by name, and stable permissions. Reference:
#   https://www.gnu.org/software/tar/manual/html_node/Reproducibility.html
#   https://reproducible-builds.org/docs/archives/
pack_tree() {
  local src="$1" out="$2"
  [[ -e "$src" ]] || die "Pack source not found: $src"
  log "Packing (deterministic) $src -> $out"
  # Requires GNU tar. If your tar lacks options, fall back or skip determinism.
  TAR_MTIME="@${STAMP_EPOCH}"
  tar \
    --format=gnu \
    --sort=name \
    --mtime="${TAR_MTIME}" \
    --owner=0 --group=0 --numeric-owner \
    --mode=u+rw,go+r-wx \
    -C "$(dirname "$src")" \
    -cf - "$(basename "$src")" \
  | gzip -n > "$out"
}

if (( ${#PACK_SPECS[@]} )); then
  for spec in "${PACK_SPECS[@]}"; do
    src="${spec%%:*}"; out="${spec#*:}"
    mkdir -p "$(dirname "$out")"
    pack_tree "$src" "$out"
  done
fi

# ---------------- Collect artifacts to sign (exclude signatures) ----------
# We sign any regular file in RELEASE_DIR (and archives we just packed),
# excluding known signature extensions to avoid infinite nesting.
mapfile -d '' ARTIFACTS < <(find "$RELEASE_DIR" -type f \
  ! -name '*.asc' ! -name '*.sig' ! -name '*.pem' ! -name '*.cosign.*' \
  -print0)

(( ${#ARTIFACTS[@]} )) || die "No artifacts found in $RELEASE_DIR"

# ------------------------ SHA256 checksums ---------------------------------
CHECKSUMS_FILE="${OUT_DIR}/SHA256SUMS"
log "Generating checksums -> ${CHECKSUMS_FILE}"
: > "$CHECKSUMS_FILE"
# man sha256sum: https://man7.org/linux/man-pages/man1/sha256sum.1.html
while IFS= read -r -d '' f; do
  # store relative path for portability
  rel=$(realpath --relative-to "$RELEASE_DIR" "$f")
  (cd "$RELEASE_DIR" && sha256sum "$rel") >> "$CHECKSUMS_FILE"
done < <(printf '%s\0' "${ARTIFACTS[@]}")

# ------------------------ GPG signing -------------------------------------
# Detached ASCII-armored signature for CHECKSUMS.
# GnuPG detach-sign: https://www.gnupg.org/gph/en/manual/x135.html
GPG_OUT="${CHECKSUMS_FILE}.asc"
log "GPG signing checksums -> ${GPG_OUT}"
if [[ -n "$GPG_KEY_ID" ]]; then
  gpg --armor --local-user "$GPG_KEY_ID" --output "$GPG_OUT" --detach-sign "$CHECKSUMS_FILE"
else
  gpg --armor --output "$GPG_OUT" --detach-sign "$CHECKSUMS_FILE"
fi

# (Optional) per-asset signatures (disabled by default).
# Set PER_ASSET_GPG=1 to enable.
if [[ "${PER_ASSET_GPG:-0}" == "1" ]]; then
  for f in "${ARTIFACTS[@]}"; do
    rel=$(realpath --relative-to "$RELEASE_DIR" "$f")
    out="${OUT_DIR}/${rel}.asc"
    mkdir -p "$(dirname "$out")"
    log "GPG signing asset -> ${out}"
    if [[ -n "$GPG_KEY_ID" ]]; then
      gpg --armor --local-user "$GPG_KEY_ID" --output "$out" --detach-sign "$f"
    else
      gpg --armor --output "$out" --detach-sign "$f"
    fi
  done
fi

# ------------------------ Cosign (optional) --------------------------------
# Cosign signs "blobs" (arbitrary files) and supports in-toto attestations.
# Docs:
#   https://docs.sigstore.dev/quickstart/quickstart-cosign/
#   https://docs.sigstore.dev/cosign/verifying/attestation/
#
cosign_sign_blob() {
  local src="$1" sig="$2" cert="$3"
  if [[ -n "$COSIGN_KEY" ]]; then
    cosign sign-blob --yes --key "$COSIGN_KEY" --output-signature "$sig" --output-certificate "$cert" "$src"
  else
    # keyless (OIDC) or environment-provided flow; may require interactive auth in CI with OIDC.
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes --output-signature "$sig" --output-certificate "$cert" "$src"
  fi
}

cosign_attest_blob_if_possible() {
  # Prefer attest-blob if available in this cosign build; else fall back to sign-blob.
  # Note: Support for 'attest-blob' varies between releases. Not universally guaranteed.
  local subject="$1" predicate="$2" atype="$3"
  if cosign help 2>/dev/null | grep -q "attest-blob"; then
    if [[ -n "$COSIGN_KEY" ]]; then
      cosign attest-blob --yes --key "$COSIGN_KEY" --predicate "$predicate" --type "$atype" "$subject"
    else
      COSIGN_EXPERIMENTAL=1 cosign attest-blob --yes --predicate "$predicate" --type "$atype" "$subject"
    fi
  else
    # Fallback: sign the SBOM as a blob (not a formal in-toto Statement).
    local sig="${predicate}.cosign.sig" cert="${predicate}.cosign.pem"
    cosign_sign_blob "$predicate" "$sig" "$cert"
    log "cosign attest-blob not available; SBOM signed as blob instead (not an in-toto statement)."
  fi
}

if (( COSIGN_AVAILABLE )); then
  log "Cosign detected; signing blobs."
  # Sign CHECKSUMS
  cosign_sign_blob "$CHECKSUMS_FILE" "${CHECKSUMS_FILE}.cosign.sig" "${CHECKSUMS_FILE}.cosign.pem"

  # Sign each artifact as a blob
  while IFS= read -r -d '' f; do
    rel=$(realpath --relative-to "$RELEASE_DIR" "$f")
    out_sig="${OUT_DIR}/${rel}.cosign.sig"
    out_cert="${OUT_DIR}/${rel}.cosign.pem"
    mkdir -p "$(dirname "$out_sig")"
    log "Cosign sign-blob -> ${out_sig}"
    cosign_sign_blob "$f" "$out_sig" "$out_cert"
  done < <(printf '%s\0' "${ARTIFACTS[@]}")

  # Optional: attest SBOMs (SPDX). SPDX spec: https://spdx.dev/use/specifications/
  shopt -s nullglob globstar
  mapfile -t SBOMS < <(cd "$RELEASE_DIR" && printf '%s\n' $SBOM_GLOB || true)
  if (( ${#SBOMS[@]} )); then
    log "Found SBOMs to attest: ${#SBOMS[@]}"
    for sb in "${SBOMS[@]}"; do
      subj_path="${RELEASE_DIR}/${sb}"
      cosign_attest_blob_if_possible "$subj_path" "$subj_path" "$ATTEST_TYPE"
    done
  fi
else
  log "Cosign not found; skipping sigstore signing/attestation."
fi

# ----------------------------- Summary ------------------------------------
log "Signing completed."
log "Artifacts dir:  ${RELEASE_DIR}"
log "Output dir:     ${OUT_DIR}"
log "Checksums:      ${CHECKSUMS_FILE}"
log "GPG signature:  ${CHECKSUMS_FILE}.asc"
if (( COSIGN_AVAILABLE )); then
  log "Cosign sig:     ${CHECKSUMS_FILE}.cosign.sig"
  log "Cosign cert:    ${CHECKSUMS_FILE}.cosign.pem"
fi
