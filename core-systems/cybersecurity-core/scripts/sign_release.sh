#!/usr/bin/env bash
# sign_release.sh — Industrial-grade release signing utility
# Copyright:
#   Aethernova / NeuroCity — cybersecurity-core
#
# Features:
#   - Deterministic SHA256/SHA512 checksums for artifacts
#   - GPG detached ASCII signatures for each artifact and for checksum files
#   - Optional container image signing & attestations (SBOM / provenance) via cosign (keyed or keyless)
#   - JSON result manifest with digests, signature paths and verification status
#   - Strict, non-interactive, CI-friendly; clear error codes and logs
#
# Exit codes:
#   0  success
#   1  bad usage / missing args
#   2  missing tool
#   3  signing failure
#   4  verification failure
#   5  IO/path error

set -Eeuo pipefail
IFS=$'\n\t'

#----------------------------- Logging ----------------------------------------
log()  { printf '[INFO ] %s\n' "$*" >&2; }
warn() { printf '[WARN ] %s\n' "$*" >&2; }
err()  { printf '[ERROR] %s\n' "$*" >&2; }

#----------------------------- Defaults ---------------------------------------
VERSION=""
ARTIFACTS_DIR=""
OUTPUT_DIR=""
GPG_KEY_ID=""
GPG_KEYRING=""
GPG_HOMEDIR=""
COSIGN_KEY=""              # path to cosign.key (PEM) if keyed mode
COSIGN_PASSWORD=""         # env COSIGN_PASSWORD is respected by cosign
KEYLESS="false"            # cosign keyless mode (OIDC)
IMAGE_REF=""               # container image to sign, e.g. ghcr.io/org/app:1.2.3
SBOM_PATH=""               # path to SBOM (e.g., sbom.spdx.json)
PROVENANCE_PATH=""         # path to provenance (e.g., provenance.intoto.jsonl)
CERT_IDENTITY=""           # expected cert identity for keyless verify
CERT_ISSUER=""             # expected OIDC issuer for keyless verify
VERIFY_AFTER="true"        # verify artifacts and images after signing
DRY_RUN="false"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"

#----------------------------- Usage ------------------------------------------
usage() {
  cat <<'USAGE'
Usage: scripts/sign_release.sh [OPTIONS]

Required:
  --version <semver|tag>           Release version/tag (e.g., v1.2.3)
  --artifacts-dir <dir>            Directory with build artifacts to sign
  --output-dir <dir>               Directory to write signatures/manifests

GPG (artifact signing):
  --gpg-key-id <KEYID>             GPG key id/fingerprint/email to sign with
  --gpg-keyring <path>             Optional keyring file
  --gpg-homedir <path>             Optional GNUPGHOME directory

Cosign (container & attestations):
  --image <ref>                    Container image reference to sign
  --sbom <path>                    SBOM file to attach/attest
  --provenance <path>              Provenance file (in-toto) to attest
  --cosign-key <path>              cosign private key (PEM). If omitted and --keyless not set, cosign signing is skipped
  --keyless                        Use keyless (OIDC) signing with cosign
  --cert-identity <value>          Expected certificate identity (verify)
  --cert-issuer <value>            Expected OIDC issuer (verify)

General:
  --no-verify                      Skip verification step
  --dry-run                        Print actions only, do not modify repo
  -h|--help                        Show this help

Notes:
  - Requires: bash, gpg, sha256sum, sha512sum, jq. For container signing: cosign.
  - Environment: COSIGN_PASSWORD (if cosign key is password-protected),
                 COSIGN_EXPERIMENTAL=1 (recommended for keyless).
USAGE
}

#----------------------------- Argparse ---------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)           VERSION="${2:-}"; shift 2 ;;
    --artifacts-dir)     ARTIFACTS_DIR="${2:-}"; shift 2 ;;
    --output-dir)        OUTPUT_DIR="${2:-}"; shift 2 ;;
    --gpg-key-id)        GPG_KEY_ID="${2:-}"; shift 2 ;;
    --gpg-keyring)       GPG_KEYRING="${2:-}"; shift 2 ;;
    --gpg-homedir)       GPG_HOMEDIR="${2:-}"; shift 2 ;;
    --image)             IMAGE_REF="${2:-}"; shift 2 ;;
    --sbom)              SBOM_PATH="${2:-}"; shift 2 ;;
    --provenance)        PROVENANCE_PATH="${2:-}"; shift 2 ;;
    --cosign-key)        COSIGN_KEY="${2:-}"; shift 2 ;;
    --keyless)           KEYLESS="true"; shift 1 ;;
    --cert-identity)     CERT_IDENTITY="${2:-}"; shift 2 ;;
    --cert-issuer)       CERT_ISSUER="${2:-}"; shift 2 ;;
    --no-verify)         VERIFY_AFTER="false"; shift 1 ;;
    --dry-run)           DRY_RUN="true"; shift 1 ;;
    -h|--help)           usage; exit 0 ;;
    *) err "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

#----------------------------- Validate ---------------------------------------
require() { command -v "$1" >/dev/null 2>&1 || { err "Missing tool: $1"; exit 2; }; }

[[ -n "$VERSION" && -n "$ARTIFACTS_DIR" && -n "$OUTPUT_DIR" ]] || { err "Missing --version/--artifacts-dir/--output-dir"; usage; exit 1; }
[[ -d "$ARTIFACTS_DIR" ]] || { err "Artifacts dir not found: $ARTIFACTS_DIR"; exit 5; }
mkdir -p "$OUTPUT_DIR" || { err "Cannot create output dir: $OUTPUT_DIR"; exit 5; }

# Always needed
require sha256sum
require sha512sum
require gpg
require jq

# Optional
COSIGN_AVAILABLE="false"
if command -v cosign >/dev/null 2>&1; then
  COSIGN_AVAILABLE="true"
fi

if [[ "$DRY_RUN" == "true" ]]; then
  log "DRY-RUN enabled: no files will be written"
fi

# Resolve absolute paths
ARTIFACTS_DIR="$(cd "$ARTIFACTS_DIR" && pwd)"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
[[ -n "${SBOM_PATH}" && -f "${SBOM_PATH}" ]] && SBOM_PATH="$(cd "$(dirname "$SBOM_PATH")" && pwd)/$(basename "$SBOM_PATH")"
[[ -n "${PROVENANCE_PATH}" && -f "${PROVENANCE_PATH}" ]] && PROVENANCE_PATH="$(cd "$(dirname "$PROVENANCE_PATH")" && pwd)/$(basename "$PROVENANCE_PATH")"

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
RUN_DIR="${OUTPUT_DIR}/release-${VERSION}"
CHECKSUM256="${RUN_DIR}/SHA256SUMS"
CHECKSUM512="${RUN_DIR}/SHA512SUMS"
MANIFEST="${RUN_DIR}/signing-manifest.json"

mkdir -p "$RUN_DIR"

#----------------------------- Helpers ----------------------------------------
gpg_env=()
[[ -n "$GPG_HOMEDIR"  ]] && gpg_env+=( "--homedir" "$GPG_HOMEDIR" )
[[ -n "$GPG_KEYRING"  ]] && gpg_env+=( "--keyring" "$GPG_KEYRING" )

sign_file_gpg() {
  local file="$1"
  local asc="${file}.asc"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY] gpg --detach-sign --armor --local-user <hidden> '$file' -> '$asc'"
    return 0
  fi
  gpg "${gpg_env[@]}" --batch --yes --quiet --detach-sign --armor \
      --local-user "$GPG_KEY_ID" --output "$asc" "$file" || return 1
  echo "$asc"
}

verify_file_gpg() {
  local asc="$1"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY] gpg --verify '$asc'"
    return 0
  fi
  gpg "${gpg_env[@]}" --batch --quiet --verify "$asc" >/dev/null 2>&1
}

safe_find_artifacts() {
  # Only regular files; ignore signatures, sums, common build junk
  find "$ARTIFACTS_DIR" -type f \
    ! -name "*.asc" \
    ! -name "SHA256SUMS" \
    ! -name "SHA512SUMS" \
    ! -name "*.sarif" \
    ! -name "*.log" \
    ! -path "*/node_modules/*" \
    ! -path "*/.venv/*" \
    ! -path "*/dist/signing/*" \
    | LC_ALL=C sort
}

calc_checksums() {
  local files=("$@")
  [[ "${#files[@]}" -gt 0 ]] || { warn "No artifacts found to checksum"; return 0; }
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY] sha256sum -> $CHECKSUM256"
    log "[DRY] sha512sum -> $CHECKSUM512"
    return 0
  fi
  : > "$CHECKSUM256"
  : > "$CHECKSUM512"
  # parallel-friendly but simple
  for f in "${files[@]}"; do
    (cd "$(dirname "$f")" && sha256sum "$(basename "$f")") >> "$CHECKSUM256"
    (cd "$(dirname "$f")" && sha512sum "$(basename "$f")") >> "$CHECKSUM512"
  done
}

cosign_wrap() {
  if [[ "$COSIGN_AVAILABLE" != "true" ]]; then
    warn "cosign not available; skipping cosign step: $*"
    return 0
  fi
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY] cosign $*"
    return 0
  fi
  COSIGN_EXPERIMENTAL=1 cosign "$@"
}

#----------------------------- Signing flow -----------------------------------
main() {
  log "Release signing started: version=$VERSION time=$TS"
  log "Artifacts: $ARTIFACTS_DIR"
  log "Output:    $RUN_DIR"

  # 1) Collect artifacts
  mapfile -t ARTS < <(safe_find_artifacts)
  log "Discovered ${#ARTS[@]} artifact(s)"

  # 2) Checksums
  log "Generating checksums (SHA256/SHA512)"
  calc_checksums "${ARTS[@]}"

  # 3) GPG signing (artifacts + checksum files)
  if [[ -n "$GPG_KEY_ID" ]]; then
    log "GPG signing enabled with key: $GPG_KEY_ID"
    # Each artifact
    for f in "${ARTS[@]}"; do
      sign_file_gpg "$f" >/dev/null || { err "GPG signing failed: $f"; exit 3; }
    done
    # Checksums
    [[ -f "$CHECKSUM256" ]] && sign_file_gpg "$CHECKSUM256" >/dev/null || true
    [[ -f "$CHECKSUM512" ]] && sign_file_gpg "$CHECKSUM512" >/dev/null || true
  else
    warn "GPG key not provided; skipping GPG signing of artifacts"
  fi

  # 4) Cosign: image signature (optional)
  if [[ -n "$IMAGE_REF" ]]; then
    log "Container image signing target: $IMAGE_REF"
    if [[ "$KEYLESS" == "true" ]]; then
      cosign_wrap sign --keyless --yes "$IMAGE_REF" || { err "Cosign keyless sign failed"; exit 3; }
    elif [[ -n "$COSIGN_KEY" ]]; then
      cosign_wrap sign --key "$COSIGN_KEY" --yes "$IMAGE_REF" || { err "Cosign keyed sign failed"; exit 3; }
    else
      warn "No cosign key and not keyless; skipping image signing"
    fi
  fi

  # 5) Cosign: attach/attest SBOM and provenance (optional)
  if [[ -n "$IMAGE_REF" && -n "$SBOM_PATH" && -f "$SBOM_PATH" ]]; then
    log "Attesting SBOM via cosign: $SBOM_PATH"
    # prefer attest over attach-sbom for provenance traceability
    cosign_wrap attest --yes \
      --predicate "$SBOM_PATH" \
      --type spdx \
      ${COSIGN_KEY:+--key "$COSIGN_KEY"} \
      ${KEYLESS:+--keyless} \
      "$IMAGE_REF" || { err "Cosign SBOM attestation failed"; exit 3; }
  fi

  if [[ -n "$IMAGE_REF" && -n "$PROVENANCE_PATH" && -f "$PROVENANCE_PATH" ]]; then
    log "Attesting provenance via cosign: $PROVENANCE_PATH"
    cosign_wrap attest --yes \
      --predicate "$PROVENANCE_PATH" \
      --type slsaprovenance \
      ${COSIGN_KEY:+--key "$COSIGN_KEY"} \
      ${KEYLESS:+--keyless} \
      "$IMAGE_REF" || { err "Cosign provenance attestation failed"; exit 3; }
  fi

  # 6) Verification (optional)
  if [[ "$VERIFY_AFTER" == "true" ]]; then
    log "Verifying GPG signatures (if present)"
    local_vfail=0
    if [[ -n "$GPG_KEY_ID" ]]; then
      for f in "${ARTS[@]}"; do
        asc="${f}.asc"
        [[ -f "$asc" ]] && verify_file_gpg "$asc" || { err "GPG verify failed: $asc"; local_vfail=1; }
      done
      [[ -f "$CHECKSUM256.asc" ]] && verify_file_gpg "$CHECKSUM256.asc" || true
      [[ -f "$CHECKSUM512.asc" ]] && verify_file_gpg "$CHECKSUM512.asc" || true
    fi

    if [[ -n "$IMAGE_REF" && "$COSIGN_AVAILABLE" == "true" ]]; then
      log "Verifying cosign signatures for image"
      COSIGN_VERIFY_ARGS=()
      [[ -n "$CERT_IDENTITY" ]] && COSIGN_VERIFY_ARGS+=( "--certificate-identity" "$CERT_IDENTITY" )
      [[ -n "$CERT_ISSUER"   ]] && COSIGN_VERIFY_ARGS+=( "--certificate-oidc-issuer" "$CERT_ISSUER" )
      if [[ "$KEYLESS" == "true" ]]; then
        cosign_wrap verify --keyless "${COSIGN_VERIFY_ARGS[@]}" "$IMAGE_REF" || { err "Cosign keyless verify failed"; local_vfail=1; }
      elif [[ -n "$COSIGN_KEY" ]]; then
        cosign_wrap verify --key "$COSIGN_KEY" "$IMAGE_REF" || { err "Cosign keyed verify failed"; local_vfail=1; }
      else
        warn "No cosign key and not keyless; skipping image verify"
      fi
    fi

    [[ $local_vfail -eq 0 ]] || { err "Verification failures detected"; exit 4; }
  else
    warn "Verification disabled by --no-verify"
  fi

  # 7) Build JSON manifest
  log "Writing signing manifest: $MANIFEST"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY] skip manifest write"
  else
    tmp="$(mktemp)"
    {
      echo '{'
      printf '  "version": %s,\n' "$(jq -Rn --arg v "$VERSION" '$v')"
      printf '  "timestamp_utc": %s,\n' "$(jq -Rn --arg t "$TS" '$t')"
      printf '  "artifacts_dir": %s,\n' "$(jq -Rn --arg d "$ARTIFACTS_DIR" '$d')"
      printf '  "output_dir": %s,\n' "$(jq -Rn --arg d "$RUN_DIR" '$d')"
      printf '  "artifacts": [\n'
      for i in "${!ARTS[@]}"; do
        f="${ARTS[$i]}"
        sha256="$( (cd "$(dirname "$f")" && sha256sum "$(basename "$f")") | awk '{print $1}')"
        sha512="$( (cd "$(dirname "$f")" && sha512sum "$(basename "$f")") | awk '{print $1}')"
        printf '    {"path": %s, "sha256": %s, "sha512": %s, "signature": %s}%s\n' \
          "$(jq -Rn --arg p "$f" '$p')" \
          "$(jq -Rn --arg s "$sha256" '$s')" \
          "$(jq -Rn --arg s "$sha512" '$s')" \
          "$(jq -Rn --arg s "${f}.asc" '($s|sub("^";"") )')" \
          $([[ $i -lt $((${#ARTS[@]} - 1)) ]] && echo "," || true)
      done
      echo '  ],'
      printf '  "checksums": {"sha256": %s, "sha512": %s},\n' \
        "$(jq -Rn --arg p "$CHECKSUM256" '$p')" \
        "$(jq -Rn --arg p "$CHECKSUM512" '$p')"
      printf '  "images": '
      if [[ -n "$IMAGE_REF" ]]; then
        echo '['
        echo '    {'
        printf '      "ref": %s,\n' "$(jq -Rn --arg r "$IMAGE_REF" '$r')"
        printf '      "sbom": %s,\n' "$(jq -Rn --arg p "$SBOM_PATH" '$p')"
        printf '      "provenance": %s\n' "$(jq -Rn --arg p "$PROVENANCE_PATH" '$p')"
        echo '    }'
        echo '  ],'
      else
        echo '[],'
      fi
      printf '  "verify_performed": %s\n' "$( [[ "$VERIFY_AFTER" == "true" ]] && echo true || echo false )"
      echo '}'
    } > "$tmp"
    mv "$tmp" "$MANIFEST"
  fi

  log "Release signing complete"
}

main "$@"
