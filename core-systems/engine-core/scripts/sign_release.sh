#!/usr/bin/env bash

# ==============================================================================
# Industrial-grade artifact signing script using Cosign and Sigstore
# Location: engine-core/scripts/sign_release.sh
# Dependencies: cosign, jq, gh (optional)
# ==============================================================================
set -euo pipefail

ARTIFACTS_DIR="./dist"
SIGNED_DIR="./.signed"
KEYLESS=true                 # true: use OIDC (CI), false: manual key
COSIGN_PWD="${COSIGN_PASSWORD:-}"
RELEASE_TAG="${RELEASE_TAG:-}"

mkdir -p "$SIGNED_DIR"

# === Function: Check dependencies ===
function check_dependencies() {
  for tool in cosign jq; do
    if ! command -v "$tool" &>/dev/null; then
      echo "Error: $tool is not installed"
      exit 1
    fi
  done
}

# === Function: Sign artifact (keyless) ===
function sign_artifact_keyless() {
  local file="$1"
  echo "[*] Signing artifact (keyless): $file"
  cosign sign-blob --yes \
    --output-signature "$SIGNED_DIR/$(basename "$file").sig" \
    --output-certificate "$SIGNED_DIR/$(basename "$file").crt" \
    "$file"
}

# === Function: Sign artifact (with key) ===
function sign_artifact_keyed() {
  local file="$1"
  echo "[*] Signing artifact (keyed): $file"
  cosign sign-blob --yes \
    --key env://COSIGN_PRIVATE_KEY \
    --output-signature "$SIGNED_DIR/$(basename "$file").sig" \
    --output-certificate "$SIGNED_DIR/$(basename "$file").crt" \
    "$file"
}

# === Function: Publish to transparency log ===
function show_transparency() {
  local file="$1"
  local sig="$SIGNED_DIR/$(basename "$file").sig"
  echo "[+] Signature stored: $sig"
}

# === Function: Sign all release files ===
function sign_all() {
  echo "[*] Searching artifacts in $ARTIFACTS_DIR"

  for file in "$ARTIFACTS_DIR"/*; do
    [[ -f "$file" ]] || continue
    if [[ "$KEYLESS" == true ]]; then
      sign_artifact_keyless "$file"
    else
      if [[ -z "$COSIGN_PWD" ]]; then
        echo "Error: COSIGN_PASSWORD must be set"
        exit 1
      fi
      export COSIGN_PASSWORD="$COSIGN_PWD"
      sign_artifact_keyed "$file"
    fi
    show_transparency "$file"
  done
}

# === Function: Optional attach to GitHub Release ===
function attach_to_github_release() {
  if [[ -n "$RELEASE_TAG" && -x "$(command -v gh)" ]]; then
    echo "[*] Attaching signatures to GitHub release: $RELEASE_TAG"
    for f in "$SIGNED_DIR"/*; do
      gh release upload "$RELEASE_TAG" "$f" --clobber
    done
  fi
}

# === MAIN ===
check_dependencies
sign_all
attach_to_github_release

echo "[✓] All artifacts signed and stored in $SIGNED_DIR"
