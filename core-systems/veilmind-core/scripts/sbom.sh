#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Robust SBOM generator for VeilMind Core
# Features:
#  - Sources: directory, docker image, venv path
#  - Formats: CycloneDX (JSON/XML), SPDX (JSON/Tag-Value)
#  - Tools: syft (primary), optional cyclonedx-cli (validate/merge), jq (post-process), cosign (sign)
#  - CI-friendly: deterministic output dirs, checksums, quiet/non-interactive
#  - Optional bootstrap of syft binary when not installed (controlled by SBOM_BOOTSTRAP=1)
#
# Usage:
#   scripts/sbom.sh gen dir ./src
#   scripts/sbom.sh gen image ghcr.io/org/app:1.2.3
#   scripts/sbom.sh gen venv .venv
#   scripts/sbom.sh gen all            # smart autodetect
#   scripts/sbom.sh validate path/to/bom.cdx.json
#   scripts/sbom.sh sign path/to/bom.cdx.json          # requires cosign
#   scripts/sbom.sh merge bom1.json bom2.json -o merged.cdx.json   # requires cyclonedx-cli
# Environment:
#   SBOM_OUT_DIR=build/sbom
#   SBOM_FORMAT=cdx-json|cdx-xml|spdx-json|spdx-tv     (default: cdx-json)
#   SBOM_BOOTSTRAP=1                                   (enable syft auto-download)
#   SYFT_VERSION=v1.0.0                                (used when bootstrapping)
#   COSIGN_KEY=cosign.key|k8s://...                    (for 'sign')
#   COSIGN_ARGS="--predicate-type cyclonedx"           (extra flags for cosign attest)
#   SOURCE_DATE_EPOCH=<unix_ts>                        (normalizes timestamps where supported)

set -Eeuo pipefail

# ------------- globals & defaults -------------
SBOM_OUT_DIR="${SBOM_OUT_DIR:-build/sbom}"
SBOM_FORMAT="${SBOM_FORMAT:-cdx-json}" # cdx-json|cdx-xml|spdx-json|spdx-tv
SYFT_VERSION="${SYFT_VERSION:-v1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/veilmind/sbom-tools"
PATH="$CACHE_DIR:$PATH"

# ------------- logging -------------
log()   { printf "%s %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()   { log "ERROR: $*"; exit 1; }
note()  { log "INFO:  $*"; }
warn()  { log "WARN:  $*"; }

# ------------- utils -------------
need() {
  command -v "$1" >/dev/null 2>&1 || return 1
}

sha256() {
  if need shasum; then shasum -a 256 "$@"
  elif need sha256sum; then sha256sum "$@"
  else warn "no sha256 tool found"; return 0; fi
}

# ------------- tool bootstrap (syft) -------------
detect_os_arch() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "Unsupported arch: $arch" ;;
  esac
  echo "${os}-${arch}"
}

bootstrap_syft() {
  if need syft; then return 0; fi
  if [[ "${SBOM_BOOTSTRAP:-0}" != "1" ]]; then
    die "syft not found in PATH. Install it or set SBOM_BOOTSTRAP=1 for auto-download."
  fi
  mkdir -p "$CACHE_DIR"
  local osarch tar url
  osarch="$(detect_os_arch)"
  tar="syft_${SYFT_VERSION#v}_${osarch}.tar.gz"
  url="https://github.com/anchore/syft/releases/download/${SYFT_VERSION}/${tar}"
  note "Bootstrapping syft ${SYFT_VERSION} -> $CACHE_DIR"
  curl -fsSL "$url" -o "$CACHE_DIR/$tar"
  tar -C "$CACHE_DIR" -xzf "$CACHE_DIR/$tar" syft
  chmod +x "$CACHE_DIR/syft"
  rm -f "$CACHE_DIR/$tar"
  if ! need syft; then die "Failed to install syft"; fi
}

# ------------- format mapping -------------
# syft output flags
syft_flag_for_format() {
  case "$1" in
    cdx-json)  echo "cyclonedx-json" ;;
    cdx-xml)   echo "cyclonedx-xml" ;;
    spdx-json) echo "spdx-json" ;;
    spdx-tv)   echo "spdx-tag-value" ;;
    *) die "Unknown SBOM_FORMAT: $1" ;;
  esac
}

ext_for_format() {
  case "$1" in
    cdx-json)  echo "cdx.json" ;;
    cdx-xml)   echo "cdx.xml" ;;
    spdx-json) echo "spdx.json" ;;
    spdx-tv)   echo "spdx.spdx" ;;
    *) die "Unknown SBOM_FORMAT: $1" ;;
  esac
}

# ------------- generators -------------
gen_dir() {
  local dir="${1:?path required}"
  bootstrap_syft
  local fmt_flag out_ext ts base out_file
  fmt_flag="$(syft_flag_for_format "$SBOM_FORMAT")"
  out_ext="$(ext_for_format "$SBOM_FORMAT")"
  ts="$(date -u +'%Y%m%dT%H%M%SZ')"
  base="$(basename "$(realpath "$dir")")"
  mkdir -p "$SBOM_OUT_DIR/$ts"
  out_file="$SBOM_OUT_DIR/$ts/sbom-dir-${base}.${out_ext}"
  note "Generating SBOM for dir:$dir -> $out_file"
  # SOURCE_DATE_EPOCH helps reproducibility for some formats
  env SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date -u +%s)}" syft "dir:${dir}" -o "${fmt_flag}" > "$out_file"
  sha256 "$out_file" > "$out_file.sha256"
  note "Done: $out_file"
  echo "$out_file"
}

gen_image() {
  local image="${1:?image required}"
  bootstrap_syft
  local fmt_flag out_ext ts safe out_file
  fmt_flag="$(syft_flag_for_format "$SBOM_FORMAT")"
  out_ext="$(ext_for_format "$SBOM_FORMAT")"
  ts="$(date -u +'%Y%m%dT%H%M%SZ')"
  safe="$(echo "$image" | tr '/:@' '___')"
  mkdir -p "$SBOM_OUT_DIR/$ts"
  out_file="$SBOM_OUT_DIR/$ts/sbom-image-${safe}.${out_ext}"
  note "Generating SBOM for image:$image -> $out_file"
  env SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date -u +%s)}" syft "image:${image}" -o "${fmt_flag}" > "$out_file"
  sha256 "$out_file" > "$out_file.sha256"
  note "Done: $out_file"
  echo "$out_file"
}

gen_venv() {
  local venv="${1:?venv path required}"
  if [[ ! -d "$venv" ]]; then die "venv not found: $venv"; fi
  # Use syft on site-packages (works without activating venv)
  local site
  if [[ -d "$venv/lib" ]]; then
    site="$(find "$venv/lib" -type d -name site-packages | head -n1 || true)"
  fi
  if [[ -z "${site:-}" ]]; then
    warn "site-packages not found in venv, fallback to scanning venv root"
    site="$venv"
  fi
  gen_dir "$site"
}

gen_all() {
  local out=""
  # prefer image if DOCKER_IMAGE env is provided
  if [[ -n "${DOCKER_IMAGE:-}" ]]; then out="$(gen_image "$DOCKER_IMAGE")"; fi
  # scan repository root (one level up from scripts/)
  local repo_root
  repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"
  out="$(gen_dir "$repo_root")"
  # venv if exists
  if [[ -d "$repo_root/.venv" ]]; then gen_venv "$repo_root/.venv" >/dev/null; fi
  echo "$out"
}

# ------------- validate / merge / sign -------------
cmd_validate() {
  local file="${1:?bom file required}"
  if ! need cyclonedx; then
    warn "cyclonedx-cli not found; basic file presence only"
    [[ -s "$file" ]] || die "file empty: $file"
    note "File present: $file"
    exit 0
  fi
  note "Validating CycloneDX with cyclonedx-cli: $file"
  cyclonedx validate --input-file "$file"
  note "Valid"
}

cmd_merge() {
  if ! need cyclonedx; then die "cyclonedx-cli required for merge"; fi
  local out="merged.$(ext_for_format "$SBOM_FORMAT")"
  local files=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output) out="$2"; shift 2 ;;
      *) files+=("$1"); shift ;;
    esac
  done
  [[ ${#files[@]} -ge 2 ]] || die "need >=2 SBOM files to merge"
  note "Merging -> $out"
  cyclonedx merge --input-files "${files[@]}" --output-file "$out" --output-format "$(syft_flag_for_format "$SBOM_FORMAT" )" || die "merge failed"
  sha256 "$out" > "$out.sha256"
  note "Merged: $out"
}

cmd_sign() {
  local file="${1:?bom file required}"
  need cosign || die "cosign not found"
  local key="${COSIGN_KEY:-}"
  if [[ -z "$key" ]]; then
    note "No COSIGN_KEY provided; signing as blob with keyless"
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes "$file" --output-signature "$file.sig"
  else
    note "Signing with COSIGN_KEY=$key"
    cosign sign-blob --yes --key "$key" "$file" --output-signature "$file.sig"
  fi
  sha256 "$file.sig" > "$file.sig.sha256"
  note "Signature: $file.sig"
}

# ------------- usage -------------
usage() {
  cat <<'USAGE'
SBOM utility for VeilMind Core

Commands:
  gen dir <path>           Generate SBOM for directory
  gen image <name:tag>     Generate SBOM for container image
  gen venv <path>          Generate SBOM for Python virtualenv (site-packages)
  gen all                  Autodetect repo root (+ optional DOCKER_IMAGE, .venv)
  validate <file>          Validate CycloneDX SBOM (requires cyclonedx-cli)
  merge <f1> <f2> ... -o out.json   Merge multiple SBOMs (requires cyclonedx-cli)
  sign <file>              Sign SBOM file with cosign (COSIGN_KEY optional)

Environment:
  SBOM_OUT_DIR, SBOM_FORMAT, SBOM_BOOTSTRAP, SYFT_VERSION, COSIGN_KEY, COSIGN_ARGS, SOURCE_DATE_EPOCH

Examples:
  SBOM_FORMAT=spdx-json scripts/sbom.sh gen image ghcr.io/acme/app:1.2.3
  SBOM_BOOTSTRAP=1 scripts/sbom.sh gen dir .
  scripts/sbom.sh validate build/sbom/20240101T000000Z/sbom-dir-src.cdx.json
USAGE
}

# ------------- main -------------
main() {
  mkdir -p "$SBOM_OUT_DIR"
  local cmd="${1:-}"; shift || true
  case "${cmd:-}" in
    gen)
      local sub="${1:-}"; shift || true
      case "${sub:-}" in
        dir)   gen_dir "${1:-.}" ;;
        image) gen_image "${1:?image required}" ;;
        venv)  gen_venv "${1:?venv path required}" ;;
        all)   gen_all ;;
        *)     usage; die "unknown gen subcommand: ${sub:-}" ;;
      esac
      ;;
    validate) cmd_validate "${1:-}";;
    merge)    cmd_merge "$@";;
    sign)     cmd_sign "${1:-}";;
    -h|--help|help|"") usage ;;
    *)        usage; die "unknown command: ${cmd:-}" ;;
  esac
}

main "$@"
