#!/usr/bin/env bash
# SBOM generator and attestor (industrial-grade)
# Supports: CycloneDX (JSON/XML), SPDX (JSON/Tag), OCI image or filesystem targets.
# Tools: Syft (preferred), CycloneDX cdxgen (fallback/multi-ecosystem), cosign (optional attest).
# Safe-by-default: read-only operations; no execution of target code.
#
# References:
# - Syft features: container images/filesystems; outputs CycloneDX/SPDX; attestations. (see docs in README)
# - CycloneDX spec & JSON reference (bomFormat/specVersion/serialNumber).
# - SPDX spec & conformance; 2.3 formats and 3.0.1 notes.
# - cosign: SBOM in OCI / attestations for CycloneDX & SPDX.
# - cdxgen: CycloneDX generator CLI & --spec-version.
#
# Exit codes:
#   0 OK
#   2 invalid usage
#   3 missing tools
#   4 generation error
#   5 attestation error
set -Eeuo pipefail

SCRIPT_VERSION="1.4.0"
umask 022

# ----------------------------- defaults -----------------------------
DEFAULT_FORMATS="cyclonedx-json"   # comma-separated: cyclonedx-json,cyclonedx-xml,spdx-json,spdx-tag
OUT_DIR="${PWD}/sbom"
NAME=""
VERSION=""
TARGET=""
TARGET_TYPE=""   # dir|image (auto-detected if not set)
SPEC_VERSION_CDX="1.6"  # CycloneDX
SPEC_VERSION_SPDX=""    # empty -> tool default (SPDX 2.3 JSON for syft)
ATTACH_ATTESTATION="false"
COSIGN_KEY=""     # path to cosign.key (optional). If empty, cosign keyless could be used by the environment.
EXTRA_LABEL=""
MERGE="false"     # merge multiple partial SBOMs when possible (CycloneDX CLI not required; we fallback to jq concat)

# ----------------------------- logging ------------------------------
log()  { printf '%s %s\n' "[SBOM]" "$*" >&2; }
die()  { printf '%s %s\n' "[SBOM][ERROR]" "$*" >&2; exit "${2:-4}"; }

# ----------------------------- usage --------------------------------
usage() {
  cat >&2 <<'USAGE'
Usage:
  sbom.sh -t <target> [--image|--dir] [-o <outdir>] [-f <formats>] [--name <name>] [--version <ver>]
          [--cdx-spec <1.5|1.6>] [--spdx-spec <2.3>] [--attest [--cosign-key <path>]] [--label k=v]
          [--merge]

Targets:
  -t, --target <path|image>    Filesystem/project directory OR OCI/Docker image ref (e.g. alpine:3.20)
      --image                  Force treat target as image
      --dir                    Force treat target as directory

Output:
  -o, --outdir <dir>           Output directory (default: ./sbom)
  -f, --formats <list>         Comma-separated: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag
                               Default: cyclonedx-json
      --cdx-spec <ver>         CycloneDX spec version (default: 1.6)
      --spdx-spec <ver>        SPDX spec version hint (tool-dependent; default tool behavior)

Metadata:
      --name <name>            Component/application name for SBOM metadata
      --version <ver>          Component/application version
      --label k=v              Extra label to include in SBOM metadata (if tool allows)

Attestation (OCI image subjects only):
      --attest                 Create in-toto SBOM attestation with cosign (predicate = generated SBOM)
      --cosign-key <path>      Path to cosign private key (optional; environment may use keyless)

Other:
      --merge                  Attempt to merge multiple SBOMs of different tools into a combined view
      -h, --help               Show this help

Examples:
  sbom.sh -t . -o dist/sbom -f cyclonedx-json,spdx-json --name myapp --version 1.2.3
  sbom.sh -t ghcr.io/library/alpine:3.20 --image --attest
USAGE
}

# ----------------------------- deps ---------------------------------
need_cmd() { command -v "$1" >/dev/null 2>&1; }
require_any() {
  for c in "$@"; do
    if need_cmd "$c"; then return 0; fi
  done
  return 1
}

# Preferred: syft; Fallback/augment: cdxgen
detect_generators() {
  GEN_SYFT="false"
  GEN_CDXGEN="false"
  if need_cmd syft;   then GEN_SYFT="true";   fi
  if need_cmd cdxgen; then GEN_CDXGEN="true"; fi
  if [[ "$GEN_SYFT" = "false" && "$GEN_CDXGEN" = "false" ]]; then
    die "Neither 'syft' nor 'cdxgen' found in PATH" 3
  fi
}

detect_cosign() {
  COSIGN_AVAIL="false"
  if need_cmd cosign; then COSIGN_AVAIL="true"; fi
}

detect_helpers() {
  HAS_JQ="false"; HAS_SHA256="false"
  if need_cmd jq; then HAS_JQ="true"; fi
  if need_cmd sha256sum; then HAS_SHA256="true"
  elif need_cmd shasum; then HAS_SHA256="true"
  fi
}

# ----------------------------- args ---------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target) TARGET="${2:-}"; shift 2;;
      --image) TARGET_TYPE="image"; shift;;
      --dir)   TARGET_TYPE="dir"; shift;;
      -o|--outdir) OUT_DIR="${2:-}"; shift 2;;
      -f|--formats) DEFAULT_FORMATS="${2:-}"; shift 2;;
      --name) NAME="${2:-}"; shift 2;;
      --version) VERSION="${2:-}"; shift 2;;
      --cdx-spec) SPEC_VERSION_CDX="${2:-}"; shift 2;;
      --spdx-spec) SPEC_VERSION_SPDX="${2:-}"; shift 2;;
      --attest) ATTACH_ATTESTATION="true"; shift;;
      --cosign-key) COSIGN_KEY="${2:-}"; shift 2;;
      --label) EXTRA_LABEL="${2:-}"; shift 2;;
      --merge) MERGE="true"; shift;;
      -h|--help) usage; exit 0;;
      *) die "Unknown option: $1" 2;;
    esac
  done

  [[ -n "$TARGET" ]] || { usage; die "Missing --target" 2; }

  if [[ -z "$TARGET_TYPE" ]]; then
    # Heuristics: treat as image if it contains ':' with a repo or has '@sha256:'
    if [[ "$TARGET" =~ ^([[:alnum:].\/\-]+(:[[:alnum:]._\-]+)?(@sha256:[0-9a-f]{64})?)$ ]] && [[ "$TARGET" == *":"* || "$TARGET" == *"@sha256:"* ]]; then
      TARGET_TYPE="image"
    else
      TARGET_TYPE="dir"
    fi
  fi

  if [[ "$ATTACH_ATTESTATION" = "true" && "$TARGET_TYPE" != "image" ]]; then
    die "--attest is only supported for OCI/Docker image targets" 2
  fi
}

# -------------------------- filesystem ------------------------------
prepare_outdir() {
  mkdir -p "$OUT_DIR"
  [[ -w "$OUT_DIR" ]] || die "Output directory not writable: $OUT_DIR"
}

sha256_file() {
  local f="$1"
  if [[ "$HAS_SHA256" = "true" ]]; then
    if need_cmd sha256sum; then sha256sum "$f" | awk '{print $1}'
    else shasum -a 256 "$f" | awk '{print $1}'
    fi
  else
    echo "-"
  fi
}

# -------------------------- generation ------------------------------
syft_output_flag() {
  # Map format token to syft -o string
  case "$1" in
    cyclonedx-json) echo "cyclonedx-json";;
    cyclonedx-xml)  echo "cyclonedx-xml";;
    spdx-json)      echo "spdx-json";;
    spdx-tag)       echo "spdx-tag-value";;
    *) return 1;;
  esac
}

cdxgen_args_for() {
  # Map to cdxgen args; cdxgen emits CycloneDX only
  case "$1" in
    cyclonedx-json) echo "--format json";;
    cyclonedx-xml)  echo "--format xml";;
    *) return 1;;
  esac
}

safe_name() {
  # Compose base filename
  local base
  if [[ -n "$NAME" && -n "$VERSION" ]]; then
    base="${NAME}-${VERSION}"
  elif [[ -n "$NAME" ]]; then
    base="${NAME}"
  else
    base="$(basename "$TARGET" | tr '@/:' '__')"
  fi
  echo "$base"
}

annotate_metadata_json() {
  # Add tool metadata into CycloneDX/SPDX JSON if jq is available
  local file="$1"
  [[ "$HAS_JQ" = "true" ]] || return 0
  tmp="$(mktemp)"
  jq --arg v "$SCRIPT_VERSION" \
     --arg name "$NAME" \
     --arg ver "$VERSION" \
     '
     .metadata = (.metadata // {}) |
     .metadata.tools = ((.metadata.tools // []) + [{"name":"sbom.sh","vendor":"Aethernova","version":$v}]) |
     (if $name != "" then .metadata.component = ((.metadata.component // {}) + {"name":$name}) else . end) |
     (if $ver  != "" then .metadata.component = ((.metadata.component // {}) + {"version":$ver}) else . end)
     ' "$file" > "$tmp" && mv "$tmp" "$file"
}

generate_with_syft() {
  local fmt="$1" out="$2"
  local flag
  flag="$(syft_output_flag "$fmt")" || return 1

  local src="$TARGET"
  # Syft accepts filesystem paths or images (registry/daemon) directly
  if [[ "$TARGET_TYPE" = "dir" ]]; then
    src="dir:$TARGET"
  else
    src="$TARGET"
  fi

  local extra=()
  # CycloneDX spec version hint (syft aligns to latest; no strict pin flag yet)
  # SPDX JSON/tag are supported by syft directly.
  if [[ -n "$EXTRA_LABEL" ]]; then
    extra+=(--scope all) # harmless; include everything deterministically
  fi

  log "Generating via syft ($flag) → $out"
  syft "$src" -o "$flag" > "$out"
}

generate_with_cdxgen() {
  local fmt="$1" out="$2"
  local fmtarg
  fmtarg="$(cdxgen_args_for "$fmt")" || return 1

  local target_arg=("$TARGET")
  local specarg=()
  if [[ -n "$SPEC_VERSION_CDX" ]]; then
    specarg=(--spec-version "$SPEC_VERSION_CDX")
  fi

  # cdxgen supports directory and image refs; -r recurses, tries to auto-detect ecosystems
  log "Generating via cdxgen ($fmtarg ${specarg[*]}) → $out"
  cdxgen -r ${specarg[*]:-} $fmtarg -o "$out" "${target_arg[@]}"
}

do_generate() {
  local formats_csv="$1"
  IFS=',' read -r -a formats <<<"$formats_csv"
  local base; base="$(safe_name)"
  local outputs=()

  for fmt in "${formats[@]}"; do
    case "$fmt" in
      cyclonedx-json)  ext="cdx.json";;
      cyclonedx-xml)   ext="cdx.xml";;
      spdx-json)       ext="spdx.json";;
      spdx-tag)        ext="spdx.tag";;
      *) die "Unsupported format token: $fmt" 2;;
    esac
    out="$OUT_DIR/${base}.${ext}"

    # Prefer Syft where possible; fall back to cdxgen for CycloneDX
    if [[ "$GEN_SYFT" = "true" ]] && generate_with_syft "$fmt" "$out"; then
      :
    else
      if [[ "$fmt" == cyclonedx-* && "$GEN_CDXGEN" = "true" ]]; then
        generate_with_cdxgen "$fmt" "$out" || die "cdxgen failed for $fmt" 4
      else
        die "No generator available for format: $fmt" 3
      fi
    fi

    # Minimal spec conformance checks (structure-level) can be added here.
    if [[ "$fmt" == "cyclonedx-json" || "$fmt" == "spdx-json" ]]; then
      annotate_metadata_json "$out" || true
    fi

    # Hash file
    if [[ "$HAS_SHA256" = "true" ]]; then
      echo "$(sha256_file "$out")  $(basename "$out")" > "$out.sha256"
    fi

    outputs+=("$out")
  done

  # Optional merge (best-effort, JSON-only)
  if [[ "$MERGE" = "true" ]]; then
    merged="$OUT_DIR/${base}.merged.json"
    if [[ "$HAS_JQ" = "true" ]]; then
      log "Merging JSON SBOMs (best-effort) → $merged"
      jq -s '
        # naive union for package lists if CycloneDX; keep first as base
        def merge_cdx(a;b):
          a as $a | b as $b |
          if ($a.bomFormat? == "CycloneDX") and ($b.bomFormat? == "CycloneDX") then
            $a | .components = ((.components // []) + ($b.components // []))
          else $a end;
        reduce .[] as $doc ({}; if . == {} then $doc else merge_cdx(.; $doc) end)
      ' "${outputs[@]}" > "$merged" || log "Merge failed; leaving separate files."
    else
      log "jq not found; --merge skipped."
    fi
  fi

  printf '%s\n' "${outputs[@]}"
}

# ------------------------- attestation ------------------------------
attest_with_cosign() {
  local sbom_file="$1"
  [[ "$COSIGN_AVAIL" = "true" ]] || die "cosign not found; cannot --attest" 5

  # Determine predicate type from extension
  local ptype="spdx"
  if [[ "$sbom_file" == *.cdx.json || "$sbom_file" == *.cdx.xml ]]; then
    ptype="cyclonedx"
  elif [[ "$sbom_file" == *.spdx.json || "$sbom_file" == *.spdx.tag ]]; then
    ptype="spdx"
  fi

  # cosign attach attestation for image SUBJECT = $TARGET
  local args=(attest --type "$ptype" --predicate "$sbom_file" "$TARGET")
  if [[ -n "$COSIGN_KEY" ]]; then
    args+=(--key "$COSIGN_KEY")
  fi
  log "cosign ${args[*]}"
  cosign "${args[@]}"
}

# ----------------------------- main ---------------------------------
main() {
  parse_args "$@"
  detect_generators
  detect_cosign
  detect_helpers
  prepare_outdir

  log "Start SBOM generation v$SCRIPT_VERSION"
  log "Target: $TARGET ($TARGET_TYPE); Out: $OUT_DIR"
  [[ -n "$NAME" ]]    && log "Name: $NAME"
  [[ -n "$VERSION" ]] && log "Version: $VERSION"
  [[ -n "$EXTRA_LABEL" ]] && log "Label: $EXTRA_LABEL"

  outputs="$(do_generate "$DEFAULT_FORMATS")" || exit $?
  log "Generated files:"
  printf ' - %s\n' $outputs >&2

  if [[ "$ATTACH_ATTESTATION" = "true" ]]; then
    # choose the first generated SBOM as predicate (prefer CycloneDX JSON)
    chosen=""
    for f in $outputs; do
      if [[ "$f" == *.cdx.json ]]; then chosen="$f"; break; fi
    done
    if [[ -z "$chosen" ]]; then chosen="$(echo "$outputs" | head -n1)"; fi
    log "Attesting SBOM with cosign: predicate=$chosen subject=$TARGET"
    attest_with_cosign "$chosen" || die "cosign attestation failed" 5
  fi

  log "Done."
}

main "$@"
