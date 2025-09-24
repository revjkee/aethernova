# neuroforge-core/scripts/download_models.sh
#!/usr/bin/env bash
# Industrial model downloader for NeuroForge Core
# Features:
#  - Manifest-driven (JSON/YAML/TSV) downloads with checksum/signature verification
#  - HTTP(S)/S3/GCS/HuggingFace sources, resumable, parallel
#  - Safe cache, atomic publish, archive extraction, retries, logging, locking
#  - Idempotent and CI-friendly
#
# Usage:
#   scripts/download_models.sh -m manifest.json -d models/ [-c .cache/models] [-j 4] [-r 5]
#   scripts/download_models.sh -m manifest.yaml --dry-run
#
# Manifest schema (JSON/YAML array of objects). Minimal example:
# [
#   {
#     "name": "bert-base-uncased",
#     "version": "1.0.0",
#     "url": "https://huggingface.co/google-bert/bert-base-uncased/resolve/main/pytorch_model.bin",
#     "sha256": "HEX...",
#     "target": "bert/base-uncased/",
#     "unpack": false
#   },
#   {
#     "name": "my-archive",
#     "version": "2024-10-01",
#     "urls": ["https://host/model.tar.gz", "https://mirror/model.tar.gz"],
#     "sha512": "HEX...",
#     "target": "my-archive/",
#     "unpack": true,
#     "strip": 1
#   },
#   {
#     "name": "hf-example",
#     "hf_repo": "TheBloke/Mistral-7B-Instruct-v0.2-GGUF",
#     "path_in_repo": "mistral-7b-instruct-v0.2.Q4_K_M.gguf",
#     "hf_revision": "main",
#     "sha256": "HEX...",
#     "target": "mistral/",
#     "unpack": false
#   },
#   {
#     "name": "s3-checkpoint",
#     "s3_uri": "s3://mybucket/models/ckpt.pt",
#     "sha256": "HEX...",
#     "target": "ckpts/",
#     "unpack": false
#   },
#   {
#     "name": "signed-asset",
#     "url": "https://host/weights.bin",
#     "gpg_sig_url": "https://host/weights.bin.asc",
#     "gpg_keyring": ".keys/trusted.gpg",
#     "sha256": "HEX...",
#     "target": "signed/",
#     "unpack": false
#   }
# ]
#
# TSV fallback (no jq/yq): columns: name <TAB> url <TAB> sha256 <TAB> target <TAB> unpack(true|false) [strip]
#
# Environment:
#   MODELS_DIR, CACHE_DIR, CONCURRENCY, RETRIES, TIMEOUT, NO_COLOR, HTTP_PROXY/HTTPS_PROXY, HF_TOKEN, AWS_*, CLOUDSDK_*, S3_ANON
#   CHECKSUM_STRICT=1 (fail if checksum missing), GPG_STRICT=1 (require signature if sig URL given)
#   USE_ARIA2=0/1, DRY_RUN=1

set -Eeuo pipefail
IFS=$'\n\t'

# ------------ Defaults ------------
MODELS_DIR="${MODELS_DIR:-models}"
CACHE_DIR="${CACHE_DIR:-.cache/models}"
LOG_DIR="${LOG_DIR:-logs}"
CONCURRENCY="${CONCURRENCY:-4}"
RETRIES="${RETRIES:-5}"
TIMEOUT="${TIMEOUT:-600}"
USE_ARIA2="${USE_ARIA2:-1}"
CHECKSUM_STRICT="${CHECKSUM_STRICT:-0}"
GPG_STRICT="${GPG_STRICT:-0}"
DRY_RUN="${DRY_RUN:-0}"

mkdir -p "$MODELS_DIR" "$CACHE_DIR" "$LOG_DIR"

TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$LOG_DIR/download_models-$TS.log"

# ------------ Colors ------------
if [[ "${NO_COLOR:-0}" != "0" ]] || ! command -v tput >/dev/null 2>&1; then
  C_BOLD=""; C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_RST=""
else
  C_BOLD="$(tput bold)"; C_RED="$(tput setaf 1)"; C_YEL="$(tput setaf 3)"; C_GRN="$(tput setaf 2)"; C_CYN="$(tput setaf 6)"; C_RST="$(tput sgr0)"
fi

# ------------ Logging ------------
log()   { printf "%s [%s] %s\n" "$(date -Iseconds)" "$1" "$2" | tee -a "$LOG_FILE" >&2; }
info()  { log "${C_CYN}INFO${C_RST}" "$*"; }
succ()  { log "${C_GRN}OK${C_RST}" "$*"; }
warn()  { log "${C_YEL}WARN${C_RST}" "$*"; }
err()   { log "${C_RED}ERR${C_RST}" "$*"; }
die()   { err "$*"; exit 1; }

# ------------ Cleanup & Lock ------------
TMP_ROOT="$(mktemp -d -t nf-models-XXXXXX)"
cleanup() { rm -rf "$TMP_ROOT" 2>/dev/null || true; }
trap cleanup EXIT

LOCK_FILE="${CACHE_DIR}/.download.lock"
if command -v flock >/dev/null 2>&1; then
  exec 200>"$LOCK_FILE"
  flock -n 200 || die "Another download process holds the lock: $LOCK_FILE"
else
  # Portable lock via directory
  if ! mkdir "$LOCK_FILE" 2>/dev/null; then
    die "Another download process holds the lock (dir): $LOCK_FILE"
  fi
  trap 'rmdir "$LOCK_FILE" 2>/dev/null || true' EXIT
fi

# ------------ CLI ------------
MANIFEST=""
usage() {
  cat <<EOF
Usage: $0 -m <manifest.{json|yaml|yml|tsv|csv}> [options]

Options:
  -m, --manifest FILE     Manifest file (JSON/YAML/TSV)
  -d, --dest DIR          Models directory (default: $MODELS_DIR)
  -c, --cache DIR         Cache directory (default: $CACHE_DIR)
  -j, --jobs N            Parallel jobs (default: $CONCURRENCY)
  -r, --retries N         Retries per artifact (default: $RETRIES)
  -t, --timeout SEC       Network timeout seconds (default: $TIMEOUT)
      --checksum-strict   Fail if checksum missing
      --gpg-strict        Fail if signature check fails/enforced
      --no-aria2          Disable aria2 even if available
      --dry-run           Print actions without executing
  -h, --help              Show help

Environment:
  HTTP(S)_PROXY, HF_TOKEN, AWS_*, GOOGLE_APPLICATION_CREDENTIALS, S3_ANON=1, NO_COLOR=1
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--manifest) MANIFEST="$2"; shift 2;;
    -d|--dest) MODELS_DIR="$2"; shift 2;;
    -c|--cache) CACHE_DIR="$2"; shift 2;;
    -j|--jobs) CONCURRENCY="$2"; shift 2;;
    -r|--retries) RETRIES="$2"; shift 2;;
    -t|--timeout) TIMEOUT="$2"; shift 2;;
    --checksum-strict) CHECKSUM_STRICT=1; shift;;
    --gpg-strict) GPG_STRICT=1; shift;;
    --no-aria2) USE_ARIA2=0; shift;;
    --dry-run) DRY_RUN=1; shift;;
    -h|--help) usage; exit 0;;
    *) err "Unknown argument: $1"; usage; exit 2;;
  esac
done

[[ -n "$MANIFEST" ]] || { usage; exit 2; }
[[ -f "$MANIFEST" ]] || die "Manifest not found: $MANIFEST"

# ------------ Downloader selection ------------
HAVE_ARIA2=0
if [[ "$USE_ARIA2" == "1" ]] && command -v aria2c >/dev/null 2>&1; then
  HAVE_ARIA2=1
fi
HAVE_CURL=0; command -v curl >/dev/null 2>&1 && HAVE_CURL=1
HAVE_WGET=0; command -v wget >/dev/null 2>&1 && HAVE_WGET=1
(( HAVE_CURL + HAVE_WGET + HAVE_ARIA2 > 0 )) || die "No downloader found (aria2c/curl/wget)."

download_http() {
  local url="$1" out="$2"
  local attempt="${3:-1}" total="${4:-$RETRIES}"
  if [[ "$DRY_RUN" == "1" ]]; then info "[DRY] GET $url -> $out"; return 0; fi
  mkdir -p "$(dirname "$out")"
  if (( HAVE_ARIA2 )); then
    aria2c \
      --file-allocation=none --auto-file-renaming=false \
      --summary-interval=0 --enable-color=false \
      --max-connection-per-server=16 --split=16 --min-split-size=1M \
      --timeout="$TIMEOUT" --retry-wait=2 --max-tries="$RETRIES" \
      -c -o "$(basename "$out")" -d "$(dirname "$out")" "$url" >>"$LOG_FILE" 2>&1 && return 0
  elif (( HAVE_CURL )); then
    curl -fL --retry "$RETRIES" --retry-all-errors --retry-delay 2 --connect-timeout 15 --max-time "$TIMEOUT" -C - \
      -o "$out" "$url" >>"$LOG_FILE" 2>&1 && return 0
  elif (( HAVE_WGET )); then
    wget -c --tries="$RETRIES" --timeout="$TIMEOUT" -O "$out" "$url" >>"$LOG_FILE" 2>&1 && return 0
  fi
  if (( attempt < total )); then
    warn "Retry $attempt/$total for $url"
    sleep 2
    download_http "$url" "$out" "$((attempt+1))" "$total"
  else
    return 1
  fi
}

download_s3() {
  local s3uri="$1" out="$2"
  if [[ "$DRY_RUN" == "1" ]]; then info "[DRY] aws s3 cp $s3uri $out"; return 0; fi
  command -v aws >/dev/null 2>&1 || die "aws CLI not found for S3 URI: $s3uri"
  mkdir -p "$(dirname "$out")"
  local extra=()
  [[ "${S3_ANON:-0}" == "1" ]] && extra+=(--no-sign-request)
  aws s3 cp "${extra[@]}" "$s3uri" "$out" >>"$LOG_FILE" 2>&1
}

download_gs() {
  local gsuri="$1" out="$2"
  if [[ "$DRY_RUN" == "1" ]]; then info "[DRY] gsutil cp $gsuri $out"; return 0; fi
  command -v gsutil >/dev/null 2>&1 || die "gsutil not found for GCS URI: $gsuri"
  mkdir -p "$(dirname "$out")"
  gsutil cp "$gsuri" "$out" >>"$LOG_FILE" 2>&1
}

download_hf() {
  local repo="$1" path_in_repo="$2" rev="$3" out="$4"
  if [[ "$DRY_RUN" == "1" ]]; then info "[DRY] huggingface-cli download $repo $path_in_repo --revision $rev -> $out"; return 0; fi
  if command -v huggingface-cli >/dev/null 2>&1; then
    mkdir -p "$(dirname "$out")"
    # huggingface-cli download returns path; we move it into place
    local dest_dir; dest_dir="$(dirname "$out")"
    huggingface-cli download "$repo" "$path_in_repo" --revision "${rev:-main}" --local-dir "$dest_dir" >>"$LOG_FILE" 2>&1 || return 1
    # File will appear at $dest_dir/$path_in_repo
    [[ -f "$out" ]] || { # move if nested
      mkdir -p "$(dirname "$out")"
      mv -f "$dest_dir/$path_in_repo" "$out" 2>/dev/null || true
    }
  else
    die "huggingface-cli not found for hf repo: $repo"
  fi
}

# ------------ Verify ------------
sha256_hex() { command -v shasum >/dev/null 2>&1 && shasum -a 256 "$1" | awk '{print $1}' || sha256sum "$1" | awk '{print $1}'; }
sha512_hex() { command -v shasum >/dev/null 2>&1 && shasum -a 512 "$1" | awk '{print $1}' || sha512sum "$1" | awk '{print $1}'; }

verify_checksum() {
  local file="$1" want256="${2:-}" want512="${3:-}"
  if [[ -n "$want256" ]]; then
    local got; got="$(sha256_hex "$file")"
    [[ "$got" == "$want256" ]] || { err "SHA256 mismatch for $(basename "$file")"; return 1; }
  fi
  if [[ -n "$want512" ]]; then
    local got; got="$(sha512_hex "$file")"
    [[ "$got" == "$want512" ]] || { err "SHA512 mismatch for $(basename "$file")"; return 1; }
  fi
  if [[ -z "$want256" && -z "$want512" && "$CHECKSUM_STRICT" == "1" ]]; then
    err "Checksum missing and CHECKSUM_STRICT=1"
    return 1
  fi
  return 0
}

verify_gpg() {
  local file="$1" sig_url="$2" keyring="$3"
  [[ -n "$sig_url" ]] || return 0
  local sig="$TMP_ROOT/$(basename "$file").asc"
  download_http "$sig_url" "$sig" || { err "Failed to fetch signature: $sig_url"; return 1; }
  if [[ "$DRY_RUN" == "1" ]]; then info "[DRY] gpg --verify with keyring $keyring"; return 0; fi
  command -v gpg >/dev/null 2>&1 || { err "gpg not found"; return 1; }
  local gpg_args=(--batch --no-tty --status-fd 1)
  [[ -n "$keyring" ]] && gpg_args+=(--keyring "$keyring" --trust-model always)
  if gpg "${gpg_args[@]}" --verify "$sig" "$file" >>"$LOG_FILE" 2>&1; then
    return 0
  else
    [[ "$GPG_STRICT" == "1" ]] && return 1 || { warn "GPG verify failed (non-strict)"; return 0; }
  fi
}

# ------------ Extraction ------------
extract_archive() {
  local file="$1" dest="$2" strip="${3:-0}"
  if [[ "$DRY_RUN" == "1" ]]; then info "[DRY] extract $file -> $dest (strip=$strip)"; return 0; fi
  mkdir -p "$dest"
  case "$file" in
    *.tar.gz|*.tgz)   tar -xzf "$file" -C "$dest" --strip-components="$strip" ;;
    *.tar.bz2|*.tbz2) tar -xjf "$file" -C "$dest" --strip-components="$strip" ;;
    *.tar.zst|*.tzst) command -v zstd >/dev/null 2>&1 || die "zstd not found"; zstd -dc "$file" | tar -x -C "$dest" --strip-components="$strip" ;;
    *.tar.xz|*.txz)   tar -xJf "$file" -C "$dest" --strip-components="$strip" ;;
    *.tar)            tar -xf "$file" -C "$dest" --strip-components="$strip" ;;
    *.zip)            command -v unzip >/dev/null 2>&1 || die "unzip not found"; unzip -o "$file" -d "$dest" >>"$LOG_FILE" 2>&1 ;;
    *.gz)             gunzip -c "$file" > "$dest/$(basename "${file%.gz}")" ;;
    *.bz2)            bunzip2 -c "$file" > "$dest/$(basename "${file%.bz2}")" ;;
    *.xz)             unxz -c "$file" > "$dest/$(basename "${file%.xz}")" ;;
    *)                warn "Unknown archive type: $file; copying as-is"; cp -f "$file" "$dest/" ;;
  esac
}

# ------------ Manifest parsing ------------
ext="${MANIFEST##*.}"
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1
HAVE_YQ=0; command -v yq >/dev/null 2>&1 && HAVE_YQ=1

# Normalize manifest to NDJSON (one JSON per line) for iteration
NDJSON="$TMP_ROOT/manifest.ndjson"

normalize_manifest() {
  case "$ext" in
    json)
      (( HAVE_JQ )) || die "jq required for JSON manifest"
      jq -c '.[]' "$MANIFEST" > "$NDJSON"
      ;;
    yaml|yml)
      (( HAVE_YQ )) || die "yq required for YAML manifest"
      yq -o=json '.[]' "$MANIFEST" | jq -c '.' > "$NDJSON"
      ;;
    tsv|csv)
      # Expect header or fixed positions. We will parse as TSV.
      awk -F'\t' 'NF>=5 && $1 !~ /^#/ { printf("{\"name\":\"%s\",\"url\":\"%s\",\"sha256\":\"%s\",\"target\":\"%s\",\"unpack\":%s", $1,$2,$3,$4,$5);
        if (NF>=6 && $6!="") printf(",\"strip\":%d",$6);
        printf("}\n"); }' "$MANIFEST" > "$NDJSON"
      ;;
    *)
      die "Unsupported manifest extension: .$ext"
      ;;
  esac
}
normalize_manifest

# ------------ Work item processing ------------
process_item() {
  local json="$1"
  # Fields
  local name url urls sha256 sha512 target unpack strip gpg_sig gpg_ring s3 gs hf_repo hf_rev path_in_repo size chmod_mode
  name="$(jq -r '.name // empty' <<<"$json")"
  url="$(jq -r '.url // empty' <<<"$json")"
  urls="$(jq -c '.urls // empty' <<<"$json")"
  sha256="$(jq -r '.sha256 // empty' <<<"$json")"
  sha512="$(jq -r '.sha512 // empty' <<<"$json")"
  target="$(jq -r '.target // empty' <<<"$json")"
  unpack="$(jq -r '.unpack // false' <<<"$json")"
  strip="$(jq -r '.strip // 0' <<<"$json")"
  gpg_sig="$(jq -r '.gpg_sig_url // empty' <<<"$json")"
  gpg_ring="$(jq -r '.gpg_keyring // empty' <<<"$json")"
  s3="$(jq -r '.s3_uri // empty' <<<"$json")"
  gs="$(jq -r '.gcs_uri // empty' <<<"$json")"
  hf_repo="$(jq -r '.hf_repo // empty' <<<"$json")"
  hf_rev="$(jq -r '.hf_revision // "main"' <<<"$json")"
  path_in_repo="$(jq -r '.path_in_repo // empty' <<<"$json")"
  size="$(jq -r '.size // empty' <<<"$json")"
  chmod_mode="$(jq -r '.chmod // empty' <<<"$json")"

  [[ -n "$target" ]] || target="."
  local pub_dir="$MODELS_DIR/$target"
  local cache_dir="$CACHE_DIR/$name"
  mkdir -p "$pub_dir" "$cache_dir"

  info "Processing: ${name:-<unnamed>} -> $target"

  local src_file=""
  # Determine download source
  if [[ -n "$hf_repo" && -n "$path_in_repo" ]]; then
    src_file="$cache_dir/$(basename "$path_in_repo")"
    download_hf "$hf_repo" "$path_in_repo" "$hf_rev" "$src_file" || { err "HF download failed: $hf_repo/$path_in_repo"; return 1; }
  elif [[ -n "$s3" ]]; then
    src_file="$cache_dir/$(basename "$s3")"
    download_s3 "$s3" "$src_file" || { err "S3 download failed: $s3"; return 1; }
  elif [[ -n "$gs" ]]; then
    src_file="$cache_dir/$(basename "$gs")"
    download_gs "$gs" "$src_file" || { err "GCS download failed: $gs"; return 1; }
  else
    # http(s) with optional mirrors
    local primary="$url"
    local mirrors=()
    if [[ -n "$urls" && "$urls" != "null" ]]; then
      # first element acts as primary if url empty
      mapfile -t mirrors < <(jq -r '.[]' <<<"$urls")
      if [[ -z "$primary" && "${#mirrors[@]}" -gt 0 ]]; then
        primary="${mirrors[0]}"; mirrors=("${mirrors[@]:1}")
      fi
    fi
    [[ -n "$primary" ]] || { err "No URL provided for $name"; return 1; }
    src_file="$cache_dir/$(basename "$primary")"
    if ! download_http "$primary" "$src_file"; then
      warn "Primary failed, trying mirrors..."
      local ok=0
      for m in "${mirrors[@]}"; do
        if download_http "$m" "$src_file"; then ok=1; break; fi
      done
      [[ "$ok" == "1" ]] || { err "All URLs failed for $name"; return 1; }
    fi
  fi

  # Optional size check
  if [[ -n "$size" && "$DRY_RUN" != "1" ]]; then
    local got_size; got_size="$(stat -c%s "$src_file" 2>/dev/null || stat -f%z "$src_file")"
    if [[ "$got_size" != "$size" ]]; then
      warn "Size mismatch for $name: expected $size, got $got_size"
    fi
  fi

  # Verify checksum
  verify_checksum "$src_file" "$sha256" "$sha512" || return 1

  # Verify signature if provided
  verify_gpg "$src_file" "$gpg_sig" "$gpg_ring" || { err "GPG verification failed for $name"; return 1; }

  # Publish
  if [[ "$unpack" == "true" || "$unpack" == "1" ]]; then
    local tmp_dest="$TMP_ROOT/pub-$name"
    extract_archive "$src_file" "$tmp_dest" "$strip"
    # Atomic publish
    local stamp="$pub_dir/.ok"
    if [[ "$DRY_RUN" != "1" ]]; then
      mkdir -p "$pub_dir"
      rsync -a --delete "$tmp_dest"/ "$pub_dir"/ >>"$LOG_FILE" 2>&1
      date -Iseconds > "$stamp"
    else
      info "[DRY] rsync $tmp_dest -> $pub_dir"
    fi
  else
    # Single file publish
    local dest="$pub_dir/$(basename "$src_file")"
    if [[ "$DRY_RUN" != "1" ]]; then
      mkdir -p "$pub_dir"
      rsync -a "$src_file" "$dest" >>"$LOG_FILE" 2>&1
      [[ -n "$chmod_mode" && "$chmod_mode" != "null" ]] && chmod "$chmod_mode" "$dest" || true
    else
      info "[DRY] copy $src_file -> $dest"
    fi
  fi

  succ "Done: ${name:-<unnamed>}"
  return 0
}

# ------------ Concurrency driver ------------
TOTAL="$(wc -l < "$NDJSON" | tr -d ' ')"
info "Manifest items: $TOTAL; jobs=$CONCURRENCY; cache=$CACHE_DIR; dest=$MODELS_DIR"
FAILED=0

if (( CONCURRENCY > 1 )); then
  # Use xargs -P for portability
  export -f info warn err succ die download_http download_s3 download_gs download_hf verify_checksum verify_gpg extract_archive process_item sha256_hex sha512_hex
  export MODELS_DIR CACHE_DIR TMP_ROOT LOG_FILE DRY_RUN RETRIES TIMEOUT HAVE_ARIA2 HAVE_CURL HAVE_WGET CHECKSUM_STRICT GPG_STRICT
  # GNU awk is not guaranteed; pass JSON lines directly
  if ! xargs -P "$CONCURRENCY" -I{} bash -c 'process_item "$@"' _ {} < "$NDJSON"; then
    FAILED=1
  fi
else
  while IFS= read -r line; do
    process_item "$line" || FAILED=1
  done < "$NDJSON"
fi

if [[ "$FAILED" == "0" ]]; then
  succ "All items completed successfully. Log: $LOG_FILE"
  exit 0
else
  err "Some items failed. See log: $LOG_FILE"
  exit 3
fi
