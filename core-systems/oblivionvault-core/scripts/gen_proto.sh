#!/usr/bin/env bash
# ==============================================================================
# Protobuf/gRPC codegen for oblivionvault-core
# Deterministic, cache-friendly, works locally and in CI.
# ==============================================================================
set -euo pipefail
IFS=$'\n\t'

# -------------
# Defaults
# -------------
REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$REPO_ROOT"

# Tooling selection:
#   MODE=local  -> use local buf binary
#   MODE=docker -> use Buf container (hermetic)
MODE="${MODE:-docker}"

# Buf container image (pinned; override via env if needed)
BUF_IMAGE="${BUF_IMAGE:-ghcr.io/bufbuild/buf:1.40.0}"

# Docker runtime options
DOCKER_PLATFORM="${DOCKER_PLATFORM:-}"          # e.g., "linux/amd64" on Apple Silicon (optional)
DOCKER_UIDGID="${DOCKER_UIDGID:-$(id -u):$(id -g)}"

# Cache mounts (for docker mode)
XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
BUF_CACHE_DIR="${BUF_CACHE_DIR:-$XDG_CACHE_HOME/buf}"
mkdir -p "$BUF_CACHE_DIR"

# Concurrency control (Buf honors GOMAXPROCS for plugin execution fanout)
GOMAXPROCS="${GOMAXPROCS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
export GOMAXPROCS

# -------------
# Logging utils
# -------------
if [[ -t 1 ]]; then
  C_BOLD="$(printf '\033[1m')"; C_RED="$(printf '\033[31m')"
  C_GRN="$(printf '\033[32m')"; C_YEL="$(printf '\033[33m')"
  C_BLU="$(printf '\033[34m')"; C_RST="$(printf '\033[0m')"
else
  C_BOLD=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_RST=""
fi

log()     { printf "%s[%s]%s %s\n" "$C_BOLD" "$1" "$C_RST" "${*:2}"; }
info()    { log "${C_BLU}info${C_RST}" "$@"; }
warn()    { log "${C_YEL}warn${C_RST}" "$@"; }
error()   { log "${C_RED}error${C_RST}" "$@"; }
success() { log "${C_GRN}ok${C_RST}" "$@"; }

die() { error "$@"; exit 1; }

# -------------
# Usage
# -------------
usage() {
  cat <<'EOF'
Usage:
  gen_proto.sh [--generate|--verify|--clean] [--mode local|docker] [--print-template]

Commands:
  --generate        run code generation via buf
  --verify          run generation and fail if it produces changes (CI gate)
  --clean           remove generated outputs (parsed from buf.gen.yaml)
  --print-template  print a safe buf.gen.yaml template to stdout

Options:
  --mode <m>        'local' (use local buf) or 'docker' (default; hermetic)
Env vars:
  MODE=docker|local         same as --mode
  BUF_IMAGE=<ref>           default: ghcr.io/bufbuild/buf:1.40.0
  DOCKER_PLATFORM=<plat>    e.g. linux/amd64 (for Apple Silicon)
  GOMAXPROCS=<n>            parallelism for plugins
  BUF_CACHE_DIR=<dir>       cache mount for docker mode
  REPO_ROOT=<path>          repository root (auto-detected)

Requirements:
  - buf.yaml in repo root (module definition)
  - buf.gen.yaml in repo root (plugin/out config). If absent, use --print-template.

Examples:
  MODE=docker scripts/gen_proto.sh --generate
  MODE=local  scripts/gen_proto.sh --verify
  scripts/gen_proto.sh --clean
  scripts/gen_proto.sh --print-template > buf.gen.yaml
EOF
}

# -------------
# Arg parse
# -------------
CMD=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --generate) CMD="generate"; shift ;;
    --verify)   CMD="verify";   shift ;;
    --clean)    CMD="clean";    shift ;;
    --print-template) CMD="template"; shift ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ -z "${CMD:-}" ]] && { usage; exit 2; }

# -------------
# Preconditions
# -------------
[[ -f buf.yaml ]] || die "buf.yaml not found in $REPO_ROOT"
if [[ "$CMD" != "template" ]]; then
  [[ -f buf.gen.yaml ]] || die "buf.gen.yaml not found. Generate a template via --print-template."
fi

# -------------
# Buf runner
# -------------
buf_local() {
  command -v buf >/dev/null 2>&1 || die "buf not found on PATH; set MODE=docker or install buf"
  BUF_BIN="buf"
  "$BUF_BIN" "$@"
}

buf_docker() {
  command -v docker >/dev/null 2>&1 || die "docker not available for MODE=docker"
  # Compose docker args
  local platform_args=()
  [[ -n "$DOCKER_PLATFORM" ]] && platform_args=(--platform "$DOCKER_PLATFORM")
  docker run --rm -u "$DOCKER_UIDGID" \
    "${platform_args[@]}" \
    -e "BUF_CACHE_DIR=/home/buf/.cache" \
    -e "GOMAXPROCS=$GOMAXPROCS" \
    -v "$REPO_ROOT:/work" \
    -v "$BUF_CACHE_DIR:/home/buf/.cache" \
    -w /work \
    "$BUF_IMAGE" "$@"
}

buf() {
  if [[ "$MODE" == "local" ]]; then
    buf_local "$@"
  else
    buf_docker "$@"
  fi
}

# -------------
# Helpers
# -------------
git_dirty() {
  # Return 0 if there are staged or unstaged changes
  if ! command -v git >/dev/null 2>&1; then return 1; fi
  ! git diff --quiet || ! git diff --cached --quiet
}

extract_out_dirs() {
  # Parse buf.gen.yaml to list 'out:' directories (best-effort without yq)
  awk '
    $1 ~ /^out:/ {
      # strip "out:" and possible quotes
      sub(/^out:[[:space:]]*/, "", $0)
      gsub(/["'\'']/, "", $0)
      print $0
    }' buf.gen.yaml | sed 's/[[:space:]]*$//g' | sort -u
}

clean_outputs() {
  local dirs
  mapfile -t dirs < <(extract_out_dirs)
  if [[ "${#dirs[@]}" -eq 0 ]]; then
    warn "no out: entries detected in buf.gen.yaml; nothing to clean"
    return 0
  fi
  for d in "${dirs[@]}"; do
    if [[ -d "$d" ]]; then
      info "removing generated dir: $d"
      rm -rf -- "$d"
    else
      warn "skip missing dir: $d"
    fi
  done
}

# -------------
# Commands
# -------------
cmd_generate() {
  info "running buf generate (mode=$MODE, image=${BUF_IMAGE##*/}, procs=$GOMAXPROCS)"
  buf --version || true
  # Validate module before generation
  buf lint
  buf build
  # Generate
  buf generate
  success "codegen finished"
}

cmd_verify() {
  info "verifying codegen is up-to-date"
  if git_dirty; then
    warn "working tree has changes; verification will include them"
  fi
  # Record pre-state
  local pre
  pre="$(git rev-parse --verify HEAD 2>/dev/null || echo "NO-GIT")"
  # Run generation
  cmd_generate
  # Fail if diff appeared
  if git_dirty; then
    error "codegen produced changes. Please commit generated files."
    # Print concise diff names to help CI logs
    git --no-pager status --porcelain || true
    exit 3
  fi
  success "no changes after generation"
}

cmd_clean() {
  info "cleaning generated outputs (parsed from buf.gen.yaml)"
  clean_outputs
  success "clean done"
}

cmd_template() {
  cat <<'YAML'
# buf.gen.yaml template (safe defaults; adjust to your project).
# This file intentionally avoids asserting specific remote plugin IDs.
# Replace <...> with values that match your codegen toolchain.
version: v1
managed:
  enabled: true
  # Fill a proper Go package prefix if you generate Go code:
  # go_package_prefix:
  #   default: github.com/<org>/oblivionvault-core/gen/go
plugins:
  # --- Go (example) ---
  # - plugin: <go-plugin-id>
  #   out: gen/go
  # - plugin: <go-grpc-plugin-id>
  #   out: gen/go
  #
  # --- Python (example) ---
  # - plugin: <python-plugin-id>
  #   out: gen/python
  # - plugin: <python-grpc-plugin-id>
  #   out: gen/python
  #
  # --- TypeScript (example) ---
  # - plugin: <ts-plugin-id>
  #   out: gen/ts
  #   opt: <comma-separated-opts>
  #
  # --- gRPC-Gateway / OpenAPI (example) ---
  # - plugin: <grpc-gateway-plugin-id>
  #   out: gen/gateway
  #   opt: paths=source_relative
  # - plugin: <openapi-plugin-id>
  #   out: gen/openapi
  #   opt: allow_merge=true,merge_file_name=api
YAML
}

# -------------
# Dispatch
# -------------
case "$CMD" in
  generate) cmd_generate ;;
  verify)   cmd_verify ;;
  clean)    cmd_clean ;;
  template) cmd_template ;;
  *) usage; exit 2 ;;
esac
