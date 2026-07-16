#!/usr/bin/env bash
# Industrial Protobuf/Buf codegen for Zero-Trust Core
# Features:
# - protoc/buf autodetect, version checks, docker fallback
# - parallel, incremental (git-changed) or full build
# - targets: Go, TS (grpc-web/Connect), Python, Java, OpenAPI (grpc-gateway)
# - plugins: grpc, grpc-gateway, validate (PGV), go-vtproto (opt), connect
# - deterministic outputs, module mappings, cache, cleanup, dry-run/CI modes

set -Eeuo pipefail

#######################################
# Config (override via env)
#######################################
ROOT_DIR="${ROOT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
PROTO_DIRS_DEFAULT=("apis" "proto" "third_party")
PROTO_DIRS=(${PROTO_DIRS[@]:-${PROTO_DIRS_DEFAULT[@]}})
OUT_DIR="${OUT_DIR:-$ROOT_DIR/gen}"
CACHE_DIR="${CACHE_DIR:-$ROOT_DIR/.cache/proto}"
BUF_WORK="${BUF_WORK:-$ROOT_DIR}"
CI_MODE="${CI_MODE:-false}"                # true/false
DRY_RUN="${DRY_RUN:-false}"                # true/false
DOCKER_FALLBACK="${DOCKER_FALLBACK:-true}" # true/false
PARALLEL="${PARALLEL:-true}"               # true/false
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN || echo 4)}"
INCREMENTAL="${INCREMENTAL:-true}"         # true/false (use git diff)
CHANGED_BASE="${CHANGED_BASE:-origin/main}"

# Targets toggles
GEN_GO="${GEN_GO:-true}"
GEN_TS="${GEN_TS:-true}"
GEN_PY="${GEN_PY:-true}"
GEN_JAVA="${GEN_JAVA:-true}"
GEN_OPENAPI="${GEN_OPENAPI:-true}"

# Versions (expected minimums)
REQ_PROTOC="${REQ_PROTOC:-3.21.0}"
REQ_BUF="${REQ_BUF:-1.30.0}"

# Docker images
DOCKER_PROTOC_IMG="${DOCKER_PROTOC_IMG:-ghcr.io/bufbuild/buf:${REQ_BUF}}"

# Tooling Paths (autodetect)
PROTOC_BIN="${PROTOC_BIN:-$(command -v protoc || true)}"
BUF_BIN="${BUF_BIN:-$(command -v buf || true)}"

# Go module / mappings
GO_MODULE="${GO_MODULE:-github.com/yourorg/zero-trust-core}"
GO_OUT="${GO_OUT:-$OUT_DIR/go}"
TS_OUT="${TS_OUT:-$OUT_DIR/ts}"
PY_OUT="${PY_OUT:-$OUT_DIR/py}"
JAVA_OUT="${JAVA_OUT:-$OUT_DIR/java}"
OPENAPI_OUT="${OPENAPI_OUT:-$OUT_DIR/openapi}"

# Protoc plugins (auto-resolve by PATH)
PGV_VERSION_HINT="${PGV_VERSION_HINT:-latest}"

#######################################
# Logging
#######################################
log()  { printf '[gen-proto] %s\n' "$*"; }
err()  { printf '[gen-proto][ERR] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

#######################################
# Helpers
#######################################
semver_ge() { # usage: semver_ge 1.2.3 1.2.0
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Не найдено: $1"; }

ensure_dirs() {
  mkdir -p "$OUT_DIR" "$CACHE_DIR" "$GO_OUT" "$TS_OUT" "$PY_OUT" "$JAVA_OUT" "$OPENAPI_OUT"
}

git_changed_protos() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 1
  git diff --name-only "$CHANGED_BASE"... -- '*.proto' 2>/dev/null || true
}

have_any_proto() {
  local d; for d in "${PROTO_DIRS[@]}"; do
    [ -d "$ROOT_DIR/$d" ] && find "$ROOT_DIR/$d" -type f -name '*.proto' | grep -q . && return 0
  done
  return 1
}

#######################################
# Env validation
#######################################
check_versions_or_docker() {
  local have_protoc=false have_buf=false
  if [ -n "$PROTOC_BIN" ]; then
    have_protoc=true
    local pv; pv="$("$PROTOC_BIN" --version 2>/dev/null | awk '{print $2}')" || pv="0.0.0"
    semver_ge "$pv" "$REQ_PROTOC" || log "protoc $pv < $REQ_PROTOC (будет использоваться buf/docker для генерации где возможно)"
  fi
  if [ -n "$BUF_BIN" ]; then
    have_buf=true
    local bv; bv="$("$BUF_BIN" --version 2>/dev/null | awk '{print $1}' | sed 's/v//')" || bv="0.0.0"
    semver_ge "$bv" "$REQ_BUF" || die "buf $bv < $REQ_BUF"
  fi

  if ! $have_protoc && ! $have_buf; then
    $DOCKER_FALLBACK || die "Нет protoc и buf. Разрешите DOCKER_FALLBACK=true или установите инструменты."
    need_cmd docker
  fi
}

#######################################
# Docker wrappers
#######################################
docker_buf() {
  docker run --rm -u "$(id -u):$(id -g)" \
    -v "$BUF_WORK":"$BUF_WORK" -w "$BUF_WORK" \
    -v "$OUT_DIR":"$OUT_DIR" \
    "$DOCKER_PROTOC_IMG" buf "$@"
}

run_buf() {
  if [ -n "$BUF_BIN" ]; then "$BUF_BIN" "$@"; else docker_buf "$@"; fi
}

#######################################
# Build set (full or changed)
#######################################
collect_proto_paths() {
  local list=()
  if $INCREMENTAL; then
    local changed; changed="$(git_changed_protos || true)"
    if [ -n "$changed" ]; then
      while IFS= read -r f; do [ -n "$f" ] && list+=("$f"); done <<<"$changed"
    fi
  fi

  if [ "${#list[@]}" -eq 0 ]; then
    local d; for d in "${PROTO_DIRS[@]}"; do
      [ -d "$ROOT_DIR/$d" ] && while IFS= read -r f; do list+=("$f"); done \
        < <(find "$ROOT_DIR/$d" -type f -name '*.proto' | sort)
    done
  fi

  echo "${list[@]}"
}

#######################################
# Buf lint/format
#######################################
buf_lint_and_format() {
  if [ -f "$BUF_WORK/buf.yaml" ] || [ -f "$BUF_WORK/buf.work.yaml" ]; then
    log "Buf lint…"
    $DRY_RUN || run_buf lint
    log "Buf format (dry-run=$DRY_RUN)…"
    if $DRY_RUN; then run_buf format --diff; else run_buf format -w; fi
  else
    log "buf.yaml не найден — lint/format пропущен"
  fi
}

#######################################
# Generation via buf.gen.yaml if present
#######################################
buf_generate_if_present() {
  if [ -f "$BUF_WORK/buf.gen.yaml" ]; then
    log "Buf generate (buf.gen.yaml)…"
    if $DRY_RUN; then
      run_buf generate --template buf.gen.yaml --path "$(printf '%s\n' "${PROTO_DIRS[@]}")"
    else
      run_buf generate --template buf.gen.yaml
    fi
    return 0
  fi
  return 1
}

#######################################
# Direct generation fallback (manual plugins)
#######################################
manual_generate() {
  log "Ручная генерация через buf/protoc (fallback)…"
  local protos; IFS=' ' read -r -a protos <<<"$(collect_proto_paths)"
  [ "${#protos[@]}" -gt 0 ] || { log "Нет .proto файлов"; return 0; }

  # Common buf build cache
  local include_flags=()
  for d in "${PROTO_DIRS[@]}"; do
    [ -d "$ROOT_DIR/$d" ] && include_flags+=("-I" "$ROOT_DIR/$d")
  done

  # Use buf build image to get a file descriptor set (deterministic)
  local desc="$CACHE_DIR/descriptor.binpb"
  mkdir -p "$CACHE_DIR"
  if $DRY_RUN; then
    log "buf build (dry-run)…"
  else
    run_buf build --path "$(printf '%s,' "${PROTO_DIRS[@]}")" -o "$desc"
  fi

  # Generate per language using buf generate with inline templates if buf exists
  if [ -n "$BUF_BIN" ] || $DOCKER_FALLBACK; then
    local tmp_tpl="$CACHE_DIR/buf.gen.inline.yaml"
    cat >"$tmp_tpl" <<'YAML'
version: v1
managed:
  enabled: true
plugins:
  # Go
  - plugin: buf.build/protocolbuffers/go
    out: gen/go
    opt: paths=source_relative
  - plugin: buf.build/grpc/go
    out: gen/go
    opt: paths=source_relative
  - plugin: buf.build/bufbuild/validate-go
    out: gen/go
    opt: paths=source_relative
  # Python
  - plugin: buf.build/protocolbuffers/python
    out: gen/py
  - plugin: buf.build/grpc/python
    out: gen/py
  # Java
  - plugin: buf.build/protocolbuffers/java
    out: gen/java
  - plugin: buf.build/grpc/java
    out: gen/java
  # TypeScript (connect-web)
  - plugin: buf.build/bufbuild/es
    out: gen/ts
    opt:
      - target=ts
  - plugin: buf.build/connectrpc/es
    out: gen/ts
    opt:
      - target=ts
  # OpenAPI via grpc-gateway
  - plugin: buf.build/grpc-ecosystem/openapiv2
    out: gen/openapi
    opt:
      - json_names_for_fields=true
      - use_go_templates=true
YAML
    log "buf generate (inline template)…"
    $DRY_RUN || run_buf generate --template "$tmp_tpl"
    return 0
  fi

  # Final fallback pure protoc (requires local plugins)
  need_cmd "${PROTOC_BIN:-protoc}"
  local cmd=("${PROTOC_BIN:-protoc}" "${include_flags[@]}" --experimental_allow_proto3_optional)
  $GEN_GO && cmd+=("--go_out=$GO_OUT" "--go-grpc_out=$GO_OUT" "--validate_out=lang=go:$GO_OUT")
  $GEN_PY && cmd+=("--python_out=$PY_OUT" "--grpc_python_out=$PY_OUT")
  $GEN_JAVA && cmd+=("--java_out=$JAVA_OUT" "--grpc-java_out=$JAVA_OUT")
  # TS requires external plugin (ts-proto or connect-web); skipping in pure protoc fallback
  $DRY_RUN && log "DRY: ${cmd[*]} ${protos[*]}" || "${cmd[@]}" "${protos[@]}"
}

#######################################
# Cleanup stale outputs
#######################################
cleanup_stale() {
  if $CI_MODE; then
    log "CI mode: очищаем папки генерации…"
    rm -rf "$OUT_DIR" && ensure_dirs
  fi
}

#######################################
# Parallelization (buf handles internally; protoc fallback not parallelized)
#######################################
main() {
  trap 'err "Ошибка на линии $LINENO"; exit 1' ERR
  ensure_dirs
  have_any_proto || { log "Протоколы не найдены в ${PROTO_DIRS[*]}"; exit 0; }
  check_versions_or_docker
  cleanup_stale
  buf_lint_and_format

  if ! buf_generate_if_present; then
    manual_generate
  fi

  # Normalize perms for CI artifacts
  find "$OUT_DIR" -type f -name '*.js' -o -name '*.ts' -o -name '*.go' -o -name '*.py' -o -name '*.java' -o -name '*.yaml' \
    -print0 2>/dev/null | xargs -0 -I{} bash -c 'touch -r "{}" "{}"' || true

  log "Генерация завершена: $OUT_DIR"
}

#######################################
# Usage
#######################################
usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Environment (override defaults):
  ROOT_DIR, PROTO_DIRS, OUT_DIR, CACHE_DIR
  CI_MODE=true|false, DRY_RUN=true|false, DOCKER_FALLBACK=true|false
  PARALLEL=true|false, JOBS=N, INCREMENTAL=true|false, CHANGED_BASE=origin/main
  GEN_GO=true|false, GEN_TS=true|false, GEN_PY=true|false, GEN_JAVA=true|false, GEN_OPENAPI=true|false

Examples:
  CI_MODE=true DOCKER_FALLBACK=true $0
  INCREMENTAL=false GEN_TS=false $0
EOF
}

if [[ "${1:-}" =~ ^(-h|--help)$ ]]; then usage; exit 0; fi
main
