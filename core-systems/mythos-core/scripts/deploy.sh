#!/usr/bin/env bash
# Industrial-grade deployment script for Mythos Core
# shellcheck shell=bash

set -Eeuo pipefail

# -----------
# Configuration (env with sane defaults)
# -----------
APP_NAME="${APP_NAME:-mythos-core}"
IMAGE_REPO="${IMAGE_REPO:-registry.local/mythos/$APP_NAME}"
IMAGE_TAG="${IMAGE_TAG:-}"
REGISTRY_USERNAME="${REGISTRY_USERNAME:-}"
REGISTRY_PASSWORD="${REGISTRY_PASSWORD:-}"
PUSH_IMAGE="${PUSH_IMAGE:-1}"

KUBE_NAMESPACE="${KUBE_NAMESPACE:-default}"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
HELM_BIN="${HELM_BIN:-helm}"
HELM_RELEASE="${HELM_RELEASE:-$APP_NAME}"
HELM_CHART_PATH="${HELM_CHART_PATH:-./deploy/helm/$APP_NAME}"
KUSTOMIZE_PATH="${KUSTOMIZE_PATH:-}"
MANIFEST_PATH="${MANIFEST_PATH:-./deploy/k8s/rendered.yaml}"
WAIT_ROLLOUT="${WAIT_ROLLOUT:-1}"
ROLLOUT_TIMEOUT="${ROLLOUT_TIMEOUT:-180s}"

# Optional supply chain
COSIGN_BIN="${COSIGN_BIN:-cosign}"
COSIGN_SIGN="${COSIGN_SIGN:-0}"
COSIGN_KEY="${COSIGN_KEY:-}"  # path or KMS ref

SYFT_BIN="${SYFT_BIN:-syft}"
GENERATE_SBOM="${GENERATE_SBOM:-0}"
SBOM_FORMAT="${SBOM_FORMAT:-cyclonedx-json}"
SBOM_OUT="${SBOM_OUT:-./dist/${APP_NAME}-sbom.json}"

# Build
DOCKER_BIN="${DOCKER_BIN:-docker}"
BUILD_CONTEXT="${BUILD_CONTEXT:-.}"
DOCKERFILE="${DOCKERFILE:-./Dockerfile}"
PLATFORM="${PLATFORM:-linux/amd64}"
BUILD_ARGS="${BUILD_ARGS:-}"  # e.g. "KEY=VAL,FOO=BAR"
BUILD_PUSH_INLINE="${BUILD_PUSH_INLINE:-0}"  # use buildx --push instead of separate push

# Logging
LOG_LEVEL="${LOG_LEVEL:-info}"

# -----------
# Utilities
# -----------
_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

jlog() {
  # jlog level event json
  local lvl="$1"; shift
  local evt="$1"; shift
  local data="${1:-{}}"
  printf '{"ts":"%s","level":"%s","event":"%s","data":%s}\n' "$(_now)" "${lvl^^}" "$evt" "$data" >&2
}

require_bin() {
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1 || { jlog error missing_bin "{\"bin\":\"$bin\"}"; exit 127; }
}

try_login_registry() {
  if [[ -n "$REGISTRY_USERNAME" && -n "$REGISTRY_PASSWORD" ]]; then
    echo "$REGISTRY_PASSWORD" | $DOCKER_BIN login --username "$REGISTRY_USERNAME" --password-stdin "$(echo "$IMAGE_REPO" | awk -F/ '{print $1}')" >/dev/null
    jlog info registry_login '{"status":"ok"}'
  else
    jlog info registry_login '{"status":"skipped"}'
  fi
}

git_sha() {
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git rev-parse --short=12 HEAD
  else
    echo "nogit$(date +%s)"
  fi
}

calc_version() {
  local base="${IMAGE_TAG:-}"
  if [[ -z "$base" ]]; then
    base="$(date -u +%Y.%m.%d)-$(git_sha)"
  fi
  echo "$base"
}

full_ref() {
  local tag="$1"
  echo "${IMAGE_REPO}:${tag}"
}

parse_build_args() {
  local args=()
  IFS=',' read -r -a pairs <<< "${BUILD_ARGS}"
  for kv in "${pairs[@]}"; do
    [[ -z "$kv" ]] && continue
    args+=("--build-arg" "$kv")
  done
  echo "${args[@]}"
}

retry() {
  local max="$1"; shift
  local backoff="$1"; shift
  local i=0
  until "$@"; do
    i=$((i+1))
    if (( i >= max )); then
      jlog error retry_failed "{\"attempts\":$i}"
      return 1
    fi
    jlog warn retry_wait "{\"attempt\":$i,\"sleep\":${backoff}}"
    sleep "$backoff"
    backoff=$(( backoff*2 ))
  done
}

cleanup() { jlog info cleanup '{}'; }
trap cleanup EXIT
trap 'jlog warn interrupted "{}"; exit 130' INT TERM

# -----------
# Actions
# -----------
cmd_version() {
  local ver; ver="$(calc_version)"
  jlog info version "{\"app\":\"$APP_NAME\",\"version\":\"$ver\"}"
  echo "$ver"
}

cmd_build() {
  require_bin "$DOCKER_BIN"
  require_bin "$DOCKER_BIN" # ensures docker exists; buildx checked below
  local ver; ver="$(calc_version)"
  local ref; ref="$(full_ref "$ver")"
  local args; args="$(parse_build_args)"

  if ! $DOCKER_BIN buildx inspect >/dev/null 2>&1; then
    $DOCKER_BIN buildx create --use >/dev/null
  fi

  jlog info build_start "{\"ref\":\"$ref\",\"platform\":\"$PLATFORM\"}"
  if [[ "$BUILD_PUSH_INLINE" == "1" ]]; then
    retry 3 2 $DOCKER_BIN buildx build --push --platform "$PLATFORM" -t "$ref" -f "$DOCKERFILE" $args "$BUILD_CONTEXT"
  else
    retry 3 2 $DOCKER_BIN buildx build --load --platform "$PLATFORM" -t "$ref" -f "$DOCKERFILE" $args "$BUILD_CONTEXT"
  fi
  jlog info build_done "{\"ref\":\"$ref\"}"

  if [[ "$GENERATE_SBOM" == "1" ]]; then
    cmd_sbom "$ref"
  fi

  if [[ "$COSIGN_SIGN" == "1" && "$BUILD_PUSH_INLINE" == "1" ]]; then
    cmd_sign "$ref"
  fi

  echo "$ref"
}

cmd_push() {
  require_bin "$DOCKER_BIN"
  local ver; ver="$(calc_version)"
  local ref; ref="$(full_ref "$ver")"

  try_login_registry
  jlog info push_start "{\"ref\":\"$ref\"}"
  retry 3 2 $DOCKER_BIN push "$ref"
  jlog info push_done "{\"ref\":\"$ref\"}"

  if [[ "$COSIGN_SIGN" == "1" ]]; then
    cmd_sign "$ref"
  fi
}

cmd_sbom() {
  local ref="${1:-}"
  [[ -z "$ref" ]] && { jlog error missing_ref '{"hint":"cmd_sbom requires image ref"}'; exit 1; }
  if ! command -v "$SYFT_BIN" >/dev/null 2>&1; then
    jlog warn sbom_skipped '{"reason":"syft not found"}'
    return 0
  fi
  mkdir -p "$(dirname "$SBOM_OUT")"
  jlog info sbom_start "{\"ref\":\"$ref\",\"format\":\"$SBOM_FORMAT\",\"out\":\"$SBOM_OUT\"}"
  "$SYFT_BIN" packages "registry:$ref" -o "$SBOM_FORMAT" > "$SBOM_OUT"
  jlog info sbom_done "{\"size\":$(wc -c < "$SBOM_OUT" | tr -d ' ')}"
}

cmd_sign() {
  local ref="${1:-}"
  [[ -z "$ref" ]] && { jlog error missing_ref '{"hint":"cmd_sign requires image ref"}'; exit 1; }
  if ! command -v "$COSIGN_BIN" >/dev/null 2>&1; then
    jlog warn sign_skipped '{"reason":"cosign not found"}'
    return 0
  fi
  jlog info sign_start "{\"ref\":\"$ref\"}"
  if [[ -n "$COSIGN_KEY" ]]; then
    COSIGN_EXPERIMENTAL=1 "$COSIGN_BIN" sign --key "$COSIGN_KEY" "$ref" >/dev/null
  else
    COSIGN_EXPERIMENTAL=1 "$COSIGN_BIN" sign "$ref" >/dev/null
  fi
  jlog info sign_done "{\"ref\":\"$ref\"}"
}

render_manifest_kustomize() {
  require_bin "$KUBECTL_BIN"
  require_bin "$KUBECTL_BIN" >/dev/null
  if ! command -v kustomize >/dev/null 2>&1; then
    jlog error kustomize_missing '{}'
    return 1
  fi
  jlog info render_start "{\"mode\":\"kustomize\",\"path\":\"$KUSTOMIZE_PATH\"}"
  mkdir -p "$(dirname "$MANIFEST_PATH")"
  kustomize build "$KUSTOMIZE_PATH" > "$MANIFEST_PATH"
  jlog info render_done "{\"out\":\"$MANIFEST_PATH\"}"
}

render_manifest_helm() {
  require_bin "$HELM_BIN"
  jlog info render_start "{\"mode\":\"helm\",\"chart\":\"$HELM_CHART_PATH\",\"release\":\"$HELM_RELEASE\",\"namespace\":\"$KUBE_NAMESPACE\"}"
  mkdir -p "$(dirname "$MANIFEST_PATH")"
  "$HELM_BIN" template "$HELM_RELEASE" "$HELM_CHART_PATH" \
    --namespace "$KUBE_NAMESPACE" \
    --set image.repository="$IMAGE_REPO" \
    --set image.tag="$(calc_version)" > "$MANIFEST_PATH"
  jlog info render_done "{\"out\":\"$MANIFEST_PATH\"}"
}

cmd_render() {
  if [[ -n "$KUSTOMIZE_PATH" ]]; then
    render_manifest_kustomize
  else
    render_manifest_helm
  fi
}

cmd_deploy() {
  require_bin "$KUBECTL_BIN"
  local ver; ver="$(calc_version)"
  local ref; ref="$(full_ref "$ver")"

  if [[ "$BUILD_PUSH_INLINE" != "1" ]]; then
    cmd_build >/dev/null
    if [[ "$PUSH_IMAGE" == "1" ]]; then
      cmd_push
    fi
  else
    # buildx --push already executed in cmd_build
    cmd_build >/dev/null
  fi

  cmd_render

  jlog info apply_start "{\"manifest\":\"$MANIFEST_PATH\",\"namespace\":\"$KUBE_NAMESPACE\"}"
  retry 3 2 "$KUBECTL_BIN" -n "$KUBE_NAMESPACE" apply -f "$MANIFEST_PATH" >/dev/null
  jlog info apply_done "{\"image\":\"$ref\"}"

  if [[ "$WAIT_ROLLOUT" == "1" ]]; then
    cmd_status
  fi
}

cmd_status() {
  require_bin "$KUBECTL_BIN"
  local dep="${DEPLOYMENT_NAME:-$APP_NAME}"
  jlog info rollout_wait "{\"deployment\":\"$dep\",\"timeout\":\"$ROLLOUT_TIMEOUT\"}"
  "$KUBECTL_BIN" -n "$KUBE_NAMESPACE" rollout status "deployment/$dep" --timeout="$ROLLOUT_TIMEOUT"
  jlog info rollout_ok "{\"deployment\":\"$dep\"}"
}

cmd_rollback() {
  require_bin "$KUBECTL_BIN"
  local dep="${DEPLOYMENT_NAME:-$APP_NAME}"
  local rev="${REVISION:-}"
  jlog warn rollback_start "{\"deployment\":\"$dep\",\"revision\":\"${rev:-latest}\"}"
  if [[ -n "$rev" ]]; then
    "$KUBECTL_BIN" -n "$KUBE_NAMESPACE" rollout undo "deployment/$dep" --to-revision="$rev"
  else
    "$KUBECTL_BIN" -n "$KUBE_NAMESPACE" rollout undo "deployment/$dep"
  fi
  "$KUBECTL_BIN" -n "$KUBE_NAMESPACE" rollout status "deployment/$dep" --timeout="$ROLLOUT_TIMEOUT"
  jlog warn rollback_done "{\"deployment\":\"$dep\"}"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

Commands:
  version        Print resolved version (date.gitsha or IMAGE_TAG)
  build          Build image with docker buildx (optional SBOM)
  push           Push image to registry (optional cosign sign)
  sbom           Generate SBOM for image ref (uses syft)
  sign           Sign image ref with cosign
  render         Render Kubernetes manifest (Helm by default, Kustomize if KUSTOMIZE_PATH set)
  deploy         Build->Push->Render->Apply and wait rollout
  status         Wait for rollout status of deployment
  rollback       Roll back deployment (env REVISION optional)

Environment (key):
  APP_NAME, IMAGE_REPO, IMAGE_TAG, REGISTRY_USERNAME, REGISTRY_PASSWORD
  KUBE_NAMESPACE, KUBECTL_BIN, HELM_BIN, HELM_RELEASE, HELM_CHART_PATH, KUSTOMIZE_PATH, MANIFEST_PATH
  COSIGN_SIGN, COSIGN_KEY, COSIGN_BIN
  GENERATE_SBOM, SYFT_BIN, SBOM_FORMAT, SBOM_OUT
  BUILD_CONTEXT, DOCKERFILE, PLATFORM, BUILD_ARGS, BUILD_PUSH_INLINE, PUSH_IMAGE
  WAIT_ROLLOUT, ROLLOUT_TIMEOUT

Examples:
  APP_NAME=mythos-core IMAGE_REPO=registry.local/mythos/mythos-core ./scripts/deploy.sh deploy
  IMAGE_TAG=1.2.3 ./scripts/deploy.sh deploy
  KUSTOMIZE_PATH=./deploy/kustomize ./scripts/deploy.sh render
EOF
}

# -----------
# Router
# -----------
main() {
  local cmd="${1:-}"
  case "$cmd" in
    version)   shift; cmd_version "$@";;
    build)     shift; cmd_build "$@";;
    push)      shift; cmd_push "$@";;
    sbom)      shift; cmd_sbom "$(full_ref "$(calc_version)")";;
    sign)      shift; cmd_sign "$(full_ref "$(calc_version)")";;
    render)    shift; cmd_render "$@";;
    deploy)    shift; cmd_deploy "$@";;
    status)    shift; cmd_status "$@";;
    rollback)  shift; cmd_rollback "$@";;
    ""|help|-h|--help) usage;;
    *) jlog error bad_command "{\"cmd\":\"$cmd\"}"; usage; exit 2;;
  esac
}

main "$@"
