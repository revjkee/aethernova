#!/usr/bin/env bash
# scripts/deploy.sh
# SPDX-License-Identifier: MIT
# Industrial deploy helper for physical-integration-core
# Features:
#  - Targets: helm (Kubernetes) | compose (Docker Compose)
#  - Safe bash: set -Eeuo pipefail, error traps, locking
#  - Build/push docker image with git-based tag
#  - Env overlays: values-{env}.yaml (Helm) / docker-compose.{env}.yml (Compose)
#  - Rollout wait, health checks, rollback, logs, status
#  - Dry-run and helm diff (if plugin installed)
#  - Optional migration command/job
#  - Loads .env.{env} / configs/env/{env}.env if present

set -Eeuo pipefail

#--------------------------- Defaults & Globals --------------------------------#

APP_NAME="${APP_NAME:-physical-integration-core}"
TARGET="${TARGET:-helm}"                   # helm | compose
ENVIRONMENT="${ENVIRONMENT:-dev}"         # dev | staging | prod
REGISTRY="${REGISTRY:-ghcr.io/example}"   # override via CI
IMAGE_NAME="${IMAGE_NAME:-$APP_NAME}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"
CHART_PATH="${CHART_PATH:-ops/helm/$APP_NAME}"
HELM_RELEASE="${HELM_RELEASE:-$APP_NAME}"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-$APP_NAME}"
TIMEOUT="${TIMEOUT:-10m0s}"
DRY_RUN="${DRY_RUN:-0}"                    # 1 to simulate
CONFIRM="${CONFIRM:-0}"                    # 1 to auto-confirm (CI)
LOCK_FILE="${LOCK_FILE:-/tmp/${APP_NAME}_deploy.lock}"
MIGRATION_CMD="${MIGRATION_CMD:-}"         # e.g. "python -m app.migrate"
K8S_CONTEXT="${K8S_CONTEXT:-}"             # optional kubectl/helm --kube-context

# Tag: prefer CI provided TAG; else from git
GIT_SHA="$(git rev-parse --short=12 HEAD 2>/dev/null || echo nosha)"
BUILD_ID="${BUILD_ID:-local}"
VERSION_GIT="$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0)"
TAG="${TAG:-${VERSION_GIT}-${GIT_SHA}-${BUILD_ID}}"
IMAGE="${IMAGE:-$REGISTRY/$IMAGE_NAME:$TAG}"

# Paths derived
VALUES_BASE="${VALUES_BASE:-$CHART_PATH/values.yaml}"
VALUES_ENV="${VALUES_ENV:-$CHART_PATH/values-$ENVIRONMENT.yaml}"
COMPOSE_BASE="${COMPOSE_BASE:-docker-compose.yml}"
COMPOSE_ENV="${COMPOSE_ENV:-docker-compose.$ENVIRONMENT.yml}"

# Colors (optional)
if [[ -t 1 ]]; then
  c_bold=$(printf '\033[1m'); c_red=$(printf '\033[31m'); c_yel=$(printf '\033[33m'); c_grn=$(printf '\033[32m'); c_dim=$(printf '\033[2m'); c_off=$(printf '\033[0m')
else
  c_bold=""; c_red=""; c_yel=""; c_grn=""; c_dim=""; c_off=""
fi

#------------------------------ Logging & utils --------------------------------#

log()  { printf "%s[%s]%s %s\n" "$c_dim" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$c_off" "$*"; }
info() { printf "%sINFO%s  %s\n" "$c_grn" "$c_off" "$*"; }
warn() { printf "%sWARN%s  %s\n" "$c_yel" "$c_off" "$*"; }
err()  { printf "%sERROR%s %s\n" "$c_red" "$c_off" "$*" >&2; }
die()  { err "$*"; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

run() {
  # DRY_RUN-aware executor
  if [[ "${DRY_RUN}" == "1" ]]; then
    printf "%sDRY-RUN%s %s\n" "$c_yel" "$c_off" "$*"
  else
    set -x
    "$@"
    { set +x; } 2>/dev/null
  fi
}

on_error() {
  local ec=$?; local cmd=${BASH_COMMAND:-unknown}
  err "Failed (exit $ec) on: $cmd"
  cleanup_lock || true
  exit "$ec"
}
trap on_error ERR

# Concurrency lock
acquire_lock() {
  if [[ -e "$LOCK_FILE" ]]; then
    die "Another deploy appears to be running (lock: $LOCK_FILE). Remove it if stale."
  fi
  echo "$$" >"$LOCK_FILE"
}
cleanup_lock() { [[ -e "$LOCK_FILE" ]] && rm -f "$LOCK_FILE"; }
trap cleanup_lock EXIT

#--------------------------- Usage & argument parse ----------------------------#

usage() {
  cat <<EOF
${c_bold}Deploy helper for ${APP_NAME}${c_off}

Usage:
  scripts/deploy.sh <command> [--flags]

Commands:
  build                 Build docker image
  push                  Push image to registry
  deploy                Build+push (optional) and deploy to target (helm|compose)
  status                Show deployment status
  logs                  Tail logs (K8s deploy/Compose service)
  rollback [REV]        Rollback Helm release to revision or previous
  render                Helm template render (no apply)
  diff                  Helm diff upgrade (requires helm-diff plugin)
  tag                   Print computed image tag

Common flags (can be set via env vars):
  --target {helm|compose}         TARGET (default: $TARGET)
  --env {dev|staging|prod}        ENVIRONMENT (default: $ENVIRONMENT)
  --registry REG                  REGISTRY (default: $REGISTRY)
  --image-name NAME               IMAGE_NAME (default: $IMAGE_NAME)
  --tag TAG                       TAG override (default computed)
  --namespace NS                  KUBE_NAMESPACE (default: $KUBE_NAMESPACE)
  --release NAME                  HELM_RELEASE (default: $HELM_RELEASE)
  --chart PATH                    CHART_PATH (default: $CHART_PATH)
  --timeout DUR                   TIMEOUT (default: $TIMEOUT)
  --dry-run                       DRY_RUN=1 (no changes)
  --yes                           CONFIRM=1 (no interactive prompts)

Examples:
  scripts/deploy.sh build --env staging
  scripts/deploy.sh deploy --target helm --env prod --yes
  scripts/deploy.sh rollback           # to previous Helm revision

Environment files auto-load (if exist):
  .env.\$ENVIRONMENT  or  configs/env/\$ENVIRONMENT.env
EOF
}

# Lightweight args parser
parse_args() {
  CMD="${1:-}"; [[ -n "${CMD:-}" ]] || { usage; exit 1; }; shift || true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target) TARGET="$2"; shift 2;;
      --env) ENVIRONMENT="$2"; shift 2;;
      --registry) REGISTRY="$2"; shift 2;;
      --image-name) IMAGE_NAME="$2"; shift 2;;
      --namespace) KUBE_NAMESPACE="$2"; shift 2;;
      --release) HELM_RELEASE="$2"; shift 2;;
      --chart) CHART_PATH="$2"; shift 2;;
      --tag) TAG="$2"; IMAGE="$REGISTRY/$IMAGE_NAME:$TAG"; shift 2;;
      --timeout) TIMEOUT="$2"; shift 2;;
      --dry-run) DRY_RUN="1"; shift 1;;
      --yes) CONFIRM="1"; shift 1;;
      -h|--help) usage; exit 0;;
      *) die "Unknown flag: $1";;
    esac
  done
}

#--------------------------- Env loading & checks -------------------------------#

load_env_files() {
  local f1=".env.${ENVIRONMENT}"
  local f2="configs/env/${ENVIRONMENT}.env"
  for f in "$f1" "$f2"; do
    if [[ -f "$f" ]]; then
      info "Loading environment file: $f"
      set -a; # export everything
      # shellcheck disable=SC1090
      source "$f"
      set +a;
    fi
  done
}

confirm_prod() {
  if [[ "$ENVIRONMENT" == "prod" && "$CONFIRM" != "1" ]]; then
    printf "%sCONFIRM%s Deploying to PROD. Type 'yes' to continue: " "$c_yel" "$c_off"
    read -r ans
    [[ "$ans" == "yes" ]] || die "Aborted by user."
  fi
}

check_tools() {
  require_cmd git
  require_cmd docker
  if [[ "$TARGET" == "helm" ]]; then
    require_cmd helm
    require_cmd kubectl
  elif [[ "$TARGET" == "compose" ]]; then
    require_cmd docker
    require_cmd docker compose
  else
    die "Unsupported TARGET: $TARGET"
  fi
}

kube_flags() {
  # echo kube context flags if provided
  if [[ -n "${K8S_CONTEXT}" ]]; then
    printf -- "--kube-context %s " "$K8S_CONTEXT"
  fi
}

#------------------------------ Build & Push -----------------------------------#

cmd_build() {
  info "Building image: $IMAGE (Dockerfile=$DOCKERFILE)"
  run docker build -f "$DOCKERFILE" --build-arg "BUILD_ENV=$ENVIRONMENT" -t "$IMAGE" .
}

cmd_push() {
  info "Pushing image: $IMAGE"
  run docker push "$IMAGE"
}

#------------------------------ Kubernetes (Helm) -------------------------------#

helm_upgrade() {
  local kflags; kflags="$(kube_flags || true)"
  local set_image="--set image.repository=${REGISTRY}/${IMAGE_NAME%:*} --set image.tag=${TAG}"
  local files=()
  [[ -f "$VALUES_BASE" ]] && files+=("-f" "$VALUES_BASE")
  [[ -f "$VALUES_ENV" ]] && files+=("-f" "$VALUES_ENV")

  info "Helm upgrade --install release=$HELM_RELEASE ns=$KUBE_NAMESPACE image=$IMAGE"
  run helm upgrade --install "$HELM_RELEASE" "$CHART_PATH" \
    --namespace "$KUBE_NAMESPACE" --create-namespace \
    ${files[@]+"${files[@]}"} \
    $set_image \
    --wait --timeout "$TIMEOUT" \
    ${kflags}
}

helm_diff_upgrade() {
  if helm plugin list 2>/dev/null | grep -q diff; then
    local kflags; kflags="$(kube_flags || true)"
    local files=()
    [[ -f "$VALUES_BASE" ]] && files+=("-f" "$VALUES_BASE")
    [[ -f "$VALUES_ENV" ]] && files+=("-f" "$VALUES_ENV")
    info "Helm diff (proposed changes): release=$HELM_RELEASE"
    run helm diff upgrade "$HELM_RELEASE" "$CHART_PATH" \
      --namespace "$KUBE_NAMESPACE" \
      ${files[@]+"${files[@]}"} \
      --set image.repository="${REGISTRY}/${IMAGE_NAME%:*}" --set image.tag="${TAG}" \
      ${kflags} || true
  else
    warn "helm-diff plugin not installed; skipping diff"
  fi
}

helm_wait_rollout() {
  info "Waiting for rollout to complete (namespace=$KUBE_NAMESPACE)"
  run kubectl -n "$KUBE_NAMESPACE" rollout status deploy/"$HELM_RELEASE" --timeout="$TIMEOUT" || {
    err "Rollout status failed"
    return 1
  }
}

helm_migrate_if_needed() {
  [[ -z "$MIGRATION_CMD" ]] && return 0
  info "Running migration command as ephemeral pod"
  local pod="${HELM_RELEASE}-migrate-$(date +%s)"
  run kubectl -n "$KUBE_NAMESPACE" run "$pod" --rm --restart=Never --image="$IMAGE" --quiet --command -- sh -lc "$MIGRATION_CMD"
}

cmd_helm_deploy() {
  helm_diff_upgrade
  helm_upgrade
  helm_migrate_if_needed
  helm_wait_rollout
  info "Deployed $HELM_RELEASE to $ENVIRONMENT (image=$IMAGE)"
}

cmd_helm_status() {
  local kflags; kflags="$(kube_flags || true)"
  run helm status "$HELM_RELEASE" --namespace "$KUBE_NAMESPACE" ${kflags}
  run kubectl -n "$KUBE_NAMESPACE" get pods -l "app.kubernetes.io/instance=$HELM_RELEASE" -o wide
}

cmd_helm_logs() {
  info "Tailing logs for deployment/$HELM_RELEASE (Ctrl-C to exit)"
  run kubectl -n "$KUBE_NAMESPACE" logs deploy/"$HELM_RELEASE" -f --tail=200
}

cmd_helm_rollback() {
  local rev="${1:-0}"
  info "Rolling back Helm release=$HELM_RELEASE to revision=${rev:-previous}"
  if [[ "$rev" == "0" ]]; then
    run helm rollback "$HELM_RELEASE" --namespace "$KUBE_NAMESPACE"
  else
    run helm rollback "$HELM_RELEASE" "$rev" --namespace "$KUBE_NAMESPACE"
  fi
  helm_wait_rollout
}

cmd_helm_render() {
  local files=()
  [[ -f "$VALUES_BASE" ]] && files+=("-f" "$VALUES_BASE")
  [[ -f "$VALUES_ENV" ]] && files+=("-f" "$VALUES_ENV")
  info "Rendering Helm templates (no apply)"
  run helm template "$HELM_RELEASE" "$CHART_PATH" --namespace "$KUBE_NAMESPACE" \
    ${files[@]+"${files[@]}"} \
    --set image.repository="${REGISTRY}/${IMAGE_NAME%:*}" --set image.tag="${TAG}"
}

#------------------------------ Docker Compose ---------------------------------#

cmd_compose_up() {
  local files=("-f" "$COMPOSE_BASE")
  [[ -f "$COMPOSE_ENV" ]] && files+=("-f" "$COMPOSE_ENV")
  info "Docker Compose up (env=$ENVIRONMENT)"
  run docker compose "${files[@]}" pull || true
  run docker compose "${files[@]}" up -d --remove-orphans
}

cmd_compose_status() {
  local files=("-f" "$COMPOSE_BASE")
  [[ -f "$COMPOSE_ENV" ]] && files+=("-f" "$COMPOSE_ENV")
  run docker compose "${files[@]}" ps
}

cmd_compose_logs() {
  local files=("-f" "$COMPOSE_BASE")
  [[ -f "$COMPOSE_ENV" ]] && files+=("-f" "$COMPOSE_ENV")
  run docker compose "${files[@]}" logs -f --tail=200
}

#------------------------------- High-level cmds --------------------------------#

cmd_deploy() {
  confirm_prod
  if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    cmd_build
  else
    info "Skipping build (SKIP_BUILD=1)"
  fi
  if [[ "${SKIP_PUSH:-0}" != "1" ]]; then
    cmd_push
  else
    info "Skipping push (SKIP_PUSH=1)"
  fi
  if [[ "$TARGET" == "helm" ]]; then
    cmd_helm_deploy
  else
    cmd_compose_up
  fi
}

cmd_status() {
  if [[ "$TARGET" == "helm" ]]; then
    cmd_helm_status
  else
    cmd_compose_status
  fi
}

cmd_logs() {
  if [[ "$TARGET" == "helm" ]]; then
    cmd_helm_logs
  else
    cmd_compose_logs
  fi
}

cmd_diff() {
  [[ "$TARGET" == "helm" ]] || die "diff is only available for TARGET=helm"
  helm_diff_upgrade
}

cmd_tag() { echo "$TAG"; }

#------------------------------- Entry point ------------------------------------#

main() {
  parse_args "$@"
  acquire_lock
  load_env_files
  check_tools

  info "App=$APP_NAME Target=$TARGET Env=$ENVIRONMENT Release=$HELM_RELEASE Namespace=$KUBE_NAMESPACE"
  info "Image=$IMAGE Chart=$CHART_PATH Compose=$COMPOSE_BASE"

  case "$CMD" in
    build)    cmd_build;;
    push)     cmd_push;;
    deploy)   cmd_deploy;;
    status)   cmd_status;;
    logs)     cmd_logs;;
    rollback) shift || true; cmd_helm_rollback "${1:-0}";;
    render)   cmd_helm_render;;
    diff)     cmd_diff;;
    tag)      cmd_tag;;
    *)        usage; exit 1;;
  esac
}

main "$@"
