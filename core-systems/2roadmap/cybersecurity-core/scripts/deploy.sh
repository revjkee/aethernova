#!/usr/bin/env bash
# cybersecurity-core/scripts/deploy.sh
# Industrial-grade deploy script: build → scan → sbom → sign → push → helm deploy → health/rollback
# Requires: bash 4+, docker, (optional) trivy, syft, cosign, helm, kubectl

set -Eeuo pipefail

#######################################
# Logging
#######################################
readonly _NO_COLOR="${NO_COLOR:-}"
if [[ -z "${_NO_COLOR}" && -t 1 ]]; then
  readonly C_RESET='\033[0m'; readonly C_DIM='\033[2m'
  readonly C_RED='\033[31m'; readonly C_GRN='\033[32m'
  readonly C_YEL='\033[33m'; readonly C_BLU='\033[34m'
else
  readonly C_RESET=''; readonly C_DIM=''
  readonly C_RED=''; readonly C_GRN=''
  readonly C_YEL=''; readonly C_BLU=''
fi

log()    { printf "%b[%s]%b %s\n" "${C_DIM}" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "${C_RESET}" "$*"; }
info()   { printf "%bINFO%b    %s\n"    "${C_BLU}" "${C_RESET}" "$*"; }
warn()   { printf "%bWARN%b    %s\n"    "${C_YEL}" "${C_RESET}" "$*"; }
error()  { printf "%bERROR%b   %s\n"    "${C_RED}" "${C_RESET}" "$*" >&2; }
ok()     { printf "%bOK%b      %s\n"    "${C_GRN}" "${C_RESET}" "$*"; }

trap 'rc=$?; error "Failed at line $LINENO (exit=$rc)"; exit $rc' ERR

#######################################
# Defaults and env
#######################################
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-"${ROOT_DIR}/.env"}"

APP_NAME="${APP_NAME:-cybersecurity-core}"
IMAGE_NAME="${IMAGE_NAME:-${APP_NAME}}"
REGISTRY="${REGISTRY:-}"                # e.g. ghcr.io/org, registry.gitlab.com/group, your-registry.local:5000
IMAGE_TAG="${IMAGE_TAG:-}"              # if empty → git sha/date
IMAGE_REPO="${IMAGE_REPO:-}"            # if empty → "${REGISTRY}/${IMAGE_NAME}"

K8S_NAMESPACE="${K8S_NAMESPACE:-security}"
RELEASE_NAME="${RELEASE_NAME:-${APP_NAME}}"
CHART_DIR="${CHART_DIR:-}"              # if empty → autodetect
VALUES_FILE="${VALUES_FILE:-}"          # e.g. helm/values-prod.yaml
TIMEOUT="${TIMEOUT:-5m}"
DRY_RUN="${DRY_RUN:-false}"

# Security/QA toggles (auto-skip if tool missing)
ENABLE_TRIVY="${ENABLE_TRIVY:-true}"
ENABLE_SYFT="${ENABLE_SYFT:-true}"
ENABLE_COSIGN="${ENABLE_COSIGN:-true}"

# Build
DOCKERFILE="${DOCKERFILE:-${ROOT_DIR}/Dockerfile}"
PLATFORM="${PLATFORM:-linux/amd64}"
BUILD_CONTEXT="${BUILD_CONTEXT:-${ROOT_DIR}}"
PUSH_CACHE="${PUSH_CACHE:-false}"       # push cache to registry (requires configured cache)
BUILD_ARGS="${BUILD_ARGS:-}"            # e.g. "GIT_SHA=... SENTRY_DSN=..."; pass as KEY=VAL

#######################################
# Helpers
#######################################
usage() {
  cat <<'USAGE'
Usage: scripts/deploy.sh <command> [options]

Commands:
  build             Build container image (docker buildx)
  scan              Run Trivy scan (if installed)
  sbom              Generate SBOM with Syft (if installed)
  sign              Sign image with Cosign (if installed)
  push              Push image to container registry
  deploy            Helm upgrade --install to Kubernetes
  health            Wait for rollout & run basic health checks
  rollback          Helm rollback to a specific revision
  full              build → scan → sbom → sign → push → deploy → health

Common options:
  -e, --env <name>            Logical env name used for values file discovery (e.g. dev|staging|prod)
  -t, --tag <tag>             Override image tag
  -n, --namespace <ns>        Kubernetes namespace (default: security)
  -r, --registry <reg>        Container registry host/org (e.g. ghcr.io/org)
  --release <name>            Helm release name (default: cybersecurity-core)
  --chart <dir>               Helm chart directory (autodetect if not set)
  --values <file>             Helm values file path (autodetect if not set)
  --timeout <dur>             Helm/K8s wait timeout (default: 5m)
  --dry-run                   Show what would happen without executing (deploy/push/rollback)
  -h, --help                  Show this help

Environment variables (override defaults):
  APP_NAME, IMAGE_NAME, REGISTRY, IMAGE_REPO, IMAGE_TAG, K8S_NAMESPACE,
  RELEASE_NAME, CHART_DIR, VALUES_FILE, TIMEOUT, DOCKERFILE, PLATFORM,
  BUILD_CONTEXT, ENABLE_TRIVY, ENABLE_SYFT, ENABLE_COSIGN, ENV_FILE

Examples:
  scripts/deploy.sh full -e prod -r ghcr.io/aethernova
  scripts/deploy.sh rollback --release cybersecurity-core --to 23 -n security
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }

require() {
  local missing=()
  for c in "$@"; do have "$c" || missing+=("$c"); done
  if (( ${#missing[@]} )); then
    error "Missing required tools: ${missing[*]}"
    exit 127
  fi
}

bool() { [[ "${1:-}" =~ ^(1|true|yes|on)$ ]]; }

load_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC2046
    export $(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "${ENV_FILE}" | sed 's/#.*//g' | xargs -I{} echo {})
    info "Loaded env from ${ENV_FILE}"
  else
    warn "ENV file not found at ${ENV_FILE}; proceeding with current environment"
  fi
}

git_sha() {
  if have git && git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git -C "${ROOT_DIR}" rev-parse --short=12 HEAD
  else
    date -u +%Y%m%d%H%M%S
  fi
}

ensure_defaults() {
  [[ -n "${IMAGE_TAG}" ]] || IMAGE_TAG="git-$(git_sha)"
  [[ -n "${IMAGE_REPO}" ]] || {
    if [[ -z "${REGISTRY}" ]]; then
      error "REGISTRY is not set and IMAGE_REPO is empty"
      exit 2
    fi
    IMAGE_REPO="${REGISTRY}/${IMAGE_NAME}"
  }
  if [[ -z "${CHART_DIR}" ]]; then
    for p in "${ROOT_DIR}/helm/${APP_NAME}" "${ROOT_DIR}/deploy/helm/${APP_NAME}" "${ROOT_DIR}/charts/${APP_NAME}"; do
      if [[ -d "${p}" ]]; then CHART_DIR="${p}"; break; fi
    done
  fi
  if [[ -z "${VALUES_FILE:-}" && -n "${ENV_NAME:-}" ]]; then
    for vf in "${CHART_DIR}/values-${ENV_NAME}.yaml" "${CHART_DIR}/values/${ENV_NAME}.yaml"; do
      [[ -f "${vf}" ]] && VALUES_FILE="${vf}" && break
    done
  fi
  : "${VALUES_FILE:=}" # may remain empty
  ok "Resolved: IMAGE=${IMAGE_REPO}:${IMAGE_TAG}; CHART_DIR=${CHART_DIR:-<none>}; VALUES=${VALUES_FILE:-<none>}"
}

#######################################
# Steps
#######################################
docker_build() {
  require docker
  export DOCKER_BUILDKIT=1
  local tag="${IMAGE_REPO}:${IMAGE_TAG}"
  info "Building image ${tag} (platform=${PLATFORM})"
  if ! docker buildx inspect builder >/dev/null 2>&1; then
    info "Creating docker buildx builder"
    docker buildx create --name builder --use >/dev/null
  fi
  local args=()
  if [[ -n "${BUILD_ARGS}" ]]; then
    # split BUILD_ARGS by space into KEY=VAL pairs
    for kv in ${BUILD_ARGS}; do args+=(--build-arg "${kv}"); done
  fi
  docker buildx build \
    --platform "${PLATFORM}" \
    -t "${tag}" \
    -f "${DOCKERFILE}" \
    "${args[@]}" \
    "${BUILD_CONTEXT}" \
    $(bool "${PUSH_CACHE}" && echo "--push" || echo "--load")
  ok "Image built: ${tag}"
}

trivy_scan() {
  if ! bool "${ENABLE_TRIVY}" || ! have trivy; then
    warn "Trivy scan skipped (disabled or trivy not installed)"
    return 0
  fi
  local tag="${IMAGE_REPO}:${IMAGE_TAG}"
  info "Running Trivy scan for ${tag}"
  trivy image --scanners vuln,secret,config --severity HIGH,CRITICAL --exit-code 1 "${tag}" || {
    error "Trivy found HIGH/CRITICAL issues"
    exit 3
  }
  ok "Trivy scan passed"
}

syft_sbom() {
  if ! bool "${ENABLE_SYFT}" || ! have syft; then
    warn "Syft SBOM skipped (disabled or syft not installed)"
    return 0
  fi
  local tag="${IMAGE_REPO}:${IMAGE_TAG}"
  local outdir="${ROOT_DIR}/sbom"
  mkdir -p "${outdir}"
  info "Generating SBOM (SPDX JSON) for ${tag}"
  syft "registry:${tag}" -o spdx-json > "${outdir}/${IMAGE_NAME}-${IMAGE_TAG}.spdx.json"
  ok "SBOM written: ${outdir}/${IMAGE_NAME}-${IMAGE_TAG}.spdx.json"
}

cosign_sign() {
  if ! bool "${ENABLE_COSIGN}" || ! have cosign; then
    warn "Cosign sign skipped (disabled or cosign not installed)"
    return 0
  fi
  local tag="${IMAGE_REPO}:${IMAGE_TAG}"
  export COSIGN_EXPERIMENTAL=1
  export COSIGN_YES=1
  info "Signing image with Cosign: ${tag}"
  if [[ -n "${COSIGN_KEY:-}" ]]; then
    cosign sign --key "${COSIGN_KEY}" "${tag}"
  else
    # keyless OIDC (e.g., GitHub OIDC in CI)
    cosign sign "${tag}"
  fi
  ok "Cosign signature attached"
}

docker_push() {
  require docker
  local tag="${IMAGE_REPO}:${IMAGE_TAG}"
  info "Pushing image ${tag}"
  if bool "${DRY_RUN}"; then
    warn "DRY-RUN: skip docker push ${tag}"
    return 0
  fi
  docker push "${tag}"
  ok "Pushed: ${tag}"
}

helm_deploy() {
  require helm kubectl
  if [[ -z "${CHART_DIR}" || ! -d "${CHART_DIR}" ]]; then
    error "CHART_DIR not found: ${CHART_DIR:-<empty>}"
    exit 4
  fi
  local set_image="image.repository=${IMAGE_REPO},image.tag=${IMAGE_TAG}"
  local args=(upgrade --install "${RELEASE_NAME}" "${CHART_DIR}"
              --namespace "${K8S_NAMESPACE}" --create-namespace
              --set-string "${set_image}"
              --atomic --wait --timeout "${TIMEOUT}")
  [[ -n "${VALUES_FILE}" ]] && args+=( -f "${VALUES_FILE}" )

  info "Helm deploy release=${RELEASE_NAME} ns=${K8S_NAMESPACE} chart=${CHART_DIR}"
  if bool "${DRY_RUN}"; then
    warn "DRY-RUN: helm ${args[*]}"
    helm "${args[@]}" --dry-run >/dev/null
    return 0
  fi
  helm "${args[@]}"
  ok "Helm deploy completed"
}

k8s_health() {
  require kubectl
  info "Waiting for rollout in ns=${K8S_NAMESPACE}, release=${RELEASE_NAME}"
  # Try Deployment first; fallback to StatefulSet/DaemonSet
  local kinds=(deployment statefulset daemonset)
  for k in "${kinds[@]}"; do
    local names
    names=$(kubectl -n "${K8S_NAMESPACE}" get "${k}" -l "app.kubernetes.io/instance=${RELEASE_NAME}" -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}') || true
    for n in ${names}; do
      info "Rollout status ${k}/${n}"
      kubectl -n "${K8S_NAMESPACE}" rollout status "${k}/${n}" --timeout="${TIMEOUT}"
    done
  done
  ok "Kubernetes rollout healthy"
}

helm_rollback() {
  require helm
  local to_rev="${1:-}"
  if [[ -z "${to_rev}" ]]; then
    error "Specify target revision: rollback <revision>"
    exit 5
  end if
  info "Helm rollback release=${RELEASE_NAME} to revision=${to_rev} ns=${K8S_NAMESPACE}"
  if bool "${DRY_RUN}"; then
    warn "DRY-RUN: helm rollback ${RELEASE_NAME} ${to_rev} -n ${K8S_NAMESPACE}"
    return 0
  fi
  helm rollback "${RELEASE_NAME}" "${to_rev}" --namespace "${K8S_NAMESPACE}" --wait --timeout "${TIMEOUT}"
  ok "Rollback done"
}

#######################################
# Arg parsing
#######################################
CMD="${1:-}"
shift || true

ENV_NAME=""
while (( "$#" )); do
  case "$1" in
    -e|--env)        ENV_NAME="$2"; shift 2;;
    -t|--tag)        IMAGE_TAG="$2"; shift 2;;
    -n|--namespace)  K8S_NAMESPACE="$2"; shift 2;;
    -r|--registry)   REGISTRY="$2"; shift 2;;
    --release)       RELEASE_NAME="$2"; shift 2;;
    --chart)         CHART_DIR="$2"; shift 2;;
    --values)        VALUES_FILE="$2"; shift 2;;
    --timeout)       TIMEOUT="$2"; shift 2;;
    --dry-run)       DRY_RUN=true; shift 1;;
    -h|--help)       usage; exit 0;;
    *)               error "Unknown option: $1"; usage; exit 2;;
  esac
done

if [[ -z "${CMD}" ]]; then usage; exit 2; fi

#######################################
# Main flow
#######################################
load_env
ensure_defaults

case "${CMD}" in
  build)
    docker_build
    ;;
  scan)
    trivy_scan
    ;;
  sbom)
    syft_sbom
    ;;
  sign)
    cosign_sign
    ;;
  push)
    docker_push
    ;;
  deploy)
    helm_deploy
    ;;
  health)
    k8s_health
    ;;
  rollback)
    # expects --release/--namespace via env/flags and <revision> via position?
    # For safety, ask for revision via positional arg after 'rollback' in CI usage
    error "Specify revision as positional after 'rollback' (e.g., rollback 23)"
    ;;
  full)
    docker_build
    trivy_scan
    syft_sbom
    cosign_sign
    docker_push
    helm_deploy
    k8s_health
    ;;
  *)
    if [[ "${CMD}" == "rollback" ]]; then
      # shellcheck disable=SC2124
      to_rev="${*:-}"
      if [[ -z "${to_rev}" ]]; then
        error "Usage: scripts/deploy.sh rollback <revision> [flags]"
        exit 2
      fi
      helm_rollback "${to_rev}"
    else
      error "Unknown command: ${CMD}"
      usage
      exit 2
    fi
    ;;
esac
