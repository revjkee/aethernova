#!/usr/bin/env bash
# Industrial deployment script for ledger-core
# Shell: bash 4+
# Copyright: MIT

set -Eeuo pipefail

# -------------- Defaults / Config --------------
APP_DEFAULT="ledger-core"
REGISTRY_DEFAULT="${REGISTRY:-}"                 # e.g. ghcr.io/org
IMAGE_DEFAULT="${IMAGE:-${REGISTRY_DEFAULT}/${APP_DEFAULT}}"
KUBE_CONTEXT_DEFAULT="${KUBE_CONTEXT:-}"
KUBE_NS_DEFAULT="${KUBE_NAMESPACE:-ledger}"
HELM_CHART_DEFAULT="${HELM_CHART:-./deploy/helm/ledger-core}"
HELM_VALUES_DEFAULT="${HELM_VALUES:-}"
TIMEOUT_DEFAULT="${TIMEOUT:-300s}"
LOG_DIR="${LOG_DIR:-./.deploy}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/deploy_$(date +%Y%m%d_%H%M%S).log}"
VERSION_FILE="${VERSION_FILE:-./VERSION}"
CHANGELOG_FILE="${CHANGELOG_FILE:-./CHANGELOG.md}"

DRY_RUN=false
RUN_TESTS=true
BUILD_DOCKER=true
DEPLOY_K8S=true
PUSH_DOCKER=true

# -------------- Logging --------------
mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1

log() { printf "%s | %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
err() { printf "%s | ERROR | %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die() { err "$*"; exit 1; }

# -------------- Traps --------------
cleanup() { log "cleanup: done"; }
trap cleanup EXIT
trap 'die "interrupted"' INT
trap 'die "error on line $LINENO (exitcode=$?)"' ERR

# -------------- Usage --------------
usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --env NAME                Environment name (dev|staging|prod). Affects Helm values selection. Default: dev
  --app NAME                Application name. Default: ${APP_DEFAULT}
  --image NAME              Full image name (registry/repo). Default: ${IMAGE_DEFAULT:-<required or REGISTRY env>}
  --tag TAG                 Image tag. Default: read from VERSION file
  --registry URL            Container registry (if IMAGE not set). Example: ghcr.io/org
  --kube-context CTX        kubectl/helm context to use. Default: env KUBE_CONTEXT
  --namespace NS            Kubernetes namespace. Default: ${KUBE_NS_DEFAULT}
  --helm-chart PATH         Helm chart path or packaged chart. Default: ${HELM_CHART_DEFAULT}
  --values PATH[,PATH...]   Extra Helm values files (comma-separated). Default: env HELM_VALUES
  --timeout DURATION        Helm --timeout (e.g., 300s). Default: ${TIMEOUT_DEFAULT}
  --dry-run                 Perform a dry run (no changes)
  --no-tests                Skip tests
  --no-docker               Skip Docker build/push
  --no-push                 Build but do not push image
  --no-k8s                  Skip Kubernetes release
  --blue                    Set canary/blue flag via Helm values (service route stays on green)
  --green                   Set canary/green flag via Helm values (switch route to green)
  -h|--help                 Show this help

Environment:
  REGISTRY, IMAGE, KUBE_CONTEXT, KUBE_NAMESPACE, HELM_CHART, HELM_VALUES, TIMEOUT, LOG_DIR, VERSION_FILE
EOF
}

# -------------- Args --------------
ENV_NAME="dev"
APP_NAME="${APP_DEFAULT}"
IMAGE_NAME="${IMAGE_DEFAULT}"
TAG=""
REGISTRY_URL="${REGISTRY_DEFAULT}"
KUBE_CONTEXT="${KUBE_CONTEXT_DEFAULT}"
KUBE_NS="${KUBE_NS_DEFAULT}"
HELM_CHART="${HELM_CHART_DEFAULT}"
HELM_VALUES="${HELM_VALUES_DEFAULT}"
TIMEOUT="${TIMEOUT_DEFAULT}"
FLAG_BLUE=false
FLAG_GREEN=false

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env) ENV_NAME="$2"; shift 2;;
      --app) APP_NAME="$2"; shift 2;;
      --image) IMAGE_NAME="$2"; shift 2;;
      --registry) REGISTRY_URL="$2"; shift 2;;
      --tag) TAG="$2"; shift 2;;
      --kube-context) KUBE_CONTEXT="$2"; shift 2;;
      --namespace) KUBE_NS="$2"; shift 2;;
      --helm-chart) HELM_CHART="$2"; shift 2;;
      --values) HELM_VALUES="$2"; shift 2;;
      --timeout) TIMEOUT="$2"; shift 2;;
      --dry-run) DRY_RUN=true; shift;;
      --no-tests) RUN_TESTS=false; shift;;
      --no-docker) BUILD_DOCKER=false; shift;;
      --no-push) PUSH_DOCKER=false; shift;;
      --no-k8s) DEPLOY_K8S=false; shift;;
      --blue) FLAG_BLUE=true; shift;;
      --green) FLAG_GREEN=true; shift;;
      -h|--help) usage; exit 0;;
      *) err "unknown option: $1"; usage; exit 2;;
    esac
  done
}

parse_args "$@"

# -------------- Preconditions --------------
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

need_tools() {
  need_cmd git
  need_cmd jq || true  # optional but useful
  need_cmd awk
  need_cmd sed
  if "${BUILD_DOCKER}"; then need_cmd docker; fi
  if "${DEPLOY_K8S}"; then need_cmd helm; need_cmd kubectl; fi
}

# -------------- Version / Tag --------------
read_version() {
  [[ -f "${VERSION_FILE}" ]] || die "VERSION file not found at ${VERSION_FILE}"
  local v
  v="$(tr -d '\n\r ' < "${VERSION_FILE}")"
  [[ -n "$v" ]] || die "empty VERSION"
  printf "%s" "$v"
}

# -------------- Git info --------------
git_rev() { git rev-parse --short=12 HEAD 2>/dev/null || echo "nogit"; }
git_dirty() { [[ -n "$(git status --porcelain 2>/dev/null || true)" ]] && echo "-dirty" || echo ""; }
git_branch() { git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown"; }

# -------------- SBOM / Checksums (optional) --------------
maybe_sbom() {
  if command -v syft >/dev/null 2>&1; then
    log "sbom: generating with syft"
    syft packages "dir:." -o spdx-json > "${LOG_DIR}/sbom_${APP_NAME}_${TAG}.spdx.json" || log "sbom: failed (non-fatal)"
  else
    log "sbom: syft not found, skipping"
  fi
}

sha256_file() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }

# -------------- Docker --------------
docker_build_push() {
  [[ -n "${IMAGE_NAME}" ]] || IMAGE_NAME="${REGISTRY_URL}/${APP_NAME}"
  [[ -n "${TAG}" ]] || TAG="$(read_version)"
  local full="${IMAGE_NAME}:${TAG}"
  local rev branch dirty
  rev="$(git_rev)"; branch="$(git_branch)"; dirty="$(git_dirty)"

  log "docker: building ${full}"
  local build_args=(
    --pull
    --build-arg "VCS_REF=${rev}"
    --build-arg "VCS_BRANCH=${branch}"
    --build-arg "BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    --build-arg "APP_VERSION=${TAG}"
    -t "${full}"
    .
  )
  if "${DRY_RUN}"; then
    log "[dry-run] docker build ${build_args[*]}"
  else
    docker build "${build_args[@]}"
  fi

  if "${PUSH_DOCKER}"; then
    if "${DRY_RUN}"; then
      log "[dry-run] docker push ${full}"
    else
      log "docker: pushing ${full}"
      docker push "${full}"
    fi
  fi

  echo "${full}"
}

# -------------- Tests (placeholder) --------------
run_tests() {
  if ! "${RUN_TESTS}"; then log "tests: skipped"; return 0; fi
  if command -v pytest >/dev/null 2>&1; then
    if "${DRY_RUN}"; then
      log "[dry-run] pytest -q"
    else
      log "tests: running pytest"
      pytest -q
    fi
  else
    log "tests: pytest not found, skipping"
  fi
}

# -------------- Helm Deploy --------------
helm_values_args() {
  local args=()
  [[ -n "${HELM_VALUES}" ]] && IFS=',' read -ra _v <<< "${HELM_VALUES}" && for f in "${_v[@]}"; do args+=( -f "$f" ); done
  # environment specific values files if exist: values-<env>.yaml
  local env_vals="${HELM_CHART}/values-${ENV_NAME}.yaml"
  [[ -f "${env_vals}" ]] && args+=( -f "${env_vals}" )
  # blue/green flags via --set
  if "${FLAG_BLUE}"; then args+=( --set "routing.blue=true" --set "routing.green=false" ); fi
  if "${FLAG_GREEN}"; then args+=( --set "routing.blue=false" --set "routing.green=true" ); fi
  echo "${args[@]}"
}

kubectl_wait_rollout() {
  local selector="$1"
  local kind="${2:-deployment}"
  local to="${3:-300s}"
  if "${DRY_RUN}"; then
    log "[dry-run] kubectl rollout status ${kind} -l ${selector} -n ${KUBE_NS} --timeout=${to}"
  else
    kubectl --context "${KUBE_CONTEXT}" -n "${KUBE_NS}" rollout status "${kind}" -l "${selector}" --timeout="${to}"
  fi
}

helm_release_name() {
  # Ensure a stable helm release name per env/app
  echo "${APP_NAME}-${ENV_NAME}"
}

helm_deploy() {
  "${DEPLOY_K8S}" || { log "k8s: skipped"; return 0; }

  need_cmd helm; need_cmd kubectl
  [[ -n "${KUBE_NS}" ]] || die "namespace required"
  [[ -n "${KUBE_CONTEXT}" ]] || log "k8s: KUBE_CONTEXT not set, using current context"

  if ! "${DRY_RUN}"; then
    kubectl --context "${KUBE_CONTEXT}" get ns "${KUBE_NS}" >/dev/null 2>&1 || kubectl --context "${KUBE_CONTEXT}" create ns "${KUBE_NS}"
  else
    log "[dry-run] ensure namespace ${KUBE_NS}"
  fi

  local rel; rel="$(helm_release_name)"
  local image_full="${1}" # image:tag from build
  local extra_values; extra_values="$(helm_values_args)"

  local helm_args=(
    upgrade "${rel}" "${HELM_CHART}"
    --install
    --namespace "${KUBE_NS}"
    --create-namespace
    --atomic
    --wait
    --timeout "${TIMEOUT}"
    --set "image.repository=$(echo "${image_full}" | awk -F: '{print $1}')"
    --set "image.tag=$(echo "${image_full}" | awk -F: '{print $2}')"
    --set "app.version=${TAG}"
    --set "app.env=${ENV_NAME}"
  )

  # shellcheck disable=SC2206
  helm_args=(${helm_args[@]} ${extra_values})

  if "${DRY_RUN}"; then
    log "[dry-run] helm ${helm_args[*]}"
    return 0
  fi

  log "helm: deploying release=${rel}"
  if ! helm --kube-context "${KUBE_CONTEXT}" "${helm_args[@]}"; then
    err "helm: upgrade failed, attempting rollback"
    helm --kube-context "${KUBE_CONTEXT}" rollback "${rel}" >/dev/null 2>&1 || true
    return 1
  fi

  # Optional health selector from chart labels
  local selector="app.kubernetes.io/name=${APP_NAME},app.kubernetes.io/instance=${rel}"
  kubectl_wait_rollout "${selector}" deployment "${TIMEOUT}"
}

# -------------- Main --------------
main() {
  log "deploy: start"
  need_tools

  [[ -n "${IMAGE_NAME}" ]] || [[ -n "${REGISTRY_URL}" ]] || die "IMAGE or REGISTRY must be provided"

  [[ -n "${TAG}" ]] || TAG="$(read_version)"
  log "version: ${TAG} | branch=$(git_branch) | rev=$(git_rev)$(git_dirty)"

  run_tests

  local image_ref="skip"
  if "${BUILD_DOCKER}"; then
    image_ref="$(docker_build_push)"
  else
    [[ -n "${IMAGE_NAME}" && -n "${TAG}" ]] && image_ref="${IMAGE_NAME}:${TAG}"
    log "docker: build skipped, using ${image_ref}"
  fi

  maybe_sbom

  if "${DEPLOY_K8S}"; then
    helm_deploy "${image_ref}"
  fi

  log "deploy: success image=${image_ref} env=${ENV_NAME} ns=${KUBE_NS} context=${KUBE_CONTEXT:-current}"
}

main "$@"
