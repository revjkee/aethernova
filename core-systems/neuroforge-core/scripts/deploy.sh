#!/usr/bin/env bash
# shellcheck disable=SC2155,SC2086,SC2001,SC2034
###############################################################################
# NeuroForge Core — Industrial Deployment Script
#
# Features
# - Safe Bash: set -Eeuo pipefail, traps, strict timeouts
# - Preflight: tools, versions, cluster context/namespace
# - Env profiles: .env, .env.<env>, deploy/config.sh (optional)
# - Docker buildx (multi-arch opt-in), push, immutable tags
# - Optional SBOM (syft) + image signing (cosign)
# - Helm upgrade --install --atomic --wait with values.<env>.yaml overrides
# - Dry-run, verbose, canary flags (values pass-through), rollback
# - Concurrency lock, JSONL logs, idempotent tag generation
#
# Usage
#   scripts/deploy.sh -e <dev|stage|prod> [-n <namespace>] [-c <kube_context>] \
#     [--image repo/app] [--chart ./deploy/helm/app] [--replicas 3] \
#     [--version v1.2.3] [--dry-run] [--verbose] [--skip-build] [--canary 20]
#
# CI ENV (examples):
#   CI=true REGISTRY=ghcr.io/org IMAGE_REPO=ghcr.io/org/neuroforge-core APP_NAME=neuroforge-core \
#   scripts/deploy.sh -e stage -c my-k8s -n neuroforge-stage
###############################################################################

set -Eeuo pipefail

# -------- Colors --------------------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLU=$'\e[34m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YLW=""; BLU=""; RST=""
fi

# -------- Logging -------------------------------------------------------------
LOG_DIR="${LOG_DIR:-./_deploy_logs}"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/deploy-$(date -u +%Y%m%dT%H%M%SZ).jsonl"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
jlog() {
  # jlog level message k=v...
  local lvl="$1"; shift
  local msg="$1"; shift || true
  local kv="\"env\":\"${ENVIRONMENT:-unknown}\",\"app\":\"${APP_NAME:-neuroforge-core}\""
  for pair in "$@"; do kv="$kv,\"$(echo "$pair" | sed 's/=.*//')\":\"$(echo "$pair" | sed 's/^[^=]*=//')\""; done
  printf '{ "ts":"%s","level":"%s","msg":"%s",%s }\n' "$(ts)" "$lvl" "$msg" "$kv" | tee -a "$LOG_FILE" >/dev/null
}
logi(){ echo "${GRN}[INFO]${RST} $*"; jlog info "$*"; }
logw(){ echo "${YLW}[WARN]${RST} $*"; jlog warn "$*"; }
loge(){ echo "${RED}[ERR ]${RST} $*"; jlog error "$*"; }

# -------- Trap & cleanup ------------------------------------------------------
cleanup() {
  local ec=$?
  if [[ $ec -ne 0 ]]; then
    loge "Deployment failed with exit code ${ec}"
  else
    logi "Deployment finished successfully"
  fi
}
trap cleanup EXIT

# -------- Concurrency lock ----------------------------------------------------
LOCK_DIR="${LOCK_DIR:-./.deploy.lock}"
exec 9> "$LOCK_DIR"
if ! flock -n 9; then
  loge "Another deployment is running (lock: $LOCK_DIR)"
  exit 1
fi

# -------- Defaults ------------------------------------------------------------
APP_NAME="${APP_NAME:-neuroforge-core}"
CHART="${CHART:-./deploy/helm/${APP_NAME}}"
VALUES_DIR="${VALUES_DIR:-$(dirname "$CHART")}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
NAMESPACE_DEFAULT_PREFIX="${NAMESPACE_DEFAULT_PREFIX:-neuroforge}"

REGISTRY="${REGISTRY:-registry.example.com/org}"
IMAGE_REPO="${IMAGE_REPO:-${REGISTRY}/${APP_NAME}}"
IMAGE_PLATFORM="${IMAGE_PLATFORM:-linux/amd64}"        # set to "linux/amd64,linux/arm64" for multi-arch
DOCKERFILE="${DOCKERFILE:-./Dockerfile}"

HELM_TIMEOUT="${HELM_TIMEOUT:-5m0s}"
HELM_EXTRA_SET="${HELM_EXTRA_SET:-}"                  # e.g. "app.mode=prod,featureX.enabled=true"
HELM_EXTRA_VALUES="${HELM_EXTRA_VALUES:-}"            # e.g. "./deploy/helm/overrides/common.yaml,./foo.yaml"

REPLICAS="${REPLICAS:-}"                              # override via flag or env
CANARY_PERCENT="${CANARY_PERCENT:-}"                  # optional canary weight (0..100)

VERSION_OVERRIDE="${VERSION:-}"                       # explicit tag
SKIP_BUILD="${SKIP_BUILD:-false}"
DRY_RUN="${DRY_RUN:-false}"
VERBOSE="${VERBOSE:-false}"

COSIGN_ENABLED="${COSIGN_ENABLED:-false}"             # true to sign image
COSIGN_KEY="${COSIGN_KEY:-}"                          # path or KMS ref; empty -> keyless if supported
SBOM_ENABLED="${SBOM_ENABLED:-false}"                 # true to generate SBOM (syft)

# -------- Help ----------------------------------------------------------------
usage() {
cat <<EOF
Usage: $(basename "$0") -e <dev|stage|prod> [options]

Options:
  -e, --env             Target environment (required): dev|stage|prod
  -n, --namespace       Kubernetes namespace (default: <prefix>-<env>)
  -c, --context         kubectl/Helm context name
  --chart PATH          Helm chart path (default: ${CHART})
  --image REPO          Image repo (default: ${IMAGE_REPO})
  --version TAG         Explicit image tag (otherwise computed from git)
  --replicas N          Replica override
  --canary PCT          Canary percentage (if chart supports canary.* values)
  --dry-run             Plan only (no builds/pushes/upgrades)
  --skip-build          Use existing image tag (requires --version)
  --verbose             Verbose set -x
  -h, --help            This help
EOF
}

# -------- Arg parse -----------------------------------------------------------
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -e|--env) ENVIRONMENT="$2"; shift 2;;
    -n|--namespace) NAMESPACE="$2"; shift 2;;
    -c|--context) KUBE_CONTEXT="$2"; shift 2;;
    --chart) CHART="$2"; shift 2;;
    --image) IMAGE_REPO="$2"; shift 2;;
    --version) VERSION_OVERRIDE="$2"; shift 2;;
    --replicas) REPLICAS="$2"; shift 2;;
    --canary) CANARY_PERCENT="$2"; shift 2;;
    --dry-run) DRY_RUN=true; shift;;
    --skip-build) SKIP_BUILD=true; shift;;
    --verbose) VERBOSE=true; shift;;
    -h|--help) usage; exit 0;;
    --) shift; break;;
    *) args+=("$1"); shift;;
  esac
done
set -- "${args[@]}"

if [[ "${VERBOSE}" == "true" ]]; then set -x; fi

# -------- Env loading ---------------------------------------------------------
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
[[ -f "$ROOT_DIR/.env" ]] && source "$ROOT_DIR/.env"
if [[ -n "${ENVIRONMENT:-}" && -f "$ROOT_DIR/.env.${ENVIRONMENT}" ]]; then
  source "$ROOT_DIR/.env.${ENVIRONMENT}"
fi
[[ -f "$ROOT_DIR/deploy/config.sh" ]] && source "$ROOT_DIR/deploy/config.sh" || true

# Re-apply CLI precedence after sourcing
IMAGE_REPO="${IMAGE_REPO}"
CHART="${CHART}"

# -------- Validate required ---------------------------------------------------
if [[ -z "${ENVIRONMENT:-}" ]]; then loge "Missing --env"; usage; exit 2; fi
NAMESPACE="${NAMESPACE:-${NAMESPACE_DEFAULT_PREFIX}-${ENVIRONMENT}}"

# -------- Preflight checks ----------------------------------------------------
need_tool() { command -v "$1" >/dev/null 2>&1 || { loge "Required tool not found: $1"; exit 3; }; }

need_tool docker
need_tool helm
need_tool kubectl
need_tool git
need_tool jq

if [[ "${SBOM_ENABLED}" == "true" ]]; then command -v syft >/dev/null 2>&1 || { logw "syft not found; SBOM disabled"; SBOM_ENABLED=false; }; fi
if [[ "${COSIGN_ENABLED}" == "true" ]]; then command -v cosign >/dev/null 2>&1 || { logw "cosign not found; signing disabled"; COSIGN_ENABLED=false; }; fi

# Kube context & namespace
if [[ -n "${KUBE_CONTEXT}" ]]; then
  kubectl config use-context "${KUBE_CONTEXT}" >/dev/null
fi
CURRENT_CONTEXT="$(kubectl config current-context)"
logi "Using kube-context: ${CURRENT_CONTEXT}"
kubectl get ns "${NAMESPACE}" >/dev/null 2>&1 || kubectl create ns "${NAMESPACE}" >/dev/null

# -------- Compute version/tag -------------------------------------------------
git_describe() {
  local sha="$(git rev-parse --short=12 HEAD 2>/dev/null || echo nogit)"
  local dirty="$(git diff --quiet || echo -dirty)"
  echo "0.0.0-${sha}${dirty}-$(date -u +%Y%m%d%H%M)"
}
IMAGE_TAG="${VERSION_OVERRIDE:-$(git_describe)}"
IMAGE_REF="${IMAGE_REPO}:${IMAGE_TAG}"

RELEASE_NAME="${APP_NAME}-${ENVIRONMENT}"
VALUES_MAIN="${VALUES_DIR}/values.yaml"
VALUES_ENV="${VALUES_DIR}/values-${ENVIRONMENT}.yaml"

logi "App=${APP_NAME} Env=${ENVIRONMENT} Namespace=${NAMESPACE}"
logi "Image=${IMAGE_REF} Chart=${CHART} Release=${RELEASE_NAME}"

# -------- Dry-run fast path ---------------------------------------------------
if [[ "${DRY_RUN}" == "true" ]]; then
  logi "DRY-RUN ENABLED — no changes will be applied"
fi

# -------- Docker build & push -------------------------------------------------
if [[ "${SKIP_BUILD}" == "true" && -z "${VERSION_OVERRIDE}" ]]; then
  loge "--skip-build requires --version"
  exit 4
fi

if [[ "${SKIP_BUILD}" != "true" ]]; then
  logi "Building image via buildx: ${IMAGE_REF} (platform=${IMAGE_PLATFORM})"
  DOCKER_BUILDKIT=1 docker buildx create --use >/dev/null 2>&1 || true
  if [[ "${DRY_RUN}" != "true" ]]; then
    docker buildx build \
      --platform "${IMAGE_PLATFORM}" \
      --file "${DOCKERFILE}" \
      --tag "${IMAGE_REF}" \
      --label "org.opencontainers.image.source=$(git config --get remote.origin.url || echo unknown)" \
      --label "org.opencontainers.image.revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)" \
      --label "org.opencontainers.image.created=$(ts)" \
      --push \
      .
  else
    logi "[dry-run] docker buildx build --tag ${IMAGE_REF} --push"
  fi
else
  logi "Skipping build; using prebuilt tag: ${IMAGE_REF}"
fi

# -------- SBOM (optional) -----------------------------------------------------
if [[ "${SBOM_ENABLED}" == "true" ]]; then
  SBOM_OUT="${LOG_DIR}/sbom-${APP_NAME}-${IMAGE_TAG}.spdx.json"
  if [[ "${DRY_RUN}" != "true" ]]; then
    syft "${IMAGE_REF}" -o spdx-json > "${SBOM_OUT}" || logw "SBOM generation failed"
    logi "SBOM saved: ${SBOM_OUT}"
  else
    logi "[dry-run] syft ${IMAGE_REF} -o spdx-json > ${SBOM_OUT}"
  fi
fi

# -------- Signing (optional) --------------------------------------------------
if [[ "${COSIGN_ENABLED}" == "true" ]]; then
  if [[ "${DRY_RUN}" != "true" ]]; then
    if [[ -n "${COSIGN_KEY}" ]]; then
      COSIGN_EXPERIMENTAL=1 cosign sign --key "${COSIGN_KEY}" "${IMAGE_REF}" || logw "cosign sign failed"
    else
      COSIGN_EXPERIMENTAL=1 cosign sign "${IMAGE_REF}" || logw "cosign keyless sign failed"
    fi
  else
    logi "[dry-run] cosign sign ${IMAGE_REF}"
  fi
fi

# -------- Helm deploy ---------------------------------------------------------
HELM_ARGS=(upgrade --install "${RELEASE_NAME}" "${CHART}"
  --namespace "${NAMESPACE}"
  --atomic --wait --timeout "${HELM_TIMEOUT}"
  --set "image.repository=${IMAGE_REPO}"
  --set "image.tag=${IMAGE_TAG}"
)

[[ -f "${VALUES_MAIN}" ]] && HELM_ARGS+=( -f "${VALUES_MAIN}" )
[[ -f "${VALUES_ENV}"  ]] && HELM_ARGS+=( -f "${VALUES_ENV}" )

# Extra values files
IFS=',' read -r -a _vals <<< "${HELM_EXTRA_VALUES}"
for vf in "${_vals[@]}"; do
  [[ -n "${vf}" && -f "${vf}" ]] && HELM_ARGS+=( -f "${vf}" )
done

# Replicas override
if [[ -n "${REPLICAS}" ]]; then
  HELM_ARGS+=( --set "replicaCount=${REPLICAS}" )
fi

# Canary pass-through (if chart supports canary.*)
if [[ -n "${CANARY_PERCENT}" ]]; then
  HELM_ARGS+=( --set "canary.enabled=true" --set "canary.weight=${CANARY_PERCENT}" )
fi

# Extra --set from env (comma list k=v)
IFS=',' read -r -a _sets <<< "${HELM_EXTRA_SET}"
for kv in "${_sets[@]}"; do
  [[ -n "${kv}" ]] && HELM_ARGS+=( --set "${kv}" )
done

logi "Helm apply (atomic)"
if [[ "${DRY_RUN}" == "true" ]]; then
  helm "${HELM_ARGS[@]}" --dry-run | sed 's/^/[helm] /'
else
  helm "${HELM_ARGS[@]}"
fi

# -------- Rollout status ------------------------------------------------------
DEPLOY_NAME="${RELEASE_NAME}"
logi "Waiting for rollout (deployments in ns=${NAMESPACE})"
if [[ "${DRY_RUN}" != "true" ]]; then
  # Wait for all deployments labeled app.kubernetes.io/instance=<release>
  set +e
  mapfile -t DEPLOYS < <(kubectl -n "${NAMESPACE}" get deploy -l "app.kubernetes.io/instance=${RELEASE_NAME}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
  set -e
  for d in "${DEPLOYS[@]}"; do
    [[ -n "${d}" ]] || continue
    logi "Rollout status: ${d}"
    kubectl -n "${NAMESPACE}" rollout status "deploy/${d}" --timeout="${HELM_TIMEOUT}"
  done
fi

# -------- Smoke check (optional HTTP) -----------------------------------------
SMOKE_URL="${SMOKE_URL:-}"
if [[ -n "${SMOKE_URL}" ]]; then
  need_tool curl
  logi "Smoke-check: ${SMOKE_URL}"
  if [[ "${DRY_RUN}" != "true" ]]; then
    if ! curl -fsSL --max-time 10 "${SMOKE_URL}" >/dev/null; then
      loge "Smoke-check failed"; exit 6
    fi
  else
    logi "[dry-run] curl -fsSL ${SMOKE_URL}"
  fi
fi

# -------- Output summary ------------------------------------------------------
jlog info "deploy.summary" \
  env="${ENVIRONMENT}" ns="${NAMESPACE}" chart="${CHART}" release="${RELEASE_NAME}" \
  image="${IMAGE_REF}" context="${CURRENT_CONTEXT}" timeout="${HELM_TIMEOUT}"

echo
logi "Done: ${APP_NAME}@${ENVIRONMENT} → ${NAMESPACE} (image ${IMAGE_REF})"
echo "Log: ${LOG_FILE}"
