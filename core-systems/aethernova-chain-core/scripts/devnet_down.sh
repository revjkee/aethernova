#!/usr/bin/env bash
# aethernova-chain-core/scripts/devnet_down.sh
# Industrial-grade teardown script for DevNet (Docker Compose + Kubernetes + Helm + optional Terraform)
# Safe by default. Destructive actions require explicit flags or confirmation.

set -Eeuo pipefail

################################################################################
# CONFIG & DEFAULTS
################################################################################

# Defaults (override via env or flags)
STACK="${STACK:-all}"                              # docker|k8s|all
NAMESPACE="${DEVNET_NAMESPACE:-devnet}"            # k8s namespace to clean
K8S_CONTEXT="${K8S_CONTEXT:-}"                     # optional kubectl context
CLUSTER_NAME="${DEVNET_CLUSTER_NAME:-devnet}"      # for kind/k3d/minikube deletion
TF_DIR="${DEVNET_TF_DIR:-}"                        # path to terraform env (optional)
HELM_SELECTOR="${HELM_SELECTOR:-}"                 # label selector for releases (optional)

YES="${YES:-false}"                                # --yes to skip prompts
DRY_RUN="${DRY_RUN:-false}"                        # --dry-run to print actions only
PURGE="${PURGE:-false}"                            # also prune volumes/networks/images where applicable
DELETE_NAMESPACE="${DELETE_NAMESPACE:-false}"      # delete k8s namespace entirely
ZAP_FINALIZERS="${ZAP_FINALIZERS:-false}"          # force-remove finalizers if stuck (dangerous)
DELETE_CLUSTER="${DELETE_CLUSTER:-false}"          # delete local cluster (kind/k3d/minikube)
DESTROY_TF="${DESTROY_TF:-false}"                  # terraform destroy for TF_DIR

# Compose file autodetection (overridden via --compose-file)
COMPOSE_FILE="${DEVNET_COMPOSE_FILE:-}"
CANDIDATE_COMPOSE_FILES=(
  "./docker-compose.devnet.yml"
  "./compose.devnet.yml"
  "./docker/devnet.compose.yml"
  "./ops/docker/compose/devnet.yaml"
  "./docker-compose.yml"
)

# Timeouts
K8S_DELETE_TIMEOUT="${K8S_DELETE_TIMEOUT:-300s}"
NS_TERMINATION_TIMEOUT="${NS_TERMINATION_TIMEOUT:-300}"  # seconds

################################################################################
# LOGGING & UX
################################################################################

is_tty() { [[ -t 1 ]]; }
if is_tty; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_CYN=$'\033[36m'
else
  C_RESET=""; C_DIM=""; C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""
fi

log()   { printf "%s[devnet-down]%s %s\n" "$C_DIM" "$C_RESET" "$*"; }
info()  { printf "%s[INFO]%s  %s\n" "$C_CYN" "$C_RESET" "$*"; }
warn()  { printf "%s[WARN]%s  %s\n" "$C_YEL" "$C_RESET" "$*"; }
err()   { printf "%s[ERROR]%s %s\n" "$C_RED" "$C_RESET" "$*"; }
ok()    { printf "%s[OK]%s    %s\n" "$C_GRN" "$C_RESET" "$*"; }

run() {
  local cmd="$*"
  if [[ "$DRY_RUN" == "true" ]]; then
    info "(dry-run) $cmd"
  else
    info "$cmd"
    eval "$cmd"
  fi
}

confirm() {
  local prompt="${1:-Proceed?} [y/N]: "
  if [[ "$YES" == "true" ]]; then return 0; fi
  if [[ -n "${CI:-}" ]]; then warn "CI detected; proceeding without prompt"; return 0; fi
  read -r -p "$prompt" ans || ans=""
  [[ "$ans" == "y" || "$ans" == "Y" ]]
}

have() { command -v "$1" >/dev/null 2>&1; }

cleanup() {
  local ec=$?
  if [[ $ec -ne 0 ]]; then err "Aborted with exit code $ec"; fi
}
trap cleanup EXIT

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --stack [docker|k8s|all]       Which stack to tear down (default: ${STACK})
  --namespace NAME               Kubernetes namespace (default: ${NAMESPACE})
  --context CTX                  kubectl context to use
  --compose-file FILE            Compose file path (auto-detected if omitted)
  --helm-selector LABELSEL       Helm label selector (uninstall only matching releases)
  --delete-namespace             Delete namespace entirely (asks confirm unless --yes)
  --zap-finalizers               Dangerous: remove finalizers from stuck resources
  --delete-cluster               Delete local cluster (tries kind/k3d/minikube)
  --destroy-tf --tf-dir PATH     Run 'terraform destroy' in PATH
  --purge                        Aggressive cleanup (volumes/networks/images)
  --dry-run                      Print actions only
  --yes                          Non-interactive (assume yes)
  -h|--help                      Help
EOF
}

################################################################################
# ARGS
################################################################################

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stack) STACK="$2"; shift 2;;
    --namespace) NAMESPACE="$2"; shift 2;;
    --context) K8S_CONTEXT="$2"; shift 2;;
    --compose-file) COMPOSE_FILE="$2"; shift 2;;
    --helm-selector) HELM_SELECTOR="$2"; shift 2;;
    --delete-namespace) DELETE_NAMESPACE=true; shift;;
    --zap-finalizers) ZAP_FINALIZERS=true; shift;;
    --delete-cluster) DELETE_CLUSTER=true; shift;;
    --destroy-tf) DESTROY_TF=true; shift;;
    --tf-dir) TF_DIR="$2"; shift 2;;
    --purge) PURGE=true; shift;;
    --dry-run) DRY_RUN=true; shift;;
    --yes) YES=true; shift;;
    -h|--help) usage; exit 0;;
    *) err "Unknown arg: $1"; usage; exit 2;;
  esac
done

################################################################################
# PREP
################################################################################

# Compose file autodetect
if [[ -z "$COMPOSE_FILE" ]]; then
  for f in "${CANDIDATE_COMPOSE_FILES[@]}"; do
    if [[ -f "$f" ]]; then COMPOSE_FILE="$f"; break; fi
  done
fi

# Compose command detection
COMPOSE_BIN=""
if have docker && docker compose version >/dev/null 2>&1; then
  COMPOSE_BIN="docker compose"
elif have docker-compose; then
  COMPOSE_BIN="docker-compose"
fi

# kubectl/helm presence when needed
need_k8s=false
case "$STACK" in
  k8s|all) need_k8s=true ;;
  docker)  need_k8s=false ;;
  *) err "Invalid --stack: $STACK"; exit 2;;
esac

if $need_k8s; then
  have kubectl || { err "kubectl is required for --stack=$STACK"; exit 1; }
  have helm || warn "helm not found; will skip Helm uninstalls"
fi

################################################################################
# HELPERS
################################################################################

kubectl_ctx() {
  if [[ -n "$K8S_CONTEXT" ]]; then echo "--context=\"$K8S_CONTEXT\""; fi
}

k_delete_all_in_ns() {
  # Deletes namespaced resources; namespace remains unless --delete-namespace
  local ns="$1"
  local kc; kc=$(kubectl_ctx)
  local timeout="${K8S_DELETE_TIMEOUT}"

  # Try helm uninstalls first (if helm available)
  if have helm; then
    if [[ -n "$HELM_SELECTOR" ]]; then
      local rels
      rels=$(helm list -n "$ns" -a -o json | jq -r ".[] | select(.labels | tostring | test(\"$HELM_SELECTOR\")) | .name" || true)
      if [[ -n "$rels" ]]; then
        while IFS= read -r r; do
          [[ -z "$r" ]] && continue
          run helm uninstall "$r" -n "$ns"
        done <<< "$rels"
      else
        info "No helm releases with selector '$HELM_SELECTOR' in ns/$ns"
      fi
    else
      # Uninstall everything in namespace
      local rels_all
      rels_all=$(helm list -n "$ns" -a -q 2>/dev/null || true)
      if [[ -n "$rels_all" ]]; then
        while IFS= read -r r; do
          [[ -z "$r" ]] && continue
          run helm uninstall "$r" -n "$ns"
        done <<< "$rels_all"
      else
        info "No helm releases in ns/$ns"
      fi
    fi
  fi

  # Delete common resources
  local kinds=(
    "ingress,service,endpoint,endpointslice"
    "deployment,statefulset,daemonset,replicaset"
    "job,cronjob"
    "pod,pdb,hpa,configmap,secret,serviceaccount"
    "networkpolicy,role,rolebinding"
    "persistentvolumeclaim"
  )

  for g in "${kinds[@]}"; do
    run kubectl $kc -n "$ns" delete "$g" --ignore-not-found --all --wait=true --timeout="$timeout"
  done
}

k_delete_namespace() {
  local ns="$1"
  local kc; kc=$(kubectl_ctx)
  if [[ "$ns" == "kube-system" || "$ns" == "kube-public" || "$ns" == "kube-node-lease" ]]; then
    err "Refusing to delete critical namespace: $ns"; return 1
  fi

  if confirm "Delete namespace '$ns' and all its resources?"; then
    run kubectl $kc delete namespace "$ns" --wait=true --timeout="$K8S_DELETE_TIMEOUT" || true

    # Wait for termination
    local waited=0
    while kubectl $kc get ns "$ns" >/dev/null 2>&1; do
      [[ "$DRY_RUN" == "true" ]] && break
      if (( waited >= NS_TERMINATION_TIMEOUT )); then
        warn "Namespace '$ns' still Terminating after ${NS_TERMINATION_TIMEOUT}s"
        if [[ "$ZAP_FINALIZERS" == "true" ]]; then
          warn "Attempting dangerous finalizer removal for ns/$ns"
          # Remove finalizers from namespaced resources
          local kinds=(pods services deployments statefulsets daemonsets jobs cronjobs pvc secrets configmaps rolebindings roles serviceaccounts networkpolicies pdb hpa)
          for k in "${kinds[@]}"; do
            # Patch each resource to clear metadata.finalizers
            mapfile -t items < <(kubectl $kc -n "$ns" get "$k" -o name 2>/dev/null || true)
            for it in "${items[@]}"; do
              [[ -z "$it" ]] && continue
              run kubectl $kc -n "$ns" patch "$it" -p '{"metadata":{"finalizers":[]}}' --type=merge || true
            done
          done
          # Finally, clear ns finalizers
          run kubectl $kc patch ns "$ns" -p '{"metadata":{"finalizers":[]}}' --type=merge || true
        fi
        break
      fi
      sleep 2; waited=$(( waited + 2 ))
    done
  else
    warn "Namespace deletion cancelled by user"
  fi
}

docker_down() {
  if [[ -z "$COMPOSE_BIN" ]]; then
    warn "docker compose not available; skipping Docker teardown"
    return 0
  fi

  local cf_arg=""
  if [[ -n "$COMPOSE_FILE" ]]; then
    if [[ -f "$COMPOSE_FILE" ]]; then
      cf_arg="-f \"$COMPOSE_FILE\""
    else
      warn "Compose file not found: $COMPOSE_FILE (will try without -f)"
    fi
  fi

  # down with or without purge options
  if [[ "$PURGE" == "true" ]]; then
    run $COMPOSE_BIN $cf_arg down --remove-orphans --volumes
    # Optional network/image prune (interactive unless YES)
    if confirm "Prune Docker networks/images related to devnet?"; then
      run docker network prune -f
      run docker image prune -f
      run docker volume prune -f
    fi
  else
    run $COMPOSE_BIN $cf_arg down --remove-orphans
  fi
}

delete_cluster() {
  # Try kind, then k3d, then minikube
  local name="$CLUSTER_NAME"
  if have kind && kind get clusters | grep -qx "$name"; then
    if confirm "Delete kind cluster '$name'?"; then
      run kind delete cluster --name "$name"
    fi
    return
  fi
  if have k3d && k3d cluster list -o json | grep -q "\"name\":\"$name\""; then
    if confirm "Delete k3d cluster '$name'?"; then
      run k3d cluster delete "$name"
    fi
    return
  fi
  if have minikube && minikube status -p "$name" >/dev/null 2>&1; then
    if confirm "Delete minikube profile '$name'?"; then
      run minikube delete -p "$name"
    fi
    return
  fi
  warn "No local cluster named '$name' found (kind/k3d/minikube)"
}

terraform_destroy() {
  local dir="$1"
  if [[ -z "$dir" ]]; then warn "--destroy-tf requires --tf-dir PATH"; return 1; fi
  if ! have terraform; then warn "terraform not found; skipping destroy"; return 0; fi
  if [[ ! -d "$dir" ]]; then warn "Terraform dir not found: $dir"; return 0; fi
  if confirm "Run 'terraform destroy' in '$dir'?"; then
    if [[ "$DRY_RUN" == "true" ]]; then
      info "(dry-run) terraform -chdir=\"$dir\" destroy -auto-approve"
    else
      ( set -Eeuo pipefail; terraform -chdir="$dir" destroy -auto-approve )
    fi
  fi
}

################################################################################
# EXECUTION
################################################################################

info "Stack: $STACK | Namespace: $NAMESPACE | Context: ${K8S_CONTEXT:-default} | Compose: ${COMPOSE_FILE:-auto} | Dry-run: $DRY_RUN"

case "$STACK" in
  docker)
    docker_down
    ;;
  k8s)
    k_delete_all_in_ns "$NAMESPACE"
    if [[ "$DELETE_NAMESPACE" == "true" ]]; then
      k_delete_namespace "$NAMESPACE"
    fi
    ;;
  all)
    # Prefer to remove Helm/K8s first, then Docker
    if $need_k8s; then
      k_delete_all_in_ns "$NAMESPACE"
      if [[ "$DELETE_NAMESPACE" == "true" ]]; then
        k_delete_namespace "$NAMESPACE"
      fi
    fi
    docker_down
    ;;
esac

if [[ "$DELETE_CLUSTER" == "true" ]]; then
  delete_cluster
fi

if [[ "$DESTROY_TF" == "true" ]]; then
  terraform_destroy "$TF_DIR"
fi

ok "DevNet teardown completed."
