#!/usr/bin/env bash
# cybersecurity-core/scripts/policy_push.sh
# Industrial Policy-as-Code deployer for Kubernetes and OPA.
# Supports: k8s YAML (inc. Kyverno/Gatekeeper/Falco as manifests), OPA Rego/Data.
# Author: Aethernova / NeuroCity

set -Eeuo pipefail

# --------------------------- Defaults -----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

POLICY_DIR="${REPO_ROOT}/policies"
TARGETS=("kubernetes" "opa")     # default targets
KUBE_CONTEXT=""
KUBE_NAMESPACE=""
OPA_URL=""
OPA_TOKEN=""
DRY_RUN="false"
VALIDATE="false"
FORCE="false"
VERBOSE="false"
SIGN_MODE="none"                 # none|gpg
GPG_KEY_ID=""                    # e.g. ABCDEF12
CACHE_DIR="${REPO_ROOT}/.cache/policy"
ARTIFACTS_DIR="${REPO_ROOT}/.artifacts/policy"
HASH_FILE_K8S="${CACHE_DIR}/k8s.hash"
HASH_FILE_OPA="${CACHE_DIR}/opa.hash"

# --------------------------- Colors & Log -------------------------------------
: "${NO_COLOR:=}"
if [[ -t 1 && -z "${NO_COLOR}" ]]; then
  c_reset=$'\033[0m'; c_dim=$'\033[2m'; c_red=$'\033[31m'; c_green=$'\033[32m'; c_yellow=$'\033[33m'; c_blue=$'\033[34m'
else
  c_reset=""; c_dim=""; c_red=""; c_green=""; c_yellow=""; c_blue=""
fi

log()  { echo "${c_dim}[$(date +'%H:%M:%S')]${c_reset} $*"; }
info() { echo "${c_blue}[INFO]${c_reset} $*"; }
ok()   { echo "${c_green}[OK]${c_reset} $*"; }
warn() { echo "${c_yellow}[WARN]${c_reset} $*"; }
err()  { echo "${c_red}[ERROR]${c_reset} $*" >&2; }

trap 'err "Failure on line $LINENO"; exit 1' ERR

# --------------------------- Usage --------------------------------------------
usage() {
  cat <<'USAGE'
policy_push.sh — Industrial Policy-as-Code deployer

Usage:
  scripts/policy_push.sh [options]

Options:
  --policies DIR          Root dir with policies. Default: ./policies
  --targets LIST          Comma-separated: kubernetes,opa,all. Default: kubernetes,opa
  --kubecontext NAME      kubectl context
  --namespace NS          Default namespace for kubectl apply (optional)
  --opa-url URL           OPA base URL, e.g. http://localhost:8181
  --opa-token TOKEN       OPA Bearer token (optional)
  --dry-run               Do not change remote state (k8s server-side dry-run; OPA skip writes)
  --validate              Validate policies before push (kubeconform, opa check/fmt)
  --force                 Ignore cache and push anyway
  --verbose               Verbose logging
  --sign MODE             none|gpg  (sign artifacts tarball in .artifacts/policy)
  --gpg-key-id ID         GPG key id/email for --sign gpg
  -h, --help              Show help

Layout expectations (can be customized by repo):
  policies/
    kubernetes/           # *.yaml|*.yml manifests or kustomize trees
    opa/
      policies/           # *.rego policies
      data/               # *.json|*.yaml document data (converted to JSON)

Examples:
  scripts/policy_push.sh --targets kubernetes --kubecontext prod --validate
  scripts/policy_push.sh --targets opa --opa-url http://opa:8181 --opa-token "$TOKEN"
  scripts/policy_push.sh --dry-run --sign gpg --gpg-key-id secops@org.io
USAGE
}

# --------------------------- Helpers ------------------------------------------
contains_word() {
  local x="$1"; shift
  for t in "$@"; do [[ "$t" == "$x" ]] && return 0; done
  return 1
}
join_by() { local IFS="$1"; shift; echo "$*"; }
ensure_dir() { mkdir -p "$1"; }

check_cmd() { command -v "$1" >/dev/null 2>&1; }

read_targets() {
  local list="$1"
  IFS=',' read -r -a TARGETS <<< "$list"
  if contains_word "all" "${TARGETS[@]}"; then
    TARGETS=("kubernetes" "opa")
  fi
}

hash_tree() {
  local dir="$1" ; local pattern="$2"
  find "$dir" -type f -regextype posix-extended -regex "$pattern" -print0 2>/dev/null \
    | sort -z \
    | xargs -0 sha256sum 2>/dev/null || true
}

compute_k8s_hash() {
  { echo "kubecontext=${KUBE_CONTEXT}"; echo "namespace=${KUBE_NAMESPACE}";
    hash_tree "${POLICY_DIR}/kubernetes" '.+\.(yaml|yml)$';
  } | sha256sum | awk '{print $1}'
}

compute_opa_hash() {
  { echo "opa_url=${OPA_URL}";
    hash_tree "${POLICY_DIR}/opa/policies" '.+\.rego$';
    hash_tree "${POLICY_DIR}/opa/data" '.+\.(json|ya?ml)$';
  } | sha256sum | awk '{print $1}'
}

opa_auth_header() {
  [[ -n "${OPA_TOKEN}" ]] && echo "Authorization: Bearer ${OPA_TOKEN}" || true
}

render_json_from_yaml() {
  # requires yq, outputs JSON to stdout
  yq -o=json -I=0 '.' "$1"
}

validate_k8s() {
  if check_cmd kubeconform; then
    info "kubeconform validating Kubernetes manifests..."
    kubeconform -strict -summary -ignore-missing-schemas \
      -schema-location default \
      -schema-location 'https://raw.githubusercontent.com/yannh/kubernetes-json-schema/master/{{.NormalizedKubernetesVersion}}-standalone/{{.ResourceKind}}.json' \
      "$(find "${POLICY_DIR}/kubernetes" -type f -name '*.y*ml' -print0 | xargs -0 echo)" || {
        err "kubeconform validation failed"; exit 1; }
    ok "kubeconform validation passed."
  else
    warn "kubeconform not found; skipping k8s schema validation."
  fi
}

validate_opa() {
  if check_cmd opa; then
    if [[ -d "${POLICY_DIR}/opa/policies" ]]; then
      info "opa check policies..."
      opa check "$(find "${POLICY_DIR}/opa/policies" -type f -name '*.rego' -print0 | xargs -0 echo)" || {
        err "opa check failed"; exit 1; }
      ok "opa check passed."
      info "opa fmt (verify formatting)..."
      opa fmt -l "${POLICY_DIR}/opa/policies" >/dev/null || true
    fi
  else
    warn "opa CLI not found; skipping OPA static checks."
  fi
}

sign_artifacts() {
  local tarball="$1"
  local sums="$2"
  case "${SIGN_MODE}" in
    gpg)
      check_cmd gpg || { err "gpg not found, cannot sign"; exit 1; }
      [[ -n "${GPG_KEY_ID}" ]] || { err "--gpg-key-id required for --sign gpg"; exit 1; }
      info "Signing artifacts with GPG key ${GPG_KEY_ID}..."
      gpg --batch --yes --local-user "${GPG_KEY_ID}" --armor --detach-sign -o "${tarball}.asc" "${tarball}"
      gpg --batch --yes --local-user "${GPG_KEY_ID}" --armor --detach-sign -o "${sums}.asc" "${sums}"
      ok "Signatures written: ${tarball}.asc, ${sums}.asc"
      ;;
    none|*)
      ;;
  esac
}

package_artifacts() {
  ensure_dir "${ARTIFACTS_DIR}"
  local ts="$(date -u +'%Y%m%dT%H%M%SZ')"
  local artifact="${ARTIFACTS_DIR}/policies-${ts}.tar.gz"
  local sums="${ARTIFACTS_DIR}/policies-${ts}.sha256"

  tar -C "${POLICY_DIR}" -czf "${artifact}" \
    $( [[ -d "${POLICY_DIR}/kubernetes" ]] && echo "kubernetes" ) \
    $( [[ -d "${POLICY_DIR}/opa" ]] && echo "opa" )
  sha256sum "${artifact}" > "${sums}"
  info "Artifacts packaged: ${artifact}"
  sign_artifacts "${artifact}" "${sums}"
}

kubectl_apply_file() {
  local file="$1"
  local args=(apply -f "$file")
  [[ -n "${KUBE_CONTEXT}" ]] && args+=(--context "${KUBE_CONTEXT}")
  [[ -n "${KUBE_NAMESPACE}" ]] && args+=(--namespace "${KUBE_NAMESPACE}")
  [[ "${DRY_RUN}" == "true" ]] && args+=(--dry-run=server)
  # Prefer server-side apply for better conflicts diagnostics
  args+=(--server-side --force-conflicts)
  if [[ "${VERBOSE}" == "true" ]]; then set -x; fi
  kubectl "${args[@]}"
  if [[ "${VERBOSE}" == "true" ]]; then set +x; fi
}

kubectl_apply_path() {
  local path="$1"
  if [[ -f "${path}/kustomization.yaml" || -f "${path}/Kustomization" ]]; then
    local args=(apply -k "${path}")
    [[ -n "${KUBE_CONTEXT}" ]] && args+=(--context "${KUBE_CONTEXT}")
    [[ -n "${KUBE_NAMESPACE}" ]] && args+=(--namespace "${KUBE_NAMESPACE}")
    [[ "${DRY_RUN}" == "true" ]] && args+=(--dry-run=server)
    args+=(--server-side --force-conflicts)
    [[ "${VERBOSE}" == "true" ]] && set -x
    kubectl "${args[@]}"
    [[ "${VERBOSE}" == "true" ]] && set +x
  else
    # apply all manifests in dir
    local files
    IFS=$'\n' read -r -d '' -a files < <(find "${path}" -type f -name '*.y*ml' -print0 | xargs -0 -I{} echo {} && printf '\0')
    for f in "${files[@]}"; do kubectl_apply_file "$f"; done
  fi
}

push_kubernetes() {
  check_cmd kubectl || { err "kubectl is required for target=kubernetes"; exit 1; }
  [[ -d "${POLICY_DIR}/kubernetes" ]] || { warn "No policies/kubernetes directory; skipping Kubernetes."; return 0; }

  [[ "${VALIDATE}" == "true" ]] && validate_k8s

  local new_hash
  new_hash="$(compute_k8s_hash)"
  if [[ "${FORCE}" != "true" ]] && [[ -f "${HASH_FILE_K8S}" ]] && [[ "${new_hash}" == "$(cat "${HASH_FILE_K8S}")" ]]; then
    ok "Kubernetes policies unchanged. Skip apply."
    return 0
  fi

  info "Applying Kubernetes policies from ${POLICY_DIR}/kubernetes ..."
  # Apply kustomize bases first (if any), then the rest deterministically
  if [[ -f "${POLICY_DIR}/kubernetes/kustomization.yaml" || -f "${POLICY_DIR}/kubernetes/Kustomization" ]]; then
    kubectl_apply_path "${POLICY_DIR}/kubernetes"
  else
    # sort to ensure CRDs first if present
    # naive order: crd -> ns -> rbac -> everything else
    mapfile -t crds < <(grep -lR --null -e 'kind: *CustomResourceDefinition' "${POLICY_DIR}/kubernetes" | xargs -0 -I{} echo {})
    for f in "${crds[@]:-}"; do kubectl_apply_file "$f"; done
    # then the rest
    mapfile -t rest < <(find "${POLICY_DIR}/kubernetes" -type f -name '*.y*ml' -print | sort)
    for f in "${rest[@]:-}"; do
      # skip already-applied CRDs
      if [[ " ${crds[*]-} " == *" $f "* ]]; then continue; fi
      kubectl_apply_file "$f"
    done
  fi

  ensure_dir "${CACHE_DIR}"
  echo "${new_hash}" > "${HASH_FILE_K8S}"
  ok "Kubernetes push complete."
}

# --------------------------- OPA (REST) ---------------------------------------
opa_put_policy() {
  local file="$1"
  local id="$2" # policy id
  local url="${OPA_URL%/}/v1/policies/${id}"

  [[ "${DRY_RUN}" == "true" ]] && { info "DRY-RUN OPA PUT policy ${id} <- ${file}"; return 0; }

  local hdrs=(-H "Content-Type: text/plain")
  local auth; auth="$(opa_auth_header || true)"
  [[ -n "${auth}" ]] && hdrs+=(-H "${auth}")

  if [[ "${VERBOSE}" == "true" ]]; then set -x; fi
  curl -fsSL -X PUT "${url}" "${hdrs[@]}" --data-binary "@${file}" >/dev/null
  if [[ "${VERBOSE}" == "true" ]]; then set +x; fi
}

opa_put_data() {
  local file="$1" # json or yaml
  # ID path derived from relative path under data/, dots from dirs -> dots in data path
  local rel="${file#"${POLICY_DIR}/opa/data/"}"
  local keypath
  keypath="$(echo "${rel%.*}" | sed 's#/#.#g')"
  local url="${OPA_URL%/}/v1/data/${keypath}"

  [[ "${DRY_RUN}" == "true" ]] && { info "DRY-RUN OPA PUT data ${keypath} <- ${file}"; return 0; }

  local payload
  case "$file" in
    *.json) payload="$(cat "$file")" ;;
    *.yml|*.yaml) check_cmd yq || { err "yq is required for YAML data files"; exit 1; }
                  payload="$(render_json_from_yaml "$file")" ;;
    *) err "Unsupported data file: $file"; exit 1 ;;
  esac

  local hdrs=(-H "Content-Type: application/json")
  local auth; auth="$(opa_auth_header || true)"
  [[ -n "${auth}" ]] && hdrs+=(-H "${auth}")

  if [[ "${VERBOSE}" == "true" ]]; then set -x; fi
  curl -fsSL -X PUT "${url}" "${hdrs[@]}" --data "${payload}" >/dev/null
  if [[ "${VERBOSE}" == "true" ]]; then set +x; fi
}

push_opa() {
  [[ -n "${OPA_URL}" ]] || { warn "OPA URL not provided; skipping OPA."; return 0; }
  check_cmd curl || { err "curl is required for target=opa"; exit 1; }
  [[ -d "${POLICY_DIR}/opa" ]] || { warn "No policies/opa directory; skipping OPA."; return 0; }

  [[ "${VALIDATE}" == "true" ]] && validate_opa

  local new_hash
  new_hash="$(compute_opa_hash)"
  if [[ "${FORCE}" != "true" ]] && [[ -f "${HASH_FILE_OPA}" ]] && [[ "${new_hash}" == "$(cat "${HASH_FILE_OPA}")" ]]; then
    ok "OPA policies unchanged. Skip push."
    return 0
  fi

  # Push data first (so policies can reference it)
  if [[ -d "${POLICY_DIR}/opa/data" ]]; then
    info "Pushing OPA data documents..."
    mapfile -t data_files < <(find "${POLICY_DIR}/opa/data" -type f \( -name '*.json' -o -name '*.ya?ml' \) -print | sort)
    for f in "${data_files[@]:-}"; do opa_put_data "$f"; done
  fi

  # Push policies
  if [[ -d "${POLICY_DIR}/opa/policies" ]]; then
    info "Pushing OPA policies..."
    mapfile -t rego_files < <(find "${POLICY_DIR}/opa/policies" -type f -name '*.rego' -print | sort)
    for f in "${rego_files[@]:-}"; do
      # policy id derived from relative path with slashes
      local rel="${f#"${POLICY_DIR}/opa/policies/"}"
      local id="$(echo "${rel%.*}" | sed 's# #_#g')"
      opa_put_policy "$f" "$id"
    done
  fi

  ensure_dir "${CACHE_DIR}"
  echo "${new_hash}" > "${HASH_FILE_OPA}"
  ok "OPA push complete."
}

# --------------------------- Arg Parsing --------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --policies)   POLICY_DIR="$2"; shift 2 ;;
    --targets)    read_targets "$2"; shift 2 ;;
    --kubecontext) KUBE_CONTEXT="$2"; shift 2 ;;
    --namespace)  KUBE_NAMESPACE="$2"; shift 2 ;;
    --opa-url)    OPA_URL="$2"; shift 2 ;;
    --opa-token)  OPA_TOKEN="$2"; shift 2 ;;
    --dry-run)    DRY_RUN="true"; shift ;;
    --validate)   VALIDATE="true"; shift ;;
    --force)      FORCE="true"; shift ;;
    --verbose)    VERBOSE="true"; shift ;;
    --sign)       SIGN_MODE="$2"; shift 2 ;;
    --gpg-key-id) GPG_KEY_ID="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            err "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# Normalize policy dir
POLICY_DIR="$(cd "${POLICY_DIR}" 2>/dev/null && pwd -P || true)"
[[ -d "${POLICY_DIR}" ]] || { err "Policies directory not found: ${POLICY_DIR:-<empty>}"; exit 1; }

# --------------------------- Preflight ----------------------------------------
ensure_dir "${CACHE_DIR}"
ensure_dir "${ARTIFACTS_DIR}"

# Tool presence hints (non-fatal if not required)
contains_word "kubernetes" "${TARGETS[@]}" && check_cmd kubectl || true
contains_word "opa"        "${TARGETS[@]}" && check_cmd curl || true

# --------------------------- Validate (optional) -------------------------------
if [[ "${VALIDATE}" == "true" ]]; then
  contains_word "kubernetes" "${TARGETS[@]}" && validate_k8s
  contains_word "opa"        "${TARGETS[@]}" && validate_opa
fi

# --------------------------- Package & Sign -----------------------------------
package_artifacts

# --------------------------- Push per target ----------------------------------
for t in "${TARGETS[@]}"; do
  case "$t" in
    kubernetes) push_kubernetes ;;
    opa)        push_opa ;;
    *)          warn "Unsupported target: $t (skipped)";;
  esac
done

ok "Policy push finished."
