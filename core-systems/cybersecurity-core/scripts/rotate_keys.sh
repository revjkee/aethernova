#!/usr/bin/env bash
# cybersecurity-core/scripts/rotate_keys.sh
# Industrial key/secret rotation utility for multi-provider environments.
# Types: random, jwt, ssh, tls
# Providers: k8s, vault, file, aws-sm, gcp-sm, azure-kv
# Backup: age recipient or OpenSSL passphrase
# Audit: JSONL to ${ROOT_DIR}/audit/keys-rotation.log

set -Eeuo pipefail

#######################################
# Logging
#######################################
readonly _NO_COLOR="${NO_COLOR:-}"
if [[ -z "${_NO_COLOR}" && -t 1 ]]; then
  readonly C_RESET=$'\033[0m'; readonly C_DIM=$'\033[2m'
  readonly C_RED=$'\033[31m'; readonly C_GRN=$'\033[32m'
  readonly C_YEL=$'\033[33m'; readonly C_BLU=$'\033[34m'
else
  readonly C_RESET=''; readonly C_DIM=''
  readonly C_RED=''; readonly C_GRN=''
  readonly C_YEL=''; readonly C_BLU=''
endif 2>/dev/null || true

log()    { printf "%s[%s]%s %s\n" "${C_DIM}" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "${C_RESET}" "$*"; }
info()   { printf "%sINFO%s    %s\n"    "${C_BLU}" "${C_RESET}" "$*"; }
warn()   { printf "%sWARN%s    %s\n"    "${C_YEL}" "${C_RESET}" "$*"; }
error()  { printf "%sERROR%s   %s\n"    "${C_RED}" "${C_RESET}" "$*" >&2; }
ok()     { printf "%sOK%s      %s\n"    "${C_GRN}" "${C_RESET}" "$*"; }

trap 'rc=$?; error "Failed at line $LINENO (exit=$rc)"; exit $rc' ERR

#######################################
# Globals / Defaults
#######################################
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT_DIR="${AUDIT_DIR:-${ROOT_DIR}/audit}"
AUDIT_LOG="${AUDIT_LOG:-${AUDIT_DIR}/keys-rotation.log}"
BACKUP_DIR="${BACKUP_DIR:-${ROOT_DIR}/backups}"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"

APP_NAME="${APP_NAME:-cybersecurity-core}"
DRY_RUN="${DRY_RUN:-false}"
TIMEOUT="${TIMEOUT:-5m}"
GRACE="${GRACE:-0s}" # поддержка для внешних провайдеров, где есть версии

# K8s
K8S_NAMESPACE="${K8S_NAMESPACE:-security}"
K8S_CONTEXT="${K8S_CONTEXT:-}"
K8S_RESTART_TARGETS="${K8S_RESTART_TARGETS:-}" # CSV: kind/name,kind/name  e.g., "deployment/api,deployment/worker"
K8S_ANNOTATE_SELECTOR="${K8S_ANNOTATE_SELECTOR:-app.kubernetes.io/instance=${APP_NAME}}"

# Vault
VAULT_ADDR="${VAULT_ADDR:-}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-}"
VAULT_MOUNT="${VAULT_MOUNT:-secret}" # kv v2 mount

# AWS/GCP/Azure: предполагается авторизация через стандартные механизмы CLI
AWS_REGION="${AWS_REGION:-}"
GCP_PROJECT="${GCP_PROJECT:-}"
AZURE_KEYVAULT_NAME="${AZURE_KEYVAULT_NAME:-}"

# Backup encryption
AGE_RECIPIENT="${AGE_RECIPIENT:-}"          # if set, use age
BACKUP_PASSPHRASE="${BACKUP_PASSPHRASE:-}"  # fallback to openssl enc

#######################################
# Utils
#######################################
usage() {
  cat <<'USAGE'
Usage:
  rotate_keys.sh rotate   --type <random|jwt|ssh|tls> --provider <k8s|vault|file|aws-sm|gcp-sm|azure-kv> --name <id> [options]
  rotate_keys.sh promote  --provider <...> --name <id> --version <ver>
  rotate_keys.sh revoke   --provider <...> --name <id> --version <ver>
  rotate_keys.sh list     --provider <...> --name <id>
  rotate_keys.sh verify   --provider <...> --name <id>
  rotate_keys.sh backup   --provider <...> --name <id> --version <ver>

Common options:
  --dry-run                 Do not change state in providers
  --timeout <dur>           Wait timeout for operations (default: 5m)
  --grace <dur>             Grace period before revocation (provider-dependent)
  --meta <k=v[,k=v...]>     Extra metadata to store as annotations/labels

K8s options:
  --namespace <ns>          Kubernetes namespace (default: security)
  --context <ctx>           kubectl context
  --restart <targets>       CSV list of targets to rollout restart (kind/name)

Vault options:
  --vault-path <kv-path>    e.g. secret/data/cyber/keys/<name> (KVv2 logical path)

AWS Secrets Manager:
  --aws-arn <secret-arn|id> Secret identifier (if absent, will create)

GCP Secret Manager:
  --gcp-secret <name>       Secret id; project from $GCP_PROJECT

Azure Key Vault:
  --azure-secret <name>     Secret name in Key Vault $AZURE_KEYVAULT_NAME

TLS options:
  --cn <cn>                 Common Name for self-signed cert
  --sans <dns1,dns2,...>    SubjectAltName DNS entries
  --days <n>                Validity in days (default: 365)
USAGE
}

have() { command -v "$1" >/dev/null 2>&1; }
bool() { [[ "${1:-}" =~ ^(1|true|yes|on)$ ]]; }

require() {
  local missing=()
  for c in "$@"; do have "$c" || missing+=("$c"); done
  if (( ${#missing[@]} )); then
    error "Missing required tools: ${missing[*]}"
    exit 127
  fi
}

load_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC2046
    export $(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "${ENV_FILE}" | sed 's/#.*//g' | xargs -I{} echo {})
    info "Loaded env from ${ENV_FILE}"
  fi
}

mkdirs() {
  mkdir -p "${AUDIT_DIR}" "${BACKUP_DIR}"
}

now_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
ver_id()  { date -u +"%Y%m%d%H%M%S"; }

sha256_of_file() { sha256sum "$1" | awk '{print $1}'; }
redact_hash()    { echo "$1" | cut -c1-12; }

audit_log() {
  local action="$1"; shift
  local json="{\"ts\":\"$(now_utc)\",\"app\":\"${APP_NAME}\",\"action\":\"${action}\",$*}"
  printf "%s\n" "${json}" >> "${AUDIT_LOG}"
}

with_tmpdir() {
  local td; td="$(mktemp -d)"; echo "${td}"
}

#######################################
# Generators
#######################################
gen_random_secret() {
  local out="$1"; local bytes="${2:-32}"
  # 32 bytes → 43 base64 chars; do not print to stdout
  openssl rand -out "${out}" "${bytes}"
}

gen_jwt_secret() {
  local out="$1"; local bytes="${2:-64}"
  openssl rand -out "${out}" "${bytes}"
}

gen_ssh_keypair() {
  local dir="$1"
  ssh-keygen -t ed25519 -N "" -f "${dir}/id_ed25519" -C "rotated-$(now_utc)" >/dev/null
}

gen_tls_selfsigned() {
  local dir="$1"; local cn="$2"; local sans_csv="$3"; local days="${4:-365}"
  local key="${dir}/tls.key" cert="${dir}/tls.crt" cnf="${dir}/csr.cnf"
  : > "${cnf}"
  {
    echo "[req]"
    echo "distinguished_name = dn"
    echo "x509_extensions = v3_req"
    echo "prompt = no"
    echo "[dn]"
    echo "CN = ${cn:-cybersecurity-core.local}"
    echo "[v3_req]"
    echo "keyUsage = keyEncipherment, dataEncipherment, digitalSignature"
    echo "extendedKeyUsage = serverAuth, clientAuth"
    if [[ -n "${sans_csv}" ]]; then
      echo "subjectAltName = @alt_names"
      echo "[alt_names]"
      local i=1
      IFS=',' read -ra SANS <<< "${sans_csv}"
      for s in "${SANS[@]}"; do echo "DNS.${i} = ${s}"; ((i++)); done
    fi
  } >> "${cnf}"
  openssl req -x509 -nodes -newkey rsa:4096 -keyout "${key}" -out "${cert}" -sha256 -days "${days}" -config "${cnf}" >/dev/null 2>&1
}

#######################################
# Backup (age or OpenSSL)
#######################################
backup_encrypt() {
  local src_dir="$1" name="$2" version="$3"
  local ts; ts="$(date -u +%Y%m%d)"
  local outd="${BACKUP_DIR}/${ts}"; mkdir -p "${outd}"
  local tarball="${outd}/${name}-${version}.tar"
  tar -C "${src_dir}" -cf "${tarball}" .
  if [[ -n "${AGE_RECIPIENT}" && "$(have age && echo 1 || echo 0)" -eq 1 ]]; then
    info "Encrypting backup with age"
    age -r "${AGE_RECIPIENT}" -o "${tarball}.age" "${tarball}"
    rm -f "${tarball}"
    echo "${tarball}.age"
  elif [[ -n "${BACKUP_PASSPHRASE}" ]]; then
    info "Encrypting backup with OpenSSL"
    openssl enc -aes-256-cbc -md sha256 -salt -pbkdf2 -pass env:BACKUP_PASSPHRASE -in "${tarball}" -out "${tarball}.enc"
    rm -f "${tarball}"
    echo "${tarball}.enc"
  else
    warn "Backup left unencrypted; set AGE_RECIPIENT or BACKUP_PASSPHRASE"
    echo "${tarball}"
  fi
}

#######################################
# Providers: store/load
#######################################
store_k8s() {
  require kubectl
  local name="$1" version="$2" dir="$3" meta="$4"

  local ns="${K8S_NAMESPACE}"
  local ctx="${K8S_CONTEXT:+--context ${K8S_CONTEXT}}"
  local secret_name="${name}"
  local ann="rotation.version=${version},rotation.ts=$(now_utc),rotation.app=${APP_NAME}"
  if [[ -n "${meta}" ]]; then ann="${ann},${meta}"; fi

  # prepare kubectl manifest
  local yml; yml="$(mktemp)"
  {
    echo "apiVersion: v1"
    echo "kind: Secret"
    echo "metadata:"
    echo "  name: ${secret_name}"
    echo "  namespace: ${ns}"
    echo "  annotations:"
    IFS=',' read -ra KV <<< "${ann}"
    for kv in "${KV[@]}"; do
      echo "    ${kv%%=*}: \"${kv#*=}\""
    done
    echo "type: Opaque"
    echo "data:"
    for f in "${dir}"/*; do
      local k; k="$(basename "$f")"
      local v; v="$(base64 -w0 < "$f")"
      echo "  ${k}: ${v}"
    done
  } > "${yml}"

  if bool "${DRY_RUN}"; then
    warn "DRY-RUN: apply Secret/${secret_name} in ns=${ns}"
  else
    kubectl ${ctx} apply -f "${yml}"
    ok "K8s Secret applied: ${secret_name}"
    # annotate consumers and rollout restart
    if [[ -n "${K8S_RESTART_TARGETS}" ]]; then
      IFS=',' read -ra TARGETS <<< "${K8S_RESTART_TARGETS}"
      for t in "${TARGETS[@]}"; do
        kubectl ${ctx} -n "${ns}" rollout restart "${t}"
        info "Rollout restarted: ${t}"
      done
    else
      # best-effort restart by label selector
      kubectl ${ctx} -n "${ns}" rollout restart deployment -l "${K8S_ANNOTATE_SELECTOR}" || true
    fi
  fi
  rm -f "${yml}"
}

store_vault() {
  require vault jq
  local name="$1" version="$2" dir="$3" kv_path="$4" meta="$5"

  [[ -n "${VAULT_ADDR}" ]] || warn "VAULT_ADDR not set"
  local ns_flag=()
  [[ -n "${VAULT_NAMESPACE}" ]] && ns_flag=( -namespace="${VAULT_NAMESPACE}" )
  local payload; payload="$(jq -n)"
  for f in "${dir}"/*; do
    local key; key="$(basename "$f")"
    local val; val="$(base64 -w0 < "$f")"
    payload="$(jq --arg k "$key" --arg v "$val" '. + {($k): $v}' <<< "${payload}")"
  done
  local ann="$(jq -n --arg ver "${version}" --arg app "${APP_NAME}" --arg ts "$(now_utc)" '. + {rotation_version:$ver, rotation_app:$app, rotation_ts:$ts}')"
  if [[ -n "${meta}" ]]; then
    IFS=',' read -ra KV <<< "${meta}"
    for kv in "${KV[@]}"; do ann="$(jq --arg k "${kv%%=*}" --arg v "${kv#*=}" '. + {($k):$v}' <<< "${ann}")"; done
  fi
  local body; body="$(jq -n --argjson d "${payload}" --argjson m "${ann}" '{data:$d, metadata:$m}')"

  if bool "${DRY_RUN}"; then
    warn "DRY-RUN: vault kv put ${kv_path}"
  else
    vault "${ns_flag[@]}" kv put "${kv_path}" @- <<< "${body}" >/dev/null
    ok "Vault KV updated at ${kv_path}"
  fi
}

store_file() {
  local name="$1" version="$2" dir="$3"
  local outd="${ROOT_DIR}/secrets/${name}/${version}"
  mkdir -p "${outd}"
  chmod 700 "${outd}"
  cp -f "${dir}"/* "${outd}/"
  chmod 600 "${outd}"/*
  ok "Files stored at ${outd}"
}

store_aws_sm() {
  require aws jq
  local name="$1" version="$2" dir="$3" secret_id="$4"
  local region=()
  [[ -n "${AWS_REGION}" ]] && region=( --region "${AWS_REGION}" )
  # build JSON object {k: base64data}
  local payload; payload="$(jq -n)"
  for f in "${dir}"/*; do
    local key; key="$(basename "$f")"
    local val; val="$(base64 -w0 < "$f")"
    payload="$(jq --arg k "$key" --arg v "$val" '. + {($k):$v}' <<< "${payload}")"
  done
  if bool "${DRY_RUN}"; then
    warn "DRY-RUN: aws secretsmanager put-secret-value ${secret_id}"
  else
    if ! aws "${region[@]}" secretsmanager describe-secret --secret-id "${secret_id}" >/dev/null 2>&1; then
      aws "${region[@]}" secretsmanager create-secret --name "${secret_id}" --secret-string "${payload}" >/dev/null
      info "AWS SM secret created: ${secret_id}"
    else
      aws "${region[@]}" secretsmanager put-secret-value --secret-id "${secret_id}" --secret-string "${payload}" >/dev/null
      info "AWS SM new version stored for: ${secret_id}"
    fi
  fi
}

store_gcp_sm() {
  require gcloud jq
  local name="$1" version="$2" dir="$3" secret_name="$4"
  [[ -n "${GCP_PROJECT}" ]] || { error "GCP_PROJECT not set"; return 1; }
  local payload; payload="$(jq -n)"
  for f in "${dir}"/*; do
    local key; key="$(basename "$f")"
    local val; val="$(base64 -w0 < "$f")"
    payload="$(jq --arg k "$key" --arg v "$val" '. + {($k):$v}' <<< "${payload}")"
  done
  if bool "${DRY_RUN}"; then
    warn "DRY-RUN: gcloud secrets versions add ${secret_name}"
  else
    if ! gcloud secrets describe "${secret_name}" --project "${GCP_PROJECT}" >/dev/null 2>&1; then
      echo -n "${payload}" | gcloud secrets create "${secret_name}" --project "${GCP_PROJECT}" --data-file=- >/dev/null
      info "GCP SM secret created: ${secret_name}"
    else
      echo -n "${payload}" | gcloud secrets versions add "${secret_name}" --project "${GCP_PROJECT}" --data-file=- >/dev/null
      info "GCP SM new version stored for: ${secret_name}"
    fi
  fi
}

store_azure_kv() {
  require az jq
  local name="$1" version="$2" dir="$3" secret_name="$4"
  [[ -n "${AZURE_KEYVAULT_NAME}" ]] || { error "AZURE_KEYVAULT_NAME not set"; return 1; }
  local payload; payload="$(jq -n)"
  for f in "${dir}"/*; do
    local key; key="$(basename "$f")"
    local val; val="$(base64 -w0 < "$f")"
    payload="$(jq --arg k "$key" --arg v "$val" '. + {($k):$v}' <<< "${payload}")"
  done
  if bool "${DRY_RUN}"; then
    warn "DRY-RUN: az keyvault secret set ${secret_name}"
  else
    az keyvault secret set --vault-name "${AZURE_KEYVAULT_NAME}" --name "${secret_name}" --value "${payload}" >/dev/null
    info "Azure KV secret updated: ${secret_name}"
  fi
}

#######################################
# High-level operations
#######################################
do_rotate() {
  local type="$1" provider="$2" name="$3" meta="$4"
  local cn="${CN:-}"; local sans="${SANS:-}"; local days="${DAYS:-365}"
  local version; version="$(ver_id)"
  local tmp; tmp="$(with_tmpdir)"

  case "${type}" in
    random)
      gen_random_secret "${tmp}/secret" 32
      ;;
    jwt)
      gen_jwt_secret "${tmp}/jwt_secret" 64
      ;;
    ssh)
      gen_ssh_keypair "${tmp}"
      ;;
    tls)
      gen_tls_selfsigned "${tmp}" "${cn}" "${sans}" "${days}"
      ;;
    *)
      error "Unknown type: ${type}"; exit 2;;
  esac

  # Compute hash for audit without leaking content
  local concat; concat="$(mktemp)"
  cat "${tmp}"/* > "${concat}"
  local sh; sh="$(sha256_of_file "${concat}")"
  rm -f "${concat}"
  info "Prepared new material for ${name} type=${type} ver=${version} hash=${sh:0:12}"

  # Store to provider
  case "${provider}" in
    k8s)
      store_k8s "${name}" "${version}" "${tmp}" "${meta}"
      ;;
    vault)
      local kv_path="${VAULT_PATH:-${VAULT_MOUNT}/data/${APP_NAME}/keys/${name}}"
      store_vault "${name}" "${version}" "${tmp}" "${kv_path}" "${meta}"
      ;;
    file)
      store_file "${name}" "${version}" "${tmp}"
      ;;
    aws-sm)
      local secret_id="${AWS_SECRET_ID:-${APP_NAME}/${name}}"
      store_aws_sm "${name}" "${version}" "${tmp}" "${secret_id}"
      ;;
    gcp-sm)
      local secret_name="${GCP_SECRET_NAME:-${APP_NAME}-${name}}"
      store_gcp_sm "${name}" "${version}" "${tmp}" "${secret_name}"
      ;;
    azure-kv)
      local secret_name="${AZURE_SECRET_NAME:-${APP_NAME}-${name}}"
      store_azure_kv "${name}" "${version}" "${tmp}" "${secret_name}"
      ;;
    *)
      error "Unknown provider: ${provider}"; exit 2;;
  esac

  # Backup
  local bpath; bpath="$(backup_encrypt "${tmp}" "${name}" "${version}")"
  ok "Backup created at ${bpath}"

  # Audit
  audit_log "rotate" "\"type\":\"${type}\",\"name\":\"${name}\",\"provider\":\"${provider}\",\"version\":\"${version}\",\"hash\":\"${sh}\""

  # Cleanup
  rm -rf "${tmp}"
  ok "Rotation completed for ${name} version=${version}"
}

do_promote() {
  local provider="$1" name="$2" version="$3"
  # Promotion semantics depend on provider; for K8s/Vault we already overwrite "current" on rotate.
  # For cloud SM you can move staging labels; we log intent.
  warn "Promote is a no-op for k8s/vault/file. For cloud SM, implement label moves in CI if needed."
  audit_log "promote" "\"name\":\"${name}\",\"provider\":\"${provider}\",\"version\":\"${version}\""
}

do_revoke() {
  local provider="$1" name="$2" version="$3"
  # Provider-specific revocation is non-trivial; we only log and rely on provider retention policies.
  warn "Revoke requested for ${provider}/${name}@${version}; manual cleanup may be required."
  audit_log "revoke" "\"name\":\"${name}\",\"provider\":\"${provider}\",\"version\":\"${version}\""
}

do_list() {
  local provider="$1" name="$2"
  case "${provider}" in
    k8s)
      require kubectl
      kubectl ${K8S_CONTEXT:+--context ${K8S_CONTEXT}} -n "${K8S_NAMESPACE}" get secret "${name}" -o go-template='{{range $k,$v := .metadata.annotations}}{{println $k ":" $v}}{{end}}' || true
      ;;
    vault)
      require vault jq
      local kv_path="${VAULT_PATH:-${VAULT_MOUNT}/metadata/${APP_NAME}/keys/${name}}"
      vault kv metadata get "${kv_path}" || true
      ;;
    file)
      ls -1 "${ROOT_DIR}/secrets/${name}" 2>/dev/null || true
      ;;
    aws-sm)
      require aws
      local sid="${AWS_SECRET_ID:-${APP_NAME}/${name}}"
      aws ${AWS_REGION:+--region ${AWS_REGION}} secretsmanager describe-secret --secret-id "${sid}" || true
      ;;
    gcp-sm)
      require gcloud
      local sname="${GCP_SECRET_NAME:-${APP_NAME}-${name}}"
      gcloud secrets versions list "${sname}" --project "${GCP_PROJECT}" || true
      ;;
    azure-kv)
      require az
      local sname="${AZURE_SECRET_NAME:-${APP_NAME}-${name}}"
      az keyvault secret list-versions --vault-name "${AZURE_KEYVAULT_NAME}" --name "${sname}" || true
      ;;
    *)
      error "Unknown provider: ${provider}"; exit 2;;
  esac
}

do_verify() {
  local provider="$1" name="$2"
  case "${provider}" in
    k8s)
      require kubectl
      kubectl ${K8S_CONTEXT:+--context ${K8S_CONTEXT}} -n "${K8S_NAMESPACE}" get secret "${name}" >/dev/null
      ok "K8s secret present: ${name}"
      ;;
    vault)
      require vault
      local kv_path="${VAULT_PATH:-${VAULT_MOUNT}/data/${APP_NAME}/keys/${name}}"
      vault kv get "${kv_path}" >/dev/null
      ok "Vault secret present at ${kv_path}"
      ;;
    file)
      [[ -d "${ROOT_DIR}/secrets/${name}" ]] && ok "File secrets exist for ${name}" || error "Not found"
      ;;
    aws-sm)
      require aws
      aws ${AWS_REGION:+--region ${AWS_REGION}} secretsmanager describe-secret --secret-id "${AWS_SECRET_ID:-${APP_NAME}/${name}}" >/dev/null
      ok "AWS SM secret present"
      ;;
    gcp-sm)
      require gcloud
      gcloud secrets describe "${GCP_SECRET_NAME:-${APP_NAME}-${name}}" --project "${GCP_PROJECT}" >/dev/null
      ok "GCP SM secret present"
      ;;
    azure-kv)
      require az
      az keyvault secret show --vault-name "${AZURE_KEYVAULT_NAME}" --name "${AZURE_SECRET_NAME:-${APP_NAME}-${name}}" >/dev/null
      ok "Azure KV secret present"
      ;;
    *)
      error "Unknown provider: ${provider}"; exit 2;;
  esac
}

do_backup() {
  local provider="$1" name="$2" version="$3"
  warn "Backup operation re-packs last rotated material only if temp is preserved externally."
  audit_log "backup" "\"name\":\"${name}\",\"provider\":\"${provider}\",\"version\":\"${version}\""
}

#######################################
# Arg parsing
#######################################
CMD="${1:-}"; shift || true
[[ -z "${CMD}" ]] && { usage; exit 2; }

TYPE=""; PROVIDER=""; NAME=""; VERSION=""
META=""
VAULT_PATH=""
AWS_SECRET_ID=""
GCP_SECRET_NAME=""
AZURE_SECRET_NAME=""
CN=""; SANS=""; DAYS="365"

while (( "$#" )); do
  case "$1" in
    --type)            TYPE="$2"; shift 2;;
    --provider)        PROVIDER="$2"; shift 2;;
    --name)            NAME="$2"; shift 2;;
    --version)         VERSION="$2"; shift 2;;
    --meta)            META="$2"; shift 2;;
    --dry-run)         DRY_RUN=true; shift 1;;
    --timeout)         TIMEOUT="$2"; shift 2;;
    --grace)           GRACE="$2"; shift 2;;
    # K8s
    --namespace)       K8S_NAMESPACE="$2"; shift 2;;
    --context)         K8S_CONTEXT="$2"; shift 2;;
    --restart)         K8S_RESTART_TARGETS="$2"; shift 2;;
    # Vault
    --vault-path)      VAULT_PATH="$2"; shift 2;;
    # AWS/GCP/Azure
    --aws-arn|--aws-id) AWS_SECRET_ID="$2"; shift 2;;
    --gcp-secret)      GCP_SECRET_NAME="$2"; shift 2;;
    --azure-secret)    AZURE_SECRET_NAME="$2"; shift 2;;
    # TLS
    --cn)              CN="$2"; shift 2;;
    --sans)            SANS="$2"; shift 2;;
    --days)            DAYS="$2"; shift 2;;
    -h|--help)         usage; exit 0;;
    *)                 error "Unknown option: $1"; usage; exit 2;;
  esac
done

#######################################
# Main
#######################################
load_env
mkdirs

case "${CMD}" in
  rotate)
    [[ -n "${TYPE}" && -n "${PROVIDER}" && -n "${NAME}" ]] || { error "rotate requires --type --provider --name"; exit 2; }
    do_rotate "${TYPE}" "${PROVIDER}" "${NAME}" "${META}"
    ;;
  promote)
    [[ -n "${PROVIDER}" && -n "${NAME}" && -n "${VERSION}" ]] || { error "promote requires --provider --name --version"; exit 2; }
    do_promote "${PROVIDER}" "${NAME}" "${VERSION}"
    ;;
  revoke)
    [[ -n "${PROVIDER}" && -n "${NAME}" && -n "${VERSION}" ]] || { error "revoke requires --provider --name --version"; exit 2; }
    do_revoke "${PROVIDER}" "${NAME}" "${VERSION}"
    ;;
  list)
    [[ -n "${PROVIDER}" && -n "${NAME}" ]] || { error "list requires --provider --name"; exit 2; }
    do_list "${PROVIDER}" "${NAME}"
    ;;
  verify)
    [[ -n "${PROVIDER}" && -n "${NAME}" ]] || { error "verify requires --provider --name"; exit 2; }
    do_verify "${PROVIDER}" "${NAME}"
    ;;
  backup)
    [[ -n "${PROVIDER}" && -n "${NAME}" && -n "${VERSION}" ]] || { error "backup requires --provider --name --version"; exit 2; }
    do_backup "${PROVIDER}" "${NAME}" "${VERSION}"
    ;;
  *)
    error "Unknown command: ${CMD}"; usage; exit 2;;
esac
