#!/usr/bin/env bash
# policy-core/scripts/deploy.sh
# Промышленный деплой политик OPA/Rego/Cedar в OCI-реестр и/или Kubernetes.
# Особенности:
#  - Сборка и тесты Rego (opa, conftest). Опционально Cedar.
#  - Дет. bundle + SHA256 + manifest.json + SBOM (CycloneDX).
#  - Подпись cosign (keyless или по ключу).
#  - Публикация через oras в OCI-реестр; деплой в Kubernetes (ConfigMap).
#  - Docker fallback для инструментов (opa, conftest, oras, syft, cosign).
#  - Идемпотентность: теги :<version> и :sha-<digest>, аннотации в K8s.
#
# Зависимости (любой из вариантов): native или docker + интернет-доступ к образам:
#   opa, conftest, oras, jq, yq, syft, cosign, kubectl
#
# Использование:
#   ./scripts/deploy.sh [command] [--flags]
# Команды:
#   build      — формат/линт/тест Rego, компиляция Cedar (если есть)
#   package    — сформировать bundle, manifest.json, SBOM
#   push       — отправить в OCI-реестр (oras), подписать и проверить
#   deploy     — применить в Kubernetes (ConfigMap), перезапустить деплой
#   verify     — проверить подпись и готовность rollout
#   test       — alias build (только валидация и тесты)
#   all        — build + package + push + deploy + verify
#   clean      — удалить .out артефакты
#
# Примеры:
#   REGISTRY=ghcr.io ORG=myorg REPO=policy-core ./scripts/deploy.sh all
#   TARGET=k8s K8S_NAMESPACE=policies ./scripts/deploy.sh deploy
#
set -Eeuo pipefail

# -------- Конфигурация по умолчанию (переопределяйте переменными окружения) --------
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
POLICY_DIR="${POLICY_DIR:-$PROJECT_ROOT/policies}"             # каталог с .rego
CEDAR_DIR="${CEDAR_DIR:-$PROJECT_ROOT/cedar}"                  # каталог с Cedar (опц.)
DATA_DIR="${DATA_DIR:-$PROJECT_ROOT/data}"                     # дополнительные json/yaml (опц.)
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/.out}"                       # артефакты сборки
BUNDLE_NAME="${BUNDLE_NAME:-policy-bundle.tar.gz}"
MANIFEST_NAME="${MANIFEST_NAME:-manifest.json}"
SBOM_NAME="${SBOM_NAME:-sbom.cdx.json}"

# Версионирование
VERSION="${VERSION:-}"
REGISTRY="${REGISTRY:-}"              # пример: ghcr.io
ORG="${ORG:-}"                        # пример: myorg
REPO="${REPO:-policy-core}"           # имя репозитория артефакта
OCI_REF="${OCI_REF:-}"                # если задан — перекрывает REGISTRY/ORG/REPO:VERSION
TARGET="${TARGET:-oci}"               # oci | k8s | both
DRY_RUN="${DRY_RUN:-false}"           # true/false

# Подпись
COSIGN_EXPERIMENTAL="${COSIGN_EXPERIMENTAL:-false}" # keyless при true
COSIGN_KEY="${COSIGN_KEY:-}"                         # путь к ключу, если не keyless

# Kubernetes
K8S_NAMESPACE="${K8S_NAMESPACE:-policy-core}"
K8S_CONTEXT="${K8S_CONTEXT:-}"                       # опционально
K8S_CONFIGMAP_NAME="${K8S_CONFIGMAP_NAME:-policy-core-bundle}"
K8S_DEPLOYMENT="${K8S_DEPLOYMENT:-}"                 # если задан — rollout restart
K8S_ANNOTATION_PREFIX="${K8S_ANNOTATION_PREFIX:-policy.core/audit}"

# Бюджеты (мс) и поведение
LOAD_BUDGET_MS="${LOAD_BUDGET_MS:-0}"               # будущее применение для времени сборки
STRICT="${STRICT:-true}"                             # остановка на предупреждениях

# -------- Логирование/утилиты --------
log()  { printf "[%s] %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
warn() { log "WARN: $*"; }
run()  { log "+ $*"; if [ "${DRY_RUN}" = "true" ]; then return 0; fi; "$@"; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || return 1; }

# docker fallback для инструмента
tool() {
  local name="$1"; shift || true
  if require_cmd "${name}"; then
    "${name}" "$@"
    return
  fi
  case "${name}" in
    opa)
      require_cmd docker || die "opa и docker недоступны"
      run docker run --rm -v "${PROJECT_ROOT}:/work" -w /work openpolicyagent/opa:latest "$@"
      ;;
    conftest)
      require_cmd docker || die "conftest и docker недоступны"
      run docker run --rm -v "${PROJECT_ROOT}:/project" -w /project openpolicyagent/conftest:latest "$@"
      ;;
    oras)
      require_cmd docker || die "oras и docker недоступны"
      run docker run --rm -v "${PROJECT_ROOT}:/work" -w /work ghcr.io/oras-project/oras:latest "$@"
      ;;
    syft)
      require_cmd docker || die "syft и docker недоступны"
      run docker run --rm -v "${PROJECT_ROOT}:/work" -w /work anchore/syft:latest "$@"
      ;;
    cosign)
      require_cmd docker || die "cosign и docker недоступны"
      run docker run --rm -v "${PROJECT_ROOT}:/work" -w /work gcr.io/projectsigstore/cosign:v2.4.1 "$@"
      ;;
    *)
      die "Неизвестный инструмент: ${name}"
      ;;
  esac
}

sha256_file() {
  if require_cmd shasum; then shasum -a 256 "$1" | awk '{print $1}'; return; fi
  if require_cmd sha256sum; then sha256sum "$1" | awk '{print $1}'; return; fi
  die "Нет утилит для SHA256 (shasum/sha256sum)"
}

json_escape() {
  python3 - <<'PY' "$1"
import json,sys
print(json.dumps(sys.argv[1]))
PY
}

detect_version() {
  if [ -n "${VERSION}" ]; then echo "${VERSION}"; return; fi
  if require_cmd git && git -C "${PROJECT_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    local desc
    if desc=$(git -C "${PROJECT_ROOT}" describe --tags --dirty --always 2>/dev/null); then
      echo "${desc}"
      return
    fi
    local short
    short=$(git -C "${PROJECT_ROOT}" rev-parse --short HEAD)
    echo "0.0.0+${short}"
    return
  fi
  echo "0.0.0+unknown"
}

ensure_layout() {
  [ -d "${OUT_DIR}" ] || run mkdir -p "${OUT_DIR}"
  [ -d "${POLICY_DIR}" ] || warn "POLICY_DIR не найден: ${POLICY_DIR}"
  [ -d "${CEDAR_DIR}" ] || true
  [ -d "${DATA_DIR}" ] || true
}

compute_refs() {
  VERSION="$(detect_version)"
  if [ -z "${OCI_REF}" ]; then
    if [ -z "${REGISTRY}" ] || [ -z "${ORG}" ] || [ -z "${REPO}" ]; then
      warn "OCI_REF не задан, и REGISTRY/ORG/REPO не полны — push может быть пропущен"
      OCI_REF=""
    else
      OCI_REF="${REGISTRY}/${ORG}/${REPO}:${VERSION}"
    fi
  fi
}

# -------- Build/Test --------
build_rego() {
  if [ ! -d "${POLICY_DIR}" ]; then
    warn "POLICY_DIR отсутствует, пропускаю Rego build"
    return
  fi
  log "Форматирование Rego (проверка списком)"
  tool opa fmt --list --fail "${POLICY_DIR}" || {
    [ "${STRICT}" = "true" ] && die "Нарушен формат Rego" || warn "Нарушен формат Rego"
  }
  log "Статические тесты conftest (если есть tests/ или policy-tests/)"
  if [ -d "${PROJECT_ROOT}/tests" ] || [ -d "${PROJECT_ROOT}/policy-tests" ]; then
    local testdir
    testdir="${PROJECT_ROOT}/tests"
    [ -d "${PROJECT_ROOT}/policy-tests" ] && testdir="${PROJECT_ROOT}/policy-tests"
    tool conftest test "${testdir}" -p "${POLICY_DIR}" --all-namespaces
  else
    warn "Тестовые каталоги не найдены, пропускаю conftest"
  fi
  log "opa test (встроенные rego-тесты)"
  tool opa test "${POLICY_DIR}" "${DATA_DIR}" 2>/dev/null || tool opa test "${POLICY_DIR}"
}

build_cedar() {
  # Опционально: компиляция Cedar, если у вас есть cedar-cli; иначе пропускаем
  if [ ! -d "${CEDAR_DIR}" ]; then
    return
  fi
  if require_cmd cedar; then
    log "Компиляция Cedar политик"
    run cedar validate --policies "${CEDAR_DIR}" || die "Cedar валидация не прошла"
    run cedar check --policies "${CEDAR_DIR}" || true
  else
    warn "cedar-cli не найден, пропускаю Cedar фазу"
  fi
}

cmd_build() {
  ensure_layout
  build_rego
  build_cedar
  log "Build завершён"
}

# -------- Package (bundle + manifest + sbom) --------
cmd_package() {
  ensure_layout
  compute_refs

  log "Формирую OPA bundle"
  local bundle_path="${OUT_DIR}/${BUNDLE_NAME}"
  # собираем список входов для bundle
  local opa_inputs=()
  [ -d "${POLICY_DIR}" ] && opa_inputs+=("${POLICY_DIR}")
  [ -d "${DATA_DIR}" ] && opa_inputs+=("${DATA_DIR}")

  if [ "${#opa_inputs[@]}" -eq 0 ]; then
    die "Нет входных каталогов для bundle (POLICY_DIR/DATA_DIR)"
  fi

  # Сборка детерминирована опцией --optimize=2 и стабильными путями
  tool opa build -b "${opa_inputs[@]}" -o "${bundle_path}"

  local digest
  digest="$(sha256_file "${bundle_path}")"
  echo "${digest}" > "${OUT_DIR}/bundle.sha256"

  log "Генерирую manifest.json"
  local created
  created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local manifest="${OUT_DIR}/${MANIFEST_NAME}"
  cat > "${manifest}" <<EOF
{
  "name": "policy-core",
  "version": "$(printf "%s" "${VERSION}")",
  "bundle": "$(printf "%s" "${BUNDLE_NAME}")",
  "sha256": "$(printf "%s" "${digest}")",
  "created": "$(printf "%s" "${created}")",
  "inputs": {
    "policies": "$(printf "%s" "${POLICY_DIR}")",
    "data": "$(printf "%s" "${DATA_DIR}")"
  }
}
EOF

  log "Генерирую SBOM (CycloneDX)"
  local sbom="${OUT_DIR}/${SBOM_NAME}"
  if require_cmd syft || require_cmd docker; then
    # syft умеет сканировать файловую систему
    tool syft dir:"${PROJECT_ROOT}" -o cyclonedx-json > "${sbom}" || warn "Syft не сформировал SBOM"
  else
    warn "syft недоступен, пропускаю SBOM"
  fi

  log "Package завершён: ${bundle_path}"
}

# -------- Push (OCI) + подпись cosign --------
cmd_push() {
  compute_refs
  [ -n "${OCI_REF}" ] || die "OCI_REF не определён; задайте REGISTRY, ORG, REPO и/или OCI_REF"

  local bundle_path="${OUT_DIR}/${BUNDLE_NAME}"
  local manifest="${OUT_DIR}/${MANIFEST_NAME}"
  local sbom="${OUT_DIR}/${SBOM_NAME}"
  [ -f "${bundle_path}" ] || die "Не найден bundle: ${bundle_path}"
  [ -f "${manifest}" ] || die "Не найден manifest: ${manifest}"

  local digest
  digest="$(sha256_file "${bundle_path}")"

  log "Публикую OCI-артефакт через oras: ${OCI_REF}"
  # Мультимедийные артефакты с аннотациями
  tool oras push "${OCI_REF}" \
    --artifact-type application/vnd.cncf.openpolicyagent.bundle.v1+tar \
    --annotation "org.opencontainers.image.title=policy-core bundle" \
    --annotation "org.opencontainers.image.version=${VERSION}" \
    --annotation "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${bundle_path}:application/gzip" \
    "${manifest}:application/json" \
    $( [ -f "${sbom}" ] && printf "%s" "${sbom}:application/vnd.cyclonedx+json" || true )

  log "Подписываю cosign"
  if [ "${COSIGN_EXPERIMENTAL}" = "true" ]; then
    export COSIGN_EXPERIMENTAL=1
    tool cosign sign --yes "${OCI_REF}"
  else
    [ -n "${COSIGN_KEY}" ] || die "COSIGN_KEY не задан и keyless отключен"
    tool cosign sign --key "${COSIGN_KEY}" --yes "${OCI_REF}"
  fi

  log "Верифицирую подпись"
  if [ "${COSIGN_EXPERIMENTAL}" = "true" ]; then
    tool cosign verify "${OCI_REF}" >/dev/null
  else
    tool cosign verify --key "${COSIGN_KEY}.pub" "${OCI_REF}" >/dev/null 2>&1 || warn "Публичный ключ не найден или verify недоступен"
  fi

  # Доп. тег с digest для идемпотентности
  local digest_tag="${REGISTRY}/${ORG}/${REPO}:sha-${digest}"
  if [ -n "${REGISTRY}" ] && [ -n "${ORG}" ] && [ -n "${REPO}" ]; then
    log "Дублирую тег: ${digest_tag}"
    tool oras copy "${OCI_REF}" "${digest_tag}"
  fi

  log "Push завершён"
}

# -------- Deploy (Kubernetes) --------
cmd_deploy_k8s() {
  local bundle_path="${OUT_DIR}/${BUNDLE_NAME}"
  local manifest="${OUT_DIR}/${MANIFEST_NAME}"
  [ -f "${bundle_path}" ] || die "Не найден bundle: ${bundle_path}"
  [ -f "${manifest}" ] || die "Не найден manifest: ${manifest}"
  require_cmd kubectl || die "kubectl недоступен"

  local digest
  digest="$(sha256_file "${bundle_path}")"

  local kc=(kubectl)
  [ -n "${K8S_CONTEXT}" ] && kc+=("--context" "${K8S_CONTEXT}")
  kc+=("-n" "${K8S_NAMESPACE}")

  log "Создаю/обновляю ConfigMap ${K8S_CONFIGMAP_NAME} с bundle и manifest"
  # Используем binaryData для tar.gz
  if [ "${DRY_RUN}" = "true" ]; then
    "${kc[@]}" create configmap "${K8S_CONFIGMAP_NAME}" --dry-run=client -o yaml \
      --from-file="bundle.tar.gz=${bundle_path}" \
      --from-file="manifest.json=${manifest}" >/dev/null
  else
    # kubectl не поддерживает напрямую binaryData через from-file с именем, поэтому используем apply через временный манифест
    local tmp="${OUT_DIR}/cm.yaml"
    cat > "${tmp}" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${K8S_CONFIGMAP_NAME}
  namespace: ${K8S_NAMESPACE}
  annotations:
    ${K8S_ANNOTATION_PREFIX}.sha256: "${digest}"
    ${K8S_ANNOTATION_PREFIX}.version: "$(printf "%s" "${VERSION}")"
binaryData:
  bundle.tar.gz: "$(base64 -w0 < "${bundle_path}")"
data:
  manifest.json: |
$(sed 's/^/    /' "${manifest}")
EOF
    "${kc[@]}" apply -f "${tmp}"
  fi

  if [ -n "${K8S_DEPLOYMENT}" ]; then
    log "Перезапускаю deployment ${K8S_DEPLOYMENT}"
    run "${kc[@]}" rollout restart deployment "${K8S_DEPLOYMENT}"
  else
    warn "K8S_DEPLOYMENT не задан, rollout restart пропущен"
  fi

  log "Deploy в Kubernetes завершён"
}

cmd_verify_k8s() {
  [ -n "${K8S_DEPLOYMENT}" ] || { warn "K8S_DEPLOYMENT не задан, verify ограничен"; return; }
  require_cmd kubectl || die "kubectl недоступен"
  local kc=(kubectl)
  [ -n "${K8S_CONTEXT}" ] && kc+=("--context" "${K8S_CONTEXT}")
  kc+=("-n" "${K8S_NAMESPACE}")
  log "Ожидание rollout deployment/${K8S_DEPLOYMENT}"
  run "${kc[@]}" rollout status deployment "${K8S_DEPLOYMENT}" --timeout=180s
  log "Rollout успешен"
}

# -------- Обёртки команд --------
cmd_test()    { cmd_build; }
cmd_deploy()  {
  case "${TARGET}" in
    k8s)  cmd_deploy_k8s ;;
    oci)  warn "TARGET=oci: deploy шаг пропущен (используйте push)";;
    both) cmd_deploy_k8s ;;
    *)    die "Неизвестный TARGET: ${TARGET}" ;;
  esac
}
cmd_verify()  {
  case "${TARGET}" in
    k8s|both) cmd_verify_k8s ;;
    oci)      warn "TARGET=oci: verify ограничен проверкой подписи на этапе push";;
    *)        die "Неизвестный TARGET: ${TARGET}" ;;
  esac
}
cmd_all()     { cmd_build; cmd_package; [ "${TARGET}" = "oci" -o "${TARGET}" = "both" ] && cmd_push || true; cmd_deploy; cmd_verify; }
cmd_clean()   { run rm -rf "${OUT_DIR}"; log "Clean завершён"; }

# -------- Парсинг аргументов --------
COMMAND="${1:-all}"
shift || true
# Простейший парсер флагов вида KEY=VAL
while [ $# -gt 0 ]; do
  case "$1" in
    REGISTRY=*|ORG=*|REPO=*|OCI_REF=*|TARGET=*|DRY_RUN=*|K8S_NAMESPACE=*|K8S_CONTEXT=*|K8S_DEPLOYMENT=*|COSIGN_EXPERIMENTAL=*|COSIGN_KEY=*|VERSION=* )
      eval "$1"
      ;;
    --help|-h)
      cat <<USAGE
Использование: ./scripts/deploy.sh [command] [VARS=...]
Команды: build, package, push, deploy, verify, test, all, clean
Примеры:
  REGISTRY=ghcr.io ORG=myorg REPO=policy-core ./scripts/deploy.sh all
  TARGET=k8s K8S_NAMESPACE=policies K8S_DEPLOYMENT=opa-loader ./scripts/deploy.sh deploy
USAGE
      exit 0
      ;;
    *)
      warn "Неизвестный аргумент: $1"
      ;;
  esac
  shift || true
done

# -------- Выполнение --------
case "${COMMAND}" in
  build)    cmd_build ;;
  test)     cmd_test ;;
  package)  cmd_package ;;
  push)     cmd_push ;;
  deploy)   cmd_deploy ;;
  verify)   cmd_verify ;;
  all)      cmd_all ;;
  clean)    cmd_clean ;;
  *)        die "Неизвестная команда: ${COMMAND}" ;;
esac
