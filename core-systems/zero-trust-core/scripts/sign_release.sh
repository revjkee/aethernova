#!/usr/bin/env bash
# sign_release.sh — промышленный инструмент подписания релиза для zero-trust-core
# Features:
# - Безопасный Bash: -Eeuo pipefail, строгая обработка ошибок и ловушки
# - Детальные логи, dry-run, idempotency
# - SHA256 суммарник SHASUMS256.txt + подпись суммарника
# - GPG ASCII-armor подписи *.asc для каждого артефакта и для git-тега
# - Опционально: Cosign подписи файлов и OCI-артефактов, SLSA provenance, SBOM через Syft
# - Верификация созданных подписей
#
# Requirements (в зависимости от включенных фич):
# - git, gpg, sha256sum (или shasum -a 256 на macOS), awk, sed
# - cosign (optional), syft (optional), jq (optional)
#
# Usage:
#   scripts/sign_release.sh all --version v1.2.3 --artifacts ./dist --out ./out --gpg-key <KEYID> [--cosign-key cosign.key] [--provenance] [--sbom]
#   scripts/sign_release.sh verify --version v1.2.3 --artifacts ./dist --out ./out
#
# Переменные окружения (альтернатива флагам):
#   RELEASE_VERSION, ARTIFACTS_DIR, OUT_DIR, GPG_KEY, COSIGN_KEY, GIT_REMOTE=origin, DRY_RUN=1, CI=1
#
set -Eeuo pipefail

# -------- logging ----------
log()  { printf "%s\n" "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
die()  { log "ERROR: $*"; exit 1; }
run()  { if [[ "${DRY_RUN:-0}" == "1" ]]; then log "DRY-RUN: $*"; else "$@"; fi; }

cleanup() { :; }
trap cleanup EXIT
trap 'die "Interrupted (signal)";' INT TERM

# -------- defaults ----------
OS="$(uname -s || echo unknown)"
GIT_REMOTE="${GIT_REMOTE:-origin}"
CHECKSUM_FILE="SHASUMS256.txt"

# sha256 tool detection
if command -v sha256sum >/dev/null 2>&1; then
  SHA256="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256="shasum -a 256"
else
  die "sha256sum or shasum not found"
fi

# -------- help ----------
usage() {
  cat <<'USAGE'
sign_release.sh <command> [options]

Commands:
  checksums     Generate SHA256 checksums for artifacts
  gpg           Create GPG .asc signatures for artifacts and checksum file
  git-tag       Create signed git tag for the given version
  cosign        Cosign file signatures (and OCI if configured)
  sbom          Generate SBOM (Syft) and sign it
  attest        Generate SLSA provenance (cosign attest) for artifacts
  verify        Verify checksums and signatures
  all           Run checksums + gpg + git-tag (+cosign/sbom/attest if flags given)

Common options:
  --version <vX.Y.Z>       Release version tag (e.g., v1.2.3) [env: RELEASE_VERSION]
  --artifacts <dir>        Directory with artifacts to sign       [env: ARTIFACTS_DIR]
  --out <dir>              Output directory for signatures/out    [env: OUT_DIR, default: ./out]
  --gpg-key <KEYID>        GPG key id or fingerprint              [env: GPG_KEY]
  --cosign-key <path>      Cosign private key (file or KMS URI)   [env: COSIGN_KEY]
  --provenance             Enable SLSA provenance attestation (cosign)
  --sbom                   Generate and sign SBOM (requires syft)
  --oci-ref <ref>          OCI image reference to sign/attest (optional)
  --dry-run                Do not execute, only log actions       [env: DRY_RUN=1]
  -h|--help                This help

Examples:
  scripts/sign_release.sh all --version v1.2.3 --artifacts dist --out out --gpg-key ABCDEF1234567890
  DRY_RUN=1 scripts/sign_release.sh verify --version v1.2.3 --artifacts dist --out out
USAGE
}

# -------- arg parse ----------
CMD="${1:-}"
if [[ -z "${CMD}" || "${CMD}" == "-h" || "${CMD}" == "--help" ]]; then usage; exit 0; fi
shift || true

RELEASE_VERSION="${RELEASE_VERSION:-}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-}"
OUT_DIR="${OUT_DIR:-./out}"
GPG_KEY="${GPG_KEY:-}"
COSIGN_KEY="${COSIGN_KEY:-}"
DO_PROVENANCE="0"
DO_SBOM="0"
OCI_REF=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) RELEASE_VERSION="$2"; shift 2 ;;
    --artifacts) ARTIFACTS_DIR="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --gpg-key) GPG_KEY="$2"; shift 2 ;;
    --cosign-key) COSIGN_KEY="$2"; shift 2 ;;
    --provenance) DO_PROVENANCE="1"; shift ;;
    --sbom) DO_SBOM="1"; shift ;;
    --oci-ref) OCI_REF="$2"; shift 2 ;;
    --dry-run) DRY_RUN="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

# -------- validations ----------
[[ -n "${RELEASE_VERSION}" ]] || die "--version is required (e.g., v1.2.3)"
[[ "${RELEASE_VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Version must match vMAJOR.MINOR.PATCH"
[[ -n "${ARTIFACTS_DIR}" ]] || die "--artifacts is required"
[[ -d "${ARTIFACTS_DIR}" ]] || die "Artifacts dir not found: ${ARTIFACTS_DIR}"
mkdir -p "${OUT_DIR}"

need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }

# -------- core functions ----------

list_artifacts() {
  # Все файлы из каталога артефактов, исключая служебные подписи/суммы
  find "${ARTIFACTS_DIR}" -maxdepth 1 -type f ! -name "*.asc" ! -name "${CHECKSUM_FILE}" | sort
}

do_checksums() {
  need awk
  log "Generating checksums for artifacts in ${ARTIFACTS_DIR}"
  local tmp="${OUT_DIR}/${CHECKSUM_FILE}.tmp"
  : > "${tmp}"
  while IFS= read -r f; do
    local base; base="$(basename "$f")"
    # Дет. порядок: имя файла без путей
    if [[ "${OS}" == "Darwin" && "${SHA256}" == "shasum -a 256" ]]; then
      local line; line="$(${SHA256} "$f")"
      # Формат shasum: "<hash>  <path>"
      local h; h="$(echo "${line}" | awk '{print $1}')"
      printf "%s  %s\n" "${h}" "${base}" >> "${tmp}"
    else
      # sha256sum уже выводит "hash  path"
      ${SHA256} "$f" | awk -v base="${base}" '{print $1"  "base}' >> "${tmp}"
    fi
  done < <(list_artifacts)
  mv "${tmp}" "${OUT_DIR}/${CHECKSUM_FILE}"
  log "Checksums written: ${OUT_DIR}/${CHECKSUM_FILE}"
}

do_gpg_sign_files() {
  need gpg
  [[ -n "${GPG_KEY}" ]] || die "--gpg-key is required for gpg command"
  log "Signing artifacts with GPG key ${GPG_KEY}"
  while IFS= read -r f; do
    local base; base="$(basename "$f")"
    local out_sig="${OUT_DIR}/${base}.asc"
    if [[ -f "${out_sig}" ]]; then
      log "Signature exists, skipping: ${out_sig}"
      continue
    fi
    run gpg --batch --yes --armor --local-user "${GPG_KEY}" --output "${out_sig}" --detach-sign "${f}"
    log "Signed: ${out_sig}"
  done < <(list_artifacts)

  # Подписываем суммарник
  if [[ -f "${OUT_DIR}/${CHECKSUM_FILE}" ]]; then
    local sum_sig="${OUT_DIR}/${CHECKSUM_FILE}.asc"
    if [[ ! -f "${sum_sig}" ]]; then
      run gpg --batch --yes --armor --local-user "${GPG_KEY}" --output "${sum_sig}" --detach-sign "${OUT_DIR}/${CHECKSUM_FILE}"
      log "Signed: ${sum_sig}"
    fi
  fi
}

do_git_tag() {
  need git
  need gpg
  # Проверяем чистоту дерева и наличие версии в файлах
  if ! git diff --quiet; then
    die "Working tree has uncommitted changes"
  fi
  # Создаём подписанный тег
  if git rev-parse "${RELEASE_VERSION}" >/dev/null 2>&1; then
    log "Tag ${RELEASE_VERSION} already exists, skipping"
  else
    run git tag -s "${RELEASE_VERSION}" -m "zero-trust-core ${RELEASE_VERSION}"
    log "Created signed git tag ${RELEASE_VERSION}"
  fi
  # Публикуем
  run git push "${GIT_REMOTE}" "${RELEASE_VERSION}"
  log "Pushed tag to ${GIT_REMOTE}"
}

do_cosign_files() {
  [[ -n "${COSIGN_KEY}" ]] || die "--cosign-key or COSIGN_KEY required for cosign"
  need cosign
  log "Cosign signing files into ${OUT_DIR}"
  while IFS= read -r f; do
    local base; base="$(basename "$f")"
    local sig="${OUT_DIR}/${base}.sig"
    local cert="${OUT_DIR}/${base}.pem"
    if [[ -f "${sig}" ]]; then
      log "Cosign signature exists, skipping: ${sig}"
      continue
    fi
    run cosign sign-blob --key "${COSIGN_KEY}" --output-signature "${sig}" --output-certificate "${cert}" "${f}"
    log "Cosign signed: ${sig}"
  done < <(list_artifacts)

  if [[ -n "${OCI_REF}" ]]; then
    log "Cosign signing OCI: ${OCI_REF}"
    run cosign sign --key "${COSIGN_KEY}" "${OCI_REF}"
  fi
}

do_slsa_attest() {
  [[ -n "${COSIGN_KEY}" ]] || die "--cosign-key or COSIGN_KEY required for provenance"
  need cosign
  need jq
  log "Generating SLSA provenance via cosign attest"
  while IFS= read -r f; do
    local base; base="$(basename "$f")"
    local att="${OUT_DIR}/${base}.intoto.jsonl"
    if [[ -f "${att}" ]]; then
      log "Provenance exists, skipping: ${att}"
      continue
    fi
    # Минимальный субъект provenance (predicateType: slsa.dev/provenance/v1)
    local tmp; tmp="$(mktemp)"
    cat > "${tmp}" <<JSON
{
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "resolvedDependencies": [
        {"uri": "git:$(git rev-parse HEAD)", "digest": {"sha1": "$(git rev-parse HEAD)"}}
      ]
    },
    "runDetails": {"builder": {"id": "zero-trust-core-ci"}}
  }
}
JSON
    run cosign attest --key "${COSIGN_KEY}" --predicate "${tmp}" --type slsaprovenance --yes --predicate-format json --output "${att}" "${f}"
    rm -f "${tmp}"
    log "Provenance created: ${att}"
  done < <(list_artifacts)

  if [[ -n "${OCI_REF}" ]]; then
    log "Attesting OCI: ${OCI_REF}"
    local tmpo; tmpo="$(mktemp)"
    echo '{}' > "${tmpo}"
    run cosign attest --key "${COSIGN_KEY}" --predicate "${tmpo}" --type slsaprovenance "${OCI_REF}"
    rm -f "${tmpo}"
  fi
}

do_sbom() {
  need syft
  log "Generating SBOM for artifacts directory"
  local sbom="${OUT_DIR}/sbom.syft.json"
  if [[ ! -f "${sbom}" ]]; then
    run syft packages "dir:${ARTIFACTS_DIR}" -o json > "${sbom}"
    log "SBOM created: ${sbom}"
  fi
  if command -v gpg >/dev/null 2>&1 && [[ -n "${GPG_KEY}" ]]; then
    local sbom_sig="${sbom}.asc"
    if [[ ! -f "${sbom_sig}" ]]; then
      run gpg --batch --yes --armor --local-user "${GPG_KEY}" --output "${sbom_sig}" --detach-sign "${sbom}"
      log "SBOM signed: ${sbom_sig}"
    fi
  fi
}

do_verify() {
  # Проверка сумм
  if [[ -f "${OUT_DIR}/${CHECKSUM_FILE}" ]]; then
    log "Verifying checksums"
    # Подменяем путь на базовые имена (мы сохраняли базовые имена при генерации)
    # Создаём временный файл со связкой базовое имя -> фактический путь
    local tmp="${OUT_DIR}/${CHECKSUM_FILE}.verify"
    : > "${tmp}"
    while IFS= read -r line; do
      local h file; h="$(echo "${line}" | awk '{print $1}')" ; file="$(echo "${line}" | awk '{print $2}')"
      # Находим реальный путь по имени файла
      local p; p="$(find "${ARTIFACTS_DIR}" -maxdepth 1 -type f -name "${file}" | head -n1)"
      if [[ -z "${p}" ]]; then die "Missing artifact for checksum: ${file}"; fi
      printf "%s  %s\n" "${h}" "${p}" >> "${tmp}"
    done < "${OUT_DIR}/${CHECKSUM_FILE}"
    if [[ "${SHA256}" == "sha256sum" ]]; then
      run sha256sum --check --quiet "${tmp}"
    else
      # shasum: формат "hash  path"
      run shasum -a 256 --check "${tmp}" >/dev/null
    fi
    rm -f "${tmp}"
    log "Checksums OK"
  else
    log "No ${CHECKSUM_FILE}, skipping checksum verification"
  fi

  # Проверка GPG подписей
  if command -v gpg >/dev/null 2>&1; then
    log "Verifying GPG signatures"
    local failures=0
    while IFS= read -r f; do
      local base; base="$(basename "$f")"
      local sig="${OUT_DIR}/${base}.asc"
      if [[ -f "${sig}" ]]; then
        if run gpg --verify "${sig}" "${f}" 2>/dev/null; then
          log "OK: ${sig}"
        else
          log "FAIL: ${sig}"
          failures=$((failures+1))
        fi
      fi
    done < <(list_artifacts)

    if [[ -f "${OUT_DIR}/${CHECKSUM_FILE}.asc" ]]; then
      run gpg --verify "${OUT_DIR}/${CHECKSUM_FILE}.asc" "${OUT_DIR}/${CHECKSUM_FILE}" >/dev/null 2>&1 || die "Checksum signature invalid"
      log "OK: ${CHECKSUM_FILE}.asc"
    fi

    if (( failures > 0 )); then die "GPG verification failed for ${failures} file(s)"; fi
  else
    log "gpg not found, skipping signature verification"
  fi

  # Проверка cosign (если есть)
  if command -v cosign >/dev/null 2>&1; then
    if [[ -n "${COSIGN_KEY}" ]]; then
      log "Verifying cosign signatures"
      while IFS= read -r f; do
        local base; base="$(basename "$f")"
        local sig="${OUT_DIR}/${base}.sig"
        local cert="${OUT_DIR}/${base}.pem"
        if [[ -f "${sig}" ]]; then
          run cosign verify-blob --key "${COSIGN_KEY}" --signature "${sig}" --certificate "${cert}" "${f}"
          log "OK: cosign ${base}"
        fi
      done < <(list_artifacts)
    fi
    if [[ -n "${OCI_REF}" ]]; then
      log "Verifying OCI cosign signatures for ${OCI_REF}"
      run cosign verify "${OCI_REF}" >/dev/null
    fi
  fi

  log "Verification completed"
}

# -------- command dispatcher ----------
case "${CMD}" in
  checksums) do_checksums ;;
  gpg) do_gpg_sign_files ;;
  git-tag) do_git_tag ;;
  cosign) do_cosign_files ;;
  sbom) do_sbom ;;
  attest) do_slsa_attest ;;
  verify) do_verify ;;
  all)
    do_checksums
    do_gpg_sign_files
    do_git_tag
    if [[ -n "${COSIGN_KEY}" ]]; then do_cosign_files; fi
    if [[ "${DO_SBOM}" == "1" ]]; then do_sbom; fi
    if [[ "${DO_PROVENANCE}" == "1" ]]; then do_slsa_attest; fi
    do_verify
    ;;
  *) die "Unknown command: ${CMD}" ;;
esac

log "Done: ${CMD}"
