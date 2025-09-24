#!/usr/bin/env bash
# datafabric-core/scripts/sign_release.sh
# Подписание релизов: git-теги, архивы/бинарники, манифесты, SBOM и опциональные attestations.
# Требования: bash, git, gpg, sha256sum/sha512sum (или shasum на macOS).
# Опционально: cosign, syft, openssl (RFC3161 ts, если нужно).

set -Eeuo pipefail

# ---------------------------
# ЛОГИРОВАНИЕ/УТИЛИТЫ
# ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
cd "${REPO_ROOT}"

_red(){ printf '\033[31m%s\033[0m\n' "$*" >&2; }
_green(){ printf '\033[32m%s\033[0m\n' "$*"; }
_yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
_blue(){ printf '\033[34m%s\033[0m\n' "$*"; }
log(){ _blue "[sign] $*"; }
warn(){ _yellow "[sign] $*"; }
die(){ _red "[sign] $*"; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Не найдено: $1"; }

# Кроссплатформенные hashlib
have_sha256sum(){ command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1; }
SHA256(){ if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
SHA512(){ if command -v sha512sum >/dev/null 2>&1; then sha512sum "$@"; else shasum -a 512 "$@"; fi; }

# ---------------------------
# ОКРУЖЕНИЕ
# ---------------------------
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^\s*#' "${ENV_FILE}" | sed 's/#.*//g' | xargs -I{} echo {} )
fi

VERSION="${VERSION:-}"                 # vX.Y.Z или X.Y.Z
TAG_PREFIX="${TAG_PREFIX:-v}"
RELEASE_DIR="${RELEASE_DIR:-${REPO_ROOT}/dist}"   # где лежат артефакты релиза
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/release}"       # куда писать подписи/манифест
GPG_KEY="${GPG_KEY:-}"                 # fpr или email ключа GPG для подписи
GPG_OPTS="${GPG_OPTS:---armor --detach-sign}"    # дополнительные флаги GPG
COSIGN_ENABLE="${COSIGN_ENABLE:-0}"    # 1=доп. подписи cosign *.sig
COSIGN_KEY="${COSIGN_KEY:-}"           # путь к ключу (или KMS URI)
SYFT_ENABLE="${SYFT_ENABLE:-1}"        # 1=генерировать SBOM, если есть syft
PROV_ENABLE="${PROV_ENABLE:-0}"        # 1=cosign attest (если есть cosign)
DRY_RUN="${DRY_RUN:-0}"                # 1=только печать команд
STRICT="${STRICT:-1}"                  # 1=ошибки при отсутствии артефактов

mkdir -p "${OUT_DIR}"

# ---------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ---------------------------
run(){ if [[ "${DRY_RUN}" == "1" ]]; then echo "+ $*"; else "$@"; fi; }

git_dirty(){
  [[ -n "$(git status --porcelain)" ]] && return 0 || return 1
}

normalize_version(){
  local v="$1"
  if [[ -z "${v}" ]]; then
    # Попытка взять из pyproject.toml / VERSION / git describe
    if [[ -f "pyproject.toml" ]]; then
      v="$(grep -E '^version\s*=\s*' pyproject.toml | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')"
    fi
    if [[ -z "${v}" && -f "VERSION" ]]; then v="$(cat VERSION | tr -d ' \n')"; fi
    if [[ -z "${v}" ]]; then v="$(git describe --tags --abbrev=0 2>/dev/null || true)"; fi
  fi
  [[ -z "${v}" ]] && die "Не удалось определить VERSION. Экспортируйте VERSION=X.Y.Z"
  # префикс
  if [[ "${v}" != "${TAG_PREFIX}"* ]]; then v="${TAG_PREFIX}${v}"; fi
  echo "${v}"
}

find_artifacts(){
  # Ищем файлы в RELEASE_DIR: архивы/whl/tar.gz, бинарники и т.п.
  [[ -d "${RELEASE_DIR}" ]] || { [[ "${STRICT}" == "1" ]] && die "Артефакты не найдены: ${RELEASE_DIR}"; echo ""; return 0; }
  find "${RELEASE_DIR}" -maxdepth 1 -type f \( \
    -name "*.tar.gz" -o -name "*.zip" -o -name "*.whl" -o -name "*.tgz" -o -name "*.gz" -o -name "*.bz2" -o -name "*.xz" -o -name "*.bin" -o -name "*.so" \
  \) | sort
}

write_manifest(){
  local tag="$1"; local manifest="${OUT_DIR}/manifest.json"
  local date_iso; date_iso="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  local repo; repo="$(git config --get remote.origin.url || echo "")"
  # shellcheck disable=SC2016
  python - "$manifest" <<PY
import json,sys,os,subprocess,hashlib,glob
out=sys.argv[1]
def sha256(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for chunk in iter(lambda:f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()
artifacts=sorted(glob.glob(os.path.join(os.environ.get('RELEASE_DIR','dist'),"*")))
items=[]
for a in artifacts:
    if os.path.isfile(a):
        items.append({"path": a, "sha256": sha256(a), "size": os.path.getsize(a)})
data={
  "tag": "${tag}",
  "created": "${date_iso}",
  "repo": "${repo}",
  "artifacts": items
}
os.makedirs(os.path.dirname(out), exist_ok=True)
json.dump(data, open(out,'w'), indent=2)
print(out)
PY
}

# ---------------------------
# ДЕЙСТВИЯ
# ---------------------------
prepare(){
  need git; need gpg; have_sha256sum || die "Нет sha256sum/shasum"
  [[ "${COSIGN_ENABLE}" == "1" ]] && need cosign || true
  [[ "${SYFT_ENABLE}" == "1" ]] && command -v syft >/dev/null 2>&1 || true
  _green "Окружение готово."
}

tag_release(){
  local tag; tag="$(normalize_version "${VERSION}")"
  log "Подписание git-тега: ${tag}"
  if git rev-parse "${tag}" >/dev/null 2>&1; then
    warn "Тег уже существует: ${tag} — пропускаю создание"
  else
    if git_dirty; then
      warn "Working tree dirty — рекомендуется коммитить перед тегированием"
    fi
    local msg="Release ${tag}"
    if [[ -n "${GPG_KEY}" ]]; then
      run git tag -s "${tag}" -u "${GPG_KEY}" -m "${msg}"
    else
      run git tag -s "${tag}" -m "${msg}"
    fi
  fi
  _green "Git-тег готов: ${tag}"
}

hashes(){
  local tag; tag="$(normalize_version "${VERSION}")"
  local files; files="$(find_artifacts)"
  [[ -z "${files}" ]] && { warn "Нет файлов для хэширования в ${RELEASE_DIR}"; return 0; }
  log "Формирование хэшей для ${RELEASE_DIR}"
  local f256="${OUT_DIR}/${tag#${TAG_PREFIX}}-SHA256SUMS.txt"
  local f512="${OUT_DIR}/${tag#${TAG_PREFIX}}-SHA512SUMS.txt"
  : > "${f256}"; : > "${f512}"
  while IFS= read -r f; do
    SHA256 "$f" >> "${f256}"
    SHA512 "$f" >> "${f512}"
  done <<< "${files}"
  _green "Хэши записаны: ${f256}, ${f512}"
}

sign_artifacts(){
  local tag; tag="$(normalize_version "${VERSION}")"
  local files; files="$(find_artifacts)"
  [[ -z "${files}" ]] && { warn "Нет файлов для подписи"; return 0; }
  log "Подписание артефактов (GPG)"
  while IFS= read -r f; do
    local asc="${f}.asc"
    if [[ -f "${asc}" ]]; then
      warn "Уже подписан: ${asc} — пропускаю"
    else
      if [[ -n "${GPG_KEY}" ]]; then
        run gpg --batch --yes -u "${GPG_KEY}" ${GPG_OPTS} -o "${asc}" "${f}"
      else
        run gpg --batch --yes ${GPG_OPTS} -o "${asc}" "${f}"
      fi
    fi
  done <<< "${files}"

  # Подпись файлов с хэшами
  for hf in "${OUT_DIR}/${tag#${TAG_PREFIX}}-SHA256SUMS.txt" "${OUT_DIR}/${tag#${TAG_PREFIX}}-SHA512SUMS.txt"; do
    [[ -f "${hf}" ]] || continue
    [[ -f "${hf}.asc" ]] || {
      if [[ -n "${GPG_KEY}" ]]; then
        run gpg --batch --yes -u "${GPG_KEY}" ${GPG_OPTS} -o "${hf}.asc" "${hf}"
      else
        run gpg --batch --yes ${GPG_OPTS} -o "${hf}.asc" "${hf}"
      fi
    }
  done
  _green "Подписи GPG созданы."

  if [[ "${COSIGN_ENABLE}" == "1" ]]; then
    need cosign
    log "Дополнительные подписи cosign (keyless/или ключ)"
    while IFS= read -r f; do
      local sig="${f}.sig"
      if [[ -n "${COSIGN_KEY}" ]]; then
        run cosign sign-blob --yes --key "${COSIGN_KEY}" --output-signature "${sig}" "${f}"
      else
        run cosign sign-blob --yes --output-signature "${sig}" "${f}"
      fi
    done <<< "${files}"
    _green "Подписи cosign созданы."
  fi
}

sbom_and_manifest(){
  local tag; tag="$(normalize_version "${VERSION}")"
  local manifest; manifest="$(write_manifest "${tag}")"
  _green "Манифест релиза: ${manifest}"

  if [[ "${SYFT_ENABLE}" == "1" ]] && command -v syft >/dev/null 2>&1; then
    local sbom="${OUT_DIR}/${tag#${TAG_PREFIX}}-sbom.spdx.json"
    log "Генерация SBOM (Syft) -> ${sbom}"
    run syft packages dir:"${REPO_ROOT}" -o spdx-json > "${sbom}"
    # Подпишем SBOM
    if [[ -n "${GPG_KEY}" ]]; then
      run gpg --batch --yes -u "${GPG_KEY}" ${GPG_OPTS} -o "${sbom}.asc" "${sbom}"
    else
      run gpg --batch --yes ${GPG_OPTS} -o "${sbom}.asc" "${sbom}"
    fi
  else
    warn "Syft не найден или отключён (SYFT_ENABLE=0) — пропускаю SBOM"
  fi
}

attest(){
  [[ "${PROV_ENABLE}" == "1" ]] || { warn "PROV_ENABLE=0 — пропускаю attestation"; return 0; }
  need cosign
  local files; files="$(find_artifacts)"
  [[ -z "${files}" ]] && { warn "Нет файлов для attestation"; return 0; }
  log "Cosign attest (generic predicate)"
  while IFS= read -r f; do
    local pred="${f}.predicate.json"
    cat > "${pred}" <<JSON
{
  "predicateType": "https://slsa.dev/provenance/v1",
  "buildType": "manual/scripts/sign_release.sh",
  "buildConfig": {
    "repo": "$(git config --get remote.origin.url || echo "")",
    "commit": "$(git rev-parse HEAD 2>/dev/null || echo "")"
  }
}
JSON
    if [[ -n "${COSIGN_KEY}" ]]; then
      run cosign attest --yes --key "${COSIGN_KEY}" --predicate "${pred}" --type slsaprovenance --artifact "${f}"
    else
      run cosign attest --yes --predicate "${pred}" --type slsaprovenance --artifact "${f}"
    fi
  done <<< "${files}"
  _green "Attestations созданы."
}

verify(){
  local tag; tag="$(normalize_version "${VERSION}")"
  log "Проверка подписей GPG и хэшей"
  # Проверка хэшей
  local f256="${OUT_DIR}/${tag#${TAG_PREFIX}}-SHA256SUMS.txt"
  local f512="${OUT_DIR}/${tag#${TAG_PREFIX}}-SHA512SUMS.txt"
  if [[ -f "${f256}" ]]; then
    if command -v sha256sum >/dev/null 2>&1; then
      (cd / && sha256sum -c "${f256}") || warn "Некоторые SHA256SUMS не совпали"
    else
      # shasum не умеет -c — проверим вручную
      while IFS= read -r line; do
        local sum file; sum="$(echo "$line" | awk '{print $1}')" ; file="$(echo "$line" | awk '{print $2}')"
        [[ -f "${file}" ]] || continue
        local calc; calc="$(shasum -a 256 "${file}" | awk '{print $1}')"
        [[ "${sum}" == "${calc}" ]] || die "SHA256 mismatch: ${file}"
      done < "${f256}"
    fi
  fi

  # Проверка gpg-подписей
  local files; files="$(find_artifacts)"
  while IFS= read -r f; do
    [[ -f "${f}.asc" ]] || { warn "Нет подписи: ${f}.asc"; continue; }
    run gpg --verify "${f}.asc" "${f}" >/dev/null 2>&1 && _green "OK: ${f}" || die "GPG verify failed: ${f}"
  done <<< "${files}"

  for hf in "${f256}" "${f512}"; do
    [[ -f "${hf}.asc" ]] || continue
    run gpg --verify "${hf}.asc" "${hf}" >/dev/null 2>&1 && _green "OK: $(basename "${hf}")"
  done
}

all(){
  prepare
  tag_release
  hashes
  sign_artifacts
  sbom_and_manifest
  attest
  verify
  _green "Релиз подписан и проверен успешно."
}

usage(){
  cat <<'USAGE'
Использование: scripts/sign_release.sh <команда>

Команды:
  prepare            — проверка окружения и инструментов
  tag                — создать и подписать git-тег (VERSION/X.Y.Z или vX.Y.Z)
  hashes             — сгенерировать SHA256/512 для артефактов из $RELEASE_DIR
  sign               — подписать артефакты и файлы хэшей (GPG, опционально cosign)
  sbom               — сгенерировать SBOM (Syft) и подписать его (GPG)
  attest             — создать attestations (cosign) для артефактов
  verify             — проверить подписи и хэши
  all                — полный цикл: prepare+tag+hashes+sign+sbom+attest+verify

Ключевые ENV:
  VERSION=X.Y.Z              Версия (если без префикса — добавится TAG_PREFIX)
  TAG_PREFIX=v               Префикс тега (по умолчанию "v")
  RELEASE_DIR=dist           Каталог артефактов
  OUT_DIR=release            Куда писать подписи/манифест/SBOM
  GPG_KEY=<fpr|email>        Идентификатор ключа GPG для подписи
  GPG_OPTS="--armor --detach-sign"
  COSIGN_ENABLE=0|1          Включить подписи cosign (sign-blob)
  COSIGN_KEY=...             Ключ cosign (файл, KMS URI, или пусто для keyless)
  SYFT_ENABLE=0|1            Генерация SBOM при наличии syft (по умолчанию 1)
  PROV_ENABLE=0|1            Cosign attest (по умолчанию 0)
  DRY_RUN=0|1                Печатать команды вместо выполнения
  STRICT=1|0                 Ошибка, если нет артефактов (по умолчанию 1)

Примеры:
  VERSION=1.2.3 GPG_KEY="build@company.com" ./scripts/sign_release.sh all
  COSIGN_ENABLE=1 COSIGN_KEY=cosign.key VERSION=1.2.3 ./scripts/sign_release.sh sign
  VERSION=1.2.3 ./scripts/sign_release.sh verify
USAGE
}

trap 'rc=$?; [[ $rc -ne 0 ]] && _red "Ошибка. Код: $rc"; exit $rc' EXIT

CMD="${1:-}"; shift || true
case "${CMD}" in
  prepare) prepare ;;
  tag)     tag_release ;;
  hashes)  hashes ;;
  sign)    sign_artifacts ;;
  sbom)    sbom_and_manifest ;;
  attest)  attest ;;
  verify)  verify ;;
  all)     all ;;
  ""|help|-h|--help) usage ;;
  *) die "Неизвестная команда: ${CMD}" ;;
esac
