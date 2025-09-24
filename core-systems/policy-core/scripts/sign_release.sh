#!/usr/bin/env bash
# policy-core/scripts/sign_release.sh
# Создание воспроизводимого релиз-архива с подписями и метаданными.
# Требования (обязательные): bash, tar, gpg, awk, sort, find
# Необязательные: cosign, git, syft, sha256sum | shasum | openssl

set -euo pipefail

# --------------------------- Константы и умолчания ---------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${ROOT_DIR}/.release"
PROVENANCE_FILE_NAME="provenance.json"
SBOM_FILE_NAME="sbom.spdx.json"

# Опции: см. usage()
BUNDLE_PATH="${ROOT_DIR}/policies"
VERSION=""
GPG_KEY_ID="${GPG_KEY_ID:-}"        # Можно передать через env или --gpg-key
COSIGN_KEY="${COSIGN_KEY:-}"        # Путь к приватному ключу Cosign (опционально)
PRODUCT_NAME="policy-core"
ARCHIVE_PREFIX="${PRODUCT_NAME}"
TAR_GZIP_LEVEL="${TAR_GZIP_LEVEL:-9}"

# ------------------------------ Утилиты --------------------------------------
die() { echo "[FATAL] $*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

sha256_file() {
  # Универсальный SHA256 с фолбэками
  local f="$1"
  if have sha256sum; then
    sha256sum "$f" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "$f" | awk '{print $1}'
  elif have openssl; then
    # Разные платформы печатают по-разному — нормализуем
    openssl dgst -sha256 "$f" | awk '{print $NF}'
  else
    die "Нет ни sha256sum, ни shasum, ни openssl"
  fi
}

git_info_json() {
  if have git && git -C "${ROOT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    local rev branch tag dirty
    rev="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || true)"
    branch="$(git -C "${ROOT_DIR}" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    tag="$(git -C "${ROOT_DIR}" describe --tags --abbrev=0 2>/dev/null || true)"
    dirty="false"
    git -C "${ROOT_DIR}" diff --quiet || dirty="true"
    printf '{"commit":"%s","branch":"%s","tag":"%s","dirty":%s}' \
      "${rev}" "${branch}" "${tag}" "${dirty}"
  else
    printf '{"commit":"","branch":"","tag":"","dirty":false}'
  fi
}

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

usage() {
  cat <<'USAGE'
Usage:
  sign_release.sh --version <semver> [--bundle <path>] [--gpg-key <KEYID>] [--out <dir>] [--cosign-key <path>] [--name <product>]

Options:
  --version <semver>    Версия релиза (например, 1.2.3). Обязательно.
  --bundle <path>       Путь к директории бандла (по умолчанию: ./policies).
  --gpg-key <KEYID>     Идентификатор GPG ключа (env GPG_KEY_ID тоже подходит).
  --cosign-key <path>   Путь к приватному ключу Cosign (опционально).
  --out <dir>           Каталог для артефактов (.release по умолчанию).
  --name <product>      Префикс имени архива (policy-core по умолчанию).

Env:
  TAR_GZIP_LEVEL        Уровень gzip компрессии (0..9, по умолчанию 9).

Скрипт делает:
  1) Пакует содержимое --bundle в воспроизводимый TAR.GZ.
  2) Строит SHA256SUMS и подписывает GPG (armor detached).
  3) Подписывает сам архив GPG; при наличии COSIGN — cosign sign-blob.
  4) Генерирует provenance.json с метаданными (git, версия, sha256).
  5) Если установлен syft — генерирует SBOM в SPDX JSON.

Примеры:
  ./scripts/sign_release.sh --version 1.0.0 --bundle ./policies --gpg-key ABCDEF01
  COSIGN_KEY=cosign.key ./scripts/sign_release.sh --version 1.0.0 --cosign-key cosign.key
USAGE
}

# ------------------------------ Парсинг флагов -------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --bundle)  BUNDLE_PATH="$(cd -- "$2" && pwd)"; shift 2 ;;
    --gpg-key) GPG_KEY_ID="${2:-}"; shift 2 ;;
    --cosign-key) COSIGN_KEY="${2:-}"; shift 2 ;;
    --out)     OUT_DIR="$(cd -- "$2" && pwd)"; shift 2 ;;
    --name)    ARCHIVE_PREFIX="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Неизвестный аргумент: $1 (см. --help)" ;;
  esac
done

[[ -n "${VERSION}" ]] || { usage; die "Требуется --version"; }
[[ -d "${BUNDLE_PATH}" ]] || die "--bundle '${BUNDLE_PATH}' не существует или не директория"

# ------------------------ Проверки инструментов ------------------------------
have tar      || die "Требуется tar"
have gpg      || die "Требуется gpg"
have awk      || die "Требуется awk"
have sort     || die "Требуется sort"
have find     || die "Требуется find"

if [[ -n "${COSIGN_KEY}" ]]; then
  have cosign || die "Указан --cosign-key, но cosign не найден"
fi

mkdir -p "${OUT_DIR}"

# ------------------------- Имя архива и пути вывода --------------------------
ARCHIVE_BASENAME="${ARCHIVE_PREFIX}-${VERSION}"
ARCHIVE_TAR="${OUT_DIR}/${ARCHIVE_BASENAME}.tar"
ARCHIVE_TGZ="${ARCHIVE_TAR}.gz"
SHA_FILE="${OUT_DIR}/SHA256SUMS"
GPG_ASC_SHA="${SHA_FILE}.asc"
GPG_ASC_TGZ="${ARCHIVE_TGZ}.asc"
PROVENANCE_PATH="${OUT_DIR}/${PROVENANCE_FILE_NAME}"
SBOM_PATH="${OUT_DIR}/${SBOM_FILE_NAME}"

echo "[INFO] Release version: ${VERSION}"
echo "[INFO] Bundle: ${BUNDLE_PATH}"
echo "[INFO] Output dir: ${OUT_DIR}"

# -------------------- Воспроизводимая упаковка TAR.GZ ------------------------
# Нормализуем время модификации, владельцев и порядок файлов.
# Примечание: --mtime требует GNU tar >= 1.28; для BSD tar будет отличаться.
MTIME="UTC 1970-01-01"
OWNER_FLAGS=(--owner=0 --group=0 --numeric-owner)
SORT_FLAG=(--sort=name)
if tar --help 2>/dev/null | grep -q -- '--sort=name'; then
  :
else
  SORT_FLAG=() # BSD tar не поддерживает сортировку — порядок обеспечим find | sort | tar -T -
fi

TMP_LIST="$(mktemp)"
trap 'rm -f "${TMP_LIST}"' EXIT

# Получаем список файлов (исключая скрытые системные из .git, если вдруг запускают из корня)
( cd "${BUNDLE_PATH}" && find . -type f -print | sort ) > "${TMP_LIST}"

echo "[INFO] Files to pack: $(wc -l < "${TMP_LIST}")"

if [[ ${#SORT_FLAG[@]} -gt 0 ]]; then
  # GNU tar: используем --mtime/--sort
  tar "${SORT_FLAG[@]}" \
      "${OWNER_FLAGS[@]}" \
      --mtime="${MTIME}" \
      -cf "${ARCHIVE_TAR}" \
      -C "${BUNDLE_PATH}" \
      -T "${TMP_LIST}"
else
  # BSD tar: без --sort, читаем из отсортированного списка
  tar "${OWNER_FLAGS[@]}" \
      --mtime "${MTIME}" \
      -cf "${ARCHIVE_TAR}" \
      -C "${BUNDLE_PATH}" \
      -T "${TMP_LIST}"
fi

# Сжимаем с предсказуемым gzip уровнем
if have pigz; then
  pigz -"${TAR_GZIP_LEVEL}" -n -f "${ARCHIVE_TAR}"
else
  GZIP="-${TAR_GZIP_LEVEL} -n" gzip -f "${ARCHIVE_TAR}"
fi

echo "[INFO] Archive created: ${ARCHIVE_TGZ}"

# --------------------------- Контрольные суммы -------------------------------
SHA_TGZ="$(sha256_file "${ARCHIVE_TGZ}")"
{
  printf "%s  %s\n" "${SHA_TGZ}" "$(basename "${ARCHIVE_TGZ}")"
} > "${SHA_FILE}"

echo "[INFO] SHA256 for archive: ${SHA_TGZ}"

# ------------------------------- Подписи GPG ---------------------------------
# Подписываем SHA256SUMS и сам архив (detached armor)
GPG_ARGS=(--armor --detach-sign)
if [[ -n "${GPG_KEY_ID}" ]]; then
  GPG_ARGS+=(--local-user "${GPG_KEY_ID}")
fi

gpg "${GPG_ARGS[@]}" --output "${GPG_ASC_SHA}" "${SHA_FILE}"
gpg "${GPG_ARGS[@]}" --output "${GPG_ASC_TGZ}" "${ARCHIVE_TGZ}"

echo "[INFO] GPG signatures written:"
echo "       - $(basename "${GPG_ASC_SHA}")"
echo "       - $(basename "${GPG_ASC_TGZ}")"

# ------------------------ Доп. подпись Cosign (опционально) ------------------
if [[ -n "${COSIGN_KEY}" ]]; then
  echo "[INFO] Cosign signing enabled"
  cosign sign-blob --key "${COSIGN_KEY}" --output-signature "${ARCHIVE_TGZ}.cosign.sig" "${ARCHIVE_TGZ}"
  cosign sign-blob --key "${COSIGN_KEY}" --output-signature "${SHA_FILE}.cosign.sig" "${SHA_FILE}"
  echo "[INFO] Cosign signatures written:"
  echo "       - $(basename "${ARCHIVE_TGZ}.cosign.sig")"
  echo "       - $(basename "${SHA_FILE}.cosign.sig")"
fi

# ------------------------------- SBOM (опц.) ---------------------------------
if have syft; then
  echo "[INFO] Generating SBOM via syft (SPDX JSON)"
  # SBOM по исходным политикам; при желании можно по распакованному архиву
  syft "${BUNDLE_PATH}" -o spdx-json > "${SBOM_PATH}" || echo "[WARN] syft failed; SBOM skipped"
else
  echo "[INFO] syft not found; SBOM skipped"
fi

# ------------------------------ Provenance -----------------------------------
GIT_JSON="$(git_info_json)"
cat > "${PROVENANCE_PATH}" <<JSON
{
  "product": "${PRODUCT_NAME}",
  "version": "${VERSION}",
  "built_at": "$(timestamp_utc())",
  "archive": "$(basename "${ARCHIVE_TGZ}")",
  "archive_sha256": "${SHA_TGZ}",
  "bundle_dir": "$(realpath "${BUNDLE_PATH}")",
  "tools": {
    "tar": "$(tar --version 2>/dev/null | head -n1 || echo "unknown")",
    "gpg": "$(gpg --version 2>/dev/null | head -n1 || echo "unknown")",
    "cosign": "$([[ -n "${COSIGN_KEY}" ]] && (cosign version 2>/dev/null | head -n1) || echo "disabled")"
  },
  "git": ${GIT_JSON}
}
JSON

echo "[INFO] Provenance written: $(basename "${PROVENANCE_PATH}")"

# ------------------------------- Итоги ---------------------------------------
echo "[OK] Release artifacts in: ${OUT_DIR}"
ls -1 "${OUT_DIR}" | sed 's/^/ - /'
