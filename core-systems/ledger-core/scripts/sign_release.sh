#!/usr/bin/env bash
# ledger-core/scripts/sign_release.sh
# Industrial-grade release signing & verification utility.
# Features:
# - Deterministic SHA256/SHA512 checksums for release artifacts
# - Detached GPG signatures (*.asc) with strong digest (SHA512)
# - Optional Sigstore cosign signatures for container images and files
# - Optional minisign signatures
# - Manifest (RELEASE.MF) with normalized paths, sizes, hashes, created-at
# - Verification mode: checksums + GPG/cosign/minisign
# - Safe defaults: strict shell flags, no secrets echo, explicit outputs under dist/signatures
# - Supports hardware tokens via gpg-agent (pinentry)
#
# Requirements (auto-detected):
#   bash, coreutils (sha256sum/sha512sum), gpg
# Optional:
#   cosign (for OCI), minisign
#
# Usage:
#   ./scripts/sign_release.sh --artifacts "dist/*" [--gpg-key ABCDEF..] [--out dist/signatures] [--cosign] [--minisign]
#   ./scripts/sign_release.sh --verify --artifacts "dist/*" [--out dist/signatures]
#
# Environment (optional):
#   SIGN_GPG_KEY              - key id / fingerprint / email
#   SIGN_OUT_DIR              - output directory (default: dist/signatures)
#   SIGN_COSIGN               - "1" to enable cosign
#   SIGN_MINISIGN             - "1" to enable minisign
#   COSIGN_EXPERIMENTAL       - set by user if needed
#   COSIGN_PASSWORD           - read by cosign (if key-protected)
#   MINISIGN_KEY              - path to private key (unencrypted not recommended)
#
# Exit codes: 0 OK, 1 usage/error, 2 verification failed

set -euo pipefail

# -------------- Logging --------------

log()  { printf '%s %s\n' "[sign]" "$*" >&2; }
die()  { printf '%s ERROR: %s\n' "[sign]" "$*" >&2; exit 1; }

# -------------- Defaults --------------

ARTIFACTS_PATTERN=""
OUT_DIR="${SIGN_OUT_DIR:-dist/signatures}"
GPG_KEY="${SIGN_GPG_KEY:-}"
DO_VERIFY=0
DO_COSIGN=0
DO_MINISIGN=0
MANIFEST_NAME="RELEASE.MF"
RELEASE_NOTE_NAME="RELEASE.NOTE"   # optional: if present alongside artifacts, it will be included in manifest

# -------------- Helpers --------------

usage() {
  cat >&2 <<EOF
Usage:
  $0 --artifacts "<glob>" [--out <dir>] [--gpg-key <id>] [--cosign] [--minisign]
  $0 --verify --artifacts "<glob>" [--out <dir>]

Options:
  --artifacts   Glob паттерн для артефактов (кавычки обязательны).
  --out         Каталог вывода (default: ${OUT_DIR}).
  --gpg-key     Идентификатор GPG-ключа (fingerprint/email). Если не указан, gpg выберет по умолчанию.
  --cosign      Включить подпись cosign (при наличии cosign).
  --minisign    Включить подпись minisign (при наличии minisign).
  --verify      Проверить чексуммы и подписи вместо подписания.

Примеры:
  $0 --artifacts "dist/*" --gpg-key 0xDEADBEEF --cosign
  $0 --verify --artifacts "dist/*"
EOF
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Требуется команда '$1'"
}

normalize_path() {
  # Normalize path to POSIX style (no leading ./, spaces preserved)
  local p="$1"
  p="${p#./}"
  printf '%s' "$p"
}

sha256() { sha256sum "$1" | awk '{print $1}'; }
sha512() { sha512sum "$1" | awk '{print $1}'; }

timestamp_iso() {
  # UTC ISO8601
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# -------------- Cosign helpers (optional) --------------

cosign_available() {
  command -v cosign >/dev/null 2>&1
}

minisign_available() {
  command -v minisign >/dev/null 2>&1
}

gpg_available() {
  command -v gpg >/dev/null 2>&1
}

# Detect if target is an OCI image reference (e.g., ghcr.io/org/app:tag)
is_image_ref() {
  local ref="$1"
  [[ "$ref" == *":"* && "$ref" == *"/"* && "$ref" != *.* && "$ref" != *"/."* ]] && return 1 # heuristic not reliable
  # Relaxed heuristic: treat strings with "/" and ":" (repo:tag) OR with "@sha256:" as images if no local file exists
  if [[ "$ref" == *"@sha256:"* || "$ref" == *":"* ]]; then
    [[ ! -e "$ref" ]]
    return
  fi
  return 1
}

# -------------- Parse args --------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) ARTIFACTS_PATTERN="${2:-}"; shift 2 ;;
    --out)       OUT_DIR="${2:-}"; shift 2 ;;
    --gpg-key)   GPG_KEY="${2:-}"; shift 2 ;;
    --cosign)    DO_COSIGN=1; shift ;;
    --minisign)  DO_MINISIGN=1; shift ;;
    --verify)    DO_VERIFY=1; shift ;;
    -h|--help)   usage ;;
    *) die "Неизвестный аргумент: $1" ;;
  esac
done

[[ -n "${ARTIFACTS_PATTERN}" ]] || usage

# -------------- Preconditions --------------

require_cmd sha256sum
require_cmd sha512sum
gpg_available || die "gpg не найден (обязателен для GPG-подписей)"
[[ "${DO_COSIGN}" -eq 0 || "$(cosign_available; echo $?)" -eq 0 ]] || die "cosign не найден, уберите --cosign"
[[ "${DO_MINISIGN}" -eq 0 || "$(minisign_available; echo $?)" -eq 0 ]] || die "minisign не найден, уберите --minisign"

mkdir -p "${OUT_DIR}"

# Собираем список артефактов
shopt -s nullglob
# shellcheck disable=SC2206
ARTIFACTS=( ${ARTIFACTS_PATTERN} )
shopt -u nullglob
[[ ${#ARTIFACTS[@]} -gt 0 ]] || die "По паттерну не найдено артефактов: ${ARTIFACTS_PATTERN}"

# -------------- Functions: manifest, sign, verify --------------

write_manifest() {
  local mf="${OUT_DIR}/${MANIFEST_NAME}"
  : > "${mf}"
  {
    echo "manifest-version: 1"
    echo "created-at: $(timestamp_iso)"
    echo "created-by: sign_release.sh"
    [[ -f "${RELEASE_NOTE_NAME}" ]] && echo "release-note: $(normalize_path "${RELEASE_NOTE_NAME}")"
    echo "entries:"
  } >> "${mf}"

  for f in "${ARTIFACTS[@]}"; do
    [[ -f "$f" ]] || continue
    local p s size h256 h512
    p="$(normalize_path "$f")"
    size="$(stat -c '%s' "$f")"
    h256="$(sha256 "$f")"
    h512="$(sha512 "$f")"
    {
      echo "  - path: ${p}"
      echo "    size: ${size}"
      echo "    sha256: ${h256}"
      echo "    sha512: ${h512}"
    } >> "${mf}"
  done
  log "Манифест создан: ${mf}"
}

sign_gpg_file() {
  local target="$1"
  local asc="${target}.asc"
  local args=( --armor --detach-sign --digest-algo SHA512 --output "${asc}" )
  [[ -n "${GPG_KEY}" ]] && args+=( --local-user "${GPG_KEY}" )
  # Используем gpg-agent и pinentry для безопасного доступа к ключу
  gpg "${args[@]}" -- "${target}"
  log "GPG подписано: ${asc}"
}

sign_minisign_file() {
  local target="$1"
  local sig="${target}.minisig"
  minisign -Sm "${target}" -x "${sig}"
  log "minisign подписано: ${sig}"
}

sign_cosign_for_file() {
  local target="$1"
  # Cosign умеет sign-blob; сохраняем подпись и bundle с протоколом прозрачности
  local sig="${target}.cosign.sig"
  local bnd="${target}.cosign.bundle"
  COSIGN_EXPERIMENTAL="${COSIGN_EXPERIMENTAL:-}" cosign sign-blob --yes --output-signature "${sig}" --output-certificate "${bnd}" "${target}"
  log "cosign sign-blob: ${sig} / ${bnd}"
}

sign_cosign_for_image() {
  local ref="$1"
  COSIGN_EXPERIMENTAL="${COSIGN_EXPERIMENTAL:-}" cosign sign --yes "${ref}"
  log "cosign подписал образ: ${ref}"
}

verify_checksums() {
  local mf="${OUT_DIR}/${MANIFEST_NAME}"
  [[ -f "${mf}" ]] || die "Манифест не найден: ${mf}"
  # Собираем проверочный список по sha256
  local tmplist sha
  tmplist="$(mktemp)"
  # Формат sha256sum --check: "<hash>  <path>"
  awk '/sha256:/{h=$2} /path:/{p=$2; gsub(/^[ \t]+|[ \t]+$/, "", p); printf("%s  %s\n", h, p)}' "${mf}" > "${tmplist}"
  # shellcheck disable=SC2046
  ( cd . && sha256sum --check --strict --status "${tmplist}" ) || die "Проверка sha256 провалена"
  rm -f "${tmplist}"
  log "Чексуммы OK"
}

verify_gpg_for_file() {
  local target="$1"
  local asc="${target}.asc"
  [[ -f "${asc}" ]] || die "Нет подписи: ${asc}"
  gpg --verify "${asc}" "${target}" >/dev/null 2>&1 || die "GPG verify провален: ${asc}"
}

verify_minisign_for_file() {
  local target="$1"
  local sig="${target}.minisig"
  [[ -f "${sig}" ]] || die "Нет подписи: ${sig}"
  minisign -Vm "${target}" -x "${sig}" >/dev/null 2>&1 || die "minisign verify провален: ${sig}"
}

verify_cosign_for_file() {
  local target="$1"
  local sig="${target}.cosign.sig"
  local bnd="${target}.cosign.bundle"
  [[ -f "${sig}" && -f "${bnd}" ]] || die "Нет cosign артефактов: ${sig}, ${bnd}"
  COSIGN_EXPERIMENTAL="${COSIGN_EXPERIMENTAL:-}" cosign verify-blob --signature "${sig}" --certificate "${bnd}" "${target}" >/dev/null 2>&1 \
    || die "cosign verify-blob провален: ${target}"
}

verify_cosign_for_image() {
  local ref="$1"
  COSIGN_EXPERIMENTAL="${COSIGN_EXPERIMENTAL:-}" cosign verify "${ref}" >/dev/null 2>&1 \
    || die "cosign verify провален: ${ref}"
}

# -------------- Main paths --------------

if [[ "${DO_VERIFY}" -eq 1 ]]; then
  log "Режим проверки"
  verify_checksums

  for f in "${ARTIFACTS[@]}"; do
    if [[ -f "$f" ]]; then
      # Проверяем подписи, если присутствуют
      [[ -f "${f}.asc"      ]] && verify_gpg_for_file "${f}"
      if minisign_available && [[ -f "${f}.minisig" ]]; then
        verify_minisign_for_file "${f}"
      fi
      if cosign_available && [[ -f "${f}.cosign.sig" ]]; then
        verify_cosign_for_file "${f}"
      fi
    elif is_image_ref "$f"; then
      if cosign_available; then
        verify_cosign_for_image "$f"
      else
        die "Проверка образа требует cosign: $f"
      fi
    else
      die "Артефакт не найден: $f"
    fi
  done
  log "Проверка завершена успешно"
  exit 0
fi

# -------------- Signing mode --------------

log "Подготовка манифеста и подписей"
write_manifest

# Подписываем манифест GPG в любом случае (ядро доверия релиза)
sign_gpg_file "${OUT_DIR}/${MANIFEST_NAME}"
[[ "${DO_MINISIGN}" -eq 1 && "$(minisign_available; echo $?)" -eq 0 ]] && sign_minisign_file "${OUT_DIR}/${MANIFEST_NAME}"
[[ "${DO_COSIGN}"   -eq 1 && "$(cosign_available; echo $?)"   -eq 0 ]] && sign_cosign_for_file "${OUT_DIR}/${MANIFEST_NAME}"

# Подписываем каждый файл-артефакт
for f in "${ARTIFACTS[@]}"; do
  if [[ -f "$f" ]]; then
    sign_gpg_file "$f"
    [[ "${DO_MINISIGN}" -eq 1 && "$(minisign_available; echo $?)" -eq 0 ]] && sign_minisign_file "$f"
    [[ "${DO_COSIGN}"   -eq 1 && "$(cosign_available; echo $?)"   -eq 0 ]] && sign_cosign_for_file "$f"
  elif is_image_ref "$f"; then
    if [[ "${DO_COSIGN}" -eq 1 && "$(cosign_available; echo $?)" -eq 0 ]]; then
      sign_cosign_for_image "$f"
    else
      log "Пропуск образа (нет --cosign или cosign недоступен): $f"
    fi
  else
    die "Артефакт не найден: $f"
  fi
done

# Дополнительно подписываем SHA‑файлы для удобства распространения (если нужны отдельные списки)
SHA256_TXT="${OUT_DIR}/SHA256SUMS.txt"
SHA512_TXT="${OUT_DIR}/SHA512SUMS.txt"
: > "${SHA256_TXT}"
: > "${SHA512_TXT}"
for f in "${ARTIFACTS[@]}"; do
  [[ -f "$f" ]] || continue
  printf '%s  %s\n' "$(sha256 "$f")" "$(normalize_path "$f")" >> "${SHA256_TXT}"
  printf '%s  %s\n' "$(sha512 "$f")" "$(normalize_path "$f")" >> "${SHA512_TXT}"
done
sign_gpg_file "${SHA256_TXT}"
sign_gpg_file "${SHA512_TXT}"

log "Готово: подписи и манифест в ${OUT_DIR}"
