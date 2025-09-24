#!/usr/bin/env bash
#
# sign_release.sh — промышленный скрипт подписания релизов
# - Генерация хэшей (sha256/sha512) для артефактов
# - Формирование манифестов CHECKSUMS и release.json
# - GPG detached signatures (.asc или .sig)
# - Опциональная верификация результатов
#
# Лицензия: Apache-2.0 (или ваша корпоративная)
#
# Использование:
#   scripts/sign_release.sh \
#     --release-dir dist \
#     --out-dir dist \
#     --key-id ABCDEF1234567890 \
#     --version v1.2.3 \
#     --armor \
#     --algorithms "sha256 sha512" \
#     --verify
#
# Параметры/ENV:
#   --release-dir / RELEASE_DIR     Каталог с артефактами (по умолчанию: dist)
#   --out-dir     / OUT_DIR         Куда класть подписи и манифесты (по умолчанию: как release-dir)
#   --key-id      / KEY_ID          Идентификатор GPG-ключа (обязателен для подписания)
#   --version     / VERSION         Версия релиза (для release.json; необязателен)
#   --armor       / ARMOR=1         Подписывать в ASCII armor (.asc), иначе бинарно (.sig)
#   --no-armor                      Отключить armor
#   --algorithms  / ALGORITHMS      Список алгоритмов, напр. "sha256 sha512"
#   --manifest-only                 Подписывать только манифесты, без per-file подписей
#   --verify     / VERIFY=1         После создания — проверить подписи/хэши
#   --include-hidden                Включать скрытые файлы (начинающиеся с ".")
#   SOURCE_DATE_EPOCH               Используется как детерминированное время (если задан)
#
set -euo pipefail
IFS=$'\n\t'

# ---------- Logging ----------
log()  { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

# ---------- Defaults ----------
RELEASE_DIR="${RELEASE_DIR:-dist}"
OUT_DIR="${OUT_DIR:-$RELEASE_DIR}"
KEY_ID="${KEY_ID:-}"
VERSION="${VERSION:-}"
ARMOR="${ARMOR:-1}"
ALGORITHMS="${ALGORITHMS:-sha256 sha512}"
MANIFEST_ONLY="${MANIFEST_ONLY:-0}"
VERIFY="${VERIFY:-0}"
INCLUDE_HIDDEN="${INCLUDE_HIDDEN:-0}"

# ---------- Args parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-dir) RELEASE_DIR="$2"; shift 2 ;;
    --out-dir)     OUT_DIR="$2";     shift 2 ;;
    --key-id)      KEY_ID="$2";      shift 2 ;;
    --version)     VERSION="$2";     shift 2 ;;
    --armor)       ARMOR=1;          shift 1 ;;
    --no-armor)    ARMOR=0;          shift 1 ;;
    --algorithms)  ALGORITHMS="$2";  shift 2 ;;
    --manifest-only) MANIFEST_ONLY=1; shift 1 ;;
    --verify)      VERIFY=1;         shift 1 ;;
    --include-hidden) INCLUDE_HIDDEN=1; shift 1 ;;
    -h|--help)
      sed -n '1,100p' "$0"; exit 0 ;;
    *)
      die "Неизвестный аргумент: $1"
      ;;
  esac
done

# ---------- Dependencies ----------
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Требуется команда: $1"; }

need_cmd gpg

# Поддержка sha256/sha512: предпочитаем *sum, fallback на shasum
choose_hasher() {
  local algo="$1"
  case "$algo" in
    sha256)
      if command -v sha256sum >/dev/null 2>&1; then echo "sha256sum"; else echo "shasum -a 256"; fi
      ;;
    sha512)
      if command -v sha512sum >/dev/null 2>&1; then echo "sha512sum"; else echo "shasum -a 512"; fi
      ;;
    *)
      die "Неподдерживаемый алгоритм: $algo"
      ;;
  esac
}

need_cmd find
need_cmd awk
need_cmd sed
need_cmd sort
need_cmd stat
# sha* команды проверим динамически при использовании

# ---------- Setup ----------
umask 077
mkdir -p "$OUT_DIR"

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/signrel.XXXXXX")"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# Детерминированное время
NOW_EPOCH="${SOURCE_DATE_EPOCH:-$(date -u +%s)}"
NOW_ISO="$(date -u -d "@${NOW_EPOCH}" +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u +'%Y-%m-%dT%H:%M:%SZ')"

# ---------- Collect artifacts ----------
log "Сканирую артефакты в: $RELEASE_DIR"
[[ -d "$RELEASE_DIR" ]] || die "Каталог не найден: $RELEASE_DIR"

exclude_expr='\( -name "*.asc" -o -name "*.sig" -o -name "*CHECKSUMS*" -o -name "*.sha256" -o -name "*.sha512" -o -name "release.json" \) -prune -o'
if [[ "$INCLUDE_HIDDEN" -eq 1 ]]; then
  hidden_expr=""
else
  # исключаем скрытые файлы/каталоги
  hidden_expr='-not -path "*/.*" -not -name ".*"'
fi

# Разрешаем только обычные файлы первого уровня (без поддиректорий), чтобы не подпись временных и служебных
mapfile -t ARTIFACTS < <(eval "find \"$RELEASE_DIR\" -maxdepth 1 -type f $exclude_expr -print $hidden_expr" | sort)
if [[ "${#ARTIFACTS[@]}" -eq 0 ]]; then
  die "Артефактов не найдено"
fi
for f in "${ARTIFACTS[@]}"; do
  [[ -s "$f" ]] || die "Пустой или отсутствующий файл: $f"
done
log "Найдено файлов: ${#ARTIFACTS[@]}"

# ---------- Hashing ----------
declare -A HASHERS
for algo in $ALGORITHMS; do
  HASHERS["$algo"]="$(choose_hasher "$algo")"
  need_cmd ${HASHERS["$algo"]%% *}
done

declare -A CHECKMAN
for algo in $ALGORITHMS; do
  CHECKMAN["$algo"]="$OUT_DIR/RELEASE_CHECKSUMS_${algo}.txt"
  : > "${CHECKMAN[$algo]}"
done

# Пер-файл .shaXXX и общий манифест
for f in "${ARTIFACTS[@]}"; do
  rel="$(basename "$f")"
  for algo in $ALGORITHMS; do
    hasher="${HASHERS[$algo]}"
    # shellcheck disable=SC2086
    sum_line="$($hasher \"$f\" | awk '{print $1}')  $rel"
    echo "$sum_line" >> "${CHECKMAN[$algo]}"
    echo "$sum_line" > "$OUT_DIR/${rel}.${algo}"
  done
done

# Отсортируем манифесты по имени файла (детерминированность)
for algo in $ALGORITHMS; do
  sort -k2,2 "${CHECKMAN[$algo]}" -o "${CHECKMAN[$algo]}"
done

log "Хэши сгенерированы: ${ALGORITHMS}"

# ---------- release.json ----------
RELEASE_JSON="$OUT_DIR/release.json"

git_commit="$(git rev-parse --verify HEAD 2>/dev/null || echo "unknown")"
git_dirty="$(git diff --quiet 2>/dev/null || echo "dirty")"
git_tag="$(git describe --tags --always 2>/dev/null || echo "")"
version_effective="${VERSION:-${git_tag}}"

# Собираем список файлов с размерами и хэшами
# Формируем временный JSON и потом упорядочиваем поля с помощью jq (если есть)
need_cmd printf
{
  printf '{\n'
  printf '  "version": %s,\n' "$(printf '%s' "${version_effective:-unknown}" | sed 's/"/\\"/g' | awk '{printf("\"%s\"", $0)}')"
  printf '  "timestamp": "%s",\n' "$NOW_ISO"
  printf '  "commit": "%s",\n' "$git_commit"
  printf '  "dirty": "%s",\n' "${git_dirty:+true}${git_dirty:+"false"}"
  printf '  "algorithms": ['
  first=1
  for algo in $ALGORITHMS; do
    if [[ $first -eq 0 ]]; then printf ', '; fi
    printf '"%s"' "$algo"; first=0
  done
  printf '],\n'
  printf '  "files": [\n'
  idx=0
  total="${#ARTIFACTS[@]}"
  for f in "${ARTIFACTS[@]}"; do
    rel="$(basename "$f")"
    size="$(stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f")"
    printf '    { "name": "%s", "size": %s' "$rel" "$size"
    # Хэши
    for algo in $ALGORITHMS; do
      hasher="${HASHERS[$algo]}"
      sum="$($hasher "$f" | awk '{print $1}')"
      printf ', "%s": "%s"' "$algo" "$sum"
    done
    printf ' }'
    idx=$((idx+1))
    if [[ $idx -lt $total ]]; then printf ','; fi
    printf '\n'
  done
  printf '  ]\n'
  printf '}\n'
} > "$RELEASE_JSON"

log "Сформирован $RELEASE_JSON"

# ---------- Signing helpers ----------
[[ -n "$KEY_ID" ]] || die "Не указан --key-id / KEY_ID"

gpg_detach_sign() {
  local infile="$1"
  local armor_flag="$2"
  local ext
  if [[ "$armor_flag" -eq 1 ]]; then ext="asc"; else ext="sig"; fi
  local outfile="${infile}.${ext}"
  # --batch/--yes для CI, без явного запроса pinentry (безопаснее через агент)
  gpg --batch --yes --detach-sign \
      $([[ "$armor_flag" -eq 1 ]] && echo "--armor") \
      --local-user "$KEY_ID" \
      --output "$outfile" \
      "$infile"
  echo "$outfile"
}

gpg_verify_detach() {
  local infile="$1"
  local sigfile="$2"
  gpg --verify "$sigfile" "$infile" >/dev/null 2>&1
}

# ---------- Sign per-file (optional) ----------
if [[ "$MANIFEST_ONLY" -eq 0 ]]; then
  log "Подписываю каждый артефакт ключом: $KEY_ID"
  for f in "${ARTIFACTS[@]}"; do
    gpg_detach_sign "$f" "$ARMOR" >/dev/null
  done
fi

# ---------- Sign manifests and release.json ----------
log "Подписываю манифесты CHECKSUMS и release.json"
for algo in $ALGORITHMS; do
  gpg_detach_sign "${CHECKMAN[$algo]}" "$ARMOR" >/dev/null
done
gpg_detach_sign "$RELEASE_JSON" "$ARMOR" >/dev/null

# ---------- Verify (optional) ----------
if [[ "$VERIFY" -eq 1 ]]; then
  log "Верификация включена — проверяю подписи и хэши"
  # Подписи
  if [[ "$MANIFEST_ONLY" -eq 0 ]]; then
    for f in "${ARTIFACTS[@]}"; do
      sig="$f.$([[ "$ARMOR" -eq 1 ]] && echo asc || echo sig)"
      gpg_verify_detach "$f" "$sig" || die "Провал верификации подписи: $sig"
    done
  fi
  for algo in $ALGORITHMS; do
    man="${CHECKMAN[$algo]}"
    sig="$man.$([[ "$ARMOR" -eq 1 ]] && echo asc || echo sig)"
    gpg_verify_detach "$man" "$sig" || die "Провал верификации подписи: $sig"
  done
  sig="$RELEASE_JSON.$([[ "$ARMOR" -eq 1 ]] && echo asc || echo sig)"
  gpg_verify_detach "$RELEASE_JSON" "$sig" || die "Провал верификации подписи: $sig"

  # Хэши: сверяем per-file .shaXXX с реальными значениями
  for f in "${ARTIFACTS[@]}"; do
    rel="$(basename "$f")"
    for algo in $ALGORITHMS; do
      hasher="${HASHERS[$algo]}"
      actual="$($hasher "$f" | awk '{print $1}')"
      recorded="$(awk '{print $1}' "$OUT_DIR/${rel}.${algo}")"
      [[ "$actual" == "$recorded" ]] || die "Несовпадение $algo для $rel"
    done
  done
  log "Верификация успешно пройдена"
fi

# ---------- Summary ----------
log "Готово. Создано:"
{
  [[ "$MANIFEST_ONLY" -eq 0 ]] && for f in "${ARTIFACTS[@]}"; do
    ext="$([[ "$ARMOR" -eq 1 ]] && echo asc || echo sig)"
    printf '%s\n' "$f.$ext"
  done
  for algo in $ALGORITHMS; do
    printf '%s\n' "${CHECKMAN[$algo]}"
    printf '%s\n' "${CHECKMAN[$algo]}.$([[ "$ARMOR" -eq 1 ]] && echo asc || echo sig)"
  done
  printf '%s\n' "$RELEASE_JSON"
  printf '%s\n' "$RELEASE_JSON.$([[ "$ARMOR" -eq 1 ]] && echo asc || echo sig)"
} | sed "s#^# - #"

exit 0
