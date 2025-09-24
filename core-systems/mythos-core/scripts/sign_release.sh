#!/usr/bin/env bash
# mythos-core/scripts/sign_release.sh
# Secure, reproducible release signing for Mythos Core.
# Requirements: bash >= 4, gpg >= 2.2, coreutils, openssl (or sha256sum/sha512sum)
# Optional: cosign >= 2 for container-style signatures.
set -euo pipefail

# ------------------------------ Defaults & Globals ------------------------------
SCRIPT_NAME="$(basename "$0")"
UMASK_DEFAULT="077"                    # Restrict group/other permissions by default
CHECKSUM_SHA256="CHECKSUMS.sha256"
CHECKSUM_SHA512="CHECKSUMS.sha512"
PROVENANCE_JSON="PROVENANCE.json"
PROVENANCE_SIG="${PROVENANCE_JSON}.asc"

# Colored logging if TTY
if [ -t 2 ]; then
  BOLD="$(printf '\033[1m')"; RED="$(printf '\033[31m')"; GREEN="$(printf '\033[32m')"
  YELLOW="$(printf '\033[33m')"; BLUE="$(printf '\033[34m')"; RESET="$(printf '\033[0m')"
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

log()  { printf "%s[%s]%s %s\n" "$BLUE" "$SCRIPT_NAME" "$RESET" "$*" >&2; }
ok()   { printf "%s[%s]%s %s\n" "$GREEN" "$SCRIPT_NAME" "$RESET" "$*" >&2; }
warn() { printf "%s[%s]%s %s\n" "$YELLOW" "$SCRIPT_NAME" "$RESET" "$*" >&2; }
err()  { printf "%s[%s]%s %s\n" "$RED" "$SCRIPT_NAME" "$RESET" "$*" >&2; }

die() { err "$*"; exit 2; }

cleanup() {
  local ec=$?
  if [[ -n "${TMPDIR_SIGN:-}" && -d "${TMPDIR_SIGN}" ]]; then rm -rf "${TMPDIR_SIGN}" || true; fi
  exit "$ec"
}
trap cleanup EXIT INT TERM

# ------------------------------ Help -------------------------------------------
usage() {
  cat <<EOF
${SCRIPT_NAME} — промышленная подпись релизов Mythos Core.

Использование:
  ${SCRIPT_NAME} sign   --artifacts DIR --version VER [--key GPG_KEY] [--cosign-key PATH] [--identity ID] [--sbom PATH] [--no-sha512]
  ${SCRIPT_NAME} verify --artifacts DIR [--key GPG_KEY]

Опции:
  --artifacts DIR     Каталог с артефактами релиза (файлы будут отсортированы детерминированно).
  --version VER       Версия релиза (встраивается в PROVENANCE.json).
  --key GPG_KEY       Идентификатор ключа GPG (fingerprint/email/short id). По умолчанию — ключ по умолчанию агентом GPG.
  --cosign-key PATH   Ключ Cosign (опционально). Если задан — cosign подпишет файлы сумм и PROVENANCE.json.
  --identity ID       Идентичность (build provenance: CI job, git ref, builder id).
  --sbom PATH         Путь к SBOM (SPDX/CycloneDX). Будет включён в провенанс и подписан.
  --no-sha512         Не генерировать SHA-512 (по умолчанию генерируются sha256 и sha512).
  -h|--help           Показать справку.

Команды:
  sign                Сгенерировать суммы, подписи GPG, провенанс и (опц.) подписи Cosign.
  verify              Проверить суммы и подписи (GPG), соответствие провенанса.

Возвращаемые коды:
  0 — успех; 1 — частичная верификация провалилась; 2 — неверные аргументы/ошибка среды; 3 — внутренняя ошибка исполнения.

Примеры:
  ${SCRIPT_NAME} sign --artifacts ./dist --version 1.4.0 --key 0xDEADBEEF --identity "github-actions/mythos-core@main"
  ${SCRIPT_NAME} verify --artifacts ./dist --key releases@mythos-core.org
EOF
}

# ------------------------------ Utilities --------------------------------------
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Не найден требуемый бинарь: $1"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

sha256_impl() {
  if have_cmd sha256sum; then sha256sum "$@"
  elif have_cmd shasum; then shasum -a 256 "$@"
  elif have_cmd openssl; then openssl dgst -sha256 "$@"
  else die "Нет инструмента для SHA-256 (sha256sum/shasum/openssl)"
  fi
}

sha512_impl() {
  if have_cmd sha512sum; then sha512sum "$@"
  elif have_cmd shasum; then shasum -a 512 "$@"
  elif have_cmd openssl; then openssl dgst -sha512 "$@"
  else die "Нет инструмента для SHA-512 (sha512sum/shasum/openssl)"
  fi
}

abs_path() {
  # Resolve to absolute path without realpath dependency
  (cd "$1" >/dev/null 2>&1 && pwd)
}

list_artifacts() {
  # List regular files only; exclude signatures/checksums from previous runs
  local dir="$1"
  LC_ALL=C find "$dir" -maxdepth 1 -type f ! -name '*.asc' ! -name "${CHECKSUM_SHA256}" ! -name "${CHECKSUM_SHA512}" \
                        ! -name "${PROVENANCE_JSON}" ! -name "${PROVENANCE_SIG}" -print0 \
    | LC_ALL=C sort -z \
    | tr -d '\0' | tr '\0' '\n'
}

gpg_sign_detached() {
  local key="${1:-}"; shift
  local file="$1"
  local args=(--batch --yes --armor --detach-sign)
  [[ -n "$key" ]] && args+=(-u "$key")
  gpg "${args[@]}" "$file"
}

gpg_verify_detached() {
  local sig="$1"
  local file="$2"
  # gpg --verify return code: 0 ok, non-zero fail
  if gpg --verify "$sig" "$file" >/dev/null 2>&1; then return 0; else return 1; fi
}

cosign_sign_file() {
  local keypath="$1"
  local file="$2"
  COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes --key "$keypath" --output-signature "${file}.sig" "$file" >/dev/null
}

cosign_verify_file() {
  local keypath="$1"
  local file="$2"
  COSIGN_EXPERIMENTAL=1 cosign verify-blob --key "$keypath" --signature "${file}.sig" "$file" >/dev/null
}

write_provenance() {
  local out_json="$1"
  local version="$2"
  local identity="${3:-}"
  local artifacts_json_array="$4"
  local sbom_path="${5:-}"

  local builder="$(hostname -f 2>/dev/null || hostname || echo "unknown")"
  local now_iso
  now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  umask 077
  cat >"$out_json" <<JSON
{
  "schema": "https://mythos-core.org/provenance/1-0",
  "version": "${version}",
  "builtAt": "${now_iso}",
  "builder": "${builder}",
  "identity": "${identity}",
  "artifacts": ${artifacts_json_array},
  "vcs": {
    "commit": "$(git rev-parse --verify HEAD 2>/dev/null || echo "")",
    "branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")",
    "tag": "$(git describe --tags --exact-match 2>/dev/null || echo "")",
    "remote": "$(git config --get remote.origin.url 2>/dev/null || echo "")"
  },
  "environment": {
    "os": "$(uname -s)",
    "arch": "$(uname -m)"
  },
  "sbom": $( if [[ -n "$sbom_path" && -f "$sbom_path" ]]; then printf "%s" "\"$(basename "$sbom_path")\""; else printf "null"; fi )
}
JSON
}

json_escape() {
  # minimal escape for filenames in JSON
  printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
}

# ------------------------------ Commands ---------------------------------------
cmd_sign() {
  local artifacts_dir="" version="" gpg_key="" cosign_key="" identity="" sbom_path="" do_sha512=1

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --artifacts) artifacts_dir="${2:-}"; shift 2;;
      --version)   version="${2:-}"; shift 2;;
      --key)       gpg_key="${2:-}"; shift 2;;
      --cosign-key) cosign_key="${2:-}"; shift 2;;
      --identity)  identity="${2:-}"; shift 2;;
      --sbom)      sbom_path="${2:-}"; shift 2;;
      --no-sha512) do_sha512=0; shift;;
      -h|--help) usage; exit 0;;
      *) die "Неизвестный аргумент: $1";;
    esac
  done

  [[ -n "$artifacts_dir" ]] || die "--artifacts обязателен"
  [[ -n "$version" ]]       || die "--version обязателен"
  [[ -d "$artifacts_dir" ]] || die "Каталог не существует: $artifacts_dir"
  [[ -z "$sbom_path" || -f "$sbom_path" ]] || die "SBOM не найден: $sbom_path"

  need_cmd gpg
  need_cmd sort
  need_cmd find
  # Cosign — опционально
  if [[ -n "$cosign_key" ]]; then need_cmd cosign; fi

  umask "$UMASK_DEFAULT"
  artifacts_dir="$(abs_path "$artifacts_dir")"
  cd "$artifacts_dir"

  TMPDIR_SIGN="$(mktemp -d -t mythos-sign.XXXXXXXX)"
  log "Временный каталог: ${TMPDIR_SIGN}"

  # ---------- Собираем список артефактов ----------
  mapfile -t files < <(list_artifacts ".")
  ((${#files[@]} > 0)) || die "Артефактов не найдено в: ${artifacts_dir}"

  log "Артефакты (${#files[@]}):"
  for f in "${files[@]}"; do printf " - %s\n" "$(basename "$f")"; done >&2

  # ---------- Чек-суммы ----------
  : > "${CHECKSUM_SHA256}"
  for f in "${files[@]}"; do
    # sha256
    if have_cmd sha256sum; then
      sha256sum "$(basename "$f")" >> "${CHECKSUM_SHA256}"
    elif have_cmd shasum; then
      shasum -a 256 "$(basename "$f")" >> "${CHECKSUM_SHA256}"
    else
      # openssl формат отличается, нормализуем как у coreutils: "<hash>  <file>"
      openssl dgst -sha256 "$(basename "$f")" | awk '{print $2"  "$4}' >> "${CHECKSUM_SHA256}"
    fi
  done
  LC_ALL=C sort -o "${CHECKSUM_SHA256}" "${CHECKSUM_SHA256}"

  if [[ "$do_sha512" -eq 1 ]]; then
    : > "${CHECKSUM_SHA512}"
    for f in "${files[@]}"; do
      if have_cmd sha512sum; then
        sha512sum "$(basename "$f")" >> "${CHECKSUM_SHA512}"
      elif have_cmd shasum; then
        shasum -a 512 "$(basename "$f")" >> "${CHECKSUM_SHA512}"
      else
        openssl dgst -sha512 "$(basename "$f")" | awk '{print $2"  "$4}' >> "${CHECKSUM_SHA512}"
      fi
    done
    LC_ALL=C sort -o "${CHECKSUM_SHA512}" "${CHECKSUM_SHA512}"
  fi

  ok "Сгенерированы CHECKSUMS: ${CHECKSUM_SHA256}$([[ "$do_sha512" -eq 1 ]] && printf ", %s" "${CHECKSUM_SHA512}")"

  # ---------- Подписи GPG для каждого файла и файлов сумм ----------
  for f in "${files[@]}" "${CHECKSUM_SHA256}" $( [[ "$do_sha512" -eq 1 ]] && echo "${CHECKSUM_SHA512}" ); do
    gpg_sign_detached "$gpg_key" "$f"
  done
  ok "Подписи GPG созданы для артефактов и чек-сумм"

  # ---------- Подписываем SBOM (если задан) ----------
  if [[ -n "$sbom_path" ]]; then
    cp -f "$sbom_path" .
    gpg_sign_detached "$gpg_key" "$(basename "$sbom_path")"
    ok "SBOM включён и подписан: $(basename "$sbom_path")"
  fi

  # ---------- Провенанс ----------
  # Подготовим JSON массив артефактов с именем/sha256
  artifacts_json="[]"
  {
    echo "["
    local first=1
    for f in "${files[@]}"; do
      # извлечём sha256 из файла сумм
      sha_hash="$(grep -E "[[:space:]]$(printf '%q' "$(basename "$f")")$" "${CHECKSUM_SHA256}" | awk '{print $1}' | head -n1)"
      [[ -n "$sha_hash" ]] || sha_hash="$(grep -E "[[:space:]]$(basename "$f")$" "${CHECKSUM_SHA256}" | awk '{print $1}' | head -n1)"
      [[ "$first" -eq 1 ]] || printf ",\n"
      first=0
      printf '  {"name": %s, "sha256": "%s"}' "$(json_escape "$(basename "$f")")" "$sha_hash"
    done
    echo ""
    echo "]"
  } > "${TMPDIR_SIGN}/artifacts.json"
  artifacts_json="$(cat "${TMPDIR_SIGN}/artifacts.json")"

  write_provenance "${PROVENANCE_JSON}" "$version" "$identity" "$artifacts_json" "$( [[ -n "$sbom_path" ]] && basename "$sbom_path" || echo "" )"
  gpg_sign_detached "$gpg_key" "${PROVENANCE_JSON}"
  ok "Провенанс создан и подписан: ${PROVENANCE_JSON}, ${PROVENANCE_SIG}"

  # ---------- Cosign (опционально) ----------
  if [[ -n "$cosign_key" ]]; then
    cosign_sign_file "$cosign_key" "${CHECKSUM_SHA256}" || die "Cosign подпись не удалась: ${CHECKSUM_SHA256}"
    [[ "$do_sha512" -eq 1 ]] && cosign_sign_file "$cosign_key" "${CHECKSUM_SHA512}" || true
    cosign_sign_file "$cosign_key" "${PROVENANCE_JSON}" || die "Cosign подпись не удалась: ${PROVENANCE_JSON}"
    ok "Cosign подписи созданы для CHECKSUMS и PROVENANCE"
  fi

  # ---------- Самопроверка ----------
  "${0}" verify --artifacts "${artifacts_dir}" ${gpg_key:+--key "$gpg_key"} || { err "Самопроверка провалилась"; exit 1; }

  ok "Готово: артефакты подписаны, суммы и провенанс созданы."
}

cmd_verify() {
  local artifacts_dir="" gpg_key=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --artifacts) artifacts_dir="${2:-}"; shift 2;;
      --key)       gpg_key="${2:-}"; shift 2;;
      -h|--help) usage; exit 0;;
      *) die "Неизвестный аргумент: $1";;
    esac
  done

  [[ -n "$artifacts_dir" ]] || die "--artifacts обязателен"
  [[ -d "$artifacts_dir" ]] || die "Каталог не существует: $artifacts_dir"
  need_cmd gpg
  need_cmd sort
  need_cmd grep
  umask "$UMASK_DEFAULT"

  artifacts_dir="$(abs_path "$artifacts_dir")"
  cd "$artifacts_dir"

  local status=0

  # Проверяем подписи чек-сумм и провенанса, если присутствуют
  for f in "${CHECKSUM_SHA256}" "${CHECKSUM_SHA512}" "${PROVENANCE_JSON}"; do
    if [[ -f "$f" && -f "${f}.asc" ]]; then
      if gpg_verify_detached "${f}.asc" "$f"; then ok "GPG OK: $f"; else err "GPG FAIL: $f"; status=1; fi
    fi
  done

  # Проверяем суммы
  if [[ -f "${CHECKSUM_SHA256}" ]]; then
    if have_cmd sha256sum; then
      if sha256sum -c "${CHECKSUM_SHA256}" --ignore-missing >/dev/null 2>&1; then ok "SHA256 OK"; else err "SHA256 FAIL"; status=1; fi
    elif have_cmd shasum; then
      if shasum -a 256 -c "${CHECKSUM_SHA256}" --ignore-missing >/dev/null 2>&1; then ok "SHA256 OK"; else err "SHA256 FAIL"; status=1; fi
    else
      warn "Нет инструмента для автоматической проверки SHA256; пропущено"
    fi
  fi

  if [[ -f "${CHECKSUM_SHA512}" ]]; then
    if have_cmd sha512sum; then
      if sha512sum -c "${CHECKSUM_SHA512}" --ignore-missing >/dev/null 2>&1; then ok "SHA512 OK"; else err "SHA512 FAIL"; status=1; fi
    elif have_cmd shasum; then
      if shasum -a 512 -c "${CHECKSUM_SHA512}" --ignore-missing >/dev/null 2>&1; then ok "SHA512 OK"; else err "SHA512 FAIL"; status=1; fi
    else
      warn "Нет инструмента для автоматической проверки SHA512; пропущено"
    fi
  fi

  # Проверка подписей на отдельных артефактах (если .asc существует)
  mapfile -t files < <(list_artifacts ".")
  for f in "${files[@]}"; do
    if [[ -f "${f}.asc" ]]; then
      if gpg_verify_detached "${f}.asc" "$f"; then ok "GPG OK: $(basename "$f")"; else err "GPG FAIL: $(basename "$f")"; status=1; fi
    else
      warn "Нет подписи для $(basename "$f") — пропуск"
    fi
  done

  # Лёгкая проверка провенанса на согласованность (соответствие имён и sha256)
  if [[ -f "${PROVENANCE_JSON}" && -f "${CHECKSUM_SHA256}" ]]; then
    local mismatches=0
    while IFS= read -r name; do
      [[ -z "$name" ]] && continue
      # извлечь sha256 из provenance
      prov_sha="$(python3 - <<PY
import json,sys
p=json.load(open("${PROVENANCE_JSON}"))
name=${name!q}
for a in p.get("artifacts", []):
    if a.get("name")==name:
        print(a.get("sha256","")); break
PY
)"
      [[ -n "$prov_sha" ]] || { err "PROVENANCE: нет sha256 для $name"; mismatches=$((mismatches+1)); continue; }
      file_sha="$(grep -E "[[:space:]]${name}$" "${CHECKSUM_SHA256}" | awk '{print $1}' | head -n1 || true)"
      if [[ "$prov_sha" != "$file_sha" ]]; then
        err "Несоответствие sha256 для $name: provenance=$prov_sha checksums=$file_sha"
        mismatches=$((mismatches+1))
      fi
    done < <(jq -r '.artifacts[].name' "${PROVENANCE_JSON}" 2>/dev/null || python3 -c 'import json,sys; d=json.load(open("'"${PROVENANCE_JSON}"'")); [print(a.get("name","")) for a in d.get("artifacts",[])]')
    if [[ $mismatches -gt 0 ]]; then status=1; else ok "Провенанс согласован с CHECKSUMS"; fi
  fi

  exit "$status"
}

# ------------------------------ Main -------------------------------------------
main() {
  [[ $# -gt 0 ]] || { usage; exit 2; }
  case "$1" in
    sign)   shift; cmd_sign "$@";;
    verify) shift; cmd_verify "$@";;
    -h|--help) usage;;
    *) die "Неизвестная команда: $1 (ожидалось: sign|verify)";;
  esac
}

main "$@"
