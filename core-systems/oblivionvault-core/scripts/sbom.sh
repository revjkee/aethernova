#!/usr/bin/env bash
# scripts/sbom.sh - Генерация и подпись SBOM (CycloneDX/SPDX) для каталога или контейнерного образа.
# Требуемые/опциональные инструменты: syft, trivy, jq, cosign, cyclonedx-bom (python),
# cyclonedx-npm, cyclonedx-gomod, mvn (с cyclonedx-maven-plugin), sha256sum|shasum.
set -Eeuo pipefail
umask 027

# -------- Логи --------
LOG_FMT="${LOG_FMT:-json}"
log() {
  local level="$1"; shift
  local msg="$*"
  if [[ "$LOG_FMT" == "json" ]]; then
    printf '{"ts":"%s","level":"%s","msg":%s}\n' "$(date -u +%FT%TZ)" "$level" "$(jq -Rs . <<<"$msg")"
  else
    printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "$level" "$msg"
  fi
}

# -------- Ошибки/очистка --------
TMPDIR_ROOT="${TMPDIR:-/tmp}"
WORKDIR="$(mktemp -d "${TMPDIR_ROOT%/}/sbom.XXXXXXXX")"
cleanup() {
  [[ -d "$WORKDIR" ]] && rm -rf "$WORKDIR" || true
}
trap cleanup EXIT INT TERM

die() { log "ERROR" "$*"; exit 2; }

have() { command -v "$1" >/dev/null 2>&1; }

# -------- Хелп --------
usage() {
cat <<'EOF'
Usage:
  sbom.sh (--dir PATH | --image REF) [--out DIR] [--formats cyclonedx,spdx]
          [--project-name NAME] [--project-version VER]
          [--label KEY=VAL]... [--sign] [--attest] [--strict]

Targets:
  --dir PATH       Генерировать SBOM для каталога исходников PATH.
  --image REF      Генерировать SBOM для контейнерного образа (например, repo/app:tag).

Output:
  --out DIR        Каталог вывода (по умолчанию ./dist/sbom).
  --formats LIST   Список форматов через запятую: cyclonedx,spdx (по умолчанию cyclonedx,spdx).

Metadata:
  --project-name NAME         Имя проекта (попадает в metadata->component->name).
  --project-version VER       Версия проекта (по умолчанию из GIT_DESCRIBE или "0.0.0").
  --label KEY=VAL             Добавить label в metadata.tools/metadata.properties (можно несколько).
  --strict                    Заваливать процесс при отсутствии ключевых инструментов (syft/jq).

Security:
  --sign                      Подписать все итоговые файлы (cosign sign-blob).
  --attest                    Для цели --image: добавить cosign attestation (CycloneDX как predicate).

Env:
  SOURCE_DATE_EPOCH           Таймштамп для воспроизводимости (unix epoch).
  LOG_FMT=json|text           Формат логов (по умолчанию json).
EOF
}

# -------- Парсинг аргументов --------
TARGET_KIND=""
TARGET_VALUE=""
OUT_DIR="${OUT_DIR:-dist/sbom}"
FORMATS="cyclonedx,spdx"
PROJECT_NAME="${PROJECT_NAME:-}"
PROJECT_VERSION="${PROJECT_VERSION:-}"
STRICT=0
DO_SIGN=0
DO_ATTEST=0
LABELS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) TARGET_KIND="dir"; TARGET_VALUE="$2"; shift 2;;
    --image) TARGET_KIND="image"; TARGET_VALUE="$2"; shift 2;;
    --out) OUT_DIR="$2"; shift 2;;
    --formats) FORMATS="$2"; shift 2;;
    --project-name) PROJECT_NAME="$2"; shift 2;;
    --project-version) PROJECT_VERSION="$2"; shift 2;;
    --label) LABELS+=("$2"); shift 2;;
    --sign) DO_SIGN=1; shift;;
    --attest) DO_ATTEST=1; shift;;
    --strict) STRICT=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done

[[ -z "$TARGET_KIND" || -z "$TARGET_VALUE" ]] && { usage; die "Specify --dir or --image"; }

mkdir -p "$OUT_DIR"

# -------- Проверка инструментов --------
require() { have "$1" || { [[ $STRICT -eq 1 ]] && die "Required tool not found: $1"; return 1; }; }

need_syft=0; need_jq=0
[[ "$FORMATS" == *cyclonedx* || "$FORMATS" == *spdx* ]] && need_syft=1
need_jq=1 # для merge и логов
[[ $need_syft -eq 1 ]] && require syft || true
[[ $need_jq -eq 1 ]] && require jq || true

# Опциональные инструменты
have trivy && TRIVY=1 || TRIVY=0
have cosign && COSIGN=1 || COSIGN=0
have cyclonedx-bom && CDX_PY=1 || CDX_PY=0
have cyclonedx-npm && CDX_NPM=1 || CDX_NPM=0
have cyclonedx-gomod && CDX_GOMOD=1 || CDX_GOMOD=0
have mvn && MVN=1 || MVN=0

# -------- Метаданные проекта --------
if [[ -z "$PROJECT_VERSION" ]]; then
  if have git && git -C "${TARGET_KIND}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    PROJECT_VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")"
  else
    PROJECT_VERSION="0.0.0"
  fi
fi
if [[ -z "$PROJECT_NAME" ]]; then
  if [[ "$TARGET_KIND" == "dir" ]]; then
    PROJECT_NAME="$(basename "$(realpath "$TARGET_VALUE")")"
  else
    PROJECT_NAME="${TARGET_VALUE%%@*}"
  fi
fi

log "INFO" "Target kind=${TARGET_KIND} value=${TARGET_VALUE} out=${OUT_DIR} formats=${FORMATS} project=${PROJECT_NAME}@${PROJECT_VERSION}"

# -------- Вспомогательные функции --------
sha256_file() {
  if have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "sha256sum/shasum not found"
  fi
}

write_checksums() {
  local out_file="$1"; local sum
  sum="$(sha256_file "$out_file")"
  printf '%s  %s\n' "$sum" "$(basename "$out_file")" >> "${OUT_DIR%/}/SHA256SUMS"
}

# merge нескольких CycloneDX JSON -> один файл (dedup components/services)
merge_cyclonedx() {
  local out="$1"; shift
  local files=("$@")
  [[ ${#files[@]} -eq 0 ]] && die "merge_cyclonedx: no input files"

  if ! have jq; then
    cp -f "${files[0]}" "$out"
    return 0
  fi

  # Используем первый документ за основу; объединяем components/services с уникализацией по bom-ref/purl/name
  jq -s '
    def uniq_by_ref:
      (unique_by(.["bom-ref"] // .purl // .name));
    def merge_arrays(a):
      ( [.[].components // []] | add | uniq_by_ref ) as $comps
      | ( [.[].services // []] | add | unique_by(.name) ) as $svcs
      | (.[0] * { components: $comps } )
      | if ($svcs|length) > 0 then . * { services: $svcs } else . end;

    # Добавляем/нормализуем metadata.component
    def ensure_metadata(name; version):
      .metadata = (.metadata // {})
      | .metadata.component = (.metadata.component // { type:"application", name:name, version:version });

    merge_arrays(.) 
    | ensure_metadata($env.PROJECT_NAME; $env.PROJECT_VERSION)
  ' "${files[@]}" > "$out"
}

# -------- Сбор SBOM --------
CYCLONEDX_PARTS=()

# 1) syft (основной генератор)
if [[ $need_syft -eq 1 ]]; then
  case "$TARGET_KIND" in
    dir)
      if have syft; then
        if [[ "$FORMATS" == *cyclonedx* ]]; then
          syft "dir:${TARGET_VALUE}" -o cyclonedx-json > "${WORKDIR}/syft.cdx.json"
          CYCLONEDX_PARTS+=("${WORKDIR}/syft.cdx.json")
          log "INFO" "syft CycloneDX generated"
        fi
        if [[ "$FORMATS" == *spdx* ]]; then
          syft "dir:${TARGET_VALUE}" -o spdx-json > "${OUT_DIR%/}/sbom.spdx.json"
          write_checksums "${OUT_DIR%/}/sbom.spdx.json"
          log "INFO" "syft SPDX generated: sbom.spdx.json"
        fi
      fi
      ;;
    image)
      if have syft; then
        if [[ "$FORMATS" == *cyclonedx* ]]; then
          syft "${TARGET_VALUE}" -o cyclonedx-json > "${WORKDIR}/syft-image.cdx.json"
          CYCLONEDX_PARTS+=("${WORKDIR}/syft-image.cdx.json")
          log "INFO" "syft CycloneDX for image generated"
        fi
        if [[ "$FORMATS" == *spdx* ]]; then
          syft "${TARGET_VALUE}" -o spdx-json > "${OUT_DIR%/}/image.sbom.spdx.json"
          write_checksums "${OUT_DIR%/}/image.sbom.spdx.json"
          log "INFO" "syft SPDX for image generated: image.sbom.spdx.json"
        fi
      fi
      ;;
  esac
fi

# 2) trivy CycloneDX (дополнение)
if [[ $TRIVY -eq 1 && "$FORMATS" == *cyclonedx* ]]; then
  case "$TARGET_KIND" in
    dir)
      trivy fs --cache-dir "${WORKDIR}/trivy-cache" --format cyclonedx --output "${WORKDIR}/trivy.cdx.json" "${TARGET_VALUE}" || true
      [[ -s "${WORKDIR}/trivy.cdx.json" ]] && CYCLONEDX_PARTS+=("${WORKDIR}/trivy.cdx.json") && log "INFO" "trivy CycloneDX added"
      ;;
    image)
      trivy image --cache-dir "${WORKDIR}/trivy-cache" --format cyclonedx --output "${WORKDIR}/trivy-image.cdx.json" "${TARGET_VALUE}" || true
      [[ -s "${WORKDIR}/trivy-image.cdx.json" ]] && CYCLONEDX_PARTS+=("${WORKDIR}/trivy-image.cdx.json") && log "INFO" "trivy CycloneDX for image added"
      ;;
  esac
fi

# 3) Языковые CycloneDX (если доступно и найден манифест)
if [[ "$TARGET_KIND" == "dir" && "$FORMATS" == *cyclonedx* ]]; then
  pushd "$TARGET_VALUE" >/dev/null
  # Python
  if [[ $CDX_PY -eq 1 ]]; then
    if [[ -f "poetry.lock" || -f "requirements.txt" || -f "Pipfile.lock" ]]; then
      cyclonedx-bom --format json --output "${WORKDIR}/cdx-python.json" 2>/dev/null || true
      [[ -s "${WORKDIR}/cdx-python.json" ]] && CYCLONEDX_PARTS+=("${WORKDIR}/cdx-python.json") && log "INFO" "cyclonedx-bom (python) added"
    fi
  fi
  # npm/yarn
  if [[ $CDX_NPM -eq 1 ]]; then
    if [[ -f "package-lock.json" || -f "pnpm-lock.yaml" || -f "yarn.lock" ]]; then
      cyclonedx-npm --output-file "${WORKDIR}/cdx-npm.json" --omit dev || true
      [[ -s "${WORKDIR}/cdx-npm.json" ]] && CYCLONEDX_PARTS+=("${WORKDIR}/cdx-npm.json") && log "INFO" "cyclonedx-npm added"
    fi
  fi
  # Go
  if [[ $CDX_GOMOD -eq 1 && -f "go.mod" ]]; then
    cyclonedx-gomod app -json -output "${WORKDIR}/cdx-gomod.json" || true
    [[ -s "${WORKDIR}/cdx-gomod.json" ]] && CYCLONEDX_PARTS+=("${WORKDIR}/cdx-gomod.json") && log "INFO" "cyclonedx-gomod added"
  fi
  # Maven (требует подключенного плагина в pom.xml; если нет — команда вернёт ошибку)
  if [[ $MVN -eq 1 && -f "pom.xml" ]]; then
    mvn -q -DskipTests -Dcyclonedx.skipAttach=true org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json -DoutputName="cdx-maven" || true
    if [[ -f "target/cdx-maven.json" ]]; then
      cp "target/cdx-maven.json" "${WORKDIR}/cdx-maven.json"
      CYCLONEDX_PARTS+=("${WORKDIR}/cdx-maven.json")
      log "INFO" "cyclonedx-maven added"
    fi
  fi
  popd >/dev/null
fi

# -------- Сборка единого CycloneDX --------
COMBINED_CDX="${OUT_DIR%/}/sbom.cyclonedx.json"
if [[ ${#CYCLONEDX_PARTS[@]} -gt 0 ]]; then
  export PROJECT_NAME PROJECT_VERSION
  merge_cyclonedx "$COMBINED_CDX" "${CYCLONEDX_PARTS[@]}"
  write_checksums "$COMBINED_CDX"
  log "INFO" "Combined CycloneDX written: ${COMBINED_CDX}"
else
  log "WARN" "No CycloneDX parts produced; skipping combined file"
fi

# -------- Добавление properties/labels --------
if [[ -s "$COMBINED_CDX" && ${#LABELS[@]} -gt 0 && $(have jq && echo 1 || echo 0) -eq 1 ]]; then
  tmp="${WORKDIR}/cdx-labeled.json"
  jq --argjson props "$(printf '%s\n' "${LABELS[@]}" | awk -F= '{printf "{\"name\":%q,\"value\":%q}\n",$1,$2}' | jq -s '.')" '
    .metadata.properties = ((.metadata.properties // []) + $props)
  ' "$COMBINED_CDX" > "$tmp" && mv "$tmp" "$COMBINED_CDX"
  log "INFO" "Labels added to CycloneDX: ${#LABELS[@]}"
fi

# -------- Подписи файлов --------
if [[ $DO_SIGN -eq 1 ]]; then
  if [[ $COSIGN -eq 1 ]]; then
    export COSIGN_EXPERIMENTAL=1
    for f in "$COMBINED_CDX" "${OUT_DIR%/}/sbom.spdx.json" "${OUT_DIR%/}/image.sbom.spdx.json"; do
      [[ -s "$f" ]] || continue
      cosign sign-blob --yes --output-signature "${f}.sig" "$f" >/dev/null
      write_checksums "${f}.sig"
      log "INFO" "Signed: $(basename "$f") -> $(basename "${f}.sig")"
    done
  else
    log "WARN" "cosign not found; --sign ignored"
  fi
fi

# -------- Attestation для образа --------
if [[ "$TARGET_KIND" == "image" && $DO_ATTEST -eq 1 ]]; then
  if [[ $COSIGN -eq 1 && -s "$COMBINED_CDX" ]]; then
    export COSIGN_EXPERIMENTAL=1
    # Тип attestations: CycloneDX SBOM
    cosign attest --yes --type cyclonedx --predicate "$COMBINED_CDX" "$TARGET_VALUE" >/dev/null || die "cosign attest failed"
    log "INFO" "Cosign attestation uploaded for image: $TARGET_VALUE"
  else
    log "WARN" "cosign or combined CycloneDX not available; --attest ignored"
  fi
fi

# -------- Итоговый вывод --------
SUMMARY="${OUT_DIR%/}/summary.json"
{
  printf '{'
  printf '"project":{"name":%s,"version":%s},' "$(jq -Rs . <<<"$PROJECT_NAME")" "$(jq -Rs . <<<"$PROJECT_VERSION")"
  printf '"target":{"kind":%s,"value":%s},' "$(jq -Rs . <<<"$TARGET_KIND")" "$(jq -Rs . <<<"$TARGET_VALUE")"
  printf '"artifacts":{'
  printf '"cyclonedx":%s,' "$( [[ -s "$COMBINED_CDX" ]] && jq -Rs . <<<"$COMBINED_CDX" || echo null )"
  printf '"spdx":%s' "$( [[ -s "${OUT_DIR%/}/sbom.spdx.json" ]] && jq -Rs . <<<"${OUT_DIR%/}/sbom.spdx.json" || ([[ -s "${OUT_DIR%/}/image.sbom.spdx.json" ]] && jq -Rs . <<<"${OUT_DIR%/}/image.sbom.spdx.json") || echo null )"
  printf '},'
  printf '"checksums":%s' "$( [[ -s "${OUT_DIR%/}/SHA256SUMS" ]] && jq -Rs . < "${OUT_DIR%/}/SHA256SUMS" || echo '""' )"
  printf '}'
} > "$SUMMARY"
log "INFO" "Summary: $SUMMARY"
