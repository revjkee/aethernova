#!/usr/bin/env bash
# cybersecurity-core/scripts/run_scans.sh
# Универсальный оркестратор безопасностных сканов:
# Secrets, SAST, SCA (deps), IaC, Container/FS, SBOM, DAST (опц.)
# Выходные форматы: SARIF/JSON + сводка.
# Требования: bash, git, (опц.) docker, jq. Остальные инструменты — локально или через контейнер.

set -Eeuo pipefail
IFS=$'\n\t'

#####################################
# Константы и значения по умолчанию #
#####################################

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${REPO_ROOT}" ]]; then
  echo "Не удалось определить корень репозитория git. Запускайте из проекта или инициализируйте git." >&2
  exit 2
fi

TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
DEFAULT_OUT_DIR="${REPO_ROOT}/reports/security/${TIMESTAMP}"

MODE="full"                              # quick|full
OUT_DIR="${DEFAULT_OUT_DIR}"
SEVERITY_THRESHOLD="high"                # low|medium|high|critical
APP_URL=""                               # для DAST
USE_DOCKER="yes"                         # yes|no
SKIP_LIST=""                             # csv имён инструментов
ONLY_FILTER=""                           # фильтр категории/инструмента
MAX_PROCS="$(nproc 2>/dev/null || echo 4)"

# Списки инструментов по категориям
TOOLS_SECRETS=(gitleaks trufflehog)
TOOLS_SAST=(semgrep bandit)
TOOLS_SCA=(pip-audit safety)
TOOLS_IAC=(checkov tfsec)
TOOLS_CONTAINER=(trivy grype)
TOOLS_SBOM=(syft)
TOOLS_DAST=(zap-baseline) # опционально, если передан --app-url

# Карта образов Docker (актуальные public-образы)
declare -A DOCKER_IMG=(
  ["gitleaks"]="zricethezav/gitleaks:latest"
  ["trufflehog"]="ghcr.io/trufflesecurity/trufflehog:latest"
  ["semgrep"]="semgrep/semgrep:latest"
  ["bandit"]="pyupio/pyup:bandit"                 # альтернатива: python:3 + pip install bandit
  ["pip-audit"]="trailofbits/pip-audit:latest"
  ["safety"]="pyupio/safety"                      # альтернатива: python:3 + pip install safety
  ["checkov"]="bridgecrew/checkov:latest"
  ["tfsec"]="aquasec/tfsec:latest"
  ["trivy"]="aquasec/trivy:latest"
  ["grype"]="anchore/grype:latest"
  ["syft"]="anchore/syft:latest"
  ["zap-baseline"]="owasp/zap2docker-stable"
)

# Цвета для читаемых логов (отключатся в не-TTY)
if [[ -t 1 ]]; then
  C_BOLD="\033[1m"; C_RED="\033[31m"; C_YELLOW="\033[33m"; C_GREEN="\033[32m"; C_RESET="\033[0m"
else
  C_BOLD=""; C_RED=""; C_YELLOW=""; C_GREEN=""; C_RESET=""
fi

#################
# Утилиты/логи  #
#################

log()  { echo -e "${C_BOLD}[*]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[!]${C_RESET} $*" >&2; }
err()  { echo -e "${C_RED}[x]${C_RESET} $*" >&2; }

die() {
  err "$*"
  exit 1
}

usage() {
  cat <<EOF
run_scans.sh — объединённый запуск сканеров безопасности.

Использование:
  $(basename "$0") [опции]

Опции:
  --mode [quick|full]             Режим сканирования (по умолчанию: ${MODE})
  --severity-threshold LEVEL      Уровень для фатального выхода: low|medium|high|critical (по умолчанию: ${SEVERITY_THRESHOLD})
  --out-dir PATH                  Куда писать отчёты (по умолчанию: ${DEFAULT_OUT_DIR})
  --app-url URL                   URL для DAST (OWASP ZAP baseline). Если не задан — DAST пропускается.
  --no-docker                     Не использовать Docker-образы (только локально установленные утилиты)
  --skip "a,b,c"                  Пропустить указанные инструменты (например: "gitleaks,tfsec")
  --only FILTER                   Запуск только по категории/инструменту: secrets|sast|sca|iac|container|sbom|dast|<tool>
  --max-procs N                   Максимум параллельных задач (по умолчанию: ${MAX_PROCS})
  -h|--help                       Показать помощь

Выход:
  0 — нет находок выше порога (или всё пропущено/отсутствуют инструменты),
  1 — обнаружены проблемы >= threshold,
  2 — ошибка выполнения.

Примеры:
  $(basename "$0") --mode quick --severity-threshold high
  $(basename "$0") --app-url https://example.com --only dast
  $(basename "$0") --skip "trufflehog,grype" --out-dir ./reports/security/custom
EOF
}

######################################
# Разбор аргументов командной строки #
######################################

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2;;
    --severity-threshold) SEVERITY_THRESHOLD="${2:-}"; shift 2;;
    --out-dir) OUT_DIR="${2:-}"; shift 2;;
    --app-url) APP_URL="${2:-}"; shift 2;;
    --no-docker) USE_DOCKER="no"; shift 1;;
    --skip) SKIP_LIST="${2:-}"; shift 2;;
    --only) ONLY_FILTER="${2:-}"; shift 2;;
    --max-procs) MAX_PROCS="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) die "Неизвестный аргумент: $1. См. --help";;
  esac
done

case "${MODE}" in quick|full) ;; *) die "Неверный --mode: ${MODE} (quick|full)";; esac
case "${SEVERITY_THRESHOLD}" in low|medium|high|critical) ;; *) die "Неверный --severity-threshold: ${SEVERITY_THRESHOLD}";; esac

#########################
# Подготовка каталогов  #
#########################

mkdir -p "${OUT_DIR}"/{logs,secrets,sast,sca,iac,container,sbom,dast}
SUMMARY_JSON="${OUT_DIR}/summary.json"
COMBINED_SARIF="${OUT_DIR}/combined.sarif"
MASTER_LOG="${OUT_DIR}/logs/run_scans.log"

exec > >(tee -a "${MASTER_LOG}") 2>&1

log "Репозиторий: ${REPO_ROOT}"
log "Каталог отчётов: ${OUT_DIR}"
log "Режим: ${MODE}, Порог критичности: ${SEVERITY_THRESHOLD}, Docker: ${USE_DOCKER}, MaxProcs: ${MAX_PROCS}"

#########################
# Вспомогательные funcs #
#########################

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Запуск инструмента локально или через docker.
# Args: tool_name, mount_dir(REPO_ROOT), workdir(/src), extra docker args..., -- <cmd...>
run_tool() {
  local tool="$1"; shift
  local docker_img="${DOCKER_IMG[$tool]:-}"
  local docker_cmd=()
  local local_cmd=()
  local mode="local"

  # найти разделитель -- и команду
  local args=("$@")
  local sep_idx=-1
  for i in "${!args[@]}"; do
    if [[ "${args[$i]}" == "--" ]]; then sep_idx="$i"; break; fi
  done
  if [[ "$sep_idx" -lt 0 ]]; then
    die "run_tool: требуется разделитель -- между docker-args и командой"
  fi
  local docker_args=("${args[@]:0:$sep_idx}")
  local_cmd=("${args[@]:$((sep_idx+1)):${#args[@]}}")

  if [[ "$USE_DOCKER" == "yes" && -n "$docker_img" && have_cmd docker ]]; then
    mode="docker"
    docker_cmd=( docker run --rm --network host
      -v "${REPO_ROOT}:/src:rw"
      -v "${OUT_DIR}:/out:rw"
      -w /src
      "${docker_args[@]}"
      "$docker_img"
    )
  fi

  if [[ "$mode" == "local" ]]; then
    # локальный запуск
    "${local_cmd[@]}"
  else
    "${docker_cmd[@]}" "${local_cmd[@]}"
  fi
}

# Проверка пропуска/фильтра
should_run() {
  local name="$1"
  if [[ -n "$ONLY_FILTER" ]]; then
    [[ "$name" == "$ONLY_FILTER" ]] || [[ "$ONLY_FILTER" =~ (^|,)(secrets|sast|sca|iac|container|sbom|dast)($|,) && "$name" =~ ${ONLY_FILTER} ]] || return 1
  fi
  if [[ -n "$SKIP_LIST" ]]; then
    [[ ",${SKIP_LIST}," == *",${name},"* ]] && return 1
  fi
  return 0
}

# Добавление SARIF в сводный файл
append_sarif() {
  local file="$1"
  if [[ ! -s "$file" ]]; then return 0; fi
  if ! have_cmd jq; then
    warn "jq не найден, пропускаю объединение SARIF: $file"
    return 0
  fi
  if [[ ! -s "$COMBINED_SARIF" ]]; then
    cp "$file" "$COMBINED_SARIF"
  else
    # Объединяем runs
    jq -s '{ "$schema": (.[0]."$schema"), version: (.[0].version), runs: (.[0].runs + .[1].runs) }' "$COMBINED_SARIF" "$file" > "${COMBINED_SARIF}.tmp"
    mv "${COMBINED_SARIF}.tmp" "$COMBINED_SARIF"
  fi
}

# Маппинг SARIF уровней к порогу
level_to_rank() {
  case "$1" in
    error) echo 3;;
    warning) echo 2;;
    note) echo 1;;
    *) echo 0;;
  esac
}
threshold_to_min_level() {
  case "$SEVERITY_THRESHOLD" in
    critical|high) echo "error";;
    medium) echo "warning";;
    low) echo "note";;
  esac
}

# Анализ SARIF по порогу
evaluate_findings() {
  if ! have_cmd jq || [[ ! -s "$COMBINED_SARIF" ]]; then
    warn "Нет jq или комбинированного SARIF — не могу строго оценить порог. Рекомендую установить jq."
    echo '{"status":"unknown","reason":"no_jq_or_no_sarif"}' > "${SUMMARY_JSON}"
    return 0
  fi
  local min_level
  min_level="$(threshold_to_min_level)"
  local count
  count="$(jq --arg min "${min_level}" '
    def level_rank(l):
      if l=="error" then 3 elif l=="warning" then 2 elif l=="note" then 1 else 0 end;
    [ .runs[].results[]?.level // "warning" | select(level_rank(.) >= level_rank($min)) ] | length
  ' "$COMBINED_SARIF")"
  jq --arg ts "$TIMESTAMP" --arg thr "$SEVERITY_THRESHOLD" --argjson count "$count" '
    {timestamp:$ts, threshold:$thr, matched_findings:$count}
  ' < /dev/null > "${SUMMARY_JSON}"

  if [[ "${count}" -gt 0 ]]; then
    return 1
  fi
  return 0
}

#############################
# Реализация сканеров       #
#############################

run_gitleaks() {
  should_run "gitleaks" || { log "SKIP gitleaks"; return 0; }
  log "Secrets: gitleaks"
  local out="${OUT_DIR}/secrets/gitleaks.sarif"
  run_tool "gitleaks" "${REPO_ROOT}" "/src" -- \
    gitleaks detect --source /src --no-git --report-format sarif --report-path /out/secrets/gitleaks.sarif || true
  append_sarif "$out"
}

run_trufflehog() {
  should_run "trufflehog" || { log "SKIP trufflehog"; return 0; }
  log "Secrets: trufflehog"
  local out="${OUT_DIR}/secrets/trufflehog.json"
  run_tool "trufflehog" "${REPO_ROOT}" "/src" -- \
    trufflehog filesystem --json /src > /out/secrets/trufflehog.json || true
  # Конвертация в SARIF (упрощённая)
  if have_cmd jq; then
    local sarif="${OUT_DIR}/secrets/trufflehog.sarif"
    jq -s '{
      "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
      "version":"2.1.0",
      "runs":[{"tool":{"driver":{"name":"trufflehog"}},"results": (.[]
        | {ruleId:(.DetectorName//"secret"), level:"error", message:{text:(.Raw//"secret")}, locations:[{physicalLocation:{artifactLocation:{uri:(.SourceMetadata.Data//"filesystem")}, region:{startLine:0}}}]} )}]
    }' "$out" > "$sarif" 2>/dev/null || true
    append_sarif "$sarif"
  fi
}

run_semgrep() {
  should_run "semgrep" || { log "SKIP semgrep"; return 0; }
  log "SAST: semgrep"
  local sarif="${OUT_DIR}/sast/semgrep.sarif"
  run_tool "semgrep" "${REPO_ROOT}" "/src" -- \
    semgrep --config auto --sarif --error --max-target-bytes 200000000 --timeout 120 --no-git -o /out/sast/semgrep.sarif /src || true
  append_sarif "$sarif"
}

run_bandit() {
  should_run "bandit" || { log "SKIP bandit"; return 0; }
  # Запускаем только если есть Python-код
  if ! find "${REPO_ROOT}" -type f -name "*.py" -print -quit | grep -q .; then
    log "Bandit: Python-файлов не найдено — пропуск"
    return 0
  fi
  log "SAST: bandit"
  local json="${OUT_DIR}/sast/bandit.json"
  run_tool "bandit" "${REPO_ROOT}" "/src" -- \
    bandit -r /src -f json -o /out/sast/bandit.json || true
  # Простейшая конвертация в SARIF
  if have_cmd jq; then
    local sarif="${OUT_DIR}/sast/bandit.sarif"
    jq '{
      "$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
      "runs":[{"tool":{"driver":{"name":"bandit"}},"results":(
        .results[]? | {
          ruleId:(.test_id//"BANDIT"), level:(if .issue_severity=="HIGH" then "error" elif .issue_severity=="MEDIUM" then "warning" else "note" end),
          message:{text:(.issue_text//"bandit finding")},
          locations:[{physicalLocation:{artifactLocation:{uri:(.filename)}, region:{startLine:(.line_number//0)}}}]
        }
      )}]}' "$json" > "$sarif" 2>/dev/null || true
    append_sarif "$sarif"
  fi
}

run_pip_audit() {
  should_run "pip-audit" || { log "SKIP pip-audit"; return 0; }
  # ищем зависимости python
  if ! (compgen -G "${REPO_ROOT}/requirements*.txt" >/dev/null || [[ -f "${REPO_ROOT}/pyproject.toml" ]]); then
    log "pip-audit: не найден requirements*.txt или pyproject.toml — пропуск"
    return 0
  end
  log "SCA: pip-audit"
  local json="${OUT_DIR}/sca/pip-audit.json"
  if [[ -f "${REPO_ROOT}/pyproject.toml" ]]; then
    # Попытка аудита через pyproject/poetry.lock, если доступно
    run_tool "pip-audit" "${REPO_ROOT}" "/src" -- \
      sh -lc 'pip-audit -f json --scan-type=installed || pip-audit -f json -r requirements.txt' > "$json" 2>&1 || true
  else
    # requirements.txt*
    local req
    req="$(ls -1 "${REPO_ROOT}"/requirements*.txt 2>/dev/null | head -n1)"
    run_tool "pip-audit" "${REPO_ROOT}" "/src" -- \
      pip-audit -f json -r "/src/$(basename "$req")" > "$json" 2>/dev/null || true
  fi
  # Конвертация в SARIF (упрощённо)
  if have_cmd jq; then
    local sarif="${OUT_DIR}/sca/pip-audit.sarif"
    jq '{
      "$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
      "runs":[{"tool":{"driver":{"name":"pip-audit"}},"results":(
        .[]? as $r |
        ($r.vulns[]? | {
          ruleId:($r.name + "@" + ($r.version//"") + ":" + (.id//"CVE?")),
          level:(if (.severity//"HIGH")|ascii_upcase=="HIGH" then "error" elif (.severity//"MEDIUM")|ascii_upcase=="MEDIUM" then "warning" else "note" end),
          message:{text:(.fix_version as $fv | "Vuln " + (.id//"?") + " in " + $r.name + "@" + ($r.version//"") + (if $fv then " (fix "+$fv+")" else "" end))},
          locations:[{physicalLocation:{artifactLocation:{uri:"requirements.lock"}}}]
        })
      )}]}' "$json" > "$sarif" 2>/dev/null || true
    append_sarif "$sarif"
  fi
}

run_safety() {
  should_run "safety" || { log "SKIP safety"; return 0; }
  if ! (compgen -G "${REPO_ROOT}/requirements*.txt" >/dev/null); then
    log "safety: не найден requirements*.txt — пропуск"
    return 0
  fi
  log "SCA: safety"
  local json="${OUT_DIR}/sca/safety.json"
  local req
  req="$(ls -1 "${REPO_ROOT}"/requirements*.txt 2>/dev/null | head -n1)"
  run_tool "safety" "${REPO_ROOT}" "/src" -- \
    sh -lc 'safety check --full-report --json -r "/src/'"$(basename "$req")"'"' > "$json" 2>/dev/null || true
  # Простейшая SARIF-обёртка
  if have_cmd jq; then
    local sarif="${OUT_DIR}/sca/safety.sarif"
    jq '{
      "$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
      "runs":[{"tool":{"driver":{"name":"safety"}},"results":(
        .issues[]? | {
          ruleId:(.vulnerability_id//"SAFETY"),
          level:(if (.severity|ascii_downcase)=="high" then "error" elif (.severity|ascii_downcase)=="medium" then "warning" else "note" end),
          message:{text:(.message//"safety finding")},
          locations:[{physicalLocation:{artifactLocation:{uri:"requirements.txt"}}}]
        }
      )}]}' "$json" > "$sarif" 2>/dev/null || true
    append_sarif "$sarif"
  fi
}

run_checkov() {
  should_run "checkov" || { log "SKIP checkov"; return 0; }
  log "IaC: checkov"
  local sarif="${OUT_DIR}/iac/checkov.sarif"
  run_tool "checkov" "${REPO_ROOT}" "/src" -- \
    checkov -d /src -o sarif --output-file-path /out/iac/checkov.sarif || true
  append_sarif "$sarif"
}

run_tfsec() {
  should_run "tfsec" || { log "SKIP tfsec"; return 0; }
  # Запуск только если есть Terraform
  if ! find "${REPO_ROOT}" -type f -name "*.tf" -print -quit | grep -q .; then
    log "tfsec: Terraform-файлы не найдены — пропуск"
    return 0
  fi
  log "IaC: tfsec"
  local sarif="${OUT_DIR}/iac/tfsec.sarif"
  run_tool "tfsec" "${REPO_ROOT}" "/src" -- \
    tfsec /src --format sarif --out /out/iac/tfsec.sarif || true
  append_sarif "$sarif"
}

run_trivy_fs() {
  should_run "trivy" || { log "SKIP trivy"; return 0; }
  log "Container/FS: trivy fs"
  local sarif="${OUT_DIR}/container/trivy-fs.sarif"
  run_tool "trivy" "${REPO_ROOT}" "/src" -- \
    trivy fs --security-checks vuln,config,secret --scanners vuln,secret,misconfig \
    --timeout 5m --format sarif --output /out/container/trivy-fs.sarif /src || true
  append_sarif "$sarif"
}

run_grype_fs() {
  should_run "grype" || { log "SKIP grype"; return 0; }
  log "Container/FS: grype dir"
  local sarif="${OUT_DIR}/container/grype-dir.sarif"
  run_tool "grype" "${REPO_ROOT}" "/src" -- \
    grype dir:/src --fail-on medium --output sarif > "$sarif" 2>/dev/null || true
  append_sarif "$sarif"
}

run_syft_sbom() {
  should_run "syft" || { log "SKIP syft"; return 0; }
  log "SBOM: syft"
  local spdx="${OUT_DIR}/sbom/sbom.spdx.json"
  run_tool "syft" "${REPO_ROOT}" "/src" -- \
    syft dir:/src -o spdx-json > "$spdx" 2>/dev/null || true
  # Конвертация в SARIF (только как носитель сведений)
  if have_cmd jq; then
    local sarif="${OUT_DIR}/sbom/sbom.sarif"
    jq -n --arg f "$(basename "$spdx")" '{
      "$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
      "runs":[{"tool":{"driver":{"name":"syft"}},"results":[{"ruleId":"SBOM","level":"note","message":{"text":"SBOM generated (SPDX)"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":$f}}}]}]}]
    }' > "$sarif"
    append_sarif "$sarif"
  fi
}

run_zap_baseline() {
  should_run "dast" || { log "SKIP dast (filter)"; return 0; }
  if [[ -z "$APP_URL" ]]; then
    log "DAST: APP_URL не задан — пропуск"
    return 0
  fi
  should_run "zap-baseline" || { log "SKIP zap-baseline"; return 0; }
  log "DAST: OWASP ZAP baseline → ${APP_URL}"
  local json="${OUT_DIR}/dast/zap-baseline.json"
  local html="${OUT_DIR}/dast/zap-baseline.html"
  run_tool "zap-baseline" "${REPO_ROOT}" "/zap/wrk" -v "${OUT_DIR}:/zap/wrk:rw" -- \
    zap-baseline.py -t "${APP_URL}" -J "/zap/wrk/$(basename "$json")" -r "/zap/wrk/$(basename "$html")" -m 5 || true
  # SARIF-обёртка (упрощённая)
  if have_cmd jq; then
    local sarif="${OUT_DIR}/dast/zap-baseline.sarif"
    jq -n --arg url "$APP_URL" --arg f "$(basename "$json")" '{
      "$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
      "runs":[{"tool":{"driver":{"name":"OWASP ZAP Baseline"}},"results":[{"ruleId":"ZAP-BASELINE","level":"warning","message":{"text":"Baseline scan executed"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":$f}}}],"properties":{"target":$url}}]}]
    }' > "$sarif"
    append_sarif "$sarif"
  fi
}

#####################################
# Параллельный запуск по категориям #
#####################################

# Списки задач по категориям зависят от режима
declare -a TASKS=()

enqueue() { TASKS+=("$1"); }

# Secrets
if [[ "$MODE" == "full" || "$MODE" == "quick" ]]; then
  enqueue run_gitleaks
  [[ "$MODE" == "full" ]] && enqueue run_trufflehog
fi

# SAST
enqueue run_semgrep
[[ "$MODE" == "full" ]] && enqueue run_bandit

# SCA (deps)
enqueue run_pip_audit
[[ "$MODE" == "full" ]] && enqueue run_safety

# IaC
enqueue run_checkov
[[ "$MODE" == "full" ]] && enqueue run_tfsec

# Container/FS
enqueue run_trivy_fs
[[ "$MODE" == "full" ]] && enqueue run_grype_fs

# SBOM
enqueue run_syft_sbom

# DAST (только при наличии URL)
if [[ -n "$APP_URL" ]]; then
  enqueue run_zap_baseline
fi

# Применяем фильтры ONLY/СКИП на уровне задач
filtered_tasks=()
for t in "${TASKS[@]}"; do
  # соответствие категории по имени функции
  case "$t" in
    run_gitleaks|run_trufflehog) catg="secrets" ;;
    run_semgrep|run_bandit)      catg="sast" ;;
    run_pip_audit|run_safety)    catg="sca" ;;
    run_checkov|run_tfsec)       catg="iac" ;;
    run_trivy_fs|run_grype_fs)   catg="container" ;;
    run_syft_sbom)               catg="sbom" ;;
    run_zap_baseline)            catg="dast" ;;
    *)                           catg="misc" ;;
  esac
  # фильтр ONLY
  if [[ -n "$ONLY_FILTER" && "$ONLY_FILTER" != "$catg" && "$ONLY_FILTER" != "${t#run_}" ]]; then
    continue
  fi
  # фильтр SKIP по инструменту
  tool_name="${t#run_}"
  if [[ -n "$SKIP_LIST" && ",${SKIP_LIST}," == *",${tool_name},"* ]]; then
    continue
  fi
  filtered_tasks+=("$t")
done
TASKS=("${filtered_tasks[@]}")

log "Всего задач к запуску: ${#TASKS[@]}"

# Параллельный пул
pids=()
running=0
fail_any=0

run_in_background() {
  local func="$1"
  {
    set +e
    "$func"
    local rc=$?
    echo "TASK ${func} RC=${rc}" >> "${OUT_DIR}/logs/tasks.rc"
    exit $rc
  } &
  pids+=("$!")
  running=$((running+1))
}

for func in "${TASKS[@]}"; do
  while [[ "$running" -ge "$MAX_PROCS" ]]; do
    wait -n || true
    running=$((running-1))
  done
  run_in_background "$func"
done

# дождаться всех
for pid in "${pids[@]}"; do
  wait "$pid" || true
  running=$((running-1))
done

#########################
# Итоговая оценка       #
#########################

log "Объединение SARIF и оценка порога..."
if ! evaluate_findings; then
  fail_any=1
fi

log "Сводка:"
if [[ -s "$SUMMARY_JSON" ]]; then
  cat "$SUMMARY_JSON"
else
  echo '{"status":"unknown"}'
fi

if [[ "$fail_any" -ne 0 ]]; then
  err "Обнаружены находки на уровне '${SEVERITY_THRESHOLD}' или выше. См. ${COMBINED_SARIF} и каталог ${OUT_DIR}"
  exit 1
fi

log "Сканирование завершено: находок выше порога нет. Отчёты: ${OUT_DIR}"
exit 0
