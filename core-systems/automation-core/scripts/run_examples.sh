#!/usr/bin/env bash
# run_examples.sh — промышленный раннер примеров/демо с параллельным выполнением, таймаутами,
# логированием, JUnit-отчётом и безопасным Bash-режимом.
#
# Размещение: automation-core/scripts/run_examples.sh
#
# Требования: bash 4+, coreutils, timeout (GNU coreutils), find, xargs.
# Необязательные интерпретаторы: python3, node, bash (для .sh), pwsh, go, ruby, php.
#
# Примеры:
#   ./run_examples.sh --dir ../examples --pattern "*.sh" --max-parallel 4 --timeout 120 \
#       --report "../artifacts/junit/examples.xml" --log "../artifacts/logs/run_$(date +%F).log"
#
#   ./run_examples.sh --list                              # только вывести список найденных примеров
#   ./run_examples.sh --dry-run --pattern "*.py"          # показать, что было бы запущено
#   ./run_examples.sh --env ../.env --fail-fast           # загрузить переменные, падать при первой ошибке
#
# Код возврата:
#   0 — все примеры прошли;
#   1 — найдены/запущены, но есть падения;
#   2 — неправильное использование/внутренняя ошибка.

set -Eeuo pipefail
IFS=$'\n\t'

# ------------------------------ Цвета/формат ------------------------------
: "${NO_COLOR:=}"
if [[ -t 1 && -z "${NO_COLOR}" ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'; RESET=$'\033[0m'
else
  BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; RESET=''
fi

# ------------------------------ Глобальные дефолты ------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)" # automation-core/
DEFAULT_SEARCH_DIRS=(
  "${REPO_ROOT}/examples"
  "${REPO_ROOT}/demos"
  "${REPO_ROOT}/samples"
)
SEARCH_DIRS=()                      # --dir
INCLUDE_PATTERN="*"                 # --pattern
EXCLUDE_PATTERN=""                  # --exclude
MAX_PARALLEL="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"  # --max-parallel
TIMEOUT_SEC=300                     # --timeout
DRY_RUN=false                       # --dry-run
LIST_ONLY=false                     # --list
FAIL_FAST=false                     # --fail-fast
REPORT_PATH=""                      # --report (JUnit)
LOG_PATH=""                         # --log
ENV_FILE=""                         # --env
SHELL_OVERRIDE=""                   # --shell (принудительный интерпретатор для .sh)
VERBOSE=false                       # --verbose
ALLOW_EXTENSIONS="sh,py,js,ts,pwsh,ps1,go,rb,php" # --allow-extensions

# ------------------------------ Утилиты логирования ------------------------------
log_ts() { date +"%Y-%m-%dT%H:%M:%S%z"; }
log()     { echo -e "[$(log_ts)] $*"; }
info()    { log "${BLUE}INFO${RESET}  $*"; }
warn()    { log "${YELLOW}WARN${RESET}  $*"; }
error()   { log "${RED}ERROR${RESET} $*"; }
ok()      { log "${GREEN}OK${RESET}    $*"; }
dbg()     { $VERBOSE && log "${DIM}DEBUG${RESET} $*"; return 0; }

tee_log() {
  # Пишем в STDOUT и в лог, если задан
  if [[ -n "$LOG_PATH" ]]; then
    mkdir -p -- "$(dirname -- "$LOG_PATH")"
    sed -u 's/.*/[LOG] &/' | tee -a "$LOG_PATH"
  else
    cat -u
  fi
}

# ------------------------------ Trap/cleanup ------------------------------
_tmpdir=""
cleanup() {
  local ec=$?
  [[ -n "$_tmpdir" && -d "$_tmpdir" ]] && rm -rf -- "$_tmpdir" || true
  if (( ec == 0 )); then
    ok "Завершено успешно."
  else
    error "Завершение с кодом $ec."
  fi
}
trap cleanup EXIT
trap 'error "Прервано (INT)"; exit 130' INT
trap 'error "Остановлено (TERM)"; exit 143' TERM

# ------------------------------ Справка ------------------------------
usage() {
  cat <<'USAGE'
run_examples.sh — промышленный раннер примеров/демо.

Флаги:
  --dir DIR                Добавить директорию поиска (можно несколько). По умолчанию: ./examples, ./demos, ./samples
  --pattern GLOB           Какой шаблон включать (по умолчанию "*")
  --exclude GLOB           Какой шаблон исключать (опционально)
  --allow-extensions LIST  Список разрешённых расширений через запятую (по умолчанию: sh,py,js,ts,pwsh,ps1,go,rb,php)
  --max-parallel N         Параллелизм (по умолчанию: кол-во ядер, минимум 2)
  --timeout SEC            Таймаут одного примера в секундах (по умолчанию 300)
  --shell PATH             Принудительный шелл для .sh (например, /usr/bin/bash)
  --env FILE               Загрузить переменные из .env (экспортируются)
  --report PATH            Сохранить JUnit XML отчёт по выполнению
  --log PATH               Сохранять подробный лог выполнения
  --list                   Только вывести список найденных примеров и выйти
  --dry-run                Ничего не запускать, только показать план
  --fail-fast              Остановить все при первой ошибке
  --verbose                Подробный вывод отладки
  -h | --help              Показать эту справку

Коды возврата:
  0 — все примеры прошли; 1 — были падения; 2 — неправильное использование или внутренняя ошибка.

USAGE
}

# ------------------------------ Парсинг аргументов ------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir)             [[ $# -lt 2 ]] && { error "Требуется аргумент для --dir"; exit 2; } ; SEARCH_DIRS+=("$(cd -- "$2" && pwd)"); shift 2 ;;
      --pattern)         [[ $# -lt 2 ]] && { error "Требуется аргумент для --pattern"; exit 2; } ; INCLUDE_PATTERN="$2"; shift 2 ;;
      --exclude)         [[ $# -lt 2 ]] && { error "Требуется аргумент для --exclude"; exit 2; } ; EXCLUDE_PATTERN="$2"; shift 2 ;;
      --allow-extensions) [[ $# -lt 2 ]] && { error "Требуется аргумент для --allow-extensions"; exit 2; } ; ALLOW_EXTENSIONS="$2"; shift 2 ;;
      --max-parallel)    [[ $# -lt 2 ]] && { error "Требуется аргумент для --max-parallel"; exit 2; } ; MAX_PARALLEL="$2"; shift 2 ;;
      --timeout)         [[ $# -lt 2 ]] && { error "Требуется аргумент для --timeout"; exit 2; } ; TIMEOUT_SEC="$2"; shift 2 ;;
      --shell)           [[ $# -lt 2 ]] && { error "Требуется аргумент для --shell"; exit 2; } ; SHELL_OVERRIDE="$2"; shift 2 ;;
      --env)             [[ $# -lt 2 ]] && { error "Требуется аргумент для --env"; exit 2; } ; ENV_FILE="$2"; shift 2 ;;
      --report)          [[ $# -lt 2 ]] && { error "Требуется аргумент для --report"; exit 2; } ; REPORT_PATH="$2"; shift 2 ;;
      --log)             [[ $# -lt 2 ]] && { error "Требуется аргумент для --log"; exit 2; } ; LOG_PATH="$2"; shift 2 ;;
      --list)            LIST_ONLY=true; shift ;;
      --dry-run)         DRY_RUN=true; shift ;;
      --fail-fast)       FAIL_FAST=true; shift ;;
      --verbose)         VERBOSE=true; shift ;;
      -h|--help)         usage; exit 0 ;;
      *)                 error "Неизвестный аргумент: $1"; usage; exit 2 ;;
    esac
  done
}

# ------------------------------ Загрузка .env ------------------------------
load_env() {
  if [[ -n "$ENV_FILE" ]]; then
    if [[ -f "$ENV_FILE" ]]; then
      info "Загрузка переменных из $ENV_FILE"
      # shellcheck disable=SC1090
      set -a; source "$ENV_FILE"; set +a
    else
      warn "Файл .env не найден: $ENV_FILE"
    fi
  fi
}

# ------------------------------ Проверки зависимостей ------------------------------
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { error "Требуется утилита: $1"; exit 2; }
}
check_deps() {
  need_cmd find
  need_cmd xargs
  need_cmd timeout
  : # Дополнительно проверим наличие интерпретаторов по необходимости при диспетчеризации
}

# ------------------------------ Поиск примеров ------------------------------
split_csv() { tr ',' '\n' <<<"$1" | sed 's/^\s*//;s/\s*$//' | sed '/^$/d'; }

should_allow_ext() {
  local ext="$1"
  local allowed
  while read -r allowed; do
    [[ "$ext" == "$allowed" ]] && return 0
  done < <(split_csv "$ALLOW_EXTENSIONS")
  return 1
}

find_examples() {
  local paths=()
  if ((${#SEARCH_DIRS[@]} == 0)); then
    for d in "${DEFAULT_SEARCH_DIRS[@]}"; do
      [[ -d "$d" ]] && paths+=("$d")
    done
  else
    for d in "${SEARCH_DIRS[@]}"; do
      [[ -d "$d" ]] && paths+=("$d") || warn "Директория не найдена и будет пропущена: $d"
    done
  fi

  if ((${#paths[@]} == 0)); then
    warn "Директории поиска отсутствуют. Нечего запускать."
    return 0
  fi

  local find_cmd=(find "${paths[@]}" -type f -name "$INCLUDE_PATTERN")
  if [[ -n "$EXCLUDE_PATTERN" ]]; then
    find_cmd+=( -not -name "$EXCLUDE_PATTERN" )
  fi

  dbg "Команда поиска: ${find_cmd[*]}"
  mapfile -t all_files < <("${find_cmd[@]}" | sort)

  EXAMPLES=()
  for f in "${all_files[@]}"; do
    # Определим расширение без точки (в нижнем регистре)
    local base ext
    base="$(basename -- "$f")"
    ext="${base##*.}"
    ext="${ext,,}"
    if [[ "$base" == "$ext" ]]; then
      # нет расширения — пропускаем
      continue
    fi
    if should_allow_ext "$ext"; then
      EXAMPLES+=("$f")
    fi
  done
}

# ------------------------------ Диспетчер интерпретаторов ------------------------------
interpreter_for() {
  local file="$1"
  local base ext
  base="$(basename -- "$file")"
  ext="${base##*.}"
  ext="${ext,,}"

  case "$ext" in
    sh)
      if [[ -n "$SHELL_OVERRIDE" ]]; then
        printf '%s\0' "$SHELL_OVERRIDE"
      else
        command -v bash >/dev/null 2>&1 && printf '%s\0' "bash" || printf '%s\0' "/bin/sh"
      fi
      ;;
    py)   command -v python3 >/dev/null 2>&1 && printf 'python3\0' || printf '\0' ;;
    js)   command -v node    >/dev/null 2>&1 && printf 'node\0'    || printf '\0' ;;
    ts)   command -v ts-node >/dev/null 2>&1 && printf 'ts-node\0' || printf '\0' ;;
    ps1|pwsh)
           command -v pwsh   >/dev/null 2>&1 && printf 'pwsh\0'    || printf '\0' ;;
    go)   command -v go      >/dev/null 2>&1 && printf 'go\0'      || printf '\0' ;;
    rb)   command -v ruby    >/dev/null 2>&1 && printf 'ruby\0'    || printf '\0' ;;
    php)  command -v php     >/dev/null 2>&1 && printf 'php\0'     || printf '\0' ;;
    *)    printf '\0' ;;
  esac
}

build_cmdline() {
  local file="$1"
  local interp
  interp="$(interpreter_for "$file" | tr -d '\0')"

  if [[ -z "$interp" ]]; then
    echo "" # означает: нет подходящего интерпретатора
    return 0
  fi

  case "$interp" in
    go)   echo "$interp run \"$file\"" ;;
    pwsh) echo "$interp -NoLogo -NoProfile -File \"$file\"" ;;
    *)    echo "$interp \"$file\"" ;;
  esac
}

# ------------------------------ Запуск одного примера ------------------------------
run_one() {
  # Аргументы: <id> <file>
  local id="$1"; shift
  local file="$1"; shift

  local start_ts end_ts status ec=0 cmd
  cmd="$(build_cmdline "$file")"

  if [[ -z "$cmd" ]]; then
    warn "[$id] Пропуск: нет интерпретатора для $(basename -- "$file")"
    echo -e "$id\t$file\tSKIPPED\t0" >> "$_tmpdir/results.tsv"
    return 0
  fi

  info "[$id] Запуск: $cmd"
  start_ts="$(date +%s)"

  if $DRY_RUN; then
    echo -e "$id\t$file\tDRY-RUN\t0" >> "$_tmpdir/results.tsv"
    return 0
  fi

  # Вывод каждого примера пишем в отдельный лог
  local out_dir="$_tmpdir/out"
  mkdir -p -- "$out_dir"
  local outfile="$out_dir/$(printf '%04d' "$id")_$(basename -- "$file").log"

  # Таймаут и выполнение
  set +e
  timeout --preserve-status "${TIMEOUT_SEC}s" bash -c "$cmd" >"$outfile" 2>&1
  ec=$?
  set -e

  end_ts="$(date +%s)"
  local elapsed=$(( end_ts - start_ts ))

  case "$ec" in
    0)       status="PASSED" ;;
    124|137) status="TIMEOUT" ;;  # 124 — timeout; 137 — SIGKILL
    *)       status="FAILED" ;;
  esac

  if [[ "$status" == "PASSED" ]]; then
    ok "[$id] Успех (${elapsed}s): $(basename -- "$file")"
  elif [[ "$status" == "TIMEOUT" ]]; then
    error "[$id] Таймаут (${elapsed}s): $(basename -- "$file")"
  else
    error "[$id] Падение (ec=$ec, ${elapsed}s): $(basename -- "$file")"
  fi

  # Сохраним сводку
  echo -e "$id\t$file\t$status\t$elapsed\t$ec\t$outfile" >> "$_tmpdir/results.tsv"

  # При fail-fast — сигнализируем
  if $FAIL_FAST && [[ "$status" != "PASSED" ]]; then
    echo "FAIL-FAST" > "$_tmpdir/fail_fast.trigger"
  fi

  return 0
}

# ------------------------------ Параллельное выполнение ------------------------------
run_all() {
  local -a list=("${EXAMPLES[@]}")
  local n="${#list[@]}"
  if (( n == 0 )); then
    warn "Примеры не найдены."
    return 0
  fi

  info "Найдено примеров: $n"
  $DRY_RUN && info "Режим DRY-RUN: выполнение имитируется."

  # Подготовка результатов
  : > "$_tmpdir/results.tsv"

  # Подготовим файл со списком для xargs
  local idx=0
  : > "$_tmpdir/todo.tsv"
  for f in "${list[@]}"; do
    ((idx++))
    printf "%d\t%s\n" "$idx" "$f" >> "$_tmpdir/todo.tsv"
  done

  # xargs параллельно вызывает run_one
  # shellcheck disable=SC2016
  if $DRY_RUN || $LIST_ONLY; then
    cat "$_tmpdir/todo.tsv" | tee_log
    return 0
  fi

  export -f run_one build_cmdline interpreter_for ok info warn error dbg
  export TIMEOUT_SEC DRY_RUN FAIL_FAST _tmpdir VERBOSE YELLOW RED GREEN BLUE RESET DIM

  # Параллельный запуск
  xargs -0 >/dev/null 2>&1 || true # прогрев для корректного поведения на некоторых системах
  <"$_tmpdir/todo.tsv" awk -F'\t' '{print $1"\t"$2}' | \
  while IFS=$'\t' read -r id f; do
    printf '%s\0' "$id" "$f"
  done | xargs -0 -n2 -P "$MAX_PARALLEL" bash -c 'run_one "$@"' _

  # При fail-fast — если был триггер, завершим с ошибкой
  if [[ -f "$_tmpdir/fail_fast.trigger" ]]; then
    warn "FAIL-FAST: остановка после первой ошибки."
  fi
}

# ------------------------------ Отчёт JUnit ------------------------------
write_junit() {
  local results="$1"
  local outfile="$2"

  mkdir -p -- "$(dirname -- "$outfile")"

  local total passed failed skipped time_sum
  total=0; passed=0; failed=0; skipped=0; time_sum=0

  # Подсчёты
  while IFS=$'\t' read -r id file status elapsed ec outlog; do
    ((total++))
    (( time_sum += elapsed ))
    case "$status" in
      PASSED) ((passed++)) ;;
      FAILED|TIMEOUT) ((failed++)) ;;
      DRY-RUN|SKIPPED) ((skipped++)) ;;
    esac
  done < <(cat "$results")

  # Генерация XML
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    printf '<testsuite name="run_examples" tests="%d" failures="%d" skipped="%d" time="%d">\n' \
      "$total" "$failed" "$skipped" "$time_sum"

    while IFS=$'\t' read -r id file status elapsed ec outlog; do
      local case_name
      case_name="$(basename -- "$file")"
      printf '  <testcase classname="examples" name="%s" time="%s">\n' "$case_name" "$elapsed"
      case "$status" in
        FAILED)
          echo '    <failure message="failed" type="Error"></failure>'
          ;;
        TIMEOUT)
          echo '    <failure message="timeout" type="Timeout"></failure>'
          ;;
        DRY-RUN|SKIPPED)
          echo '    <skipped/>'
          ;;
      esac
      # Прикрепим системный вывод как system-out (обрезать большой лог по желанию)
      if [[ -n "$outlog" && -f "$outlog" ]]; then
        echo '    <system-out><![CDATA['
        sed -e 's/]]>/]]]]><![CDATA[>/' "$outlog"
        echo '    ]]></system-out>'
      fi
      echo '  </testcase>'
    done < <(cat "$results")

    echo '</testsuite>'
  } > "$outfile"

  info "JUnit отчёт записан: $outfile"
}

# ------------------------------ Итоговая сводка ------------------------------
print_summary() {
  local results="$1"
  local total passed failed skipped timeout time_sum
  total=0; passed=0; failed=0; skipped=0; timeout=0; time_sum=0

  while IFS=$'\t' read -r _id _file status elapsed _ec _outlog; do
    (( time_sum += elapsed ))
    case "$status" in
      PASSED) ((passed++)) ;;
      FAILED) ((failed++)) ;;
      TIMEOUT) ((timeout++)); ((failed++)) ;;
      DRY-RUN|SKIPPED) ((skipped++)) ;;
    esac
    (( total++ ))
  done < <(cat "$results")

  echo
  echo "-------------------- СВОДКА --------------------"
  echo "Всего:     $total"
  echo "Успехов:   $passed"
  echo "Падений:   $failed (включая таймаутов: $timeout)"
  echo "Пропусков: $skipped"
  echo "Время сумм: ${time_sum}s"
  echo "------------------------------------------------"

  # В лог дублируем
  {
    echo "SUMMARY total=$total passed=$passed failed=$failed skipped=$skipped time_sum=${time_sum}s"
  } | tee_log >/dev/null 2>&1 || true

  # Код возврата
  if (( failed > 0 )); then
    return 1
  fi
  return 0
}

# ------------------------------ Основной поток ------------------------------
main() {
  parse_args "$@"

  _tmpdir="$(mktemp -d -t run-examples.XXXXXXXX)"
  dbg "Временная директива: $_tmpdir"

  load_env
  check_deps

  find_examples
  local count="${#EXAMPLES[@]}"

  if $LIST_ONLY; then
    if (( count == 0 )); then
      warn "Нет примеров для вывода."
      exit 0
    fi
    printf "%s\n" "${EXAMPLES[@]}"
    exit 0
  fi

  if (( count == 0 )); then
    warn "Нечего запускать. Проверьте --dir/--pattern/--allow-extensions."
    exit 0
  fi

  # Лог-файл: по умолчанию в artifacts/logs/ если не задан
  if [[ -z "$LOG_PATH" ]]; then
    LOG_PATH="${REPO_ROOT}/artifacts/logs/run_$(date +%Y%m%d_%H%M%S).log"
  fi
  mkdir -p -- "$(dirname -- "$LOG_PATH")"
  info "Лог: $LOG_PATH" | tee -a "$LOG_PATH" >/dev/null

  # Запуск
  run_all

  # Отчёт JUnit
  if [[ -n "$REPORT_PATH" ]]; then
    write_junit "$_tmpdir/results.tsv" "$REPORT_PATH"
  fi

  # Выводим сводку и устанавливаем код возврата
  if $DRY_RUN; then
    ok "DRY-RUN завершён. Ничего не выполнялось."
    exit 0
  fi

  if print_summary "$_tmpdir/results.tsv"; then
    exit 0
  else
    exit 1
  fi
}

# ------------------------------ Точка входа ------------------------------
declare -a EXAMPLES=()
main "$@"
