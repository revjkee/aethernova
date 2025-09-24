#!/usr/bin/env bash
# Aethernova Engine | Codegen v1
# CI Check: линт .proto + генерация + валидация + проверка git diff
# Платформы: Linux/macOS. Требуется bash, python3.
# Опционально: buf (lint), protoc.

set -Eeuo pipefail

PRODUCT="Aethernova Engine CI Check"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

COLOR="${COLOR:-auto}"
if [[ -t 1 && "${COLOR}" != "never" ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; BLU=$'\e[34m'; DIM=$'\e[2m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YLW=""; BLU=""; DIM=""; RST=""
fi

log()  { echo -e "${DIM}[$(date -u +%H:%M:%S)]${RST} $*"; }
info() { echo -e "${GRN}INFO${RST}  $*"; }
warn() { echo -e "${YLW}WARN${RST}  $*"; }
err()  { echo -e "${RED}ERROR${RST} $*" 1>&2; }
die()  { err "$*"; exit 1; }

# ---------- Параметры ----------
PROFILE="ci"
PARALLELISM="${PARALLELISM:-4}"
PYTHON="${PYTHON:-python3}"
USE_VENV="${USE_VENV:-0}"              # 1 — создать/использовать .venv
VENV_DIR="${VENV_DIR:-${REPO_ROOT}/.venv-codegen}"
SCHEMAS_ROOT="${SCHEMAS_ROOT:-${REPO_ROOT}/engine-core/schemas/proto}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/engine-core/codegen/python/v1/generated}"
AUTOGEN_DIR="${AUTOGEN_DIR:-_autogen}"
OUT_AUTOGEN="${OUT_ROOT}/${AUTOGEN_DIR}"

# Воспроизводимость
export LC_ALL=C
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1715107200}" # 2024-05-07T00:00:00Z

# ---------- Проверки окружения ----------
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Требуется команда: $1"; }
require_cmd "$PYTHON"
command -v git >/dev/null 2>&1 || warn "git недоступен — проверки diff будут ограничены"

# ---------- Виртуальное окружение (опционально) ----------
if [[ "$USE_VENV" == "1" ]]; then
  log "Используется виртуальное окружение: ${VENV_DIR}"
  if [[ ! -d "$VENV_DIR" ]]; then
    "$PYTHON" -m venv "$VENV_DIR"
  fi
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
  PYTHON="python"
fi

# ---------- Python зависимости ----------
py_deps_ok() {
  "$PYTHON" - <<'PY' || exit 1
missing=[]
try:
  import google.protobuf  # noqa
except Exception:
  missing.append("protobuf")
try:
  import grpc_tools.protoc  # noqa
except Exception:
  missing.append("grpcio-tools")
if missing:
  import sys
  sys.stderr.write("Отсутствуют Python-пакеты: %s\n" % ", ".join(missing))
  sys.exit(2)
PY
}
if ! py_deps_ok; then
  info "Установка зависимостей protobuf/grpcio-tools"
  "$PYTHON" -m pip install --upgrade pip >/dev/null
  "$PYTHON" -m pip install --upgrade protobuf grpcio grpcio-tools >/dev/null
fi

# ---------- Пути к инструментам репозитория ----------
GEN_SH="${REPO_ROOT}/engine-core/codegen/python/v1/scripts/generate_all.sh"
LINT_PY="${REPO_ROOT}/engine-core/codegen/python/v1/scripts/proto_lint.py"
VALIDATE_PY="${REPO_ROOT}/engine-core/codegen/python/v1/scripts/validate_generated.py"

[[ -x "$GEN_SH" ]] || die "Не найден генератор: $GEN_SH"
[[ -f "$LINT_PY" ]] || die "Не найден линтер: $LINT_PY"
[[ -f "$VALIDATE_PY" ]] || die "Не найден валидатор: $VALIDATE_PY"
[[ -d "$SCHEMAS_ROOT" ]] || die "Не найден каталог схем: $SCHEMAS_ROOT"

# ---------- Шаг 1: Линт .proto ----------
info "Линт .proto (proto_lint.py, профиль ${PROFILE})"
set +e
"$PYTHON" "$LINT_PY" --profile "$PROFILE"
LINT_RC=$?
set -e
if [[ $LINT_RC -ne 0 ]]; then
  die "Линт завершился с ошибками (rc=$LINT_RC)"
fi

# ---------- Шаг 2: Генерация артефактов ----------
info "Генерация артефактов (generate_all.sh, профиль ${PROFILE}, parallel=${PARALLELISM})"
bash "$GEN_SH" --profile "$PROFILE" --parallel "$PARALLELISM" --verbose
GEN_RC=$?
if [[ $GEN_RC -ne 0 ]]; then
  die "Генерация завершилась с ошибкой (rc=$GEN_RC)"
fi

# ---------- Шаг 3: Валидация артефактов ----------
info "Валидация артефактов (validate_generated.py)"
set +e
"$PYTHON" "$VALIDATE_PY" --profile "$PROFILE"
VAL_RC=$?
set -e
if [[ $VAL_RC -ne 0 ]]; then
  die "Валидация выявила проблемы (rc=$VAL_RC)"
fi

# ---------- Шаг 4: Проверка чистоты git diff ----------
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  info "Проверка отсутствия незакоммиченных изменений в ${OUT_AUTOGEN}"
  rel_path="$(realpath --relative-to="$REPO_ROOT" "$OUT_AUTOGEN" 2>/dev/null || true)"
  rel_path="${rel_path:-engine-core/codegen/python/v1/generated/_autogen}"
  set +e
  git -C "$REPO_ROOT" status --porcelain -- "$rel_path"
  DIFF_RC=$?
  CHANGED="$(git -C "$REPO_ROOT" status --porcelain -- "$rel_path" | wc -l | tr -d ' ')"
  set -e
  if [[ "$CHANGED" != "0" ]]; then
    git -C "$REPO_ROOT" --no-pager diff -- "$rel_path" | sed 's/^/+ /' || true
    die "Обнаружены несохраненные изменения в сгенерированных файлах: ${CHANGED}"
  fi
else
  warn "git репозиторий не обнаружен, пропускаю проверку diff"
fi

# ---------- Итог ----------
info "CI проверка завершена успешно"
echo "RESULT: OK"
exit 0
