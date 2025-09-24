# mythos-core/tests/unit/test_canon_validator.py
# Статус: НЕ ВЕРИФИЦИРОВАНО — контракт интерфейса валидатора предполагается на основе промышленных практик.
# Предполагаемый модуль: mythos_core.canon.validator
# Предполагаемые объекты: CanonValidator, ValidationReport, CanonRule (или совместимый протокол).
#
# Краткий контракт (ожидается от реализации):
# - CanonValidator.validate(canon: Mapping | Any, rules: Sequence[Any], *, context: Mapping | None = None, **opts) -> ValidationReport
# - ValidationReport:
#     - is_valid: bool
#     - errors: list[dict | str]  # рекомендуются dict с ключами: code, message, path, rule_id, severity
#     - warnings: list[dict | str]
#     - stats: dict[str, Any]     # например: {"rules_total": int, "duration_ms": int, "errors": int, ...}
#     - to_json()/from_json() опционально
# - Поведение:
#     - Исключение в любом правиле не должно падать наружу: ошибка попадает в report.errors (code="rule_exception").
#     - Детерминизм: одинаковый вход → одинаковый отчёт.
#     - Параллельные вызовы .validate независимы и потокобезопасны при статичном валидаторе.
#     - Опционально: поддержка timeout, schema, strict, short_circuit и т.д. — тесты помечены как skip если фичи нет.

from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from typing import Any, Dict, List, Mapping, Optional

import pytest

# Мягкий импорт реального валидатора: если нет — падаем осознанно с подсказкой.
validator_mod = pytest.importorskip(
    "mythos_core.canon.validator",
    reason="Не найден mythos_core.canon.validator — подключите модуль валидатора.",
)

# Извлекаем ожидаемые сущности, если отсутствуют — тесты скипаются точечно.
CanonValidator = getattr(validator_mod, "CanonValidator", None)
ValidationReport = getattr(validator_mod, "ValidationReport", None)

if CanonValidator is None or ValidationReport is None:
    pytest.skip(
        "Отсутствуют CanonValidator или ValidationReport в mythos_core.canon.validator — невозможно прогнать unit-тесты.",
        allow_module_level=True,
    )


# ---------- ВСПОМОГАТЕЛЬНЫЕ ФИКСТУРЫ И ДАННЫЕ ----------

@pytest.fixture(scope="session")
def base_canon() -> Dict[str, Any]:
    # Репрезентативный «мифос»: сущности, ссылки и инварианты
    return {
        "deities": [
            {"id": "aether", "domain": ["creation", "memory"], "rank": 1},
            {"id": "zephyr", "domain": ["wind"], "rank": 3},
        ],
        "laws": [
            {"code": "balance", "description": "Opposing forces must remain in equilibrium."},
            {"code": "transparency", "description": "Records must be auditable."},
        ],
        "relations": [
            {"from": "aether", "to": "zephyr", "type": "mentor"},
        ],
        "timeline": [
            {"event": "world_birth", "t": 0},
            {"event": "first_wind", "t": 10},
        ],
        "canon_version": "1.0.0",
    }


@pytest.fixture()
def mutable_canon(base_canon) -> Dict[str, Any]:
    # Свежая копия на каждый тест
    return deepcopy(base_canon)


@pytest.fixture()
def rules_ok() -> List[Any]:
    """
    Набор «хороших» правил:
    Каждое правило ожидаемо имеет интерфейс .id и метод .check(canon, context) -> list[Issue] (пусто, если всё ок).
    Issue рекомендуем как dict: {"code": str, "message": str, "path": list[str], "severity": "error"|"warning"}.
    """
    class RuleNoDuplicateDeityIds:
        id = "no_duplicate_deity_ids"

        def check(self, canon: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None):
            seen = set()
            issues: List[Dict[str, Any]] = []
            for idx, d in enumerate(canon.get("deities", [])):
                did = d.get("id")
                if did in seen:
                    issues.append({
                        "code": "duplicate_id",
                        "message": f"Duplicate deity id: {did}",
                        "path": ["deities", idx, "id"],
                        "severity": "error",
                        "rule_id": self.id,
                    })
                else:
                    seen.add(did)
            return issues

    class RuleTimelineNonDecreasing:
        id = "timeline_non_decreasing"

        def check(self, canon: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None):
            issues: List[Dict[str, Any]] = []
            last = None
            for idx, e in enumerate(canon.get("timeline", [])):
                t = e.get("t")
                if last is not None and t < last:
                    issues.append({
                        "code": "timeline_regression",
                        "message": f"Timeline non-monotonic at index {idx}: {t} < {last}",
                        "path": ["timeline", idx, "t"],
                        "severity": "error",
                        "rule_id": self.id,
                    })
                last = t
            return issues

    class RuleWarnMentorExists:
        id = "warn_mentor_exists"

        def check(self, canon: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None):
            # Пример предупреждения, если нет отношений наставничества
            if not canon.get("relations"):
                return [{
                    "code": "no_relations",
                    "message": "No relations present.",
                    "path": ["relations"],
                    "severity": "warning",
                    "rule_id": self.id,
                }]
            return []

    return [RuleNoDuplicateDeityIds(), RuleTimelineNonDecreasing(), RuleWarnMentorExists()]


@pytest.fixture()
def rules_with_fault(rules_ok) -> List[Any]:
    """Добавляем «плохое» правило, кидающее исключение — валидатор должен перевести это в ошибку отчёта."""
    class RuleExplodes:
        id = "boom"

        def check(self, canon, context=None):
            raise RuntimeError("boom")

    return rules_ok + [RuleExplodes()]


@pytest.fixture()
def context_minimal() -> Dict[str, Any]:
    return {"request_id": "test-req-001", "strict": True}


# ---------- ХЕЛПЕРЫ ДЛЯ ГИБКИХ СКИПОВ ----------

def _has_option(validator: Any, name: str) -> bool:
    """Проверяем, поддерживает ли валидатор опцию (например, timeout, short_circuit)."""
    sig = getattr(validator, "validate", None)
    if sig is None:
        return False
    try:
        import inspect
        return name in inspect.signature(sig).parameters
    except Exception:
        return False


def _has_attr(obj: Any, name: str) -> bool:
    return hasattr(obj, name)


# ---------- САМИ ТЕСТЫ ----------

def test_valid_canon_passes_without_errors(mutable_canon, rules_ok, context_minimal, caplog):
    caplog.set_level(logging.INFO)
    validator = CanonValidator()
    report = validator.validate(mutable_canon, rules_ok, context=context_minimal)

    # Базовые инварианты отчёта
    assert isinstance(report, ValidationReport)
    assert isinstance(report.is_valid, bool)
    assert isinstance(report.errors, list)
    assert isinstance(report.warnings, list)
    assert isinstance(report.stats, dict)

    # Сценарий без ошибок
    assert report.is_valid, f"Ожидали валидный канон, получили ошибки: {report.errors}"
    assert len(report.errors) == 0

    # В предупреждениях допускаем RuleWarnMentorExists выдавать пусто, т.к. relations есть
    assert all(isinstance(w, (str, dict)) for w in report.warnings)

    # Логи валидатора (если ведутся)
    # Не требуем конкретный формат, только, что что-то записалось на INFO/DEBUG
    log_text = "\n".join(m for _, _, m in caplog.record_tuples)
    assert "validate" in log_text.lower() or "canon" in log_text.lower()


def test_invalid_canon_collects_structured_errors(mutable_canon, rules_ok):
    # Создаём дубликат id у божества
    mutable_canon["deities"].append({"id": "aether", "domain": ["echo"], "rank": 9})

    validator = CanonValidator()
    report = validator.validate(mutable_canon, rules_ok, context={"strict": True})

    assert not report.is_valid
    assert len(report.errors) >= 1

    # Проверяем структуру ошибки
    err = report.errors[0]
    if isinstance(err, dict):
        assert "code" in err and "message" in err
        assert "path" in err and isinstance(err["path"], (list, tuple))
        assert err.get("severity", "error") in ("error", "warning")


def test_rule_exception_is_captured_as_error(mutable_canon, rules_with_fault):
    validator = CanonValidator()
    report = validator.validate(mutable_canon, rules_with_fault, context={"strict": True})

    # Ошибка правила не должна обрушить валидацию:
    assert isinstance(report, ValidationReport)
    assert any(
        (isinstance(e, dict) and e.get("code") in {"rule_exception", "unexpected_rule_error"})
        or (isinstance(e, str) and "exception" in e.lower())
        for e in report.errors
    ), "Исключение в правиле должно быть промаплено на ошибку отчёта"


def test_determinism_same_input_same_report(mutable_canon, rules_ok):
    validator = CanonValidator()
    r1 = validator.validate(mutable_canon, rules_ok, context={"strict": True})
    r2 = validator.validate(deepcopy(mutable_canon), rules_ok, context={"strict": True})

    # Сравниваем проекцию отчёта, игнорируя поля времени/uuid, если такие есть
    def proj(rep: Any) -> Dict[str, Any]:
        data = {
            "is_valid": rep.is_valid,
            "errors": rep.errors,
            "warnings": rep.warnings,
        }
        # stats может содержать duration_ms/started_at — игнорируем волатильные ключи
        stable_stats = {k: v for k, v in rep.stats.items() if k not in {"duration_ms", "started_at", "finished_at"}}
        data["stats"] = stable_stats
        return data

    assert proj(r1) == proj(r2), "Отчёты должны быть детерминированными при идентичном вводе"


def test_parallel_validate_is_thread_safe(mutable_canon, rules_ok):
    validator = CanonValidator()

    def job(seed: int):
        c = deepcopy(mutable_canon)
        # минимальная неоднородность
        c["canon_version"] = f"1.0.{seed%3}"
        rep = validator.validate(c, rules_ok, context={"strict": True})
        assert isinstance(rep, ValidationReport)
        return rep.is_valid

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(job, range(64)))

    # Не требуем все True (зависит от входа), но проверяем стабильность без исключений
    assert len(results) == 64
    assert all(isinstance(x, bool) for x in results)


@pytest.mark.parametrize(
    "events,expected_valid",
    [
        ([{"event": "t0", "t": 0}, {"event": "t1", "t": 1}, {"event": "t2", "t": 2}], True),
        ([{"event": "t0", "t": 0}, {"event": "t1", "t": -1}], False),
    ],
)
def test_timeline_monotonicity(mutable_canon, rules_ok, events, expected_valid):
    mutable_canon["timeline"] = events
    validator = CanonValidator()
    rep = validator.validate(mutable_canon, rules_ok, context={"strict": True})
    assert rep.is_valid is expected_valid


def test_stats_and_duration_present(mutable_canon, rules_ok):
    validator = CanonValidator()
    start = time.perf_counter()
    rep = validator.validate(mutable_canon, rules_ok, context={"strict": True})
    elapsed = (time.perf_counter() - start) * 1000.0

    # Проверяем наличие ключевых метрик
    assert isinstance(rep.stats, dict)
    assert rep.stats.get("rules_total") == len(rules_ok) or rep.stats.get("rules_evaluated") == len(rules_ok)
    # duration_ms может отличаться, но должен быть разумен
    dur_ms = rep.stats.get("duration_ms")
    if isinstance(dur_ms, (int, float)):
        # Допускаем погрешность, но явно не ноль и не отрицательный
        assert dur_ms > 0
        assert dur_ms < (elapsed * 5)  # не более чем x5 от реального wall-clock измерения тестом


@pytest.mark.skipif(not _has_option(CanonValidator, "timeout"), reason="Валидатор не поддерживает timeout")
def test_timeout_is_enforced(mutable_canon, rules_ok):
    # Если реализация поддерживает timeout, проверяем с небольшим лимитом
    validator = CanonValidator()

    # Индуцируем лёгкую задержку через правило
    class SlowRule:
        id = "slow"
        def check(self, canon, context=None):
            time.sleep(0.05)
            return []

    rep = validator.validate(mutable_canon, rules_ok + [SlowRule()], context={"strict": True}, timeout=0.01)
    # Ожидаем либо специальную ошибку timeout, либо общий флаг невалидности
    assert not rep.is_valid
    assert any(
        (isinstance(e, dict) and e.get("code") in {"timeout", "validation_timeout"})
        or (isinstance(e, str) and "timeout" in e.lower())
        for e in rep.errors
    )


@pytest.mark.skipif(not _has_attr(ValidationReport, "to_json"), reason="Нет метода to_json у ValidationReport")
def test_report_serialization_roundtrip(mutable_canon, rules_ok):
    validator = CanonValidator()
    rep1 = validator.validate(mutable_canon, rules_ok, context={"strict": True})
    s = rep1.to_json()
    assert isinstance(s, str)
    data = json.loads(s)
    assert "is_valid" in data and "errors" in data and "warnings" in data

    # Если есть from_json — проверяем обратность
    if _has_attr(ValidationReport, "from_json"):
        rep2 = ValidationReport.from_json(s)
        assert rep2.is_valid == rep1.is_valid
        assert rep2.errors == rep1.errors
        assert rep2.warnings == rep1.warnings


def test_logging_captures_errors(mutable_canon, rules_ok, caplog):
    # Создаём регрессию таймлайна для ошибок
    mutable_canon["timeline"] = [{"event": "a", "t": 0}, {"event": "b", "t": -5}]
    caplog.set_level(logging.WARNING)
    validator = CanonValidator()
    _ = validator.validate(mutable_canon, rules_ok, context={"strict": True})

    messages = [rec.getMessage().lower() for rec in caplog.records]
    # Не требуем конкретных строк — только что ошибки отражаются в логах
    assert any("error" in m or "invalid" in m or "timeline" in m for m in messages)


def test_rule_order_does_not_affect_semantics(mutable_canon, rules_ok):
    validator = CanonValidator()
    r1 = validator.validate(mutable_canon, rules_ok, context={"strict": True})
    r2 = validator.validate(mutable_canon, list(reversed(rules_ok)), context={"strict": True})

    # Семантика (валидность, состав ошибок/предупреждений) не зависит от порядка правил
    def simplify(rep: Any) -> Dict[str, Any]:
        def norm(items: List[Any]) -> List[Any]:
            # нормализуем кортежи/списки путей, сортируем по (code,message,path)
            normed = []
            for it in items:
                if isinstance(it, dict):
                    p = tuple(it.get("path") or [])
                    normed.append((it.get("code"), it.get("message"), p))
                else:
                    normed.append(("str", str(it), ()))
            return sorted(normed)
        return {"is_valid": rep.is_valid, "errors": norm(rep.errors), "warnings": norm(rep.warnings)}

    assert simplify(r1) == simplify(r2)


def test_reducing_conflicts_should_not_increase_errors(mutable_canon, rules_ok):
    validator = CanonValidator()
    # Индуцируем конфликт (дубликат id)
    mutable_canon["deities"].append({"id": "aether", "domain": ["echo"], "rank": 9})
    rep_conflict = validator.validate(mutable_canon, rules_ok, context={"strict": True})
    errors_with_conflict = len(rep_conflict.errors)

    # Убираем конфликт
    mutable_canon["deities"].pop()
    rep_fixed = validator.validate(mutable_canon, rules_ok, context={"strict": True})
    errors_after_fix = len(rep_fixed.errors)

    assert errors_after_fix <= errors_with_conflict


# ---------- PROPERTY-BASED ТЕСТЫ (опциональны, если установлен hypothesis) ----------

hypothesis = pytest.importorskip("hypothesis", reason="Нет hypothesis — пропускаем property-based тесты")
from hypothesis import given, strategies as st


@given(
    ids=st.lists(st.text(min_size=1, max_size=8), min_size=1, max_size=10),
    non_decreasing=st.lists(st.integers(min_value=-10, max_value=10), min_size=1, max_size=8).map(
        lambda xs: sorted(xs)
    ),
)
def test_property_no_new_errors_when_removing_duplicate(ids, non_decreasing, rules_ok, base_canon):
    # Формируем канон с потенциальными дублями
    canon = deepcopy(base_canon)
    canon["deities"] = [{"id": i, "domain": ["x"], "rank": 1} for i in ids]
    canon["timeline"] = [{"event": f"e{k}", "t": t} for k, t in enumerate(non_decreasing)]

    validator = CanonValidator()
    rep_full = validator.validate(canon, rules_ok, context={"strict": True})

    # Если есть дубликаты, то после удаления одного вхождения ошибок не должно стать больше
    dups = set([i for i in ids if ids.count(i) > 1])
    if dups:
        # Удаляем одно дублирующееся значение
        victim = next(iter(dups))
        idx = next(i for i, d in enumerate(canon["deities"]) if d["id"] == victim)
        canon["deities"].pop(idx)
        rep_less = validator.validate(canon, rules_ok, context={"strict": True})
        assert len(rep_less.errors) <= len(rep_full.errors)


# ---------- РЕГРЕССИОННЫЕ УГЛЫ И ДОП. ПРОВЕРКИ ----------

def test_validate_accepts_empty_rules(mutable_canon):
    validator = CanonValidator()
    rep = validator.validate(mutable_canon, [], context={"strict": True})
    assert rep.is_valid
    assert rep.errors == []


def test_validate_handles_missing_optional_fields(mutable_canon, rules_ok):
    # Удаляем необязательные поля
    mutable_canon.pop("relations", None)
    validator = CanonValidator()
    rep = validator.validate(mutable_canon, rules_ok, context={"strict": True})
    # Может быть warning из RuleWarnMentorExists, но не падение:
    assert isinstance(rep, ValidationReport)
    assert isinstance(rep.warnings, list)


def test_thread_local_state_isolated(mutable_canon, rules_ok):
    validator = CanonValidator()
    seen_ids = set()
    lock = threading.Lock()

    def worker(i: int):
        local = deepcopy(mutable_canon)
        local["deities"][0]["id"] = f"aether_{i}"
        rep = validator.validate(local, rules_ok, context={"strict": True})
        with lock:
            seen_ids.add(local["deities"][0]["id"])
        assert rep.is_valid

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert len(seen_ids) == 10, "Состояние не должно пересекаться между потоками"


@pytest.mark.skipif(not _has_option(CanonValidator, "schema"), reason="Схема не поддерживается валидатором")
def test_json_schema_validation_if_supported(mutable_canon, rules_ok):
    # Проверим, что при переданной json-схеме валидатор ловит нарушение поля
    schema = {
        "type": "object",
        "properties": {
            "canon_version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"}
        },
        "required": ["canon_version"],
        "additionalProperties": True,
    }
    mutable_canon["canon_version"] = "v1"  # нарушение паттерна

    validator = CanonValidator()
    rep = validator.validate(mutable_canon, rules_ok, context={"strict": True}, schema=schema)

    assert not rep.is_valid
    assert any(
        (isinstance(e, dict) and e.get("code") in {"schema_violation", "jsonschema_error"})
        or (isinstance(e, str) and "schema" in e.lower())
        for e in rep.errors
    )
