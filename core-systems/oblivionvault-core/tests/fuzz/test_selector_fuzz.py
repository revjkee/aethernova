# path: oblivionvault-core/tests/fuzz/test_selector_fuzz.py
# ВНИМАНИЕ: Часть контрактов API селектора не подтверждена. Тесты используют feature-detection
# и корректно помечают skip при отсутствии функций.
# Unverified: конкретные имена модулей/функций зависят от вашей реализации. I cannot verify this.
from __future__ import annotations

import importlib
import json
import re
import time
import types
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

# Требуем Hypothesis для fuzz/property-based:
hyp = pytest.importorskip("hypothesis")
st = pytest.importorskip("hypothesis.strategies")
from hypothesis import given, settings, HealthCheck

# Кандидаты модулей селектора (первый успешно импортированный и будет использован).
SELECTOR_MODULE_CANDIDATES = [
    "oblivionvault.selector",
    "oblivionvault.selectors.selector",
    "oblivionvault.core.selector",
    "oblivionvault.query.selector",
    "oblivionvault.policy.selector",
]

# Попробуем также QuerySpec для проверки build_queryspec (если есть):
try:
    DF = importlib.import_module("oblivionvault.adapters.datafabric_adapter")
    QuerySpec = getattr(DF, "QuerySpec", None)
except Exception:
    QuerySpec = None  # не критично, просто будет skip в соответствующих тестах


def _import_selector_module() -> types.ModuleType:
    errs: List[str] = []
    for m in SELECTOR_MODULE_CANDIDATES:
        try:
            return importlib.import_module(m)
        except Exception as e:
            errs.append(f"{m}: {e}")
            continue
    pytest.skip("Selector module not found. Tried: " + "; ".join(errs))


def _get_callable(mod: types.ModuleType, names: List[str]) -> Optional[Callable[..., Any]]:
    for n in names:
        if hasattr(mod, n) and callable(getattr(mod, n)):
            return getattr(mod, n)
    return None


@pytest.fixture(scope="module")
def api():
    """
    Обнаруживаем доступные функции селектора:
      parse_fn: parse/loads/from_string      — парсит фильтр (str|dict|AST)
      dumps_fn: dumps/to_string/stringify    — сериализует AST/нормализованный фильтр в строку
      norm_fn:  normalize/canonicalize/...   — нормализует фильтр (приводит к канонической форме)
      eval_fn:  evaluate/match/apply         — проверяет запись на соответствие фильтру
      build_qs: build_queryspec/to_queryspec — строит QuerySpec из фильтра
      validate: validate_filter/validate     — валидирует фильтр (безопасность, глубина и т.п.)
    """
    mod = _import_selector_module()
    parse_fn = _get_callable(mod, ["parse", "loads", "from_string"])
    dumps_fn = _get_callable(mod, ["dumps", "to_string", "stringify", "serialize"])
    norm_fn = _get_callable(mod, ["normalize", "canonicalize", "to_normal_form", "normalize_ast"])
    eval_fn = _get_callable(mod, ["evaluate", "match", "apply", "eval", "select_match"])
    build_qs = _get_callable(mod, ["build_queryspec", "to_queryspec", "build_query_spec"])
    validate = _get_callable(mod, ["validate_filter", "validate"])
    return {
        "mod": mod,
        "parse": parse_fn,
        "dumps": dumps_fn,
        "normalize": norm_fn,
        "evaluate": eval_fn,
        "build_queryspec": build_qs,
        "validate": validate,
    }


# ------------------------------------------------------------------------------
# Стратегии генерации фильтров: AST (JSON-подобный) и безопасные строки DSL
# ------------------------------------------------------------------------------
SAFE_FIELD = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=list("_-./"),
        min_codepoint=0x20,
        max_codepoint=0x10FFFF,
    ),
    min_size=1,
    max_size=20,
).filter(lambda s: not s.startswith((".", "__")))

SAFE_STR = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=list(" _-./@:+"),
        min_codepoint=0x20,
        max_codepoint=0x10FFFF,
    ),
    min_size=0,
    max_size=24,
)

NUM = st.one_of(st.integers(min_value=-10**9, max_value=10**9), st.floats(allow_nan=False, allow_infinity=False, width=32))
BOOL = st.booleans()

VALUE = st.one_of(SAFE_STR, NUM, BOOL, st.none())

CMPOP = st.sampled_from(["eq", "neq", "lt", "lte", "gt", "gte", "contains", "prefix", "in"])
LOGOP = st.sampled_from(["and", "or"])
NOTOP = st.just("not")

# Лист сравнения: {"eq":{"field":"a","value":123}}
CMP_NODE = st.builds(
    lambda op, f, v: {op: {"field": f, "value": v}},
    CMPOP,
    SAFE_FIELD,
    VALUE,
)

# Рекурсивная генерация AST: {"and":[<sub>, ...]} | {"or":[...]} | {"not": <sub>} | <cmp>
FILTER_AST = st.recursive(
    base=CMP_NODE,
    extend=lambda inner: st.one_of(
        st.builds(lambda subs: {"and": subs}, st.lists(inner, min_size=1, max_size=4)),
        st.builds(lambda subs: {"or": subs}, st.lists(inner, min_size=1, max_size=4)),
        st.builds(lambda sub: {"not": sub}, inner),
    ),
    max_leaves=20,
)

# Простейший безопасный DSL (если парсер умеет строки вида: field op value)
# Пример: "a eq 10 and (b lt 5 or not c contains foo)"
DSL_OP_MAP = {
    "eq": "==",
    "neq": "!=",
    "lt": "<",
    "lte": "<=",
    "gt": ">",
    "gte": ">=",
    "contains": "~",
    "prefix": "^",
    "in": "in",
}

def _ast_to_simple_dsl(ast: Dict[str, Any]) -> str:
    if not isinstance(ast, dict) or not ast:
        return "true"
    k = next(iter(ast))
    v = ast[k]
    if k in ("and", "or") and isinstance(v, list):
        joiner = f" {k} "
        return "(" + joiner.join(_ast_to_simple_dsl(x) for x in v) + ")"
    if k == "not":
        return f"not ({_ast_to_simple_dsl(v)})"
    # cmp
    op = k
    if isinstance(v, dict):
        field = v.get("field", "x")
        value = v.get("value", None)
        sop = DSL_OP_MAP.get(op, op)
        if isinstance(value, str):
            sval = '"' + value.replace('"', '\\"') + '"'
        else:
            sval = json.dumps(value)
        return f"{field} {sop} {sval}"
    return "true"


DSL_EXPR = FILTER_AST.map(_ast_to_simple_dsl)


# ------------------------------------------------------------------------------
# Вспомогательные функции для безопасного вызова API селектора
# ------------------------------------------------------------------------------
def _try_parse(parse_fn: Optional[Callable[..., Any]], obj: Any) -> Any:
    if parse_fn is None:
        pytest.skip("parse() is not available in selector API")
    try:
        return parse_fn(obj)
    except TypeError:
        # возможно, парсер принимает только строки — попробуем json.dumps
        if not isinstance(obj, str):
            return parse_fn(json.dumps(obj))
        raise

def _maybe_normalize(norm_fn: Optional[Callable[..., Any]], obj: Any) -> Any:
    return obj if norm_fn is None else norm_fn(obj)

def _maybe_dump(dumps_fn: Optional[Callable[..., Any]], obj: Any) -> str:
    if dumps_fn is None:
        # безопасный fallback
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return dumps_fn(obj)

def _fast_hash(s: str) -> int:
    # пусть будет быстрая хэш-оценка для сравнения нормализованных строк
    return hash(s)


# ------------------------------------------------------------------------------
# Свойства: round-trip, идемпотентность, коммутативность
# ------------------------------------------------------------------------------
@settings(deadline=500, suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=200)
@given(FILTER_AST)
def test_roundtrip_parse_normalize_dump(api, filt):
    parsed = _try_parse(api["parse"], filt)
    n1 = _maybe_normalize(api["normalize"], parsed)
    s1 = _maybe_dump(api["dumps"], n1)

    # повторный парс того, что получили из dumps
    parsed2 = _try_parse(api["parse"], s1)
    n2 = _maybe_normalize(api["normalize"], parsed2)
    s2 = _maybe_dump(api["dumps"], n2)

    assert _fast_hash(s1) == _fast_hash(s2), "Нарушена стабильность round-trip (parse→normalize→dumps→parse→normalize→dumps)"


@settings(deadline=500, suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=150)
@given(st.lists(FILTER_AST, min_size=2, max_size=5))
def test_commutativity_and_or_when_normalized(api, subs):
    if api["normalize"] is None:
        pytest.skip("normalize() is not available to assert commutativity")

    a_and = {"and": subs}
    b_and = {"and": list(reversed(subs))}

    a_or = {"or": subs}
    b_or = {"or": list(reversed(subs))}

    na1 = _maybe_dump(api["dumps"], api["normalize"](_try_parse(api["parse"], a_and)))
    na2 = _maybe_dump(api["dumps"], api["normalize"](_try_parse(api["parse"], b_and)))
    no1 = _maybe_dump(api["dumps"], api["normalize"](_try_parse(api["parse"], a_or)))
    no2 = _maybe_dump(api["dumps"], api["normalize"](_try_parse(api["parse"], b_or)))

    assert na1 == na2, "AND должен быть коммутативен после нормализации"
    assert no1 == no2, "OR должен быть коммутативен после нормализации"


# ------------------------------------------------------------------------------
# DSL-путь (если парсер поддерживает строки)
# ------------------------------------------------------------------------------
@settings(deadline=600, suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=120)
@given(DSL_EXPR)
def test_dsl_roundtrip_if_supported(api, expr):
    if api["parse"] is None:
        pytest.skip("parse() отсутствует")
    # Если парсер не принимает строки, будет TypeError и тест корректно skip-нется
    try:
        parsed = api["parse"](expr)
    except TypeError:
        pytest.skip("parse() не принимает DSL-строки")
    n1 = _maybe_normalize(api["normalize"], parsed)
    s1 = _maybe_dump(api["dumps"], n1)

    parsed2 = _try_parse(api["parse"], s1)
    n2 = _maybe_normalize(api["normalize"], parsed2)
    s2 = _maybe_dump(api["dumps"], n2)
    assert s1 == s2


# ------------------------------------------------------------------------------
# Валидация: глубина, размер, инъекции
# ------------------------------------------------------------------------------
DANGEROUS_STRINGS = [
    "__import__",
    "os.system",
    "subprocess",
    "eval(",
    "open(",
    "socket",
    "`",
    "${",
    "$( ",
]

@settings(deadline=800, suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=80)
@given(FILTER_AST)
def test_validator_rejects_over_deep_if_supported(api, filt):
    if api["validate"] is None:
        pytest.skip("validate_filter() отсутствует")
    # Сконструируем заведомо глубокий фильтр
    deep = filt
    for _ in range(64):
        deep = {"and": [deep]}
    # Ожидаем либо исключение, либо False/ответ с флагом invalid
    try:
        res = api["validate"](deep)
    except Exception:
        return
    # Допускаем разные контракты: bool, dict, объект
    if isinstance(res, bool):
        assert res is False, "Слишком глубокий фильтр должен отклоняться валидатором"
    elif isinstance(res, dict):
        assert res.get("ok") is False or res.get("valid") is False or res.get("error"), "Ожидался отказ валидации"
    else:
        # Попробуем эвристику по атрибутам
        ok = getattr(res, "ok", None)
        valid = getattr(res, "valid", None)
        err = getattr(res, "error", None)
        assert (ok is False) or (valid is False) or bool(err), "Ожидался отказ валидации"


@settings(deadline=800, suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=80)
@given(st.sampled_from(DANGEROUS_STRINGS), FILTER_AST)
def test_validator_rejects_injections_if_supported(api, bad, base):
    if api["validate"] is None:
        pytest.skip("validate_filter() отсутствует")
    # Инъекция в поле и в значение
    inj1 = {"eq": {"field": bad, "value": "x"}}
    inj2 = {"eq": {"field": "safe", "value": bad}}
    for obj in (inj1, inj2, {"and": [inj1, base]}):
        try:
            res = api["validate"](obj)
        except Exception:
            continue
        if isinstance(res, bool):
            assert res is False, "Опасные токены должны быть отклонены"
        elif isinstance(res, dict):
            assert (res.get("ok") is False) or res.get("error") or res.get("reason"), "Ожидался отказ валидации"
        else:
            ok = getattr(res, "ok", None)
            valid = getattr(res, "valid", None)
            err = getattr(res, "error", None)
            assert (ok is False) or (valid is False) or bool(err), "Ожидался отказ валидации"


# ------------------------------------------------------------------------------
# Производительность: патологические случаи не должны взрывать время
# ------------------------------------------------------------------------------
@settings(deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=10)
@given(st.integers(min_value=1000, max_value=3000))
def test_pathological_long_chain_perf_parse_normalize(api, n):
    # Строим большой OR из однотипных лиспов
    leaf = {"eq": {"field": "x", "value": 1}}
    big = {"or": [leaf for _ in range(n)]}
    if api["parse"] is None:
        pytest.skip("parse() отсутствует")
    t0 = time.perf_counter()
    parsed = _try_parse(api["parse"], big)
    _ = _maybe_normalize(api["normalize"], parsed)
    elapsed = time.perf_counter() - t0
    # эвристический порог
    assert elapsed < 2.5, f"Слишком долгое время нормализации/парсинга для OR-цепочки (n={n}, {elapsed:.3f}s)"


# ------------------------------------------------------------------------------
# QuerySpec: сборка из фильтра (если реализовано)
# ------------------------------------------------------------------------------
@settings(deadline=600, suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=60)
@given(FILTER_AST, SAFE_FIELD, st.integers(min_value=1, max_value=5000))
def test_build_queryspec_if_supported(api, filt, dataset, limit):
    if api["build_queryspec"] is None or QuerySpec is None:
        pytest.skip("build_queryspec() или QuerySpec отсутствуют")

    qs = api["build_queryspec"](filt, dataset=str(dataset), limit=int(limit), order_by=["ts"])
    # Принимаем: возвращает QuerySpec или dict совместимой формы
    if isinstance(qs, QuerySpec):
        assert qs.dataset == str(dataset)
        assert isinstance(qs.filter, dict)
        assert qs.limit == int(limit)
        assert qs.order_by == ["ts"]
    elif isinstance(qs, dict):
        assert qs.get("dataset") == str(dataset)
        assert isinstance(qs.get("filter"), dict)
        assert qs.get("limit") == int(limit)
        assert qs.get("order_by") == ["ts"]
    else:
        # объект с атрибутами
        assert getattr(qs, "dataset", None) == str(dataset)
        assert isinstance(getattr(qs, "filter", None), dict)
        assert getattr(qs, "limit", None) == int(limit)
        ob = getattr(qs, "order_by", None)
        assert ob == ["ts"]


# ------------------------------------------------------------------------------
# Семантическая проверка (если есть evaluate): эквивалентность после нормализации
# ------------------------------------------------------------------------------
RECORD = st.fixed_dictionaries(
    {
        "x": VALUE,
        "y": VALUE,
        "z": VALUE,
    }
)

@settings(deadline=700, suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=120)
@given(FILTER_AST, RECORD)
def test_normalized_semantically_equivalent_if_evaluate_supported(api, filt, rec):
    if api["evaluate"] is None:
        pytest.skip("evaluate() отсутствует")
    parsed = _try_parse(api["parse"], filt)
    n1 = _maybe_normalize(api["normalize"], parsed)
    n2 = _maybe_normalize(api["normalize"], n1)  # повторная нормализация
    # допускаем, что evaluate принимает (ast, record) или (filter_string, record)
    try:
        r1 = api["evaluate"](n1, rec)
    except TypeError:
        r1 = api["evaluate"](_maybe_dump(api["dumps"], n1), rec)
    try:
        r2 = api["evaluate"](n2, rec)
    except TypeError:
        r2 = api["evaluate"](_maybe_dump(api["dumps"], n2), rec)

    assert bool(r1) == bool(r2), "Повторная нормализация не должна менять семантику фильтра"
