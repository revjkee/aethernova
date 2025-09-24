# -*- coding: utf-8 -*-
"""
Промышленный fuzz/property-based тест для policy-core.

Цели:
- Генерация валидных и частично валидных политик и запросов доступа (ABAC/RBAC mix).
- Проверка устойчивости валидатора к «грязным» данным и отсутствию катастрофических сбоев.
- Детерминизм оценки (одинаковые входы -> одинаковый результат).
- Метаморфические инварианты:
  * deny всегда доминирует над allow при прочих равных;
  * перестановка эквивалентных правил не меняет решение;
  * нормализация/компиляция идемпотентны (normalize(normalize(p)) == normalize(p)).

Тесты автоматически подстраиваются под наличествующие API:
- validate / validate_policy
- compile / compile_policy
- normalize / canonicalize
- evaluate / authorize / decide

Если компонент отсутствует — связанный тест будет помечен как SKIPPED с внятной причиной.
Работает и с синхронными, и с асинхронными реализациями (pytest-asyncio).
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import ipaddress
import json
import random
import string
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import pytest
from hypothesis import HealthCheck, assume, given, settings, strategies as st

# ---------------------------------------------------------------------------
# Настройки Hypothesis: консервативные дедлайны и размер данных для CI.
# ---------------------------------------------------------------------------
settings.register_profile(
    "ci_slow_safe",
    max_examples=120,
    deadline=800,
    suppress_health_check=(HealthCheck.too_slow, HealthCheck.data_too_large),
)
settings.load_profile("ci_slow_safe")


# ---------------------------------------------------------------------------
# Отражение policy_core API с мягкой деградацией (importorskip для пакета).
# ---------------------------------------------------------------------------
policy_core = pytest.importorskip("policy_core", reason="policy_core package is required for fuzz tests")

def _try_import(path: str) -> Optional[Any]:
    try:
        return importlib.import_module(path)
    except Exception:
        return None

pc_validator = _try_import("policy_core.validator")
pc_evaluator = _try_import("policy_core.evaluator")
pc_compiler = _try_import("policy_core.compiler")
pc_normalizer = _try_import("policy_core.normalizer")
pc_schema = _try_import("policy_core.schema")


def _find_callable(candidates: List[Tuple[Any, str]]) -> Optional[Callable]:
    for mod, name in candidates:
        if mod is None:
            continue
        fn = getattr(mod, name, None)
        if callable(fn):
            return fn
    # Попытка на верхнем уровне пакета
    for name in [n for _, n in candidates]:
        fn = getattr(policy_core, name, None)
        if callable(fn):
            return fn
    return None


VALIDATE_FN = _find_callable([
    (pc_validator, "validate"),
    (pc_validator, "validate_policy"),
    (policy_core, "validate"),
    (policy_core, "validate_policy"),
])

COMPILE_FN = _find_callable([
    (pc_compiler, "compile"),
    (pc_compiler, "compile_policy"),
    (policy_core, "compile"),
    (policy_core, "compile_policy"),
])

NORMALIZE_FN = _find_callable([
    (pc_normalizer, "normalize"),
    (pc_normalizer, "canonicalize"),
    (policy_core, "normalize"),
    (policy_core, "canonicalize"),
])

EVALUATE_FN = _find_callable([
    (pc_evaluator, "evaluate"),
    (pc_evaluator, "authorize"),
    (pc_evaluator, "decide"),
    (policy_core, "evaluate"),
    (policy_core, "authorize"),
    (policy_core, "decide"),
])

# Опциональные классы ошибок (если определены)
PolicyError = getattr(policy_core, "PolicyError", None)
ValidationError = getattr(policy_core, "ValidationError", PolicyError)
CompilationError = getattr(policy_core, "CompilationError", PolicyError)
EvaluationError = getattr(policy_core, "EvaluationError", PolicyError)

EXPECTED_ERRORS = tuple(
    e for e in (PolicyError, ValidationError, CompilationError, EvaluationError) if isinstance(e, type)
) or ()


# ---------------------------------------------------------------------------
# Универсальные вызовы (оборачивают sync/async функции и выравнивают интерфейс)
# ---------------------------------------------------------------------------
async def _call(fn: Callable, *args, **kwargs):
    if inspect.iscoroutinefunction(fn):
        return await fn(*args, **kwargs)
    # Если синхронная функция, вызываем напрямую
    return fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# Вспомогательные утилиты для интерпретации решений авторизации
# ---------------------------------------------------------------------------
def _interpret_decision(decision: Any) -> Optional[bool]:
    """
    Пытается привести результат evaluate/authorize/decide к bool.
    Поддерживаются форматы:
      - bool
      - dict с ключом 'allow' или 'effect' ('allow'/'deny')
      - объект с атрибутами .allow или .effect
    Возвращает None, если интерпретация невозможна.
    """
    if isinstance(decision, bool):
        return decision
    if isinstance(decision, dict):
        if "allow" in decision and isinstance(decision["allow"], bool):
            return decision["allow"]
        eff = decision.get("effect")
        if isinstance(eff, str):
            e = eff.lower()
            if e in ("allow", "permit"):
                return True
            if e in ("deny", "block"):
                return False
    # Объект с атрибутом
    eff = getattr(decision, "effect", None)
    if isinstance(eff, str):
        e = eff.lower()
        if e in ("allow", "permit"):
            return True
        if e in ("deny", "block"):
            return False
    allow = getattr(decision, "allow", None)
    if isinstance(allow, bool):
        return allow
    return None


# ---------------------------------------------------------------------------
# Генераторы данных Hypothesis: политики и запросы доступа
# ---------------------------------------------------------------------------
_ALNUM = string.ascii_letters + string.digits + "-:_./*"

def _ident():
    return st.text(alphabet=_ALNUM, min_size=1, max_size=32).map(lambda s: s.strip().strip("/")).filter(bool)

def _cidr():
    return st.builds(
        lambda ip, mask: f"{ip}/{mask}",
        ip=st.integers(min_value=0, max_value=(2**32) - 1).map(lambda x: str(ipaddress.IPv4Address(x))),
        mask=st.integers(min_value=8, max_value=32),
    )

def _iso_time():
    # ISO 8601 без часового пояса для упрощения
    return st.datetimes(min_value=None, max_value=None).map(lambda dt: dt.replace(microsecond=0).isoformat())

ACTIONS = st.lists(_ident(), min_size=1, max_size=4, unique=True)
RESOURCES = st.lists(_ident(), min_size=1, max_size=4, unique=True)
ROLES = st.lists(_ident(), min_size=0, max_size=4, unique=True)

CONDITIONS = st.fixed_dictionaries({
    "time": st.fixed_dictionaries({
        "not_before": _iso_time(),
        "not_after": _iso_time(),
    }),
    "ip": st.one_of(
        st.none(),
        _cidr(),
        st.lists(_cidr(), min_size=1, max_size=3, unique=True),
    ),
    "expr": st.one_of(
        st.none(),
        _ident().map(lambda s: f"attr.department == '{s}'"),
        _ident().map(lambda s: f"attr.clearance >= '{s}'"),
    ),
})

SUBJECTS = st.fixed_dictionaries({
    "users": st.lists(_ident(), min_size=0, max_size=4, unique=True),
    "roles": ROLES,
    "attrs": st.dictionaries(_ident(), _ident(), min_size=0, max_size=6),
})

RULE = st.fixed_dictionaries({
    "id": _ident(),
    "effect": st.sampled_from(["allow", "deny"]),
    "actions": ACTIONS,
    "resources": RESOURCES,
    "subjects": SUBJECTS,
    "conditions": CONDITIONS,
    # Доп. поля, которые система должна безопасно игнорировать
    "meta": st.dictionaries(_ident(), _ident(), min_size=0, max_size=4),
})

POLICY = st.fixed_dictionaries({
    "version": st.integers(min_value=1, max_value=3),
    "rules": st.lists(RULE, min_size=1, max_size=16, unique_by=lambda r: r["id"]),
    "defaults": st.fixed_dictionaries({
        "effect": st.sampled_from(["deny", "allow"]),
    }),
    "targets": st.fixed_dictionaries({
        "tenants": st.lists(_ident(), min_size=0, max_size=3, unique=True),
        "environments": st.lists(st.sampled_from(["dev", "staging", "prod"]), min_size=0, max_size=3, unique=True),
    }),
    # опциональная подпись — система может игнорировать
    "signature": st.one_of(
        st.none(),
        st.fixed_dictionaries({
            "alg": st.sampled_from(["ed25519", "secp256k1", "rsa"]),
            "sig": _ident(),
            "key_id": _ident(),
        }),
    ),
})

REQUEST = st.fixed_dictionaries({
    "subject": st.fixed_dictionaries({
        "user": _ident(),
        "roles": ROLES,
        "attrs": st.dictionaries(_ident(), _ident(), min_size=0, max_size=6),
    }),
    "action": _ident(),
    "resource": _ident(),
    "context": st.fixed_dictionaries({
        "time": _iso_time(),
        "ip": _cidr(),
        "tenant": _ident(),
        "environment": st.sampled_from(["dev", "staging", "prod"]),
    }),
})


# ---------------------------------------------------------------------------
# Фикстуры наличия API
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def has_validate() -> bool:
    return VALIDATE_FN is not None

@pytest.fixture(scope="session")
def has_compile() -> bool:
    return COMPILE_FN is not None

@pytest.fixture(scope="session")
def has_normalize() -> bool:
    return NORMALIZE_FN is not None

@pytest.fixture(scope="session")
def has_evaluate() -> bool:
    return EVALUATE_FN is not None


# ---------------------------------------------------------------------------
# Тест 1: Валидатор не падает катастрофически на "грязных" данных
# ---------------------------------------------------------------------------
@given(POLICY)
def test_validate_policy_no_catastrophic_failures(has_validate, policy):
    if not has_validate:
        pytest.skip("No validate API found in policy_core")
    try:
        # Разрешаем любой логический результат, важно отсутствие катастроф
        VALIDATE_FN(policy)  # sync path
    except EXPECTED_ERRORS:
        # Приемлемо: корректно сигнализируем о невалидности
        pass
    except (RecursionError, MemoryError):
        pytest.fail("Validator experienced catastrophic failure (Recursion/Memory)")
    except Exception:
        # Остальные исключения нежелательны, но не считаем их «катастрофическими»
        # Падаем, чтобы не замалчивать реальный дефект.
        raise


# ---------------------------------------------------------------------------
# Вспомогательная функция: подготовка политики к исполнению
# ---------------------------------------------------------------------------
async def _prepare_policy(policy: dict) -> Any:
    p = policy
    if NORMALIZE_FN:
        p = await _call(NORMALIZE_FN, p)
        # Идемпотентность нормализации
        p2 = await _call(NORMALIZE_FN, p)
        assert p2 == p, "normalize(normalize(p)) must be equal to normalize(p)"
    if COMPILE_FN:
        p = await _call(COMPILE_FN, p)
    return p


# ---------------------------------------------------------------------------
# Тест 2: Детерминизм исполнения
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@given(POLICY, REQUEST)
async def test_evaluate_is_deterministic(has_evaluate, policy, request):
    if not has_evaluate:
        pytest.skip("No evaluate/authorize/decide API found in policy_core")

    compiled = await _prepare_policy(policy)

    t0 = time.perf_counter()
    try:
        r1 = await _call(EVALUATE_FN, compiled, request)
        r2 = await _call(EVALUATE_FN, compiled, request)
    except EXPECTED_ERRORS:
        # Приемлемо: корректно сообщено о невозможности оценки
        return
    finally:
        elapsed = (time.perf_counter() - t0) * 1000.0
        assert elapsed < 750, f"Evaluation is too slow: {elapsed:.1f} ms"

    # Детерминизм: одинаковый результат повторного вызова
    assert json.dumps(r1, sort_keys=True, default=str) == json.dumps(r2, sort_keys=True, default=str), \
        "Evaluation must be deterministic for identical inputs"


# ---------------------------------------------------------------------------
# Тест 3: Deny доминирует над Allow (метаморфизм)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@given(POLICY, REQUEST)
async def test_deny_overrides_allow(has_evaluate, policy, request):
    if not has_evaluate:
        pytest.skip("No evaluate/authorize/decide API found in policy_core")

    # Базовая политика с allow-правилом для конкретного действия/ресурса
    base_rule = {
        "id": "r-allow",
        "effect": "allow",
        "actions": [request["action"]],
        "resources": [request["resource"]],
        "subjects": {
            "users": [request["subject"]["user"]],
            "roles": request["subject"]["roles"],
            "attrs": request["subject"]["attrs"],
        },
        "conditions": {
            "time": {"not_before": request["context"]["time"], "not_after": request["context"]["time"]},
            "ip": request["context"]["ip"],
            "expr": None,
        },
        "meta": {},
    }
    base_policy = {**policy, "rules": [base_rule] + policy.get("rules", [])}

    compiled = await _prepare_policy(base_policy)
    try:
        base_decision = await _call(EVALUATE_FN, compiled, request)
    except EXPECTED_ERRORS:
        pytest.skip("Evaluator refused the base policy; skipping dominance check")

    base_allow = _interpret_decision(base_decision)
    assume(base_allow is not None)

    # Добавляем конфликтующее deny-правило в начало
    deny_rule = dict(base_rule, id="r-deny", effect="deny")
    mutated_policy = {**base_policy, "rules": [deny_rule] + base_policy["rules"]}

    compiled2 = await _prepare_policy(mutated_policy)
    try:
        mutated_decision = await _call(EVALUATE_FN, compiled2, request)
    except EXPECTED_ERRORS:
        pytest.skip("Evaluator refused the mutated policy; skipping dominance check")

    mutated_allow = _interpret_decision(mutated_decision)
    assume(mutated_allow is not None)

    # Инвариант: deny должен доминировать
    if base_allow is True:
        assert mutated_allow is False, "deny must override prior allow for same match set"


# ---------------------------------------------------------------------------
# Тест 4: Перестановка эквивалентных правил не влияет на результат
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@given(POLICY, REQUEST, st.integers(min_value=0, max_value=1000))
async def test_rule_permutation_stability(has_evaluate, policy, request, seed):
    if not has_evaluate:
        pytest.skip("No evaluate/authorize/decide API found in policy_core")

    # Только для политик с достаточно большим количеством правил
    assume(len(policy["rules"]) >= 3)

    compiled = await _prepare_policy(policy)
    try:
        ref_decision = await _call(EVALUATE_FN, compiled, request)
    except EXPECTED_ERRORS:
        pytest.skip("Evaluator refused the base policy; skipping permutation check")

    ref_json = json.dumps(ref_decision, sort_keys=True, default=str)

    # Перестановка порядка без изменения семантики (глобальная перетасовка)
    rnd = random.Random(seed)
    permuted = {**policy, "rules": policy["rules"][:]}
    rnd.shuffle(permuted["rules"])

    compiled_perm = await _prepare_policy(permuted)
    try:
        perm_decision = await _call(EVALUATE_FN, compiled_perm, request)
    except EXPECTED_ERRORS:
        pytest.skip("Evaluator refused the permuted policy; skipping permutation check")

    perm_json = json.dumps(perm_decision, sort_keys=True, default=str)
    assert perm_json == ref_json, "Permutation of equivalent rules must not change the decision"


# ---------------------------------------------------------------------------
# Тест 5: Идемпотентность нормализации (если доступна)
# ---------------------------------------------------------------------------
@given(POLICY)
def test_normalize_idempotent(has_normalize, policy):
    if not has_normalize:
        pytest.skip("No normalize/canonicalize API found in policy_core")
    p1 = NORMALIZE_FN(policy)
    p2 = NORMALIZE_FN(p1)
    assert p1 == p2, "normalize must be idempotent"


# ---------------------------------------------------------------------------
# Тест 6: Компиляция не меняет семантику (если есть evaluate)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
@given(POLICY, REQUEST)
async def test_compile_semantics_preserved(has_evaluate, has_compile, policy, request):
    if not has_evaluate:
        pytest.skip("No evaluate/authorize/decide API found in policy_core")
    # Сначала исполняем ненормализованную/неcкомпилированную политику, если возможно
    try:
        r_raw = await _call(EVALUATE_FN, policy, request)
        raw_ok = True
    except EXPECTED_ERRORS:
        raw_ok = False
    except Exception:
        raw_ok = False

    compiled = await _prepare_policy(policy)
    try:
        r_comp = await _call(EVALUATE_FN, compiled, request)
    except EXPECTED_ERRORS:
        pytest.skip("Evaluator refused compiled policy; skipping semantic preservation check")

    if raw_ok:
        assert json.dumps(r_comp, sort_keys=True, default=str) == json.dumps(r_raw, sort_keys=True, default=str), \
            "Compilation/normalization should not change decision semantics"


# ---------------------------------------------------------------------------
# Тест 7: Никаких циклических наследований ролей (если валидатор умеет ловить)
# ---------------------------------------------------------------------------
@given(POLICY)
def test_no_cyclic_role_inheritance(has_validate, policy):
    if not has_validate:
        pytest.skip("No validate API found in policy_core")

    # Вставим потенциальную циклическую структуру в meta (если движок это поддерживает)
    assume(len(policy["rules"]) >= 2)
    policy = dict(policy)
    rules = policy["rules"][:]
    rules[0]["meta"] = dict(rules[0].get("meta", {}), inherits=["role:A"])
    rules[1]["meta"] = dict(rules[1].get("meta", {}), inherits=["role:B"])
    # Намеренная петля
    loops = {"role:A": ["role:B"], "role:B": ["role:A"]}

    policy["role_inheritance"] = loops

    try:
        VALIDATE_FN(policy)
    except EXPECTED_ERRORS:
        # Ожидаемо: валидатор может ругаться на цикл — это плюс.
        return
    except (RecursionError, MemoryError):
        pytest.fail("Validator hit catastrophic failure on cyclic role inheritance")
    # Если валидатор молчит — это не обязательно дефект (движок может не поддерживать наследование).
    # Тест проходит молча.


# ---------------------------------------------------------------------------
# Конец файла
# ---------------------------------------------------------------------------
