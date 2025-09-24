# policy-core/tests/unit/test_attributes.py
# -*- coding: utf-8 -*-
"""
Промышленный контракт-тест для слоя атрибутов policy-core.

ОЖИДАЕМЫЙ МИНИМАЛЬНЫЙ API (реализуйте в policy_core/attributes.py):
-------------------------------------------------------------------
class Attribute:
    # Обязательные поля:
    # - name: str (не пустая, trimmed)
    # - value: JSON-совместимое значение (int/float/str/bool/None/list/dict)
    # - namespace: Optional[str] = None (если None -> "default")
    # - created_at: datetime (UTC, tz-aware)
    # - ttl_seconds: Optional[int] = None ( > 0 )
    # - metadata: Optional[dict[str, Any]] = None
    # Свойства/методы:
    # - key() -> tuple[str, str]: (namespace, name)
    # - is_expired(now: datetime | None = None) -> bool
    # - to_dict() -> dict
    # - @classmethod from_dict(cls, data: dict) -> "Attribute"
    # - __hash__/__eq__ по (namespace, name, value, ttl, metadata) или как минимум по key() + value
    #
class AttributeSet:
    # Конструктор: AttributeSet(items: Iterable[Attribute] | None = None)
    # Методы:
    # - add(attr: Attribute) -> None (перезаписывает по ключу или по флагу replace=True)
    # - get(name: str, namespace: str | None = None) -> Optional[Attribute]
    # - remove(name: str, namespace: str | None = None) -> bool
    # - filter(namespace: str | None = None, prefix: str | None = None) -> "AttributeSet"
    # - merge(other: "AttributeSet", precedence: Literal["left","right"]="right") -> "AttributeSet"
    # - purge_expired(now: datetime | None = None) -> int  # кол-во удалённых
    # - to_dict() -> dict  # {"items":[...]}
    # - @classmethod from_dict(cls, data: dict) -> "AttributeSet"
    # - __len__, __iter__, __contains__
    #
# (Опционально) Простейший интерфейс движка политик, если есть:
class AttributePolicyEngine:
    # - evaluate(subject: AttributeSet, resource: AttributeSet, env: AttributeSet) -> dict
    # Ожидается, что dict содержит хотя бы поля: {"decision": "Allow"|"Deny", "matched_rules": list[str]}

Примечание:
Если модуль пока отсутствует — тесты скипнутся с понятным сообщением.
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

# property-based (опционально установите hypothesis в проекте)
hypothesis = pytest.importorskip("hypothesis", reason="Hypothesis не установлен (pip install hypothesis)")
from hypothesis import given, settings
from hypothesis import strategies as st


# --------- Импорт тестируемого модуля с graceful degrade ---------
ATTR_MODULE = None
ENGINE_CLASS = None

try:
    import importlib

    ATTR_MODULE = importlib.import_module("policy_core.attributes")
    Attribute = getattr(ATTR_MODULE, "Attribute")
    AttributeSet = getattr(ATTR_MODULE, "AttributeSet")

    ENGINE_CLASS = getattr(ATTR_MODULE, "AttributePolicyEngine", None)
except Exception as e:
    pytest.skip(f"Модуль policy_core.attributes не найден или не загружается: {e}", allow_module_level=True)


# ------------------------ Утилиты/фикстуры ------------------------

@pytest.fixture(scope="session")
def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture
def sample_attrs(utc_now):
    return [
        Attribute(name="role", value="admin", namespace="subject", created_at=utc_now),
        Attribute(name="level", value=7, namespace="subject", created_at=utc_now),
        Attribute(name="owner", value="team-alpha", namespace="resource", created_at=utc_now),
        Attribute(name="region", value="eu", namespace="env", created_at=utc_now),
    ]


def assert_json_serializable(obj: Any) -> None:
    try:
        json.dumps(obj)
    except TypeError as te:
        raise AssertionError(f"Объект не сериализуем в JSON: {te!r}") from te


# ----------------------------- ТЕСТЫ Attribute -----------------------------

def test_attribute_minimal_ok(utc_now):
    a = Attribute(name="id", value="123", created_at=utc_now)
    assert a.name == "id"
    assert a.value == "123"
    assert a.namespace in (None, "default") or isinstance(a.namespace, str)
    ns = a.namespace or "default"
    assert a.key() == (ns, "id")
    assert a.is_expired(utc_now) is False
    d = a.to_dict()
    assert isinstance(d, dict) and d.get("name") == "id"
    b = Attribute.from_dict(d)
    assert b.name == a.name and b.value == a.value


@pytest.mark.parametrize(
    "bad_name",
    ["", "   ", "\n", "\t", "   \t", None],
)
def test_attribute_rejects_bad_name(bad_name, utc_now):
    with pytest.raises((ValueError, TypeError)):
        Attribute(name=bad_name, value="x", created_at=utc_now)


@pytest.mark.parametrize("v", [1, 1.5, "x", True, False, None, {"a": 1}, [1, 2, 3]])
def test_attribute_value_json_serializable(v, utc_now):
    a = Attribute(name="v", value=v, created_at=utc_now, namespace="n")
    assert_json_serializable(a.to_dict())


def test_attribute_ttl_expiry(utc_now):
    a = Attribute(name="token", value="abc", created_at=utc_now, ttl_seconds=60, namespace="session")
    assert a.is_expired(utc_now) is False
    future = utc_now + timedelta(seconds=61)
    assert a.is_expired(future) is True


@pytest.mark.parametrize("ttl", [-1, 0])
def test_attribute_invalid_ttl(ttl, utc_now):
    with pytest.raises(ValueError):
        Attribute(name="x", value=1, created_at=utc_now, ttl_seconds=ttl)


def test_attribute_metadata_roundtrip(utc_now):
    meta = {"issued_by": "authz", "labels": ["a", "b"], "score": 0.99}
    a = Attribute(name="score", value=0.99, namespace="subject", created_at=utc_now, metadata=meta)
    d = a.to_dict()
    b = Attribute.from_dict(d)
    assert b.metadata == meta
    assert_json_serializable(d)


# Property-based: разные строковые имена и JSON-значения
@given(
    name=st.text(min_size=1).map(str.strip).filter(lambda s: len(s) > 0),
    value=st.recursive(
        st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False, allow_infinity=False) | st.text(),
        lambda children: st.lists(children, max_size=5) | st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=5),
        max_leaves=10,
    ),
)
@settings(deadline=None, max_examples=50)
def test_attribute_roundtrip_property(name, value, utc_now):
    a = Attribute(name=name, value=value, created_at=utc_now)
    d = a.to_dict()
    assert_json_serializable(d)
    b = Attribute.from_dict(d)
    assert b.name == a.name
    # Значения могут «нормализоваться» (напр. float -> int при json), но сравним по json
    assert json.dumps(b.to_dict(), sort_keys=True) == json.dumps(d, sort_keys=True)


# ----------------------------- ТЕСТЫ AttributeSet -----------------------------

def test_attributeset_basic_ops(sample_attrs):
    s = AttributeSet(sample_attrs)
    assert len(s) == 4
    assert s.get("role", "subject").value == "admin"
    assert s.get("missing", "subject") is None
    assert ("subject", "role") in {a.key() for a in s}

    removed = s.remove("role", "subject")
    assert removed is True
    assert s.get("role", "subject") is None
    assert len(s) == 3


def test_attributeset_filter_and_iter(sample_attrs):
    s = AttributeSet(sample_attrs)
    only_subject = s.filter(namespace="subject")
    assert len(only_subject) == 2
    keys = {a.key() for a in only_subject}
    assert keys == {("subject", "role"), ("subject", "level")}

    pref = s.filter(prefix="re")
    keys2 = {a.key() for a in pref}
    assert ("resource", "owner") in keys2
    assert ("env", "region") not in keys2  # prefix "re" — не "region" по имени, а по namespace/name; уточните логику


def test_attributeset_merge_right_precedence():
    left = AttributeSet([
        Attribute(name="role", value="user", namespace="subject", created_at=datetime.now(timezone.utc)),
        Attribute(name="region", value="eu", namespace="env", created_at=datetime.now(timezone.utc)),
    ])
    right = AttributeSet([
        Attribute(name="role", value="admin", namespace="subject", created_at=datetime.now(timezone.utc)),
        Attribute(name="trace", value=True, namespace="env", created_at=datetime.now(timezone.utc)),
    ])
    merged = left.merge(right, precedence="right")
    assert merged.get("role", "subject").value == "admin"
    assert merged.get("region", "env").value == "eu"
    assert merged.get("trace", "env").value is True
    assert len(merged) == 3


def test_attributeset_merge_left_precedence():
    left = AttributeSet([
        Attribute(name="role", value="user", namespace="subject", created_at=datetime.now(timezone.utc)),
    ])
    right = AttributeSet([
        Attribute(name="role", value="admin", namespace="subject", created_at=datetime.now(timezone.utc)),
    ])
    merged = left.merge(right, precedence="left")
    assert merged.get("role", "subject").value == "user"


def test_attributeset_purge_expired(utc_now):
    s = AttributeSet([
        Attribute(name="a", value=1, created_at=utc_now, ttl_seconds=1, namespace="n"),
        Attribute(name="b", value=2, created_at=utc_now, namespace="n"),
    ])
    assert len(s) == 2
    removed = s.purge_expired(utc_now + timedelta(seconds=5))
    assert removed == 1
    assert len(s) == 1
    assert s.get("b", "n").value == 2


def test_attributeset_serialization_roundtrip(sample_attrs):
    s = AttributeSet(sample_attrs)
    d = s.to_dict()
    assert isinstance(d, dict) and "items" in d and isinstance(d["items"], list)
    s2 = AttributeSet.from_dict(d)
    assert len(s2) == len(s)
    assert {a.key() for a in s2} == {a.key() for a in s}


# Property-based для набора: идемпотентный merge и сохранение ключей
@given(
    names=st.lists(st.text(min_size=1).map(str.strip).filter(lambda s: len(s) > 0), min_size=1, max_size=5, unique=True),
    ints=st.lists(st.integers(), min_size=1, max_size=5),
)
@settings(deadline=None, max_examples=30)
def test_attributeset_merge_idempotency(names, ints, utc_now):
    left_items = [Attribute(name=n, value=ints[i % len(ints)], created_at=utc_now, namespace="x") for i, n in enumerate(names)]
    right_items = [Attribute(name=n, value=ints[(i + 1) % len(ints)], created_at=utc_now, namespace="x") for i, n in enumerate(names)]
    left = AttributeSet(left_items)
    right = AttributeSet(right_items)

    m1 = left.merge(right, precedence="right")
    m2 = left.merge(right, precedence="right")
    # Идемпотентность операции merge с одними и теми же аргументами
    assert json.dumps(m1.to_dict(), sort_keys=True) == json.dumps(m2.to_dict(), sort_keys=True)


# ----------------------------- ТЕСТЫ движка политик (если есть) -----------------------------

@pytest.mark.skipif(ENGINE_CLASS is None, reason="AttributePolicyEngine отсутствует")
def test_policy_engine_basic_allow(utc_now):
    engine = ENGINE_CLASS()
    subject = AttributeSet([Attribute(name="role", value="admin", namespace="subject", created_at=utc_now)])
    resource = AttributeSet([Attribute(name="owner", value="team-alpha", namespace="resource", created_at=utc_now)])
    env = AttributeSet([Attribute(name="region", value="eu", namespace="env", created_at=utc_now)])

    result = engine.evaluate(subject, resource, env)
    assert isinstance(result, dict)
    assert result.get("decision") in ("Allow", "Deny")
    # Базовая эвристика: админ в своей зоне — Allow (зависит от правил движка)
    # Если в вашей реализации правила иные — адаптируйте тест или добавьте xfail
    # Здесь проверим только корректность формата:
    assert "matched_rules" in result and isinstance(result["matched_rules"], list)


@pytest.mark.skipif(ENGINE_CLASS is None, reason="AttributePolicyEngine отсутствует")
@pytest.mark.parametrize(
    "op, lhs, rhs, expected",
    [
        ("eq", "a", "a", True),
        ("eq", 10, 10, True),
        ("in", "eu", ["eu", "us"], True),
        ("regex", "team-alpha", r"^team-[a-z]+$", True),
        ("ge", 7, 5, True),
        ("ge", 5, 7, False),
    ],
)
def test_policy_engine_condition_ops(op, lhs, rhs, expected, utc_now):
    engine = ENGINE_CLASS()
    subject = AttributeSet([Attribute(name="lhs", value=lhs, namespace="subject", created_at=utc_now)])
    resource = AttributeSet([Attribute(name="rhs", value=rhs, namespace="resource", created_at=utc_now)])
    env = AttributeSet([])

    # Ожидается, что движок умеет интерпретировать простую rule-схему (примерная форма):
    # rules=[{"id":"r1","when":{"op":op,"left":{"ns":"subject","name":"lhs"},"right":{"ns":"resource","name":"rhs"}},"effect":"Allow"}]
    # Для универсальности — предоставляем хинт через метод set_rules, если он есть.
    set_rules = getattr(engine, "set_rules", None)
    rule = {
        "id": f"op-{op}",
        "when": {"op": op, "left": {"ns": "subject", "name": "lhs"}, "right": {"ns": "resource", "name": "rhs"}},
        "effect": "Allow",
    }
    if callable(set_rules):
        engine.set_rules([rule])
        res = engine.evaluate(subject, resource, env)
        got = res.get("decision") == "Allow"
        assert got is expected
    else:
        # Если нет set_rules — проверяем, что движок хотя бы корректно отрабатывает без правил.
        res = engine.evaluate(subject, resource, env)
        assert isinstance(res, dict) and res.get("decision") in ("Allow", "Deny")


# ----------------------------- Негативные сценарии -----------------------------

def test_attributeset_rejects_non_attribute():
    with pytest.raises((TypeError, ValueError)):
        AttributeSet(items=["not-attribute"])  # type: ignore[arg-type]


def test_attributeset_add_overwrite_control(utc_now):
    s = AttributeSet([Attribute(name="x", value=1, namespace="n", created_at=utc_now)])
    # по умолчанию перезаписывает
    s.add(Attribute(name="x", value=2, namespace="n", created_at=utc_now))
    assert s.get("x", "n").value == 2

    # если реализация поддерживает replace=False — обязана бросать/игнорировать
    add_fn = getattr(s, "add", None)
    if add_fn is not None:
        try:
            s.add(Attribute(name="x", value=3, namespace="n", created_at=utc_now), replace=False)  # type: ignore[call-arg]
        except TypeError:
            # интерфейс без replace — ок
            pass
        except ValueError:
            # корректно отвергли перезапись
            assert s.get("x", "n").value == 2


def test_attribute_namespace_defaulting(utc_now):
    a = Attribute(name="x", value=1, created_at=utc_now)
    ns = a.namespace or "default"
    assert a.key() == (ns, "x")


# ----------------------------- Краевые случаи -----------------------------

def test_attribute_handles_large_values(utc_now):
    big_list = list(range(10_000))
    a = Attribute(name="big", value=big_list, created_at=utc_now, namespace="n")
    d = a.to_dict()
    assert len(d["value"]) == 10_000
    assert_json_serializable(d)


def test_attribute_float_precision(utc_now):
    a = Attribute(name="pi", value=math.pi, created_at=utc_now)
    b = Attribute.from_dict(a.to_dict())
    assert isinstance(b.value, float)
    assert abs(b.value - math.pi) < 1e-12


@pytest.mark.parametrize("ns", [None, "default", "subject", "resource", "env"])
def test_attribute_key_stability(ns, utc_now):
    a = Attribute(name="k", value=True, namespace=ns, created_at=utc_now)
    ns_eff = ns or "default"
    assert a.key() == (ns_eff, "k")
