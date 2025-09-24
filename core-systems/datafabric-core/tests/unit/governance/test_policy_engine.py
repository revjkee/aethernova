# tests/unit/governance/test_policy_engine.py
# -*- coding: utf-8 -*-
import asyncio
import time
import types
import pytest

# Гибкий импорт (в зависимости от структуры проекта)
try:
    from adapters.policy_adapter import (
        Policy, Rule, Obligation, PolicyStore, InMemorySource, StoreConfig,
        PolicyEngine, PIPRegistry, Decision
    )
except Exception:
    from datafabric.adapters.policy_adapter import (  # type: ignore
        Policy, Rule, Obligation, PolicyStore, InMemorySource, StoreConfig,
        PolicyEngine, PIPRegistry, Decision
    )

pytestmark = [pytest.mark.asyncio]

def _engine_from_rules(rules, ttl_seconds: int = 300):
    pol = Policy(id="test", version="1", rules=list(rules), ttl_seconds=ttl_seconds)
    store = PolicyStore(InMemorySource(pol), StoreConfig(ttl_seconds=ttl_seconds, bg_refresh=False))
    return PolicyEngine(store)

# ---------------------------
# Базовые матчи и условия
# ---------------------------

async def test_allow_by_role_action_resource_and_condition():
    engine = _engine_from_rules([
        Rule(
            id="allow_read_orders",
            effect="allow",
            actions=["read"],
            resources=["table:orders:*"],
            subjects=["analyst"],
            condition={"lte": ["${context.amount}", 100]},
            obligations=[Obligation(key="mask", value=True)],
            priority=10,
        )
    ])
    dec: Decision = await engine.decide(
        subject={"id": "u1", "roles": ["analyst", "eu"]},
        action="read",
        resource="table:orders:eu",
        context={"amount": 42},
    )
    assert dec.effect == "allow"
    assert dec.matched_rule == "allow_read_orders"
    assert any(r.startswith("lte:") for r in dec.reasons)
    assert dec.obligations.get("mask") is True

async def test_deny_by_condition_and_priority():
    engine = _engine_from_rules([
        Rule(
            id="deny_export_high",
            effect="deny",
            actions=["export"],
            resources=["table:orders:*"],
            subjects=["*"],
            condition={"gt": ["${context.amount}", 1000]},
            priority=5,
        ),
        Rule(
            id="allow_export_default",
            effect="allow",
            actions=["export"],
            resources=["table:*"],
            subjects=["*"],
            priority=50,
        ),
    ])
    dec = await engine.decide(
        subject={"id": "u2", "roles": ["analyst"]},
        action="export",
        resource="table:orders:eu",
        context={"amount": 5000},
    )
    assert dec.effect == "deny"
    assert dec.matched_rule == "deny_export_high"
    assert any("gt:True" in r or "gt:True".lower() in r.lower() for r in dec.reasons)

async def test_not_applicable_when_no_rule_matches():
    engine = _engine_from_rules([
        Rule(
            id="only_read",
            effect="allow",
            actions=["read"],
            resources=["table:orders:*"],
            subjects=["analyst"],
        )
    ])
    dec = await engine.decide(
        subject={"id": "u3", "roles": ["analyst"]},
        action="delete",
        resource="table:orders:eu",
        context={},
    )
    assert dec.effect == "not_applicable"
    assert dec.matched_rule is None
    assert "no_rule_matched" in dec.reasons

async def test_subject_match_by_id_and_roles_and_glob():
    engine = _engine_from_rules([
        Rule(
            id="allow_star",
            effect="allow",
            actions=["read"],
            resources=["table:users:*"],
            subjects=["ali*", "ops"],
        )
    ])
    # По id (glob)
    dec1 = await engine.decide({"id": "alice"}, "read", "table:users:eu", {})
    # По роли
    dec2 = await engine.decide({"id": "bob", "roles": ["ops"]}, "read", "table:users:eu", {})
    assert dec1.effect == "allow" and dec2.effect == "allow"

async def test_condition_any_all_not_regex_startswith_contains():
    engine = _engine_from_rules([
        Rule(
            id="complex",
            effect="allow",
            actions=["read"],
            resources=["table:users:*"],
            subjects=["*"],
            condition={
                "all": [
                    {"regex": ["${resource}", r"^table:users:eu$"]},
                    {"any": [
                        {"startswith": ["${subject.department}", "fin"]},
                        {"contains": ["${context.tags}", "allow"]}
                    ]},
                    {"not": {"lt": ["${context.score}", 50]}}
                ]
            },
        )
    ])
    dec = await engine.decide(
        {"id": "u", "department": "finance"},
        "read",
        "table:users:eu",
        {"tags": "preallow", "score": 77},
    )
    assert dec.effect == "allow"
    assert dec.matched_rule == "complex"
    # проверяем, что объяснимость есть
    assert any("any:true" in r for r in dec.reasons)

# ---------------------------
# Приоритеты и обязательства
# ---------------------------

async def test_priority_low_number_wins_and_obligations_collected():
    engine = _engine_from_rules([
        Rule(id="r_high_pri", effect="allow", actions=["read"], resources=["*"], subjects=["*"], priority=1,
             obligations=[Obligation("watermark", "high")]),
        Rule(id="r_low_pri", effect="deny", actions=["read"], resources=["*"], subjects=["*"], priority=100),
    ])
    dec = await engine.decide({"id": "u"}, "read", "anything", {})
    assert dec.effect == "allow"
    assert dec.matched_rule == "r_high_pri"
    assert dec.obligations.get("watermark") == "high"

# ---------------------------
# PIP обогащение
# ---------------------------

async def test_pip_enrichment_adds_role_to_subject_and_allows():
    # Политика требует роль 'pip'
    rules = [Rule(id="pip_allow", effect="allow", actions=["read"], resources=["*"], subjects=["pip"])]
    pol = Policy(id="pip", version="1", rules=rules, ttl_seconds=300)
    store = PolicyStore(InMemorySource(pol), StoreConfig(bg_refresh=False))
    pips = PIPRegistry()

    def add_role(bundle):
        subj = dict(bundle["subject"])
        roles = set(subj.get("roles", [])) | {"pip"}
        subj["roles"] = sorted(roles)
        return {"subject": subj}

    pips.register("add_role", add_role, async_fn=False)
    engine = PolicyEngine(store, pips=pips)

    dec = await engine.decide({"id": "u"}, "read", "*", {})
    assert dec.effect == "allow"
    assert dec.matched_rule == "pip_allow"

# ---------------------------
# Store / TTL / ETag обновление
# ---------------------------

class _DummySource:
    name = "dummy"
    def __init__(self):
        self._step = 0
    async def load(self):
        self._step += 1
        if self._step == 1:
            return Policy(id="p", version="1", rules=[Rule(id="r1", effect="allow", actions=["*"], resources=["*"], subjects=["*"])], ttl_seconds=300, etag="A")
        else:
            return Policy(id="p", version="2", rules=[Rule(id="r2", effect="deny", actions=["*"], resources=["*"], subjects=["*"])], ttl_seconds=300, etag="B")

async def test_store_refreshes_when_etag_changes_without_waiting_ttl():
    src = _DummySource()
    store = PolicyStore(src, StoreConfig(bg_refresh=False, min_refresh_interval_s=0))
    engine = PolicyEngine(store)

    # Первый get — версия 1
    d1 = await engine.decide({"id":"u"}, "read", "*", {})
    assert d1.policy_version == "1"
    # Сбросим внутренние таймеры, чтобы форсировать перезагрузку
    store._next_expire = 0
    store._last_fetch = 0
    d2 = await engine.decide({"id":"u"}, "read", "*", {})
    assert d2.policy_version == "2"
    assert d2.matched_rule == "r2"
    assert d2.effect == "deny"

# ---------------------------
# Валидация схемы (опционально)
# ---------------------------

async def test_schema_validation_rejects_invalid_policy_when_jsonschema_installed():
    jsonschema = pytest.importorskip("jsonschema")
    # Источник будет возвращать политику с версией 'X' (не число), а схема потребует число-строку из цифр
    class BadSource:
        name = "bad"
        async def load(self):
            return Policy(id="p", version="X", rules=[], ttl_seconds=300, etag="E")

    schema = {
        "type": "object",
        "required": ["id", "version", "ttl_seconds", "rules"],
        "properties": {
            "id": {"type": "string"},
            "version": {"type": "string", "pattern": "^[0-9]+$"},
            "ttl_seconds": {"type": "number"},
            "rules": {"type": "array"},
        },
        "additionalProperties": True,
    }

    store = PolicyStore(BadSource(), StoreConfig(validate_schema=True, schema=schema, bg_refresh=False))
    engine = PolicyEngine(store)
    with pytest.raises(Exception):
        await engine.decide({"id": "u"}, "read", "*", {})

# ---------------------------
# Регрессионные проверки reasons/latency
# ---------------------------

async def test_decision_exposes_reasons_and_latency_ms():
    engine = _engine_from_rules([
        Rule(
            id="r",
            effect="allow",
            actions=["read"],
            resources=["*"],
            subjects=["*"],
            condition={"eq":["${action}","read"]},
        )
    ])
    dec = await engine.decide({"id":"u"}, "read", "res", {})
    assert dec.effect == "allow"
    assert dec.matched_rule == "r"
    assert isinstance(dec.latency_ms, float) and dec.latency_ms >= 0.0
    assert any(r.startswith("eq:") for r in dec.reasons)
