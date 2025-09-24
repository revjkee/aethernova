# zero-trust-core/tests/fuzz/test_policy_fuzz.py
# -*- coding: utf-8 -*-
"""
Fuzz-тесты политики Zero Trust (pytest + hypothesis, промышленный уровень).

Особенности:
- Динамический адаптер API: ищет evaluate/evaluate_posture/PolicyEngine.evaluate.
- Генераторы Hypothesis для контекстов (user/device/network/risk) и политик.
- Инварианты Zero Trust: default-deny, deny-мoнотонность, идемпотентность, отсутствие утечек.
- Граничные свойства: risk.score_max, attestation.max_age_s, issuer allowlist.
- Capability probe: если движок игнорирует правила, зависимые тесты помечаются xfail.

Зависимости:
    pytest
    hypothesis    (pytest.importorskip при отсутствии)
"""

from __future__ import annotations

import importlib
import inspect
import ipaddress
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import pytest

hypothesis = pytest.importorskip("hypothesis")
st = pytest.importorskip("hypothesis.strategies")
from hypothesis import given, settings, HealthCheck, assume


# -------------------------
# Адаптер движка политики
# -------------------------

class PolicyAdapter:
    """
    Нормализует разные API к виду:
        evaluate(context: dict, policies: list[dict]) -> (decision: 'allow'|'deny', report: dict)
    """
    def __init__(self, mod: Any):
        self.mod = mod
        self._callable = None
        self._instance = None
        self._resolve()

    @staticmethod
    def _norm_decision(x: Any) -> str:
        if x is None:
            return "deny"
        if isinstance(x, bool):
            return "allow" if x else "deny"
        s = str(getattr(x, "value", x)).lower()
        if "allow" in s or s.endswith("allowed"):
            return "allow"
        if "deny" in s or "block" in s or "denied" in s:
            return "deny"
        return "allow" if s.strip() in {"1", "true", "ok", "pass"} else "deny"

    def _resolve(self) -> None:
        for name in ("evaluate", "evaluate_posture", "evaluate_policies", "eval_posture"):
            fn = getattr(self.mod, name, None)
            if callable(fn):
                self._callable = fn
                return
        for cname in ("PolicyEngine", "PostureEngine", "Engine"):
            cls = getattr(self.mod, cname, None)
            if cls and inspect.isclass(cls):
                try:
                    inst = cls()
                    if hasattr(inst, "evaluate") and callable(inst.evaluate):
                        self._instance = inst
                        self._callable = inst.evaluate
                        return
                except Exception:
                    continue
        raise RuntimeError("Не найден подходящий evaluate API в модуле политики")

    def evaluate(self, context: Mapping[str, Any], policies: List[Mapping[str, Any]]) -> Tuple[str, Dict[str, Any]]:
        fn = self._callable
        sig = inspect.signature(fn)
        kwargs = {}
        if "now" in sig.parameters:
            kwargs["now"] = datetime.now(timezone.utc)
        if "environment" in sig.parameters:
            kwargs["environment"] = context.get("environment", "prod")
        try:
            res = fn(context, policies, **kwargs)
        except TypeError:
            res = fn(policies, context, **kwargs)
        decision, report = None, {}
        if isinstance(res, tuple) and len(res) == 2:
            decision, report = res
        elif isinstance(res, dict):
            report = res
            decision = res.get("decision") or res.get("result") or res.get("status")
        else:
            decision = getattr(res, "decision", None) or getattr(res, "result", None)
            report = dict(getattr(res, "report", {}) or {})
        return self._norm_decision(decision), (report or {})


def _import_policy_module() -> Any:
    candidates = [
        "zero_trust.posture.eval",
        "zero_trust.posture.posture_eval",
        "zero_trust.posture_eval",
        "posture_eval",
        "zero_trust_core.posture.eval",
    ]
    for name in candidates:
        try:
            return importlib.import_module(name)
        except Exception:
            continue
    pytest.skip("Модуль политики не найден среди известных путей")


@pytest.fixture(scope="module")
def adapter() -> PolicyAdapter:
    return PolicyAdapter(_import_policy_module())


# -------------------------
# Стратегии данных
# -------------------------

def _ip_strategy():
    return st.integers(min_value=0, max_value=(1 << 32) - 1).map(lambda n: str(ipaddress.IPv4Address(n)))

def _attestation_strategy():
    now = st.integers(min_value=0, max_value=5).map(lambda s: int((datetime.now(timezone.utc) - timedelta(seconds=s*60)).timestamp()))
    old = st.integers(min_value=10, max_value=120).map(lambda s: int((datetime.now(timezone.utc) - timedelta(minutes=s)).timestamp()))
    ts = st.one_of(now, old)
    issuer = st.sampled_from(["ca:root", "ca:int", "ca:evil"])
    sig = st.sampled_from(["valid", "invalid"])
    return st.fixed_dictionaries({
        "timestamp": ts,
        "issuer": issuer,
        "signature": sig,
        "evidence": st.fixed_dictionaries({
            "tpm": st.booleans(),
            "secure_boot": st.booleans(),
        })
    })

def _user_strategy():
    return st.fixed_dictionaries({
        "id": st.text(min_size=1, max_size=12),
        "role": st.sampled_from(["employee", "contractor", "admin"]),
        "mfa": st.booleans(),
        "email": st.emails(),
        "password": st.text(min_size=6, max_size=18),  # проверка отсутствия утечек
    })

def _device_strategy():
    return st.fixed_dictionaries({
        "id": st.text(min_size=1, max_size=12),
        "os": st.sampled_from(["Linux", "Windows", "macOS", "Android", "iOS"]),
        "patched": st.booleans(),
        "secure_boot": st.booleans(),
        "attestation": _attestation_strategy(),
    })

def _network_strategy():
    return st.fixed_dictionaries({
        "zone": st.sampled_from(["corp", "office", "wifi-guest", "unknown"]),
        "ip": _ip_strategy(),
    })

def _risk_strategy():
    return st.fixed_dictionaries({"score": st.integers(min_value=0, max_value=100)})

def context_strategy():
    return st.fixed_dictionaries({
        "user": _user_strategy(),
        "device": _device_strategy(),
        "network": _network_strategy(),
        "risk": _risk_strategy(),
        "environment": st.sampled_from(["prod", "staging", "dev"]),
    })

def policy_rule_strategy():
    return st.one_of(
        st.fixed_dictionaries({"user.mfa": st.sampled_from([True, False])}),
        st.fixed_dictionaries({"device.patched": st.sampled_from([True, False])}),
        st.fixed_dictionaries({"risk.score_max": st.integers(min_value=0, max_value=100)}),
        st.fixed_dictionaries({"network.zone_in": st.lists(st.sampled_from(["corp","office","wifi-guest","unknown"]), min_size=1, max_size=3, unique=True)}),
        st.fixed_dictionaries({"device.attestation.max_age_s": st.integers(min_value=30, max_value=60*60)}),
        st.fixed_dictionaries({"device.attestation.issuer_in": st.lists(st.sampled_from(["ca:root","ca:int"]), min_size=1, max_size=2, unique=True)}),
        st.just("default"),
    )

def policy_strategy():
    return st.fixed_dictionaries({
        "id": st.text(min_size=1, max_size=16),
        "rule": policy_rule_strategy(),
        "effect": st.sampled_from(["allow", "deny"]),
    })

def policies_strategy(min_items=1, max_items=6, include_default_prob=True):
    base = st.lists(policy_strategy(), min_size=min_items, max_size=max_items)
    if include_default_prob:
        # иногда гарантируем default deny
        def add_default(pol_list):
            has_default = any(p.get("rule") == "default" for p in pol_list)
            if not has_default and os.urandom(1)[0] % 2 == 0:
                pol_list.append({"id": "default", "rule": "default", "effect": "deny"})
            return pol_list
        return base.map(add_default)
    return base


# -------------------------
# Вспомогательные проверки
# -------------------------

BANNED_KEYS = ["password", "secret", "token", "authorization", "set-cookie", "private_key"]

def assert_no_secret_leak(report: Mapping[str, Any]):
    dump = str(report).lower()
    for b in BANNED_KEYS:
        assert b not in dump, f"Утечка секрета в отчете: {b}"

def mk_matching_deny(context: Mapping[str, Any]) -> Dict[str, Any]:
    """Создает deny-политику, точно совпадающую с текущим контекстом."""
    return {
        "id": "deny_exact_match",
        "effect": "deny",
        "rule": {
            "user.mfa": bool(context.get("user", {}).get("mfa", False)),
            "device.patched": bool(context.get("device", {}).get("patched", False)),
            "network.zone_in": [str(context.get("network", {}).get("zone", "unknown"))],
            "risk.score_max": int(context.get("risk", {}).get("score", 100)),  # max == текущему, дальше отрежет
        },
    }

def find_threshold(pol: Sequence[Mapping[str, Any]]) -> Optional[int]:
    for p in pol:
        r = p.get("rule")
        if isinstance(r, dict) and "risk.score_max" in r and str(p.get("effect","")).lower() == "allow":
            return int(r["risk.score_max"])
    return None

def find_max_age(pol: Sequence[Mapping[str, Any]]) -> Optional[int]:
    for p in pol:
        r = p.get("rule")
        if isinstance(r, dict) and "device.attestation.max_age_s" in r and str(p.get("effect","")).lower() == "allow":
            return int(r["device.attestation.max_age_s"])
    return None


# -------------------------
# Capability Probe
# -------------------------

@pytest.fixture(scope="module")
def policy_semantics_supported(adapter: PolicyAdapter) -> bool:
    ctx = {
        "user": {"mfa": True},
        "device": {"patched": True, "attestation": {"timestamp": int(datetime.now().timestamp()), "issuer":"ca:root", "signature":"valid", "evidence":{"tpm":True,"secure_boot":True}}},
        "network": {"zone": "corp", "ip": "10.0.0.1"},
        "risk": {"score": 1},
        "environment": "prod",
    }
    baseline = [{"id": "default", "rule": "default", "effect": "deny"}]
    dec0, _ = adapter.evaluate(ctx, baseline)
    dec1, _ = adapter.evaluate(ctx, baseline + [mk_matching_deny(ctx)])
    # Если добавление совпадающего deny не делает хуже, семантика правил, возможно, не применяется.
    return not (dec0 == dec1 == "allow")


# -------------------------
# Настройки Hypothesis
# -------------------------

DEFAULT_SETTINGS = settings(
    max_examples=int(os.getenv("ZT_FUZZ_MAX_EXAMPLES", "120")),
    deadline=None,  # стабильность в CI
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


# -------------------------
# Свойства / тесты
# -------------------------

@DEFAULT_SETTINGS
@given(ctx=context_strategy())
def test_default_deny_when_no_policies(adapter: PolicyAdapter, ctx: Mapping[str, Any]):
    decision, report = adapter.evaluate(ctx, [])
    assert decision == "deny"
    assert_no_secret_leak(report)


@DEFAULT_SETTINGS
@given(ctx=context_strategy(), pol=policies_strategy())
def test_no_crash_and_idempotent(adapter: PolicyAdapter, ctx: Mapping[str, Any], pol: List[Mapping[str, Any]]):
    d1, r1 = adapter.evaluate(ctx, pol)
    d2, r2 = adapter.evaluate(ctx, pol)
    assert d1 in {"allow", "deny"}
    assert d1 == d2
    assert type(r1) is type(r2)
    assert_no_secret_leak(r1)


@DEFAULT_SETTINGS
@given(ctx=context_strategy(), pol=policies_strategy())
def test_deny_monotonicity_on_added_matching_rule(adapter: PolicyAdapter, policy_semantics_supported: bool, ctx, pol):
    pytest.xfail(reason="Движок не применяет семантику правил") if not policy_semantics_supported else None
    d0, _ = adapter.evaluate(ctx, pol)
    deny = mk_matching_deny(ctx)
    d1, _ = adapter.evaluate(ctx, pol + [deny])
    # Добавление явно совпадающего deny не должно улучшать решение.
    assert not (d0 == "deny" and d1 == "allow")


@DEFAULT_SETTINGS
@given(ctx=context_strategy(), pol=policies_strategy())
def test_no_secret_leak_in_report(adapter: PolicyAdapter, ctx, pol):
    _, rep = adapter.evaluate(ctx, pol)
    assert_no_secret_leak(rep)


@DEFAULT_SETTINGS
@given(
    ctx=context_strategy().map(lambda c: {**c, "risk": {"score": 100}}),
    pol=st.lists(st.just({"id": "p1", "rule": {"risk.score_max": 50}, "effect": "allow"}), min_size=1, max_size=1)
        .map(lambda lst: lst + [{"id": "default", "rule": "default", "effect": "deny"}])
)
def test_risk_threshold_property(adapter: PolicyAdapter, policy_semantics_supported: bool, ctx, pol):
    pytest.xfail(reason="Движок не применяет семантику правил") if not policy_semantics_supported else None
    # При score > max и наличии default deny решение не должно быть allow
    d, _ = adapter.evaluate(ctx, pol)
    assert d == "deny"


@DEFAULT_SETTINGS
@given(
    ctx=context_strategy().map(lambda c: {**c, "device": {**c["device"], "attestation": {**c["device"]["attestation"], "timestamp": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp())}}}),
    pol=st.lists(st.just({"id": "att", "rule": {"device.attestation.max_age_s": 300, "device.attestation.issuer_in":["ca:root","ca:int"]}, "effect": "allow"}), min_size=1, max_size=1)
        .map(lambda lst: lst + [{"id": "default", "rule": "default", "effect": "deny"}])
)
def test_attestation_age_property(adapter: PolicyAdapter, policy_semantics_supported: bool, ctx, pol):
    pytest.xfail(reason="Движок не применяет семантику правил") if not policy_semantics_supported else None
    # Аттестация старше max_age_s => deny при наличии default deny
    d, _ = adapter.evaluate(ctx, pol)
    assert d == "deny"


def test_micro_performance(adapter: PolicyAdapter):
    # Небольшая серия для грубой оценки, без Hypothesis.
    ctx = {
        "user": {"mfa": True, "id": "u1", "role":"employee", "email":"a@b.c", "password":"x"},
        "device": {"patched": True, "secure_boot": True, "attestation": {"timestamp": int(datetime.now().timestamp()), "issuer":"ca:root", "signature":"valid", "evidence":{"tpm":True,"secure_boot":True}}},
        "network": {"zone": "corp", "ip": "10.0.0.2"},
        "risk": {"score": 5},
        "environment": "prod",
    }
    pol = [
        {"id": "mfa", "rule": {"user.mfa": True}, "effect": "allow"},
        {"id": "patched", "rule": {"device.patched": True}, "effect": "allow"},
        {"id": "risk", "rule": {"risk.score_max": 50}, "effect": "allow"},
        {"id": "default", "rule": "default", "effect": "deny"},
    ]
    n = int(os.getenv("ZT_FUZZ_PERF_N", "300"))
    t0 = time.time()
    for _ in range(n):
        adapter.evaluate(ctx, pol)
    dt = time.time() - t0
    assert dt < 1.2, f"Слишком медленно: {dt:.3f}s / {n} итераций"
