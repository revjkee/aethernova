# zero-trust-core/tests/unit/test_posture_eval.py
# -*- coding: utf-8 -*-
"""
Contract-style unit tests for Zero-Trust posture evaluation.

These tests:
- Discover posture engine API dynamically (evaluate/evaluate_posture/PolicyEngine.evaluate).
- Enforce Zero Trust invariants: default deny, explicit allow, evidence and reasons present.
- Validate key policy dimensions: MFA, patch level, risk score, network zone, attestation age and issuer.
- Check robustness to missing fields and PII redaction in reports.
- Ensure idempotency and basic performance within reasonable bounds.

Dependencies: pytest (stdlib only otherwise).
"""

from __future__ import annotations

import importlib
import inspect
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

import pytest


# -------------------------
# Discovery / Adapter Layer
# -------------------------

class EvalAdapter:
    """
    Normalizes different posture-eval APIs to a single callable signature:
        evaluate(context: dict, policies: list[dict]) -> (decision: str, report: dict)
    Decision is normalized to 'allow' or 'deny' (lowercase).
    """
    def __init__(self, mod: Any):
        self.mod = mod
        self._callable = None
        self._instance = None
        self._resolve()

    @staticmethod
    def _normalize_decision(dec: Any) -> str:
        if dec is None:
            return "deny"
        if isinstance(dec, bool):
            return "allow" if dec else "deny"
        s = str(getattr(dec, "value", dec)).lower()
        if "allow" in s or s.endswith("allowed"):
            return "allow"
        if "deny" in s or "denied" in s or "block" in s:
            return "deny"
        # fallback: truthy -> allow
        return "allow" if s.strip() in {"1", "true", "ok", "pass"} else "deny"

    def _resolve(self) -> None:
        # Priority 1: top-level function names
        for name in ("evaluate", "evaluate_posture", "evaluate_policies", "eval_posture"):
            fn = getattr(self.mod, name, None)
            if callable(fn):
                self._callable = fn
                return
        # Priority 2: PolicyEngine class with evaluate()
        for cname in ("PolicyEngine", "PostureEngine", "Engine"):
            cls = getattr(self.mod, cname, None)
            if cls and inspect.isclass(cls):
                try:
                    self._instance = cls()  # assume default ctor
                    if hasattr(self._instance, "evaluate") and callable(self._instance.evaluate):
                        self._callable = self._instance.evaluate
                        return
                except Exception:
                    continue
        raise RuntimeError("No suitable evaluate function/class found in posture module")

    def evaluate(self, context: Mapping[str, Any], policies: List[Mapping[str, Any]]) -> Tuple[str, Dict[str, Any]]:
        # Try to be tolerant to extra kwargs like 'now' etc.
        fn = self._callable
        sig = inspect.signature(fn)
        kwargs = {}
        if "policies" in sig.parameters:
            # positional style (context, policies)
            pass
        if "now" in sig.parameters:
            kwargs["now"] = datetime.now(timezone.utc)
        if "environment" in sig.parameters:
            kwargs["environment"] = context.get("environment", "prod")

        try:
            if self._instance is not None and fn is self._instance.evaluate:
                res = fn(context, policies, **kwargs)
            else:
                res = fn(context, policies, **kwargs)
        except TypeError:
            # Fallback: maybe order (policies, context)
            res = fn(policies, context, **kwargs)

        # Normalize outputs
        decision = None
        report: Dict[str, Any] = {}
        if isinstance(res, tuple) and len(res) == 2:
            decision, report = res
        elif isinstance(res, dict):
            report = res
            decision = res.get("decision") or res.get("result") or res.get("status")
        else:
            # object?
            decision = getattr(res, "decision", None) or getattr(res, "result", None)
            try:
                report = dict(getattr(res, "report", {}) or {})
            except Exception:
                report = {}
        return self._normalize_decision(decision), report


def _import_posture_module() -> Any:
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
    pytest.skip("Posture evaluation module not found in known locations")


@pytest.fixture(scope="module")
def adapter() -> EvalAdapter:
    mod = _import_posture_module()
    try:
        return EvalAdapter(mod)
    except Exception as e:
        pytest.skip(f"Cannot adapt posture module API: {e}")


# -------------------------
# Test Fixtures / Generators
# -------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def attestation(ts: datetime, issuer: str = "ca:root", ok: bool = True) -> Dict[str, Any]:
    return {
        "timestamp": int(ts.timestamp()),
        "issuer": issuer,
        "signature": "valid" if ok else "invalid",
        "evidence": {"tpm": True, "secure_boot": True},
    }


def base_context(ok: bool = True) -> Dict[str, Any]:
    ts = now_utc()
    return {
        "user": {
            "id": "u-1",
            "role": "employee",
            "mfa": True if ok else False,
            "email": "user@example.org",
            "password": "S3cr3t!",  # should never leak into report
        },
        "device": {
            "id": "d-1",
            "os": "Linux",
            "patched": True if ok else False,
            "secure_boot": True,
            "attestation": attestation(ts - timedelta(seconds=60 if ok else 3600), issuer="ca:root", ok=ok),
        },
        "network": {"zone": "corp" if ok else "unknown", "ip": "10.0.0.5"},
        "risk": {"score": 12 if ok else 80},
        "environment": "prod",
    }


def baseline_policies() -> List[Dict[str, Any]]:
    """
    Abstract policy schema; engine may internally map it to its own types.
    Tests rely only on intuitive keys.
    """
    return [
        {"id": "require_mfa", "rule": {"user.mfa": True}, "effect": "allow"},
        {"id": "require_patched", "rule": {"device.patched": True}, "effect": "allow"},
        {"id": "restrict_risk", "rule": {"risk.score_max": 50}, "effect": "allow"},
        {"id": "network_zone", "rule": {"network.zone_in": ["corp", "office"]}, "effect": "allow"},
        {"id": "attest_fresh", "rule": {"device.attestation.max_age_s": 300, "device.attestation.issuer_in": ["ca:root"]}, "effect": "allow"},
        {"id": "default", "rule": "default", "effect": "deny"},
    ]


# -------------------------
# Tests
# -------------------------

def _decision_and_report(adapter: EvalAdapter, ctx: Mapping[str, Any], pol: List[Mapping[str, Any]]):
    decision, report = adapter.evaluate(ctx, pol)
    assert decision in {"allow", "deny"}
    assert isinstance(report, dict)
    return decision, report


def _assert_reasons_present(report: Mapping[str, Any]):
    # Accept multiple shapes: ["reason1", ...] or {"reasons":[...]} or {"why":[...]}
    reasons = report.get("reasons") or report.get("why") or report.get("explanations") or []
    if isinstance(reasons, dict):
        reasons = list(reasons.values())
    assert isinstance(reasons, list)
    assert all(isinstance(x, str) for x in reasons) or len(reasons) == 0
    return reasons


def _assert_no_secrets(report: Mapping[str, Any]):
    dump = str(report).lower()
    banned = ["password", "secret", "token", "authorization", "set-cookie", "private_key"]
    for b in banned:
        assert b not in dump, f"PII/secret leaked in report: {b}"


def test_default_deny_when_no_policies(adapter: EvalAdapter):
    ctx = base_context(ok=True)
    dec, rep = _decision_and_report(adapter, ctx, [])
    assert dec == "deny", "Zero Trust requires deny by default when policies are absent"
    _assert_no_secrets(rep)


@pytest.mark.parametrize("field_path, bad_value", [
    ("user.mfa", False),
    ("device.patched", False),
    ("network.zone", "unknown"),
    ("risk.score", 75),
])
def test_deny_on_key_controls_violation(adapter: EvalAdapter, field_path: str, bad_value: Any):
    ctx = base_context(ok=True)
    # Mutate context
    target, leaf = field_path.rsplit(".", 1)
    node = ctx
    for part in target.split("."):
        node = node[part]
    node[leaf] = bad_value
    dec, rep = _decision_and_report(adapter, ctx, baseline_policies())
    assert dec == "deny"
    reasons = _assert_reasons_present(rep)
    assert reasons or rep, "Deny should include reasons/evidence"
    _assert_no_secrets(rep)


def test_allow_when_all_requirements_met(adapter: EvalAdapter):
    ctx = base_context(ok=True)
    dec, rep = _decision_and_report(adapter, ctx, baseline_policies())
    assert dec == "allow"
    _assert_no_secrets(rep)


def test_deny_on_stale_attestation(adapter: EvalAdapter):
    ctx = base_context(ok=True)
    # make attestation too old
    ctx["device"]["attestation"] = attestation(now_utc() - timedelta(seconds=3600), issuer="ca:root", ok=True)
    dec, rep = _decision_and_report(adapter, ctx, baseline_policies())
    assert dec == "deny"
    reasons = _assert_reasons_present(rep)
    assert any("attest" in r.lower() or "age" in r.lower() for r in reasons), "Expected attestation age reason"
    _assert_no_secrets(rep)


def test_deny_on_untrusted_attestor(adapter: EvalAdapter):
    ctx = base_context(ok=True)
    ctx["device"]["attestation"]["issuer"] = "ca:evil"
    dec, rep = _decision_and_report(adapter, ctx, baseline_policies())
    assert dec == "deny"
    reasons = _assert_reasons_present(rep)
    assert any("issuer" in r.lower() or "trust" in r.lower() for r in reasons), "Expected issuer/trust reason"
    _assert_no_secrets(rep)


def test_missing_fields_are_safe_deny(adapter: EvalAdapter):
    ctx = base_context(ok=True)
    # Remove critical fields
    ctx["user"].pop("mfa", None)
    ctx["device"].pop("patched", None)
    dec, rep = _decision_and_report(adapter, ctx, baseline_policies())
    assert dec == "deny", "Missing critical attributes must not yield allow"
    _assert_no_secrets(rep)


def test_idempotency(adapter: EvalAdapter):
    ctx = base_context(ok=False)
    pol = baseline_policies()
    first = adapter.evaluate(ctx, pol)
    second = adapter.evaluate(ctx, pol)
    assert first[0] == second[0], "Decision must be idempotent for identical inputs"
    assert type(first[1]) is type(second[1])


@pytest.mark.slow
def test_basic_performance(adapter: EvalAdapter):
    ctx_ok = base_context(ok=True)
    ctx_bad = base_context(ok=False)
    pol = baseline_policies()
    N = int(os.getenv("ZT_TEST_PERF_N", "200"))  # conservative to avoid CI flakes
    start = time.time()
    # alternate contexts to exercise branches
    for i in range(N):
        adapter.evaluate(ctx_ok if i % 2 == 0 else ctx_bad, pol)
    elapsed = time.time() - start
    # Heuristic envelope: 200 decisions should be well under 1.0s on CI
    assert elapsed < 1.0, f"Posture evaluation too slow: {elapsed:.3f}s for {N} iterations"


def test_report_contains_minimal_evidence(adapter: EvalAdapter):
    ctx = base_context(ok=False)
    dec, rep = _decision_and_report(adapter, ctx, baseline_policies())
    # Accept multiple shapes: report['evidence'] or flattened keys
    ev = rep.get("evidence") or {}
    assert isinstance(rep, dict)
    # At least one of the top-level pillars should appear in evidence/reasons/keys
    snapshot = str(rep).lower()
    assert any(k in snapshot for k in ("user", "device", "network", "risk")), "Expected minimal evidence in report"
    _assert_no_secrets(rep)


@pytest.mark.parametrize("risk, expected", [
    (10, "allow"),
    (40, "allow"),
    (51, "deny"),
    (99, "deny"),
])
def test_risk_threshold(adapter: EvalAdapter, risk: int, expected: str):
    ctx = base_context(ok=True)
    ctx["risk"]["score"] = risk
    dec, _ = _decision_and_report(adapter, ctx, baseline_policies())
    assert dec == expected


def test_network_zone_allowlist(adapter: EvalAdapter):
    ctx = base_context(ok=True)
    for zone in ("corp", "office"):
        ctx["network"]["zone"] = zone
        dec, _ = _decision_and_report(adapter, ctx, baseline_policies())
        assert dec == "allow"
    ctx["network"]["zone"] = "wifi-guest"
    dec, _ = _decision_and_report(adapter, ctx, baseline_policies())
    assert dec == "deny"


def test_no_password_leak_in_any_string_field(adapter: EvalAdapter):
    ctx = base_context(ok=False)
    dec, rep = _decision_and_report(adapter, ctx, baseline_policies())
    # ensure original password is not in any string of report
    assert "S3cr3t!" not in str(rep), "Original secret leaked to report"
    _assert_no_secrets(rep)
