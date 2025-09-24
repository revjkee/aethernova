# cybersecurity-core/tests/fuzz/test_policy_engine_fuzz.py
# -*- coding: utf-8 -*-
"""
Industrial-grade fuzz & property-based tests for a policy engine.

Design goals:
- Zero-crash guarantee under adversarial inputs
- Determinism for identical inputs
- Bounded latency on small inputs
- Decision set sanity if engine exposes a decision field
- Robust autodiscovery of engine API shapes without hard dependencies

These tests are defensive: when optional capabilities are missing,
they xfail/skip rather than produce false negatives.

Requirements:
  pip install pytest hypothesis

Optional:
  HYPOTHESIS_PROFILE=ci to use stricter settings in CI
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import re
import sys
import time
import types
import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple, Union

import pytest
from hypothesis import given, settings, HealthCheck, assume, strategies as st


# ---------------------------
# Engine autodiscovery
# ---------------------------

CANDIDATE_MODULES = (
    # common internal layouts
    "cybersecurity_core.policy.engine",
    "cybersecurity_core.policy.engine_core",
    "cybersecurity_core.policy",
    "cybersecurity_core.engine",
    "cybersecurity_core",
    # generic fallbacks
    "policy.engine",
    "policy_engine",
)

DECISION_METHOD_CANDIDATES = ("evaluate", "decide", "authorize", "enforce", "check")
LOAD_METHOD_CANDIDATES = ("load_policies", "load", "set_policies", "configure")
RESET_METHOD_CANDIDATES = ("reset", "clear", "reload")


@dataclass
class EngineAPI:
    module: types.ModuleType
    instance: Any
    call: Callable[[Any, Dict[str, Any]], Any]
    load: Optional[Callable[[Any, Any], Any]]
    reset: Optional[Callable[[Any], Any]]
    decision_field: Optional[str]
    allowed_decisions: Optional[Tuple[str, ...]]


def _try_import() -> Optional[types.ModuleType]:
    last_err = None
    for name in CANDIDATE_MODULES:
        try:
            return importlib.import_module(name)
        except Exception as e:
            last_err = e
    if last_err:
        pytest.skip(f"Policy engine module not found: {last_err}")
    return None


def _find_class_or_factory(mod: types.ModuleType) -> Any:
    """
    Look for a PolicyEngine class or a factory function.
    """
    # Preferred names
    candidates = (
        "PolicyEngine",
        "Engine",
        "AuthorizationEngine",
        "DecisionEngine",
        "create_engine",
        "make_engine",
        "get_engine",
    )
    for name in candidates:
        if hasattr(mod, name):
            return getattr(mod, name)

    # Heuristic: first class with a likely method
    for _, obj in inspect.getmembers(mod, predicate=inspect.isclass):
        if any(hasattr(obj, m) for m in DECISION_METHOD_CANDIDATES):
            return obj

    for _, obj in inspect.getmembers(mod, predicate=inspect.isfunction):
        if obj.__name__ in {"create", "factory"} or any(
            kw in obj.__name__ for kw in ("engine", "policy")
        ):
            return obj

    pytest.skip("No suitable engine class or factory detected.")


def _instantiate(engine_obj: Any) -> Any:
    """
    Instantiate the engine irrespective of whether we found a class or a factory.
    """
    try:
        if inspect.isclass(engine_obj):
            try:
                return engine_obj()
            except TypeError:
                # try kwargs commonly used
                return engine_obj(config=None)
        elif callable(engine_obj):
            return engine_obj()
    except Exception as e:
        pytest.skip(f"Cannot instantiate engine: {e}")

    pytest.skip("Engine instantiation failed for unknown reason.")


def _bind_api(mod: types.ModuleType, inst: Any) -> EngineAPI:
    # decision call
    call = None
    for m in DECISION_METHOD_CANDIDATES:
        if hasattr(inst, m) and callable(getattr(inst, m)):
            call = getattr(inst, m)
            break
    if call is None:
        pytest.skip("No decision/evaluation method detected on the engine instance.")

    # load (optional)
    load = None
    for m in LOAD_METHOD_CANDIDATES:
        if hasattr(inst, m) and callable(getattr(inst, m)):
            load = getattr(inst, m)
            break

    # reset (optional)
    reset = None
    for m in RESET_METHOD_CANDIDATES:
        if hasattr(inst, m) and callable(getattr(inst, m)):
            reset = getattr(inst, m)
            break

    # decision field and allowed set, if exposed
    decision_field = None
    allowed_decisions = None

    # Common conventions
    for fld in ("decision", "result", "effect", "status"):
        if hasattr(inst, "DECISION_FIELD"):
            decision_field = getattr(inst, "DECISION_FIELD")
            break
        decision_field = fld  # default heuristic, verified later
        break

    if hasattr(inst, "ALLOWED_DECISIONS"):
        ad = getattr(inst, "ALLOWED_DECISIONS")
        if isinstance(ad, (tuple, list)) and all(isinstance(x, str) for x in ad):
            allowed_decisions = tuple(ad)

    return EngineAPI(
        module=mod,
        instance=inst,
        call=call,
        load=load,
        reset=reset,
        decision_field=decision_field,
        allowed_decisions=allowed_decisions,
    )


@pytest.fixture(scope="session")
def engine() -> EngineAPI:
    mod = _try_import()
    eng_obj = _find_class_or_factory(mod)
    inst = _instantiate(eng_obj)
    return _bind_api(mod, inst)


# ---------------------------
# Strategies
# ---------------------------

# ASCII plus selected unicode to tease parser paths but keep it reasonable
_printable_safe = st.text(
    alphabet=st.characters(
        min_codepoint=32, max_codepoint=0x10FFFF, blacklist_categories=("Cs",)
    ),
    min_size=0,
    max_size=256,
)

identifier = st.from_regex(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$", fullmatch=True)

json_scalar = st.one_of(
    st.integers(min_value=-2**31, max_value=2**31 - 1),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    _printable_safe,
    st.booleans(),
    st.none(),
)

json_leaf = json_scalar

json_obj = st.recursive(
    st.dictionaries(keys=identifier | st.sampled_from(["", " ", ".", "..", "$", "*"]), values=json_leaf, max_size=8),
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(keys=identifier, values=children, max_size=8),
    ),
    max_leaves=32,
)

security_strings = st.sampled_from(
    [
        "${jndi:ldap://evil}",
        "' OR 1=1 --",
        "\"; DROP TABLE users;--",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "`cat /etc/shadow`",
        "$(reboot)",
        "${{7*7}}",
        "%0a%0dContent-Length: 0",
        "😀" * 50,
    ]
)

# Minimal request: subject, action, resource shape is common across ABAC/XACML-like engines
access_request = st.fixed_dictionaries(
    {
        "subject": st.dictionaries(keys=identifier, values=json_scalar, max_size=8),
        "action": st.dictionaries(keys=identifier, values=json_scalar, max_size=4),
        "resource": st.dictionaries(keys=identifier, values=json_scalar, max_size=8),
        "context": st.dictionaries(keys=identifier, values=json_scalar, max_size=8),
    }
).map(lambda d: {k: v for k, v in d.items() if v})  # drop empty for variability


# ---------------------------
# Helpers
# ---------------------------

def _stable_serialize(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        return repr(obj)


def _hash(obj: Any) -> str:
    return hashlib.sha256(_stable_serialize(obj).encode("utf-8")).hexdigest()


def _call_engine(api: EngineAPI, request: Dict[str, Any]) -> Any:
    """
    Call with defensive coercions:
    - Attempt dict request
    - If engine expects JSON string, provide one
    - Fall back to kwargs if signature matches
    """
    func = api.call
    sig = None
    try:
        sig = inspect.signature(func)
    except Exception:
        pass

    try:
        if sig:
            params = list(sig.parameters.values())
            if len(params) == 2 and params[1].annotation in (dict, Dict[str, Any], dict | None):
                return func(api.instance, request)  # bound method on instance
            if len(params) == 1:
                # maybe bound method, single param is request
                return func(request)  # type: ignore
        # try JSON string input
        try:
            return func(_stable_serialize(request))  # type: ignore
        except Exception:
            # final attempt: kwargs
            return func(**request)  # type: ignore
    except Exception as e:
        # Do not fail here; upper layers will assert non-crash in the test itself
        raise e


def _extract_decision(api: EngineAPI, result: Any) -> Optional[str]:
    """
    Try to locate a decision field in result.
    Accept str result directly, or dict with known keys.
    """
    if isinstance(result, str):
        return result.lower()

    if isinstance(result, dict):
        candidates = []
        if api.decision_field:
            candidates.append(api.decision_field)
        candidates.extend(["decision", "result", "effect", "status", "outcome"])
        for k in candidates:
            if k in result and isinstance(result[k], str):
                return result[k].lower()
    return None


# ---------------------------
# Hypothesis settings
# ---------------------------

_DEFAULT_DEADLINE_MS = int(os.getenv("FUZZ_DEADLINE_MS", "200"))  # per call budget
_EXAMPLES = int(os.getenv("FUZZ_EXAMPLES", "200"))

common_settings = settings(
    max_examples=_EXAMPLES,
    deadline=_DEFAULT_DEADLINE_MS,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
    derandomize=False,
)


# ---------------------------
# Tests
# ---------------------------

@pytest.mark.fuzz
@common_settings
@given(req=st.one_of(access_request, json_obj))
def test_never_crashes_and_bounded_latency(engine: EngineAPI, req: Dict[str, Any]):
    """
    Property: evaluating arbitrary JSON-like input must not raise,
    and must complete within a small latency budget.
    """
    t0 = time.perf_counter()
    try:
        result = _call_engine(engine, req)
    except Exception as e:
        pytest.fail(f"Engine raised on adversarial input: {e}")
    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000.0
    assert elapsed_ms <= _DEFAULT_DEADLINE_MS * 5, f"Engine too slow: {elapsed_ms:.1f} ms"


@pytest.mark.fuzz
@common_settings
@given(req=access_request)
def test_deterministic_for_same_input(engine: EngineAPI, req: Dict[str, Any]):
    """
    Property: same input yields same output (pure function w.r.t. given state).
    Engines with time/context randomness should still be stable for identical req.
    """
    # Optional reset to neutralize internal caches
    if engine.reset:
        try:
            engine.reset(engine.instance)
        except Exception:
            pytest.xfail("Engine reset not reliable; skipping strict determinism check.")

    r1 = _call_engine(engine, req)
    r2 = _call_engine(engine, req)

    # Compare by normalized serialization to be resilient to dict ordering
    h1, h2 = _hash(r1), _hash(r2)
    assert h1 == h2, f"Non-deterministic output for same input: {h1} != {h2}"


@pytest.mark.fuzz
@common_settings
@given(payload=security_strings, req=access_request)
def test_robust_against_malicious_strings(engine: EngineAPI, payload: str, req: Dict[str, Any]):
    """
    Property: adversarial payloads embedded into fields must not crash or hang.
    """
    # Inject payloads in multiple places
    req = dict(req)
    req.setdefault("context", {})
    req["context"] = dict(req["context"], attacker=payload)
    req.setdefault("subject", {})
    req["subject"] = dict(req["subject"], note=payload)

    try:
        _ = _call_engine(engine, req)
    except Exception as e:
        pytest.fail(f"Engine crashed on adversarial string payload: {payload!r}, error: {e}")


@pytest.mark.fuzz
@common_settings
@given(req=access_request)
def test_decision_membership_if_exposed(engine: EngineAPI, req: Dict[str, Any]):
    """
    Property: if engine exposes a recognizable decision field or returns a string decision,
    the decision must belong to an allowed set if the engine publishes one,
    or to a conservative default set.
    """
    res = _call_engine(engine, req)
    decision = _extract_decision(engine, res)
    assume(decision is not None)

    if engine.allowed_decisions:
        allowed = tuple(d.lower() for d in engine.allowed_decisions)
    else:
        # Conservative common set across ABAC/XACML-like engines
        allowed = ("allow", "deny", "not_applicable", "indeterminate")

    assert decision in allowed, f"Unexpected decision value: {decision!r}, allowed: {allowed}"


@pytest.mark.fuzz
@common_settings
@given(req=access_request)
def test_output_is_json_serializable(engine: EngineAPI, req: Dict[str, Any]):
    """
    Property: engine output should be JSON-serializable for logging/auditing.
    """
    res = _call_engine(engine, req)
    try:
        _ = _stable_serialize(res)
    except Exception as e:
        pytest.fail(f"Engine output not JSON-serializable: {e}")


@pytest.mark.fuzz
@common_settings
@given(req=access_request)
def test_side_effect_free_by_default(engine: EngineAPI, req: Dict[str, Any]):
    """
    Property: evaluation should not mutate the input request in-place.
    """
    canonical = json.loads(_stable_serialize(req))
    _ = _call_engine(engine, req)
    assert req == canonical, "Engine mutated input request object in-place"


# ---------------------------
# Optional: policy loading fuzz
# ---------------------------

policy_condition = st.one_of(
    st.booleans(),
    st.text(min_size=0, max_size=64),
    st.dictionaries(keys=identifier, values=json_scalar, max_size=4),
)

policy_rule = st.fixed_dictionaries(
    {
        "id": identifier,
        "effect": st.sampled_from(["allow", "deny"]),
        "condition": policy_condition,
        "description": _printable_safe.filter(lambda s: len(s) <= 120),
    }
)

policy_bundle = st.fixed_dictionaries(
    {
        "version": st.sampled_from(["1", "1.0", "2025-09"]),
        "rules": st.lists(policy_rule, min_size=0, max_size=10),
        "metadata": st.dictionaries(keys=identifier, values=json_scalar, max_size=6),
    }
)


@pytest.mark.fuzz
@common_settings
@given(bundle=policy_bundle, req=access_request)
def test_loading_random_policies_does_not_crash(engine: EngineAPI, bundle: Dict[str, Any], req: Dict[str, Any]):
    """
    Property: loading arbitrary but well-formed-ish policy bundles must not crash engine.
    If engine lacks policy loading, mark as xfail.
    """
    if not engine.load:
        pytest.xfail("Engine does not expose a policy loading API.")

    # Some engines expect JSON string
    try:
        engine.load(engine.instance, bundle)  # type: ignore
    except TypeError:
        engine.load(engine.instance, _stable_serialize(bundle))  # type: ignore
    except Exception as e:
        # Loading can fail validation; the property is about non-crash behavior
        # but we still want the engine to keep functioning.
        pass

    try:
        _ = _call_engine(engine, req)
    except Exception as e:
        pytest.fail(f"Engine crashed after loading fuzzed policy bundle: {e}")


# ---------------------------
# Diagnostics: smoke test
# ---------------------------

def test_engine_smoke_signature(engine: EngineAPI):
    """
    Sanity-check that the discovered call target is callable.
    """
    assert callable(engine.call), "Engine decision function is not callable"


def test_engine_module_loaded(engine: EngineAPI):
    """
    Ensure module loaded with a non-empty __name__ and file when available.
    """
    assert isinstance(engine.module, types.ModuleType)
    assert getattr(engine.module, "__name__", None)
    # __file__ may be absent for namespace packages; do not assert strictly
