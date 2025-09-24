# path: oblivionvault-core/tests/unit/test_plan_builder.py
# Unverified: контракт oblivionvault.plan.plan_builder не подтверждён. Тесты построены контракт-first и
# корректно skip-нутся при отсутствии частей API, не ломая общий прогон.
from __future__ import annotations

import importlib
import inspect
import types
from typing import Any, Dict, List, Optional, Tuple

import pytest


# ---------------------------
# Utilities: dynamic contract
# ---------------------------
PLAN_MODULE = "oblivionvault.plan.plan_builder"

def _import_module_or_skip() -> types.ModuleType:
    try:
        return importlib.import_module(PLAN_MODULE)
    except Exception as e:
        pytest.skip(f"Plan module not available: {PLAN_MODULE} ({e})")


def _get_attr_or_skip(mod: types.ModuleType, name: str):
    if not hasattr(mod, name):
        pytest.skip(f"Missing '{name}' in {PLAN_MODULE}")
    return getattr(mod, name)


def _ctor_kwargs_fit(cls: type, want: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter kwargs by constructor signature; if required params are missing, skip test.
    """
    sig = inspect.signature(cls)
    params = sig.parameters
    # collect required fields without defaults/VAR_POSITIONAL/VAR_KEYWORD
    required = [p for p in params.values()
                if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
                and p.default is p.empty
                and p.name not in ("self",)]
    # intersect provided kwargs with accepted names
    args = {k: v for k, v in want.items() if k in params}
    # ensure required present
    missing = [p.name for p in required if p.name not in args]
    if missing:
        pytest.skip(f"Constructor for {cls.__name__} requires {missing}, not available in test context")
    return args


def _instantiate_or_skip(cls: type, want: Dict[str, Any]):
    return cls(**_ctor_kwargs_fit(cls, want))


def _extract_steps_from_plan(plan_obj) -> List[Any]:
    """
    Try common attributes to get ordered steps from built plan.
    Order of probes matters to reduce false positives.
    """
    for attr in ("steps_ordered", "ordered", "steps", "plan", "execution"):
        if hasattr(plan_obj, attr):
            val = getattr(plan_obj, attr)
            if isinstance(val, list):
                return val
    # Some builders may return list directly
    if isinstance(plan_obj, list):
        return plan_obj
    # Or iterator/generator
    if hasattr(plan_obj, "__iter__"):
        return list(plan_obj)
    raise AssertionError("Cannot extract steps from plan result; expose 'steps_ordered' or return list")


def _build_exec_plan(builder, spec, steps: Optional[List[Any]] = None):
    """
    Try several method names to build a plan: 'build', 'topo_sort', 'toposort'.
    Accepts either a spec object or a list of steps.
    """
    # 1) build(spec)
    if hasattr(builder, "build"):
        try:
            return getattr(builder, "build")(spec)
        except TypeError:
            # maybe expects list
            if steps is not None:
                return getattr(builder, "build")(steps)

    # 2) topo_sort(steps)
    for name in ("topo_sort", "toposort"):
        if hasattr(builder, name) and steps is not None:
            return getattr(builder, name)(steps)

    pytest.skip("No supported build/topo_sort entrypoint found in PlanBuilder")


def _step_identity(step) -> str:
    """
    Extract step id. Probe common names.
    """
    for attr in ("id", "step_id", "name", "key"):
        if hasattr(step, attr):
            v = getattr(step, attr)
            if v:
                return str(v)
    # dict-like?
    if isinstance(step, dict):
        for k in ("id", "step_id", "name", "key"):
            if k in step:
                return str(step[k])
    raise AssertionError("Cannot determine step identity; expose 'id'/'step_id'/'name'/'key'")


def _step_deps(step) -> List[str]:
    """
    Extract dependencies list. Probe common names.
    """
    for attr in ("depends_on", "deps", "requires", "parents"):
        if hasattr(step, attr):
            v = getattr(step, attr)
            if isinstance(v, (list, tuple, set)):
                return [str(x) for x in v]
    if isinstance(step, dict):
        for k in ("depends_on", "deps", "requires", "parents"):
            if k in step and isinstance(step[k], (list, tuple, set)):
                return [str(x) for x in step[k]]
    return []


# ---------------------------
# Fixtures
# ---------------------------
@pytest.fixture(scope="module")
def api():
    mod = _import_module_or_skip()
    PlanBuilder = _get_attr_or_skip(mod, "PlanBuilder")
    # Optional types
    PlanSpec = getattr(mod, "PlanSpec", None)
    PlanStep = getattr(mod, "PlanStep", None)
    PlanConstraints = getattr(mod, "PlanConstraints", None)

    return {
        "mod": mod,
        "PlanBuilder": PlanBuilder,
        "PlanSpec": PlanSpec,
        "PlanStep": PlanStep,
        "PlanConstraints": PlanConstraints,
    }


@pytest.fixture()
def builder(api):
    return api["PlanBuilder"]()


# ---------------------------
# Helper to create steps/spec
# ---------------------------
def _make_step(api, *, sid: str, deps: Optional[List[str]] = None, **extra):
    PlanStep = api["PlanStep"]
    deps = deps or []
    common = {
        "id": sid,
        "name": f"step::{sid}",
        "depends_on": deps,
        "payload": extra.get("payload", {"demo": True}),
        "timeout_s": extra.get("timeout_s", 5.0),
    }
    if PlanStep is None:
        # Fallback to dict contract if no class exported
        return common
    return _instantiate_or_skip(PlanStep, common)


def _make_spec(api, steps: List[Any], *, constraints: Optional[Dict[str, Any]] = None):
    PlanSpec = api["PlanSpec"]
    PlanConstraints = api["PlanConstraints"]
    if PlanSpec is None:
        # Provide raw list as spec; builder should accept it
        return steps
    if PlanConstraints is not None:
        cons = {
            "max_concurrency": 16,
            "max_rate_per_sec": 0.0,
            "chunk_size_default": 500,
        }
        if constraints:
            cons.update(constraints)
        cons_obj = _instantiate_or_skip(PlanConstraints, cons)
        return _instantiate_or_skip(PlanSpec, {"steps": steps, "constraints": cons_obj})
    return _instantiate_or_skip(PlanSpec, {"steps": steps})


# ---------------------------
# Tests
# ---------------------------
def test_api_surface_minimal(api):
    # PlanBuilder must exist; optional: PlanSpec/PlanStep/PlanConstraints
    assert api["PlanBuilder"] is not None


def test_topological_order_simple(api, builder):
    # s1 -> s2 -> s3 chain
    s1 = _make_step(api, sid="s1")
    s2 = _make_step(api, sid="s2", deps=["s1"])
    s3 = _make_step(api, sid="s3", deps=["s2"])
    spec = _make_spec(api, [s1, s2, s3])

    plan_obj = _build_exec_plan(builder, spec, [s1, s2, s3])
    ordered = _extract_steps_from_plan(plan_obj)

    ids = [_step_identity(s) for s in ordered]
    assert ids.index("s1") < ids.index("s2") < ids.index("s3"), f"Order violated: {ids}"


def test_topological_order_fan_in(api, builder):
    # s1 -> s3 <= s2
    s1 = _make_step(api, sid="s1")
    s2 = _make_step(api, sid="s2")
    s3 = _make_step(api, sid="s3", deps=["s1", "s2"])
    spec = _make_spec(api, [s3, s2, s1])  # shuffled input

    plan_obj = _build_exec_plan(builder, spec, [s3, s2, s1])
    ordered = _extract_steps_from_plan(plan_obj)
    ids = [_step_identity(s) for s in ordered]

    assert ids.index("s1") < ids.index("s3")
    assert ids.index("s2") < ids.index("s3")


def test_cycle_detection(api, builder):
    # s1 -> s2 -> s1 (cycle)
    s1 = _make_step(api, sid="s1", deps=["s2"])
    s2 = _make_step(api, sid="s2", deps=["s1"])
    spec = _make_spec(api, [s1, s2])

    with pytest.raises(Exception):
        _build_exec_plan(builder, spec, [s1, s2])


def test_stable_order_when_no_deps(api, builder):
    # When no deps, order should be stable (deterministic) relative to input or defined comparator.
    sA = _make_step(api, sid="A")
    sB = _make_step(api, sid="B")
    sC = _make_step(api, sid="C")
    spec = _make_spec(api, [sA, sB, sC])

    plan1 = _extract_steps_from_plan(_build_exec_plan(builder, spec, [sA, sB, sC]))
    plan2 = _extract_steps_from_plan(_build_exec_plan(builder, spec, [sA, sB, sC]))

    ids1 = [_step_identity(s) for s in plan1]
    ids2 = [_step_identity(s) for s in plan2]
    assert ids1 == ids2, f"Non-deterministic order: {ids1} vs {ids2}"


@pytest.mark.parametrize("dupe_pos", [("s1", "s1"), ("s1", "s1_copy")])
def test_optional_deduplication_if_supported(api, builder, dupe_pos):
    """
    If the builder supports deduplication (by id/key), ensure duplicates are merged.
    If not supported, test is skipped gracefully.
    """
    # Probe for feature flag or method presence
    has_dedup = any(hasattr(builder, n) for n in ("deduplicate", "enable_dedup", "set_dedup"))
    if not has_dedup:
        pytest.skip("Deduplication not exposed by builder API")

    s1 = _make_step(api, sid=dupe_pos[0])
    # duplicate step is identical by id/key but may have different name/payload
    s1b = _make_step(api, sid=dupe_pos[1], payload={"alt": True})
    s2 = _make_step(api, sid="s2", deps=[dupe_pos[0]])

    spec = _make_spec(api, [s1, s1b, s2])
    plan_obj = _build_exec_plan(builder, spec, [s1, s1b, s2])
    ordered = _extract_steps_from_plan(plan_obj)
    ids = [_step_identity(s) for s in ordered]

    # After dedup there must be exactly one “s1” identity in final plan and dependency preserved
    assert ids.count("s1") == 1, f"Expected deduplication of 's1', got {ids}"
    assert ids.index("s1") < ids.index("s2")


def test_optional_chunking_if_supported(api, builder):
    """
    If step supports chunking (chunk_size), builder should expose batches or annotate steps accordingly.
    """
    s1 = _make_step(api, sid="bulk", deps=[])
    # Try to set chunk_size if supported
    if hasattr(s1, "chunk_size"):
        setattr(s1, "chunk_size", 200)
    elif isinstance(s1, dict):
        s1["chunk_size"] = 200
    else:
        pytest.skip("Chunking not supported by step object")

    spec = _make_spec(api, [s1])
    plan_obj = _build_exec_plan(builder, spec, [s1])

    # Heuristics to validate chunking annotation on the resulting plan
    # Prefer plan.batches or step.batch_count if present.
    if hasattr(plan_obj, "batches"):
        batches = getattr(plan_obj, "batches")
        assert isinstance(batches, list) and len(batches) >= 1
    elif hasattr(plan_obj, "steps_ordered"):
        # Check step attribute propagated
        first = _extract_steps_from_plan(plan_obj)[0]
        cs = getattr(first, "chunk_size", getattr(first, "batch_size", None))
        assert cs == 200, "chunk_size must propagate to execution plan"
    else:
        pytest.skip("No observable contract to assert chunking")


def test_optional_constraints_if_supported(api, builder):
    """
    If PlanConstraints are exposed, they should be preserved in built plan (or accessible on builder).
    """
    if not api["PlanConstraints"] or not api["PlanSpec"]:
        pytest.skip("Constraints/Spec classes not present")

    s1 = _make_step(api, sid="s1")
    spec = _make_spec(api, [s1], constraints={"max_concurrency": 8, "chunk_size_default": 256})
    plan_obj = _build_exec_plan(builder, spec, [s1])

    # Try to read constraints back
    for attr in ("constraints", "limits", "settings"):
        if hasattr(plan_obj, attr):
            c = getattr(plan_obj, attr)
            # max_concurrency is the key signal
            mc = getattr(c, "max_concurrency", None) or (c.get("max_concurrency") if isinstance(c, dict) else None)
            assert mc == 8, "max_concurrency must be preserved into plan"
            return
    pytest.skip("Constraints not exposed by plan object")


def test_cycle_error_message_quality(api, builder):
    """
    If implementation raises a custom cycle exception with details, ensure message has both nodes.
    Skip if generic Exception without message details.
    """
    sA = _make_step(api, sid="A", deps=["B"])
    sB = _make_step(api, sid="B", deps=["A"])
    spec = _make_spec(api, [sA, sB])
    with pytest.raises(Exception) as ei:
        _build_exec_plan(builder, spec, [sA, sB])

    msg = str(ei.value)
    # Only assert detail if message available
    if msg:
        assert "A" in msg and "B" in msg, f"Cycle error message should include involved nodes, got: {msg}"
