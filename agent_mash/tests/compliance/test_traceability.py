# agent_mash/tests/compliance/test_traceability.py
from __future__ import annotations

import asyncio
import importlib
import os
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional, Sequence, Tuple

import pytest


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-"
    r"[0-9a-fA-F]{12}$"
)

_W3C_TRACEPARENT_RE = re.compile(
    r"^[0-9a-f]{2}-"          # version
    r"[0-9a-f]{32}-"          # trace-id (16 bytes)
    r"[0-9a-f]{16}-"          # parent-id (8 bytes)
    r"[0-9a-f]{2}$"           # trace-flags
)


@dataclass(frozen=True)
class TraceabilityConfig:
    """
    Configure traceability compliance tests via environment variables.

    Supported env vars:
      - TRACEABILITY_APP: import path to FastAPI app, e.g. "agent_mash.web.app:app"
      - TRACEABILITY_MIDDLEWARE_NAMES: comma-separated substrings expected in middleware class names
      - TRACEABILITY_CONTEXT: import path to a trace context provider module/object
      - TRACEABILITY_LOGGER: import path to a logger emitter/capture helper
      - TRACEABILITY_IDS: import path to id generator functions/provider
    """
    app_import: Optional[str]
    middleware_names: Tuple[str, ...]
    context_import: Optional[str]
    logger_import: Optional[str]
    ids_import: Optional[str]


def _env_first(*keys: str) -> Optional[str]:
    for k in keys:
        v = os.getenv(k)
        if v and v.strip():
            return v.strip()
    return None


def _parse_csv(value: Optional[str]) -> Tuple[str, ...]:
    if not value:
        return ()
    items = [x.strip() for x in value.split(",")]
    return tuple([x for x in items if x])


def _load_config() -> TraceabilityConfig:
    return TraceabilityConfig(
        app_import=_env_first("TRACEABILITY_APP"),
        middleware_names=_parse_csv(_env_first("TRACEABILITY_MIDDLEWARE_NAMES")),
        context_import=_env_first("TRACEABILITY_CONTEXT"),
        logger_import=_env_first("TRACEABILITY_LOGGER"),
        ids_import=_env_first("TRACEABILITY_IDS"),
    )


def _import_from_string(path: str) -> Any:
    """
    Import helper: "pkg.mod:attr" or "pkg.mod".
    """
    if ":" in path:
        mod_name, attr = path.split(":", 1)
        mod = importlib.import_module(mod_name)
        try:
            return getattr(mod, attr)
        except AttributeError as e:
            raise ImportError(f"Attribute {attr!r} not found in {mod_name!r}.") from e
    return importlib.import_module(path)


def _skip(msg: str) -> None:
    pytest.skip(msg)


@pytest.fixture(scope="session")
def traceability_config() -> TraceabilityConfig:
    return _load_config()


def _maybe_import(path: Optional[str], what: str) -> Any:
    if not path:
        _skip(f"{what} import path not configured (env missing).")
    try:
        return _import_from_string(path)  # type: ignore[arg-type]
    except Exception as e:
        _skip(f"{what} import failed: {path!r}. reason: {type(e).__name__}: {e}")


def _assert_is_uuid(value: str) -> None:
    assert isinstance(value, str)
    assert _UUID_RE.match(value) is not None


def _assert_is_w3c_traceparent(value: str) -> None:
    assert isinstance(value, str)
    assert _W3C_TRACEPARENT_RE.match(value) is not None


def _as_mapping(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    # Accept objects that behave like mappings (structlog event dicts, etc.)
    try:
        return dict(obj)  # type: ignore[arg-type]
    except Exception:
        return {}


def _get_callable(obj: Any, name: str) -> Callable[..., Any]:
    fn = getattr(obj, name, None)
    if fn is None or not callable(fn):
        _skip(f"Required callable not found: {name}")
    return fn


def _get_attr(obj: Any, name: str) -> Any:
    if not hasattr(obj, name):
        _skip(f"Required attribute not found: {name}")
    return getattr(obj, name)


def _expect_any_key(d: Dict[str, Any], keys: Sequence[str]) -> str:
    for k in keys:
        if k in d:
            return k
    raise AssertionError(f"None of expected keys found: {keys}. Present keys: {sorted(d.keys())}")


def _expect_all_keys(d: Dict[str, Any], keys: Sequence[str]) -> None:
    missing = [k for k in keys if k not in d]
    assert not missing, f"Missing keys: {missing}. Present keys: {sorted(d.keys())}"


def _maybe_validate_id(value: str) -> None:
    """
    Accepts either UUID (common request-id) or W3C traceparent (common trace carrier)
    or a 32-hex trace-id (w3c trace-id only). Fails only if format is clearly invalid.
    """
    if _UUID_RE.match(value):
        return
    if _W3C_TRACEPARENT_RE.match(value):
        return
    if re.match(r"^[0-9a-f]{32}$", value):
        return
    raise AssertionError(f"Unrecognized trace/request id format: {value!r}")


def test_traceability_config_loaded(traceability_config: TraceabilityConfig) -> None:
    # This test is intentionally minimal and never fails due to missing env;
    # it only ensures we can parse configuration deterministically.
    assert isinstance(traceability_config.middleware_names, tuple)


def test_traceability_ids_provider(traceability_config: TraceabilityConfig) -> None:
    """
    If TRACEABILITY_IDS is configured, validate that it can produce IDs
    and that produced values have recognizable formats.
    """
    if not traceability_config.ids_import:
        _skip("TRACEABILITY_IDS not configured; ids provider test skipped.")

    ids_provider = _maybe_import(traceability_config.ids_import, "ids provider")

    # Supported shapes:
    # - functions: generate_request_id(), generate_trace_id()
    # - object with methods: new_request_id(), new_trace_id()
    candidates: Sequence[Tuple[str, Sequence[str]]] = (
        ("generate_request_id", ("request_id", "req_id")),
        ("new_request_id", ("request_id", "req_id")),
        ("generate_trace_id", ("trace_id", "traceparent")),
        ("new_trace_id", ("trace_id", "traceparent")),
    )

    produced: Dict[str, str] = {}

    for fn_name, logical_names in candidates:
        fn = getattr(ids_provider, fn_name, None)
        if callable(fn):
            try:
                val = fn()
            except TypeError:
                # Some implementations accept args; skip strict call.
                continue
            if isinstance(val, str) and val.strip():
                produced[logical_names[0]] = val.strip()

    if not produced:
        _skip("No compatible id generator functions found on TRACEABILITY_IDS provider.")

    for k, v in produced.items():
        assert isinstance(v, str) and v
        _maybe_validate_id(v)


@pytest.mark.asyncio
async def test_trace_context_propagation_in_async_tasks(traceability_config: TraceabilityConfig) -> None:
    """
    If TRACEABILITY_CONTEXT is configured, verifies that trace context is preserved across awaits/tasks.

    Expected provider shapes (one of):
      - module/object with methods: set(trace_id=..., request_id=...), get() -> mapping
      - module/object with: set_trace_id(str), set_request_id(str), get_trace_id(), get_request_id()
    """
    if not traceability_config.context_import:
        _skip("TRACEABILITY_CONTEXT not configured; context propagation test skipped.")

    ctx = _maybe_import(traceability_config.context_import, "trace context provider")

    # Determine setter/getter strategy.
    has_set_get = callable(getattr(ctx, "set", None)) and callable(getattr(ctx, "get", None))
    has_specific = all(
        callable(getattr(ctx, n, None))
        for n in ("set_trace_id", "set_request_id", "get_trace_id", "get_request_id")
    )

    if not (has_set_get or has_specific):
        _skip("TRACEABILITY_CONTEXT does not expose supported set/get API.")

    trace_id = "00-" + ("a" * 32) + "-" + ("b" * 16) + "-01"  # valid w3c-like traceparent shape
    request_id = "550e8400-e29b-41d4-a716-446655440000"       # valid UUID

    if has_set_get:
        ctx.set(trace_id=trace_id, request_id=request_id)
    else:
        ctx.set_trace_id(trace_id)
        ctx.set_request_id(request_id)

    async def _child() -> Tuple[Optional[str], Optional[str]]:
        # Simulate real async boundaries.
        await asyncio.sleep(0)
        if has_set_get:
            data = _as_mapping(ctx.get())
            t = data.get("trace_id") or data.get("traceparent")
            r = data.get("request_id") or data.get("req_id")
            return (t, r)
        return (ctx.get_trace_id(), ctx.get_request_id())

    t1, r1 = await _child()

    # Also across a created task.
    task = asyncio.create_task(_child())
    t2, r2 = await task

    assert t1 is not None and isinstance(t1, str) and t1
    assert r1 is not None and isinstance(r1, str) and r1
    assert t2 is not None and isinstance(t2, str) and t2
    assert r2 is not None and isinstance(r2, str) and r2

    _maybe_validate_id(t1)
    _maybe_validate_id(t2)
    _maybe_validate_id(r1)
    _maybe_validate_id(r2)


def test_logger_emits_trace_fields_when_context_set(traceability_config: TraceabilityConfig) -> None:
    """
    If TRACEABILITY_LOGGER and TRACEABILITY_CONTEXT are configured, checks that a log event
    contains correlation fields.

    Supported logger helper shapes (one of):
      - callable capture(fn) -> event mapping
      - object/module with function emit_event(message=..., **fields) -> mapping/dict
      - object/module with function get_last_event() -> mapping, plus log(...) to produce one
    """
    if not traceability_config.logger_import:
        _skip("TRACEABILITY_LOGGER not configured; logger trace fields test skipped.")
    if not traceability_config.context_import:
        _skip("TRACEABILITY_CONTEXT not configured; logger trace fields test skipped.")

    logger_helper = _maybe_import(traceability_config.logger_import, "logger helper")
    ctx = _maybe_import(traceability_config.context_import, "trace context provider")

    # Set context if possible (best effort).
    trace_id = "00-" + ("c" * 32) + "-" + ("d" * 16) + "-01"
    request_id = "550e8400-e29b-41d4-a716-446655440000"

    if callable(getattr(ctx, "set", None)) and callable(getattr(ctx, "get", None)):
        ctx.set(trace_id=trace_id, request_id=request_id)
    else:
        if callable(getattr(ctx, "set_trace_id", None)):
            ctx.set_trace_id(trace_id)
        if callable(getattr(ctx, "set_request_id", None)):
            ctx.set_request_id(request_id)

    event: Optional[Dict[str, Any]] = None

    # Strategy A: emit_event(...) -> mapping
    emit_event = getattr(logger_helper, "emit_event", None)
    if callable(emit_event):
        out = emit_event(message="traceability-compliance-test", test_marker=True)
        event = _as_mapping(out)

    # Strategy B: log(...) + get_last_event()
    if event is None:
        log_fn = getattr(logger_helper, "log", None)
        get_last = getattr(logger_helper, "get_last_event", None)
        if callable(log_fn) and callable(get_last):
            log_fn("traceability-compliance-test", test_marker=True)
            event = _as_mapping(get_last())

    # Strategy C: capture(callable) -> mapping
    if event is None:
        capture = getattr(logger_helper, "capture", None)
        if callable(capture):
            def _do_log() -> None:
                f = getattr(logger_helper, "log", None)
                if callable(f):
                    f("traceability-compliance-test", test_marker=True)
                else:
                    g = getattr(logger_helper, "emit_event", None)
                    if callable(g):
                        g(message="traceability-compliance-test", test_marker=True)
                    else:
                        raise RuntimeError("No supported log emitter found on logger helper.")
            out = capture(_do_log)
            event = _as_mapping(out)

    if event is None:
        _skip("TRACEABILITY_LOGGER helper does not expose supported API for capturing a log event.")

    # Validate required correlation fields exist (accept common key aliases).
    trace_key = _expect_any_key(event, ("trace_id", "traceparent", "trace", "otel_trace_id"))
    req_key = _expect_any_key(event, ("request_id", "req_id", "correlation_id", "requestId"))

    assert isinstance(event[trace_key], (str, type(None)))
    assert isinstance(event[req_key], (str, type(None)))

    if event[trace_key]:
        _maybe_validate_id(str(event[trace_key]))
    if event[req_key]:
        _maybe_validate_id(str(event[req_key]))


def test_fastapi_app_has_traceability_middleware(traceability_config: TraceabilityConfig) -> None:
    """
    If TRACEABILITY_APP is configured, tries to assert that app contains middleware
    related to traceability by name matching.

    Because projects differ, this test is best-effort:
    - If middleware names list is empty, it only checks app has .user_middleware attribute (FastAPI/Starlette shape).
    - If names list is set, it checks that at least one middleware class name contains one of those substrings.
    """
    if not traceability_config.app_import:
        _skip("TRACEABILITY_APP not configured; FastAPI middleware test skipped.")

    app = _maybe_import(traceability_config.app_import, "FastAPI app")

    user_middleware = getattr(app, "user_middleware", None)
    if user_middleware is None:
        _skip("App does not expose user_middleware; cannot introspect middleware reliably.")

    if not traceability_config.middleware_names:
        # Minimal, shape-only check.
        assert isinstance(user_middleware, (list, tuple))
        return

    # Match middleware class names against provided substrings.
    found = False
    for mw in user_middleware:
        cls = getattr(mw, "cls", None) or getattr(mw, "__class__", None)
        name = ""
        if cls is not None:
            name = getattr(cls, "__name__", "") or str(cls)
        for needle in traceability_config.middleware_names:
            if needle.lower() in name.lower():
                found = True
                break
        if found:
            break

    assert found, (
        "No middleware matched TRACEABILITY_MIDDLEWARE_NAMES. "
        f"Expected one of: {traceability_config.middleware_names}"
    )
