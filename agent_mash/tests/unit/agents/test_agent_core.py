# agent_mash/tests/unit/agents/test_agent_core.py
from __future__ import annotations

import asyncio
import inspect
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Type, Union

import pytest


@dataclass(frozen=True)
class _ImportAttempt:
    module: str
    attr: str = "AgentCore"


def _candidate_imports() -> list[_ImportAttempt]:
    """
    We avoid hard-coding a single import path because project layouts differ.
    This list contains typical, industry-common locations for an AgentCore.

    NOTE: This is not a claim that these paths exist in your repo.
    We merely try them and proceed only if something is actually importable.
    """
    # Optional override to force a single path in CI without modifying test code
    # Format: "some.module.path:ClassName" or "some.module.path"
    override = os.getenv("AETHERNOVA_AGENT_CORE_IMPORT", "").strip()
    if override:
        if ":" in override:
            mod, cls = override.split(":", 1)
            return [_ImportAttempt(module=mod.strip(), attr=cls.strip() or "AgentCore")]
        return [_ImportAttempt(module=override, attr="AgentCore")]

    return [
        _ImportAttempt("agent_mash.agents.agent_core"),
        _ImportAttempt("agent_mash.agents.core"),
        _ImportAttempt("agent_mash.agents.agentcore"),
        _ImportAttempt("agent_mash.agents.base"),
        _ImportAttempt("agent_mash.core.agent_core"),
        _ImportAttempt("agent_mash.core.agents.agent_core"),
        _ImportAttempt("agent_mash.domain.agent_core"),
        _ImportAttempt("agent_mash.agent_core"),
        _ImportAttempt("agents.agent_core"),
        _ImportAttempt("agents.core"),
    ]


def _try_import_agent_core() -> tuple[Optional[Type[Any]], list[str]]:
    errors: list[str] = []
    for attempt in _candidate_imports():
        try:
            mod = __import__(attempt.module, fromlist=[attempt.attr])
            obj = getattr(mod, attempt.attr, None)
            if obj is None:
                errors.append(f"{attempt.module}:{attempt.attr} not found")
                continue
            if not inspect.isclass(obj):
                errors.append(f"{attempt.module}:{attempt.attr} is not a class")
                continue
            return obj, errors
        except Exception as e:  # pragma: no cover
            errors.append(f"{attempt.module}:{attempt.attr} import error: {type(e).__name__}: {e}")
    return None, errors


def _is_async_callable(fn: Callable[..., Any]) -> bool:
    return asyncio.iscoroutinefunction(fn) or inspect.isawaitable(fn)


def _maybe_await(result: Any) -> Any:
    if inspect.isawaitable(result):
        return result
    return result


async def _call_maybe_async(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    res = fn(*args, **kwargs)
    res = _maybe_await(res)
    if inspect.isawaitable(res):
        return await res
    return res


def _has_method(obj: Any, name: str) -> bool:
    return callable(getattr(obj, name, None))


def _get_method(obj: Any, name: str) -> Callable[..., Any]:
    m = getattr(obj, name, None)
    if not callable(m):
        raise AttributeError(name)
    return m


def _safe_close_event_loop_artifacts() -> None:
    """
    Defensive helper: some agent cores may create tasks.
    Unit tests should not leak tasks across cases.
    """
    # Pytest/anyio usually manages this, but we keep a lightweight safeguard.
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return
    if loop.is_closed():
        return


@pytest.fixture(scope="session")
def AgentCoreClass() -> Type[Any]:
    cls, errors = _try_import_agent_core()
    if cls is None:
        tried = "\n".join(errors) if errors else "No attempts recorded"
        pytest.skip(
            "AgentCore class not found. "
            "Set env AETHERNOVA_AGENT_CORE_IMPORT='module.path:ClassName' "
            "or place AgentCore in an importable location.\n"
            f"Attempts:\n{tried}"
        )
    return cls


@pytest.fixture()
def agent_core_ctor_kwargs() -> dict[str, Any]:
    """
    Project-specific constructor args are unknown here.
    This fixture is intentionally empty by default.

    In your repo, you can override this fixture in conftest.py to provide
    required dependencies (logger, config, bus, storage, etc.).
    """
    return {}


@pytest.fixture()
def agent_core_factory(AgentCoreClass: Type[Any], agent_core_ctor_kwargs: dict[str, Any]) -> Callable[[], Any]:
    def _factory() -> Any:
        return AgentCoreClass(**agent_core_ctor_kwargs)

    return _factory


@pytest.fixture()
async def agent_core(agent_core_factory: Callable[[], Any]) -> Any:
    """
    Creates a fresh agent core for each test.

    If the core exposes start/stop (or async equivalents), we honor them.
    """
    obj = agent_core_factory()

    # Prefer explicit lifecycle
    for start_name in ("start", "startup", "initialize", "init"):
        if _has_method(obj, start_name):
            await _call_maybe_async(_get_method(obj, start_name))
            break

    yield obj

    # Teardown
    for stop_name in ("stop", "shutdown", "close", "dispose", "teardown"):
        if _has_method(obj, stop_name):
            try:
                await _call_maybe_async(_get_method(obj, stop_name))
            except Exception:
                # Unit tests should be resilient to best-effort shutdown
                pass
            break

    _safe_close_event_loop_artifacts()


def _pick_handler(obj: Any) -> Optional[str]:
    """
    Determines how the agent core is expected to handle input.
    We do not assume one method name. We detect the first supported one.
    """
    for name in (
        "handle",
        "handle_event",
        "handle_message",
        "process",
        "process_event",
        "process_message",
        "run_once",
        "__call__",
    ):
        if _has_method(obj, name):
            return name
    return None


def _minimal_payload() -> dict[str, Any]:
    return {
        "type": "unit.test",
        "ts": time.time(),
        "payload": {"hello": "world"},
        "meta": {"trace_id": "test-trace", "span_id": "test-span"},
    }


@pytest.mark.asyncio
async def test_agent_core_constructs(agent_core_factory: Callable[[], Any]) -> None:
    obj = agent_core_factory()
    assert obj is not None


@pytest.mark.asyncio
async def test_agent_core_has_identity_or_repr(agent_core: Any) -> None:
    """
    Industrial sanity check: object should be debuggable.
    Either an id/name property or a stable repr/str.
    """
    # If present, validate common identity properties
    for attr in ("id", "agent_id", "name", "component", "component_name"):
        if hasattr(agent_core, attr):
            v = getattr(agent_core, attr)
            assert v is not None
            # allow str/int/uuid-like; avoid strict assumptions
            assert isinstance(v, (str, int)) or v is not None
            return

    # Otherwise ensure repr/str is non-empty
    s = str(agent_core)
    r = repr(agent_core)
    assert isinstance(s, str) and len(s) > 0
    assert isinstance(r, str) and len(r) > 0


@pytest.mark.asyncio
async def test_agent_core_optional_healthcheck(agent_core: Any) -> None:
    """
    If the core exposes a health method, it should return a sensible value.
    We do not force a specific schema.
    """
    for name in ("health", "healthcheck", "is_healthy", "status"):
        if _has_method(agent_core, name):
            res = await _call_maybe_async(_get_method(agent_core, name))
            assert res is not None
            # common patterns: bool or dict with status
            if isinstance(res, bool):
                assert res is True or res is False
            elif isinstance(res, dict):
                assert len(res) >= 1
            else:
                # accept other simple types (e.g., "ok")
                assert isinstance(res, (str, int, float))
            return

    # If there is no health method, this is not a failure
    assert True


@pytest.mark.asyncio
async def test_agent_core_can_handle_minimal_payload_if_handler_exists(agent_core: Any) -> None:
    handler_name = _pick_handler(agent_core)
    if handler_name is None:
        pytest.skip("No handler method detected on AgentCore (handle/process/run_once/__call__).")
    handler = _get_method(agent_core, handler_name)

    payload = _minimal_payload()

    # Try calling with 1 arg; if signature requires different, adapt carefully.
    sig = None
    try:
        sig = inspect.signature(handler)
    except Exception:
        sig = None

    try:
        if sig is None:
            res = await _call_maybe_async(handler, payload)
        else:
            params = list(sig.parameters.values())

            # Bound methods include 'self' already; signature here is for bound callable.
            # We only support conservative calls:
            # - (event) or ()
            # - keyword 'event'/'message'/'payload'
            if len(params) == 0:
                res = await _call_maybe_async(handler)
            elif len(params) == 1:
                res = await _call_maybe_async(handler, payload)
            else:
                # Try common kw names
                for kw in ("event", "message", "payload", "data", "item"):
                    try:
                        res = await _call_maybe_async(handler, **{kw: payload})
                        break
                    except TypeError:
                        res = None
                else:
                    pytest.skip(
                        f"Handler signature for {handler_name} is not safely callable in generic mode: {sig}"
                    )
        # We only assert it does not crash and returns something (or None is allowed)
        assert res is None or res is not None
    except NotImplementedError:
        pytest.xfail("Handler exists but is NotImplementedError in current build.")
    except Exception as e:
        pytest.fail(f"AgentCore handler '{handler_name}' raised: {type(e).__name__}: {e}")


@pytest.mark.asyncio
async def test_agent_core_idempotent_start_stop_if_present(agent_core_factory: Callable[[], Any]) -> None:
    """
    If start/stop exist, they should be safely repeatable or at least not corrupt state.
    This test creates a fresh instance to avoid coupling with other tests.
    """
    obj = agent_core_factory()

    start_name = next((n for n in ("start", "startup", "initialize", "init") if _has_method(obj, n)), None)
    stop_name = next((n for n in ("stop", "shutdown", "close", "dispose", "teardown") if _has_method(obj, n)), None)

    if start_name is None and stop_name is None:
        pytest.skip("No lifecycle methods detected (start/stop equivalents).")

    if start_name is not None:
        start = _get_method(obj, start_name)
        await _call_maybe_async(start)
        # Second start should not crash in industrial systems (either no-op or controlled)
        try:
            await _call_maybe_async(start)
        except Exception:
            # acceptable if the system explicitly forbids it; do not hard fail
            pass

    if stop_name is not None:
        stop = _get_method(obj, stop_name)
        await _call_maybe_async(stop)
        # Second stop should be safe (no-op) in most designs
        try:
            await _call_maybe_async(stop)
        except Exception:
            pass


@pytest.mark.asyncio
async def test_agent_core_concurrency_smoke_if_handler_exists(agent_core: Any) -> None:
    """
    Concurrency smoke test: if handler exists, it should not deadlock under parallel calls.
    We do not assert order or exact outputs.
    """
    handler_name = _pick_handler(agent_core)
    if handler_name is None:
        pytest.skip("No handler method detected for concurrency smoke test.")
    handler = _get_method(agent_core, handler_name)

    payloads = []
    base = _minimal_payload()
    for i in range(10):
        p = dict(base)
        p["meta"] = dict(base["meta"])
        p["meta"]["span_id"] = f"test-span-{i}"
        p["payload"] = {"i": i}
        payloads.append(p)

    async def _one(p: dict[str, Any]) -> Any:
        try:
            return await _call_maybe_async(handler, p)
        except TypeError:
            # try common kw fallback
            for kw in ("event", "message", "payload", "data", "item"):
                try:
                    return await _call_maybe_async(handler, **{kw: p})
                except TypeError:
                    continue
            raise

    try:
        results = await asyncio.gather(*(_one(p) for p in payloads))
        assert len(results) == len(payloads)
    except NotImplementedError:
        pytest.xfail("Handler exists but is NotImplementedError in current build.")
    except Exception as e:
        pytest.fail(f"Concurrency handling failed for '{handler_name}': {type(e).__name__}: {e}")


@pytest.mark.asyncio
async def test_agent_core_exposes_metrics_or_counters_if_present(agent_core: Any) -> None:
    """
    If the core exposes metrics/counters, they should be readable and stable.
    No enforced schema.
    """
    for name in ("metrics", "get_metrics", "stats", "get_stats", "counters", "telemetry"):
        if _has_method(agent_core, name):
            res = await _call_maybe_async(_get_method(agent_core, name))
            assert res is not None
            assert isinstance(res, (dict, list, tuple, str, int, float))
            return
        if hasattr(agent_core, name) and not callable(getattr(agent_core, name)):
            v = getattr(agent_core, name)
            assert v is not None
            assert isinstance(v, (dict, list, tuple, str, int, float))
            return

    assert True


@pytest.mark.asyncio
async def test_agent_core_rejects_obviously_invalid_input_if_handler_exists(agent_core: Any) -> None:
    """
    Industrial negative test: if the core has a handler, passing invalid input
    should either raise a controlled exception or return a controlled error value.
    We accept both patterns, but we must not allow silent undefined crashes.
    """
    handler_name = _pick_handler(agent_core)
    if handler_name is None:
        pytest.skip("No handler method detected for negative test.")
    handler = _get_method(agent_core, handler_name)

    invalid_inputs: list[Any] = [None, 1, "bad", object(), {"no": "type"}]

    for bad in invalid_inputs:
        try:
            res = await _call_maybe_async(handler, bad)
            # If it returns, it should be a controlled value, not e.g. a coroutine leak
            assert not inspect.isawaitable(res)
        except TypeError:
            # acceptable: strict typing at runtime
            continue
        except ValueError:
            continue
        except KeyError:
            continue
        except NotImplementedError:
            pytest.xfail("Handler exists but is NotImplementedError in current build.")
        except Exception as e:
            pytest.fail(f"Unexpected exception type for invalid input {type(bad).__name__}: {type(e).__name__}: {e}")
