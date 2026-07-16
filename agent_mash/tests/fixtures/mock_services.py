# agent_mash/tests/fixtures/mock_services.py
"""
Industrial pytest fixtures + mock utilities for service-layer testing.

What this module guarantees:
- Strict, typed mocking (autospec where possible)
- First-class async support (AsyncMock helpers)
- Deterministic time and UUID generation
- Clean patching utilities (context manager + fixture)

Important:
- Project-specific import paths for patching are not included because I cannot verify this.
  Use `patch_attr("your.module.path", "name", value)` or `patch_many(...)` with your real paths.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as _dt
import inspect
import types
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from typing import Any, Generic, Optional, Protocol, TypeVar, cast

import pytest
from unittest.mock import ANY, AsyncMock, MagicMock, Mock, call, create_autospec, patch

T = TypeVar("T")
R = TypeVar("R")


# -----------------------------
# Core protocols (optional use)
# -----------------------------

class SupportsClose(Protocol):
    def close(self) -> None: ...


class SupportsAClose(Protocol):
    async def aclose(self) -> None: ...


class Clock(Protocol):
    def now(self) -> _dt.datetime: ...


class UuidFactory(Protocol):
    def __call__(self) -> uuid.UUID: ...


# -----------------------------
# Deterministic clock + UUID
# -----------------------------

@dataclasses.dataclass(frozen=True, slots=True)
class FrozenClock:
    """Deterministic clock for tests (timezone-aware UTC by default)."""
    _now: _dt.datetime

    def now(self) -> _dt.datetime:
        return self._now


@dataclasses.dataclass(slots=True)
class StepClock:
    """
    Deterministic clock that advances by a fixed delta each time now() is called.
    Useful for ordering, TTL logic, and audit timestamps.
    """
    _current: _dt.datetime
    _step: _dt.timedelta = dataclasses.field(default_factory=lambda: _dt.timedelta(seconds=1))

    def now(self) -> _dt.datetime:
        value = self._current
        self._current = self._current + self._step
        return value


@dataclasses.dataclass(slots=True)
class UuidSequence:
    """
    Deterministic UUID generator.
    By default generates UUIDs from a fixed namespace + counter.
    """
    namespace: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")
    _counter: int = 0

    def __call__(self) -> uuid.UUID:
        self._counter += 1
        # Use uuid5 for stable deterministic UUIDs
        return uuid.uuid5(self.namespace, f"test-{self._counter}")


# -----------------------------
# Async utilities
# -----------------------------

def is_awaitable(value: Any) -> bool:
    return inspect.isawaitable(value)


async def maybe_await(value: Any) -> Any:
    return await value if is_awaitable(value) else value


def ensure_asyncmock(fn_name: str = "async_call") -> AsyncMock:
    """
    Creates an AsyncMock with a readable name.
    """
    m = AsyncMock(name=fn_name)
    return m


def async_return(value: Any) -> AsyncMock:
    """
    AsyncMock that returns a value when awaited/called.
    """
    m = ensure_asyncmock("async_return")
    m.return_value = value
    return m


def async_raise(exc: BaseException) -> AsyncMock:
    """
    AsyncMock that raises an exception when awaited/called.
    """
    m = ensure_asyncmock("async_raise")
    m.side_effect = exc
    return m


@contextlib.asynccontextmanager
async def aclosing(resource: Any) -> AsyncIterator[Any]:
    """
    Async equivalent of contextlib.closing.
    Calls aclose() if available, otherwise close() if available.
    """
    try:
        yield resource
    finally:
        if hasattr(resource, "aclose") and callable(getattr(resource, "aclose")):
            await cast(SupportsAClose, resource).aclose()
        elif hasattr(resource, "close") and callable(getattr(resource, "close")):
            cast(SupportsClose, resource).close()


# -----------------------------
# Patch helpers
# -----------------------------

@dataclasses.dataclass(frozen=True, slots=True)
class PatchSpec:
    target: str
    attribute: str
    value: Any
    autospec: bool = False


@contextlib.contextmanager
def patch_attr(target: str, attribute: str, value: Any, *, autospec: bool = False) -> Iterator[Mock]:
    """
    Patch `attribute` on module/object at `target` import path.

    Example:
        with patch_attr("myapp.services.user_service", "email_client", fake_client):
            ...
    """
    p = patch(f"{target}.{attribute}", new=value, autospec=autospec)
    started = p.start()
    try:
        yield started
    finally:
        p.stop()


@contextlib.contextmanager
def patch_many(specs: list[PatchSpec]) -> Iterator[dict[str, Mock]]:
    """
    Patch multiple attributes, returns a dict key "<target>.<attr>" -> started mock/obj.
    """
    patchers: list[patch] = []
    started: dict[str, Mock] = {}
    try:
        for s in specs:
            p = patch(f"{s.target}.{s.attribute}", new=s.value, autospec=s.autospec)
            patchers.append(p)
            started[f"{s.target}.{s.attribute}"] = p.start()
        yield started
    finally:
        for p in reversed(patchers):
            with contextlib.suppress(Exception):
                p.stop()


# -----------------------------
# Strict mocks (autospec)
# -----------------------------

def strict_mock(spec: type[T] | T, *, instance: bool = True, name: str | None = None) -> T:
    """
    Create a strict mock that errors on unknown attributes (autospec).

    - If `spec` is a type: autospec that type.
    - If `spec` is an instance: autospec its class and behave like an instance.

    Returns a value typed as T.
    """
    if isinstance(spec, type):
        mocked = create_autospec(spec, spec_set=True, instance=instance)
    else:
        mocked = create_autospec(spec.__class__, spec_set=True, instance=True)
    if name:
        mocked._mock_name = name  # type: ignore[attr-defined]
    return cast(T, mocked)


def strict_async_service(spec: type[T] | T, *, name: str | None = None) -> T:
    """
    Like strict_mock, but converts coroutine functions on the spec into AsyncMock,
    ensuring awaitable behavior in async code.

    Note:
    - This is best-effort: it inspects the spec's callables and replaces coroutine funcs.
    """
    m = strict_mock(spec, instance=True, name=name)

    # Patch coroutine methods to AsyncMock for correct await behavior.
    # We do it only for attributes that exist in the spec_set.
    attrs = dir(spec if isinstance(spec, type) else spec.__class__)
    for attr in attrs:
        if attr.startswith("__"):
            continue
        try:
            value = getattr(spec if isinstance(spec, type) else spec.__class__, attr)
        except Exception:
            continue

        if inspect.iscoroutinefunction(value):
            try:
                setattr(m, attr, AsyncMock(name=f"{name or 'service'}.{attr}"))
            except Exception:
                # If spec_set prevents setting (rare), ignore.
                pass

    return m


# -----------------------------
# Common fake clients (generic)
# -----------------------------

@dataclasses.dataclass(slots=True)
class FakeHttpResponse:
    status_code: int = 200
    json_data: Any = dataclasses.field(default_factory=dict)
    text_data: str = ""
    headers: dict[str, str] = dataclasses.field(default_factory=dict)

    def json(self) -> Any:
        return self.json_data

    @property
    def text(self) -> str:
        return self.text_data


@dataclasses.dataclass(slots=True)
class FakeHttpClient:
    """
    Minimal async HTTP client fake for service tests.
    Behaves like httpx/aiohttp patterns (best-effort).
    """
    requests: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    routes: dict[tuple[str, str], FakeHttpResponse] = dataclasses.field(default_factory=dict)

    async def request(self, method: str, url: str, **kwargs: Any) -> FakeHttpResponse:
        method_u = method.upper()
        self.requests.append({"method": method_u, "url": url, **kwargs})
        return self.routes.get((method_u, url), FakeHttpResponse(status_code=404, text_data="Not Found"))

    async def get(self, url: str, **kwargs: Any) -> FakeHttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> FakeHttpResponse:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        return


@dataclasses.dataclass(slots=True)
class FakeEventBus:
    """
    Generic async event bus fake.
    Captures publishes and allows injecting handlers.
    """
    published: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    handlers: dict[str, list[Callable[[Any], Awaitable[None]]]] = dataclasses.field(default_factory=dict)

    async def publish(self, topic: str, payload: Any, **meta: Any) -> None:
        self.published.append({"topic": topic, "payload": payload, "meta": meta})
        for h in self.handlers.get(topic, []):
            await h(payload)

    def on(self, topic: str, handler: Callable[[Any], Awaitable[None]]) -> None:
        self.handlers.setdefault(topic, []).append(handler)

    async def aclose(self) -> None:
        return


@dataclasses.dataclass(slots=True)
class FakeKeyValueStore:
    """
    Generic async key-value store fake (Redis-like subset).
    """
    _store: dict[str, Any] = dataclasses.field(default_factory=dict)

    async def get(self, key: str) -> Any:
        return self._store.get(key)

    async def set(self, key: str, value: Any, *, ex: int | None = None) -> None:
        # TTL (ex) intentionally not implemented because I cannot verify this is needed.
        self._store[key] = value

    async def delete(self, key: str) -> int:
        existed = 1 if key in self._store else 0
        self._store.pop(key, None)
        return existed

    async def aclose(self) -> None:
        return


# -----------------------------
# Pytest fixtures (industrial)
# -----------------------------

@pytest.fixture
def frozen_utc_now() -> _dt.datetime:
    """
    Fixed, timezone-aware timestamp (UTC).
    """
    return _dt.datetime(2030, 1, 1, 0, 0, 0, tzinfo=_dt.timezone.utc)


@pytest.fixture
def clock(frozen_utc_now: _dt.datetime) -> Clock:
    """
    Deterministic Clock dependency.
    """
    return FrozenClock(frozen_utc_now)


@pytest.fixture
def step_clock(frozen_utc_now: _dt.datetime) -> StepClock:
    """
    Deterministic clock that moves forward each call.
    """
    return StepClock(frozen_utc_now, _dt.timedelta(milliseconds=10))


@pytest.fixture
def uuid_seq() -> UuidSequence:
    """
    Deterministic UUID factory dependency.
    """
    return UuidSequence(namespace=uuid.UUID("11111111-1111-1111-1111-111111111111"))


@pytest.fixture
def http_client() -> FakeHttpClient:
    """
    Async fake HTTP client.
    """
    return FakeHttpClient()


@pytest.fixture
def event_bus() -> FakeEventBus:
    """
    Async fake event bus / message broker facade.
    """
    return FakeEventBus()


@pytest.fixture
def kv_store() -> FakeKeyValueStore:
    """
    Async fake KV store (Redis-like).
    """
    return FakeKeyValueStore()


@pytest.fixture
def anyio_backend() -> str:
    """
    If your project uses pytest-anyio, this selects asyncio backend.
    Safe to keep even if not used.
    """
    return "asyncio"


# -----------------------------
# Assertion helpers
# -------------------------
