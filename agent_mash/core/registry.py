# agent_mash/core/registry.py
from __future__ import annotations

import asyncio
import dataclasses
import functools
import importlib
import inspect
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)

try:
    # Python 3.11+
    from importlib.metadata import entry_points, EntryPoint
except Exception:  # pragma: no cover
    entry_points = None  # type: ignore
    EntryPoint = Any  # type: ignore


T = TypeVar("T")


# -----------------------------
# Errors
# -----------------------------
class RegistryError(RuntimeError):
    """Base registry error."""


class RegistryValidationError(RegistryError):
    """Raised when a spec or provider does not satisfy constraints."""


class RegistryConflictError(RegistryError):
    """Raised when attempting to overwrite or duplicate entries."""


class RegistryNotFoundError(RegistryError):
    """Raised when an entry cannot be found."""


class RegistryLoadError(RegistryError):
    """Raised when plugin auto-loading fails."""


# -----------------------------
# Contracts
# -----------------------------
class Agent(Protocol):
    """
    Minimal contract for runtime agent instances.

    Your concrete agent can be any class; if it implements these methods,
    the registry can orchestrate optional lifecycle hooks.
    """

    async def start(self) -> None:
        ...

    async def stop(self) -> None:
        ...


@dataclass(frozen=True, slots=True)
class AgentRef:
    """
    Strong identifier of an agent provider.
    """
    name: str
    version: str = "0.0.0"

    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass(frozen=True, slots=True)
class AgentSpec:
    """
    Immutable specification that describes what is registered.
    """
    ref: AgentRef
    title: str
    description: str = ""
    tags: Tuple[str, ...] = ()
    capabilities: Tuple[str, ...] = ()
    author: str = ""
    license: str = ""
    homepage: str = ""
    created_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.ref.name,
            "version": self.ref.version,
            "title": self.title,
            "description": self.description,
            "tags": list(self.tags),
            "capabilities": list(self.capabilities),
            "author": self.author,
            "license": self.license,
            "homepage": self.homepage,
            "created_at_utc": self.created_at_utc,
        }


ProviderFactory = Callable[..., Union[Agent, Awaitable[Agent]]]


@dataclass(slots=True)
class ProviderRecord:
    spec: AgentSpec
    factory: ProviderFactory
    module: str
    qualname: str
    registered_at_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    meta: Dict[str, Any] = field(default_factory=dict)

    def as_public_dict(self) -> Dict[str, Any]:
        d = self.spec.as_dict()
        d.update(
            {
                "module": self.module,
                "qualname": self.qualname,
                "registered_at_utc": self.registered_at_utccia
            }
        )
        return d

    @property
    def register_key(self) -> str:
        return self.spec.ref.key()


# -----------------------------
# Eventing
# -----------------------------
@dataclass(frozen=True, slots=True)
class RegistryEvent:
    ts_utc: str
    type: str
    payload: Mapping[str, Any]


EventHandler = Callable[[RegistryEvent], None]


# -----------------------------
# Utilities (validation / normalization)
# -----------------------------
_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]{1,127}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.\-]+)?$")


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_tag(s: str) -> str:
    return s.strip().lower()


def _dedupe_preserve(seq: Iterable[str]) -> Tuple[str, ...]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in seq:
        x2 = _norm_tag(x)
        if not x2:
            continue
        if x2 not in seen:
            seen.add(x2)
            out.append(x2)
    return tuple(out)


def _validate_name(name: str) -> None:
    if not name or not isinstance(name, str):
        raise RegistryValidationError("name must be a non-empty string")
    if not _NAME_RE.match(name):
        raise RegistryValidationError(
            "name must match pattern: ^[a-zA-Z][a-zA-Z0-9._-]{1,127}$"
        )


def _validate_version(version: str) -> None:
    if not version or not isinstance(version, str):
        raise RegistryValidationError("version must be a non-empty string")
    if not _VERSION_RE.match(version):
        raise RegistryValidationError(
            "version must be semver-like: MAJOR.MINOR.PATCH (optionally with -prerelease or +build)"
        )


def _validate_spec(spec: AgentSpec) -> None:
    _validate_name(spec.ref.name)
    _validate_version(spec.ref.version)
    if not spec.title or not isinstance(spec.title, str):
        raise RegistryValidationError("title must be a non-empty string")
    # Defensive: limit sizes for operational safety
    if len(spec.title) > 256:
        raise RegistryValidationError("title too long (max 256)")
    if len(spec.description) > 4096:
        raise RegistryValidationError("description too long (max 4096)")
    if len(spec.tags) > 128:
        raise RegistryValidationError("too many tags (max 128)")
    if len(spec.capabilities) > 256:
        raise RegistryValidationError("too many capabilities (max 256)")


def _callable_qualname(fn: Callable[..., Any]) -> Tuple[str, str]:
    mod = getattr(fn, "__module__", "") or ""
    qn = getattr(fn, "__qualname__", "") or getattr(fn, "__name__", "callable")
    return mod, qn


async def _maybe_await(x: Union[T, Awaitable[T]]) -> T:
    if inspect.isawaitable(x):
        return await x  # type: ignore[no-any-return]
    return x  # type: ignore[return-value]


# -----------------------------
# Registry
# -----------------------------
class AgentRegistry:
    """
    Industrial-grade registry for agent providers.

    Design goals:
    - deterministic keys (name@version)
    - strict validation
    - async-safe (single-process) with asyncio.Lock
    - safe snapshot/export
    - optional auto-loading via entrypoints
    - optional event hooks (register/unregister/load/instantiate)
    """

    def __init__(
        self,
        *,
        allow_overwrite: bool = False,
        max_records: int = 10_000,
        entrypoint_group: str = "agent_mash.agents",
    ) -> None:
        self._allow_overwrite = bool(allow_overwrite)
        self._max_records = int(max_records)
        self._entrypoint_group = entrypoint_group

        self._records: Dict[str, ProviderRecord] = {}
        self._by_name: Dict[str, Set[str]] = {}
        self._lock = asyncio.Lock()

        self._handlers: List[EventHandler] = []
        self._event_ring: List[RegistryEvent] = []
        self._event_ring_max = 1024

        self._loaded_entrypoints: Set[str] = set()

    # -----------------------------
    # Event API
    # -----------------------------
    def add_handler(self, handler: EventHandler) -> None:
        if handler is None or not callable(handler):
            raise RegistryValidationError("handler must be callable")
        self._handlers.append(handler)

    def remove_handler(self, handler: EventHandler) -> None:
        self._handlers = [h for h in self._handlers if h is not handler]

    def events_snapshot(self) -> Tuple[RegistryEvent, ...]:
        return tuple(self._event_ring)

    def _emit(self, etype: str, payload: Mapping[str, Any]) -> None:
        ev = RegistryEvent(ts_utc=_now_utc_iso(), type=etype, payload=MappingProxyType(dict(payload)))
        self._event_ring.append(ev)
        if len(self._event_ring) > self._event_ring_max:
            self._event_ring = self._event_ring[-self._event_ring_max :]
        for h in list(self._handlers):
            try:
                h(ev)
            except Exception:
                # Never allow observers to break registry operations.
                continue

    # -----------------------------
    # Introspection
    # -----------------------------
    async def size(self) -> int:
        async with self._lock:
            return len(self._records)

    async def list_keys(self) -> Tuple[str, ...]:
        async with self._lock:
            return tuple(sorted(self._records.keys()))

    async def list_versions(self, name: str) -> Tuple[str, ...]:
        _validate_name(name)
        async with self._lock:
            keys = sorted(self._by_name.get(name, set()))
            versions: List[str] = []
            for k in keys:
                rec = self._records.get(k)
                if rec:
                    versions.append(rec.spec.ref.version)
            return tuple(versions)

    async def get_record(self, name: str, version: str) -> ProviderRecord:
        _validate_name(name)
        _validate_version(version)
        k = f"{name}@{version}"
        async with self._lock:
            rec = self._records.get(k)
            if not rec:
                raise RegistryNotFoundError(f"agent not found: {k}")
            return rec

    async def find(
        self,
        *,
        tags_any: Optional[Sequence[str]] = None,
        tags_all: Optional[Sequence[str]] = None,
        capabilities_any: Optional[Sequence[str]] = None,
        name_prefix: Optional[str] = None,
    ) -> Tuple[ProviderRecord, ...]:
        tags_any_n = set(_dedupe_preserve(tags_any or []))
        tags_all_n = set(_dedupe_preserve(tags_all or []))
        caps_any_n = set(_dedupe_preserve(capabilities_any or []))
        name_prefix_n = (name_prefix or "").strip()

        async with self._lock:
            out: List[ProviderRecord] = []
            for rec in self._records.values():
                if name_prefix_n and not rec.spec.ref.name.startswith(name_prefix_n):
                    continue
                rtags = set(rec.spec.tags)
                rcaps = set(rec.spec.capabilities)

                if tags_any_n and not (rtags & tags_any_n):
                    continue
                if tags_all_n and not tags_all_n.issubset(rtags):
                    continue
                if caps_any_n and not (rcaps & caps_any_n):
                    continue

                out.append(rec)

            out.sort(key=lambda r: (r.spec.ref.name, r.spec.ref.version))
            return tuple(out)

    async def snapshot(self) -> Dict[str, Any]:
        async with self._lock:
            data = {
                "ts_utc": _now_utc_iso(),
                "count": len(self._records),
                "entrypoint_group": self._entrypoint_group,
                "records": [
                    {
                        "key": k,
                        "spec": rec.spec.as_dict(),
                        "module": rec.module,
                        "qualname": rec.qualname,
                        "registered_at_utc": rec.registered_at_utc,
                        "meta": dict(rec.meta),
                    }
                    for k, rec in sorted(self._records.items(), key=lambda kv: kv[0])
                ],
            }
            return data

    async def export_json(self, *, indent: int = 2) -> str:
        snap = await self.snapshot()
        return json.dumps(snap, ensure_ascii=False, indent=indent)

    # -----------------------------
    # Registration
    # -----------------------------
    async def register(
        self,
        *,
        spec: AgentSpec,
        factory: ProviderFactory,
        meta: Optional[Mapping[str, Any]] = None,
        allow_overwrite: Optional[bool] = None,
    ) -> str:
        """
        Register an agent provider factory with a spec.

        Returns: register key "name@version".
        """
        if factory is None or not callable(factory):
            raise RegistryValidationError("factory must be callable")
        _validate_spec(spec)

        tags = _dedupe_preserve(spec.tags)
        caps = _dedupe_preserve(spec.capabilities)
        spec2 = dataclasses.replace(spec, tags=tags, capabilities=caps)

        mod, qn = _callable_qualname(factory)
        key = spec2.ref.key()

        async with self._lock:
            if len(self._records) >= self._max_records and key not in self._records:
                raise RegistryError(f"registry capacity exceeded: max_records={self._max_records}")

            overwrite = self._allow_overwrite if allow_overwrite is None else bool(allow_overwrite)

            if key in self._records and not overwrite:
                raise RegistryConflictError(f"agent already registered: {key}")

            rec = ProviderRecord(
                spec=spec2,
                factory=factory,
                module=mod,
                qualname=qn,
                meta=dict(meta or {}),
            )
            self._records[key] = rec
            self._by_name.setdefault(spec2.ref.name, set()).add(key)

        self._emit(
            "register",
            {
                "key": key,
                "name": spec2.ref.name,
                "version": spec2.ref.version,
                "module": mod,
                "qualname": qn,
            },
        )
        return key

    async def unregister(self, name: str, version: str) -> None:
        _validate_name(name)
        _validate_version(version)
        key = f"{name}@{version}"

        async with self._lock:
            rec = self._records.pop(key, None)
            if not rec:
                raise RegistryNotFoundError(f"agent not found: {key}")

            s = self._by_name.get(name)
            if s:
                s.discard(key)
                if not s:
                    self._by_name.pop(name, None)

        self._emit("unregister", {"key": key, "name": name, "version": version})

    async def clear(self) -> None:
        async with self._lock:
            self._records.clear()
            self._by_name.clear()
            self._loaded_entrypoints.clear()
        self._emit("clear", {"ok": True})

    # -----------------------------
    # Instantiation
    # -----------------------------
    async def create(
        self,
        name: str,
        version: str,
        *args: Any,
        **kwargs: Any,
    ) -> Agent:
        """
        Instantiate an agent by (name, version).
        Supports async factories.
        """
        rec = await self.get_record(name, version)

        self._emit(
            "instantiate.begin",
            {"key": rec.spec.ref.key(), "name": name, "version": version},
        )

        created = await _maybe_await(rec.factory(*args, **kwargs))
        # Optional sanity checks without forcing a rigid base class.
        if created is None:
            raise RegistryError(f"factory returned None for {rec.spec.ref.key()}")

        self._emit(
            "instantiate.ok",
            {
                "key": rec.spec.ref.key(),
                "type": f"{created.__class__.__module__}.{created.__class__.__qualname__}",
            },
        )
        return created  # type: ignore[return-value]

    # -----------------------------
    # Auto-loading (entrypoints)
    # -----------------------------
    async def load_entrypoints(self) -> Tuple[str, ...]:
        """
        Load agent provider registrars from Python entrypoints.
        Convention:
          entrypoint object can be:
            - a callable(registry) -> None / awaitable
            - a module attribute with function 'register_agents(registry)'
        """
        if entry_points is None:
            raise RegistryLoadError("importlib.metadata.entry_points is unavailable in this runtime")

        loaded: List[str] = []

        try:
            eps = entry_points()
            # new API returns object with .select(group=...)
            if hasattr(eps, "select"):
                selected = list(eps.select(group=self._entrypoint_group))
            else:
                selected = list(eps.get(self._entrypoint_group, []))  # type: ignore[call-arg]
        except Exception as e:
            raise RegistryLoadError(f"failed to read entrypoints for group={self._entrypoint_group}: {e}") from e

        for ep in selected:
            ep_id = getattr(ep, "name", "entrypoint")
            token = f"{self._entrypoint_group}:{ep_id}"
            async with self._lock:
                if token in self._loaded_entrypoints:
                    continue
                self._loaded_entrypoints.add(token)

            try:
                obj = ep.load() if hasattr(ep, "load") else None
                if obj is None:
                    raise RegistryLoadError(f"entrypoint load returned None: {token}")

                await self._invoke_registrar(obj, token)
                loaded.append(token)
                self._emit("entrypoint.loaded", {"token": token})
            except Exception as e:
                self._emit("entrypoint.failed", {"token": token, "error": str(e)})
                raise RegistryLoadError(f"failed to load {token}: {e}") from e

        return tuple(loaded)

    async def _invoke_registrar(self, obj: Any, token: str) -> None:
        # 1) callable(registry)
        if callable(obj):
            res = obj(self)
            if inspect.isawaitable(res):
                await res
            return

        # 2) module-like with register_agents(registry)
        fn = getattr(obj, "register_agents", None)
        if callable(fn):
            res = fn(self)
            if inspect.isawaitable(res):
                await res
            return

        raise RegistryLoadError(
            f"invalid registrar for {token}: expected callable(registry) or object.register_agents(registry)"
        )


# -----------------------------
# Decorator helper
# -----------------------------
def agent_provider(
    *,
    name: str,
    version: str,
    title: str,
    description: str = "",
    tags: Sequence[str] = (),
    capabilities: Sequence[str] = (),
    author: str = "",
    license: str = "",
    homepage: str = "",
    meta: Optional[Mapping[str, Any]] = None,
) -> Callable[[ProviderFactory], ProviderFactory]:
    """
    Decorator that attaches a validated AgentSpec to a provider factory.
    Registry integration is explicit: use registry.register(spec=..., factory=...).

    This keeps the registry deterministic and avoids global side effects at import time.
    """
    _validate_name(name)
    _validate_version(version)
    if not title:
        raise RegistryValidationError("title must be non-empty")

    spec = AgentSpec(
        ref=AgentRef(name=name, version=version),
        title=title,
        description=description,
        tags=_dedupe_preserve(tags),
        capabilities=_dedupe_preserve(capabilities),
        author=author,
        license=license,
        homepage=homepage,
    )

    def wrap(factory: ProviderFactory) -> ProviderFactory:
        if factory is None or not callable(factory):
            raise RegistryValidationError("factory must be callable")
        _validate_spec(spec)
        setattr(factory, "__agent_mash_spec__", spec)
        setattr(factory, "__agent_mash_meta__", dict(meta or {}))
        return factory

    return wrap


async def register_decorated(registry: AgentRegistry, factory: ProviderFactory) -> str:
    """
    Convenience for factories decorated with @agent_provider(...).
    """
    spec = getattr(factory, "__agent_mash_spec__", None)
    meta = getattr(factory, "__agent_mash_meta__", None)
    if not isinstance(spec, AgentSpec):
        raise RegistryValidationError("factory is not decorated with @agent_provider")
    return await registry.register(spec=spec, factory=factory, meta=meta or {})
