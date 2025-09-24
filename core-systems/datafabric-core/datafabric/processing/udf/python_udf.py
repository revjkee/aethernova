# -*- coding: utf-8 -*-
"""
Industrial-grade Python UDF framework for DataFabric.

Features:
- UDF metadata, semantic versioning, registry with "latest" alias
- Type-annotation driven validation for inputs/outputs
- In-process or isolated (multiprocessing) execution
- Timeouts, retries with exponential backoff, jitter
- Optional CPU/RAM limits on POSIX via `resource` (best-effort)
- Deterministic seeding for random/np/random if available
- Structured logging with correlation/tracing IDs
- Metrics collection (duration, retries, cache hits, etc.)
- Optional LRU caching per-UDF
- Integrity hashing of UDF source
- Minimal dependencies (standard library only)

Note:
Real isolation/sandboxing in Python is limited. Process-level isolation with
resource limits is provided on a best-effort basis for Unix-like systems.

(c) Aethernova / DataFabric Core
"""

from __future__ import annotations

import abc
import functools
import hashlib
import inspect
import json
import logging
import math
import os
import queue
import random
import sys
import time
import types
import typing as t
from dataclasses import dataclass, field
from multiprocessing import Process, Queue
from threading import Event, Thread

# POSIX resource limits (best-effort). On non-POSIX systems this becomes a no-op.
try:
    import resource  # type: ignore
    _HAS_RESOURCE = True
except Exception:
    _HAS_RESOURCE = False

# ------------------------------------------------------------------------------
# Logging setup (library-friendly: no handlers if root already configured)
# ------------------------------------------------------------------------------
_LOG = logging.getLogger("datafabric.udf")
if not _LOG.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s trace=%(trace_id)s udf=%(udf_name)s %(message)s"
    )
    handler.setFormatter(formatter)
    _LOG.addHandler(handler)
    _LOG.setLevel(logging.INFO)


def _now_ns() -> int:
    return time.time_ns()


def _default(obj: t.Any) -> t.Any:
    try:
        return json.JSONEncoder().default(obj)
    except Exception:
        return repr(obj)


# ------------------------------------------------------------------------------
# Utilities: semantic versions, hashing, tiny LRU
# ------------------------------------------------------------------------------
def semver_tuple(v: str) -> t.Tuple[int, int, int]:
    major, minor, patch = (v.split(".") + ["0", "0", "0"])[:3]
    return int(major), int(minor), int(patch)


def hash_callable(fn: t.Callable[..., t.Any]) -> str:
    try:
        src = inspect.getsource(fn)
    except OSError:
        src = repr(fn)
    sig = str(inspect.signature(fn))
    payload = (src + "\n" + sig).encode("utf-8", errors="ignore")
    return hashlib.sha256(payload).hexdigest()


class LRUCache:
    __slots__ = ("_cap", "_store", "_order")

    def __init__(self, capacity: int = 0) -> None:
        self._cap = max(0, int(capacity))
        self._store: dict[t.Any, t.Any] = {}
        self._order: list[t.Any] = []

    def get(self, key: t.Any) -> t.Any:
        if self._cap == 0:
            return None
        if key in self._store:
            # move to end (MRU)
            try:
                self._order.remove(key)
            except ValueError:
                pass
            self._order.append(key)
            return self._store[key]
        return None

    def put(self, key: t.Any, value: t.Any) -> None:
        if self._cap == 0:
            return
        if key in self._store:
            self._store[key] = value
            try:
                self._order.remove(key)
            except ValueError:
                pass
            self._order.append(key)
            return
        if len(self._order) >= self._cap:
            oldest = self._order.pop(0)
            self._store.pop(oldest, None)
        self._order.append(key)
        self._store[key] = value


# ------------------------------------------------------------------------------
# Data classes: metadata, config, metrics, results
# ------------------------------------------------------------------------------
@dataclass(frozen=True)
class UDFMetadata:
    name: str
    version: str = "0.1.0"
    description: str = ""
    author: str = ""
    tags: t.Tuple[str, ...] = field(default_factory=tuple)
    integrity: str = ""  # sha256 of code + signature
    inputs_schema: t.Optional[t.Dict[str, t.Any]] = None  # optional loose schema
    output_schema: t.Optional[t.Dict[str, t.Any]] = None


@dataclass(frozen=True)
class UDFExecutionConfig:
    mode: t.Literal["inproc", "isolated"] = "isolated"
    timeout_sec: float = 10.0
    max_retries: int = 0
    backoff_base: float = 0.2
    backoff_factor: float = 2.0
    backoff_max: float = 2.5
    jitter: float = 0.05
    deterministic_seed: t.Optional[int] = None
    cache_size: int = 0  # per-UDF LRU size
    cpu_time_soft_sec: t.Optional[float] = None  # POSIX only
    cpu_time_hard_sec: t.Optional[float] = None  # POSIX only
    address_space_limit_mb: t.Optional[int] = None  # POSIX only
    niceness: t.Optional[int] = None  # POSIX only


@dataclass
class ExecutionMetrics:
    start_ns: int = 0
    end_ns: int = 0
    duration_ms: float = 0.0
    attempts: int = 0
    cache_hit: bool = False
    validated_input: bool = False
    validated_output: bool = False

    def finalize(self) -> None:
        self.duration_ms = (self.end_ns - self.start_ns) / 1e6


@dataclass
class ExecutionResult:
    ok: bool
    value: t.Any = None
    error: t.Optional[str] = None
    metrics: ExecutionMetrics = field(default_factory=ExecutionMetrics)
    meta: t.Dict[str, t.Any] = field(default_factory=dict)


# ------------------------------------------------------------------------------
# Validation helpers (annotation-based; best-effort and fast)
# ------------------------------------------------------------------------------
_T = t.TypeVar("_T")


def _is_instance(value: t.Any, typ: t.Any) -> bool:
    """Best-effort runtime check for typing annotations."""
    origin = t.get_origin(typ)
    args = t.get_args(typ)
    if typ is t.Any or typ is None or typ is object:
        return True
    if origin is None:
        try:
            return isinstance(value, typ)  # type: ignore[arg-type]
        except Exception:
            return True
    if origin in (list, t.List):
        if not isinstance(value, list):
            return False
        if not args:
            return True
        return all(_is_instance(v, args[0]) for v in value)
    if origin in (tuple, t.Tuple):
        if not isinstance(value, tuple):
            return False
        if not args:
            return True
        if len(args) == 2 and args[1] is Ellipsis:
            return all(_is_instance(v, args[0]) for v in value)
        if len(args) != len(value):
            return False
        return all(_is_instance(v, a) for v, a in zip(value, args))
    if origin in (dict, t.Dict):
        if not isinstance(value, dict):
            return False
        if not args:
            return True
        kt, vt = args
        return all(_is_instance(k, kt) and _is_instance(v, vt) for k, v in value.items())
    if origin in (t.Union,):  # includes Optional
        return any(_is_instance(value, a) for a in args)
    if origin in (set, t.Set, frozenset, t.FrozenSet):
        if not isinstance(value, (set, frozenset)):
            return False
        if not args:
            return True
        return all(_is_instance(v, args[0]) for v in value)
    return True


def _validate_signature_inputs(fn: t.Callable[..., t.Any], args: tuple, kwargs: dict) -> bool:
    sig = inspect.signature(fn)
    bound = sig.bind_partial(*args, **kwargs)
    bound.apply_defaults()
    hints = t.get_type_hints(fn)
    ok = True
    for name, value in bound.arguments.items():
        if name in hints:
            ok = ok and _is_instance(value, hints[name])
    return ok


def _validate_return(fn: t.Callable[..., t.Any], value: t.Any) -> bool:
    hints = t.get_type_hints(fn)
    if "return" not in hints:
        return True
    return _is_instance(value, hints["return"])


# ------------------------------------------------------------------------------
# Process isolation execution
# ------------------------------------------------------------------------------
def _apply_posix_limits(cfg: UDFExecutionConfig) -> None:
    if not _HAS_RESOURCE:
        return
    # CPU time limits
    if cfg.cpu_time_soft_sec is not None or cfg.cpu_time_hard_sec is not None:
        soft = int(cfg.cpu_time_soft_sec or 0)
        hard = int(cfg.cpu_time_hard_sec or soft or 1)
        resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))
    # Address space / virtual memory
    if cfg.address_space_limit_mb is not None:
        limit_bytes = int(cfg.address_space_limit_mb) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
    # Niceness
    if cfg.niceness is not None:
        try:
            os.nice(int(cfg.niceness))
        except Exception:
            pass


def _seed_deterministic(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as _np  # type: ignore
        _np.random.seed(seed)
    except Exception:
        pass


def _worker_target(
    fn: t.Callable[..., t.Any],
    args: tuple,
    kwargs: dict,
    cfg: UDFExecutionConfig,
    out: Queue,
) -> None:
    try:
        if cfg.deterministic_seed is not None:
            _seed_deterministic(cfg.deterministic_seed)
        _apply_posix_limits(cfg)
        result = fn(*args, **kwargs)
        out.put(("ok", result, None))
    except BaseException as e:
        out.put(("err", None, f"{type(e).__name__}: {e}"))


def _run_isolated(
    fn: t.Callable[..., t.Any], args: tuple, kwargs: dict, cfg: UDFExecutionConfig
) -> ExecutionResult:
    q: Queue = Queue(maxsize=1)
    p = Process(target=_worker_target, args=(fn, args, kwargs, cfg, q), daemon=True)
    p.start()
    try:
        status, value, err = q.get(timeout=cfg.timeout_sec)
    except queue.Empty:
        p.terminate()
        return ExecutionResult(ok=False, error="TimeoutError: execution timed out")
    finally:
        if p.is_alive():
            p.terminate()
        p.join()
    if status == "ok":
        return ExecutionResult(ok=True, value=value)
    return ExecutionResult(ok=False, error=err or "UnknownError")


# ------------------------------------------------------------------------------
# Core UDF wrapper
# ------------------------------------------------------------------------------
class PythonUDF:
    def __init__(
        self,
        fn: t.Callable[..., t.Any],
        metadata: UDFMetadata,
        exec_cfg: UDFExecutionConfig | None = None,
    ) -> None:
        self._fn = fn
        self._meta = metadata
        self._cfg = exec_cfg or UDFExecutionConfig()
        self._cache = LRUCache(self._cfg.cache_size)
        if not self._meta.integrity:
            object.__setattr__(self._meta, "integrity", hash_callable(fn))

    @property
    def metadata(self) -> UDFMetadata:
        return self._meta

    @property
    def exec_cfg(self) -> UDFExecutionConfig:
        return self._cfg

    def _cache_key(self, args: tuple, kwargs: dict) -> str:
        try:
            payload = json.dumps([args, kwargs], default=_default, sort_keys=True)
        except TypeError:
            # fallback for non-serializable
            payload = repr((args, kwargs))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _execute_once(
        self, args: tuple, kwargs: dict, trace_id: str
    ) -> ExecutionResult:
        cfg = self._cfg

        if cfg.mode == "isolated":
            res = _run_isolated(self._fn, args, kwargs, cfg)
        else:
            # In-process with timeout enforced by watchdog thread
            result_container: dict[str, t.Any] = {"status": None, "value": None, "error": None}
            done = Event()

            def runner():
                try:
                    if cfg.deterministic_seed is not None:
                        _seed_deterministic(cfg.deterministic_seed)
                    result_container["value"] = self._fn(*args, **kwargs)
                    result_container["status"] = "ok"
                except BaseException as e:
                    result_container["status"] = "err"
                    result_container["error"] = f"{type(e).__name__}: {e}"
                finally:
                    done.set()

            t_worker = Thread(target=runner, daemon=True)
            t_worker.start()
            finished = done.wait(timeout=cfg.timeout_sec)
            if not finished:
                return ExecutionResult(ok=False, error="TimeoutError: execution timed out")
            if result_container["status"] == "ok":
                return ExecutionResult(ok=True, value=result_container["value"])
            return ExecutionResult(ok=False, error=result_container["error"] or "UnknownError")

        return res

    def __call__(self, *args: t.Any, **kwargs: t.Any) -> ExecutionResult:
        trace_id = hashlib.md5(f"{_now_ns()}-{id(self)}".encode()).hexdigest()[:16]
        extra = {"trace_id": trace_id, "udf_name": self._meta.name}
        metrics = ExecutionMetrics()
        metrics.start_ns = _now_ns()

        # Cache
        key = self._cache_key(args, kwargs)
        cached = self._cache.get(key)
        if cached is not None:
            metrics.cache_hit = True
            res: ExecutionResult = cached
            res.metrics = metrics  # refresh metrics on read-through (duration set below)
            metrics.end_ns = _now_ns()
            metrics.finalize()
            _LOG.info("cache hit", extra=extra)
            return res

        # Validate inputs
        metrics.validated_input = _validate_signature_inputs(self._fn, args, kwargs)

        # Attempts with backoff
        attempts = 0
        last_res: ExecutionResult | None = None
        while True:
            attempts += 1
            metrics.attempts = attempts
            res = self._execute_once(args, kwargs, trace_id)
            if res.ok:
                # Validate output
                metrics.validated_output = _validate_return(self._fn, res.value)
                res.metrics = metrics
                self._cache.put(key, res)
                metrics.end_ns = _now_ns()
                metrics.finalize()
                _LOG.info(
                    "ok duration_ms=%.3f attempts=%d cache=%s",
                    extra=extra,
                    msg="",  # placeholder for fmt compatibility
                )
                return res
            last_res = res
            if attempts > self._cfg.max_retries:
                break
            # Backoff
            delay = min(
                self._cfg.backoff_base * (self._cfg.backoff_factor ** (attempts - 1)),
                self._cfg.backoff_max,
            )
            delay += random.uniform(0, self._cfg.jitter)
            _LOG.warning(
                "retry=%d err=%s backoff=%.3f",
                attempts,
                res.error,
                delay,
                extra=extra,
            )
            time.sleep(delay)

        # Finalize metrics and return error
        assert last_res is not None
        last_res.metrics = metrics
        metrics.end_ns = _now_ns()
        metrics.finalize()
        _LOG.error("failed err=%s attempts=%d", last_res.error, attempts, extra=extra)
        return last_res


# ------------------------------------------------------------------------------
# Registry for UDFs with versioning
# ------------------------------------------------------------------------------
class UDFRegistry:
    def __init__(self) -> None:
        # mapping: name -> version -> PythonUDF
        self._store: dict[str, dict[str, PythonUDF]] = {}

    def register(self, udf: PythonUDF) -> None:
        name = udf.metadata.name
        ver = udf.metadata.version
        self._store.setdefault(name, {})
        if ver in self._store[name]:
            raise ValueError(f"UDF {name}@{ver} already registered")
        self._store[name][ver] = udf
        # maintain "latest" alias implicitly by semver
        # no explicit alias storage; resolve on get()

    def unregister(self, name: str, version: str) -> None:
        if name not in self._store or version not in self._store[name]:
            raise KeyError(f"UDF {name}@{version} not found")
        del self._store[name][version]
        if not self._store[name]:
            del self._store[name]

    def get(self, name: str, version: str | t.Literal["latest"] = "latest") -> PythonUDF:
        if name not in self._store or not self._store[name]:
            raise KeyError(f"UDF {name} not found")
        if version == "latest":
            versions = sorted(self._store[name].keys(), key=semver_tuple)
            return self._store[name][versions[-1]]
        if version not in self._store[name]:
            raise KeyError(f"UDF {name}@{version} not found")
        return self._store[name][version]

    def list(self, name: str | None = None) -> dict[str, list[str]]:
        if name:
            if name not in self._store:
                return {}
            return {name: sorted(self._store[name].keys(), key=semver_tuple)}
        return {k: sorted(v.keys(), key=semver_tuple) for k, v in self._store.items()}


# Global default registry
_default_registry = UDFRegistry()


# ------------------------------------------------------------------------------
# Decorator for concise registration
# ------------------------------------------------------------------------------
def udf(
    name: str,
    version: str = "0.1.0",
    description: str = "",
    author: str = "",
    tags: t.Iterable[str] = (),
    inputs_schema: t.Optional[dict] = None,
    output_schema: t.Optional[dict] = None,
    exec_cfg: UDFExecutionConfig | None = None,
    registry: UDFRegistry | None = None,
) -> t.Callable[[t.Callable[..., t.Any]], PythonUDF]:
    """
    Decorator to declare and register a UDF.

    Usage:
        @udf(name="sum_ints", version="1.0.0")
        def add(a: int, b: int) -> int:
            return a + b
    """
    reg = registry or _default_registry
    tags_tuple = tuple(tags)

    def wrapper(fn: t.Callable[..., t.Any]) -> PythonUDF:
        meta = UDFMetadata(
            name=name,
            version=version,
            description=description,
            author=author,
            tags=tags_tuple,
            inputs_schema=inputs_schema,
            output_schema=output_schema,
            integrity=hash_callable(fn),
        )
        udf_obj = PythonUDF(fn, metadata=meta, exec_cfg=exec_cfg)
        reg.register(udf_obj)
        return udf_obj

    return wrapper


# ------------------------------------------------------------------------------
# Public API surface
# ------------------------------------------------------------------------------
__all__ = [
    "UDFMetadata",
    "UDFExecutionConfig",
    "ExecutionMetrics",
    "ExecutionResult",
    "PythonUDF",
    "UDFRegistry",
    "udf",
    "_default_registry",
]
