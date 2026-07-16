# agent_mash/monitoring/diagnostics/health_check.py
# -*- coding: utf-8 -*-
"""
Industrial Health Check framework for agent_mash.

Features:
- Async-first checks with timeouts
- Liveness vs readiness semantics
- Parallel execution with concurrency limit
- Deterministic aggregation into overall status
- Structured JSON export
- Safe defaults, minimal dependencies (stdlib only)
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

logger = logging.getLogger(__name__)


class HealthError(Exception):
    pass


class CheckRegistrationError(HealthError):
    pass


class CheckExecutionError(HealthError):
    pass


class HealthStatus(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    FAIL = "fail"
    TIMEOUT = "timeout"
    SKIP = "skip"


class HealthMode(str, Enum):
    LIVENESS = "liveness"
    READINESS = "readiness"


@dataclass(frozen=True)
class CheckContext:
    """
    Context passed to checks. Add adapters to carry clients (db, redis, etc.)
    without importing their types here.
    """
    mode: HealthMode
    now_epoch: float
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: HealthStatus
    latency_ms: int
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    critical: bool = False  # if True: failure should fail readiness
    tags: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "latency_ms": int(self.latency_ms),
            "message": self.message,
            "details": dict(self.details),
            "critical": bool(self.critical),
            "tags": list(self.tags),
        }


class HealthCheck(Protocol):
    @property
    def name(self) -> str:
        ...

    async def run(self, ctx: CheckContext) -> CheckResult:
        ...


@dataclass(frozen=True)
class HealthReport:
    mode: HealthMode
    status: HealthStatus
    started_at_epoch: float
    finished_at_epoch: float
    latency_ms: int
    results: Tuple[CheckResult, ...]
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "status": self.status.value,
            "started_at_epoch": self.started_at_epoch,
            "finished_at_epoch": self.finished_at_epoch,
            "latency_ms": int(self.latency_ms),
            "results": [r.to_dict() for r in self.results],
            "meta": dict(self.meta),
        }

    def to_json(self, pretty: bool = True) -> str:
        if pretty:
            return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class HealthCheckConfig:
    """
    Operational configuration.
    """
    timeout_seconds: int = 3
    concurrency: int = 8
    include_skipped: bool = True
    strict: bool = False  # if True: unexpected exceptions propagate
    # aggregation behavior
    degraded_on_timeout_in_liveness: bool = True
    fail_on_any_error_in_readiness: bool = True


def _now() -> float:
    return time.time()


async def _with_timeout(coro: Awaitable[CheckResult], timeout_s: int) -> CheckResult:
    return await asyncio.wait_for(coro, timeout=max(1, int(timeout_s)))


def _aggregate_status(mode: HealthMode, cfg: HealthCheckConfig, results: Sequence[CheckResult]) -> HealthStatus:
    """
    Aggregation rules (deterministic):
    - READINESS:
        - any FAIL/TIMEOUT on critical => FAIL
        - if fail_on_any_error_in_readiness and any FAIL/TIMEOUT => FAIL
        - any DEGRADED => DEGRADED
        - otherwise OK (SKIP ignored)
    - LIVENESS:
        - any FAIL on critical => FAIL
        - TIMEOUT yields DEGRADED if configured, else FAIL
        - any FAIL => FAIL
        - any DEGRADED => DEGRADED
        - otherwise OK
    """
    if not results:
        return HealthStatus.OK

    has_degraded = any(r.status == HealthStatus.DEGRADED for r in results)
    has_fail = any(r.status == HealthStatus.FAIL for r in results)
    has_timeout = any(r.status == HealthStatus.TIMEOUT for r in results)

    critical_fail = any((r.critical and r.status in (HealthStatus.FAIL, HealthStatus.TIMEOUT)) for r in results)

    if mode == HealthMode.READINESS:
        if critical_fail:
            return HealthStatus.FAIL
        if cfg.fail_on_any_error_in_readiness and (has_fail or has_timeout):
            return HealthStatus.FAIL
        if has_degraded:
            return HealthStatus.DEGRADED
        if has_fail or has_timeout:
            return HealthStatus.FAIL
        return HealthStatus.OK

    # LIVENESS
    if any((r.critical and r.status == HealthStatus.FAIL) for r in results):
        return HealthStatus.FAIL
    if has_timeout:
        return HealthStatus.DEGRADED if cfg.degraded_on_timeout_in_liveness else HealthStatus.FAIL
    if has_fail:
        return HealthStatus.FAIL
    if has_degraded:
        return HealthStatus.DEGRADED
    return HealthStatus.OK


class HealthRegistry:
    """
    Registry for health checks.
    """

    def __init__(self) -> None:
        self._checks: Dict[str, HealthCheck] = {}

    def register(self, check: HealthCheck) -> None:
        name = getattr(check, "name", None)
        if not isinstance(name, str) or not name.strip():
            raise CheckRegistrationError("HealthCheck must have a non-empty 'name'")
        if name in self._checks:
            raise CheckRegistrationError(f"Duplicate check name: {name}")
        self._checks[name] = check

    def register_fn(
        self,
        name: str,
        fn: Callable[[CheckContext], Awaitable[Tuple[HealthStatus, str, Dict[str, Any]]]],
        *,
        critical: bool = False,
        tags: Optional[Iterable[str]] = None,
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise CheckRegistrationError("name must be non-empty")

        t = tuple(str(x).strip() for x in (tags or []) if str(x).strip())

        class _FnCheck:
            @property
            def name(self) -> str:
                return name

            async def run(self, ctx: CheckContext) -> CheckResult:
                start = _now()
                status, message, details = await fn(ctx)
                latency = int((_now() - start) * 1000)
                if not isinstance(status, HealthStatus):
                    status = HealthStatus(str(status))
                return CheckResult(
                    name=name,
                    status=status,
                    latency_ms=latency,
                    message=str(message or ""),
                    details=dict(details or {}),
                    critical=bool(critical),
                    tags=t,
                )

        self.register(_FnCheck())

    def list(self) -> Tuple[HealthCheck, ...]:
        return tuple(self._checks[k] for k in sorted(self._checks.keys()))

    def get(self, name: str) -> HealthCheck:
        try:
            return self._checks[name]
        except KeyError as e:
            raise CheckRegistrationError(f"Unknown check: {name}") from e


class HealthChecker:
    """
    Executes checks from a registry and produces HealthReport.
    """

    def __init__(self, registry: HealthRegistry, config: Optional[HealthCheckConfig] = None) -> None:
        self._registry = registry
        self._cfg = config or HealthCheckConfig()

    @property
    def config(self) -> HealthCheckConfig:
        return self._cfg

    async def run(
        self,
        mode: HealthMode,
        *,
        meta: Optional[Mapping[str, Any]] = None,
        only: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
    ) -> HealthReport:
        started = _now()
        ctx = CheckContext(mode=mode, now_epoch=started, meta=dict(meta or {}))

        checks = list(self._registry.list())
        if only is not None:
            only_set = {str(x).strip() for x in only if str(x).strip()}
            checks = [c for c in checks if c.name in only_set]
        if exclude is not None:
            ex_set = {str(x).strip() for x in exclude if str(x).strip()}
            checks = [c for c in checks if c.name not in ex_set]

        sem = asyncio.Semaphore(max(1, int(self._cfg.concurrency)))

        async def _run_one(ch: HealthCheck) -> CheckResult:
            async with sem:
                start = _now()
                try:
                    res = await _with_timeout(ch.run(ctx), timeout_s=self._cfg.timeout_seconds)
                    return res
                except asyncio.TimeoutError:
                    latency = int((_now() - start) * 1000)
                    return CheckResult(
                        name=ch.name,
                        status=HealthStatus.TIMEOUT,
                        latency_ms=latency,
                        message="timeout",
                        details={"timeout_seconds": int(self._cfg.timeout_seconds)},
                        critical=False,
                        tags=(),
                    )
                except Exception as e:
                    if self._cfg.strict:
                        raise
                    latency = int((_now() - start) * 1000)
                    logger.exception("Health check failed: %s", ch.name)
                    return CheckResult(
                        name=ch.name,
                        status=HealthStatus.FAIL,
                        latency_ms=latency,
                        message=f"{type(e).__name__}",
                        details={"error": str(e)},
                        critical=False,
                        tags=(),
                    )

        results_list: List[CheckResult] = []
        if checks:
            results_list = await asyncio.gather(*[_run_one(c) for c in checks])
        else:
            results_list = []

        # Optional: drop SKIP (not produced by default)
        if not self._cfg.include_skipped:
            results_list = [r for r in results_list if r.status != HealthStatus.SKIP]

        # Deterministic sort for stable outputs
        results_list.sort(key=lambda r: r.name)

        status = _aggregate_status(mode, self._cfg, results_list)

        finished = _now()
        report = HealthReport(
            mode=mode,
            status=status,
            started_at_epoch=started,
            finished_at_epoch=finished,
            latency_ms=int((finished - started) * 1000),
            results=tuple(results_list),
            meta=dict(meta or {}),
        )
        return report


__all__ = [
    "HealthStatus",
    "HealthMode",
    "CheckContext",
    "CheckResult",
    "HealthReport",
    "HealthCheckConfig",
    "HealthRegistry",
    "HealthChecker",
    "HealthError",
    "CheckRegistrationError",
    "CheckExecutionError",
]
