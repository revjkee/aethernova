# agent_mash/monitoring/diagnostics/final_health_check.py
from __future__ import annotations

import asyncio
import dataclasses
import enum
import json
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


class HealthCheckError(Exception):
    pass


class HealthStatus(str, enum.Enum):
    OK = "ok"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


_STATUS_PRIORITY: Dict[HealthStatus, int] = {
    HealthStatus.OK: 0,
    HealthStatus.DEGRADED: 1,
    HealthStatus.CRITICAL: 2,
    HealthStatus.UNKNOWN: 3,
}


@dataclass(frozen=True)
class CheckConfig:
    timeout_s: float = 2.0
    retries: int = 0
    retry_backoff_s: float = 0.05
    critical: bool = False
    tags: Tuple[str, ...] = ()

    def normalized(self) -> "CheckConfig":
        t = float(self.timeout_s)
        if t <= 0:
            raise HealthCheckError("timeout_must_be_positive")
        r = int(self.retries)
        if r < 0:
            raise HealthCheckError("retries_must_be_non_negative")
        b = float(self.retry_backoff_s)
        if b < 0:
            raise HealthCheckError("retry_backoff_must_be_non_negative")
        return CheckConfig(
            timeout_s=t,
            retries=r,
            retry_backoff_s=b,
            critical=bool(self.critical),
            tags=tuple(sorted({str(x).strip() for x in (self.tags or ()) if str(x).strip()})),
        )


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: HealthStatus
    duration_ms: int
    message: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)
    critical: bool = False
    tags: Tuple[str, ...] = ()
    error_type: Optional[str] = None
    error_trace: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "duration_ms": int(self.duration_ms),
            "message": self.message,
            "details": dict(self.details or {}),
            "critical": bool(self.critical),
            "tags": list(self.tags or ()),
            "error_type": self.error_type,
            "error_trace": self.error_trace,
        }


@dataclass(frozen=True)
class HealthReport:
    at_epoch_s: int
    total_duration_ms: int
    status: HealthStatus
    checks: Tuple[CheckResult, ...]
    summary: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "at_epoch_s": int(self.at_epoch_s),
            "total_duration_ms": int(self.total_duration_ms),
            "status": self.status.value,
            "summary": dict(self.summary or {}),
            "metadata": dict(self.metadata or {}),
            "checks": [c.to_dict() for c in self.checks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


AsyncCheckFn = Callable[[], Awaitable[Union[HealthStatus, CheckResult, Mapping[str, Any], str, None]]]
SyncCheckFn = Callable[[], Union[HealthStatus, CheckResult, Mapping[str, Any], str, None]]
CheckFn = Union[AsyncCheckFn, SyncCheckFn]


@dataclass(frozen=True)
class RegisteredCheck:
    name: str
    fn: CheckFn
    config: CheckConfig
    dependencies: Tuple[str, ...] = ()

    def normalized(self) -> "RegisteredCheck":
        n = str(self.name).strip()
        if not n:
            raise HealthCheckError("check_name_required")
        if not callable(self.fn):
            raise HealthCheckError("check_fn_must_be_callable")
        cfg = self.config.normalized()
        deps = tuple(sorted({str(x).strip() for x in (self.dependencies or ()) if str(x).strip()}))
        if n in deps:
            raise HealthCheckError("check_cannot_depend_on_itself")
        return RegisteredCheck(name=n, fn=self.fn, config=cfg, dependencies=deps)


class HealthRegistry:
    def __init__(self) -> None:
        self._checks: Dict[str, RegisteredCheck] = {}

    def register(
        self,
        *,
        name: str,
        fn: CheckFn,
        config: Optional[CheckConfig] = None,
        dependencies: Optional[Sequence[str]] = None,
    ) -> None:
        rc = RegisteredCheck(
            name=name,
            fn=fn,
            config=config or CheckConfig(),
            dependencies=tuple(dependencies or ()),
        ).normalized()
        if rc.name in self._checks:
            raise HealthCheckError("duplicate_check_name")
        self._checks[rc.name] = rc

    def list_checks(self) -> Tuple[RegisteredCheck, ...]:
        return tuple(self._checks[k] for k in sorted(self._checks.keys()))

    def get(self, name: str) -> RegisteredCheck:
        try:
            return self._checks[name]
        except KeyError as e:
            raise HealthCheckError("check_not_found") from e

    def resolve_execution_plan(self, only: Optional[Sequence[str]] = None) -> Tuple[RegisteredCheck, ...]:
        """
        Возвращает топологически отсортированный план.
        Проверяет циклы и отсутствующие зависимости.
        """
        if only is None:
            target = set(self._checks.keys())
        else:
            target = {str(x).strip() for x in only if str(x).strip()}
            for n in target:
                if n not in self._checks:
                    raise HealthCheckError("unknown_check_in_only")

        # Expand deps
        expanded = set()

        def add_with_deps(n: str) -> None:
            if n in expanded:
                return
            rc = self.get(n)
            expanded.add(n)
            for d in rc.dependencies:
                if d not in self._checks:
                    raise HealthCheckError("missing_dependency")
                add_with_deps(d)

        for n in list(target):
            add_with_deps(n)

        # Topological sort (Kahn)
        indeg: Dict[str, int] = {n: 0 for n in expanded}
        adj: Dict[str, List[str]] = {n: [] for n in expanded}
        for n in expanded:
            rc = self.get(n)
            for d in rc.dependencies:
                if d in expanded:
                    indeg[n] += 1
                    adj[d].append(n)

        queue = [n for n, deg in indeg.items() if deg == 0]
        queue.sort()
        out: List[str] = []
        while queue:
            n = queue.pop(0)
            out.append(n)
            for m in adj.get(n, []):
                indeg[m] -= 1
                if indeg[m] == 0:
                    queue.append(m)
                    queue.sort()

        if len(out) != len(expanded):
            raise HealthCheckError("dependency_cycle_detected")

        return tuple(self.get(n) for n in out)


@dataclass(frozen=True)
class RunnerConfig:
    max_concurrency: int = 8
    fail_fast: bool = False
    include_traces: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def normalized(self) -> "RunnerConfig":
        mc = int(self.max_concurrency)
        if mc <= 0:
            raise HealthCheckError("max_concurrency_must_be_positive")
        return RunnerConfig(
            max_concurrency=mc,
            fail_fast=bool(self.fail_fast),
            include_traces=bool(self.include_traces),
            metadata=dict(self.metadata or {}),
        )


class FinalHealthChecker:
    def __init__(self, registry: HealthRegistry, config: Optional[RunnerConfig] = None) -> None:
        self._registry = registry
        self._config = (config or RunnerConfig()).normalized()

    async def run(self, *, only: Optional[Sequence[str]] = None) -> HealthReport:
        plan = self._registry.resolve_execution_plan(only=only)
        started = time.monotonic()
        at_epoch_s = int(time.time())

        # Dependency-aware execution: we can parallelize only checks whose deps are finished.
        semaphore = asyncio.Semaphore(self._config.max_concurrency)
        results: Dict[str, CheckResult] = {}
        pending: Dict[str, asyncio.Task[CheckResult]] = {}

        deps_map: Dict[str, Tuple[str, ...]] = {rc.name: rc.dependencies for rc in plan}
        remaining = set(rc.name for rc in plan)

        async def run_one(rc: RegisteredCheck) -> CheckResult:
            async with semaphore:
                return await self._execute_check(rc)

        def deps_done(name: str) -> bool:
            return all(d in results for d in deps_map.get(name, ()))

        while remaining:
            # Schedule all ready checks
            scheduled_any = False
            for name in sorted(list(remaining)):
                if name in pending:
                    continue
                if not deps_done(name):
                    continue
                rc = self._registry.get(name)
                pending[name] = asyncio.create_task(run_one(rc))
                scheduled_any = True

            if not scheduled_any and pending:
                # Wait for at least one check completion
                done, _ = await asyncio.wait(set(pending.values()), return_when=asyncio.FIRST_COMPLETED)
            elif not scheduled_any and not pending:
                # Deadlock indicates cycle or missing deps, but those already checked earlier.
                raise HealthCheckError("execution_plan_deadlock")
            else:
                done, _ = await asyncio.wait(set(pending.values()), return_when=asyncio.FIRST_COMPLETED)

            # Collect done
            finished_names = [n for n, t in pending.items() if t in done]
            for n in finished_names:
                t = pending.pop(n)
                try:
                    res = t.result()
                except Exception as e:
                    # Should not happen because _execute_check catches, but keep safe.
                    res = CheckResult(
                        name=n,
                        status=HealthStatus.CRITICAL,
                        duration_ms=0,
                        message="runner_exception",
                        details={"error": str(e)},
                        critical=True,
                        error_type=type(e).__name__,
                        error_trace=traceback.format_exc() if self._config.include_traces else None,
                    )
                results[n] = res
                remaining.discard(n)

                if self._config.fail_fast and res.status in (HealthStatus.CRITICAL,):
                    # Cancel remaining tasks
                    for pt in pending.values():
                        pt.cancel()
                    pending.clear()
                    remaining.clear()
                    break

        total_ms = int((time.monotonic() - started) * 1000)
        ordered_results = tuple(results[rc.name] for rc in plan if rc.name in results)

        status = self._aggregate_status(ordered_results)
        summary = self._build_summary(ordered_results)

        return HealthReport(
            at_epoch_s=at_epoch_s,
            total_duration_ms=total_ms,
            status=status,
            checks=ordered_results,
            summary=summary,
            metadata=dict(self._config.metadata or {}),
        )

    async def _execute_check(self, rc: RegisteredCheck) -> CheckResult:
        cfg = rc.config.normalized()
        started = time.monotonic()

        async def call_fn() -> Union[HealthStatus, CheckResult, Mapping[str, Any], str, None]:
            out = rc.fn()
            if asyncio.iscoroutine(out) or isinstance(out, Awaitable):
                return await out  # type: ignore[misc]
            return out  # type: ignore[return-value]

        last_exc: Optional[BaseException] = None
        for attempt in range(cfg.retries + 1):
            try:
                result = await asyncio.wait_for(call_fn(), timeout=cfg.timeout_s)
                duration_ms = int((time.monotonic() - started) * 1000)

                # Normalize output
                if isinstance(result, CheckResult):
                    return dataclasses.replace(
                        result,
                        name=rc.name,
                        duration_ms=int(result.duration_ms) if result.duration_ms else duration_ms,
                        critical=bool(result.critical) or bool(cfg.critical),
                        tags=tuple(sorted(set(result.tags or ()) | set(cfg.tags or ()))),
                    )

                if isinstance(result, HealthStatus):
                    return CheckResult(
                        name=rc.name,
                        status=result,
                        duration_ms=duration_ms,
                        message="ok" if result == HealthStatus.OK else "",
                        details={},
                        critical=bool(cfg.critical),
                        tags=cfg.tags,
                    )

                if isinstance(result, str):
                    return CheckResult(
                        name=rc.name,
                        status=HealthStatus.OK,
                        duration_ms=duration_ms,
                        message=result,
                        details={},
                        critical=bool(cfg.critical),
                        tags=cfg.tags,
                    )

                if isinstance(result, Mapping):
                    # If mapping contains status, use it; else OK with details.
                    st = result.get("status")
                    status = HealthStatus(str(st)) if st in set(x.value for x in HealthStatus) else HealthStatus.OK
                    msg = str(result.get("message") or "")
                    det = dict(result)
                    det.pop("status", None)
                    det.pop("message", None)
                    return CheckResult(
                        name=rc.name,
                        status=status,
                        duration_ms=duration_ms,
                        message=msg,
                        details=det,
                        critical=bool(cfg.critical),
                        tags=cfg.tags,
                    )

                # None treated as OK
                return CheckResult(
                    name=rc.name,
                    status=HealthStatus.OK,
                    duration_ms=duration_ms,
                    message="ok",
                    details={},
                    critical=bool(cfg.critical),
                    tags=cfg.tags,
                )

            except asyncio.TimeoutError as e:
                last_exc = e
                if attempt < cfg.retries:
                    await asyncio.sleep(cfg.retry_backoff_s)
                    continue
                duration_ms = int((time.monotonic() - started) * 1000)
                return CheckResult(
                    name=rc.name,
                    status=HealthStatus.CRITICAL if cfg.critical else HealthStatus.DEGRADED,
                    duration_ms=duration_ms,
                    message="timeout",
                    details={"timeout_s": cfg.timeout_s, "attempts": attempt + 1},
                    critical=bool(cfg.critical),
                    tags=cfg.tags,
                    error_type="TimeoutError",
                    error_trace=None,
                )
            except asyncio.CancelledError:
                duration_ms = int((time.monotonic() - started) * 1000)
                return CheckResult(
                    name=rc.name,
                    status=HealthStatus.UNKNOWN,
                    duration_ms=duration_ms,
                    message="cancelled",
                    details={},
                    critical=bool(cfg.critical),
                    tags=cfg.tags,
                )
            except Exception as e:
                last_exc = e
                if attempt < cfg.retries:
                    await asyncio.sleep(cfg.retry_backoff_s)
                    continue
                duration_ms = int((time.monotonic() - started) * 1000)
                return CheckResult(
                    name=rc.name,
                    status=HealthStatus.CRITICAL if cfg.critical else HealthStatus.DEGRADED,
                    duration_ms=duration_ms,
                    message="exception",
                    details={"error": str(e), "attempts": attempt + 1},
                    critical=bool(cfg.critical),
                    tags=cfg.tags,
                    error_type=type(e).__name__,
                    error_trace=traceback.format_exc() if self._config.include_traces else None,
                )

        # Defensive fallback
        duration_ms = int((time.monotonic() - started) * 1000)
        return CheckResult(
            name=rc.name,
            status=HealthStatus.CRITICAL if cfg.critical else HealthStatus.DEGRADED,
            duration_ms=duration_ms,
            message="unknown_failure",
            details={"error": str(last_exc) if last_exc else ""},
            critical=bool(cfg.critical),
            tags=cfg.tags,
            error_type=type(last_exc).__name__ if last_exc else None,
            error_trace=traceback.format_exc() if (last_exc and self._config.include_traces) else None,
        )

    def _aggregate_status(self, results: Sequence[CheckResult]) -> HealthStatus:
        # Priority: CRITICAL (any critical check failing) -> CRITICAL
        # Else DEGRADED if any degraded
        # Else OK
        if not results:
            return HealthStatus.UNKNOWN

        any_degraded = False
        for r in results:
            if r.status == HealthStatus.CRITICAL:
                return HealthStatus.CRITICAL
            if r.critical and r.status != HealthStatus.OK:
                return HealthStatus.CRITICAL
            if r.status == HealthStatus.DEGRADED:
                any_degraded = True

        return HealthStatus.DEGRADED if any_degraded else HealthStatus.OK

    def _build_summary(self, results: Sequence[CheckResult]) -> Dict[str, Any]:
        counts = {s.value: 0 for s in HealthStatus}
        slowest: List[Tuple[int, str]] = []

        for r in results:
            counts[r.status.value] = int(counts.get(r.status.value, 0)) + 1
            slowest.append((int(r.duration_ms), r.name))

        slowest.sort(reverse=True)
        top5 = [{"name": n, "duration_ms": ms} for ms, n in slowest[:5]]

        return {
            "counts": counts,
            "slowest_top5": top5,
            "checks_total": len(results),
        }


def default_registry() -> HealthRegistry:
    """
    Базовый реестр без инфраструктурных зависимостей.
    Добавляй сюда безопасные проверки, которые не требуют внешних сервисов.
    """
    reg = HealthRegistry()

    async def event_loop_ok() -> Mapping[str, Any]:
        # Проверка, что event loop живой, и базовые операции работают.
        t0 = time.monotonic()
        await asyncio.sleep(0)
        dt_ms = int((time.monotonic() - t0) * 1000)
        return {"status": "ok", "message": "event_loop", "latency_ms": dt_ms}

    def monotonic_ok() -> Mapping[str, Any]:
        a = time.monotonic()
        b = time.monotonic()
        if b < a:
            return {"status": "critical", "message": "monotonic_regressed"}
        return {"status": "ok", "message": "monotonic"}

    reg.register(
        name="runtime.event_loop",
        fn=event_loop_ok,
        config=CheckConfig(timeout_s=1.0, retries=0, critical=True, tags=("runtime", "core")),
    )
    reg.register(
        name="runtime.monotonic",
        fn=monotonic_ok,
        config=CheckConfig(timeout_s=1.0, retries=0, critical=True, tags=("runtime", "core")),
    )
    return reg
