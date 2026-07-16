from __future__ import annotations

import asyncio
import inspect
import json
import logging
import socket
import time
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Iterable, Mapping, Protocol, Sequence, runtime_checkable


logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


class AuditStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComponentState(str, Enum):
    UNKNOWN = "unknown"
    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    STOPPED = "stopped"


class CheckKind(str, Enum):
    REGISTRATION = "registration"
    CONNECTIVITY = "connectivity"
    HEALTH = "health"
    SELF_TEST = "self_test"
    HEARTBEAT = "heartbeat"
    DEPENDENCIES = "dependencies"
    METRICS = "metrics"
    CUSTOM = "custom"


@dataclass(slots=True)
class AuditEvidence:
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=utcnow_iso)


@dataclass(slots=True)
class AuditCheckResult:
    check_name: str
    check_kind: CheckKind
    status: AuditStatus
    severity: Severity
    duration_ms: int
    message: str
    evidences: list[AuditEvidence] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=utcnow_iso)
    finished_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ComponentSnapshot:
    component_id: str
    name: str
    state: ComponentState
    version: str | None = None
    host: str | None = None
    pid: int | None = None
    started_at: str | None = None
    last_heartbeat_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ComponentAuditReport:
    component_id: str
    component_name: str
    state: ComponentState
    checks: list[AuditCheckResult] = field(default_factory=list)
    summary_status: AuditStatus = AuditStatus.PASS
    risk_score: int = 0
    snapshot: ComponentSnapshot | None = None
    started_at: str = field(default_factory=utcnow_iso)
    finished_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["checks"] = [check.to_dict() for check in self.checks]
        if self.snapshot is not None:
            data["snapshot"] = self.snapshot.to_dict()
        return data


@dataclass(slots=True)
class AuditSummary:
    total_components: int = 0
    passed_components: int = 0
    warned_components: int = 0
    failed_components: int = 0
    errored_components: int = 0
    skipped_components: int = 0
    total_checks: int = 0
    passed_checks: int = 0
    warned_checks: int = 0
    failed_checks: int = 0
    errored_checks: int = 0
    skipped_checks: int = 0
    global_status: AuditStatus = AuditStatus.PASS
    generated_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SystemAuditReport:
    audit_id: str
    node_name: str
    started_at: str
    finished_at: str
    duration_ms: int
    summary: AuditSummary
    components: list[ComponentAuditReport]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "node_name": self.node_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "summary": self.summary.to_dict(),
            "components": [component.to_dict() for component in self.components],
            "metadata": self.metadata,
        }

    def to_json(self, *, ensure_ascii: bool = False, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=ensure_ascii, indent=indent, default=str)


@dataclass(slots=True)
class AuditorPolicy:
    check_registration: bool = True
    check_connectivity: bool = True
    check_health: bool = True
    check_self_test: bool = True
    check_heartbeat: bool = True
    check_dependencies: bool = True
    check_metrics: bool = True
    default_timeout_sec: float = 5.0
    connectivity_timeout_sec: float = 1.5
    self_test_timeout_sec: float = 10.0
    max_heartbeat_age_sec: float = 60.0
    fail_on_missing_dependency: bool = True
    enable_best_effort_mode: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ComponentRegistration:
    component_id: str
    name: str
    instance: Any
    version: str | None = None
    dependencies: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    critical: bool = False
    tags: tuple[str, ...] = ()
    host: str | None = None
    pid: int | None = None
    registered_at: str = field(default_factory=utcnow_iso)
    last_heartbeat_at: str | None = None

    def to_snapshot(self) -> ComponentSnapshot:
        state = extract_component_state(self.instance)
        return ComponentSnapshot(
            component_id=self.component_id,
            name=self.name,
            state=state,
            version=self.version,
            host=self.host,
            pid=self.pid,
            started_at=self.metadata.get("started_at"),
            last_heartbeat_at=self.last_heartbeat_at,
            metadata=dict(self.metadata),
        )


@runtime_checkable
class SupportsHealthCheck(Protocol):
    async def health_check(self) -> Any:
        ...


@runtime_checkable
class SupportsPing(Protocol):
    async def ping(self) -> Any:
        ...


@runtime_checkable
class SupportsSelfTest(Protocol):
    async def self_test(self) -> Any:
        ...


@runtime_checkable
class SupportsMetrics(Protocol):
    async def collect_metrics(self) -> Mapping[str, Any]:
        ...


def extract_component_state(instance: Any) -> ComponentState:
    raw_state = getattr(instance, "state", None)
    if isinstance(raw_state, ComponentState):
        return raw_state
    if isinstance(raw_state, str):
        normalized = raw_state.strip().lower()
        for candidate in ComponentState:
            if candidate.value == normalized:
                return candidate
    return ComponentState.UNKNOWN


def normalize_check_status(value: Any) -> AuditStatus:
    if isinstance(value, AuditStatus):
        return value

    if isinstance(value, bool):
        return AuditStatus.PASS if value else AuditStatus.FAIL

    if isinstance(value, str):
        normalized = value.strip().lower()
        aliases = {
            "ok": AuditStatus.PASS,
            "pass": AuditStatus.PASS,
            "passed": AuditStatus.PASS,
            "success": AuditStatus.PASS,
            "healthy": AuditStatus.PASS,
            "warn": AuditStatus.WARN,
            "warning": AuditStatus.WARN,
            "degraded": AuditStatus.WARN,
            "fail": AuditStatus.FAIL,
            "failed": AuditStatus.FAIL,
            "unhealthy": AuditStatus.FAIL,
            "error": AuditStatus.ERROR,
            "skip": AuditStatus.SKIP,
            "skipped": AuditStatus.SKIP,
        }
        return aliases.get(normalized, AuditStatus.WARN)

    if isinstance(value, Mapping):
        raw = value.get("status")
        if raw is not None:
            return normalize_check_status(raw)

    return AuditStatus.WARN


def severity_from_status(status: AuditStatus, critical: bool = False) -> Severity:
    if status == AuditStatus.PASS:
        return Severity.LOW
    if status == AuditStatus.SKIP:
        return Severity.LOW
    if status == AuditStatus.WARN:
        return Severity.HIGH if critical else Severity.MEDIUM
    if status in {AuditStatus.FAIL, AuditStatus.ERROR}:
        return Severity.CRITICAL if critical else Severity.HIGH
    return Severity.MEDIUM


def compute_risk_score(checks: Sequence[AuditCheckResult]) -> int:
    weights: dict[AuditStatus, int] = {
        AuditStatus.PASS: 0,
        AuditStatus.SKIP: 1,
        AuditStatus.WARN: 15,
        AuditStatus.FAIL: 35,
        AuditStatus.ERROR: 45,
    }
    score = sum(weights.get(check.status, 0) for check in checks)
    return min(score, 100)


def summarize_component_status(checks: Sequence[AuditCheckResult]) -> AuditStatus:
    statuses = {check.status for check in checks}
    if AuditStatus.ERROR in statuses:
        return AuditStatus.ERROR
    if AuditStatus.FAIL in statuses:
        return AuditStatus.FAIL
    if AuditStatus.WARN in statuses:
        return AuditStatus.WARN
    if AuditStatus.PASS in statuses:
        return AuditStatus.PASS
    return AuditStatus.SKIP


async def maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def call_with_timeout(
    fn: Callable[..., Any] | Callable[..., Awaitable[Any]],
    *args: Any,
    timeout_sec: float,
    **kwargs: Any,
) -> Any:
    result = fn(*args, **kwargs)
    if inspect.isawaitable(result):
        return await asyncio.wait_for(result, timeout=timeout_sec)
    return result


def parse_health_payload(payload: Any) -> tuple[AuditStatus, str, dict[str, Any]]:
    if payload is None:
        return AuditStatus.WARN, "Health payload is empty", {}

    if isinstance(payload, bool):
        return (
            AuditStatus.PASS if payload else AuditStatus.FAIL,
            "Boolean health check result",
            {"raw": payload},
        )

    if isinstance(payload, str):
        status = normalize_check_status(payload)
        return status, f"Health status: {payload}", {"raw": payload}

    if isinstance(payload, Mapping):
        status = normalize_check_status(payload)
        message = str(payload.get("message", "Health payload received"))
        return status, message, dict(payload)

    return AuditStatus.WARN, "Unsupported health payload format", {"type": type(payload).__name__}


class SystemAuditor:
    def __init__(
        self,
        *,
        policy: AuditorPolicy | None = None,
        node_name: str | None = None,
        logger_: logging.Logger | None = None,
    ) -> None:
        self._policy = policy or AuditorPolicy()
        self._node_name = node_name or socket.gethostname()
        self._logger = logger_ or logger
        self._components: dict[str, ComponentRegistration] = {}
        self._custom_checks: dict[str, list[Callable[[ComponentRegistration], Awaitable[AuditCheckResult] | AuditCheckResult]]] = {}
        self._lock = asyncio.Lock()

    @property
    def policy(self) -> AuditorPolicy:
        return self._policy

    @property
    def node_name(self) -> str:
        return self._node_name

    async def register_component(
        self,
        *,
        component_id: str,
        name: str,
        instance: Any,
        version: str | None = None,
        dependencies: Iterable[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
        critical: bool = False,
        tags: Iterable[str] | None = None,
        host: str | None = None,
        pid: int | None = None,
    ) -> None:
        registration = ComponentRegistration(
            component_id=component_id,
            name=name,
            instance=instance,
            version=version,
            dependencies=tuple(dependencies or ()),
            metadata=dict(metadata or {}),
            critical=critical,
            tags=tuple(tags or ()),
            host=host,
            pid=pid,
        )
        async with self._lock:
            self._components[component_id] = registration

    async def unregister_component(self, component_id: str) -> None:
        async with self._lock:
            self._components.pop(component_id, None)
            self._custom_checks.pop(component_id, None)

    async def mark_heartbeat(
        self,
        component_id: str,
        *,
        heartbeat_at: datetime | None = None,
    ) -> None:
        async with self._lock:
            if component_id in self._components:
                self._components[component_id].last_heartbeat_at = (heartbeat_at or utcnow()).isoformat()

    async def add_custom_check(
        self,
        component_id: str,
        check: Callable[[ComponentRegistration], Awaitable[AuditCheckResult] | AuditCheckResult],
    ) -> None:
        async with self._lock:
            self._custom_checks.setdefault(component_id, []).append(check)

    async def list_components(self) -> list[ComponentSnapshot]:
        async with self._lock:
            return [component.to_snapshot() for component in self._components.values()]

    async def snapshot_registry(self) -> dict[str, Any]:
        async with self._lock:
            components = {
                component_id: registration.to_snapshot().to_dict()
                for component_id, registration in self._components.items()
            }
            custom_checks = {
                component_id: [
                    getattr(check, "__name__", check.__class__.__name__)
                    for check in checks
                ]
                for component_id, checks in self._custom_checks.items()
            }
            custom_check_counts = {
                component_id: len(checks)
                for component_id, checks in self._custom_checks.items()
            }

            return {
                "node_name": self._node_name,
                "policy": self._policy.to_dict(),
                "components": components,
                "custom_checks": custom_checks,
                "custom_check_counts": custom_check_counts,
            }

    async def clean(self) -> None:
        async with self._lock:
            self._components.clear()
            self._custom_checks.clear()

    async def run_full_audit(
        self,
        *,
        component_ids: Sequence[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> SystemAuditReport:
        started_at_dt = utcnow()
        started_ms = monotonic_ms()
        audit_id = f"audit-{int(started_at_dt.timestamp() * 1000)}"

        async with self._lock:
            if component_ids is None:
                selected = list(self._components.values())
            else:
                selected = [self._components[cid] for cid in component_ids if cid in self._components]

        component_reports = await asyncio.gather(
            *(self.run_component_audit(component.component_id) for component in selected),
            return_exceptions=True,
        )

        normalized_reports: list[ComponentAuditReport] = []
        for item, component in zip(component_reports, selected, strict=False):
            if isinstance(item, Exception):
                self._logger.exception(
                    "Component audit crashed",
                    extra={"component_id": component.component_id, "component_name": component.name},
                )
                normalized_reports.append(
                    ComponentAuditReport(
                        component_id=component.component_id,
                        component_name=component.name,
                        state=extract_component_state(component.instance),
                        checks=[
                            AuditCheckResult(
                                check_name="component_audit_execution",
                                check_kind=CheckKind.CUSTOM,
                                status=AuditStatus.ERROR,
                                severity=Severity.CRITICAL if component.critical else Severity.HIGH,
                                duration_ms=0,
                                message=f"Unhandled audit error: {item!r}",
                                evidences=[
                                    AuditEvidence(
                                        code="AUDIT_EXECUTION_CRASH",
                                        message="Unhandled exception while auditing component",
                                        details={"exception": repr(item)},
                                    )
                                ],
                            )
                        ],
                        summary_status=AuditStatus.ERROR,
                        risk_score=100 if component.critical else 80,
                        snapshot=component.to_snapshot(),
                        started_at=started_at_dt.isoformat(),
                        finished_at=utcnow_iso(),
                    )
                )
            else:
                normalized_reports.append(item)

        summary = self._build_summary(normalized_reports)
        finished_at_dt = utcnow()
        finished_ms = monotonic_ms()

        report = SystemAuditReport(
            audit_id=audit_id,
            node_name=self._node_name,
            started_at=started_at_dt.isoformat(),
            finished_at=finished_at_dt.isoformat(),
            duration_ms=max(finished_ms - started_ms, 0),
            summary=summary,
            components=normalized_reports,
            metadata=dict(metadata or {}),
        )
        return report

    async def run_component_audit(self, component_id: str) -> ComponentAuditReport:
        async with self._lock:
            component = self._components.get(component_id)
            custom_checks = list(self._custom_checks.get(component_id, []))

        if component is None:
            now = utcnow_iso()
            missing_check = AuditCheckResult(
                check_name="registration",
                check_kind=CheckKind.REGISTRATION,
                status=AuditStatus.FAIL,
                severity=Severity.HIGH,
                duration_ms=0,
                message=f"Component '{component_id}' is not registered",
                evidences=[
                    AuditEvidence(
                        code="COMPONENT_NOT_REGISTERED",
                        message="Requested component is absent in auditor registry",
                        details={"component_id": component_id},
                    )
                ],
                started_at=now,
                finished_at=now,
            )
            return ComponentAuditReport(
                component_id=component_id,
                component_name=component_id,
                state=ComponentState.UNKNOWN,
                checks=[missing_check],
                summary_status=AuditStatus.FAIL,
                risk_score=60,
                started_at=now,
                finished_at=now,
            )

        report_started = utcnow_iso()
        checks: list[AuditCheckResult] = []

        if self._policy.check_registration:
            checks.append(self._check_registration(component))

        if self._policy.check_connectivity:
            checks.append(await self._safe_execute_check(self._check_connectivity, component))

        if self._policy.check_health:
            checks.append(await self._safe_execute_check(self._check_health, component))

        if self._policy.check_self_test:
            checks.append(await self._safe_execute_check(self._check_self_test, component))

        if self._policy.check_heartbeat:
            checks.append(self._check_heartbeat(component))

        if self._policy.check_dependencies:
            checks.append(await self._safe_execute_check(self._check_dependencies, component))

        if self._policy.check_metrics:
            checks.append(await self._safe_execute_check(self._check_metrics, component))

        for custom_check in custom_checks:
            checks.append(await self._safe_execute_custom_check(component, custom_check))

        summary_status = summarize_component_status(checks)
        risk_score = compute_risk_score(checks)
        return ComponentAuditReport(
            component_id=component.component_id,
            component_name=component.name,
            state=extract_component_state(component.instance),
            checks=checks,
            summary_status=summary_status,
            risk_score=risk_score,
            snapshot=component.to_snapshot(),
            started_at=report_started,
            finished_at=utcnow_iso(),
        )

    def _check_registration(self, component: ComponentRegistration) -> AuditCheckResult:
        started_ms = monotonic_ms()
        evidences: list[AuditEvidence] = []

        valid = bool(component.component_id and component.name and component.instance is not None)
        if not valid:
            evidences.append(
                AuditEvidence(
                    code="INVALID_REGISTRATION",
                    message="Component registration is incomplete",
                    details={
                        "component_id": component.component_id,
                        "name": component.name,
                        "has_instance": component.instance is not None,
                    },
                )
            )

        status = AuditStatus.PASS if valid else AuditStatus.FAIL
        duration_ms = monotonic_ms() - started_ms

        return AuditCheckResult(
            check_name="registration",
            check_kind=CheckKind.REGISTRATION,
            status=status,
            severity=severity_from_status(status, critical=component.critical),
            duration_ms=duration_ms,
            message="Component registration is valid" if valid else "Component registration is invalid",
            evidences=evidences,
            tags=list(component.tags),
            data={
                "component_id": component.component_id,
                "name": component.name,
                "version": component.version,
                "critical": component.critical,
                "dependencies": list(component.dependencies),
            },
        )

    async def _check_connectivity(self, component: ComponentRegistration) -> AuditCheckResult:
        started_at = utcnow_iso()
        started_ms = monotonic_ms()

        instance = component.instance
        ping_callable = getattr(instance, "ping", None)

        if ping_callable is None or not callable(ping_callable):
            return AuditCheckResult(
                check_name="connectivity",
                check_kind=CheckKind.CONNECTIVITY,
                status=AuditStatus.SKIP,
                severity=Severity.LOW,
                duration_ms=monotonic_ms() - started_ms,
                message="Connectivity check skipped: ping() is not implemented",
                tags=list(component.tags),
                data={},
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

        try:
            payload = await call_with_timeout(
                ping_callable,
                timeout_sec=self._policy.connectivity_timeout_sec,
            )
            status = normalize_check_status(payload)
            return AuditCheckResult(
                check_name="connectivity",
                check_kind=CheckKind.CONNECTIVITY,
                status=status,
                severity=severity_from_status(status, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Ping succeeded" if status == AuditStatus.PASS else "Ping returned non-pass status",
                tags=list(component.tags),
                data={"response": payload},
                started_at=started_at,
                finished_at=utcnow_iso(),
            )
        except asyncio.TimeoutError:
            return AuditCheckResult(
                check_name="connectivity",
                check_kind=CheckKind.CONNECTIVITY,
                status=AuditStatus.FAIL,
                severity=severity_from_status(AuditStatus.FAIL, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Ping timed out",
                evidences=[
                    AuditEvidence(
                        code="PING_TIMEOUT",
                        message="Component ping exceeded timeout threshold",
                        details={"timeout_sec": self._policy.connectivity_timeout_sec},
                    )
                ],
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

    async def _check_health(self, component: ComponentRegistration) -> AuditCheckResult:
        started_at = utcnow_iso()
        started_ms = monotonic_ms()

        instance = component.instance
        health_callable = getattr(instance, "health_check", None)
        if health_callable is None or not callable(health_callable):
            health_callable = getattr(instance, "health", None)

        if health_callable is None or not callable(health_callable):
            return AuditCheckResult(
                check_name="health",
                check_kind=CheckKind.HEALTH,
                status=AuditStatus.SKIP,
                severity=Severity.LOW,
                duration_ms=monotonic_ms() - started_ms,
                message="Health check skipped: health_check() or health() is not implemented",
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

        try:
            payload = await call_with_timeout(
                health_callable,
                timeout_sec=self._policy.default_timeout_sec,
            )
            status, message, data = parse_health_payload(payload)
            return AuditCheckResult(
                check_name="health",
                check_kind=CheckKind.HEALTH,
                status=status,
                severity=severity_from_status(status, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message=message,
                tags=list(component.tags),
                data=data,
                started_at=started_at,
                finished_at=utcnow_iso(),
            )
        except asyncio.TimeoutError:
            return AuditCheckResult(
                check_name="health",
                check_kind=CheckKind.HEALTH,
                status=AuditStatus.FAIL,
                severity=severity_from_status(AuditStatus.FAIL, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Health check timed out",
                evidences=[
                    AuditEvidence(
                        code="HEALTH_TIMEOUT",
                        message="Health check exceeded timeout threshold",
                        details={"timeout_sec": self._policy.default_timeout_sec},
                    )
                ],
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

    async def _check_self_test(self, component: ComponentRegistration) -> AuditCheckResult:
        started_at = utcnow_iso()
        started_ms = monotonic_ms()

        self_test_callable = getattr(component.instance, "self_test", None)
        if self_test_callable is None or not callable(self_test_callable):
            return AuditCheckResult(
                check_name="self_test",
                check_kind=CheckKind.SELF_TEST,
                status=AuditStatus.SKIP,
                severity=Severity.LOW,
                duration_ms=monotonic_ms() - started_ms,
                message="Self-test skipped: self_test() is not implemented",
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

        try:
            payload = await call_with_timeout(
                self_test_callable,
                timeout_sec=self._policy.self_test_timeout_sec,
            )
            status = normalize_check_status(payload)
            return AuditCheckResult(
                check_name="self_test",
                check_kind=CheckKind.SELF_TEST,
                status=status,
                severity=severity_from_status(status, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Self-test completed",
                tags=list(component.tags),
                data={"result": payload},
                started_at=started_at,
                finished_at=utcnow_iso(),
            )
        except asyncio.TimeoutError:
            return AuditCheckResult(
                check_name="self_test",
                check_kind=CheckKind.SELF_TEST,
                status=AuditStatus.FAIL,
                severity=severity_from_status(AuditStatus.FAIL, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Self-test timed out",
                evidences=[
                    AuditEvidence(
                        code="SELF_TEST_TIMEOUT",
                        message="Self-test exceeded timeout threshold",
                        details={"timeout_sec": self._policy.self_test_timeout_sec},
                    )
                ],
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

    def _check_heartbeat(self, component: ComponentRegistration) -> AuditCheckResult:
        started_at = utcnow_iso()
        started_ms = monotonic_ms()

        if not component.last_heartbeat_at:
            status = AuditStatus.WARN
            return AuditCheckResult(
                check_name="heartbeat",
                check_kind=CheckKind.HEARTBEAT,
                status=status,
                severity=severity_from_status(status, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Heartbeat timestamp is missing",
                evidences=[
                    AuditEvidence(
                        code="HEARTBEAT_MISSING",
                        message="Component has no registered heartbeat",
                        details={"component_id": component.component_id},
                    )
                ],
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

        try:
            last = datetime.fromisoformat(component.last_heartbeat_at)
            age = (utcnow() - last).total_seconds()
        except ValueError:
            return AuditCheckResult(
                check_name="heartbeat",
                check_kind=CheckKind.HEARTBEAT,
                status=AuditStatus.FAIL,
                severity=severity_from_status(AuditStatus.FAIL, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Heartbeat timestamp format is invalid",
                evidences=[
                    AuditEvidence(
                        code="HEARTBEAT_INVALID_FORMAT",
                        message="Failed to parse heartbeat timestamp",
                        details={"last_heartbeat_at": component.last_heartbeat_at},
                    )
                ],
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

        if age <= self._policy.max_heartbeat_age_sec:
            status = AuditStatus.PASS
            message = "Heartbeat is fresh"
        elif age <= self._policy.max_heartbeat_age_sec * 2:
            status = AuditStatus.WARN
            message = "Heartbeat is stale"
        else:
            status = AuditStatus.FAIL
            message = "Heartbeat is expired"

        return AuditCheckResult(
            check_name="heartbeat",
            check_kind=CheckKind.HEARTBEAT,
            status=status,
            severity=severity_from_status(status, critical=component.critical),
            duration_ms=monotonic_ms() - started_ms,
            message=message,
            tags=list(component.tags),
            data={
                "last_heartbeat_at": component.last_heartbeat_at,
                "heartbeat_age_sec": age,
                "max_heartbeat_age_sec": self._policy.max_heartbeat_age_sec,
            },
            started_at=started_at,
            finished_at=utcnow_iso(),
        )

    async def _check_dependencies(self, component: ComponentRegistration) -> AuditCheckResult:
        started_at = utcnow_iso()
        started_ms = monotonic_ms()

        if not component.dependencies:
            return self._build_no_dependencies_result(component, started_at, started_ms)

        async with self._lock:
            dependencies = {
                dep: self._components.get(dep)
                for dep in component.dependencies
            }

        missing = [dep for dep, reg in dependencies.items() if reg is None]
        unhealthy, degraded = self._classify_dependency_states(dependencies)

        status, message = self._resolve_dependency_audit_status(
            missing=missing,
            unhealthy=unhealthy,
            degraded=degraded,
        )
        evidences = self._build_dependency_evidences(
            missing=missing,
            unhealthy=unhealthy,
            degraded=degraded,
        )

        return AuditCheckResult(
            check_name="dependencies",
            check_kind=CheckKind.DEPENDENCIES,
            status=status,
            severity=severity_from_status(status, critical=component.critical),
            duration_ms=monotonic_ms() - started_ms,
            message=message,
            evidences=evidences,
            tags=list(component.tags),
            data={
                "declared_dependencies": list(component.dependencies),
                "missing_dependencies": missing,
                "unhealthy_dependencies": unhealthy,
                "degraded_dependencies": degraded,
            },
            started_at=started_at,
            finished_at=utcnow_iso(),
        )


    def _build_no_dependencies_result(
        self,
        component: ComponentRegistration,
        started_at: str,
        started_ms: int,
    ) -> AuditCheckResult:
        return AuditCheckResult(
            check_name="dependencies",
            check_kind=CheckKind.DEPENDENCIES,
            status=AuditStatus.PASS,
            severity=Severity.LOW,
            duration_ms=monotonic_ms() - started_ms,
            message="No dependencies declared",
            tags=list(component.tags),
            started_at=started_at,
            finished_at=utcnow_iso(),
        )


    def _classify_dependency_states(
        self,
        dependencies: Mapping[str, ComponentRegistration | None],
    ) -> tuple[list[str], list[str]]:
        unhealthy: list[str] = []
        degraded: list[str] = []

        for dep, reg in dependencies.items():
            if reg is None:
                continue

            state = extract_component_state(reg.instance)
            if state in {ComponentState.UNHEALTHY, ComponentState.STOPPED}:
                unhealthy.append(dep)
            elif state in {
                ComponentState.DEGRADED,
                ComponentState.UNKNOWN,
                ComponentState.STARTING,
            }:
                degraded.append(dep)

        return unhealthy, degraded


    def _resolve_dependency_audit_status(
        self,
        *,
        missing: Sequence[str],
        unhealthy: Sequence[str],
        degraded: Sequence[str],
    ) -> tuple[AuditStatus, str]:
        if missing:
            status = AuditStatus.FAIL if self._policy.fail_on_missing_dependency else AuditStatus.WARN
            return status, "Missing dependencies detected"

        if unhealthy:
            return AuditStatus.FAIL, "Unhealthy dependencies detected"

        if degraded:
            return AuditStatus.WARN, "Degraded dependencies detected"

        return AuditStatus.PASS, "All dependencies are available"


    def _build_dependency_evidences(
        self,
        *,
        missing: Sequence[str],
        unhealthy: Sequence[str],
        degraded: Sequence[str],
    ) -> list[AuditEvidence]:
        evidences: list[AuditEvidence] = []

        if missing:
            evidences.append(
                AuditEvidence(
                    code="DEPENDENCIES_MISSING",
                    message="Some declared dependencies are not registered",
                    details={"missing": list(missing)},
                )
            )

        if unhealthy:
            evidences.append(
                AuditEvidence(
                    code="DEPENDENCIES_UNHEALTHY",
                    message="Some dependencies are unhealthy or stopped",
                    details={"unhealthy": list(unhealthy)},
                )
            )

        if degraded:
            evidences.append(
                AuditEvidence(
                    code="DEPENDENCIES_DEGRADED",
                    message="Some dependencies are degraded or not fully ready",
                    details={"degraded": list(degraded)},
                )
            )

        return evidences

    async def _check_metrics(self, component: ComponentRegistration) -> AuditCheckResult:
        started_at = utcnow_iso()
        started_ms = monotonic_ms()

        metrics_callable = getattr(component.instance, "collect_metrics", None)
        if metrics_callable is None or not callable(metrics_callable):
            metrics_callable = getattr(component.instance, "metrics", None)

        if metrics_callable is None or not callable(metrics_callable):
            return AuditCheckResult(
                check_name="metrics",
                check_kind=CheckKind.METRICS,
                status=AuditStatus.SKIP,
                severity=Severity.LOW,
                duration_ms=monotonic_ms() - started_ms,
                message="Metrics collection skipped: collect_metrics() or metrics() is not implemented",
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

        try:
            payload = await call_with_timeout(
                metrics_callable,
                timeout_sec=self._policy.default_timeout_sec,
            )
            if isinstance(payload, Mapping):
                status = AuditStatus.PASS
                data = dict(payload)
                message = "Metrics collected successfully"
            else:
                status = AuditStatus.WARN
                data = {"raw": payload}
                message = "Metrics returned unsupported format"
            return AuditCheckResult(
                check_name="metrics",
                check_kind=CheckKind.METRICS,
                status=status,
                severity=severity_from_status(status, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message=message,
                tags=list(component.tags),
                data=data,
                started_at=started_at,
                finished_at=utcnow_iso(),
            )
        except asyncio.TimeoutError:
            return AuditCheckResult(
                check_name="metrics",
                check_kind=CheckKind.METRICS,
                status=AuditStatus.WARN,
                severity=severity_from_status(AuditStatus.WARN, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Metrics collection timed out",
                evidences=[
                    AuditEvidence(
                        code="METRICS_TIMEOUT",
                        message="Metrics collection exceeded timeout threshold",
                        details={"timeout_sec": self._policy.default_timeout_sec},
                    )
                ],
                tags=list(component.tags),
                started_at=started_at,
                finished_at=utcnow_iso(),
            )

    async def _safe_execute_check(
        self,
        fn: Callable[[ComponentRegistration], Awaitable[AuditCheckResult]],
        component: ComponentRegistration,
    ) -> AuditCheckResult:
        try:
            return await fn(component)
        except Exception as exc:
            self._logger.exception(
                "Audit check failed with unhandled exception",
                extra={
                    "component_id": component.component_id,
                    "component_name": component.name,
                    "check_name": fn.__name__,
                },
            )
            return AuditCheckResult(
                check_name=fn.__name__.removeprefix("_check_"),
                check_kind=CheckKind.CUSTOM,
                status=AuditStatus.ERROR,
                severity=severity_from_status(AuditStatus.ERROR, critical=component.critical),
                duration_ms=0,
                message=f"Unhandled exception during check: {exc!r}",
                evidences=[
                    AuditEvidence(
                        code="CHECK_UNHANDLED_EXCEPTION",
                        message="Audit check raised an unhandled exception",
                        details={"exception": repr(exc), "check": fn.__name__},
                    )
                ],
                tags=list(component.tags),
            )

    async def _safe_execute_custom_check(
        self,
        component: ComponentRegistration,
        check: Callable[[ComponentRegistration], Awaitable[AuditCheckResult] | AuditCheckResult],
    ) -> AuditCheckResult:
        started_ms = monotonic_ms()
        try:
            result = check(component)
            if inspect.isawaitable(result):
                result = await asyncio.wait_for(result, timeout=self._policy.default_timeout_sec)

            if not isinstance(result, AuditCheckResult):
                return AuditCheckResult(
                    check_name=getattr(check, "__name__", "custom_check"),
                    check_kind=CheckKind.CUSTOM,
                    status=AuditStatus.ERROR,
                    severity=severity_from_status(AuditStatus.ERROR, critical=component.critical),
                    duration_ms=monotonic_ms() - started_ms,
                    message="Custom check returned invalid result type",
                    evidences=[
                        AuditEvidence(
                            code="CUSTOM_CHECK_INVALID_RESULT",
                            message="Custom check must return AuditCheckResult",
                            details={"returned_type": type(result).__name__},
                        )
                    ],
                    tags=list(component.tags),
                )

            return result
        except asyncio.TimeoutError:
            return AuditCheckResult(
                check_name=getattr(check, "__name__", "custom_check"),
                check_kind=CheckKind.CUSTOM,
                status=AuditStatus.FAIL,
                severity=severity_from_status(AuditStatus.FAIL, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message="Custom check timed out",
                evidences=[
                    AuditEvidence(
                        code="CUSTOM_CHECK_TIMEOUT",
                        message="Custom check exceeded timeout threshold",
                        details={"timeout_sec": self._policy.default_timeout_sec},
                    )
                ],
                tags=list(component.tags),
            )
        except Exception as exc:
            self._logger.exception(
                "Custom check failed",
                extra={"component_id": component.component_id, "component_name": component.name},
            )
            return AuditCheckResult(
                check_name=getattr(check, "__name__", "custom_check"),
                check_kind=CheckKind.CUSTOM,
                status=AuditStatus.ERROR,
                severity=severity_from_status(AuditStatus.ERROR, critical=component.critical),
                duration_ms=monotonic_ms() - started_ms,
                message=f"Custom check crashed: {exc!r}",
                evidences=[
                    AuditEvidence(
                        code="CUSTOM_CHECK_CRASH",
                        message="Custom check raised an unhandled exception",
                        details={"exception": repr(exc)},
                    )
                ],
                tags=list(component.tags),
            )

    def _build_summary(
        self,
        components: Sequence[ComponentAuditReport],
    ) -> AuditSummary:
        summary = AuditSummary(total_components=len(components))

        for component in components:
            self._update_component_summary(summary, component)
            self._update_checks_summary(summary, component.checks)

        summary.global_status = self._resolve_global_status(components)
        return summary


    def _update_component_summary(
        self,
        summary: AuditSummary,
        component: ComponentAuditReport,
    ) -> None:
        self._increment_by_status(
            summary=summary,
            status=component.summary_status,
            field_map={
                AuditStatus.PASS: "passed_components",
                AuditStatus.WARN: "warned_components",
                AuditStatus.FAIL: "failed_components",
                AuditStatus.ERROR: "errored_components",
                AuditStatus.SKIP: "skipped_components",
            },
        )


    def _update_checks_summary(
        self,
        summary: AuditSummary,
        checks: Sequence[AuditCheckResult],
    ) -> None:
        for check in checks:
            summary.total_checks += 1
            self._increment_by_status(
                summary=summary,
                status=check.status,
                field_map={
                    AuditStatus.PASS: "passed_checks",
                    AuditStatus.WARN: "warned_checks",
                    AuditStatus.FAIL: "failed_checks",
                    AuditStatus.ERROR: "errored_checks",
                    AuditStatus.SKIP: "skipped_checks",
                },
            )


    def _increment_by_status(
        self,
        summary: AuditSummary,
        status: AuditStatus,
        field_map: dict[AuditStatus, str],
    ) -> None:
        field_name = field_map.get(status)
        if field_name is None:
            return

        setattr(summary, field_name, getattr(summary, field_name) + 1)


    def _resolve_global_status(
        self,
        components: Sequence[ComponentAuditReport],
    ) -> AuditStatus:
        component_statuses = {component.summary_status for component in components}

        for status in (
            AuditStatus.ERROR,
            AuditStatus.FAIL,
            AuditStatus.WARN,
            AuditStatus.PASS,
        ):
            if status in component_statuses:
                return status

        return AuditStatus.SKIP


    async def export_report_to_file(
        self,
        path: str,
        report: SystemAuditReport,
    ) -> None:
        from pathlib import Path

        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        payload = self._serialize_export_value(report)
        content = json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        
        await asyncio.to_thread(
            target_path.write_text,
            content,
            encoding="utf-8",
        )


    def _serialize_export_value(self, value: Any) -> Any:
        from dataclasses import is_dataclass
        from datetime import date
        from pathlib import Path

        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, (datetime, date)):
            return value.isoformat()

        if isinstance(value, Path):
            return str(value)

        if is_dataclass(value):
            return self._serialize_export_value(asdict(value))

        if isinstance(value, dict):
            return self._serialize_export_mapping(value)

        if isinstance(value, (list, tuple, set)):
            return self._serialize_export_iterable(value)

        return self._serialize_export_object(value)


    def _serialize_export_mapping(self, value: Mapping[Any, Any]) -> dict[str, Any]:
        return {
            str(key): self._serialize_export_value(item)
            for key, item in value.items()
        }


    def _serialize_export_iterable(self, value: Iterable[Any]) -> list[Any]:
        return [self._serialize_export_value(item) for item in value]


    def _serialize_export_object(self, value: Any) -> Any:
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            return self._serialize_export_value(to_dict())

        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            return self._serialize_export_value(model_dump())

        to_snapshot = getattr(value, "to_snapshot", None)
        if callable(to_snapshot):
            return self._serialize_export_value(to_snapshot())

        return str(value)