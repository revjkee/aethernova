# agent_mash/intel/health_analysis/unhealthy.py
from __future__ import annotations

import abc
import asyncio
import dataclasses
import datetime as dt
import json
import os
import time
import typing as t
import uuid

from agent_mash.governance.audit_log import AuditContext, AuditLogger

Json = dict[str, t.Any]


class HealthAnalysisError(RuntimeError):
    pass


class Severity:
    """
    Строгие значения уровней важности.
    Не Enum, чтобы не ломать сериализацию и совместимость при расширениях.
    """
    OK = "OK"
    WARN = "WARN"
    CRIT = "CRIT"

    @staticmethod
    def order(sev: str) -> int:
        if sev == Severity.OK:
            return 0
        if sev == Severity.WARN:
            return 1
        if sev == Severity.CRIT:
            return 2
        raise HealthAnalysisError(f"Unknown severity: {sev}")


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _safe_uuid() -> str:
    return str(uuid.uuid4())


def _stable_json(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _clamp_int(v: int, *, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _clamp_float(v: float, *, lo: float, hi: float) -> float:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _as_float(x: t.Any, *, name: str) -> float:
    if x is None:
        raise HealthAnalysisError(f"{name} is None")
    if isinstance(x, (int, float)):
        return float(x)
    if isinstance(x, str):
        s = x.strip()
        if not s:
            raise HealthAnalysisError(f"{name} is empty string")
        try:
            return float(s)
        except ValueError as e:
            raise HealthAnalysisError(f"{name} must be float-like, got {x!r}") from e
    raise HealthAnalysisError(f"{name} has unsupported type: {type(x).__name__}")


def _as_int(x: t.Any, *, name: str) -> int:
    if x is None:
        raise HealthAnalysisError(f"{name} is None")
    if isinstance(x, bool):
        raise HealthAnalysisError(f"{name} must be int, got bool")
    if isinstance(x, int):
        return x
    if isinstance(x, float):
        return int(x)
    if isinstance(x, str):
        s = x.strip()
        if not s:
            raise HealthAnalysisError(f"{name} is empty string")
        try:
            return int(float(s))
        except ValueError as e:
            raise HealthAnalysisError(f"{name} must be int-like, got {x!r}") from e
    raise HealthAnalysisError(f"{name} has unsupported type: {type(x).__name__}")


@dataclasses.dataclass(frozen=True, slots=True)
class Thresholds:
    """
    Пороги. Все значения интерпретируются однозначно.
    """
    max_cpu_pct_warn: float = 85.0
    max_cpu_pct_crit: float = 95.0

    max_mem_used_pct_warn: float = 85.0
    max_mem_used_pct_crit: float = 95.0

    max_disk_used_pct_warn: float = 85.0
    max_disk_used_pct_crit: float = 95.0

    max_p95_latency_ms_warn: float = 800.0
    max_p95_latency_ms_crit: float = 2000.0

    max_error_rate_pct_warn: float = 2.0
    max_error_rate_pct_crit: float = 5.0

    max_queue_lag_warn: int = 500
    max_queue_lag_crit: int = 2000

    max_clock_skew_ms_warn: float = 3000.0
    max_clock_skew_ms_crit: float = 15000.0

    max_restart_count_warn: int = 3
    max_restart_count_crit: int = 10

    @staticmethod
    def from_env(prefix: str = "AGENT_MASH_HEALTH_") -> "Thresholds":
        def env(name: str, default: str) -> str:
            v = os.environ.get(prefix + name, default)
            v = v.strip()
            return v if v else default

        def env_f(name: str, default: float) -> float:
            return _as_float(env(name, str(default)), name=prefix + name)

        def env_i(name: str, default: int) -> int:
            return _as_int(env(name, str(default)), name=prefix + name)

        t_ = Thresholds(
            max_cpu_pct_warn=env_f("MAX_CPU_PCT_WARN", 85.0),
            max_cpu_pct_crit=env_f("MAX_CPU_PCT_CRIT", 95.0),
            max_mem_used_pct_warn=env_f("MAX_MEM_USED_PCT_WARN", 85.0),
            max_mem_used_pct_crit=env_f("MAX_MEM_USED_PCT_CRIT", 95.0),
            max_disk_used_pct_warn=env_f("MAX_DISK_USED_PCT_WARN", 85.0),
            max_disk_used_pct_crit=env_f("MAX_DISK_USED_PCT_CRIT", 95.0),
            max_p95_latency_ms_warn=env_f("MAX_P95_LATENCY_MS_WARN", 800.0),
            max_p95_latency_ms_crit=env_f("MAX_P95_LATENCY_MS_CRIT", 2000.0),
            max_error_rate_pct_warn=env_f("MAX_ERROR_RATE_PCT_WARN", 2.0),
            max_error_rate_pct_crit=env_f("MAX_ERROR_RATE_PCT_CRIT", 5.0),
            max_queue_lag_warn=env_i("MAX_QUEUE_LAG_WARN", 500),
            max_queue_lag_crit=env_i("MAX_QUEUE_LAG_CRIT", 2000),
            max_clock_skew_ms_warn=env_f("MAX_CLOCK_SKEW_MS_WARN", 3000.0),
            max_clock_skew_ms_crit=env_f("MAX_CLOCK_SKEW_MS_CRIT", 15000.0),
            max_restart_count_warn=env_i("MAX_RESTART_COUNT_WARN", 3),
            max_restart_count_crit=env_i("MAX_RESTART_COUNT_CRIT", 10),
        )

        # Жёсткая валидация: warn не должен превышать crit
        _validate_warn_crit(t_.max_cpu_pct_warn, t_.max_cpu_pct_crit, "cpu_pct")
        _validate_warn_crit(t_.max_mem_used_pct_warn, t_.max_mem_used_pct_crit, "mem_used_pct")
        _validate_warn_crit(t_.max_disk_used_pct_warn, t_.max_disk_used_pct_crit, "disk_used_pct")
        _validate_warn_crit(t_.max_p95_latency_ms_warn, t_.max_p95_latency_ms_crit, "p95_latency_ms")
        _validate_warn_crit(t_.max_error_rate_pct_warn, t_.max_error_rate_pct_crit, "error_rate_pct")
        _validate_warn_crit(float(t_.max_queue_lag_warn), float(t_.max_queue_lag_crit), "queue_lag")
        _validate_warn_crit(t_.max_clock_skew_ms_warn, t_.max_clock_skew_ms_crit, "clock_skew_ms")
        _validate_warn_crit(float(t_.max_restart_count_warn), float(t_.max_restart_count_crit), "restart_count")

        return t_


def _validate_warn_crit(warn: float, crit: float, name: str) -> None:
    if warn < 0 or crit < 0:
        raise HealthAnalysisError(f"{name}: thresholds must be non-negative")
    if warn > crit:
        raise HealthAnalysisError(f"{name}: warn threshold must be <= crit threshold")


@dataclasses.dataclass(frozen=True, slots=True)
class HealthSignals:
    """
    Унифицированные входные сигналы.

    Все проценты: 0..100
    latency_ms: миллисекунды
    error_rate_pct: 0..100
    queue_lag: количество элементов/сообщений в отставании
    clock_skew_ms: абсолютное значение рассинхронизации времени
    restart_count: число рестартов процесса/контейнера за окно наблюдения
    """
    cpu_pct: float | None = None
    mem_used_pct: float | None = None
    disk_used_pct: float | None = None

    p95_latency_ms: float | None = None
    error_rate_pct: float | None = None

    queue_lag: int | None = None
    clock_skew_ms: float | None = None
    restart_count: int | None = None

    # произвольные дополнительные сигналы
    extra: Json = dataclasses.field(default_factory=dict)

    def normalized(self) -> "HealthSignals":
        def norm_pct(v: float | None) -> float | None:
            if v is None:
                return None
            vv = float(v)
            return _clamp_float(vv, lo=0.0, hi=100.0)

        def norm_ms(v: float | None) -> float | None:
            if v is None:
                return None
            vv = float(v)
            return _clamp_float(vv, lo=0.0, hi=10_000_000.0)

        def norm_i(v: int | None) -> int | None:
            if v is None:
                return None
            vv = int(v)
            return _clamp_int(vv, lo=0, hi=2_000_000_000)

        return HealthSignals(
            cpu_pct=norm_pct(self.cpu_pct),
            mem_used_pct=norm_pct(self.mem_used_pct),
            disk_used_pct=norm_pct(self.disk_used_pct),
            p95_latency_ms=norm_ms(self.p95_latency_ms),
            error_rate_pct=norm_pct(self.error_rate_pct),
            queue_lag=norm_i(self.queue_lag),
            clock_skew_ms=norm_ms(self.clock_skew_ms),
            restart_count=norm_i(self.restart_count),
            extra=dict(self.extra) if isinstance(self.extra, dict) else {},
        )

    def to_dict(self) -> Json:
        return {
            "cpu_pct": self.cpu_pct,
            "mem_used_pct": self.mem_used_pct,
            "disk_used_pct": self.disk_used_pct,
            "p95_latency_ms": self.p95_latency_ms,
            "error_rate_pct": self.error_rate_pct,
            "queue_lag": self.queue_lag,
            "clock_skew_ms": self.clock_skew_ms,
            "restart_count": self.restart_count,
            "extra": self.extra,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    check_id: str
    severity: str
    message: str
    metric: str
    value: float | int | None
    threshold_warn: float | int | None
    threshold_crit: float | int | None
    tags: t.FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        Severity.order(self.severity)
        if not self.check_id:
            raise HealthAnalysisError("Finding.check_id must be non-empty")
        if not self.metric:
            raise HealthAnalysisError("Finding.metric must be non-empty")
        if not self.message:
            raise HealthAnalysisError("Finding.message must be non-empty")

    def to_dict(self) -> Json:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "message": self.message,
            "metric": self.metric,
            "value": self.value,
            "threshold_warn": self.threshold_warn,
            "threshold_crit": self.threshold_crit,
            "tags": sorted(self.tags),
        }


@dataclasses.dataclass(frozen=True, slots=True)
class HealthReport:
    report_id: str
    generated_at: dt.datetime
    overall: str
    findings: list[Finding]
    signals: HealthSignals
    meta: Json = dataclasses.field(default_factory=dict)

    def is_unhealthy(self) -> bool:
        return Severity.order(self.overall) >= Severity.order(Severity.WARN)

    def to_dict(self) -> Json:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "overall": self.overall,
            "findings": [f.to_dict() for f in self.findings],
            "signals": self.signals.to_dict(),
            "meta": self.meta,
        }


class HealthCheck(abc.ABC):
    @property
    @abc.abstractmethod
    def check_id(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        raise NotImplementedError


def _mk_finding(
    *,
    check_id: str,
    severity: str,
    message: str,
    metric: str,
    value: float | int | None,
    warn: float | int | None,
    crit: float | int | None,
    tags: t.Iterable[str] = (),
) -> Finding:
    return Finding(
        check_id=check_id,
        severity=severity,
        message=message,
        metric=metric,
        value=value,
        threshold_warn=warn,
        threshold_crit=crit,
        tags=frozenset(tags),
    )


class CpuCheck(HealthCheck):
    @property
    def check_id(self) -> str:
        return "cpu_pct"

    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        v = signals.cpu_pct
        if v is None:
            return []
        if v >= thresholds.max_cpu_pct_crit:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.CRIT,
                    message="CPU usage is critically high",
                    metric="cpu_pct",
                    value=v,
                    warn=thresholds.max_cpu_pct_warn,
                    crit=thresholds.max_cpu_pct_crit,
                    tags=("resource", "cpu"),
                )
            ]
        if v >= thresholds.max_cpu_pct_warn:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="CPU usage is high",
                    metric="cpu_pct",
                    value=v,
                    warn=thresholds.max_cpu_pct_warn,
                    crit=thresholds.max_cpu_pct_crit,
                    tags=("resource", "cpu"),
                )
            ]
        return []


class MemoryCheck(HealthCheck):
    @property
    def check_id(self) -> str:
        return "mem_used_pct"

    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        v = signals.mem_used_pct
        if v is None:
            return []
        if v >= thresholds.max_mem_used_pct_crit:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.CRIT,
                    message="Memory usage is critically high",
                    metric="mem_used_pct",
                    value=v,
                    warn=thresholds.max_mem_used_pct_warn,
                    crit=thresholds.max_mem_used_pct_crit,
                    tags=("resource", "memory"),
                )
            ]
        if v >= thresholds.max_mem_used_pct_warn:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="Memory usage is high",
                    metric="mem_used_pct",
                    value=v,
                    warn=thresholds.max_mem_used_pct_warn,
                    crit=thresholds.max_mem_used_pct_crit,
                    tags=("resource", "memory"),
                )
            ]
        return []


class DiskCheck(HealthCheck):
    @property
    def check_id(self) -> str:
        return "disk_used_pct"

    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        v = signals.disk_used_pct
        if v is None:
            return []
        if v >= thresholds.max_disk_used_pct_crit:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.CRIT,
                    message="Disk usage is critically high",
                    metric="disk_used_pct",
                    value=v,
                    warn=thresholds.max_disk_used_pct_warn,
                    crit=thresholds.max_disk_used_pct_crit,
                    tags=("resource", "disk"),
                )
            ]
        if v >= thresholds.max_disk_used_pct_warn:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="Disk usage is high",
                    metric="disk_used_pct",
                    value=v,
                    warn=thresholds.max_disk_used_pct_warn,
                    crit=thresholds.max_disk_used_pct_crit,
                    tags=("resource", "disk"),
                )
            ]
        return []


class LatencyCheck(HealthCheck):
    @property
    def check_id(self) -> str:
        return "p95_latency_ms"

    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        v = signals.p95_latency_ms
        if v is None:
            return []
        if v >= thresholds.max_p95_latency_ms_crit:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.CRIT,
                    message="p95 latency is critically high",
                    metric="p95_latency_ms",
                    value=v,
                    warn=thresholds.max_p95_latency_ms_warn,
                    crit=thresholds.max_p95_latency_ms_crit,
                    tags=("sli", "latency"),
                )
            ]
        if v >= thresholds.max_p95_latency_ms_warn:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="p95 latency is high",
                    metric="p95_latency_ms",
                    value=v,
                    warn=thresholds.max_p95_latency_ms_warn,
                    crit=thresholds.max_p95_latency_ms_crit,
                    tags=("sli", "latency"),
                )
            ]
        return []


class ErrorRateCheck(HealthCheck):
    @property
    def check_id(self) -> str:
        return "error_rate_pct"

    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        v = signals.error_rate_pct
        if v is None:
            return []
        if v >= thresholds.max_error_rate_pct_crit:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.CRIT,
                    message="Error rate is critically high",
                    metric="error_rate_pct",
                    value=v,
                    warn=thresholds.max_error_rate_pct_warn,
                    crit=thresholds.max_error_rate_pct_crit,
                    tags=("sli", "errors"),
                )
            ]
        if v >= thresholds.max_error_rate_pct_warn:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="Error rate is elevated",
                    metric="error_rate_pct",
                    value=v,
                    warn=thresholds.max_error_rate_pct_warn,
                    crit=thresholds.max_error_rate_pct_crit,
                    tags=("sli", "errors"),
                )
            ]
        return []


class QueueLagCheck(HealthCheck):
    @property
    def check_id(self) -> str:
        return "queue_lag"

    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        v = signals.queue_lag
        if v is None:
            return []
        if v >= thresholds.max_queue_lag_crit:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.CRIT,
                    message="Queue lag is critically high",
                    metric="queue_lag",
                    value=v,
                    warn=thresholds.max_queue_lag_warn,
                    crit=thresholds.max_queue_lag_crit,
                    tags=("queue", "backpressure"),
                )
            ]
        if v >= thresholds.max_queue_lag_warn:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="Queue lag is high",
                    metric="queue_lag",
                    value=v,
                    warn=thresholds.max_queue_lag_warn,
                    crit=thresholds.max_queue_lag_crit,
                    tags=("queue", "backpressure"),
                )
            ]
        return []


class ClockSkewCheck(HealthCheck):
    @property
    def check_id(self) -> str:
        return "clock_skew_ms"

    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        v = signals.clock_skew_ms
        if v is None:
            return []
        if v >= thresholds.max_clock_skew_ms_crit:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.CRIT,
                    message="Clock skew is critically high",
                    metric="clock_skew_ms",
                    value=v,
                    warn=thresholds.max_clock_skew_ms_warn,
                    crit=thresholds.max_clock_skew_ms_crit,
                    tags=("time", "ntp"),
                )
            ]
        if v >= thresholds.max_clock_skew_ms_warn:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="Clock skew is high",
                    metric="clock_skew_ms",
                    value=v,
                    warn=thresholds.max_clock_skew_ms_warn,
                    crit=thresholds.max_clock_skew_ms_crit,
                    tags=("time", "ntp"),
                )
            ]
        return []


class RestartCountCheck(HealthCheck):
    @property
    def check_id(self) -> str:
        return "restart_count"

    def evaluate(self, signals: HealthSignals, thresholds: Thresholds) -> list[Finding]:
        v = signals.restart_count
        if v is None:
            return []
        if v >= thresholds.max_restart_count_crit:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.CRIT,
                    message="Restart count is critically high",
                    metric="restart_count",
                    value=v,
                    warn=thresholds.max_restart_count_warn,
                    crit=thresholds.max_restart_count_crit,
                    tags=("stability", "restarts"),
                )
            ]
        if v >= thresholds.max_restart_count_warn:
            return [
                _mk_finding(
                    check_id=self.check_id,
                    severity=Severity.WARN,
                    message="Restart count is elevated",
                    metric="restart_count",
                    value=v,
                    warn=thresholds.max_restart_count_warn,
                    crit=thresholds.max_restart_count_crit,
                    tags=("stability", "restarts"),
                )
            ]
        return []


DEFAULT_CHECKS: tuple[HealthCheck, ...] = (
    CpuCheck(),
    MemoryCheck(),
    DiskCheck(),
    LatencyCheck(),
    ErrorRateCheck(),
    QueueLagCheck(),
    ClockSkewCheck(),
    RestartCountCheck(),
)


class SignalsProvider(abc.ABC):
    @abc.abstractmethod
    async def collect(self) -> HealthSignals:
        raise NotImplementedError


class HealthAnalyzer:
    def __init__(
        self,
        *,
        thresholds: Thresholds | None = None,
        checks: t.Sequence[HealthCheck] | None = None,
        audit: AuditLogger | None = None,
        emit_audit: bool = True,
        environment: str = "dev",
    ) -> None:
        self._thresholds = thresholds or Thresholds.from_env()
        self._checks = list(checks) if checks is not None else list(DEFAULT_CHECKS)
        self._audit = audit
        self._emit_audit = bool(emit_audit)
        self._env = environment

        # Проверка уникальности check_id
        seen: set[str] = set()
        for c in self._checks:
            cid = c.check_id
            if cid in seen:
                raise HealthAnalysisError(f"Duplicate check_id: {cid}")
            seen.add(cid)

    @property
    def thresholds(self) -> Thresholds:
        return self._thresholds

    @property
    def checks(self) -> tuple[HealthCheck, ...]:
        return tuple(self._checks)

    def analyze(
        self,
        signals: HealthSignals,
        *,
        meta: Json | None = None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> HealthReport:
        started = time.time()
        corr = correlation_id or _safe_uuid()
        sig = signals.normalized()

        findings: list[Finding] = []
        for chk in self._checks:
            res = chk.evaluate(sig, self._thresholds)
            if res:
                findings.extend(res)

        overall = self._overall(findings)
        report = HealthReport(
            report_id=_safe_uuid(),
            generated_at=_utc_now(),
            overall=overall,
            findings=sorted(findings, key=_finding_sort_key),
            signals=sig,
            meta=dict(meta) if isinstance(meta, dict) else {},
        )

        self._maybe_audit(
            report=report,
            correlation_id=corr,
            actor_id=actor_id,
            duration_ms=int((time.time() - started) * 1000),
        )

        return report

    async def analyze_async(
        self,
        signals: HealthSignals,
        *,
        meta: Json | None = None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> HealthReport:
        # CPU-лёгкая логика; но оставляем async API для симметрии с внешним кодом.
        return self.analyze(signals, meta=meta, correlation_id=correlation_id, actor_id=actor_id)

    async def analyze_from_provider(
        self,
        provider: SignalsProvider,
        *,
        meta: Json | None = None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> HealthReport:
        signals = await provider.collect()
        return await self.analyze_async(signals, meta=meta, correlation_id=correlation_id, actor_id=actor_id)

    def _overall(self, findings: list[Finding]) -> str:
        if not findings:
            return Severity.OK
        # Если есть хотя бы один CRIT -> overall CRIT, иначе WARN
        max_sev = max(findings, key=lambda f: Severity.order(f.severity)).severity
        return max_sev

    def _maybe_audit(self, *, report: HealthReport, correlation_id: str, actor_id: str | None, duration_ms: int) -> None:
        if not self._emit_audit or self._audit is None:
            return
        ctx = AuditContext(
            correlation_id=correlation_id,
            actor_id=actor_id,
            actor_type="service",
            request_id=_safe_uuid(),
        )
        # Устанавливать глобальный контекст тут не делаем, чтобы не создавать побочные эффекты;
        # пишем явно correlation_id и report_id в data.
        try:
            self._audit.log(
                "intel.health_analysis.completed",
                severity="WARN" if report.is_unhealthy() else "INFO",
                message="Health analysis completed",
                data={
                    "env": self._env,
                    "report_id": report.report_id,
                    "overall": report.overall,
                    "findings_count": len(report.findings),
                    "duration_ms": duration_ms,
                    "correlation_id": ctx.correlation_id,
                },
            )
        except Exception:
            # аудит не должен ломать основной поток
            return


def _finding_sort_key(f: Finding) -> tuple[int, str, str]:
    # CRIT выше WARN выше OK; затем metric/check_id для стабильности
    return (-Severity.order(f.severity), f.metric, f.check_id)


__all__ = [
    "HealthAnalysisError",
    "Severity",
    "Thresholds",
    "HealthSignals",
    "Finding",
    "HealthReport",
    "HealthCheck",
    "SignalsProvider",
    "HealthAnalyzer",
    "DEFAULT_CHECKS",
]
