# agent_mash/resilience/repair/unhealthy_repairer.py
from __future__ import annotations

import abc
import dataclasses
import datetime as dt
import time
import typing as t
import uuid

from agent_mash.intel.health_analysis.unhealthy import (
    HealthReport,
    Finding,
    Severity,
)
from agent_mash.governance.audit_log import AuditLogger, AuditContext

Json = dict[str, t.Any]


class RepairError(RuntimeError):
    pass


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _safe_uuid() -> str:
    return str(uuid.uuid4())


@dataclasses.dataclass(frozen=True, slots=True)
class RepairActionResult:
    action_id: str
    success: bool
    message: str
    started_at: dt.datetime
    finished_at: dt.datetime
    meta: Json = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Json:
        return {
            "action_id": self.action_id,
            "success": self.success,
            "message": self.message,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "meta": self.meta,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class RepairReport:
    report_id: str
    generated_at: dt.datetime
    health_report_id: str
    overall_before: str
    actions: list[RepairActionResult]
    overall_after: str | None
    meta: Json = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Json:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "health_report_id": self.health_report_id,
            "overall_before": self.overall_before,
            "overall_after": self.overall_after,
            "actions": [a.to_dict() for a in self.actions],
            "meta": self.meta,
        }


class RepairExecutor(abc.ABC):
    """
    Исполнитель конкретного действия восстановления.
    """

    @property
    @abc.abstractmethod
    def action_type(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def execute(self, finding: Finding) -> RepairActionResult:
        raise NotImplementedError


class NoopExecutor(RepairExecutor):
    """
    Безопасный исполнитель по умолчанию.
    Используется, если стратегия определена, но реальное действие запрещено.
    """

    @property
    def action_type(self) -> str:
        return "noop"

    def execute(self, finding: Finding) -> RepairActionResult:
        started = _utc_now()
        time.sleep(0.01)
        finished = _utc_now()
        return RepairActionResult(
            action_id=_safe_uuid(),
            success=True,
            message="No operation performed",
            started_at=started,
            finished_at=finished,
            meta={"finding": finding.check_id},
        )


@dataclasses.dataclass(frozen=True, slots=True)
class RepairStrategy:
    """
    Связывает finding с типом действия.
    """
    check_id: str
    min_severity: str
    action_type: str

    def applicable(self, finding: Finding) -> bool:
        return (
            finding.check_id == self.check_id
            and Severity.order(finding.severity) >= Severity.order(self.min_severity)
        )


class UnhealthyRepairer:
    def __init__(
        self,
        *,
        strategies: t.Sequence[RepairStrategy],
        executors: t.Sequence[RepairExecutor],
        audit: AuditLogger | None = None,
        emit_audit: bool = True,
        environment: str = "dev",
    ) -> None:
        self._strategies = list(strategies)
        self._executors: dict[str, RepairExecutor] = {
            ex.action_type: ex for ex in executors
        }
        self._audit = audit
        self._emit_audit = bool(emit_audit)
        self._env = environment

    def repair(
        self,
        health_report: HealthReport,
        *,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> RepairReport:
        corr = correlation_id or _safe_uuid()
        started = time.time()

        actions: list[RepairActionResult] = []

        for finding in health_report.findings:
            strat = self._match_strategy(finding)
            if strat is None:
                continue

            executor = self._executors.get(strat.action_type)
            if executor is None:
                raise RepairError(f"No executor for action_type {strat.action_type}")

            result = executor.execute(finding)
            actions.append(result)

        report = RepairReport(
            report_id=_safe_uuid(),
            generated_at=_utc_now(),
            health_report_id=health_report.report_id,
            overall_before=health_report.overall,
            overall_after=None,
            actions=actions,
            meta={
                "env": self._env,
                "duration_ms": int((time.time() - started) * 1000),
            },
        )

        self._maybe_audit(
            report=report,
            correlation_id=corr,
            actor_id=actor_id,
        )

        return report

    def _match_strategy(self, finding: Finding) -> RepairStrategy | None:
        for s in self._strategies:
            if s.applicable(finding):
                return s
        return None

    def _maybe_audit(
        self,
        *,
        report: RepairReport,
        correlation_id: str,
        actor_id: str | None,
    ) -> None:
        if not self._emit_audit or self._audit is None:
            return

        ctx = AuditContext(
            correlation_id=correlation_id,
            actor_id=actor_id,
            actor_type="service",
            request_id=_safe_uuid(),
        )

        try:
            self._audit.log(
                "resilience.repair.completed",
                severity="WARN" if report.actions else "INFO",
                message="Unhealthy repair cycle completed",
                data={
                    "report_id": report.report_id,
                    "health_report_id": report.health_report_id,
                    "actions_count": len(report.actions),
                    "env": self._env,
                    "correlation_id": ctx.correlation_id,
                },
            )
        except Exception:
            return


__all__ = [
    "RepairError",
    "RepairActionResult",
    "RepairReport",
    "RepairExecutor",
    "NoopExecutor",
    "RepairStrategy",
    "UnhealthyRepairer",
]
