# agent_mash/intel/recommendations/action_plans.py
from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union


JsonDict = Dict[str, Any]
JsonLike = Union[JsonDict, List[Any], str, int, float, bool, None]


class ActionPlanError(RuntimeError):
    pass


class PayloadInvalid(ActionPlanError):
    pass


class PolicyMisconfigured(ActionPlanError):
    pass


class AuditSinkError(ActionPlanError):
    pass


class Priority(str, enum.Enum):
    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"


class PlanStatus(str, enum.Enum):
    DRAFT = "draft"
    READY = "ready"
    APPROVED = "approved"
    EXECUTING = "executing"
    DONE = "done"


class TaskType(str, enum.Enum):
    DIAGNOSE = "diagnose"
    MITIGATE = "mitigate"
    REMEDIATE = "remediate"
    VERIFY = "verify"
    ROLLBACK = "rollback"
    COMMUNICATE = "communicate"


@dataclasses.dataclass(frozen=True)
class PlanSignal:
    key: str
    value: JsonLike
    ts_ms: int
    source: str = "unknown"
    tags: Tuple[str, ...] = ()
    details: Mapping[str, JsonLike] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class PlanHit:
    rule_id: str
    severity: str
    reason: str
    confidence: float = 1.0
    tags: Tuple[str, ...] = ()
    details: Mapping[str, JsonLike] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class PlanContext:
    tenant_id: Optional[str]
    actor_id: Optional[str]
    environment: str
    service: Optional[str]
    region: Optional[str]
    request_id: str
    trace_id: str
    created_at_ms: int


@dataclasses.dataclass(frozen=True)
class ActionTask:
    task_id: str
    title: str
    description: str
    task_type: TaskType
    priority: Priority
    owner: str
    steps: Tuple[str, ...] = ()
    checks: Tuple[str, ...] = ()
    rollback: Tuple[str, ...] = ()
    evidence: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()
    links: Tuple[str, ...] = ()
    related_rule_ids: Tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class ActionPlan:
    plan_id: str
    status: PlanStatus
    priority: Priority
    title: str
    summary: str
    context: PlanContext
    tasks: Tuple[ActionTask, ...]
    signals: Tuple[PlanSignal, ...] = ()
    hits: Tuple[PlanHit, ...] = ()
    policy_version: str = "action-plan-v1"
    score: float = 0.0

    def to_dict(self) -> JsonDict:
        return {
            "plan_id": self.plan_id,
            "status": self.status.value,
            "priority": self.priority.value,
            "title": self.title,
            "summary": self.summary,
            "policy_version": self.policy_version,
            "score": float(self.score),
            "context": dataclasses.asdict(self.context),
            "tasks": [
                {
                    "task_id": t.task_id,
                    "title": t.title,
                    "description": t.description,
                    "task_type": t.task_type.value,
                    "priority": t.priority.value,
                    "owner": t.owner,
                    "steps": list(t.steps),
                    "checks": list(t.checks),
                    "rollback": list(t.rollback),
                    "evidence": list(t.evidence),
                    "tags": list(t.tags),
                    "links": list(t.links),
                    "related_rule_ids": list(t.related_rule_ids),
                }
                for t in self.tasks
            ],
            "signals": [dataclasses.asdict(s) for s in self.signals],
            "hits": [dataclasses.asdict(h) for h in self.hits],
        }


class AuditSink(Protocol):
    async def emit(self, event: Mapping[str, JsonLike]) -> None:
        ...


def _stable_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError as e:
        raise PayloadInvalid(f"Not JSON-serializable: {e}") from e


def _blake2b_hex(data: bytes, digest_size: int = 16) -> str:
    h_ = hashlib.blake2b(digest_size=digest_size)
    h_.update(data)
    return h_.hexdigest()


def _hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _slug(s: str, *, max_len: int = 80) -> str:
    s2 = s.strip().lower()
    s2 = re.sub(r"[^a-z0-9]+", "-", s2)
    s2 = re.sub(r"-{2,}", "-", s2).strip("-")
    if len(s2) > max_len:
        s2 = s2[:max_len].rstrip("-")
    return s2 or "plan"


def _priority_from_severity(sev: str) -> Priority:
    s = (sev or "").strip().lower()
    if s in ("critical", "sev0", "p0", "fatal"):
        return Priority.P0
    if s in ("high", "sev1", "p1"):
        return Priority.P1
    if s in ("medium", "sev2", "p2", "warn", "warning"):
        return Priority.P2
    return Priority.P3


def _priority_max(a: Priority, b: Priority) -> Priority:
    order = {Priority.P0: 0, Priority.P1: 1, Priority.P2: 2, Priority.P3: 3}
    return a if order[a] <= order[b] else b


@dataclasses.dataclass(frozen=True)
class PlanPolicy:
    policy_version: str = "action-plan-v1"
    default_owner: str = "oncall"
    environment_default: str = "prod"
    trace_hmac_key: Optional[bytes] = None
    max_tasks: int = 64
    max_signals: int = 2000
    max_hits: int = 2000

    # weights (0..1) used to compute plan score
    severity_weight: float = 0.7
    confidence_weight: float = 0.3


class PlanTemplate(Protocol):
    template_id: str

    def match(self, *, signals: Sequence[PlanSignal], hits: Sequence[PlanHit], ctx: PlanContext) -> bool:
        ...

    def build(self, *, signals: Sequence[PlanSignal], hits: Sequence[PlanHit], ctx: PlanContext, policy: PlanPolicy) -> Sequence[ActionTask]:
        ...


def _trace_id(policy: PlanPolicy, *, created_at_ms: int, request_id: str, title: str, summary: str) -> str:
    base = {"ts": created_at_ms, "req": request_id, "title": title, "summary": summary, "policy": policy.policy_version}
    raw = _stable_json(base).encode("utf-8")
    if policy.trace_hmac_key:
        return _hmac_sha256_hex(policy.trace_hmac_key, raw)
    return _blake2b_hex(raw, digest_size=16)


def _request_id(*, created_at_ms: int, tenant_id: Optional[str], actor_id: Optional[str], environment: str) -> str:
    base = {"ts": created_at_ms, "tenant": tenant_id, "actor": actor_id, "env": environment}
    raw = _stable_json(base).encode("utf-8")
    return _blake2b_hex(raw, digest_size=16)


def _plan_id(*, created_at_ms: int, trace_id: str) -> str:
    raw = f"{created_at_ms}:{trace_id}:{uuid.uuid4().hex}".encode("utf-8")
    return _blake2b_hex(raw, digest_size=16)


def _plan_score(policy: PlanPolicy, hits: Sequence[PlanHit]) -> float:
    if not hits:
        return 0.0
    # Score 0..100: higher => more urgent/valuable
    # Convert severity strings to a base number
    sev_map = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.25,
        "info": 0.1,
    }

    max_sev = 0.0
    max_conf = 0.0
    for h in hits:
        sev = sev_map.get((h.severity or "").strip().lower(), 0.25)
        conf = float(h.confidence)
        if sev > max_sev:
            max_sev = sev
        if conf > max_conf:
            max_conf = conf

    val = (policy.severity_weight * max_sev + policy.confidence_weight * max_conf) * 100.0
    return float(round(min(max(val, 0.0), 100.0), 2))


def _dedup_tasks(tasks: Sequence[ActionTask]) -> Tuple[ActionTask, ...]:
    seen: set[str] = set()
    out: List[ActionTask] = []
    for t in tasks:
        key = (t.title.strip().lower(), t.task_type.value, t.priority.value, t.owner.strip().lower())
        fp = _blake2b_hex(_stable_json(key).encode("utf-8"), digest_size=16)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(t)
    return tuple(out)


def _enforce_limits(policy: PlanPolicy, signals: Sequence[PlanSignal], hits: Sequence[PlanHit], tasks: Sequence[ActionTask]) -> Tuple[
    Tuple[PlanSignal, ...], Tuple[PlanHit, ...], Tuple[ActionTask, ...]
]:
    s = tuple(signals[: policy.max_signals])
    h = tuple(hits[: policy.max_hits])
    t = tuple(tasks[: policy.max_tasks])
    return s, h, t


class ActionPlanBuilder:
    def __init__(
        self,
        *,
        policy: PlanPolicy,
        templates: Sequence[PlanTemplate] = (),
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        if not policy.policy_version:
            raise PolicyMisconfigured("policy_version must be non-empty")
        self._policy = policy
        self._templates = tuple(templates)
        self._audit_sink = audit_sink

    @property
    def policy(self) -> PlanPolicy:
        return self._policy

    async def build(
        self,
        *,
        signals: Sequence[PlanSignal],
        hits: Sequence[PlanHit],
        tenant_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        environment: Optional[str] = None,
        service: Optional[str] = None,
        region: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> ActionPlan:
        created_at_ms = _now_ms()
        env = (environment or self._policy.environment_default).strip() or self._policy.environment_default

        req_id = request_id or _request_id(created_at_ms=created_at_ms, tenant_id=tenant_id, actor_id=actor_id, environment=env)

        # priority derived from hits, otherwise P3
        priority = Priority.P3
        for h in hits:
            priority = _priority_max(priority, _priority_from_severity(h.severity))

        title = self._title_from_inputs(signals=signals, hits=hits, env=env, service=service)
        summary = self._summary_from_inputs(signals=signals, hits=hits)

        trace = _trace_id(self._policy, created_at_ms=created_at_ms, request_id=req_id, title=title, summary=summary)
        ctx = PlanContext(
            tenant_id=tenant_id,
            actor_id=actor_id,
            environment=env,
            service=service,
            region=region,
            request_id=req_id,
            trace_id=trace,
            created_at_ms=created_at_ms,
        )

        tasks = self._build_tasks(signals=signals, hits=hits, ctx=ctx)
        tasks = _dedup_tasks(tasks)

        signals2, hits2, tasks2 = _enforce_limits(self._policy, signals, hits, tasks)

        plan = ActionPlan(
            plan_id=_plan_id(created_at_ms=created_at_ms, trace_id=trace),
            status=PlanStatus.READY,
            priority=priority,
            title=title,
            summary=summary,
            context=ctx,
            tasks=tasks2,
            signals=signals2,
            hits=hits2,
            policy_version=self._policy.policy_version,
            score=_plan_score(self._policy, hits2),
        )

        await self._audit(plan)
        return plan

    def _build_tasks(self, *, signals: Sequence[PlanSignal], hits: Sequence[PlanHit], ctx: PlanContext) -> Sequence[ActionTask]:
        matched: List[PlanTemplate] = []
        for t in self._templates:
            try:
                if t.match(signals=signals, hits=hits, ctx=ctx):
                    matched.append(t)
            except Exception:
                continue

        tasks: List[ActionTask] = []
        for tmpl in matched:
            try:
                built = list(tmpl.build(signals=signals, hits=hits, ctx=ctx, policy=self._policy))
                tasks.extend(built)
            except Exception:
                continue

        if not tasks:
            tasks.extend(self._fallback_tasks(signals=signals, hits=hits, ctx=ctx))

        # Attach related_rule_ids if possible by matching reason tags
        related = tuple({h.rule_id for h in hits if h.rule_id})
        out: List[ActionTask] = []
        for t in tasks:
            out.append(dataclasses.replace(t, related_rule_ids=tuple(sorted(set(t.related_rule_ids) | set(related)))))
        return out

    def _fallback_tasks(self, *, signals: Sequence[PlanSignal], hits: Sequence[PlanHit], ctx: PlanContext) -> List[ActionTask]:
        owner = self._policy.default_owner
        prio = Priority.P2 if hits else Priority.P3
        task_base_tags = ("action_plan", ctx.environment, ctx.service or "unknown_service")

        diagnose = ActionTask(
            task_id=_blake2b_hex(f"diagnose:{ctx.trace_id}".encode("utf-8"), digest_size=16),
            title="Diagnose issue and confirm scope",
            description="Collect evidence from metrics/logs/traces, confirm blast radius, and identify likely root cause.",
            task_type=TaskType.DIAGNOSE,
            priority=prio,
            owner=owner,
            steps=(
                "Collect top signals and recent changes (deploys, config, traffic).",
                "Check error rate, latency, saturation, and dependency health.",
                "Correlate hits with time window and affected components.",
            ),
            checks=("Evidence collected and stored", "Scope confirmed"),
            rollback=("If a recent deploy correlates, prepare rollback plan.",),
            evidence=("Attach links to dashboards/log excerpts.",),
            tags=task_base_tags + ("diagnose",),
            links=(),
        )

        mitigate = ActionTask(
            task_id=_blake2b_hex(f"mitigate:{ctx.trace_id}".encode("utf-8"), digest_size=16),
            title="Mitigate impact",
            description="Apply safe mitigation steps to reduce user impact while preserving forensics.",
            task_type=TaskType.MITIGATE,
            priority=prio,
            owner=owner,
            steps=(
                "Enable circuit breakers / rate limits if available.",
                "Scale out if saturation is suspected.",
                "Disable non-critical features contributing to load.",
            ),
            checks=("User impact reduced",),
            rollback=("Revert mitigation if it increases error rate.",),
            evidence=("Record changes and timestamps.",),
            tags=task_base_tags + ("mitigate",),
        )

        verify = ActionTask(
            task_id=_blake2b_hex(f"verify:{ctx.trace_id}".encode("utf-8"), digest_size=16),
            title="Verify recovery",
            description="Validate that key SLO/SLI metrics recovered and no regressions remain.",
            task_type=TaskType.VERIFY,
            priority=Priority.P3,
            owner=owner,
            steps=(
                "Verify latency/error/saturation within thresholds for 30-60 minutes.",
                "Confirm downstream dependencies are healthy.",
                "Close or downgrade incident if stable.",
            ),
            checks=("SLO/SLI within thresholds", "No active alerts for window",),
            rollback=(),
            evidence=("Snapshot dashboards before/after.",),
            tags=task_base_tags + ("verify",),
        )

        communicate = ActionTask(
            task_id=_blake2b_hex(f"communicate:{ctx.trace_id}".encode("utf-8"), digest_size=16),
            title="Communicate status",
            description="Notify stakeholders and keep a short timeline of actions and impacts.",
            task_type=TaskType.COMMUNICATE,
            priority=Priority.P3,
            owner=owner,
            steps=(
                "Post incident summary to the incident channel.",
                "Update status page if applicable.",
            ),
            checks=("Stakeholders informed",),
            rollback=(),
            evidence=("Link to incident thread",),
            tags=task_base_tags + ("comms",),
        )

        return [diagnose, mitigate, verify, communicate]

    def _title_from_inputs(self, *, signals: Sequence[PlanSignal], hits: Sequence[PlanHit], env: str, service: Optional[str]) -> str:
        if hits:
            top = hits[0]
            sname = service or "service"
            return f"{env}:{sname}: action plan for {top.rule_id}"
        return f"{env}:{service or 'service'}: action plan"

    def _summary_from_inputs(self, *, signals: Sequence[PlanSignal], hits: Sequence[PlanHit]) -> str:
        if not hits:
            return "No rule hits provided; plan is based on signals only."
        top = hits[0]
        return f"Top hit: {top.rule_id} ({top.severity}) reason={top.reason}"

    async def _audit(self, plan: ActionPlan) -> None:
        if self._audit_sink is None:
            return
        event: JsonDict = {
            "kind": "action_plan",
            "plan_id": plan.plan_id,
            "policy_version": plan.policy_version,
            "created_at_ms": plan.context.created_at_ms,
            "trace_id": plan.context.trace_id,
            "request_id": plan.context.request_id,
            "tenant_id": plan.context.tenant_id,
            "actor_id": plan.context.actor_id,
            "environment": plan.context.environment,
            "service": plan.context.service,
            "region": plan.context.region,
            "status": plan.status.value,
            "priority": plan.priority.value,
            "score": plan.score,
            "title": plan.title,
            "summary": plan.summary,
            "tasks": [t.__dict__ for t in plan.tasks],
            "hits": [h.__dict__ for h in plan.hits],
            "signals": [s.__dict__ for s in plan.signals],
        }
        try:
            await self._audit_sink.emit(event)
        except Exception as e:
            raise AuditSinkError(str(e)) from e
