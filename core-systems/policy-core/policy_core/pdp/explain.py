# policy_core/pdp/explain.py
# Industrial-grade PDP explainability module for ABAC/RBAC/XACML/OPA-like engines.
# Python 3.11+

from __future__ import annotations

import contextlib
import dataclasses
import functools
import hashlib
import json
import logging
import re
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

try:
    # Optional OpenTelemetry integration
    from opentelemetry import trace as otel_trace  # type: ignore
    _OTEL_TRACER = otel_trace.get_tracer("policy_core.pdp.explain")
except Exception:  # pragma: no cover
    class _NoOtelTracer:
        @contextlib.contextmanager
        def start_as_current_span(self, name: str):
            yield

    _OTEL_TRACER = _NoOtelTracer()  # type: ignore


__all__ = [
    "DecisionEffect",
    "ConditionStatus",
    "ConditionResult",
    "RuleTrace",
    "PolicyTrace",
    "DecisionExplanation",
    "PolicyExplainer",
    "ExplainError",
    "CombiningAlg",
]


# ----------------------------- Logging ---------------------------------------

_LOG = logging.getLogger("policy_core.pdp.explain")
if not _LOG.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
    _handler.setFormatter(_formatter)
    _LOG.addHandler(_handler)
    _LOG.setLevel(logging.INFO)


# ----------------------------- Errors ----------------------------------------

class ExplainError(RuntimeError):
    """Domain error for explainability module."""


# ----------------------------- Enums & Constants ------------------------------

class DecisionEffect(Enum):
    PERMIT = "Permit"
    DENY = "Deny"
    NOT_APPLICABLE = "NotApplicable"
    INDETERMINATE = "Indeterminate"


class ConditionStatus(Enum):
    PASSED = "Passed"
    FAILED = "Failed"
    ERROR = "Error"
    SKIPPED = "Skipped"


class CombiningAlg(Enum):
    DENY_OVERRIDES = "deny-overrides"
    PERMIT_OVERRIDES = "permit-overrides"
    FIRST_APPLICABLE = "first-applicable"


_DEFAULT_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"password", r"secret", r"token", r"api[_-]?key", r"private[_-]?key",
        r"auth", r"bearer", r"session", r"cookie", r"ssn", r"passport"
    )
)

_I18N = {
    "en": {
        "request": "Request",
        "subject": "subject",
        "resource": "resource",
        "action": "action",
        "environment": "environment",
        "effect": "Effect",
        "algorithm": "Combining Algorithm",
        "matched_rules": "Matched Rules",
        "not_applicable": "No applicable rules.",
        "obligations": "Obligations",
        "advice": "Advice",
        "policy": "Policy",
        "rule": "Rule",
        "condition": "Condition",
        "result": "Result",
        "evaluation_time_ms": "Evaluation time (ms)",
        "cache_hit": "Cache hit",
        "rationale": "Rationale",
        "missing_attributes": "Missing attributes",
        "conflicts": "Conflicts",
        "error": "Error",
    },
    "ru": {
        "request": "Запрос",
        "subject": "субъект",
        "resource": "ресурс",
        "action": "действие",
        "environment": "окружение",
        "effect": "Эффект",
        "algorithm": "Алгоритм комбинирования",
        "matched_rules": "Сработавшие правила",
        "not_applicable": "Подходящих правил нет.",
        "obligations": "Обязанности",
        "advice": "Советы",
        "policy": "Политика",
        "rule": "Правило",
        "condition": "Условие",
        "result": "Результат",
        "evaluation_time_ms": "Время вычисления (мс)",
        "cache_hit": "Попадание в кэш",
        "rationale": "Обоснование",
        "missing_attributes": "Отсутствующие атрибуты",
        "conflicts": "Конфликты",
        "error": "Ошибка",
    },
}


# ----------------------------- Dataclasses ------------------------------------

def _redact_value(value: Any, patterns: Sequence[re.Pattern[str]]) -> Any:
    """Redact sensitive scalars and keys in nested mappings/lists."""
    if isinstance(value, Mapping):
        return {k: ("***" if any(p.search(str(k)) for p in patterns) else _redact_value(v, patterns))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        t = type(value)
        return t(_redact_value(v, patterns) for v in value)
    if isinstance(value, str):
        # Redact tokens that look like keys/secrets
        if any(p.search(value) for p in patterns) or re.fullmatch(r"[A-Za-z0-9_\-]{24,}", value):
            return "***"
    return value


@dataclass(slots=True, kw_only=True)
class ConditionResult:
    expression: str
    status: ConditionStatus
    value: Optional[bool] = None
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "expression": self.expression,
            "status": self.status.value,
            "value": self.value,
            "error": self.error,
            "details": self.details,
        }


@dataclass(slots=True, kw_only=True)
class RuleTrace:
    rule_id: str
    name: Optional[str] = None
    effect_if_matched: DecisionEffect = DecisionEffect.DENY
    matched: bool = False
    conditions: List[ConditionResult] = field(default_factory=list)
    obligations: List[Mapping[str, Any]] = field(default_factory=list)
    advice: List[Mapping[str, Any]] = field(default_factory=list)
    rationale: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "effect_if_matched": self.effect_if_matched.value,
            "matched": self.matched,
            "conditions": [c.to_dict() for c in self.conditions],
            "obligations": self.obligations,
            "advice": self.advice,
            "rationale": self.rationale,
            "error": self.error,
        }


@dataclass(slots=True, kw_only=True)
class PolicyTrace:
    policy_id: str
    name: Optional[str] = None
    algorithm: CombiningAlg = CombiningAlg.DENY_OVERRIDES
    rules: List[RuleTrace] = field(default_factory=list)
    effect: DecisionEffect = DecisionEffect.NOT_APPLICABLE
    rationale: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "algorithm": self.algorithm.value,
            "rules": [r.to_dict() for r in self.rules],
            "effect": self.effect.value,
            "rationale": self.rationale,
            "error": self.error,
        }


@dataclass(slots=True, kw_only=True)
class DecisionExplanation:
    request_id: str
    effect: DecisionEffect
    subject: Mapping[str, Any]
    resource: Mapping[str, Any]
    action: Mapping[str, Any]
    environment: Mapping[str, Any] = field(default_factory=dict)
    policies: List[PolicyTrace] = field(default_factory=list)
    obligations: List[Mapping[str, Any]] = field(default_factory=list)
    advice: List[Mapping[str, Any]] = field(default_factory=list)
    evaluation_time_ms: float = 0.0
    cache_hit: bool = False
    missing_attributes: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    rationale: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "effect": self.effect.value,
            "subject": self.subject,
            "resource": self.resource,
            "action": self.action,
            "environment": self.environment,
            "policies": [p.to_dict() for p in self.policies],
            "obligations": self.obligations,
            "advice": self.advice,
            "evaluation_time_ms": self.evaluation_time_ms,
            "cache_hit": self.cache_hit,
            "missing_attributes": self.missing_attributes,
            "conflicts": self.conflicts,
            "rationale": self.rationale,
        }

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=None if indent else (",", ":"), indent=indent)

    def to_text(self, locale: str = "ru") -> str:
        L = _I18N.get(locale, _I18N["en"])
        lines: List[str] = []
        lines.append(f"{L['request']}:")
        lines.append(f"  {L['subject']}: {self.subject}")
        lines.append(f"  {L['resource']}: {self.resource}")
        lines.append(f"  {L['action']}: {self.action}")
        if self.environment:
            lines.append(f"  {L['environment']}: {self.environment}")
        lines.append(f"{L['effect']}: {self.effect.value}")
        if self.rationale:
            lines.append(f"{L['rationale']}: {self.rationale}")
        for pol in self.policies:
            lines.append(f"{L['policy']}: {pol.name or pol.policy_id} [{L['algorithm']}: {pol.algorithm.value}] -> {pol.effect.value}")
            if pol.rationale:
                lines.append(f"  {L['rationale']}: {pol.rationale}")
            for rule in pol.rules:
                prefix = "  "
                lines.append(f"{prefix}{L['rule']}: {rule.name or rule.rule_id} -> {'MATCH' if rule.matched else 'NO MATCH'} ({rule.effect_if_matched.value})")
                if rule.rationale:
                    lines.append(f"{prefix}  {L['rationale']}: {rule.rationale}")
                if rule.error:
                    lines.append(f"{prefix}  {L['error']}: {rule.error}")
                for cond in rule.conditions:
                    lines.append(f"{prefix}  {L['condition']}: {cond.expression} | {L['result']}: {cond.status.value}"
                                 + (f" = {cond.value}" if cond.value is not None else "")
                                 + (f" | {L['error']}: {cond.error}" if cond.error else ""))
        if self.obligations:
            lines.append(f"{L['obligations']}: {self.obligations}")
        if self.advice:
            lines.append(f"{L['advice']}: {self.advice}")
        if self.missing_attributes:
            lines.append(f"{L['missing_attributes']}: {self.missing_attributes}")
        if self.conflicts:
            lines.append(f"{L['conflicts']}: {self.conflicts}")
        lines.append(f"{L['evaluation_time_ms']}: {round(self.evaluation_time_ms, 3)}")
        lines.append(f"{L['cache_hit']}: {self.cache_hit}")
        return "\n".join(lines)


# ----------------------------- Time Budget ------------------------------------

class _TimeBudget:
    """Wall-clock time budget guard."""

    def __init__(self, timeout_ms: Optional[int]):
        self._timeout_ms = timeout_ms
        self._start = time.perf_counter()

    def ensure_time(self) -> None:
        if self._timeout_ms is None:
            return
        elapsed = (time.perf_counter() - self._start) * 1000.0
        if elapsed > self._timeout_ms:
            raise ExplainError(f"Time budget exceeded: {elapsed:.2f} ms > {self._timeout_ms} ms")

    @property
    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000.0


# ----------------------------- Trace Recorder ---------------------------------

@dataclass(slots=True)
class _Recorder:
    policies: List[PolicyTrace] = field(default_factory=list)
    current_policy: Optional[PolicyTrace] = None
    current_rule: Optional[RuleTrace] = None

    def push_policy(self, policy: PolicyTrace) -> None:
        self.current_policy = policy
        self.policies.append(policy)

    def push_rule(self, rule: RuleTrace) -> None:
        if not self.current_policy:
            raise ExplainError("No active policy when starting a rule")
        self.current_rule = rule
        self.current_policy.rules.append(rule)

    def add_condition(self, cond: ConditionResult) -> None:
        if not self.current_rule:
            raise ExplainError("No active rule when adding a condition")
        self.current_rule.conditions.append(cond)

    def end_rule(self, *, matched: bool, rationale: Optional[str] = None, error: Optional[str] = None) -> None:
        if not self.current_rule:
            raise ExplainError("No active rule to end")
        self.current_rule.matched = matched
        self.current_rule.rationale = rationale
        self.current_rule.error = error
        self.current_rule = None

    def end_policy(self, *, effect: DecisionEffect, rationale: Optional[str] = None, error: Optional[str] = None) -> None:
        if not self.current_policy:
            raise ExplainError("No active policy to end")
        self.current_policy.effect = effect
        self.current_policy.rationale = rationale
        self.current_policy.error = error
        self.current_policy = None


_thread_local = threading.local()


def _get_recorder() -> _Recorder:
    rec = getattr(_thread_local, "recorder", None)
    if rec is None:
        rec = _Recorder()
        _thread_local.recorder = rec
    return rec


# ----------------------------- Policy Explainer --------------------------------

class PolicyExplainer:
    """
    Industrial explainability engine.

    Typical usage inside PDP:
        explainer = PolicyExplainer()
        with explainer.session(request=..., locale="ru") as sx:
            with sx.policy("policy-1", algorithm=CombiningAlg.DENY_OVERRIDES, name="Base Policy") as px:
                with px.rule("rule-1", effect_if_matched=DecisionEffect.PERMIT, name="AllowAdmins") as rx:
                    rx.check("subject.role == 'admin'", status=ConditionStatus.PASSED, value=True)
                    rx.close(matched=True, rationale="Subject is admin")
                px.close(effect=px.evaluate())  # compute effect from rules by selected algorithm
            explanation = sx.finalize(effect=..., obligations=[...], advice=[...])

    If you already computed final effect externally, pass it to finalize().
    """

    def __init__(
        self,
        *,
        namespace: uuid.UUID = uuid.UUID("00000000-0000-0000-0000-00000000a11e"),
        redact_patterns: Sequence[re.Pattern[str]] = _DEFAULT_REDACT_PATTERNS,
        cache_size: int = 512,
    ) -> None:
        self._ns = namespace
        self._redact_patterns = tuple(redact_patterns)
        self._cache = functools.lru_cache(maxsize=cache_size)(self._build_explanation)  # type: ignore
        self._listeners: List[Callable[[DecisionExplanation], None]] = []

    # -------- Public API --------

    def add_listener(self, listener: Callable[[DecisionExplanation], None]) -> None:
        """Register a listener that receives finalized DecisionExplanation."""
        self._listeners.append(listener)

    @contextlib.contextmanager
    def session(
        self,
        *,
        request: Mapping[str, Any],
        locale: str = "ru",
        time_budget_ms: Optional[int] = 2000,
        enable_cache: bool = True,
    ):
        """Context manager to build trace and finalize explanation."""
        budget = _TimeBudget(time_budget_ms)
        budget.ensure_time()
        red_req = self._redact_request(request)
        request_id = self._request_uuid(red_req)
        recorder = _Recorder()
        _thread_local.recorder = recorder
        cache_key = None
        if enable_cache:
            cache_key = self._cache_key(red_req, locale)

        with _OTEL_TRACER.start_as_current_span("pdp.explain.session"):
            try:
                yield _Session(self, recorder, budget, red_req, request_id, locale, cache_key)
            finally:
                # Safety: clear current rule/policy on exit
                recorder.current_rule = None
                recorder.current_policy = None
                # Do not clear policies — they are needed for finalize()

    def finalize(
        self,
        *,
        request: Mapping[str, Any],
        effect: DecisionEffect,
        policies: Sequence[PolicyTrace],
        evaluation_time_ms: float,
        locale: str,
        obligations: Sequence[Mapping[str, Any]] | None = None,
        advice: Sequence[Mapping[str, Any]] | None = None,
        cache_key: Optional[str] = None,
        missing_attributes: Sequence[str] | None = None,
        conflicts: Sequence[str] | None = None,
        rationale: Optional[str] = None,
        cache_hit: bool = False,
    ) -> DecisionExplanation:
        """Build DecisionExplanation and notify listeners."""
        exp = self._build_explanation_manifest(
            request=request,
            effect=effect,
            policies=policies,
            evaluation_time_ms=evaluation_time_ms,
            locale=locale,
            obligations=list(obligations or []),
            advice=list(advice or []),
            missing_attributes=list(missing_attributes or []),
            conflicts=list(conflicts or []),
            rationale=rationale,
            cache_hit=cache_hit,
        )
        for listener in self._listeners:
            try:
                listener(exp)
            except Exception as e:  # pragma: no cover
                _LOG.warning("Listener error: %s", e)
        if cache_key:
            # Store in LRU (value is unused; we memoize via _build_explanation)
            pass
        return exp

    # -------- Internal helpers --------

    def _redact_request(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        subj = _redact_value(request.get("subject", {}), self._redact_patterns)
        res = _redact_value(request.get("resource", {}), self._redact_patterns)
        act = _redact_value(request.get("action", {}), self._redact_patterns)
        env = _redact_value(request.get("environment", {}), self._redact_patterns)
        return {"subject": subj, "resource": res, "action": act, "environment": env}

    def _request_uuid(self, red_req: Mapping[str, Any]) -> str:
        payload = json.dumps(red_req, sort_keys=True, ensure_ascii=False).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        return str(uuid.uuid5(self._ns, digest))

    def _cache_key(self, red_req: Mapping[str, Any], locale: str) -> str:
        return hashlib.sha256(
            (json.dumps(red_req, sort_keys=True, ensure_ascii=False) + f"|{locale}").encode("utf-8")
        ).hexdigest()

    def _build_explanation_manifest(
        self,
        *,
        request: Mapping[str, Any],
        effect: DecisionEffect,
        policies: Sequence[PolicyTrace],
        evaluation_time_ms: float,
        locale: str,
        obligations: List[Mapping[str, Any]],
        advice: List[Mapping[str, Any]],
        missing_attributes: List[str],
        conflicts: List[str],
        rationale: Optional[str],
        cache_hit: bool,
    ) -> DecisionExplanation:
        red_req = self._redact_request(request)
        request_id = self._request_uuid(red_req)
        return DecisionExplanation(
            request_id=request_id,
            effect=effect,
            subject=red_req["subject"],
            resource=red_req["resource"],
            action=red_req["action"],
            environment=red_req.get("environment", {}),
            policies=list(policies),
            obligations=obligations,
            advice=advice,
            evaluation_time_ms=evaluation_time_ms,
            cache_hit=cache_hit,
            missing_attributes=missing_attributes,
            conflicts=conflicts,
            rationale=rationale,
        )

    # For external memoization: build explanation from frozen trace (used by session)
    def _build_explanation(
        self, cache_key: str, request: Mapping[str, Any], effect: DecisionEffect, policies: Tuple[PolicyTrace, ...],
        evaluation_time_ms: float, locale: str, obligations: Tuple[Mapping[str, Any], ...], advice: Tuple[Mapping[str, Any], ...],
        missing_attributes: Tuple[str, ...], conflicts: Tuple[str, ...], rationale: Optional[str]
    ) -> DecisionExplanation:
        return self._build_explanation_manifest(
            request=request,
            effect=effect,
            policies=list(policies),
            evaluation_time_ms=evaluation_time_ms,
            locale=locale,
            obligations=list(obligations),
            advice=list(advice),
            missing_attributes=list(missing_attributes),
            conflicts=list(conflicts),
            rationale=rationale,
            cache_hit=True,
        )


# ----------------------------- Session / Policy / Rule Scopes -----------------

class _Session:
    def __init__(
        self,
        explainer: PolicyExplainer,
        recorder: _Recorder,
        budget: _TimeBudget,
        request: Mapping[str, Any],
        request_id: str,
        locale: str,
        cache_key: Optional[str],
    ) -> None:
        self._explainer = explainer
        self._recorder = recorder
        self._budget = budget
        self._request = request
        self._request_id = request_id
        self._locale = locale
        self._cache_key = cache_key

    @contextlib.contextmanager
    def policy(self, policy_id: str, *, algorithm: CombiningAlg, name: Optional[str] = None):
        self._budget.ensure_time()
        pol = PolicyTrace(policy_id=policy_id, name=name, algorithm=algorithm)
        _get_recorder().push_policy(pol)
        with _OTEL_TRACER.start_as_current_span(f"pdp.policy:{name or policy_id}"):
            try:
                yield _PolicyScope(self._explainer, self._budget, pol)
            finally:
                # If user forgot to close policy, keep NOT_APPLICABLE, but do not crash.
                pass

    def finalize(
        self,
        *,
        effect: DecisionEffect,
        obligations: Sequence[Mapping[str, Any]] | None = None,
        advice: Sequence[Mapping[str, Any]] | None = None,
        missing_attributes: Sequence[str] | None = None,
        conflicts: Sequence[str] | None = None,
        rationale: Optional[str] = None,
    ) -> DecisionExplanation:
        self._budget.ensure_time()
        elapsed = self._budget.elapsed_ms

        policies = tuple(_get_recorder().policies)
        # Use LRU if cache key exists
        if self._cache_key:
            try:
                exp = self._explainer._cache(  # type: ignore[attr-defined]
                    self._cache_key,
                    self._request,
                    effect,
                    policies,
                    elapsed,
                    self._locale,
                    tuple(obligations or ()),
                    tuple(advice or ()),
                    tuple(missing_attributes or ()),
                    tuple(conflicts or ()),
                    rationale,
                )
                # Returned explanation already flagged as cache_hit=True
                return exp
            except TypeError:
                # Fallback: unhashable dicts in obligations/advice; bypass cache
                pass

        return self._explainer.finalize(
            request=self._request,
            effect=effect,
            policies=list(policies),
            evaluation_time_ms=elapsed,
            locale=self._locale,
            obligations=obligations,
            advice=advice,
            cache_key=self._cache_key,
            missing_attributes=missing_attributes,
            conflicts=conflicts,
            rationale=rationale,
            cache_hit=False,
        )


class _PolicyScope:
    def __init__(self, explainer: PolicyExplainer, budget: _TimeBudget, pol: PolicyTrace) -> None:
        self._explainer = explainer
        self._budget = budget
        self._pol = pol

    @contextlib.contextmanager
    def rule(
        self,
        rule_id: str,
        *,
        effect_if_matched: DecisionEffect,
        name: Optional[str] = None,
        obligations: Optional[Sequence[Mapping[str, Any]]] = None,
        advice: Optional[Sequence[Mapping[str, Any]]] = None,
    ):
        self._budget.ensure_time()
        rt = RuleTrace(
            rule_id=rule_id, name=name, effect_if_matched=effect_if_matched,
            obligations=list(obligations or []), advice=list(advice or [])
        )
        _get_recorder().push_rule(rt)
        with _OTEL_TRACER.start_as_current_span(f"pdp.rule:{name or rule_id}"):
            try:
                yield _RuleScope(self._budget, rt)
            finally:
                pass

    def evaluate(self) -> DecisionEffect:
        """Compute policy effect from its rules using selected combining algorithm."""
        alg = self._pol.algorithm
        rules = self._pol.rules
        self._budget.ensure_time()

        if alg is CombiningAlg.DENY_OVERRIDES:
            for r in rules:
                if r.matched and r.effect_if_matched == DecisionEffect.DENY:
                    self._pol.effect = DecisionEffect.DENY
                    self._pol.rationale = self._pol.rationale or "deny-overrides: matched deny"
                    return self._pol.effect
            for r in rules:
                if r.matched and r.effect_if_matched == DecisionEffect.PERMIT:
                    self._pol.effect = DecisionEffect.PERMIT
                    self._pol.rationale = self._pol.rationale or "deny-overrides: matched permit (no deny)"
                    return self._pol.effect
            self._pol.effect = DecisionEffect.NOT_APPLICABLE
            self._pol.rationale = self._pol.rationale or "deny-overrides: no matches"
            return self._pol.effect

        if alg is CombiningAlg.PERMIT_OVERRIDES:
            for r in rules:
                if r.matched and r.effect_if_matched == DecisionEffect.PERMIT:
                    self._pol.effect = DecisionEffect.PERMIT
                    self._pol.rationale = self._pol.rationale or "permit-overrides: matched permit"
                    return self._pol.effect
            for r in rules:
                if r.matched and r.effect_if_matched == DecisionEffect.DENY:
                    self._pol.effect = DecisionEffect.DENY
                    self._pol.rationale = self._pol.rationale or "permit-overrides: matched deny (no permit)"
                    return self._pol.effect
            self._pol.effect = DecisionEffect.NOT_APPLICABLE
            self._pol.rationale = self._pol.rationale or "permit-overrides: no matches"
            return self._pol.effect

        if alg is CombiningAlg.FIRST_APPLICABLE:
            for r in rules:
                if r.matched:
                    self._pol.effect = r.effect_if_matched
                    self._pol.rationale = self._pol.rationale or f"first-applicable: {r.name or r.rule_id}"
                    return self._pol.effect
            self._pol.effect = DecisionEffect.NOT_APPLICABLE
            self._pol.rationale = self._pol.rationale or "first-applicable: no matches"
            return self._pol.effect

        # Safety fallback
        self._pol.effect = DecisionEffect.INDETERMINATE
        self._pol.rationale = self._pol.rationale or f"unsupported algorithm: {alg.value}"
        return self._pol.effect

    def close(
        self,
        *,
        effect: DecisionEffect,
        rationale: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        _get_recorder().end_policy(effect=effect, rationale=rationale, error=error)


class _RuleScope:
    def __init__(self, budget: _TimeBudget, rule: RuleTrace) -> None:
        self._budget = budget
        self._rule = rule

    def check(
        self,
        expression: str,
        *,
        status: ConditionStatus,
        value: Optional[bool] = None,
        error: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self._budget.ensure_time()
        cond = ConditionResult(
            expression=expression, status=status, value=value, error=error, details=dict(details or {})
        )
        _get_recorder().add_condition(cond)

    def close(self, *, matched: bool, rationale: Optional[str] = None, error: Optional[str] = None) -> None:
        self._budget.ensure_time()
        _get_recorder().end_rule(matched=matched, rationale=rationale, error=error)


# ----------------------------- Convenience API --------------------------------

def explainable(decide: Callable[..., Tuple[DecisionEffect, Sequence[Mapping[str, Any]], Sequence[Mapping[str, Any]]]]):
    """
    Decorator: wrap a PDP 'decide' function to automatically produce DecisionExplanation.
    The wrapped function must accept 'explainer' kwarg and 'request' kwarg.
    It must return (effect, obligations, advice).
    """

    @functools.wraps(decide)
    def _wrapper(*args, **kwargs) -> Tuple[DecisionExplanation, DecisionEffect, Sequence[Mapping[str, Any]], Sequence[Mapping[str, Any]]]:
        explainer: PolicyExplainer = kwargs.get("explainer")
        request: Mapping[str, Any] = kwargs.get("request")
        if explainer is None or request is None:
            raise ExplainError("explainable: 'explainer' and 'request' kwargs are required")

        locale = kwargs.get("locale", "ru")
        time_budget_ms = kwargs.get("time_budget_ms", 2000)
        enable_cache = kwargs.get("enable_cache", True)

        with explainer.session(request=request, locale=locale, time_budget_ms=time_budget_ms, enable_cache=enable_cache) as sx:
            with _OTEL_TRACER.start_as_current_span("pdp.decide"):
                effect, obligations, advice = decide(*args, **kwargs)
            explanation = sx.finalize(effect=effect, obligations=obligations, advice=advice)
            return explanation, effect, obligations, advice

    return _wrapper


# ----------------------------- JSON Utilities ---------------------------------

def dumps_explanation(expl: DecisionExplanation, *, indent: Optional[int] = 2) -> str:
    """Stable JSON dump for logging or persistence."""
    return expl.to_json(indent=indent)


def loads_explanation(data: str) -> DecisionExplanation:
    """Load DecisionExplanation from JSON string."""
    raw = json.loads(data)
    return DecisionExplanation(
        request_id=raw["request_id"],
        effect=DecisionEffect(raw["effect"]),
        subject=raw["subject"],
        resource=raw["resource"],
        action=raw["action"],
        environment=raw.get("environment", {}),
        policies=[
            PolicyTrace(
                policy_id=p["policy_id"],
                name=p.get("name"),
                algorithm=CombiningAlg(p["algorithm"]),
                rules=[
                    RuleTrace(
                        rule_id=r["rule_id"],
                        name=r.get("name"),
                        effect_if_matched=DecisionEffect(r["effect_if_matched"]),
                        matched=r["matched"],
                        conditions=[
                            ConditionResult(
                                expression=c["expression"],
                                status=ConditionStatus(c["status"]),
                                value=c.get("value"),
                                error=c.get("error"),
                                details=c.get("details", {}),
                            )
                            for c in r.get("conditions", [])
                        ],
                        obligations=r.get("obligations", []),
                        advice=r.get("advice", []),
                        rationale=r.get("rationale"),
                        error=r.get("error"),
                    )
                    for r in p.get("rules", [])
                ],
                effect=DecisionEffect(p["effect"]),
                rationale=p.get("rationale"),
                error=p.get("error"),
            )
            for p in raw.get("policies", [])
        ],
        obligations=raw.get("obligations", []),
        advice=raw.get("advice", []),
        evaluation_time_ms=float(raw.get("evaluation_time_ms", 0.0)),
        cache_hit=bool(raw.get("cache_hit", False)),
        missing_attributes=list(raw.get("missing_attributes", [])),
        conflicts=list(raw.get("conflicts", [])),
        rationale=raw.get("rationale"),
    )


# ----------------------------- Minimal Self-Test (Optional) -------------------

if __name__ == "__main__":  # pragma: no cover
    # Simple smoke test to illustrate behavior without external PDP.
    request = {
        "subject": {"id": "u1", "role": "admin", "password": "super-secret"},
        "resource": {"id": "doc-42", "owner": "u1"},
        "action": {"op": "read"},
        "environment": {"ip": "10.0.0.1"},
    }

    explainer = PolicyExplainer()

    with explainer.session(request=request, locale="ru", time_budget_ms=1000) as sx:
        with sx.policy("pol-base", algorithm=CombiningAlg.DENY_OVERRIDES, name="BasePolicy") as px:
            with px.rule("r1", effect_if_matched=DecisionEffect.PERMIT, name="AllowAdmins") as rx:
                rx.check("subject.role == 'admin'", status=ConditionStatus.PASSED, value=True)
                rx.close(matched=True, rationale="Subject is admin")
            with px.rule("r2", effect_if_matched=DecisionEffect.DENY, name="DenyBanned") as rx:
                rx.check("subject.banned == True", status=ConditionStatus.SKIPPED, value=None)
                rx.close(matched=False, rationale="Attribute not present")
            px.close(effect=px.evaluate())

        exp = sx.finalize(effect=DecisionEffect.PERMIT, rationale="Policy permitted")
    print(exp.to_text("ru"))
    print(exp.to_json(indent=2))
