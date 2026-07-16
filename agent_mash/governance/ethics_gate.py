# agent_mash/governance/ethics_gate.py
from __future__ import annotations

import abc
import asyncio
import dataclasses
import enum
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

logger = logging.getLogger(__name__)


JsonDict = Dict[str, Any]
JsonLike = Union[JsonDict, List[Any], str, int, float, bool, None]


class EthicsGateError(RuntimeError):
    pass


class RuleMisconfigured(EthicsGateError):
    pass


class PayloadInvalid(EthicsGateError):
    pass


class AuditSinkError(EthicsGateError):
    pass


class Verdict(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclasses.dataclass(frozen=True)
class RuleHit:
    rule_id: str
    verdict: Verdict
    severity: Severity
    reason: str
    confidence: float = 1.0
    tags: Tuple[str, ...] = ()
    details: Mapping[str, JsonLike] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class EthicsDecision:
    verdict: Verdict
    trace_id: str
    policy_version: str
    created_at_ms: int
    hits: Tuple[RuleHit, ...] = ()
    summary: str = ""
    allow: bool = True
    escalate: bool = False
    block: bool = False

    def to_dict(self) -> JsonDict:
        return {
            "verdict": self.verdict.value,
            "trace_id": self.trace_id,
            "policy_version": self.policy_version,
            "created_at_ms": self.created_at_ms,
            "summary": self.summary,
            "allow": self.allow,
            "escalate": self.escalate,
            "block": self.block,
            "hits": [
                {
                    "rule_id": h.rule_id,
                    "verdict": h.verdict.value,
                    "severity": h.severity.value,
                    "reason": h.reason,
                    "confidence": float(h.confidence),
                    "tags": list(h.tags),
                    "details": dict(h.details),
                }
                for h in self.hits
            ],
        }


@dataclasses.dataclass(frozen=True)
class EthicsContext:
    action: str
    actor_id: str
    tenant_id: Optional[str]
    request_id: str
    trace_id: str
    created_at_ms: int
    payload: Mapping[str, JsonLike]
    metadata: Mapping[str, JsonLike]
    redacted_payload: Mapping[str, JsonLike]


class AuditSink(Protocol):
    async def emit(self, event: Mapping[str, JsonLike]) -> None:
        ...


class Clock(Protocol):
    def now_ms(self) -> int:
        ...


class SystemClock:
    def now_ms(self) -> int:
        return int(time.time() * 1000)


class BaseEthicsRule(abc.ABC):
    rule_id: str

    @abc.abstractmethod
    def evaluate(self, ctx: EthicsContext) -> Union[None, RuleHit, Awaitable[Optional[RuleHit]]]:
        raise NotImplementedError


def _stable_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError as e:
        raise PayloadInvalid(f"Payload is not JSON-serializable: {e}") from e


def _blake2b_hex(data: bytes, digest_size: int = 16) -> str:
    h_ = hashlib.blake2b(digest_size=digest_size)
    h_.update(data)
    return h_.hexdigest()


def _hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _as_mapping(value: Any, name: str) -> Mapping[str, JsonLike]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return value  # type: ignore[return-value]
    raise PayloadInvalid(f"{name} must be a mapping/dict")


_REDACT_DEFAULT_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"cookie", re.IGNORECASE),
    re.compile(r"session", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"seed", re.IGNORECASE),
    re.compile(r"mnemonic", re.IGNORECASE),
)


def redact_mapping(
    obj: Mapping[str, Any],
    *,
    redaction: str = "[REDACTED]",
    key_patterns: Sequence[re.Pattern[str]] = _REDACT_DEFAULT_PATTERNS,
    max_depth: int = 8,
    max_list: int = 64,
) -> Mapping[str, JsonLike]:
    def _should_redact_key(k: str) -> bool:
        for p in key_patterns:
            if p.search(k):
                return True
        return False

    def _walk(v: Any, depth: int) -> JsonLike:
        if depth <= 0:
            return "[TRUNCATED]"
        if isinstance(v, Mapping):
            out: Dict[str, JsonLike] = {}
            for kk, vv in v.items():
                kks = str(kk)
                if _should_redact_key(kks):
                    out[kks] = redaction
                else:
                    out[kks] = _walk(vv, depth - 1)
            return out
        if isinstance(v, (list, tuple)):
            out_list: List[JsonLike] = []
            for i, item in enumerate(v):
                if i >= max_list:
                    out_list.append("[TRUNCATED_LIST]")
                    break
                out_list.append(_walk(item, depth - 1))
            return out_list
        if isinstance(v, (str, int, float, bool)) or v is None:
            return v
        return str(v)

    return _walk(obj, max_depth)  # type: ignore[return-value]


@dataclasses.dataclass(frozen=True)
class PolicyConfig:
    policy_version: str
    hard_block_on: Tuple[Severity, ...] = (Severity.CRITICAL,)
    default_escalate_on: Tuple[Severity, ...] = (Severity.HIGH,)
    require_actor_id: bool = True
    require_action: bool = True
    max_rules: int = 256
    rule_timeout_ms: int = 250
    gate_timeout_ms: int = 1500
    trace_hmac_key: Optional[bytes] = None


@dataclasses.dataclass(frozen=True)
class GateInput:
    action: str
    actor_id: str
    tenant_id: Optional[str] = None
    request_id: Optional[str] = None
    payload: Optional[Mapping[str, JsonLike]] = None
    metadata: Optional[Mapping[str, JsonLike]] = None


class EthicsGate:
    def __init__(
        self,
        *,
        rules: Sequence[BaseEthicsRule],
        policy: PolicyConfig,
        audit_sink: Optional[AuditSink] = None,
        clock: Optional[Clock] = None,
    ) -> None:
        if not policy.policy_version or not isinstance(policy.policy_version, str):
            raise RuleMisconfigured("policy_version must be a non-empty string")
        if len(rules) > policy.max_rules:
            raise RuleMisconfigured("rules exceed max_rules")
        self._rules: Tuple[BaseEthicsRule, ...] = tuple(rules)
        self._policy = policy
        self._audit_sink = audit_sink
        self._clock: Clock = clock or SystemClock()

    @property
    def policy(self) -> PolicyConfig:
        return self._policy

    def _make_trace_id(self, *, created_at_ms: int, action: str, actor_id: str, tenant_id: Optional[str], payload: Mapping[str, Any]) -> str:
        base = {
            "ts": created_at_ms,
            "action": action,
            "actor": actor_id,
            "tenant": tenant_id,
            "payload": payload,
        }
        raw = _stable_json(base).encode("utf-8")
        if self._policy.trace_hmac_key:
            return _hmac_sha256_hex(self._policy.trace_hmac_key, raw)
        return _blake2b_hex(raw, digest_size=16)

    def _make_request_id(self, *, created_at_ms: int, action: str, actor_id: str, tenant_id: Optional[str], payload: Mapping[str, Any]) -> str:
        base = {
            "ts": created_at_ms,
            "action": action,
            "actor": actor_id,
            "tenant": tenant_id,
            "payload": payload,
        }
        raw = _stable_json(base).encode("utf-8")
        return _blake2b_hex(raw, digest_size=16)

    def _validate_input(self, inp: GateInput) -> Tuple[str, str]:
        if self._policy.require_action and not inp.action:
            raise PayloadInvalid("action is required")
        if self._policy.require_actor_id and not inp.actor_id:
            raise PayloadInvalid("actor_id is required")
        return inp.action, inp.actor_id

    async def evaluate(self, inp: GateInput) -> EthicsDecision:
        created_at_ms = self._clock.now_ms()
        action, actor_id = self._validate_input(inp)

        payload = _as_mapping(inp.payload, "payload")
        metadata = _as_mapping(inp.metadata, "metadata")

        redacted_payload = redact_mapping(payload)

        request_id = inp.request_id or self._make_request_id(
            created_at_ms=created_at_ms,
            action=action,
            actor_id=actor_id,
            tenant_id=inp.tenant_id,
            payload=redacted_payload,
        )
        trace_id = self._make_trace_id(
            created_at_ms=created_at_ms,
            action=action,
            actor_id=actor_id,
            tenant_id=inp.tenant_id,
            payload=redacted_payload,
        )

        ctx = EthicsContext(
            action=action,
            actor_id=actor_id,
            tenant_id=inp.tenant_id,
            request_id=request_id,
            trace_id=trace_id,
            created_at_ms=created_at_ms,
            payload=payload,
            metadata=metadata,
            redacted_payload=redacted_payload,
        )

        decision = await self._run_rules_with_budget(ctx)
        await self._audit(ctx, decision)
        return decision

    async def _run_rules_with_budget(self, ctx: EthicsContext) -> EthicsDecision:
        start = self._clock.now_ms()
        hits: List[RuleHit] = []

        async def _run_one(rule: BaseEthicsRule) -> Optional[RuleHit]:
            try:
                res = rule.evaluate(ctx)
                if asyncio.iscoroutine(res):
                    return await asyncio.wait_for(res, timeout=self._policy.rule_timeout_ms / 1000)
                return res  # type: ignore[return-value]
            except asyncio.TimeoutError:
                return RuleHit(
                    rule_id=getattr(rule, "rule_id", rule.__class__.__name__),
                    verdict=Verdict.ESCALATE,
                    severity=Severity.HIGH,
                    reason="rule timeout",
                    confidence=1.0,
                    tags=("timeout",),
                    details={"timeout_ms": self._policy.rule_timeout_ms},
                )
            except Exception as e:
                logger.exception("Ethics rule failed: %s", getattr(rule, "rule_id", rule.__class__.__name__))
                return RuleHit(
                    rule_id=getattr(rule, "rule_id", rule.__class__.__name__),
                    verdict=Verdict.ESCALATE,
                    severity=Severity.HIGH,
                    reason="rule error",
                    confidence=1.0,
                    tags=("rule_error",),
                    details={"error": str(e)},
                )

        tasks = [asyncio.create_task(_run_one(r)) for r in self._rules]

        try:
            done, pending = await asyncio.wait(
                tasks,
                timeout=self._policy.gate_timeout_ms / 1000,
                return_when=asyncio.ALL_COMPLETED,
            )
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()

        for t in tasks:
            if t.done() and not t.cancelled():
                try:
                    hit = t.result()
                    if hit is not None:
                        hits.append(hit)
                except Exception:
                    continue

        elapsed = self._clock.now_ms() - start
        if elapsed > self._policy.gate_timeout_ms:
            hits.append(
                RuleHit(
                    rule_id="gate_timeout",
                    verdict=Verdict.ESCALATE,
                    severity=Severity.HIGH,
                    reason="gate timeout",
                    confidence=1.0,
                    tags=("timeout",),
                    details={"elapsed_ms": int(elapsed), "budget_ms": int(self._policy.gate_timeout_ms)},
                )
            )

        verdict, summary = self._aggregate(hits)
        return EthicsDecision(
            verdict=verdict,
            trace_id=ctx.trace_id,
            policy_version=self._policy.policy_version,
            created_at_ms=ctx.created_at_ms,
            hits=tuple(hits),
            summary=summary,
            allow=(verdict == Verdict.ALLOW),
            escalate=(verdict == Verdict.ESCALATE),
            block=(verdict == Verdict.BLOCK),
        )

    def _aggregate(self, hits: Sequence[RuleHit]) -> Tuple[Verdict, str]:
        if not hits:
            return Verdict.ALLOW, "no hits"

        def sev_rank(s: Severity) -> int:
            order = {
                Severity.INFO: 0,
                Severity.LOW: 1,
                Severity.MEDIUM: 2,
                Severity.HIGH: 3,
                Severity.CRITICAL: 4,
            }
            return order.get(s, 0)

        block_hits = [h for h in hits if h.verdict == Verdict.BLOCK or h.severity in self._policy.hard_block_on]
        if block_hits:
            top = sorted(block_hits, key=lambda x: (sev_rank(x.severity), x.confidence), reverse=True)[0]
            return Verdict.BLOCK, f"blocked by {top.rule_id}: {top.reason}"

        escalate_hits = [h for h in hits if h.verdict == Verdict.ESCALATE or h.severity in self._policy.default_escalate_on]
        if escalate_hits:
            top = sorted(escalate_hits, key=lambda x: (sev_rank(x.severity), x.confidence), reverse=True)[0]
            return Verdict.ESCALATE, f"escalated by {top.rule_id}: {top.reason}"

        top = sorted(hits, key=lambda x: (sev_rank(x.severity), x.confidence), reverse=True)[0]
        return Verdict.ALLOW, f"allowed with observations from {top.rule_id}"

    async def _audit(self, ctx: EthicsContext, decision: EthicsDecision) -> None:
        if self._audit_sink is None:
            return

        event: JsonDict = {
            "kind": "ethics_decision",
            "trace_id": ctx.trace_id,
            "request_id": ctx.request_id,
            "policy_version": decision.policy_version,
            "created_at_ms": decision.created_at_ms,
            "action": ctx.action,
            "actor_id": ctx.actor_id,
            "tenant_id": ctx.tenant_id,
            "verdict": decision.verdict.value,
            "summary": decision.summary,
            "payload": dict(ctx.redacted_payload),
            "metadata": dict(ctx.metadata),
            "hits": [h.__dict__ for h in decision.hits],
        }

        try:
            await self._audit_sink.emit(event)
        except Exception as e:
            raise AuditSinkError(str(e)) from e


class RegexBlockRule(BaseEthicsRule):
    def __init__(
        self,
        *,
        rule_id: str,
        patterns: Sequence[str],
        field: str = "text",
        verdict: Verdict = Verdict.BLOCK,
        severity: Severity = Severity.HIGH,
        reason: str = "matched blocked pattern",
        tags: Sequence[str] = ("regex_block",),
        flags: int = re.IGNORECASE,
        max_len: int = 200_000,
    ) -> None:
        if not rule_id:
            raise RuleMisconfigured("rule_id is required")
        if not patterns:
            raise RuleMisconfigured("patterns must be non-empty")
        self.rule_id = rule_id
        self._compiled: Tuple[re.Pattern[str], ...] = tuple(re.compile(p, flags) for p in patterns)
        self._field = field
        self._verdict = verdict
        self._severity = severity
        self._reason = reason
        self._tags = tuple(tags)
        self._max_len = int(max_len)

    def evaluate(self, ctx: EthicsContext) -> Optional[RuleHit]:
        value = ctx.payload.get(self._field)
        if not isinstance(value, str):
            return None
        if len(value) > self._max_len:
            return RuleHit(
                rule_id=self.rule_id,
                verdict=Verdict.ESCALATE,
                severity=Severity.MEDIUM,
                reason="field too large",
                confidence=1.0,
                tags=("size_limit",),
                details={"field": self._field, "len": len(value), "max_len": self._max_len},
            )
        for pat in self._compiled:
            if pat.search(value):
                return RuleHit(
                    rule_id=self.rule_id,
                    verdict=self._verdict,
                    severity=self._severity,
                    reason=self._reason,
                    confidence=1.0,
                    tags=self._tags,
                    details={"field": self._field, "pattern": pat.pattern},
                )
        return None


class RequireKeysRule(BaseEthicsRule):
    def __init__(
        self,
        *,
        rule_id: str,
        required_keys: Sequence[str],
        verdict: Verdict = Verdict.ESCALATE,
        severity: Severity = Severity.MEDIUM,
        reason: str = "missing required keys",
        tags: Sequence[str] = ("schema",),
    ) -> None:
        if not rule_id:
            raise RuleMisconfigured("rule_id is required")
        if not required_keys:
            raise RuleMisconfigured("required_keys must be non-empty")
        self.rule_id = rule_id
        self._required = tuple(required_keys)
        self._verdict = verdict
        self._severity = severity
        self._reason = reason
        self._tags = tuple(tags)

    def evaluate(self, ctx: EthicsContext) -> Optional[RuleHit]:
        missing = [k for k in self._required if k not in ctx.payload]
        if not missing:
            return None
        return RuleHit(
            rule_id=self.rule_id,
            verdict=self._verdict,
            severity=self._severity,
            reason=self._reason,
            confidence=1.0,
            tags=self._tags,
            details={"missing": missing},
        )
