# security-core/security/self_inhibitor/rules.py
# Copyright (c) Aethernova.
# SPDX-License-Identifier: Apache-2.0
#
# Industrial-grade self-inhibitor rules engine for security-core.
# Features:
#   - Declarative rules, rich predicates (regex, CIDR, time windows, rate limit)
#   - Effects: ALLOW, DENY, INHIBIT, CHALLENGE, LOG_ONLY with precedence
#   - Policy-level risk thresholds and pluggable risk scorer
#   - Async evaluation, deterministic merging, structured reasons
#   - In-memory rate counters, thread/async safety
#   - Safe redaction for logs and audit trails (no secret leakage)
#
# No external dependencies. Python 3.10+.

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Tuple

logger = logging.getLogger("security_core.self_inhibitor")

# ---------------------------------------------------------------------------
# Core types
# ---------------------------------------------------------------------------

Effect = Literal["ALLOW", "DENY", "INHIBIT", "CHALLENGE", "LOG_ONLY"]

EFFECT_PRECEDENCE: Dict[Effect, int] = {
    "DENY": 100,
    "INHIBIT": 90,
    "CHALLENGE": 80,
    "ALLOW": 10,
    "LOG_ONLY": 0,
}

@dataclass(slots=True)
class EvaluationContext:
    subject: Dict[str, Any]                  # e.g., {"id": "...", "roles": [...], "mfa": True}
    action: str                              # e.g., "secrets.access" or "auth.login"
    resource: Dict[str, Any]                 # resource attributes
    environment: Dict[str, Any]              # e.g., {"ip": "1.2.3.4", "user_agent": "...", "geo": "SE"}
    attributes: Dict[str, Any] = field(default_factory=dict)  # arbitrary extra
    now_s: Optional[int] = None

    def now(self) -> int:
        return self.now_s if self.now_s is not None else int(time.time())

@dataclass(slots=True)
class Decision:
    allow: bool
    inhibited: bool
    challenge_required: bool
    effect: Effect
    risk_score: float
    reasons: List[str] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

# ---------------------------------------------------------------------------
# Predicate protocol and implementations
# ---------------------------------------------------------------------------

class Predicate(Protocol):
    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        """
        Returns tuple: (matched, reason).
        reason must be safe to log (no secret leakage).
        """

# Helpers

def _get_path(d: Dict[str, Any], path: str) -> Any:
    """
    Dot-path getter: "environment.ip" -> d["environment"]["ip"]
    Returns None if path missing.
    """
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

def _safe_repr(v: Any, max_len: int = 128) -> str:
    try:
        s = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
    except Exception:
        s = str(v)
    s = s if len(s) <= max_len else s[:max_len] + "..."
    # Redact obvious tokens
    redaction_keys = ("token", "secret", "password", "authorization")
    for rk in redaction_keys:
        s = re.sub(rf'"{rk}"\s*:\s*".+?"', f'"{rk}":"<redacted>"', s, flags=re.IGNORECASE)
    return s

# Attribute equality/containment

@dataclass(slots=True)
class AttributePredicate:
    path: str
    op: Literal["eq", "neq", "in", "nin", "contains", "ncontains"]
    value: Any

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        v = _get_path(ctx.__dict__, self.path)
        if self.op == "eq":
            ok = v == self.value
        elif self.op == "neq":
            ok = v != self.value
        elif self.op == "in":
            ok = v in self.value if isinstance(self.value, (list, tuple, set)) else False
        elif self.op == "nin":
            ok = v not in self.value if isinstance(self.value, (list, tuple, set)) else True
        elif self.op == "contains":
            ok = (isinstance(v, (list, tuple, set)) and self.value in v) or (isinstance(v, str) and str(self.value) in v)
        elif self.op == "ncontains":
            ok = not ((isinstance(v, (list, tuple, set)) and self.value in v) or (isinstance(v, str) and str(self.value) in v))
        else:
            ok = False
        return ok, f"{self.path} {self.op} { _safe_repr(self.value) }"

# Regex match

@dataclass(slots=True)
class RegexPredicate:
    path: str
    pattern: str
    flags: int = re.IGNORECASE

    def __post_init__(self):
        self._rx = re.compile(self.pattern, self.flags)

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        v = _get_path(ctx.__dict__, self.path)
        s = str(v) if v is not None else ""
        ok = self._rx.search(s) is not None
        return ok, f"regex({self.path}, /{self.pattern}/)"

# Glob match

@dataclass(slots=True)
class GlobPredicate:
    path: str
    pattern: str

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        v = _get_path(ctx.__dict__, self.path)
        s = str(v) if v is not None else ""
        ok = fnmatch.fnmatch(s, self.pattern)
        return ok, f"glob({self.path}, {self.pattern})"

# CIDR match

@dataclass(slots=True)
class CIDRPredicate:
    path: str
    cidrs: List[str]

    def __post_init__(self):
        self._nets = [ipaddress.ip_network(c) for c in self.cidrs]

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        v = _get_path(ctx.__dict__, self.path)
        try:
            ip = ipaddress.ip_address(str(v))
            ok = any(ip in n for n in self._nets)
        except Exception:
            ok = False
        return ok, f"cidr({self.path} in {self.cidrs})"

# Numeric compare

@dataclass(slots=True)
class NumberPredicate:
    path: str
    op: Literal["gt", "gte", "lt", "lte"]
    value: float

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        v = _get_path(ctx.__dict__, self.path)
        try:
            f = float(v)
            if self.op == "gt":
                ok = f > self.value
            elif self.op == "gte":
                ok = f >= self.value
            elif self.op == "lt":
                ok = f < self.value
            else:
                ok = f <= self.value
        except Exception:
            ok = False
        return ok, f"{self.path} {self.op} {self.value}"

# Time windows (UTC, day-of-week 0-6 Monday..Sunday)

@dataclass(slots=True)
class TimeWindowPredicate:
    windows: List[Tuple[int, int, int, int]]  # [(dow_start, dow_end, start_min, end_min)]
    negate: bool = False

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        now = ctx.now()
        import datetime as dt
        t = dt.datetime.utcfromtimestamp(now)
        dow = (t.weekday())  # 0..6
        minutes = t.hour * 60 + t.minute
        match = False
        for ds, de, ms, me in self.windows:
            in_day = ds <= dow <= de if ds <= de else (dow >= ds or dow <= de)
            in_min = ms <= minutes <= me
            if in_day and in_min:
                match = True
                break
        ok = not match if self.negate else match
        return ok, f"time_window({'NOT ' if self.negate else ''}match)"

# Rate limit predicate (sliding token bucket)

class RateCounter(Protocol):
    async def allow(self, key: str, capacity: int, refill_per_sec: float, cost: float = 1.0) -> bool:
        ...

class MemoryRateCounter:
    def __init__(self) -> None:
        self._state: Dict[str, Tuple[float, float, float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str, capacity: int, refill_per_sec: float, cost: float = 1.0) -> bool:
        now = time.monotonic()
        async with self._lock:
            tokens, last, cap = self._state.get(key, (float(capacity), now, float(capacity)))
            tokens = min(capacity, tokens + (now - last) * refill_per_sec)
            ok = tokens >= cost
            tokens = tokens - cost if ok else tokens
            self._state[key] = (tokens, now, float(capacity))
            return ok

@dataclass(slots=True)
class RateLimitPredicate:
    key_template: str               # e.g., "act:{action}:sub:{subject.id}:ip:{environment.ip}"
    capacity: int
    refill_per_sec: float
    cost: float = 1.0
    counter: RateCounter = field(default_factory=MemoryRateCounter)

    def _render_key(self, ctx: EvaluationContext) -> str:
        # Very small templating: {path} replaced by ctx path value
        def repl(m: re.Match) -> str:
            p = m.group(1)
            v = _get_path(ctx.__dict__, p)
            return str(v) if v is not None else ""
        return re.sub(r"\{([a-zA-Z0-9_.]+)\}", repl, self.key_template)

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        key = self._render_key(ctx)
        ok = await self.counter.allow(key, self.capacity, self.refill_per_sec, self.cost)
        return ok, f"rate_limit({key} <= {self.capacity}@{self.refill_per_sec}/s)"

# Logical composition

@dataclass(slots=True)
class AnyPredicate:
    items: List[Predicate]

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        reasons = []
        for p in self.items:
            ok, rsn = await p.evaluate(ctx)
            reasons.append(rsn)
            if ok:
                return True, f"any({'; '.join(r for r in reasons if r)})"
        return False, f"any(no match)"

@dataclass(slots=True)
class AllPredicate:
    items: List[Predicate]

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        reasons = []
        for p in self.items:
            ok, rsn = await p.evaluate(ctx)
            reasons.append(rsn)
            if not ok:
                return False, f"all(failed: {rsn})"
        return True, f"all({'; '.join(r for r in reasons if r)})"

@dataclass(slots=True)
class NotPredicate:
    item: Predicate

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        ok, rsn = await self.item.evaluate(ctx)
        return (not ok), f"not({rsn})"

# Kill switch

@dataclass(slots=True)
class KillSwitchPredicate:
    enabled: bool = True
    exceptions: List[Predicate] = field(default_factory=list)  # if any exception matches, kill switch does not fire

    async def evaluate(self, ctx: EvaluationContext) -> Tuple[bool, Optional[str]]:
        if not self.enabled:
            return False, "killswitch(off)"
        for p in self.exceptions:
            ok, _ = await p.evaluate(ctx)
            if ok:
                return False, "killswitch(exception)"
        return True, "killswitch(on)"

# ---------------------------------------------------------------------------
# Rule and Policy
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Rule:
    id: str
    version: str = "1"
    description: str = ""
    priority: int = 0
    effect: Effect = "LOG_ONLY"
    enabled: bool = True
    risk_delta: float = 0.0
    predicate: Predicate = field(default_factory=lambda: AttributePredicate("action", "eq", "__none__"))
    tags: List[str] = field(default_factory=list)

@dataclass(slots=True)
class Policy:
    id: str
    version: str = "1"
    rules: List[Rule] = field(default_factory=list)
    max_risk_allowed: float = 70.0
    challenge_threshold: float = 50.0

# ---------------------------------------------------------------------------
# Risk scorer interface
# ---------------------------------------------------------------------------

class RiskScorer(Protocol):
    async def score(self, ctx: EvaluationContext) -> float:
        ...

class ZeroRiskScorer:
    async def score(self, ctx: EvaluationContext) -> float:
        return 0.0

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Engine:
    policy: Policy
    risk_scorer: RiskScorer = field(default_factory=ZeroRiskScorer)

    async def evaluate(self, ctx: EvaluationContext) -> Decision:
        """Evaluate policy against context, compute final decision."""
        # Calculate baseline risk
        base_risk = await self.risk_scorer.score(ctx)

        # Sort rules by priority desc, then id
        rules = [r for r in self.policy.rules if r.enabled]
        rules.sort(key=lambda r: (-r.priority, r.id))

        cumulative_risk = base_risk
        matched: List[str] = []
        reasons: List[str] = []
        winning_effect: Effect = "ALLOW"  # default allow unless inhibited/denied by rules or risk
        effect_prec = -1
        challenge_required = False
        inhibited = False

        for r in rules:
            ok, rsn = await r.predicate.evaluate(ctx)
            if not ok:
                continue
            matched.append(r.id)
            if rsn:
                reasons.append(f"{r.id}:{rsn}")
            cumulative_risk = max(0.0, cumulative_risk + r.risk_delta)

            # Determine effect with precedence
            p = EFFECT_PRECEDENCE.get(r.effect, 0)
            if p > effect_prec:
                winning_effect = r.effect
                effect_prec = p

            # Side flags
            if r.effect == "CHALLENGE":
                challenge_required = True
            if r.effect == "INHIBIT":
                inhibited = True
            if r.effect == "DENY":
                inhibited = True  # deny implies inhibit

        # Risk-based gating
        if cumulative_risk >= self.policy.max_risk_allowed:
            winning_effect = "INHIBIT" if effect_prec < EFFECT_PRECEDENCE["INHIBIT"] else winning_effect
            inhibited = True
            reasons.append(f"risk>=max({cumulative_risk:.1f}>={self.policy.max_risk_allowed:.1f})")
        elif cumulative_risk >= self.policy.challenge_threshold:
            # If not already denied/inhibited, require challenge
            if effect_prec < EFFECT_PRECEDENCE["CHALLENGE"]:
                winning_effect = "CHALLENGE"
            challenge_required = True
            reasons.append(f"risk>=challenge({cumulative_risk:.1f}>={self.policy.challenge_threshold:.1f})")

        # Final allow
        allow = (not inhibited) and (winning_effect in ("ALLOW", "LOG_ONLY", "CHALLENGE"))

        # Normalize effect if allow and no special effect
        if allow and winning_effect == "LOG_ONLY":
            winning_effect = "ALLOW"

        return Decision(
            allow=allow,
            inhibited=inhibited and not allow,
            challenge_required=challenge_required,
            effect=winning_effect,
            risk_score=cumulative_risk,
            reasons=reasons,
            matched_rules=matched,
        )

    # Synchronous helper
    def evaluate_sync(self, ctx: EvaluationContext) -> Decision:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            # Caller is responsible to await evaluate() in async context
            raise RuntimeError("evaluate_sync called inside running event loop")
        return asyncio.run(self.evaluate(ctx))

# ---------------------------------------------------------------------------
# Builders and loaders
# ---------------------------------------------------------------------------

def build_predicate(spec: Dict[str, Any]) -> Predicate:
    """Build predicate from dict spec. Minimal schema with type and fields."""
    t = spec.get("type")
    if t == "attribute":
        return AttributePredicate(path=spec["path"], op=spec["op"], value=spec.get("value"))
    if t == "regex":
        return RegexPredicate(path=spec["path"], pattern=spec["pattern"], flags=re.IGNORECASE if spec.get("ignore_case", True) else 0)
    if t == "glob":
        return GlobPredicate(path=spec["path"], pattern=spec["pattern"])
    if t == "cidr":
        return CIDRPredicate(path=spec["path"], cidrs=list(spec["cidrs"]))
    if t == "number":
        return NumberPredicate(path=spec["path"], op=spec["op"], value=float(spec["value"]))
    if t == "time_window":
        return TimeWindowPredicate(windows=[tuple(w) for w in spec["windows"]], negate=bool(spec.get("negate", False)))
    if t == "rate_limit":
        return RateLimitPredicate(
            key_template=spec["key_template"],
            capacity=int(spec["capacity"]),
            refill_per_sec=float(spec["refill_per_sec"]),
            cost=float(spec.get("cost", 1.0)),
        )
    if t == "any":
        return AnyPredicate(items=[build_predicate(s) for s in spec["items"]])
    if t == "all":
        return AllPredicate(items=[build_predicate(s) for s in spec["items"]])
    if t == "not":
        return NotPredicate(item=build_predicate(spec["item"]))
    if t == "killswitch":
        return KillSwitchPredicate(
            enabled=bool(spec.get("enabled", True)),
            exceptions=[build_predicate(s) for s in spec.get("exceptions", [])],
        )
    raise ValueError(f"Unknown predicate type: {t}")

def build_rule(spec: Dict[str, Any]) -> Rule:
    pred = build_predicate(spec["predicate"])
    return Rule(
        id=spec["id"],
        version=str(spec.get("version", "1")),
        description=spec.get("description", ""),
        priority=int(spec.get("priority", 0)),
        effect=spec.get("effect", "LOG_ONLY"),
        enabled=bool(spec.get("enabled", True)),
        risk_delta=float(spec.get("risk_delta", 0.0)),
        predicate=pred,
        tags=list(spec.get("tags", [])),
    )

def load_policy(doc: Dict[str, Any]) -> Policy:
    return Policy(
        id=doc["id"],
        version=str(doc.get("version", "1")),
        rules=[build_rule(r) for r in doc.get("rules", [])],
        max_risk_allowed=float(doc.get("max_risk_allowed", 70.0)),
        challenge_threshold=float(doc.get("challenge_threshold", 50.0)),
    )

# ---------------------------------------------------------------------------
# Example default policy (commented)
# ---------------------------------------------------------------------------
# DEFAULT_POLICY = load_policy({
#   "id": "security-core-default",
#   "rules": [
#     {
#       "id": "killswitch-global",
#       "priority": 1000,
#       "effect": "INHIBIT",
#       "enabled": False,
#       "predicate": { "type": "killswitch", "enabled": False, "exceptions": [] }
#     },
#     {
#       "id": "block-high-risk-countries",
#       "priority": 900,
#       "effect": "INHIBIT",
#       "risk_delta": 30.0,
#       "predicate": {
#         "type": "attribute",
#         "path": "environment.geo",
#         "op": "in",
#         "value": ["RU","KP","IR"]
#       }
#     },
#     {
#       "id": "challenge-new-device",
#       "priority": 500,
#       "effect": "CHALLENGE",
#       "risk_delta": 10.0,
#       "predicate": {
#         "type": "regex",
#         "path": "attributes.device_trust",
#         "pattern": "^(unknown|low)$"
#       }
#     },
#     {
#       "id": "rate-limit-secrets-access",
#       "priority": 400,
#       "effect": "INHIBIT",
#       "predicate": {
#         "type": "rate_limit",
#         "key_template": "act:{action}:sub:{subject.id}:ip:{environment.ip}",
#         "capacity": 30,
#         "refill_per_sec": 0.5
#       }
#     },
#     {
#       "id": "business-hours-only-for-admin-ops",
#       "priority": 300,
#       "effect": "INHIBIT",
#       "predicate": {
#         "type": "all",
#         "items": [
#           { "type": "glob", "path": "action", "pattern": "admin.*" },
#           { "type": "time_window", "windows": [[0,4,8*60,18*60]] }  # Mon-Fri 08:00-18:00 UTC only
#         ]
#       }
#     }
#   ],
#   "max_risk_allowed": 80.0,
#   "challenge_threshold": 50.0
# })

# ---------------------------------------------------------------------------
# Public API convenience
# ---------------------------------------------------------------------------

__all__ = [
    "Effect",
    "EvaluationContext",
    "Decision",
    "Predicate",
    "AttributePredicate",
    "RegexPredicate",
    "GlobPredicate",
    "CIDRPredicate",
    "NumberPredicate",
    "TimeWindowPredicate",
    "RateLimitPredicate",
    "AnyPredicate",
    "AllPredicate",
    "NotPredicate",
    "KillSwitchPredicate",
    "RateCounter",
    "MemoryRateCounter",
    "Rule",
    "Policy",
    "RiskScorer",
    "ZeroRiskScorer",
    "Engine",
    "build_predicate",
    "build_rule",
    "load_policy",
]
