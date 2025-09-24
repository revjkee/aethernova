# mythos-core/mythos/adapters/policy_core_adapter.py
# Unified policy & feature flag adapter for Mythos. Safe expressions, file/HTTP providers, sticky rollout,
# caching, and explainability traces. No mandatory third-party deps.

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import logging
import os
import re
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# Optional YAML support
_YAML_AVAILABLE = False
try:
    import yaml  # type: ignore
    _YAML_AVAILABLE = True
except Exception:
    _YAML_AVAILABLE = False

# =========================
# Public enums & models
# =========================

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"
    TRANSFORM = "TRANSFORM"
    REDACT = "REDACT"
    QUARANTINE = "QUARANTINE"

@dataclass
class Rule:
    id: str
    priority: int = 100
    when: str = "true"                     # safe expression over ctx/sub
    actions: List[str] = field(default_factory=list)
    decision: Decision = Decision.ALLOW
    percentage: Optional[float] = None     # 0..100, apply after 'when'
    bucket_key: Optional[str] = None       # expression producing sticky key (e.g. sub.user_id)
    expires_at: Optional[float] = None     # unix ts; ignore if in past
    score: Optional[float] = None          # for best_score mode
    tags: List[str] = field(default_factory=list)
    note: Optional[str] = None

@dataclass
class Policy:
    id: str
    version: str = "v1"
    mode: str = "first_match"              # first_match | best_score
    default_decision: Decision = Decision.ALLOW
    default_actions: List[str] = field(default_factory=lambda: ["log_only"])
    rules: List[Rule] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RuleTrace:
    rule_id: str
    matched: bool
    reason: str
    probability_gate: Optional[float] = None
    bucket: Optional[int] = None

@dataclass
class DecisionResult:
    policy_id: str
    policy_version: str
    decision: Decision
    actions: List[str]
    matched_rule_id: Optional[str]
    traces: List[RuleTrace]
    context_hash: str
    latency_ms: int

# =========================
# Safe expression evaluation
# =========================

_ALLOWED_AST = {
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.IfExp,
    ast.Dict, ast.Set, ast.List, ast.Tuple,
    ast.Compare, ast.Name, ast.Load, ast.Constant,
    ast.Subscript, ast.Index, ast.Slice,
    ast.And, ast.Or, ast.Not,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq,
    ast.Call, ast.keyword, ast.Attribute,
}

_BUILTINS: Dict[str, Any] = {
    "len": len, "min": min, "max": max, "abs": abs, "int": int, "float": float, "str": str, "bool": bool,
    "round": round, "sum": sum, "any": any, "all": all,
}

_REGEX_CACHE: Dict[str, re.Pattern] = {}
def _regex(pattern: str) -> re.Pattern:
    pat = _REGEX_CACHE.get(pattern)
    if pat is None:
        pat = re.compile(pattern)
        _REGEX_CACHE[pattern] = pat
    return pat

def _now() -> float:
    return time.time()

def _hash32(s: str) -> int:
    # Deterministic 32-bit unsigned int (xxh/no external) using sha256
    return int(hashlib.sha256(s.encode("utf-8")).hexdigest()[:8], 16)

def _bucket(key: str, buckets: int = 100) -> int:
    if buckets <= 0:
        buckets = 100
    return _hash32(key) % buckets

def _pct_gate(key: str, percentage: float, seed: str = "") -> bool:
    pct = max(0.0, min(float(percentage), 100.0))
    if pct <= 0:
        return False
    if pct >= 100:
        return True
    b = _bucket(f"{seed}:{key}", buckets=10000)  # 0..9999
    return b < int(pct * 100)

def _assert_safe(node: ast.AST) -> None:
    for child in ast.walk(node):
        if type(child) not in _ALLOWED_AST:
            raise ValueError(f"Disallowed expression node: {type(child).__name__}")
        if isinstance(child, ast.Attribute):
            # Allow attribute access on ctx/sub only, forbid dunders
            if child.attr.startswith("__"):
                raise ValueError("Dunder attribute access is not allowed")
            base_ok = isinstance(child.value, ast.Name) and child.value.id in {"ctx", "sub"}
            if not base_ok:
                raise ValueError("Attribute access only allowed on 'ctx' or 'sub'")
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                if child.func.id not in _BUILTINS and child.func.id not in {"regex"}:
                    raise ValueError(f"Call to '{child.func.id}' is not allowed")
            elif isinstance(child.func, ast.Attribute):
                # Allow ctx.* and sub.* attribute reads only, not calls via attribute
                raise ValueError("Attribute calls are not allowed")

def _safe_eval(expr: str, env: Dict[str, Any]) -> Any:
    parsed = ast.parse(expr, mode="eval")
    _assert_safe(parsed)
    return eval(compile(parsed, "<policy>", "eval"), {"__builtins__": {}}, env)

# =========================
# Providers & cache
# =========================

class PolicyProvider:
    def get(self, policy_id: str) -> Policy:
        raise NotImplementedError

class InMemoryPolicyProvider(PolicyProvider):
    def __init__(self, policies: Dict[str, Policy]):
        self._policies = policies

    def get(self, policy_id: str) -> Policy:
        p = self._policies.get(policy_id)
        if not p:
            raise KeyError(f"Policy '{policy_id}' not found")
        return p

class FilePolicyProvider(PolicyProvider):
    """
    Load policy from YAML/JSON file with lazy reload on mtime change.
    """
    def __init__(self, path: str, policy_id: Optional[str] = None, ttl_seconds: float = 2.0):
        self.path = path
        self.policy_id = policy_id
        self.ttl = ttl_seconds
        self._lock = threading.RLock()
        self._cached: Optional[Policy] = None
        self._cached_at: float = 0.0
        self._mtime: float = 0.0

    def _load_raw(self) -> Dict[str, Any]:
        with open(self.path, "r", encoding="utf-8") as f:
            text = f.read()
        if self.path.endswith((".yaml", ".yml")) and _YAML_AVAILABLE:
            return yaml.safe_load(text)  # type: ignore
        return json.loads(text)

    def _compile(self, data: Dict[str, Any]) -> Policy:
        pid = self.policy_id or data.get("id") or "policy"
        mode = data.get("mode", "first_match")
        default_decision = Decision(data.get("defaultDecision", "ALLOW"))
        default_actions = list(data.get("defaultActions", []) or [])
        rules: List[Rule] = []
        for r in data.get("rules", []) or []:
            rules.append(
                Rule(
                    id=str(r.get("id") or f"r{len(rules)+1}"),
                    priority=int(r.get("priority", 100)),
                    when=str(r.get("when", "true")),
                    actions=list(r.get("actions", []) or []),
                    decision=Decision(r.get("decision", "ALLOW")),
                    percentage=float(r["percentage"]) if "percentage" in r and r["percentage"] is not None else None,
                    bucket_key=r.get("bucketKey"),
                    expires_at=float(r["expiresAt"]) if "expiresAt" in r and r["expiresAt"] is not None else None,
                    score=float(r["score"]) if "score" in r and r["score"] is not None else None,
                    tags=list(r.get("tags", []) or []),
                    note=r.get("note"),
                )
            )
        rules.sort(key=lambda x: (x.priority, x.id))
        return Policy(
            id=pid,
            version=str(data.get("version", "v1")),
            mode=str(mode),
            default_decision=default_decision,
            default_actions=default_actions,
            rules=rules,
            metadata=data.get("metadata", {}) or {},
        )

    def get(self, policy_id: str) -> Policy:
        # policy_id ignored if file contains single policy; kept for interface uniformity
        with self._lock:
            now = time.time()
            if self._cached and (now - self._cached_at) < self.ttl:
                return self._cached
            try:
                mtime = os.path.getmtime(self.path)
            except FileNotFoundError:
                raise KeyError(f"Policy file not found: {self.path}")
            if not self._cached or mtime != self._mtime:
                data = self._load_raw()
                self._cached = self._compile(data)
                self._mtime = mtime
                self._cached_at = now
            else:
                self._cached_at = now
            return self._cached

class HTTPPolicyProvider(PolicyProvider):
    """
    Load policy from HTTP(S) endpoint with ETag caching. Server should return JSON/YAML.
    """
    def __init__(self, url: str, ttl_seconds: float = 5.0, timeout: float = 2.0):
        self.url = url
        self.ttl = ttl_seconds
        self.timeout = timeout
        self._lock = threading.RLock()
        self._cached: Optional[Policy] = None
        self._cached_at: float = 0.0
        self._etag: Optional[str] = None

    def _parse(self, body: bytes, content_type: str) -> Dict[str, Any]:
        text = body.decode("utf-8", "replace")
        if "yaml" in content_type and _YAML_AVAILABLE:
            return yaml.safe_load(text)  # type: ignore
        return json.loads(text)

    def get(self, policy_id: str) -> Policy:
        with self._lock:
            now = time.time()
            if self._cached and (now - self._cached_at) < self.ttl:
                return self._cached
            req = urllib.request.Request(self.url, headers={"Accept": "application/json, text/yaml, application/yaml"})
            if self._etag:
                req.add_header("If-None-Match", self._etag)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 304 and self._cached:
                        self._cached_at = now
                        return self._cached
                    body = resp.read()
                    ctype = resp.headers.get_content_type()
                    data = self._parse(body, ctype or "application/json")
                    pol = FilePolicyProvider._compile(self, data)  # reuse compiler
                    self._cached = pol
                    self._cached_at = now
                    self._etag = resp.headers.get("ETag")
                    return pol
            except urllib.error.HTTPError as e:
                if e.code == 304 and self._cached:
                    self._cached_at = now
                    return self._cached
                raise
            except Exception as e:
                # On fetch error, return cached if exists
                if self._cached:
                    log.warning("policy_http_provider: using cached policy due to error: %s", e)
                    return self._cached
                raise

# =========================
# Adapter
# =========================

def _context_hash(subject: Dict[str, Any], ctx: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps({"sub": subject, "ctx": ctx}, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()

def _coalesce_actions(decision: Decision, rule_actions: List[str], default_actions: List[str]) -> List[str]:
    if rule_actions:
        return rule_actions
    # Reasonable defaults
    if decision == Decision.ALLOW:
        return ["none"]
    if decision == Decision.REVIEW:
        return ["require_human_review"]
    if decision == Decision.DENY:
        return ["drop"]
    if decision == Decision.REDACT:
        return ["mask"]
    if decision == Decision.TRANSFORM:
        return ["safe_completion"]
    if decision == Decision.QUARANTINE:
        return ["quarantine"]
    return default_actions or ["log_only"]

class PolicyCoreAdapter:
    """
    Core evaluator that unifies decisions for moderation gates, feature flags and access control.
    """

    def __init__(self, provider: PolicyProvider):
        self.provider = provider

    def decide(self, policy_id: str, subject: Dict[str, Any], context: Dict[str, Any]) -> DecisionResult:
        t0 = time.perf_counter()
        policy = self.provider.get(policy_id)
        env = {
            **_BUILTINS,
            "ctx": context,
            "sub": subject,
            "now": _now(),
            "bucket_of": _bucket,
            "percent_gate_of": _pct_gate,
            "regex": _regex,
        }

        traces: List[RuleTrace] = []
        chosen: Optional[Rule] = None

        if policy.mode == "best_score":
            best: Tuple[float, Rule] | None = None

        for r in policy.rules:
            # Expiration
            if r.expires_at is not None and _now() > r.expires_at:
                traces.append(RuleTrace(rule_id=r.id, matched=False, reason="expired"))
                continue
            # Condition
            try:
                cond = bool(_safe_eval(r.when or "true", env))
            except Exception as e:
                traces.append(RuleTrace(rule_id=r.id, matched=False, reason=f"expr_error:{e}"))
                continue
            if not cond:
                traces.append(RuleTrace(rule_id=r.id, matched=False, reason="when=false"))
                continue

            # Percentage / sticky bucketing
            matched = True
            prob_gate = None
            bucket_val = None
            if r.percentage is not None:
                key = ""
                if r.bucket_key:
                    try:
                        key_val = _safe_eval(r.bucket_key, env)
                        key = str(key_val)
                    except Exception:
                        key = ""
                else:
                    # try common keys
                    key = str(subject.get("user_id") or subject.get("id") or context.get("session_id") or "global")
                matched = _pct_gate(key, r.percentage, seed=r.id)
                prob_gate = r.percentage
                bucket_val = _bucket(f"{r.id}:{key}")
            if not matched:
                traces.append(RuleTrace(rule_id=r.id, matched=False, reason="percent_gate=false", probability_gate=prob_gate, bucket=bucket_val))
                continue

            # Matched path
            traces.append(RuleTrace(rule_id=r.id, matched=True, reason="match", probability_gate=prob_gate, bucket=bucket_val))
            if policy.mode == "first_match":
                chosen = r
                break
            else:  # best_score
                sc = r.score if r.score is not None else float(100 - r.priority)
                if best is None or sc > best[0]:
                    best = (sc, r)
        if policy.mode == "best_score" and "best" in locals() and best is not None:
            chosen = best[1]

        if chosen:
            actions = _coalesce_actions(chosen.decision, chosen.actions, policy.default_actions)
            latency = int((time.perf_counter() - t0) * 1000)
            return DecisionResult(
                policy_id=policy.id,
                policy_version=policy.version,
                decision=chosen.decision,
                actions=actions,
                matched_rule_id=chosen.id,
                traces=traces,
                context_hash=_context_hash(subject, context),
                latency_ms=latency,
            )

        # Fallback
        actions = _coalesce_actions(policy.default_decision, [], policy.default_actions)
        latency = int((time.perf_counter() - t0) * 1000)
        return DecisionResult(
            policy_id=policy.id,
            policy_version=policy.version,
            decision=policy.default_decision,
            actions=actions,
            matched_rule_id=None,
            traces=traces,
            context_hash=_context_hash(subject, context),
            latency_ms=latency,
        )

# =========================
# Helpers to build from dict/yaml/json for tests/tools
# =========================

def policy_from_dict(data: Dict[str, Any]) -> Policy:
    return FilePolicyProvider._compile(FilePolicyProvider("__dummy__"), data)

def policy_from_yaml(text: str) -> Policy:
    if not _YAML_AVAILABLE:
        raise RuntimeError("PyYAML is not installed")
    return FilePolicyProvider._compile(FilePolicyProvider("__dummy__.yaml"), yaml.safe_load(text))  # type: ignore

# =========================
# Example schema (for documentation)
# =========================
"""
YAML example:

id: "moderation-default"
version: "2025-08-27"
mode: "first_match"  # or best_score
defaultDecision: "ALLOW"
defaultActions: ["log_only"]
rules:
  - id: "pii_block"
    priority: 10
    when: "ctx.category == 'PRIVACY' and ctx.score >= 0.9"
    decision: "REDACT"
    actions: ["mask"]
    note: "Redact PII"
  - id: "rollout_canary"
    priority: 50
    when: "ctx.service == 'llm-chat' and ctx.env == 'prod'"
    percentage: 10              # 10% sticky rollout
    bucketKey: "sub.user_id"    # sticky key
    decision: "ALLOW"
    actions: ["none"]
  - id: "block_high_risk"
    priority: 90
    when: "ctx.overall_risk > 0.85"
    decision: "REVIEW"
    actions: ["require_human_review"]
"""

# =========================
# Optional: logging correlation IDs (if middleware is installed)
# =========================

try:
    from mythos.api.http.middleware.logging import get_request_id, get_trace_id  # type: ignore

    def _attach_correlation(extra: Dict[str, Any]) -> Dict[str, Any]:
        rid = get_request_id()
        tid = get_trace_id()
        if rid:
            extra["request_id"] = rid
        if tid:
            extra["trace_id"] = tid
        return extra

    # Thin wrapper for debug logs with correlation
    def log_decision(result: DecisionResult, extra: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "policy_id": result.policy_id,
            "policy_version": result.policy_version,
            "decision": result.decision.value,
            "matched_rule": result.matched_rule_id,
            "latency_ms": result.latency_ms,
        }
        if extra:
            payload.update(extra)
        log.info("policy_decision", extra={"extra": _attach_correlation(payload)})
except Exception:
    def log_decision(result: DecisionResult, extra: Optional[Dict[str, Any]] = None) -> None:
        log.info("policy_decision %s", {
            "policy_id": result.policy_id,
            "version": result.policy_version,
            "decision": result.decision.value,
            "rule": result.matched_rule_id,
            "latency_ms": result.latency_ms,
            **(extra or {}),
        })
