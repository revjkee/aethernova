# adapters/policy_adapter.py
# -*- coding: utf-8 -*-
"""
DataFabric-Core | Policy Adapter (PDP + PIP + Sources)

Features:
- Sources: File(YAML/JSON), HTTP(ETag/If-None-Match), InMemory
- Store: versioned cache with TTL, background refresh, thread/async-safe
- Engine: ABAC/RBAC hybrid, safe expression evaluator (no eval), regex/list ops
- PDP: decide(subject, action, resource, context) -> Decision(effect, reasons, obligations)
- PIP: attribute providers (sync/async) with memoization per decision
- Observability: optional metrics via datafabric.observability.metrics, structured logging
- Schema: optional validation via jsonschema (if installed)
- CLI: validate & dry-run decisions from stdin or file

No hard external deps. Optional: PyYAML, httpx, jsonschema.

© DataFabric-Core
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Tuple, Union

# Optional deps
try:
    import yaml  # type: ignore
except Exception:
    yaml = None

try:
    import httpx  # type: ignore
except Exception:
    httpx = None

try:
    import jsonschema  # type: ignore
except Exception:
    jsonschema = None

# Observability (optional)
try:
    from datafabric.observability.metrics import get_metrics
    _METRICS = get_metrics()
    M_DECISIONS = _METRICS.counter("policy_decisions_total", "Total policy decisions", labels=("effect", "policy_id"))
    M_LATENCY = _METRICS.histogram("policy_decision_latency_seconds", "Decision latency", labels=("policy_id",))
    M_REFRESH = _METRICS.counter("policy_refresh_total", "Policy refresh events", labels=("source", "status"))
except Exception:
    class _N:
        def inc(self, *a, **k): ...
        def observe(self, *a, **k): ...
    M_DECISIONS = _N()
    M_LATENCY = _N()
    M_REFRESH = _N()

LOG = logging.getLogger("datafabric.policy")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s policy:%(message)s"))
    LOG.addHandler(h)
    LOG.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

Effect = Literal["allow", "deny", "not_applicable"]
ConditionExpr = Dict[str, Any]  # safe JSON-like DSL

@dataclass
class Obligation:
    key: str
    value: Any

@dataclass
class Rule:
    id: str
    effect: Effect  # "allow" | "deny"
    actions: List[str] = field(default_factory=list)           # e.g. ["read","write","*"]
    resources: List[str] = field(default_factory=list)         # simple glob, e.g. "table:orders:*"
    subjects: List[str] = field(default_factory=list)          # RBAC principals or roles
    condition: Optional[ConditionExpr] = None                  # ABAC predicate
    obligations: List[Obligation] = field(default_factory=list)
    priority: int = 100                                        # lower number = higher priority
    description: str = ""

@dataclass
class Policy:
    id: str
    version: str
    rules: List[Rule] = field(default_factory=list)
    updated_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    etag: Optional[str] = None
    ttl_seconds: int = 300
    schema_version: str = "1.0"

@dataclass
class Decision:
    effect: Effect
    policy_id: Optional[str]
    policy_version: Optional[str]
    matched_rule: Optional[str]
    reasons: List[str] = field(default_factory=list)
    obligations: Dict[str, Any] = field(default_factory=dict)
    latency_ms: Optional[float] = None

# ---------------------------------------------------------------------------
# Utilities: glob-like match for resources/actions, role/subject expansion
# ---------------------------------------------------------------------------

def _glob_match(pattern: str, value: str) -> bool:
    # simple '*' wildcard match without importing fnmatch for speed/predictability
    if pattern == "*" or pattern == "**":
        return True
    # escape regex special, then replace '*' with '.*'
    rx = "^" + re.escape(pattern).replace("\\*", ".*") + "$"
    return re.match(rx, value) is not None

def _any_match(patterns: List[str], value: str) -> bool:
    return any(_glob_match(p, value) for p in (patterns or ["*"]))

# ---------------------------------------------------------------------------
# Safe condition evaluator (no eval)
# Supported ops: eq, ne, gt, gte, lt, lte, in, nin, regex, startswith, endswith, contains, all, any, not
# Example:
# {"all":[
#   {"eq":["${subject.department}","finance"]},
#   {"in":["${action}",["read","export"]]},
#   {"regex":["${resource}", "^table:orders:.*$"]},
#   {"gt":["${context.amount}", 100]}
# ]}
# Vars use ${path.to.value} with roots subject/action/resource/context
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"^\$\{([a-zA-Z0-9_.]+)\}$")

def _resolve_var(token: Any, ctx: Dict[str, Any]) -> Any:
    if isinstance(token, str):
        m = _PLACEHOLDER_RE.match(token)
        if m:
            path = m.group(1).split(".")
            cur: Any = ctx
            for p in path:
                if isinstance(cur, dict) and p in cur:
                    cur = cur[p]
                else:
                    return None
            return cur
    return token

def _op_eq(a, b): return a == b
def _op_ne(a, b): return a != b
def _op_gt(a, b): 
    try: return float(a) > float(b)
    except Exception: return False
def _op_gte(a, b):
    try: return float(a) >= float(b)
    except Exception: return False
def _op_lt(a, b):
    try: return float(a) < float(b)
    except Exception: return False
def _op_lte(a, b):
    try: return float(a) <= float(b)
    except Exception: return False
def _op_in(a, b): 
    try: return a in b
    except Exception: return False
def _op_nin(a, b):
    try: return a not in b
    except Exception: return False
def _op_regex(a, pattern):
    try: return re.match(pattern, str(a or "")) is not None
    except Exception: return False
def _op_startswith(a, b): 
    try: return str(a).startswith(str(b))
    except Exception: return False
def _op_endswith(a, b): 
    try: return str(a).endswith(str(b))
    except Exception: return False
def _op_contains(a, b):
    try: return str(b) in str(a)
    except Exception: return False

_BIN_OPS: Dict[str, Callable[[Any, Any], bool]] = {
    "eq": _op_eq, "ne": _op_ne,
    "gt": _op_gt, "gte": _op_gte, "lt": _op_lt, "lte": _op_lte,
    "in": _op_in, "nin": _op_nin,
    "regex": _op_regex, "startswith": _op_startswith, "endswith": _op_endswith, "contains": _op_contains,
}

def _eval_expr(expr: ConditionExpr, ctx: Dict[str, Any], reasons: List[str]) -> bool:
    if not expr:
        return True
    if "all" in expr:
        arr = expr["all"] or []
        for sub in arr:
            if not _eval_expr(sub, ctx, reasons):
                reasons.append("all:false")
                return False
        reasons.append("all:true")
        return True
    if "any" in expr:
        arr = expr["any"] or []
        for sub in arr:
            if _eval_expr(sub, ctx, reasons):
                reasons.append("any:true")
                return True
        reasons.append("any:false")
        return False
    if "not" in expr:
        res = not _eval_expr(expr["not"], ctx, reasons)
        reasons.append(f"not:{res}")
        return res
    # binary op: {"eq":[lhs, rhs]}
    for op, fn in _BIN_OPS.items():
        if op in expr:
            args = expr[op] if isinstance(expr[op], list) else [expr[op]]
            if len(args) != 2:
                reasons.append(f"{op}:arity_error")
                return False
            lhs = _resolve_var(args[0], ctx)
            rhs = _resolve_var(args[1], ctx)
            ok = fn(lhs, rhs)
            reasons.append(f"{op}:{ok}")
            return ok
    reasons.append("unknown_expr")
    return False

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class PolicySource:
    name: str = "source"
    async def load(self) -> Policy:
        raise NotImplementedError

class InMemorySource(PolicySource):
    name = "memory"
    def __init__(self, policy: Policy):
        self._policy = policy
    async def load(self) -> Policy:
        return self._policy

class FileSource(PolicySource):
    name = "file"
    def __init__(self, path: str):
        self.path = path
        self._etag = None  # fake etag by mtime+size
    async def load(self) -> Policy:
        if not os.path.exists(self.path):
            raise FileNotFoundError(self.path)
        st = os.stat(self.path)
        etag = f"{st.st_mtime_ns}-{st.st_size}"
        if self._etag == etag:
            # no change; still need to return a Policy (caller may cache)
            pass
        self._etag = etag
        with open(self.path, "r", encoding="utf-8") as f:
            txt = f.read()
        try:
            data = yaml.safe_load(txt) if (self.path.endswith((".yml", ".yaml")) and yaml) else json.loads(txt)
        except Exception:
            # last resort: try json
            data = json.loads(txt)
        pol = _decode_policy(data)
        pol.etag = etag
        return pol

class HttpSource(PolicySource):
    name = "http"
    def __init__(self, url: str, headers: Optional[Dict[str,str]] = None, timeout_s: float = 10.0):
        if httpx is None:
            raise RuntimeError("httpx not installed")
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout_s
        self._etag: Optional[str] = None

    async def load(self) -> Policy:
        async with httpx.AsyncClient(timeout=self.timeout) as cli:
            hdrs = dict(self.headers)
            if self._etag:
                hdrs["If-None-Match"] = self._etag
            r = await cli.get(self.url, headers=hdrs)
            if r.status_code == 304 and self._etag:
                # not modified: fabricate policy with etag to signal no-change
                data = {"id":"unknown","version":"unchanged","rules":[]}
                pol = _decode_policy(data)
                pol.etag = self._etag
                return pol
            r.raise_for_status()
            etag = r.headers.get("ETag")
            data = r.json()
            pol = _decode_policy(data)
            pol.etag = etag
            self._etag = etag
            return pol

# ---------------------------------------------------------------------------
# Store with TTL and background refresh
# ---------------------------------------------------------------------------

@dataclass
class StoreConfig:
    ttl_seconds: int = 300
    validate_schema: bool = False
    schema: Optional[Dict[str, Any]] = None
    bg_refresh: bool = True
    min_refresh_interval_s: int = 5

class PolicyStore:
    def __init__(self, source: PolicySource, cfg: Optional[StoreConfig] = None):
        self.source = source
        self.cfg = cfg or StoreConfig()
        self._lock = threading.RLock()
        self._policy: Optional[Policy] = None
        self._next_expire = 0.0
        self._last_fetch = 0.0

    def current(self) -> Optional[Policy]:
        with self._lock:
            return self._policy

    async def get(self) -> Policy:
        now = time.time()
        with self._lock:
            if self._policy and now < self._next_expire:
                return self._policy
            # throttle refresh bursts
            if now - self._last_fetch < self.cfg.min_refresh_interval_s and self._policy:
                return self._policy
            self._last_fetch = now
        # load outside lock
        try:
            pol = await self.source.load()
            if self.cfg.validate_schema and jsonschema and self.cfg.schema:
                jsonschema.validate(_encode_policy(pol), self.cfg.schema)  # may raise
            with self._lock:
                replace = False
                if self._policy is None:
                    replace = True
                elif (pol.etag and pol.etag != self._policy.etag) or (pol.version != self._policy.version):
                    replace = True
                if replace:
                    self._policy = pol
                    M_REFRESH.inc(1, source=self.source.name, status="updated")
                    LOG.info("Policy updated: id=%s version=%s etag=%s", pol.id, pol.version, pol.etag)
                else:
                    M_REFRESH.inc(1, source=self.source.name, status="not_modified")
                ttl = pol.ttl_seconds or self.cfg.ttl_seconds
                self._next_expire = time.time() + max(5, ttl)
                return self._policy
        except Exception as e:
            M_REFRESH.inc(1, source=self.source.name, status="error")
            LOG.error("Policy refresh failed: %s", e)
            # serve stale if present
            with self._lock:
                if self._policy:
                    self._next_expire = time.time() + 30  # short extend
                    return self._policy
            raise

# ---------------------------------------------------------------------------
# PIP: attribute providers (subject/resource/context enrichment)
# ---------------------------------------------------------------------------

PIPFunc = Callable[[Dict[str, Any]], Dict[str, Any]]
AsyncPIPFunc = Callable[[Dict[str, Any]], "Awaitable[Dict[str, Any]]"]  # type: ignore

class PIPRegistry:
    def __init__(self):
        self._sync: Dict[str, PIPFunc] = {}
        self._async: Dict[str, AsyncPIPFunc] = {}

    def register(self, name: str, func: Union[PIPFunc, AsyncPIPFunc], async_fn: bool = False):
        if async_fn:
            self._async[name] = func  # type: ignore
        else:
            self._sync[name] = func  # type: ignore

    async def enrich(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(bundle)
        # sync first
        for name, fn in list(self._sync.items()):
            try:
                res = fn(out)
                if res:
                    out.update(res)
            except Exception as e:
                LOG.debug("PIP sync '%s' failed: %s", name, e)
        # async
        for name, fn in list(self._async.items()):
            try:
                res = await fn(out)  # type: ignore
                if res:
                    out.update(res)
            except Exception as e:
                LOG.debug("PIP async '%s' failed: %s", name, e)
        return out

# ---------------------------------------------------------------------------
# Engine & PDP
# ---------------------------------------------------------------------------

class PolicyEngine:
    def __init__(self, store: PolicyStore, pips: Optional[PIPRegistry] = None):
        self.store = store
        self.pips = pips or PIPRegistry()

    async def decide(self, subject: Dict[str, Any], action: str, resource: str, context: Optional[Dict[str, Any]] = None) -> Decision:
        t0 = time.perf_counter()
        pol = await self.store.get()
        subj = dict(subject or {})
        ctx0 = dict(context or {})
        # Enrich via PIP
        bundle = await self.pips.enrich({"subject": subj, "action": action, "resource": resource, "context": ctx0})
        subject = bundle.get("subject", subj)
        action = bundle.get("action", action)
        resource = bundle.get("resource", resource)
        context = bundle.get("context", ctx0)

        # Evaluate rules by priority then order
        matches: List[Tuple[int, Rule, List[str]]] = []
        for r in sorted(pol.rules, key=lambda x: (x.priority, x.id)):
            reasons: List[str] = []
            if r.actions and not _any_match(r.actions, action):
                continue
            if r.resources and not _any_match(r.resources, resource):
                continue
            if r.subjects and not _subject_match(r.subjects, subject):
                continue
            ok = _eval_expr(r.condition or {}, {"subject": subject, "action": action, "resource": resource, "context": context}, reasons)
            if ok:
                matches.append((r.priority, r, reasons))

        if not matches:
            dec = Decision(effect="not_applicable", policy_id=pol.id, policy_version=pol.version,
                           matched_rule=None, reasons=["no_rule_matched"], obligations={}, latency_ms=(time.perf_counter()-t0)*1000.0)
            M_DECISIONS.inc(1, effect=dec.effect, policy_id=pol.id)
            M_LATENCY.observe(dec.latency_ms/1000.0, policy_id=pol.id)
            return dec

        # Winner: minimal priority
        _, rule, reasons = sorted(matches, key=lambda x: x[0])[0]
        obligations = {ob.key: ob.value for ob in (rule.obligations or [])}
        dec = Decision(effect=rule.effect, policy_id=pol.id, policy_version=pol.version,
                       matched_rule=rule.id, reasons=[f"rule:{rule.id}", *reasons], obligations=obligations,
                       latency_ms=(time.perf_counter()-t0)*1000.0)
        M_DECISIONS.inc(1, effect=dec.effect, policy_id=pol.id)
        M_LATENCY.observe(dec.latency_ms/1000.0, policy_id=pol.id)
        return dec

def _subject_match(patterns: List[str], subject: Dict[str, Any]) -> bool:
    """
    Matches by:
     - subject.id equals pattern
     - subject.roles contains pattern
     - wildcard patterns via _glob_match
    """
    sid = str(subject.get("id") or "")
    roles = [str(r) for r in (subject.get("roles") or [])]
    for p in patterns:
        if _glob_match(p, sid):
            return True
        if any(_glob_match(p, r) for r in roles):
            return True
    return False

# ---------------------------------------------------------------------------
# Encoding/Decoding helpers
# ---------------------------------------------------------------------------

def _decode_policy(data: Dict[str, Any]) -> Policy:
    pid = data.get("id") or "policy"
    ver = str(data.get("version") or "0")
    ttl = int(data.get("ttl_seconds") or 300)
    rules: List[Rule] = []
    for i, rd in enumerate(data.get("rules", [])):
        obligations = [Obligation(key=o.get("key"), value=o.get("value")) for o in (rd.get("obligations") or [])]
        r = Rule(
            id=str(rd.get("id") or f"r{i}"),
            effect=rd.get("effect", "deny"),
            actions=list(rd.get("actions") or []),
            resources=list(rd.get("resources") or []),
            subjects=list(rd.get("subjects") or []),
            condition=rd.get("condition"),
            obligations=obligations,
            priority=int(rd.get("priority") or 100),
            description=rd.get("description",""),
        )
        rules.append(r)
    return Policy(id=pid, version=ver, rules=rules, ttl_seconds=ttl, schema_version=str(data.get("schema_version","1.0")))

def _encode_policy(pol: Policy) -> Dict[str, Any]:
    return {
        "id": pol.id,
        "version": pol.version,
        "ttl_seconds": pol.ttl_seconds,
        "schema_version": pol.schema_version,
        "rules": [
            {
                "id": r.id,
                "effect": r.effect,
                "actions": r.actions,
                "resources": r.resources,
                "subjects": r.subjects,
                "condition": r.condition,
                "obligations": [{"key": o.key, "value": o.value} for o in r.obligations],
                "priority": r.priority,
                "description": r.description,
            }
            for r in pol.rules
        ],
    }

# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def build_file_adapter(path: str, store_cfg: Optional[StoreConfig] = None) -> PolicyEngine:
    src = FileSource(path)
    store = PolicyStore(src, store_cfg)
    return PolicyEngine(store)

def build_http_adapter(url: str, headers: Optional[Dict[str,str]] = None, store_cfg: Optional[StoreConfig] = None) -> PolicyEngine:
    if httpx is None:
        raise RuntimeError("httpx is not installed")
    src = HttpSource(url, headers=headers)
    store = PolicyStore(src, store_cfg)
    return PolicyEngine(store)

def build_memory_adapter(policy_data: Dict[str, Any], store_cfg: Optional[StoreConfig] = None) -> PolicyEngine:
    pol = _decode_policy(policy_data)
    src = InMemorySource(pol)
    store = PolicyStore(src, store_cfg)
    return PolicyEngine(store)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli():
    """
    Examples:
      python -m adapters.policy_adapter --file ./policy.yaml --action read --resource table:orders:eu --subject '{"id":"u1","roles":["analyst","eu"]}' --context '{"amount":120}'
      python -m adapters.policy_adapter --http https://example/policy --action write --resource table:orders:us --subject @subject.json
    """
    import argparse, sys, json as _json
    p = argparse.ArgumentParser(description="DataFabric Policy Adapter (PDP)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="Policy file (YAML/JSON)")
    src.add_argument("--http", help="Policy URL (JSON)")
    src.add_argument("--memory", help="Inline policy JSON")
    p.add_argument("--action", required=True)
    p.add_argument("--resource", required=True)
    p.add_argument("--subject", required=True, help='JSON or @file.json')
    p.add_argument("--context", default="{}", help='JSON or @file.json')
    p.add_argument("--schema", help="Optional JSON schema for policy validation")
    p.add_argument("--verbose", "-v", action="count", default=0)
    args = p.parse_args()

    if args.verbose >= 2:
        LOG.setLevel(logging.DEBUG)
    elif args.verbose == 1:
        LOG.setLevel(logging.INFO)

    def _load_json_arg(val: str) -> Dict[str, Any]:
        if val.startswith("@"):
            with open(val[1:], "r", encoding="utf-8") as fh:
                return _json.load(fh)
        return _json.loads(val)

    subj = _load_json_arg(args.subject)
    ctx = _load_json_arg(args.context)

    store_cfg = StoreConfig()
    if args.schema:
        with open(args.schema, "r", encoding="utf-8") as fh:
            schema = json.load(fh)
        store_cfg.validate_schema = True
        store_cfg.schema = schema

    if args.file:
        engine = build_file_adapter(args.file, store_cfg)
    elif args.http:
        engine = build_http_adapter(args.http, store_cfg=store_cfg)
    else:
        engine = build_memory_adapter(_load_json_arg(args.memory), store_cfg=store_cfg)

    import asyncio
    dec: Decision = asyncio.run(engine.decide(subj, args.action, args.resource, ctx))
    print(json.dumps({
        "effect": dec.effect,
        "policy_id": dec.policy_id,
        "policy_version": dec.policy_version,
        "matched_rule": dec.matched_rule,
        "reasons": dec.reasons,
        "obligations": dec.obligations,
        "latency_ms": dec.latency_ms,
    }, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    _cli()
