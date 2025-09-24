# cybersecurity-core/cybersecurity/edr/rules.py
# Industrial EDR rule engine: deterministic matchers, sliding-window aggregation,
# safe DSL compilation, multi-tenant context, dynamic block/allow lists, and
# action recommendations. No external dependencies (stdlib-only).
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

# --------------------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------------------

LOG = logging.getLogger("edr.rules")
if not LOG.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('%(asctime)s %(levelname)s edr.rules: %(message)s'))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO)

# --------------------------------------------------------------------------------------
# Types and Models
# --------------------------------------------------------------------------------------

class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ActionType(str, Enum):
    kill_process = "kill_process"
    quarantine_file = "quarantine_file"
    delete_file = "delete_file"
    block_hash = "block_hash"
    block_ip = "block_ip"
    terminate_network_connection = "terminate_network_connection"
    isolate_host = "isolate_host"
    unisolate_host = "unisolate_host"
    scan = "scan"
    suspend_user = "suspend_user"
    disable_network = "disable_network"
    add_to_blocklist = "add_to_blocklist"
    add_to_allowlist = "add_to_allowlist"
    rollback = "rollback"
    alert_only = "alert_only"
    custom = "custom"


@dataclass(frozen=True)
class ActionRecommendation:
    type: ActionType
    # hint содержит минимально необходимый контекст для выполнения действия
    hint: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Detection:
    rule_id: str
    name: str
    description: str
    severity: Severity
    confidence: int  # 0..100
    tags: Tuple[str, ...]
    mitre_attack: Tuple[str, ...]
    tenant_id: str
    matched_at: float
    actions: Tuple[ActionRecommendation, ...]
    details: Dict[str, Any] = field(default_factory=dict)

# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------

def _now() -> float:
    return time.time()

def _get(event: Mapping[str, Any], path: str, default: Any = None) -> Any:
    """Safe nested get: path like 'process.command_line' or 'file.hashes.sha256'."""
    cur: Any = event
    for p in path.split("."):
        if isinstance(cur, Mapping) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def _normalize_str(v: Any, limit: int = 10_000) -> Optional[str]:
    if v is None:
        return None
    s = str(v)
    if len(s) > limit:
        return s[:limit]
    return s

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

# --------------------------------------------------------------------------------------
# Dynamic Lists (block/allow) with RCU-style swap
# --------------------------------------------------------------------------------------

class DynamicSet:
    """Lock-free reads, thread-safe writes via atomic swap + RLock for writers."""
    def __init__(self, initial: Optional[Iterable[str]] = None) -> None:
        self._set = frozenset(map(str, initial or ()))
        self._lock = threading.RLock()

    def contains(self, value: str) -> bool:
        return str(value) in self._set

    def snapshot(self) -> frozenset[str]:
        return self._set

    def update(self, values: Iterable[str]) -> None:
        s = frozenset(map(str, values))
        with self._lock:
            self._set = s

# --------------------------------------------------------------------------------------
# Sliding window counters
# --------------------------------------------------------------------------------------

class SlidingWindowCounter:
    """
    Per-key counter in a time window. O(1) amortized updates.
    """
    def __init__(self) -> None:
        self._data: Dict[Tuple[Any, ...], Deque[float]] = defaultdict(deque)
        self._lock = threading.RLock()

    def inc_and_count(self, key: Tuple[Any, ...], window_sec: int, now: Optional[float] = None) -> int:
        now = _now() if now is None else now
        w = self._data[key]
        with self._lock:
            w.append(now)
            cutoff = now - window_sec
            while w and w[0] < cutoff:
                w.popleft()
            return len(w)

# --------------------------------------------------------------------------------------
# Conditions
# --------------------------------------------------------------------------------------

class Condition:
    def evaluate(self, event: Mapping[str, Any], ctx: "EvalContext") -> bool:
        raise NotImplementedError

@dataclass
class FieldCondition(Condition):
    path: str
    op: str
    value: Any
    ci: bool = False  # case-insensitive for textual ops

    def evaluate(self, event: Mapping[str, Any], ctx: "EvalContext") -> bool:
        left = _get(event, self.path)
        right = self.value
        if self.op in {"eq", "ne", "gt", "gte", "lt", "lte"}:
            if self.ci:
                left = _normalize_str(left)
                right = _normalize_str(right)
                if left is None or right is None:
                    return False
                if self.op == "eq":
                    return left.lower() == right.lower()
                if self.op == "ne":
                    return left.lower() != right.lower()
                # gt/gte/lt/lte на строках — лексикографически
                if self.op == "gt":
                    return left.lower() > right.lower()
                if self.op == "gte":
                    return left.lower() >= right.lower()
                if self.op == "lt":
                    return left.lower() < right.lower()
                if self.op == "lte":
                    return left.lower() <= right.lower()
            # числовое/лексикографическое сравнение
            try:
                if self.op == "eq":
                    return left == right
                if self.op == "ne":
                    return left != right
                if self.op == "gt":
                    return left > right
                if self.op == "gte":
                    return left >= right
                if self.op == "lt":
                    return left < right
                if self.op == "lte":
                    return left <= right
            except Exception:
                return False

        if self.op == "contains":
            ls = _normalize_str(left)
            rs = _normalize_str(right)
            if ls is None or rs is None:
                return False
            if self.ci:
                return rs.lower() in ls.lower()
            return rs in ls

        if self.op == "startswith":
            ls = _normalize_str(left)
            rs = _normalize_str(right)
            if ls is None or rs is None:
                return False
            return ls.lower().startswith(rs.lower()) if self.ci else ls.startswith(rs)

        if self.op == "endswith":
            ls = _normalize_str(left)
            rs = _normalize_str(right)
            if ls is None or rs is None:
                return False
            return ls.lower().endswith(rs.lower()) if self.ci else ls.endswith(rs)

        if self.op == "in":
            seq = right if isinstance(right, (list, tuple, set, frozenset)) else [right]
            if self.ci:
                lv = _normalize_str(left)
                if lv is None:
                    return False
                return lv.lower() in {str(x).lower() for x in seq}
            return left in set(seq)

        if self.op == "wildmatch":
            ls = _normalize_str(left)
            rs = _normalize_str(right)
            if ls is None or rs is None:
                return False
            pattern = rs.lower() if self.ci else rs
            text = ls.lower() if self.ci else ls
            return fnmatch.fnmatch(text, pattern)

        if self.op == "ip_in":
            val = _normalize_str(left)
            if val is None:
                return False
            try:
                ip = ipaddress.ip_address(val)
            except ValueError:
                return False
            nets = right if isinstance(right, (list, tuple)) else [right]
            try:
                for n in nets:
                    net = ipaddress.ip_network(str(n), strict=False)
                    if ip in net:
                        return True
                return False
            except ValueError:
                return False

        if self.op == "member_of":
            # проверка в динамических наборах по имени списка
            ls_name = str(right)
            ds = ctx.dynamic_sets.get(ls_name)
            if ds is None:
                return False
            v = _normalize_str(left)
            return False if v is None else ds.contains(v)

        return False

@dataclass
class RegexCondition(Condition):
    path: str
    pattern: str
    ci: bool = False
    fullmatch: bool = False
    timeout_ms: int = 8  # "софт"-таймаут на сложные regex через re2 нет, ограничиваем сложность паттернов

    def __post_init__(self) -> None:
        flags = re.IGNORECASE if self.ci else 0
        # Безопасность: запрещаем inline-флаги со сменой флагов (?...)
        if "(?" in self.pattern:
            raise ValueError("inline regex flags are not allowed")
        self._re = re.compile(self.pattern, flags=flags)

    def evaluate(self, event: Mapping[str, Any], ctx: "EvalContext") -> bool:
        s = _normalize_str(_get(event, self.path))
        if s is None:
            return False
        # Псевдо-таймаут: ограничим длину входной строки и сложность паттерна на этапе инициализации
        if len(s) > 10_000:
            s = s[:10_000]
        m = self._re.fullmatch(s) if self.fullmatch else self._re.search(s)
        return m is not None

@dataclass
class And(Condition):
    items: Tuple[Condition, ...]

    def evaluate(self, event: Mapping[str, Any], ctx: "EvalContext") -> bool:
        for c in self.items:
            if not c.evaluate(event, ctx):
                return False
        return True

@dataclass
class Or(Condition):
    items: Tuple[Condition, ...]

    def evaluate(self, event: Mapping[str, Any], ctx: "EvalContext") -> bool:
        for c in self.items:
            if c.evaluate(event, ctx):
                return True
        return False

@dataclass
class Not(Condition):
    item: Condition

    def evaluate(self, event: Mapping[str, Any], ctx: "EvalContext") -> bool:
        return not self.item.evaluate(event, ctx)

@dataclass
class ThresholdCondition(Condition):
    """
    Активируется, если внутренняя condition истинна N раз за окно W секунд по ключу группировки.
    """
    inner: Condition
    threshold: int
    window_sec: int
    group_by: Tuple[str, ...]  # пути для ключа
    counter: SlidingWindowCounter = field(default_factory=SlidingWindowCounter)

    def evaluate(self, event: Mapping[str, Any], ctx: "EvalContext") -> bool:
        if not self.inner.evaluate(event, ctx):
            return False
        key = tuple(_get(event, p) for p in self.group_by)
        cnt = self.counter.inc_and_count(key, self.window_sec)
        return cnt >= self.threshold

# --------------------------------------------------------------------------------------
# Rule and Context
# --------------------------------------------------------------------------------------

@dataclass
class Rule:
    rule_id: str
    name: str
    description: str
    severity: Severity
    confidence: int
    condition: Condition
    actions: Tuple[ActionRecommendation, ...] = field(default_factory=tuple)
    tags: Tuple[str, ...] = field(default_factory=tuple)
    mitre_attack: Tuple[str, ...] = field(default_factory=tuple)
    version: str = "1.0.0"

    def fingerprint(self) -> str:
        payload = {
            "rule_id": self.rule_id,
            "name": self.name,
            "version": self.version,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "mitre": list(self.mitre_attack),
        }
        return _sha256_hex(json.dumps(payload, sort_keys=True))

@dataclass
class EvalContext:
    tenant_id: str
    dynamic_sets: Dict[str, DynamicSet] = field(default_factory=dict)

# --------------------------------------------------------------------------------------
# Rule Engine
# --------------------------------------------------------------------------------------

class RuleEngine:
    """
    Потокобезопасный движок правил. Поддерживает:
      - add_rule/remove_rule
      - evaluate(event, tenant_id)
      - горячее обновление dynamic sets
    """
    def __init__(self) -> None:
        self._rules: Dict[str, Rule] = {}
        self._lock = threading.RLock()
        self._dyn_sets: Dict[str, DynamicSet] = {}

    # ---- Dynamic sets ----
    def upsert_dynamic_set(self, name: str, values: Iterable[str]) -> None:
        with self._lock:
            if name in self._dyn_sets:
                self._dyn_sets[name].update(values)
            else:
                self._dyn_sets[name] = DynamicSet(values)

    def get_dynamic_set_snapshot(self, name: str) -> frozenset[str]:
        ds = self._dyn_sets.get(name)
        return ds.snapshot() if ds else frozenset()

    # ---- Rules management ----
    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            self._rules[rule.rule_id] = rule
            LOG.info(f"rule_add id={rule.rule_id} name={rule.name} sev={rule.severity.value}")

    def remove_rule(self, rule_id: str) -> None:
        with self._lock:
            self._rules.pop(rule_id, None)
            LOG.info(f"rule_remove id={rule_id}")

    def list_rules(self) -> List[Rule]:
        with self._lock:
            return list(self._rules.values())

    # ---- Evaluation ----
    def evaluate(self, event: Mapping[str, Any], tenant_id: str) -> List[Detection]:
        ctx = EvalContext(tenant_id=tenant_id, dynamic_sets=self._dyn_sets)
        matched: List[Detection] = []
        # Опционально: быстрый фильтр по severity/tags мог бы жить снаружи
        with self._lock:
            rules_snapshot = list(self._rules.values())
        for r in rules_snapshot:
            try:
                ok = r.condition.evaluate(event, ctx)
            except Exception as e:
                LOG.exception(f"rule_error id={r.rule_id} name={r.name}: {e}")
                continue
            if ok:
                det = Detection(
                    rule_id=r.rule_id,
                    name=r.name,
                    description=r.description,
                    severity=r.severity,
                    confidence=r.confidence,
                    tags=r.tags,
                    mitre_attack=r.mitre_attack,
                    tenant_id=tenant_id,
                    matched_at=_now(),
                    actions=r.actions,
                    details=_build_detection_details(event, r),
                )
                matched.append(det)
        return matched

# --------------------------------------------------------------------------------------
# DSL Compilation
# --------------------------------------------------------------------------------------

def compile_condition(spec: Mapping[str, Any]) -> Condition:
    """
    Безопасная компиляция условий из dict:
      {"and": [ ... ]}
      {"or":  [ ... ]}
      {"not": {...}}
      {"field": {"path":"process.name","op":"eq","value":"powershell.exe","ci":true}}
      {"regex": {"path":"process.command_line","pattern":"(?i)--encoded(Command)?", "ci":true}}
      {"threshold": {"inner": {...}, "threshold": 5, "window_sec": 60, "group_by": ["host.hostname"]}}
      Доп. ops: contains, startswith, endswith, in, wildmatch, ip_in, member_of
    """
    if not isinstance(spec, Mapping) or not spec:
        raise ValueError("invalid condition spec")

    if "and" in spec:
        items = tuple(compile_condition(x) for x in _as_list(spec["and"]))
        if not items:
            raise ValueError("and requires items")
        return And(items=items)

    if "or" in spec:
        items = tuple(compile_condition(x) for x in _as_list(spec["or"]))
        if not items:
            raise ValueError("or requires items")
        return Or(items=items)

    if "not" in spec:
        return Not(item=compile_condition(spec["not"]))

    if "field" in spec:
        d = spec["field"]
        path = _required_str(d, "path")
        op = _required_str(d, "op")
        value = d.get("value", None)
        ci = bool(d.get("ci", False))
        return FieldCondition(path=path, op=op, value=value, ci=ci)

    if "regex" in spec:
        d = spec["regex"]
        path = _required_str(d, "path")
        pattern = _required_str(d, "pattern")
        ci = bool(d.get("ci", False))
        full = bool(d.get("fullmatch", False))
        return RegexCondition(path=path, pattern=pattern, ci=ci, fullmatch=full)

    if "threshold" in spec:
        d = spec["threshold"]
        inner = compile_condition(d["inner"])
        thr = int(d.get("threshold", 1))
        win = int(d.get("window_sec", 60))
        gb = tuple(_as_list(d.get("group_by", [])))
        if thr < 1 or win < 1 or not gb:
            raise ValueError("threshold requires threshold>=1, window_sec>=1 and non-empty group_by")
        return ThresholdCondition(inner=inner, threshold=thr, window_sec=win, group_by=gb)

    raise ValueError("unknown condition operator")


def compile_rule(spec: Mapping[str, Any]) -> Rule:
    """
    Rule DSL:
    {
      "rule_id": "R-PWSH-ENC-001",
      "name": "PowerShell encoded command",
      "description": "...",
      "severity": "high",
      "confidence": 85,
      "tags": ["powershell","lolbin","defense-evasion"],
      "mitre_attack": ["T1059.001"],
      "version": "1.2.0",
      "condition": { ... },
      "actions": [
         {"type":"kill_process","hint":{"path":"process.path"}},
         {"type":"add_to_blocklist","hint":{"path":"file.hashes.sha256"}}
      ]
    }
    """
    rid = _required_str(spec, "rule_id")
    name = _required_str(spec, "name")
    desc = _required_str(spec, "description")
    sev = Severity(_required_str(spec, "severity"))
    conf = int(spec.get("confidence", 70))
    tags = tuple(str(x) for x in _as_list(spec.get("tags", [])))
    mitre = tuple(str(x) for x in _as_list(spec.get("mitre_attack", [])))
    ver = str(spec.get("version", "1.0.0"))
    cond = compile_condition(_required_map(spec, "condition"))
    actions: List[ActionRecommendation] = []
    for a in _as_list(spec.get("actions", [])):
        at = ActionType(_required_str(a, "type"))
        hint = dict(a.get("hint", {}))
        actions.append(ActionRecommendation(type=at, hint=hint))
    return Rule(
        rule_id=rid,
        name=name,
        description=desc,
        severity=sev,
        confidence=conf,
        tags=tags,
        mitre_attack=mitre,
        version=ver,
        condition=cond,
        actions=tuple(actions),
    )

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, tuple):
        return list(v)
    return [v]

def _required_str(m: Mapping[str, Any], key: str) -> str:
    if key not in m:
        raise ValueError(f"required key missing: {key}")
    val = m[key]
    if not isinstance(val, str) or not val:
        raise ValueError(f"key {key} must be non-empty string")
    return val

def _required_map(m: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    if key not in m or not isinstance(m[key], Mapping):
        raise ValueError(f"required map missing: {key}")
    return m[key]

def _build_detection_details(event: Mapping[str, Any], rule: Rule) -> Dict[str, Any]:
    # Извлекаем полезные поля, если есть
    return {
        "host": {
            "hostname": _get(event, "host.hostname"),
            "asset_id": _get(event, "host.asset_id"),
            "ip": _get(event, "host.ip_addresses.0"),  # берём первый
        },
        "process": {
            "pid": _get(event, "process.pid"),
            "name": _get(event, "process.name"),
            "path": _get(event, "process.path"),
            "user": _get(event, "process.user"),
        },
        "file": {
            "path": _get(event, "file.path"),
            "sha256": _get(event, "file.hashes.sha256"),
        },
        "network": {
            "remote_ip": _get(event, "network_connection.remote_ip"),
            "remote_port": _get(event, "network_connection.remote_port"),
            "domain": _get(event, "network_connection.domain"),
        },
        "rule": {
            "id": rule.rule_id,
            "fingerprint": rule.fingerprint(),
        },
    }

# --------------------------------------------------------------------------------------
# Built-in example rules (safe defaults)
# --------------------------------------------------------------------------------------

BUILTIN_RULES: List[Mapping[str, Any]] = [
    {
        "rule_id": "R-PWSH-ENC-001",
        "name": "PowerShell encoded command",
        "description": "Suspicious PowerShell usage with encoded command.",
        "severity": "high",
        "confidence": 85,
        "tags": ["powershell", "lolbin", "defense-evasion"],
        "mitre_attack": ["T1059.001"],
        "version": "1.1.0",
        "condition": {
            "and": [
                {"field": {"path": "process.name", "op": "eq", "value": "powershell.exe", "ci": True}},
                {"or": [
                    {"regex": {"path": "process.command_line", "pattern": r"-enc(odedcommand)?\\s+[A-Za-z0-9/+]{20,}", "ci": True}},
                    {"regex": {"path": "process.command_line", "pattern": r"FromBase64String\\(", "ci": True}}
                ]}
            ]
        },
        "actions": [
            {"type": "kill_process", "hint": {"path": "process.pid"}},
            {"type": "quarantine_file", "hint": {"path": "file.path"}}
        ]
    },
    {
        "rule_id": "R-OFFICE-SHELL-002",
        "name": "Office spawning shell",
        "description": "Office process spawning cmd/powershell/wscript which may indicate macro abuse.",
        "severity": "high",
        "confidence": 80,
        "tags": ["office", "macro", "lateral-movement"],
        "mitre_attack": ["T1204", "T1566.001"],
        "version": "1.0.0",
        "condition": {
            "and": [
                {"field": {"path": "parent_process.name", "op": "in", "value": ["winword.exe", "excel.exe", "powerpnt.exe"], "ci": True}},
                {"field": {"path": "process.name", "op": "in", "value": ["cmd.exe", "powershell.exe", "wscript.exe"], "ci": True}}
            ]
        },
        "actions": [
            {"type": "kill_process", "hint": {"path": "process.pid"}},
            {"type": "alert_only"}
        ]
    },
    {
        "rule_id": "R-MULTIPLE-FAIL-LOGIN-003",
        "name": "Multiple failed logons by user",
        "description": "N failed logons by the same user within time window may indicate brute force.",
        "severity": "medium",
        "confidence": 70,
        "tags": ["auth", "brute-force"],
        "mitre_attack": ["T1110"],
        "version": "1.0.0",
        "condition": {
            "threshold": {
                "inner": {"field": {"path": "auth.status", "op": "eq", "value": "failed", "ci": True}},
                "threshold": 5,
                "window_sec": 60,
                "group_by": ["auth.username"]
            }
        },
        "actions": [
            {"type": "suspend_user", "hint": {"path": "auth.username"}},
            {"type": "alert_only"}
        ]
    },
    {
        "rule_id": "R-OUTBOUND-BLOCK-IP-004",
        "name": "Outbound to blocked IP",
        "description": "Connection to IP in dynamic blocklist.",
        "severity": "high",
        "confidence": 90,
        "tags": ["network", "c2"],
        "mitre_attack": ["T1071"],
        "version": "1.0.0",
        "condition": {
            "field": {"path": "network_connection.remote_ip", "op": "member_of", "value": "blocked_ips"}
        },
        "actions": [
            {"type": "terminate_network_connection"},
            {"type": "block_ip", "hint": {"path": "network_connection.remote_ip"}}
        ]
    }
]

# --------------------------------------------------------------------------------------
# Initialization helpers
# --------------------------------------------------------------------------------------

def build_engine_with_builtin() -> RuleEngine:
    eng = RuleEngine()
    for r in BUILTIN_RULES:
        eng.add_rule(compile_rule(r))
    # example dynamic set
    eng.upsert_dynamic_set("blocked_ips", [])
    return eng

# --------------------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------------------

__all__ = [
    "Severity",
    "ActionType",
    "ActionRecommendation",
    "Detection",
    "Condition",
    "FieldCondition",
    "RegexCondition",
    "And",
    "Or",
    "Not",
    "ThresholdCondition",
    "Rule",
    "EvalContext",
    "RuleEngine",
    "compile_condition",
    "compile_rule",
    "build_engine_with_builtin",
]
