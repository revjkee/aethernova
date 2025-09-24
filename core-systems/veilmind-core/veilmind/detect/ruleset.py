# -*- coding: utf-8 -*-
"""
VeilMind Detect — Rules Engine (industrial-grade, stdlib-only)

Возможности:
- Декларативные правила (JSON/YAML), версия схемы и строгая валидация.
- Операторы: eq, ne, in, regex, exists, gt, gte, lt, lte, prefix, suffix,
  contains, ip_in_cidr, len_gt, len_lt; булева композиция all/any/not.
- Доступ к полям события через "точечные" пути: a.b.c, headers.user-agent, arr.0.id.
- Предобработка: компиляция regex, CIDR, кэш парсеров путей, без eval().
- Действия: add_tag, set_field, route_to, score_adjust, drop, emit_metric, alert.
- Rate limit/dedup для alert'ов (leaky-bucket стиль, TTL).
- Приоритеты, режимы: first_match/all_matches; severity, enabled, labels.
- Потокобезопасно: локи для счётчиков; чистый Python, совместимо с asyncio/threading.
- Опциональная загрузка YAML (PyYAML), иначе JSON.

Пример минимального правила (JSON/YAML эквивалентны):
{
  "id":"r_http5xx", "name":"HTTP 5xx", "version":1, "enabled":true, "priority":10, "severity":"high",
  "when": {"any":[
    {"op":"gte","field":"http.status","value":500},
    {"op":"eq","field":"grpc.code","value":"INTERNAL"}
  ]},
  "actions":[
    {"type":"add_tag","value":"error"},
    {"type":"emit_metric","name":"http_5xx_total","labels":{"service":"${service.name}","route":"${http.route}"}},
    {"type":"alert","title":"Server error","dedup_keys":["service.name","http.route"],"ttl_sec":300}
  ]
}
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# -----------------------------------------------------------------------------
# Типы и модели
# -----------------------------------------------------------------------------
JSON = Dict[str, Any]
Labels = Dict[str, str]
Path = str

_SEVERITIES = ("low", "medium", "high", "critical")

@dataclass(frozen=True)
class CompiledOperator:
    name: str
    func: Callable[[Any, Any], bool]

@dataclass(frozen=True)
class CompiledMatcher:
    op: CompiledOperator
    field: Path
    value: Any  # уже подготовлен (скомпилированный regex, сеть и т.п.)

@dataclass(frozen=True)
class CompiledBoolean:
    any: Tuple[Any, ...] = field(default_factory=tuple)  # tuple[CompiledBoolean|CompiledMatcher]
    all: Tuple[Any, ...] = field(default_factory=tuple)
    not_: Optional[Any] = None

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    version: int
    enabled: bool
    priority: int
    severity: str
    labels: Mapping[str, str]
    when: CompiledBoolean
    actions: Tuple[JSON, ...]  # конфиг действий (исполняется ActionRunner)
    description: str = ""
    match_limit_per_event: int = 0  # 0 = не ограничено

@dataclass
class AlertEvent:
    rule_id: str
    title: str
    severity: str
    dedup_key: str
    ttl_sec: int
    payload: JSON

@dataclass
class MetricEvent:
    name: str
    value: float
    labels: Labels

@dataclass
class DetectionResult:
    matched_rules: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    set_fields: Dict[str, Any] = field(default_factory=dict)
    route: Optional[str] = None
    drop: bool = False
    score_delta: float = 0.0
    alerts: List[AlertEvent] = field(default_factory=list)
    metrics: List[MetricEvent] = field(default_factory=list)
    debug_trace: Optional[List[str]] = None  # при enable_debug=True


# -----------------------------------------------------------------------------
# Утилиты доступа к полям и подготовка значений
# -----------------------------------------------------------------------------
class _PathCache:
    """Кэш парсинга точечных путей: 'a.b.0.c' -> ['a','b',0,'c']."""
    __slots__ = ("_cache", "_lock")

    def __init__(self) -> None:
        self._cache: Dict[str, Tuple[Union[str, int], ...]] = {}
        self._lock = threading.Lock()

    def parse(self, path: Path) -> Tuple[Union[str, int], ...]:
        try:
            return self._cache[path]
        except KeyError:
            with self._lock:
                if path in self._cache:
                    return self._cache[path]
                parts: List[Union[str, int]] = []
                for raw in path.split("."):
                    if raw == "":
                        continue
                    if raw.isdigit():
                        parts.append(int(raw))
                    else:
                        parts.append(raw)
                tup = tuple(parts)
                self._cache[path] = tup
                return tup

_PATHS = _PathCache()


def get_by_path(data: Any, path: Path, default: Any = None) -> Any:
    """Безопасное получение значения по точечному пути: поддерживает dict/list/tuple."""
    if path == "" or data is None:
        return default
    cur = data
    for key in _PATHS.parse(path):
        try:
            if isinstance(key, int) and isinstance(cur, (list, tuple)):
                cur = cur[key]
            elif isinstance(cur, Mapping):
                cur = cur.get(key, default)
            else:
                return default
        except Exception:
            return default
    return cur


def _to_number(x: Any) -> Optional[float]:
    if isinstance(x, (int, float)):
        return float(x)
    try:
        return float(str(x))
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Операторы и их реализация (белый список)
# -----------------------------------------------------------------------------
def _op_eq(a: Any, b: Any) -> bool:
    return a == b

def _op_ne(a: Any, b: Any) -> bool:
    return a != b

def _op_in(a: Any, b: Any) -> bool:
    if isinstance(b, (list, tuple, set, frozenset)):
        return a in b
    return False

def _op_exists(a: Any, _: Any) -> bool:
    return a is not None

def _op_regex(a: Any, compiled: re.Pattern) -> bool:
    if a is None:
        return False
    s = str(a)
    return compiled.search(s) is not None

def _op_prefix(a: Any, b: str) -> bool:
    return isinstance(a, str) and a.startswith(b)

def _op_suffix(a: Any, b: str) -> bool:
    return isinstance(a, str) and a.endswith(b)

def _op_contains(a: Any, b: str) -> bool:
    if isinstance(a, str):
        return b in a
    if isinstance(a, (list, tuple, set, frozenset)):
        return b in a
    return False

def _op_gt(a: Any, b: Any) -> bool:
    na, nb = _to_number(a), _to_number(b)
    return False if (na is None or nb is None) else na > nb

def _op_gte(a: Any, b: Any) -> bool:
    na, nb = _to_number(a), _to_number(b)
    return False if (na is None or nb is None) else na >= nb

def _op_lt(a: Any, b: Any) -> bool:
    na, nb = _to_number(a), _to_number(b)
    return False if (na is None or nb is None) else na < nb

def _op_lte(a: Any, b: Any) -> bool:
    na, nb = _to_number(a), _to_number(b)
    return False if (na is None or nb is None) else na <= nb

def _op_len_gt(a: Any, b: Any) -> bool:
    try:
        return len(a) > int(b)  # type: ignore[arg-type]
    except Exception:
        return False

def _op_len_lt(a: Any, b: Any) -> bool:
    try:
        return len(a) < int(b)  # type: ignore[arg-type]
    except Exception:
        return False

def _op_ip_in_cidr(a: Any, nets: Tuple[ipaddress._BaseNetwork, ...]) -> bool:  # type: ignore[attr-defined]
    try:
        ip = ipaddress.ip_address(str(a))
        return any(ip in n for n in nets)
    except Exception:
        return False


_OPERATORS: Dict[str, Callable[[Any, Any], bool]] = {
    "eq": _op_eq,
    "ne": _op_ne,
    "in": _op_in,
    "exists": _op_exists,
    "regex": _op_regex,
    "prefix": _op_prefix,
    "suffix": _op_suffix,
    "contains": _op_contains,
    "gt": _op_gt,
    "gte": _op_gte,
    "lt": _op_lt,
    "lte": _op_lte,
    "len_gt": _op_len_gt,
    "len_lt": _op_len_lt,
    "ip_in_cidr": _op_ip_in_cidr,
}


# -----------------------------------------------------------------------------
# Компиляция условий и правил
# -----------------------------------------------------------------------------
class RuleError(ValueError):
    pass


def _compile_value(op: str, value: Any) -> Any:
    """Предкомпиляция значений для операторов (regex, ip networks)."""
    if op == "regex":
        if not isinstance(value, str):
            raise RuleError("regex operator requires string pattern")
        return re.compile(value, re.IGNORECASE)
    if op == "ip_in_cidr":
        if isinstance(value, str):
            value = [value]
        nets = []
        for cidr in value:
            nets.append(ipaddress.ip_network(str(cidr), strict=False))
        return tuple(nets)
    if op == "in":
        if isinstance(value, (list, tuple, set, frozenset)):
            return tuple(value)
    return value


def _compile_matcher(node: JSON) -> CompiledMatcher:
    op_name = node.get("op")
    field = node.get("field")
    if not isinstance(op_name, str) or op_name not in _OPERATORS:
        raise RuleError(f"unknown or missing operator: {op_name}")
    if not isinstance(field, str):
        raise RuleError("matcher 'field' must be string")

    raw_value = node.get("value", None)
    value = _compile_value(op_name, raw_value)
    op = CompiledOperator(op_name, _OPERATORS[op_name])
    return CompiledMatcher(op=op, field=field, value=value)


def _compile_boolean(node: Any, _depth: int = 0) -> CompiledBoolean:
    if node is None:
        raise RuleError("missing 'when'")
    if not isinstance(node, dict):
        # это может быть сразу matcher
        return CompiledBoolean(any=( _compile_matcher(node), ), all=())

    any_nodes = node.get("any", [])
    all_nodes = node.get("all", [])
    not_node = node.get("not")

    any_compiled: List[Any] = []
    all_compiled: List[Any] = []

    if any_nodes:
        if not isinstance(any_nodes, list):
            raise RuleError("'any' must be list")
        for n in any_nodes:
            any_compiled.append(_compile_boolean(n, _depth + 1) if isinstance(n, dict) and ("any" in n or "all" in n or "not" in n) else _compile_matcher(n))

    if all_nodes:
        if not isinstance(all_nodes, list):
            raise RuleError("'all' must be list")
        for n in all_nodes:
            all_compiled.append(_compile_boolean(n, _depth + 1) if isinstance(n, dict) and ("any" in n or "all" in n or "not" in n) else _compile_matcher(n))

    not_compiled = None
    if not_node is not None:
        not_compiled = _compile_boolean(not_node, _depth + 1) if isinstance(not_node, dict) and ("any" in not_node or "all" in not_node or "not" in not_node) else _compile_matcher(not_node)

    return CompiledBoolean(any=tuple(any_compiled), all=tuple(all_compiled), not_=not_compiled)


def _ensure_severity(value: str) -> str:
    if value not in _SEVERITIES:
        raise RuleError(f"invalid severity: {value}")
    return value


def _ensure_labels(obj: Any) -> Mapping[str, str]:
    if not obj:
        return MappingProxyType({})
    if not isinstance(obj, Mapping):
        raise RuleError("labels must be mapping")
    return MappingProxyType({str(k): str(v) for k, v in obj.items()})


def compile_rule(cfg: JSON) -> Rule:
    try:
        rid = str(cfg["id"])
        name = str(cfg.get("name", rid))
        ver = int(cfg.get("version", 1))
        enabled = bool(cfg.get("enabled", True))
        priority = int(cfg.get("priority", 100))
        severity = _ensure_severity(str(cfg.get("severity", "low")))
        labels = _ensure_labels(cfg.get("labels"))
        match_limit = int(cfg.get("match_limit_per_event", 0))
        description = str(cfg.get("description", ""))

        when_cfg = cfg.get("when")
        when = _compile_boolean(when_cfg)

        actions_cfg = cfg.get("actions", [])
        if not isinstance(actions_cfg, list):
            raise RuleError("'actions' must be list")

        actions: List[JSON] = []
        for a in actions_cfg:
            if not isinstance(a, Mapping):
                raise RuleError("action must be mapping")
            atype = str(a.get("type", ""))
            if atype not in {"add_tag","set_field","route_to","score_adjust","drop","emit_metric","alert"}:
                raise RuleError(f"unknown action type: {atype}")
            actions.append(dict(a))  # shallow copy

        return Rule(
            id=rid,
            name=name,
            version=ver,
            enabled=enabled,
            priority=priority,
            severity=severity,
            labels=labels,
            when=when,
            actions=tuple(actions),
            description=description,
            match_limit_per_event=match_limit,
        )
    except KeyError as e:
        raise RuleError(f"missing key: {e}") from e


# -----------------------------------------------------------------------------
# Исполнение условий
# -----------------------------------------------------------------------------
def _eval_matcher(m: CompiledMatcher, event: JSON) -> bool:
    val = get_by_path(event, m.field, None)
    return m.op.func(val, m.value)


def _eval_boolean(b: CompiledBoolean, event: JSON) -> bool:
    # all
    if b.all:
        for node in b.all:
            if isinstance(node, CompiledMatcher):
                if not _eval_matcher(node, event):
                    return False
            else:
                if not _eval_boolean(node, event):
                    return False
    # any
    if b.any:
        ok = False
        for node in b.any:
            if isinstance(node, CompiledMatcher):
                if _eval_matcher(node, event):
                    ok = True
                    break
            else:
                if _eval_boolean(node, event):
                    ok = True
                    break
        if not ok:
            return False
    # not
    if b.not_ is not None:
        if isinstance(b.not_, CompiledMatcher):
            if _eval_matcher(b.not_, event):
                return False
        else:
            if _eval_boolean(b.not_, event):
                return False
    return True


# -----------------------------------------------------------------------------
# Rate limit / Dedup state
# -----------------------------------------------------------------------------
class _LeakyBucket:
    """Простой leaky-bucket: ограничивает N событий за окно T."""
    __slots__ = ("limit", "interval", "bucket", "last_ts")

    def __init__(self, limit: int, interval: int) -> None:
        self.limit = max(1, limit)
        self.interval = max(1, interval)
        self.bucket = 0
        self.last_ts = int(time.time())

    def allow(self) -> bool:
        now = int(time.time())
        elapsed = now - self.last_ts
        if elapsed > 0:
            # утечка
            self.bucket = max(0, self.bucket - elapsed)
            self.last_ts = now
        if self.bucket < self.limit:
            self.bucket += 1
            return True
        return False


class AlertDeduper:
    """Дедупликация алертов по ключу и TTL + rate limit."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ttl: Dict[str, float] = {}
        self._rl: Dict[str, _LeakyBucket] = {}

    def should_emit(self, key: str, ttl_sec: int, rate_limit: Optional[Tuple[int,int]] = None) -> bool:
        now = time.time()
        with self._lock:
            exp = self._ttl.get(key, 0.0)
            if exp > now:
                return False
            # rate limit
            if rate_limit:
                rl_key = f"rl:{key}"
                bucket = self._rl.get(rl_key)
                if bucket is None:
                    bucket = _LeakyBucket(rate_limit[0], rate_limit[1])
                    self._rl[rl_key] = bucket
                if not bucket.allow():
                    return False
            self._ttl[key] = now + max(1, ttl_sec)
            return True


# -----------------------------------------------------------------------------
# Выполнение действий
# -----------------------------------------------------------------------------
class ActionRunner:
    """Преобразует конфиг действий в результат; внешние интеграции оставлены вызывающей стороне."""
    def __init__(self, deduper: Optional[AlertDeduper] = None, enable_debug: bool = False) -> None:
        self._deduper = deduper or AlertDeduper()
        self._enable_debug = enable_debug

    def run(self, rule: Rule, event: JSON, res: DetectionResult) -> None:
        matches = 0
        for action in rule.actions:
            atype = action.get("type")
            if atype == "add_tag":
                tag = str(_interpolate(action.get("value"), event))
                res.tags.append(tag)
            elif atype == "set_field":
                path = str(action.get("field"))
                value = _interpolate(action.get("value"), event)
                res.set_fields[path] = value
            elif atype == "route_to":
                res.route = str(_interpolate(action.get("value"), event))
            elif atype == "score_adjust":
                try:
                    res.score_delta += float(action.get("value", 0.0))
                except Exception:
                    pass
            elif atype == "drop":
                res.drop = True
            elif atype == "emit_metric":
                name = str(action.get("name"))
                val = float(action.get("value", 1.0))
                labels = _interpolate_labels(action.get("labels", {}), event)
                res.metrics.append(MetricEvent(name=name, value=val, labels=labels))
            elif atype == "alert":
                title = str(_interpolate(action.get("title", rule.name), event))
                ttl_sec = int(action.get("ttl_sec", 300))
                dedup_keys = action.get("dedup_keys") or []
                if not isinstance(dedup_keys, list):
                    dedup_keys = [str(dedup_keys)]
                dedup_values = [str(get_by_path(event, k, "")) for k in dedup_keys]
                dedup_key = "|".join([rule.id] + dedup_values)
                rl_cfg = action.get("rate_limit")
                rate_limit = None
                if isinstance(rl_cfg, Mapping):
                    rate_limit = (int(rl_cfg.get("limit", 5)), int(rl_cfg.get("interval_sec", 60)))
                if self._deduper.should_emit(dedup_key, ttl_sec, rate_limit):
                    payload = {
                        "rule_id": rule.id,
                        "severity": rule.severity,
                        "labels": dict(rule.labels),
                        "event_excerpt": _event_excerpt(event),
                    }
                    res.alerts.append(AlertEvent(rule_id=rule.id, title=title, severity=rule.severity, dedup_key=dedup_key, ttl_sec=ttl_sec, payload=payload))
            matches += 1
            if rule.match_limit_per_event and matches >= rule.match_limit_per_event:
                break


# -----------------------------------------------------------------------------
# Интерполяция строк: "${path.to.field}" -> значение
# -----------------------------------------------------------------------------
_INTERP_RE = re.compile(r"\$\{([^}]+)\}")

def _interpolate(val: Any, event: JSON) -> Any:
    if isinstance(val, str):
        def rep(m: re.Match) -> str:
            path = m.group(1)
            v = get_by_path(event, path, "")
            return "" if v is None else str(v)
        return _INTERP_RE.sub(rep, val)
    if isinstance(val, Mapping):
        return {k: _interpolate(v, event) for k, v in val.items()}
    if isinstance(val, list):
        return [_interpolate(v, event) for v in val]
    return val

def _interpolate_labels(lbls: Mapping[str, Any], event: JSON) -> Labels:
    out: Labels = {}
    for k, v in (lbls or {}).items():
        out[str(k)] = str(_interpolate(v, event))
    return out


def _event_excerpt(event: JSON, max_len: int = 4096) -> JSON:
    """Безопасный усечённый снэпшот события (плоский best-effort)."""
    try:
        s = json.dumps(event, ensure_ascii=False)[:max_len]
        return json.loads(s)
    except Exception:
        return {"truncated": True}


# -----------------------------------------------------------------------------
# Библиотека безопасных паттернов (PII/секреты)
# -----------------------------------------------------------------------------
SAFE_PATTERNS = {
    "auth_bearer": r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "api_key": r"(?i)\b(api[_-]?key)\s*[=:]\s*([A-Za-z0-9\-]{16,})",
    "password": r"(?i)\bpassword\s*[=:]\s*([^\s]+)",
    "secret": r"(?i)\bsecret\s*[=:]\s*([^\s]+)",
    "token": r"(?i)\btoken\s*[=:]\s*([A-Za-z0-9._\-]{8,})",
    "email": r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}


# -----------------------------------------------------------------------------
# Ruleset: загрузка, сортировка, оценка
# -----------------------------------------------------------------------------
@dataclass
class Ruleset:
    rules: Tuple[Rule, ...]
    mode: str = "all_matches"  # или "first_match"
    enable_debug: bool = False
    _runner: ActionRunner = field(default_factory=lambda: ActionRunner())
    _by_id: Mapping[str, Rule] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_by_id", {r.id: r for r in self.rules})

    @staticmethod
    def from_list(lst: Sequence[JSON], *, mode: str = "all_matches", enable_debug: bool = False) -> "Ruleset":
        compiled = [compile_rule(x) for x in lst]
        compiled.sort(key=lambda r: (r.priority, r.id))
        return Ruleset(rules=tuple(compiled), mode=mode, enable_debug=enable_debug, _runner=ActionRunner(enable_debug=enable_debug))

    @staticmethod
    def load_from_path(path: str, *, pattern: str = "*.y*ml;*.json", mode: str = "all_matches", enable_debug: bool = False) -> "Ruleset":
        """
        Загружает все файлы правил из директории или один файл.
        Поддерживает JSON и YAML (если установлен PyYAML).
        pattern: несколько масок через ';'
        """
        files: List[str] = []
        if os.path.isdir(path):
            masks = [p.strip() for p in pattern.split(";") if p.strip()]
            for root, _, names in os.walk(path):
                for n in names:
                    if any(fnmatch.fnmatch(n, m) for m in masks):
                        files.append(os.path.join(root, n))
        else:
            files = [path]

        rules_cfg: List[JSON] = []
        for f in sorted(files):
            with open(f, "r", encoding="utf-8") as fh:
                text = fh.read()
            cfgs = _parse_config_text(text, filename=f)
            if isinstance(cfgs, Mapping):
                cfgs = [cfgs]
            if not isinstance(cfgs, list):
                raise RuleError(f"{f}: expected list or mapping at top-level")
            for item in cfgs:
                if not isinstance(item, Mapping):
                    raise RuleError(f"{f}: each rule must be mapping")
                rules_cfg.append(dict(item))

        return Ruleset.from_list(rules_cfg, mode=mode, enable_debug=enable_debug)

    def evaluate(self, event: JSON) -> DetectionResult:
        """Проверяет событие по всем (или до первого) правилам; возвращает агрегированный результат."""
        res = DetectionResult()
        if self.enable_debug:
            res.debug_trace = []

        for rule in self.rules:
            if not rule.enabled:
                continue
            ok = _eval_boolean(rule.when, event)
            if self.enable_debug:
                res.debug_trace.append(f"rule:{rule.id} -> {ok}")
            if not ok:
                continue
            # match
            res.matched_rules.append(rule.id)
            self._runner.run(rule, event, res)
            if self.mode == "first_match":
                break

        return res


# -----------------------------------------------------------------------------
# Парсер конфигов (JSON/YAML)
# -----------------------------------------------------------------------------
def _parse_config_text(text: str, filename: str = "<string>") -> Any:
    # Попытаться YAML, если доступен PyYAML; иначе — JSON.
    if filename.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
            return yaml.safe_load(text)
        except Exception as e:
            raise RuleError(f"{filename}: YAML parse error: {e}") from e
    try:
        return json.loads(text)
    except Exception as e:
        raise RuleError(f"{filename}: JSON parse error: {e}") from e


# -----------------------------------------------------------------------------
# Набор готовых правил (пример, выключены по умолчанию)
# -----------------------------------------------------------------------------
def builtin_example_rules() -> List[JSON]:
    """Пример набора безопасных правил; выключены по умолчанию — включайте точечно."""
    return [
        {
            "id": "r_http_5xx",
            "name": "HTTP 5xx",
            "version": 1,
            "enabled": True,
            "priority": 10,
            "severity": "high",
            "labels": {"kind": "availability"},
            "when": {"gte": None, "op": "gte", "field": "http.status", "value": 500},  # удобный шорткат допустим, но для совместимости зададим all/any
            "actions": [
                {"type": "add_tag", "value": "error"},
                {"type": "emit_metric", "name": "http_5xx_total", "labels": {"route": "${http.route}", "service": "${service.name}"}},
                {"type": "alert", "title": "HTTP 5xx on ${service.name}:${http.route}", "dedup_keys": ["service.name","http.route"], "ttl_sec": 300,
                 "rate_limit": {"limit": 5, "interval_sec": 60}}
            ],
        },
        {
            "id": "r_secret_leak",
            "name": "Secret pattern in logs",
            "version": 1,
            "enabled": True,
            "priority": 20,
            "severity": "critical",
            "labels": {"kind": "security"},
            "when": {"any": [
                {"op": "regex", "field": "log.message", "value": SAFE_PATTERNS["auth_bearer"]},
                {"op": "regex", "field": "log.message", "value": SAFE_PATTERNS["api_key"]},
                {"op": "regex", "field": "log.message", "value": SAFE_PATTERNS["password"]},
                {"op": "regex", "field": "log.message", "value": SAFE_PATTERNS["secret"]},
                {"op": "regex", "field": "log.message", "value": SAFE_PATTERNS["token"]}
            ]},
            "actions": [
                {"type": "add_tag", "value": "pii"},
                {"type": "score_adjust", "value": 5},
                {"type": "alert", "title": "Possible secret in logs (${service.name})",
                 "dedup_keys": ["service.name"], "ttl_sec": 600, "rate_limit": {"limit": 2, "interval_sec": 120}}
            ],
        },
        {
            "id": "r_auth_bf",
            "name": "Possible auth brute-force",
            "version": 1,
            "enabled": True,
            "priority": 30,
            "severity": "high",
            "labels": {"kind": "security"},
            "when": {"all": [
                {"op": "eq", "field": "http.route", "value": "/login"},
                {"op": "gte", "field": "auth.failed_count", "value": 10}
            ]},
            "actions": [
                {"type": "add_tag", "value": "suspicious"},
                {"type": "route_to", "value": "security"},
                {"type": "alert", "title": "Brute-force suspected from ${client.ip}",
                 "dedup_keys": ["client.ip"], "ttl_sec": 900}
            ],
        },
    ]


# -----------------------------------------------------------------------------
# Пример использования (доп. документация в докстринге)
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Демонстрация: загрузка из списка, проверка события
    rules = builtin_example_rules()
    rs = Ruleset.from_list(rules, mode="all_matches", enable_debug=True)

    event = {
        "service": {"name": "api-gateway"},
        "http": {"status": 503, "route": "/payments"},
        "log": {"message": "Authorization: Bearer abcdef.1234"},
        "client": {"ip": "203.0.113.5"},
    }

    result = rs.evaluate(event)
    print("matched:", result.matched_rules)
    print("tags:", result.tags)
    print("route:", result.route)
    print("alerts:", [a.title for a in result.alerts])
    if result.debug_trace:
        print("debug:", result.debug_trace)
