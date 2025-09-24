# cybersecurity-core/cybersecurity/ids/sigma_engine.py
from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # мягкая зависимость

try:
    import jsonschema  # type: ignore
except Exception:  # pragma: no cover
    jsonschema = None

logger = logging.getLogger(__name__)


# =============================================================================
# Errors
# =============================================================================

class SigmaEngineError(Exception):
    """Base error for Sigma engine."""


class SigmaRuleLoadError(SigmaEngineError):
    """Raised when rule cannot be loaded or parsed."""


class SigmaRuleValidationError(SigmaEngineError):
    """Raised when rule is structurally invalid."""


class SigmaConditionParseError(SigmaEngineError):
    """Raised when condition string cannot be parsed."""


# =============================================================================
# AST for matching
# =============================================================================

class Expr:
    """Base expression node."""

    def evaluate(self, event: Mapping[str, Any]) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def to_es(self) -> Dict[str, Any]:  # pragma: no cover - interface
        """Return simplified Elasticsearch query DSL."""
        raise NotImplementedError

    def to_sql(self) -> str:  # pragma: no cover - interface
        """Return simplified SQL WHERE condition."""
        raise NotImplementedError


@dataclass(frozen=True)
class TrueExpr(Expr):
    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return True

    def to_es(self) -> Dict[str, Any]:
        return {"match_all": {}}

    def to_sql(self) -> str:
        return "1=1"


@dataclass(frozen=True)
class FalseExpr(Expr):
    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return False

    def to_es(self) -> Dict[str, Any]:
        return {"bool": {"must_not": [{"match_all": {}}]}}

    def to_sql(self) -> str:
        return "1=0"


@dataclass(frozen=True)
class AndExpr(Expr):
    items: Tuple[Expr, ...]

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return all(it.evaluate(event) for it in self.items)

    def to_es(self) -> Dict[str, Any]:
        return {"bool": {"must": [it.to_es() for it in self.items]}}

    def to_sql(self) -> str:
        return "(" + " AND ".join(it.to_sql()) + ")"


@dataclass(frozen=True)
class OrExpr(Expr):
    items: Tuple[Expr, ...]

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return any(it.evaluate(event) for it in self.items)

    def to_es(self) -> Dict[str, Any]:
        return {"bool": {"should": [it.to_es() for it in self.items], "minimum_should_match": 1}}

    def to_sql(self) -> str:
        return "(" + " OR ".join(it.to_sql()) + ")"


@dataclass(frozen=True)
class NotExpr(Expr):
    item: Expr

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return not self.item.evaluate(event)

    def to_es(self) -> Dict[str, Any]:
        return {"bool": {"must_not": [self.item.to_es()]}}

    def to_sql(self) -> str:
        return "(NOT " + self.item.to_sql() + ")"


# ---- Field comparators -------------------------------------------------------

def _get_field(event: Mapping[str, Any], path: str) -> Any:
    """
    Dot-path getter with safe descent: 'a.b.c'.
    If path not found returns None.
    """
    cur: Any = event
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _as_str(x: Any) -> Optional[str]:
    if x is None:
        return None
    if isinstance(x, str):
        return x
    try:
        return str(x)
    except Exception:
        return None


def _value_in_iterable(val: Any, container: Any) -> bool:
    if isinstance(container, (list, tuple, set)):
        return val in container
    # treat comma-separated strings as list
    if isinstance(container, str) and "," in container:
        return val in [s.strip() for s in container.split(",")]
    return False


@dataclass(frozen=True)
class MatchExpr(Expr):
    """
    Field match with operator.
    Supported ops: eq, wildcard, regex, contains, startswith, endswith, cidr, in
    """
    field: str
    op: str
    value: Any

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        v = _get_field(event, self.field)
        if self.op == "eq":
            if isinstance(self.value, (list, tuple, set)):
                return v in self.value
            return v == self.value
        if self.op == "wildcard":
            s = _as_str(v)
            return s is not None and fnmatch.fnmatch(s, str(self.value))
        if self.op == "regex":
            s = _as_str(v)
            return s is not None and re.search(self.value, s) is not None
        if self.op == "contains":
            if isinstance(v, str):
                return str(self.value) in v
            return _value_in_iterable(self.value, v)
        if self.op == "startswith":
            s = _as_str(v)
            return s is not None and s.startswith(str(self.value))
        if self.op == "endswith":
            s = _as_str(v)
            return s is not None and s.endswith(str(self.value))
        if self.op == "cidr":
            try:
                if v is None:
                    return False
                ip = ipaddress.ip_address(str(v))
                net = ipaddress.ip_network(str(self.value), strict=False)
                return ip in net
            except Exception:
                return False
        if self.op == "in":
            return _value_in_iterable(v, self.value)
        return False

    def to_es(self) -> Dict[str, Any]:
        if self.op == "eq":
            if isinstance(self.value, (list, tuple, set)):
                return {"terms": {self.field: list(self.value)}}
            return {"term": {self.field: self.value}}
        if self.op == "wildcard":
            return {"wildcard": {self.field: str(self.value)}}
        if self.op == "regex":
            return {"regexp": {self.field: str(self.value)}}
        if self.op == "contains":
            # ES does not have universal contains; use wildcard "*x*"
            return {"wildcard": {self.field: f"*{self.value}*"}}
        if self.op == "startswith":
            return {"prefix": {self.field: str(self.value)}}
        if self.op == "endswith":
            return {"wildcard": {self.field: f"*{self.value}"}}
        if self.op == "cidr":
            return {"term": {self.field: str(self.value)}}  # simplification
        if self.op == "in":
            return {"terms": {self.field: list(self.value)}}
        return {"match_none": {}}

    def to_sql(self) -> str:
        val = self.value
        if self.op == "eq":
            if isinstance(val, (list, tuple, set)):
                inside = ", ".join(_sql_quote(v) for v in val)
                return f"{_sql_ident(self.field)} IN ({inside})"
            return f"{_sql_ident(self.field)} = {_sql_quote(val)}"
        if self.op == "wildcard":
            like = str(val).replace("*", "%").replace("?", "_")
            return f"{_sql_ident(self.field)} LIKE {_sql_quote(like)}"
        if self.op == "regex":
            return f"{_sql_ident(self.field)} ~ {_sql_quote(str(val))}"
        if self.op == "contains":
            return f"{_sql_ident(self.field)} LIKE {_sql_quote('%' + str(val) + '%')}"
        if self.op == "startswith":
            return f"{_sql_ident(self.field)} LIKE {_sql_quote(str(val) + '%')}"
        if self.op == "endswith":
            return f"{_sql_ident(self.field)} LIKE {_sql_quote('%' + str(val))}"
        if self.op == "cidr":
            # SQL backend dependent; leave as equality for simplicity
            return f"{_sql_ident(self.field)} = {_sql_quote(str(val))}"
        if self.op == "in":
            inside = ", ".join(_sql_quote(v) for v in val)
            return f"{_sql_ident(self.field)} IN ({inside})"
        return "1=0"


def _sql_ident(name: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9_.]', "_", name)
    return '"' + safe.replace('"', "") + '"'


def _sql_quote(val: Any) -> str:
    if val is None:
        return "NULL"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val).replace("'", "''")
    return f"'{s}'"


@dataclass(frozen=True)
class CountOfExpr(Expr):
    """At least min_count (and optionally at most max_count) of selections must match."""
    choices: Tuple[Tuple[str, Expr], ...]
    min_count: int = 1
    max_count: Optional[int] = None  # None => unlimited

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        matched = 0
        for name, ex in self.choices:
            if ex.evaluate(event):
                matched += 1
        if matched < self.min_count:
            return False
        if self.max_count is not None and matched > self.max_count:
            return False
        return True

    def to_es(self) -> Dict[str, Any]:
        should = [ex.to_es() for _, ex in self.choices]
        return {"bool": {"should": should, "minimum_should_match": self.min_count}}

    def to_sql(self) -> str:
        parts = [f"CASE WHEN {ex.to_sql()} THEN 1 ELSE 0 END" for _, ex in self.choices]
        return "(" + " + ".join(parts) + f") >= {self.min_count}" + (
            f" AND (" + " + ".join(parts) + f") <= {self.max_count}" if self.max_count is not None else ""
        )


# =============================================================================
# Condition parser (Sigma-like)
# Supports: identifiers, 'and'/'or'/'not', parentheses,
# 'any of <group>', 'all of <group>', 'N of <group>', group can be 'them' or 'name*'
# =============================================================================

_TOKEN_SPEC = [
    ("WS", r"[ \t\n\r]+"),
    ("LP", r"\("),
    ("RP", r"\)"),
    ("AND", r"(?i)\band\b"),
    ("OR", r"(?i)\bor\b"),
    ("NOT", r"(?i)\bnot\b"),
    ("ANY", r"(?i)\bany\b"),
    ("ALL", r"(?i)\ball\b"),
    ("OF", r"(?i)\bof\b"),
    ("THEM", r"(?i)\bthem\b"),
    ("NUM", r"\b\d+\b"),
    ("ID", r"[A-Za-z_][A-Za-z0-9_]*\*?"),
]

_TOKEN_RE = re.compile("|".join(f"(?P<{n}>{p})" for n, p in _TOKEN_SPEC))


@dataclass
class _Token:
    kind: str
    text: str


def _tokenize(s: str) -> List[_Token]:
    pos = 0
    out: List[_Token] = []
    while pos < len(s):
        m = _TOKEN_RE.match(s, pos)
        if not m:
            raise SigmaConditionParseError(f"Unexpected token at {s[pos:pos+20]!r}")
        kind = m.lastgroup or ""
        if kind != "WS":
            out.append(_Token(kind, m.group(0)))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, tokens: List[_Token], index: int = 0):
        self.toks = tokens
        self.i = index

    def peek(self) -> Optional[_Token]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def eat(self, kind: str) -> _Token:
        t = self.peek()
        if not t or t.kind != kind:
            raise SigmaConditionParseError(f"Expected {kind}, got {t.kind if t else 'EOF'}")
        self.i += 1
        return t

    def match(self, kind: str) -> Optional[_Token]:
        if self.peek() and self.peek().kind == kind:
            return self.eat(kind)
        return None

    # Grammar:
    # expr := term (OR term)*
    # term := factor (AND factor)*
    # factor := NOT factor | group | ID | '(' expr ')'
    # group := (ANY|ALL|NUM) OF (THEM|ID)
    def parse(self) -> List[_Token]:
        return self.toks

    def parse_expr(self, builder: "ConditionBuilder") -> Expr:
        node = self.parse_term(builder)
        while self.match("OR"):
            right = self.parse_term(builder)
            node = OrExpr((node, right))
        return node

    def parse_term(self, builder: "ConditionBuilder") -> Expr:
        node = self.parse_factor(builder)
        while self.match("AND"):
            right = self.parse_factor(builder)
            node = AndExpr((node, right))
        return node

    def parse_factor(self, builder: "ConditionBuilder") -> Expr:
        if self.match("NOT"):
            return NotExpr(self.parse_factor(builder))
        if self.match("LP"):
            n = self.parse_expr(builder)
            self.eat("RP")
            return n
        # group forms
        t = self.peek()
        if t and t.kind in ("ANY", "ALL", "NUM"):
            return self.parse_group(builder)
        # identifier selection
        t = self.eat("ID")
        return builder.selection_ref(t.text)

    def parse_group(self, builder: "ConditionBuilder") -> Expr:
        # ANY|ALL|NUM OF (THEM|ID)
        first = self.peek()
        if self.match("ANY"):
            self.eat("OF")
            target = self._parse_group_target()
            return builder.group_of("any", target)
        if self.match("ALL"):
            self.eat("OF")
            target = self._parse_group_target()
            return builder.group_of("all", target)
        num_tok = self.eat("NUM")
        self.eat("OF")
        target = self._parse_group_target()
        return builder.group_of(int(num_tok.text), target)

    def _parse_group_target(self) -> str:
        if self.match("THEM"):
            return "them"
        t = self.eat("ID")
        return t.text


# =============================================================================
# Compiler from Sigma rule dict to Expr
# =============================================================================

def _normalize_value(val: Any) -> Any:
    # Strings delimited with /.../ => regex (without trailing flags handling here)
    if isinstance(val, str) and len(val) >= 2 and val.startswith("/") and val.endswith("/"):
        return {"regex": val[1:-1]}
    return val


@dataclass
class SigmaCompiled:
    rule_id: str
    title: str
    expr: Expr
    meta: Dict[str, Any] = field(default_factory=dict)

    def evaluate(self, event: Mapping[str, Any]) -> bool:
        return self.expr.evaluate(event)

    def to_es(self) -> Dict[str, Any]:
        return self.expr.to_es()

    def to_sql(self) -> str:
        return self.expr.to_sql()


class ConditionBuilder:
    def __init__(self, selections: Dict[str, Expr]):
        self.selections = selections

    def selection_ref(self, name: str) -> Expr:
        if name.endswith("*"):
            prefix = name[:-1]
            matched = sorted([(k, v) for k, v in self.selections.items() if k.startswith(prefix)], key=lambda x: x[0])
            if not matched:
                raise SigmaConditionParseError(f"No selections match prefix '{prefix}*'")
            return OrExpr(tuple(e for _, e in matched))
        if name not in self.selections:
            raise SigmaConditionParseError(f"Unknown selection '{name}'")
        return self.selections[name]

    def group_of(self, kind: Union[str, int], target: str) -> Expr:
        # target: 'them' or name/prefix with optional '*'
        if target == "them":
            items = list(self.selections.items())
        else:
            if target.endswith("*"):
                prefix = target[:-1]
                items = [(k, v) for k, v in self.selections.items() if k.startswith(prefix)]
            else:
                if target not in self.selections:
                    raise SigmaConditionParseError(f"Unknown selection '{target}'")
                items = [(target, self.selections[target])]
        if not items:
            raise SigmaConditionParseError("Group 'of' expanded to empty set")

        if kind == "any":
            return CountOfExpr(tuple(items), min_count=1)
        if kind == "all":
            return CountOfExpr(tuple(items), min_count=len(items))
        if isinstance(kind, int):
            if kind < 0:
                raise SigmaConditionParseError("Negative count not allowed")
            return CountOfExpr(tuple(items), min_count=kind)
        raise SigmaConditionParseError(f"Invalid group kind: {kind}")


class SigmaCompiler:
    """
    Compile Sigma rule dict into executable Expr.
    Supports:
      - selection bodies with:
          * field: value
          * field: [v1, v2, ...]  (OR)
          * field|contains / |startswith / |endswith
          * field: {"regex": "..."} or "/.../"
          * field: {"cidr": "1.2.3.0/24"}
          * field: {"in": [a,b,c]}
          * wildcards in string values ('*','?') -> wildcard match
      - condition string with AND/OR/NOT, parentheses
      - ANY/ALL/N OF them / name* groups
    """

    OP_SUFFIXES = {"contains", "startswith", "endswith", "re", "regex", "cidr", "in"}

    def compile(self, rule: Mapping[str, Any]) -> SigmaCompiled:
        # Basic structural validation
        for key in ("title", "detection"):
            if key not in rule:
                raise SigmaRuleValidationError(f"Missing required key: {key}")

        rule_id = str(rule.get("id", rule.get("rule_id", rule.get("title"))))
        title = str(rule["title"])
        detection = rule["detection"]
        if not isinstance(detection, Mapping):
            raise SigmaRuleValidationError("detection must be a mapping")

        selections_raw: Dict[str, Any] = {}
        condition: Optional[str] = None

        for k, v in detection.items():
            if k == "condition":
                condition = str(v)
            else:
                selections_raw[k] = v

        if not condition:
            # default: OR over all selections
            condition = "any of them"

        # Build selection expressions
        selections_compiled: Dict[str, Expr] = {}
        for name, body in selections_raw.items():
            ex = self._compile_selection(body)
            selections_compiled[name] = ex

        # Parse condition using compiled selections
        tokens = _tokenize(condition)
        parser = _Parser(tokens)
        builder = ConditionBuilder(selections_compiled)
        expr = parser.parse_expr(builder)

        meta = {
            "level": rule.get("level"),
            "logsource": rule.get("logsource"),
            "tags": rule.get("tags") or [],
            "references": rule.get("references") or [],
        }
        return SigmaCompiled(rule_id=rule_id, title=title, expr=expr, meta=meta)

    def _compile_selection(self, body: Any) -> Expr:
        """
        Selection body to Expr:
          - dict of field -> matchers combined with AND.
          - list of dicts => OR of compiled dicts.
        """
        if isinstance(body, list):
            parts = [self._compile_selection(it) for it in body]
            return OrExpr(tuple(parts))
        if isinstance(body, Mapping):
            return self._compile_field_map(body)
        raise SigmaRuleValidationError(f"Unsupported selection type: {type(body)!r}")

    def _compile_field_map(self, m: Mapping[str, Any]) -> Expr:
        items: List[Expr] = []
        for raw_key, raw_val in m.items():
            field, op = self._split_field_op(str(raw_key))
            val = _normalize_value(raw_val)

            # Dict value with explicit operator
            if isinstance(val, Mapping):
                if "regex" in val:
                    items.append(MatchExpr(field, "regex", str(val["regex"])))
                    continue
                if "cidr" in val:
                    items.append(MatchExpr(field, "cidr", str(val["cidr"])))
                    continue
                if "in" in val:
                    items.append(MatchExpr(field, "in", list(val["in"])))
                    continue
                # fallback: all sub-conditions ANDed
                sub = [MatchExpr(field, k, v) for k, v in val.items()]
                items.append(AndExpr(tuple(sub)))
                continue

            # List value => OR of equals/wildcards
            if isinstance(val, list):
                sub: List[Expr] = []
                for it in val:
                    it = _normalize_value(it)
                    sub.append(self._match_for_value(field, op, it))
                items.append(OrExpr(tuple(sub)))
                continue

            items.append(self._match_for_value(field, op, val))

        if not items:
            return TrueExpr()
        if len(items) == 1:
            return items[0]
        return AndExpr(tuple(items))

    def _split_field_op(self, raw: str) -> Tuple[str, Optional[str]]:
        # Supports "field|contains"
        if "|" in raw:
            field, suffix = raw.split("|", 1)
            suffix = suffix.strip().lower()
            if suffix in self.OP_SUFFIXES:
                if suffix in ("re", "regex"):
                    return field, "regex"
                return field, suffix
        return raw, None

    def _match_for_value(self, field: str, op_hint: Optional[str], val: Any) -> Expr:
        if isinstance(val, str):
            if op_hint:
                return MatchExpr(field, op_hint, val)
            if "*" in val or "?" in val:
                return MatchExpr(field, "wildcard", val)
            return MatchExpr(field, "eq", val)
        if isinstance(val, (int, float, bool)) or val is None:
            return MatchExpr(field, "eq", val)
        if isinstance(val, Mapping) and "regex" in val:
            return MatchExpr(field, "regex", str(val["regex"]))
        return MatchExpr(field, "eq", val)


# =============================================================================
# Rule registry and high-level engine
# =============================================================================

@dataclass
class SigmaRule:
    raw: Dict[str, Any]
    compiled: SigmaCompiled


class SigmaEngine:
    """
    High-level API:
      engine = SigmaEngine()
      engine.load_paths(["rules/**/*.yml"])
      matches = engine.evaluate(event_dict)  # -> list of SigmaCompiled
    """
    def __init__(self, validate_schema: bool = True):
        self._rules: List[SigmaRule] = []
        self._lock = threading.RLock()
        self._compiler = SigmaCompiler()
        self._validate = validate_schema

    # ----- Loading & Validation ------------------------------------------------

    def load_paths(self, globs: Sequence[Union[str, Path]]) -> int:
        count = 0
        for g in globs:
            for p in Path().glob(str(g)):
                if p.is_file() and p.suffix.lower() in (".yml", ".yaml"):
                    self.load_file(p)
                    count += 1
        return count

    def load_file(self, path: Union[str, Path]) -> SigmaCompiled:
        try:
            data = path.read_text(encoding="utf-8")
        except Exception as e:  # pragma: no cover
            raise SigmaRuleLoadError(f"Cannot read {path}: {e}") from e
        return self.load_rule_text(data, source=str(path))

    def load_rule_text(self, text: str, source: str = "<inline>") -> SigmaCompiled:
        rule = self._parse_yaml_or_json(text, source)
        self._maybe_validate(rule, source)
        compiled = self._compiler.compile(rule)
        with self._lock:
            self._rules.append(SigmaRule(raw=rule, compiled=compiled))
        logger.info("sigma_rule_loaded", extra={"id": compiled.rule_id, "title": compiled.title, "source": source})
        return compiled

    def _parse_yaml_or_json(self, text: str, source: str) -> Dict[str, Any]:
        if yaml:
            try:
                obj = yaml.safe_load(text)
                if not isinstance(obj, Mapping):
                    raise SigmaRuleLoadError(f"{source}: document is not a mapping")
                return dict(obj)
            except Exception as e:
                raise SigmaRuleLoadError(f"{source}: YAML parse error: {e}") from e
        # Fallback to JSON
        try:
            obj = json.loads(text)
            if not isinstance(obj, Mapping):
                raise SigmaRuleLoadError(f"{source}: document is not a mapping")
            return dict(obj)
        except Exception as e:  # pragma: no cover
            raise SigmaRuleLoadError(f"{source}: JSON parse error: {e}") from e

    def _maybe_validate(self, rule: Mapping[str, Any], source: str) -> None:
        if not self._validate or not jsonschema:
            return
        # Minimal Sigma skeleton schema (non-exhaustive; ensures essential keys)
        schema = {
            "type": "object",
            "required": ["title", "detection"],
            "properties": {
                "id": {"type": ["string", "number"]},
                "title": {"type": "string"},
                "level": {"type": ["string", "number", "null"]},
                "logsource": {"type": ["object", "null"]},
                "tags": {"type": ["array", "null"]},
                "references": {"type": ["array", "null"]},
                "detection": {"type": "object"},
            },
            "additionalProperties": True,
        }
        try:
            jsonschema.validate(instance=rule, schema=schema)  # type: ignore
        except Exception as e:
            raise SigmaRuleValidationError(f"{source}: schema validation failed: {e}") from e

    # ----- Evaluation ----------------------------------------------------------

    @property
    def rules(self) -> List[SigmaCompiled]:
        with self._lock:
            return [r.compiled for r in self._rules]

    def evaluate(self, event: Mapping[str, Any]) -> List[SigmaCompiled]:
        matched: List[SigmaCompiled] = []
        with self._lock:
            for r in self._rules:
                try:
                    if r.compiled.evaluate(event):
                        matched.append(r.compiled)
                except Exception:
                    logger.exception("sigma_evaluate_error", extra={"rule": r.compiled.rule_id})
        return matched

    # ----- Utilities -----------------------------------------------------------

    def to_es(self, rule_id: str) -> Dict[str, Any]:
        r = self._find(rule_id)
        return r.to_es()

    def to_sql(self, rule_id: str) -> str:
        r = self._find(rule_id)
        return r.to_sql()

    def _find(self, rule_id: str) -> SigmaCompiled:
        with self._lock:
            for r in self._rules:
                if r.compiled.rule_id == rule_id:
                    return r.compiled
        raise SigmaEngineError(f"Rule not found: {rule_id}")


# =============================================================================
# Public helpers
# =============================================================================

def compile_sigma_rule(rule: Mapping[str, Any]) -> SigmaCompiled:
    """Compile a single Sigma rule dict to executable form."""
    return SigmaCompiler().compile(rule)


def evaluate_event(compiled_rules: Iterable[SigmaCompiled], event: Mapping[str, Any]) -> List[SigmaCompiled]:
    """Evaluate event against a list of compiled rules and return matches."""
    out: List[SigmaCompiled] = []
    for r in compiled_rules:
        try:
            if r.evaluate(event):
                out.append(r)
        except Exception:
            logger.exception("evaluate_event_error", extra={"rule": r.rule_id})
    return out
