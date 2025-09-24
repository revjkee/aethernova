# mythos-core/mythos/dialogue/dsl.py
# Industrial-grade dialogue DSL and runtime for Mythos.
from __future__ import annotations

import ast
import json
import logging
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

log = logging.getLogger(__name__)

# =========================
# Exceptions
# =========================

class DSLValidationError(Exception):
    pass

class DSLSafetyError(Exception):
    pass

class NodeNotFoundError(Exception):
    pass

class TransitionError(Exception):
    pass


# =========================
# Enums and constants
# =========================

class NodeType(str, Enum):
    INPUT = "input"
    DIALOG = "dialog"
    CHOICE = "choice"
    TASK = "task"
    BRANCH = "branch"
    ENDING = "ending"

class EndingStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    ABANDONED = "abandoned"

ALLOWED_BUILTINS: Dict[str, Any] = {
    "len": len,
    "min": min,
    "max": max,
    "abs": abs,
    "int": int,
    "float": float,
    "str": str,
    "bool": bool,
    "round": round,
    "sum": sum,
    "any": any,
    "all": all,
}

_ALLOWED_AST_NODES = {
    ast.Expression,
    ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.IfExp,
    ast.Dict, ast.Set, ast.List, ast.Tuple,
    ast.Compare, ast.Name, ast.Load, ast.Constant,
    ast.Subscript, ast.Index, ast.Slice,
    ast.And, ast.Or, ast.Not,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq,
    ast.Call, ast.keyword, ast.Attribute,
}

# =========================
# Safe evaluation and templating
# =========================

def _assert_safe_ast(node: ast.AST) -> None:
    for child in ast.walk(node):
        if type(child) not in _ALLOWED_AST_NODES:
            raise DSLSafetyError(f"Disallowed expression node: {type(child).__name__}")
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                if child.func.id not in ALLOWED_BUILTINS and child.func.id not in {"get", "choice"}:
                    raise DSLSafetyError(f"Call to '{child.func.id}' is not allowed")
            elif isinstance(child.func, ast.Attribute):
                # Allow attribute access on whitelisted objects only (e.g., random.choice)
                if not isinstance(child.value, ast.Name) or child.value.id not in {"random", "context"}:
                    raise DSLSafetyError("Attribute calls only allowed on 'random' or 'context'")
        if isinstance(child, ast.Attribute):
            # Disallow dunder attributes
            if child.attr.startswith("__"):
                raise DSLSafetyError("Dunder attribute access is not allowed")

def safe_eval(expr: str, scope: Dict[str, Any]) -> Any:
    try:
        parsed = ast.parse(expr, mode="eval")
        _assert_safe_ast(parsed)
        return eval(compile(parsed, "<expr>", "eval"), {"__builtins__": {}}, scope)
    except DSLSafetyError:
        raise
    except Exception as e:
        raise DSLValidationError(f"Expression error '{expr}': {e}")

_TEMPLATE_RE = re.compile(r"\{\{\s*(.+?)\s*\}\}")

def render_template(template: str, scope: Dict[str, Any]) -> str:
    def repl(m: re.Match) -> str:
        expr = m.group(1)
        val = safe_eval(expr, scope)
        return str(val if val is not None else "")
    try:
        return _TEMPLATE_RE.sub(repl, template)
    except Exception as e:
        raise DSLValidationError(f"Template render error: {e}")


# =========================
# Validators
# =========================

@dataclass
class ValidationResult:
    ok: bool
    error: Optional[str] = None

class Validator:
    def validate(self, value: Any, i18n: "I18N") -> ValidationResult:
        return ValidationResult(ok=True)

@dataclass
class RegexValidator(Validator):
    pattern: str
    on_fail_text_ref: Optional[str] = None

    def validate(self, value: Any, i18n: "I18N") -> ValidationResult:
        s = str(value or "")
        if not re.fullmatch(self.pattern, s):
            msg = i18n.text(self.on_fail_text_ref) if self.on_fail_text_ref else "Invalid format"
            return ValidationResult(ok=False, error=msg)
        return ValidationResult(ok=True)

@dataclass
class LengthValidator(Validator):
    min: int = 0
    max: int = 2**31 - 1
    on_fail_text_ref: Optional[str] = None

    def validate(self, value: Any, i18n: "I18N") -> ValidationResult:
        s = str(value or "")
        if not (self.min <= len(s) <= self.max):
            msg = i18n.text(self.on_fail_text_ref) if self.on_fail_text_ref else "Invalid length"
            return ValidationResult(ok=False, error=msg)
        return ValidationResult(ok=True)

@dataclass
class RangeValidator(Validator):
    min: Optional[float] = None
    max: Optional[float] = None
    on_fail_text_ref: Optional[str] = None

    def validate(self, value: Any, i18n: "I18N") -> ValidationResult:
        try:
            v = float(value)
        except Exception:
            v = None
        ok = True if v is not None else False
        if ok and self.min is not None:
            ok = ok and v >= self.min
        if ok and self.max is not None:
            ok = ok and v <= self.max
        if not ok:
            msg = i18n.text(self.on_fail_text_ref) if self.on_fail_text_ref else "Out of range"
            return ValidationResult(ok=False, error=msg)
        return ValidationResult(ok=True)


# =========================
# I18N
# =========================

@dataclass
class I18N:
    default_locale: str
    supported: List[str]
    strings: Dict[str, Dict[str, str]]

    def text(self, key_or_text: Optional[str], locale: Optional[str] = None) -> str:
        if not key_or_text:
            return ""
        loc = locale or self.default_locale
        bucket = self.strings.get(loc, {})
        return bucket.get(key_or_text, key_or_text)


# =========================
# Telemetry and moderation adapters
# =========================

class TelemetrySink:
    def emit(self, event: str, payload: Dict[str, Any]) -> None:
        log.debug("telemetry_emit %s %s", event, payload)

class ModerationAdapter:
    def allow(self, user_text: str, context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        return True, None


# =========================
# State and Effects
# =========================

@dataclass
class SessionState:
    session_id: str
    quest_id: str
    locale: str
    node_id: str
    vars: Dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=lambda: time.time())
    turns: int = 0
    ended: bool = False
    ending_status: Optional[EndingStatus] = None

# Effect format: "vars.reputation = vars.reputation + 1", "emit('event',{...})"
_EFFECT_ASSIGN_RE = re.compile(r"^vars\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
_EFFECT_EMIT_RE = re.compile(r"^emit\(\s*'([A-Za-z0-9_.-]+)'\s*,\s*(\{.*\})\s*\)$")

def apply_effects(effects: List[str], scope: Dict[str, Any], telemetry: TelemetrySink, state: SessionState) -> None:
    for eff in effects or []:
        eff = eff.strip()
        if not eff:
            continue
        m = _EFFECT_ASSIGN_RE.match(eff)
        if m:
            var_name, expr = m.group(1), m.group(2)
            value = safe_eval(expr, scope)
            state.vars[var_name] = value
            continue
        m = _EFFECT_EMIT_RE.match(eff)
        if m:
            event_name, json_payload = m.group(1), m.group(2)
            try:
                payload = json.loads(json_payload)
            except Exception as e:
                raise DSLValidationError(f"Invalid emit payload: {e}")
            telemetry.emit(event_name, {"session_id": state.session_id, **payload})
            continue
        raise DSLValidationError(f"Unsupported effect syntax: {eff}")


# =========================
# Nodes and transitions
# =========================

@dataclass
class Transition:
    to: str
    when: str = "true"
    probability: Optional[float] = None
    effects: List[str] = field(default_factory=list)

@dataclass
class InputSpec:
    var: str
    validators: List[Validator] = field(default_factory=list)

@dataclass
class Node:
    id: str
    type: NodeType
    prompt_system: Optional[str] = None
    prompt_text: Optional[str] = None           # direct text or i18n key
    prompt_text_ref: Optional[str] = None       # i18n key
    user_template: Optional[str] = None
    choices: List[Dict[str, Any]] = field(default_factory=list)  # for DIALOG with explicit choices
    input: Optional[InputSpec] = None
    description: Optional[str] = None
    requirements: Dict[str, Any] = field(default_factory=dict)
    ending_status: Optional[EndingStatus] = None
    transitions: List[Transition] = field(default_factory=list)
    effects: List[str] = field(default_factory=list)

@dataclass
class Quest:
    id: str
    name: str
    start: str
    nodes: Dict[str, Node]
    i18n: I18N
    runtime_llm: Dict[str, Any] = field(default_factory=dict)
    runtime_limits: Dict[str, Any] = field(default_factory=dict)


# =========================
# Engine
# =========================

class DialogueEngine:
    def __init__(self, quest: Quest, telemetry: Optional[TelemetrySink] = None, moderation: Optional[ModerationAdapter] = None):
        self.quest = quest
        self.telemetry = telemetry or TelemetrySink()
        self.moderation = moderation or ModerationAdapter()

    def start_session(self, locale: Optional[str] = None, initial_vars: Optional[Dict[str, Any]] = None) -> SessionState:
        node_id = self.quest.start
        if node_id not in self.quest.nodes:
            raise NodeNotFoundError(f"Start node '{node_id}' not found")
        state = SessionState(
            session_id=str(uuid.uuid4()),
            quest_id=self.quest.id,
            locale=locale or self.quest.i18n.default_locale,
            node_id=node_id,
            vars=(initial_vars or {}).copy(),
        )
        self.telemetry.emit("quest_started", {"session_id": state.session_id, "quest_id": state.quest_id})
        return state

    def _scope(self, state: SessionState, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "vars": state.vars,
            "context": {"locale": state.locale, **(context or {})},
            "random": random,
            **ALLOWED_BUILTINS,
        }

    def render_node(self, state: SessionState) -> Dict[str, Any]:
        node = self.quest.nodes.get(state.node_id)
        if not node:
            raise NodeNotFoundError(f"Node '{state.node_id}' not found")
        scope = self._scope(state)
        out: Dict[str, Any] = {
            "node_id": node.id,
            "type": node.type.value,
            "choices": [],
        }
        if node.prompt_text_ref:
            out["text"] = self.quest.i18n.text(node.prompt_text_ref, state.locale)
        elif node.prompt_text:
            out["text"] = render_template(node.prompt_text, scope)
        else:
            out["text"] = ""

        if node.user_template:
            out["user_template"] = render_template(node.user_template, scope)
        if node.type == NodeType.DIALOG and node.choices:
            rendered = []
            for c in node.choices:
                text_ref = c.get("textRef")
                text = c.get("text")
                rendered.append({
                    "id": c.get("id", ""),
                    "text": self.quest.i18n.text(text_ref, state.locale) if text_ref else render_template(text or "", scope)
                })
            out["choices"] = rendered
        if node.type == NodeType.INPUT and node.input:
            out["input"] = {"var": node.input.var}
        if node.type == NodeType.ENDING:
            out["ending"] = {"status": node.ending_status.value if node.ending_status else None}
        return out

    def _select_transition(self, node: Node, state: SessionState, ctx: Optional[Dict[str, Any]] = None) -> Optional[Transition]:
        candidates: List[Tuple[Transition, float]] = []
        scope = self._scope(state, ctx)
        for t in node.transitions or []:
            cond = t.when or "true"
            try:
                ok = bool(safe_eval(cond, scope))
            except Exception:
                ok = False
            if not ok:
                continue
            prob = t.probability if t.probability is not None else 1.0
            if prob <= 0:
                continue
            candidates.append((t, prob))
        if not candidates:
            return None
        if len(candidates) == 1 and candidates[0][1] >= 1.0:
            return candidates[0][0]
        # Weighted choice
        total = sum(w for _, w in candidates)
        r = random.random() * total
        acc = 0.0
        for t, w in candidates:
            acc += w
            if r <= acc:
                return t
        return candidates[-1][0]

    def input_text(self, state: SessionState, text: str) -> Dict[str, Any]:
        """
        Process user's free-form text at current node. Returns rendered next node payload.
        """
        node = self.quest.nodes.get(state.node_id)
        if not node:
            raise NodeNotFoundError(f"Node '{state.node_id}' not found")
        if node.type not in {NodeType.INPUT, NodeType.DIALOG}:
            raise TransitionError(f"Node '{node.id}' does not accept free-form input")

        allowed, reason = self.moderation.allow(text, {"session_id": state.session_id, "node_id": node.id})
        if not allowed:
            raise DSLSafetyError(reason or "Input rejected")

        if node.type == NodeType.INPUT and node.input:
            # Validate
            for v in node.input.validators:
                res = v.validate(text, self.quest.i18n)
                if not res.ok:
                    return {
                        "node_id": node.id,
                        "type": node.type.value,
                        "error": res.error,
                    }
            # Assign variable
            state.vars[node.input.var] = text

        # Node-level effects before transitions
        apply_effects(node.effects, self._scope(state), self.telemetry, state)

        # Transition
        t = self._select_transition(node, state, {"_input": text})
        if not t:
            raise TransitionError(f"No valid transition from node '{node.id}'")
        apply_effects(t.effects, self._scope(state, {"_input": text}), self.telemetry, state)
        self._move(state, t.to)

        return self.render_node(state)

    def choose(self, state: SessionState, choice_id: str) -> Dict[str, Any]:
        """
        Choose a labeled option at DIALOG node.
        """
        node = self.quest.nodes.get(state.node_id)
        if not node or node.type != NodeType.DIALOG:
            raise TransitionError("Choice available only at dialog nodes with choices")
        # Optionally store last_choice
        state.vars["_last_choice"] = choice_id

        apply_effects(node.effects, self._scope(state), self.telemetry, state)
        t = self._select_transition(node, state, {"_choice": choice_id})
        if not t:
            raise TransitionError(f"No valid transition on choice '{choice_id}'")
        apply_effects(t.effects, self._scope(state, {"_choice": choice_id}), self.telemetry, state)
        self._move(state, t.to)
        return self.render_node(state)

    def _move(self, state: SessionState, to_node_id: str) -> None:
        if to_node_id not in self.quest.nodes:
            raise NodeNotFoundError(f"Destination node '{to_node_id}' not found")
        state.node_id = to_node_id
        state.turns += 1
        node = self.quest.nodes[to_node_id]
        if node.type == NodeType.ENDING:
            state.ended = True
            state.ending_status = node.ending_status
            self.telemetry.emit("quest_completed", {
                "session_id": state.session_id,
                "quest_id": state.quest_id,
                "result": node.ending_status.value if node.ending_status else None
            })


# =========================
# Builders and compilers
# =========================

def _build_validator(v: Dict[str, Any]) -> Validator:
    kind = (v.get("kind") or "").lower()
    if kind == "regex":
        return RegexValidator(pattern=v["pattern"], on_fail_text_ref=v.get("onFailTextRef"))
    if kind == "length":
        return LengthValidator(min=int(v.get("min", 0)), max=int(v.get("max", 2**31-1)), on_fail_text_ref=v.get("onFailTextRef"))
    if kind == "range":
        mn = v.get("min"); mx = v.get("max")
        return RangeValidator(min=float(mn) if mn is not None else None, max=float(mx) if mx is not None else None, on_fail_text_ref=v.get("onFailTextRef"))
    raise DSLValidationError(f"Unknown validator kind: {kind}")

def _build_transitions(raw_list: List[Dict[str, Any]]) -> List[Transition]:
    out: List[Transition] = []
    for t in raw_list or []:
        out.append(Transition(
            to=t["to"],
            when=t.get("when", "true"),
            probability=float(t["probability"]) if "probability" in t and t["probability"] is not None else None,
            effects=list(t.get("effects", [])),
        ))
    return out

def _build_node(n: Dict[str, Any]) -> Node:
    ntype = NodeType(n["type"])
    input_spec = None
    if "input" in n and n["input"]:
        inp = n["input"]
        validators = [_build_validator(v) for v in inp.get("validators", [])]
        input_spec = InputSpec(var=inp["var"], validators=validators)
    ending_status = EndingStatus(n["ending"]["status"]) if ntype == NodeType.ENDING and n.get("ending") else None
    return Node(
        id=n["id"],
        type=ntype,
        prompt_system=n.get("prompt", {}).get("system") if n.get("prompt") else n.get("prompt_system"),
        prompt_text_ref=(n.get("prompt", {}) or {}).get("textRef") or n.get("promptTextRef"),
        prompt_text=(n.get("prompt", {}) or {}).get("text") or n.get("promptText"),
        user_template=(n.get("prompt", {}) or {}).get("userTemplate") or n.get("userTemplate"),
        choices=n.get("choices", []),
        input=input_spec,
        description=n.get("description"),
        requirements=n.get("requirements", {}) or {},
        ending_status=ending_status,
        transitions=_build_transitions(n.get("transitions", [])),
        effects=list(n.get("effects", [])),
    )

def compile_from_dict(cfg: Dict[str, Any]) -> Quest:
    try:
        spec = cfg["spec"]
        i18n_raw = spec.get("i18n") or {
            "defaultLocale": cfg.get("metadata", {}).get("locale", "en-US"),
            "supportedLocales": [cfg.get("metadata", {}).get("locale", "en-US")],
            "strings": {},
        }
        i18n = I18N(
            default_locale=i18n_raw.get("defaultLocale", "en-US"),
            supported=i18n_raw.get("supportedLocales", ["en-US"]),
            strings=i18n_raw.get("strings", {}),
        )
        graph = spec["graph"]
        nodes_list = graph["nodes"]
        nodes = {}
        for n in nodes_list:
            node = _build_node(n)
            if node.id in nodes:
                raise DSLValidationError(f"Duplicate node id: {node.id}")
            nodes[node.id] = node
        start = graph["start"]
        if start not in nodes:
            raise DSLValidationError(f"Start node '{start}' not found among nodes")
        quest = Quest(
            id=cfg.get("metadata", {}).get("id") or cfg.get("id") or "quest",
            name=cfg.get("metadata", {}).get("name") or cfg.get("name") or "Quest",
            start=start,
            nodes=nodes,
            i18n=i18n,
            runtime_llm=spec.get("runtime", {}).get("llm", {}),
            runtime_limits={
                "turnSeconds": (spec.get("runtime", {}).get("timeouts", {}) or {}).get("turnSeconds", 30),
                "questTotalMinutes": (spec.get("runtime", {}).get("timeouts", {}) or {}).get("questTotalMinutes", 60),
            },
        )
        return quest
    except KeyError as e:
        raise DSLValidationError(f"Missing required key: {e}")

def compile_from_yaml(yaml_text: str) -> Quest:
    try:
        import yaml  # optional dependency
    except Exception:
        raise DSLValidationError("PyYAML is not installed; use compile_from_dict")
    try:
        data = yaml.safe_load(yaml_text)
        return compile_from_dict(data)
    except Exception as e:
        raise DSLValidationError(f"YAML parse error: {e}")


# =========================
# Pythonic DSL builder (for tests and programmatic definitions)
# =========================

class QuestBuilder:
    def __init__(self, quest_id: str, name: str, default_locale: str = "en-US"):
        self.quest_id = quest_id
        self.name = name
        self._nodes: Dict[str, Node] = {}
        self._start: Optional[str] = None
        self._i18n = I18N(default_locale=default_locale, supported=[default_locale], strings={default_locale: {}})

    def start(self, node_id: str) -> "QuestBuilder":
        self._start = node_id
        return self

    def i18n(self, locale: str, strings: Dict[str, str]) -> "QuestBuilder":
        self._i18n.strings.setdefault(locale, {}).update(strings)
        if locale not in self._i18n.supported:
            self._i18n.supported.append(locale)
        return self

    def node(self, node: Node) -> "QuestBuilder":
        if node.id in self._nodes:
            raise DSLValidationError(f"Duplicate node id: {node.id}")
        self._nodes[node.id] = node
        return self

    def build(self) -> Quest:
        if not self._start:
            raise DSLValidationError("Start node is not set")
        if self._start not in self._nodes:
            raise DSLValidationError(f"Start node '{self._start}' not found")
        return Quest(
            id=self.quest_id,
            name=self.name,
            start=self._start,
            nodes=self._nodes,
            i18n=self._i18n,
        )

# Convenience constructors
def InputNode(id: str, prompt_text_ref: Optional[str] = None, prompt_text: Optional[str] = None,
              var: str = "", validators: Optional[List[Validator]] = None, transitions: Optional[List[Transition]] = None,
              effects: Optional[List[str]] = None) -> Node:
    return Node(
        id=id, type=NodeType.INPUT, prompt_text_ref=prompt_text_ref, prompt_text=prompt_text,
        input=InputSpec(var=var, validators=validators or []),
        transitions=transitions or [], effects=effects or [],
    )

def DialogNode(id: str, prompt_text_ref: Optional[str] = None, prompt_text: Optional[str] = None,
               user_template: Optional[str] = None, choices: Optional[List[Dict[str, Any]]] = None,
               transitions: Optional[List[Transition]] = None, effects: Optional[List[str]] = None) -> Node:
    return Node(
        id=id, type=NodeType.DIALOG, prompt_text_ref=prompt_text_ref, prompt_text=prompt_text,
        user_template=user_template, choices=choices or [], transitions=transitions or [], effects=effects or [],
    )

def BranchNode(id: str, transitions: List[Transition]) -> Node:
    return Node(id=id, type=NodeType.BRANCH, transitions=transitions)

def TaskNode(id: str, description: str, transitions: List[Transition], effects: Optional[List[str]] = None) -> Node:
    return Node(id=id, type=NodeType.TASK, description=description, transitions=transitions, effects=effects or [])

def EndingNode(id: str, status: EndingStatus, prompt_text_ref: Optional[str] = None, prompt_text: Optional[str] = None) -> Node:
    return Node(id=id, type=NodeType.ENDING, ending_status=status, prompt_text_ref=prompt_text_ref, prompt_text=prompt_text)


# =========================
# Minimal self-test (used by unit tests)
# =========================

def _self_test() -> None:
    qb = QuestBuilder("quest.example", "Example", default_locale="en-US")
    qb.i18n("en-US", {"ask.name": "What is your name?", "victory": "Well done"})
    qb.start("intro")
    qb.node(InputNode(
        id="intro",
        prompt_text_ref="ask.name",
        var="player_name",
        validators=[LengthValidator(min=1, max=40)],
        transitions=[Transition(to="end", when="len(vars.player_name) > 0")]
    ))
    qb.node(EndingNode(id="end", status=EndingStatus.SUCCESS, prompt_text_ref="victory"))
    quest = qb.build()

    eng = DialogueEngine(quest)
    st = eng.start_session()
    assert eng.render_node(st)["text"] == "What is your name?"
    nxt = eng.input_text(st, "Aria")
    assert nxt["type"] == "ending" and nxt["ending"]["status"] == "success"

if __name__ == "__main__":
    _self_test()
