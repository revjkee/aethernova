# file: zero-trust-core/zero_trust/policy/translators/cedar_adapter.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# ============================================================================
# Внутренняя нормализованная модель политик (минимальный, но промышленный AST)
# ============================================================================

JsonPrimitive = Union[str, int, float, bool]
JsonValue = Union[JsonPrimitive, Sequence["JsonValue"], Mapping[str, "JsonValue"]]


class Effect(str, Enum):
    PERMIT = "permit"
    FORBID = "forbid"


@dataclass(frozen=True)
class EntityUID:
    """Литерал сущности Cedar: Type::"id"."""
    type: str
    id: str


# ---- Атрибуты и значения -----------------------------------------------------

@dataclass(frozen=True)
class AttrRef:
    """Ссылка на атрибут principal|resource|context: e.g. principal.department.name"""
    root: str  # "principal" | "resource" | "context"
    path: Tuple[str, ...]


Value = Union[JsonPrimitive, EntityUID, AttrRef, "SetLiteral"]


@dataclass(frozen=True)
class SetLiteral:
    items: Tuple[Value, ...]


# ---- Булевы и сравнения ------------------------------------------------------

class Op(str, Enum):
    EQ = "=="
    NE = "!="
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="
    IN = "in"


@dataclass(frozen=True)
class BinOp:
    left: Value
    op: Op
    right: Value


@dataclass(frozen=True)
class Not:
    expr: "Expr"


@dataclass(frozen=True)
class And:
    terms: Tuple["Expr", ...]


@dataclass(frozen=True)
class Or:
    terms: Tuple["Expr", ...]


Expr = Union[BinOp, Not, And, Or]

# ---- Политика ----------------------------------------------------------------

@dataclass(frozen=True)
class Policy:
    id: str
    effect: Effect
    principal_type: str
    action_ids: Tuple[str, ...]          # список идентификаторов действий (Action::"id")
    resource_type: str
    when: Optional[Expr] = None
    unless: Optional[Expr] = None
    description: Optional[str] = None
    annotations: Mapping[str, JsonValue] = field(default_factory=dict)  # произвольные аннотации


# ============================================================================
# Рендерер Cedar
# ============================================================================

_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(::[A-Za-z][A-Za-z0-9_]*)*$")
_ROOTS = {"principal", "resource", "context"}


class CedarRenderError(ValueError):
    pass


def _escape_str(s: str) -> str:
    return (
        '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t") + '"'
    )


def _validate_type_name(name: str) -> None:
    if not _IDENT_RE.match(name):
        raise CedarRenderError(f"Invalid Cedar type/namespace identifier: {name}")


def _render_entity_uid(u: EntityUID) -> str:
    _validate_type_name(u.type)
    return f'{u.type}::{_escape_str(u.id)}'


def _render_attr_ref(a: AttrRef) -> str:
    if a.root not in _ROOTS:
        raise CedarRenderError(f"Invalid attribute root: {a.root}")
    if not a.path:
        raise CedarRenderError("Attribute path cannot be empty")
    # Cedar атрибуты — через точку, без кавычек (ожидается нормализация имён на стороне домена)
    for seg in a.path:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", seg):
            raise CedarRenderError(f"Invalid attribute segment: {seg}")
    return f'{a.root}.' + ".".join(a.path)


def _render_set_literal(s: SetLiteral) -> str:
    return "[" + ", ".join(_render_value(v) for v in s.items) + "]"


def _render_value(v: Value) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        # Cedar поддерживает целые/вещественные — используем Python‑представление
        return str(v)
    if isinstance(v, str):
        return _escape_str(v)
    if isinstance(v, EntityUID):
        return _render_entity_uid(v)
    if isinstance(v, AttrRef):
        return _render_attr_ref(v)
    if isinstance(v, SetLiteral):
        return _render_set_literal(v)
    raise CedarRenderError(f"Unsupported value type: {type(v)}")


def _paren(expr_s: str) -> str:
    return f"({expr_s})"


def _render_expr(e: Expr) -> str:
    if isinstance(e, BinOp):
        # Специальный случай для члена множества: left in [..] или left in set
        if e.op is Op.IN:
            return f"{_render_value(e.left)} in {_render_value(e.right)}"
        return f"{_render_value(e.left)} {e.op.value} {_render_value(e.right)}"
    if isinstance(e, Not):
        inner = _render_expr(e.expr)
        return f"!{_paren(inner)}"
    if isinstance(e, And):
        if not e.terms:
            return "true"
        return _paren(" && ".join(_render_expr(t) for t in e.terms))
    if isinstance(e, Or):
        if not e.terms:
            return "false"
        return _paren(" || ".join(_render_expr(t) for t in e.terms))
    raise CedarRenderError(f"Unsupported expr type: {type(e)}")


def _render_header(effect: Effect, principal_type: str, action_ids: Sequence[str], resource_type: str) -> str:
    _validate_type_name(principal_type)
    _validate_type_name(resource_type)
    # Действия: Action::"id" — тип Action предполагается по умолчанию; при необходимости укажите namespace в id до ::
    actions = ", ".join(f'Action::{_escape_str(a)}' for a in action_ids)
    return (
        f"{effect.value}(\n"
        f"  principal is {principal_type},\n"
        f"  action in [{actions}],\n"
        f"  resource is {resource_type}\n"
        f")"
    )


def _render_when_unless(when: Optional[Expr], unless: Optional[Expr]) -> str:
    parts: List[str] = []
    if when is not None:
        parts.append("when {\n    " + _render_expr(when).replace("\n", "\n    ") + "\n  }")
    if unless is not None:
        parts.append("unless {\n    " + _render_expr(unless).replace("\n", "\n    ") + "\n  }")
    return ("\n  " + "\n  ".join(parts)) if parts else ""


def render_policy_to_cedar(p: Policy) -> str:
    """Рендерит одну политику Cedar (как statement; ID и аннотации добавляются комментариями)."""
    if not p.id or not re.match(r"^[A-Za-z0-9_.:-]{1,256}$", p.id):
        raise CedarRenderError(f"Invalid policy id: {p.id!r}")
    if not p.action_ids:
        raise CedarRenderError("Policy must declare at least one action id")
    hdr = _render_header(p.effect, p.principal_type, p.action_ids, p.resource_type)
    body = _render_when_unless(p.when, p.unless)
    ann = ""
    if p.description:
        ann += f"// {p.description}\n"
    if p.annotations:
        # Аннотации встраиваем комментарием в JSON для отладки пайплайна
        ann += "// annotations: " + json.dumps(p.annotations, ensure_ascii=False, separators=(",", ":")) + "\n"
    # Cedar требует ';' на конце statement
    return f"{ann}{hdr}{body};"


def render_bundle_to_cedar(policies: Iterable[Policy]) -> str:
    stmts = [render_policy_to_cedar(p) for p in policies]
    return "\n\n".join(stmts) + ("\n" if stmts else "")


# ============================================================================
# Утилиты построения выражений (синтаксический сахар)
# ============================================================================

def principal(*path: str) -> AttrRef:
    return AttrRef("principal", tuple(path))


def resource(*path: str) -> AttrRef:
    return AttrRef("resource", tuple(path))


def context(*path: str) -> AttrRef:
    return AttrRef("context", tuple(path))


def S(*items: Value) -> SetLiteral:
    return SetLiteral(tuple(items))


def eq(a: Value, b: Value) -> BinOp:
    return BinOp(a, Op.EQ, b)


def ne(a: Value, b: Value) -> BinOp:
    return BinOp(a, Op.NE, b)


def lt(a: Value, b: Value) -> BinOp:
    return BinOp(a, Op.LT, b)


def le(a: Value, b: Value) -> BinOp:
    return BinOp(a, Op.LE, b)


def gt(a: Value, b: Value) -> BinOp:
    return BinOp(a, Op.GT, b)


def ge(a: Value, b: Value) -> BinOp:
    return BinOp(a, Op.GE, b)


def contains(a: Value, collection: SetLiteral) -> BinOp:
    """a in [ ... ]"""
    return BinOp(a, Op.IN, collection)


def any_of(*exprs: Expr) -> Or:
    return Or(tuple(exprs))


def all_of(*exprs: Expr) -> And:
    return And(tuple(exprs))


def negate(expr: Expr) -> Not:
    return Not(expr)


# ============================================================================
# Пример использования (локальная проверка) — без внешних зависимостей
# ============================================================================

if __name__ == "__main__":
    # Пример: администраторам из SE/FI разрешён доступ к Document при включённом шифровании диска;
    # для других — forbid.
    pol1 = Policy(
        id="admin_allow_in_trusted_geo",
        effect=Effect.PERMIT,
        principal_type="User",
        action_ids=("view", "edit"),
        resource_type="Document",
        when=all_of(
            eq(principal("role"), "admin"),
            contains(context("geo", "country"), S("SE", "FI", "NO", "DK")),
            eq(principal("device", "disk_encryption"), "YES"),
        ),
        description="Администраторы из доверенных стран со шифрованием диска получают доступ.",
        annotations={"severity": "high", "owner": "platform-security"},
    )

    pol2 = Policy(
        id="geo_block_list",
        effect=Effect.FORBID,
        principal_type="User",
        action_ids=("view", "edit", "delete"),
        resource_type="Document",
        when=any_of(
            contains(context("geo", "country"), S("RU", "BY", "KP", "IR")),
            eq(context("network", "vpn_or_tor"), True),
        ),
        description="Блокировка доступа из запрещённых регионов или VPN/Tor.",
    )

    print(render_bundle_to_cedar([pol1, pol2]))
