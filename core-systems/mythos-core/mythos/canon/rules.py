# -*- coding: utf-8 -*-
"""
Mythos Canon — безопасный rule-engine для проверки и аудита изменений.

Особенности:
- Декларативные правила с безопасными выражениями (AST whitelist).
- Контекст: request (env/action/resource/actor/context) + policy (freeze окна, immutable поля и т.п.).
- Встроенные предикаты: exists/get, touches_path (JSON Patch), contains_secrets, role_in,
  within_freeze_window, approvals_at_least, now(), re_match() и др.
- Серьезности нарушений: INFO/WARN/BLOCK; итоговое allow/deny и список причин.
- Загрузка правил из dict/JSON; кэширование скомпилированных выражений.
- Набор DEFAULT_RULES, согласованный с ранее выданной OPA/Rego политикой.

Без внешних зависимостей; совместим с Python 3.10+.
"""
from __future__ import annotations

import ast
import base64
import datetime as _dt
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union, cast

__all__ = [
    "Severity",
    "Rule",
    "CompiledRule",
    "EvaluationContext",
    "EnforcementResult",
    "RuleEngine",
    "DEFAULT_RULES",
]

# --------------------------------------------------------------------------------------
# Типы и модели
# --------------------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    BLOCK = "BLOCK"  # нарушение, запрещающее изменение


@dataclass(frozen=True)
class Rule:
    """
    Декларативное правило.

    when: булево выражение (если пусто/None — считается True).
    assert_expr: булево выражение, которое должно быть True. Если False — нарушение.
    message: человекочитаемое описание при нарушении.
    code: машинный код нарушения (для алёртов/метрик).
    """
    id: str
    description: str
    severity: Severity
    when: Optional[str]
    assert_expr: str
    message: str
    code: str


@dataclass
class CompiledRule:
    rule: Rule
    when_code: Optional[ast.AST]
    assert_code: ast.AST


@dataclass
class EnforcementResult:
    allow: bool
    violations: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, rule: Rule, detail: Optional[str], context: Dict[str, Any]) -> None:
        self.violations.append(
            {
                "id": rule.id,
                "severity": rule.severity.value,
                "code": rule.code,
                "message": rule.message,
                "detail": detail,
                "context": context,
            }
        )

    @property
    def has_block(self) -> bool:
        return any(v["severity"] == Severity.BLOCK.value for v in self.violations)


@dataclass
class DotMap:
    """
    Обёртка для точечной адресации полей словаря: obj.a.b вместо obj['a']['b'].
    """
    data: Any

    def __getattr__(self, item: str) -> Any:
        if isinstance(self.data, Mapping) and item in self.data:
            v = self.data[item]
            return DotMap(v) if isinstance(v, Mapping) else v
        raise AttributeError(item)

    def __getitem__(self, key: Any) -> Any:
        v = self.data[key]
        return DotMap(v) if isinstance(v, Mapping) else v

    def __repr__(self) -> str:
        return f"DotMap({self.data!r})"


@dataclass
class EvaluationContext:
    """
    Контекст исполнения правил: request и policy — любые словари, зависящие от вашей интеграции.
    Обязательные ожидаемые поля в request соответствуют ранее описанной Rego-политике.
    """
    request: Dict[str, Any]
    policy: Dict[str, Any]

# --------------------------------------------------------------------------------------
# Безопасный вычислитель выражений
# --------------------------------------------------------------------------------------

_ALLOWED_NODES = {
    ast.Expression, ast.BoolOp, ast.UnaryOp, ast.BinOp, ast.Compare, ast.IfExp,
    ast.Name, ast.Load, ast.Constant, ast.Subscript, ast.Attribute, ast.Dict,
    ast.List, ast.Tuple, ast.Set, ast.Call, ast.Slice, ast.Index,
    ast.And, ast.Or, ast.Not, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.In, ast.NotIn, ast.Is, ast.IsNot, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
    ast.Pow, ast.USub, ast.UAdd, ast.JoinedStr, ast.FormattedValue,
}

_ALLOWED_NAMES = set([
    "True", "False", "None",
    # Встроенные хелперы-предикаты заполняются динамически (см. _make_env)
])

# Регулярные выражения для поиска секретов
_SECRET_KEY_RE = re.compile(r"(?i)(pass|password|secret|token|api[_-]?key|private[_-]?key|credential)")
_SECRET_VALUE_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_-]{32,}={0,2}$")
_SECRET_VALUE_HEX_RE = re.compile(r"^[A-Fa-f0-9]{40,}$")

class UnsafeExpressionError(ValueError):
    pass


def _ast_sanitize(node: ast.AST) -> None:
    for child in ast.walk(node):
        if type(child) not in _ALLOWED_NODES:
            raise UnsafeExpressionError(f"Disallowed AST node: {type(child).__name__}")
        if isinstance(child, ast.Call):
            # Разрешаем вызовы только whitelisted функций (имя — простое Name)
            if not isinstance(child.func, (ast.Name, ast.Attribute)):
                raise UnsafeExpressionError("Only simple calls allowed")
            # Аргументы: позиционные/именованные без звёздочек
            if any(isinstance(a, (ast.Starred)) for a in child.args):
                raise UnsafeExpressionError("Starred args not allowed")
            if any(k.arg is None for k in child.keywords):
                raise UnsafeExpressionError("Kw **kwargs not allowed")


def _parse_expr(expr: str) -> ast.AST:
    try:
        node = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise UnsafeExpressionError(f"Syntax error: {e}") from e
    _ast_sanitize(node)
    return node


def _parse_time(s: str) -> _dt.datetime:
    # RFC3339/ISO-8601 («Z» -> +00:00)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return _dt.datetime.fromisoformat(s)


def _now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _walk(obj: Any):
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield None, v


def _contains_secrets(obj: Any) -> bool:
    for k, v in _walk(obj):
        if isinstance(k, str) and _SECRET_KEY_RE.search(k):
            return True
        if isinstance(v, str):
            if _SECRET_VALUE_BASE64_RE.match(v) or _SECRET_VALUE_HEX_RE.match(v):
                return True
    return False


def _jsonpatch_touches(ops: Sequence[Mapping[str, Any]] | None, path: str) -> bool:
    if not ops:
        return False
    target = path.strip("/").split("/")
    for op in ops:
        op_path = str(op.get("path", "")).strip("/").split("/")
        # касание, если целевой путь — префикс пути операции
        if len(op_path) >= len(target) and op_path[: len(target)] == target:
            return True
    return False


def _get_path(d: Any, path: str, default: Any = None) -> Any:
    cur = d
    for p in path.split("."):
        if isinstance(cur, Mapping) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def _exists_path(d: Any, path: str) -> bool:
    sentinel = object()
    return _get_path(d, path, sentinel) is not sentinel


def _approvals_at_least(approvals: Sequence[Mapping[str, Any]] | None, roles: Sequence[str], n: int) -> bool:
    if not approvals or n <= 0:
        return False
    approvers: set = set()
    for a in approvals:
        if a and a.get("role") in roles and a.get("by"):
            approvers.add(a["by"])
    return len(approvers) >= n


def _within_freeze(now: _dt.datetime, windows: Sequence[Mapping[str, str]] | None) -> bool:
    if not windows:
        return False
    for w in windows:
        try:
            start = _parse_time(w["start"])
            end = _parse_time(w["end"])
        except Exception:
            continue
        if start <= now <= end:
            return True
    return False


def _make_env(ctx: EvaluationContext) -> Dict[str, Any]:
    # Разворачиваем request для удобных имён
    req = ctx.request
    res = req.get("resource", {}) or {}
    change_ops = ((res.get("change_set") or {}).get("ops")) or []
    actor = req.get("actor", {}) or {}
    cctx = req.get("context", {}) or {}
    env = req.get("env")
    action = req.get("action")
    # Белый список доступных функций/предикатов в выражениях
    helpers: Dict[str, Any] = {
        # контекстные «короткие» имена
        "env": env,
        "action": action,
        "resource": DotMap(res),
        "actor": DotMap(actor),
        "context": DotMap(cctx),
        "policy": DotMap(ctx.policy),

        # утилиты
        "len": len,
        "any": any,
        "all": all,
        "min": min,
        "max": max,
        "abs": abs,
        "re_match": lambda pat, s: re.search(pat, s or "") is not None,
        "get": lambda path, default=None: _get_path(req, path, default),
        "exists": lambda path: _exists_path(req, path),
        "now": _now,
        "touches_path": lambda path: _jsonpatch_touches(change_ops, path),
        "contains_secrets": _contains_secrets,
        "approvals_at_least": lambda roles, n: _approvals_at_least(cctx.get("approvals"), roles, int(n)),
        "within_freeze_window": lambda: _within_freeze(_now(), ctx.policy.get("freeze_windows")),
        "role_in": lambda roles: any(r in set(roles or []) for r in (actor.get("roles") or [])),
    }
    return helpers


def _eval(node: ast.AST, names: Dict[str, Any]) -> Any:
    return eval(  # noqa: S307 — eval безопасен после AST-санитайзинга и пустого builtins
        compile(node, filename="<expr>", mode="eval"),
        {"__builtins__": {}},
        names,
    )

# --------------------------------------------------------------------------------------
# Компиляция и исполнение правил
# --------------------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, rules: Sequence[Rule]) -> None:
        self._compiled: List[CompiledRule] = []
        for r in rules:
            when_code = _parse_expr(r.when) if r.when else None
            assert_code = _parse_expr(r.assert_expr)
            self._compiled.append(CompiledRule(rule=r, when_code=when_code, assert_code=assert_code))

    @classmethod
    def from_dicts(cls, rules: Sequence[Mapping[str, Any]]) -> "RuleEngine":
        return cls([Rule(**cast(Dict[str, Any], r)) for r in rules])

    @classmethod
    def from_json(cls, data: str) -> "RuleEngine":
        return cls.from_dicts(json.loads(data))

    def evaluate(self, ctx: EvaluationContext) -> EnforcementResult:
        env = _make_env(ctx)
        res = EnforcementResult(allow=True)
        for cr in self._compiled:
            try:
                when_ok = True if cr.when_code is None else bool(_eval(cr.when_code, env))
            except Exception as e:
                # Ошибка в секции when — трактуем как False (правило не применяется)
                when_ok = False
                detail = f"when evaluation error: {e}"
                res.add(
                    Rule(
                        id=f"{cr.rule.id}#when",
                        description="Internal when-eval error",
                        severity=Severity.WARN,
                        when=None,
                        assert_expr="True",
                        message="when() evaluation failed; rule skipped",
                        code="ENGINE_WHEN_ERROR",
                    ),
                    detail=detail,
                    context={"rule": cr.rule.id},
                )
            if not when_ok:
                continue

            try:
                ok = bool(_eval(cr.assert_code, env))
            except Exception as e:
                # Ошибка в assert — это блокирующее нарушение (правило не может быть проверено надёжно)
                res.add(cr.rule, f"assert evaluation error: {e}", context={"rule": cr.rule.id})
                continue

            if not ok:
                res.add(cr.rule, None, context={"rule": cr.rule.id})

        # allow, если нет BLOCK
        res.allow = not res.has_block
        return res

# --------------------------------------------------------------------------------------
# Набор готовых «промышленных» правил (согласован с canon_protection.rego)
# --------------------------------------------------------------------------------------

DEFAULT_RULES: List[Rule] = [
    # Трассируемость
    Rule(
        id="trace-id",
        description="Запрошено наличие trace_id",
        severity=Severity.BLOCK,
        when=None,
        assert_expr="bool(context.trace_id)",
        message="missing trace_id",
        code="TRACE_ID_MISSING",
    ),
    # Prod требует change_ticket
    Rule(
        id="prod-ticket",
        description="В prod обязателен change_ticket",
        severity=Severity.BLOCK,
        when="env == 'prod'",
        assert_expr="bool(context.change_ticket)",
        message="prod requires change_ticket",
        code="PROD_TICKET_MISSING",
    ),
    # Запрет прямых destructive операций в prod
    Rule(
        id="prod-direct-destructive",
        description="В prod запрещены create/update/delete для защищённых видов",
        severity=Severity.BLOCK,
        when="env == 'prod' and resource.kind in set(policy.protected_kinds or [])",
        assert_expr="action not in ('create','update','delete')",
        message="direct create/update/delete is forbidden in prod; use proposals + release",
        code="PROD_DIRECT_DESTRUCTIVE",
    ),
    # Stage: delete только soft_delete=true
    Rule(
        id="stage-soft-delete",
        description="В stage delete разрешён только как soft_delete=true",
        severity=Severity.BLOCK,
        when="env == 'stage' and action == 'delete' and resource.kind in set(policy.protected_kinds or [])",
        assert_expr="bool(resource.payload and resource.payload.get('soft_delete') == True)",
        message="delete in stage requires soft_delete=true",
        code="STAGE_SOFT_DELETE_REQUIRED",
    ),
    # Freeze windows (prod), допускается breakglass для SRE
    Rule(
        id="prod-freeze-window",
        description="Блокировка изменений в freeze окна",
        severity=Severity.BLOCK,
        when="env == 'prod' and action in ('create','update','delete','merge_proposal','release')",
        assert_expr="not within_freeze_window() or (context.breakglass == True and role_in(['sre']))",
        message="change within freeze window is forbidden (unless breakglass by SRE)",
        code="FREEZE_WINDOW",
    ),
    # Одобрения 2-из-N для merge_proposal/release
    Rule(
        id="prod-approvals",
        description="В prod требуются одобрения (2-из-N) для merge_proposal/release",
        severity=Severity.BLOCK,
        when="env == 'prod' and action in ('merge_proposal','release')",
        assert_expr="approvals_at_least(list(policy.approval_roles or []), int(policy.min_approvals_prod or 2))",
        message="not enough approvals for action",
        code="PROD_APPROVALS_MISSING",
    ),
    # Подпись релиза
    Rule(
        id="release-signature",
        description="Релиз должен быть криптографически подписан",
        severity=Severity.BLOCK,
        when="env == 'prod' and action == 'release'",
        assert_expr="bool(context.signature_present)",
        message="release requires cryptographic signature",
        code="RELEASE_SIGNATURE_REQUIRED",
    ),
    # Неизменяемые поля при update/merge
    Rule(
        id="immutable-fields",
        description="Запрет изменения immutable полей",
        severity=Severity.BLOCK,
        when="action in ('update','merge_proposal') and resource.kind in policy.immutable_fields",
        assert_expr="all(not touches_path(path) for path in list(policy.immutable_fields.get(resource.kind, [])))",
        message="immutable field modified",
        code="IMMUTABLE_FIELD_CHANGED",
    ),
    # Проверка на секреты
    Rule(
        id="secrets-payload",
        description="Запрет потенциальных секретов в payload",
        severity=Severity.BLOCK,
        when="True",
        assert_expr="not contains_secrets(resource.payload)",
        message="payload contains potential secrets",
        code="SECRETS_DETECTED",
    ),
    # Алёрт-инфо: неизвестные действия/виды (мягкий сигнал)
    Rule(
        id="unknown-action-kind",
        description="Информационный сигнал о неизвестных action/kind",
        severity=Severity.INFO,
        when="True",
        assert_expr="action in ('create','update','delete','merge_proposal','release') and resource.kind in ('tablet','angel','canon','chronicle','proposal','release')",
        message="unknown action or kind encountered",
        code="UNKNOWN_ACTION_KIND",
    ),
]

# --------------------------------------------------------------------------------------
# Пример использования (док-строка):
# --------------------------------------------------------------------------------------
"""
Пример:

from mythos.canon.rules import RuleEngine, EvaluationContext, DEFAULT_RULES

engine = RuleEngine(DEFAULT_RULES)

ctx = EvaluationContext(
    request={
        "env": "prod",
        "action": "update",
        "resource": {
            "kind": "canon",
            "id": "c_1",
            "payload": {"title": "X"},
            "change_set": {"ops": [{"op": "replace", "path": "/id", "value": "hack"}]},
            "version": "v1.2.3",
        },
        "actor": {"id": "u_1", "roles": ["developer"]},
        "context": {
            "time": "2025-09-01T10:00:00Z",
            "trace_id": "abc123",
            "change_ticket": "JIRA-42",
            "approvals": [{"by": "u_7", "role": "sre"}, {"by": "u_8", "role": "core-platform"}],
            "signature_present": True,
            "breakglass": False
        },
    },
    policy={
        "freeze_windows": [{"start": "2025-12-24T00:00:00Z", "end": "2025-12-26T23:59:59Z"}],
        "immutable_fields": {"canon": ["id", "created_at"]},
        "protected_kinds": ["tablet", "angel", "canon", "chronicle"],
        "approval_roles": ["sre", "core-platform", "lore-keeper"],
        "min_approvals_prod": 2,
    },
)

result = engine.evaluate(ctx)
if not result.allow:
    # обработать нарушения
    for v in result.violations:
        print(v["severity"], v["code"], v["message"], v.get("detail"))

"""
