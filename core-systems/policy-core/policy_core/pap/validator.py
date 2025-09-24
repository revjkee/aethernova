# policy-core/policy_core/pap/validator.py
from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Set, Callable, Union

__all__ = [
    "Severity",
    "IssueCode",
    "ValidationIssue",
    "ValidationResult",
    "ValidationConfig",
    "PolicyRepository",
    "DummyRepository",
    "PolicyValidator",
    "ValidationError",
]

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ----------------------------- Diagnostics -----------------------------

class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class IssueCode(str, Enum):
    SCHEMA_MISSING_FIELD = "schema.missing_field"
    SCHEMA_TYPE_MISMATCH = "schema.type_mismatch"
    SCHEMA_VALUE_RANGE = "schema.value_range"
    SCHEMA_INVALID_ID = "schema.invalid_id"
    SCHEMA_INVALID_NAME = "schema.invalid_name"
    SCHEMA_INVALID_TAG = "schema.invalid_tag"
    SCHEMA_INVALID_TTL = "schema.invalid_ttl"
    SCHEMA_INVALID_EFFECT = "schema.invalid_effect"
    SCHEMA_INVALID_PRIORITY = "schema.invalid_priority"
    SCHEMA_RULES_LIMIT = "schema.rules_limit"
    SCHEMA_HASH_MISMATCH = "schema.hash_mismatch"
    SCHEMA_HASH_MISSING = "schema.hash_missing"

    CONDITION_TYPE = "condition.type"
    CONDITION_DEPTH = "condition.depth"
    CONDITION_SIZE = "condition.size"
    CONDITION_UNKNOWN_OPERATOR = "condition.unknown_operator"
    CONDITION_OPERATOR_SHAPE = "condition.operator_shape"
    CONDITION_FORBIDDEN_VAR_PATH = "condition.forbidden_var_path"
    CONDITION_REGEX_INVALID = "condition.regex_invalid"

    TARGET_PATTERN_INVALID = "target.pattern_invalid"
    TARGET_WILDCARD_ABUSE = "target.wildcard_abuse"
    TARGET_EMPTY_SET = "target.empty_set"

    RULE_DUPLICATE_ID = "rule.duplicate_id"
    RULE_CONFLICTING_EFFECT = "rule.conflicting_effect"
    RULE_MISSING_EFFECT = "rule.missing_effect"

    REF_UNKNOWN_SUBJECT = "ref.unknown_subject"
    REF_UNKNOWN_RESOURCE = "ref.unknown_resource"
    REF_UNKNOWN_ACTION = "ref.unknown_action"
    REF_UNKNOWN_ROLE = "ref.unknown_role"

    INTERNAL_EXCEPTION = "internal.exception"
    PLUGIN_ISSUE = "plugin.issue"


@dataclass(slots=True)
class ValidationIssue:
    severity: Severity
    code: IssueCode
    message: str
    path: str = ""
    hint: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ValidationResult:
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(i.severity == Severity.ERROR for i in self.issues)

    def errors(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == Severity.ERROR]

    def warnings(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == Severity.WARNING]

    def infos(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == Severity.INFO]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "issues": [
                {
                    "severity": i.severity.value,
                    "code": i.code.value,
                    "message": i.message,
                    "path": i.path,
                    "hint": i.hint,
                    "context": i.context,
                }
                for i in self.issues
            ],
        }


class ValidationError(RuntimeError):
    """Raised when strict validation fails."""


# ----------------------------- Repository API -----------------------------

class PolicyRepository(Protocol):
    """Abstract context for referential checks (subjects/resources/actions/roles)."""

    async def subject_exists(self, subject_id: str) -> bool: ...
    async def resource_exists(self, resource_id: str) -> bool: ...
    async def action_exists(self, action: str) -> bool: ...
    async def role_exists(self, role: str) -> bool: ...


class DummyRepository:
    """Accept-everything repository (useful for bootstrap/testing)."""

    async def subject_exists(self, subject_id: str) -> bool:
        return True

    async def resource_exists(self, resource_id: str) -> bool:
        return True

    async def action_exists(self, action: str) -> bool:
        return True

    async def role_exists(self, role: str) -> bool:
        return True


# ----------------------------- Configuration -----------------------------

@dataclass(slots=True)
class ValidationConfig:
    max_rules: int = 1000
    max_condition_depth: int = 12
    max_condition_nodes: int = 2000
    # restrict wildcard usage per target vector
    max_target_globs_per_vector: int = 64
    # allowed JSON-Logic-like operators
    allowed_operators: Set[str] = field(default_factory=lambda: {
        "==", "!=", ">", ">=", "<", "<=", "in", "and", "or", "not",
        "all", "none", "some", "min", "max", "contains",
        "startsWith", "endsWith", "regex",
        # networking-safe helpers
        "ipInCidr", "cidrContains",
        # variable accessor
        "var", "exists", "missing",
        # arithmetic (optional but common)
        "+", "-", "*", "/", "%",
    })
    # permitted var path roots
    allowed_var_roots: Set[str] = field(default_factory=lambda: {
        "subject", "resource", "action", "context",
    })
    # forbidden var prefixes (security hardening)
    forbidden_var_prefixes: Set[str] = field(default_factory=lambda: {
        "policy", "__", "sys", "os", "posix", "nt", "import", "builtins",
    })
    # id/name/tag constraints
    id_regex: re.Pattern = field(default_factory=lambda: re.compile(r"^[A-Za-z0-9][\w:\-]{2,127}$"))
    name_regex: re.Pattern = field(default_factory=lambda: re.compile(r"^[\w\s\-\.:/]{3,256}$", re.UNICODE))
    tag_regex: re.Pattern = field(default_factory=lambda: re.compile(r"^[A-Za-z0-9][\w\-:]{1,63}$"))
    # TTL constraints (ISO-8601 duration like P30D, PT12H, P1DT2H)
    ttl_regex: re.Pattern = field(default_factory=lambda: re.compile(
        r"^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$"
    ))
    max_ttl_days: int = 365  # safety bound
    # priority range
    min_priority: int = 0
    max_priority: int = 1_000_000
    # enable strict mode / warnings-as-errors
    strict: bool = True
    warnings_as_errors: bool = False
    # hash field name (if provided by policy)
    hash_field: str = "hash"
    # plugin validators: Callable[[dict], list[ValidationIssue]]
    plugin_validators: List[Callable[[Dict[str, Any]], List[ValidationIssue]]] = field(default_factory=list)


# ----------------------------- Utilities -----------------------------

def _maybe_load_yaml() -> Optional[Any]:
    try:
        import yaml  # type: ignore
        return yaml
    except Exception:
        return None


def parse_policy_input(data: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(data, dict):
        return data
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="strict")
    if isinstance(data, str):
        s = data.strip()
        # try JSON first
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            # try YAML if available
            yaml = _maybe_load_yaml()
            if yaml is None:
                raise ValueError("Input is not valid JSON; PyYAML not available to parse YAML.")
            return yaml.safe_load(s)
    raise TypeError("Unsupported policy input type; expected dict | str | bytes.")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def policy_canonical_hash(policy: Dict[str, Any], exclude_keys: Iterable[str] = ("hash",)) -> str:
    def _without_keys(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: _without_keys(v) for k, v in o.items() if k not in exclude_keys}
        if isinstance(o, list):
            return [_without_keys(v) for v in o]
        return o

    normalized = _without_keys(policy)
    payload = canonical_json(normalized).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _is_glob(s: str) -> bool:
    return "*" in s or "?" in s


def _safe_compile_regex(pattern: str) -> Optional[re.Pattern]:
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _iso8601_ttl_to_days(ttl: str) -> Optional[int]:
    # Minimal estimate: Y=365, M=30, W=7, D=1; ignore time-part granularity < 1 day
    m = re.match(r"^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T.*)?$", ttl)
    if not m:
        return None
    y, mo, w, d = m.groups()
    days = 0
    if y: days += int(y) * 365
    if mo: days += int(mo) * 30
    if w: days += int(w) * 7
    if d: days += int(d)
    return days


def _flatten_condition_nodes(cond: Any) -> int:
    if isinstance(cond, dict):
        return 1 + sum(_flatten_condition_nodes(v) for v in cond.values())
    if isinstance(cond, list):
        return 1 + sum(_flatten_condition_nodes(v) for v in cond)
    return 1


def _condition_depth(cond: Any) -> int:
    if isinstance(cond, dict):
        return 1 + (max((_condition_depth(v) for v in cond.values()), default=0))
    if isinstance(cond, list):
        return 1 + (max((_condition_depth(v) for v in cond), default=0))
    return 1


def _iter_var_paths(cond: Any) -> Iterable[str]:
    # JSON-Logic-like: {"var": "subject.department"} or {"var": ["subject.level", 0]}
    if isinstance(cond, dict):
        for k, v in cond.items():
            if k == "var":
                if isinstance(v, str):
                    yield v
                elif isinstance(v, list) and v and isinstance(v[0], str):
                    yield v[0]
            yield from _iter_var_paths(v)
    elif isinstance(cond, list):
        for v in cond:
            yield from _iter_var_paths(v)


def _same_condition(a: Any, b: Any) -> bool:
    # structural equality via canonical JSON
    try:
        return canonical_json(a) == canonical_json(b)
    except Exception:
        return a == b


# ----------------------------- Core Validator -----------------------------

class PolicyValidator:
    def __init__(
        self,
        repository: Optional[PolicyRepository] = None,
        config: Optional[ValidationConfig] = None,
    ) -> None:
        self.repo = repository or DummyRepository()
        self.cfg = config or ValidationConfig()
        self._custom_ops: Set[str] = set()

    # ---------- Public API ----------

    async def validate_policy(self, policy_input: Union[Dict[str, Any], str, bytes]) -> ValidationResult:
        try:
            policy = parse_policy_input(policy_input)
        except Exception as e:
            return ValidationResult(issues=[
                ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_TYPE_MISMATCH,
                    message=f"Unable to parse policy input: {e!r}",
                    path="$",
                    context={"exception": repr(e)},
                )
            ])

        issues: List[ValidationIssue] = []

        # Run independent phases concurrently
        schema_task = asyncio.create_task(self._validate_schema(policy))
        rules_task = asyncio.create_task(self._validate_rules(policy))
        refs_task = asyncio.create_task(self._validate_references(policy))
        hash_task = asyncio.create_task(self._validate_hash(policy))
        plugin_task = asyncio.create_task(self._run_plugins(policy))

        phases = await asyncio.gather(schema_task, rules_task, refs_task, hash_task, plugin_task, return_exceptions=True)

        for ph in phases:
            if isinstance(ph, Exception):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.INTERNAL_EXCEPTION,
                    message="Internal validator exception.",
                    hint="Check validator configuration and input policy.",
                    context={"exception": repr(ph)},
                ))
            else:
                issues.extend(ph)

        result = ValidationResult(issues=issues)

        if self.cfg.warnings_as_errors:
            # upgrade all warnings to errors
            for i in result.issues:
                if i.severity == Severity.WARNING:
                    i.severity = Severity.ERROR

        if self.cfg.strict and not result.ok:
            # Produce a single aggregated error to allow upstream short-circuiting
            raise ValidationError(json.dumps(result.to_dict(), ensure_ascii=False))

        return result

    def register_custom_operator(self, op: str) -> None:
        """Extend the allowed set of condition operators."""
        if not op or not isinstance(op, str):
            raise ValueError("Operator name must be a non-empty string.")
        self._custom_ops.add(op)

    # ---------- Phases ----------

    async def _validate_schema(self, policy: Dict[str, Any]) -> List[ValidationIssue]:
        cfg = self.cfg
        issues: List[ValidationIssue] = []

        required_fields = ["id", "version", "name", "priority", "enabled", "targets", "rules"]
        for f in required_fields:
            if f not in policy:
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_MISSING_FIELD,
                    message=f"Missing required field '{f}'.",
                    path=f"$.{f}",
                    hint="Provide all required fields: id, version, name, priority, enabled, targets, rules.",
                ))

        # If critical fields are missing, skip deeper type checks gracefully
        if issues:
            return issues

        # id
        pid = policy.get("id")
        if not isinstance(pid, str) or not cfg.id_regex.match(pid):
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                code=IssueCode.SCHEMA_INVALID_ID,
                message="Field 'id' must match pattern and length constraints.",
                path="$.id",
                hint="Allowed: letters/digits/_-: ; length 3..128, must start with alnum.",
            ))

        # version
        ver = policy.get("version")
        if not isinstance(ver, int) or ver < 1:
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                code=IssueCode.SCHEMA_VALUE_RANGE,
                message="Field 'version' must be integer >= 1.",
                path="$.version",
            ))

        # name
        name = policy.get("name")
        if not isinstance(name, str) or not cfg.name_regex.match(name):
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                code=IssueCode.SCHEMA_INVALID_NAME,
                message="Field 'name' must be 3..256 chars, allowed letters/digits/space/._-:/",
                path="$.name",
            ))

        # description (optional)
        desc = policy.get("description")
        if desc is not None and (not isinstance(desc, str) or len(desc) > 4096):
            issues.append(ValidationIssue(
                severity=Severity.WARNING,
                code=IssueCode.SCHEMA_TYPE_MISMATCH,
                message="Field 'description' must be a string up to 4096 chars.",
                path="$.description",
            ))

        # priority
        pr = policy.get("priority")
        if not isinstance(pr, int) or not (self.cfg.min_priority <= pr <= self.cfg.max_priority):
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                code=IssueCode.SCHEMA_INVALID_PRIORITY,
                message=f"'priority' must be integer in [{self.cfg.min_priority}, {self.cfg.max_priority}].",
                path="$.priority",
            ))

        # enabled
        if not isinstance(policy.get("enabled"), bool):
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                code=IssueCode.SCHEMA_TYPE_MISMATCH,
                message="'enabled' must be boolean.",
                path="$.enabled",
            ))

        # tags
        tags = policy.get("tags", [])
        if tags is not None:
            if not isinstance(tags, list):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_TYPE_MISMATCH,
                    message="'tags' must be a list of strings.",
                    path="$.tags",
                ))
            else:
                for idx, t in enumerate(tags):
                    if not isinstance(t, str) or not cfg.tag_regex.match(t):
                        issues.append(ValidationIssue(
                            severity=Severity.WARNING,
                            code=IssueCode.SCHEMA_INVALID_TAG,
                            message=f"Tag at index {idx} is invalid.",
                            path=f"$.tags[{idx}]",
                            hint="Allowed: letters/digits/_-: ; length 2..64; must start with alnum.",
                        ))

        # TTL
        ttl = policy.get("ttl")
        if ttl is not None:
            if not isinstance(ttl, str) or not cfg.ttl_regex.match(ttl):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_INVALID_TTL,
                    message="TTL must be ISO-8601 duration like 'P30D' or 'PT12H'.",
                    path="$.ttl",
                ))
            else:
                days = _iso8601_ttl_to_days(ttl)
                if days is None or days > cfg.max_ttl_days:
                    issues.append(ValidationIssue(
                        severity=Severity.WARNING,
                        code=IssueCode.SCHEMA_INVALID_TTL,
                        message=f"TTL seems too large (> {cfg.max_ttl_days} days).",
                        path="$.ttl",
                    ))

        # targets
        targets = policy.get("targets")
        if not isinstance(targets, dict):
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                code=IssueCode.SCHEMA_TYPE_MISMATCH,
                message="'targets' must be an object with subjects/resources/actions arrays.",
                path="$.targets",
            ))
            return issues

        for vec in ("subjects", "resources", "actions"):
            arr = targets.get(vec)
            if not isinstance(arr, list) or any(not isinstance(x, str) or not x for x in arr):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_TYPE_MISMATCH,
                    message=f"'targets.{vec}' must be a non-empty list of non-empty strings.",
                    path=f"$.targets.{vec}",
                ))
                continue

            if len(arr) == 0:
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.TARGET_EMPTY_SET,
                    message=f"'targets.{vec}' must not be empty.",
                    path=f"$.targets.{vec}",
                ))

            # wildcard control
            glob_count = sum(1 for s in arr if _is_glob(s))
            if glob_count > self.cfg.max_target_globs_per_vector:
                issues.append(ValidationIssue(
                    severity=Severity.WARNING,
                    code=IssueCode.TARGET_WILDCARD_ABUSE,
                    message=f"Too many wildcards in '{vec}' ({glob_count}).",
                    path=f"$.targets.{vec}",
                    hint=f"Reduce wildcard usage to <= {self.cfg.max_target_globs_per_vector}.",
                ))

            # basic sanity for patterns
            for idx, s in enumerate(arr):
                if "**" in s or ".." in s:
                    issues.append(ValidationIssue(
                        severity=Severity.ERROR,
                        code=IssueCode.TARGET_PATTERN_INVALID,
                        message="Pattern must not contain '**' or '..'.",
                        path=f"$.targets.{vec}[{idx}]",
                    ))

        # rules
        rules = policy.get("rules")
        if not isinstance(rules, list):
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                code=IssueCode.SCHEMA_TYPE_MISMATCH,
                message="'rules' must be a list of rule objects.",
                path="$.rules",
            ))
            return issues

        if len(rules) > self.cfg.max_rules:
            issues.append(ValidationIssue(
                severity=Severity.ERROR,
                code=IssueCode.SCHEMA_RULES_LIMIT,
                message=f"Too many rules: {len(rules)} > {self.cfg.max_rules}.",
                path="$.rules",
            ))

        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_TYPE_MISMATCH,
                    message="Rule must be an object.",
                    path=f"$.rules[{i}]",
                ))
                continue
            rid = r.get("id")
            if not isinstance(rid, str) or not self.cfg.id_regex.match(rid):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_INVALID_ID,
                    message="Rule 'id' is invalid.",
                    path=f"$.rules[{i}].id",
                ))
            eff = r.get("effect")
            if eff is None:
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.RULE_MISSING_EFFECT,
                    message="Rule must have 'effect'.",
                    path=f"$.rules[{i}].effect",
                ))
            elif eff not in ("permit", "deny"):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_INVALID_EFFECT,
                    message="Rule 'effect' must be 'permit' or 'deny'.",
                    path=f"$.rules[{i}].effect",
                ))

            # condition optional but if present -> dict (JSON-Logic-like)
            cond = r.get("condition")
            if cond is not None and not isinstance(cond, (dict, list, str, int, float, bool)):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.CONDITION_TYPE,
                    message="Unsupported condition type.",
                    path=f"$.rules[{i}].condition",
                ))

        return issues

    async def _validate_rules(self, policy: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        rules = policy.get("rules", [])
        if not isinstance(rules, list):
            return issues

        # duplicate rule ids
        seen: Dict[str, int] = {}
        for i, r in enumerate(rules):
            rid = r.get("id")
            if isinstance(rid, str):
                if rid in seen:
                    issues.append(ValidationIssue(
                        severity=Severity.ERROR,
                        code=IssueCode.RULE_DUPLICATE_ID,
                        message=f"Duplicate rule id '{rid}'.",
                        path=f"$.rules[{i}].id",
                        context={"first_index": seen[rid]},
                    ))
                else:
                    seen[rid] = i

        # condition checks
        allowed_ops = set(self.cfg.allowed_operators) | self._custom_ops

        for i, r in enumerate(rules):
            cond = r.get("condition")
            if cond is None:
                # condition-less rule is allowed; effect applies to target
                continue

            # JSON-Logic-like must be dict or list at top level
            if not isinstance(cond, (dict, list)):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.CONDITION_TYPE,
                    message="Condition must be an object or array (JSON-Logic-like).",
                    path=f"$.rules[{i}].condition",
                ))
                continue

            depth = _condition_depth(cond)
            if depth > self.cfg.max_condition_depth:
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.CONDITION_DEPTH,
                    message=f"Condition depth {depth} exceeds limit {self.cfg.max_condition_depth}.",
                    path=f"$.rules[{i}].condition",
                ))

            size = _flatten_condition_nodes(cond)
            if size > self.cfg.max_condition_nodes:
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.CONDITION_SIZE,
                    message=f"Condition size {size} exceeds limit {self.cfg.max_condition_nodes}.",
                    path=f"$.rules[{i}].condition",
                ))

            # walk operators
            for op, loc in self._iter_ops(cond, path=f"$.rules[{i}].condition"):
                if op not in allowed_ops:
                    issues.append(ValidationIssue(
                        severity=Severity.ERROR,
                        code=IssueCode.CONDITION_UNKNOWN_OPERATOR,
                        message=f"Unknown/forbidden operator '{op}'.",
                        path=loc,
                        hint=f"Allowed operators: {sorted(allowed_ops)}",
                    ))

            # forbidden var prefixes / allowed roots
            for var_path in _iter_var_paths(cond):
                loc = f"$.rules[{i}].condition"
                # strip leading dots
                vp = var_path.lstrip(".")
                root = vp.split(".", 1)[0] if vp else ""
                if any(vp.startswith(pfx) for pfx in self.cfg.forbidden_var_prefixes):
                    issues.append(ValidationIssue(
                        severity=Severity.ERROR,
                        code=IssueCode.CONDITION_FORBIDDEN_VAR_PATH,
                        message=f"Forbidden var path prefix in '{var_path}'.",
                        path=loc,
                    ))
                if root and root not in self.cfg.allowed_var_roots:
                    issues.append(ValidationIssue(
                        severity=Severity.ERROR,
                        code=IssueCode.CONDITION_FORBIDDEN_VAR_PATH,
                        message=f"Var path root '{root}' is not allowed.",
                        path=loc,
                        hint=f"Allowed roots: {sorted(self.cfg.allowed_var_roots)}",
                    ))

            # validate regex operands if present
            for op, loc, args in self._iter_ops_with_args(cond, "regex", path=f"$.rules[{i}].condition"):
                # args like ["^a.*b$", value]
                if isinstance(args, list) and args:
                    patt = args[0]
                    if isinstance(patt, str):
                        if _safe_compile_regex(patt) is None:
                            issues.append(ValidationIssue(
                                severity=Severity.ERROR,
                                code=IssueCode.CONDITION_REGEX_INVALID,
                                message="Invalid regex pattern.",
                                path=loc,
                                context={"pattern": patt},
                            ))

        # conflicting rules (same condition canonical + different effect)
        self._detect_conflicting_rules(rules, issues)

        return issues

    async def _validate_references(self, policy: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        targets = policy.get("targets", {})
        if not isinstance(targets, dict):
            return issues

        subjects = [s for s in targets.get("subjects", []) if isinstance(s, str) and not _is_glob(s)]
        resources = [r for r in targets.get("resources", []) if isinstance(r, str) and not _is_glob(r)]
        actions = [a for a in targets.get("actions", []) if isinstance(a, str) and not _is_glob(a)]

        # basic heuristics: role:*, user:*
        roles = [s.split("role:")[1] for s in subjects if s.startswith("role:")]
        subj_ids = [s for s in subjects if not s.startswith("role:")]

        async def _check_subjects() -> List[ValidationIssue]:
            out: List[ValidationIssue] = []
            for sid in subj_ids:
                try:
                    ok = await self.repo.subject_exists(sid)
                except Exception as e:
                    logger.exception("subject_exists failed: %s", sid)
                    ok = True
                if not ok:
                    out.append(ValidationIssue(
                        severity=Severity.WARNING,
                        code=IssueCode.REF_UNKNOWN_SUBJECT,
                        message=f"Unknown subject '{sid}'.",
                        path="$.targets.subjects",
                    ))
            return out

        async def _check_roles() -> List[ValidationIssue]:
            out: List[ValidationIssue] = []
            for role in roles:
                try:
                    ok = await self.repo.role_exists(role)
                except Exception as e:
                    logger.exception("role_exists failed: %s", role)
                    ok = True
                if not ok:
                    out.append(ValidationIssue(
                        severity=Severity.WARNING,
                        code=IssueCode.REF_UNKNOWN_ROLE,
                        message=f"Unknown role '{role}'.",
                        path="$.targets.subjects",
                    ))
            return out

        async def _check_resources() -> List[ValidationIssue]:
            out: List[ValidationIssue] = []
            for rid in resources:
                try:
                    ok = await self.repo.resource_exists(rid)
                except Exception as e:
                    logger.exception("resource_exists failed: %s", rid)
                    ok = True
                if not ok:
                    out.append(ValidationIssue(
                        severity=Severity.WARNING,
                        code=IssueCode.REF_UNKNOWN_RESOURCE,
                        message=f"Unknown resource '{rid}'.",
                        path="$.targets.resources",
                    ))
            return out

        async def _check_actions() -> List[ValidationIssue]:
            out: List[ValidationIssue] = []
            for act in actions:
                try:
                    ok = await self.repo.action_exists(act)
                except Exception as e:
                    logger.exception("action_exists failed: %s", act)
                    ok = True
                if not ok:
                    out.append(ValidationIssue(
                        severity=Severity.WARNING,
                        code=IssueCode.REF_UNKNOWN_ACTION,
                        message=f"Unknown action '{act}'.",
                        path="$.targets.actions",
                    ))
            return out

        batches = await asyncio.gather(
            _check_subjects(), _check_roles(), _check_resources(), _check_actions(), return_exceptions=True
        )
        for b in batches:
            if isinstance(b, Exception):
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.INTERNAL_EXCEPTION,
                    message="Reference check failed due to repository exception.",
                    path="$.targets",
                    context={"exception": repr(b)},
                ))
            else:
                issues.extend(b)
        return issues

    async def _validate_hash(self, policy: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        field = self.cfg.hash_field
        if field in policy:
            actual = str(policy.get(field))
            expected = policy_canonical_hash(policy, exclude_keys=(field,))
            if actual != expected:
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.SCHEMA_HASH_MISMATCH,
                    message="Policy hash mismatch.",
                    path=f"$.{field}",
                    hint="Recompute hash from canonical JSON without the hash field.",
                    context={"expected": expected, "actual": actual},
                ))
        else:
            # Not fatal: INFO encourages immutable tracking
            expected = policy_canonical_hash(policy, exclude_keys=(field,))
            issues.append(ValidationIssue(
                severity=Severity.INFO,
                code=IssueCode.SCHEMA_HASH_MISSING,
                message="Policy 'hash' is absent; consider storing canonical SHA-256 for immutability.",
                path=f"$.{field}",
                context={"suggested": expected},
            ))
        return issues

    async def _run_plugins(self, policy: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        for idx, validator in enumerate(self.cfg.plugin_validators):
            try:
                out = validator(policy) or []
                for i in out:
                    if not isinstance(i, ValidationIssue):
                        raise TypeError("Plugin must return List[ValidationIssue].")
                issues.extend(out)
            except Exception as e:
                issues.append(ValidationIssue(
                    severity=Severity.ERROR,
                    code=IssueCode.PLUGIN_ISSUE,
                    message="Plugin validator raised an exception.",
                    path=f"$.plugins[{idx}]",
                    context={"exception": repr(e), "plugin": getattr(validator, "__name__", str(validator))},
                ))
        return issues

    # ---------- Helpers ----------

    def _iter_ops(self, node: Any, path: str) -> Iterable[Tuple[str, str]]:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k not in ("var",):
                    yield (k, f"{path}.{k}")
                # dive
                yield from self._iter_ops(v, f"{path}.{k}")
        elif isinstance(node, list):
            for idx, v in enumerate(node):
                yield from self._iter_ops(v, f"{path}[{idx}]")

    def _iter_ops_with_args(self, node: Any, op_name: str, path: str) -> Iterable[Tuple[str, str, Any]]:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == op_name:
                    yield (k, f"{path}.{k}", v)
                yield from self._iter_ops_with_args(v, op_name, f"{path}.{k}")
        elif isinstance(node, list):
            for idx, v in enumerate(node):
                yield from self._iter_ops_with_args(v, op_name, f"{path}[{idx}]")

    def _detect_conflicting_rules(self, rules: List[Dict[str, Any]], issues: List[ValidationIssue]) -> None:
        # Map canonical condition + canonical target subset (if per-rule targets exist later) -> effect
        # Current design: detect identical conditions with different effects
        seen: Dict[str, Tuple[str, int]] = {}
        for i, r in enumerate(rules):
            cond = r.get("condition")
            key = canonical_json(cond) if cond is not None else "__NO_CONDITION__"
            eff = r.get("effect")
            if not isinstance(eff, str):
                continue
            if key in seen:
                prev_eff, prev_idx = seen[key]
                if prev_eff != eff:
                    issues.append(ValidationIssue(
                        severity=Severity.ERROR,
                        code=IssueCode.RULE_CONFLICTING_EFFECT,
                        message="Conflicting rules with identical conditions but different effects.",
                        path=f"$.rules[{i}]",
                        context={"first_index": prev_idx, "first_effect": prev_eff, "second_effect": eff},
                    ))
            else:
                seen[key] = (eff, i)
