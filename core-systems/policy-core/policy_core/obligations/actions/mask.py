# policy_core/obligations/actions/mask.py
# Industrial-grade masking/redaction engine for PAP "obligations".
# No external deps. Python 3.10+.
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | obligations.mask | %(message)s"))
    LOGGER.addHandler(_h)
LOGGER.setLevel(logging.INFO)


# ============ Exceptions ============

class MaskError(Exception):
    pass

class SelectorError(MaskError):
    pass

class RuleError(MaskError):
    pass


# ============ Types & Models ============

JSON = Union[Dict[str, Any], List[Any], str, int, float, bool, None]

@dataclasses.dataclass(frozen=True)
class MaskRule:
    """
    A single masking rule.
    - selector: dot/wildcard selector for JSON-like data:
        user.email
        cards[*].pan
        **.ssn
        orders[*].items[*].sku
    - mode: fixed|partial|regex|charclass|hash|tokenize|null|zero
    - params: mode-specific parameters (see MaskingEngine._apply_*).
    - idempotent: skip if value already looks masked by this rule (best-effort).
    - max_matches: optional cap for number of replacements per rule.
    """
    rule_id: str
    selector: str
    mode: str
    params: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    idempotent: bool = True
    max_matches: Optional[int] = None


@dataclasses.dataclass(frozen=True)
class RedactionEvent:
    rule_id: str
    path: str
    original_preview: str
    new_preview: str

@dataclasses.dataclass(frozen=True)
class RedactionReport:
    total: int
    by_rule: Mapping[str, int]
    events: Sequence[RedactionEvent]


# ============ Secrets Provider ============

class SecretProvider:
    def get_secret(self, name: str) -> bytes:
        raise NotImplementedError

class EnvSecretProvider(SecretProvider):
    """
    Fetch secrets from environment variables.
    - prefix: ENV prefix for names (e.g. "POLICY_"); "HMAC_KEY" => "POLICY_HMAC_KEY".
    Returns raw bytes; base64 is supported if variable ends with "_B64".
    """
    def __init__(self, prefix: str = "POLICY_") -> None:
        self.prefix = prefix

    def get_secret(self, name: str) -> bytes:
        key = f"{self.prefix}{name}"
        b64 = f"{key}_B64"
        if b64 in os.environ:
            try:
                return base64.b64decode(os.environ[b64].encode("ascii"))
            except Exception as e:
                raise RuleError(f"Invalid base64 secret in {b64}: {e}")
        val = os.environ.get(key)
        if val is None:
            raise RuleError(f"Missing secret: {key}")
        return val.encode("utf-8")


# ============ Selector Engine (dot/wildcards) ============

# Selector features:
#   - Simple dots for dict keys: a.b.c
#   - Wildcard for one level: *
#   - Recursive wildcard: ** (match any depth)
#   - Arrays: [*] for all, [N] for index
# Examples:
#   "user.email"
#   "cards[*].pan"
#   "**.ssn"
#   "orders[*].items[*].sku"

_SEGMENT_RE = re.compile(r"""
    (?P<name>[A-Za-z0-9_\-]+|\*)       # dict key or '*'
    (\[(?P<idx>\*|\d+)\])?             # optional [*] or [N]
""", re.VERBOSE)

def _split_selector(selector: str) -> List[str]:
    parts: List[str] = []
    buf = []
    i = 0
    while i < len(selector):
        if selector[i] == ".":
            if buf:
                parts.append("".join(buf))
                buf = []
            i += 1
            continue
        if selector[i] == "*" and i + 1 < len(selector) and selector[i+1] == "*":
            # consume "**"
            if buf:
                parts.append("".join(buf))
                buf = []
            parts.append("**")
            i += 2
            # optional dot after **
            if i < len(selector) and selector[i] == ".":
                i += 1
            continue
        buf.append(selector[i])
        i += 1
    if buf:
        parts.append("".join(buf))
    return parts

def _iter_matches(root: JSON, selector: str, *, max_depth: int = 64) -> List[Tuple[List[Union[str,int]], Any, Any]]:
    """
    Returns list of (path_list, parent_container, key_or_index) for all matches.
    """
    parts = _split_selector(selector)
    if not parts:
        raise SelectorError("Empty selector")

    results: List[Tuple[List[Union[str,int]], Any, Any]] = []

    def walk(node: JSON, pi: int, path: List[Union[str,int]], parent: Any, key: Any, depth: int) -> None:
        if depth > max_depth:
            raise SelectorError("Max selector depth exceeded")
        if pi >= len(parts):
            results.append((path.copy(), parent, key))
            return

        seg = parts[pi]

        if seg == "**":
            # 1) match zero levels
            walk(node, pi + 1, path, parent, key, depth + 1)
            # 2) descend arbitrarily
            if isinstance(node, dict):
                for k, v in node.items():
                    path.append(k)
                    walk(v, pi, path, node, k, depth + 1)
                    path.pop()
            elif isinstance(node, list):
                for idx, v in enumerate(node):
                    path.append(idx)
                    walk(v, pi, path, node, idx, depth + 1)
                    path.pop()
            return

        m = _SEGMENT_RE.fullmatch(seg)
        if not m:
            raise SelectorError(f"Invalid selector segment: {seg}")

        name = m.group("name")
        idx = m.group("idx")

        def match_node(child: Any, child_key: Union[str, int]) -> None:
            path.append(child_key)
            walk(child, pi + 1, path, node, child_key, depth + 1)
            path.pop()

        if isinstance(node, dict):
            if name == "*":
                for k, v in node.items():
                    # optional array index further
                    if idx is None:
                        match_node(v, k)
                    else:
                        # we expect list at this dict entry
                        if not isinstance(v, list):
                            continue
                        if idx == "*":
                            for j, vv in enumerate(v):
                                path.extend([k, j])
                                walk(vv, pi + 1, path, v, j, depth + 1)
                                path.pop(); path.pop()
                        else:
                            j = int(idx)
                            if 0 <= j < len(v):
                                path.extend([k, j])
                                walk(v[j], pi + 1, path, v, j, depth + 1)
                                path.pop(); path.pop()
            else:
                if name in node:
                    child = node[name]
                    if idx is None:
                        match_node(child, name)
                    else:
                        if not isinstance(child, list):
                            return
                        if idx == "*":
                            for j, vv in enumerate(child):
                                path.extend([name, j])
                                walk(vv, pi + 1, path, child, j, depth + 1)
                                path.pop(); path.pop()
                        else:
                            j = int(idx)
                            if 0 <= j < len(child):
                                path.extend([name, j])
                                walk(child[j], pi + 1, path, child, j, depth + 1)
                                path.pop(); path.pop()
        elif isinstance(node, list):
            if name not in ("*",):
                return
            if idx is None:
                # match all elements as dict step
                for j, vv in enumerate(node):
                    match_node(vv, j)
            else:
                if idx == "*":
                    for j, vv in enumerate(node):
                        match_node(vv, j)
                else:
                    j = int(idx)
                    if 0 <= j < len(node):
                        match_node(node[j], j)
        else:
            return

    walk(root, 0, [], None, None, 0)
    return results


# ============ Masking Engine ============

@dataclasses.dataclass
class MaskingLimits:
    max_string_len: int = 1_000_000
    max_matches_total: int = 100_000

@dataclasses.dataclass
class MaskingContext:
    """
    Contextual metadata for audit. Does not affect masking logic.
    """
    tenant: Optional[str] = None
    policy_id: Optional[str] = None
    obligation_id: Optional[str] = None
    actor: Optional[str] = None
    reason: Optional[str] = None


class MaskingEngine:
    def __init__(self, *, secret_provider: Optional[SecretProvider] = None, limits: Optional[MaskingLimits] = None) -> None:
        self.secrets = secret_provider or EnvSecretProvider("POLICY_")
        self.limits = limits or MaskingLimits()

    # -------- public API --------

    def apply(self, data: JSON, rules: Sequence[MaskRule], *, context: Optional[MaskingContext] = None, in_place: bool = False) -> Tuple[JSON, RedactionReport]:
        """
        Apply rules to JSON-like data. Returns (masked_data, report).
        If in_place is False, input is deep-copied via JSON roundtrip for safety.
        """
        if not in_place:
            data = self._deepcopy_json(data)

        total = 0
        by_rule: Dict[str, int] = {}
        events: List[RedactionEvent] = []

        matches_total = 0

        for rule in rules:
            try:
                hits = _iter_matches(data, rule.selector)
            except SelectorError as e:
                raise RuleError(f"Rule {rule.rule_id} selector error: {e}") from e

            applied = 0
            for path_list, parent, key in hits:
                if rule.max_matches is not None and applied >= rule.max_matches:
                    break
                if self.limits.max_matches_total is not None and matches_total >= self.limits.max_matches_total:
                    LOGGER.warning("Global max_matches_total reached; further replacements skipped")
                    break

                try:
                    old_val = parent[key] if parent is not None else None
                except Exception:
                    continue

                try:
                    new_val, idempotent_skip = self._apply_rule_value(old_val, rule)
                except Exception as e:
                    raise RuleError(f"Rule {rule.rule_id} failed at {self._path_to_str(path_list)}: {e}") from e

                if idempotent_skip:
                    continue

                if parent is not None:
                    parent[key] = new_val
                    applied += 1
                    matches_total += 1
                    total += 1
                    by_rule[rule.rule_id] = by_rule.get(rule.rule_id, 0) + 1
                    events.append(
                        RedactionEvent(
                            rule_id=rule.rule_id,
                            path=self._path_to_str(path_list),
                            original_preview=self._preview(old_val),
                            new_preview=self._preview(new_val),
                        )
                    )

        return data, RedactionReport(total=total, by_rule=by_rule, events=events)

    # -------- per-value masking --------

    def _apply_rule_value(self, value: Any, rule: MaskRule) -> Tuple[Any, bool]:
        mode = rule.mode.lower()
        if mode == "fixed":
            return self._apply_fixed(value, rule.params), False
        if mode == "partial":
            # idempotency: if already contains full-mask token, skip
            token = str(rule.params.get("fill", "*"))
            if isinstance(value, str) and value and all(ch == token for ch in set(value)):
                return value, True
            return self._apply_partial(value, rule.params), False
        if mode == "regex":
            return self._apply_regex(value, rule.params), False
        if mode == "charclass":
            return self._apply_charclass(value, rule.params), False
        if mode == "hash":
            # deterministic; if looks like hex of expected length and flag enabled, skip
            expected_len = int(rule.params.get("truncate", 32))
            encoding = str(rule.params.get("encoding", "hex"))
            if rule.idempotent and self._looks_hashed(value, expected_len, encoding):
                return value, True
            return self._apply_hash(value, rule.params), False
        if mode == "tokenize":
            prefix = str(rule.params.get("prefix", "tok_"))
            if rule.idempotent and isinstance(value, str) and value.startswith(prefix):
                return value, True
            return self._apply_tokenize(value, rule.params), False
        if mode == "null":
            return None, False
        if mode == "zero":
            return 0, False
        raise RuleError(f"Unknown mode: {rule.mode}")

    # -------- helpers --------

    def _apply_fixed(self, value: Any, params: Mapping[str, Any]) -> Any:
        replacement = params.get("value", "*****")
        # Preserve type only for strings; otherwise replace as-is
        return str(replacement)

    def _apply_partial(self, value: Any, params: Mapping[str, Any]) -> Any:
        if value is None:
            return None
        s = self._to_str(value)
        keep_start = int(params.get("keep_start", 0))
        keep_end = int(params.get("keep_end", 0))
        fill = str(params.get("fill", "*"))
        min_mask = int(params.get("min_mask", 1))

        if len(s) > self.limits.max_string_len:
            raise MaskError("String too large")

        start = s[:max(keep_start, 0)]
        end = s[-max(keep_end, 0):] if keep_end > 0 else ""
        middle_len = max(len(s) - len(start) - len(end), 0)
        middle_len = max(middle_len, min_mask) if len(s) > 0 else 0
        masked = start + (fill * middle_len) + end
        return masked

    def _apply_regex(self, value: Any, params: Mapping[str, Any]) -> Any:
        if value is None:
            return None
        s = self._to_str(value)
        if len(s) > self.limits.max_string_len:
            raise MaskError("String too large")
        pattern = params.get("pattern")
        repl = params.get("repl", "*****")
        flags = 0
        if params.get("ignore_case"):
            flags |= re.IGNORECASE
        if not pattern:
            raise RuleError("regex: 'pattern' required")
        try:
            rgx = re.compile(pattern, flags)
        except re.error as e:
            raise RuleError(f"Invalid regex: {e}")
        return rgx.sub(str(repl), s)

    def _apply_charclass(self, value: Any, params: Mapping[str, Any]) -> Any:
        if value is None:
            return None
        s = self._to_str(value)
        if len(s) > self.limits.max_string_len:
            raise MaskError("String too large")

        digit = str(params.get("digit", "*"))
        alpha = str(params.get("alpha", "x"))
        alnum = params.get("alnum")  # if provided, overrides digit/alpha for isalnum
        other = params.get("other")  # if provided, overrides non-alnum
        preserve = set(str(params.get("preserve", " -_@.:+/()[]{},")))

        out = []
        for ch in s:
            if ch.isalnum():
                if alnum is not None:
                    out.append(str(alnum))
                else:
                    out.append(digit if ch.isdigit() else alpha)
            else:
                if ch in preserve:
                    out.append(ch)
                else:
                    out.append(str(other) if other is not None else "*")
        return "".join(out)

    def _apply_hash(self, value: Any, params: Mapping[str, Any]) -> Any:
        s = self._normalize_for_hash(value)
        salt_name = params.get("salt_name", "HASH_SALT")
        salt = params.get("salt_bytes")
        if salt is None:
            salt = self.secrets.get_secret(str(salt_name))
        elif isinstance(salt, str):
            salt = salt.encode("utf-8")

        digest = hashlib.sha256(salt + s).digest()
        encoding = str(params.get("encoding", "hex")).lower()
        truncate = int(params.get("truncate", 32))
        if encoding == "hex":
            out = digest.hex()
        elif encoding == "base32":
            out = base64.b32encode(digest).decode("ascii").rstrip("=")
        elif encoding == "base64url":
            out = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        else:
            raise RuleError("hash: unsupported encoding")

        if truncate > 0:
            out = out[:truncate]
        return out

    def _apply_tokenize(self, value: Any, params: Mapping[str, Any]) -> Any:
        """
        Deterministic pseudonymization using HMAC-SHA256.
        Not reversible. Produces prefix + base32(token)[:length]
        """
        s = self._normalize_for_hash(value)
        key_name = params.get("key_name", "HMAC_KEY")
        key = params.get("key_bytes")
        if key is None:
            key = self.secrets.get_secret(str(key_name))
        elif isinstance(key, str):
            key = key.encode("utf-8")

        mac = hmac.new(key, s, hashlib.sha256).digest()
        prefix = str(params.get("prefix", "tok_"))
        length = int(params.get("length", 20))
        enc = base64.b32encode(mac).decode("ascii").rstrip("=")
        token = enc[:max(length, 1)]
        return f"{prefix}{token}"

    # -------- utils --------

    def _normalize_for_hash(self, value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            b = value
        elif isinstance(value, str):
            b = value.encode("utf-8")
        else:
            # stable JSON for non-strings
            b = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(b) > self.limits.max_string_len:
            raise MaskError("Value too large for hashing/tokenizing")
        return b

    def _to_str(self, value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _looks_hashed(self, value: Any, expected_len: int, encoding: str) -> bool:
        if not isinstance(value, str):
            return False
        s = value.strip()
        if encoding == "hex":
            return bool(re.fullmatch(r"[0-9a-f]{%d}" % expected_len, s))
        if encoding == "base32":
            return bool(re.fullmatch(r"[A-Z2-7]{%d}" % expected_len, s))
        if encoding == "base64url":
            return bool(re.fullmatch(r"[A-Za-z0-9\-_]{%d}" % expected_len, s))
        return False

    def _path_to_str(self, path: List[Union[str,int]]) -> str:
        out: List[str] = []
        for p in path:
            if isinstance(p, int):
                out[-1] = f"{out[-1]}[{p}]"
            else:
                out.append(str(p))
        return ".".join(out)

    def _preview(self, val: Any, limit: int = 64) -> str:
        try:
            s = val if isinstance(val, str) else json.dumps(val, ensure_ascii=False)
        except Exception:
            s = str(val)
        s = s.replace("\n", "\\n")
        return s[:limit] + ("…" if len(s) > limit else "")

    def _deepcopy_json(self, data: JSON) -> JSON:
        try:
            return json.loads(json.dumps(data, ensure_ascii=False))
        except Exception:
            # fallback shallow copy
            if isinstance(data, dict):
                return {k: self._deepcopy_json(v) for k, v in data.items()}
            if isinstance(data, list):
                return [self._deepcopy_json(v) for v in data]
            return data


# ============ Convenience API ============

def mask_apply(
    data: JSON,
    rules: Sequence[MaskRule],
    *,
    secret_provider: Optional[SecretProvider] = None,
    limits: Optional[MaskingLimits] = None,
    context: Optional[MaskingContext] = None,
    in_place: bool = False,
) -> Tuple[JSON, RedactionReport]:
    engine = MaskingEngine(secret_provider=secret_provider, limits=limits)
    return engine.apply(data, rules, context=context, in_place=in_place)


# ============ __all__ ============

__all__ = [
    # Exceptions
    "MaskError",
    "SelectorError",
    "RuleError",
    # Models
    "MaskRule",
    "RedactionReport",
    "RedactionEvent",
    "MaskingLimits",
    "MaskingContext",
    # Secrets
    "SecretProvider",
    "EnvSecretProvider",
    # Engine
    "MaskingEngine",
    "mask_apply",
]
