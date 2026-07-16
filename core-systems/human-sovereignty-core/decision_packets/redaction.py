# human-sovereignty-core/decision_packets/redaction.py
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, MutableSequence, Optional, Sequence, Set, Tuple, Union

try:
    # Optional support for Pydantic models
    from pydantic import BaseModel as PydanticBaseModel  # type: ignore
except Exception:  # pragma: no cover
    PydanticBaseModel = None  # type: ignore


JsonLike = Union[None, bool, int, float, str, List["JsonLike"], Dict[str, "JsonLike"]]


DEFAULT_REDACTED_TEXT = "[REDACTED]"
DEFAULT_REDACTED_HASH_PREFIX = "redacted:"
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_ITEMS = 50000
DEFAULT_MAX_STRING_LENGTH = 20000


def _is_mapping(v: Any) -> bool:
    return isinstance(v, Mapping)


def _is_sequence(v: Any) -> bool:
    return isinstance(v, (list, tuple))


def _safe_str(v: Any) -> str:
    try:
        return str(v)
    except Exception:  # pragma: no cover
        return "<unprintable>"


def _lower(s: str) -> str:
    return s.lower()


def _path_join(parent: str, key: str) -> str:
    if not parent:
        return key
    return f"{parent}.{key}"


def _mask_keep_last(s: str, keep_last: int = 4, mask_char: str = "*") -> str:
    if keep_last <= 0:
        return DEFAULT_REDACTED_TEXT
    if len(s) <= keep_last:
        return mask_char * len(s)
    return (mask_char * (len(s) - keep_last)) + s[-keep_last:]


def _mask_email(email: str) -> str:
    parts = email.split("@")
    if len(parts) != 2:
        return DEFAULT_REDACTED_TEXT
    local, domain = parts
    if not local:
        return DEFAULT_REDACTED_TEXT
    local_masked = _mask_keep_last(local, keep_last=1)
    return f"{local_masked}@{domain}"


def _mask_phone(phone: str) -> str:
    digits = re.sub(r"\D+", "", phone)
    if len(digits) < 6:
        return DEFAULT_REDACTED_TEXT
    return _mask_keep_last(digits, keep_last=2)


def _mask_credit_card(cc: str) -> str:
    digits = re.sub(r"\D+", "", cc)
    if len(digits) < 12:
        return DEFAULT_REDACTED_TEXT
    return _mask_keep_last(digits, keep_last=4)


@dataclass(frozen=True)
class RedactionMatch:
    kind: str
    pattern: str
    detail: str = ""


@dataclass
class RedactionResult:
    value: Any
    matches: List[RedactionMatch] = field(default_factory=list)


KeyPredicate = Callable[[str, str], bool]
ValuePredicate = Callable[[Any, str, str], bool]
ValueTransformer = Callable[[Any, str, str, List[RedactionMatch]], Any]


@dataclass
class RedactionRule:
    name: str
    key_predicate: Optional[KeyPredicate] = None
    value_predicate: Optional[ValuePredicate] = None
    transform: Optional[ValueTransformer] = None

    def applies(self, key: str, path: str, value: Any) -> bool:
        if self.key_predicate is not None:
            try:
                if self.key_predicate(key, path):
                    return True
            except Exception:
                pass
        if self.value_predicate is not None:
            try:
                if self.value_predicate(value, key, path):
                    return True
            except Exception:
                pass
        return False


@dataclass
class RedactionPolicy:
    redacted_text: str = DEFAULT_REDACTED_TEXT

    max_depth: int = DEFAULT_MAX_DEPTH
    max_items: int = DEFAULT_MAX_ITEMS
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH

    redact_unknown_large_strings: bool = True
    large_string_threshold: int = 4096

    redact_by_key: bool = True
    redact_by_value_patterns: bool = True

    allowlist_paths: Set[str] = field(default_factory=set)
    denylist_paths: Set[str] = field(default_factory=set)

    allowlist_keys: Set[str] = field(default_factory=set)
    denylist_keys: Set[str] = field(default_factory=set)

    rules: List[RedactionRule] = field(default_factory=list)

    email_masking: bool = True
    phone_masking: bool = True
    credit_card_masking: bool = True

    def is_path_allowed(self, path: str) -> bool:
        if not path:
            return True
        if path in self.denylist_paths:
            return False
        if not self.allowlist_paths:
            return True
        return path in self.allowlist_paths

    def is_key_allowed(self, key: str) -> bool:
        k = _lower(key)
        if k in { _lower(x) for x in self.denylist_keys }:
            return False
        if not self.allowlist_keys:
            return True
        return k in { _lower(x) for x in self.allowlist_keys }

    @staticmethod
    def default() -> "RedactionPolicy":
        policy = RedactionPolicy()

        key_deny = {
            "password",
            "pass",
            "passwd",
            "pwd",
            "secret",
            "secrets",
            "token",
            "access_token",
            "refresh_token",
            "api_key",
            "apikey",
            "x_api_key",
            "authorization",
            "auth",
            "bearer",
            "private_key",
            "ssh_private_key",
            "client_secret",
            "session",
            "cookie",
            "set_cookie",
            "credit_card",
            "cc",
            "card_number",
            "iban",
            "ssn",
            "sin",
            "pin",
            "otp",
            "mfa",
        }
        policy.denylist_keys = set(key_deny)

        # Content patterns for secrets and PII
        jwt_re = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
        pem_re = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.IGNORECASE)
        aws_key_re = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
        gh_pat_re = re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")
        slack_token_re = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
        generic_bearer_re = re.compile(r"\bBearer\s+[A-Za-z0-9._=-]{10,}\b", re.IGNORECASE)

        email_re = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b")
        phone_re = re.compile(r"\b(?:\+?\d[\d\s().-]{6,}\d)\b")
        cc_re = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

        def key_contains_any(*needles: str) -> KeyPredicate:
            lowered = tuple(_lower(n) for n in needles)

            def _pred(key: str, path: str) -> bool:
                k = _lower(key)
                return any(n in k for n in lowered)

            return _pred

        def value_matches_regex(rx: re.Pattern, kind: str) -> ValuePredicate:
            def _pred(value: Any, key: str, path: str) -> bool:
                if not isinstance(value, str):
                    return False
                if len(value) > policy.max_string_length:
                    v = value[: policy.max_string_length]
                else:
                    v = value
                return bool(rx.search(v))
            return _pred

        def redact_full(value: Any, key: str, path: str, matches: List[RedactionMatch]) -> Any:
            return policy.redacted_text

        def redact_bearer(value: Any, key: str, path: str, matches: List[RedactionMatch]) -> Any:
            if not isinstance(value, str):
                return policy.redacted_text
            return "Bearer " + policy.redacted_text

        def redact_email(value: Any, key: str, path: str, matches: List[RedactionMatch]) -> Any:
            if not isinstance(value, str):
                return policy.redacted_text
            return email_re.sub(lambda m: _mask_email(m.group(0)) if policy.email_masking else policy.redacted_text, value)

        def redact_phone(value: Any, key: str, path: str, matches: List[RedactionMatch]) -> Any:
            if not isinstance(value, str):
                return policy.redacted_text
            return phone_re.sub(lambda m: _mask_phone(m.group(0)) if policy.phone_masking else policy.redacted_text, value)

        def redact_cc(value: Any, key: str, path: str, matches: List[RedactionMatch]) -> Any:
            if not isinstance(value, str):
                return policy.redacted_text
            return cc_re.sub(lambda m: _mask_credit_card(m.group(0)) if policy.credit_card_masking else policy.redacted_text, value)

        # Key-based rules
        policy.rules.extend(
            [
                RedactionRule(
                    name="key_password_like",
                    key_predicate=key_contains_any("password", "passwd", "pwd", "pass"),
                    transform=redact_full,
                ),
                RedactionRule(
                    name="key_token_like",
                    key_predicate=key_contains_any("token", "authorization", "bearer", "session", "cookie"),
                    transform=redact_full,
                ),
                RedactionRule(
                    name="key_key_like",
                    key_predicate=key_contains_any("api_key", "apikey", "private_key", "client_secret", "secret"),
                    transform=redact_full,
                ),
                RedactionRule(
                    name="key_otp_like",
                    key_predicate=key_contains_any("otp", "mfa", "pin"),
                    transform=redact_full,
                ),
            ]
        )

        # Value-based rules (secrets)
        policy.rules.extend(
            [
                RedactionRule(
                    name="value_jwt",
                    value_predicate=value_matches_regex(jwt_re, "jwt"),
                    transform=redact_full,
                ),
                RedactionRule(
                    name="value_pem_private_key",
                    value_predicate=value_matches_regex(pem_re, "pem_private_key"),
                    transform=redact_full,
                ),
                RedactionRule(
                    name="value_aws_access_key_id",
                    value_predicate=value_matches_regex(aws_key_re, "aws_access_key_id"),
                    transform=redact_full,
                ),
                RedactionRule(
                    name="value_github_pat",
                    value_predicate=value_matches_regex(gh_pat_re, "github_pat"),
                    transform=redact_full,
                ),
                RedactionRule(
                    name="value_slack_token",
                    value_predicate=value_matches_regex(slack_token_re, "slack_token"),
                    transform=redact_full,
                ),
                RedactionRule(
                    name="value_bearer_header",
                    value_predicate=value_matches_regex(generic_bearer_re, "bearer"),
                    transform=redact_bearer,
                ),
            ]
        )

        # Value-based rules (PII masking, not full wipe)
        policy.rules.extend(
            [
                RedactionRule(
                    name="value_email_mask",
                    value_predicate=value_matches_regex(email_re, "email"),
                    transform=redact_email,
                ),
                RedactionRule(
                    name="value_phone_mask",
                    value_predicate=value_matches_regex(phone_re, "phone"),
                    transform=redact_phone,
                ),
                RedactionRule(
                    name="value_credit_card_mask",
                    value_predicate=value_matches_regex(cc_re, "credit_card"),
                    transform=redact_cc,
                ),
            ]
        )

        return policy


class Redactor:
    def __init__(self, policy: Optional[RedactionPolicy] = None) -> None:
        self.policy = policy or RedactionPolicy.default()
        self._seen_ids: Set[int] = set()
        self._items_processed: int = 0

    def redact(self, value: Any) -> Any:
        self._seen_ids.clear()
        self._items_processed = 0
        return self._redact_value(value=value, key="", path="", depth=0)

    def _check_limits(self, depth: int) -> None:
        if depth > self.policy.max_depth:
            raise ValueError("Redaction max_depth exceeded")
        self._items_processed += 1
        if self._items_processed > self.policy.max_items:
            raise ValueError("Redaction max_items exceeded")

    def _redact_value(self, value: Any, key: str, path: str, depth: int) -> Any:
        self._check_limits(depth)

        if value is None:
            return None

        # Pydantic model normalization
        if PydanticBaseModel is not None and isinstance(value, PydanticBaseModel):
            try:
                if hasattr(value, "model_dump"):
                    value = value.model_dump(mode="python")  # pydantic v2
                else:
                    value = value.dict()  # pydantic v1
            except Exception:
                return self.policy.redacted_text

        # Prevent infinite recursion on cyclic structures
        oid = id(value)
        if isinstance(value, (dict, list, tuple, set)):
            if oid in self._seen_ids:
                return self.policy.redacted_text
            self._seen_ids.add(oid)

        if isinstance(value, str):
            return self._redact_string(value=value, key=key, path=path)

        if isinstance(value, (bool, int, float)):
            return value

        if _is_mapping(value):
            return self._redact_mapping(value=value, path=path, depth=depth)

        if _is_sequence(value):
            return self._redact_sequence(value=value, path=path, depth=depth)

        # Fallback for objects: try best-effort conversion
        try:
            s = _safe_str(value)
        except Exception:
            return self.policy.redacted_text

        if self.policy.redact_unknown_large_strings and isinstance(s, str) and len(s) > self.policy.large_string_threshold:
            return self.policy.redacted_text

        return s

    def _redact_mapping(self, value: Mapping[Any, Any], path: str, depth: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k_raw, v in value.items():
            k = _safe_str(k_raw)
            child_path = _path_join(path, k)

            if not self.policy.is_path_allowed(child_path):
                out[k] = self.policy.redacted_text
                continue

            if self.policy.redact_by_key and not self.policy.is_key_allowed(k):
                out[k] = self.policy.redacted_text
                continue

            if self.policy.redact_by_key and self._should_redact_by_rules(key=k, path=child_path, value=v):
                out[k] = self._apply_rules(value=v, key=k, path=child_path)
                continue

            out[k] = self._redact_value(value=v, key=k, path=child_path, depth=depth + 1)

        return out

    def _redact_sequence(self, value: Sequence[Any], path: str, depth: int) -> List[Any]:
        out: List[Any] = []
        for idx, item in enumerate(value):
            child_path = _path_join(path, str(idx))
            out.append(self._redact_value(value=item, key=str(idx), path=child_path, depth=depth + 1))
        return out

    def _redact_string(self, value: str, key: str, path:
