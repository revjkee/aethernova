# human-sovereignty-core/security/safeguards.py
from __future__ import annotations

import hashlib
import hmac
import json
import os
import posixpath
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, MutableMapping, Sequence


class SafeguardsError(RuntimeError):
    pass


class ValidationError(SafeguardsError):
    pass


class LimitError(SafeguardsError):
    pass


class SecurityViolation(SafeguardsError):
    pass


class DeadlineExceeded(SafeguardsError):
    pass


_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9_.:\-]{1,256}$")
_SAFE_KEY_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")
_SAFE_HOST_RE = re.compile(
    r"^(?:localhost|127\.0\.0\.1|\[::1\]|"
    r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}|"
    r"(?:\d{1,3}\.){3}\d{1,3})$"
)
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*$")


def now_unix() -> float:
    return time.time()


def ct_eq(a: str | bytes, b: str | bytes) -> bool:
    if isinstance(a, str):
        a_b = a.encode("utf-8")
    else:
        a_b = a
    if isinstance(b, str):
        b_b = b.encode("utf-8")
    else:
        b_b = b
    return hmac.compare_digest(a_b, b_b)


def clamp_int(value: Any, default: int, lo: int, hi: int) -> int:
    try:
        v = int(value)
    except Exception:
        return default
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def safe_str(value: Any, *, max_len: int = 4096) -> str:
    s = "" if value is None else str(value)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def require_safe_id(value: str, *, label: str = "id") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{label} must be non-empty string")
    v = value.strip()
    if not _SAFE_ID_RE.fullmatch(v):
        raise ValidationError(f"{label} contains unsafe characters")
    return v


def require_safe_key(value: str, *, label: str = "key") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{label} must be non-empty string")
    v = value.strip()
    if not _SAFE_KEY_RE.fullmatch(v):
        raise ValidationError(f"{label} contains unsafe characters")
    return v


def require_non_empty(value: Any, *, label: str = "value", max_len: int = 4096) -> str:
    s = safe_str(value, max_len=max_len).strip()
    if not s:
        raise ValidationError(f"{label} must be non-empty")
    return s


def require_bytes(value: Any, *, label: str = "bytes", max_len: int = 1_048_576) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValidationError(f"{label} must be bytes")
    b = bytes(value)
    if len(b) > max_len:
        raise LimitError(f"{label} exceeds max_len")
    return b


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def canonical_json_bytes(obj: Any) -> bytes:
    try:
        s = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    except Exception as exc:
        raise ValidationError("Object is not JSON-serializable") from exc
    return s.encode("utf-8")


def canonical_json_str(obj: Any) -> str:
    return canonical_json_bytes(obj).decode("utf-8")


def enforce_max_size(obj: Any, *, max_bytes: int, label: str = "payload") -> None:
    b = canonical_json_bytes(obj)
    if len(b) > int(max_bytes):
        raise LimitError(f"{label} exceeds max_bytes")


def normalize_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        raise ValidationError("headers must be a mapping")
    out: dict[str, str] = {}
    for k, v in headers.items():
        ks = safe_str(k, max_len=256).strip()
        if not ks:
            continue
        vs = safe_str(v, max_len=8192).strip()
        if not vs:
            continue
        out[ks.lower()] = vs
    return out


def get_header(headers: Mapping[str, Any], name: str) -> str | None:
    h = normalize_headers(headers)
    return h.get(name.lower())


def parse_origin(origin: str) -> tuple[str, str, int | None]:
    s = require_non_empty(origin, label="origin", max_len=2048)
    s = s.strip()

    if "://" not in s:
        raise ValidationError("origin must include scheme")

    scheme, rest = s.split("://", 1)
    scheme = scheme.strip().lower()
    if not _SCHEME_RE.fullmatch(scheme):
        raise ValidationError("invalid origin scheme")

    rest = rest.strip()
    path_start = rest.find("/")
    if path_start != -1:
        rest = rest[:path_start]

    host = rest
    port: int | None = None

    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            raise ValidationError("invalid ipv6 host")
        hpart = host[: end + 1]
        tail = host[end + 1 :]
        host = hpart
        if tail.startswith(":"):
            port = int(tail[1:])
    else:
        if ":" in host:
            hpart, p = host.rsplit(":", 1)
            if p.isdigit():
                host = hpart
                port = int(p)

    host = host.strip()
    if not host:
        raise ValidationError("origin host missing")

    return scheme, host, port


def is_loopback_host(host: str) -> bool:
    h = host.strip().lower()
    return h in {"localhost", "127.0.0.1", "[::1]"}


def validate_host(host: str) -> str:
    h = require_non_empty(host, label="host", max_len=255).strip()
    if not _SAFE_HOST_RE.fullmatch(h):
        raise ValidationError("invalid host")
    return h


def enforce_allowed_origins(*, origin: str | None, allowed_origins: Sequence[str]) -> None:
    if origin is None:
        raise SecurityViolation("missing origin")

    _, host, _ = parse_origin(origin)
    host = validate_host(host)

    allowed_set = set()
    for ao in allowed_origins:
        try:
            _, ah, _ = parse_origin(ao)
            allowed_set.add(validate_host(ah).lower())
        except Exception:
            continue

    if host.lower() not in allowed_set:
        raise SecurityViolation("origin not allowed")


def enforce_local_only_binding(*, bind_host: str) -> None:
    h = validate_host(bind_host)
    if not is_loopback_host(h):
        raise SecurityViolation("binding must be loopback only")


def redact_secrets(obj: Any, *, keys: Iterable[str] | None = None) -> Any:
    red_keys = {k.lower() for k in (keys or _default_redaction_keys())}

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            ks = safe_str(k, max_len=256)
            if ks.lower() in red_keys:
                out[ks] = "[REDACTED]"
            else:
                out[ks] = redact_secrets(v, keys=red_keys)
        return out

    if isinstance(obj, list):
        return [redact_secrets(v, keys=red_keys) for v in obj]

    if isinstance(obj, tuple):
        return tuple(redact_secrets(v, keys=red_keys) for v in obj)

    return obj


def _default_redaction_keys() -> set[str]:
    return {
        "password",
        "pass",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "key",
        "private_key",
        "authorization",
        "cookie",
        "session",
        "set-cookie",
    }


def safe_join_posix(base_dir: str, user_path: str) -> str:
    base = require_non_empty(base_dir, label="base_dir", max_len=4096)
    up = require_non_empty(user_path, label="user_path", max_len=4096)

    if "\x00" in up:
        raise ValidationError("nul byte in path")

    norm = posixpath.normpath(up).lstrip("/")
    if norm.startswith("..") or "/../" in f"/{norm}/":
        raise SecurityViolation("path traversal detected")

    joined = posixpath.join(base, norm)
    joined = posixpath.normpath(joined)
    return joined


@dataclass(frozen=True, slots=True)
class Deadline:
    start_unix: float
    timeout_ms: int

    @staticmethod
    def create(timeout_ms: int, *, start_unix: float | None = None) -> "Deadline":
        t = clamp_int(timeout_ms, 1500, 1, 120_000)
        s = float(start_unix) if start_unix is not None else now_unix()
        return Deadline(start_unix=s, timeout_ms=t)

    def remaining_ms(self, *, now_unix_val: float | None = None) -> int:
        n = float(now_unix_val) if now_unix_val is not None else now_unix()
        elapsed = (n - self.start_unix) * 1000.0
        rem = float(self.timeout_ms) - elapsed
        if rem <= 0:
            return 0
        if rem > 2_147_483_647:
            return 2_147_483_647
        return int(rem)

    def enforce(self, *, now_unix_val: float | None = None) -> None:
        if self.remaining_ms(now_unix_val=now_unix_val) <= 0:
            raise DeadlineExceeded("deadline exceeded")


@dataclass(frozen=True, slots=True)
class AntiReplayToken:
    token: str
    issued_at_unix: float
    expires_at_unix: float
    subject_id: str
    digest_hex: str

    def is_expired(self, *, now_unix_val: float | None = None) -> bool:
        n = float(now_unix_val) if now_unix_val is not None else now_unix()
        return n > self.expires_at_unix


def issue_anti_replay_token(
    *,
    subject_id: str,
    ttl_seconds: int = 120,
    secret_key: bytes,
    purpose: str = "challenge",
) -> AntiReplayToken:
    sid = require_safe_id(subject_id, label="subject_id")
    t = clamp_int(ttl_seconds, 120, 1, 3600)
    p = require_safe_id(purpose, label="purpose")

    issued = now_unix()
    expires = issued + float(t)

    rnd = os.urandom(32)
    token = hashlib.sha256(rnd).hexdigest()

    msg = canonical_json_bytes(
        {
            "v": 1,
            "purpose": p,
            "subject_id": sid,
            "token": token,
            "issued_at_unix": issued,
            "expires_at_unix": expires,
        }
    )
    digest = hmac_sha256_hex(secret_key, msg)

    return AntiReplayToken(
        token=token,
        issued_at_unix=issued,
        expires_at_unix=expires,
        subject_id=sid,
        digest_hex=digest,
    )


def verify_anti_replay_token(
    *,
    subject_id: str,
    token: str,
    issued_at_unix: float,
    expires_at_unix: float,
    digest_hex: str,
    secret_key: bytes,
    purpose: str = "challenge",
    now_unix_val: float | None = None,
) -> None:
    sid = require_safe_id(subject_id, label="subject_id")
    tok = require_non_empty(token, label="token", max_len=512)
    dg = require_non_empty(digest_hex, label="digest_hex", max_len=256)
    p = require_safe_id(purpose, label="purpose")

    n = float(now_unix_val) if now_unix_val is not None else now_unix()
    if n > float(expires_at_unix):
        raise SecurityViolation("anti-replay token expired")
    if float(expires_at_unix) < float(issued_at_unix):
        raise ValidationError("invalid token timestamps")

    msg = canonical_json_bytes(
        {
            "v": 1,
            "purpose": p,
            "subject_id": sid,
            "token": tok,
            "issued_at_unix": float(issued_at_unix),
            "expires_at_unix": float(expires_at_unix),
        }
    )
    expected = hmac_sha256_hex(secret_key, msg)
    if not ct_eq(expected, dg):
        raise SecurityViolation("anti-replay token digest mismatch")


def merge_headers_safely(
    base: MutableMapping[str, str],
    additions: Mapping[str, str],
    *,
    overwrite: bool = False,
) -> None:
    if not isinstance(base, MutableMapping):
        raise ValidationError("base must be mutable mapping")
    if not isinstance(additions, Mapping):
        raise ValidationError("additions must be mapping")

    for k, v in additions.items():
        key = require_non_empty(k, label="header_name", max_len=256)
        val = require_non_empty(v, label="header_value", max_len=8192)
        lk = key.lower()

        existing_key = None
        for bk in base.keys():
            if bk.lower() == lk:
                existing_key = bk
                break

        if existing_key is None:
            base[key] = val
            continue

        if overwrite:
            base.pop(existing_key, None)
            base[key] = val


__all__ = [
    "SafeguardsError",
    "ValidationError",
    "LimitError",
    "SecurityViolation",
    "DeadlineExceeded",
    "now_unix",
    "ct_eq",
    "clamp_int",
    "safe_str",
    "require_safe_id",
    "require_safe_key",
    "require_non_empty",
    "require_bytes",
    "sha256_hex",
    "hmac_sha256_hex",
    "canonical_json_bytes",
    "canonical_json_str",
    "enforce_max_size",
    "normalize_headers",
    "get_header",
    "parse_origin",
    "validate_host",
    "is_loopback_host",
    "enforce_allowed_origins",
    "enforce_local_only_binding",
    "redact_secrets",
    "safe_join_posix",
    "Deadline",
    "AntiReplayToken",
    "issue_anti_replay_token",
    "verify_anti_replay_token",
    "merge_headers_safely",
]
