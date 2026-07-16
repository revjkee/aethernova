# human-sovereignty-core/approval/challenge/challenge_issuer.py
#
# Industrial-grade Challenge Issuer for CLI/WebUI binding.
#
# Purpose:
# - Issue short-lived, one-time cryptographically signed challenges
#   to bind CLI confirmation flows with WebUI approval flows.
#
# Security goals:
# - Prevent replay (one-time JTI, storage-backed consumption)
# - Prevent tampering (HMAC signature over canonical payload)
# - Limit scope (audience, subject, operation, optional device/session binding)
# - Time bound (iat/exp, clock skew tolerance)
#
# Non-goals:
# - No external network calls
# - No framework coupling
#
# This module asserts no external facts; it implements security logic only.

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple


class ChallengeError(ValueError):
    pass


class ChallengeReplayError(ChallengeError):
    pass


class ChallengeExpiredError(ChallengeError):
    pass


class ChallengeSignatureError(ChallengeError):
    pass


class ChallengeStorage(Protocol):
    """
    Storage contract used to prevent replay.

    Required behavior:
    - put_if_absent(key, ttl_seconds) returns True if inserted, False if already exists
    - mark_consumed(key, ttl_seconds) returns True if marked, False if already consumed
    - is_consumed(key) returns True if consumed, False otherwise
    """

    def put_if_absent(self, key: str, ttl_seconds: int) -> bool:
        ...

    def mark_consumed(self, key: str, ttl_seconds: int) -> bool:
        ...

    def is_consumed(self, key: str) -> bool:
        ...


class InMemoryChallengeStorage:
    """
    Minimal in-memory storage.

    Notes:
    - Suitable for single-process usage, tests, local runs.
    - Not suitable for multi-replica deployments (use Redis or equivalent).
    """

    def __init__(self) -> None:
        self._items: Dict[str, Tuple[float, str]] = {}

    def _gc(self) -> None:
        now = time.time()
        dead = [k for k, (exp, _) in self._items.items() if exp <= now]
        for k in dead:
            self._items.pop(k, None)

    def put_if_absent(self, key: str, ttl_seconds: int) -> bool:
        self._gc()
        if key in self._items:
            return False
        exp = time.time() + max(1, int(ttl_seconds))
        self._items[key] = (exp, "issued")
        return True

    def mark_consumed(self, key: str, ttl_seconds: int) -> bool:
        self._gc()
        if key not in self._items:
            exp = time.time() + max(1, int(ttl_seconds))
            self._items[key] = (exp, "consumed")
            return True
        exp, state = self._items[key]
        if state == "consumed":
            return False
        new_exp = max(exp, time.time() + max(1, int(ttl_seconds)))
        self._items[key] = (new_exp, "consumed")
        return True

    def is_consumed(self, key: str) -> bool:
        self._gc()
        v = self._items.get(key)
        if not v:
            return False
        _, state = v
        return state == "consumed"


@dataclass(frozen=True)
class ChallengeBindings:
    """
    Optional bindings to restrict where the challenge can be used.

    audience: logical consumer (e.g. "webui", "cli", "approval-gate")
    subject: user or principal id
    session_id: session correlation id
    device_id: stable device identifier or fingerprint hash
    """

    audience: str
    subject: str
    operation: str
    session_id: Optional[str] = None
    device_id: Optional[str] = None


@dataclass(frozen=True)
class ChallengePayload:
    """
    Canonical payload that is signed.

    Fields:
    - ver: payload version
    - jti: unique token id (nonce)
    - iat: issued-at (unix seconds)
    - exp: expiry (unix seconds)
    - bindings: ChallengeBindings fields
    - nonce: additional entropy (separate from jti) to harden uniqueness
    """

    ver: int
    jti: str
    iat: int
    exp: int
    bindings: ChallengeBindings
    nonce: str


@dataclass(frozen=True)
class IssuedChallenge:
    """
    Issued challenge token.

    token: compact string for transport
    payload: parsed payload dict form
    """

    token: str
    payload: Dict[str, Any]


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    s = data.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _now() -> int:
    return int(time.time())


def _require_str(v: Any, name: str, *, allow_empty: bool = False, max_len: int = 256) -> str:
    if not isinstance(v, str):
        raise ChallengeError(f"{name} must be string")
    s = v.strip()
    if not allow_empty and not s:
        raise ChallengeError(f"{name} must be non-empty")
    if len(s) > max_len:
        raise ChallengeError(f"{name} too long")
    return s


def _canonical_json(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _payload_to_dict(p: ChallengePayload) -> Dict[str, Any]:
    b = p.bindings
    out: Dict[str, Any] = {
        "ver": p.ver,
        "jti": p.jti,
        "iat": p.iat,
        "exp": p.exp,
        "nonce": p.nonce,
        "bindings": {
            "aud": b.audience,
            "sub": b.subject,
            "op": b.operation,
        },
    }
    if b.session_id is not None:
        out["bindings"]["sid"] = b.session_id
    if b.device_id is not None:
        out["bindings"]["did"] = b.device_id
    return out


def _dict_to_payload(d: Mapping[str, Any]) -> ChallengePayload:
    try:
        ver = int(d["ver"])
        jti = _require_str(d["jti"], "jti", max_len=128)
        iat = int(d["iat"])
        exp = int(d["exp"])
        nonce = _require_str(d["nonce"], "nonce", max_len=256)
        bd = d["bindings"]
        if not isinstance(bd, dict):
            raise ChallengeError("bindings must be object")
        aud = _require_str(bd["aud"], "bindings.aud", max_len=128)
        sub = _require_str(bd["sub"], "bindings.sub", max_len=256)
        op = _require_str(bd["op"], "bindings.op", max_len=128)
        sid = bd.get("sid")
        did = bd.get("did")
        session_id = _require_str(sid, "bindings.sid", max_len=256) if sid is not None else None
        device_id = _require_str(did, "bindings.did", max_len=256) if did is not None else None
        bindings = ChallengeBindings(
            audience=aud,
            subject=sub,
            operation=op,
            session_id=session_id,
            device_id=device_id,
        )
        return ChallengePayload(ver=ver, jti=jti, iat=iat, exp=exp, bindings=bindings, nonce=nonce)
    except KeyError as e:
        raise ChallengeError(f"missing field: {str(e)}") from e
    except (TypeError, ValueError) as e:
        raise ChallengeError("invalid payload types") from e


class ChallengeIssuer:
    """
    Challenge issuer and verifier.

    Token format (compact):
      base64url(payload_json) + "." + base64url(signature)

    Signature:
      HMAC-SHA256(secret, canonical_json(payload))
    """

    def __init__(
        self,
        *,
        secret_key: bytes,
        storage: ChallengeStorage,
        token_version: int = 1,
        ttl_seconds: int = 120,
        consume_ttl_seconds: int = 600,
        clock_skew_seconds: int = 30,
    ) -> None:
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < 32:
            raise ChallengeError("secret_key must be bytes and at least 32 bytes long")
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            raise ChallengeError("ttl_seconds must be in range 1..3600")
        if consume_ttl_seconds <= 0 or consume_ttl_seconds > 86400:
            raise ChallengeError("consume_ttl_seconds must be in range 1..86400")
        if clock_skew_seconds < 0 or clock_skew_seconds > 300:
            raise ChallengeError("clock_skew_seconds must be in range 0..300")

        self._key = bytes(secret_key)
        self._storage = storage
        self._ver = int(token_version)
        self._ttl = int(ttl_seconds)
        self._consume_ttl = int(consume_ttl_seconds)
        self._skew = int(clock_skew_seconds)

    def issue(self, bindings: ChallengeBindings) -> IssuedChallenge:
        aud = _require_str(bindings.audience, "audience", max_len=128)
        sub = _require_str(bindings.subject, "subject", max_len=256)
        op = _require_str(bindings.operation, "operation", max_len=128)
        sid = _require_str(bindings.session_id, "session_id", max_len=256) if bindings.session_id else None
        did = _require_str(bindings.device_id, "device_id", max_len=256) if bindings.device_id else None

        now = _now()
        exp = now + self._ttl

        jti = "ch_" + secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)

        payload = ChallengePayload(
            ver=self._ver,
            jti=jti,
            iat=now,
            exp=exp,
            bindings=ChallengeBindings(audience=aud, subject=sub, operation=op, session_id=sid, device_id=did),
            nonce=nonce,
        )

        payload_dict = _payload_to_dict(payload)

        storage_key = self._issued_key(payload.ver, payload.jti)
        inserted = self._storage.put_if_absent(storage_key, ttl_seconds=self._ttl)
        if not inserted:
            raise ChallengeReplayError("challenge id collision or replay detected at issuance")

        token = self._encode(payload_dict)
        return IssuedChallenge(token=token, payload=payload_dict)

    def verify_and_consume(
        self,
        token: str,
        *,
        expected_audience: str,
        expected_subject: str,
        expected_operation: str,
        expected_session_id: Optional[str] = None,
        expected_device_id: Optional[str] = None,
    ) -> ChallengePayload:
        """
        Verifies token integrity, validates bindings, checks time bounds,
        and consumes the challenge to prevent replay.

        Returns parsed payload on success.
        Raises ChallengeError subclasses on failure.
        """
        payload_dict = self._decode_and_verify_signature(token)
        payload = _dict_to_payload(payload_dict)

        now = _now()

        if payload.iat - self._skew > now:
            raise ChallengeExpiredError("challenge issued in the future beyond skew tolerance")

        if now > payload.exp + self._skew:
            raise ChallengeExpiredError("challenge expired")

        b = payload.bindings
        if b.audience != _require_str(expected_audience, "expected_audience", max_len=128):
            raise ChallengeError("audience mismatch")
        if b.subject != _require_str(expected_subject, "expected_subject", max_len=256):
            raise ChallengeError("subject mismatch")
        if b.operation != _require_str(expected_operation, "expected_operation", max_len=128):
            raise ChallengeError("operation mismatch")

        if expected_session_id is not None:
            if b.session_id is None or b.session_id != _require_str(expected_session_id, "expected_session_id", max_len=256):
                raise ChallengeError("session_id mismatch")

        if expected_device_id is not None:
            if b.device_id is None or b.device_id != _require_str(expected_device_id, "expected_device_id", max_len=256):
                raise ChallengeError("device_id mismatch")

        issued_key = self._issued_key(payload.ver, payload.jti)
        consumed_key = self._consumed_key(payload.ver, payload.jti)

        if self._storage.is_consumed(consumed_key):
            raise ChallengeReplayError("challenge already consumed")

        if not self._storage.mark_consumed(consumed_key, ttl_seconds=self._consume_ttl):
            raise ChallengeReplayError("challenge already consumed")

        return payload

    def peek(self, token: str) -> ChallengePayload:
        """
        Verify signature and parse payload without consuming it.
        Useful for diagnostics, but do not use for security decisions alone.
        """
        payload_dict = self._decode_and_verify_signature(token)
        return _dict_to_payload(payload_dict)

    def _encode(self, payload_dict: Mapping[str, Any]) -> str:
        payload_bytes = _canonical_json(payload_dict)
        sig = _hmac_sha256(self._key, payload_bytes)
        return _b64url_encode(payload_bytes) + "." + _b64url_encode(sig)

    def _decode_and_verify_signature(self, token: str) -> Dict[str, Any]:
        t = _require_str(token, "token", max_len=4096)
        if "." not in t:
            raise ChallengeSignatureError("invalid token format")
        a, b = t.split(".", 1)
        if not a or not b:
            raise ChallengeSignatureError("invalid token format")

        try:
            payload_bytes = _b64url_decode(a)
            sig_bytes = _b64url_decode(b)
        except Exception as e:
            raise ChallengeSignatureError("invalid base64url encoding") from e

        expected_sig = _hmac_sha256(self._key, payload_bytes)
        if not hmac.compare_digest(sig_bytes, expected_sig):
            raise ChallengeSignatureError("signature mismatch")

        try:
            obj = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            raise ChallengeError("payload is not valid json") from e

        if not isinstance(obj, dict):
            raise ChallengeError("payload must be json object")

        return obj

    @staticmethod
    def _issued_key(ver: int, jti: str) -> str:
        return f"issued:v{int(ver)}:{jti}"

    @staticmethod
    def _consumed_key(ver: int, jti: str) -> str:
        return f"consumed:v{int(ver)}:{jti}"


def derive_device_id_fingerprint(*, raw: str, salt: bytes) -> str:
    """
    Derive a stable device identifier fingerprint from raw input and a salt.

    This function does not define what "raw" must be.
    Typical usage is hashing a normalized device descriptor string.

    Output is a hex digest string.
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ChallengeError("salt must be bytes and at least 16 bytes long")
    s = _require_str(raw, "raw", max_len=2048)
    h = hashlib.sha256()
    h.update(bytes(salt))
    h.update(b"\x00")
    h.update(s.encode("utf-8"))
    return h.hexdigest()
