# human-sovereignty-core/approval/human_token.py

from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple


class HumanApprovalTokenError(Exception):
    """Base error for human approval token operations."""


class HumanApprovalTokenParseError(HumanApprovalTokenError):
    """Raised when token cannot be parsed."""


class HumanApprovalTokenValidationError(HumanApprovalTokenError):
    """Raised when token claims or structure is invalid."""


class HumanApprovalTokenSignatureError(HumanApprovalTokenValidationError):
    """Raised when token signature is invalid."""


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _to_int_ts(dt: _dt.datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return int(dt.timestamp())


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not s:
        raise HumanApprovalTokenParseError("Invalid base64url input")
    padding = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode((s + padding).encode("ascii"))
    except Exception as e:
        raise HumanApprovalTokenParseError("Invalid base64url encoding") from e


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _hmac_sha256(secret: bytes, msg: bytes) -> bytes:
    return hmac.new(secret, msg, hashlib.sha256).digest()


def _consteq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


@dataclass(frozen=True)
class TokenHeader:
    alg: str = "HS256"
    typ: str = "HAT"  # Human Approval Token
    kid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"alg": self.alg, "typ": self.typ}
        if self.kid is not None:
            d["kid"] = self.kid
        return d


@dataclass(frozen=True)
class TokenClaims:
    """
    Minimal required claims for human approval.

    sub: who approved
    iat: issued at (unix seconds)
    exp: expiration (unix seconds)
    policy_id: policy identifier binding the approval to a specific policy
    action_id: action identifier binding the approval to a specific action
    Optional: jti, iss, aud, nonce, meta
    """

    sub: str
    iat: int
    exp: int
    policy_id: str
    action_id: str
    jti: Optional[str] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    nonce: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "sub": self.sub,
            "iat": int(self.iat),
            "exp": int(self.exp),
            "policy_id": self.policy_id,
            "action_id": self.action_id,
        }
        if self.jti is not None:
            d["jti"] = self.jti
        if self.iss is not None:
            d["iss"] = self.iss
        if self.aud is not None:
            d["aud"] = self.aud
        if self.nonce is not None:
            d["nonce"] = self.nonce
        if self.meta is not None:
            d["meta"] = self.meta
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "TokenClaims":
        if not isinstance(d, Mapping):
            raise HumanApprovalTokenValidationError("Claims must be an object")

        def req_str(k: str) -> str:
            v = d.get(k)
            if not isinstance(v, str) or not v:
                raise HumanApprovalTokenValidationError(f"Missing or invalid claim: {k}")
            return v

        def req_int(k: str) -> int:
            v = d.get(k)
            if not isinstance(v, int):
                raise HumanApprovalTokenValidationError(f"Missing or invalid claim: {k}")
            return int(v)

        sub = req_str("sub")
        iat = req_int("iat")
        exp = req_int("exp")
        policy_id = req_str("policy_id")
        action_id = req_str("action_id")

        jti = d.get("jti")
        if jti is not None and not isinstance(jti, str):
            raise HumanApprovalTokenValidationError("Invalid claim: jti")

        iss = d.get("iss")
        if iss is not None and not isinstance(iss, str):
            raise HumanApprovalTokenValidationError("Invalid claim: iss")

        aud = d.get("aud")
        if aud is not None and not isinstance(aud, str):
            raise HumanApprovalTokenValidationError("Invalid claim: aud")

        nonce = d.get("nonce")
        if nonce is not None and not isinstance(nonce, str):
            raise HumanApprovalTokenValidationError("Invalid claim: nonce")

        meta = d.get("meta")
        if meta is not None and not isinstance(meta, dict):
            raise HumanApprovalTokenValidationError("Invalid claim: meta")

        return TokenClaims(
            sub=sub,
            iat=iat,
            exp=exp,
            policy_id=policy_id,
            action_id=action_id,
            jti=jti,
            iss=iss,
            aud=aud,
            nonce=nonce,
            meta=meta,
        )


@dataclass(frozen=True)
class HumanApprovalTokenCodec:
    """
    Compact JWS-like token codec with HS256 signing, without external dependencies.

    Token format: base64url(header_json).base64url(payload_json).base64url(signature)

    Industrial features:
    - Deterministic JSON (canonical) for stable signing
    - Constant-time signature compare
    - Key rotation via kid
    - Strict time validation with leeway and max_ttl
    - Optional issuer and audience binding
    """

    secrets_by_kid: Mapping[str, bytes]
    default_kid: str

    leeway_seconds: int = 30
    max_ttl_seconds: int = 900

    required_alg: str = "HS256"
    required_typ: str = "HAT"

    require_iss: Optional[str] = None
    require_aud: Optional[str] = None

    def issue(
        self,
        *,
        sub: str,
        policy_id: str,
        action_id: str,
        ttl_seconds: Optional[int] = None,
        kid: Optional[str] = None,
        iss: Optional[str] = None,
        aud: Optional[str] = None,
        jti: Optional[str] = None,
        nonce: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        now: Optional[_dt.datetime] = None,
    ) -> str:
        if not isinstance(sub, str) or not sub:
            raise HumanApprovalTokenValidationError("sub must be a non-empty string")
        if not isinstance(policy_id, str) or not policy_id:
            raise HumanApprovalTokenValidationError("policy_id must be a non-empty string")
        if not isinstance(action_id, str) or not action_id:
            raise HumanApprovalTokenValidationError("action_id must be a non-empty string")

        used_kid = kid or self.default_kid
        secret = self.secrets_by_kid.get(used_kid)
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise HumanApprovalTokenValidationError("Signing secret not found for kid")

        now_dt = now or _utc_now()
        iat = _to_int_ts(now_dt)

        ttl = int(ttl_seconds) if ttl_seconds is not None else int(self.max_ttl_seconds)
        if ttl <= 0:
            raise HumanApprovalTokenValidationError("ttl_seconds must be positive")
        if ttl > self.max_ttl_seconds:
            raise HumanApprovalTokenValidationError("ttl_seconds exceeds max_ttl_seconds")

        exp = iat + ttl

        header = TokenHeader(alg=self.required_alg, typ=self.required_typ, kid=used_kid).to_dict()
        claims = TokenClaims(
            sub=sub,
            iat=iat,
            exp=exp,
            policy_id=policy_id,
            action_id=action_id,
            jti=jti,
            iss=iss,
            aud=aud,
            nonce=nonce,
            meta=meta,
        ).to_dict()

        h64 = _b64url_encode(_canonical_json_bytes(header))
        p64 = _b64url_encode(_canonical_json_bytes(claims))
        signing_input = f"{h64}.{p64}".encode("ascii")
        sig = _hmac_sha256(bytes(secret), signing_input)
        s64 = _b64url_encode(sig)
        return f"{h64}.{p64}.{s64}"

    def verify(
        self,
        token: str,
        *,
        expected_policy_id: Optional[str] = None,
        expected_action_id: Optional[str] = None,
        expected_sub: Optional[str] = None,
        now: Optional[_dt.datetime] = None,
    ) -> TokenClaims:
        header, payload, sig = self._parse_compact(token)
        self._validate_header(header)
        secret = self._resolve_secret(header)

        signing_input = self._signing_input_from_parts(token)
        expected_sig = _hmac_sha256(secret, signing_input)
        if not _consteq(expected_sig, sig):
            raise HumanApprovalTokenSignatureError("Invalid token signature")

        claims = TokenClaims.from_dict(payload)
        self._validate_time(claims, now=now)

        if self.require_iss is not None:
            if claims.iss != self.require_iss:
                raise HumanApprovalTokenValidationError("Issuer mismatch")

        if self.require_aud is not None:
            if claims.aud != self.require_aud:
                raise HumanApprovalTokenValidationError("Audience mismatch")

        if expected_policy_id is not None and claims.policy_id != expected_policy_id:
            raise HumanApprovalTokenValidationError("policy_id mismatch")

        if expected_action_id is not None and claims.action_id != expected_action_id:
            raise HumanApprovalTokenValidationError("action_id mismatch")

        if expected_sub is not None and claims.sub != expected_sub:
            raise HumanApprovalTokenValidationError("sub mismatch")

        ttl = claims.exp - claims.iat
        if ttl <= 0:
            raise HumanApprovalTokenValidationError("Invalid token lifetime")
        if ttl > self.max_ttl_seconds:
            raise HumanApprovalTokenValidationError("Token lifetime exceeds max_ttl_seconds")

        return claims

    def decode_unverified(self, token: str) -> Tuple[TokenHeader, Dict[str, Any]]:
        header, payload, _sig = self._parse_compact(token)
        kid = header.get("kid")
        th = TokenHeader(
            alg=str(header.get("alg", "")),
            typ=str(header.get("typ", "")),
            kid=str(kid) if isinstance(kid, str) else None,
        )
        return th, payload

    def _parse_compact(self, token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes]:
        if not isinstance(token, str) or not token:
            raise HumanApprovalTokenParseError("Token must be a non-empty string")

        parts = token.split(".")
        if len(parts) != 3:
            raise HumanApprovalTokenParseError("Token must have exactly 3 parts")

        h64, p64, s64 = parts
        header = self._json_from_b64url(h64, "header")
        payload = self._json_from_b64url(p64, "payload")
        sig = _b64url_decode(s64)

        if not isinstance(header, dict):
            raise HumanApprovalTokenParseError("Header must be an object")
        if not isinstance(payload, dict):
            raise HumanApprovalTokenParseError("Payload must be an object")

        return header, payload, sig

    def _signing_input_from_parts(self, token: str) -> bytes:
        # Safe: do not reserialize; take original first two segments.
        h64, p64, _s64 = token.split(".", 2)
        return f"{h64}.{p64}".encode("ascii")

    def _json_from_b64url(self, s: str, part_name: str) -> Any:
        raw = _b64url_decode(s)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise HumanApprovalTokenParseError(f"Invalid JSON in {part_name}") from e

    def _validate_header(self, header: Mapping[str, Any]) -> None:
        alg = header.get("alg")
        typ = header.get("typ")
        if alg != self.required_alg:
            raise HumanApprovalTokenValidationError("Unsupported alg")
        if typ != self.required_typ:
            raise HumanApprovalTokenValidationError("Unsupported typ")

        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise HumanApprovalTokenValidationError("Invalid kid type")

    def _resolve_secret(self, header: Mapping[str, Any]) -> bytes:
        kid = header.get("kid")
        used_kid = kid if isinstance(kid, str) and kid else self.default_kid
        secret = self.secrets_by_kid.get(used_kid)
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise HumanApprovalTokenValidationError("Verification secret not found for kid")
        return bytes(secret)

    def _validate_time(self, claims: TokenClaims, *, now: Optional[_dt.datetime]) -> None:
        now_dt = now or _utc_now()
        now_ts = _to_int_ts(now_dt)
        leeway = int(self.leeway_seconds)

        if claims.iat > now_ts + leeway:
            raise HumanApprovalTokenValidationError("Token used before issued (iat in future)")

        if claims.exp <= 0 or claims.iat <= 0:
            raise HumanApprovalTokenValidationError("Invalid iat/exp values")

        if now_ts > claims.exp + leeway:
            raise HumanApprovalTokenValidationError("Token expired")

        if claims.exp <= claims.iat:
            raise HumanApprovalTokenValidationError("Invalid token time window")
