# decision_packets/validator.py
from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


class DecisionPacketError(Exception):
    """Base error for decision packet validation."""


class DecisionPacketParseError(DecisionPacketError):
    """Raised when input cannot be parsed into a packet."""


class DecisionPacketValidationError(DecisionPacketError):
    """Raised when packet fails validation."""

    def __init__(self, message: str, path: str = "", code: str = "invalid"):
        super().__init__(message)
        self.message = message
        self.path = path
        self.code = code

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


class DecisionPacketIntegrityError(DecisionPacketValidationError):
    """Raised when integrity hash check fails."""


class DecisionPacketSignatureError(DecisionPacketValidationError):
    """Raised when signature verification fails."""


JSONValue = Union[None, bool, int, float, str, List["JSONValue"], Dict[str, "JSONValue"]]
PacketInput = Union[str, bytes, bytearray, Mapping[str, Any]]


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-:.]{7,127}$")
_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][A-Za-z0-9.\-+]+)?$")


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _is_iso8601_utc(s: str) -> bool:
    # Accepts "2026-01-27T12:34:56Z" or with fractional seconds.
    try:
        if s.endswith("Z"):
            _dt.datetime.fromisoformat(s[:-1]).replace(tzinfo=_dt.timezone.utc)
            return True
        dt = _dt.datetime.fromisoformat(s)
        return dt.tzinfo is not None
    except Exception:
        return False


def _b64decode(s: str, *, path: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:
        raise DecisionPacketValidationError("Invalid base64 encoding", path=path, code="base64") from e


def _canonical_json(obj: Any) -> bytes:
    # Deterministic representation for hashing/signatures.
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_len(x: Any) -> int:
    try:
        return len(x)  # type: ignore[arg-type]
    except Exception:
        return 0


@dataclass(frozen=True)
class ValidatorPolicy:
    """
    Industrial policy defaults:
    - strict schema: forbid unknown keys at top-level and for known nested blocks
    - size limits to prevent abuse
    - deterministic canonicalization for stable hashing
    """

    max_input_bytes: int = 512_000
    max_json_depth: int = 64
    max_list_items: int = 10_000
    max_str_len: int = 64_000

    require_version: bool = True
    require_id: bool = True
    require_created_at: bool = True
    require_kind: bool = True

    allow_unknown_top_level_keys: bool = False
    allow_unknown_metadata_keys: bool = True

    allowed_kinds: Tuple[str, ...] = ("decision_packet",)

    # Integrity section behavior.
    integrity_required: bool = False
    integrity_algorithm: str = "sha256"
    integrity_field: str = "integrity"
    integrity_hash_field: str = "hash"

    # Signature section behavior (optional).
    signature_required: bool = False
    signature_field: str = "signature"
    signature_algorithms: Tuple[str, ...] = ("ed25519", "rsa-pss-sha256", "hmac-sha256")
    # If using hmac-sha256, provide secret via verify_hmac_secret callback or directly in validate().
    # For public key algorithms, provide key material through verify_public_key callback.

    # Time window checks.
    max_clock_skew_seconds: int = 300
    max_packet_age_seconds: int = 7 * 24 * 3600

    # Strictness for nested blocks
    forbid_unknown_context_keys: bool = False
    forbid_unknown_decisions_keys: bool = False


@dataclass(frozen=True)
class ValidationResult:
    packet: Dict[str, Any]
    canonical_bytes: bytes
    canonical_sha256: str


def _ensure_type(value: Any, expected: Union[type, Tuple[type, ...]], *, path: str) -> None:
    if not isinstance(value, expected):
        exp = expected if isinstance(expected, tuple) else (expected,)
        exp_names = ", ".join(t.__name__ for t in exp)
        raise DecisionPacketValidationError(
            f"Expected {exp_names}, got {type(value).__name__}",
            path=path,
            code="type",
        )


def _ensure_str(value: Any, *, path: str, policy: ValidatorPolicy) -> str:
    _ensure_type(value, str, path=path)
    if len(value) > policy.max_str_len:
        raise DecisionPacketValidationError("String too long", path=path, code="size")
    return value


def _ensure_dict(value: Any, *, path: str) -> Dict[str, Any]:
    _ensure_type(value, dict, path=path)
    return value  # type: ignore[return-value]


def _ensure_list(value: Any, *, path: str, policy: ValidatorPolicy) -> List[Any]:
    _ensure_type(value, list, path=path)
    if len(value) > policy.max_list_items:
        raise DecisionPacketValidationError("List too large", path=path, code="size")
    return value  # type: ignore[return-value]


def _walk_depth(obj: Any, *, max_depth: int, path: str = "$", depth: int = 0) -> None:
    if depth > max_depth:
        raise DecisionPacketValidationError("JSON exceeds max depth", path=path, code="depth")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_depth(v, max_depth=max_depth, path=f"{path}.{k}", depth=depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_depth(v, max_depth=max_depth, path=f"{path}[{i}]", depth=depth + 1)


def _parse_input(inp: PacketInput, *, policy: ValidatorPolicy) -> Dict[str, Any]:
    if isinstance(inp, Mapping):
        return dict(inp)

    if isinstance(inp, (bytes, bytearray)):
        raw = bytes(inp)
        if len(raw) > policy.max_input_bytes:
            raise DecisionPacketParseError("Input too large")
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise DecisionPacketParseError("Invalid JSON bytes") from e

    if isinstance(inp, str):
        # Treat as JSON string, not path.
        raw = inp.encode("utf-8")
        if len(raw) > policy.max_input_bytes:
            raise DecisionPacketParseError("Input too large")
        try:
            return json.loads(inp)
        except Exception as e:
            raise DecisionPacketParseError("Invalid JSON string") from e

    raise DecisionPacketParseError("Unsupported input type")


def _expect_keys(
    obj: Dict[str, Any],
    *,
    required: Iterable[str],
    allowed: Optional[Iterable[str]],
    path: str,
    allow_unknown: bool,
) -> None:
    req = set(required)
    for k in req:
        if k not in obj:
            raise DecisionPacketValidationError("Missing required field", path=f"{path}.{k}", code="required")

    if allowed is None:
        if not allow_unknown:
            # If not provided allowed keys, we cannot enforce. Keep safe: allow.
            return
        return

    allowed_set = set(allowed)
    if not allow_unknown:
        unknown = [k for k in obj.keys() if k not in allowed_set]
        if unknown:
            raise DecisionPacketValidationError(
                "Unknown field(s) not allowed",
                path=path,
                code="unknown",
            )


def _validate_header(packet: Dict[str, Any], *, policy: ValidatorPolicy) -> None:
    allowed = {
        "version",
        "id",
        "kind",
        "created_at",
        "actor",
        "context",
        "decisions",
        "metadata",
        policy.integrity_field,
        policy.signature_field,
    }

    required: List[str] = []
    if policy.require_version:
        required.append("version")
    if policy.require_id:
        required.append("id")
    if policy.require_kind:
        required.append("kind")
    if policy.require_created_at:
        required.append("created_at")

    _expect_keys(
        packet,
        required=required,
        allowed=allowed if not policy.allow_unknown_top_level_keys else None,
        path="$",
        allow_unknown=policy.allow_unknown_top_level_keys,
    )

    if "version" in packet:
        v = _ensure_str(packet["version"], path="$.version", policy=policy)
        if not _VERSION_RE.match(v):
            raise DecisionPacketValidationError("Invalid version format", path="$.version", code="format")

    if "id" in packet:
        pid = _ensure_str(packet["id"], path="$.id", policy=policy)
        if not _ID_RE.match(pid):
            raise DecisionPacketValidationError("Invalid id format", path="$.id", code="format")

    if "kind" in packet:
        k = _ensure_str(packet["kind"], path="$.kind", policy=policy)
        if policy.allowed_kinds and k not in policy.allowed_kinds:
            raise DecisionPacketValidationError("Unsupported kind", path="$.kind", code="value")

    if "created_at" in packet:
        ca = _ensure_str(packet["created_at"], path="$.created_at", policy=policy)
        if not _is_iso8601_utc(ca):
            raise DecisionPacketValidationError("created_at must be ISO-8601 with timezone", path="$.created_at", code="format")
        # Age and skew checks
        try:
            if ca.endswith("Z"):
                created = _dt.datetime.fromisoformat(ca[:-1]).replace(tzinfo=_dt.timezone.utc)
            else:
                created = _dt.datetime.fromisoformat(ca)
        except Exception as e:
            raise DecisionPacketValidationError("created_at parse failed", path="$.created_at", code="format") from e

        now = _utc_now()
        skew = abs((now - created).total_seconds())
        if skew > (policy.max_packet_age_seconds + policy.max_clock_skew_seconds):
            # Too old or too far in future beyond acceptable window.
            raise DecisionPacketValidationError("created_at outside acceptable time window", path="$.created_at", code="time")

        if (now - created).total_seconds() < -policy.max_clock_skew_seconds:
            raise DecisionPacketValidationError("created_at is in the future beyond skew limit", path="$.created_at", code="time")

        if (now - created).total_seconds() > policy.max_packet_age_seconds:
            raise DecisionPacketValidationError("Packet too old", path="$.created_at", code="time")


def _validate_actor(packet: Dict[str, Any], *, policy: ValidatorPolicy) -> None:
    if "actor" not in packet:
        return
    actor = _ensure_dict(packet["actor"], path="$.actor")
    # actor is intentionally flexible; enforce minimal sanity if present
    if "id" in actor:
        _ensure_str(actor["id"], path="$.actor.id", policy=policy)
    if "type" in actor:
        _ensure_str(actor["type"], path="$.actor.type", policy=policy)
    if "roles" in actor:
        roles = _ensure_list(actor["roles"], path="$.actor.roles", policy=policy)
        for i, r in enumerate(roles):
            _ensure_str(r, path=f"$.actor.roles[{i}]", policy=policy)


def _validate_context(packet: Dict[str, Any], *, policy: ValidatorPolicy) -> None:
    if "context" not in packet:
        return
    ctx = _ensure_dict(packet["context"], path="$.context")
    # Optional strict key control for context
    if policy.forbid_unknown_context_keys:
        allowed = {"trace_id", "request_id", "session_id", "tenant_id", "environment", "tags"}
        unknown = [k for k in ctx.keys() if k not in allowed]
        if unknown:
            raise DecisionPacketValidationError("Unknown context key(s) not allowed", path="$.context", code="unknown")

    if "tags" in ctx:
        tags = _ensure_list(ctx["tags"], path="$.context.tags", policy=policy)
        for i, t in enumerate(tags):
            _ensure_str(t, path=f"$.context.tags[{i}]", policy=policy)

    for key in ("trace_id", "request_id", "session_id", "tenant_id", "environment"):
        if key in ctx:
            _ensure_str(ctx[key], path=f"$.context.{key}", policy=policy)


def _validate_decisions(packet: Dict[str, Any], *, policy: ValidatorPolicy) -> None:
    if "decisions" not in packet:
        return
    decisions = _ensure_list(packet["decisions"], path="$.decisions", policy=policy)

    for i, d in enumerate(decisions):
        _ensure_type(d, dict, path=f"$.decisions[{i}]")
        dd = d  # type: ignore[assignment]
        # Minimal required in each decision
        required = {"action", "confidence"}
        allowed = {"action", "confidence", "reason", "constraints", "evidence", "effects", "meta"}
        _expect_keys(
            dd,
            required=required,
            allowed=allowed if policy.forbid_unknown_decisions_keys else None,
            path=f"$.decisions[{i}]",
            allow_unknown=not policy.forbid_unknown_decisions_keys,
        )

        _ensure_str(dd.get("action"), path=f"$.decisions[{i}].action", policy=policy)

        conf = dd.get("confidence")
        if not isinstance(conf, (int, float)):
            raise DecisionPacketValidationError("confidence must be number", path=f"$.decisions[{i}].confidence", code="type")
        if conf < 0.0 or conf > 1.0:
            raise DecisionPacketValidationError("confidence must be in [0,1]", path=f"$.decisions[{i}].confidence", code="value")

        if "reason" in dd:
            _ensure_str(dd["reason"], path=f"$.decisions[{i}].reason", policy=policy)

        if "constraints" in dd:
            _ensure_type(dd["constraints"], (dict, list), path=f"$.decisions[{i}].constraints")

        if "evidence" in dd:
            _ensure_type(dd["evidence"], (dict, list, str), path=f"$.decisions[{i}].evidence")
            if isinstance(dd["evidence"], str):
                _ensure_str(dd["evidence"], path=f"$.decisions[{i}].evidence", policy=policy)

        if "effects" in dd:
            _ensure_type(dd["effects"], (dict, list), path=f"$.decisions[{i}].effects")

        if "meta" in dd:
            _ensure_type(dd["meta"], dict, path=f"$.decisions[{i}].meta")


def _validate_metadata(packet: Dict[str, Any], *, policy: ValidatorPolicy) -> None:
    if "metadata" not in packet:
        return
    md = _ensure_dict(packet["metadata"], path="$.metadata")
    if not policy.allow_unknown_metadata_keys:
        allowed = {"source", "labels", "notes"}
        unknown = [k for k in md.keys() if k not in allowed]
        if unknown:
            raise DecisionPacketValidationError("Unknown metadata key(s) not allowed", path="$.metadata", code="unknown")

    if "labels" in md:
        labels = _ensure_list(md["labels"], path="$.metadata.labels", policy=policy)
        for i, x in enumerate(labels):
            _ensure_str(x, path=f"$.metadata.labels[{i}]", policy=policy)

    for key in ("source", "notes"):
        if key in md:
            _ensure_str(md[key], path=f"$.metadata.{key}", policy=policy)


def _strip_integrity_and_signature(packet: Dict[str, Any], *, policy: ValidatorPolicy) -> Dict[str, Any]:
    # Exclude fields from canonical hashing/signing.
    clone = json.loads(json.dumps(packet))
    clone.pop(policy.integrity_field, None)
    clone.pop(policy.signature_field, None)
    return clone


def _validate_integrity(packet: Dict[str, Any], canonical_bytes: bytes, *, policy: ValidatorPolicy) -> None:
    integ_key = policy.integrity_field
    if integ_key not in packet:
        if policy.integrity_required:
            raise DecisionPacketIntegrityError("Missing integrity block", path=f"$.{integ_key}", code="required")
        return

    integ = _ensure_dict(packet[integ_key], path=f"$.{integ_key}")
    alg = integ.get("alg", policy.integrity_algorithm)
    _ensure_str(alg, path=f"$.{integ_key}.alg", policy=policy)
    if alg.lower() != "sha256":
        raise DecisionPacketIntegrityError("Unsupported integrity algorithm", path=f"$.{integ_key}.alg", code="value")

    hfield = policy.integrity_hash_field
    if hfield not in integ:
        raise DecisionPacketIntegrityError("Missing integrity hash", path=f"$.{integ_key}.{hfield}", code="required")

    expected = _ensure_str(integ[hfield], path=f"$.{integ_key}.{hfield}", policy=policy)
    actual = _sha256_hex(canonical_bytes)
    if not hmac.compare_digest(expected, actual):
        raise DecisionPacketIntegrityError("Integrity hash mismatch", path=f"$.{integ_key}.{hfield}", code="integrity")


def _try_verify_signature_cryptography(alg: str, public_key_b64: str, signature_b64: str, message: bytes, *, path: str) -> None:
    # This verifier is optional and only runs if cryptography is installed.
    try:
        from cryptography.hazmat.primitives import hashes, serialization  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa  # type: ignore
    except Exception as e:
        raise DecisionPacketSignatureError("Signature verification unavailable (cryptography not installed)", path=path, code="unavailable") from e

    sig = _b64decode(signature_b64, path=f"{path}.sig")
    pk_bytes = _b64decode(public_key_b64, path=f"{path}.public_key")

    if alg == "ed25519":
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
            pk.verify(sig, message)
            return
        except Exception as e:
            raise DecisionPacketSignatureError("ed25519 signature invalid", path=path, code="signature") from e

    if alg == "rsa-pss-sha256":
        try:
            pk = serialization.load_der_public_key(pk_bytes)
            if not isinstance(pk, rsa.RSAPublicKey):
                raise DecisionPacketSignatureError("Public key is not RSA", path=path, code="type")
            pk.verify(
                sig,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return
        except DecisionPacketValidationError:
            raise
        except Exception as e:
            raise DecisionPacketSignatureError("rsa-pss-sha256 signature invalid", path=path, code="signature") from e

    raise DecisionPacketSignatureError("Unsupported signature algorithm", path=f"{path}.alg", code="value")


def _validate_signature(
    packet: Dict[str, Any],
    canonical_bytes: bytes,
    *,
    policy: ValidatorPolicy,
    verify_public_key: Optional[Callable[[str, Dict[str, Any]], Tuple[str, str]]] = None,
    verify_hmac_secret: Optional[Callable[[str, Dict[str, Any]], bytes]] = None,
    hmac_secret: Optional[bytes] = None,
) -> None:
    sfield = policy.signature_field
    if sfield not in packet:
        if policy.signature_required:
            raise DecisionPacketSignatureError("Missing signature block", path=f"$.{sfield}", code="required")
        return

    sigblk = _ensure_dict(packet[sfield], path=f"$.{sfield}")
    required = {"alg", "sig"}
    allowed = {"alg", "sig", "kid", "public_key", "meta"}
    _expect_keys(sigblk, required=required, allowed=allowed, path=f"$.{sfield}", allow_unknown=True)

    alg = _ensure_str(sigblk["alg"], path=f"$.{sfield}.alg", policy=policy)
    if policy.signature_algorithms and alg not in policy.signature_algorithms:
        raise DecisionPacketSignatureError("Unsupported signature algorithm", path=f"$.{sfield}.alg", code="value")

    sig_b64 = _ensure_str(sigblk["sig"], path=f"$.{sfield}.sig", policy=policy)

    if alg == "hmac-sha256":
        secret = hmac_secret
        kid = sigblk.get("kid")
        if secret is None and verify_hmac_secret is not None:
            if kid is None:
                raise DecisionPacketSignatureError("kid required for HMAC key lookup", path=f"$.{sfield}.kid", code="required")
            kid_s = _ensure_str(kid, path=f"$.{sfield}.kid", policy=policy)
            secret = verify_hmac_secret(kid_s, packet)
        if secret is None:
            raise DecisionPacketSignatureError("HMAC secret not provided", path=f"$.{sfield}", code="unavailable")

        expected = hmac.new(secret, canonical_bytes, hashlib.sha256).digest()
        actual = _b64decode(sig_b64, path=f"$.{sfield}.sig")
        if not hmac.compare_digest(expected, actual):
            raise DecisionPacketSignatureError("HMAC signature invalid", path=f"$.{sfield}", code="signature")
        return

    # Public-key verification
    public_key_b64: Optional[str] = None
    if "public_key" in sigblk:
        public_key_b64 = _ensure_str(sigblk["public_key"], path=f"$.{sfield}.public_key", policy=policy)

    kid = sigblk.get("kid")
    kid_s: Optional[str] = None
    if kid is not None:
        kid_s = _ensure_str(kid, path=f"$.{sfield}.kid", policy=policy)

    if public_key_b64 is None:
        if verify_public_key is None:
            raise DecisionPacketSignatureError("Public key not provided and verify_public_key not configured", path=f"$.{sfield}", code="unavailable")
        if kid_s is None:
            raise DecisionPacketSignatureError("kid required for public key lookup", path=f"$.{sfield}.kid", code="required")
        resolved_alg, resolved_pk = verify_public_key(kid_s, packet)
        if resolved_alg != alg:
            raise DecisionPacketSignatureError("Resolved key algorithm mismatch", path=f"$.{sfield}.alg", code="value")
        public_key_b64 = resolved_pk

    _try_verify_signature_cryptography(alg, public_key_b64, sig_b64, canonical_bytes, path=f"$.{sfield}")


def validate_packet(
    inp: PacketInput,
    *,
    policy: Optional[ValidatorPolicy] = None,
    extra_rules: Optional[Sequence[Callable[[Dict[str, Any]], None]]] = None,
    verify_public_key: Optional[Callable[[str, Dict[str, Any]], Tuple[str, str]]] = None,
    verify_hmac_secret: Optional[Callable[[str, Dict[str, Any]], bytes]] = None,
    hmac_secret: Optional[bytes] = None,
    normalize: bool = True,
) -> ValidationResult:
    """
    Validates and optionally normalizes a decision packet.

    Input formats:
    - dict-like mapping
    - JSON string
    - JSON bytes

    Returns:
    - normalized packet (if normalize=True)
    - canonical bytes of packet content excluding integrity/signature
    - sha256 of canonical bytes

    Raises:
    - DecisionPacketParseError
    - DecisionPacketValidationError
    - DecisionPacketIntegrityError
    - DecisionPacketSignatureError
    """
    pol = policy or ValidatorPolicy()
    packet = _parse_input(inp, policy=pol)
    _ensure_type(packet, dict, path="$")
    _walk_depth(packet, max_depth=pol.max_json_depth)

    _validate_header(packet, policy=pol)
    _validate_actor(packet, policy=pol)
    _validate_context(packet, policy=pol)
    _validate_decisions(packet, policy=pol)
    _validate_metadata(packet, policy=pol)

    # Normalization step (safe, deterministic)
    if normalize:
        # Ensure stable top-level key order indirectly through canonicalization.
        # Convert any datetime objects mistakenly passed in dict-like inputs.
        def _convert(x: Any) -> Any:
            if isinstance(x, _dt.datetime):
                if x.tzinfo is None:
                    x = x.replace(tzinfo=_dt.timezone.utc)
                return x.isoformat().replace("+00:00", "Z")
            if isinstance(x, dict):
                return {str(k): _convert(v) for k, v in x.items()}
            if isinstance(x, list):
                return [_convert(v) for v in x]
            return x

        packet = _convert(packet)

    canonical_obj = _strip_integrity_and_signature(packet, policy=pol)
    canonical_bytes = _canonical_json(canonical_obj)
    canonical_sha = _sha256_hex(canonical_bytes)

    _validate_integrity(packet, canonical_bytes, policy=pol)
    _validate_signature(
        packet,
        canonical_bytes,
        policy=pol,
        verify_public_key=verify_public_key,
        verify_hmac_secret=verify_hmac_secret,
        hmac_secret=hmac_secret,
    )

    if extra_rules:
        for idx, rule in enumerate(extra_rules):
            try:
                rule(packet)
            except DecisionPacketValidationError:
                raise
            except Exception as e:
                raise DecisionPacketValidationError(
                    "Extra rule failed",
                    path=f"$.extra_rules[{idx}]",
                    code="rule",
                ) from e

    return ValidationResult(packet=packet, canonical_bytes=canonical_bytes, canonical_sha256=canonical_sha)


def compute_integrity_hash(inp: PacketInput, *, policy: Optional[ValidatorPolicy] = None) -> str:
    """
    Computes sha256 over canonical packet bytes excluding integrity/signature.
    Useful to populate integrity.hash before signing.
    """
    pol = policy or ValidatorPolicy()
    packet = _parse_input(inp, policy=pol)
    _ensure_type(packet, dict, path="$")
    _walk_depth(packet, max_depth=pol.max_json_depth)
    canonical_obj = _strip_integrity_and_signature(packet, policy=pol)
    return _sha256_hex(_canonical_json(canonical_obj))


def attach_integrity(packet: Dict[str, Any], *, policy: Optional[ValidatorPolicy] = None) -> Dict[str, Any]:
    """
    Returns a copy of packet with integrity block populated (sha256).
    Does not sign.
    """
    pol = policy or ValidatorPolicy()
    clone = json.loads(json.dumps(packet))
    h = compute_integrity_hash(clone, policy=pol)
    clone.setdefault(pol.integrity_field, {})
    _ensure_type(clone[pol.integrity_field], dict, path=f"$.{pol.integrity_field}")
    clone[pol.integrity_field]["alg"] = "sha256"
    clone[pol.integrity_field][pol.integrity_hash_field] = h
    return clone
