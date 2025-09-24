# engine/security/signature.py
# Industrial-grade signing/verification module with domain separation,
# canonical JSON, streaming hashing, and async wrappers.
# Dependencies: cryptography (https://cryptography.io)
from __future__ import annotations

import base64
import dataclasses
import json
import time
import hmac
import hashlib
import io
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Union, Iterable, Tuple, Protocol

try:
    from cryptography.hazmat.primitives import hashes, serialization, hmac as crypto_hmac
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec, utils
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        PublicFormat,
        NoEncryption,
        load_pem_private_key,
        load_pem_public_key,
    )
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_OK = True
except Exception:  # cryptography not available or misconfigured
    _CRYPTO_OK = False


# ========= Errors =========

class SignatureError(Exception):
    """Base class for signature errors."""


class CryptoUnavailable(SignatureError):
    """cryptography library is not available."""
    pass


class VerificationError(SignatureError):
    """Verification failed."""
    pass


class CanonicalizationError(SignatureError):
    """JSON canonicalization failed."""
    pass


class ClockSkewError(SignatureError):
    """Message timestamp is out of allowed skew."""
    pass


# ========= Utilities =========

def _require_crypto():
    if not _CRYPTO_OK:
        raise CryptoUnavailable("cryptography is not available in runtime")

def b64u_encode(data: bytes) -> str:
    """Base64 URL-safe no-padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64u_decode(data: str) -> bytes:
    pad = '=' * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))

def consteq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def sha256_stream(chunks: Iterable[bytes]) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()

def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def now_s() -> int:
    return int(time.time())

# ========= Canonical JSON (RFC8785-inspired minimal set) =========

def _canonical_sort(obj: Dict[str, Any]) -> Dict[str, Any]:
    # Return the same dict but rely on json dumps with sort_keys=True
    return obj

def _float_to_str(x: float) -> str:
    # RFC8785 prefers finite numbers and minimal form; we use Python's repr with safeguards
    if x != x or x in (float("inf"), float("-inf")):
        raise CanonicalizationError("Non-finite number in JSON")
    s = repr(x)
    # Remove trailing .0 where safe
    if s.endswith(".0"): s = s[:-2]
    return s

def json_canonical_dumps(value: Any) -> str:
    def _transform(v: Any) -> Any:
        if v is None or isinstance(v, (bool, str, int)):
            return v
        if isinstance(v, float):
            return _float_to_str(v)
        if isinstance(v, list):
            return [_transform(i) for i in v]
        if isinstance(v, dict):
            # Keys must be strings
            if any(not isinstance(k, str) for k in v.keys()):
                raise CanonicalizationError("Non-string key in JSON object")
            # Recursively transform values
            transformed = {k: _transform(v[k]) for k in v.keys()}
            # Sorting happens in dumps
            return transformed
        raise CanonicalizationError(f"Unsupported type for canonical JSON: {type(v)}")

    transformed = _transform(value)
    # separators ensure no whitespace; sort_keys ensures lexicographic order
    return json.dumps(transformed, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def canonicalize_bytes(value: Union[bytes, str, Dict[str, Any], list]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    try:
        return json_canonical_dumps(value).encode("utf-8")
    except CanonicalizationError:
        raise
    except Exception as e:
        raise CanonicalizationError(str(e))

# ========= Algorithms & Key Encodings =========

class SignatureAlg(str, Enum):
    ED25519 = "Ed25519"
    ECDSA_SECP256K1 = "ECDSA_secp256k1_SHA256"

class KeyEncoding(str, Enum):
    RAW = "raw"
    PEM = "pem"
    DER = "der"

# ========= Metadata =========

@dataclass(frozen=True)
class SignOptions:
    alg: SignatureAlg
    kid: Optional[str] = None                 # key identifier
    domain: str = "engine-core/signature"     # domain separation tag
    nonce: Optional[str] = None
    timestamp_s: Optional[int] = None         # override current time if needed
    include_public_key: bool = False          # optionally carry public key
    expires_in_s: Optional[int] = None        # expiry relative to timestamp

@dataclass(frozen=True)
class VerifyOptions:
    domain: Optional[str] = None
    max_clock_skew_s: int = 300               # +/- 5 minutes allowed skew
    require_kid: bool = False
    require_nonce: bool = False
    # If provided, enforce absolute expiry validation; otherwise rely on embedded expires_in_s
    current_time_s: Optional[int] = None

# ========= KMS Hook (optional) =========

class KMSClient(Protocol):
    def sign(self, key_id: str, digest: bytes, alg: SignatureAlg) -> bytes: ...
    def get_public_key(self, key_id: str, alg: SignatureAlg) -> bytes: ...

# ========= Key Wrappers =========

@dataclass
class PrivateKey:
    alg: SignatureAlg
    _sk: Any

    @staticmethod
    def generate(alg: SignatureAlg) -> "PrivateKey":
        _require_crypto()
        if alg == SignatureAlg.ED25519:
            return PrivateKey(alg, ed25519.Ed25519PrivateKey.generate())
        elif alg == SignatureAlg.ECDSA_SECP256K1:
            return PrivateKey(alg, ec.generate_private_key(ec.SECP256K1()))
        else:
            raise ValueError(f"Unsupported alg: {alg}")

    @staticmethod
    def from_pem(pem: bytes, password: Optional[bytes] = None, alg_hint: Optional[SignatureAlg] = None) -> "PrivateKey":
        _require_crypto()
        sk = load_pem_private_key(pem, password=password)
        if isinstance(sk, ed25519.Ed25519PrivateKey):
            alg = SignatureAlg.ED25519
        elif isinstance(sk, ec.EllipticCurvePrivateKey) and isinstance(sk.curve, ec.SECP256K1):
            alg = SignatureAlg.ECDSA_SECP256K1
        elif alg_hint:
            alg = alg_hint
        else:
            raise ValueError("Cannot infer algorithm from PEM")
        return PrivateKey(alg, sk)

    def to_pem(self) -> bytes:
        _require_crypto()
        return self._sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    def public_key(self) -> "PublicKey":
        _require_crypto()
        return PublicKey(self.alg, self._sk.public_key())

@dataclass
class PublicKey:
    alg: SignatureAlg
    _pk: Any

    @staticmethod
    def from_pem(pem: bytes, alg_hint: Optional[SignatureAlg] = None) -> "PublicKey":
        _require_crypto()
        pk = load_pem_public_key(pem)
        if isinstance(pk, ed25519.Ed25519PublicKey):
            alg = SignatureAlg.ED25519
        elif isinstance(pk, ec.EllipticCurvePublicKey) and isinstance(pk.curve, ec.SECP256K1):
            alg = SignatureAlg.ECDSA_SECP256K1
        elif alg_hint:
            alg = alg_hint
        else:
            raise ValueError("Cannot infer algorithm from PEM")
        return PublicKey(alg, pk)

    def to_pem(self) -> bytes:
        _require_crypto()
        return self._pk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

# ========= Core Signing =========

@dataclass(frozen=True)
class SignatureEnvelope:
    alg: SignatureAlg
    kid: Optional[str]
    domain: str
    ts: int
    expires_in_s: Optional[int]
    nonce: Optional[str]
    payload_hash_alg: str
    payload_hash_b64u: str
    signature_b64u: str
    public_key_pem_b64u: Optional[str] = None

    def to_json_bytes(self) -> bytes:
        # Canonical, sorted JSON to ensure stable representation
        as_dict = dataclasses.asdict(self)
        return canonicalize_bytes(as_dict)

    @staticmethod
    def from_bytes(data: Union[str, bytes]) -> "SignatureEnvelope":
        if isinstance(data, bytes):
            obj = json.loads(data.decode("utf-8"))
        else:
            obj = json.loads(data)
        # We accept normal JSON, but verify fields presence later
        required = {"alg","domain","ts","payload_hash_alg","payload_hash_b64u","signature_b64u"}
        if not required.issubset(obj.keys()):
            missing = required - set(obj.keys())
            raise VerificationError(f"Envelope is missing fields: {missing}")
        return SignatureEnvelope(
            alg=SignatureAlg(obj["alg"]),
            kid=obj.get("kid"),
            domain=obj["domain"],
            ts=int(obj["ts"]),
            expires_in_s=int(obj["expires_in_s"]) if obj.get("expires_in_s") is not None else None,
            nonce=obj.get("nonce"),
            payload_hash_alg=obj["payload_hash_alg"],
            payload_hash_b64u=obj["payload_hash_b64u"],
            signature_b64u=obj["signature_b64u"],
            public_key_pem_b64u=obj.get("public_key_pem_b64u"),
        )

def _compute_payload_hash(payload: Union[bytes, str, Dict[str, Any], list]) -> Tuple[str, bytes]:
    # For industrial simplicity, we standardize on SHA-256 for payload hashing.
    b = canonicalize_bytes(payload)
    return "SHA-256", sha256_bytes(b)

def _serialize_to_be_signed(env: SignatureEnvelope) -> bytes:
    # We sign a canonical serialization of envelope metadata without the signature field
    meta = {
        "alg": env.alg.value,
        "kid": env.kid,
        "domain": env.domain,
        "ts": env.ts,
        "expires_in_s": env.expires_in_s,
        "nonce": env.nonce,
        "payload_hash_alg": env.payload_hash_alg,
        "payload_hash_b64u": env.payload_hash_b64u,
        "public_key_pem_b64u": env.public_key_pem_b64u,
    }
    return canonicalize_bytes(meta)

def _sign_bytes(sk: PrivateKey, data: bytes) -> bytes:
    _require_crypto()
    if sk.alg == SignatureAlg.ED25519:
        return sk._sk.sign(data)
    elif sk.alg == SignatureAlg.ECDSA_SECP256K1:
        # ECDSA with SHA256. cryptography uses randomized k; deterministic RFC6979 is internal
        # when using utils.Prehashed if desired; we keep standard ECDSA(SHA256).
        return sk._sk.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported alg: {sk.alg}")

def _verify_bytes(pk: PublicKey, sig: bytes, data: bytes) -> None:
    _require_crypto()
    try:
        if pk.alg == SignatureAlg.ED25519:
            pk._pk.verify(sig, data)
        elif pk.alg == SignatureAlg.ECDSA_SECP256K1:
            pk._pk.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported alg: {pk.alg}")
    except InvalidSignature as e:
        raise VerificationError("Invalid signature") from e

# ========= Public API =========

def sign(
    payload: Union[bytes, str, Dict[str, Any], list, Iterable[bytes]],
    key: Union[PrivateKey, str, bytes],
    options: SignOptions,
    *,
    kms: Optional[KMSClient] = None,
) -> SignatureEnvelope:
    """
    Create a detached signature envelope for payload.
    payload: bytes/str/JSON-like or iterable of byte chunks for streaming.
    key: PrivateKey instance or PEM bytes/str if not using KMS.
    """
    ts = options.timestamp_s if options.timestamp_s is not None else now_s()

    # Hash payload (streaming supported)
    if isinstance(payload, (bytes, str, dict, list)):
        hash_name, digest = _compute_payload_hash(payload)
    else:
        # streaming case
        digest = sha256_stream(payload)  # type: ignore
        hash_name = "SHA-256"

    kid = options.kid
    include_pk_b64 = None

    # Resolve private key
    if kms and isinstance(key, str):
        # KMS expects digest and returns raw signature
        alg = options.alg
        # envelope placeholder to compute to_be_signed
        env_tmp = SignatureEnvelope(
            alg=alg,
            kid=kid,
            domain=options.domain,
            ts=ts,
            expires_in_s=options.expires_in_s,
            nonce=options.nonce,
            payload_hash_alg=hash_name,
            payload_hash_b64u=b64u_encode(digest),
            signature_b64u="",  # placeholder
            public_key_pem_b64u=None,  # typically not embedded for KMS
        )
        to_be_signed = _serialize_to_be_signed(env_tmp)
        signature = kms.sign(kid or "", to_be_signed, alg)
        sig_b64 = b64u_encode(signature)
        env = dataclasses.replace(env_tmp, signature_b64u=sig_b64)
        return env

    # Local key path
    if isinstance(key, (bytes, str)):
        pem = key.encode("utf-8") if isinstance(key, str) else key
        sk = PrivateKey.from_pem(pem, password=None, alg_hint=options.alg)
    elif isinstance(key, PrivateKey):
        sk = key
    else:
        raise ValueError("Unsupported key type")

    alg = sk.alg
    pk = sk.public_key()

    if options.include_public_key:
        include_pk_b64 = b64u_encode(pk.to_pem())

    env_tmp = SignatureEnvelope(
        alg=alg,
        kid=kid,
        domain=options.domain,
        ts=ts,
        expires_in_s=options.expires_in_s,
        nonce=options.nonce,
        payload_hash_alg=hash_name,
        payload_hash_b64u=b64u_encode(digest),
        signature_b64u="",
        public_key_pem_b64u=include_pk_b64,
    )

    to_be_signed = _serialize_to_be_signed(env_tmp)
    signature = _sign_bytes(sk, to_be_signed)
    sig_b64 = b64u_encode(signature)
    env = dataclasses.replace(env_tmp, signature_b64u=sig_b64)
    return env

def verify(
    payload: Union[bytes, str, Dict[str, Any], list, Iterable[bytes]],
    envelope: Union[SignatureEnvelope, bytes, str],
    key: Optional[Union[PublicKey, bytes, str]] = None,
    options: Optional[VerifyOptions] = None,
    *,
    kms: Optional[KMSClient] = None,
) -> bool:
    """
    Verify detached signature. If key is None, envelope must carry public key.
    """
    opts = options or VerifyOptions()
    if isinstance(envelope, (bytes, str)):
        env = SignatureEnvelope.from_bytes(envelope)
    else:
        env = envelope

    # Domain enforcement
    if opts.domain is not None and env.domain != opts.domain:
        raise VerificationError(f"Domain mismatch: expected {opts.domain}, got {env.domain}")

    # Timestamp checks
    current = opts.current_time_s if opts.current_time_s is not None else now_s()
    if abs(current - env.ts) > opts.max_clock_skew_s:
        raise ClockSkewError(f"Timestamp skew exceeded: current={current}, ts={env.ts}")

    if env.expires_in_s is not None:
        if current > env.ts + env.expires_in_s:
            raise VerificationError("Envelope expired")

    if opts.require_kid and not env.kid:
        raise VerificationError("kid is required but missing")
    if opts.require_nonce and not env.nonce:
        raise VerificationError("nonce is required but missing")

    # Recompute payload hash
    if isinstance(payload, (bytes, str, dict, list)):
        hash_name, digest = _compute_payload_hash(payload)
    else:
        digest = sha256_stream(payload)  # type: ignore
        hash_name = "SHA-256"

    if env.payload_hash_alg != hash_name:
        raise VerificationError("Payload hash algorithm mismatch")

    if not consteq(b64u_decode(env.payload_hash_b64u), digest):
        raise VerificationError("Payload hash mismatch")

    # Rebuild TBS (to-be-signed)
    tbs = _serialize_to_be_signed(env)
    sig = b64u_decode(env.signature_b64u)

    # Resolve public key
    pk_obj: Optional[PublicKey] = None

    if key is not None:
        if isinstance(key, (bytes, str)):
            pem = key.encode("utf-8") if isinstance(key, str) else key
            pk_obj = PublicKey.from_pem(pem, alg_hint=env.alg)
        elif isinstance(key, PublicKey):
            pk_obj = key
        else:
            raise ValueError("Unsupported key type for verification")
    elif env.public_key_pem_b64u:
        pk_pem = b64u_decode(env.public_key_pem_b64u)
        pk_obj = PublicKey.from_pem(pk_pem, alg_hint=env.alg)
    elif kms and env.kid:
        # KMS path: obtain public key via KMS
        pk_der_or_pem = kms.get_public_key(env.kid, env.alg)
        # Try PEM first; if looks like DER, wrap to PEM is out-of-scope here -> try load_pem_public_key
        try:
            pk_obj = PublicKey.from_pem(pk_der_or_pem, alg_hint=env.alg)
        except Exception as e:
            raise VerificationError(f"KMS public key retrieval failed: {e}")
    else:
        raise VerificationError("No public key available to verify")

    _verify_bytes(pk_obj, sig, tbs)
    return True

# ========= Enveloped helpers (signature carried alongside payload) =========

@dataclass(frozen=True)
class SignedMessage:
    payload_b64u: str
    envelope: SignatureEnvelope

    def to_json_bytes(self) -> bytes:
        obj = {
            "payload_b64u": self.payload_b64u,
            "envelope": json.loads(self.envelope.to_json_bytes().decode("utf-8")),
        }
        return canonicalize_bytes(obj)

    @staticmethod
    def from_bytes(data: Union[str, bytes]) -> "SignedMessage":
        obj = json.loads(data if isinstance(data, str) else data.decode("utf-8"))
        env = SignatureEnvelope.from_bytes(json.dumps(obj["envelope"], separators=(",", ":"), sort_keys=True))
        return SignedMessage(payload_b64u=obj["payload_b64u"], envelope=env)

def sign_enveloped(
    payload: Union[bytes, str, Dict[str, Any], list],
    key: Union[PrivateKey, str, bytes],
    options: SignOptions,
    *,
    kms: Optional[KMSClient] = None,
) -> SignedMessage:
    payload_bytes = canonicalize_bytes(payload)
    env = sign(payload_bytes, key, options, kms=kms)
    return SignedMessage(payload_b64u=b64u_encode(payload_bytes), envelope=env)

def verify_enveloped(
    message: Union[SignedMessage, bytes, str],
    key: Optional[Union[PublicKey, bytes, str]] = None,
    options: Optional[VerifyOptions] = None,
    *,
    kms: Optional[KMSClient] = None,
) -> Tuple[bool, bytes]:
    if isinstance(message, (bytes, str)):
        msg = SignedMessage.from_bytes(message)
    else:
        msg = message
    payload = b64u_decode(msg.payload_b64u)
    ok = verify(payload, msg.envelope, key=key, options=options, kms=kms)
    return ok, payload

# ========= Async wrappers =========

async def sign_async(
    payload: Union[bytes, str, Dict[str, Any], list, Iterable[bytes]],
    key: Union[PrivateKey, str, bytes],
    options: SignOptions,
    *,
    kms: Optional[KMSClient] = None,
) -> SignatureEnvelope:
    # CPU-bound and tiny; provide simple async facade
    return sign(payload, key, options, kms=kms)

async def verify_async(
    payload: Union[bytes, str, Dict[str, Any], list, Iterable[bytes]],
    envelope: Union[SignatureEnvelope, bytes, str],
    key: Optional[Union[PublicKey, bytes, str]] = None,
    options: Optional[VerifyOptions] = None,
    *,
    kms: Optional[KMSClient] = None,
) -> bool:
    return verify(payload, envelope, key=key, options=options, kms=kms)

# ========= Example factory helpers (not tests) =========

def generate_keypair(alg: SignatureAlg = SignatureAlg.ED25519) -> Tuple[bytes, bytes]:
    """
    Generate a new keypair and return (private_pem, public_pem).
    """
    sk = PrivateKey.generate(alg)
    pk = sk.public_key()
    return sk.to_pem(), pk.to_pem()

# ========= Hardening notes (docstring) =========
__doc__ = """
Security notes:
- Domain separation: options.domain is mandatory (default set). Use unique domains per subsystem.
- Canonical JSON: deterministic dumps with sorted keys and no whitespace; non-finite floats rejected.
- Detached vs enveloped: both supported; detached recommended for large payloads or regulated storage.
- Time checks: VerifyOptions enforces clock skew and optional expiry.
- Key delivery: Prefer external KMS via KMSClient; module supports embedding public key when needed.
- Hash: SHA-256 standardized; streaming hashing for large inputs.
- Side-channels: constant-time comparisons for hash equality; cryptography backend handles low-level primitives.
- Upgrades: Add new algorithms by extending SignatureAlg and _sign/_verify dispatchers.
"""
