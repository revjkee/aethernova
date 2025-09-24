# File: security-core/security/authn/webauthn.py
# Industrial-grade WebAuthn (FIDO2) utilities for registration and authentication.
# Python: 3.10+
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

# Optional deps (fail closed with clear message)
try:
    import cbor2  # type: ignore
except Exception as _e_cbor:
    cbor2 = None  # type: ignore

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
    )
    from cryptography.hazmat.backends import default_backend
except Exception as _e_crypto:
    hashes = serialization = ec = rsa = padding = ed25519 = decode_dss_signature = default_backend = None  # type: ignore


# =========================
# Exceptions
# =========================

class WebAuthnError(Exception):
    pass

class DependencyMissing(WebAuthnError):
    def __init__(self, lib: str, instructions: str) -> None:
        super().__init__(f"Missing dependency: {lib}. {instructions}")

class ChallengeError(WebAuthnError):
    pass

class OriginError(WebAuthnError):
    pass

class RPError(WebAuthnError):
    pass

class AttestationError(WebAuthnError):
    pass

class AssertionErrorWebAuthn(WebAuthnError):
    pass


# =========================
# Base64URL helpers
# =========================

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


# =========================
# Constants / enums (COSE etc.)
# =========================

class COSEKeyType(IntEnum):
    OKP = 1
    EC2 = 2
    RSA = 3

class COSEAlg(IntEnum):
    ES256 = -7       # ECDSA w/ SHA-256
    RS256 = -257     # RSASSA-PKCS1-v1_5 w/ SHA-256
    EdDSA = -8       # Ed25519/Ed448

# EC2 parameters
COSE_EC2_CRV = -1
COSE_EC2_X = -2
COSE_EC2_Y = -3

# OKP parameters
COSE_OKP_CRV = -1
COSE_OKP_X = -2
COSE_OKP_CRV_ED25519 = 6

# RSA parameters
COSE_RSA_N = -1
COSE_RSA_E = -2

# authenticatorData flags
FLAG_UP = 0x01  # user present
FLAG_UV = 0x04  # user verified
FLAG_AT = 0x40  # attested credential data included
FLAG_ED = 0x80  # extension data included


# =========================
# Data models and Protocols
# =========================

@dataclass(frozen=True)
class RelyingPartyConfig:
    rp_id: str
    rp_name: str
    origins: Tuple[str, ...]  # e.g. ("https://app.example.com",)
    timeout_ms: int = 60000
    user_verification: str = "preferred"  # "required"|"preferred"|"discouraged"
    attestation: str = "none"             # "none"|"indirect"|"direct"

@dataclass
class UserRef:
    user_id: bytes        # stable binary id (<=64 bytes as per spec)
    username: str
    display_name: str
    tenant_id: Optional[str] = None

@dataclass
class CredentialRecord:
    credential_id: bytes
    user_handle: bytes
    public_key_cose: bytes
    sign_count: int
    transports: Tuple[str, ...] = dataclasses.field(default_factory=tuple)
    aaguid: Optional[bytes] = None

class CredentialStore(Protocol):
    async def get_by_id(self, credential_id: bytes) -> Optional[CredentialRecord]: ...
    async def list_user_credentials(self, user_handle: bytes) -> List[CredentialRecord]: ...
    async def save_credential(self, record: CredentialRecord) -> None: ...
    async def update_sign_count(self, credential_id: bytes, new_sign_count: int) -> None: ...

class ChallengeStore(Protocol):
    async def put(self, key: str, challenge: bytes, *, ttl_sec: int, meta: Mapping[str, Any]) -> None: ...
    async def take(self, key: str) -> Optional[Tuple[bytes, Mapping[str, Any]]]: ...

class AttestationVerifier(Protocol):
    async def verify(self, fmt: str, att_stmt: Mapping[str, Any], auth_data: bytes, client_data_hash: bytes) -> None: ...


# =========================
# Default in-memory stores (for testing/dev; replace in production)
# =========================

class InMemoryChallengeStore:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[bytes, float, Dict[str, Any]]] = {}

    async def put(self, key: str, challenge: bytes, *, ttl_sec: int, meta: Mapping[str, Any]) -> None:
        self._store[key] = (challenge, time.time() + ttl_sec, dict(meta))

    async def take(self, key: str) -> Optional[Tuple[bytes, Mapping[str, Any]]]:
        item = self._store.pop(key, None)
        if not item:
            return None
        chal, exp, meta = item
        if time.time() > exp:
            return None
        return chal, meta

class NoopAttestationVerifier:
    async def verify(self, fmt: str, att_stmt: Mapping[str, Any], auth_data: bytes, client_data_hash: bytes) -> None:
        # Policy "none": accept all; real deployments should implement FIDO MDS checks for fmt "packed"/"tpm"/etc.
        return


# =========================
# Utilities
# =========================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _require_deps() -> None:
    if cbor2 is None:
        raise DependencyMissing("cbor2", "Install with: pip install cbor2")
    if hashes is None:
        raise DependencyMissing("cryptography", "Install with: pip install cryptography")

def _constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def _check_origin(allowed: Iterable[str], origin: str) -> None:
    if origin not in allowed:
        raise OriginError(f"Origin not allowed: {origin}")

def _rp_id_hash(rp_id: str) -> bytes:
    return sha256(rp_id.encode("idna"))


# =========================
# COSE -> cryptography key conversion
# =========================

def public_key_from_cose(cose_key: Mapping[int, Any]):
    _require_deps()
    kty = int(cose_key.get(1))  # 1 == kty
    alg = int(cose_key.get(3))  # 3 == alg
    if kty == COSEKeyType.EC2:
        x = int.from_bytes(cose_key[COSE_EC2_X], "big")
        y = int.from_bytes(cose_key[COSE_EC2_Y], "big")
        curve = ec.SECP256R1()  # WebAuthn default for ES256
        pub_nums = ec.EllipticCurvePublicNumbers(x, y, curve)
        return pub_nums.public_key(default_backend()), COSEAlg(alg)
    if kty == COSEKeyType.RSA:
        n = int.from_bytes(cose_key[COSE_RSA_N], "big")
        e = int.from_bytes(cose_key[COSE_RSA_E], "big")
        pub_nums = rsa.RSAPublicNumbers(e, n)
        return pub_nums.public_key(default_backend()), COSEAlg(alg)
    if kty == COSEKeyType.OKP:
        crv = int(cose_key.get(COSE_OKP_CRV))
        if crv != COSE_OKP_CRV_ED25519:
            raise WebAuthnError(f"Unsupported OKP curve: {crv}")
        x = cose_key[COSE_OKP_X]
        return ed25519.Ed25519PublicKey.from_public_bytes(x), COSEAlg(alg)
    raise WebAuthnError(f"Unsupported COSE kty: {kty}")

def verify_signature(pubkey, alg: COSEAlg, data: bytes, sig: bytes) -> None:
    _require_deps()
    if alg == COSEAlg.ES256:
        # WebAuthn ECDSA uses DER-encoded signature in assertions
        try:
            pubkey.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            raise AssertionErrorWebAuthn(f"ECDSA verify failed: {e}")
        return
    if alg == COSEAlg.RS256:
        try:
            pubkey.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        except Exception as e:
            raise AssertionErrorWebAuthn(f"RSA verify failed: {e}")
        return
    if alg == COSEAlg.EdDSA:
        try:
            pubkey.verify(sig, data)
        except Exception as e:
            raise AssertionErrorWebAuthn(f"EdDSA verify failed: {e}")
        return
    raise WebAuthnError(f"Unsupported COSE alg: {alg}")


# =========================
# Authenticator data parsing
# =========================

@dataclass
class ParsedAuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: Optional[bytes] = None
    credential_id: Optional[bytes] = None
    credential_public_key_cose: Optional[bytes] = None  # raw CBOR of COSE key
    extensions: Optional[bytes] = None

def parse_authenticator_data(auth_data: bytes) -> ParsedAuthData:
    if len(auth_data) < 37:
        raise WebAuthnError("authenticatorData too short")
    rp_hash = auth_data[0:32]
    flags = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")
    offset = 37
    aaguid = cred_id = cose = None
    if flags & FLAG_AT:
        if len(auth_data) < offset + 16 + 2:
            raise WebAuthnError("attested credential data truncated")
        aaguid = auth_data[offset : offset + 16]
        offset += 16
        cred_len = int.from_bytes(auth_data[offset : offset + 2], "big")
        offset += 2
        cred_id = auth_data[offset : offset + cred_len]
        offset += cred_len
        # Rest is CBOR for credentialPublicKey; decode to determine length by parsing via cbor2
        if cbor2 is None:
            raise DependencyMissing("cbor2", "Install with: pip install cbor2")
        # Decode starting from offset; cbor2.loads expects full bytes of the object
        cose_key_obj = cbor2.loads(auth_data[offset:])
        # To store exact COSE bytes, re-encode normalized object
        cose = cbor2.dumps(cose_key_obj)
        # Advance offset to end of CBOR object by re-encoding length; not strictly required here
    ext_bytes = None
    if flags & FLAG_ED:
        # If extensions present, the bytes follow (CBOR map); we preserve raw tail as extensions
        ext_bytes = auth_data[offset:] if offset < len(auth_data) else b""
    return ParsedAuthData(
        rp_id_hash=rp_hash,
        flags=flags,
        sign_count=sign_count,
        aaguid=aaguid,
        credential_id=cred_id,
        credential_public_key_cose=cose,
        extensions=ext_bytes,
    )


# =========================
# ClientData parsing
# =========================

@dataclass
class ClientData:
    typ: str
    challenge_b64u: str
    origin: str
    cross_origin: Optional[bool]

def parse_client_data(client_data_json: bytes) -> ClientData:
    try:
        obj = json.loads(client_data_json.decode("utf-8"))
    except Exception as e:
        raise WebAuthnError(f"Invalid clientDataJSON: {e}")
    return ClientData(
        typ=obj.get("type"),
        challenge_b64u=obj.get("challenge"),
        origin=obj.get("origin"),
        cross_origin=obj.get("crossOrigin"),
    )


# =========================
# Manager
# =========================

class WebAuthnManager:
    def __init__(
        self,
        rp: RelyingPartyConfig,
        cred_store: CredentialStore,
        chal_store: ChallengeStore,
        attestation_verifier: Optional[AttestationVerifier] = None,
    ) -> None:
        self.rp = rp
        self.creds = cred_store
        self.chals = chal_store
        self.attest = attestation_verifier or NoopAttestationVerifier()

    # ---------- Registration ----------

    async def start_registration(
        self,
        user: UserRef,
        *,
        authenticator_attachment: Optional[str] = None,   # "platform"|"cross-platform"|None
        resident_key: Optional[str] = None,                # "required"|"preferred"|"discouraged"
        require_user_verification: Optional[bool] = None,
        exclude_existing: bool = True,
        pubkey_algs: Optional[List[int]] = None,           # COSE alg list
        challenge_ttl_sec: int = 300,
    ) -> Dict[str, Any]:
        challenge = os.urandom(32)
        chal_key = self._challenge_key(user, "webauthn.create")
        await self.chals.put(chal_key, challenge, ttl_sec=challenge_ttl_sec, meta={"user": b64u_encode(user.user_id)})
        exclude: List[Dict[str, Any]] = []
        if exclude_existing:
            creds = await self.creds.list_user_credentials(user.user_id)
            exclude = [{"type": "public-key", "id": b64u_encode(c.credential_id)} for c in creds]

        params = [{"type": "public-key", "alg": a} for a in (pubkey_algs or [COSEAlg.ES256, COSEAlg.RS256, COSEAlg.EdDSA])]
        opts: Dict[str, Any] = {
            "challenge": b64u_encode(challenge),
            "rp": {"id": self.rp.rp_id, "name": self.rp.rp_name},
            "user": {
                "id": b64u_encode(user.user_id),
                "name": user.username,
                "displayName": user.display_name,
            },
            "pubKeyCredParams": params,
            "timeout": self.rp.timeout_ms,
            "attestation": self.rp.attestation,
            "excludeCredentials": exclude,
            "authenticatorSelection": {
                "authenticatorAttachment": authenticator_attachment,
                "residentKey": resident_key or "preferred",
                "userVerification": self.rp.user_verification if require_user_verification is None else ("required" if require_user_verification else "preferred"),
            },
        }
        # Remove None values (clean JSON)
        _compact(opts)
        return opts

    async def finish_registration(
        self,
        user: UserRef,
        attestation_response: Mapping[str, Any],
    ) -> CredentialRecord:
        """
        attestation_response:
          {
            "id": b64u,
            "rawId": b64u,
            "type": "public-key",
            "response": {
               "clientDataJSON": b64u,
               "attestationObject": b64u
            }
          }
        """
        _require_deps()
        # 1) Validate and consume challenge
        client_data_json = b64u_decode(attestation_response["response"]["clientDataJSON"])
        client = parse_client_data(client_data_json)
        if client.typ != "webauthn.create":
            raise AttestationError(f"Unexpected clientData.type: {client.typ}")
        chal_entry = await self.chals.take(self._challenge_key(user, "webauthn.create"))
        if not chal_entry:
            raise ChallengeError("Registration challenge missing or expired")
        challenge_expected, meta = chal_entry
        if not _constant_time_eq(b64u_decode(client.challenge_b64u), challenge_expected):
            raise ChallengeError("Challenge mismatch")
        _check_origin(self.rp.origins, client.origin)

        # 2) Parse attestation object
        att_obj = cbor2.loads(b64u_decode(attestation_response["response"]["attestationObject"]))
        fmt = att_obj.get("fmt")
        att_stmt = att_obj.get("attStmt", {})
        auth_data = att_obj.get("authData")
        if not isinstance(auth_data, (bytes, bytearray)):
            raise AttestationError("authData missing")
        parsed = parse_authenticator_data(auth_data)

        # 3) RP ID hash must match
        if not _constant_time_eq(parsed.rp_id_hash, _rp_id_hash(self.rp.rp_id)):
            raise RPError("rpIdHash mismatch")

        # 4) Attested credential must be present
        if not (parsed.flags & FLAG_AT):
            raise AttestationError("attested credential data not present")
        if not parsed.credential_id or not parsed.credential_public_key_cose:
            raise AttestationError("credential id/public key missing")

        # 5) Optional: verify attestation statement (configurable)
        client_hash = sha256(client_data_json)
        await self.attest.verify(fmt, att_stmt, auth_data, client_hash)

        # 6) Persist credential
        record = CredentialRecord(
            credential_id=parsed.credential_id,
            user_handle=user.user_id,
            public_key_cose=parsed.credential_public_key_cose,
            sign_count=parsed.sign_count,
            transports=tuple(attestation_response.get("transports") or ()),
            aaguid=parsed.aaguid,
        )
        await self.creds.save_credential(record)
        return record

    # ---------- Authentication ----------

    async def start_authentication(
        self,
        user: UserRef,
        *,
        allow_credentials: Optional[List[bytes]] = None,
        challenge_ttl_sec: int = 180,
    ) -> Dict[str, Any]:
        challenge = os.urandom(32)
        await self.chals.put(self._challenge_key(user, "webauthn.get"), challenge, ttl_sec=challenge_ttl_sec, meta={"user": b64u_encode(user.user_id)})
        allow: List[Dict[str, Any]] = []
        if allow_credentials is not None:
            allow = [{"type": "public-key", "id": b64u_encode(cid)} for cid in allow_credentials]
        else:
            creds = await self.creds.list_user_credentials(user.user_id)
            allow = [{"type": "public-key", "id": b64u_encode(c.credential_id)} for c in creds]

        opts = {
            "challenge": b64u_encode(challenge),
            "rpId": self.rp.rp_id,
            "timeout": self.rp.timeout_ms,
            "allowCredentials": allow,
            "userVerification": self.rp.user_verification,
        }
        _compact(opts)
        return opts

    async def finish_authentication(
        self,
        user: UserRef,
        assertion_response: Mapping[str, Any],
        *,
        require_user_verification: bool = False,
    ) -> Dict[str, Any]:
        """
        assertion_response:
          {
            "id": b64u, "rawId": b64u, "type":"public-key",
            "response": {
              "clientDataJSON": b64u,
              "authenticatorData": b64u,
              "signature": b64u,
              "userHandle": b64u | null
            }
          }
        Returns: {"ok": bool, "clone_warning": bool, "new_sign_count": int, "credential_id": str}
        """
        _require_deps()
        client_data_json = b64u_decode(assertion_response["response"]["clientDataJSON"])
        client = parse_client_data(client_data_json)
        if client.typ != "webauthn.get":
            raise AssertionErrorWebAuthn(f"Unexpected clientData.type: {client.typ}")
        chal_entry = await self.chals.take(self._challenge_key(user, "webauthn.get"))
        if not chal_entry:
            raise ChallengeError("Authentication challenge missing or expired")
        challenge_expected, _meta = chal_entry
        if not _constant_time_eq(b64u_decode(client.challenge_b64u), challenge_expected):
            raise ChallengeError("Challenge mismatch")
        _check_origin(self.rp.origins, client.origin)

        auth_data = b64u_decode(assertion_response["response"]["authenticatorData"])
        sig = b64u_decode(assertion_response["response"]["signature"])
        parsed = parse_authenticator_data(auth_data)

        # RP hash must match
        if not _constant_time_eq(parsed.rp_id_hash, _rp_id_hash(self.rp.rp_id)):
            raise RPError("rpIdHash mismatch")

        # UV requirement
        if require_user_verification and not (parsed.flags & FLAG_UV):
            raise AssertionErrorWebAuthn("User verification required")

        # Resolve credential
        cred_id = b64u_decode(assertion_response["id"])
        record = await self.creds.get_by_id(cred_id)
        if not record or not _constant_time_eq(record.user_handle, user.user_id):
            raise AssertionErrorWebAuthn("Unknown credential or user mismatch")

        # Build signed data: authenticatorData || SHA256(clientDataJSON)
        signed_data = auth_data + sha256(client_data_json)

        # Verify signature using stored COSE key
        cose_map = cbor2.loads(record.public_key_cose)
        pubkey, alg = public_key_from_cose(cose_map)
        verify_signature(pubkey, alg, signed_data, sig)

        # Sign count handling (anti-replay)
        clone_warning = False
        if parsed.sign_count > 0:
            if parsed.sign_count <= record.sign_count:
                # Not necessarily fatal (some authenticators don't increase), flag as warning for risk engine
                clone_warning = True
            else:
                await self.creds.update_sign_count(record.credential_id, parsed.sign_count)

        return {
            "ok": True,
            "clone_warning": clone_warning,
            "new_sign_count": max(parsed.sign_count, record.sign_count),
            "credential_id": b64u_encode(record.credential_id),
        }

    # ---------- Helpers ----------

    def _challenge_key(self, user: UserRef, op: str) -> str:
        # a unique key per user+operation; tenant can be included if needed
        return f"{self.rp.rp_id}:{op}:{b64u_encode(user.user_id)}"


# =========================
# JSON compactor (remove None)
# =========================

def _compact(obj: Any) -> Any:
    if isinstance(obj, dict):
        keys = list(obj.keys())
        for k in keys:
            v = obj[k]
            if v is None:
                del obj[k]
            else:
                _compact(v)
    elif isinstance(obj, list):
        for i in range(len(obj)):
            _compact(obj[i])
    return obj
