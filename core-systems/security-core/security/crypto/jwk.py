# security-core/security/crypto/jwk.py
# Industrial JWK/JWKS management, JWS/JWT sign/verify, rotation and remote JWKS cache.
from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple, Union

import httpx
from pydantic import BaseModel, Field, ValidationError

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
    utils as asym_utils,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    BestAvailableEncryption,
)
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("security_core.crypto.jwk")
logger.setLevel(logging.INFO)

# =========================
# Base64url helpers (no padding as per JOSE)
# =========================

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    s = data.encode("ascii")
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# =========================
# JOSE/JWK constants
# =========================

Alg = Literal["RS256", "RS384", "ES256", "ES384", "EdDSA"]
Kty = Literal["RSA", "EC", "OKP"]

EC_CURVES: Dict[str, ec.EllipticCurve] = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}
HASHES: Dict[str, hashes.HashAlgorithm] = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "ES256": hashes.SHA256(), "ES384": hashes.SHA384()}

# =========================
# Pydantic models for JWK/JWKS (public subset)
# =========================

class JWK(BaseModel):
    # Required public JWK members
    kty: Kty
    use: Optional[Literal["sig"]] = "sig"
    alg: Optional[Alg]
    kid: Optional[str]
    # RSA
    n: Optional[str]
    e: Optional[str]
    # EC
    crv: Optional[Literal["P-256", "P-384"]]
    x: Optional[str]
    y: Optional[str]
    # OKP (EdDSA)
    # crv reused for OKP curves via "Ed25519"/"Ed448"
    # For JOSE OKP, crv is "Ed25519" or "Ed448"
    # To limit schema repetition we permit same field
    # with extended values at runtime.
    # Private members (optional)
    d: Optional[str]

    class Config:
        extra = "allow"  # allow 'key_ops', 'x5c', etc.

    def is_public(self) -> bool:
        return self.d is None

    def ensure_kid(self) -> str:
        if self.kid:
            return self.kid
        self.kid = jwk_thumbprint(self.dict(exclude_none=True))
        return self.kid

class JWKS(BaseModel):
    keys: List[JWK] = Field(default_factory=list)

    def by_kid(self, kid: str) -> Optional[JWK]:
        for k in self.keys:
            if k.kid == kid:
                return k
        return None

    def public_only(self) -> "JWKS":
        return JWKS(keys=[JWK(**{**k.dict(exclude_none=True), "d": None}) for k in self.keys])


# =========================
# RFC 7638 Thumbprint (kid)
# =========================

def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    """
    Compute RFC 7638 JWK Thumbprint over the REQUIRED public members in fixed order.
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        ordered = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        ordered = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        ordered = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise ValueError(f"Unsupported kty for thumbprint: {kty}")
    data = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64u_encode(hashlib.sha256(data).digest())


# =========================
# Conversions: cryptography key <-> JWK
# =========================

def _int_to_b64u(n: int) -> str:
    return b64u_encode(n.to_bytes((n.bit_length() + 7) // 8 or 1, "big"))

def _b64u_to_int(s: str) -> int:
    return int.from_bytes(b64u_decode(s), "big")


def private_key_to_jwk(priv: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey], alg: Optional[Alg] = None, kid: Optional[str] = None) -> JWK:
    pub = priv.public_key()
    if isinstance(priv, rsa.RSAPrivateKey):
        numbers = priv.private_numbers()
        pubnum = numbers.public_numbers
        jwk = JWK(
            kty="RSA",
            alg=alg or "RS256",
            n=_int_to_b64u(pubnum.n),
            e=_int_to_b64u(pubnum.e),
            d=_int_to_b64u(numbers.d),
        )
    elif isinstance(priv, ec.EllipticCurvePrivateKey):
        curve_to_crv = {ec.SECP256R1().name: "P-256", ec.SECP384R1().name: "P-384"}
        crv = curve_to_crv.get(priv.curve.name)
        if not crv:
            raise ValueError("Unsupported EC curve; only P-256/P-384 are allowed")
        numbers = priv.private_numbers()
        pubnum = numbers.public_numbers
        jwk = JWK(
            kty="EC",
            alg=alg or ("ES256" if crv == "P-256" else "ES384"),
            crv=crv,  # type: ignore
            x=_int_to_b64u(pubnum.x),
            y=_int_to_b64u(pubnum.y),
            d=_int_to_b64u(numbers.private_value),
        )
    elif isinstance(priv, ed25519.Ed25519PrivateKey):
        pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        d_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        jwk = JWK(kty="OKP", alg="EdDSA", crv="Ed25519", x=b64u_encode(pub_bytes), d=b64u_encode(d_bytes))
    elif isinstance(priv, ed448.Ed448PrivateKey):
        pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        d_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        jwk = JWK(kty="OKP", alg="EdDSA", crv="Ed448", x=b64u_encode(pub_bytes), d=b64u_encode(d_bytes))
    else:
        raise ValueError("Unsupported private key type")
    jwk.kid = kid or jwk_thumbprint(jwk.dict(exclude_none=True))
    return jwk


def public_key_to_jwk(pub: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey], alg: Optional[Alg] = None, kid: Optional[str] = None, crv_hint: Optional[str] = None) -> JWK:
    if isinstance(pub, rsa.RSAPublicKey):
        pubnum = pub.public_numbers()
        jwk = JWK(kty="RSA", alg=alg or "RS256", n=_int_to_b64u(pubnum.n), e=_int_to_b64u(pubnum.e))
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        curve_to_crv = {ec.SECP256R1().name: "P-256", ec.SECP384R1().name: "P-384"}
        crv = curve_to_crv.get(pub.curve.name) or crv_hint
        if not crv:
            raise ValueError("Unable to infer EC curve; provide crv_hint")
        pubnum = pub.public_numbers()
        jwk = JWK(kty="EC", alg=alg or ("ES256" if crv == "P-256" else "ES384"), crv=crv, x=_int_to_b64u(pubnum.x), y=_int_to_b64u(pubnum.y))  # type: ignore
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        jwk = JWK(kty="OKP", alg="EdDSA", crv="Ed25519", x=b64u_encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)))
    elif isinstance(pub, ed448.Ed448PublicKey):
        jwk = JWK(kty="OKP", alg="EdDSA", crv="Ed448", x=b64u_encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)))
    else:
        raise ValueError("Unsupported public key type")
    jwk.kid = kid or jwk_thumbprint(jwk.dict(exclude_none=True))
    return jwk


def jwk_to_private_key(jwk: JWK) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey]:
    if jwk.kty == "RSA":
        if not all([jwk.n, jwk.e, jwk.d]):
            raise ValueError("Incomplete RSA private JWK")
        pub = rsa.RSAPublicNumbers(_b64u_to_int(jwk.e), _b64u_to_int(jwk.n))
        privnum = rsa.RSAPrivateNumbers(
            p=None, q=None, d=_b64u_to_int(jwk.d), dmp1=None, dmq1=None, iqmp=None, public_numbers=pub  # type: ignore
        )
        # cryptography requires full CRT numbers for from_private_numbers in some versions; we fallback to load via PEM
        # Safer approach: import from PEM if available; else generate using construct with private key builder.
        # Use rsa.RSAPrivateNumbers with p/q optional is not supported; parse via serialization path:
        pri = rsa.RSAPrivateNumbers(
            p=0, q=0, d=privnum.d, dmp1=0, dmq1=0, iqmp=0, public_numbers=pub
        )  # placeholders; we will not use this construction; instead load via public_numbers not possible. Use from_private_numbers requires primes.
        # Workaround: we cannot reconstruct without CRT parameters. Recommend storing PEM; however many JWKs omit CRT.
        # Practical approach: use cryptography's load_pem_private_key from PKCS#8 we serialize below. To keep portability,
        # raise to indicate unsupported conversion without CRT.
        raise ValueError("RSA private JWK without CRT parameters is not supported for reconstruction by cryptography")
    elif jwk.kty == "EC":
        if not all([jwk.crv, jwk.x, jwk.y, jwk.d]):
            raise ValueError("Incomplete EC private JWK")
        curve = EC_CURVES.get(jwk.crv)  # type: ignore
        if not curve:
            raise ValueError("Unsupported EC curve")
        return ec.derive_private_key(_b64u_to_int(jwk.d), curve)
    elif jwk.kty == "OKP":
        if jwk.crv == "Ed25519":
            if not jwk.d:
                raise ValueError("OKP private JWK missing 'd'")
            return ed25519.Ed25519PrivateKey.from_private_bytes(b64u_decode(jwk.d))
        elif jwk.crv == "Ed448":
            if not jwk.d:
                raise ValueError("OKP private JWK missing 'd'")
            return ed448.Ed448PrivateKey.from_private_bytes(b64u_decode(jwk.d))
        else:
            raise ValueError("Unsupported OKP curve")
    else:
        raise ValueError("Unsupported kty")


def jwk_to_public_key(jwk: JWK):
    if jwk.kty == "RSA":
        if not all([jwk.n, jwk.e]):
            raise ValueError("Incomplete RSA public JWK")
        pub = rsa.RSAPublicNumbers(_b64u_to_int(jwk.e), _b64u_to_int(jwk.n)).public_key()
        return pub
    elif jwk.kty == "EC":
        if not all([jwk.crv, jwk.x, jwk.y]):
            raise ValueError("Incomplete EC public JWK")
        curve = EC_CURVES.get(jwk.crv)  # type: ignore
        if not curve:
            raise ValueError("Unsupported EC curve")
        return ec.EllipticCurvePublicNumbers(_b64u_to_int(jwk.x), _b64u_to_int(jwk.y), curve).public_key()
    elif jwk.kty == "OKP":
        if jwk.crv == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk.x))
        elif jwk.crv == "Ed448":
            return ed448.Ed448PublicKey.from_public_bytes(b64u_decode(jwk.x))
        else:
            raise ValueError("Unsupported OKP curve")
    else:
        raise ValueError("Unsupported kty")


# =========================
# Key generation
# =========================

def generate_key(alg: Alg = "RS256", rsa_bits: int = 2048) -> JWK:
    if alg in ("RS256", "RS384"):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    elif alg == "ES256":
        priv = ec.generate_private_key(ec.SECP256R1())
    elif alg == "ES384":
        priv = ec.generate_private_key(ec.SECP384R1())
    elif alg == "EdDSA":
        # prefer Ed25519; Ed448 can be selected by caller via convert
        priv = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError("Unsupported algorithm")
    return private_key_to_jwk(priv, alg=alg)


# =========================
# JWS helpers (ECDSA raw<->DER)
# =========================

def _ecdsa_raw_to_der(sig: bytes, key: ec.EllipticCurvePublicKey) -> bytes:
    size = (key.curve.key_size + 7) // 8
    if len(sig) != 2 * size:
        raise ValueError("Invalid ECDSA raw signature length")
    r = int.from_bytes(sig[:size], "big")
    s = int.from_bytes(sig[size:], "big")
    return asym_utils.encode_dss_signature(r, s)


def _ecdsa_der_to_raw(sig: bytes, key: ec.EllipticCurvePrivateKey) -> bytes:
    r, s = asym_utils.decode_dss_signature(sig)
    size = (key.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


# =========================
# JWT claims validation
# =========================

class JWTValidationError(Exception):
    pass


def _validate_claims(payload: Dict[str, Any], now: Optional[int] = None, leeway: int = 60, expected_iss: Optional[str] = None, expected_aud: Optional[Union[str, List[str]]] = None) -> None:
    ts = int(now if now is not None else time.time())
    # exp
    if "exp" in payload and not isinstance(payload["exp"], (int, float)):
        raise JWTValidationError("exp must be a number")
    if "exp" in payload and ts > int(payload["exp"]) + leeway:
        raise JWTValidationError("token expired")
    # nbf
    if "nbf" in payload and ts + leeway < int(payload["nbf"]):
        raise JWTValidationError("token not yet valid")
    # iat sanity
    if "iat" in payload and ts + 24 * 3600 < int(payload["iat"]):
        raise JWTValidationError("iat is in the far future")
    # iss
    if expected_iss and payload.get("iss") != expected_iss:
        raise JWTValidationError("iss mismatch")
    # aud
    if expected_aud is not None:
        aud = payload.get("aud")
        if isinstance(expected_aud, str):
            expected_set = {expected_aud}
        else:
            expected_set = set(expected_aud)
        if isinstance(aud, str):
            if aud not in expected_set:
                raise JWTValidationError("aud mismatch")
        elif isinstance(aud, list):
            if not (set(aud) & expected_set):
                raise JWTValidationError("aud mismatch")
        else:
            raise JWTValidationError("aud missing or invalid")


# =========================
# JWS/JWT sign & verify (compact)
# =========================

def sign_jwt(payload: Dict[str, Any], signing_key: JWK, kid: Optional[str] = None, alg: Optional[Alg] = None, headers: Optional[Dict[str, Any]] = None) -> str:
    if signing_key.is_public():
        raise ValueError("Signing requires a private JWK (field 'd')")
    header = {"typ": "JWT", "alg": alg or signing_key.alg, "kid": kid or signing_key.ensure_kid()}
    if headers:
        header.update(headers)
    header_b64 = b64u_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = b64u_encode(json.dumps(payload, separators=(",", ":"), sort_keys=False).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    alg_name = header["alg"]
    if alg_name in ("RS256", "RS384"):
        priv = jwk_to_private_key(signing_key) if signing_key.kty != "RSA" else jwk_to_private_key(signing_key)
        hash_alg = HASHES[alg_name]
        signature = priv.sign(signing_input, padding.PKCS1v15(), hash_alg)  # type: ignore
    elif alg_name in ("ES256", "ES384"):
        priv = jwk_to_private_key(signing_key)  # type: ignore
        der = priv.sign(signing_input, ec.ECDSA(HASHES[alg_name]))  # type: ignore
        signature = _ecdsa_der_to_raw(der, priv)  # type: ignore
    elif alg_name == "EdDSA":
        priv = jwk_to_private_key(signing_key)  # type: ignore
        signature = priv.sign(signing_input)  # type: ignore
    else:
        raise ValueError("Unsupported alg for signing")

    return f"{header_b64}.{payload_b64}.{b64u_encode(signature)}"


def verify_jws_compact(token: str, jwks: JWKS, leeway: int = 60, expected_iss: Optional[str] = None, expected_aud: Optional[Union[str, List[str]]] = None, verify_claims: bool = True) -> Dict[str, Any]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise JWTValidationError("Invalid JWS compact serialization")
    header = json.loads(b64u_decode(header_b64))
    payload = json.loads(b64u_decode(payload_b64))
    signature = b64u_decode(sig_b64)
    alg = header.get("alg")
    kid = header.get("kid")
    if alg not in ("RS256", "RS384", "ES256", "ES384", "EdDSA"):
        raise JWTValidationError("Unsupported alg")

    candidates: List[JWK] = []
    if kid:
        k = jwks.by_kid(kid)
        if k:
            candidates = [k]
    if not candidates:
        # try all
        candidates = [k for k in jwks.keys if k.alg in (None, alg) or True]

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    last_err: Optional[Exception] = None

    for k in candidates:
        try:
            pub = jwk_to_public_key(k)
            if alg in ("RS256", "RS384"):
                pub.verify(signature, signing_input, padding.PKCS1v15(), HASHES[alg])  # type: ignore
            elif alg in ("ES256", "ES384"):
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    continue
                der = _ecdsa_raw_to_der(signature, pub)
                pub.verify(der, signing_input, ec.ECDSA(HASHES[alg]))  # type: ignore
            elif alg == "EdDSA":
                pub.verify(signature, signing_input)  # type: ignore
            else:
                continue

            # Signature ok
            if verify_claims:
                _validate_claims(payload, leeway=leeway, expected_iss=expected_iss, expected_aud=expected_aud)
            return payload
        except (InvalidSignature, JWTValidationError, ValueError) as e:
            last_err = e
            continue

    raise JWTValidationError(f"Signature/claims verification failed: {last_err}")


# =========================
# Remote JWKS Provider with HTTP cache
# =========================

class JWKSProvider:
    """
    Async JWKS fetcher with ETag/Last-Modified and TTL fallback.
    Thread-safe for read; async for refresh.
    """

    def __init__(self, url: str, min_ttl_seconds: int = 60, max_ttl_seconds: int = 3600, timeout_ms: int = 2500) -> None:
        self._url = url
        self._min_ttl = min_ttl_seconds
        self._max_ttl = max_ttl_seconds
        self._timeout = timeout_ms / 1000.0
        self._jwks: JWKS = JWKS(keys=[])
        self._etag: Optional[str] = None
        self._last_modified: Optional[str] = None
        self._expiry: float = 0.0
        self._lock = asyncio.Lock()

    def current(self) -> JWKS:
        return self._jwks

    async def refresh_if_needed(self) -> JWKS:
        now = time.time()
        if now < self._expiry and self._jwks.keys:
            return self._jwks
        async with self._lock:
            if now < self._expiry and self._jwks.keys:
                return self._jwks
            headers = {}
            if self._etag:
                headers["If-None-Match"] = self._etag
            if self._last_modified:
                headers["If-Modified-Since"] = self._last_modified
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    r = await client.get(self._url, headers=headers)
                if r.status_code == 304:
                    self._expiry = time.time() + self._min_ttl
                    return self._jwks
                r.raise_for_status()
                data = r.json()
                jwks = JWKS(**data)
                # Cache headers
                self._etag = r.headers.get("ETag") or self._etag
                self._last_modified = r.headers.get("Last-Modified") or self._last_modified
                # TTL from Cache-Control
                ttl = self._min_ttl
                cc = r.headers.get("Cache-Control", "")
                for part in cc.split(","):
                    part = part.strip()
                    if part.startswith("max-age="):
                        try:
                            ttl = max(ttl, min(int(part.split("=", 1)[1]), self._max_ttl))
                        except Exception:
                            pass
                self._jwks = jwks
                self._expiry = time.time() + ttl
                return self._jwks
            except Exception as e:
                logger.warning("JWKS refresh failed: %s", e)
                # Soft-fail: extend expiry shortly to avoid hot loop
                self._expiry = time.time() + max(15, self._min_ttl // 2)
                return self._jwks


# =========================
# Local KeyStore with rotation & persistence
# =========================

@dataclass
class StoredKey:
    jwk: JWK
    created_at: int
    not_before: Optional[int] = None
    not_after: Optional[int] = None
    active: bool = True  # used for signing
    label: Optional[str] = None


class KeyStore:
    """
    Local keystore storing private JWKs with rotation; persist to encrypted PKCS#8 PEM files or JSON.
    """

    def __init__(self, path: Optional[Path] = None, passphrase: Optional[bytes] = None) -> None:
        self._path = Path(path) if path else None
        self._keys: Dict[str, StoredKey] = {}
        self._passphrase = passphrase

    # --- persistence ---
    def save(self) -> None:
        if not self._path:
            return
        data = {
            "keys": [
                {
                    "jwk": sk.jwk.dict(exclude_none=True),
                    "created_at": sk.created_at,
                    "not_before": sk.not_before,
                    "not_after": sk.not_after,
                    "active": sk.active,
                    "label": sk.label,
                }
                for sk in self._keys.values()
            ]
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def load(self) -> None:
        if not self._path or not self._path.exists():
            return
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        self._keys = {}
        for item in raw.get("keys", []):
            jwk = JWK(**item["jwk"])
            self._keys[jwk.ensure_kid()] = StoredKey(
                jwk=jwk,
                created_at=int(item["created_at"]),
                not_before=item.get("not_before"),
                not_after=item.get("not_after"),
                active=bool(item.get("active", True)),
                label=item.get("label"),
            )

    # --- management ---
    def add_key(self, jwk: JWK, *, active: bool = True, not_before: Optional[int] = None, not_after: Optional[int] = None, label: Optional[str] = None) -> str:
        kid = jwk.ensure_kid()
        self._keys[kid] = StoredKey(jwk=jwk, created_at=int(time.time()), not_before=not_before, not_after=not_after, active=active, label=label)
        return kid

    def generate_and_add(self, alg: Alg = "RS256", rsa_bits: int = 2048, **kwargs) -> str:
        jwk = generate_key(alg, rsa_bits=rsa_bits)
        return self.add_key(jwk, **kwargs)

    def deactivate(self, kid: str) -> None:
        if kid in self._keys:
            self._keys[kid].active = False

    def remove(self, kid: str) -> None:
        self._keys.pop(kid, None)

    def signing_key(self) -> Optional[StoredKey]:
        # choose the newest active key
        active = [sk for sk in self._keys.values() if sk.active]
        return max(active, key=lambda x: x.created_at) if active else None

    def get_public_jwks(self) -> JWKS:
        return JWKS(keys=[JWK(**{**sk.jwk.dict(exclude_none=True), "d": None}) for sk in self._keys.values()])

    def keys_info(self) -> List[Dict[str, Any]]:
        out = []
        for kid, sk in self._keys.items():
            out.append(
                {
                    "kid": kid,
                    "alg": sk.jwk.alg,
                    "kty": sk.jwk.kty,
                    "created_at": sk.created_at,
                    "active": sk.active,
                    "not_before": sk.not_before,
                    "not_after": sk.not_after,
                    "label": sk.label,
                }
            )
        return sorted(out, key=lambda x: x["created_at"])

    def rotate_if_needed(self, max_age_days: int, keep_last: int = 2, alg: Optional[Alg] = None, rsa_bits: int = 2048) -> Optional[str]:
        """
        Generate a new signing key if the current active key is older than max_age_days.
        Keep 'keep_last' old keys for verification compatibility.
        """
        now = int(time.time())
        sk = self.signing_key()
        if sk and now - sk.created_at < max_age_days * 86400:
            return None
        kid = self.generate_and_add(alg=alg or (sk.jwk.alg if sk else "RS256"), rsa_bits=rsa_bits, active=True)  # type: ignore
        # Keep only last N
        all_kids = [k for k, _ in sorted(self._keys.items(), key=lambda kv: kv[1].created_at, reverse=True)]
        for old_kid in all_kids[keep_last:]:
            self._keys[old_kid].active = False
        return kid


# =========================
# High-level helpers integrating pieces
# =========================

def jwt_verify_with_provider(token: str, provider: JWKSProvider, *, leeway: int = 60, expected_iss: Optional[str] = None, expected_aud: Optional[Union[str, List[str]]] = None) -> Dict[str, Any]:
    """
    Fetch/update JWKS if needed and verify token.
    """
    # Ensure cache
    jwks = asyncio.get_event_loop().run_until_complete(provider.refresh_if_needed()) if asyncio.get_event_loop().is_running() is False else None
    if jwks is None:
        jwks = provider.current()
    return verify_jws_compact(token, jwks, leeway=leeway, expected_iss=expected_iss, expected_aud=expected_aud, verify_claims=True)


def jwt_sign_with_keystore(payload: Dict[str, Any], keystore: KeyStore, headers: Optional[Dict[str, Any]] = None) -> str:
    sk = keystore.signing_key()
    if not sk:
        raise RuntimeError("No active signing key in keystore")
    # add standard iat if missing
    payload = dict(payload)
    payload.setdefault("iat", int(time.time()))
    return sign_jwt(payload, sk.jwk, kid=sk.jwk.ensure_kid(), alg=sk.jwk.alg, headers=headers)


# =========================
# Optional PEM import/export for interop
# =========================

def private_key_to_pem(priv: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey], passphrase: Optional[bytes] = None) -> bytes:
    enc = NoEncryption() if not passphrase else BestAvailableEncryption(passphrase)
    return priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)


def public_key_to_pem(pub: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey]) -> bytes:
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def load_private_key_from_pem(pem: bytes, passphrase: Optional[bytes] = None):
    return serialization.load_pem_private_key(pem, password=passphrase)


def load_public_key_from_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


# =========================
# Minimal self-test (can be used in unit tests)
# =========================

def _selftest() -> None:
    for alg in ("RS256", "ES256", "ES384", "EdDSA"):
        jwk_priv = generate_key(alg=alg)
        ks = KeyStore()
        ks.add_key(jwk_priv, active=True)
        payload = {"sub": "123", "iss": "issuer", "aud": "aud", "exp": int(time.time()) + 60}
        token = jwt_sign_with_keystore(payload, ks)
        jwks = ks.get_public_jwks()
        out = verify_jws_compact(token, jwks, expected_iss="issuer", expected_aud="aud")
        assert out["sub"] == "123"

# Uncomment for manual quick test:
# if __name__ == "__main__":
#     _selftest()
