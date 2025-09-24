# policy-core/policy_core/utils/jwk.py
"""
Industrial-grade JWK utilities.
Standards: RFC 7517 (JWK), RFC 7518 (JWA), RFC 7638 (JWK Thumbprint), RFC 8037 (OKP).
Features:
- Safe base64url (no padding), strict parsing/validation
- JWK ↔ PEM (public/private), x5c/x5t support
- RFC7638 thumbprint (configurable digest), kid derivation
- Key generation: RSA, EC (P-256/384/521), OKP (Ed25519), oct (symmetric)
- JWS signing/verifying: RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, HS256/384/512
- JWK Set helpers
- Works without cryptography for parsing/thumbprint; cryptographic ops require it

This module avoids ambiguous behaviors and enforces JOSE safety limits.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# ---- Optional cryptography backend ----
_CRYPTO_AVAILABLE = True
try:
    from cryptography.hazmat.primitives import hashes, serialization, hmac as _chmac
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption,
        load_pem_private_key, load_pem_public_key, load_der_public_key
    )
    from cryptography.x509 import load_der_x509_certificate
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature, decode_dss_signature
    )
except Exception:  # pragma: no cover
    _CRYPTO_AVAILABLE = False

# ---- Errors ----

class JWKError(Exception):
    pass

class JWKValidationError(JWKError):
    pass

class AlgorithmNotSupported(JWKError):
    pass

class CryptoBackendUnavailable(JWKError):
    pass

# ---- Constants / policies ----

# JOSE base64url safe alphabet
_B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]*$")

_RSA_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi", "oth"}
_EC_PRIVATE_PARAMS = {"d"}
_OKP_PRIVATE_PARAMS = {"d"}
_SYM_PARAMS = {"k"}

# RFC7518 Section 6.2.1.1: crit parameter not supported in this utility on purpose.

_EC_CURVE_MAP = {
    "P-256": ec.SECP256R1 if _CRYPTO_AVAILABLE else "P-256",
    "P-384": ec.SECP384R1 if _CRYPTO_AVAILABLE else "P-384",
    "P-521": ec.SECP521R1 if _CRYPTO_AVAILABLE else "P-521",
}

_ALLOWED_KTYS = {"RSA", "EC", "OKP", "oct"}
_ALLOWED_ALGS = {
    # RSA
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    # EC
    "ES256", "ES384", "ES512",
    # OKP
    "EdDSA",
    # HMAC
    "HS256", "HS384", "HS512",
}

# kty → required public members
_REQUIRED_PUBLIC = {
    "RSA": {"n", "e"},
    "EC": {"crv", "x", "y"},
    "OKP": {"crv", "x"},
    "oct": {"k"},
}

# ---- Base64url helpers ----

def b64u_encode(data: bytes) -> str:
    """base64url without padding."""
    s = base64.urlsafe_b64encode(data).decode("ascii")
    return s.rstrip("=")

def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str):
        raise JWKValidationError("base64url value must be str")
    if not _B64URL_RE.match(s):
        raise JWKValidationError("Invalid base64url characters")
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception as e:
        raise JWKValidationError(f"Invalid base64url: {e}") from e

def _int_to_b64u(i: int) -> str:
    if i < 0:
        raise JWKValidationError("Negative integers not allowed for key params")
    length = (i.bit_length() + 7) // 8 or 1
    return b64u_encode(i.to_bytes(length, "big"))

def _b64u_to_int(s: str) -> int:
    return int.from_bytes(b64u_decode(s), "big")

# ---- Thumbprint (RFC 7638) ----

def jwk_thumbprint(jwk: Dict[str, Any], hash_name: str = "sha256") -> str:
    """
    RFC 7638: thumbprint over a JSON object containing only required members
    in lexicographic order.
    """
    if "kty" not in jwk or jwk.get("kty") not in _ALLOWED_KTYS:
        raise JWKValidationError("kty is missing or unsupported for thumbprint")

    kty = jwk["kty"]
    if kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        members = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    elif kty == "oct":
        # Though thumbprints for 'oct' are uncommon, RFC7638 allows it using required members.
        members = {"k": jwk["k"], "kty": "oct"}
    else:
        raise JWKValidationError("Unsupported kty for thumbprint")

    serialized = json.dumps(members, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    try:
        digest = hashlib.new(hash_name, serialized).digest()
    except Exception as e:
        raise JWKError(f"Unknown hash: {hash_name}") from e
    return b64u_encode(digest)

# ---- Utilities ----

def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def is_private_jwk(jwk: Dict[str, Any]) -> bool:
    kty = jwk.get("kty")
    if kty == "RSA":
        return any(p in jwk for p in _RSA_PRIVATE_PARAMS)
    if kty == "EC":
        return "d" in jwk
    if kty == "OKP":
        return "d" in jwk
    if kty == "oct":
        # symmetric is always "private" but treated specially
        return True
    return False

def public_only(jwk: Dict[str, Any]) -> Dict[str, Any]:
    kty = jwk.get("kty")
    if kty == "RSA":
        keep = {"kty", "n", "e", "kid", "alg", "use", "key_ops", "x5c", "x5t", "x5t#S256"}
    elif kty == "EC":
        keep = {"kty", "crv", "x", "y", "kid", "alg", "use", "key_ops", "x5c", "x5t", "x5t#S256"}
    elif kty == "OKP":
        keep = {"kty", "crv", "x", "kid", "alg", "use", "key_ops", "x5c", "x5t", "x5t#S256"}
    elif kty == "oct":
        # oct has no true public form; redact material
        raise JWKValidationError("oct keys cannot be made public")
    else:
        raise JWKValidationError("Unknown kty")
    return {k: v for k, v in jwk.items() if k in keep}

def _validate_required(jwk: Dict[str, Any]) -> None:
    kty = jwk.get("kty")
    if kty not in _ALLOWED_KTYS:
        raise JWKValidationError("Unsupported or missing kty")
    req = _REQUIRED_PUBLIC[kty]
    missing = [m for m in req if m not in jwk]
    if missing:
        raise JWKValidationError(f"Missing required members for {kty}: {missing}")

def _validate_base64url_fields(jwk: Dict[str, Any]) -> None:
    kty = jwk["kty"]
    fields = []
    if kty == "RSA":
        fields = ["n", "e"] + [p for p in ["d", "p", "q", "dp", "dq", "qi"] if p in jwk]
    elif kty == "EC":
        fields = ["x", "y"] + (["d"] if "d" in jwk else [])
    elif kty == "OKP":
        fields = ["x"] + (["d"] if "d" in jwk else [])
    elif kty == "oct":
        fields = ["k"]
    for f in fields:
        if not isinstance(jwk.get(f), str):
            raise JWKValidationError(f"Member '{f}' must be base64url string")
        _ = b64u_decode(jwk[f])  # will raise on invalid

def _validate_alg_consistency(jwk: Dict[str, Any]) -> None:
    alg = jwk.get("alg")
    if alg is None:
        return
    if alg not in _ALLOWED_ALGS:
        raise AlgorithmNotSupported(f"alg '{alg}' is not supported")

    kty = jwk["kty"]
    if kty == "RSA" and not alg.startswith(("RS", "PS")):
        raise JWKValidationError("RSA keys must use RS* or PS* algorithms")
    if kty == "EC" and not alg.startswith("ES"):
        raise JWKValidationError("EC keys must use ES* algorithms")
    if kty == "OKP" and alg != "EdDSA":
        raise JWKValidationError("OKP keys must use EdDSA algorithm")
    if kty == "oct" and not alg.startswith("HS"):
        raise JWKValidationError("oct (symmetric) keys must use HS* algorithms")

def _validate_use_key_ops(jwk: Dict[str, Any]) -> None:
    # RFC7517 Section 4.2/4.3: "use" vs "key_ops" should not conflict.
    use = jwk.get("use")
    key_ops = jwk.get("key_ops")
    if use and key_ops:
        # Minimal check: if 'sig' use then ops must include sign/verify or similar
        if use == "sig":
            allowed = {"sign", "verify"}
            if not any(op in allowed for op in key_ops):
                raise JWKValidationError("use='sig' conflicts with key_ops")
        if use == "enc":
            allowed = {"encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"}
            if not any(op in allowed for op in key_ops):
                raise JWKValidationError("use='enc' conflicts with key_ops")

def _validate_x5_chain(jwk: Dict[str, Any]) -> None:
    x5c = jwk.get("x5c")
    if x5c is None:
        return
    if not isinstance(x5c, list) or not all(isinstance(s, str) for s in x5c):
        raise JWKValidationError("x5c must be a list of base64 DER certs")
    # Verify x5t/x5t#S256 if present
    first = x5c[0] if x5c else None
    if first:
        try:
            der = base64.b64decode(first.encode("ascii"))
        except Exception as e:
            raise JWKValidationError(f"x5c[0] is not valid base64: {e}") from e
        sha1 = hashlib.sha1(der).digest()
        sha256 = hashlib.sha256(der).digest()
        if "x5t" in jwk and jwk["x5t"] != b64u_encode(sha1):
            raise JWKValidationError("x5t does not match x5c[0]")
        if "x5t#S256" in jwk and jwk["x5t#S256"] != b64u_encode(sha256):
            raise JWKValidationError("x5t#S256 does not match x5c[0]")

def validate_jwk(jwk: Dict[str, Any]) -> None:
    if not isinstance(jwk, dict):
        raise JWKValidationError("JWK must be an object")
    _validate_required(jwk)
    _validate_base64url_fields(jwk)
    _validate_alg_consistency(jwk)
    _validate_use_key_ops(jwk)
    _validate_x5_chain(jwk)

# ---- JWK class ----

@dataclass(slots=True)
class JWK:
    data: Dict[str, Any] = field(default_factory=dict)

    # -------- Parsing / Validation --------
    @staticmethod
    def from_json(s: Union[str, bytes, Dict[str, Any]]) -> "JWK":
        if isinstance(s, dict):
            d = s
        else:
            if isinstance(s, bytes):
                s = s.decode("utf-8")
            d = json.loads(s)
        j = JWK(d)
        j.validate()
        return j

    def to_json(self) -> str:
        return json.dumps(self.data, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    def validate(self) -> None:
        validate_jwk(self.data)

    # -------- Public/Private views --------
    def is_private(self) -> bool:
        return is_private_jwk(self.data)

    def to_public(self) -> "JWK":
        return JWK(public_only(self.data))

    # -------- kid / thumbprint --------
    def thumbprint(self, hash_name: str = "sha256") -> str:
        return jwk_thumbprint(self.data, hash_name=hash_name)

    def ensure_kid(self, strategy: str = "thumbprint", hash_name: str = "sha256") -> str:
        kid = self.data.get("kid")
        if kid:
            return kid
        if strategy == "thumbprint":
            kid = self.thumbprint(hash_name=hash_name)
            self.data["kid"] = kid
            return kid
        raise JWKError("Unknown kid strategy")

    # -------- x5c to PEM helper --------
    def x5c_chain_pem(self) -> Optional[List[bytes]]:
        x5c = self.data.get("x5c")
        if not x5c:
            return None
        if not _CRYPTO_AVAILABLE:
            raise CryptoBackendUnavailable("cryptography is required for x5c handling")
        pems: List[bytes] = []
        for s in x5c:
            der = base64.b64decode(s.encode("ascii"))
            cert = load_der_x509_certificate(der)
            pems.append(cert.public_bytes(Encoding.PEM))
        return pems

    # -------- PEM conversions --------
    def to_pem(self, private: bool = True, password: Optional[bytes] = None) -> Tuple[bytes, Optional[bytes]]:
        """
        Returns (public_pem, private_pem or None).
        private=True exports private key if available, otherwise raises.
        """
        if not _CRYPTO_AVAILABLE:
            raise CryptoBackendUnavailable("cryptography is required for PEM conversions")

        kty = self.data["kty"]
        if kty == "RSA":
            pub, prv = _rsa_from_jwk(self.data)
        elif kty == "EC":
            pub, prv = _ec_from_jwk(self.data)
        elif kty == "OKP":
            pub, prv = _okp_from_jwk(self.data)
        elif kty == "oct":
            raise JWKValidationError("oct has no PEM representation")
        else:
            raise JWKValidationError("Unknown kty")

        public_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        private_pem = None
        if private:
            if prv is None:
                raise JWKValidationError("Private parameters missing")
            if password:
                enc = BestAvailableEncryption(password)
            else:
                enc = NoEncryption()
            private_pem = prv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
        return public_pem, private_pem

    @staticmethod
    def from_pem(public_pem: Optional[bytes] = None,
                 private_pem: Optional[bytes] = None,
                 password: Optional[bytes] = None,
                 alg: Optional[str] = None,
                 use: Optional[str] = None,
                 kid_strategy: str = "thumbprint") -> "JWK":
        if not _CRYPTO_AVAILABLE:
            raise CryptoBackendUnavailable("cryptography is required for PEM conversions")

        pub = None
        prv = None
        if private_pem:
            prv = load_pem_private_key(private_pem, password=password)
            pub = prv.public_key()
        if public_pem:
            pub = load_pem_public_key(public_pem)

        if pub is None:
            raise JWKValidationError("At least public_pem or private_pem must be provided")

        jwk = None
        # RSA
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa_mod, ec as _ec_mod, ed25519 as _ed_mod

        if isinstance(pub, _rsa_mod.RSAPublicKey):
            jwk = _rsa_to_jwk(pub, prv)
        elif isinstance(pub, _ec_mod.EllipticCurvePublicKey):
            jwk = _ec_to_jwk(pub, prv)
        elif isinstance(pub, _ed_mod.Ed25519PublicKey):
            jwk = _okp_to_jwk(pub, prv)
        else:
            raise AlgorithmNotSupported("Unsupported key type in PEM")

        if alg:
            jwk["alg"] = alg
        if use:
            jwk["use"] = use
        obj = JWK(jwk)
        obj.ensure_kid(strategy=kid_strategy)
        obj.validate()
        return obj

    # -------- Generation --------
    @staticmethod
    def generate_rsa(bits: int = 2048, alg: str = "RS256", use: Optional[str] = "sig") -> "JWK":
        if not _CRYPTO_AVAILABLE:
            raise CryptoBackendUnavailable("cryptography is required for key generation")
        if bits < 2048:
            raise JWKValidationError("RSA key must be >= 2048 bits")
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        jwk = _rsa_to_jwk(key.public_key(), key)
        jwk["alg"] = alg
        if use:
            jwk["use"] = use
        obj = JWK(jwk)
        obj.ensure_kid()
        obj.validate()
        return obj

    @staticmethod
    def generate_ec(crv: str = "P-256", alg: Optional[str] = None, use: Optional[str] = "sig") -> "JWK":
        if not _CRYPTO_AVAILABLE:
            raise CryptoBackendUnavailable("cryptography is required for key generation")
        if crv not in _EC_CURVE_MAP:
            raise AlgorithmNotSupported("Unsupported EC curve")
        key = ec.generate_private_key(_EC_CURVE_MAP[crv]())
        jwk = _ec_to_jwk(key.public_key(), key)
        if alg is None:
            alg = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}[crv]
        jwk["alg"] = alg
        if use:
            jwk["use"] = use
        obj = JWK(jwk)
        obj.ensure_kid()
        obj.validate()
        return obj

    @staticmethod
    def generate_okp(alg: str = "EdDSA", use: Optional[str] = "sig") -> "JWK":
        if not _CRYPTO_AVAILABLE:
            raise CryptoBackendUnavailable("cryptography is required for key generation")
        key = ed25519.Ed25519PrivateKey.generate()
        jwk = _okp_to_jwk(key.public_key(), key)
        jwk["alg"] = alg
        if use:
            jwk["use"] = use
        obj = JWK(jwk)
        obj.ensure_kid()
        obj.validate()
        return obj

    @staticmethod
    def generate_oct(size_bytes: int = 32, alg: str = "HS256", use: Optional[str] = "sig") -> "JWK":
        if size_bytes < 16:
            raise JWKValidationError("oct key must be at least 128 bits")
        k = os.urandom(size_bytes)
        jwk = {"kty": "oct", "k": b64u_encode(k)}
        jwk["alg"] = alg
        if use:
            jwk["use"] = use
        obj = JWK(jwk)
        obj.ensure_kid()
        obj.validate()
        return obj

    # -------- Signing / verifying --------
    def sign(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise JWKError("data must be bytes")
        alg = self.data.get("alg")
        if not alg:
            raise AlgorithmNotSupported("alg is required for signing")
        if self.data["kty"] == "oct":
            return _sign_hs(self.data, alg, data)
        if not _CRYPTO_AVAILABLE:
            raise CryptoBackendUnavailable("cryptography is required for signing")

        kty = self.data["kty"]
        if kty == "RSA":
            return _sign_rsa(self.data, alg, data)
        if kty == "EC":
            return _sign_ec(self.data, alg, data)
        if kty == "OKP":
            return _sign_okp(self.data, alg, data)
        raise AlgorithmNotSupported("Unsupported kty for signing")

    def verify(self, data: bytes, signature: bytes) -> bool:
        if not isinstance(data, (bytes, bytearray)):
            raise JWKError("data must be bytes")
        alg = self.data.get("alg")
        if not alg:
            raise AlgorithmNotSupported("alg is required for verification")
        if self.data["kty"] == "oct":
            expect = _sign_hs(self.data, alg, data)
            return constant_time_equals(expect, signature)
        if not _CRYPTO_AVAILABLE:
            raise CryptoBackendUnavailable("cryptography is required for verification")

        kty = self.data["kty"]
        if kty == "RSA":
            return _verify_rsa(self.data, alg, data, signature)
        if kty == "EC":
            return _verify_ec(self.data, alg, data, signature)
        if kty == "OKP":
            return _verify_okp(self.data, alg, data, signature)
        raise AlgorithmNotSupported("Unsupported kty for verification")

# ---- RSA helpers ----

def _rsa_to_jwk(pub, prv=None) -> Dict[str, Any]:
    numbers = pub.public_numbers()
    jwk = {
        "kty": "RSA",
        "n": _int_to_b64u(numbers.n),
        "e": _int_to_b64u(numbers.e),
    }
    if prv is not None:
        pn = prv.private_numbers()
        jwk.update({
            "d": _int_to_b64u(pn.d),
            "p": _int_to_b64u(pn.p),
            "q": _int_to_b64u(pn.q),
            "dp": _int_to_b64u(pn.dmp1),
            "dq": _int_to_b64u(pn.dmq1),
            "qi": _int_to_b64u(pn.iqmp),
        })
    return jwk

def _rsa_from_jwk(jwk: Dict[str, Any]):
    n = _b64u_to_int(jwk["n"])
    e = _b64u_to_int(jwk["e"])
    pub_numbers = rsa.RSAPublicNumbers(e=e, n=n)
    pub = pub_numbers.public_key()
    prv = None
    if all(k in jwk for k in ["d", "p", "q", "dp", "dq", "qi"]):
        d = _b64u_to_int(jwk["d"])
        p = _b64u_to_int(jwk["p"])
        q = _b64u_to_int(jwk["q"])
        dp = _b64u_to_int(jwk["dp"])
        dq = _b64u_to_int(jwk["dq"])
        qi = _b64u_to_int(jwk["qi"])
        prv_numbers = rsa.RSAPrivateNumbers(
            p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi, public_numbers=pub_numbers
        )
        prv = prv_numbers.private_key()
    return pub, prv

def _rsa_hash(alg: str):
    if alg.endswith("256"):
        return hashes.SHA256()
    if alg.endswith("384"):
        return hashes.SHA384()
    if alg.endswith("512"):
        return hashes.SHA512()
    raise AlgorithmNotSupported("Unsupported RSA hash")

def _sign_rsa(jwk: Dict[str, Any], alg: str, data: bytes) -> bytes:
    pub, prv = _rsa_from_jwk(jwk)
    if prv is None:
        raise JWKValidationError("Private RSA parameters required for signing")
    h = _rsa_hash(alg)
    if alg.startswith("RS"):
        return prv.sign(data, padding.PKCS1v15(), h)
    if alg.startswith("PS"):
        return prv.sign(data, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
    raise AlgorithmNotSupported("Unsupported RSA alg")

def _verify_rsa(jwk: Dict[str, Any], alg: str, data: bytes, sig: bytes) -> bool:
    pub, _ = _rsa_from_jwk(jwk)
    h = _rsa_hash(alg)
    try:
        if alg.startswith("RS"):
            pub.verify(sig, data, padding.PKCS1v15(), h)
        elif alg.startswith("PS"):
            pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
        else:
            return False
        return True
    except Exception:
        return False

# ---- EC helpers ----

def _ec_curve(crv: str):
    if crv not in _EC_CURVE_MAP:
        raise AlgorithmNotSupported("Unsupported EC curve")
    return _EC_CURVE_MAP[crv]()

def _ec_to_jwk(pub, prv=None) -> Dict[str, Any]:
    numbers = pub.public_numbers()
    x = numbers.x.to_bytes((numbers.curve.key_size + 7) // 8, "big")
    y = numbers.y.to_bytes((numbers.curve.key_size + 7) // 8, "big")
    crv = {256: "P-256", 384: "P-384", 521: "P-521"}[numbers.curve.key_size]
    jwk = {"kty": "EC", "crv": crv, "x": b64u_encode(x), "y": b64u_encode(y)}
    if prv is not None:
        d = prv.private_numbers().private_value
        size = (numbers.curve.key_size + 7) // 8
        jwk["d"] = b64u_encode(d.to_bytes(size, "big"))
    return jwk

def _ec_from_jwk(jwk: Dict[str, Any]):
    crv = jwk["crv"]
    curve = _ec_curve(crv)
    x = int.from_bytes(b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)
    pub = pub_numbers.public_key()
    prv = None
    if "d" in jwk:
        d = int.from_bytes(b64u_decode(jwk["d"]), "big")
        prv = ec.derive_private_key(d, curve)
    return pub, prv

def _ec_hash(alg: str):
    if alg == "ES256":
        return hashes.SHA256()
    if alg == "ES384":
        return hashes.SHA384()
    if alg == "ES512":
        return hashes.SHA512()
    raise AlgorithmNotSupported("Unsupported EC alg")

def _sign_ec(jwk: Dict[str, Any], alg: str, data: bytes) -> bytes:
    _, prv = _ec_from_jwk(jwk)
    if prv is None:
        raise JWKValidationError("Private EC parameter 'd' required for signing")
    h = _ec_hash(alg)
    der_sig = prv.sign(data, ec.ECDSA(h))
    # Convert DER to raw (r||s) as used in JWS
    r, s = decode_dss_signature(der_sig)
    size = (prv.curve.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")

def _verify_ec(jwk: Dict[str, Any], alg: str, data: bytes, sig: bytes) -> bool:
    pub, _ = _ec_from_jwk(jwk)
    h = _ec_hash(alg)
    try:
        size = (pub.curve.key_size + 7) // 8
        if len(sig) != 2 * size:
            return False
        r = int.from_bytes(sig[:size], "big")
        s = int.from_bytes(sig[size:], "big")
        der = encode_dss_signature(r, s)
        pub.verify(der, data, ec.ECDSA(h))
        return True
    except Exception:
        return False

# ---- OKP (Ed25519) helpers ----

def _okp_to_jwk(pub, prv=None) -> Dict[str, Any]:
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u_encode(pub_bytes)}
    if prv is not None:
        prv_bytes = prv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        jwk["d"] = b64u_encode(prv_bytes)
    return jwk

def _okp_from_jwk(jwk: Dict[str, Any]):
    x = b64u_decode(jwk["x"])
    pub = ed25519.Ed25519PublicKey.from_public_bytes(x)
    prv = None
    if "d" in jwk:
        d = b64u_decode(jwk["d"])
        prv = ed25519.Ed25519PrivateKey.from_private_bytes(d)
    return pub, prv

def _sign_okp(jwk: Dict[str, Any], alg: str, data: bytes) -> bytes:
    if alg != "EdDSA":
        raise AlgorithmNotSupported("Ed25519 requires alg=EdDSA")
    _, prv = _okp_from_jwk(jwk)
    if prv is None:
        raise JWKValidationError("Private OKP parameter 'd' required for signing")
    return prv.sign(data)

def _verify_okp(jwk: Dict[str, Any], alg: str, data: bytes, sig: bytes) -> bool:
    if alg != "EdDSA":
        return False
    pub, _ = _okp_from_jwk(jwk)
    try:
        pub.verify(sig, data)
        return True
    except Exception:
        return False

# ---- HMAC (oct) ----

def _hs_hash(alg: str):
    if alg == "HS256":
        return hashlib.sha256
    if alg == "HS384":
        return hashlib.sha384
    if alg == "HS512":
        return hashlib.sha512
    raise AlgorithmNotSupported("Unsupported HMAC alg")

def _sign_hs(jwk: Dict[str, Any], alg: str, data: bytes) -> bytes:
    key = b64u_decode(jwk["k"])
    return hmac.new(key, data, _hs_hash(alg)).digest()

# ---- JWK Set helpers ----

def load_jwk_set(s: Union[str, bytes, Dict[str, Any]]) -> List[JWK]:
    if isinstance(s, dict):
        obj = s
    else:
        if isinstance(s, bytes):
            s = s.decode("utf-8")
        obj = json.loads(s)
    if "keys" not in obj or not isinstance(obj["keys"], list):
        raise JWKValidationError("JWK Set must contain 'keys' array")
    jwks = [JWK.from_json(k) for k in obj["keys"]]
    # Ensure unique kid
    seen = set()
    for j in jwks:
        kid = j.data.get("kid") or j.ensure_kid()
        if kid in seen:
            raise JWKValidationError(f"Duplicate kid in JWK Set: {kid}")
        seen.add(kid)
    return jwks

def dump_jwk_set(keys: Iterable[JWK]) -> str:
    arr = []
    for k in keys:
        # maintain provided kid; ensure if missing
        kid = k.data.get("kid") or k.ensure_kid()
        arr.append({**k.data, "kid": kid})
    return json.dumps({"keys": arr}, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

# ---- High-level JOSE helpers ----

def jws_sign_compact(jwk: JWK, header: Dict[str, Any], payload: bytes) -> str:
    """
    Build compact JWS using provided JWK. Header must contain or will be filled with alg/kid.
    """
    hdr = dict(header or {})
    alg = hdr.get("alg") or jwk.data.get("alg")
    if not alg:
        raise AlgorithmNotSupported("alg is required")
    hdr["alg"] = alg
    hdr["kid"] = hdr.get("kid") or jwk.ensure_kid()
    header_b64 = b64u_encode(json.dumps(hdr, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = b64u_encode(payload)
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    sig = jwk.sign(signing_input)
    return header_b64 + "." + payload_b64 + "." + b64u_encode(sig)

def jws_verify_compact(jwk: JWK, token: str) -> Tuple[Dict[str, Any], bytes]:
    """
    Verify compact JWS; returns (header, payload). Raises on failure.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as e:
        raise JWKError("Invalid JWS compact serialization") from e
    header = json.loads(b64u_decode(header_b64))
    payload = b64u_decode(payload_b64)
    alg = header.get("alg")
    # If JWK has alg, enforce match
    if jwk.data.get("alg") and alg and jwk.data["alg"] != alg:
        raise JWKValidationError("alg in header does not match JWK")
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    if not jwk.verify(signing_input, b64u_decode(sig_b64)):
        raise JWKValidationError("Signature verification failed")
    return header, payload
