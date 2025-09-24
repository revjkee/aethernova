# security-core/security/tokens/bind_mtls.py
# Certificate-Bound Access Tokens for OAuth2 mTLS (RFC 8705) with JOSE/JWT.
# Dependencies: cryptography (hazmat), stdlib only otherwise.
# Provides:
#  - cert_thumbprint_sha256(cert_der) -> base64url(x5t#S256)
#  - issue_bound_access_token(...) -> at+jwt string
#  - verify_bound_access_token(...) -> dict claims (raises on failure)
#  - JWK/JWKS helpers, ECDSA JWS raw<->DER conversion, safe base64url, constant-time compare

from __future__ import annotations

import base64
import binascii
import json
import time
import uuid
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple, List, Union

# cryptography primitives
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding, ec, ed25519, ed448
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography import x509

__all__ = [
    "cert_thumbprint_sha256",
    "cnf_for_cert",
    "issue_bound_access_token",
    "verify_bound_access_token",
    "load_jwk_public_key",
    "load_jwks",
    "VerificationOptions",
    "TokenBindingError",
    "SignatureError",
    "ClaimsError",
]

# ==========================
# Utilities
# ==========================

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception as e:
        raise ValueError(f"invalid base64url: {e}")

def _json_dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _consteq(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    if isinstance(a, str): a = a.encode("utf-8")
    if isinstance(b, str): b = b.encode("utf-8")
    return hmac.compare_digest(a, b)

def _now() -> int:
    return int(time.time())

# ==========================
# Thumbprint & cnf helpers
# ==========================

def cert_thumbprint_sha256(cert_der: bytes) -> str:
    """
    RFC 8705 uses SHA-256 thumbprint of the X.509 certificate (DER-encoded).
    This is equivalent to the JOSE x5t#S256 value (base64url encoded).
    """
    h = hashlib.sha256(cert_der).digest()
    return _b64url_encode(h)

def cnf_for_cert(cert_der: bytes) -> Dict[str, str]:
    """
    Build the 'cnf' claim object for JWT: {"x5t#S256": "<b64url>"}.
    """
    return {"x5t#S256": cert_thumbprint_sha256(cert_der)}

# ==========================
# JOSE/JWS signing & verify
# ==========================

SUPPORTED_ALGS = {"RS256", "RS384", "RS512",
                  "PS256", "PS384", "PS512",
                  "ES256", "ES384", "ES512",
                  "EdDSA"}

def _ecdsa_sig_der_to_raw(sig_der: bytes, key: ec.EllipticCurvePublicKey) -> bytes:
    r, s = decode_dss_signature(sig_der)
    n = (key.curve.key_size + 7) // 8
    return r.to_bytes(n, "big") + s.to_bytes(n, "big")

def _ecdsa_sig_raw_to_der(sig_raw: bytes) -> bytes:
    n = len(sig_raw) // 2
    r = int.from_bytes(sig_raw[:n], "big")
    s = int.from_bytes(sig_raw[n:], "big")
    return encode_dss_signature(r, s)

def _sign(alg: str, private_key, data: bytes) -> bytes:
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"unsupported alg {alg}")
    if alg.startswith("RS"):
        hash_alg = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}[alg]
        return private_key.sign(data, padding.PKCS1v15(), hash_alg)
    if alg.startswith("PS"):
        hash_alg = {"PS256": hashes.SHA256(), "PS384": hashes.SHA384(), "PS512": hashes.SHA512()}[alg]
        return private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
            hash_alg,
        )
    if alg.startswith("ES"):
        hash_alg = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}[alg]
        sig_der = private_key.sign(data, ec.ECDSA(hash_alg))
        # JWS requires raw(R||S)
        pub = private_key.public_key()
        return _ecdsa_sig_der_to_raw(sig_der, pub)
    if alg == "EdDSA":
        return private_key.sign(data)
    raise ValueError(f"unsupported alg {alg}")

def _verify(alg: str, public_key, data: bytes, sig: bytes) -> None:
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"unsupported alg {alg}")
    if alg.startswith("RS"):
        hash_alg = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}[alg]
        public_key.verify(sig, data, padding.PKCS1v15(), hash_alg)
        return
    if alg.startswith("PS"):
        hash_alg = {"PS256": hashes.SHA256(), "PS384": hashes.SHA384(), "PS512": hashes.SHA512()}[alg]
        public_key.verify(sig, data, padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH), hash_alg)
        return
    if alg.startswith("ES"):
        hash_alg = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}[alg]
        # Convert raw -> DER for cryptography
        sig_der = _ecdsa_sig_raw_to_der(sig)
        public_key.verify(sig_der, data, ec.ECDSA(hash_alg))
        return
    if alg == "EdDSA":
        public_key.verify(sig, data)
        return
    raise ValueError(f"unsupported alg {alg}")

# ==========================
# JWK / JWKS utilities
# ==========================

def _int_from_b64url(s: str) -> int:
    return int.from_bytes(_b64url_decode(s), "big")

def load_jwk_public_key(jwk: Dict[str, Any]):
    """
    Load a public key from a JWK dict. Supports RSA, EC, OKP(Ed25519/Ed448).
    """
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _int_from_b64url(jwk["n"])
        e = _int_from_b64url(jwk["e"])
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub
    if kty == "EC":
        crv = jwk["crv"]
        x = _int_from_b64url(jwk["x"])
        y = _int_from_b64url(jwk["y"])
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[crv]
        pub = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        return pub
    if kty == "OKP":
        crv = jwk["crv"]
        x = _b64url_decode(jwk["x"])
        if crv == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(x)
        if crv == "Ed448":
            return ed448.Ed448PublicKey.from_public_bytes(x)
    raise ValueError(f"unsupported JWK kty={kty}")

def load_jwks(jwks: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a JWKS {"keys":[...]} into mapping kid->(alg?, public_key)
    """
    keys = {}
    for k in jwks.get("keys", []):
        kid = k.get("kid")
        alg = k.get("alg")
        pub = load_jwk_public_key(k)
        if kid:
            keys[kid] = {"alg": alg, "key": pub}
        else:
            # single-key JWKS without kid: use special key
            keys.setdefault("_single", {"alg": alg, "key": pub})
    return keys

# ==========================
# Errors & Options
# ==========================

class TokenBindingError(Exception): ...
class SignatureError(Exception): ...
class ClaimsError(Exception): ...

@dataclass
class VerificationOptions:
    issuer: Optional[str] = None
    audience: Optional[str] = None
    require_scope: Optional[List[str]] = None     # ["read", "write"] -> each must be present (space-separated scope claim)
    clock_skew_sec: int = 60                      # allowed clock skew ±
    # resolver: given kid, alg -> public key; if None, use jwks mapping
    key_resolver: Optional[Callable[[Optional[str], Optional[str]], Any]] = None

# ==========================
# Issuance
# ==========================

def issue_bound_access_token(
    *,
    private_key,                         # cryptography private key object
    alg: str,                            # "RS256" | "PS256" | "ES256" | "EdDSA" ...
    subject: str,
    audience: str,
    issuer: str,
    cert_der: bytes,
    scope: Optional[str] = None,         # space-separated
    lifetime_sec: int = 600,
    not_before: Optional[int] = None,
    kid: Optional[str] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
    include_x5c: Optional[List[bytes]] = None,  # optional list of DER certs for header "x5c"
) -> str:
    """
    Issues an 'at+jwt' access token bound to mTLS client cert via cnf.x5t#S256.
    """
    if alg not in SUPPORTED_ALGS:
        raise ValueError(f"unsupported alg {alg}")

    now = _now()
    iat = now
    nbf = not_before if not_before is not None else now
    exp = iat + int(lifetime_sec)

    cnf = cnf_for_cert(cert_der)

    claims: Dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": iat,
        "nbf": nbf,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "cnf": cnf,
    }
    if scope:
        claims["scope"] = scope
    if extra_claims:
        # do not allow overwrite of cnf/time critical claims
        for k, v in extra_claims.items():
            if k in {"cnf", "exp", "nbf", "iat"}:
                continue
            claims[k] = v

    header: Dict[str, Any] = {"alg": alg, "typ": "at+jwt"}
    if kid:
        header["kid"] = kid
    if include_x5c:
        # per JWS, x5c is base64 DER chain (leaf first)
        header["x5c"] = [_b64url_encode(c).replace("-", "+").replace("_", "/") for c in include_x5c]  # keep as base64 (not url) if needed by consumers

    signing_input = _b64url_encode(_json_dumps(header)) + "." + _b64url_encode(_json_dumps(claims))
    sig = _sign(alg, private_key, signing_input.encode("ascii"))
    token = signing_input + "." + _b64url_encode(sig)
    return token

# ==========================
# Verification
# ==========================

def _parse_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes, bytes]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise SignatureError("invalid token format")
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise SignatureError(f"invalid token JSON: {e}")
    try:
        sig = _b64url_decode(sig_b64)
    except Exception as e:
        raise SignatureError(f"invalid signature encoding: {e}")
    return header, payload, (header_b64 + "." + payload_b64).encode("ascii"), sig

def _resolve_key(header: Dict[str, Any], jwks: Optional[Dict[str, Any]], opts: VerificationOptions):
    kid = header.get("kid")
    alg = header.get("alg")
    if opts.key_resolver:
        return opts.key_resolver(kid, alg)
    if jwks:
        if kid and kid in jwks:
            return jwks[kid]["key"]
        # fallback single
        single = jwks.get("_single")
        if single:
            return single["key"]
    raise SignatureError("unable to resolve verification key")

def _extract_thumbprint_from_cnf(payload: Dict[str, Any]) -> str:
    cnf = payload.get("cnf")
    if not isinstance(cnf, dict):
        raise TokenBindingError("cnf claim missing")
    val = cnf.get("x5t#S256")
    if not isinstance(val, str):
        raise TokenBindingError("cnf.x5t#S256 missing")
    return val

def verify_bound_access_token(
    token: str,
    cert_der: bytes,
    *,
    jwks: Optional[Dict[str, Any]] = None,        # mapping kid->{"alg","key"}, from load_jwks()
    options: Optional[VerificationOptions] = None
) -> Dict[str, Any]:
    """
    Verify signature, temporal claims and certificate binding (cnf.x5t#S256).
    Returns payload claims dict on success, otherwise raises.
    """
    if options is None:
        options = VerificationOptions()

    header, payload, signing_input, sig = _parse_jwt(token)

    alg = header.get("alg")
    if alg not in SUPPORTED_ALGS:
        raise SignatureError(f"unsupported alg {alg}")

    pubkey = _resolve_key(header, jwks, options)
    try:
        _verify(alg, pubkey, signing_input, sig)
    except Exception as e:
        raise SignatureError(f"signature verification failed: {e}")

    # time validation
    now = _now()
    skew = max(0, int(options.clock_skew_sec))
    exp = int(payload.get("exp", 0))
    nbf = int(payload.get("nbf", 0)) if "nbf" in payload else None
    iat = int(payload.get("iat", 0)) if "iat" in payload else None
    if exp and now > exp + skew:
        raise ClaimsError("token expired")
    if nbf is not None and now + skew < nbf:
        raise ClaimsError("token not yet valid")
    if iat and iat - skew > now:
        raise ClaimsError("issued in the future")

    # iss/aud
    if options.issuer and payload.get("iss") != options.issuer:
        raise ClaimsError("issuer mismatch")
    if options.audience:
        aud = payload.get("aud")
        if isinstance(aud, list):
            if options.audience not in aud:
                raise ClaimsError("audience mismatch")
        elif isinstance(aud, str):
            if aud != options.audience:
                raise ClaimsError("audience mismatch")
        else:
            raise ClaimsError("aud claim missing")

    # scope
    if options.require_scope:
        scope = payload.get("scope", "")
        have = set(scope.split())
        need = set(options.require_scope)
        if not need.issubset(have):
            raise ClaimsError("insufficient scope")

    # binding
    expected = cert_thumbprint_sha256(cert_der)
    actual = _extract_thumbprint_from_cnf(payload)
    if not _consteq(expected, actual):
        raise TokenBindingError("certificate thumbprint mismatch")

    return payload

# ==========================
# Convenience loaders
# ==========================

def load_leaf_cert_der_from_pem(pem: str) -> bytes:
    """
    Load first certificate from PEM bundle and return DER.
    """
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    return cert.public_bytes(serialization.Encoding.DER)

def load_private_key_pem(pem: str, password: Optional[bytes] = None):
    return load_pem_private_key(pem.encode("utf-8"), password=password)

def load_public_key_pem(pem: str):
    return load_pem_public_key(pem.encode("utf-8"))

# ==========================
# Minimal self-test (optional)
# ==========================

if __name__ == "__main__":
    # Generate a quick Ed25519 key for demo
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    # Fake leaf certificate DER (use any real DER for real test)
    # Here we create a self-signed minimal cert for demo.
    from datetime import datetime, timedelta
    from cryptography.x509.oid import NameOID
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo")]))
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=1))
    )
    cert = builder.sign(private_key=priv, algorithm=None)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    jwks_map = {"_single": {"alg": "EdDSA", "key": pub}}

    tok = issue_bound_access_token(
        private_key=priv,
        alg="EdDSA",
        subject="user-123",
        audience="api://resource",
        issuer="https://issuer.example",
        cert_der=cert_der,
        scope="read write",
        lifetime_sec=300,
    )
    print("TOKEN:", tok)

    payload = verify_bound_access_token(
        tok, cert_der, jwks=jwks_map, options=VerificationOptions(audience="api://resource", issuer="https://issuer.example", require_scope=["read"])
    )
    print("PAYLOAD OK:", payload)
