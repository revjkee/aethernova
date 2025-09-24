# cybersecurity-core/cybersecurity/crypto/signatures.py
from __future__ import annotations

import base64
import dataclasses
import hmac
import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Union, Iterable, List

try:
    # cryptography is a de-facto standard for industrial crypto in Python
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PrivateFormat,
        PublicFormat,
        BestAvailableEncryption,
        NoEncryption,
    )
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding, utils as asym_utils
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except Exception:  # pragma: no cover
    HAS_CRYPTO = False

logger = logging.getLogger(__name__)

__all__ = [
    "SignatureError",
    "UnsupportedAlgorithm",
    "KeyFormatError",
    "SignatureAlg",
    "SignEnvelope",
    "kid_from_public_key",
    "generate_ed25519_key",
    "generate_rsa_key",
    "generate_ec_key",
    "load_private_key_pem",
    "load_public_key_pem",
    "load_key_jwk",
    "dump_public_jwk",
    "dump_private_jwk",
    "sign_detached",
    "verify_detached",
    "sign_envelope",
    "verify_envelope",
    "StreamSigner",
    "StreamVerifier",
]


# ============================== Errors =======================================

class SignatureError(Exception):
    pass


class UnsupportedAlgorithm(SignatureError):
    pass


class KeyFormatError(SignatureError):
    pass


# ============================== Helpers ======================================

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_dec(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


class SignatureAlg(str, Enum):
    ED25519 = "ed25519"
    ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
    ECDSA_P384_SHA384 = "ecdsa-p384-sha384"
    RSA_PSS_SHA256 = "rsa-pss-sha256"
    RSA_PSS_SHA384 = "rsa-pss-sha384"
    RSA_PSS_SHA512 = "rsa-pss-sha512"


def _hash_for_alg(alg: SignatureAlg):
    if alg in (SignatureAlg.ED25519,):
        return None
    if alg == SignatureAlg.ECDSA_P256_SHA256 or alg == SignatureAlg.RSA_PSS_SHA256:
        return hashes.SHA256()
    if alg == SignatureAlg.ECDSA_P384_SHA384 or alg == SignatureAlg.RSA_PSS_SHA384:
        return hashes.SHA384()
    if alg == SignatureAlg.RSA_PSS_SHA512:
        return hashes.SHA512()
    raise UnsupportedAlgorithm(f"Unsupported hash for {alg}")


def _ctx_domain_separate(payload: bytes, ctx: Optional[str]) -> bytes:
    """
    Domain separation to prevent cross-protocol signature re-use.
    Format: b"SIGCTX\\0" + ctx + b"\\0" + payload
    """
    if not ctx:
        return payload
    if not isinstance(ctx, str):
        raise SignatureError("Context must be a string")
    return b"SIGCTX\x00" + ctx.encode("utf-8") + b"\x00" + payload


def _is_ed25519_key(priv_or_pub) -> bool:
    return HAS_CRYPTO and isinstance(priv_or_pub, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey))


def _is_ec_key(priv_or_pub) -> bool:
    return HAS_CRYPTO and isinstance(priv_or_pub, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey))


def _is_rsa_key(priv_or_pub) -> bool:
    return HAS_CRYPTO and isinstance(priv_or_pub, (rsa.RSAPrivateKey, rsa.RSAPublicKey))


def _ensure_crypto():
    if not HAS_CRYPTO:
        raise SignatureError("cryptography package is required but not installed")


# ============================== Key Ops ======================================

def generate_ed25519_key():
    _ensure_crypto()
    return ed25519.Ed25519PrivateKey.generate()


def generate_rsa_key(bits: int = 3072, public_exponent: int = 65537):
    _ensure_crypto()
    if bits < 2048:
        raise KeyFormatError("RSA key size must be >= 2048")
    return rsa.generate_private_key(public_exponent=public_exponent, key_size=bits, backend=default_backend())


def generate_ec_key(curve: str = "P-256"):
    _ensure_crypto()
    curve = curve.upper()
    if curve in ("P-256", "SECP256R1"):
        c = ec.SECP256R1()
    elif curve in ("P-384", "SECP384R1"):
        c = ec.SECP384R1()
    else:
        raise KeyFormatError("Supported curves: P-256, P-384")
    return ec.generate_private_key(c, backend=default_backend())


def load_private_key_pem(pem: Union[str, bytes], password: Optional[Union[str, bytes]] = None):
    _ensure_crypto()
    data = pem.encode() if isinstance(pem, str) else pem
    pwd = password.encode() if isinstance(password, str) else password
    try:
        return serialization.load_pem_private_key(data, password=pwd, backend=default_backend())
    except Exception as e:
        raise KeyFormatError(f"Failed to load private key: {e}") from e


def load_public_key_pem(pem: Union[str, bytes]):
    _ensure_crypto()
    data = pem.encode() if isinstance(pem, str) else pem
    try:
        try:
            return serialization.load_pem_public_key(data, backend=default_backend())
        except ValueError:
            # maybe certificate
            cert = serialization.load_pem_x509_certificate(data, backend=default_backend())  # type: ignore[attr-defined]
            return cert.public_key()
    except Exception as e:
        raise KeyFormatError(f"Failed to load public key: {e}") from e


def serialize_private_key_pem(priv, password: Optional[Union[str, bytes]] = None) -> bytes:
    _ensure_crypto()
    if password:
        enc = BestAvailableEncryption(password.encode() if isinstance(password, str) else password)
    else:
        enc = NoEncryption()
    return priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)


def serialize_public_key_pem(pub) -> bytes:
    _ensure_crypto()
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def kid_from_public_key(pub) -> str:
    """
    KID = b64url(SHA-256(SPKI DER)). Truncated KIDs may be used by caller.
    """
    _ensure_crypto()
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(spki)
    return _b64url(digest.finalize())


# ============================== JWK IO =======================================

def load_key_jwk(jwk: Union[str, Dict[str, Any]]):
    """
    Load private or public key from JWK (OKP/EC/RSA).
    """
    _ensure_crypto()
    obj = json.loads(jwk) if isinstance(jwk, str) else jwk
    kty = obj.get("kty")
    if kty == "OKP" and obj.get("crv") == "Ed25519":
        x = _b64url_dec(obj["x"])
        if "d" in obj:
            d = _b64url_dec(obj["d"])
            return ed25519.Ed25519PrivateKey.from_private_bytes(d)
        return ed25519.Ed25519PublicKey.from_public_bytes(x)
    if kty == "EC":
        crv = obj.get("crv")
        if crv == "P-256":
            curve = ec.SECP256R1()
            hash_check = hashes.SHA256()
        elif crv == "P-384":
            curve = ec.SECP384R1()
            hash_check = hashes.SHA384()
        else:
            raise KeyFormatError("Unsupported EC crv; only P-256, P-384")
        x = int.from_bytes(_b64url_dec(obj["x"]), "big")
        y = int.from_bytes(_b64url_dec(obj["y"]), "big")
        pub_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        if "d" in obj:
            d = int.from_bytes(_b64url_dec(obj["d"]), "big")
            priv_numbers = ec.EllipticCurvePrivateNumbers(d, pub_numbers)
            return priv_numbers.private_key(default_backend())
        return pub_numbers.public_key(default_backend())
    if kty == "RSA":
        n = int.from_bytes(_b64url_dec(obj["n"]), "big")
        e = int.from_bytes(_b64url_dec(obj["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n)
        if "d" in obj:
            d = int.from_bytes(_b64url_dec(obj["d"]), "big")
            p = int.from_bytes(_b64url_dec(obj["p"]), "big") if "p" in obj else None
            q = int.from_bytes(_b64url_dec(obj["q"]), "big") if "q" in obj else None
            if p and q:
                dp = int.from_bytes(_b64url_dec(obj["dp"]), "big") if "dp" in obj else None
                dq = int.from_bytes(_b64url_dec(obj["dq"]), "big") if "dq" in obj else None
                qi = int.from_bytes(_b64url_dec(obj["qi"]), "big") if "qi" in obj else None
                priv_nums = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, pub)
                return priv_nums.private_key(default_backend())
            # without CRT params
            return rsa.RSAPrivateNumbers(
                p=0, q=0, d=d, dmp1=0, dmq1=0, iqmp=0, public_numbers=pub
            ).private_key(default_backend())  # type: ignore[arg-type]
        return pub.public_key(default_backend())
    raise KeyFormatError("Unsupported JWK kty")


def dump_public_jwk(pub) -> Dict[str, Any]:
    _ensure_crypto()
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256" if isinstance(nums.curve, ec.SECP256R1) else "P-384",
            "x": _b64url(nums.x.to_bytes((nums.x.bit_length() + 7) // 8, "big")),
            "y": _b64url(nums.y.to_bytes((nums.y.bit_length() + 7) // 8, "big")),
        }
    if isinstance(pub, rsa.RSAPublicKey):
        nums = pub.public_numbers()
        return {
            "kty": "RSA",
            "n": _b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
            "e": _b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")),
        }
    raise KeyFormatError("Unsupported public key type")


def dump_private_jwk(priv) -> Dict[str, Any]:
    _ensure_crypto()
    if isinstance(priv, ed25519.Ed25519PrivateKey):
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "d": _b64url(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            "x": _b64url(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        }
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        nums = priv.private_numbers()
        pub = nums.public_numbers
        return {
            "kty": "EC",
            "crv": "P-256" if isinstance(pub.curve, ec.SECP256R1) else "P-384",
            "d": _b64url(nums.private_value.to_bytes((nums.private_value.bit_length() + 7) // 8, "big")),
            "x": _b64url(pub.x.to_bytes((pub.x.bit_length() + 7) // 8, "big")),
            "y": _b64url(pub.y.to_bytes((pub.y.bit_length() + 7) // 8, "big")),
        }
    if isinstance(priv, rsa.RSAPrivateKey):
        nums = priv.private_numbers()
        pub = nums.public_numbers
        jwk = {
            "kty": "RSA",
            "n": _b64url(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")),
            "e": _b64url(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big")),
            "d": _b64url(nums.d.to_bytes((nums.d.bit_length() + 7) // 8, "big")),
            "p": _b64url(nums.p.to_bytes((nums.p.bit_length() + 7) // 8, "big")),
            "q": _b64url(nums.q.to_bytes((nums.q.bit_length() + 7) // 8, "big")),
            "dp": _b64url(nums.dmp1.to_bytes((nums.dmp1.bit_length() + 7) // 8, "big")),
            "dq": _b64url(nums.dmq1.to_bytes((nums.dmq1.bit_length() + 7) // 8, "big")),
            "qi": _b64url(nums.iqmp.to_bytes((nums.iqmp.bit_length() + 7) // 8, "big")),
        }
        return jwk
    raise KeyFormatError("Unsupported private key type")


# ============================== ECDSA raw/der =================================

def _ecdsa_der_to_raw(sig_der: bytes, key) -> bytes:
    r, s = decode_dss_signature(sig_der)
    size = (key.key_size + 7) // 8
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def _ecdsa_raw_to_der(sig_raw: bytes, key) -> bytes:
    size = (key.key_size + 7) // 8
    if len(sig_raw) != 2 * size:
        raise SignatureError("Invalid ECDSA raw signature length")
    r = int.from_bytes(sig_raw[:size], "big")
    s = int.from_bytes(sig_raw[size:], "big")
    return encode_dss_signature(r, s)


# ============================== Sign/Verify (bytes) ===========================

def sign_detached(private_key, data: bytes, alg: SignatureAlg, *, context: Optional[str] = None, ecdsa_raw: bool = False) -> bytes:
    """
    Detached signature over data (optionally domain-separated with context).
    For ECDSA you can choose raw (r||s) output via ecdsa_raw=True. Default is DER.
    """
    _ensure_crypto()
    msg = _ctx_domain_separate(data, context)

    if alg == SignatureAlg.ED25519:
        if not _is_ed25519_key(private_key):
            raise KeyFormatError("Private key must be Ed25519 for ed25519 alg")
        return private_key.sign(msg)

    if alg in (SignatureAlg.ECDSA_P256_SHA256, SignatureAlg.ECDSA_P384_SHA384):
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise KeyFormatError("Private key must be EC for ECDSA")
        chosen_hash = _hash_for_alg(alg)
        der = private_key.sign(msg, ec.ECDSA(chosen_hash))
        return _ecdsa_der_to_raw(der, private_key.public_key()) if ecdsa_raw else der

    if alg in (SignatureAlg.RSA_PSS_SHA256, SignatureAlg.RSA_PSS_SHA384, SignatureAlg.RSA_PSS_SHA512):
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise KeyFormatError("Private key must be RSA for RSA-PSS")
        chosen_hash = _hash_for_alg(alg)
        return private_key.sign(
            msg,
            padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=padding.PSS.MAX_LENGTH),
            chosen_hash,
        )

    raise UnsupportedAlgorithm(f"Unsupported signing algorithm: {alg}")


def verify_detached(public_key, data: bytes, signature: bytes, alg: SignatureAlg, *, context: Optional[str] = None, ecdsa_raw: bool = False) -> bool:
    _ensure_crypto()
    msg = _ctx_domain_separate(data, context)
    try:
        if alg == SignatureAlg.ED25519:
            if not _is_ed25519_key(public_key):
                raise KeyFormatError("Public key must be Ed25519 for ed25519 alg")
            public_key.verify(signature, msg)
            return True

        if alg in (SignatureAlg.ECDSA_P256_SHA256, SignatureAlg.ECDSA_P384_SHA384):
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise KeyFormatError("Public key must be EC for ECDSA")
            chosen_hash = _hash_for_alg(alg)
            sig_der = _ecdsa_raw_to_der(signature, public_key) if ecdsa_raw else signature
            public_key.verify(sig_der, msg, ec.ECDSA(chosen_hash))
            return True

        if alg in (SignatureAlg.RSA_PSS_SHA256, SignatureAlg.RSA_PSS_SHA384, SignatureAlg.RSA_PSS_SHA512):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise KeyFormatError("Public key must be RSA for RSA-PSS")
            chosen_hash = _hash_for_alg(alg)
            public_key.verify(
                signature,
                msg,
                padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=padding.PSS.MAX_LENGTH),
                chosen_hash,
            )
            return True
    except Exception:
        return False
    raise UnsupportedAlgorithm(f"Unsupported verification algorithm: {alg}")


# ============================== Envelope (JOSE-like) ==========================

@dataclass
class SignEnvelope:
    alg: SignatureAlg
    kid: str
    ts: int
    sig_b64: str
    sig_fmt: str  # "der" | "raw" | "raw64" (ed25519 always raw)
    hash_alg: Optional[str] = None  # "sha256"/"sha384"/"sha512" or None
    payload_hash_b64: Optional[str] = None
    ctx: Optional[str] = None
    meta: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "alg": self.alg.value,
            "kid": self.kid,
            "ts": self.ts,
            "sig": self.sig_b64,
            "sig_fmt": self.sig_fmt,
            "hash": self.hash_alg,
            "payload_hash": self.payload_hash_b64,
            "ctx": self.ctx,
            "meta": self.meta,
        }, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def from_json(s: Union[str, bytes]) -> "SignEnvelope":
        obj = json.loads(s.decode() if isinstance(s, (bytes, bytearray)) else s)
        return SignEnvelope(
            alg=SignatureAlg(obj["alg"]),
            kid=obj["kid"],
            ts=int(obj["ts"]),
            sig_b64=obj["sig"],
            sig_fmt=obj.get("sig_fmt", "der"),
            hash_alg=obj.get("hash"),
            payload_hash_b64=obj.get("payload_hash"),
            ctx=obj.get("ctx"),
            meta=obj.get("meta") or {},
        )


def _compute_hash(data: bytes, name: Optional[str]) -> Optional[bytes]:
    if not name:
        return None
    name = name.lower()
    _ensure_crypto()
    if name == "sha256":
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    elif name == "sha384":
        h = hashes.Hash(hashes.SHA384(), backend=default_backend())
    elif name == "sha512":
        h = hashes.Hash(hashes.SHA512(), backend=default_backend())
    else:
        raise UnsupportedAlgorithm("Supported hashes: sha256, sha384, sha512")
    h.update(data)
    return h.finalize()


def sign_envelope(private_key, payload: bytes, alg: SignatureAlg, *, ctx: Optional[str] = None, include_payload_hash: bool = True, ecdsa_raw: bool = False, kid: Optional[str] = None) -> SignEnvelope:
    """
    Produce a JSON envelope with signature and minimal metadata (kid, ts, ctx).
    """
    _ensure_crypto()
    pub = private_key.public_key()
    kid_val = kid or kid_from_public_key(pub)
    ts = int(time.time())
    # choose hash name for envelope (for integrity of detached payload)
    hash_map = {
        SignatureAlg.ED25519: None,
        SignatureAlg.ECDSA_P256_SHA256: "sha256",
        SignatureAlg.ECDSA_P384_SHA384: "sha384",
        SignatureAlg.RSA_PSS_SHA256: "sha256",
        SignatureAlg.RSA_PSS_SHA384: "sha384",
        SignatureAlg.RSA_PSS_SHA512: "sha512",
    }
    hash_name = hash_map[alg]
    payload_hash_b64 = _b64url(_compute_hash(payload, hash_name)) if (include_payload_hash and hash_name) else None
    sig = sign_detached(private_key, payload, alg, context=ctx, ecdsa_raw=ecdsa_raw)
    sig_b64 = _b64url(sig)
    sig_fmt = "raw" if (ecdsa_raw or alg == SignatureAlg.ED25519) else "der"
    return SignEnvelope(alg=alg, kid=kid_val, ts=ts, sig_b64=sig_b64, sig_fmt=sig_fmt, hash_alg=hash_name, payload_hash_b64=payload_hash_b64, ctx=ctx)


def verify_envelope(public_key, payload: bytes, envelope: Union[SignEnvelope, str, bytes], *, expected_ctx: Optional[str] = None) -> bool:
    """
    Verify envelope and payload. If expected_ctx is provided, it must match envelope.ctx.
    """
    env = SignEnvelope.from_json(envelope) if not isinstance(envelope, SignEnvelope) else envelope

    if expected_ctx is not None:
        # constant-time compare
        a = (env.ctx or "").encode("utf-8")
        b = expected_ctx.encode("utf-8")
        if not hmac.compare_digest(a, b):
            return False

    # optional payload hash check
    if env.payload_hash_b64 and env.hash_alg:
        calc = _compute_hash(payload, env.hash_alg)
        if calc is None:
            return False
        if not hmac.compare_digest(_b64url(calc), env.payload_hash_b64):
            return False

    sig = _b64url_dec(env.sig_b64)
    ecdsa_raw = (env.sig_fmt == "raw")
    try:
        return verify_detached(public_key, payload, sig, env.alg, context=env.ctx, ecdsa_raw=ecdsa_raw)
    except UnsupportedAlgorithm:
        return False


# ============================== Streaming (RSA/ECDSA) =========================

class _HashCtx:
    def __init__(self, name: str):
        _ensure_crypto()
        if name == "sha256":
            self._h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        elif name == "sha384":
            self._h = hashes.Hash(hashes.SHA384(), backend=default_backend())
        elif name == "sha512":
            self._h = hashes.Hash(hashes.SHA512(), backend=default_backend())
        else:
            raise UnsupportedAlgorithm("Only sha256/384/512 are supported for stream mode")
        self.name = name

    def update(self, b: bytes):
        self._h.update(b)

    def finalize(self) -> bytes:
        return self._h.finalize()


class StreamSigner:
    """
    Stream signing for RSA-PSS and ECDSA (hash-then-sign).
    Ed25519 streaming is not supported here (use sign_detached on full bytes).
    """
    def __init__(self, private_key, alg: SignatureAlg, *, ctx: Optional[str] = None, ecdsa_raw: bool = False):
        if alg == SignatureAlg.ED25519:
            raise UnsupportedAlgorithm("Use non-stream sign for Ed25519")
        self.private_key = private_key
        self.alg = alg
        self.ctx = ctx
        self.ecdsa_raw = ecdsa_raw
        self.hash_name = {
            SignatureAlg.ECDSA_P256_SHA256: "sha256",
            SignatureAlg.ECDSA_P384_SHA384: "sha384",
            SignatureAlg.RSA_PSS_SHA256: "sha256",
            SignatureAlg.RSA_PSS_SHA384: "sha384",
            SignatureAlg.RSA_PSS_SHA512: "sha512",
        }[alg]
        self._h = _HashCtx(self.hash_name)
        # include domain separation into hash
        if ctx:
            self._h.update(b"SIGCTX\x00" + ctx.encode("utf-8") + b"\x00")

    def update(self, chunk: bytes):
        self._h.update(chunk)

    def finalize(self) -> bytes:
        digest = self._h.finalize()
        # Sign the prehashed message for RSA/ECDSA
        if self.alg in (SignatureAlg.RSA_PSS_SHA256, SignatureAlg.RSA_PSS_SHA384, SignatureAlg.RSA_PSS_SHA512):
            chosen_hash = _hash_for_alg(self.alg)
            return self.private_key.sign(
                digest,
                padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=padding.PSS.MAX_LENGTH),
                chosen_hash,
            )
        if self.alg in (SignatureAlg.ECDSA_P256_SHA256, SignatureAlg.ECDSA_P384_SHA384):
            chosen_hash = _hash_for_alg(self.alg)
            der = self.private_key.sign(digest, ec.ECDSA(asym_utils.Prehashed(chosen_hash)))
            return _ecdsa_der_to_raw(der, self.private_key.public_key()) if self.ecdsa_raw else der
        raise UnsupportedAlgorithm("Unsupported algorithm for streaming")


class StreamVerifier:
    """
    Stream verification for RSA-PSS and ECDSA (hash-then-verify).
    """
    def __init__(self, public_key, alg: SignatureAlg, *, ctx: Optional[str] = None, ecdsa_raw: bool = False):
        if alg == SignatureAlg.ED25519:
            raise UnsupportedAlgorithm("Use non-stream verify for Ed25519")
        self.public_key = public_key
        self.alg = alg
        self.ctx = ctx
        self.ecdsa_raw = ecdsa_raw
        self.hash_name = {
            SignatureAlg.ECDSA_P256_SHA256: "sha256",
            SignatureAlg.ECDSA_P384_SHA384: "sha384",
            SignatureAlg.RSA_PSS_SHA256: "sha256",
            SignatureAlg.RSA_PSS_SHA384: "sha384",
            SignatureAlg.RSA_PSS_SHA512: "sha512",
        }[alg]
        self._h = _HashCtx(self.hash_name)
        if ctx:
            self._h.update(b"SIGCTX\x00" + ctx.encode("utf-8") + b"\x00")

    def update(self, chunk: bytes):
        self._h.update(chunk)

    def finalize(self, signature: bytes) -> bool:
        digest = self._h.finalize()
        try:
            if self.alg in (SignatureAlg.RSA_PSS_SHA256, SignatureAlg.RSA_PSS_SHA384, SignatureAlg.RSA_PSS_SHA512):
                chosen_hash = _hash_for_alg(self.alg)
                self.public_key.verify(
                    signature,
                    digest,
                    padding.PSS(mgf=padding.MGF1(chosen_hash), salt_length=padding.PSS.MAX_LENGTH),
                    chosen_hash,
                )
                return True
            if self.alg in (SignatureAlg.ECDSA_P256_SHA256, SignatureAlg.ECDSA_P384_SHA384):
                chosen_hash = _hash_for_alg(self.alg)
                sig_der = _ecdsa_raw_to_der(signature, self.public_key) if self.ecdsa_raw else signature
                self.public_key.verify(sig_der, digest, ec.ECDSA(asym_utils.Prehashed(chosen_hash)))
                return True
        except Exception:
            return False
        raise UnsupportedAlgorithm("Unsupported algorithm for streaming verify")
