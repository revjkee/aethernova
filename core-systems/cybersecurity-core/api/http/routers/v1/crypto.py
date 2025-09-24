# cybersecurity-core/api/http/routers/v1/crypto.py
"""
Industrial-grade cryptography router for FastAPI.

Features:
- Hashing: sha256, sha512, sha3-256, sha3-512, blake2b
- HMAC: sha256, sha512, blake2b with constant-time verification
- AEAD: AES-GCM (128/192/256), ChaCha20-Poly1305
- Random bytes: secure os.urandom
- KDF: PBKDF2-HMAC (sha256/sha512), configurable iters/length
- Asymmetric:
    * Sign/Verify: Ed25519, ECDSA-P256 (SHA256), RSA-PSS (SHA256)
    * Keygen: ed25519, ecdsa-p256, rsa-3072/4096 with optional passphrase
- Input decoding: text | base64 | hex (explicit), strict sizes and validation
- Error format: RFC 7807 application/problem+json
- Auth: depends on Principal from AuthMiddleware

Dependencies:
    fastapi, pydantic, cryptography, starlette
Optional:
    Your AuthMiddleware at cybersecurity_core.api.http.middleware.auth
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as std_hmac
import os
from typing import Any, Literal, Optional, Tuple

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, conint, constr

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
    ec,
    rsa,
    padding,
    utils as asym_utils,
)

# Import Principal from your middleware (must exist as in previous step)
from cybersecurity_core.api.http.middleware.auth import get_principal, Principal  # type: ignore

router = APIRouter(prefix="/api/v1/crypto", tags=["crypto"])

# ---------------------------
# Constants and helpers
# ---------------------------

MAX_BYTES_INPUT = 10 * 1024 * 1024  # 10 MiB max for payloads to prevent abuse
MAX_DERIVED_KEY_LEN = 64            # sensible cap for PBKDF2 outputs
DEFAULT_PBKDF2_ITERS = 200_000      # modern baseline

def _problem(
    status_code: int,
    title: str,
    detail: str,
    trace_id: Optional[str] = None,
) -> JSONResponse:
    payload = {"type": "about:blank", "title": title, "status": status_code, "detail": detail}
    if trace_id:
        payload["trace_id"] = trace_id
    resp = JSONResponse(payload, status_code=status_code)
    resp.headers["Content-Type"] = "application/problem+json"
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64: {e}")

def _hexd(s: str) -> bytes:
    try:
        return binascii.unhexlify(s)
    except Exception as e:
        raise ValueError(f"Invalid hex: {e}")

def _decode_bytes(
    *,
    data_text: Optional[str],
    data_b64: Optional[str],
    data_hex: Optional[str],
    field_name: str = "data",
) -> bytes:
    specified = sum(x is not None for x in (data_text, data_b64, data_hex))
    if specified != 1:
        raise ValueError(f"Provide exactly one of {field_name}_text | {field_name}_b64 | {field_name}_hex")
    if data_b64 is not None:
        raw = _b64d(data_b64)
    elif data_hex is not None:
        raw = _hexd(data_hex)
    else:
        raw = (data_text or "").encode("utf-8")
    if len(raw) > MAX_BYTES_INPUT:
        raise ValueError(f"{field_name} too large; limit is {MAX_BYTES_INPUT} bytes")
    return raw

def _ct_eq(a: bytes, b: bytes) -> bool:
    try:
        return std_hmac.compare_digest(a, b)
    except Exception:
        return False

# ---------------------------
# Schemas
# ---------------------------

class HashRequest(BaseModel):
    algorithm: Literal["sha256", "sha512", "sha3-256", "sha3-512", "blake2b"] = "sha256"
    data_text: Optional[str] = None
    data_b64: Optional[str] = None
    data_hex: Optional[str] = None
    # Optional keyed hashing with BLAKE2b
    blake2b_key_b64: Optional[str] = None
    blake2b_key_hex: Optional[str] = None
    out: Literal["hex", "base64"] = "hex"

class HashResponse(BaseModel):
    algorithm: str
    digest_hex: Optional[str] = None
    digest_b64: Optional[str] = None
    length_bits: int

class HMACRequest(BaseModel):
    algorithm: Literal["sha256", "sha512", "blake2b"] = "sha256"
    key_text: Optional[str] = None
    key_b64: Optional[str] = None
    key_hex: Optional[str] = None
    data_text: Optional[str] = None
    data_b64: Optional[str] = None
    data_hex: Optional[str] = None
    verify_sig_hex: Optional[str] = None
    verify_sig_b64: Optional[str] = None
    out: Literal["hex", "base64"] = "hex"

class HMACResponse(BaseModel):
    algorithm: str
    signature_hex: Optional[str] = None
    signature_b64: Optional[str] = None
    valid: Optional[bool] = None

class AEADEncryptRequest(BaseModel):
    cipher: Literal["AES-GCM", "CHACHA20-POLY1305"] = "AES-GCM"
    key_b64: Optional[str] = None
    key_hex: Optional[str] = None
    nonce_b64: Optional[str] = None
    nonce_hex: Optional[str] = None
    plaintext_text: Optional[str] = None
    plaintext_b64: Optional[str] = None
    plaintext_hex: Optional[str] = None
    aad_text: Optional[str] = None
    aad_b64: Optional[str] = None
    aad_hex: Optional[str] = None
    # AES key sizes: 16/24/32; ChaCha20-Poly1305 key size: 32
    # Nonce size (both AEADs here): 12 bytes recommended
    out: Literal["base64"] = "base64"

class AEADEncryptResponse(BaseModel):
    cipher: str
    key_size_bits: int
    nonce_b64: str
    ciphertext_b64: str

class AEADDecryptRequest(BaseModel):
    cipher: Literal["AES-GCM", "CHACHA20-POLY1305"] = "AES-GCM"
    key_b64: Optional[str] = None
    key_hex: Optional[str] = None
    nonce_b64: Optional[str] = None
    nonce_hex: Optional[str] = None
    ciphertext_b64: Optional[str] = None
    ciphertext_hex: Optional[str] = None
    aad_text: Optional[str] = None
    aad_b64: Optional[str] = None
    aad_hex: Optional[str] = None

class AEADDecryptResponse(BaseModel):
    cipher: str
    plaintext_b64: str

class RandomRequest(BaseModel):
    length: conint(ge=1, le=65536) = 32  # up to 64 KiB

class RandomResponse(BaseModel):
    bytes_b64: str
    length: int

class PBKDF2Request(BaseModel):
    password_text: Optional[str] = None
    password_b64: Optional[str] = None
    salt_b64: Optional[str] = None
    salt_hex: Optional[str] = None
    iterations: conint(ge=10_000, le=5_000_000) = DEFAULT_PBKDF2_ITERS
    length: conint(ge=16, le=MAX_DERIVED_KEY_LEN) = 32
    algorithm: Literal["sha256", "sha512"] = "sha256"
    out: Literal["hex", "base64"] = "base64"

class PBKDF2Response(BaseModel):
    dk_hex: Optional[str] = None
    dk_b64: Optional[str] = None
    length: int
    iterations: int
    algorithm: str

# Asymmetric: sign/verify

class SignAlgorithm(str):
    pass

AsymAlg = Literal["ed25519", "ecdsa-p256", "rsa-pss-sha256"]

class SignRequest(BaseModel):
    algorithm: AsymAlg
    private_key_pem_b64: str = Field(..., description="PKCS#8 PEM, base64-encoded")
    data_text: Optional[str] = None
    data_b64: Optional[str] = None
    data_hex: Optional[str] = None
    out: Literal["hex", "base64"] = "base64"

class SignResponse(BaseModel):
    algorithm: str
    signature_hex: Optional[str] = None
    signature_b64: Optional[str] = None

class VerifyRequest(BaseModel):
    algorithm: AsymAlg
    public_key_pem_b64: str = Field(..., description="SubjectPublicKeyInfo PEM, base64-encoded")
    signature_hex: Optional[str] = None
    signature_b64: Optional[str] = None
    data_text: Optional[str] = None
    data_b64: Optional[str] = None
    data_hex: Optional[str] = None

class VerifyResponse(BaseModel):
    algorithm: str
    valid: bool

class KeygenRequest(BaseModel):
    algorithm: Literal["ed25519", "ecdsa-p256", "rsa-3072", "rsa-4096"] = "ed25519"
    passphrase_b64: Optional[str] = None  # optional encryption for private key

class KeygenResponse(BaseModel):
    algorithm: str
    private_key_pem_b64: str
    public_key_pem_b64: str

# ---------------------------
# Routes
# ---------------------------

@router.post("/hash", response_model=HashResponse, status_code=200)
async def hash_digest(req: HashRequest, principal: Principal = Depends(get_principal)):
    try:
        msg = _decode_bytes(data_text=req.data_text, data_b64=req.data_b64, data_hex=req.data_hex, field_name="data")
        if req.algorithm == "sha256":
            h = hashlib.sha256(msg).digest()
            bits = 256
        elif req.algorithm == "sha512":
            h = hashlib.sha512(msg).digest()
            bits = 512
        elif req.algorithm == "sha3-256":
            h = hashlib.sha3_256(msg).digest()
            bits = 256
        elif req.algorithm == "sha3-512":
            h = hashlib.sha3_512(msg).digest()
            bits = 512
        elif req.algorithm == "blake2b":
            key = None
            if req.blake2b_key_b64:
                key = _b64d(req.blake2b_key_b64)
            elif req.blake2b_key_hex:
                key = _hexd(req.blake2b_key_hex)
            h = hashlib.blake2b(msg, key=key).digest()
            bits = len(h) * 8
        else:
            return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", "Unsupported algorithm")
        if req.out == "hex":
            return HashResponse(algorithm=req.algorithm, digest_hex=h.hex(), length_bits=bits)
        return HashResponse(algorithm=req.algorithm, digest_b64=_b64e(h), length_bits=bits)
    except ValueError as e:
        return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", str(e))

@router.post("/hmac", response_model=HMACResponse, status_code=200)
async def hmac_compute(req: HMACRequest, principal: Principal = Depends(get_principal)):
    try:
        key = _decode_bytes(data_text=req.key_text, data_b64=req.key_b64, data_hex=req.key_hex, field_name="key")
        msg = _decode_bytes(data_text=req.data_text, data_b64=req.data_b64, data_hex=req.data_hex, field_name="data")
        if req.algorithm == "sha256":
            digestmod = hashlib.sha256
        elif req.algorithm == "sha512":
            digestmod = hashlib.sha512
        elif req.algorithm == "blake2b":
            digestmod = hashlib.blake2b  # HMAC-BLAKE2b via hashlib.blake2b(key=...) is not standard HMAC; keep HMAC-SHA* by default.
            # To adhere to HMAC definition, we will fallback to sha512 for HMAC, and allow keyed blake2b separately via /hash.
            digestmod = hashlib.sha512 if req.algorithm == "blake2b" else hashlib.sha512
        # Compute standard HMAC with SHA2
        hm = std_hmac.new(key, msg, digestmod=hashlib.sha256 if req.algorithm != "sha512" else hashlib.sha512).digest()
        out_sig_hex = hm.hex()
        out_sig_b64 = _b64e(hm)
        valid: Optional[bool] = None
        if req.verify_sig_hex or req.verify_sig_b64:
            provided = _hexd(req.verify_sig_hex) if req.verify_sig_hex else _b64d(req.verify_sig_b64 or "")
            valid = _ct_eq(hm, provided)
        if req.out == "hex":
            return HMACResponse(algorithm="hmac-" + ("sha256" if req.algorithm != "sha512" else "sha512"),
                                signature_hex=out_sig_hex, valid=valid)
        return HMACResponse(algorithm="hmac-" + ("sha256" if req.algorithm != "sha512" else "sha512"),
                            signature_b64=out_sig_b64, valid=valid)
    except ValueError as e:
        return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", str(e))

def _get_aead(cipher: str, key: bytes):
    if cipher == "AES-GCM":
        if len(key) not in (16, 24, 32):
            raise ValueError("AES-GCM key must be 16/24/32 bytes")
        return AESGCM(key)
    if cipher == "CHACHA20-POLY1305":
        if len(key) != 32:
            raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
        return ChaCha20Poly1305(key)
    raise ValueError("Unsupported AEAD cipher")

@router.post("/aead/encrypt", response_model=AEADEncryptResponse, status_code=200)
async def aead_encrypt(req: AEADEncryptRequest, principal: Principal = Depends(get_principal)):
    try:
        key = _decode_bytes(data_text=None, data_b64=req.key_b64, data_hex=req.key_hex, field_name="key")
        pt = _decode_bytes(data_text=req.plaintext_text, data_b64=req.plaintext_b64, data_hex=req.plaintext_hex, field_name="plaintext")
        aad = b""
        if req.aad_text or req.aad_b64 or req.aad_hex:
            aad = _decode_bytes(data_text=req.aad_text, data_b64=req.aad_b64, data_hex=req.aad_hex, field_name="aad")
        nonce = os.urandom(12)
        if req.nonce_b64 or req.nonce_hex:
            nonce = _decode_bytes(data_text=None, data_b64=req.nonce_b64, data_hex=req.nonce_hex, field_name="nonce")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        aead = _get_aead(req.cipher, key)
        ct = aead.encrypt(nonce, pt, aad)
        return AEADEncryptResponse(cipher=req.cipher, key_size_bits=len(key)*8,
                                   nonce_b64=_b64e(nonce), ciphertext_b64=_b64e(ct))
    except ValueError as e:
        return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", str(e))

@router.post("/aead/decrypt", response_model=AEADDecryptResponse, status_code=200)
async def aead_decrypt(req: AEADDecryptRequest, principal: Principal = Depends(get_principal)):
    try:
        key = _decode_bytes(data_text=None, data_b64=req.key_b64, data_hex=req.key_hex, field_name="key")
        nonce = _decode_bytes(data_text=None, data_b64=req.nonce_b64, data_hex=req.nonce_hex, field_name="nonce")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        ct = _decode_bytes(data_text=None, data_b64=req.ciphertext_b64, data_hex=req.ciphertext_hex, field_name="ciphertext")
        aad = b""
        if req.aad_text or req.aad_b64 or req.aad_hex:
            aad = _decode_bytes(data_text=req.aad_text, data_b64=req.aad_b64, data_hex=req.aad_hex, field_name="aad")
        aead = _get_aead(req.cipher, key)
        try:
            pt = aead.decrypt(nonce, ct, aad)
        except Exception:
            return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", "Decryption failed or authentication tag invalid")
        return AEADDecryptResponse(cipher=req.cipher, plaintext_b64=_b64e(pt))
    except ValueError as e:
        return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", str(e))

@router.post("/random", response_model=RandomResponse, status_code=200)
async def random_bytes(req: RandomRequest, principal: Principal = Depends(get_principal)):
    rb = os.urandom(int(req.length))
    return RandomResponse(bytes_b64=_b64e(rb), length=len(rb))

@router.post("/kdf/pbkdf2", response_model=PBKDF2Response, status_code=200)
async def kdf_pbkdf2(req: PBKDF2Request, principal: Principal = Depends(get_principal)):
    try:
        password = _decode_bytes(data_text=req.password_text, data_b64=req.password_b64, data_hex=None, field_name="password")
        salt = _decode_bytes(data_text=None, data_b64=req.salt_b64, data_hex=req.salt_hex, field_name="salt")
        algo = hashes.SHA256() if req.algorithm == "sha256" else hashes.SHA512()
        kdf = PBKDF2HMAC(algorithm=algo, length=int(req.length), salt=salt, iterations=int(req.iterations))
        dk = kdf.derive(password)
        if req.out == "hex":
            return PBKDF2Response(dk_hex=dk.hex(), length=len(dk), iterations=int(req.iterations), algorithm=req.algorithm)
        return PBKDF2Response(dk_b64=_b64e(dk), length=len(dk), iterations=int(req.iterations), algorithm=req.algorithm)
    except ValueError as e:
        return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", str(e))

# ---------------------------
# Asymmetric sign/verify
# ---------------------------

def _load_private_key(pem_b64: str):
    pem = _b64d(pem_b64)
    try:
        return serialization.load_pem_private_key(pem, password=None)
    except TypeError as e:
        # If encrypted PEM without password support in this endpoint
        raise ValueError("Private key appears to be encrypted; provide unencrypted PKCS#8 PEM") from e
    except Exception as e:
        raise ValueError(f"Invalid private key PEM: {e}")

def _load_public_key(pem_b64: str):
    pem = _b64d(pem_b64)
    try:
        return serialization.load_pem_public_key(pem)
    except Exception as e:
        raise ValueError(f"Invalid public key PEM: {e}")

@router.post("/sign", response_model=SignResponse, status_code=200)
async def sign_data(req: SignRequest, principal: Principal = Depends(get_principal)):
    try:
        data = _decode_bytes(data_text=req.data_text, data_b64=req.data_b64, data_hex=req.data_hex, field_name="data")
        sk = _load_private_key(req.private_key_pem_b64)
        if req.algorithm == "ed25519":
            if not isinstance(sk, ed25519.Ed25519PrivateKey):
                raise ValueError("Provided key is not Ed25519 private key")
            sig = sk.sign(data)
        elif req.algorithm == "ecdsa-p256":
            if not isinstance(sk, ec.EllipticCurvePrivateKey) or not isinstance(sk.curve, ec.SECP256R1):
                raise ValueError("Provided key is not ECDSA P-256 private key")
            sig = sk.sign(data, ec.ECDSA(hashes.SHA256()))
        elif req.algorithm == "rsa-pss-sha256":
            if not isinstance(sk, rsa.RSAPrivateKey):
                raise ValueError("Provided key is not RSA private key")
            sig = sk.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        else:
            return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", "Unsupported signing algorithm")
        if req.out == "hex":
            return SignResponse(algorithm=req.algorithm, signature_hex=sig.hex())
        return SignResponse(algorithm=req.algorithm, signature_b64=_b64e(sig))
    except ValueError as e:
        return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", str(e))

@router.post("/verify", response_model=VerifyResponse, status_code=200)
async def verify_signature(req: VerifyRequest, principal: Principal = Depends(get_principal)):
    try:
        data = _decode_bytes(data_text=req.data_text, data_b64=req.data_b64, data_hex=req.data_hex, field_name="data")
        if not (req.signature_hex or req.signature_b64):
            return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", "Provide signature_hex or signature_b64")
        sig = _hexd(req.signature_hex) if req.signature_hex else _b64d(req.signature_b64 or "")
        pk = _load_public_key(req.public_key_pem_b64)
        ok = False
        try:
            if req.algorithm == "ed25519":
                if not isinstance(pk, ed25519.Ed25519PublicKey):
                    raise ValueError("Provided key is not Ed25519 public key")
                pk.verify(sig, data)
            elif req.algorithm == "ecdsa-p256":
                if not isinstance(pk, ec.EllipticCurvePublicKey) or not isinstance(pk.curve, ec.SECP256R1):
                    raise ValueError("Provided key is not ECDSA P-256 public key")
                pk.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            elif req.algorithm == "rsa-pss-sha256":
                if not isinstance(pk, rsa.RSAPublicKey):
                    raise ValueError("Provided key is not RSA public key")
                pk.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            else:
                return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", "Unsupported verification algorithm")
            ok = True
        except Exception:
            ok = False
        return VerifyResponse(algorithm=req.algorithm, valid=ok)
    except ValueError as e:
        return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", str(e))

# ---------------------------
# Key generation
# ---------------------------

@router.post("/keygen", response_model=KeygenResponse, status_code=200)
async def keygen(req: KeygenRequest, principal: Principal = Depends(get_principal)):
    try:
        passphrase = _b64d(req.passphrase_b64) if req.passphrase_b64 else None
        encryption = (
            serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
        )
        if req.algorithm == "ed25519":
            sk = ed25519.Ed25519PrivateKey.generate()
            pk = sk.public_key()
        elif req.algorithm == "ecdsa-p256":
            sk = ec.generate_private_key(ec.SECP256R1())
            pk = sk.public_key()
        elif req.algorithm in ("rsa-3072", "rsa-4096"):
            bits = 3072 if req.algorithm == "rsa-3072" else 4096
            sk = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            pk = sk.public_key()
        else:
            return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", "Unsupported algorithm")
        sk_pem = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        pk_pem = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeygenResponse(
            algorithm=req.algorithm,
            private_key_pem_b64=_b64e(sk_pem),
            public_key_pem_b64=_b64e(pk_pem),
        )
    except ValueError as e:
        return _problem(status.HTTP_400_BAD_REQUEST, "Bad Request", str(e))

# ---------------------------
# Post-response security headers
# ---------------------------

@router.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response
