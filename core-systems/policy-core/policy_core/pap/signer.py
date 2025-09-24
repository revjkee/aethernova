# policy_core/pap/signer.py
from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import pathlib
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Protocol, Tuple, Union, List, Literal

try:
    from pydantic import BaseModel, Field, validator
except Exception as e:  # pragma: no cover
    raise ImportError("pydantic is required for policy_core.pap.signer") from e

# cryptography is optional per backend; import guardedly inside backends
# to avoid forcing all deps for all runners.

LOGGER = logging.getLogger("policy_core.pap.signer")
DEFAULT_DIGEST_ALG = "SHA256"
SUPPORTED_DIGESTS = {"SHA256", "BLAKE2B-256"}

ENVELOPE_VERSION = "1.1"

# =========================
# Utilities
# =========================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _canon_json(obj: Any) -> bytes:
    """
    Canonical JSON for signing: UTF-8, sorted keys, no spaces.
    """
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

def _now_ts() -> int:
    return int(time.time())

def _constant_time_str_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def _hash_bytes(data: bytes, alg: str) -> bytes:
    alg = alg.upper()
    if alg == "SHA256":
        return hashlib.sha256(data).digest()
    elif alg == "BLAKE2B-256":
        return hashlib.blake2b(data, digest_size=32).digest()
    raise ValueError(f"Unsupported digest alg: {alg}")

# =========================
# Exceptions
# =========================

class SignerError(Exception):
    pass

class SignerConfigError(SignerError):
    pass

class VerificationError(SignerError):
    pass

class BackendNotAvailableError(SignerError):
    pass

# =========================
# Envelope
# =========================

@dataclasses.dataclass(frozen=True)
class SignatureEnvelope:
    """
    JSON envelope for detached signatures of policy artifacts.

    Fields:
      - version: envelope schema version
      - alg: algorithm identifier ("ED25519", "RSASSA-PSS-SHA256", "GPG")
      - kid: key identifier (fingerprint/base64url of pubkey fingerprint)
      - ts: unix timestamp of signature creation
      - digest_alg: name of hash function over payload
      - digest: base64url digest(payload)
      - sig: base64url of signature over canonical "to_sign" object
      - ctx: optional signing context/domain separation string
      - chain: optional X.509 certificate chain (PEM) for RSA
      - meta: optional metadata dict (key usage, policy id, etc.)
    """
    version: str
    alg: str
    kid: str
    ts: int
    digest_alg: str
    digest: str
    sig: str
    ctx: Optional[str] = None
    chain: Optional[List[str]] = None
    meta: Optional[Dict[str, Any]] = None

    def to_json_bytes(self) -> bytes:
        return _canon_json(dataclasses.asdict(self))

    @staticmethod
    def from_json_bytes(b: bytes) -> "SignatureEnvelope":
        try:
            d = json.loads(b.decode("utf-8"))
            return SignatureEnvelope(
                version=d["version"],
                alg=d["alg"],
                kid=d["kid"],
                ts=int(d["ts"]),
                digest_alg=d["digest_alg"],
                digest=d["digest"],
                sig=d["sig"],
                ctx=d.get("ctx"),
                chain=d.get("chain"),
                meta=d.get("meta"),
            )
        except Exception as e:
            raise VerificationError(f"Invalid envelope JSON: {e}") from e


# =========================
# Config
# =========================

class SignerType:
    ED25519 = "ed25519"
    RSA_PSS = "rsa-pss"
    GPG = "gpg"

class SignerConfig(BaseModel):
    """
    Generic signer configuration. Only the relevant fields for a given type must be provided.
    """
    type: Literal["ed25519", "rsa-pss", "gpg"] = Field(..., description="Signer backend type")
    # Common
    key_id: Optional[str] = Field(None, description="Override computed KID if provided")
    digest_alg: Literal["SHA256", "BLAKE2B-256"] = Field(DEFAULT_DIGEST_ALG, description="Digest for payload")
    context: Optional[str] = Field(None, description="Optional signing context string")
    meta: Optional[Dict[str, Any]] = Field(default=None, description="Arbitrary metadata to embed in envelope")

    # ED25519 / RSA
    private_key_path: Optional[str] = Field(None, description="Path to PEM private key")
    private_key_pass_env: Optional[str] = Field(None, description="ENV var name holding passphrase for private key")
    public_cert_path: Optional[str] = Field(None, description="Path to PEM cert (RSA)")
    chain_paths: Optional[List[str]] = Field(None, description="Optional cert chain (PEM) for RSA")

    # GPG
    gpg_key_id: Optional[str] = Field(None, description="GPG key id / fingerprint")
    gpg_binary: Optional[str] = Field(default="gpg", description="Path to gpg binary")
    gpg_homedir: Optional[str] = Field(default=None, description="GPG home directory")

    @validator("private_key_path", "public_cert_path", "gpg_binary", "gpg_homedir", pre=True, always=True)
    def _expanduser(cls, v):
        if v is None:
            return v
        return os.path.expanduser(str(v))

# =========================
# Key ID helpers
# =========================

def _kid_from_bytes(pubkey_bytes: bytes) -> str:
    """
    Compute a stable KID (key identifier) from public-key bytes: KID = b64u(SHA256(pubkey_bytes)).
    """
    return _b64u(hashlib.sha256(pubkey_bytes).digest())

# =========================
# Abstract Signer
# =========================

class BaseSigner(ABC):
    """
    Abstract signer. Implementations must sign the canonical "to_sign" structure.
    """

    def __init__(self, cfg: SignerConfig):
        self.cfg = cfg

    @property
    @abstractmethod
    def alg(self) -> str:
        ...

    @property
    @abstractmethod
    def kid(self) -> str:
        ...

    @abstractmethod
    def _sign_raw(self, message: bytes) -> bytes:
        """
        Backend-specific raw signing of message bytes.
        """
        ...

    @abstractmethod
    def _verify_raw(self, message: bytes, signature: bytes) -> None:
        """
        Backend-specific verify. Raise VerificationError on failure.
        """
        ...

    def _to_sign(self, payload_digest_b64u: str, ts: int) -> Dict[str, Any]:
        """
        Canonical object to sign. The signature is computed over canon_json(this object).
        """
        obj = {
            "version": ENVELOPE_VERSION,
            "alg": self.alg,
            "kid": self.kid,
            "ts": ts,
            "digest_alg": self.cfg.digest_alg,
            "digest": payload_digest_b64u,
        }
        if self.cfg.context:
            obj["ctx"] = self.cfg.context
        return obj

    def sign(self, payload: bytes) -> SignatureEnvelope:
        """
        Synchronous signing path.
        """
        digest_bytes = _hash_bytes(payload, self.cfg.digest_alg)
        digest_b64u = _b64u(digest_bytes)
        ts = _now_ts()

        to_sign_obj = self._to_sign(digest_b64u, ts)
        message = _canon_json(to_sign_obj)
        signature = self._sign_raw(message)

        chain: Optional[List[str]] = None
        if hasattr(self, "_chain_pems"):
            chain = getattr(self, "_chain_pems")  # type: ignore

        env = SignatureEnvelope(
            version=ENVELOPE_VERSION,
            alg=self.alg,
            kid=self.kid,
            ts=ts,
            digest_alg=self.cfg.digest_alg,
            digest=digest_b64u,
            sig=_b64u(signature),
            ctx=self.cfg.context,
            chain=chain,
            meta=self.cfg.meta,
        )
        LOGGER.info(
            "policy-sign: signed",
            extra={
                "alg": self.alg,
                "kid": self.kid,
                "ts": ts,
                "digest_alg": self.cfg.digest_alg,
                "digest_prefix": env.digest[:16],
            },
        )
        return env

    def verify(self, payload: bytes, envelope: SignatureEnvelope) -> None:
        """
        Synchronous verification; raise VerificationError on failure.
        """
        if envelope.version != ENVELOPE_VERSION:
            raise VerificationError(f"Envelope version mismatch: got {envelope.version}, expect {ENVELOPE_VERSION}")

        if envelope.alg != self.alg:
            raise VerificationError(f"Algorithm mismatch: envelope={envelope.alg}, signer={self.alg}")

        if not _constant_time_str_eq(envelope.kid, self.kid):
            raise VerificationError("Key ID mismatch")

        if envelope.digest_alg not in SUPPORTED_DIGESTS:
            raise VerificationError(f"Unsupported digest algorithm in envelope: {envelope.digest_alg}")

        computed_digest = _b64u(_hash_bytes(payload, envelope.digest_alg))
        if not _constant_time_str_eq(computed_digest, envelope.digest):
            raise VerificationError("Payload digest mismatch")

        # Reconstruct canonical "to_sign" for verification
        to_sign_obj = {
            "version": envelope.version,
            "alg": envelope.alg,
            "kid": envelope.kid,
            "ts": envelope.ts,
            "digest_alg": envelope.digest_alg,
            "digest": envelope.digest,
        }
        if envelope.ctx is not None:
            to_sign_obj["ctx"] = envelope.ctx

        message = _canon_json(to_sign_obj)
        try:
            self._verify_raw(message, _b64u_decode(envelope.sig))
        except VerificationError:
            raise
        except Exception as e:
            raise VerificationError(f"Signature backend verification error: {e}") from e

        LOGGER.info(
            "policy-sign: verified",
            extra={
                "alg": self.alg,
                "kid": self.kid,
                "ts": envelope.ts,
                "digest_alg": envelope.digest_alg,
                "digest_prefix": envelope.digest[:16],
            },
        )

    # ---------- Async wrappers ----------

    async def async_sign(self, payload: bytes) -> SignatureEnvelope:
        return await asyncio.to_thread(self.sign, payload)

    async def async_verify(self, payload: bytes, envelope: SignatureEnvelope) -> None:
        return await asyncio.to_thread(self.verify, payload, envelope)

# =========================
# ED25519 backend
# =========================

class Ed25519Signer(BaseSigner):
    def __init__(self, cfg: SignerConfig):
        super().__init__(cfg)
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey, Ed25519PublicKey
            )
            from cryptography.hazmat.primitives import serialization
        except Exception as e:
            raise BackendNotAvailableError("cryptography is required for ED25519 signer") from e

        if not cfg.private_key_path:
            raise SignerConfigError("ED25519 requires private_key_path")

        self._serialization = serialization
        self._Ed25519PrivateKey = Ed25519PrivateKey
        self._Ed25519PublicKey = Ed25519PublicKey

        pem = pathlib.Path(cfg.private_key_path).read_bytes()
        password: Optional[bytes] = None
        if cfg.private_key_pass_env:
            pw = os.environ.get(cfg.private_key_pass_env)
            if pw:
                password = pw.encode("utf-8")

        try:
            self._priv = serialization.load_pem_private_key(pem, password=password)
        except Exception as e:
            raise SignerConfigError(f"Failed to load ED25519 private key: {e}") from e

        pub = self._priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=self._serialization.Encoding.Raw,
            format=self._serialization.PublicFormat.Raw
        )
        self._kid = cfg.key_id or _kid_from_bytes(pub_bytes)

    @property
    def alg(self) -> str:
        return "ED25519"

    @property
    def kid(self) -> str:
        return self._kid

    def _sign_raw(self, message: bytes) -> bytes:
        return self._priv.sign(message)

    def _verify_raw(self, message: bytes, signature: bytes) -> None:
        pub = self._priv.public_key()
        try:
            pub.verify(signature, message)
        except Exception as e:
            raise VerificationError("ED25519 signature invalid") from e

# =========================
# RSA-PSS backend
# =========================

class RSAPSSSigner(BaseSigner):
    def __init__(self, cfg: SignerConfig):
        super().__init__(cfg)
        try:
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa
            from cryptography import x509
        except Exception as e:
            raise BackendNotAvailableError("cryptography is required for RSA-PSS signer") from e

        if not cfg.private_key_path:
            raise SignerConfigError("RSA-PSS requires private_key_path")
        self._serialization = serialization
        self._hashes = hashes
        self._padding = padding
        self._rsa = rsa
        self._x509 = x509

        pem = pathlib.Path(cfg.private_key_path).read_bytes()
        password: Optional[bytes] = None
        if cfg.private_key_pass_env:
            pw = os.environ.get(cfg.private_key_pass_env)
            if pw:
                password = pw.encode("utf-8")

        try:
            self._priv = serialization.load_pem_private_key(pem, password=password)
        except Exception as e:
            raise SignerConfigError(f"Failed to load RSA private key: {e}") from e

        if cfg.public_cert_path:
            cert_pem = pathlib.Path(cfg.public_cert_path).read_bytes()
            cert = x509.load_pem_x509_certificate(cert_pem)
            pub = cert.public_key()
            # kid from public key DER
            pub_der = pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self._kid = cfg.key_id or _kid_from_bytes(pub_der)
            chain_pems: List[str] = [cert_pem.decode("utf-8")]
            if cfg.chain_paths:
                for p in cfg.chain_paths:
                    chain_pems.append(pathlib.Path(p).read_text(encoding="utf-8"))
            self._chain_pems = chain_pems
        else:
            # fallback: compute kid from public key (without cert)
            pub = self._priv.public_key()
            pub_der = pub.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self._kid = cfg.key_id or _kid_from_bytes(pub_der)
            self._chain_pems = None  # type: ignore

        # Hash mapping
        if self.cfg.digest_alg == "SHA256":
            self._hash = self._hashes.SHA256()
        elif self.cfg.digest_alg == "BLAKE2B-256":
            # RSA-PSS operates over hashed message; use SHA256 for PSS while digest for payload may be blake2b.
            # We fix PSS hash to SHA256 (interoperable in most FIPS profiles).
            self._hash = self._hashes.SHA256()
        else:
            raise SignerConfigError(f"Unsupported digest_alg for RSA-PSS: {self.cfg.digest_alg}")

    @property
    def alg(self) -> str:
        return "RSASSA-PSS-SHA256"

    @property
    def kid(self) -> str:
        return self._kid

    def _sign_raw(self, message: bytes) -> bytes:
        return self._priv.sign(
            message,
            self._padding.PSS(
                mgf=self._padding.MGF1(self._hashes.SHA256()),
                salt_length=self._padding.PSS.MAX_LENGTH,
            ),
            self._hashes.SHA256(),
        )

    def _verify_raw(self, message: bytes, signature: bytes) -> None:
        pub = self._priv.public_key()
        try:
            pub.verify(
                signature,
                message,
                self._padding.PSS(
                    mgf=self._padding.MGF1(self._hashes.SHA256()),
                    salt_length=self._padding.PSS.MAX_LENGTH,
                ),
                self._hashes.SHA256(),
            )
        except Exception as e:
            raise VerificationError("RSA-PSS signature invalid") from e

# =========================
# GPG backend (detached signature via gpg CLI)
# =========================

class GPGSigner(BaseSigner):
    """
    Uses the system 'gpg' CLI to sign/verify the canonical message. The payload digest remains in envelope.
    """
    def __init__(self, cfg: SignerConfig):
        super().__init__(cfg)
        if not cfg.gpg_key_id:
            raise SignerConfigError("GPG requires gpg_key_id")
        self._gpg = cfg.gpg_binary or "gpg"
        self._homedir = cfg.gpg_homedir
        self._kid = cfg.key_id or cfg.gpg_key_id

        # Quick availability check
        try:
            subprocess.run([self._gpg, "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            raise BackendNotAvailableError(f"gpg binary not available: {e}") from e

    @property
    def alg(self) -> str:
        return "GPG"

    @property
    def kid(self) -> str:
        return self._kid

    def _gpg_env(self) -> Dict[str, str]:
        env = dict(os.environ)
        # Try to isolate GPG_TTY to avoid pinentry noise in headless environments
        env.pop("GPG_TTY", None)
        return env

    def _run_gpg(self, args: List[str], data: bytes) -> bytes:
        cmd = [self._gpg]
        if self._homedir:
            cmd.extend(["--homedir", self._homedir])
        cmd.extend(args)
        proc = subprocess.run(
            cmd,
            input=data,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._gpg_env(),
        )
        if proc.returncode != 0:
            raise SignerError(f"gpg failed: rc={proc.returncode} stderr={proc.stderr.decode('utf-8', 'ignore')}")
        return proc.stdout

    def _sign_raw(self, message: bytes) -> bytes:
        # Create a binary detached signature over message
        args = [
            "--batch",
            "--yes",
            "--local-user", self._kid,
            "--detach-sign",
            "--digest-algo", "SHA256",
            "--armor",  # ASCII armor so we can base64url without binary -> still ok
        ]
        sig = self._run_gpg(args, message)
        # Remove ASCII armor headers/footers, keep base64 payload
        armored = sig.decode("utf-8", "ignore")
        lines = [ln.strip() for ln in armored.splitlines() if ln and not ln.startswith("-----")]
        raw_b64 = "".join(lines)
        return base64.b64decode(raw_b64)

    def _verify_raw(self, message: bytes, signature: bytes) -> None:
        # gpg --verify expects signature file + message; we emulate via single call by feeding message on stdin
        # Workaround: we pass signature via stdin is non-trivial; instead, spawn gpg twice:
        # 1) write temp files. To avoid disk IO dependencies here, we emulate minimal check using gpg --verify
        import tempfile
        with tempfile.TemporaryDirectory(prefix="gpg-verify-") as td:
            sig_path = os.path.join(td, "sig.asc")
            msg_path = os.path.join(td, "msg.bin")
            with open(sig_path, "wb") as f:
                # restore ASCII armor for gpg --verify convenience
                armored = b"-----BEGIN PGP SIGNATURE-----\n" + base64.b64encode(signature) + b"\n-----END PGP SIGNATURE-----\n"
                f.write(armored)
            with open(msg_path, "wb") as f:
                f.write(message)
            cmd = [self._gpg]
            if self._homedir:
                cmd.extend(["--homedir", self._homedir])
            cmd.extend(["--batch", "--yes", "--verify", sig_path, msg_path])
            proc = subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._gpg_env(),
            )
            if proc.returncode != 0:
                raise VerificationError(f"GPG signature invalid: {proc.stderr.decode('utf-8', 'ignore')}")

# =========================
# Factory
# =========================

class SignerFactory:
    @staticmethod
    def from_config(cfg: SignerConfig) -> BaseSigner:
        st = cfg.type.lower()
        if st == SignerType.ED25519:
            return Ed25519Signer(cfg)
        if st == SignerType.RSA_PSS:
            return RSAPSSSigner(cfg)
        if st == SignerType.GPG:
            return GPGSigner(cfg)
        raise SignerConfigError(f"Unknown signer type: {cfg.type}")

# =========================
# High-level API
# =========================

class PolicySigner:
    """
    High-level façade for signing and verifying policy blobs.
    """
    def __init__(self, signer: BaseSigner):
        self._signer = signer

    def sign_bytes(self, data: bytes) -> SignatureEnvelope:
        return self._signer.sign(data)

    def verify_bytes(self, data: bytes, envelope: Union[SignatureEnvelope, bytes]) -> None:
        if isinstance(envelope, bytes):
            envelope = SignatureEnvelope.from_json_bytes(envelope)
        return self._signer.verify(data, envelope)

    async def async_sign_bytes(self, data: bytes) -> SignatureEnvelope:
        return await self._signer.async_sign(data)

    async def async_verify_bytes(self, data: bytes, envelope: Union[SignatureEnvelope, bytes]) -> None:
        if isinstance(envelope, bytes):
            envelope = SignatureEnvelope.from_json_bytes(envelope)
        return await self._signer.async_verify(data, envelope)

# =========================
# Optional: file helpers
# =========================

def sign_file(path: Union[str, pathlib.Path], signer: BaseSigner, chunk_size: int = 1024 * 1024) -> SignatureEnvelope:
    """
    Efficiently hash a file (streaming) then sign the digest via unified envelope.
    """
    digest_alg = signer.cfg.digest_alg
    h = hashlib.sha256() if digest_alg == "SHA256" else hashlib.blake2b(digest_size=32)
    p = pathlib.Path(path)
    with p.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    digest_b64u = _b64u(h.digest())
    ts = _now_ts()
    to_sign_obj = {
        "version": ENVELOPE_VERSION,
        "alg": signer.alg,
        "kid": signer.kid,
        "ts": ts,
        "digest_alg": digest_alg,
        "digest": digest_b64u,
    }
    if signer.cfg.context:
        to_sign_obj["ctx"] = signer.cfg.context
    message = _canon_json(to_sign_obj)
    sig = signer._sign_raw(message)
    chain: Optional[List[str]] = None
    if hasattr(signer, "_chain_pems"):
        chain = getattr(signer, "_chain_pems")  # type: ignore
    env = SignatureEnvelope(
        version=ENVELOPE_VERSION,
        alg=signer.alg,
        kid=signer.kid,
        ts=ts,
        digest_alg=digest_alg,
        digest=digest_b64u,
        sig=_b64u(sig),
        ctx=signer.cfg.context,
        chain=chain,
        meta=signer.cfg.meta,
    )
    LOGGER.info(
        "policy-sign: signed file",
        extra={"path": str(p), "alg": signer.alg, "kid": signer.kid, "digest_alg": digest_alg, "digest_prefix": env.digest[:16]},
    )
    return env

def verify_file(path: Union[str, pathlib.Path], signer: BaseSigner, envelope: Union[SignatureEnvelope, bytes], chunk_size: int = 1024 * 1024) -> None:
    """
    Streaming verify for a file with a provided envelope.
    """
    if isinstance(envelope, bytes):
        envelope = SignatureEnvelope.from_json_bytes(envelope)
    digest_alg = envelope.digest_alg
    if digest_alg not in SUPPORTED_DIGESTS:
        raise VerificationError(f"Unsupported digest algorithm in envelope: {digest_alg}")
    h = hashlib.sha256() if digest_alg == "SHA256" else hashlib.blake2b(digest_size=32)
    p = pathlib.Path(path)
    with p.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    computed = _b64u(h.digest())
    if not _constant_time_str_eq(computed, envelope.digest):
        raise VerificationError("Payload digest mismatch for file")
    # Recreate signed object and verify
    to_sign_obj = {
        "version": envelope.version,
        "alg": envelope.alg,
        "kid": envelope.kid,
        "ts": envelope.ts,
        "digest_alg": envelope.digest_alg,
        "digest": envelope.digest,
    }
    if envelope.ctx is not None:
        to_sign_obj["ctx"] = envelope.ctx
    message = _canon_json(to_sign_obj)
    try:
        signer._verify_raw(message, _b64u_decode(envelope.sig))
    except VerificationError:
        raise
    except Exception as e:
        raise VerificationError(f"Signature backend verification error: {e}") from e
    LOGGER.info(
        "policy-sign: verified file",
        extra={"path": str(p), "alg": signer.alg, "kid": signer.kid, "digest_alg": digest_alg, "digest_prefix": envelope.digest[:16]},
    )

# =========================
# Minimal self-check (import-time only; no execution)
# =========================

__all__ = [
    "SignatureEnvelope",
    "SignerConfig",
    "SignerFactory",
    "PolicySigner",
    "BaseSigner",
    "Ed25519Signer",
    "RSAPSSSigner",
    "GPGSigner",
    "SignerError",
    "SignerConfigError",
    "VerificationError",
    "BackendNotAvailableError",
    "sign_file",
    "verify_file",
]
