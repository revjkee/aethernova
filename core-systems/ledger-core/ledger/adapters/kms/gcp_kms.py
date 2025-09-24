# ledger/adapters/kms/gcp_kms.py
"""
GCP KMS Adapter for ledger-core (industrial-grade)

Features:
- Async wrapper over google-cloud-kms (blocking) via anyio.to_thread.run_sync
- Config via env / constructor with validation
- Resiliency: timeouts, bounded exponential backoff with jitter, idempotent retries
- Crypto:
  * Symmetric KMS encrypt/decrypt (AES-GCM/GOOGLE_MANAGED handled by KMS)
  * Envelope encryption: local AES-GCM with DEK sealed by KMS
  * Asymmetric sign/verify using KMS key versions
- Key management helpers: get_public_key, create version, set primary version
- Secure memory handling for plaintexts/keys where possible
- Structured logging and optional metrics hooks
- 100% type hints, clear docstrings, no synchronous leaks

Requirements (at runtime in your environment, not imported here):
- google-cloud-kms>=2.17
- google-auth
- anyio>=3.6
"""

from __future__ import annotations

import os
import base64
import json
import hmac
import hashlib
import logging
import time
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple, Callable, Awaitable, Protocol, Dict, Any, Union

try:
    import anyio  # runtime dep; used for to_thread and cancellation scopes
except Exception as _e:  # pragma: no cover
    raise RuntimeError("anyio is required for gcp_kms adapter") from _e

# Lazy imports for google packages inside worker functions to avoid import cost at module import.


__all__ = [
    "KMSAdapterError",
    "KMSTimeout",
    "KMSUnavailable",
    "KMSVerificationError",
    "GCPKMSConfig",
    "KMSMetrics",
    "GCPKMSAdapter",
]


# =========================
# Errors
# =========================

class KMSAdapterError(Exception):
    """Base adapter error."""


class KMSTimeout(KMSAdapterError):
    """Operation timed out."""


class KMSUnavailable(KMSAdapterError):
    """KMS temporarily unavailable after retries."""


class KMSVerificationError(KMSAdapterError):
    """Signature verification failed or integrity check failed."""


# =========================
# Metrics (optional hook)
# =========================

class KMSMetrics(Protocol):
    def inc(self, name: str, labels: Optional[Dict[str, str]] = None) -> None: ...
    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None: ...


class _NoopMetrics:
    def inc(self, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        return

    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        return


# =========================
# Config
# =========================

@dataclass(frozen=True)
class GCPKMSConfig:
    project_id: str
    location_id: str
    key_ring_id: str
    key_id: str
    # Optional key version for asymmetric operations; for symmetric, KMS chooses primary.
    key_version_id: Optional[str] = None

    # Resiliency
    request_timeout_s: float = 15.0
    overall_timeout_s: float = 60.0
    max_retries: int = 5
    initial_backoff_s: float = 0.2
    max_backoff_s: float = 5.0

    # Envelope crypto
    aead_tag_bytes: int = 16  # AES-GCM tag length (128-bit)

    @staticmethod
    def from_env(prefix: str = "GCP_KMS_") -> "GCPKMSConfig":
        def _get(name: str, default: Optional[str] = None, required: bool = True) -> str:
            val = os.getenv(prefix + name, default)
            if required and not val:
                raise KMSAdapterError(f"Missing environment variable: {prefix}{name}")
            return str(val) if val is not None else ""
        return GCPKMSConfig(
            project_id=_get("PROJECT"),
            location_id=_get("LOCATION"),
            key_ring_id=_get("KEY_RING"),
            key_id=_get("KEY"),
            key_version_id=os.getenv(prefix + "KEY_VERSION", None),
            request_timeout_s=float(os.getenv(prefix + "REQUEST_TIMEOUT_S", "15")),
            overall_timeout_s=float(os.getenv(prefix + "OVERALL_TIMEOUT_S", "60")),
            max_retries=int(os.getenv(prefix + "MAX_RETRIES", "5")),
            initial_backoff_s=float(os.getenv(prefix + "INITIAL_BACKOFF_S", "0.2")),
            max_backoff_s=float(os.getenv(prefix + "MAX_BACKOFF_S", "5.0")),
            aead_tag_bytes=int(os.getenv(prefix + "AEAD_TAG_BYTES", "16")),
        )

    def key_name(self) -> str:
        """
        Full resource name for CryptoKey (primary version for symmetric ops):
        projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key}
        """
        return f"projects/{self.project_id}/locations/{self.location_id}/keyRings/{self.key_ring_id}/cryptoKeys/{self.key_id}"

    def key_version_name(self) -> str:
        """
        Full resource name for CryptoKeyVersion (asymmetric ops):
        projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
        """
        if not self.key_version_id:
            raise KMSAdapterError("key_version_id is required for version-specific operations")
        return f"{self.key_name()}/cryptoKeyVersions/{self.key_version_id}"


# =========================
# Logging
# =========================

logger = logging.getLogger("ledger.adapters.kms.gcp")
if not logger.handlers:
    # Conservative default; in production, configure logging centrally
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# =========================
# Helpers: retry/backoff, timeouts, secure ops
# =========================

async def _retry_async(
    fn: Callable[[], Awaitable[Any]],
    *,
    max_retries: int,
    initial_backoff_s: float,
    max_backoff_s: float,
    overall_timeout_s: float,
    metrics: KMSMetrics,
    op_name: str,
) -> Any:
    start = time.monotonic()
    attempt = 0
    backoff = initial_backoff_s
    last_exc: Optional[Exception] = None

    while True:
        elapsed = time.monotonic() - start
        if elapsed > overall_timeout_s:
            metrics.inc("kms_timeout", {"op": op_name})
            raise KMSTimeout(f"{op_name} exceeded overall timeout {overall_timeout_s}s") from last_exc
        try:
            t0 = time.monotonic()
            res = await fn()
            metrics.observe("kms_latency_seconds", time.monotonic() - t0, {"op": op_name, "attempt": str(attempt)})
            return res
        except Exception as e:  # Broad: surfaces google.api_core exceptions and transport errors
            last_exc = e
            attempt += 1
            if attempt > max_retries:
                metrics.inc("kms_unavailable", {"op": op_name})
                logger.error("KMS op '%s' failed after %d retries: %s", op_name, attempt - 1, repr(e))
                raise KMSUnavailable(f"{op_name} failed after {max_retries} retries") from e
            # bounded exp backoff + jitter
            sleep_for = min(backoff, max_backoff_s) + secrets.randbelow(100) / 1000.0
            logger.warning("KMS op '%s' attempt %d failed: %s; backing off %.3fs", op_name, attempt, repr(e), sleep_for)
            metrics.inc("kms_retry", {"op": op_name, "attempt": str(attempt)})
            with anyio.move_on_after(max(0.0, overall_timeout_s - (time.monotonic() - start))):
                await anyio.sleep(sleep_for)
            backoff = min(backoff * 2.0, max_backoff_s)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


def _hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    if salt is None:
        salt = b""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _wipe(b: Union[bytearray, memoryview]) -> None:
    try:
        for i in range(len(b)):
            b[i] = 0
    except Exception:
        pass


# AES-GCM (cryptography is a heavy dep; we avoid importing if not present at import time)
# We lazy-import inside function to keep module import light. This is used for envelope mode only.

def _aes_gcm_encrypt(plaintext: bytes, aad: Optional[bytes], key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Returns (nonce, ciphertext_with_tag, tag)
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    except Exception as e:  # pragma: no cover
        raise KMSAdapterError("cryptography package is required for envelope AES-GCM operations") from e

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad if aad else None)
    # AESGCM returns ciphertext||tag; tag is last 16 bytes by default
    tag = ct[-16:]
    return nonce, ct, tag


def _aes_gcm_decrypt(nonce: bytes, ciphertext_with_tag: bytes, aad: Optional[bytes], key: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    except Exception as e:  # pragma: no cover
        raise KMSAdapterError("cryptography package is required for envelope AES-GCM operations") from e

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad if aad else None)


# =========================
# Adapter
# =========================

class GCPKMSAdapter:
    """
    Industrial-grade async adapter for Google Cloud KMS.

    Notes:
    - All Google Cloud client calls are executed in threadpool via anyio.to_thread.run_sync
    - For symmetric encryption, use cryptoKey resource (KMS primary version)
    - For asymmetric sign/verify, use cryptoKeyVersion resource (requires key_version_id)
    """

    def __init__(self, config: GCPKMSConfig, *, metrics: Optional[KMSMetrics] = None) -> None:
        self._cfg = config
        self._metrics = metrics or _NoopMetrics()

    # -------------
    # Low-level: client factories (lazy)
    # -------------

    @staticmethod
    def _kms_client_sync():
        # Imported lazily inside thread
        from google.cloud import kms_v1  # type: ignore
        return kms_v1.KeyManagementServiceClient()

    # -------------
    # Core ops: symmetric encrypt/decrypt via KMS
    # -------------

    async def encrypt_symmetric(self, plaintext: bytes, *, aad: Optional[bytes] = None) -> Dict[str, str]:
        """
        Encrypt plaintext using KMS symmetric key (primary version).
        Returns dict with base64 fields: {"ciphertext_b64", "aad_b64?"}
        """
        key_name = self._cfg.key_name()
        aad_bytes = aad if aad else b""

        async def _call():
            def _worker():
                client = self._kms_client_sync()
                from google.cloud.kms_v1 import EncryptRequest  # type: ignore
                req = EncryptRequest(
                    name=key_name,
                    plaintext=plaintext,
                    additional_authenticated_data=aad_bytes or None,
                )
                resp = client.encrypt(request=req, timeout=self._cfg.request_timeout_s)
                return resp.ciphertext  # bytes
            return await anyio.to_thread.run_sync(_worker)

        ciphertext = await _retry_async(
            _call,
            max_retries=self._cfg.max_retries,
            initial_backoff_s=self._cfg.initial_backoff_s,
            max_backoff_s=self._cfg.max_backoff_s,
            overall_timeout_s=self._cfg.overall_timeout_s,
            metrics=self._metrics,
            op_name="encrypt_symmetric",
        )

        return {
            "ciphertext_b64": _b64e(ciphertext),
            **({"aad_b64": _b64e(aad_bytes)} if aad else {}),
            "key_resource": key_name,
            "mode": "KMS_SYMMETRIC",
        }

    async def decrypt_symmetric(self, ciphertext_b64: str, *, aad_b64: Optional[str] = None) -> bytes:
        """
        Decrypt ciphertext using KMS symmetric key.
        """
        key_name = self._cfg.key_name()
        ciphertext = _b64d(ciphertext_b64)
        aad = _b64d(aad_b64) if aad_b64 else b""

        async def _call():
            def _worker():
                client = self._kms_client_sync()
                from google.cloud.kms_v1 import DecryptRequest  # type: ignore
                req = DecryptRequest(
                    name=key_name,
                    ciphertext=ciphertext,
                    additional_authenticated_data=aad or None,
                )
                resp = client.decrypt(request=req, timeout=self._cfg.request_timeout_s)
                return resp.plaintext  # bytes
            return await anyio.to_thread.run_sync(_worker)

        plaintext = await _retry_async(
            _call,
            max_retries=self._cfg.max_retries,
            initial_backoff_s=self._cfg.initial_backoff_s,
            max_backoff_s=self._cfg.max_backoff_s,
            overall_timeout_s=self._cfg.overall_timeout_s,
            metrics=self._metrics,
            op_name="decrypt_symmetric",
        )
        return plaintext

    # -------------
    # Envelope encryption: local AES-GCM with DEK sealed by KMS
    # -------------

    async def envelope_encrypt(
        self,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        dek_length: int = 32,  # AES-256
        kek_name_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        1) Generate random DEK (or HKDF-expand if policy requires)
        2) Encrypt plaintext locally with AES-GCM using DEK
        3) Encrypt DEK using KMS Encrypt (KEK)
        Returns JSON-safe dict for storage/transit.
        """
        dek = bytearray(secrets.token_bytes(dek_length))
        try:
            nonce, ct_with_tag, tag = _aes_gcm_encrypt(bytes(plaintext), aad, bytes(dek))
            kek_name = kek_name_override or self._cfg.key_name()
            sealed_dek = await self._encrypt_raw_(kek_name, bytes(dek))
            package = {
                "mode": "ENVELOPE_AES_GCM_KMS",
                "kek_resource": kek_name,
                "aad_b64": _b64e(aad) if aad else "",
                "nonce_b64": _b64e(nonce),
                "ciphertext_b64": _b64e(ct_with_tag),
                "tag_b64": _b64e(tag),  # redundant (tag is last 16 bytes of ct), kept for audit clarity
                "sealed_dek_b64": _b64e(sealed_dek),
                "meta": {
                    "aead_tag_bytes": self._cfg.aead_tag_bytes,
                    "dek_alg": "AES-256-GCM" if dek_length == 32 else f"AES-{8*dek_length}-GCM",
                    "v": 1,
                },
            }
            return package
        finally:
            _wipe(dek)

    async def envelope_decrypt(self, package: Dict[str, Any]) -> bytes:
        """
        Reverse of envelope_encrypt. Validates structure and AAD.
        """
        if package.get("mode") != "ENVELOPE_AES_GCM_KMS":
            raise KMSAdapterError("Unsupported envelope package mode")

        kek_name = str(package["kek_resource"])
        aad_b64 = package.get("aad_b64") or ""
        aad = _b64d(aad_b64) if aad_b64 else None
        nonce = _b64d(package["nonce_b64"])
        ct_with_tag = _b64d(package["ciphertext_b64"])
        sealed_dek = _b64d(package["sealed_dek_b64"])

        dek = bytearray(await self._decrypt_raw_(kek_name, sealed_dek))
        try:
            pt = _aes_gcm_decrypt(nonce, ct_with_tag, aad, bytes(dek))
            return pt
        finally:
            _wipe(dek)

    # -------------
    # Asymmetric: sign/verify using KMS
    # -------------

    async def get_public_key_pem(self, *, key_version_name: Optional[str] = None) -> str:
        """
        Fetch public key in PEM for asymmetric key version (RSASSA/ECDSA, etc.)
        """
        version = key_version_name or self._cfg.key_version_name()

        async def _call():
            def _worker():
                client = self._kms_client_sync()
                resp = client.get_public_key(request={"name": version}, timeout=self._cfg.request_timeout_s)
                return resp.pem  # str
            return await anyio.to_thread.run_sync(_worker)

        return await _retry_async(
            _call,
            max_retries=self._cfg.max_retries,
            initial_backoff_s=self._cfg.initial_backoff_s,
            max_backoff_s=self._cfg.max_backoff_s,
            overall_timeout_s=self._cfg.overall_timeout_s,
            metrics=self._metrics,
            op_name="get_public_key",
        )

    async def sign(self, message: bytes, *, digest_alg: str = "SHA256", key_version_name: Optional[str] = None) -> Dict[str, str]:
        """
        Sign message using KMS asymmetric key version. KMS expects a precomputed digest for many key types.
        digest_alg: 'SHA256'|'SHA384'|'SHA512'
        Returns {'signature_b64': ..., 'digest_b64': ...}
        """
        version = key_version_name or self._cfg.key_version_name()
        if digest_alg not in ("SHA256", "SHA384", "SHA512"):
            raise KMSAdapterError("Unsupported digest_alg")

        hv = getattr(hashlib, digest_alg.lower())()
        hv.update(message)
        digest = hv.digest()

        async def _call():
            def _worker():
                client = self._kms_client_sync()
                from google.cloud.kms_v1 import Digest  # type: ignore
                resp = client.asymmetric_sign(
                    request={"name": version, "digest": Digest(**{digest_alg.lower(): digest})},
                    timeout=self._cfg.request_timeout_s,
                )
                return resp.signature  # bytes
            return await anyio.to_thread.run_sync(_worker)

        signature = await _retry_async(
            _call,
            max_retries=self._cfg.max_retries,
            initial_backoff_s=self._cfg.initial_backoff_s,
            max_backoff_s=self._cfg.max_backoff_s,
            overall_timeout_s=self._cfg.overall_timeout_s,
            metrics=self._metrics,
            op_name="asymmetric_sign",
        )
        return {"signature_b64": _b64e(signature), "digest_b64": _b64e(digest), "alg": digest_alg, "key_version": version}

    async def verify(self, message: bytes, signature_b64: str, *, digest_alg: str = "SHA256", key_version_name: Optional[str] = None) -> bool:
        """
        Verify signature using public key fetched from KMS.
        Validation happens client-side using cryptography, not a KMS call.
        """
        pem = await self.get_public_key_pem(key_version_name=key_version_name)
        signature = _b64d(signature_b64)

        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding, ec, utils, rsa
            from cryptography.hazmat.backends import default_backend
        except Exception as e:  # pragma: no cover
            raise KMSAdapterError("cryptography package is required for verify") from e

        pub = serialization.load_pem_public_key(pem.encode("ascii"), backend=default_backend())
        dg_map = {"SHA256": hashes.SHA256(), "SHA384": hashes.SHA384(), "SHA512": hashes.SHA512()}
        if digest_alg not in dg_map:
            raise KMSAdapterError("Unsupported digest_alg")

        # Hash message
        h = hashes.Hash(dg_map[digest_alg], backend=default_backend())
        h.update(message)
        digest = h.finalize()

        try:
            if isinstance(pub, rsa.RSAPublicKey):
                pub.verify(
                    signature,
                    digest,
                    padding.PKCS1v15(),
                    utils.Prehashed(dg_map[digest_alg]),
                )
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                pub.verify(
                    signature,
                    digest,
                    ec.ECDSA(utils.Prehashed(dg_map[digest_alg])),
                )
            else:
                raise KMSAdapterError("Unsupported public key type")
            return True
        except Exception:
            raise KMSVerificationError("Signature verification failed")

    # -------------
    # Key management helpers (admin-level ops depending on IAM)
    # -------------

    async def create_crypto_key_version(self, *, key_name: Optional[str] = None) -> str:
        """
        Creates a new key version for given crypto key. Requires appropriate IAM.
        Returns version resource name.
        """
        crypto_key = key_name or self._cfg.key_name()

        async def _call():
            def _worker():
                client = self._kms_client_sync()
                resp = client.create_crypto_key_version(
                    request={"parent": crypto_key, "crypto_key_version": {}},
                    timeout=self._cfg.request_timeout_s,
                )
                return resp.name  # str
            return await anyio.to_thread.run_sync(_worker)

        return await _retry_async(
            _call,
            max_retries=self._cfg.max_retries,
            initial_backoff_s=self._cfg.initial_backoff_s,
            max_backoff_s=self._cfg.max_backoff_s,
            overall_timeout_s=self._cfg.overall_timeout_s,
            metrics=self._metrics,
            op_name="create_crypto_key_version",
        )

    async def set_primary_version(self, *, key_name: Optional[str] = None, version_id: str) -> str:
        """
        Sets primary version for symmetric key. Requires IAM permissions.
        Returns updated crypto key name.
        """
        crypto_key = key_name or self._cfg.key_name()

        async def _call():
            def _worker():
                client = self._kms_client_sync()
                resp = client.update_crypto_key_primary_version(
                    request={"name": crypto_key, "crypto_key_version_id": version_id},
                    timeout=self._cfg.request_timeout_s,
                )
                return resp.name  # str
            return await anyio.to_thread.run_sync(_worker)

        return await _retry_async(
            _call,
            max_retries=self._cfg.max_retries,
            initial_backoff_s=self._cfg.initial_backoff_s,
            max_backoff_s=self._cfg.max_backoff_s,
            overall_timeout_s=self._cfg.overall_timeout_s,
            metrics=self._metrics,
            op_name="set_primary_version",
        )

    # -------------
    # Internal raw helpers (non-public)
    # -------------

    async def _encrypt_raw_(self, key_name: str, plaintext: bytes) -> bytes:
        """
        Raw KMS encrypt (no base64), used for sealing DEK.
        """
        async def _call():
            def _worker():
                client = self._kms_client_sync()
                from google.cloud.kms_v1 import EncryptRequest  # type: ignore
                req = EncryptRequest(name=key_name, plaintext=plaintext)
                resp = client.encrypt(request=req, timeout=self._cfg.request_timeout_s)
                return resp.ciphertext
            return await anyio.to_thread.run_sync(_worker)

        return await _retry_async(
            _call,
            max_retries=self._cfg.max_retries,
            initial_backoff_s=self._cfg.initial_backoff_s,
            max_backoff_s=self._cfg.max_backoff_s,
            overall_timeout_s=self._cfg.overall_timeout_s,
            metrics=self._metrics,
            op_name="_encrypt_raw",
        )

    async def _decrypt_raw_(self, key_name: str, ciphertext: bytes) -> bytes:
        """
        Raw KMS decrypt (no base64), used for unsealing DEK.
        """
        async def _call():
            def _worker():
                client = self._kms_client_sync()
                from google.cloud.kms_v1 import DecryptRequest  # type: ignore
                req = DecryptRequest(name=key_name, ciphertext=ciphertext)
                resp = client.decrypt(request=req, timeout=self._cfg.request_timeout_s)
                return resp.plaintext
            return await anyio.to_thread.run_sync(_worker)

        return await _retry_async(
            _call,
            max_retries=self._cfg.max_retries,
            initial_backoff_s=self._cfg.initial_backoff_s,
            max_backoff_s=self._cfg.max_backoff_s,
            overall_timeout_s=self._cfg.overall_timeout_s,
            metrics=self._metrics,
            op_name="_decrypt_raw",
        )

    # -------------
    # Serialization helpers
    # -------------

    @staticmethod
    def serialize_package(package: Dict[str, Any]) -> bytes:
        """
        Stable JSON serialization for envelope package.
        """
        return json.dumps(package, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def deserialize_package(data: bytes) -> Dict[str, Any]:
        return json.loads(data.decode("utf-8"))


# =========================
# Factory
# =========================

def make_gcp_kms_from_env(metrics: Optional[KMSMetrics] = None) -> GCPKMSAdapter:
    """
    Build adapter using environment variables:
      GCP_KMS_PROJECT
      GCP_KMS_LOCATION
      GCP_KMS_KEY_RING
      GCP_KMS_KEY
      [optional] GCP_KMS_KEY_VERSION
      [optional] GCP_KMS_REQUEST_TIMEOUT_S
      [optional] GCP_KMS_OVERALL_TIMEOUT_S
      [optional] GCP_KMS_MAX_RETRIES
      [optional] GCP_KMS_INITIAL_BACKOFF_S
      [optional] GCP_KMS_MAX_BACKOFF_S
      [optional] GCP_KMS_AEAD_TAG_BYTES
    """
    cfg = GCPKMSConfig.from_env()
    return GCPKMSAdapter(cfg, metrics=metrics or _NoopMetrics())
