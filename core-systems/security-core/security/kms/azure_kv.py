# security-core/security/kms/azure_kv.py
"""
Azure Key Vault KMS adapter for security-core.

Features:
- Sync and Async clients (azure.keyvault.* and azure.keyvault.*.aio)
- Sign/Verify, Encrypt/Decrypt, Wrap/Unwrap
- Deterministic algorithm mapping: RSA-PSS, ECDSA (P-256/384/521), Ed25519, RSA-OAEP/AES-GCM (MHSM)
- Robust retries with exponential backoff on transient errors (throttling/timeout)
- TTL caches for Key metadata, JWK/SPKI, and CryptographyClient instances
- Key ID normalization (vault_url + /keys/{name}/{version})
- Optional SPKI (if 'cryptography' installed); always returns JWK
- Structured exceptions: KmsError subclasses
- Strong typing and minimal external dependencies (only Azure SDKs; 'cryptography' optional)

Note:
- Azure SDK already includes pipeline retries; we add a lightweight guard for transient failures.
- AES-GCM operations require Managed HSM with symmetric keys (oct/AES). If unavailable, methods raise.
"""

from __future__ import annotations

import base64
import binascii
import os
import time
import math
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Mapping, Union, Iterable, Callable

# Azure SDK imports (sync)
try:
    from azure.identity import DefaultAzureCredential
    from azure.core.exceptions import HttpResponseError, ResourceNotFoundError, ServiceRequestError, ClientAuthenticationError, ServiceResponseError
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.keys.crypto import CryptographyClient
    from azure.keyvault.keys.crypto import SignatureAlgorithm as _SigAlg
    from azure.keyvault.keys.crypto import EncryptionAlgorithm as _EncAlg
    from azure.keyvault.keys.crypto import KeyWrapAlgorithm as _WrapAlg
except Exception as _e:
    # Delay hard import errors until class construction
    DefaultAzureCredential = object  # type: ignore
    HttpResponseError = ResourceNotFoundError = ServiceRequestError = ClientAuthenticationError = ServiceResponseError = Exception  # type: ignore
    KeyClient = CryptographyClient = object  # type: ignore
    _SigAlg = _EncAlg = _WrapAlg = object  # type: ignore

# Azure SDK imports (async) — optional
try:
    from azure.identity.aio import DefaultAzureCredential as AioDefaultAzureCredential  # type: ignore
    from azure.keyvault.keys.aio import KeyClient as AioKeyClient  # type: ignore
    from azure.keyvault.keys.crypto.aio import CryptographyClient as AioCryptographyClient  # type: ignore
except Exception:
    AioDefaultAzureCredential = AioKeyClient = AioCryptographyClient = None  # type: ignore

# Optional SPKI builder (cryptography)
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
    from cryptography.hazmat.primitives import serialization
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False


# =========================
# Exceptions
# =========================

class KmsError(Exception):
    pass

class KmsNotFound(KmsError):
    pass

class KmsUnauthorized(KmsError):
    pass

class KmsUnavailable(KmsError):
    pass

class KmsInvalidArgument(KmsError):
    pass


# =========================
# TTL cache (thread-safe)
# =========================

class _TTLCache:
    def __init__(self, ttl_seconds: int = 300, max_size: int = 2048) -> None:
        self.ttl = ttl_seconds
        self.max = max_size
        self._store: Dict[str, Tuple[Any, float]] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        now = time.time()
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            val, exp = item
            if exp < now:
                self._store.pop(key, None)
                return None
            return val

    def set(self, key: str, value: Any) -> None:
        exp = time.time() + self.ttl
        with self._lock:
            if len(self._store) >= self.max:
                # drop an arbitrary item
                self._store.pop(next(iter(self._store)))
            self._store[key] = (value, exp)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


# =========================
# Algorithm mappings
# =========================

# Public names used by security-core
SigAlg = str
EncAlg = str
WrapAlg = str

_SIG_MAP: Mapping[SigAlg, str] = {
    # RSA-PSS
    "rsa_pss_2048": "PS256",
    "rsa_pss_3072": "PS384",
    "rsa_pss_4096": "PS512",
    # ECDSA
    "ecdsa_p256": "ES256",
    "ecdsa_p384": "ES384",
    "ecdsa_p521": "ES512",
    # EdDSA (Ed25519)
    "ed25519": "EdDSA",
    # Legacy RSA (avoid unless required)
    "rs256": "RS256",
    "rs384": "RS384",
    "rs512": "RS512",
}

_ENC_MAP: Mapping[EncAlg, str] = {
    # RSA-OAEP
    "rsa_oaep": "RSA-OAEP",
    "rsa_oaep_256": "RSA-OAEP-256",
    # AES-GCM (MHSM symmetric keys)
    "aes_gcm_128": "A256GCM" if False else "A128GCM",  # KV expects A128GCM/A192GCM/A256GCM labels for MHSM
    "aes_gcm_192": "A192GCM",
    "aes_gcm_256": "A256GCM",
}

_WRAP_MAP: Mapping[WrapAlg, str] = {
    "rsa_oaep": "RSA-OAEP",
    "rsa_oaep_256": "RSA-OAEP-256",
    "rsa1_5": "RSA1_5",
}


# =========================
# Helpers
# =========================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64u_to_bytes(s: str) -> bytes:
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def _is_key_id(s: str) -> bool:
    return s.startswith("https://") and "/keys/" in s

def _normalize_key_id(vault_url: str, name_or_id: str, version: Optional[str] = None) -> str:
    if _is_key_id(name_or_id):
        return name_or_id
    v = vault_url.rstrip("/")
    if version:
        return f"{v}/keys/{name_or_id}/{version}"
    return f"{v}/keys/{name_or_id}"

def _retryable(err: Exception) -> bool:
    return isinstance(err, (ServiceRequestError, ServiceResponseError, HttpResponseError))  # network/5xx typically

def _translate_error(e: Exception) -> KmsError:
    if isinstance(e, ResourceNotFoundError):
        return KmsNotFound(str(e))
    if isinstance(e, ClientAuthenticationError):
        return KmsUnauthorized(str(e))
    if isinstance(e, (ServiceRequestError, ServiceResponseError)):
        return KmsUnavailable(str(e))
    if isinstance(e, HttpResponseError):
        # 429/5xx treated as unavailable
        return KmsUnavailable(str(e))
    return KmsError(str(e))

def _backoff_attempts(total: int, base: float = 0.2, cap: float = 2.0) -> Iterable[float]:
    for i in range(total):
        yield min(cap, base * (2 ** i))


# =========================
# AzureKeyVaultKMS (sync)
# =========================

@dataclass
class AzureKeyVaultKMS:
    vault_url: str
    credential: Any = None
    user_agent_suffix: str = "security-core/azure-kv"
    cache_ttl_seconds: int = 300
    crypto_cache_ttl_seconds: int = 1800
    retry_attempts: int = 4

    def __post_init__(self) -> None:
        if KeyClient is object:
            raise KmsError("Azure SDK not available. Install azure-identity and azure-keyvault-keys.")
        self._cred = self.credential or DefaultAzureCredential()
        self._key_client = KeyClient(self.vault_url, credential=self._cred, user_agent=self.user_agent_suffix)
        self._key_cache = _TTLCache(self.cache_ttl_seconds, 4096)
        self._jwk_cache = _TTLCache(self.cache_ttl_seconds, 4096)
        self._crypto_cache = _TTLCache(self.crypto_cache_ttl_seconds, 4096)
        self._lock = threading.RLock()

    # --------- Public API ---------

    def sign(self, key: str, algorithm: SigAlg, data: bytes, *, prehashed: bool = False) -> bytes:
        """
        Sign data. If prehashed=False, the service will hash internally when supported.
        For PSS/ES/EdDSA Azure may expect raw data (sign_data) or digest (sign).
        We attempt sign_data first, fallback to sign(digest) if KV rejects.
        """
        key_id = self._require_key_id(key)
        alg = self._sig_alg(algorithm)
        crypto = self._crypto_client(key_id)

        for delay in _backoff_attempts(self.retry_attempts):
            try:
                # Prefer sign_data when available
                if hasattr(crypto, "sign_data") and not prehashed:
                    res = crypto.sign_data(alg, data)  # type: ignore[attr-defined]
                else:
                    res = crypto.sign(alg, data)
                return bytes(res.signature)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
                time.sleep(delay)
        raise KmsUnavailable("Signing failed after retries")

    def verify(self, key: str, algorithm: SigAlg, data: bytes, signature: bytes, *, prehashed: bool = False) -> bool:
        key_id = self._require_key_id(key)
        alg = self._sig_alg(algorithm)
        crypto = self._crypto_client(key_id)
        for delay in _backoff_attempts(self.retry_attempts):
            try:
                if hasattr(crypto, "verify_data") and not prehashed:
                    res = crypto.verify_data(alg, data, signature)  # type: ignore[attr-defined]
                else:
                    res = crypto.verify(alg, data, signature)
                return bool(res.is_valid)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
                time.sleep(delay)
        raise KmsUnavailable("Verify failed after retries")

    def encrypt(self, key: str, algorithm: EncAlg, plaintext: bytes, *, aad: Optional[bytes] = None) -> Tuple[str, bytes, Optional[bytes]]:
        """
        Returns (alg, ciphertext, auth_tag|None). For RSA-* auth_tag is None.
        AES-GCM requires MHSM symmetric key; AAD used only for GCM modes.
        """
        key_id = self._require_key_id(key)
        alg = self._enc_alg(algorithm)
        crypto = self._crypto_client(key_id)
        for delay in _backoff_attempts(self.retry_attempts):
            try:
                if aad is not None and alg.endswith("GCM"):
                    res = crypto.encrypt(alg, plaintext, additional_authenticated_data=aad)
                else:
                    res = crypto.encrypt(alg, plaintext)
                return alg, bytes(res.ciphertext), getattr(res, "authentication_tag", None)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
                time.sleep(delay)
        raise KmsUnavailable("Encrypt failed after retries")

    def decrypt(self, key: str, algorithm: EncAlg, ciphertext: bytes, *, aad: Optional[bytes] = None, auth_tag: Optional[bytes] = None) -> bytes:
        key_id = self._require_key_id(key)
        alg = self._enc_alg(algorithm)
        crypto = self._crypto_client(key_id)
        for delay in _backoff_attempts(self.retry_attempts):
            try:
                kwargs = {}
                if aad is not None and alg.endswith("GCM"):
                    kwargs["additional_authenticated_data"] = aad
                if auth_tag is not None and alg.endswith("GCM"):
                    kwargs["authentication_tag"] = auth_tag
                res = crypto.decrypt(alg, ciphertext, **kwargs)
                return bytes(res.plaintext)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
                time.sleep(delay)
        raise KmsUnavailable("Decrypt failed after retries")

    def wrap_key(self, key: str, algorithm: WrapAlg, cek: bytes) -> Tuple[str, bytes]:
        key_id = self._require_key_id(key)
        alg = self._wrap_alg(algorithm)
        crypto = self._crypto_client(key_id)
        for delay in _backoff_attempts(self.retry_attempts):
            try:
                res = crypto.wrap_key(alg, cek)
                return alg, bytes(res.encrypted_key)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
                time.sleep(delay)
        raise KmsUnavailable("Wrap failed after retries")

    def unwrap_key(self, key: str, algorithm: WrapAlg, wrapped: bytes) -> bytes:
        key_id = self._require_key_id(key)
        alg = self._wrap_alg(algorithm)
        crypto = self._crypto_client(key_id)
        for delay in _backoff_attempts(self.retry_attempts):
            try:
                res = crypto.unwrap_key(alg, wrapped)
                return bytes(res.key)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
                time.sleep(delay)
        raise KmsUnavailable("Unwrap failed after retries")

    def get_public_jwk(self, name_or_id: str, *, version: Optional[str] = None) -> Dict[str, Any]:
        """
        Returns public JWK (dict). Uses TTL cache.
        """
        key_id = _normalize_key_id(self.vault_url, name_or_id, version)
        cached = self._jwk_cache.get(key_id)
        if cached:
            return cached
        kvk = self._get_key(key_id)
        jwk: Dict[str, Any] = {"kid": kvk.id, "kty": kvk.key_type}
        # RSA
        if hasattr(kvk, "key") and getattr(kvk.key, "n", None) is not None:
            jwk.update({
                "n": _b64u(kvk.key.n),
                "e": _b64u(kvk.key.e),
            })
        # EC
        if hasattr(kvk, "key") and getattr(kvk.key, "x", None) is not None:
            jwk.update({
                "crv": kvk.key.crv,
                "x": _b64u(kvk.key.x),
                "y": _b64u(kvk.key.y),
            })
        # OKP (Ed25519)
        if hasattr(kvk, "key") and getattr(kvk.key, "x", None) is not None and str(kvk.key_type).upper().startswith("OKP"):
            jwk.update({
                "crv": getattr(kvk.key, "crv", "Ed25519"),
                "x": _b64u(kvk.key.x),
            })
        self._jwk_cache.set(key_id, jwk)
        return jwk

    def get_public_spki(self, name_or_id: str, *, version: Optional[str] = None) -> Optional[bytes]:
        """
        Returns DER-encoded SubjectPublicKeyInfo when 'cryptography' is available, else None.
        """
        if not _HAS_CRYPTO:
            return None
        key_id = _normalize_key_id(self.vault_url, name_or_id, version)
        cache_key = f"spki:{key_id}"
        cached = self._key_cache.get(cache_key)
        if cached:
            return cached
        kvk = self._get_key(key_id)
        spki: Optional[bytes] = None
        if kvk.key_type and "RSA" in str(kvk.key_type).upper():
            pub = rsa.RSAPublicNumbers(
                e=int.from_bytes(kvk.key.e, "big"),
                n=int.from_bytes(kvk.key.n, "big"),
            ).public_key()
            spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        elif kvk.key_type and "EC" in str(kvk.key_type).upper():
            curve_map = {
                "P-256": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "P-521": ec.SECP521R1(),
            }
            crv = curve_map.get(str(kvk.key.crv))
            if crv:
                pub = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(kvk.key.x, "big"),
                    int.from_bytes(kvk.key.y, "big"),
                    crv
                ).public_key()
                spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        elif kvk.key_type and "OKP" in str(kvk.key_type).upper():
            pub = ed25519.Ed25519PublicKey.from_public_bytes(kvk.key.x)
            spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if spki:
            self._key_cache.set(cache_key, spki)
        return spki

    # --------- Internals ---------

    def _get_key(self, key_id: str):
        cached = self._key_cache.get(key_id)
        if cached:
            return cached
        for delay in _backoff_attempts(self.retry_attempts):
            try:
                if _is_key_id(key_id):
                    # extract name/version from id
                    parts = key_id.split("/keys/")[1].split("/")
                    name = parts[0]
                    version = parts[1] if len(parts) > 1 else None
                else:
                    name, version = key_id, None
                kvk = self._key_client.get_key(name, version=version)
                self._key_cache.set(key_id, kvk)
                return kvk
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
                time.sleep(delay)
        raise KmsUnavailable("Get key failed after retries")

    def _crypto_client(self, key_id: str) -> CryptographyClient:
        cached = self._crypto_cache.get(key_id)
        if cached:
            return cached  # type: ignore[return-value]
        with self._lock:
            cached = self._crypto_cache.get(key_id)
            if cached:
                return cached  # type: ignore[return-value]
            client = CryptographyClient(key_id, credential=self._cred)
            self._crypto_cache.set(key_id, client)
            return client

    def _require_key_id(self, name_or_id: str) -> str:
        if not name_or_id:
            raise KmsInvalidArgument("Key identifier is required")
        return _normalize_key_id(self.vault_url, name_or_id)

    @staticmethod
    def _sig_alg(alg: SigAlg) -> Any:
        m = _SIG_MAP.get(alg.lower())
        if not m:
            raise KmsInvalidArgument(f"Unsupported signature algorithm: {alg}")
        # Azure SDK accepts string or enum; return string for compatibility
        return m

    @staticmethod
    def _enc_alg(alg: EncAlg) -> Any:
        m = _ENC_MAP.get(alg.lower())
        if not m:
            raise KmsInvalidArgument(f"Unsupported encryption algorithm: {alg}")
        return m

    @staticmethod
    def _wrap_alg(alg: WrapAlg) -> Any:
        m = _WRAP_MAP.get(alg.lower())
        if not m:
            raise KmsInvalidArgument(f"Unsupported key wrap algorithm: {alg}")
        return m


# =========================
# AzureKeyVaultKMSAsync (asyncio)
# =========================

class AzureKeyVaultKMSAsync:
    def __init__(
        self,
        vault_url: str,
        credential: Any = None,
        user_agent_suffix: str = "security-core/azure-kv",
        cache_ttl_seconds: int = 300,
        crypto_cache_ttl_seconds: int = 1800,
        retry_attempts: int = 4,
    ) -> None:
        if AioKeyClient is None or AioDefaultAzureCredential is None:
            raise KmsError("Azure async SDK not available. Install azure-identity and azure-keyvault-keys >= 4.x.")
        self.vault_url = vault_url
        self._cred = credential or AioDefaultAzureCredential()
        self._key_client = AioKeyClient(self.vault_url, credential=self._cred, user_agent=user_agent_suffix)
        self._key_cache = _TTLCache(cache_ttl_seconds, 4096)
        self._jwk_cache = _TTLCache(cache_ttl_seconds, 4096)
        self._crypto_cache = _TTLCache(crypto_cache_ttl_seconds, 4096)
        self._lock = threading.RLock()
        self._retry_attempts = retry_attempts

    async def close(self) -> None:
        try:
            await self._key_client.close()
            await self._cred.close()
        except Exception:
            pass

    # -------- operations --------

    async def sign(self, key: str, algorithm: SigAlg, data: bytes, *, prehashed: bool = False) -> bytes:
        key_id = _normalize_key_id(self.vault_url, key)
        alg = AzureKeyVaultKMS._sig_alg(algorithm)
        crypto = await self._crypto_client(key_id)
        async for _ in self._retriable():
            try:
                if hasattr(crypto, "sign_data") and not prehashed:
                    res = await crypto.sign_data(alg, data)  # type: ignore[attr-defined]
                else:
                    res = await crypto.sign(alg, data)
                return bytes(res.signature)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
        raise KmsUnavailable("Signing failed after retries")

    async def verify(self, key: str, algorithm: SigAlg, data: bytes, signature: bytes, *, prehashed: bool = False) -> bool:
        key_id = _normalize_key_id(self.vault_url, key)
        alg = AzureKeyVaultKMS._sig_alg(algorithm)
        crypto = await self._crypto_client(key_id)
        async for _ in self._retriable():
            try:
                if hasattr(crypto, "verify_data") and not prehashed:
                    res = await crypto.verify_data(alg, data, signature)  # type: ignore[attr-defined]
                else:
                    res = await crypto.verify(alg, data, signature)
                return bool(res.is_valid)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
        raise KmsUnavailable("Verify failed after retries")

    async def encrypt(self, key: str, algorithm: EncAlg, plaintext: bytes, *, aad: Optional[bytes] = None) -> Tuple[str, bytes, Optional[bytes]]:
        key_id = _normalize_key_id(self.vault_url, key)
        alg = AzureKeyVaultKMS._enc_alg(algorithm)
        crypto = await self._crypto_client(key_id)
        async for _ in self._retriable():
            try:
                if aad is not None and alg.endswith("GCM"):
                    res = await crypto.encrypt(alg, plaintext, additional_authenticated_data=aad)
                else:
                    res = await crypto.encrypt(alg, plaintext)
                return alg, bytes(res.ciphertext), getattr(res, "authentication_tag", None)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
        raise KmsUnavailable("Encrypt failed after retries")

    async def decrypt(self, key: str, algorithm: EncAlg, ciphertext: bytes, *, aad: Optional[bytes] = None, auth_tag: Optional[bytes] = None) -> bytes:
        key_id = _normalize_key_id(self.vault_url, key)
        alg = AzureKeyVaultKMS._enc_alg(algorithm)
        crypto = await self._crypto_client(key_id)
        async for _ in self._retriable():
            try:
                kwargs = {}
                if aad is not None and alg.endswith("GCM"):
                    kwargs["additional_authenticated_data"] = aad
                if auth_tag is not None and alg.endswith("GCM"):
                    kwargs["authentication_tag"] = auth_tag
                res = await crypto.decrypt(alg, ciphertext, **kwargs)
                return bytes(res.plaintext)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
        raise KmsUnavailable("Decrypt failed after retries")

    async def wrap_key(self, key: str, algorithm: WrapAlg, cek: bytes) -> Tuple[str, bytes]:
        key_id = _normalize_key_id(self.vault_url, key)
        alg = AzureKeyVaultKMS._wrap_alg(algorithm)
        crypto = await self._crypto_client(key_id)
        async for _ in self._retriable():
            try:
                res = await crypto.wrap_key(alg, cek)
                return alg, bytes(res.encrypted_key)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
        raise KmsUnavailable("Wrap failed after retries")

    async def unwrap_key(self, key: str, algorithm: WrapAlg, wrapped: bytes) -> bytes:
        key_id = _normalize_key_id(self.vault_url, key)
        alg = AzureKeyVaultKMS._wrap_alg(algorithm)
        crypto = await self._crypto_client(key_id)
        async for _ in self._retriable():
            try:
                res = await crypto.unwrap_key(alg, wrapped)
                return bytes(res.key)
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
        raise KmsUnavailable("Unwrap failed after retries")

    async def get_public_jwk(self, name_or_id: str, *, version: Optional[str] = None) -> Dict[str, Any]:
        key_id = _normalize_key_id(self.vault_url, name_or_id, version)
        cached = self._jwk_cache.get(key_id)
        if cached:
            return cached
        kvk = await self._get_key(key_id)
        jwk: Dict[str, Any] = {"kid": kvk.id, "kty": kvk.key_type}
        if hasattr(kvk, "key") and getattr(kvk.key, "n", None) is not None:
            jwk.update({"n": _b64u(kvk.key.n), "e": _b64u(kvk.key.e)})
        if hasattr(kvk, "key") and getattr(kvk.key, "x", None) is not None:
            # EC/OKP share x; add y/crv when present
            if getattr(kvk.key, "y", None) is not None:
                jwk.update({"crv": kvk.key.crv, "x": _b64u(kvk.key.x), "y": _b64u(kvk.key.y)})
            else:
                jwk.update({"crv": getattr(kvk.key, "crv", "Ed25519"), "x": _b64u(kvk.key.x)})
        self._jwk_cache.set(key_id, jwk)
        return jwk

    async def get_public_spki(self, name_or_id: str, *, version: Optional[str] = None) -> Optional[bytes]:
        if not _HAS_CRYPTO:
            return None
        key_id = _normalize_key_id(self.vault_url, name_or_id, version)
        cache_key = f"spki:{key_id}"
        cached = self._key_cache.get(cache_key)
        if cached:
            return cached
        kvk = await self._get_key(key_id)
        # Reuse sync SPKI logic by constructing numbers if possible
        try:
            if kvk.key_type and "RSA" in str(kvk.key_type).upper():
                pub = rsa.RSAPublicNumbers(
                    e=int.from_bytes(kvk.key.e, "big"),
                    n=int.from_bytes(kvk.key.n, "big"),
                ).public_key()
                spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            elif kvk.key_type and "EC" in str(kvk.key_type).upper():
                curve_map = {
                    "P-256": ec.SECP256R1(),
                    "P-384": ec.SECP384R1(),
                    "P-521": ec.SECP521R1(),
                }
                crv = curve_map.get(str(kvk.key.crv))
                if not crv:
                    return None
                pub = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(kvk.key.x, "big"),
                    int.from_bytes(kvk.key.y, "big"),
                    crv
                ).public_key()
                spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            elif kvk.key_type and "OKP" in str(kvk.key_type).upper():
                pub = ed25519.Ed25519PublicKey.from_public_bytes(kvk.key.x)
                spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            else:
                return None
            self._key_cache.set(cache_key, spki)
            return spki
        except Exception:
            return None

    # -------- internals --------

    async def _get_key(self, key_id: str):
        cached = self._key_cache.get(key_id)
        if cached:
            return cached
        async for _ in self._retriable():
            try:
                if _is_key_id(key_id):
                    parts = key_id.split("/keys/")[1].split("/")
                    name = parts[0]
                    version = parts[1] if len(parts) > 1 else None
                else:
                    name, version = key_id, None
                kvk = await self._key_client.get_key(name, version=version)
                self._key_cache.set(key_id, kvk)
                return kvk
            except Exception as e:
                if not _retryable(e):
                    raise _translate_error(e)
        raise KmsUnavailable("Get key failed after retries")

    async def _crypto_client(self, key_id: str) -> AioCryptographyClient:  # type: ignore[valid-type]
        cached = self._crypto_cache.get(key_id)
        if cached:
            return cached  # type: ignore[return-value]
        with self._lock:
            cached = self._crypto_cache.get(key_id)
            if cached:
                return cached  # type: ignore[return-value]
            client = AioCryptographyClient(key_id, credential=self._cred)  # type: ignore[call-arg]
            self._crypto_cache.set(key_id, client)
            return client

    def _retriable(self):
        # Async generator yielding attempts with backoff sleeps
        async def gen():
            for delay in _backoff_attempts(self._retry_attempts):
                if delay:
                    await self._sleep(delay)
                yield True
        return gen()

    @staticmethod
    async def _sleep(seconds: float) -> None:
        try:
            import asyncio
            await asyncio.sleep(seconds)
        except Exception:
            time.sleep(seconds)


# =========================
# Minimal self-check (optional)
# =========================

if __name__ == "__main__":
    # This block is a non-executed placeholder in production deployments.
    # It documents expected usage without side effects.
    """
    Example (sync):
        kms = AzureKeyVaultKMS(vault_url="https://myvault.vault.azure.net")
        kid = "my-signing-key"  # or full key id
        sig = kms.sign(kid, "ps256", b"message", prehashed=False)
        ok = kms.verify(kid, "ps256", b"message", sig)

    Example (async):
        import asyncio
        async def main():
            kms = AzureKeyVaultKMSAsync(vault_url="https://myvault.vault.azure.net")
            sig = await kms.sign("my-key", "es256", b"data")
            await kms.close()
        asyncio.run(main())
    """
    pass
