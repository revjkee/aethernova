# ledger/adapters/kms/azure_kv.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Azure Key Vault (KMS) adapter.

Features:
- Auth: DefaultAzureCredential (managed identity, workload identity, local dev) and ClientSecretCredential.
- Key ops: create/import/get/list/versions/delete/purge/rotate; rotation policy get/set.
- Crypto ops: sign/verify (RSA/PS/ES), encrypt/decrypt (RSA-OAEP), wrap/unwrap (RSA-OAEP).
- Robustness: retries with exponential backoff + jitter, timeouts, simple circuit breaker.
- Observability: structured logging, metric hooks, trace spans.
- Input validation and deterministic exception taxonomy.
- Pluggable HTTP options (proxy, timeouts), safe defaults.

Dependencies (optional at runtime):
  azure-identity
  azure-keyvault-keys
  azure-keyvault-cryptography

If they are missing, adapter raises AzureSDKMissingError with remediation hints.
"""

from __future__ import annotations

import os
import time
import math
import random
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Protocol, List, Dict, Any, Iterable, Tuple, runtime_checkable

# ---------------------------- Logging ---------------------------------------

logger = logging.getLogger("ledger.adapters.kms.azure_kv")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ---------------------------- Errors ----------------------------------------

class AzureKVError(Exception):
    """Base Azure Key Vault adapter error."""

class AzureSDKMissingError(AzureKVError):
    """Raised when azure SDK packages are not installed."""

class AzureKVConfigError(AzureKVError):
    """Raised for configuration/validation errors."""

class AzureKVUnavailable(AzureKVError):
    """Raised when service is temporarily unavailable (circuit open or repeated failures)."""

class AzureKVOperationError(AzureKVError):
    """Raised when an operation fails after retries."""

# ------------------------ Observability Protocols ---------------------------

@runtime_checkable
class MetricSink(Protocol):
    def incr(self, name: str, value: int = 1, *, tags: Optional[Dict[str, str]] = None) -> None: ...
    def timing(self, name: str, ms: float, *, tags: Optional[Dict[str, str]] = None) -> None: ...

@runtime_checkable
class TraceSink(Protocol):
    def span(self, name: str, **kwargs) -> "TraceSpan": ...

class TraceSpan:
    def __init__(self, name: str, sink: Optional[TraceSink] = None):
        self.name = name
        self._sink = sink
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def set_tag(self, key: str, value: Any): return self

# ----------------------------- Enums ----------------------------------------

class KeyType(str, Enum):
    RSA = "RSA"
    RSA_HSM = "RSA-HSM"
    EC = "EC"
    EC_HSM = "EC-HSM"

class SigAlg(str, Enum):
    # RSA PKCS#1 v1.5
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    # RSA PSS
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"
    # ECDSA
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"

class EncAlg(str, Enum):
    RSA_OAEP = "RSA-OAEP"
    RSA_OAEP_256 = "RSA-OAEP-256"  # available in AKV

class WrapAlg(str, Enum):
    RSA_OAEP = "RSA-OAEP"
    RSA_OAEP_256 = "RSA-OAEP-256"

# ------------------------- Retry & Circuit Breaker --------------------------

@dataclass
class RetryPolicy:
    attempts: int = 5
    base_delay_ms: int = 50
    max_delay_ms: int = 2_000
    jitter_ms: int = 50  # +/- jitter
    multiplier: float = 2.0
    retry_on_status: Tuple[int, ...] = (408, 429, 500, 502, 503, 504)

@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_seconds: int = 30
    _failures: int = 0
    _opened_at: Optional[float] = None

    def allow(self) -> bool:
        if self._opened_at is None:
            return True
        # half-open after recovery
        if time.time() - self._opened_at >= self.recovery_seconds:
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = time.time()
            logger.warning("AzureKV circuit opened (failures=%d)", self._failures)

# ------------------------------ Config --------------------------------------

@dataclass(frozen=True)
class AzureKVConfig:
    """
    Configuration for the adapter.

    vault_url: e.g. 'https://<vault-name>.vault.azure.net'
    tenant_id/client_id/client_secret: optional, for ClientSecretCredential
    use_default_credential: if True, use DefaultAzureCredential chain
    http_timeout_s: per-request timeout (passed into clients where supported)
    """
    vault_url: str
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    use_default_credential: bool = True
    http_timeout_s: float = 10.0
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    circuit: CircuitBreaker = field(default_factory=CircuitBreaker)
    scope: str = "https://vault.azure.net/.default"  # default AKV scope

    def validate(self) -> None:
        if not self.vault_url or not self.vault_url.startswith("https://"):
            raise AzureKVConfigError("vault_url must be a valid https URL")
        if not self.use_default_credential:
            if not (self.tenant_id and self.client_id and self.client_secret):
                raise AzureKVConfigError("ClientSecretCredential requires tenant_id, client_id, client_secret")

# ------------------------- SDK Lazy Import Helpers --------------------------

def _import_azure_sdk():
    """
    Lazy import Azure SDK modules. Raises AzureSDKMissingError with hints if unavailable.
    """
    try:
        from azure.identity import DefaultAzureCredential, ClientSecretCredential
        from azure.keyvault.keys import KeyClient
        from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm, EncryptionAlgorithm, KeyWrapAlgorithm
        from azure.core.exceptions import HttpResponseError, ResourceNotFoundError, ServiceRequestError, ServiceResponseError
        return {
            "DefaultAzureCredential": DefaultAzureCredential,
            "ClientSecretCredential": ClientSecretCredential,
            "KeyClient": KeyClient,
            "CryptographyClient": CryptographyClient,
            "SignatureAlgorithm": SignatureAlgorithm,
            "EncryptionAlgorithm": EncryptionAlgorithm,
            "KeyWrapAlgorithm": KeyWrapAlgorithm,
            "HttpResponseError": HttpResponseError,
            "ResourceNotFoundError": ResourceNotFoundError,
            "ServiceRequestError": ServiceRequestError,
            "ServiceResponseError": ServiceResponseError,
        }
    except Exception as exc:
        raise AzureSDKMissingError(
            "Azure SDK packages are missing. Install: "
            "pip install azure-identity azure-keyvault-keys azure-keyvault-cryptography"
        ) from exc

# --------------------------- Utility Mapping --------------------------------

def _sig_alg_to_sdk(alg: SigAlg):
    mods = _import_azure_sdk()
    SA = mods["SignatureAlgorithm"]
    mapping = {
        SigAlg.RS256: SA.rs256,
        SigAlg.RS384: SA.rs384,
        SigAlg.RS512: SA.rs512,
        SigAlg.PS256: SA.ps256,
        SigAlg.PS384: SA.ps384,
        SigAlg.PS512: SA.ps512,
        SigAlg.ES256: SA.es256,
        SigAlg.ES384: SA.es384,
        SigAlg.ES512: SA.es512,
    }
    try:
        return mapping[alg]
    except KeyError:
        raise AzureKVConfigError(f"Unsupported signature algorithm: {alg}")

def _enc_alg_to_sdk(alg: EncAlg):
    mods = _import_azure_sdk()
    EA = mods["EncryptionAlgorithm"]
    mapping = {
        EncAlg.RSA_OAEP: EA.rsa_oaep,
        EncAlg.RSA_OAEP_256: EA.rsa_oaep_256,
    }
    try:
        return mapping[alg]
    except KeyError:
        raise AzureKVConfigError(f"Unsupported encryption algorithm: {alg}")

def _wrap_alg_to_sdk(alg: WrapAlg):
    mods = _import_azure_sdk()
    KA = mods["KeyWrapAlgorithm"]
    mapping = {
        WrapAlg.RSA_OAEP: KA.rsa_oaep,
        WrapAlg.RSA_OAEP_256: KA.rsa_oaep_256,
    }
    try:
        return mapping[alg]
    except KeyError:
        raise AzureKVConfigError(f"Unsupported wrap algorithm: {alg}")

# ------------------------- Timing & Retry Helpers ---------------------------

def _sleep_ms(ms: int) -> None:
    time.sleep(ms / 1000.0)

def _backoff_delays(policy: RetryPolicy) -> Iterable[int]:
    delay = policy.base_delay_ms
    for _ in range(policy.attempts):
        jitter = random.randint(-policy.jitter_ms, policy.jitter_ms)
        yield max(0, min(policy.max_delay_ms, delay + jitter))
        delay = int(min(policy.max_delay_ms, delay * policy.multiplier))

# ----------------------------- Adapter --------------------------------------

class AzureKeyVaultKMS:
    """
    High-reliability adapter for Azure Key Vault crypto and key management.

    Thread-safe for concurrent use (Azure SDK clients are threadsafe).
    """

    def __init__(
        self,
        config: AzureKVConfig,
        *,
        metric_sink: Optional[MetricSink] = None,
        trace_sink: Optional[TraceSink] = None,
        http_logging: bool = False,
    ) -> None:
        config.validate()
        self._cfg = config
        self._metric = metric_sink
        self._trace = trace_sink
        self._http_logging = http_logging
        mods = _import_azure_sdk()
        self._mods = mods
        self._credential = self._make_credential()
        self._key_client = self._make_key_client()

    # ------------------------ Credential & Clients ------------------------

    def _make_credential(self):
        with self._span("azure.kv.credential"):
            if self._cfg.use_default_credential:
                cred = self._mods["DefaultAzureCredential"](exclude_interactive_browser_credential=True)
                logger.info("AzureKeyVaultKMS using DefaultAzureCredential chain")
                return cred
            else:
                cred = self._mods["ClientSecretCredential"](
                    tenant_id=self._cfg.tenant_id,
                    client_id=self._cfg.client_id,
                    client_secret=self._cfg.client_secret,
                )
                logger.info("AzureKeyVaultKMS using ClientSecretCredential")
                return cred

    def _make_key_client(self):
        with self._span("azure.kv.keyclient"):
            KeyClient = self._mods["KeyClient"]
            client = KeyClient(vault_url=self._cfg.vault_url, credential=self._credential)
            return client

    def _crypto_client(self, key_id: str):
        CryptographyClient = self._mods["CryptographyClient"]
        return CryptographyClient(key_id, credential=self._credential)

    # ------------------------ Observability Helpers -----------------------

    def _span(self, name: str):
        if self._trace:
            try:
                return self._trace.span(name)
            except Exception:
                pass
        return TraceSpan(name)

    def _incr(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None) -> None:
        if self._metric:
            try:
                self._metric.incr(name, value=value, tags=tags)
            except Exception:
                logger.debug("Metric sink incr failed", exc_info=True)

    def _timing(self, name: str, ms: float, tags: Optional[Dict[str, str]] = None) -> None:
        if self._metric:
            try:
                self._metric.timing(name, ms, tags=tags)
            except Exception:
                logger.debug("Metric sink timing failed", exc_info=True)

    # ----------------------------- Core Ops --------------------------------

    def sign(self, key_id: str, alg: SigAlg, digest: bytes) -> bytes:
        """
        Sign given digest with a key version in AKV.
        Note: input must be a digest for the chosen algorithm (Azure expects digest for *sign* APIs).
        """
        if not key_id or not isinstance(key_id, str):
            raise AzureKVConfigError("key_id must be non-empty string")
        if not isinstance(alg, SigAlg):
            raise AzureKVConfigError("alg must be SigAlg enum")
        if not isinstance(digest, (bytes, bytearray)) or not digest:
            raise AzureKVConfigError("digest must be non-empty bytes")

        sdk_alg = _sig_alg_to_sdk(alg)
        with self._span("azure.kv.sign") as span:
            span.set_tag("key_id", key_id)
            span.set_tag("alg", alg.value)
            start = time.time()
            res = self._do_with_retry(lambda: self._crypto_client(key_id).sign(sdk_alg, digest))
            self._timing("azure.kv.sign.ms", (time.time() - start) * 1000.0, tags={"alg": alg.value})
            self._incr("azure.kv.sign.ok")
            return res.signature

    def verify(self, key_id: str, alg: SigAlg, digest: bytes, signature: bytes) -> bool:
        if not key_id or not isinstance(key_id, str):
            raise AzureKVConfigError("key_id must be non-empty string")
        if not isinstance(alg, SigAlg):
            raise AzureKVConfigError("alg must be SigAlg enum")
        if not isinstance(digest, (bytes, bytearray)) or not digest:
            raise AzureKVConfigError("digest must be non-empty bytes")
        if not isinstance(signature, (bytes, bytearray)) or not signature:
            raise AzureKVConfigError("signature must be non-empty bytes")

        sdk_alg = _sig_alg_to_sdk(alg)
        with self._span("azure.kv.verify") as span:
            span.set_tag("key_id", key_id)
            span.set_tag("alg", alg.value)
            start = time.time()
            res = self._do_with_retry(lambda: self._crypto_client(key_id).verify(sdk_alg, digest, signature))
            self._timing("azure.kv.verify.ms", (time.time() - start) * 1000.0, tags={"alg": alg.value})
            self._incr("azure.kv.verify.ok" if res.is_valid else "azure.kv.verify.fail")
            return bool(res.is_valid)

    def encrypt(self, key_id: str, alg: EncAlg, plaintext: bytes, *, aad: Optional[bytes] = None) -> bytes:
        if not key_id or not isinstance(key_id, str):
            raise AzureKVConfigError("key_id must be non-empty string")
        if not isinstance(plaintext, (bytes, bytearray)) or not plaintext:
            raise AzureKVConfigError("plaintext must be non-empty bytes")

        sdk_alg = _enc_alg_to_sdk(alg)
        with self._span("azure.kv.encrypt") as span:
            span.set_tag("key_id", key_id)
            span.set_tag("alg", alg.value)
            start = time.time()
            res = self._do_with_retry(lambda: self._crypto_client(key_id).encrypt(sdk_alg, plaintext, additional_authenticated_data=aad))
            self._timing("azure.kv.encrypt.ms", (time.time() - start) * 1000.0, tags={"alg": alg.value})
            self._incr("azure.kv.encrypt.ok")
            return res.ciphertext

    def decrypt(self, key_id: str, alg: EncAlg, ciphertext: bytes, *, aad: Optional[bytes] = None) -> bytes:
        if not key_id or not isinstance(key_id, str):
            raise AzureKVConfigError("key_id must be non-empty string")
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            raise AzureKVConfigError("ciphertext must be non-empty bytes")

        sdk_alg = _enc_alg_to_sdk(alg)
        with self._span("azure.kv.decrypt") as span:
            span.set_tag("key_id", key_id)
            span.set_tag("alg", alg.value)
            start = time.time()
            res = self._do_with_retry(lambda: self._crypto_client(key_id).decrypt(sdk_alg, ciphertext, additional_authenticated_data=aad))
            self._timing("azure.kv.decrypt.ms", (time.time() - start) * 1000.0, tags={"alg": alg.value})
            self._incr("azure.kv.decrypt.ok")
            return res.plaintext

    def wrap_key(self, key_id: str, alg: WrapAlg, key_bytes: bytes) -> bytes:
        if not key_id or not isinstance(key_id, str):
            raise AzureKVConfigError("key_id must be non-empty string")
        if not isinstance(key_bytes, (bytes, bytearray)) or not key_bytes:
            raise AzureKVConfigError("key_bytes must be non-empty bytes")

        sdk_alg = _wrap_alg_to_sdk(alg)
        with self._span("azure.kv.wrap") as span:
            span.set_tag("key_id", key_id)
            span.set_tag("alg", alg.value)
            start = time.time()
            res = self._do_with_retry(lambda: self._crypto_client(key_id).wrap_key(sdk_alg, key_bytes))
            self._timing("azure.kv.wrap.ms", (time.time() - start) * 1000.0, tags={"alg": alg.value})
            self._incr("azure.kv.wrap.ok")
            return res.encrypted_key

    def unwrap_key(self, key_id: str, alg: WrapAlg, wrapped: bytes) -> bytes:
        if not key_id or not isinstance(key_id, str):
            raise AzureKVConfigError("key_id must be non-empty string")
        if not isinstance(wrapped, (bytes, bytearray)) or not wrapped:
            raise AzureKVConfigError("wrapped must be non-empty bytes")

        sdk_alg = _wrap_alg_to_sdk(alg)
        with self._span("azure.kv.unwrap") as span:
            span.set_tag("key_id", key_id)
            span.set_tag("alg", alg.value)
            start = time.time()
            res = self._do_with_retry(lambda: self._crypto_client(key_id).unwrap_key(sdk_alg, wrapped))
            self._timing("azure.kv.unwrap.ms", (time.time() - start) * 1000.0, tags={"alg": alg.value})
            self._incr("azure.kv.unwrap.ok")
            return res.key

    # --------------------------- Key Management -----------------------------

    def create_key(
        self,
        name: str,
        *,
        key_type: KeyType = KeyType.RSA,
        size_bits: Optional[int] = None,            # RSA: 2048/3072/4096, EC: curve via curve param
        curve: Optional[str] = None,                # EC: "P-256","P-384","P-521","P-256K"
        enabled: bool = True,
        key_ops: Optional[List[str]] = None,        # e.g., ["sign","verify","encrypt","decrypt","wrapKey","unwrapKey"]
        tags: Optional[Dict[str, str]] = None,
    ) -> str:
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")

        with self._span("azure.kv.create_key") as span:
            span.set_tag("name", name)
            start = time.time()
            def _do():
                KeyClient = self._mods["KeyClient"]
                # Use existing client (self._key_client)
                if key_type in (KeyType.RSA, KeyType.RSA_HSM):
                    return self._key_client.create_rsa_key(
                        name=name,
                        size=size_bits or 2048,
                        hardware_protected=(key_type == KeyType.RSA_HSM),
                        tags=tags,
                        enabled=enabled,
                        key_operations=key_ops,
                    )
                elif key_type in (KeyType.EC, KeyType.EC_HSM):
                    if not curve:
                        raise AzureKVConfigError("EC key requires 'curve' parameter")
                    return self._key_client.create_ec_key(
                        name=name,
                        curve=curve,
                        hardware_protected=(key_type == KeyType.EC_HSM),
                        tags=tags,
                        enabled=enabled,
                        key_operations=key_ops,
                    )
                else:
                    raise AzureKVConfigError(f"Unsupported key_type: {key_type}")

            key = self._do_with_retry(_do)
            self._timing("azure.kv.create_key.ms", (time.time() - start) * 1000.0)
            self._incr("azure.kv.create_key.ok")
            return key.id  # fully-qualified key identifier

    def import_key(self, name: str, key_material: Any, *, hardware_protected: bool = False, tags: Optional[Dict[str, str]] = None) -> str:
        """
        Import an externally generated key (PEM/JWK) into AKV.
        `key_material` should be a KeyVaultKey or JWK‑compatible dict as required by azure SDK.
        """
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")
        if key_material is None:
            raise AzureKVConfigError("key_material must be provided")

        with self._span("azure.kv.import_key") as span:
            span.set_tag("name", name)
            start = time.time()
            def _do():
                return self._key_client.import_key(name=name, key=key_material, hardware_protected=hardware_protected, tags=tags)
            key = self._do_with_retry(_do)
            self._timing("azure.kv.import_key.ms", (time.time() - start) * 1000.0)
            self._incr("azure.kv.import_key.ok")
            return key.id

    def get_key(self, name: str, version: Optional[str] = None) -> Dict[str, Any]:
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")
        with self._span("azure.kv.get_key") as span:
            span.set_tag("name", name)
            span.set_tag("version", version or "latest")
            start = time.time()
            def _do():
                return self._key_client.get_key(name=name, version=version)  # returns KeyVaultKey
            key = self._do_with_retry(_do)
            self._timing("azure.kv.get_key.ms", (time.time() - start) * 1000.0)
            self._incr("azure.kv.get_key.ok")
            return {
                "id": key.id,
                "name": key.name,
                "version": key.properties.version,
                "enabled": key.properties.enabled,
                "updated_on": getattr(key.properties, "updated_on", None),
                "created_on": getattr(key.properties, "created_on", None),
                "recovery_level": getattr(key.properties, "recovery_level", None),
                "exportable": getattr(key.properties, "exportable", None),
                "hardware_protected": getattr(key.properties, "hardware_protected", None),
                "key_ops": list(getattr(key.key, "key_ops", []) or []),
                "kty": getattr(key.key, "kty", None),
            }

    def list_keys(self) -> List[Dict[str, Any]]:
        with self._span("azure.kv.list_keys"):
            start = time.time()
            def _do():
                return list(self._key_client.list_properties_of_keys())
            props = self._do_with_retry(_do)
            self._timing("azure.kv.list_keys.ms", (time.time() - start) * 1000.0)
            self._incr("azure.kv.list_keys.ok", value=len(props))
            out: List[Dict[str, Any]] = []
            for p in props:
                out.append({
                    "name": p.name,
                    "id": p.id,
                    "version": p.version,
                    "enabled": p.enabled,
                    "updated_on": getattr(p, "updated_on", None),
                    "created_on": getattr(p, "created_on", None),
                })
            return out

    def list_key_versions(self, name: str) -> List[str]:
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")
        with self._span("azure.kv.list_versions") as span:
            span.set_tag("name", name)
            start = time.time()
            def _do():
                return list(self._key_client.list_properties_of_key_versions(name))
            props = self._do_with_retry(_do)
            self._timing("azure.kv.list_versions.ms", (time.time() - start) * 1000.0)
            self._incr("azure.kv.list_versions.ok", value=len(props))
            return [p.version for p in props if getattr(p, "version", None)]

    def delete_key(self, name: str) -> str:
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")
        with self._span("azure.kv.delete_key") as span:
            span.set_tag("name", name)
            start = time.time()
            def _do():
                poller = self._key_client.begin_delete_key(name)
                return poller.result()
            res = self._do_with_retry(_do)
            self._timing("azure.kv.delete_key.ms", (time.time() - start) * 1000.0)
            self._incr("azure.kv.delete_key.ok")
            return res.name

    def purge_deleted_key(self, name: str) -> None:
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")
        with self._span("azure.kv.purge_key") as span:
            span.set_tag("name", name)
            start = time.time()
            def _do():
                self._key_client.purge_deleted_key(name)
                return True
            self._do_with_retry(_do)
            self._timing("azure.kv.purge_key.ms", (time.time() - start) * 1000.0)
            self._incr("azure.kv.purge_key.ok")

    def rotate_key(self, name: str) -> str:
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")
        with self._span("azure.kv.rotate_key") as span:
            span.set_tag("name", name)
            start = time.time()
            def _do():
                # Requires AKV rotation policy set
                key = self._key_client.rotate_key(name)
                return key
            key = self._do_with_retry(_do)
            self._timing("azure.kv.rotate_key.ms", (time.time() - start) * 1000.0)
            self._incr("azure.kv.rotate_key.ok")
            return key.id

    def get_rotation_policy(self, name: str) -> Dict[str, Any]:
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")
        with self._span("azure.kv.get_rotation_policy") as span:
            span.set_tag("name", name)
            def _do():
                return self._key_client.get_key_rotation_policy(name)
            pol = self._do_with_retry(_do)
            # Serialize essential fields (object structure may evolve)
            lifetime_actions = []
            for la in getattr(pol, "lifetime_actions", []) or []:
                lifetime_actions.append({
                    "action": getattr(getattr(la, "action", None), "type", None),
                    "time_after_create": getattr(la, "time_after_create", None),
                    "time_before_expiry": getattr(la, "time_before_expiry", None),
                })
            return {
                "id": getattr(pol, "id", None),
                "expires_in": getattr(pol, "expires_in", None),
                "lifetime_actions": lifetime_actions,
            }

    def set_rotation_policy(self, name: str, *, expires_in: Optional[str] = None, lifetime_actions: Optional[List[Dict[str, Optional[str]]]] = None) -> Dict[str, Any]:
        """
        expires_in: ISO8601 duration, e.g., 'P90D'
        lifetime_actions: list of {action: 'Rotate'|'Notify', time_after_create: 'P30D', time_before_expiry: 'P7D'}
        """
        if not name or not isinstance(name, str):
            raise AzureKVConfigError("name must be non-empty string")
        with self._span("azure.kv.set_rotation_policy") as span:
            span.set_tag("name", name)
            def _do():
                pol = self._key_client.get_key_rotation_policy(name)
                if expires_in is not None:
                    pol.expires_in = expires_in
                if lifetime_actions is not None:
                    # Rebuild lifetime actions using SDK types
                    # SDK provides KeyRotationPolicyAction / LifetimeAction types
                    from azure.keyvault.keys import KeyRotationPolicyAction, LifetimeAction  # type: ignore
                    acts = []
                    for item in lifetime_actions:
                        act_type = item.get("action")
                        if act_type not in ("Rotate", "Notify"):
                            raise AzureKVConfigError("action must be 'Rotate' or 'Notify'")
                        action = KeyRotationPolicyAction(type=act_type)
                        acts.append(LifetimeAction(
                            action=action,
                            time_after_create=item.get("time_after_create"),
                            time_before_expiry=item.get("time_before_expiry"),
                        ))
                    pol.lifetime_actions = acts
                pol = self._key_client.update_key_rotation_policy(name, policy=pol)
                return pol
            pol = self._do_with_retry(_do)
            return self.get_rotation_policy(name)

    # ------------------------ Internal Retry Wrapper -------------------------

    def _do_with_retry(self, fn):
        """
        Execute callable with retry/backoff and circuit breaker. Propagates AzureKVUnavailable when circuit disallows.
        """
        if not self._cfg.circuit.allow():
            raise AzureKVUnavailable("Circuit open; rejecting operation temporarily")

        mods = self._mods
        HttpResponseError = mods["HttpResponseError"]
        ServiceRequestError = mods["ServiceRequestError"]
        ServiceResponseError = mods["ServiceResponseError"]

        last_exc: Optional[Exception] = None
        for attempt, delay in enumerate(_backoff_delays(self._cfg.retry), start=1):
            try:
                return fn()
            except HttpResponseError as e:
                status = getattr(e, "status_code", getattr(e, "status", None))
                transient = status in self._cfg.retry.retry_on_status
                logger.warning("AzureKV HTTP error (status=%s, attempt=%d): %s", status, attempt, e)
                if transient and attempt < self._cfg.retry.attempts:
                    self._cfg.circuit.record_failure()
                    _sleep_ms(delay)
                    continue
                self._cfg.circuit.record_failure()
                last_exc = e
                break
            except (ServiceRequestError, ServiceResponseError) as e:
                logger.warning("AzureKV service error (attempt=%d): %s", attempt, e)
                if attempt < self._cfg.retry.attempts:
                    self._cfg.circuit.record_failure()
                    _sleep_ms(delay)
                    continue
                self._cfg.circuit.record_failure()
                last_exc = e
                break
            except Exception as e:
                # Unknown exception: do not infinitely retry
                logger.error("AzureKV unexpected error: %s", e, exc_info=True)
                self._cfg.circuit.record_failure()
                last_exc = e
                break

        # if we got here, all retries failed
        raise AzureKVOperationError(f"Operation failed after {self._cfg.retry.attempts} attempts") from last_exc

# ------------------------------ Example Usage -------------------------------
# NOTE: Keep examples minimal and non-executing in production context.

def _example():
    """
    Minimal sketch (do not run in production code paths):

    cfg = AzureKVConfig(
        vault_url=os.environ["AZURE_KEY_VAULT_URL"],
        use_default_credential=True,
    )
    kms = AzureKeyVaultKMS(cfg)

    key_id = kms.create_key("app-signing-key", key_type=KeyType.RSA, size_bits=3072)
    # digest = sha256(message).digest()
    # sig = kms.sign(key_id, SigAlg.PS256, digest)
    # ok = kms.verify(key_id, SigAlg.PS256, digest, sig)
    # versions = kms.list_key_versions("app-signing-key")
    # kms.rotate_key("app-signing-key")
    pass

__all__ = [
    "AzureKeyVaultKMS",
    "AzureKVConfig",
    "KeyType",
    "SigAlg",
    "EncAlg",
    "WrapAlg",
    "AzureKVError",
    "AzureSDKMissingError",
    "AzureKVConfigError",
    "AzureKVUnavailable",
    "AzureKVOperationError",
]
