# security-core/security/kms/gcp_kms.py
# Промышленный клиент GCP KMS: Encrypt/Decrypt, AsymmetricSign/Verify,
# конвертное шифрование AES-256-GCM + KMS wrap, CRC32C, ретраи/тайм-ауты,
# метрики Prometheus, кэш публичных ключей (TTL), многоарендность.
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Optional, Tuple, Union

# ---- Опциональные зависимости (аккуратные фоллбеки) ----
try:
    from google.cloud import kms_v1
    from google.api_core import retry as g_retry
    from google.api_core import exceptions as g_exceptions
except Exception as e:  # noqa: BLE001
    kms_v1 = None  # type: ignore
    g_retry = None  # type: ignore
    g_exceptions = None  # type: ignore

try:
    import google_crc32c
except Exception:  # noqa: BLE001
    google_crc32c = None  # type: ignore

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography import x509
except Exception as e:  # noqa: BLE001
    AESGCM = None  # type: ignore

try:
    from prometheus_client import Counter, Histogram
except Exception:  # noqa: BLE001
    Counter = Histogram = None  # type: ignore


# =========================
# Исключения и утилиты
# =========================

class KmsError(Exception):
    code: str = "KMS_ERROR"
    def __init__(self, message: str, *, code: Optional[str] = None) -> None:
        super().__init__(message)
        if code:
            self.code = code

class DependencyMissing(KmsError): code = "DEPENDENCY_MISSING"
class NotConfigured(KmsError):     code = "NOT_CONFIGURED"
class IntegrityError(KmsError):    code = "INTEGRITY_ERROR"
class VerifyError(KmsError):       code = "VERIFY_ERROR"
class NotAvailable(KmsError):      code = "NOT_AVAILABLE"

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def crc32c(data: bytes) -> int:
    if google_crc32c:
        return int(google_crc32c.value(data))
    raise DependencyMissing("google-crc32c is required for integrity checks with GCP KMS")

def canonical_json(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


# =========================
# Конфигурация и метрики
# =========================

@dataclass(frozen=True)
class GcpKeyRef:
    # Полный путь: projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}
    # Для асимметричных операций используйте версию: .../cryptoKeyVersions/{v}
    resource: str

    def key_name(self) -> str:
        return self.resource

    def version_name(self, version: Union[str, int]) -> str:
        return f"{self.resource}/cryptoKeyVersions/{version}"

@dataclass
class KmsConfig:
    default_key: Optional[GcpKeyRef] = None
    timeout_seconds: float = 10.0
    # Ретраи только на транзиентные коды
    max_attempts: int = 5
    initial_backoff: float = 0.2
    max_backoff: float = 2.0
    backoff_multiplier: float = 2.0
    user_agent_suffix: Optional[str] = "aethernova-security-core/1.0"
    # Кэш публичных ключей
    public_key_ttl: int = 1800  # сек
    # Метрики
    metrics_enabled: bool = True

# Метрики (опционально)
if Counter and Histogram:
    _KMS_CALLS = Counter("kms_calls_total", "KMS API calls", ["method", "code"])
    _KMS_LAT = Histogram("kms_call_duration_seconds", "KMS call duration", ["method"])
else:
    _KMS_CALLS = _KMS_LAT = None  # type: ignore

logger = logging.getLogger(os.getenv("SERVICE_NAME", "security-core.kms.gcp"))
logger.setLevel(getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO))


# =========================
# Сериализация конверта (envelope)
# =========================

@dataclass
class Envelope:
    v: int
    kid: str              # KMS key resource (symmetric)
    dek_wrapped: str      # b64(ciphertext from KMS.encrypt)
    iv: str               # b64 12 bytes
    aad_hash: str         # b64 sha256(canonical AAD)
    ct: str               # b64 AESGCM ciphertext (ct||tag)
    alg: str = "AES256_GCM"
    created: str = field(default_factory=lambda: now_utc().isoformat())

    def to_json(self) -> str:
        return json.dumps(self.__dict__, ensure_ascii=False, separators=(",", ":"), sort_keys=False)

    @staticmethod
    def from_json(s: Union[str, bytes]) -> "Envelope":
        obj = json.loads(s.decode("utf-8") if isinstance(s, (bytes, bytearray)) else s)
        return Envelope(**obj)


# =========================
# Клиент GCP KMS
# =========================

class GcpKmsClient:
    """
    Безопасный клиент GCP KMS с:
      - ретраями/тайм-аутами;
      - CRC32C контрольными суммами (обязательно для VERIFY_INTEGRITY);
      - конвертным шифрованием AES-256-GCM + KMS wrap;
      - подписью/верификацией асимметричных ключей KMS;
      - кэшем публичных ключей с TTL;
      - потокобезопасностью.
    """

    def __init__(self, config: KmsConfig) -> None:
        self.cfg = config
        if kms_v1 is None:
            raise NotAvailable("google-cloud-kms is not installed")
        client_opts = {}
        # Добавим кастомный user-agent
        if self.cfg.user_agent_suffix:
            client_opts["client_info"] = kms_v1.services.key_management_service.client_info.ClientInfo(
                user_agent=self.cfg.user_agent_suffix
            )
        self._client = kms_v1.KeyManagementServiceClient(**client_opts)
        self._pk_cache: Dict[str, Tuple[bytes, float]] = {}
        self._lock = threading.RLock()

        # Предварительно соберём Retry, если доступно
        if g_retry:
            self._retry = g_retry.Retry(
                predicate=g_retry.if_exception_type(
                    getattr(g_exceptions, "DeadlineExceeded", Exception),
                    getattr(g_exceptions, "ServiceUnavailable", Exception),
                    getattr(g_exceptions, "InternalServerError", Exception),
                    getattr(g_exceptions, "Aborted", Exception),
                ),
                initial=self.cfg.initial_backoff,
                maximum=self.cfg.max_backoff,
                multiplier=self.cfg.backoff_multiplier,
                deadline=self.cfg.timeout_seconds,
            )
        else:
            self._retry = None

    # ---------- Вспомогательные вызовы с метриками ----------
    def _call(self, method: str, func, *args, **kwargs):
        t0 = time.time()
        code = "OK"
        try:
            if self._retry:
                kwargs.setdefault("retry", self._retry)
                kwargs.setdefault("timeout", self.cfg.timeout_seconds)
            result = func(*args, **kwargs)
            return result
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", lambda: "ERR")()
            if hasattr(e, "code") and callable(e.code):  # grpc-style
                try:
                    code = str(e.code().name)
                except Exception:
                    code = "ERR"
            logger.exception("KMS call failed: method=%s code=%s err=%s", method, code, e)
            raise
        finally:
            dur = time.time() - t0
            if _KMS_CALLS and self.cfg.metrics_enabled:
                _KMS_CALLS.labels(method=method, code=code).inc()
            if _KMS_LAT and self.cfg.metrics_enabled:
                _KMS_LAT.labels(method=method).observe(dur)

    # =========================
    # Симметричное шифрование (wrap/unwrap DEK)
    # =========================

    def _encrypt_with_kms(self, key_name: str, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        # CRC32C согласно контракту GCP, проверяем round-trip.
        pt_crc = crc32c(plaintext)
        aad_crc = crc32c(aad or b"")
        req = {
            "name": key_name,
            "plaintext": plaintext,
            "plaintext_crc32c": pt_crc,
        }
        if aad:
            req["additional_authenticated_data"] = aad
            req["additional_authenticated_data_crc32c"] = aad_crc

        resp = self._call("Encrypt", self._client.encrypt, request=req)
        if not resp.verified_plaintext_crc32c:
            raise IntegrityError("KMS did not verify plaintext CRC32C")
        if aad and not resp.verified_additional_authenticated_data_crc32c:
            raise IntegrityError("KMS did not verify AAD CRC32C")
        # Проверим целостность ciphertext по CRC
        if resp.ciphertext_crc32c != crc32c(resp.ciphertext):
            raise IntegrityError("KMS ciphertext CRC32C mismatch")
        return bytes(resp.ciphertext)

    def _decrypt_with_kms(self, key_name: str, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        ct_crc = crc32c(ciphertext)
        aad_crc = crc32c(aad or b"")
        req = {
            "name": key_name,
            "ciphertext": ciphertext,
            "ciphertext_crc32c": ct_crc,
        }
        if aad:
            req["additional_authenticated_data"] = aad
            req["additional_authenticated_data_crc32c"] = aad_crc

        resp = self._call("Decrypt", self._client.decrypt, request=req)
        if resp.plaintext_crc32c != crc32c(resp.plaintext):
            raise IntegrityError("KMS plaintext CRC32C mismatch")
        return bytes(resp.plaintext)

    # =========================
    # Конвертное шифрование AES-256-GCM
    # =========================

    def encrypt_envelope(
        self,
        plaintext: bytes,
        *,
        key: Optional[GcpKeyRef] = None,
        aad: Optional[Mapping[str, Any]] = None,
        iv: Optional[bytes] = None,
    ) -> Envelope:
        """
        Генерирует DEK (32 байта), шифрует plaintext с AES-256-GCM и заворачивает DEK в KMS.
        AAD сериализуется канонически и включается в AES-GCM и KMS AAD.
        """
        if AESGCM is None:
            raise DependencyMissing("cryptography is required for envelope encryption")
        kref = key or self.cfg.default_key
        if not kref:
            raise NotConfigured("default_key is not configured and key is not provided")

        # 1) Сериализуем AAD
        aad_canon = canonical_json(aad or {})
        aad_hash = hashes.Hash(hashes.SHA256())
        aad_hash.update(aad_canon)
        aad_digest = aad_hash.finalize()

        # 2) Сгенерируем DEK
        dek = AESGCM.generate_key(bit_length=256)
        aes = AESGCM(dek)
        if iv is None:
            iv = os.urandom(12)

        # 3) AES-GCM шифрование
        ct = aes.encrypt(iv, plaintext, aad_canon)

        # 4) KMS wrap DEK (Encrypt with symmetric key)
        wrapped = self._encrypt_with_kms(kref.key_name(), dek, aad=aad_canon)

        # 5) Соберём конверт
        env = Envelope(
            v=1,
            kid=kref.key_name(),
            dek_wrapped=b64e(wrapped),
            iv=b64e(iv),
            aad_hash=b64e(aad_digest),
            ct=b64e(ct),
        )
        return env

    def decrypt_envelope(
        self,
        envelope: Union[Envelope, str, bytes, Mapping[str, Any]],
        *,
        aad: Optional[Mapping[str, Any]] = None,
    ) -> bytes:
        """
        Раскрывает конверт: KMS unwrap DEK + AES-256-GCM decrypt.
        Проводит проверку соответствия AAD (sha256).
        """
        if AESGCM is None:
            raise DependencyMissing("cryptography is required for envelope decryption")

        env = envelope
        if isinstance(envelope, (str, bytes, bytearray)):
            env = Envelope.from_json(envelope)
        elif isinstance(envelope, Mapping):
            env = Envelope(**envelope)  # type: ignore[arg-type]
        assert isinstance(env, Envelope)

        # Проверим AAD‑хэш
        aad_canon = canonical_json(aad or {})
        h = hashes.Hash(hashes.SHA256()); h.update(aad_canon)
        digest = h.finalize()
        if b64e(digest) != env.aad_hash:
            raise IntegrityError("AAD hash mismatch; wrong or missing AAD for envelope")

        # Unwrap DEK через KMS
        dek = self._decrypt_with_kms(env.kid, b64d(env.dek_wrapped), aad=aad_canon)
        aes = AESGCM(dek)
        iv = b64d(env.iv)
        ct = b64d(env.ct)
        return aes.decrypt(iv, ct, aad_canon)

    # =========================
    # Асимметричная подпись и верификация
    # =========================

    def sign_digest(
        self,
        *,
        key_version: GcpKeyRef,
        digest: bytes,
        hash_alg: str = "SHA256",
    ) -> bytes:
        """
        Подписывает digest через KMS AsymmetricSign.
        key_version.resource должен указывать на cryptoKeyVersions/{n}.
        """
        name = key_version.resource
        if kms_v1 is None:
            raise NotAvailable("google-cloud-kms is not installed")

        # Сформируем kms_v1.Digest
        if hash_alg.upper() == "SHA256":
            d = kms_v1.Digest(sha256=digest)
        elif hash_alg.upper() == "SHA384":
            d = kms_v1.Digest(sha384=digest)
        elif hash_alg.upper() == "SHA512":
            d = kms_v1.Digest(sha512=digest)
        else:
            raise KmsError(f"Unsupported hash_alg: {hash_alg}")

        req = {"name": name, "digest": d}
        resp = self._call("AsymmetricSign", self._client.asymmetric_sign, request=req)
        # Проверим CRC подписи (если присутствует)
        if getattr(resp, "signature_crc32c", None) is not None:
            if resp.signature_crc32c != crc32c(resp.signature):
                raise IntegrityError("KMS signature CRC32C mismatch")
        return bytes(resp.signature)

    def get_public_key_pem(self, *, key_version: GcpKeyRef) -> bytes:
        """
        Возвращает PEM публичного ключа KMS (кэшируется на public_key_ttl секунд).
        """
        cache_key = key_version.resource
        with self._lock:
            data = self._pk_cache.get(cache_key)
            if data and data[1] > time.time():
                return data[0]
        resp = self._call("GetPublicKey", self._client.get_public_key, request={"name": key_version.resource})
        pem = resp.pem.encode("utf-8")
        with self._lock:
            self._pk_cache[cache_key] = (pem, time.time() + self.cfg.public_key_ttl)
        return pem

    def verify_signature(
        self,
        *,
        key_version: GcpKeyRef,
        digest: bytes,
        signature: bytes,
        hash_alg: str = "SHA256",
    ) -> bool:
        """
        Локальная верификация подписи, используя полученный PEM из KMS.
        Поддерживает RSA_PSS_2048/3072/4096_SHA* и EC_SIGN_P256/P384_SHA*.
        """
        pem = self.get_public_key_pem(key_version=key_version)
        pub = serialization.load_pem_public_key(pem)

        try:
            if isinstance(pub, rsa.RSAPublicKey):
                if hash_alg.upper() == "SHA256": h = hashes.SHA256()
                elif hash_alg.upper() == "SHA384": h = hashes.SHA384()
                elif hash_alg.upper() == "SHA512": h = hashes.SHA512()
                else: raise KmsError(f"Unsupported hash_alg: {hash_alg}")
                pub.verify(
                    signature,
                    digest,
                    padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.MAX_LENGTH),
                    h,
                )
                return True
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                if hash_alg.upper() == "SHA256": h = hashes.SHA256()
                elif hash_alg.upper() == "SHA384": h = hashes.SHA384()
                elif hash_alg.upper() == "SHA512": h = hashes.SHA512()
                else: raise KmsError(f"Unsupported hash_alg: {hash_alg}")
                pub.verify(signature, digest, ec.ECDSA(h))
                return True
            else:
                raise VerifyError("Unsupported public key type")
        except Exception as e:  # noqa: BLE001
            raise VerifyError(f"Signature verify failed: {e}")

    # =========================
    # Высокоуровневые удобства
    # =========================

    def encrypt_bytes(
        self,
        data: bytes,
        *,
        key: Optional[GcpKeyRef] = None,
        aad: Optional[Mapping[str, Any]] = None,
    ) -> bytes:
        """
        Возвращает сериализованный JSON-конверт в виде bytes (UTF-8).
        """
        env = self.encrypt_envelope(data, key=key, aad=aad)
        return env.to_json().encode("utf-8")

    def decrypt_bytes(self, env_blob: Union[str, bytes, Mapping[str, Any]], *, aad: Optional[Mapping[str, Any]] = None) -> bytes:
        return self.decrypt_envelope(env_blob, aad=aad)

    # =========================
    # Вспомогательное: фабрики ссылок
    # =========================

    @staticmethod
    def key_ref(project: str, location: str, ring: str, key: str) -> GcpKeyRef:
        return GcpKeyRef(resource=f"projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}")

    @staticmethod
    def key_version_ref(project: str, location: str, ring: str, key: str, ver: Union[str, int]) -> GcpKeyRef:
        return GcpKeyRef(resource=f"projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{ver}")


# =========================
# Пример использования (докстринг)
# =========================
"""
cfg = KmsConfig(
    default_key=GcpKmsClient.key_ref("my-project", "europe-north1", "sec-ring", "env-key"),
    timeout_seconds=10.0,
    max_attempts=5,
)

kms = GcpKmsClient(cfg)

# Конвертное шифрование с AAD
plaintext = b"secret bytes"
aad = {"tenant": "acme", "purpose": "db-backup"}
blob = kms.encrypt_bytes(plaintext, aad=aad)
restored = kms.decrypt_bytes(blob, aad=aad)
assert restored == plaintext

# Подпись SHA256(docs) и верификация
from cryptography.hazmat.primitives import hashes
h = hashes.Hash(hashes.SHA256()); h.update(b"data"); digest = h.finalize()
ver_ref = GcpKmsClient.key_version_ref("my-project", "europe-north1", "sec-ring", "sign-key", 1)
sig = kms.sign_digest(key_version=ver_ref, digest=digest, hash_alg="SHA256")
kms.verify_signature(key_version=ver_ref, digest=digest, signature=sig, hash_alg="SHA256")
"""
