# file: security-core/security/kms/aws_kms.py
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import BotoCoreError, ClientError
except Exception as e:
    raise ImportError("aws_kms.py requires boto3 and botocore") from e

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as e:
    raise ImportError("aws_kms.py requires cryptography (pip install cryptography)") from e


# =============================================================================
# Логирование и утилиты
# =============================================================================

logger = logging.getLogger("security_core.kms.aws")

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==="[: (4 - len(s) % 4) % 4])

def _redact(s: Optional[str], keep: int = 4) -> str:
    if not s:
        return ""
    if len(s) <= 2 * keep:
        return "****"
    return s[:keep] + "…" + s[-keep:]


# =============================================================================
# Исключения
# =============================================================================

class KmsError(Exception):
    pass

class KmsEncryptError(KmsError):
    pass

class KmsDecryptError(KmsError):
    pass

class KmsSignError(KmsError):
    pass

class KmsVerifyError(KmsError):
    pass


# =============================================================================
# Конфиг и фабрика клиентов (AssumeRole + таймауты/ретраи)
# =============================================================================

@dataclass
class AwsKmsConfig:
    # Основное
    primary_region: str
    failover_regions: List[str] = field(default_factory=list)  # для MRK расшифрования
    default_key_id: Optional[str] = None  # alias/ARN/KeyId для Encrypt (можно передавать per-call)
    static_encryption_context: Dict[str, str] = field(default_factory=dict)

    # Сеть и устойчивость
    connect_timeout_s: float = 2.0
    read_timeout_s: float = 5.0
    max_attempts: int = 5  # botocore стандартные ретраи
    retry_mode: str = "standard"  # "standard" | "adaptive"

    # AssumeRole
    role_arn: Optional[str] = None
    role_session_name: str = "security-core-kms"
    role_external_id: Optional[str] = None
    role_session_duration_s: int = 3600

    # Кэширование
    cache_max_entries: int = 256
    cache_ttl_sec_plaintext: int = 0        # 0 = не кэшировать плейнтекст
    cache_ttl_sec_data_key_ciphertext: int = 900  # кэш EDK (CiphertextBlob) для Encrypt (без плейнтекста)

    # Контейнер шифртекста
    envelope_version: int = 1
    aesgcm_key_bits: int = 256  # всегда 256 для GenerateDataKey
    aesgcm_nonce_bytes: int = 12

    # Прочее
    kms_endpoint_url: Optional[str] = None
    grant_tokens: List[str] = field(default_factory=list)  # если используется AWS Grants
    user_agent_suffix: str = "aethernova-security/1.0.0"


class _SessionFactory:
    """Ленивая фабрика клиентов KMS с поддержкой AssumeRole и реюза по регионам."""
    def __init__(self, cfg: AwsKmsConfig):
        self.cfg = cfg
        self._lock = threading.RLock()
        self._cached_clients: Dict[str, Any] = {}
        self._assumed_until: Optional[float] = None
        self._assumed_creds: Optional[Dict[str, Any]] = None

    def _assume_role_if_needed(self) -> Dict[str, Any] | None:
        if not self.cfg.role_arn:
            return None
        with self._lock:
            now = time.time()
            if self._assumed_creds and self._assumed_until and now < self._assumed_until - 60:
                return self._assumed_creds
            sts = boto3.client("sts", config=BotoConfig(
                connect_timeout=self.cfg.connect_timeout_s,
                read_timeout=self.cfg.read_timeout_s,
                retries={"max_attempts": self.cfg.max_attempts, "mode": self.cfg.retry_mode},
                user_agent_extra=self.cfg.user_agent_suffix,
            ))
            kwargs = {
                "RoleArn": self.cfg.role_arn,
                "RoleSessionName": self.cfg.role_session_name,
                "DurationSeconds": self.cfg.role_session_duration_s,
            }
            if self.cfg.role_external_id:
                kwargs["ExternalId"] = self.cfg.role_external_id
            resp = sts.assume_role(**kwargs)
            creds = resp["Credentials"]
            self._assumed_creds = {
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            }
            self._assumed_until = creds["Expiration"].timestamp()
            return self._assumed_creds

    def client(self, region: str):
        with self._lock:
            if region in self._cached_clients:
                return self._cached_clients[region]
            assumed = self._assume_role_if_needed() or {}
            session = boto3.session.Session(**assumed) if assumed else boto3.session.Session()
            client = session.client(
                "kms",
                region_name=region,
                endpoint_url=self.cfg.kms_endpoint_url,
                config=BotoConfig(
                    connect_timeout=self.cfg.connect_timeout_s,
                    read_timeout=self.cfg.read_timeout_s,
                    retries={"max_attempts": self.cfg.max_attempts, "mode": self.cfg.retry_mode},
                    user_agent_extra=self.cfg.user_agent_suffix,
                ),
            )
            self._cached_clients[region] = client
            return client


# =============================================================================
# TTL‑кэш EDK/плейнтекста
# =============================================================================

class _DataKeyCache:
    """Кэш ключей данных. Значение: (ciphertext_blob: bytes, plaintext_key: Optional[bytes], exp_cipher: float, exp_plain: float)."""
    def __init__(self, max_entries: int):
        self.max_entries = max_entries
        self._lock = threading.RLock()
        self._store: Dict[str, Tuple[bytes, Optional[bytes], float, float]] = {}

    def _prune(self):
        if len(self._store) <= self.max_entries:
            return
        # простое усечение по возрасту
        to_drop = sorted(self._store.items(), key=lambda kv: kv[1][2])[: len(self._store) - self.max_entries]
        for k, _ in to_drop:
            self._store.pop(k, None)

    def put(self, key: str, edk: bytes, plaintext: Optional[bytes], ttl_cipher: int, ttl_plain: int):
        with self._lock:
            now = time.time()
            self._store[key] = (edk, plaintext, now + ttl_cipher, now + ttl_plain)
            self._prune()

    def get(self, key: str) -> Tuple[Optional[bytes], Optional[bytes]]:
        with self._lock:
            now = time.time()
            entry = self._store.get(key)
            if not entry:
                return None, None
            edk, pt, exp_c, exp_p = entry
            if now > exp_c and now > exp_p:
                self._store.pop(key, None)
                return None, None
            edk_out = edk if now <= exp_c else None
            pt_out = pt if (pt is not None and now <= exp_p) else None
            return edk_out, pt_out

    def clear_plaintext(self):
        with self._lock:
            for k, (edk, pt, exp_c, _) in list(self._store.items()):
                self._store[k] = (edk, None, exp_c, 0.0)


# =============================================================================
# Основной класс
# =============================================================================

class AwsKmsCrypto:
    """
    Envelope‑шифрование (AES‑256‑GCM) с AWS KMS GenerateDataKey, MRK‑совместимое Decrypt,
    подпись/верификация, кэширование, AssumeRole, безопасные ретраи.
    """

    def __init__(self, cfg: AwsKmsConfig):
        self.cfg = cfg
        self._factory = _SessionFactory(cfg)
        self._cache = _DataKeyCache(cfg.cache_max_entries)

    # ---------- Публичное API ----------

    def encrypt(
        self,
        plaintext: bytes,
        *,
        key_id: Optional[str] = None,
        aad: Optional[Dict[str, Any]] = None,
        encryption_context: Optional[Dict[str, str]] = None,
        tenant_id: Optional[str] = None,
    ) -> bytes:
        """
        Выполняет envelope‑шифрование.
        Возвращает JSON‑контейнер (bytes) формата:
        {
          "v": 1,
          "alg": "AES-256-GCM",
          "kid": "<KMS key id/arn/alias>",
          "mrk": true|false,
          "edk": "<b64url KMS CiphertextBlob>",
          "iv": "<b64url 12B>",
          "ct": "<b64url>",
          "aad": { ... },            # опционально, если было передано
          "ctx": { ... },            # фактический encryption context
          "enc_at": "2025-08-20T12:34:56Z",
          "region": "eu-west-1"      # регион KMS, использованный для GDK
        }
        """
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise KmsEncryptError("plaintext must be bytes-like")

        key_id_eff = key_id or self.cfg.default_key_id
        if not key_id_eff:
            raise KmsEncryptError("key_id is required (or set default_key_id in config)")

        # Построим ключ кэша: key_id + контекст (включая static) + tenant_id
        ctx = dict(self.cfg.static_encryption_context)
        if encryption_context:
            ctx.update({str(k): str(v) for k, v in encryption_context.items()})
        if tenant_id:
            ctx.setdefault("tenant_id", str(tenant_id))

        cache_key = self._cache_key(key_id_eff, ctx)

        # Попробуем кэш: EDK + (опционально) плейнтекст‑ключ
        edk, pt_key = self._cache.get(cache_key)

        # Если нет плейнтекста — либо берем из KMS, либо расшифровываем EDK локально (нельзя — нужен KMS), поэтому идем в KMS.
        region_used = self.cfg.primary_region
        if pt_key is None:
            try:
                kms = self._factory.client(self.cfg.primary_region)
                resp = kms.generate_data_key(
                    KeyId=key_id_eff,
                    KeySpec="AES_256",
                    EncryptionContext=ctx or None,
                    GrantTokens=self.cfg.grant_tokens or None,
                )
                pt_key = resp["Plaintext"]  # bytes
                edk = resp["CiphertextBlob"]  # bytes
                region_used = self.cfg.primary_region
            except (BotoCoreError, ClientError) as e:
                raise KmsEncryptError(f"GenerateDataKey failed: {self._aws_err(e)}") from e

            # Сохраним в кэш: EDK на TTL подольше, плейнтекст — по политике
            self._cache.put(
                cache_key,
                edk,
                pt_key if self.cfg.cache_ttl_sec_plaintext > 0 else None,
                ttl_cipher=self.cfg.cache_ttl_sec_data_key_ciphertext,
                ttl_plain=self.cfg.cache_ttl_sec_plaintext,
            )

        # Локальное AES‑GCM
        nonce = os.urandom(self.cfg.aesgcm_nonce_bytes)
        aead = AESGCM(pt_key)
        # AAD канонизируем
        aad_eff = None
        if aad:
            aad_eff = json.dumps(aad, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ciphertext = aead.encrypt(nonce, bytes(plaintext), aad_eff)

        # Сборка контейнера
        envelope = {
            "v": self.cfg.envelope_version,
            "alg": "AES-256-GCM",
            "kid": key_id_eff,
            "mrk": None,  # неизвестно заранее; заполняется потребителем при наличии знания о MRK
            "edk": _b64e(edk or b""),
            "iv": _b64e(nonce),
            "ct": _b64e(ciphertext),
            "aad": aad if aad else None,
            "ctx": ctx or None,
            "enc_at": _iso(_now_utc()),
            "region": region_used,
        }

        # Безопасные логи
        logger.info(
            "kms.encrypt.ok",
            extra={
                "kid": key_id_eff,
                "region": region_used,
                "edk": _redact(envelope["edk"]),
                "iv": _redact(envelope["iv"]),
                "ctx_keys": list((ctx or {}).keys()),
            },
        )
        # Пытаемся минимально "очистить" плейнтекст‑ключ из памяти
        try:
            if self.cfg.cache_ttl_sec_plaintext <= 0 and pt_key is not None:
                # если плейнтекст не кэшируем — забываем ссылку
                del pt_key
        except Exception:
            pass

        return json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def decrypt(
        self,
        envelope_bytes: bytes,
        *,
        aad: Optional[Dict[str, Any]] = None,
        encryption_context: Optional[Dict[str, str]] = None,
        region_hint: Optional[str] = None,
    ) -> bytes:
        """
        Расшифровывает JSON‑контейнер, делая KMS.Decrypt по EDK с failover по регионам для MRK.
        """
        try:
            env = json.loads(envelope_bytes.decode("utf-8"))
        except Exception as e:
            raise KmsDecryptError(f"invalid envelope: {e}") from e

        for req_field in ("v", "alg", "kid", "edk", "iv", "ct"):
            if req_field not in env:
                raise KmsDecryptError(f"envelope missing field: {req_field}")

        if env["alg"] != "AES-256-GCM" or int(env["v"]) != self.cfg.envelope_version:
            raise KmsDecryptError("unsupported envelope algorithm/version")

        edk = _b64d(env["edk"])
        iv = _b64d(env["iv"])
        ct = _b64d(env["ct"])

        # Сформируем контекст: envelope.ctx + runtime
        ctx_env = dict(env.get("ctx") or {})
        ctx_run = dict(self.cfg.static_encryption_context)
        if encryption_context:
            ctx_run.update({str(k): str(v) for k, v in encryption_context.items()})
        ctx = ctx_env or {}
        ctx.update(ctx_run)

        # Попробуем найти плейнтекст‑ключ в кэше (если включено)
        cache_key = self._cache_key(env["kid"], ctx)
        _, pt_key_cached = self._cache.get(cache_key)

        if pt_key_cached is None:
            # Нужен KMS.Decrypt. Пробуем primary_region + указанные регионы (для MRK cross‑region).
            regions = [region_hint] if region_hint else []
            if env.get("region"):
                regions.append(env["region"])
            regions.append(self.cfg.primary_region)
            regions += [r for r in self.cfg.failover_regions if r not in regions]

            last_err = None
            pt_key = None
            for reg in regions:
                if not reg:
                    continue
                try:
                    kms = self._factory.client(reg)
                    resp = kms.decrypt(
                        CiphertextBlob=edk,
                        EncryptionContext=ctx or None,
                        GrantTokens=self.cfg.grant_tokens or None,
                    )
                    pt_key = resp["Plaintext"]
                    logger.info("kms.decrypt.ok", extra={"region": reg, "kid": env["kid"]})
                    break
                except (BotoCoreError, ClientError) as e:
                    last_err = e
                    logger.warning("kms.decrypt.retry", extra={"region": reg, "kid": env["kid"], "err": self._aws_err(e)})
                    continue
            if pt_key is None:
                raise KmsDecryptError(f"Decrypt failed in all regions: {self._aws_err(last_err)}")
            # Кэшируем (по политике)
            self._cache.put(
                cache_key,
                edk,
                pt_key if self.cfg.cache_ttl_sec_plaintext > 0 else None,
                ttl_cipher=self.cfg.cache_ttl_sec_data_key_ciphertext,
                ttl_plain=self.cfg.cache_ttl_sec_plaintext,
            )
        else:
            pt_key = pt_key_cached

        aead = AESGCM(pt_key)
        aad_eff = None
        if aad or env.get("aad") is not None:
            # Если при шифровании указывали AAD — ее нужно повторить бинарно идентично
            aad_eff = json.dumps(env.get("aad") if env.get("aad") is not None else aad, separators=(",", ":"), sort_keys=True).encode("utf-8")
        try:
            plaintext = aead.decrypt(iv, ct, aad_eff)
        except Exception as e:
            raise KmsDecryptError(f"AES-GCM decrypt failed: {e}") from e
        finally:
            try:
                if self.cfg.cache_ttl_sec_plaintext <= 0:
                    del pt_key
            except Exception:
                pass

        return plaintext

    def sign(
        self,
        *,
        key_id: str,
        message: bytes,
        signing_algorithm: str,  # "RSASSA_PSS_SHA_256" | "RSASSA_PKCS1_V1_5_SHA_256" | "ECDSA_SHA_256" | ...
        message_type: str = "RAW",  # "RAW" | "DIGEST"
        region: Optional[str] = None,
    ) -> bytes:
        """Подписывает сообщение/дайджест через KMS.Sign и возвращает подпись (bytes)."""
        try:
            kms = self._factory.client(region or self.cfg.primary_region)
            resp = kms.sign(
                KeyId=key_id,
                Message=message,
                SigningAlgorithm=signing_algorithm,
                MessageType=message_type,
                GrantTokens=self.cfg.grant_tokens or None,
            )
            sig = resp["Signature"]
            logger.info("kms.sign.ok", extra={"kid": key_id, "alg": signing_algorithm})
            return sig
        except (BotoCoreError, ClientError) as e:
            raise KmsSignError(f"Sign failed: {self._aws_err(e)}") from e

    def verify(
        self,
        *,
        key_id: str,
        message: bytes,
        signature: bytes,
        signing_algorithm: str,
        message_type: str = "RAW",
        region: Optional[str] = None,
    ) -> bool:
        """Проверяет подпись через KMS.Verify и возвращает bool."""
        try:
            kms = self._factory.client(region or self.cfg.primary_region)
            resp = kms.verify(
                KeyId=key_id,
                Message=message,
                Signature=signature,
                SigningAlgorithm=signing_algorithm,
                MessageType=message_type,
                GrantTokens=self.cfg.grant_tokens or None,
            )
            ok = bool(resp.get("SignatureValid"))
            logger.info("kms.verify.ok", extra={"kid": key_id, "alg": signing_algorithm, "valid": ok})
            return ok
        except (BotoCoreError, ClientError) as e:
            raise KmsVerifyError(f"Verify failed: {self._aws_err(e)}") from e

    def ensure_grant(
        self,
        *,
        key_id: str,
        grantee_principal: str,
        operations: List[str],
        name: Optional[str] = None,
        retiring_principal: Optional[str] = None,
        constraints: Optional[Dict[str, Any]] = None,
        region: Optional[str] = None,
    ) -> str:
        """
        Идемпотентно создает Grant (выдачу) для KMS‑ключа. Возвращает grant_id.
        """
        token = str(uuid.uuid4())
        try:
            kms = self._factory.client(region or self.cfg.primary_region)
            resp = kms.create_grant(
                KeyId=key_id,
                GranteePrincipal=grantee_principal,
                Operations=operations,
                Name=name or f"grant-{token}",
                Constraints=constraints or None,
                RetiringPrincipal=retiring_principal or None,
                GrantTokens=self.cfg.grant_tokens or None,
                AllowedOperations=operations,  # для совместимости (некоторые SDK версии)
            )
            gid = resp["GrantId"]
            logger.info("kms.grant.ok", extra={"kid": key_id, "grantee": grantee_principal, "grant_id": _redact(gid)})
            return gid
        except (BotoCoreError, ClientError) as e:
            # Если уже существует grant с таким Name — считать успехом (идемпотентность)
            if isinstance(e, ClientError) and e.response.get("Error", {}).get("Code") in {"GrantAlreadyExistsException", "AlreadyExistsException"}:
                logger.info("kms.grant.exists", extra={"kid": key_id, "grantee": grantee_principal, "name": name})
                return name or "existing"
            raise KmsError(f"CreateGrant failed: {self._aws_err(e)}") from e

    def clear_plaintext_cache(self):
        """Удалить плейнтекст‑ключи из кэша (например, при SIGTERM)."""
        self._cache.clear_plaintext()

    # ---------- Внутреннее ----------

    def _cache_key(self, key_id: str, ctx: Dict[str, str]) -> str:
        # Стабильное каноническое представление контекста
        ctx_json = json.dumps(ctx or {}, separators=(",", ":"), sort_keys=True)
        return f"{key_id}|{ctx_json}"

    @staticmethod
    def _aws_err(e: Exception) -> str:
        if isinstance(e, ClientError):
            err = e.response.get("Error", {})
            return f"{err.get('Code')}:{err.get('Message')}"
        return str(e)


# =============================================================================
# DEV‑пример
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    # ВНИМАНИЕ: для запуска требуется настроенный AWS профиль/переменные окружения и существующий KMS key/alias.
    cfg = AwsKmsConfig(
        primary_region=os.getenv("AWS_REGION", "eu-west-1"),
        failover_regions=["eu-central-1", "us-east-1"],
        default_key_id=os.getenv("KMS_KEY_ID", "alias/security-core-dev"),
        static_encryption_context={"app": "security-core", "env": "dev"},
        cache_ttl_sec_plaintext=0,  # не кэшировать плейнтекст в DEV
    )
    kms = AwsKmsCrypto(cfg)

    data = b"Sensitive payload"
    env = kms.encrypt(data, aad={"type": "demo"}, encryption_context={"purpose": "test"}, tenant_id="t1")
    print("envelope:", env.decode()[:160], "...")
    out = kms.decrypt(env, aad={"type": "demo"})
    print("decrypted ok:", out == data)
