# automation-core/src/automation_core/security/secrets.py
# -*- coding: utf-8 -*-
"""
Промышленный модуль управления секретами.

Проверяемые источники:
- OWASP Secrets Management Cheat Sheet (общие принципы управления секретами):
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- Python `secrets` (криптографически стойкая генерация): https://docs.python.org/3/library/secrets.html
- Python `hmac.compare_digest` (константное время сравнения): https://docs.python.org/3/library/hmac.html#hmac.compare_digest
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
- NIST SP 800-38D (AES-GCM режим): https://csrc.nist.gov/publications/detail/sp/800-38d/final
- Docker/Kubernetes secrets (`/run/secrets` практика):
  Docker: https://docs.docker.com/engine/swarm/secrets/
  Kubernetes: https://kubernetes.io/docs/concepts/configuration/secret/
- AWS Secrets Manager: https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html
- Google Secret Manager: https://cloud.google.com/secret-manager/docs
- HashiCorp Vault (KV, AppRole и т.д.): https://developer.hashicorp.com/vault/docs

Намеренно опущено:
- Жесткое хранение секретов в коде (нарушает OWASP). Значения берутся из провайдеров.
- Нестойкие генераторы (например random). Используется `secrets` из stdlib.

Ограничения:
- Криптографическое шифрование AES-GCM доступно при установленном пакете `cryptography`.
- Провайдеры облачных секретов активируются при наличии соответствующих SDK.
- Я не могу подтвердить, что указанные SDK установлены в вашем окружении: для них предусмотрено безопасное
  «ленивое» подключение с осмысленными исключениями.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import re
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import hmac
import hashlib
import secrets as pysecrets  # криптографическая генерация: stdlib (см. ссылку выше)

# -----------------------------
# Исключения
# -----------------------------

class SecretError(Exception):
    """Базовое исключение секретов."""

class SecretNotFound(SecretError):
    """Секрет не найден ни в одном провайдере."""

class SecretValidationError(SecretError):
    """Секрет найден, но не прошёл валидацию."""

class CryptoUnavailable(SecretError):
    """Функция требует внешнюю криптобиблиотеку."""


# -----------------------------
# Спецификация и валидация
# -----------------------------

@dataclass(frozen=True)
class SecretSpec:
    """
    Описание секрета: имя, требования к длине/шаблону, тип представления.
    """
    name: str
    min_length: int = 0
    max_length: int = 4096
    pattern: Optional[str] = None  # регулярное выражение (полное совпадение)
    as_bytes: bool = False         # вернуть bytes вместо str
    required: bool = True

    def validate(self, value: Union[str, bytes]) -> None:
        if isinstance(value, bytes):
            val = value
            length = len(val)
        else:
            val = value.encode("utf-8")
            length = len(value)
        if length < self.min_length:
            raise SecretValidationError(f"{self.name}: длина {length} < min_length={self.min_length}")
        if length > self.max_length:
            raise SecretValidationError(f"{self.name}: длина {length} > max_length={self.max_length}")
        if self.pattern is not None:
            if isinstance(value, bytes):
                try:
                    s = value.decode("utf-8")
                except UnicodeDecodeError:
                    raise SecretValidationError(f"{self.name}: bytes не декодируются в UTF-8 для проверки шаблона")
            else:
                s = value
            if not re.fullmatch(self.pattern, s):
                raise SecretValidationError(f"{self.name}: значение не соответствует шаблону")


# -----------------------------
# Маскирование в логах
# -----------------------------

class SecretMasker:
    """
    Маскирование секретов в строках логов/сообщениях.
    Реализует замену известных значений на маркер **** и сокращённые отпечатки.
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._secrets: List[bytes] = []

    def register(self, value: Union[str, bytes]) -> None:
        b = value if isinstance(value, bytes) else value.encode("utf-8")
        with self._lock:
            if b and b not in self._secrets:
                self._secrets.append(b)

    def redact(self, message: str) -> str:
        with self._lock:
            redacted = message
            for b in self._secrets:
                try:
                    s = b.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if s:
                    redacted = redacted.replace(s, "****")
            return redacted

MASKER = SecretMasker()


# -----------------------------
# Кэш с TTL
# -----------------------------

@dataclass
class _CacheEntry:
    value: Union[str, bytes]
    exp: float

class SecretsCache:
    def __init__(self, default_ttl: float = 60.0) -> None:
        self._ttl = float(default_ttl)
        self._store: Dict[str, _CacheEntry] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Union[str, bytes]]:
        now = time.time()
        with self._lock:
            ent = self._store.get(key)
            if not ent:
                return None
            if ent.exp < now:
                self._store.pop(key, None)
                return None
            return ent.value

    def put(self, key: str, val: Union[str, bytes], ttl: Optional[float] = None) -> None:
        with self._lock:
            self._store[key] = _CacheEntry(val, time.time() + (self._ttl if ttl is None else float(ttl)))

CACHE = SecretsCache(default_ttl=120.0)


# -----------------------------
# Провайдеры секретов
# -----------------------------

class SecretsProvider(ABC):
    @abstractmethod
    def get(self, name: str) -> Optional[Union[str, bytes]]:
        """Возвращает секрет или None, если не найден."""

class EnvProvider(SecretsProvider):
    """
    Ищет:
    - прямой ENV: NAME
    - указание файла: NAME_FILE (Docker/K8s best practice)
    - стандартный путь Docker/K8s: /run/secrets/<name> (см. ссылки в докстроке)
    """
    def __init__(self, env: Optional[Dict[str, str]] = None, run_secrets_dir: Optional[Union[str, Path]] = "/run/secrets") -> None:
        self._env = env or os.environ
        self._dir = Path(run_secrets_dir) if run_secrets_dir else None

    def get(self, name: str) -> Optional[Union[str, bytes]]:
        # 1) прямой ENV
        if name in self._env and self._env[name]:
            return self._env[name]
        # 2) указание файла через *_FILE
        file_key = f"{name}_FILE"
        if file_key in self._env and self._env[file_key]:
            p = Path(self._env[file_key])
            try:
                return p.read_text(encoding="utf-8").rstrip("\n")
            except Exception:
                # попробуем как bytes
                try:
                    return p.read_bytes()
                except Exception:
                    return None
        # 3) /run/secrets/<name>
        if self._dir:
            p = self._dir / name
            if p.exists():
                try:
                    return p.read_text(encoding="utf-8").rstrip("\n")
                except Exception:
                    try:
                        return p.read_bytes()
                    except Exception:
                        return None
        return None

class FileProvider(SecretsProvider):
    """
    Читает секреты из указанной директории (один файл = один секрет, имя файла = имя секрета).
    """
    def __init__(self, base_dir: Union[str, Path]) -> None:
        self._base = Path(base_dir)

    def get(self, name: str) -> Optional[Union[str, bytes]]:
        p = self._base / name
        if not p.exists():
            return None
        try:
            return p.read_text(encoding="utf-8").rstrip("\n")
        except Exception:
            try:
                return p.read_bytes()
            except Exception:
                return None

class DictProvider(SecretsProvider):
    """Для тестов/локального рантайма."""
    def __init__(self, data: Dict[str, Union[str, bytes]]) -> None:
        self._data = data

    def get(self, name: str) -> Optional[Union[str, bytes]]:
        return self._data.get(name)

class AWSSecretsManagerProvider(SecretsProvider):
    """Опционально: требует boto3. См. документацию AWS Secrets Manager (ссылка в докстроке)."""
    def __init__(self, prefix: str = "", region: Optional[str] = None, profile: Optional[str] = None) -> None:
        self._prefix = prefix
        self._region = region
        self._profile = profile
        try:
            import boto3  # type: ignore
        except Exception as e:
            raise SecretError("boto3 не установлен для AWSSecretsManagerProvider") from e
        if profile:
            boto3.setup_default_session(profile_name=profile)
        self._client = boto3.client("secretsmanager", region_name=region)

    def get(self, name: str) -> Optional[Union[str, bytes]]:
        key = f"{self._prefix}{name}"
        try:
            resp = self._client.get_secret_value(SecretId=key)
        except Exception:
            return None
        if "SecretString" in resp and resp["SecretString"] is not None:
            return resp["SecretString"]
        if "SecretBinary" in resp and resp["SecretBinary"] is not None:
            return resp["SecretBinary"]
        return None

class GCPSecretManagerProvider(SecretsProvider):
    """Опционально: требует google-cloud-secret-manager. См. документацию GCP (ссылка в докстроке)."""
    def __init__(self, project_id: str, prefix: str = "", version: str = "latest") -> None:
        try:
            from google.cloud import secretmanager  # type: ignore
        except Exception as e:
            raise SecretError("google-cloud-secret-manager не установлен") from e
        self._client = secretmanager.SecretManagerServiceClient()
        self._project = project_id
        self._prefix = prefix
        self._version = version

    def get(self, name: str) -> Optional[Union[str, bytes]]:
        from google.cloud.secretmanager import SecretVersionName  # type: ignore
        full_name = f"{self._prefix}{name}"
        try:
            resname = SecretVersionName(project=self._project, secret=full_name, secret_version=self._version)
            resp = self._client.access_secret_version(name=str(resname))
            return resp.payload.data  # bytes
        except Exception:
            return None

class VaultKVProvider(SecretsProvider):
    """Опционально: HashiCorp Vault (KV v2). Требуется hvac. См. документацию Vault (ссылка в докстроке)."""
    def __init__(self, url: str, token: str, mount_point: str = "secret", prefix: str = "") -> None:
        try:
            import hvac  # type: ignore
        except Exception as e:
            raise SecretError("hvac не установлен для VaultKVProvider") from e
        self._client = hvac.Client(url=url, token=token)
        self._mount = mount_point
        self._prefix = prefix

    def get(self, name: str) -> Optional[Union[str, bytes]]:
        key = f"{self._prefix}{name}"
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(mount_point=self._mount, path=key)
            data = resp.get("data", {}).get("data", {})
            # Если значение сложное — возвращаем JSON
            return json.dumps(data)
        except Exception:
            return None


# -----------------------------
# Менеджер секретов (цепочка провайдеров)
# -----------------------------

class SecretsManager:
    def __init__(self, providers: Optional[Sequence[SecretsProvider]] = None, cache: SecretsCache = CACHE) -> None:
        self._providers: List[SecretsProvider] = list(providers) if providers else [EnvProvider()]
        self._cache = cache

    def get(self, spec: SecretSpec, *, cache_ttl: Optional[float] = None) -> Union[str, bytes, None]:
        cache_key = f"{spec.name}:{'b' if spec.as_bytes else 's'}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        value: Optional[Union[str, bytes]] = None
        # Проходим по провайдерам до первого найденного значения
        for p in self._providers:
            v = p.get(spec.name)
            if v is not None:
                value = v
                break

        if value is None:
            if spec.required:
                raise SecretNotFound(f"{spec.name} не найден")
            return None

        # Валидация и возврат
        spec.validate(value)
        MASKER.register(value if isinstance(value, bytes) else str(value))
        if not spec.as_bytes and isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeDecodeError:
                raise SecretValidationError(f"{spec.name}: bytes не декодируются в UTF-8; установите as_bytes=True")
        self._cache.put(cache_key, value, ttl=cache_ttl)
        return value


# -----------------------------
# Утилиты: сравнение, генерация, декодирование
# -----------------------------

def secure_equals(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Константное по времени сравнение (см. docs для hmac.compare_digest).
    Источник: https://docs.python.org/3/library/hmac.html#hmac.compare_digest
    """
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)

def generate_token_urlsafe(n_bytes: int = 32) -> str:
    """
    Генерирует криптостойкий токен (urlsafe, base64 без '=' паддинга).
    Источник: https://docs.python.org/3/library/secrets.html#secrets.token_urlsafe
    """
    return pysecrets.token_urlsafe(n_bytes)

def decode_possible_base64(s: Union[str, bytes]) -> bytes:
    """
    Помощник: если строка начинается с 'base64:', декодирует её как URL-safe Base64, иначе — UTF-8 bytes.
    """
    if isinstance(s, bytes):
        return s
    if s.startswith("base64:"):
        payload = s.split(":", 1)[1]
        return base64.urlsafe_b64decode(payload + "==")
    return s.encode("utf-8")


# -----------------------------
# HKDF (RFC 5869) для производных ключей
# -----------------------------

def hkdf_sha256(ikm: bytes, *, salt: Optional[bytes] = None, info: Optional[bytes] = None, length: int = 32) -> bytes:
    """
    Реализация HKDF-Extract+Expand (SHA-256), RFC 5869.
    Источник: https://www.rfc-editor.org/rfc/rfc5869
    """
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    info = info or b""
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# -----------------------------
# Опционально: AES-GCM (NIST SP 800-38D) если установлен cryptography
# -----------------------------

def aesgcm_encrypt(key: bytes, plaintext: bytes, *, aad: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
    """
    Шифрует plaintext в формате: nonce || ciphertext || tag (как возвращают многие AEAD API).
    Требует пакет `cryptography`. Режим GCM описан в NIST SP 800-38D.
    Ссылки:
      - NIST SP 800-38D: https://csrc.nist.gov/publications/detail/sp/800-38d/final
      - cryptography (AEAD AESGCM): https://cryptography.io/en/latest/hazmat/primitives/aead/#aesgcm
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    except Exception as e:
        raise CryptoUnavailable("cryptography не установлена") from e
    if not nonce:
        nonce = os.urandom(12)  # 96 бит — рекомендуемый размер nonce для GCM (см. NIST 800-38D)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return nonce + ct  # nonce||ciphertext||tag

def aesgcm_decrypt(key: bytes, data: bytes, *, aad: Optional[bytes] = None) -> bytes:
    """
    Обратная операция к aesgcm_encrypt.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    except Exception as e:
        raise CryptoUnavailable("cryptography не установлена") from e
    if len(data) < 12 + 16:
        raise SecretError("некорректный формат шифртекста")
    nonce, ct = data[:12], data[12:]
    aead = AESGCM(key)
    return aead.decrypt(nonce, ct, aad)


# -----------------------------
# Высокоуровневые помощники
# -----------------------------

_DEFAULT_MANAGER = SecretsManager()

def get_secret(
    name: str,
    *,
    required: bool = True,
    min_length: int = 0,
    max_length: int = 4096,
    pattern: Optional[str] = None,
    as_bytes: bool = False,
    cache_ttl: Optional[float] = 300.0,
    manager: Optional[SecretsManager] = None,
) -> Union[str, bytes, None]:
    """
    Загружает секрет по имени через цепочку провайдеров:
    - ENV: NAME
    - ENV: NAME_FILE (путь к файлу с секретом)
    - /run/secrets/NAME (Docker/K8s)
    - при наличии — другие провайдеры, переданные через `manager`

    Требования к формату задаются параметрами (см. OWASP Cheat Sheet).
    """
    spec = SecretSpec(
        name=name, required=required, min_length=min_length, max_length=max_length, pattern=pattern, as_bytes=as_bytes
    )
    mgr = manager or _DEFAULT_MANAGER
    return mgr.get(spec, cache_ttl=cache_ttl)

def get_json_secret(name: str, *, required: bool = True, manager: Optional[SecretsManager] = None) -> Optional[Dict[str, Any]]:
    """
    Загружает секрет и парсит как JSON (например, для облачных ключей).
    """
    raw = get_secret(name, required=required, as_bytes=False, manager=manager)
    if raw is None:
        return None
    try:
        return json.loads(raw)  # type: ignore[arg-type]
    except Exception as e:
        raise SecretValidationError(f"{name}: невалидный JSON") from e

def derive_key_from_secret(secret_name: str, *, context: str, length: int = 32, salt_env: Optional[str] = None) -> bytes:
    """
    Производный ключ из базового секрета с HKDF-SHA256 (RFC 5869).
    - context → info (байтовый контекст/метка назначения ключа)
    - salt берётся из переменной окружения `salt_env` либо нулевой по умолчанию (см. RFC 5869)
    """
    secret = get_secret(secret_name, required=True, as_bytes=True)
    assert isinstance(secret, (bytes, bytearray))
    salt = None
    if salt_env:
        s = os.environ.get(salt_env)
        if s:
            salt = decode_possible_base64(s)
    return hkdf_sha256(bytes(secret), salt=salt, info=context.encode("utf-8"), length=length)

def redact(s: str) -> str:
    """Маскирует зарегистрированные секреты в строке (для логов)."""
    return MASKER.redact(s)


# -----------------------------
# Пример типовых спецификаций (можно использовать в проекте)
# -----------------------------

# Пример: токен API — минимум 32 символа, только urlsafe base64/алфавит
API_TOKEN_SPEC = SecretSpec(
    name="API_TOKEN",
    min_length=32,
    max_length=512,
    pattern=r"[A-Za-z0-9_\-~=\.]{32,512}",
    as_bytes=False,
    required=True,
)

# Пример: ключ шифрования 32 байта (raw bytes)
ENCRYPTION_KEY_SPEC = SecretSpec(
    name="ENCRYPTION_KEY",
    min_length=32,
    max_length=32,
    as_bytes=True,
    required=True,
)


# -----------------------------
# Мини-CLI (опционально, для отладки)
# -----------------------------

def _main() -> int:
    """
    Небольшой CLI:
      python -m automation_core.security.secrets generate 32
      python -m automation_core.security.secrets get API_TOKEN
    """
    import sys
    if len(sys.argv) < 2:
        print("usage: secrets.py [generate N|get NAME]", flush=True)
        return 2
    cmd = sys.argv[1]
    if cmd == "generate":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 32
        print(generate_token_urlsafe(n))
        return 0
    if cmd == "get":
        name = sys.argv[2]
        val = get_secret(name, required=False)
        if val is None:
            print("NOT FOUND")
            return 1
        print("***" if isinstance(val, bytes) else redact(str(val)))
        return 0
    print("unknown command", flush=True)
    return 2

if __name__ == "__main__":
    raise SystemExit(_main())
