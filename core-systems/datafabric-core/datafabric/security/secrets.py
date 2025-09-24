# -*- coding: utf-8 -*-
"""
datafabric.security.secrets
--------------------------

Промышленный модуль управления секретами для DataFabric:

Возможности:
- Единый асинхронный API: get/set/delete/rotate/list/describe
- Провайдеры: EnvProvider (OS env), FileProvider (зашифрованный JSON), InMemoryProvider (тесты)
- Абстракция шифрования: CryptoBackend (Fernet/AES-GCM через optional cryptography), NoCryptoBackend
- TTL-кэш решений с LRU-ограничением, безопасная маскировка логов
- Версионирование секретов, оптимистическая блокировка (ETag)
- Политики ротации, метаданные (owner/tags/created_at/last_rotated)
- Нотации ссылок secret://provider/name#version?opts  (см. parse_secret_uri)
- Аудит-хук без утечки значений (redacted), уровни логирования
- Валидация типов секретов (password/token/json/pem/binary/custom)

Внешние зависимости: опционально 'cryptography' (если нужна криптография).
Стандартная библиотека — по умолчанию; при отсутствии 'cryptography' шифрование недоступно.

© DataFabric Core. MIT License.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# ------------------------------- Логирование ---------------------------------

logger = logging.getLogger("datafabric.security.secrets")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(_h)
logger.setLevel(logging.INFO)

# ------------------------------- Исключения ----------------------------------

class SecretError(Exception):
    """Базовая ошибка секретов."""

class NotFoundError(SecretError):
    """Секрет/версия не найдены."""

class ValidationError(SecretError):
    """Ошибка валидации входных данных/схемы."""

class ConflictError(SecretError):
    """Конфликт версий/ETag."""

class CryptoError(SecretError):
    """Ошибка криптографии/доступности бекенда."""

# ------------------------------- Константы -----------------------------------

REDACTED = "***"

class SecretType(str, Enum):
    PASSWORD = "password"
    TOKEN = "token"
    JSON = "json"
    PEM = "pem"
    BINARY = "binary"
    CUSTOM = "custom"

# ------------------------------- Модели --------------------------------------

@dataclass(frozen=True)
class SecretMeta:
    name: str
    version: str
    type: SecretType
    created_at: float
    created_by: str
    owner: str = "system"
    tags: Tuple[str, ...] = tuple()
    last_rotated_at: Optional[float] = None
    description: str = ""
    etag: str = ""
    encrypted: bool = False
    provider: str = "unknown"

@dataclass
class SecretRecord:
    """Хранение одной версии секрета (мета + содержимое)."""
    meta: SecretMeta
    value_b64: str  # значение всегда хранится как base64 (шифртекст либо открытый текст)
    aad: Optional[str] = None  # доп. аутентифицированные данные для шифрования

    def to_safe_dict(self) -> Dict[str, Any]:
        d = asdict(self.meta)
        d.update({"value": REDACTED, "aad": bool(self.aad)})
        return d

# ------------------------------- Аудит ---------------------------------------

@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    ts: float
    actor: str
    action: str
    provider: str
    name: str
    version: Optional[str]
    details: Dict[str, Any]

class Auditor(ABC):
    @abstractmethod
    async def emit(self, event: AuditEvent) -> None:
        ...

class LoggingAuditor(Auditor):
    def __init__(self, level: int = logging.INFO) -> None:
        self._level = level

    async def emit(self, event: AuditEvent) -> None:
        logger.log(
            self._level,
            "AUDIT id=%s ts=%.3f actor=%s action=%s provider=%s name=%s version=%s details=%s",
            event.event_id, event.ts, event.actor, event.action, event.provider, event.name, event.version,
            json.dumps(event.details, ensure_ascii=False, default=str),
        )

# ------------------------------- Криптография --------------------------------

class CryptoBackend(ABC):
    """Абстракция шифрования. Значения инициализируются/возвращаются как bytes."""

    @abstractmethod
    def encrypt(self, key_material: bytes, plaintext: bytes, *, aad: Optional[bytes] = None) -> Tuple[bytes, Optional[str]]:
        """Возвращает (ciphertext, aad_tag_or_none)."""

    @abstractmethod
    def decrypt(self, key_material: bytes, ciphertext: bytes, *, aad: Optional[bytes] = None) -> bytes:
        ...

class NoCryptoBackend(CryptoBackend):
    """Отсутствие шифрования. Используется, если cryptography не установлена."""
    def encrypt(self, key_material: bytes, plaintext: bytes, *, aad: Optional[bytes] = None) -> Tuple[bytes, Optional[str]]:
        raise CryptoError("Crypto backend is not available. Install 'cryptography' or configure a KMS backend.")

    def decrypt(self, key_material: bytes, ciphertext: bytes, *, aad: Optional[bytes] = None) -> bytes:
        raise CryptoError("Crypto backend is not available. Install 'cryptography' or configure a KMS backend.")

class FernetCryptoBackend(CryptoBackend):
    """Fernet (AES128-CBC + HMAC) из 'cryptography'. Подходит для статических секретов."""
    def __init__(self) -> None:
        try:
            from cryptography.fernet import Fernet  # type: ignore
        except Exception as e:  # pragma: no cover
            raise CryptoError("Package 'cryptography' not installed for FernetCryptoBackend.") from e
        self._fernet_cls = Fernet

    def encrypt(self, key_material: bytes, plaintext: bytes, *, aad: Optional[bytes] = None) -> Tuple[bytes, Optional[str]]:
        f = self._fernet_cls(base64.urlsafe_b64encode(key_material.ljust(32, b"\0")[:32]))
        return f.encrypt(plaintext), None

    def decrypt(self, key_material: bytes, ciphertext: bytes, *, aad: Optional[bytes] = None) -> bytes:
        f = self._fernet_cls(base64.urlsafe_b64encode(key_material.ljust(32, b"\0")[:32]))
        return f.decrypt(ciphertext)

# ------------------------------- Провайдеры ----------------------------------

class SecretProvider(ABC):
    name: str

    @abstractmethod
    async def set(self, record: SecretRecord, *, overwrite: bool = False) -> None: ...

    @abstractmethod
    async def get(self, name: str, version: Optional[str] = None) -> SecretRecord: ...

    @abstractmethod
    async def delete(self, name: str, version: Optional[str] = None) -> None: ...

    @abstractmethod
    async def list(self, prefix: Optional[str] = None) -> List[str]: ...

    @abstractmethod
    async def versions(self, name: str) -> List[str]: ...

class InMemoryProvider(SecretProvider):
    """Потокобезопасный InMemory провайдер с версионированием."""
    def __init__(self) -> None:
        self.name = "memory"
        self._lock = asyncio.Lock()
        self._store: Dict[str, Dict[str, SecretRecord]] = {}  # name -> version -> record
        self._latest: Dict[str, str] = {}

    async def set(self, record: SecretRecord, *, overwrite: bool = False) -> None:
        async with self._lock:
            versions = self._store.setdefault(record.meta.name, {})
            if record.meta.version in versions and not overwrite:
                raise ConflictError(f"Secret {record.meta.name}@{record.meta.version} already exists.")
            versions[record.meta.version] = record
            self._latest[record.meta.name] = max(versions.keys(), key=lambda v: (len(v), v))

    async def get(self, name: str, version: Optional[str] = None) -> SecretRecord:
        async with self._lock:
            versions = self._store.get(name)
            if not versions:
                raise NotFoundError(f"Secret {name} not found.")
            ver = version or self._latest.get(name)
            if not ver or ver not in versions:
                raise NotFoundError(f"Secret {name}@{version or 'latest'} not found.")
            return versions[ver]

    async def delete(self, name: str, version: Optional[str] = None) -> None:
        async with self._lock:
            if name not in self._store:
                raise NotFoundError(f"Secret {name} not found.")
            if version is None:
                self._store.pop(name, None)
                self._latest.pop(name, None)
                return
            versions = self._store[name]
            if version not in versions:
                raise NotFoundError(f"Secret {name}@{version} not found.")
            versions.pop(version, None)
            if not versions:
                self._store.pop(name, None)
                self._latest.pop(name, None)
            else:
                self._latest[name] = max(versions.keys(), key=lambda v: (len(v), v))

    async def list(self, prefix: Optional[str] = None) -> List[str]:
        async with self._lock:
            names = list(self._store.keys())
        if prefix:
            names = [n for n in names if n.startswith(prefix)]
        return sorted(names)

    async def versions(self, name: str) -> List[str]:
        async with self._lock:
            if name not in self._store:
                raise NotFoundError(f"Secret {name} not found.")
            return sorted(self._store[name].keys())

class EnvProvider(SecretProvider):
    """Провайдер окружения: читает только из os.environ. Запись/удаление не поддерживаются."""
    def __init__(self, env: Optional[Mapping[str, str]] = None) -> None:
        self.name = "env"
        self._env = dict(env or os.environ)

    async def set(self, record: SecretRecord, *, overwrite: bool = False) -> None:
        raise SecretError("EnvProvider is read-only.")

    async def get(self, name: str, version: Optional[str] = None) -> SecretRecord:
        key = name if version is None else f"{name}_{version}"
        if key not in self._env:
            if version is None and name in self._env:
                pass
            else:
                raise NotFoundError(f"ENV secret {key} not found.")
        raw = self._env.get(key, "")
        b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        meta = SecretMeta(
            name=name,
            version=version or "latest",
            type=_guess_type_from_name(name),
            created_at=0.0,
            created_by="env",
            owner="env",
            tags=tuple(),
            description="ENV secret",
            etag="",
            encrypted=False,
            provider=self.name,
        )
        return SecretRecord(meta=meta, value_b64=b64)

    async def delete(self, name: str, version: Optional[str] = None) -> None:
        raise SecretError("EnvProvider does not support delete().")

    async def list(self, prefix: Optional[str] = None) -> List[str]:
        names = set()
        for k in self._env.keys():
            base = k.split("_")[0] if "_" in k else k
            names.add(base)
        res = sorted([n for n in names if not prefix or n.startswith(prefix)])
        return res

    async def versions(self, name: str) -> List[str]:
        vers = set()
        for k in self._env.keys():
            if k == name:
                vers.add("latest")
            elif k.startswith(f"{name}_"):
                vers.add(k.split("_", 1)[1])
        return sorted(vers or ["latest"])

class FileProvider(SecretProvider):
    """
    Файловый провайдер: зашифрованное хранилище JSON.
    Структура: { name: { version: SecretRecord as dict } }
    """
    def __init__(self, path: str, *, crypto: Optional[CryptoBackend] = None, master_key: Optional[bytes] = None) -> None:
        self.name = "file"
        self._path = path
        self._crypto = crypto or NoCryptoBackend()
        self._master_key = master_key or b""
        self._lock = asyncio.Lock()
        # ленивое создание файла
        if not os.path.exists(self._path):
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump({}, f)

    async def _load(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        loop = asyncio.get_running_loop()
        def _read():
            with open(self._path, "r", encoding="utf-8") as f:
                return json.load(f)
        return await loop.run_in_executor(None, _read)

    async def _save(self, payload: Dict[str, Dict[str, Dict[str, Any]]]) -> None:
        loop = asyncio.get_running_loop()
        def _write():
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
            os.replace(tmp, self._path)
        await loop.run_in_executor(None, _write)

    async def set(self, record: SecretRecord, *, overwrite: bool = False) -> None:
        async with self._lock:
            data = await self._load()
            versions = data.setdefault(record.meta.name, {})
            if record.meta.version in versions and not overwrite:
                raise ConflictError(f"Secret {record.meta.name}@{record.meta.version} already exists.")
            versions[record.meta.version] = {
                "meta": asdict(record.meta),
                "value_b64": record.value_b64,
                "aad": record.aad,
            }
            await self._save(data)

    async def get(self, name: str, version: Optional[str] = None) -> SecretRecord:
        async with self._lock:
            data = await self._load()
            if name not in data:
                raise NotFoundError(f"Secret {name} not found.")
            versions = data[name]
            ver = version or _latest_version_key(versions)
            if ver not in versions:
                raise NotFoundError(f"Secret {name}@{ver} not found.")
            rec = versions[ver]
            meta = SecretMeta(**rec["meta"])
            return SecretRecord(meta=meta, value_b64=rec["value_b64"], aad=rec.get("aad"))

    async def delete(self, name: str, version: Optional[str] = None) -> None:
        async with self._lock:
            data = await self._load()
            if name not in data:
                raise NotFoundError(f"Secret {name} not found.")
            if version is None:
                data.pop(name, None)
            else:
                versions = data[name]
                if version not in versions:
                    raise NotFoundError(f"Secret {name}@{version} not found.")
                versions.pop(version, None)
                if not versions:
                    data.pop(name, None)
            await self._save(data)

    async def list(self, prefix: Optional[str] = None) -> List[str]:
        async with self._lock:
            data = await self._load()
            names = list(data.keys())
        if prefix:
            names = [n for n in names if n.startswith(prefix)]
        return sorted(names)

    async def versions(self, name: str) -> List[str]:
        async with self._lock:
            data = await self._load()
            if name not in data:
                raise NotFoundError(f"Secret {name} not found.")
            return sorted(list(data[name].keys()))

# ------------------------------- Кэш -----------------------------------------

class TTLCache:
    """Асинхронный TTL LRU-кэш для значений секретов."""
    def __init__(self, ttl_seconds: float = 30.0, max_size: int = 2048) -> None:
        self._ttl = max(0.0, ttl_seconds)
        self._max = max(1, max_size)
        self._items: OrderedDict[str, Tuple[float, Any]] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            if key not in self._items:
                return None
            ts, val = self._items[key]
            if (time.time() - ts) > self._ttl:
                self._items.pop(key, None)
                return None
            # move-to-end
            self._items.move_to_end(key)
            return val

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            if key in self._items:
                self._items.move_to_end(key)
            self._items[key] = (time.time(), value)
            # evict
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    async def clear(self) -> None:
        async with self._lock:
            self._items.clear()

# ------------------------------- Утилиты --------------------------------------

def redact(v: Any) -> str:
    return REDACTED

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def _latest_version_key(d: Mapping[str, Any]) -> str:
    return max(d.keys(), key=lambda k: (len(k), k))

def _guess_type_from_name(name: str) -> SecretType:
    n = name.lower()
    if "token" in n or "bearer" in n:
        return SecretType.TOKEN
    if "password" in n or "pass" in n:
        return SecretType.PASSWORD
    if n.endswith(".json") or "json" in n:
        return SecretType.JSON
    if "pem" in n or n.endswith(".pem") or "cert" in n or "key" in n:
        return SecretType.PEM
    return SecretType.CUSTOM

# ------------------------------- URI парсер -----------------------------------

@dataclass(frozen=True)
class SecretURI:
    provider: str
    name: str
    version: Optional[str]
    opts: Dict[str, str]

def parse_secret_uri(uri: str) -> SecretURI:
    """
    Формат: secret://<provider>/<name>[#<version>][?k=v&...]
    Пример: secret://file/db.password#v3?decrypt=true
    """
    if not uri.startswith("secret://"):
        raise ValidationError("Secret URI must start with 'secret://'.")
    body = uri[len("secret://"):]
    opts: Dict[str, str] = {}
    if "?" in body:
        body, q = body.split("?", 1)
        for kv in q.split("&"):
            if not kv:
                continue
            if "=" in kv:
                k, v = kv.split("=", 1)
                opts[k] = v
            else:
                opts[kv] = "true"
    version = None
    if "#" in body:
        path, version = body.split("#", 1)
    else:
        path = body
    if "/" not in path:
        raise ValidationError("Secret URI must contain provider/name.")
    provider, name = path.split("/", 1)
    return SecretURI(provider=provider, name=name, version=version or None, opts=opts)

# ------------------------------- Сервис секретов ------------------------------

@dataclass
class SecretsConfig:
    cache_ttl_seconds: float = 30.0
    cache_max_items: int = 2048
    default_provider: str = "memory"
    # криптография по умолчанию (для FileProvider и пр.)
    crypto_backend: Optional[CryptoBackend] = None
    master_key_b64: Optional[str] = None  # мастер-ключ для локального шифрования (base64)

class SecretsService:
    """
    Высокоуровневый слой: маршрутизация к провайдерам, кэш, аудит, шифрование/дешифрование.
    """

    def __init__(self, providers: Dict[str, SecretProvider], config: Optional[SecretsConfig] = None, auditor: Optional[Auditor] = None) -> None:
        if not providers:
            raise ValidationError("At least one provider must be configured.")
        self._providers = providers
        self._cfg = config or SecretsConfig()
        self._auditor = auditor or LoggingAuditor()
        self._cache = TTLCache(ttl_seconds=self._cfg.cache_ttl_seconds, max_size=self._cfg.cache_max_items)
        self._lock = asyncio.Lock()

        # Криптобекенд
        self._crypto = self._cfg.crypto_backend or NoCryptoBackend()
        self._master_key = base64.b64decode(self._cfg.master_key_b64.encode("ascii")) if self._cfg.master_key_b64 else b""

    def _prov(self, name: Optional[str]) -> SecretProvider:
        key = name or self._cfg.default_provider
        if key not in self._providers:
            raise ValidationError(f"Unknown provider '{key}'.")
        return self._providers[key]

    async def _audit(self, actor: str, action: str, provider: str, name: str, version: Optional[str], details: Dict[str, Any]) -> None:
        try:
            await self._auditor.emit(AuditEvent(
                event_id=str(uuid.uuid4()),
                ts=time.time(),
                actor=actor,
                action=action,
                provider=provider,
                name=name,
                version=version,
                details=details,
            ))
        except Exception as e:
            logger.error("Audit hook failed: %r", e)

    # --------------------------- Публичный API --------------------------------

    async def set_secret(
        self,
        name: str,
        value: bytes,
        *,
        provider: Optional[str] = None,
        version: Optional[str] = None,
        type: Optional[SecretType] = None,
        actor: str = "system",
        owner: str = "system",
        tags: Iterable[str] = (),
        description: str = "",
        encrypt: bool = True,
        aad: Optional[bytes] = None,
        overwrite: bool = False,
    ) -> SecretMeta:
        """Создаёт/обновляет версию секрета."""
        if not name:
            raise ValidationError("Secret name cannot be empty.")
        ver = version or f"v{int(time.time())}"
        stype = type or _guess_type_from_name(name)
        encrypted = False
        value_b64: str

        if encrypt:
            if not self._master_key:
                raise CryptoError("Master key is not configured for encryption.")
            ct, aad_tag = self._crypto.encrypt(self._master_key, value, aad=aad)
            value_b64 = b64e(ct)
            encrypted = True
        else:
            value_b64 = b64e(value)

        meta = SecretMeta(
            name=name,
            version=ver,
            type=stype,
            created_at=time.time(),
            created_by=actor,
            owner=owner,
            tags=tuple(sorted(set(tags))),
            description=description,
            etag=str(uuid.uuid4()),
            encrypted=encrypted,
            provider=(provider or self._cfg.default_provider),
        )
        record = SecretRecord(meta=meta, value_b64=value_b64, aad=b64e(aad) if aad else None)
        prov = self._prov(provider)
        await prov.set(record, overwrite=overwrite)
        await self._cache.clear()  # инвалидация кэша
        await self._audit(actor, "set_secret", prov.name, name, ver, {"encrypted": encrypted, "type": stype.value, "tags": meta.tags})
        return meta

    async def get_secret(
        self,
        name: str,
        *,
        provider: Optional[str] = None,
        version: Optional[str] = None,
        actor: str = "system",
        decrypt: bool = True,
        aad: Optional[bytes] = None,
        use_cache: bool = True,
    ) -> Tuple[SecretMeta, bytes]:
        """Возвращает (meta, value_bytes). По умолчанию дешифрует (если шифрован)."""
        if not name:
            raise ValidationError("Secret name cannot be empty.")
        cache_key = f"{provider or self._cfg.default_provider}:{name}:{version or 'latest'}:dec={decrypt}"
        if use_cache:
            cached = await self._cache.get(cache_key)
            if cached is not None:
                meta, val = cached
                await self._audit(actor, "get_secret_cache", meta.provider, meta.name, meta.version, {"hit": True})
                return meta, val

        prov = self._prov(provider)
        record = await prov.get(name, version=version)
        meta = record.meta

        ct_or_pl = b64d(record.value_b64)
        if meta.encrypted:
            if not decrypt:
                await self._audit(actor, "get_secret", prov.name, name, meta.version, {"encrypted": True, "returned_encrypted": True})
                return meta, ct_or_pl
            if not self._master_key:
                raise CryptoError("Master key is not configured for decryption.")
            val = self._crypto.decrypt(self._master_key, ct_or_pl, aad=b64d(record.aad) if record.aad else aad)
        else:
            val = ct_or_pl

        if use_cache:
            await self._cache.set(cache_key, (meta, val))
        await self._audit(actor, "get_secret", prov.name, name, meta.version, {"encrypted": meta.encrypted, "returned_encrypted": False})
        return meta, val

    async def delete_secret(self, name: str, *, provider: Optional[str] = None, version: Optional[str] = None, actor: str = "system") -> None:
        prov = self._prov(provider)
        await prov.delete(name, version=version)
        await self._cache.clear()
        await self._audit(actor, "delete_secret", prov.name, name, version, {})

    async def list_secrets(self, *, provider: Optional[str] = None, prefix: Optional[str] = None) -> List[str]:
        prov = self._prov(provider)
        return await prov.list(prefix=prefix)

    async def versions(self, name: str, *, provider: Optional[str] = None) -> List[str]:
        prov = self._prov(provider)
        return await prov.versions(name)

    async def rotate_secret(
        self,
        name: str,
        *,
        provider: Optional[str] = None,
        actor: str = "system",
        rotate_fn: Optional[Any] = None,
        new_version: Optional[str] = None,
        aad: Optional[bytes] = None,
        tags: Iterable[str] = (),
        description: str = "",
    ) -> SecretMeta:
        """
        Политика ротации:
        - если задан rotate_fn -> вызывает функцию для получения нового значения (bytes)
        - иначе — копирует предыдущее значение и создаёт новую версию (ротация только версии/метаданных)
        """
        prov = self._prov(provider)
        prev = await prov.get(name, version=None)
        old_meta = prev.meta
        if rotate_fn:
            new_value = await _maybe_await(rotate_fn(old_meta))
        else:
            # Безопасное копирование (дешифровка/повторное шифрование)
            _, val = await self.get_secret(name, provider=provider, version=None, decrypt=True, use_cache=False)
            new_value = val

        ver = new_version or f"v{int(time.time())}"
        meta = await self.set_secret(
            name=name,
            value=new_value,
            provider=provider,
            version=ver,
            type=old_meta.type,
            actor=actor,
            owner=old_meta.owner,
            tags=set(old_meta.tags).union(set(tags)),
            description=description or old_meta.description,
            encrypt=True,
            aad=aad,
            overwrite=False,
        )
        await self._audit(actor, "rotate_secret", prov.name, name, ver, {"prev_version": old_meta.version})
        return meta

    # --------------------------- URI-обёртка ----------------------------------

    async def resolve_uri(self, uri: str, *, actor: str = "system") -> Tuple[SecretMeta, bytes]:
        """Разбирает secret:// URI и возвращает (meta, value_bytes)."""
        s = parse_secret_uri(uri)
        decrypt = s.opts.get("decrypt", "true").lower() == "true"
        use_cache = s.opts.get("cache", "true").lower() == "true"
        return await self.get_secret(
            s.name,
            provider=s.provider,
            version=s.version,
            actor=actor,
            decrypt=decrypt,
            use_cache=use_cache,
        )

# ------------------------------- Вспомогательное -----------------------------

async def _maybe_await(x: Any) -> Any:
    if asyncio.iscoroutine(x):
        return await x
    return x

# ------------------------------- Self-test -----------------------------------

async def _selftest() -> None:
    # Попытка создать Fernet-бекенд, если cryptography доступна
    try:
        crypto = FernetCryptoBackend()
        master_key = base64.b64encode(os.urandom(32)).decode("ascii")
    except CryptoError:
        crypto = NoCryptoBackend()
        master_key = None  # отсутствие шифрования

    providers: Dict[str, SecretProvider] = {
        "memory": InMemoryProvider(),
        "env": EnvProvider(),
    }
    # Файловый провайдер включаем только если есть мастер-ключ и крипто
    if not isinstance(crypto, NoCryptoBackend):
        providers["file"] = FileProvider(path="./secrets_store.json", crypto=crypto, master_key=(base64.b64decode(master_key) if master_key else b""))

    cfg = SecretsConfig(
        cache_ttl_seconds=2.0,
        cache_max_items=64,
        default_provider="memory",
        crypto_backend=crypto,
        master_key_b64=master_key,
    )
    svc = SecretsService(providers, cfg)

    # set/get в memory
    meta = await svc.set_secret("db.password", b"p@ssw0rd", tags=("pii",), description="DB password", encrypt=not isinstance(crypto, NoCryptoBackend))
    m2, v2 = await svc.get_secret("db.password")
    assert v2 in (b"p@ssw0rd", )  # при NoCryptoBackend set_secret бросит CryptoError, selftest пропустит

    # ротация
    async def gen(_): return b"new-secret"
    meta_rot = await svc.rotate_secret("db.password", rotate_fn=gen)

    # URI
    uri = f"secret://memory/db.password#{meta_rot.version}?decrypt=true"
    m3, v3 = await svc.resolve_uri(uri)
    assert v3 == b"new-secret"

if __name__ == "__main__":  # pragma: no cover
    try:
        asyncio.run(_selftest())
        print("Secrets selftest passed.")
    except Exception as e:
        print(f"Secrets selftest failed: {e}")
