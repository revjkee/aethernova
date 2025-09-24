# oblivionvault-core/oblivionvault/executors/crypto_shred.py
# Криптографическое стирание (crypto-erasure) для OblivionVault-Core.
from __future__ import annotations

import abc
import asyncio
import base64
import dataclasses
import json
import re
import sys
import typing as t
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import aioboto3  # AWS KMS/S3 (опционально)
except Exception:  # pragma: no cover
    aioboto3 = None  # type: ignore

try:
    import redis.asyncio as aioredis  # Redis (опционально)
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

# Опциональная интеграция с ядром приложения
try:
    from oblivionvault.context import AppContext, get_context  # type: ignore
except Exception:  # pragma: no cover
    AppContext = None  # type: ignore

# ==========================
# Исключения и типы
# ==========================

class ShredError(RuntimeError):
    pass

class LegalHoldError(ShredError):
    pass

class RetentionViolation(ShredError):
    pass

@dataclass(frozen=True)
class ShredTarget:
    record_id: str
    hard_delete: bool = False  # помимо crypto-erase удалить сами объекты

@dataclass
class EncryptionMetadata:
    record_id: str
    # Обязательные поля для envelope encryption:
    dek_wrapped_b64: str                  # DEK, зашифрованный KEK (KMS)
    kek_key_id: str                       # ARN/ID KMS ключа (или alias) для unwrap
    encryption_context: dict[str, str]    # EC для KMS (must match)
    storage_pointers: list[str]           # s3://..., db://..., file://... (для опционального hard delete)
    cache_keys: list[str]                 # ключи кэшей, которые надо очистить
    created_at: str
    legal_hold: bool = False
    status: str = "ACTIVE"                # ACTIVE | SHREDDED
    etag: str | None = None               # для оптимистичных апдейтов
    # Необязательное: id грантов KMS для отзыва
    kms_grants: list[str] | None = None

@dataclass
class ShredOutcome:
    record_id: str
    crypto_erased: bool
    hard_deleted: bool
    already_shredded: bool
    errors: list[str]
    finished_at: str

@dataclass
class ShredReport:
    ok: int
    failed: int
    outcomes: list[ShredOutcome]

# ==========================
# Абстракции хранилищ и KMS
# ==========================

class MetadataStore(abc.ABC):
    @abc.abstractmethod
    async def get_metadata(self, record_id: str) -> EncryptionMetadata | None: ...
    @abc.abstractmethod
    async def mark_shredded(self, record_id: str, etag: str | None, tombstone: dict) -> bool: ...
    @abc.abstractmethod
    async def remove_wrapped_dek(self, record_id: str, etag: str | None) -> bool: ...
    @abc.abstractmethod
    async def append_audit(self, record_id: str, event: dict) -> None: ...

class KMSClient(abc.ABC):
    @abc.abstractmethod
    async def revoke_grants(self, key_id: str, grant_ids: list[str]) -> None: ...
    @abc.abstractmethod
    async def disable_data_key_cache(self, key_id: str) -> None: ...

class CacheClient(abc.ABC):
    @abc.abstractmethod
    async def purge(self, keys: list[str]) -> None: ...

class ObjectStorage(abc.ABC):
    @abc.abstractmethod
    async def hard_delete(self, pointers: list[str]) -> list[str]: ...

# ==========================
# Примитивные реализации (in-memory / AWS)
# ==========================

class InMemoryMetadataStore(MetadataStore):
    def __init__(self):
        self._data: dict[str, EncryptionMetadata] = {}
        self._audit: dict[str, list[dict]] = {}

    async def get_metadata(self, record_id: str) -> EncryptionMetadata | None:
        return self._data.get(record_id)

    async def mark_shredded(self, record_id: str, etag: str | None, tombstone: dict) -> bool:
        md = self._data.get(record_id)
        if not md:
            return False
        if md.status == "SHREDDED":
            return True
        md.status = "SHREDDED"
        md.dek_wrapped_b64 = ""
        await self.append_audit(record_id, {"event": "shredded", "tombstone": tombstone, "ts": _now()})
        return True

    async def remove_wrapped_dek(self, record_id: str, etag: str | None) -> bool:
        md = self._data.get(record_id)
        if not md:
            return False
        md.dek_wrapped_b64 = ""
        return True

    async def append_audit(self, record_id: str, event: dict) -> None:
        self._audit.setdefault(record_id, []).append(event)

    # поддержка тестов
    def put(self, md: EncryptionMetadata):
        self._data[md.record_id] = md

class AWSKMSClient(KMSClient):
    def __init__(self, region: str | None = None):
        if aioboto3 is None:
            raise RuntimeError("aioboto3 is required for AWSKMSClient")
        self._session = aioboto3.Session(region_name=region)

    async def revoke_grants(self, key_id: str, grant_ids: list[str]) -> None:
        if not grant_ids:
            return
        async with self._session.client("kms") as kms:
            for gid in grant_ids:
                try:
                    await kms.retire_grant(GrantToken=gid)  # если у нас только токен
                except Exception:
                    # попробуем по GrantId
                    with _suppress():
                        await kms.revoke_grant(KeyId=key_id, GrantId=gid)

    async def disable_data_key_cache(self, key_id: str) -> None:
        # Нет прямого API отключить кэш на стороне клиента.
        # Здесь можно инвалидацировать собственные кэши, если они есть.
        return

class RedisCache(CacheClient):
    def __init__(self, redis: "aioredis.Redis"):  # type: ignore
        self._redis = redis

    async def purge(self, keys: list[str]) -> None:
        if not keys:
            return
        try:
            await self._redis.delete(*keys)
        except Exception:
            pass

class S3ObjectStorage(ObjectStorage):
    _S3_RE = re.compile(r"^s3://([^/]+)/(.+)$")
    def __init__(self, region: str | None = None, endpoint: str | None = None, client=None):
        if client is not None:
            self._client = client
            return
        if aioboto3 is None:
            raise RuntimeError("aioboto3 is required for S3ObjectStorage")
        session = aioboto3.Session(region_name=region)
        self._client = session.client("s3", endpoint_url=endpoint)

    async def hard_delete(self, pointers: list[str]) -> list[str]:
        deleted: list[str] = []
        for p in pointers:
            m = self._S3_RE.match(p)
            if not m:
                continue
            bkt, key = m.group(1), m.group(2)
            try:
                await self._client.delete_object(Bucket=bkt, Key=key)
                deleted.append(p)
            except Exception:
                pass
        return deleted

# ==========================
# Исполнитель
# ==========================

@dataclass
class CryptoShredConfig:
    require_retention_check: bool = True
    retention_endpoint: str | None = "/v1/retention:enforce"  # HTTP POST
    grace_seconds: int = 0  # если >0, отложить применение (исполнителем планировщика)
    max_concurrency: int = 8
    audit_enabled: bool = True

class CryptoShredExecutor:
    def __init__(
        self,
        metadata: MetadataStore,
        kms: KMSClient | None = None,
        cache: CacheClient | None = None,
        storage: ObjectStorage | None = None,
        ctx: AppContext | None = None,  # опциональная интеграция (HTTP, лог)
        config: CryptoShredConfig | None = None,
    ):
        self.metadata = metadata
        self.kms = kms
        self.cache = cache
        self.storage = storage
        self.ctx = ctx
        self.cfg = config or CryptoShredConfig()

    # Пакетная обработка с ограничением параллелизма
    async def shred_many(self, targets: list[ShredTarget]) -> ShredReport:
        sem = asyncio.Semaphore(self.cfg.max_concurrency)
        outcomes: list[ShredOutcome] = []

        async def _one(tg: ShredTarget):
            async with sem:
                res = await self.shred_one(tg)
                outcomes.append(res)

        await asyncio.gather(*[_one(tg) for tg in targets])
        ok = sum(1 for o in outcomes if not o.errors)
        failed = len(outcomes) - ok
        return ShredReport(ok=ok, failed=failed, outcomes=outcomes)

    # Основная операция для одной записи
    async def shred_one(self, target: ShredTarget) -> ShredOutcome:
        rid = target.record_id
        errors: list[str] = []
        already = False
        hard_deleted = False
        crypto_erased = False

        md = await self.metadata.get_metadata(rid)
        if not md:
            return ShredOutcome(record_id=rid, crypto_erased=False, hard_deleted=False, already_shredded=False,
                               errors=["metadata_not_found"], finished_at=_now())

        # Проверки Legal Hold / Retention
        try:
            await self._ensure_retention_allows(rid, md, target.hard_delete)
        except (LegalHoldError, RetentionViolation) as e:
            return ShredOutcome(record_id=rid, crypto_erased=False, hard_deleted=False, already_shredded=False,
                               errors=[type(e).__name__], finished_at=_now())

        if md.status == "SHREDDED" or not md.dek_wrapped_b64:
            already = True

        # 1) Отозвать гранты KMS (необязательно)
        try:
            if self.kms and md.kms_grants:
                await self.kms.revoke_grants(md.kek_key_id, md.kms_grants)
        except Exception as e:
            errors.append(f"kms_revoke_error:{e}")

        # 2) Удалить все кэш-следы (Redis и т.п.)
        try:
            if self.cache and md.cache_keys:
                await self.cache.purge(md.cache_keys)
        except Exception as e:
            errors.append(f"cache_purge_error:{e}")

        # 3) Уничтожить единственную копию DEK: удалить/обнулить wrapped DEK в метаданных
        try:
            if not already:
                await self.metadata.remove_wrapped_dek(rid, md.etag)
            crypto_erased = True
        except Exception as e:
            errors.append(f"metadata_remove_dek_error:{e}")

        # 4) Пометить запись как SHREDDED с томбстоуном
        try:
            tomb = {"shredded_at": _now(), "method": "crypto_erasure", "kek": md.kek_key_id}
            await self.metadata.mark_shredded(rid, md.etag, tomb)
        except Exception as e:
            errors.append(f"metadata_mark_error:{e}")

        # 5) Опциональный hard delete данных (объектов)
        if target.hard_delete and self.storage:
            try:
                deleted = await self.storage.hard_delete(md.storage_pointers)
                hard_deleted = len(deleted) > 0
            except Exception as e:
                errors.append(f"hard_delete_error:{e}")

        # 6) Локальное кэш-стирание plaintext (если такое вообще было)
        _secure_zeroize_b64(md.dek_wrapped_b64)

        # 7) Аудит
        if self.cfg.audit_enabled:
            with _suppress():
                await self.metadata.append_audit(rid, {
                    "event": "crypto_shred",
                    "ts": _now(),
                    "result": "ok" if not errors else "partial",
                    "hard_delete": target.hard_delete,
                })

        return ShredOutcome(
            record_id=rid,
            crypto_erased=crypto_erased or already,
            hard_deleted=hard_deleted,
            already_shredded=already,
            errors=errors,
            finished_at=_now(),
        )

    # Проверка политик ретеншна/Legal Hold через внешнюю службу (если сконфигурировано)
    async def _ensure_retention_allows(self, rid: str, md: EncryptionMetadata, hard_delete: bool):
        if md.legal_hold:
            raise LegalHoldError("legal_hold_active")

        if not self.cfg.require_retention_check or not self.cfg.retention_endpoint or not self.ctx or not getattr(self.ctx, "http", None):
            return  # пропускаем внешнюю проверку

        body = {
            "decision_id": None,
            "record_id": rid,
            "override_action": "DELETE" if hard_delete else "DELETE",
            "actor": "crypto_shred",
            "request_time": _now()
        }
        r = await self.ctx.http.post(self.cfg.retention_endpoint, json=body)  # type: ignore
        if r.status_code >= 300:
            raise RetentionViolation(f"retention_http_{r.status_code}")
        data = r.json()
        status = data.get("status", "").upper()
        if status not in {"APPLIED", "SKIPPED"}:
            raise RetentionViolation("retention_denied")

# ==========================
# Вспомогательные функции
# ==========================

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _secure_zeroize_b64(s: str | bytes | None):
    if not s:
        return
    try:
        if isinstance(s, str):
            b = bytearray(s.encode("utf-8"))
        elif isinstance(s, bytes):
            b = bytearray(s)
        else:
            return
        for i in range(len(b)):
            b[i] = 0
    except Exception:
        pass

@dataclasses.dataclass
class CLIConfig:
    hard_delete: bool = False
    parallel: int = 8

# ==========================
# Простой CLI для батч-стирания
# ==========================

async def _cli():
    import argparse
    p = argparse.ArgumentParser(description="OblivionVault Crypto Shred Executor")
    p.add_argument("--hard-delete", action="store_true", help="Физически удалить объекты помимо криптостирания")
    p.add_argument("--parallel", type=int, default=8, help="Степень параллелизма")
    p.add_argument("--inmemory", action="store_true", help="Использовать in-memory бэкенды (для локальной отладки)")
    p.add_argument("--region", default=None, help="AWS region")
    p.add_argument("--redis-url", default=None, help="redis://...")
    p.add_argument("--s3-endpoint", default=None, help="Кастомный S3 endpoint (minio и т.п.)")
    args = p.parse_args()

    # Читаем record_id из stdin (по одному в строке) или из аргументов
    record_ids = [ln.strip() for ln in sys.stdin if ln.strip()]
    if not record_ids:
        print("Нет входных record_id. Передайте список через stdin.", file=sys.stderr)
        sys.exit(1)

    # Бэкенды
    if args.inmemory:
        md = InMemoryMetadataStore()
        # Генерируем фиктивные метаданные для демонстрации
        for rid in record_ids:
            md.put(EncryptionMetadata(
                record_id=rid,
                dek_wrapped_b64=base64.b64encode(b"dummy").decode(),
                kek_key_id="arn:aws:kms:eu-north-1:111111111111:key/abcd-ef",
                encryption_context={"rid": rid},
                storage_pointers=[f"s3://ovault-bucket/{rid}.bin"],
                cache_keys=[f"rec:{rid}:dek"],
                created_at=_now(),
            ))
        kms = AWSKMSClient(region=args.region) if aioboto3 is not None else None
        cache = None
        if aioredis and args.redis_url:
            cache = RedisCache(aioredis.Redis.from_url(args.redis_url))
        storage = S3ObjectStorage(region=args.region, endpoint=args.s3_endpoint) if aioboto3 is not None else None
        execu = CryptoShredExecutor(md, kms=kms, cache=cache, storage=storage, ctx=None,
                                    config=CryptoShredConfig(max_concurrency=args.parallel))
    else:
        # Прод-путь через AppContext (ожидается, что приложение настроило зависимости)
        if get_context:
            ctx = get_context()  # type: ignore
        else:
            ctx = None
        # Здесь ожидается внедрение реальных реализаций через DI.
        raise SystemExit("Для прод-режима используйте интеграцию через AppContext/DI вашего приложения")

    targets = [ShredTarget(rid, hard_delete=args.hard_delete) for rid in record_ids]
    rep = await execu.shred_many(targets)
    print(json.dumps(dataclasses.asdict(rep), ensure_ascii=False, indent=2))

# ==========================
# Экспорт удобных фабрик для DI
# ==========================

def make_executor_from_context(ctx: AppContext, metadata: MetadataStore, kms: KMSClient | None,
                               cache: CacheClient | None, storage: ObjectStorage | None,
                               cfg: CryptoShredConfig | None = None) -> CryptoShredExecutor:
    return CryptoShredExecutor(metadata=metadata, kms=kms, cache=cache, storage=storage, ctx=ctx, config=cfg)

# ==========================
# Вспомогательный suppress
# ==========================

class _suppress:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return True

# ==========================
# Entry point
# ==========================

if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_cli())
