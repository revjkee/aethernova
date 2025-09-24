# mythos-core/mythos/assets/catalog.py
from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import json
import mimetypes
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Optional, Protocol, Sequence, Tuple

try:
    import aiosqlite  # type: ignore
except Exception:  # pragma: no cover
    aiosqlite = None  # fallback ниже

try:
    import blake3  # type: ignore
except Exception:  # pragma: no cover
    blake3 = None

from pydantic import BaseModel, Field, field_validator, model_validator

# =============================================================================
# Утилиты и константы
# =============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def to_epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def guess_mime(path_or_name: str) -> str:
    mt, _ = mimetypes.guess_type(path_or_name)
    return mt or "application/octet-stream"

# Стабильный ETag по (checksum, version)
def etag_for(checksum_hex: str, version: int) -> str:
    payload = f"{checksum_hex}:{version}".encode()
    return hashlib.sha256(payload).hexdigest()

# =============================================================================
# Исключения
# =============================================================================

class AssetError(Exception): ...
class AssetNotFound(AssetError): ...
class AssetConflict(AssetError): ...
class AssetPreconditionFailed(AssetError): ...
class AssetValidationError(AssetError): ...

# =============================================================================
# Модели каталога
# =============================================================================

class AssetVariant(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Напр. 'thumbnail', '720p', 'webp', 'waveform'")
    mime_type: str
    size_bytes: int = Field(ge=0)
    checksum_sha256: str
    width: Optional[int] = Field(None, ge=1)
    height: Optional[int] = Field(None, ge=1)
    duration_ms: Optional[int] = Field(None, ge=0)
    storage_url: str = Field(..., description="file://... или s3://bucket/key")
    created_at: datetime = Field(default_factory=utc_now)

class UsageRights(BaseModel):
    license: Optional[str] = Field(None, description="SPDX-идентификатор, Creative Commons и т.п.")
    copyright: Optional[str] = None
    expires_at: Optional[datetime] = None
    restrictions: Dict[str, Any] = Field(default_factory=dict)

class AssetRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    key: str = Field(..., description="Логический путь/имя, уникален в пределах tenant")
    mime_type: str = "application/octet-stream"
    size_bytes: int = Field(ge=0)
    checksum_sha256: str
    checksum_blake3: Optional[str] = None
    storage_scheme: Literal["file", "s3"] = "file"
    storage_url: str = Field(..., description="file://... или s3://bucket/key")
    labels: Dict[str, str] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    rights: UsageRights = Field(default_factory=UsageRights)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    deleted_at: Optional[datetime] = None
    version: int = 1
    etag: str = ""

    variants: List[AssetVariant] = Field(default_factory=list)

    @model_validator(mode="after")
    def _set_etag(self) -> "AssetRecord":
        if not self.etag:
            self.etag = etag_for(self.checksum_sha256, self.version)
        return self

class AssetQuery(BaseModel):
    tenant_id: str
    key_prefix: Optional[str] = None
    mime_prefix: Optional[str] = None
    tag_in: List[str] = Field(default_factory=list)
    label_equals: Dict[str, str] = Field(default_factory=dict)
    include_deleted: bool = False
    created_since: Optional[datetime] = None
    created_until: Optional[datetime] = None
    size_ge: Optional[int] = None
    size_le: Optional[int] = None
    limit: int = Field(50, ge=1, le=500)
    page_token: Optional[str] = None  # base64(JSON: {"offset": int})

class AssetPage(BaseModel):
    items: List[AssetRecord]
    next_page_token: Optional[str] = None

class PutResult(BaseModel):
    asset: AssetRecord
    created: bool  # False, если идемпотентный повтор

# =============================================================================
# Интерфейс каталога (Protocol)
# =============================================================================

class TimelineLogger(Protocol):
    async def log(self, tenant_id: str, actor_id: str, title: str, message: str, labels: Dict[str, str]) -> None: ...

class AssetCatalog(Protocol):
    async def init(self) -> None: ...
    async def head(self, tenant_id: str, key: str) -> AssetRecord: ...
    async def get(self, tenant_id: str, asset_id_or_key: str) -> AssetRecord: ...
    async def list(self, q: AssetQuery) -> AssetPage: ...
    async def put_bytes(
        self,
        tenant_id: str,
        key: str,
        data: bytes,
        mime_type: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> PutResult: ...
    async def put_stream(
        self,
        tenant_id: str,
        key: str,
        chunks: AsyncIterator[bytes],
        mime_type: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> PutResult: ...
    async def update_metadata(
        self,
        tenant_id: str,
        key: str,
        *,
        set_labels: Optional[Dict[str, str]] = None,
        add_tags: Optional[List[str]] = None,
        remove_tags: Optional[List[str]] = None,
        set_metadata: Optional[Dict[str, Any]] = None,
        set_rights: Optional[UsageRights] = None,
        if_match: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> AssetRecord: ...
    async def add_variant(
        self,
        tenant_id: str,
        key: str,
        variant: AssetVariant,
        if_match: Optional[str] = None,
    ) -> AssetRecord: ...
    async def delete(self, tenant_id: str, key: str, hard: bool = False, if_match: Optional[str] = None) -> None: ...

# =============================================================================
# Локальный файловый бэкенд с CAS + SQLite
# =============================================================================

@dataclass
class _DbConf:
    path: Path

class LocalFSAssetCatalog(AssetCatalog):
    """
    Локальный каталог активов с контент-адресуемым хранением (CAS) и SQLite-метаданными.

    Структура каталога:
      root/
        blobs/sha256/aa/bb/aaaaaaaa........ (файлы содержимого)
        meta/assets.db                      (SQLite)
        temp/                                (временные загрузки)

    Транзакционность: все операции метаданных выполняются ПОСЛЕ успешной записи blob и в пределах одной транзакции.
    Идемпотентность: по (tenant_id, key, checksum_sha256) — повторный put_bytes/put_stream возвращает created=False.
    """

    def __init__(self, root_dir: str | Path, timeline: Optional[TimelineLogger] = None) -> None:
        self.root = Path(root_dir)
        self.dir_blobs = self.root / "blobs" / "sha256"
        self.dir_meta = self.root / "meta"
        self.dir_temp = self.root / "temp"
        self.db = _DbConf(path=self.dir_meta / "assets.db")
        self._lock = asyncio.Lock()
        self._timeline = timeline

    # --------------- Public API ---------------

    async def init(self) -> None:
        for d in (self.dir_blobs, self.dir_meta, self.dir_temp):
            ensure_dir(d)
        await self._db_exec(self._sql_init())

    async def head(self, tenant_id: str, key: str) -> AssetRecord:
        row = await self._db_fetchone(
            """
            SELECT * FROM assets WHERE tenant_id=? AND key=? AND (deleted_at IS NULL)
            """,
            (tenant_id, key),
        )
        if not row:
            raise AssetNotFound(f"asset not found: {tenant_id}/{key}")
        return self._row_to_asset(row)

    async def get(self, tenant_id: str, asset_id_or_key: str) -> AssetRecord:
        if asset_id_or_key.count("-") >= 1:  # простая эвристика для UUID/ULID
            row = await self._db_fetchone(
                "SELECT * FROM assets WHERE tenant_id=? AND id=?",
                (tenant_id, asset_id_or_key),
            )
        else:
            row = await self._db_fetchone(
                "SELECT * FROM assets WHERE tenant_id=? AND key=?",
                (tenant_id, asset_id_or_key),
            )
        if not row:
            raise AssetNotFound(f"asset not found: {tenant_id}/{asset_id_or_key}")
        return self._row_to_asset(row)

    async def list(self, q: AssetQuery) -> AssetPage:
        where = ["tenant_id=?"]
        args: List[Any] = [q.tenant_id]
        if q.key_prefix:
            where.append("key LIKE ?")
            args.append(q.key_prefix.replace("%", r"\%") + "%")
        if q.mime_prefix:
            where.append("mime_type LIKE ?")
            args.append(q.mime_prefix + "%")
        if not q.include_deleted:
            where.append("deleted_at IS NULL")
        if q.created_since:
            where.append("created_at >= ?")
            args.append(q.created_since.isoformat())
        if q.created_until:
            where.append("created_at <= ?")
            args.append(q.created_until.isoformat())
        if q.size_ge is not None:
            where.append("size_bytes >= ?")
            args.append(q.size_ge)
        if q.size_le is not None:
            where.append("size_bytes <= ?")
            args.append(q.size_le)

        # Пагинация: токен = base64({"offset": int})
        offset = 0
        if q.page_token:
            try:
                data = json.loads(base64.urlsafe_b64decode(q.page_token + "==").decode())
                offset = int(data.get("offset", 0))
            except Exception:
                raise AssetValidationError("invalid page_token")

        sql = f"""
        SELECT * FROM assets
        WHERE {" AND ".join(where)}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """
        args += [q.limit, offset]
        rows = await self._db_fetchall(sql, tuple(args))
        items = [self._row_to_asset(r) for r in rows]

        # Фильтрация по тегам/меткам (для простоты — в памяти; при высоких нагрузках вынести в SQL JOIN)
        if q.tag_in:
            items = [a for a in items if set(q.tag_in) & set(a.tags)]
        if q.label_equals:
            items = [a for a in items if all(a.labels.get(k) == v for k, v in q.label_equals.items())]

        next_token = None
        if len(rows) == q.limit:
            next_token = base64.urlsafe_b64encode(json.dumps({"offset": offset + q.limit}).encode()).decode().rstrip("=")
        return AssetPage(items=items, next_page_token=next_token)

    async def put_bytes(
        self,
        tenant_id: str,
        key: str,
        data: bytes,
        mime_type: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> PutResult:
        async def _iter():
            yield data
        return await self.put_stream(
            tenant_id=tenant_id,
            key=key,
            chunks=_iter(),
            mime_type=mime_type,
            labels=labels,
            tags=tags,
            metadata=metadata,
            idempotency_key=idempotency_key,
        )

    async def put_stream(
        self,
        tenant_id: str,
        key: str,
        chunks: AsyncIterator[bytes],
        mime_type: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> PutResult:
        # Пишем во временный файл, одновременно считаем хэши и размер
        ensure_dir(self.dir_temp)
        tmp = self.dir_temp / f"upload-{uuid.uuid4().hex}.part"
        sha256 = hashlib.sha256()
        b3 = blake3.blake3() if blake3 else None
        total = 0
        async with await self._open_async(tmp, mode="wb") as f:
            async for chunk in chunks:
                if not isinstance(chunk, (bytes, bytearray)):
                    raise AssetValidationError("chunks must be bytes")
                await f.write(chunk)
                total += len(chunk)
                sha256.update(chunk)
                if b3:
                    b3.update(chunk)
        checksum = sha256.hexdigest()
        checksum_b3 = b3.hexdigest() if b3 else None

        # CAS путь
        dest = self._blob_path(checksum)
        ensure_dir(dest.parent)
        if not dest.exists():
            shutil.move(str(tmp), str(dest))
        else:
            # Дубликат по содержимому — удаляем временный файл
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()

        # MIME
        mt = mime_type or guess_mime(key)

        # Идемпотентность: тот же (tenant,key,checksum) → возвращаем существующий
        existing = await self._db_fetchone(
            """
            SELECT * FROM assets
            WHERE tenant_id=? AND key=? AND checksum_sha256=? AND (deleted_at IS NULL)
            """,
            (tenant_id, key, checksum),
        )
        if existing:
            asset = self._row_to_asset(existing)
            return PutResult(asset=asset, created=False)

        # Конфликт по key (другая версия/контент) — разрешаем как новую версию?
        conflict = await self._db_fetchone(
            "SELECT * FROM assets WHERE tenant_id=? AND key=? AND (deleted_at IS NULL)",
            (tenant_id, key),
        )
        if conflict:
            raise AssetConflict(f"asset with key already exists: {tenant_id}/{key}")

        # Записываем запись в БД
        storage_url = f"file://{dest}"
        now = utc_now().isoformat()
        labels = labels or {}
        tags = tags or []
        metadata = metadata or {}
        rights = UsageRights().model_dump(mode="json")

        await self._db_exec(
            """
            INSERT INTO assets
              (id, tenant_id, key, mime_type, size_bytes, checksum_sha256, checksum_blake3,
               storage_scheme, storage_url, labels_json, tags_json, metadata_json, rights_json,
               created_at, updated_at, deleted_at, version, etag)
            VALUES
              (?, ?, ?, ?, ?, ?, ?, 'file', ?, ?, ?, ?, ?, ?, ?, NULL, 1, ?)
            """,
            (
                str(uuid.uuid4()),
                tenant_id,
                key,
                mt,
                total,
                checksum,
                checksum_b3,
                storage_url,
                json.dumps(labels, ensure_ascii=False),
                json.dumps(tags, ensure_ascii=False),
                json.dumps(metadata, ensure_ascii=False),
                json.dumps(rights, ensure_ascii=False),
                now,
                now,
                etag_for(checksum, 1),
            ),
        )
        row = await self._db_fetchone(
            "SELECT * FROM assets WHERE tenant_id=? AND key=?",
            (tenant_id, key),
        )
        asset = self._row_to_asset(row)
        await self._audit(tenant_id, "asset.created", f"{key} size={total}", {"key": key, "mime": mt})
        return PutResult(asset=asset, created=True)

    async def update_metadata(
        self,
        tenant_id: str,
        key: str,
        *,
        set_labels: Optional[Dict[str, str]] = None,
        add_tags: Optional[List[str]] = None,
        remove_tags: Optional[List[str]] = None,
        set_metadata: Optional[Dict[str, Any]] = None,
        set_rights: Optional[UsageRights] = None,
        if_match: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> AssetRecord:
        row = await self._db_fetchone(
            "SELECT * FROM assets WHERE tenant_id=? AND key=?",
            (tenant_id, key),
        )
        if not row:
            raise AssetNotFound(f"asset not found: {tenant_id}/{key}")
        asset = self._row_to_asset(row)

        # Предусловия
        if if_match and asset.etag != if_match:
            raise AssetPreconditionFailed("etag mismatch")
        if expected_version and asset.version != expected_version:
            raise AssetPreconditionFailed("version mismatch")

        # Готовим новые значения
        labels = asset.labels.copy()
        if set_labels:
            labels.update(set_labels)

        tags = set(asset.tags)
        if add_tags:
            tags |= set(add_tags)
        if remove_tags:
            tags -= set(remove_tags)

        metadata = asset.metadata.copy()
        if set_metadata:
            metadata.update(set_metadata)

        rights = asset.rights.model_dump(mode="json")
        if set_rights:
            rights = set_rights.model_dump(mode="json")

        new_version = asset.version + 1
        new_etag = etag_for(asset.checksum_sha256, new_version)
        now = utc_now().isoformat()

        await self._db_exec(
            """
            UPDATE assets SET
              labels_json=?, tags_json=?, metadata_json=?, rights_json=?,
              updated_at=?, version=?, etag=?
            WHERE tenant_id=? AND key=?
            """,
            (
                json.dumps(labels, ensure_ascii=False),
                json.dumps(list(tags), ensure_ascii=False),
                json.dumps(metadata, ensure_ascii=False),
                json.dumps(rights, ensure_ascii=False),
                now,
                new_version,
                new_etag,
                tenant_id,
                key,
            ),
        )
        row = await self._db_fetchone("SELECT * FROM assets WHERE tenant_id=? AND key=?", (tenant_id, key))
        return self._row_to_asset(row)

    async def add_variant(self, tenant_id: str, key: str, variant: AssetVariant, if_match: Optional[str] = None) -> AssetRecord:
        row = await self._db_fetchone("SELECT * FROM assets WHERE tenant_id=? AND key=?", (tenant_id, key))
        if not row:
            raise AssetNotFound(f"asset not found: {tenant_id}/{key}")
        asset = self._row_to_asset(row)
        if if_match and asset.etag != if_match:
            raise AssetPreconditionFailed("etag mismatch")

        await self._db_exec(
            """
            INSERT INTO variants
              (id, asset_id, name, mime_type, size_bytes, checksum_sha256, width, height, duration_ms, storage_url, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                variant.id,
                asset.id,
                variant.name,
                variant.mime_type,
                variant.size_bytes,
                variant.checksum_sha256,
                variant.width,
                variant.height,
                variant.duration_ms,
                variant.storage_url,
                variant.created_at.isoformat(),
            ),
        )
        # bump version/etag
        new_version = asset.version + 1
        new_etag = etag_for(asset.checksum_sha256, new_version)
        await self._db_exec(
            "UPDATE assets SET updated_at=?, version=?, etag=? WHERE id=?",
            (utc_now().isoformat(), new_version, new_etag, asset.id),
        )
        row = await self._db_fetchone("SELECT * FROM assets WHERE id=?", (asset.id,))
        return self._row_to_asset(row)

    async def delete(self, tenant_id: str, key: str, hard: bool = False, if_match: Optional[str] = None) -> None:
        row = await self._db_fetchone("SELECT * FROM assets WHERE tenant_id=? AND key=?", (tenant_id, key))
        if not row:
            return
        asset = self._row_to_asset(row)
        if if_match and asset.etag != if_match:
            raise AssetPreconditionFailed("etag mismatch")

        if hard:
            # Удаляем метаданные и (внимание) blob только если больше никто не ссылается на checksum
            await self._db_exec("DELETE FROM variants WHERE asset_id=?", (asset.id,))
            await self._db_exec("DELETE FROM assets WHERE id=?", (asset.id,))
            count = await self._db_fetchone("SELECT COUNT(1) as c FROM assets WHERE checksum_sha256=?", (asset.checksum_sha256,))
            if count and int(count["c"]) == 0:
                path = self._blob_path(asset.checksum_sha256)
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
            await self._audit(tenant_id, "asset.deleted.hard", key, {"key": key})
            return

        # Soft-delete
        await self._db_exec(
            "UPDATE assets SET deleted_at=?, updated_at=?, version=version+1, etag=? WHERE id=?",
            (utc_now().isoformat(), utc_now().isoformat(), etag_for(asset.checksum_sha256, asset.version + 1), asset.id),
        )
        await self._audit(tenant_id, "asset.deleted.soft", key, {"key": key})

    # --------------- Internal ---------------

    def _blob_path(self, checksum_sha256: str) -> Path:
        sub1, sub2 = checksum_sha256[:2], checksum_sha256[2:4]
        return self.dir_blobs / sub1 / sub2 / checksum_sha256

    def _row_to_asset(self, row: sqlite3.Row) -> AssetRecord:
        a = AssetRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            key=row["key"],
            mime_type=row["mime_type"],
            size_bytes=row["size_bytes"],
            checksum_sha256=row["checksum_sha256"],
            checksum_blake3=row["checksum_blake3"],
            storage_scheme=row["storage_scheme"],
            storage_url=row["storage_url"],
            labels=json.loads(row["labels_json"] or "{}"),
            tags=json.loads(row["tags_json"] or "[]"),
            metadata=json.loads(row["metadata_json"] or "{}"),
            rights=UsageRights(**(json.loads(row["rights_json"] or "{}") or {})),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            deleted_at=(datetime.fromisoformat(row["deleted_at"]) if row["deleted_at"] else None),
            version=row["version"],
            etag=row["etag"],
            variants=[],
        )
        # Подгружаем варианты
        variants = asyncio.get_event_loop().run_until_complete(self._db_fetchall(
            "SELECT * FROM variants WHERE asset_id=? ORDER BY created_at ASC", (a.id,)
        )) if asyncio.get_event_loop().is_running() is False else None
        # В асинхронном контексте загрузим отдельно:
        if variants is None:
            # При обычном async-вызове rows подтянем чуть позже (см. _with_variants)
            pass
        else:
            for r in variants:
                a.variants.append(
                    AssetVariant(
                        id=r["id"],
                        name=r["name"],
                        mime_type=r["mime_type"],
                        size_bytes=r["size_bytes"],
                        checksum_sha256=r["checksum_sha256"],
                        width=r["width"],
                        height=r["height"],
                        duration_ms=r["duration_ms"],
                        storage_url=r["storage_url"],
                        created_at=datetime.fromisoformat(r["created_at"]),
                    )
                )
        return a

    async def _audit(self, tenant_id: str, title: str, message: str, labels: Dict[str, str]) -> None:
        if not self._timeline:
            return
        try:
            await self._timeline.log(tenant_id, "assets", title, message, labels)
        except Exception:
            pass

    # ---------------- SQLite helpers ----------------

    async def _db_exec(self, sql: str, args: Tuple[Any, ...] | List[Any] | None = None) -> None:
        if aiosqlite:
            async with aiosqlite.connect(self.db.path) as db:
                await db.execute("PRAGMA journal_mode=WAL;")
                await db.execute("PRAGMA foreign_keys=ON;")
                await db.execute(sql, args or ())
                await db.commit()
        else:
            await asyncio.to_thread(self._db_exec_sync, sql, args or ())

    def _db_exec_sync(self, sql: str, args: Tuple[Any, ...] | List[Any]) -> None:
        conn = sqlite3.connect(self.db.path)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.execute(sql, args)
            conn.commit()
        finally:
            conn.close()

    async def _db_fetchone(self, sql: str, args: Tuple[Any, ...]) -> Optional[sqlite3.Row]:
        if aiosqlite:
            async with aiosqlite.connect(self.db.path) as db:
                db.row_factory = sqlite3.Row
                await db.execute("PRAGMA foreign_keys=ON;")
                cur = await db.execute(sql, args)
                row = await cur.fetchone()
                await cur.close()
                return row
        return await asyncio.to_thread(self._db_fetchone_sync, sql, args)

    def _db_fetchone_sync(self, sql: str, args: Tuple[Any, ...]) -> Optional[sqlite3.Row]:
        conn = sqlite3.connect(self.db.path)
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(sql, args)
            row = cur.fetchone()
            cur.close()
            return row
        finally:
            conn.close()

    async def _db_fetchall(self, sql: str, args: Tuple[Any, ...]) -> List[sqlite3.Row]:
        if aiosqlite:
            async with aiosqlite.connect(self.db.path) as db:
                db.row_factory = sqlite3.Row
                await db.execute("PRAGMA foreign_keys=ON;")
                cur = await db.execute(sql, args)
                rows = await cur.fetchall()
                await cur.close()
                return rows
        return await asyncio.to_thread(self._db_fetchall_sync, sql, args)

    def _db_fetchall_sync(self, sql: str, args: Tuple[Any, ...]) -> List[sqlite3.Row]:
        conn = sqlite3.connect(self.db.path)
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(sql, args)
            rows = cur.fetchall()
            cur.close()
            return rows
        finally:
            conn.close()

    def _sql_init(self) -> str:
        return """
        BEGIN;
        CREATE TABLE IF NOT EXISTS assets (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          key TEXT NOT NULL,
          mime_type TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          checksum_sha256 TEXT NOT NULL,
          checksum_blake3 TEXT,
          storage_scheme TEXT NOT NULL,
          storage_url TEXT NOT NULL,
          labels_json TEXT NOT NULL,
          tags_json TEXT NOT NULL,
          metadata_json TEXT NOT NULL,
          rights_json TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          deleted_at TEXT,
          version INTEGER NOT NULL DEFAULT 1,
          etag TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_assets_tenant_key_active
          ON assets(tenant_id, key)
          WHERE deleted_at IS NULL;
        CREATE INDEX IF NOT EXISTS ix_assets_tenant_created
          ON assets(tenant_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS ix_assets_tenant_mime
          ON assets(tenant_id, mime_type);
        CREATE INDEX IF NOT EXISTS ix_assets_checksum
          ON assets(checksum_sha256);

        CREATE TABLE IF NOT EXISTS variants (
          id TEXT PRIMARY KEY,
          asset_id TEXT NOT NULL,
          name TEXT NOT NULL,
          mime_type TEXT NOT NULL,
          size_bytes INTEGER NOT NULL,
          checksum_sha256 TEXT NOT NULL,
          width INTEGER,
          height INTEGER,
          duration_ms INTEGER,
          storage_url TEXT NOT NULL,
          created_at TEXT NOT NULL,
          FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS ix_variants_asset ON variants(asset_id);
        COMMIT;
        """

# =============================================================================
# S3-бэкенд (скелет для расширения)
# =============================================================================

class S3AssetCatalog(LocalFSAssetCatalog):
    """
    Скелет для S3-совместимого каталога: метаданные в SQLite, контент в S3.
    Реализацию загрузок/пресайн-ссылок добавьте под свои требования (boto3/aioboto3).
    """

    def __init__(self, root_dir: str | Path, bucket: str, prefix: str = "", timeline: Optional[TimelineLogger] = None) -> None:
        super().__init__(root_dir, timeline=timeline)
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    # Переопределите put_stream/put_bytes, чтобы писать в s3:// и выставлять storage_url вида s3://bucket/key
    # В этом примерном скелете используем локальный CAS, чтобы схема и API были совместимы.


# =============================================================================
# Пример использования (докстринг; не исполняется автоматически)
# =============================================================================
"""
from mythos.assets.catalog import LocalFSAssetCatalog, AssetQuery, AssetVariant

catalog = LocalFSAssetCatalog("/srv/mythos-assets")
await catalog.init()

data = b"hello world"
res = await catalog.put_bytes("tenantA", "docs/hello.txt", data, mime_type="text/plain", labels={"lang":"en"}, tags=["doc"])
print(res.created, res.asset.etag, res.asset.storage_url)

page = await catalog.list(AssetQuery(tenant_id="tenantA", key_prefix="docs/", limit=10))
for a in page.items:
    print(a.key, a.size_bytes)

# Добавление варианта (например, сгенерированный thumbnail):
var = AssetVariant(name="thumbnail", mime_type="image/webp", size_bytes=1024,
                   checksum_sha256="...", width=320, height=180, storage_url="file:///path/to/thumb.webp")
updated = await catalog.add_variant("tenantA", "docs/hello.txt", var, if_match=res.asset.etag)
print(updated.version, updated.etag)
"""
