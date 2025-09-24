# oblivionvault_core/api/http/routers/v1/archive.py
from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Annotated, AsyncIterator, Dict, List, Optional, Protocol, Tuple

import anyio
from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, Request, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# Используем конверты ответов из server.py для единообразия
try:
    from oblivionvault_core.api.http.server import ok_envelope, error_envelope  # type: ignore
except Exception:
    # Фолбэк на случай изоляции файла (тесты)
    def ok_envelope(data):  # type: ignore
        return {"success": True, "data": data, "error": None}

    def error_envelope(code: str, message: str, details: Optional[dict] = None):  # type: ignore
        return {"success": False, "data": None, "error": {"code": code, "message": message, "details": details}}

log = logging.getLogger("oblivionvault.http.archive")

# =========================
# Константы и утилиты
# =========================

ETag = str
ArchiveId = str
VersionId = str

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def to_http_date(dt: datetime) -> str:
    # RFC 7231
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")

def weak_etag(hex_digest: str) -> ETag:
    return f'W/"{hex_digest}"'

def sha256_stream() -> "hashlib._Hash":
    return hashlib.sha256()

def detect_mime(filename: str) -> str:
    mt, _ = mimetypes.guess_type(filename)
    return mt or "application/octet-stream"

# =========================
# Схемы API
# =========================

class ArchiveCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    tags: List[str] = Field(default_factory=list, max_items=64)

class ArchiveUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    tags: Optional[List[str]] = Field(None, max_items=64)

class ArchiveMeta(BaseModel):
    id: ArchiveId
    name: str
    created_at: datetime
    updated_at: datetime
    deleted: bool = False
    tags: List[str] = Field(default_factory=list)
    latest_version: Optional[VersionId] = None
    versions: int = 0
    size: Optional[int] = None
    content_type: Optional[str] = None
    etag: Optional[ETag] = None

class ArchiveListItem(BaseModel):
    id: ArchiveId
    name: str
    updated_at: datetime
    deleted: bool
    tags: List[str] = Field(default_factory=list)
    latest_version: Optional[VersionId] = None
    size: Optional[int] = None
    content_type: Optional[str] = None

class Page(BaseModel):
    total: int
    offset: int
    limit: int
    items: List[ArchiveListItem]

# =========================
# Модель домена и интерфейсы
# =========================

@dataclass(frozen=True)
class VersionRecord:
    version_id: VersionId
    size: int
    content_type: str
    created_at: datetime
    etag: ETag
    path: Optional[str] = None  # для файлового бэкенда
    _mem: Optional[bytes] = None  # для in-memory

@dataclass
class ArchiveRecord:
    id: ArchiveId
    name: str
    created_at: datetime
    updated_at: datetime
    deleted: bool = False
    tags: List[str] = field(default_factory=list)
    versions: List[VersionRecord] = field(default_factory=list)

    @property
    def latest(self) -> Optional[VersionRecord]:
        return self.versions[-1] if self.versions else None

class StorageBackend(Protocol):
    async def write(self, archive_id: ArchiveId, version_id: VersionId, stream: AsyncIterator[bytes], *, size_hint: Optional[int], content_type: str) -> VersionRecord: ...
    async def read(self, record: VersionRecord, *, start: Optional[int] = None, end_inclusive: Optional[int] = None) -> AsyncIterator[bytes]: ...
    async def size(self, record: VersionRecord) -> int: ...

# =========================
# Реализации стораджей
# =========================

class MemoryStorage(StorageBackend):
    async def write(self, archive_id: ArchiveId, version_id: VersionId, stream: AsyncIterator[bytes], *, size_hint: Optional[int], content_type: str) -> VersionRecord:
        h = sha256_stream()
        chunks: List[bytes] = []
        total = 0
        async for chunk in stream:
            h.update(chunk)
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        etag = weak_etag(h.hexdigest())
        return VersionRecord(version_id=version_id, size=total, content_type=content_type, created_at=utcnow(), etag=etag, _mem=data)

    async def read(self, record: VersionRecord, *, start: Optional[int] = None, end_inclusive: Optional[int] = None) -> AsyncIterator[bytes]:
        data = record._mem or b""
        s = start or 0
        e = (end_inclusive + 1) if end_inclusive is not None else len(data)
        view = memoryview(data)[s:e]
        # chunked отдача
        chunk = 64 * 1024
        for i in range(0, len(view), chunk):
            yield bytes(view[i:i+chunk])

    async def size(self, record: VersionRecord) -> int:
        return record.size

class FileSystemStorage(StorageBackend):
    """
    Файловый стор с offload блокирующих операций (без aiofiles),
    корень указывается через ENV OBLIVIONVAULT_FS_ROOT (по умолчанию /var/lib/oblivionvault).
    """
    def __init__(self, root: Optional[str] = None) -> None:
        self.root = root or os.getenv("OBLIVIONVAULT_FS_ROOT", "/var/lib/oblivionvault")

    def _vpath(self, archive_id: ArchiveId, version_id: VersionId) -> str:
        return os.path.join(self.root, archive_id, version_id)

    async def write(self, archive_id: ArchiveId, version_id: VersionId, stream: AsyncIterator[bytes], *, size_hint: Optional[int], content_type: str) -> VersionRecord:
        path = self._vpath(archive_id, version_id)
        # ensure dir
        await anyio.to_thread.run_sync(lambda: os.makedirs(os.path.dirname(path), exist_ok=True))
        h = sha256_stream()
        total = 0

        def _write_all(data_iter: List[bytes]):
            with open(path, "wb") as f:
                for chunk in data_iter:
                    f.write(chunk)

        # буферизуем файлами по 1Мб чтобы не раздувать память
        buf: List[bytes] = []
        buf_bytes = 0
        async for chunk in stream:
            h.update(chunk)
            buf.append(chunk)
            buf_bytes += len(chunk)
            total += len(chunk)
            if buf_bytes >= 1 * 1024 * 1024:
                await anyio.to_thread.run_sync(_write_all, buf)
                buf.clear()
                buf_bytes = 0
        if buf:
            await anyio.to_thread.run_sync(_write_all, buf)

        etag = weak_etag(h.hexdigest())
        return VersionRecord(version_id=version_id, size=total, content_type=content_type, created_at=utcnow(), etag=etag, path=path)

    async def read(self, record: VersionRecord, *, start: Optional[int] = None, end_inclusive: Optional[int] = None) -> AsyncIterator[bytes]:
        assert record.path, "path required for filesystem storage"

        def _open():
            return open(record.path, "rb")

        f = await anyio.to_thread.run_sync(_open)
        try:
            if start:
                await anyio.to_thread.run_sync(f.seek, start)
            remaining = None if end_inclusive is None else (end_inclusive - (start or 0) + 1)
            chunk = 64 * 1024
            while True:
                to_read = chunk if remaining is None else min(chunk, remaining)
                if to_read == 0:
                    break
                data = await anyio.to_thread.run_sync(f.read, to_read)
                if not data:
                    break
                if remaining is not None:
                    remaining -= len(data)
                yield data
        finally:
            await anyio.to_thread.run_sync(f.close)

    async def size(self, record: VersionRecord) -> int:
        assert record.path
        return await anyio.to_thread.run_sync(lambda: os.path.getsize(record.path))

# =========================
# Хранилище метаданных (in-memory)
# В реальном проде заменить на БД.
# =========================

class ArchiveRepo:
    def __init__(self) -> None:
        self._items: Dict[ArchiveId, ArchiveRecord] = {}

    async def create(self, name: str, tags: List[str]) -> ArchiveRecord:
        aid = uuid.uuid4().hex
        now = utcnow()
        rec = ArchiveRecord(id=aid, name=name, created_at=now, updated_at=now, tags=list(dict.fromkeys(tags)))
        self._items[aid] = rec
        return rec

    async def get(self, aid: ArchiveId, *, include_deleted: bool = False) -> ArchiveRecord:
        rec = self._items.get(aid)
        if not rec or (rec.deleted and not include_deleted):
            raise KeyError(aid)
        return rec

    async def update(self, aid: ArchiveId, *, name: Optional[str], tags: Optional[List[str]]) -> ArchiveRecord:
        rec = await self.get(aid, include_deleted=True)
        if name is not None:
            rec.name = name
        if tags is not None:
            rec.tags = list(dict.fromkeys(tags))
        rec.updated_at = utcnow()
        return rec

    async def add_version(self, aid: ArchiveId, version: VersionRecord) -> ArchiveRecord:
        rec = await self.get(aid, include_deleted=True)
        rec.versions.append(version)
        rec.updated_at = utcnow()
        return rec

    async def list(self, *, q: Optional[str], tag: Optional[str], offset: int, limit: int, include_deleted: bool = False) -> Tuple[int, List[ArchiveRecord]]:
        items = list(self._items.values())
        if not include_deleted:
            items = [x for x in items if not x.deleted]
        if q:
            ql = q.lower()
            items = [x for x in items if ql in x.name.lower()]
        if tag:
            items = [x for x in items if tag in x.tags]
        items.sort(key=lambda r: r.updated_at, reverse=True)
        total = len(items)
        return total, items[offset: offset + limit]

    async def soft_delete(self, aid: ArchiveId) -> None:
        rec = await self.get(aid, include_deleted=True)
        rec.deleted = True
        rec.updated_at = utcnow()

    async def restore(self, aid: ArchiveId) -> ArchiveRecord:
        rec = await self.get(aid, include_deleted=True)
        rec.deleted = False
        rec.updated_at = utcnow()
        return rec

# =========================
# Идемпотентность (простая, in-memory)
# =========================

class IdempotencyStore:
    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}

    def check_and_remember(self, key: Optional[str], ttl_sec: int = 600) -> bool:
        now = time.time()
        # очистка
        expired = [k for k, t0 in self._seen.items() if now - t0 > ttl_sec]
        for k in expired:
            self._seen.pop(k, None)
        if not key:
            return True  # без ключа — считаем неидемпотентным, но не блокируем
        if key in self._seen:
            return False
        self._seen[key] = now
        return True

idem_store = IdempotencyStore()

# =========================
# Зависимости
# =========================

_repo = ArchiveRepo()

def get_repo() -> ArchiveRepo:
    return _repo

def get_storage() -> StorageBackend:
    # Если объявлен OBLIVIONVAULT_FS_ROOT — используем файловый стор.
    root = os.getenv("OBLIVIONVAULT_FS_ROOT")
    return FileSystemStorage(root) if root else MemoryStorage()

def require_auth(request: Request) -> None:
    # Простейшая заглушка: в prod требуем Bearer, иначе допускаем.
    env = os.getenv("APP_ENV", "dev")
    if env == "prod":
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Unauthorized")

Auth = Annotated[None, Depends(require_auth)]

# =========================
# Роутер v1
# =========================

router = APIRouter(prefix="/api/v1/archives", tags=["archives"])

# --- Создать архив (метаданные)
@router.post("", status_code=201)
async def create_archive(payload: ArchiveCreate, repo: ArchiveRepo = Depends(get_repo), _: Auth = None):
    rec = await repo.create(name=payload.name, tags=payload.tags)
    meta = _to_meta(rec)
    return ok_envelope(meta.model_dump())

# --- Обновить метаданные
@router.patch("/{archive_id}")
async def update_archive(
    archive_id: Annotated[str, Path(min_length=8)],
    payload: ArchiveUpdate,
    repo: ArchiveRepo = Depends(get_repo),
    _: Auth = None,
):
    try:
        rec = await repo.update(archive_id, name=payload.name, tags=payload.tags)
    except KeyError:
        raise HTTPException(status_code=404, detail="Archive not found")
    return ok_envelope(_to_meta(rec).model_dump())

# --- Получить метаданные
@router.get("/{archive_id}")
async def get_archive(archive_id: Annotated[str, Path(min_length=8)], repo: ArchiveRepo = Depends(get_repo), _: Auth = None):
    try:
        rec = await repo.get(archive_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Archive not found")
    return ok_envelope(_to_meta(rec).model_dump())

# --- Список (пагинация, фильтры)
@router.get("")
async def list_archives(
    q: Annotated[Optional[str], Query(description="поиск по имени")] = None,
    tag: Annotated[Optional[str], Query(description="фильтр по тегу")] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(gt=0, le=200)] = 50,
    repo: ArchiveRepo = Depends(get_repo),
    _: Auth = None,
):
    total, records = await repo.list(q=q, tag=tag, offset=offset, limit=limit)
    items = [
        ArchiveListItem(
            id=r.id,
            name=r.name,
            updated_at=r.updated_at,
            deleted=r.deleted,
            tags=r.tags,
            latest_version=r.latest.version_id if r.latest else None,
            size=r.latest.size if r.latest else None,
            content_type=r.latest.content_type if r.latest else None,
        )
        for r in records
    ]
    page = Page(total=total, offset=offset, limit=limit, items=items)
    return ok_envelope(page.model_dump())

# --- Мягкое удаление
@router.delete("/{archive_id}", status_code=204)
async def delete_archive(archive_id: Annotated[str, Path(min_length=8)], repo: ArchiveRepo = Depends(get_repo), _: Auth = None):
    try:
        await repo.soft_delete(archive_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Archive not found")
    return Response(status_code=204)

# --- Восстановление
@router.post("/{archive_id}/restore")
async def restore_archive(archive_id: Annotated[str, Path(min_length=8)], repo: ArchiveRepo = Depends(get_repo), _: Auth = None):
    try:
        rec = await repo.restore(archive_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Archive not found")
    return ok_envelope(_to_meta(rec).model_dump())

# --- Загрузка нового контента (новая версия)
@router.put("/{archive_id}/content", status_code=201)
async def upload_content(
    request: Request,
    archive_id: Annotated[str, Path(min_length=8)],
    file: UploadFile = File(..., description="multipart/form-data; поле 'file'"),
    repo: ArchiveRepo = Depends(get_repo),
    storage: StorageBackend = Depends(get_storage),
    _: Auth = None,
):
    # идемпотентность по заголовку
    idem = request.headers.get("Idempotency-Key")
    if not idem_store.check_and_remember(idem):
        raise HTTPException(status_code=409, detail="Duplicate request (idempotency)")

    try:
        rec = await repo.get(archive_id, include_deleted=True)
    except KeyError:
        raise HTTPException(status_code=404, detail="Archive not found")

    if rec.deleted:
        raise HTTPException(status_code=409, detail="Archive is deleted")

    version_id = uuid.uuid4().hex
    content_type = file.content_type or detect_mime(file.filename or "blob")
    size_hint = None

    async def iter_file() -> AsyncIterator[bytes]:
        while True:
            chunk = await file.read(128 * 1024)
            if not chunk:
                break
            yield chunk

    vrec = await storage.write(archive_id, version_id, iter_file(), size_hint=size_hint, content_type=content_type)
    rec = await repo.add_version(archive_id, vrec)

    meta = _to_meta(rec)
    headers = {"ETag": vrec.etag, "Last-Modified": to_http_date(vrec.created_at)}
    return Response(content=_json_bytes(ok_envelope(meta.model_dump())), media_type="application/json", headers=headers, status_code=201)

# --- HEAD по контенту (мета)
@router.head("/{archive_id}/content")
async def head_content(
    archive_id: Annotated[str, Path(min_length=8)],
    repo: ArchiveRepo = Depends(get_repo),
    storage: StorageBackend = Depends(get_storage),
    version: Optional[str] = Query(default=None),
    _: Auth = None,
):
    try:
        rec = await repo.get(archive_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Archive not found")
    v = _select_version(rec, version)
    size = await storage.size(v)
    return Response(
        status_code=200,
        headers={
            "Content-Length": str(size),
            "Content-Type": v.content_type,
            "ETag": v.etag,
            "Last-Modified": to_http_date(v.created_at),
            "Accept-Ranges": "bytes",
        },
    )

# --- Скачать контент (поддержка Range/ETag/If-None-Match)
@router.get("/{archive_id}/content")
async def get_content(
    request: Request,
    archive_id: Annotated[str, Path(min_length=8)],
    version: Optional[str] = Query(default=None),
    repo: ArchiveRepo = Depends(get_repo),
    storage: StorageBackend = Depends(get_storage),
    _: Auth = None,
):
    try:
        rec = await repo.get(archive_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Archive not found")

    v = _select_version(rec, version)

    # Conditional If-None-Match
    inm = request.headers.get("if-none-match")
    if inm and inm.strip() == v.etag:
        return Response(status_code=304)

    size = await storage.size(v)
    start, end, status_code, content_range = _parse_range(request.headers.get("range"), size)

    async def body():
        async for chunk in storage.read(v, start=start, end_inclusive=end):
            yield chunk

    headers = {
        "ETag": v.etag,
        "Last-Modified": to_http_date(v.created_at),
        "Accept-Ranges": "bytes",
        "Content-Type": v.content_type,
    }
    if content_range:
        headers["Content-Range"] = content_range
        headers["Content-Length"] = str(end - start + 1)
    else:
        headers["Content-Length"] = str(size)

    return StreamingResponse(body(), status_code=status_code, headers=headers)

# =========================
# Вспомогательные функции
# =========================

def _to_meta(r: ArchiveRecord) -> ArchiveMeta:
    latest = r.latest
    return ArchiveMeta(
        id=r.id,
        name=r.name,
        created_at=r.created_at,
        updated_at=r.updated_at,
        deleted=r.deleted,
        tags=r.tags,
        latest_version=latest.version_id if latest else None,
        versions=len(r.versions),
        size=latest.size if latest else None,
        content_type=latest.content_type if latest else None,
        etag=latest.etag if latest else None,
    )

def _select_version(rec: ArchiveRecord, version: Optional[str]) -> VersionRecord:
    if version is None:
        v = rec.latest
        if not v:
            raise HTTPException(status_code=404, detail="No content")
        return v
    for v in rec.versions:
        if v.version_id == version:
            return v
    raise HTTPException(status_code=404, detail="Version not found")

def _parse_range(header: Optional[str], size: int) -> Tuple[int, int, int, Optional[str]]:
    """
    Возвращает (start, end, status_code, Content-Range header|None)
    Поддерживается простейший формат: bytes=start-end
    """
    if not header or not header.startswith("bytes="):
        return 0, size - 1, 200, None
    try:
        rng = header[6:]
        start_s, end_s = rng.split("-", 1)
        if start_s == "":
            # суффиксные диапазоны: bytes=-N
            length = int(end_s)
            if length <= 0:
                raise ValueError
            start = max(size - length, 0)
            end = size - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else size - 1
        if start < 0 or end >= size or start > end:
            raise ValueError
        content_range = f"bytes {start}-{end}/{size}"
        return start, end, 206, content_range
    except Exception:
        # Неверный диапазон
        raise HTTPException(
            status_code=416,
            detail="Invalid Range",
            headers={"Content-Range": f"bytes */{size}"},
        )

def _json_bytes(obj) -> bytes:
    # без лишних зависимостей
    import json
    return json.dumps(obj, default=str).encode("utf-8")
