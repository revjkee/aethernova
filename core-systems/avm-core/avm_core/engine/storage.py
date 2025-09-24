"""
avm_core.engine.storage — промышленный слой хранилищ для AVM Core.

Особенности:
- Асинхронные интерфейсы репозиториев (CRUD, поиск, пагинация, счётчики).
- Единая иерархия исключений StorageError (NotFound, Conflict, Transient, Permission, Validation).
- Оптимистическая конкуренция: версия/etag + обновление по условию (IF-MATCH).
- Unit-of-Work поверх SQLAlchemy Async (ленивый импорт; безопасно отключается).
- Ретраи с экспоненциальной задержкой для временных ошибок + идемпотентные операции.
- Шифрование на уровне приложения (плагин AEAD): envelope-режим (no-op, если крипто недоступен).
- Blob-хранилище: интерфейс + InMemory; S3-совместимый адаптер как опциональный.
- Без жёсткой зависимости от внешних библиотек — всё через lazy import. Совместимо с avm_core.deps.

Лицензия: Proprietary
Автор: NeuroCity Engineering
"""
from __future__ import annotations

import abc
import asyncio
import contextlib
import dataclasses
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Dict,
    Generic,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

# Лёгкая интеграция с DI-контейнером (deps.py)
try:
    from avm_core import deps as _deps  # type: ignore
except Exception:  # pragma: no cover
    _deps = None  # допускаем запуск вне окружения приложения

# ============================================================
# Исключения
# ============================================================

class StorageError(RuntimeError):
    """Базовая ошибка слоя хранения."""

class NotFound(StorageError):
    """Объект не найден."""

class Conflict(StorageError):
    """Конфликт версий / нарушена оптимистическая блокировка."""

class PermissionDenied(StorageError):
    """Недостаточно прав на операцию."""

class ValidationError(StorageError):
    """Невалидные данные или нарушение инвариантов."""

class TransientError(StorageError):
    """Временная/сетевой сбой — имеет смысл повторить операцию."""

# ============================================================
# Общие типы и утилиты
# ============================================================

T = TypeVar("T")
ID = Union[str, int]

@dataclass(frozen=True)
class Page:
    items: List[Any]
    total: Optional[int]
    next_cursor: Optional[str] = None

@dataclass(frozen=True)
class Query:
    filters: Mapping[str, Any] = field(default_factory=dict)
    sort: Sequence[Tuple[str, str]] = field(default_factory=list)  # [(field, "asc"|"desc")]
    limit: int = 50
    cursor: Optional[str] = None  # для keyset-пагинации

def _now_ms() -> int:
    return int(time.time() * 1000)

def _etag(payload: Union[str, bytes]) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def _logger():
    if _deps is None:
        return None
    try:
        return _deps.get_logger()
    except Exception:
        return None

def _tracer_span(name: str):
    if _deps is None:
        @contextlib.contextmanager
        def _noop():
            yield
        return _noop()
    try:
        tracer = _deps.get_tracer()
        return tracer.start_span(name)
    except Exception:
        @contextlib.contextmanager
        def _noop():
            yield
        return _noop()

# ============================================================
# AEAD / Envelope шифрование (опционально)
# ============================================================

class AEAD(Protocol):
    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes: ...
    def decrypt(self, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes: ...

class NoopAEAD:
    """Безопасная заглушка: ничего не шифрует, но сигнализирует в логах."""
    def __init__(self) -> None:
        lg = _logger()
        if lg:
            lg.warning("aead_noop_enabled")
    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        return plaintext
    def decrypt(self, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        return ciphertext

class FernetAEAD:
    """AEAD-обёртка на базе cryptography.fernet (при наличии)."""
    def __init__(self, key: Optional[bytes] = None) -> None:
        try:
            from cryptography.fernet import Fernet  # type: ignore
        except Exception as e:  # pragma: no cover
            raise TransientError("cryptography not available for AEAD") from e
        if key is None:
            # Ключ можно получить из env или deps.crypto
            k_env = os.getenv("AVM_STORAGE_FERNET_KEY")
            if k_env:
                key = k_env.encode("utf-8")
            else:
                # Если есть crypto-провайдер — можно детерминированно получить материал
                key = Fernet.generate_key()
        self._fernet = Fernet(key)  # type: ignore[unreachable]

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        # Fernet не поддерживает AAD, поэтому объединяем для аутентификации
        if aad:
            plaintext = aad + b"||" + plaintext
        return self._fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, aad: Optional[bytes] = None) -> bytes:
        pt = self._fernet.decrypt(ciphertext)
        if aad:
            try:
                prefix, real = pt.split(b"||", 1)
            except ValueError:  # pragma: no cover
                raise PermissionDenied("AEAD integrity error")
            if prefix != aad:
                raise PermissionDenied("AEAD AAD mismatch")
            return real
        return pt

def _get_aead() -> AEAD:
    # Попытка инициализировать AEAD. Если нет cryptography — fallback к Noop.
    try:
        return FernetAEAD()
    except Exception:
        return NoopAEAD()

# ============================================================
# Доменные контракты
# ============================================================

class VersionedEntity(Protocol):
    id: ID
    version: str                    # ETag/версия для оптимистической блокировки
    created_at_ms: int
    updated_at_ms: int

class AsyncRepository(Generic[T], metaclass=abc.ABCMeta):
    """Асинхронный контракт репозитория для сущности T."""
    @abc.abstractmethod
    async def get(self, obj_id: ID) -> T: ...
    @abc.abstractmethod
    async def exists(self, obj_id: ID) -> bool: ...
    @abc.abstractmethod
    async def create(self, obj: T, *, if_not_exists: bool = False) -> T: ...
    @abc.abstractmethod
    async def update(self, obj: T, *, if_match: Optional[str] = None) -> T: ...
    @abc.abstractmethod
    async def delete(self, obj_id: ID, *, if_match: Optional[str] = None) -> None: ...
    @abc.abstractmethod
    async def find(self, q: Query) -> Page: ...
    @abc.abstractmethod
    async def count(self, q: Query) -> int: ...

# ============================================================
# Ретраи/идемпотентность
# ============================================================

async def _retry(op, *, retries: int = 2, base_delay: float = 0.1, retry_for=(TransientError,)) -> Any:
    last_exc: Optional[BaseException] = None
    for attempt in range(retries + 1):
        try:
            return await op()
        except retry_for as exc:
            last_exc = exc
            if attempt >= retries:
                break
            await asyncio.sleep(base_delay * (2 ** attempt))
    assert last_exc is not None
    raise last_exc

# ============================================================
# InMemory реализация (для dev/test и как референс)
# ============================================================

class InMemoryRepository(AsyncRepository[T]):
    def __init__(self, *, aead: Optional[AEAD] = None) -> None:
        self._store: Dict[ID, Dict[str, Any]] = {}
        self._aead = aead or _get_aead()

    def _clone(self, obj: T) -> Dict[str, Any]:
        # Сериализация через JSON для детерминизма
        if dataclasses.is_dataclass(obj):
            payload = dataclasses.asdict(obj)
        elif isinstance(obj, dict):
            payload = dict(obj)
        else:
            # Лучший-effort: пытаемся через __dict__
            payload = dict(getattr(obj, "__dict__", {}))
        return json.loads(json.dumps(payload, ensure_ascii=False))

    async def get(self, obj_id: ID) -> T:
        with _tracer_span("inmem.get"):
            if obj_id not in self._store:
                raise NotFound(str(obj_id))
            raw = self._store[obj_id]
            return raw["obj"]  # type: ignore[return-value]

    async def exists(self, obj_id: ID) -> bool:
        return obj_id in self._store

    async def create(self, obj: T, *, if_not_exists: bool = False) -> T:
        with _tracer_span("inmem.create"):
            payload = self._clone(obj)
            oid = payload.get("id")
            if oid in self._store and not if_not_exists:
                raise Conflict(f"exists: {oid}")
            now = _now_ms()
            version = _etag(json.dumps(payload, ensure_ascii=False) + str(now))
            payload["created_at_ms"] = payload.get("created_at_ms", now)
            payload["updated_at_ms"] = now
            payload["version"] = version
            self._store[oid] = {"obj": payload}
            return self._store[oid]["obj"]  # type: ignore[return-value]

    async def update(self, obj: T, *, if_match: Optional[str] = None) -> T:
        with _tracer_span("inmem.update"):
            payload = self._clone(obj)
            oid = payload.get("id")
            if oid not in self._store:
                raise NotFound(str(oid))
            current = self._store[oid]["obj"]
            if if_match and current.get("version") != if_match:
                raise Conflict("version_mismatch")
            now = _now_ms()
            payload["created_at_ms"] = current.get("created_at_ms")
            payload["updated_at_ms"] = now
            payload["version"] = _etag(json.dumps(payload, ensure_ascii=False) + str(now))
            self._store[oid] = {"obj": payload}
            return payload  # type: ignore[return-value]

    async def delete(self, obj_id: ID, *, if_match: Optional[str] = None) -> None:
        with _tracer_span("inmem.delete"):
            if obj_id not in self._store:
                raise NotFound(str(obj_id))
            current = self._store[obj_id]["obj"]
            if if_match and current.get("version") != if_match:
                raise Conflict("version_mismatch")
            del self._store[obj_id]

    async def find(self, q: Query) -> Page:
        with _tracer_span("inmem.find"):
            items = [rec["obj"] for rec in self._store.values()]
            # Простые фильтры по равенству
            for k, v in q.filters.items():
                items = [i for i in items if i.get(k) == v]
            # Сортировка
            for field, order in reversed(q.sort or []):
                items.sort(key=lambda x: x.get(field), reverse=(order.lower() == "desc"))
            # Курсор: используем updated_at_ms как ключ
            if q.cursor:
                try:
                    cursor_ts = int(q.cursor)
                    items = [i for i in items if i.get("updated_at_ms", 0) < cursor_ts]
                except ValueError:
                    pass
            limited = items[: max(0, q.limit)]
            next_cursor = None
            if len(items) > len(limited):
                last = limited[-1]
                next_cursor = str(last.get("updated_at_ms", 0))
            return Page(items=limited, total=len(items), next_cursor=next_cursor)

    async def count(self, q: Query) -> int:
        page = await self.find(Query(filters=q.filters, limit=10**9))
        return page.total or 0

# ============================================================
# SQLAlchemy Async (опционально)
# ============================================================

class SARepository(AsyncRepository[T]):
    """
    Базовый репозиторий для SQLAlchemy Async.
    Требует:
      - _table: Table объект
      - _pk: имя PK колонки
      - _to_row(obj) -> dict
      - _from_row(row) -> T
    """
    _table = None
    _pk: str = "id"

    def __init__(self, engine=None, *, aead: Optional[AEAD] = None) -> None:
        self._engine = engine  # AsyncEngine
        self._aead = aead or _get_aead()
        if self._engine is None:
            # Попытка взять из deps
            if _deps:
                try:
                    self._engine = _deps.get_db()._engine  # type: ignore[attr-defined]
                except Exception as e:  # pragma: no cover
                    raise TransientError("DB engine not available; initialize deps.init_container()") from e
            else:  # pragma: no cover
                raise TransientError("No DB engine provided")

    # --- Вспомогательные методы ---
    async def _conn(self):
        try:
            from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
            from sqlalchemy.orm import sessionmaker  # type: ignore
        except Exception as e:  # pragma: no cover
            raise TransientError("sqlalchemy async not available") from e
        maker = sessionmaker(self._engine, expire_on_commit=False, class_=AsyncSession)
        return maker()

    def _ifm(self, col_version, if_match: Optional[str]):
        # Генерирует условие IF-MATCH
        if if_match is None:
            return True
        return col_version == if_match

    # --- Контракт ---
    async def get(self, obj_id: ID) -> T:
        async def _op():
            with _tracer_span("sa.get"):
                from sqlalchemy import select  # type: ignore
                async with self._conn() as s:
                    q = select(self._table).where(self._table.c[self._pk] == obj_id)
                    res = await s.execute(q)
                    row = res.mappings().first()
                    if not row:
                        raise NotFound(str(obj_id))
                    return self._from_row(row)
        return await _retry(_op)

    async def exists(self, obj_id: ID) -> bool:
        async def _op():
            from sqlalchemy import select, literal_column  # type: ignore
            async with self._conn() as s:
                q = select(literal_column("1")).select_from(self._table).where(self._table.c[self._pk] == obj_id).limit(1)
                res = await s.execute(q)
                return res.first() is not None
        return await _retry(_op)

    async def create(self, obj: T, *, if_not_exists: bool = False) -> T:
        async def _op():
            with _tracer_span("sa.create"):
                from sqlalchemy import insert  # type: ignore
                async with self._conn() as s:
                    now = _now_ms()
                    row = self._to_row(obj)
                    row.setdefault("created_at_ms", now)
                    row["updated_at_ms"] = now
                    row["version"] = _etag(json.dumps(row, ensure_ascii=False) + str(now))
                    stmt = insert(self._table).values(**row)
                    if if_not_exists:
                        # ON CONFLICT DO NOTHING (Postgres); для других СУБД адаптируйте.
                        try:
                            stmt = stmt.on_conflict_do_nothing(index_elements=[self._pk])  # type: ignore[attr-defined]
                        except Exception:
                            pass
                    await s.execute(stmt)
                    await s.commit()
                    return self._from_row(row)
        return await _retry(_op)

    async def update(self, obj: T, *, if_match: Optional[str] = None) -> T:
        async def _op():
            with _tracer_span("sa.update"):
                from sqlalchemy import update, select  # type: ignore
                async with self._conn() as s:
                    now = _now_ms()
                    row = self._to_row(obj)
                    oid = row.get(self._pk)
                    if oid is None:
                        raise ValidationError("missing primary key")
                    new_row = dict(row)
                    new_row["updated_at_ms"] = now
                    new_row["version"] = _etag(json.dumps(new_row, ensure_ascii=False) + str(now))
                    stmt = (
                        update(self._table)
                        .where(self._table.c[self._pk] == oid)
                        .where(self._ifm(self._table.c["version"], if_match))
                        .values(**new_row)
                    )
                    res = await s.execute(stmt)
                    if res.rowcount == 0:
                        # Либо нет строки, либо конфликт версии
                        # Проверим существование
                        q = select(self._table.c[self._pk]).where(self._table.c[self._pk] == oid)
                        ex = await s.execute(q)
                        if ex.first() is None:
                            raise NotFound(str(oid))
                        raise Conflict("version_mismatch")
                    await s.commit()
                    return self._from_row(new_row)
        return await _retry(_op)

    async def delete(self, obj_id: ID, *, if_match: Optional[str] = None) -> None:
        async def _op():
            with _tracer_span("sa.delete"):
                from sqlalchemy import delete, select  # type: ignore
                async with self._conn() as s:
                    stmt = (
                        delete(self._table)
                        .where(self._table.c[self._pk] == obj_id)
                    )
                    if if_match is not None:
                        # Проверим версию
                        from sqlalchemy import and_  # type: ignore
                        stmt = stmt.where(self._table.c["version"] == if_match)
                    res = await s.execute(stmt)
                    if res.rowcount == 0:
                        # Проверим существование
                        q = select(self._table.c[self._pk]).where(self._table.c[self._pk] == obj_id)
                        ex = await s.execute(q)
                        if ex.first() is None:
                            raise NotFound(str(obj_id))
                        raise Conflict("version_mismatch")
                    await s.commit()
        return await _retry(_op)

    async def find(self, q: Query) -> Page:
        async def _op():
            with _tracer_span("sa.find"):
                from sqlalchemy import select, and_, asc, desc  # type: ignore
                async with self._conn() as s:
                    conds = []
                    for k, v in q.filters.items():
                        if k in self._table.c:
                            conds.append(self._table.c[k] == v)
                    stmt = select(self._table)
                    if conds:
                        stmt = stmt.where(and_(*conds))
                    # keyset по updated_at_ms
                    if q.cursor:
                        try:
                            cur = int(q.cursor)
                            stmt = stmt.where(self._table.c["updated_at_ms"] < cur)
                        except ValueError:
                            pass
                    # сортировки
                    for field, order in (q.sort or []):
                        if field in self._table.c:
                            stmt = stmt.order_by(asc(self._table.c[field]) if order.lower() == "asc" else desc(self._table.c[field]))
                    if not q.sort:
                        stmt = stmt.order_by(desc(self._table.c["updated_at_ms"]))
                    stmt = stmt.limit(max(0, q.limit))
                    res = await s.execute(stmt)
                    rows = [self._from_row(r) for r in res.mappings().all()]
                    next_cursor = None
                    if rows:
                        # предполагаем наличие updated_at_ms
                        last = rows[-1]
                        try:
                            last_ts = getattr(last, "updated_at_ms", None) or last["updated_at_ms"]  # type: ignore[index]
                            next_cursor = str(last_ts)
                        except Exception:
                            pass
                    # total может быть дорогим — по умолчанию None
                    return Page(items=rows, total=None, next_cursor=next_cursor)
        return await _retry(_op)

    async def count(self, q: Query) -> int:
        async def _op():
            from sqlalchemy import select, func, and_  # type: ignore
            async with self._conn() as s:
                conds = []
                for k, v in q.filters.items():
                    if k in self._table.c:
                        conds.append(self._table.c[k] == v)
                stmt = select(func.count()).select_from(self._table)
                if conds:
                    stmt = stmt.where(and_(*conds))
                res = await s.execute(stmt)
                return int(res.scalar() or 0)
        return await _retry(_op)

    # Эти два метода обязан переопределить наследник под свою модель
    def _to_row(self, obj: T) -> Dict[str, Any]:  # pragma: no cover - абстрактно
        raise NotImplementedError
    def _from_row(self, row: Mapping[str, Any]) -> T:  # pragma: no cover - абстрактно
        raise NotImplementedError

# ============================================================
# Unit of Work (опциональный транзакционный контекст)
# ============================================================

@contextlib.asynccontextmanager
async def unit_of_work() -> AsyncIterator[Any]:
    """
    Универсальный UoW поверх SQLAlchemy AsyncSession (если доступен).
    Пример:
        async with unit_of_work() as uow:
            repo = MySARepo(engine=uow.bind)
            await repo.create(...)
    """
    if _deps is None:
        # Нет DI — делаем no-op UoW
        @contextlib.asynccontextmanager
        async def _noop():
            yield None
        async with _noop() as u:
            yield u
        return

    db = _deps.get_db()
    engine = getattr(db, "_engine", None)
    if engine is None:
        @contextlib.asynccontextmanager
        async def _noop():
            yield None
        async with _noop() as u:
            yield u
        return

    from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
    from sqlalchemy.orm import sessionmaker  # type: ignore

    maker = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            with contextlib.suppress(Exception):
                await session.rollback()
            raise

# ============================================================
# Blob Storage
# ============================================================

class BlobStorage(Protocol):
    async def put(self, key: str, data: bytes, *, content_type: Optional[str] = None, encrypt: bool = True) -> str: ...
    async def get(self, key: str, *, decrypt: bool = True) -> bytes: ...
    async def delete(self, key: str) -> None: ...
    async def head(self, key: str) -> Mapping[str, Any]: ...
    async def presign_get(self, key: str, *, expires_sec: int = 300) -> str: ...
    async def presign_put(self, key: str, *, expires_sec: int = 300, content_type: Optional[str] = None) -> str: ...

class InMemoryBlobStorage(BlobStorage):
    def __init__(self, *, aead: Optional[AEAD] = None) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}
        self._aead = aead or _get_aead()

    async def put(self, key: str, data: bytes, *, content_type: Optional[str] = None, encrypt: bool = True) -> str:
        blob = self._aead.encrypt(data, aad=key.encode()) if encrypt else data
        self._data[key] = {
            "blob": blob,
            "content_type": content_type or "application/octet-stream",
            "updated_at_ms": _now_ms(),
            "etag": _etag(data),
            "encrypted": encrypt,
        }
        return key

    async def get(self, key: str, *, decrypt: bool = True) -> bytes:
        meta = self._data.get(key)
        if not meta:
            raise NotFound(key)
        blob = meta["blob"]
        if decrypt and meta.get("encrypted"):
            return self._aead.decrypt(blob, aad=key.encode())
        return blob

    async def delete(self, key: str) -> None:
        if key in self._data:
            del self._data[key]
        else:
            raise NotFound(key)

    async def head(self, key: str) -> Mapping[str, Any]:
        meta = self._data.get(key)
        if not meta:
            raise NotFound(key)
        return {k: v for k, v in meta.items() if k != "blob"}

    async def presign_get(self, key: str, *, expires_sec: int = 300) -> str:
        # Для in-memory возвращаем псевдо-URL
        return f"inmem://{key}?exp={expires_sec}"

    async def presign_put(self, key: str, *, expires_sec: int = 300, content_type: Optional[str] = None) -> str:
        return f"inmem://{key}?method=PUT&exp={expires_sec}"

class S3BlobStorage(BlobStorage):
    """
    Опциональная реализация для S3-совместимого API (boto3|aioboto3).
    Требует наличия aioboto3. Если его нет — TransientError.
    """
    def __init__(self, bucket: str, *, region: Optional[str] = None, aead: Optional[AEAD] = None) -> None:
        self._bucket = bucket
        self._region = region
        self._aead = aead or _get_aead()
        self._session = None  # lazy

    async def _ensure(self):
        if self._session is not None:
            return
        try:
            import aioboto3  # type: ignore
        except Exception as e:  # pragma: no cover
            raise TransientError("aioboto3 not available for S3 storage") from e
        self._session = aioboto3.Session()

    async def put(self, key: str, data: bytes, *, content_type: Optional[str] = None, encrypt: bool = True) -> str:
        await self._ensure()
        payload = self._aead.encrypt(data, aad=key.encode()) if encrypt else data
        import aioboto3  # type: ignore
        async with self._session.client("s3", region_name=self._region) as s3:  # type: ignore
            await s3.put_object(Bucket=self._bucket, Key=key, Body=payload, ContentType=content_type or "application/octet-stream", Metadata={"encrypted": str(encrypt).lower()})
        return key

    async def get(self, key: str, *, decrypt: bool = True) -> bytes:
        await self._ensure()
        async with self._session.client("s3", region_name=self._region) as s3:  # type: ignore
            try:
                obj = await s3.get_object(Bucket=self._bucket, Key=key)
            except Exception as e:
                raise NotFound(key) from e
            body = await obj["Body"].read()
            encrypted = obj.get("Metadata", {}).get("encrypted", "false") == "true"
            if decrypt and encrypted:
                return _get_aead().decrypt(body, aad=key.encode())
            return body

    async def delete(self, key: str) -> None:
        await self._ensure()
        async with self._session.client("s3", region_name=self._region) as s3:  # type: ignore
            await s3.delete_object(Bucket=self._bucket, Key=key)

    async def head(self, key: str) -> Mapping[str, Any]:
        await self._ensure()
        async with self._session.client("s3", region_name=self._region) as s3:  # type: ignore
            try:
                h = await s3.head_object(Bucket=self._bucket, Key=key)
            except Exception as e:
                raise NotFound(key) from e
            return {
                "content_length": h.get("ContentLength"),
                "content_type": h.get("ContentType"),
                "etag": h.get("ETag"),
                "last_modified": int(h.get("LastModified").timestamp() * 1000) if h.get("LastModified") else None,  # type: ignore[union-attr]
            }

    async def presign_get(self, key: str, *, expires_sec: int = 300) -> str:
        await self._ensure()
        async with self._session.client("s3", region_name=self._region) as s3:  # type: ignore
            return await s3.generate_presigned_url("get_object", Params={"Bucket": self._bucket, "Key": key}, ExpiresIn=expires_sec)

    async def presign_put(self, key: str, *, expires_sec: int = 300, content_type: Optional[str] = None) -> str:
        await self._ensure()
        async with self._session.client("s3", region_name=self._region) as s3:  # type: ignore
            return await s3.generate_presigned_url("put_object", Params={"Bucket": self._bucket, "Key": key, "ContentType": content_type or "application/octet-stream"}, ExpiresIn=expires_sec)

# ============================================================
# Пример конкретной доменной сущности и репозитория
# (можно удалить/заменить в вашем проекте)
# ============================================================

@dataclass
class Document(VersionedEntity):
    id: str
    title: str
    content: str
    owner: str
    created_at_ms: int = field(default_factory=_now_ms)
    updated_at_ms: int = field(default_factory=_now_ms)
    version: str = field(default_factory=lambda: _etag(os.urandom(8)))

class DocumentsInMemory(InMemoryRepository[Document]):
    pass

class DocumentsSA(SARepository[Document]):
    """
    Таблица (Postgres пример):

        CREATE TABLE documents (
          id text PRIMARY KEY,
          title text NOT NULL,
          content text NOT NULL,
          owner text NOT NULL,
          version text NOT NULL,
          created_at_ms bigint NOT NULL,
          updated_at_ms bigint NOT NULL
        );

        CREATE INDEX ON documents (updated_at_ms DESC);
    """
    def __init__(self, engine=None, *, aead: Optional[AEAD] = None) -> None:
        # Ленивая инициализация таблицы
        self._table = self._ensure_table()
        super().__init__(engine=engine, aead=aead)

    def _ensure_table(self):
        try:
            from sqlalchemy import Table, Column, MetaData, String, BigInteger  # type: ignore
        except Exception as e:  # pragma: no cover
            raise TransientError("sqlalchemy not available") from e
        metadata = MetaData()
        return Table(
            "documents",
            metadata,
            Column("id", String, primary_key=True),
            Column("title", String, nullable=False),
            Column("content", String, nullable=False),
            Column("owner", String, nullable=False),
            Column("version", String, nullable=False),
            Column("created_at_ms", BigInteger, nullable=False),
            Column("updated_at_ms", BigInteger, nullable=False),
            extend_existing=True,
        )

    def _to_row(self, obj: Document) -> Dict[str, Any]:
        return dataclasses.asdict(obj)

    def _from_row(self, row: Mapping[str, Any]) -> Document:
        return Document(
            id=row["id"],
            title=row["title"],
            content=row["content"],
            owner=row["owner"],
            version=row["version"],
            created_at_ms=int(row["created_at_ms"]),
            updated_at_ms=int(row["updated_at_ms"]),
        )

# ============================================================
# Фабрики и удобные конструкторы
# ============================================================

def make_default_document_repo(in_memory: bool = False) -> AsyncRepository[Document]:
    """
    Возвращает готовый репозиторий документов:
      - InMemory в dev/test или если нет БД
      - SQLAlchemy при наличии engine
    """
    lg = _logger()
    if in_memory:
        if lg:
            lg.info("using_inmemory_repo")
        return DocumentsInMemory()

    if _deps is not None:
        try:
            db = _deps.get_db()
            engine = getattr(db, "_engine", None)
            if engine is not None:
                if lg:
                    lg.info("using_sqlalchemy_repo")
                return DocumentsSA(engine=engine)
        except Exception:
            pass

    if lg:
        lg.warning("fallback_inmemory_repo_no_db")
    return DocumentsInMemory()

def make_default_blob_storage(in_memory: bool = False) -> BlobStorage:
    lg = _logger()
    if in_memory or os.getenv("AVM_BLOB_INMEM", "0") == "1":
        if lg:
            lg.info("using_inmemory_blob")
        return InMemoryBlobStorage()
    bucket = os.getenv("AVM_BLOB_BUCKET")
    if bucket:
        try:
            return S3BlobStorage(bucket=bucket, region=os.getenv("AVM_AWS_REGION"))
        except Exception as e:
            if lg:
                lg.error("s3_blob_storage_unavailable_fallback", extra={"err": str(e)})
    if lg:
        lg.warning("fallback_inmemory_blob_no_config")
    return InMemoryBlobStorage()

# ============================================================
# Утилиты высокого уровня
# ============================================================

async def safe_create(repo: AsyncRepository[T], obj: T, *, idempotent: bool = True) -> T:
    """
    Идемпотентное создание: при конфликте — возвращаем существующий, иначе поднимаем ошибку.
    """
    try:
        return await repo.create(obj, if_not_exists=idempotent)
    except Conflict:
        # Попробуем вернуть текущее состояние
        oid = getattr(obj, "id", None) or obj["id"]  # type: ignore[index]
        return await repo.get(oid)

async def upsert(repo: AsyncRepository[T], obj: T) -> T:
    """
    Безопасный upsert: create(if_not_exists) -> update(if_match=<current.version>)
    """
    try:
        return await repo.create(obj, if_not_exists=True)
    except Conflict:
        # Не должен сюда попасть при if_not_exists=True, но оставим для универсальности
        pass
    # Получим текущую версию и попробуем обновить
    oid = getattr(obj, "id", None) or obj["id"]  # type: ignore[index]
    current = await repo.get(oid)
    v = getattr(current, "version", None) or current["version"]  # type: ignore[index]
    return await repo.update(obj, if_match=v)

# ============================================================
# Пример использования (докстринг):
# ------------------------------------------------------------
# from avm_core.engine.storage import (
#     Document, make_default_document_repo, Query, safe_create, upsert,
#     make_default_blob_storage
# )
#
# repo = make_default_document_repo()
# doc = Document(id="d1", title="Title", content="Hello", owner="alice")
# created = await safe_create(repo, doc)
# created.title = "New"
# updated = await upsert(repo, created)
#
# blobs = make_default_blob_storage(in_memory=True)
# await blobs.put("docs/d1.txt", b"secret", content_type="text/plain", encrypt=True)
# payload = await blobs.get("docs/d1.txt")
# ------------------------------------------------------------
