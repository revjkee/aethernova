# oblivionvault-core/oblivionvault/adapters/storage_postgres.py
"""
Industrial-grade Postgres storage adapter for OblivionVault.

Features:
- Async SQLAlchemy 2.x engine & sessions
- Envelope encryption: AES-GCM content key (CEK), wrapped by KEK (provider)
- LocalKeyProvider (AES-GCM) with KEK from env; pluggable KeyProvider interface
- Versioned secrets with atomic "current_version" update
- GZIP compression (optional), SHA-256 integrity checksum
- Soft delete (tombstone) & hard purge
- Concurrency control (SELECT ... FOR UPDATE), idempotent item create
- Exponential backoff retries for transient DB failures
- Strict typing, structured exceptions, minimal deps (sqlalchemy, cryptography)

Environment (defaults can be overridden via Settings):
- DATABASE_URL: e.g. postgresql+asyncpg://user:pass@host:5432/db
- OBLIVIONVAULT_KEK_HEX: 32-byte KEK in hex (256-bit) for LocalKeyProvider
- OBLIVIONVAULT_KID: key id, default "local-1"

Notes:
- AESGCM ciphertext already includes tag; we store nonce separately.
- Wrapped CEK stored as (wrapped bytes + wrap_nonce + KID + algo).
- No Alembic here; call `await adapter.initialize()` to create schema.

CAUTION:
- For production KMS (HSM, cloud KMS), implement KeyProvider accordingly.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import logging
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple, Protocol, Literal

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    LargeBinary,
    UniqueConstraint,
    Index,
    select,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    DeclarativeBase,
    relationship,
)
from sqlalchemy.exc import OperationalError, SQLAlchemyError, IntegrityError as SAIntegrityError

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import uuid
from contextlib import asynccontextmanager


# --------------------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------------------

logger = logging.getLogger("oblivionvault.storage.postgres")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# --------------------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------------------

class StorageError(Exception):
    """Base adapter error."""

class ItemNotFound(StorageError):
    """Item (namespace, name) not found or tombstoned (when include_deleted=False)."""

class VersionNotFound(StorageError):
    """Specific version not found for item."""

class KeyProviderError(StorageError):
    """Key provider failure."""

class IntegrityViolation(StorageError):
    """Checksum mismatch, tampering or data corruption detected."""

class ConcurrentModificationError(StorageError):
    """Optimistic locking / race condition detected."""

class ConfigurationError(StorageError):
    """Invalid settings or environment configuration."""


# --------------------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    database_url: str
    kek_hex: str
    kid: str = "local-1"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    echo_sql: bool = False
    retry_attempts: int = 5
    retry_base_delay: float = 0.15
    retry_max_delay: float = 2.0

    @staticmethod
    def from_env() -> "Settings":
        db = os.getenv("DATABASE_URL")
        kek_hex = os.getenv("OBLIVIONVAULT_KEK_HEX")
        kid = os.getenv("OBLIVIONVAULT_KID", "local-1")
        if not db:
            raise ConfigurationError("DATABASE_URL is required")
        if not kek_hex:
            raise ConfigurationError("OBLIVIONVAULT_KEK_HEX is required (32-byte hex)")
        if len(kek_hex) != 64:
            raise ConfigurationError("OBLIVIONVAULT_KEK_HEX must be 64 hex chars (32 bytes)")
        return Settings(
            database_url=db,
            kek_hex=kek_hex,
            kid=kid,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
            echo_sql=os.getenv("DB_ECHO_SQL", "0") == "1",
            retry_attempts=int(os.getenv("DB_RETRY_ATTEMPTS", "5")),
            retry_base_delay=float(os.getenv("DB_RETRY_BASE_DELAY", "0.15")),
            retry_max_delay=float(os.getenv("DB_RETRY_MAX_DELAY", "2.0")),
        )


# --------------------------------------------------------------------------------------
# Crypto primitives (Envelope encryption)
# --------------------------------------------------------------------------------------

CompressionAlgo = Literal["none", "gzip"]

@dataclass(frozen=True)
class WrappedKey:
    wrapped: bytes
    nonce: bytes
    kid: str
    algo: str  # e.g., "AESGCM-256"

class KeyProvider(Protocol):
    """Pluggable key wrapping provider."""
    async def wrap(self, cek: bytes) -> WrappedKey: ...
    async def unwrap(self, wrapped: WrappedKey) -> bytes: ...
    async def rewrap(self, wrapped: WrappedKey) -> WrappedKey: ...

class LocalKeyProvider:
    """
    Local AES-GCM key wrap provider using KEK from env (Settings.kek_hex).
    Intended for dev/edge/on-prem; replace with KMS provider in production.
    """
    def __init__(self, settings: Settings):
        try:
            self._kek = bytes.fromhex(settings.kek_hex)
        except ValueError as e:
            raise ConfigurationError("OBLIVIONVAULT_KEK_HEX invalid hex") from e
        if len(self._kek) != 32:
            raise ConfigurationError("KEK must be 32 bytes")
        self._kid = settings.kid
        self._algo = "AESGCM-256"

    async def wrap(self, cek: bytes) -> WrappedKey:
        try:
            nonce = secrets.token_bytes(12)
            aes = AESGCM(self._kek)
            wrapped = aes.encrypt(nonce, cek, b"oblivionvault:cek-wrap")
            return WrappedKey(wrapped=wrapped, nonce=nonce, kid=self._kid, algo=self._algo)
        except Exception as e:
            raise KeyProviderError(f"wrap failed: {e}") from e

    async def unwrap(self, wrapped: WrappedKey) -> bytes:
        try:
            aes = AESGCM(self._kek)
            cek = aes.decrypt(wrapped.nonce, wrapped.wrapped, b"oblivionvault:cek-wrap")
            return cek
        except Exception as e:
            raise KeyProviderError(f"unwrap failed: {e}") from e

    async def rewrap(self, wrapped: WrappedKey) -> WrappedKey:
        # Local provider has single KEK; rewrap == no-op (but regenerates nonce/ciphertext).
        cek = await self.unwrap(wrapped)
        return await self.wrap(cek)


# --------------------------------------------------------------------------------------
# SQLAlchemy models
# --------------------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass

def _uuid() -> str:
    return str(uuid.uuid7()) if hasattr(uuid, "uuid7") else str(uuid.uuid4())

class VaultItem(Base):
    __tablename__ = "vault_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    namespace: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    current_version_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("vault_item_versions.id"), nullable=True)

    versions: Mapped[List["VaultItemVersion"]] = relationship("VaultItemVersion", back_populates="item", cascade="all, delete-orphan")
    current_version: Mapped[Optional["VaultItemVersion"]] = relationship("VaultItemVersion", foreign_keys=[current_version_id], post_update=True)

    __table_args__ = (
        UniqueConstraint("namespace", "name", name="uq_vault_item_ns_name"),
        Index("ix_vault_item_ns_name", "namespace", "name"),
        Index("ix_vault_item_deleted", "is_deleted"),
    )

class VaultItemVersion(Base):
    __tablename__ = "vault_item_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    item_id: Mapped[str] = mapped_column(String(36), ForeignKey("vault_items.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    # Envelope encryption fields
    cek_wrapped: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    cek_wrap_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    cek_kid: Mapped[str] = mapped_column(String(120), nullable=False)
    cek_algo: Mapped[str] = mapped_column(String(32), nullable=False)

    # Payload encryption (AES-GCM)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Meta
    content_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream", nullable=False)
    compression: Mapped[str] = mapped_column(String(16), default="none", nullable=False)  # "none" | "gzip"
    size_plain: Mapped[int] = mapped_column(Integer, nullable=False)
    size_compressed: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    item: Mapped["VaultItem"] = relationship("VaultItem", back_populates="versions")

    __table_args__ = (
        UniqueConstraint("item_id", "version", name="uq_item_version"),
        Index("ix_versions_item", "item_id"),
        Index("ix_versions_version", "version"),
    )


# --------------------------------------------------------------------------------------
# DTOs
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretReference:
    namespace: str
    name: str
    version: Optional[int] = None  # None => current

@dataclass(frozen=True)
class SecretPayload:
    ref: SecretReference
    data: bytes
    content_type: str
    metadata: Dict[str, Any]
    created_at: datetime
    compression: CompressionAlgo
    size_plain: int
    size_compressed: int
    sha256: str


# --------------------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=6)

def _gzip_decompress(data: bytes) -> bytes:
    return gzip.decompress(data)

def _now_ts() -> float:
    return time.time()

def _b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")


# --------------------------------------------------------------------------------------
# Retry decorator (exponential backoff)
# --------------------------------------------------------------------------------------

def retry_async_db(attempts: int, base_delay: float, max_delay: float):
    def deco(fn):
        async def wrapper(*args, **kwargs):
            delay = base_delay
            for i in range(attempts):
                try:
                    return await fn(*args, **kwargs)
                except (OperationalError,) as e:
                    if i == attempts - 1:
                        raise
                    logger.warning("Transient DB error: %s; retrying in %.2fs", e, delay)
                    await asyncio.sleep(delay)
                    delay = min(max_delay, delay * 2)
        return wrapper
    return deco


# --------------------------------------------------------------------------------------
# Adapter
# --------------------------------------------------------------------------------------

class PostgresStorageAdapter:
    """
    OblivionVault Postgres storage adapter.
    """

    def __init__(self, settings: Settings, key_provider: Optional[KeyProvider] = None):
        self._settings = settings
        self._engine: AsyncEngine = create_async_engine(
            settings.database_url,
            echo=settings.echo_sql,
            pool_size=settings.pool_size,
            max_overflow=settings.max_overflow,
            pool_timeout=settings.pool_timeout,
            pool_pre_ping=True,
        )
        self._session_maker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine, expire_on_commit=False
        )
        self._keys: KeyProvider = key_provider or LocalKeyProvider(settings)
        self._attempts = settings.retry_attempts
        self._base_delay = settings.retry_base_delay
        self._max_delay = settings.retry_max_delay

    async def initialize(self) -> None:
        """Create schema iff not exists."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Schema initialized")

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self._session_maker() as s:
            try:
                yield s
            except:
                await s.rollback()
                raise
            else:
                await s.commit()

    # ----------------------------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------------------------

    @retry_async_db(attempts=5, base_delay=0.15, max_delay=2.0)
    async def put_secret(
        self,
        namespace: str,
        name: str,
        data: bytes | str,
        *,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, Any]] = None,
        compression: CompressionAlgo = "gzip",
    ) -> SecretPayload:
        """
        Create a new version; atomically set as current.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        metadata = metadata or {}

        size_plain = len(data)
        sha = _sha256(data)

        if compression == "gzip":
            comp = _gzip_compress(data)
        elif compression == "none":
            comp = data
        else:
            raise ValueError("Unsupported compression")
        size_compressed = len(comp)

        # Envelope: generate CEK, encrypt payload, wrap CEK, persist
        cek = secrets.token_bytes(32)  # 256-bit
        nonce = secrets.token_bytes(12)
        aes = AESGCM(cek)

        aad = f"{namespace}:{name}".encode("utf-8")
        ciphertext = aes.encrypt(nonce, comp, aad)

        wrapped = await self._keys.wrap(cek)

        async with self.session() as s:
            # Lock or create item
            item = await self._get_or_create_item_locked(s, namespace, name)

            # Determine next version
            next_version = await self._next_version(s, item.id)

            ver = VaultItemVersion(
                item_id=item.id,
                version=next_version,
                cek_wrapped=wrapped.wrapped,
                cek_wrap_nonce=wrapped.nonce,
                cek_kid=wrapped.kid,
                cek_algo=wrapped.algo,
                nonce=nonce,
                ciphertext=ciphertext,
                content_type=content_type,
                compression=compression,
                size_plain=size_plain,
                size_compressed=size_compressed,
                sha256=sha,
                metadata=metadata,
            )
            s.add(ver)
            await s.flush()

            # Atomically set current
            item.current_version_id = ver.id
            item.updated_at = func.now()

            logger.info(
                "Put secret ns=%s name=%s v=%d size=%d comp=%d sha=%s",
                namespace, name, next_version, size_plain, size_compressed, sha
            )

            return SecretPayload(
                ref=SecretReference(namespace, name, version=next_version),
                data=data,
                content_type=content_type,
                metadata=metadata,
                created_at=datetime.utcnow(),
                compression=compression,
                size_plain=size_plain,
                size_compressed=size_compressed,
                sha256=sha,
            )

    @retry_async_db(attempts=5, base_delay=0.15, max_delay=2.0)
    async def get_secret(
        self,
        namespace: str,
        name: str,
        *,
        version: Optional[int] = None,
        include_deleted: bool = False,
        verify_integrity: bool = True,
    ) -> SecretPayload:
        """
        Read and decrypt secret (current or specific version).
        """
        async with self.session() as s:
            item = await self._fetch_item(s, namespace, name, include_deleted=include_deleted)
            if not item:
                raise ItemNotFound(f"{namespace}/{name}")

            ver = await self._fetch_version(s, item, version)
            if not ver:
                raise VersionNotFound(f"{namespace}/{name} v={version}")

            wrapped = WrappedKey(
                wrapped=ver.cek_wrapped,
                nonce=ver.cek_wrap_nonce,
                kid=ver.cek_kid,
                algo=ver.cek_algo,
            )
            cek = await self._keys.unwrap(wrapped)
            aes = AESGCM(cek)
            aad = f"{namespace}:{name}".encode("utf-8")
            comp = aes.decrypt(ver.nonce, ver.ciphertext, aad)

            if ver.compression == "gzip":
                data = _gzip_decompress(comp)
            else:
                data = comp

            if verify_integrity:
                sha = _sha256(data)
                if sha != ver.sha256:
                    raise IntegrityViolation(
                        f"sha256 mismatch for {namespace}/{name}@{ver.version}: "
                        f"{sha} != {ver.sha256}"
                    )

            return SecretPayload(
                ref=SecretReference(namespace, name, version=ver.version),
                data=data,
                content_type=ver.content_type,
                metadata=ver.metadata,
                created_at=ver.created_at,
                compression=ver.compression,  # type: ignore
                size_plain=ver.size_plain,
                size_compressed=ver.size_compressed,
                sha256=ver.sha256,
            )

    @retry_async_db(attempts=5, base_delay=0.15, max_delay=2.0)
    async def list_items(
        self,
        namespace: Optional[str] = None,
        *,
        include_deleted: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Tuple[str, str, bool, Optional[int]]]:
        """
        List items: returns tuples (namespace, name, is_deleted, current_version_number or None).
        """
        async with self.session() as s:
            stmt = select(VaultItem).order_by(VaultItem.namespace, VaultItem.name).limit(limit).offset(offset)
            if namespace:
                stmt = stmt.where(VaultItem.namespace == namespace)
            if not include_deleted:
                stmt = stmt.where(VaultItem.is_deleted.is_(False))

            result = await s.execute(stmt)
            items: List[VaultItem] = list(result.scalars().all())
            out: List[Tuple[str, str, bool, Optional[int]]] = []
            for it in items:
                if it.current_version_id:
                    # fetch version number without join explosion
                    ver_stmt = select(VaultItemVersion.version).where(VaultItemVersion.id == it.current_version_id)
                    ver_num = (await s.execute(ver_stmt)).scalar_one_or_none()
                else:
                    ver_num = None
                out.append((it.namespace, it.name, it.is_deleted, ver_num))
            return out

    @retry_async_db(attempts=5, base_delay=0.15, max_delay=2.0)
    async def delete_item(
        self, namespace: str, name: str, *, soft: bool = True
    ) -> None:
        """
        Soft delete by default (tombstone). If soft=False, permanently purge.
        """
        async with self.session() as s:
            item = await self._fetch_item_for_update(s, namespace, name)
            if not item:
                raise ItemNotFound(f"{namespace}/{name}")
            if soft:
                if not item.is_deleted:
                    item.is_deleted = True
                    item.updated_at = func.now()
                logger.info("Soft-deleted %s/%s", namespace, name)
            else:
                # Hard purge: delete item and cascade delete versions
                await s.delete(item)
                logger.info("Purged %s/%s", namespace, name)

    @retry_async_db(attempts=5, base_delay=0.15, max_delay=2.0)
    async def rotate_key(
        self, namespace: str, name: str, *, version: Optional[int] = None
    ) -> None:
        """
        Rewrap CEK with provider (does not re-encrypt payload).
        Useful for KEK rotation.
        """
        async with self.session() as s:
            item = await self._fetch_item_for_update(s, namespace, name)
            if not item:
                raise ItemNotFound(f"{namespace}/{name}")
            ver = await self._fetch_version(s, item, version)
            if not ver:
                raise VersionNotFound(f"{namespace}/{name} v={version}")

            wrapped = WrappedKey(
                wrapped=ver.cek_wrapped,
                nonce=ver.cek_wrap_nonce,
                kid=ver.cek_kid,
                algo=ver.cek_algo,
            )
            new_wrapped = await self._keys.rewrap(wrapped)

            ver.cek_wrapped = new_wrapped.wrapped
            ver.cek_wrap_nonce = new_wrapped.nonce
            ver.cek_kid = new_wrapped.kid
            ver.cek_algo = new_wrapped.algo
            logger.info("Rewrapped CEK for %s/%s@%d (kid=%s)", namespace, name, ver.version, new_wrapped.kid)

    # ----------------------------------------------------------------------------------
    # Internals
    # ----------------------------------------------------------------------------------

    async def _fetch_item(
        self, s: AsyncSession, namespace: str, name: str, *, include_deleted: bool
    ) -> Optional[VaultItem]:
        stmt = select(VaultItem).where(
            VaultItem.namespace == namespace,
            VaultItem.name == name,
        )
        if not include_deleted:
            stmt = stmt.where(VaultItem.is_deleted.is_(False))
        res = await s.execute(stmt)
        return res.scalar_one_or_none()

    async def _fetch_item_for_update(
        self, s: AsyncSession, namespace: str, name: str
    ) -> Optional[VaultItem]:
        stmt = (
            select(VaultItem)
            .where(VaultItem.namespace == namespace, VaultItem.name == name)
            .with_for_update()
        )
        res = await s.execute(stmt)
        return res.scalar_one_or_none()

    async def _get_or_create_item_locked(
        self, s: AsyncSession, namespace: str, name: str
    ) -> VaultItem:
        # Try lock existing
        item = await self._fetch_item_for_update(s, namespace, name)
        if item:
            if item.is_deleted:
                # revive
                item.is_deleted = False
            return item

        # Create new
        item = VaultItem(namespace=namespace, name=name, is_deleted=False)
        s.add(item)
        try:
            await s.flush()
        except SAIntegrityError:
            # Race: item created by concurrent tx; refetch with lock
            await s.rollback()
            async with self._session_maker() as s2:
                async with s2.begin():
                    stmt = (
                        select(VaultItem)
                        .where(VaultItem.namespace == namespace, VaultItem.name == name)
                        .with_for_update()
                    )
                    res = await s2.execute(stmt)
                    existing = res.scalar_one_or_none()
                    if not existing:
                        raise ConcurrentModificationError("Failed to acquire item after integrity violation")
                    return existing
        return item

    async def _next_version(self, s: AsyncSession, item_id: str) -> int:
        stmt = select(func.coalesce(func.max(VaultItemVersion.version), 0)).where(VaultItemVersion.item_id == item_id)
        max_v = (await s.execute(stmt)).scalar_one()
        return int(max_v) + 1

    async def _fetch_version(
        self, s: AsyncSession, item: VaultItem, version: Optional[int]
    ) -> Optional[VaultItemVersion]:
        if version is None:
            if not item.current_version_id:
                return None
            stmt = select(VaultItemVersion).where(VaultItemVersion.id == item.current_version_id)
            res = await s.execute(stmt)
            return res.scalar_one_or_none()
        else:
            stmt = select(VaultItemVersion).where(
                VaultItemVersion.item_id == item.id, VaultItemVersion.version == version
            )
            res = await s.execute(stmt)
            return res.scalar_one_or_none()


# --------------------------------------------------------------------------------------
# Factory
# --------------------------------------------------------------------------------------

async def build_adapter_from_env() -> PostgresStorageAdapter:
    """
    Convenience factory using environment variables.
    """
    settings = Settings.from_env()
    adapter = PostgresStorageAdapter(settings)
    await adapter.initialize()
    return adapter


# --------------------------------------------------------------------------------------
# Optional self-test (manual)
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    async def _demo():
        settings = Settings.from_env()
        adapter = PostgresStorageAdapter(settings)
        await adapter.initialize()

        ns, name = "demo", "secret"
        payload = b"Hello OblivionVault!"
        await adapter.put_secret(ns, name, payload, content_type="text/plain", metadata={"app": "demo"})
        got = await adapter.get_secret(ns, name)
        assert got.data == payload, "roundtrip failed"

        items = await adapter.list_items(ns)
        print("Items:", items)

        await adapter.rotate_key(ns, name)
        got2 = await adapter.get_secret(ns, name)
        assert got2.data == payload

        await adapter.delete_item(ns, name, soft=True)
        # get with include_deleted allowed
        got3 = await adapter.get_secret(ns, name, include_deleted=True)
        assert got3.data == payload

        await adapter.delete_item(ns, name, soft=False)
        try:
            await adapter.get_secret(ns, name, include_deleted=True)
        except ItemNotFound:
            print("Purged as expected")

        print("Demo OK")

    asyncio.run(_demo())
