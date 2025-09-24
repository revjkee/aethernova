# oblivionvault-core/oblivionvault/archive/worm_store.py
"""
WORMStore — промышленный модуль неизменяемого архива (Write Once Read Many)
для ядра OblivionVault.

Ключевые свойства:
- Контент-адресация (BLAKE3 при наличии, иначе Blake2b).
- Атомарная запись: O_TMPFILE/временный файл + fsync + атомарный rename.
- Попытка файловой неизменяемости: readonly + FS_IOC_SETFLAGS (immutable) на Linux (если возможно).
- Асинхронный API через ThreadPoolExecutor, потокобезопасность.
- Аудит-журнал с HMAC-цепочкой (tamper-evident).
- Политики retention и legal hold (удаление физически запрещено до срока; после — через «мягкую» пометку, без перезаписи файла).
- SQLite-индекс с гарантиями целостности и уникальности.
- Опционально: компрессия (zstd при наличии, иначе zlib/none), шифрование (AES-GCM при наличии cryptography).
- Пруф-объект целостности (Merkle-корень по чанкам + общий хэш).
- Безопасная деградация: при отсутствии опций не нарушается WORM-семантика.

Зависимости:
- Стандартная библиотека. Опционально: blake3, cryptography, zstandard.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import datetime as dt
import enum
import hmac
import io
import json
import logging
import os
import secrets
import sqlite3
import stat
import tempfile
import threading
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Optional, Union, Iterable, Dict, Any, Tuple

# -------- Optional deps with safe fallback --------
try:
    import blake3  # type: ignore
    _HAS_BLAKE3 = True
except Exception:
    import hashlib
    _HAS_BLAKE3 = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

try:
    import zstandard as zstd  # type: ignore
    _HAS_ZSTD = True
except Exception:
    _HAS_ZSTD = False

# Linux immutable flag support (best-effort)
try:
    import fcntl  # type: ignore
    import struct  # for ioctl payloads
    _HAS_FCNTL = True
except Exception:
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)


# -------- Utilities --------

class HashAlgo(str, enum.Enum):
    BLAKE3 = "blake3"
    BLAKE2B = "blake2b"


def _hasher(algo: HashAlgo):
    if algo == HashAlgo.BLAKE3 and _HAS_BLAKE3:
        return blake3.blake3()
    # fallback to secure hash in stdlib
    import hashlib
    return hashlib.blake2b(digest_size=32)


def _hash_update(hasher, data: bytes):
    hasher.update(data)


def _hash_finalize(hasher) -> str:
    if _HAS_BLAKE3 and hasattr(hasher, "hexdigest"):
        return hasher.hexdigest()
    # hashlib-style as well
    return hasher.hexdigest()


def _merkle_root(chunk_hashes: Iterable[bytes], algo: HashAlgo) -> str:
    """
    Строит двоичное дерево Меркла над хэшами чанков (уже BLAKE3/BLAKE2b digest bytes).
    Возвращает hex-строку корня.
    """
    hashes = [h for h in chunk_hashes]
    if not hashes:
        # пустой контент
        return ""
    level = hashes
    import hashlib
    while len(level) > 1:
        nxt = []
        it = iter(level)
        for a in it:
            try:
                b = next(it)
            except StopIteration:
                b = a
            if algo == HashAlgo.BLAKE3 and _HAS_BLAKE3:
                node = blake3.blake3(a + b).digest()
            else:
                node = hashlib.blake2b(a + b, digest_size=32).digest()
            nxt.append(node)
        level = nxt
    return level[0].hex()


def _now_utc() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


def _ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def _set_readonly(path: Path) -> None:
    try:
        mode = path.stat().st_mode
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    except Exception as e:
        logger.warning("Failed to chmod readonly on %s: %s", path, e)


def _try_set_immutable(path: Path) -> bool:
    """
    Best-effort установка IMMUTABLE флага на Linux (требует права).
    Возвращает True при успехе.
    """
    if not (_HAS_FCNTL and os.name == "posix"):
        return False
    # FS_IOC_GETFLAGS / FS_IOC_SETFLAGS
    FS_IOC_GETFLAGS = 0x80086601
    FS_IOC_SETFLAGS = 0x40086602
    FS_IMMUTABLE_FL = 0x00000010
    try:
        with open(path, "rb") as f:
            buf = array = bytearray(4)
            # get flags
            fcntl.ioctl(f.fileno(), FS_IOC_GETFLAGS, array, True)
            flags = struct.unpack("i", array)[0]
            if flags & FS_IMMUTABLE_FL:
                return True
        with open(path, "rb+") as f:
            flags |= FS_IMMUTABLE_FL
            data = struct.pack("i", flags)
            fcntl.ioctl(f.fileno(), FS_IOC_SETFLAGS, data)
        return True
    except Exception as e:
        logger.info("Immutable flag not set for %s: %s", path, e)
        return False


class Compression(str, enum.Enum):
    NONE = "none"
    ZLIB = "zlib"
    ZSTD = "zstd"


class Encryption(str, enum.Enum):
    NONE = "none"
    AESGCM = "aesgcm"


@dataclass(frozen=True)
class ObjectInfo:
    content_id: str
    size: int
    created_at: dt.datetime
    retention_until: Optional[dt.datetime]
    legal_hold: bool
    algo: HashAlgo
    compression: Compression
    encryption: Encryption
    merkle_root: str
    chunk_size: int
    rel_path: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content_id": self.content_id,
            "size": self.size,
            "created_at": self.created_at.isoformat(),
            "retention_until": self.retention_until.isoformat() if self.retention_until else None,
            "legal_hold": self.legal_hold,
            "algo": self.algo.value,
            "compression": self.compression.value,
            "encryption": self.encryption.value,
            "merkle_root": self.merkle_root,
            "chunk_size": self.chunk_size,
            "rel_path": self.rel_path,
            "metadata": self.metadata,
        }


@dataclass
class WORMStoreConfig:
    base_dir: Path
    algo: HashAlgo = HashAlgo.BLAKE3 if _HAS_BLAKE3 else HashAlgo.BLAKE2B
    chunk_size: int = 4 * 1024 * 1024
    compression: Compression = Compression.NONE
    encryption: Encryption = Encryption.AESGCM if _HAS_CRYPTO else Encryption.NONE
    require_encryption: bool = False
    default_retention_days: int = 0
    immutable_best_effort: bool = True
    hmac_key: Optional[bytes] = None
    parallelism: int = 4
    # Принудительный umask для создаваемых файлов (минимизация прав)
    umask: int = 0o077


class _AsyncDB:
    def __init__(self, db_path: Path):
        self._db_path = str(db_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=FULL;")
        self._init_schema()

    def _init_schema(self):
        with self._conn:
            self._conn.execute("""
            CREATE TABLE IF NOT EXISTS objects (
                content_id TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                retention_until TEXT,
                legal_hold INTEGER NOT NULL DEFAULT 0,
                algo TEXT NOT NULL,
                compression TEXT NOT NULL,
                encryption TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                chunk_size INTEGER NOT NULL,
                rel_path TEXT NOT NULL,
                metadata TEXT NOT NULL
            );
            """)
            self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                content_id TEXT,
                details TEXT NOT NULL,
                hmac_prev TEXT,
                hmac_curr TEXT NOT NULL
            );
            """)
            self._conn.execute("""
            CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );
            """)

    def execute(self, sql: str, params: Tuple[Any, ...] = ()):
        with self._lock, self._conn:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def executemany(self, sql: str, seq_params: Iterable[Tuple[Any, ...]]):
        with self._lock, self._conn:
            cur = self._conn.executemany(sql, list(seq_params))
            return cur.fetchall()


class _AEAD:
    def __init__(self, key: Optional[bytes], required: bool):
        if key is None and required:
            raise RuntimeError("Encryption required but key is None.")
        if not _HAS_CRYPTO and required:
            raise RuntimeError("Encryption required but 'cryptography' is not installed.")
        self._key = key

    def encrypt(self, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
        if self._key and _HAS_CRYPTO:
            nonce = secrets.token_bytes(12)
            ct = AESGCM(self._key).encrypt(nonce, plaintext, aad)
            return nonce, ct
        # no encryption
        return b"", plaintext

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if self._key and _HAS_CRYPTO:
            return AESGCM(self._key).decrypt(nonce, ciphertext, aad)
        return ciphertext


class _Compressor:
    def __init__(self, mode: Compression):
        self.mode = mode

    def compress(self, data: bytes) -> bytes:
        if self.mode == Compression.ZSTD and _HAS_ZSTD:
            cctx = zstd.ZstdCompressor(level=10)
            return cctx.compress(data)
        if self.mode == Compression.ZLIB:
            return zlib.compress(data, level=9)
        return data

    def decompress(self, data: bytes) -> bytes:
        if self.mode == Compression.ZSTD and _HAS_ZSTD:
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        if self.mode == Compression.ZLIB:
            return zlib.decompress(data)
        return data


class WORMStore:
    """
    Асинхронное WORM-хранилище с CAS, аудитом и политиками удержания.

    Папки:
      base/objects/xx/xxxxxxxx...  — файлы объектов (RO/immutable best-effort)
      base/journal/                — аудит-журналы (в SQLite таблице audit)
      base/index.sqlite            — индекс объектов/метаданных
    """
    def __init__(self, cfg: WORMStoreConfig):
        self.cfg = cfg
        self.base = Path(cfg.base_dir)
        self.objects = self.base / "objects"
        self.journal_dir = self.base / "journal"
        _ensure_dir(self.objects)
        _ensure_dir(self.journal_dir)

        self.db = _AsyncDB(self.base / "index.sqlite")
        self._loop = asyncio.get_event_loop()
        self._pool = asyncio.get_running_loop().run_in_executor
        self._executor = asyncio.get_running_loop()._default_executor  # type: ignore
        # Если нет executor, создадим:
        if self._executor is None:
            from concurrent.futures import ThreadPoolExecutor
            self._executor = ThreadPoolExecutor(max_workers=self.cfg.parallelism)
            asyncio.get_running_loop().set_default_executor(self._executor)  # type: ignore

        # Аудит-ключ
        if cfg.hmac_key is None:
            # Персистим генерированный ключ (base64) в kv
            existing = self.db.execute("SELECT v FROM kv WHERE k='hmac_key'")
            if existing:
                self._hmac_key = base64.b64decode(existing[0][0].encode("utf-8"))
            else:
                self._hmac_key = secrets.token_bytes(32)
                self.db.execute(
                    "INSERT OR REPLACE INTO kv(k,v) VALUES('hmac_key',?)",
                    (base64.b64encode(self._hmac_key).decode("utf-8"),),
                )
        else:
            self._hmac_key = cfg.hmac_key

        # AEAD
        self._aead = _AEAD(key=self._hmac_key if (cfg.encryption == Encryption.AESGCM) else None,
                           required=cfg.require_encryption)
        self._compressor = _Compressor(cfg.compression)

        # Umask
        self._umask_lock = threading.RLock()

    # ---------- Helpers ----------

    def _atomic_write(self, target: Path, data: bytes) -> None:
        # Гарантируем строгую атомарность: tmp -> fsync -> rename
        _ensure_dir(target.parent)
        old_umask = None
        with self._umask_lock:
            try:
                old_umask = os.umask(self.cfg.umask)
                with tempfile.NamedTemporaryFile(dir=str(target.parent), delete=False) as tmp:
                    tmp.write(data)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                    tmp_path = Path(tmp.name)
                os.replace(tmp_path, target)  # атомарный rename
                with open(target, "rb") as f:
                    os.fsync(f.fileno())
                dir_fd = os.open(str(target.parent), os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            finally:
                if old_umask is not None:
                    os.umask(old_umask)

    def _content_path(self, content_id: str) -> Path:
        return self.objects / content_id[:2] / content_id

    def _audit_append(self, actor: str, action: str, content_id: Optional[str], details: Dict[str, Any]) -> None:
        # HMAC-цепочка: hmac_curr = HMAC(key, json(record)+hmac_prev)
        prev_row = self.db.execute("SELECT hmac_curr FROM audit ORDER BY id DESC LIMIT 1")
        h_prev = bytes.fromhex(prev_row[0][0]) if prev_row else b""
        payload = json.dumps({
            "ts": _now_utc().isoformat(),
            "actor": actor,
            "action": action,
            "content_id": content_id,
            "details": details
        }, sort_keys=True).encode("utf-8")
        h_curr = hmac.new(self._hmac_key, payload + h_prev, "sha256").hexdigest()
        self.db.execute(
            "INSERT INTO audit(ts,actor,action,content_id,details,hmac_prev,hmac_curr) VALUES (?,?,?,?,?,?,?)",
            (
                _now_utc().isoformat(),
                actor,
                action,
                content_id,
                json.dumps(details, ensure_ascii=False, sort_keys=True),
                h_prev.hex() if h_prev else None,
                h_curr,
            )
        )

    def _hash_stream(self, stream: io.BufferedReader, algo: HashAlgo, chunk_sz: int) -> Tuple[str, str, int]:
        hasher = _hasher(algo)
        chunk_hashes: list[bytes] = []
        total = 0
        while True:
            chunk = stream.read(chunk_sz)
            if not chunk:
                break
            total += len(chunk)
            _hash_update(hasher, chunk)
            # пер-chunk digest
            if _HAS_BLAKE3 and algo == HashAlgo.BLAKE3:
                ch = blake3.blake3(chunk).digest()
            else:
                import hashlib
                ch = hashlib.blake2b(chunk, digest_size=32).digest()
            chunk_hashes.append(ch)
        content_id = _hash_finalize(hasher)
        root = _merkle_root(chunk_hashes, algo)
        return content_id, root, total

    # ---------- Public API ----------

    async def write(
        self,
        data: Union[bytes, io.BufferedReader, AsyncIterator[bytes]],
        *,
        metadata: Optional[Dict[str, Any]] = None,
        actor: str = "system",
        retention_days: Optional[int] = None,
    ) -> ObjectInfo:
        """
        Запись объекта (write-once). Повторная запись того же контента-хэша будет идемпотентной.
        """
        meta = metadata or {}
        algo = self.cfg.algo
        chunk_sz = self.cfg.chunk_size

        # Сформируем байтовый поток в памяти безопасно, с хэшированием и опциональной компрессией/шифрованием.
        async def _collect_and_process() -> Tuple[bytes, str, str, int]:
            hasher = _hasher(algo)
            chunk_hashes: list[bytes] = []
            total = 0

            async def _iter_bytes() -> AsyncIterator[bytes]:
                if isinstance(data, (bytes, bytearray)):
                    yield bytes(data)
                    return
                if isinstance(data, io.BufferedReader):
                    while True:
                        b = await asyncio.get_running_loop().run_in_executor(None, data.read, chunk_sz)
                        if not b:
                            break
                        yield b
                    return
                # AsyncIterator
                async for b in data:  # type: ignore
                    yield b

            # собираем и хэшируем
            raw = bytearray()
            async for chunk in _iter_bytes():
                raw.extend(chunk)
                total += len(chunk)
                _hash_update(hasher, chunk)
                if _HAS_BLAKE3 and algo == HashAlgo.BLAKE3:
                    ch = blake3.blake3(chunk).digest()
                else:
                    import hashlib
                    ch = hashlib.blake2b(chunk, digest_size=32).digest()
                chunk_hashes.append(ch)

            content_id = _hash_finalize(hasher)
            merkle = _merkle_root(chunk_hashes, algo)

            # компрессия
            compressed = self._compressor.compress(bytes(raw))
            # AEAD (AАD = content_id)
            nonce, sealed = self._aead.encrypt(compressed, aad=content_id.encode("utf-8"))

            # Формат файла:
            # [header_json]\n\n[binary_payload]
            header = {
                "v": 1,
                "algo": algo.value,
                "compression": self.cfg.compression.value,
                "encryption": self.cfg.encryption.value,
                "nonce_b64": base64.b64encode(nonce).decode("ascii") if nonce else "",
                "aad": content_id,
                "size": total,
                "merkle_root": merkle,
                "chunk_size": chunk_sz,
                "metadata": meta,
                "created_at": _now_utc().isoformat(),
            }
            header_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
            blob = header_bytes + b"\n\n" + sealed
            return blob, content_id, merkle, total

        blob, content_id, merkle, total = await _collect_and_process()
        rel = f"{content_id[:2]}/{content_id}"
        target = self._content_path(content_id)

        # Если файл уже существует — просто идемпотентно завершаем (доверяя CAS)
        if target.exists():
            # ensure index row exists (или восстановим)
            rows = self.db.execute("SELECT content_id FROM objects WHERE content_id=?", (content_id,))
            if not rows:
                self._index_insert(content_id, total, merkle, rel, metadata or {}, actor, retention_days)
            return await self.stat(content_id)

        # иначе, атомарная запись и «запечатывание»
        await asyncio.get_running_loop().run_in_executor(
            None, self._atomic_write, target, blob
        )
        _set_readonly(target)
        immutable_set = False
        if self.cfg.immutable_best_effort:
            immutable_set = _try_set_immutable(target)

        self._index_insert(content_id, total, merkle, rel, metadata or {}, actor, retention_days)
        self._audit_append(
            actor=actor, action="write",
            content_id=content_id,
            details={"size": total, "immutable": immutable_set, "rel_path": rel}
        )
        return await self.stat(content_id)

    def _index_insert(
        self,
        content_id: str,
        size: int,
        merkle_root: str,
        rel_path: str,
        metadata: Dict[str, Any],
        actor: str,
        retention_days: Optional[int]
    ) -> None:
        created_at = _now_utc()
        retention_until = None
        days = retention_days if retention_days is not None else self.cfg.default_retention_days
        if days and days > 0:
            retention_until = created_at + dt.timedelta(days=days)
        self.db.execute("""
            INSERT OR REPLACE INTO objects
            (content_id,size,created_at,retention_until,legal_hold,algo,compression,encryption,merkle_root,chunk_size,rel_path,metadata)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            content_id, size, created_at.isoformat(),
            retention_until.isoformat() if retention_until else None,
            0, self.cfg.algo.value, self.cfg.compression.value, self.cfg.encryption.value,
            merkle_root, self.cfg.chunk_size, rel_path, json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        ))
        self._audit_append(actor=actor, action="index_insert", content_id=content_id, details={"rel_path": rel_path})

    async def read(self, content_id: str) -> bytes:
        """
        Полное чтение объекта. Возвращает байты полезной нагрузки (после расшифровки/распаковки).
        """
        path = self._content_path(content_id)
        if not path.exists():
            raise FileNotFoundError(f"Object {content_id} not found")

        def _read() -> bytes:
            with open(path, "rb") as f:
                header = []
                # читаем до двойного \n\n
                sep = b"\n\n"
                chunk = f.read(8192)
                buf = bytearray()
                while chunk:
                    buf.extend(chunk)
                    i = buf.find(sep)
                    if i != -1:
                        header_bytes = bytes(buf[:i])
                        payload = f.read()  # rest
                        hdr = json.loads(header_bytes.decode("utf-8"))
                        nonce = base64.b64decode(hdr.get("nonce_b64", "")) if hdr.get("nonce_b64") else b""
                        aad = hdr["aad"].encode("utf-8")
                        ct = payload
                        pt = self._aead.decrypt(nonce, ct, aad)
                        data = _Compressor(Compression(hdr["compression"])).decompress(pt)
                        return data
                    chunk = f.read(8192)
                raise ValueError("Invalid object file format")

        return await asyncio.get_running_loop().run_in_executor(None, _read)

    async def stat(self, content_id: str) -> ObjectInfo:
        rows = self.db.execute("SELECT content_id,size,created_at,retention_until,legal_hold,algo,compression,encryption,merkle_root,chunk_size,rel_path,metadata FROM objects WHERE content_id=?",
                               (content_id,))
        if not rows:
            raise FileNotFoundError(f"Object {content_id} not indexed")
        (cid, size, created_at, retention_until, legal_hold, algo, comp, enc, merkle_root, chunk_size, rel_path, metadata) = rows[0]
        return ObjectInfo(
            content_id=cid,
            size=int(size),
            created_at=dt.datetime.fromisoformat(created_at),
            retention_until=dt.datetime.fromisoformat(retention_until) if retention_until else None,
            legal_hold=bool(legal_hold),
            algo=HashAlgo(algo),
            compression=Compression(comp),
            encryption=Encryption(enc),
            merkle_root=merkle_root,
            chunk_size=int(chunk_size),
            rel_path=rel_path,
            metadata=json.loads(metadata),
        )

    async def verify(self, content_id: str) -> bool:
        """
        Полная проверка: сверка header, пересчет контент-хэша и Merkle-корня.
        """
        path = self._content_path(content_id)
        if not path.exists():
            return False

        def _verify() -> bool:
            with open(path, "rb") as f:
                sep = b"\n\n"
                buf = bytearray()
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    i = buf.find(sep)
                    if i == -1:
                        continue
                    header_bytes = bytes(buf[:i])
                    payload = bytes(buf[i + len(sep):])
                    hdr = json.loads(header_bytes.decode("utf-8"))
                    nonce = base64.b64decode(hdr.get("nonce_b64", "")) if hdr.get("nonce_b64") else b""
                    aad = hdr["aad"].encode("utf-8")
                    ct = payload
                    pt = self._aead.decrypt(nonce, ct, aad)
                    data = _Compressor(Compression(hdr["compression"])).decompress(pt)
                    # recompute hashes
                    algo = HashAlgo(hdr["algo"])
                    chunk_sz = int(hdr["chunk_size"])
                    hasher = _hasher(algo)
                    import hashlib
                    chunk_hashes = []
                    view = memoryview(data)
                    for off in range(0, len(data), chunk_sz):
                        c = view[off:off + chunk_sz].tobytes()
                        _hash_update(hasher, c)
                        if _HAS_BLAKE3 and algo == HashAlgo.BLAKE3:
                            ch = blake3.blake3(c).digest()
                        else:
                            ch = hashlib.blake2b(c, digest_size=32).digest()
                        chunk_hashes.append(ch)
                    cid2 = _hash_finalize(hasher)
                    root2 = _merkle_root(chunk_hashes, algo)
                    return (cid2 == content_id) and (root2 == hdr["merkle_root"]) and (int(hdr["size"]) == len(data))
            return False

        ok = await asyncio.get_running_loop().run_in_executor(None, _verify)
        return ok

    async def set_retention(self, content_id: str, until: dt.datetime, *, actor: str = "system") -> None:
        info = await self.stat(content_id)
        if info.retention_until and until < info.retention_until:
            # нельзя уменьшать окно удержания
            raise PermissionError("Retention can only be extended")
        self.db.execute("UPDATE objects SET retention_until=? WHERE content_id=?",
                        (until.isoformat(), content_id))
        self._audit_append(actor=actor, action="retention_extend", content_id=content_id,
                           details={"new_until": until.isoformat()})

    async def set_legal_hold(self, content_id: str, hold: bool, *, actor: str = "system") -> None:
        self.db.execute("UPDATE objects SET legal_hold=? WHERE content_id=?",
                        (1 if hold else 0, content_id))
        self._audit_append(actor=actor, action="legal_hold", content_id=content_id, details={"hold": hold})

    async def delete_soft(self, content_id: str, *, actor: str = "system") -> None:
        """
        Мягкое удаление: разрешено только если retention истек и нет legal hold.
        Физический файл не перезаписывается (WORM), запись удаляется из индекса.
        """
        info = await self.stat(content_id)
        now = _now_utc()
        if info.legal_hold:
            raise PermissionError("Object under legal hold")
        if info.retention_until and now < info.retention_until:
            raise PermissionError("Retention not expired")
        # удаляем из индекса; файл остается read-only/immutable
        self.db.execute("DELETE FROM objects WHERE content_id=?", (content_id,))
        self._audit_append(actor=actor, action="delete_soft", content_id=content_id, details={})

    async def proof(self, content_id: str) -> Dict[str, Any]:
        """
        Возвращает пруф-объект: метаданные + корни/хэши + фрагмент последних HMAC-цепочек аудита для верификации.
        """
        info = await self.stat(content_id)
        tail = self.db.execute(
            "SELECT id,ts,actor,action,content_id,hmac_prev,hmac_curr FROM audit WHERE content_id=? ORDER BY id DESC LIMIT 5",
            (content_id,)
        )
        return {
            "object": info.to_dict(),
            "audit_tail": [
                {
                    "id": r[0], "ts": r[1], "actor": r[2], "action": r[3],
                    "content_id": r[4], "hmac_prev": r[5], "hmac_curr": r[6]
                } for r in tail
            ]
        }

    async def list(self, limit: int = 100, offset: int = 0) -> list[ObjectInfo]:
        rows = self.db.execute(
            "SELECT content_id FROM objects ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        out = []
        for (cid,) in rows:
            out.append(await self.stat(cid))
        return out

    async def read_stream(self, content_id: str, chunk_size: int = 1 << 20) -> AsyncIterator[bytes]:
        """
        Стриминговое чтение полезной нагрузки (после расшифровки/распаковки).
        """
        full = await self.read(content_id)
        for i in range(0, len(full), chunk_size):
            yield full[i:i + chunk_size]

    # ---------- Administrative ----------

    async def close(self) -> None:
        # Для совместимости — SQLite соединение закрывается GC, pool — общий
        pass
