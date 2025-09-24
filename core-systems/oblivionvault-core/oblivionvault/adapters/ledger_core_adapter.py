# oblivionvault-core/oblivionvault/adapters/ledger_core_adapter.py
"""
Ledger Core Adapter for OblivionVault
-------------------------------------

Назначение:
- Предоставляет унифицированный асинхронный интерфейс для "якорения" (anchoring) объектов архива
  в проверяемом журнале (file-ledger по умолчанию; опционально EVM/Ton).
- Гарантирует идемпотентность, атомарность, tamper-evident аудит через HMAC-цепочку.
- Обеспечивает верификацию целостности (re-hash событий и проверка HMAC-цепи).

Особенности:
- Каноническая сериализация событий (json, sort_keys, компактные сепараторы).
- Строгая схема SQLite (WAL, synchronous=FULL, уникальные индексы).
- Потокобезопасность (RLock), асинхронный API с ThreadPoolExecutor.
- Батч-якорение с общей транзакцией.
- Health/metrics.

Опциональные зависимости:
- blake3 (быстрый хэш), fallback: hashlib.blake2b(digest_size=32).
- web3 / ton sdk не требуются для file-ledger; для EVM/Ton — опционально, с валидацией конфигурации.

Безопасная деградация:
- Если нет внешнего блокчейна, задействуется FileLedgerAdapter со строгой HMAC-цепью.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as dt
import enum
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# -------- Optional hashing (blake3 preferred) --------
try:
    import blake3  # type: ignore
    _HAS_BLAKE3 = True
except Exception:
    _HAS_BLAKE3 = False
    import hashlib


def _hash_bytes(data: bytes) -> str:
    if _HAS_BLAKE3:
        return blake3.blake3(data).hexdigest()
    return hashlib.blake2b(data, digest_size=32).hexdigest()


# -------- Enums / Models --------

class LedgerBackendType(str, enum.Enum):
    FILE = "file"
    EVM = "evm"
    TON = "ton"
    NULL = "null"


class AnchorStatus(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    DUPLICATE = "duplicate"


@dataclass(frozen=True)
class AnchorRequest:
    """
    Запрос на якорение сущности архива.
    """
    content_id: str                 # CAS-хэш контента (hex)
    merkle_root: str                # корень Меркла по чанкам (hex)
    size: int                       # размер полезной нагрузки (байты)
    metadata: Dict[str, Any]        # бизнес-метаданные (канонизируемы)
    created_at: dt.datetime         # время формирования запроса (UTC)
    # Дополнительно можно проставить labels/tenant и т.д.
    tenant: Optional[str] = None

    def canonical_event(self) -> bytes:
        """
        Каноническая сериализация (детерминированная) для подписи/хэширования.
        """
        obj = {
            "content_id": self.content_id,
            "merkle_root": self.merkle_root,
            "size": int(self.size),
            "metadata": self.metadata or {},
            "created_at": self.created_at.replace(tzinfo=dt.timezone.utc).isoformat(),
            "tenant": self.tenant or "",
            "schema": 1,
        }
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AnchorReceipt:
    """
    Результат якорения/запроса статуса.
    """
    status: AnchorStatus
    txid: str                       # идентификатор транзакции/записи (hex)
    chain_id: str                   # идентификатор сети/бэкенда
    block_number: Optional[int]     # для file-ledger: монотонный порядковый номер
    timestamp: dt.datetime          # когда заякорено/зафиксировано
    content_id: str
    merkle_root: str
    size: int
    metadata: Dict[str, Any]
    confirmations: Optional[int] = None
    # Доп. поля для верификации/аудита
    hmac_prev: Optional[str] = None
    hmac_curr: Optional[str] = None


@dataclass
class LedgerConfig:
    base_dir: Path
    backend: LedgerBackendType = LedgerBackendType.FILE
    # Параметры FILE ledger
    db_filename: str = "ledger.sqlite"
    synchronous_full: bool = True
    # HMAC ключ: если None — будет сгенерирован и сохранён
    hmac_key_b64: Optional[str] = None
    # Лимиты
    max_batch_size: int = 1000
    # EVM/Ton опциональные параметры (валидируются в соответствующих адаптерах)
    evm_rpc_url: Optional[str] = None
    evm_chain_id: Optional[int] = None
    evm_contract_address: Optional[str] = None
    ton_endpoint: Optional[str] = None
    ton_wallet: Optional[str] = None
    # Теги/мультиаренда
    tenant: Optional[str] = None


# -------- Abstract adapter --------

class LedgerAdapter:
    """
    Базовый интерфейс адаптера ядра Ledger.
    """
    def __init__(self, cfg: LedgerConfig):
        self.cfg = cfg

    async def anchor(self, req: AnchorRequest) -> AnchorReceipt:
        raise NotImplementedError

    async def anchor_batch(self, reqs: Sequence[AnchorRequest]) -> List[AnchorReceipt]:
        raise NotImplementedError

    async def get_by_content_id(self, content_id: str) -> Optional[AnchorReceipt]:
        raise NotImplementedError

    async def get_by_txid(self, txid: str) -> Optional[AnchorReceipt]:
        raise NotImplementedError

    async def verify(self, content_id: str) -> bool:
        """
        Полная проверка записи (пересчёт хэша события и сверка HMAC-цепи).
        """
        raise NotImplementedError

    async def health(self) -> Dict[str, Any]:
        raise NotImplementedError

    async def close(self) -> None:
        pass


# -------- File-based Ledger Adapter (tamper-evident) --------

class _FileDB:
    """
    Тонкая обёртка над sqlite3 с RLock, WAL и FULL synchronous.
    """
    def __init__(self, path: Path, synchronous_full: bool):
        self._path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute(f"PRAGMA synchronous={'FULL' if synchronous_full else 'NORMAL'};")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute("""
            CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            );""")
            self._conn.execute("""
            CREATE TABLE IF NOT EXISTS anchors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT NOT NULL UNIQUE,                -- hash(canonical_event)
                content_id TEXT NOT NULL UNIQUE,          -- idempotency
                merkle_root TEXT NOT NULL,
                size INTEGER NOT NULL,
                metadata TEXT NOT NULL,
                tenant TEXT,
                created_at TEXT NOT NULL,                 -- from request
                anchored_at TEXT NOT NULL,                -- commit time
                block_number INTEGER NOT NULL,            -- monotonic
                hmac_prev TEXT,
                hmac_curr TEXT NOT NULL
            );""")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_anchors_content ON anchors(content_id);")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_anchors_txid ON anchors(txid);")

    def q(self, sql: str, params: Tuple = ()) -> list[tuple]:
        with self._lock, self._conn:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def txn(self) -> sqlite3.Connection:
        # Явная транзакция: BEGIN IMMEDIATE
        self._conn.execute("BEGIN IMMEDIATE;")
        return self._conn

    def close(self):
        with self._lock:
            self._conn.close()


class FileLedgerAdapter(LedgerAdapter):
    """
    Неизменяемый "квазичейн" на SQLite: tamper-evident через HMAC-цепь.
    """
    CHAIN_ID = "FILE:oblivionvault"

    def __init__(self, cfg: LedgerConfig):
        super().__init__(cfg)
        base = Path(cfg.base_dir)
        base.mkdir(parents=True, exist_ok=True)
        self._db = _FileDB(base / cfg.db_filename, synchronous_full=cfg.synchronous_full)
        self._lock = threading.RLock()
        # HMAC key
        if cfg.hmac_key_b64:
            self._hmac_key = base64.b64decode(cfg.hmac_key_b64)
        else:
            row = self._db.q("SELECT v FROM kv WHERE k='hmac_key'")
            if row:
                self._hmac_key = base64.b64decode(row[0][0].encode("utf-8"))
            else:
                self._hmac_key = secrets.token_bytes(32)
                self._db.q("INSERT OR REPLACE INTO kv(k,v) VALUES('hmac_key',?)",
                           (base64.b64encode(self._hmac_key).decode("utf-8"),))
        # Metrics
        self._counters = {
            "anchor_ok": 0,
            "anchor_dup": 0,
            "anchor_fail": 0,
            "verify_ok": 0,
            "verify_fail": 0,
        }

    # ---- Internals ----

    @staticmethod
    def _canon(req: AnchorRequest) -> bytes:
        return req.canonical_event()

    def _event_hash(self, req: AnchorRequest) -> str:
        return _hash_bytes(self._canon(req))

    def _audit_tail(self, conn: sqlite3.Connection) -> Optional[str]:
        cur = conn.execute("SELECT hmac_curr FROM anchors ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        return row[0] if row else None

    def _append_anchor(self, conn: sqlite3.Connection, req: AnchorRequest, txid: str) -> AnchorReceipt:
        # Вычисляем HMAC-цепочку
        prev = self._audit_tail(conn)
        payload = self._canon(req)
        h_prev = bytes.fromhex(prev) if prev else b""
        h_curr = hmac.new(self._hmac_key, payload + h_prev, "sha256").hexdigest()

        # block_number = last.id + 1
        cur = conn.execute("SELECT COALESCE(MAX(block_number), 0) FROM anchors")
        block_number = int(cur.fetchone()[0]) + 1

        # Вставка
        now = dt.datetime.now(tz=dt.timezone.utc)
        conn.execute("""
            INSERT INTO anchors(txid,content_id,merkle_root,size,metadata,tenant,created_at,anchored_at,block_number,hmac_prev,hmac_curr)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (
            txid, req.content_id, req.merkle_root, int(req.size),
            json.dumps(req.metadata or {}, ensure_ascii=False, sort_keys=True),
            req.tenant or self.cfg.tenant,
            req.created_at.replace(tzinfo=dt.timezone.utc).isoformat(),
            now.isoformat(),
            block_number,
            prev,
            h_curr
        ))
        return AnchorReceipt(
            status=AnchorStatus.CONFIRMED,
            txid=txid,
            chain_id=self.CHAIN_ID,
            block_number=block_number,
            timestamp=now,
            content_id=req.content_id,
            merkle_root=req.merkle_root,
            size=int(req.size),
            metadata=req.metadata or {},
            confirmations=block_number,  # монотонный surrogate
            hmac_prev=prev,
            hmac_curr=h_curr,
        )

    def _fetch_by(self, field: str, value: str) -> Optional[AnchorReceipt]:
        rows = self._db.q(f"""
            SELECT txid,content_id,merkle_root,size,metadata,created_at,anchored_at,block_number,hmac_prev,hmac_curr,tenant
            FROM anchors WHERE {field}=? LIMIT 1
        """, (value,))
        if not rows:
            return None
        (txid, cid, merkle, size, meta, created_at, anchored_at, block_no, hprev, hcurr, tenant) = rows[0]
        return AnchorReceipt(
            status=AnchorStatus.CONFIRMED,
            txid=txid,
            chain_id=self.CHAIN_ID,
            block_number=int(block_no),
            timestamp=dt.datetime.fromisoformat(anchored_at),
            content_id=cid,
            merkle_root=merkle,
            size=int(size),
            metadata=json.loads(meta),
            confirmations=int(block_no),
            hmac_prev=hprev,
            hmac_curr=hcurr,
        )

    # ---- Public API ----

    async def anchor(self, req: AnchorRequest) -> AnchorReceipt:
        """
        Идемпотентное якорение события.
        """
        # Оптимистическая проверка на дубликат
        existing = await self.get_by_content_id(req.content_id)
        if existing:
            self._counters["anchor_dup"] += 1
            return dataclasses.replace(existing, status=AnchorStatus.DUPLICATE)

        txid = self._event_hash(req)

        def _commit() -> AnchorReceipt:
            with self._db._lock:
                conn = self._db.txn()
                try:
                    # Повторная проверка в txn (гонки)
                    cur = conn.execute("SELECT txid FROM anchors WHERE content_id=? LIMIT 1", (req.content_id,))
                    if cur.fetchone():
                        conn.execute("ROLLBACK;")
                        # читатель вне транзакции
                        return self._fetch_by("content_id", req.content_id)  # type: ignore
                    rcpt = self._append_anchor(conn, req, txid)
                    conn.execute("COMMIT;")
                    self._counters["anchor_ok"] += 1
                    return rcpt
                except sqlite3.IntegrityError:
                    conn.execute("ROLLBACK;")
                    self._counters["anchor_dup"] += 1
                    return self._fetch_by("content_id", req.content_id)  # type: ignore
                except Exception as e:
                    conn.execute("ROLLBACK;")
                    self._counters["anchor_fail"] += 1
                    logger.exception("anchor commit failed: %s", e)
                    raise

        loop = asyncio.get_running_loop()
        rcpt = await loop.run_in_executor(None, _commit)
        if isinstance(rcpt, AnchorReceipt):
            return rcpt
        # если вернулся None (не должен), повторно попробуем прочитать
        out = await self.get_by_content_id(req.content_id)
        if out:
            return dataclasses.replace(out, status=AnchorStatus.DUPLICATE)
        raise RuntimeError("Failed to anchor event")

    async def anchor_batch(self, reqs: Sequence[AnchorRequest]) -> List[AnchorReceipt]:
        """
        Батч-якорение в одной транзакции. Идемпотентно по content_id.
        """
        if not reqs:
            return []
        if len(reqs) > self.cfg.max_batch_size:
            raise ValueError(f"batch size exceeds limit {self.cfg.max_batch_size}")

        # Предварительно отфильтруем дубликаты по content_id
        unique: Dict[str, AnchorRequest] = {}
        for r in reqs:
            unique.setdefault(r.content_id, r)
        filtered = list(unique.values())

        # Быстрая проверка уже заякоренных
        existing_map: Dict[str, AnchorReceipt] = {}
        for r in filtered:
            ex = await self.get_by_content_id(r.content_id)
            if ex:
                existing_map[r.content_id] = dataclasses.replace(ex, status=AnchorStatus.DUPLICATE)

        def _commit_batch() -> List[AnchorReceipt]:
            results: List[AnchorReceipt] = []
            with self._db._lock:
                conn = self._db.txn()
                try:
                    for r in filtered:
                        if r.content_id in existing_map:
                            results.append(existing_map[r.content_id])
                            continue
                        txid = self._event_hash(r)
                        try:
                            rcpt = self._append_anchor(conn, r, txid)
                            results.append(rcpt)
                            self._counters["anchor_ok"] += 1
                        except sqlite3.IntegrityError:
                            # гонка/дубликат в батче
                            cur = conn.execute(
                                "SELECT txid FROM anchors WHERE content_id=? LIMIT 1", (r.content_id,)
                            )
                            if cur.fetchone():
                                # прочитаем после коммита
                                pass
                            else:
                                raise
                    conn.execute("COMMIT;")
                except Exception as e:
                    conn.execute("ROLLBACK;")
                    logger.exception("batch anchor failed: %s", e)
                    raise

            # Дочитываем те, что могли стать дубликатами
            for r in filtered:
                if any(x.content_id == r.content_id for x in results):
                    continue
                ex = self._fetch_by("content_id", r.content_id)
                if ex:
                    results.append(dataclasses.replace(ex, status=AnchorStatus.DUPLICATE))
            return results

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _commit_batch)

    async def get_by_content_id(self, content_id: str) -> Optional[AnchorReceipt]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._fetch_by("content_id", content_id))

    async def get_by_txid(self, txid: str) -> Optional[AnchorReceipt]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._fetch_by("txid", txid))

    async def verify(self, content_id: str) -> bool:
        """
        Проверяем:
        1) Событие пере-канонизируется по сохранённым полям;
        2) Хэш события совпадает с txid;
        3) hmac_curr == HMAC(key, payload + hmac_prev);
        4) Цепочка согласована с предыдущей записью.
        """
        def _verify() -> bool:
            rows = self._db.q("""
                SELECT id,txid,content_id,merkle_root,size,metadata,created_at,hmac_prev,hmac_curr
                FROM anchors WHERE content_id=? LIMIT 1
            """, (content_id,))
            if not rows:
                return False
            (row_id, txid, cid, merkle, size, meta, created_at, hprev, hcurr) = rows[0]
            # 1) восстановим AnchorRequest
            req = AnchorRequest(
                content_id=cid,
                merkle_root=merkle,
                size=int(size),
                metadata=json.loads(meta),
                created_at=dt.datetime.fromisoformat(created_at),
                tenant=self.cfg.tenant
            )
            payload = self._canon(req)
            # 2) сверка txid
            if _hash_bytes(payload) != txid:
                return False
            # 3) сверка hmac_curr
            h_prev_bytes = bytes.fromhex(hprev) if hprev else b""
            calc = hmac.new(self._hmac_key, payload + h_prev_bytes, "sha256").hexdigest()
            if calc != hcurr:
                return False
            # 4) сверка соответствия с предыдущей записью (если есть)
            if row_id > 1:
                prev = self._db.q("SELECT hmac_curr FROM anchors WHERE id=?", (row_id - 1,))
                if prev:
                    if (hprev or "") != (prev[0][0] or ""):
                        return False
            return True

        ok = await asyncio.get_running_loop().run_in_executor(None, _verify)
        self._counters["verify_ok" if ok else "verify_fail"] += 1
        return ok

    async def health(self) -> Dict[str, Any]:
        def _h() -> Dict[str, Any]:
            try:
                rows = self._db.q("SELECT COUNT(1), MAX(block_number) FROM anchors")
                cnt, maxb = rows[0]
                return {
                    "backend": self.CHAIN_ID,
                    "ok": True,
                    "items": int(cnt),
                    "max_block": int(maxb) if maxb is not None else 0,
                    "counters": dict(self._counters),
                }
            except Exception as e:
                return {"backend": self.CHAIN_ID, "ok": False, "error": str(e)}
        return await asyncio.get_running_loop().run_in_executor(None, _h)

    async def close(self) -> None:
        self._db.close()


# -------- EVM Adapter (configuration-validated stub) --------

class EvmLedgerAdapter(LedgerAdapter):
    """
    Заглушка-переходник для EVM. Выполняет валидацию конфигурации и формирование канонических
    событий/txid вне сети. Интеграция с web3 должна быть добавлена в вызывающем слое.
    """
    CHAIN_ID_PREFIX = "EVM"

    def __init__(self, cfg: LedgerConfig):
        super().__init__(cfg)
        if not cfg.evm_rpc_url or not cfg.evm_chain_id or not cfg.evm_contract_address:
            raise RuntimeError("EVM adapter misconfigured: evm_rpc_url, evm_chain_id and evm_contract_address are required.")
        self._chain_id = f"{self.CHAIN_ID_PREFIX}:{cfg.evm_chain_id}:{cfg.evm_contract_address.lower()}"

    async def anchor(self, req: AnchorRequest) -> AnchorReceipt:
        txid = _hash_bytes(req.canonical_event())  # детерминированный client-side id
        # Здесь должен быть вызов web3 для отправки tx/event; опущено в рамках ядра.
        now = dt.datetime.now(tz=dt.timezone.utc)
        return AnchorReceipt(
            status=AnchorStatus.PENDING,
            txid=txid,
            chain_id=self._chain_id,
            block_number=None,
            timestamp=now,
            content_id=req.content_id,
            merkle_root=req.merkle_root,
            size=req.size,
            metadata=req.metadata,
            confirmations=None,
        )

    async def anchor_batch(self, reqs: Sequence[AnchorRequest]) -> List[AnchorReceipt]:
        return [await self.anchor(r) for r in reqs]

    async def get_by_content_id(self, content_id: str) -> Optional[AnchorReceipt]:
        return None  # требуется реальный RPC/индексация

    async def get_by_txid(self, txid: str) -> Optional[AnchorReceipt]:
        return None

    async def verify(self, content_id: str) -> bool:
        return False  # верификация требует RPC/логов контракта

    async def health(self) -> Dict[str, Any]:
        return {"backend": self._chain_id, "ok": True, "note": "RPC integration required at higher layer"}


# -------- TON Adapter (configuration-validated stub) --------

class TonLedgerAdapter(LedgerAdapter):
    """
    Заглушка-переходник для TON. Аналогично EVM, валидация конфигурации.
    """
    CHAIN_ID = "TON"

    def __init__(self, cfg: LedgerConfig):
        super().__init__(cfg)
        if not cfg.ton_endpoint or not cfg.ton_wallet:
            raise RuntimeError("TON adapter misconfigured: ton_endpoint and ton_wallet are required.")

    async def anchor(self, req: AnchorRequest) -> AnchorReceipt:
        txid = _hash_bytes(req.canonical_event())
        now = dt.datetime.now(tz=dt.timezone.utc)
        return AnchorReceipt(
            status=AnchorStatus.PENDING,
            txid=txid,
            chain_id=self.CHAIN_ID,
            block_number=None,
            timestamp=now,
            content_id=req.content_id,
            merkle_root=req.merkle_root,
            size=req.size,
            metadata=req.metadata,
        )

    async def anchor_batch(self, reqs: Sequence[AnchorRequest]) -> List[AnchorReceipt]:
        return [await self.anchor(r) for r in reqs]

    async def get_by_content_id(self, content_id: str) -> Optional[AnchorReceipt]:
        return None

    async def get_by_txid(self, txid: str) -> Optional[AnchorReceipt]:
        return None

    async def verify(self, content_id: str) -> bool:
        return False

    async def health(self) -> Dict[str, Any]:
        return {"backend": self.CHAIN_ID, "ok": True, "note": "TON integration required at higher layer"}


# -------- NULL Adapter (no-op with deterministic txid) --------

class NullLedgerAdapter(LedgerAdapter):
    """
    No-op адаптер. Полезен для тестов. Возвращает детерминированный txid по каноническому событию.
    """
    CHAIN_ID = "NULL"

    async def anchor(self, req: AnchorRequest) -> AnchorReceipt:
        txid = _hash_bytes(req.canonical_event())
        now = dt.datetime.now(tz=dt.timezone.utc)
        return AnchorReceipt(
            status=AnchorStatus.CONFIRMED,
            txid=txid,
            chain_id=self.CHAIN_ID,
            block_number=None,
            timestamp=now,
            content_id=req.content_id,
            merkle_root=req.merkle_root,
            size=req.size,
            metadata=req.metadata,
        )

    async def anchor_batch(self, reqs: Sequence[AnchorRequest]) -> List[AnchorReceipt]:
        return [await self.anchor(r) for r in reqs]

    async def get_by_content_id(self, content_id: str) -> Optional[AnchorReceipt]:
        return None

    async def get_by_txid(self, txid: str) -> Optional[AnchorReceipt]:
        return None

    async def verify(self, content_id: str) -> bool:
        return True

    async def health(self) -> Dict[str, Any]:
        return {"backend": self.CHAIN_ID, "ok": True}


# -------- Factory --------

def build_ledger_adapter(cfg: LedgerConfig) -> LedgerAdapter:
    """
    Фабрика адаптера по типу бэкенда.
    """
    if cfg.backend == LedgerBackendType.FILE:
        return FileLedgerAdapter(cfg)
    if cfg.backend == LedgerBackendType.EVM:
        return EvmLedgerAdapter(cfg)
    if cfg.backend == LedgerBackendType.TON:
        return TonLedgerAdapter(cfg)
    if cfg.backend == LedgerBackendType.NULL:
        return NullLedgerAdapter(cfg)
    raise ValueError(f"Unknown backend: {cfg.backend}")


# -------- Helper builders --------

def make_anchor_request(
    *,
    content_id: str,
    merkle_root: str,
    size: int,
    metadata: Optional[Dict[str, Any]] = None,
    tenant: Optional[str] = None,
    created_at: Optional[dt.datetime] = None,
) -> AnchorRequest:
    """
    Утилита для безопасной сборки запроса (валидация и нормализация).
    """
    if not isinstance(content_id, str) or not content_id:
        raise ValueError("content_id must be non-empty str")
    if not isinstance(merkle_root, str):
        raise ValueError("merkle_root must be str")
    if not isinstance(size, int) or size < 0:
        raise ValueError("size must be non-negative int")

    # metadata — только JSON-совместимые типы
    meta = metadata or {}
    try:
        json.dumps(meta, ensure_ascii=False)
    except Exception as e:
        raise ValueError(f"metadata must be JSON-serializable: {e}")

    ts = created_at or dt.datetime.now(tz=dt.timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)

    return AnchorRequest(
        content_id=content_id,
        merkle_root=merkle_root,
        size=size,
        metadata=meta,
        created_at=ts,
        tenant=tenant,
    )
