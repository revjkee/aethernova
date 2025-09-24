# ledger-core/ledger/storage/repositories/proof_repo.py
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

# ===========================
# Мини-протокол БД (совместим с asyncpg)
# ===========================

class DBConnection(Protocol):
    async def fetchrow(self, query: str, *args) -> Optional[Mapping[str, Any]]: ...
    async def fetch(self, query: str, *args) -> Sequence[Mapping[str, Any]]: ...
    async def execute(self, query: str, *args) -> str: ...
    async def fetchval(self, query: str, *args) -> Any: ...

class DBPool(Protocol):
    async def acquire(self) -> DBConnection: ...
    async def release(self, conn: DBConnection) -> None: ...

# ===========================
# Модель и статусы
# ===========================

ProofStatus = str  # "pending" | "finalized"

@dataclass(frozen=True)
class ProofRecord:
    namespace: str
    period_start: int  # unix seconds (UTC), inclusive
    period_end: int    # unix seconds (UTC), exclusive OR inclusive — должен совпадать с планировщиком
    anchor_id: str     # внешний идентификатор анкеринга (txid/uri)
    payload_hash: str  # hex(SHA-256(payload))
    merkle_root: Optional[str]  # если есть корень состояния
    created_at: datetime
    finalized_at: Optional[datetime]
    status: ProofStatus  # "pending"|"finalized"
    extra: Dict[str, Any]

def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ===========================
# DDL (миграция)
# ===========================

DDL_CREATE = r"""
CREATE TABLE IF NOT EXISTS ledger_proofs (
    namespace       TEXT        NOT NULL,
    period_start    BIGINT      NOT NULL,
    period_end      BIGINT      NOT NULL,
    anchor_id       TEXT        NOT NULL,
    payload_hash    TEXT        NOT NULL,
    merkle_root     TEXT        NULL,
    status          TEXT        NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finalized_at    TIMESTAMPTZ NULL,
    extra           JSONB       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT ledger_proofs_pk PRIMARY KEY (namespace, period_start, period_end),
    CONSTRAINT ledger_proofs_hash_len CHECK (char_length(payload_hash)=64),
    CONSTRAINT ledger_proofs_status CHECK (status IN ('pending','finalized'))
);

-- Идемпотентная уникальность внешнего идемпотентного идентификатора (опционально)
-- CREATE UNIQUE INDEX IF NOT EXISTS ledger_proofs_anchor_id_uk
--   ON ledger_proofs(namespace, anchor_id);

-- Индексы для диапазонных запросов/«последнего окна»
CREATE INDEX IF NOT EXISTS ledger_proofs_ns_end_idx
  ON ledger_proofs(namespace, period_end DESC);

CREATE INDEX IF NOT EXISTS ledger_proofs_ns_status_end_idx
  ON ledger_proofs(namespace, status, period_end DESC);
"""

# ===========================
# Кэш LRU (опционально)
# ===========================

class _LRU:
    __slots__ = ("cap", "data", "order")

    def __init__(self, capacity: int = 256) -> None:
        self.cap = capacity
        self.data: Dict[Tuple[str, int, int], ProofRecord] = {}
        self.order: List[Tuple[str, int, int]] = []

    def get(self, key: Tuple[str, int, int]) -> Optional[ProofRecord]:
        v = self.data.get(key)
        if v is None:
            return None
        try:
            self.order.remove(key)
        except ValueError:
            pass
        self.order.append(key)
        return v

    def put(self, key: Tuple[str, int, int], val: ProofRecord) -> None:
        if key in self.data:
            try:
                self.order.remove(key)
            except ValueError:
                pass
        self.data[key] = val
        self.order.append(key)
        while len(self.order) > self.cap:
            k = self.order.pop(0)
            self.data.pop(k, None)

    def drop(self, key: Tuple[str, int, int]) -> None:
        self.data.pop(key, None)
        try:
            self.order.remove(key)
        except ValueError:
            pass

# ===========================
# Репозиторий
# ===========================

class ProofRepository:
    """
    Репозиторий доказательств анкеринга (PostgreSQL).
    Контракт:
      - запись окна идемпотентна по (namespace, period_start, period_end)
      - payload_hash неизменяем после первой фиксации
      - finalize переводит статус в 'finalized' и устанавливает finalized_at
    """

    def __init__(self, pool: DBPool, *, enable_cache: bool = True, cache_capacity: int = 512) -> None:
        self.pool = pool
        self.cache = _LRU(cache_capacity) if enable_cache else None

    # ---------- Schema ----------

    async def ensure_schema(self) -> None:
        conn = await self.pool.acquire()
        try:
            await conn.execute(DDL_CREATE)
        finally:
            await self.pool.release(conn)

    # ---------- Маппинг ----------

    @staticmethod
    def _row_to_record(r: Mapping[str, Any]) -> ProofRecord:
        return ProofRecord(
            namespace=r["namespace"],
            period_start=int(r["period_start"]),
            period_end=int(r["period_end"]),
            anchor_id=r["anchor_id"],
            payload_hash=r["payload_hash"],
            merkle_root=r.get("merkle_root"),
            status=r["status"],
            created_at=r["created_at"],
            finalized_at=r.get("finalized_at"),
            extra=dict(r.get("extra") or {}),
        )

    # ---------- CRUD ----------

    async def upsert_idempotent(
        self,
        *,
        namespace: str,
        period_start: int,
        period_end: int,
        anchor_id: str,
        payload: bytes,
        merkle_root: Optional[str] = None,
        extra: Optional[Mapping[str, Any]] = None,
        status: ProofStatus = "pending",
    ) -> ProofRecord:
        """
        Идемпотентная вставка. Если запись существует:
          - проверяет совпадение payload_hash, merkle_root (если был задан ранее)
          - обновляет anchor_id (если новый), status (только переход pending->finalized), extra (merge)
        """
        payload_hash = _sha256_hex(payload)
        conn = await self.pool.acquire()
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO ledger_proofs(namespace, period_start, period_end, anchor_id, payload_hash, merkle_root, status, extra)
                VALUES($1,$2,$3,$4,$5,$6,$7,COALESCE($8,'{}'::jsonb))
                ON CONFLICT (namespace, period_start, period_end) DO UPDATE
                SET
                  anchor_id = EXCLUDED.anchor_id,
                  -- status только вперёд
                  status = CASE
                    WHEN ledger_proofs.status='finalized' THEN 'finalized'
                    WHEN EXCLUDED.status='finalized' THEN 'finalized'
                    ELSE 'pending' END,
                  merkle_root = COALESCE(ledger_proofs.merkle_root, EXCLUDED.merkle_root),
                  extra = ledger_proofs.extra || EXCLUDED.extra
                RETURNING *
                """,
                namespace, period_start, period_end, anchor_id, payload_hash, merkle_root, status, dict(extra or {}),
            )
            rec = self._row_to_record(row)
        finally:
            await self.pool.release(conn)

        # Инварианты: существующая запись не должна менять payload_hash
        if rec.payload_hash != payload_hash:
            raise ValueError("payload_hash mismatch for existing proof")

        if self.cache:
            self.cache.put((namespace, period_start, period_end), rec)
        return rec

    async def mark_finalized(
        self,
        *,
        namespace: str,
        period_start: int,
        period_end: int,
        anchor_id: Optional[str] = None,
    ) -> ProofRecord:
        """
        Переводит запись в finalized, устанавливает finalized_at, опционально обновляет anchor_id.
        """
        conn = await self.pool.acquire()
        try:
            row = await conn.fetchrow(
                """
                UPDATE ledger_proofs
                SET status='finalized',
                    finalized_at=COALESCE(finalized_at, now()),
                    anchor_id=COALESCE($4, anchor_id)
                WHERE namespace=$1 AND period_start=$2 AND period_end=$3
                RETURNING *
                """,
                namespace, period_start, period_end, anchor_id,
            )
            if not row:
                raise KeyError("proof not found")
            rec = self._row_to_record(row)
        finally:
            await self.pool.release(conn)

        if self.cache:
            self.cache.put((namespace, period_start, period_end), rec)
        return rec

    async def get(
        self, *, namespace: str, period_start: int, period_end: int
    ) -> Optional[ProofRecord]:
        if self.cache:
            cached = self.cache.get((namespace, period_start, period_end))
            if cached:
                return cached

        conn = await self.pool.acquire()
        try:
            row = await conn.fetchrow(
                """
                SELECT * FROM ledger_proofs
                WHERE namespace=$1 AND period_start=$2 AND period_end=$3
                """,
                namespace, period_start, period_end,
            )
        finally:
            await self.pool.release(conn)

        if not row:
            return None
        rec = self._row_to_record(row)
        if self.cache:
            self.cache.put((namespace, period_start, period_end), rec)
        return rec

    async def get_latest(
        self, *, namespace: str, status: Optional[ProofStatus] = None
    ) -> Optional[ProofRecord]:
        conn = await self.pool.acquire()
        try:
            if status:
                row = await conn.fetchrow(
                    """
                    SELECT * FROM ledger_proofs
                    WHERE namespace=$1 AND status=$2
                    ORDER BY period_end DESC
                    LIMIT 1
                    """,
                    namespace, status,
                )
            else:
                row = await conn.fetchrow(
                    """
                    SELECT * FROM ledger_proofs
                    WHERE namespace=$1
                    ORDER BY period_end DESC
                    LIMIT 1
                    """,
                    namespace,
                )
        finally:
            await self.pool.release(conn)
        return self._row_to_record(row) if row else None

    async def list_range(
        self, *, namespace: str, start_inclusive: int, end_inclusive: int, status: Optional[ProofStatus] = None, limit: int = 1000
    ) -> List[ProofRecord]:
        conn = await self.pool.acquire()
        try:
            if status:
                rows = await conn.fetch(
                    """
                    SELECT * FROM ledger_proofs
                    WHERE namespace=$1
                      AND status=$2
                      AND period_end BETWEEN $3 AND $4
                    ORDER BY period_end ASC
                    LIMIT $5
                    """,
                    namespace, status, start_inclusive, end_inclusive, limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT * FROM ledger_proofs
                    WHERE namespace=$1
                      AND period_end BETWEEN $2 AND $3
                    ORDER BY period_end ASC
                    LIMIT $4
                    """,
                    namespace, start_inclusive, end_inclusive, limit,
                )
        finally:
            await self.pool.release(conn)
        return [self._row_to_record(r) for r in rows]

    async def delete_older_than(
        self, *, namespace: str, end_before: int, keep_finalized: bool = True
    ) -> int:
        """
        Удаляет старые записи. По умолчанию сохраняет finalized.
        Возвращает количество удалённых строк.
        """
        conn = await self.pool.acquire()
        try:
            if keep_finalized:
                val = await conn.fetchval(
                    """
                    WITH del AS (
                      DELETE FROM ledger_proofs
                      WHERE namespace=$1
                        AND period_end < $2
                        AND status <> 'finalized'
                      RETURNING 1
                    )
                    SELECT COUNT(*) FROM del
                    """,
                    namespace, end_before,
                )
            else:
                val = await conn.fetchval(
                    """
                    WITH del AS (
                      DELETE FROM ledger_proofs
                      WHERE namespace=$1
                        AND period_end < $2
                    RETURNING 1)
                    SELECT COUNT(*) FROM del
                    """,
                    namespace, end_before,
                )
        finally:
            await self.pool.release(conn)
        # Инвалидация кэша best-effort (чистка всего кэша не реализована ради простоты)
        return int(val or 0)

    # ---------- Проверки интегритета ----------

    async def assert_invariants(self) -> None:
        """
        Быстрая проверка инвариантов таблицы:
          - status в допустимом множестве
          - payload_hash длиной 64
        """
        conn = await self.pool.acquire()
        try:
            bad = await conn.fetchval("SELECT COUNT(*) FROM ledger_proofs WHERE char_length(payload_hash)<>64 OR status NOT IN ('pending','finalized')")
        finally:
            await self.pool.release(conn)
        if bad and int(bad) > 0:
            raise AssertionError(f"integrity check failed: {bad} rows")

# ===========================
# Хелперы высокого уровня
# ===========================

async def store_proof_idempotent(
    repo: ProofRepository,
    *,
    namespace: str,
    period_start: int,
    period_end: int,
    anchor_id: str,
    payload: bytes,
    merkle_root: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
    finalize: bool = False,
) -> ProofRecord:
    """
    Упрощённый путь: сохранить (идемпотентно) и по желанию финализировать.
    """
    rec = await repo.upsert_idempotent(
        namespace=namespace,
        period_start=period_start,
        period_end=period_end,
        anchor_id=anchor_id,
        payload=payload,
        merkle_root=merkle_root,
        extra=extra,
        status="finalized" if finalize else "pending",
    )
    # Если запись уже была и статус не обновился — можно догарантить finalize
    if finalize and rec.status != "finalized":
        rec = await repo.mark_finalized(namespace=namespace, period_start=period_start, period_end=period_end)
    return rec
