# path: veilmind-core/veilmind/storage/repositories/consent_repo.py
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

try:
    import asyncpg  # type: ignore
except Exception as e:  # pragma: no cover
    asyncpg = None  # type: ignore

from pydantic import BaseModel, Field, StrictBool, StrictInt, StrictStr, field_validator

# --------------------------------------------------------------------------------------
# Публичные типы и исключения
# --------------------------------------------------------------------------------------

ConsentStatus = Literal["granted", "denied", "revoked"]
LawfulBasis = Literal[
    "consent", "contract", "legal_obligation", "legitimate_interests", "vital_interests", "public_task"
]

class OptimisticLockError(RuntimeError):
    """Версия записи устарела (конкурирующее обновление)."""

class IdempotencyConflict(RuntimeError):
    """Идемпотентный ключ уже использован с другими параметрами."""

class RepositoryUnavailable(RuntimeError):
    """Драйвер БД недоступен или пул не инициализирован."""

# --------------------------------------------------------------------------------------
# Модели домена
# --------------------------------------------------------------------------------------

class ConsentRecord(BaseModel):
    id: int
    tenant_id: StrictStr
    subject_id: StrictStr
    purpose: StrictStr
    status: ConsentStatus
    lawful_basis: Optional[LawfulBasis] = None
    source: StrictStr
    proof_uri: Optional[StrictStr] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    valid_from: datetime
    valid_until: Optional[datetime] = None
    version: StrictInt
    actor: Optional[StrictStr] = None
    ip: Optional[StrictStr] = None
    user_agent: Optional[StrictStr] = None
    created_at: datetime
    updated_at: datetime
    soft_deleted: StrictBool = False
    idempotency_key: Optional[StrictStr] = None

    @field_validator("valid_from", "valid_until", "created_at", "updated_at")
    @classmethod
    def _tz_aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return v
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

class ConsentDecision(BaseModel):
    allowed: bool
    status: ConsentStatus
    effective: bool
    tenant_id: StrictStr
    subject_id: StrictStr
    purpose: StrictStr
    lawful_basis: Optional[LawfulBasis] = None
    valid_until: Optional[datetime] = None
    reason: StrictStr

class PageInfo(BaseModel):
    next_cursor: Optional[str] = None
    has_more: bool = False

class ConsentPage(BaseModel):
    items: List[ConsentRecord]
    page_info: PageInfo

# --------------------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _encode_cursor(values: Tuple[Any, ...]) -> str:
    raw = json.dumps(values, separators=(",", ":"), default=str).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")

def _decode_cursor(cursor: str) -> Tuple[Any, ...]:
    raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
    return tuple(json.loads(raw.decode("utf-8")))

def _row_to_record(row: asyncpg.Record) -> ConsentRecord:  # type: ignore[name-defined]
    return ConsentRecord(
        id=row["id"],
        tenant_id=row["tenant_id"],
        subject_id=row["subject_id"],
        purpose=row["purpose"],
        status=row["status"],
        lawful_basis=row["lawful_basis"],
        source=row["source"],
        proof_uri=row["proof_uri"],
        metadata=row["metadata"] or {},
        valid_from=row["valid_from"],
        valid_until=row["valid_until"],
        version=row["version"],
        actor=row["actor"],
        ip=row["ip"],
        user_agent=row["user_agent"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        soft_deleted=row["soft_deleted"],
        idempotency_key=row["idempotency_key"],
    )

def _effective_status(rec: ConsentRecord, ref: Optional[datetime] = None) -> Tuple[bool, str]:
    """
    Возвращает (effective, reason).
    Правила: revoked/denied -> not effective; expired -> not effective; soft_deleted -> not effective; иначе — effective.
    """
    now = ref or _utcnow()
    if rec.soft_deleted:
        return False, "soft_deleted"
    if rec.status == "revoked":
        return False, "revoked"
    if rec.status == "denied":
        return False, "denied"
    if rec.valid_until and now >= rec.valid_until:
        return False, "expired"
    return True, "active"

# --------------------------------------------------------------------------------------
# SQL DDL (idempotent)
# --------------------------------------------------------------------------------------

DDL_CONSENTS = """
CREATE TABLE IF NOT EXISTS consents (
  id               BIGSERIAL PRIMARY KEY,
  tenant_id        TEXT NOT NULL,
  subject_id       TEXT NOT NULL,
  purpose          TEXT NOT NULL,
  status           TEXT NOT NULL CHECK (status IN ('granted','denied','revoked')),
  lawful_basis     TEXT NULL CHECK (lawful_basis IN ('consent','contract','legal_obligation','legitimate_interests','vital_interests','public_task')),
  source           TEXT NOT NULL,
  proof_uri        TEXT NULL,
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
  valid_from       TIMESTAMPTZ NOT NULL DEFAULT now(),
  valid_until      TIMESTAMPTZ NULL,
  version          INT NOT NULL DEFAULT 1,
  actor            TEXT NULL,
  ip               INET NULL,
  user_agent       TEXT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  soft_deleted     BOOLEAN NOT NULL DEFAULT FALSE,
  idempotency_key  TEXT NULL
);
-- одна активная запись на (tenant, subject, purpose)
CREATE UNIQUE INDEX IF NOT EXISTS consents_uniq_active
  ON consents(tenant_id, subject_id, purpose)
  WHERE soft_deleted = FALSE;
-- фильтруемый индекс по идемпотенции
CREATE UNIQUE INDEX IF NOT EXISTS consents_idempotency_uniq
  ON consents(tenant_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS consents_tenant_subject ON consents(tenant_id, subject_id) WHERE soft_deleted = FALSE;
CREATE INDEX IF NOT EXISTS consents_tenant_purpose ON consents(tenant_id, purpose) WHERE soft_deleted = FALSE;
CREATE INDEX IF NOT EXISTS consents_updated_at ON consents(updated_at DESC);
"""

DDL_AUDIT = """
CREATE TABLE IF NOT EXISTS consent_audit (
  audit_id     BIGSERIAL PRIMARY KEY,
  consent_id   BIGINT NOT NULL,
  tenant_id    TEXT NOT NULL,
  subject_id   TEXT NOT NULL,
  purpose      TEXT NOT NULL,
  prev_status  TEXT NULL,
  new_status   TEXT NOT NULL,
  change_kind  TEXT NOT NULL, -- 'create','update','revoke','delete'
  actor        TEXT NULL,
  reason       TEXT NULL,
  at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  snapshot     JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS consent_audit_tenant ON consent_audit(tenant_id, subject_id, purpose, at DESC);
"""

# --------------------------------------------------------------------------------------
# Репозиторий
# --------------------------------------------------------------------------------------

@dataclass
class ConsentRepository:
    pool: "asyncpg.Pool"  # type: ignore[name-defined]

    # ---------------- Schema ----------------

    async def ensure_schema(self) -> None:
        if asyncpg is None:
            raise RepositoryUnavailable("asyncpg is not installed")
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(DDL_CONSENTS)
                await conn.execute(DDL_AUDIT)

    # ---------------- Основные операции ----------------

    async def create_or_update(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        purpose: str,
        status: ConsentStatus,
        lawful_basis: Optional[LawfulBasis] = None,
        source: str,
        proof_uri: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ttl_seconds: Optional[int] = None,
        actor: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> ConsentRecord:
        """
        Создаёт или обновляет согласие. Идемпотентно по (tenant_id, idempotency_key).
        Если expected_version задан — включается оптимистическая блокировка.
        """
        if asyncpg is None:
            raise RepositoryUnavailable("asyncpg is not installed")

        valid_from = _utcnow()
        valid_until = (valid_from + timedelta(seconds=ttl_seconds)) if ttl_seconds else None
        meta = metadata or {}

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                # Идемпотентность
                if idempotency_key:
                    row = await conn.fetchrow(
                        """
                        SELECT * FROM consents
                         WHERE tenant_id=$1 AND idempotency_key=$2
                        """,
                        tenant_id, idempotency_key,
                    )
                    if row:
                        rec = _row_to_record(row)
                        # тот же набор полей? если нет — конфликт
                        if (rec.subject_id != subject_id) or (rec.purpose != purpose) or (rec.status != status):
                            raise IdempotencyConflict("idempotency_key already used with different payload")
                        return rec

                # Пробуем вставить (новая запись)
                row = await conn.fetchrow(
                    """
                    INSERT INTO consents
                      (tenant_id, subject_id, purpose, status, lawful_basis, source, proof_uri, metadata,
                       valid_from, valid_until, actor, ip, user_agent, idempotency_key)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                    ON CONFLICT (tenant_id, subject_id, purpose) WHERE soft_deleted = FALSE
                    DO UPDATE SET
                      status=EXCLUDED.status,
                      lawful_basis=EXCLUDED.lawful_basis,
                      source=EXCLUDED.source,
                      proof_uri=EXCLUDED.proof_uri,
                      metadata=EXCLUDED.metadata,
                      valid_from=EXCLUDED.valid_from,
                      valid_until=EXCLUDED.valid_until,
                      actor=EXCLUDED.actor,
                      ip=EXCLUDED.ip,
                      user_agent=EXCLUDED.user_agent,
                      updated_at=now(),
                      version = consents.version + 1
                    WHERE
                      ($15::INT IS NULL OR consents.version = $15)
                    RETURNING *;
                    """,
                    tenant_id, subject_id, purpose, status, lawful_basis, source, proof_uri, meta,
                    valid_from, valid_until, actor, ip, user_agent, idempotency_key,
                    expected_version,
                )
                if row is None:
                    # не обновили из-за version mismatch
                    raise OptimisticLockError("consent version mismatch")

                rec = _row_to_record(row)

                # Аудит
                await conn.execute(
                    """
                    INSERT INTO consent_audit (consent_id, tenant_id, subject_id, purpose,
                                               prev_status, new_status, change_kind, actor, reason, snapshot)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                    """,
                    rec.id, tenant_id, subject_id, purpose,
                    None if rec.version == 1 else "unknown",
                    rec.status, "create" if rec.version == 1 else "update",
                    actor, None, json.dumps(rec.model_dump(mode="json"), ensure_ascii=False),
                )
                return rec

    async def revoke(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        purpose: str,
        reason: Optional[str] = None,
        actor: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> ConsentRecord:
        """
        Помечает согласие как revoked.
        """
        if asyncpg is None:
            raise RepositoryUnavailable("asyncpg is not installed")

        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    UPDATE consents AS c
                       SET status='revoked',
                           updated_at=now(),
                           version = c.version + 1
                     WHERE tenant_id=$1 AND subject_id=$2 AND purpose=$3 AND soft_deleted=FALSE
                       AND ($4::INT IS NULL OR version=$4)
                 RETURNING *;
                    """,
                    tenant_id, subject_id, purpose, expected_version,
                )
                if row is None:
                    raise OptimisticLockError("consent not found or version mismatch")

                rec = _row_to_record(row)

                await conn.execute(
                    """
                    INSERT INTO consent_audit (consent_id, tenant_id, subject_id, purpose,
                                               prev_status, new_status, change_kind, actor, reason, snapshot)
                    VALUES ($1,$2,$3,$4,$5,$6,'revoke',$7,$8,$9)
                    """,
                    rec.id, tenant_id, subject_id, purpose,
                    "unknown", rec.status, actor, reason,
                    json.dumps(rec.model_dump(mode="json"), ensure_ascii=False),
                )
                return rec

    async def soft_delete_subject(self, *, tenant_id: str, subject_id: str, reason: Optional[str] = None, actor: Optional[str] = None) -> int:
        """
        Мягкое удаление всех согласий субъекта (soft_deleted=TRUE). Возвращает число записей.
        """
        if asyncpg is None:
            raise RepositoryUnavailable("asyncpg is not installed")
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    """
                    UPDATE consents
                       SET soft_deleted=TRUE, updated_at=now(), version=version+1
                     WHERE tenant_id=$1 AND subject_id=$2 AND soft_deleted=FALSE
                 RETURNING *;
                    """,
                    tenant_id, subject_id,
                )
                for r in rows:
                    await conn.execute(
                        """
                        INSERT INTO consent_audit (consent_id, tenant_id, subject_id, purpose,
                                                   prev_status, new_status, change_kind, actor, reason, snapshot)
                        VALUES ($1,$2,$3,$4,$5,$6,'delete',$7,$8,$9)
                        """,
                        r["id"], r["tenant_id"], r["subject_id"], r["purpose"],
                        r["status"], r["status"], actor, reason,
                        json.dumps(dict(r), ensure_ascii=False),
                    )
                return len(rows)

    # ---------------- Чтение/проверка ----------------

    async def get(self, *, tenant_id: str, subject_id: str, purpose: str) -> Optional[ConsentRecord]:
        if asyncpg is None:
            raise RepositoryUnavailable("asyncpg is not installed")
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM consents
                 WHERE tenant_id=$1 AND subject_id=$2 AND purpose=$3 AND soft_deleted=FALSE
                """,
                tenant_id, subject_id, purpose,
            )
            return _row_to_record(row) if row else None

    async def check_effective(self, *, tenant_id: str, subject_id: str, purpose: str) -> ConsentDecision:
        """
        Возвращает решение с учётом статуса и срока действия.
        """
        rec = await self.get(tenant_id=tenant_id, subject_id=subject_id, purpose=purpose)
        if rec is None:
            return ConsentDecision(
                allowed=False, status="denied", effective=False,
                tenant_id=tenant_id, subject_id=subject_id, purpose=purpose,
                lawful_basis=None, valid_until=None, reason="not_found",
            )
        effective, reason = _effective_status(rec)
        return ConsentDecision(
            allowed=(effective and rec.status == "granted"),
            status=rec.status,
            effective=effective,
            tenant_id=rec.tenant_id,
            subject_id=rec.subject_id,
            purpose=rec.purpose,
            lawful_basis=rec.lawful_basis,
            valid_until=rec.valid_until,
            reason=reason,
        )

    async def bulk_get_effective(
        self, *, tenant_id: str, subject_ids: Sequence[str], purposes: Sequence[str]
    ) -> Dict[Tuple[str, str], ConsentDecision]:
        """
        Массовая проверка. Возвращает словарь (subject_id, purpose) -> Decision.
        """
        if asyncpg is None:
            raise RepositoryUnavailable("asyncpg is not installed")
        decisions: Dict[Tuple[str, str], ConsentDecision] = {}
        if not subject_ids or not purposes:
            return decisions

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM consents
                 WHERE tenant_id=$1 AND subject_id = ANY($2::text[]) AND purpose = ANY($3::text[]) AND soft_deleted=FALSE
                """,
                tenant_id, list(subject_ids), list(purposes),
            )
            now = _utcnow()
            seen = set()
            for row in rows:
                rec = _row_to_record(row)
                effective, reason = _effective_status(rec, now)
                decisions[(rec.subject_id, rec.purpose)] = ConsentDecision(
                    allowed=(effective and rec.status == "granted"),
                    status=rec.status,
                    effective=effective,
                    tenant_id=rec.tenant_id,
                    subject_id=rec.subject_id,
                    purpose=rec.purpose,
                    lawful_basis=rec.lawful_basis,
                    valid_until=rec.valid_until,
                    reason=reason,
                )
                seen.add((rec.subject_id, rec.purpose))

            # Для пропусков — not_found
            for s in subject_ids:
                for p in purposes:
                    if (s, p) not in seen:
                        decisions[(s, p)] = ConsentDecision(
                            allowed=False, status="denied", effective=False,
                            tenant_id=tenant_id, subject_id=s, purpose=p,
                            lawful_basis=None, valid_until=None, reason="not_found",
                        )
        return decisions

    async def list(
        self,
        *,
        tenant_id: str,
        subject_id: Optional[str] = None,
        purpose_prefix: Optional[str] = None,
        status: Optional[ConsentStatus] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> ConsentPage:
        """
        Курсорная пагинация по (updated_at DESC, id DESC).
        cursor — base64(JSON [updated_at_iso, id]).
        """
        if asyncpg is None:
            raise RepositoryUnavailable("asyncpg is not installed")

        limit = max(1, min(500, limit))
        params: List[Any] = [tenant_id]
        conds = ["tenant_id=$1", "soft_deleted=FALSE"]

        if subject_id:
            params.append(subject_id)
            conds.append(f"subject_id=${len(params)}")
        if purpose_prefix:
            params.append(purpose_prefix + "%")
            conds.append(f"purpose LIKE ${len(params)}")
        if status:
            params.append(status)
            conds.append(f"status=${len(params)}")

        after_clause = ""
        if cursor:
            try:
                updated_iso, last_id = _decode_cursor(cursor)
                params.extend([updated_iso, last_id])
                after_clause = f" AND (updated_at, id) < ($${len(params)-1}::timestamptz, $${len(params)}::bigint)"  # noqa: E501
            except Exception:
                pass

        sql = f"""
            SELECT * FROM consents
             WHERE {' AND '.join(conds)} {after_clause}
             ORDER BY updated_at DESC, id DESC
             LIMIT {limit+1};
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
            items = [_row_to_record(r) for r in rows[:limit]]
            has_more = len(rows) > limit
            next_cursor = None
            if has_more:
                last = items[-1]
                next_cursor = _encode_cursor((last.updated_at.isoformat(), last.id))
            return ConsentPage(items=items, page_info=PageInfo(next_cursor=next_cursor, has_more=has_more))

    # ---------------- Обслуживание ----------------

    async def purge_expired(self, *, tenant_id: str, older_than: Optional[datetime] = None, limit: int = 1000) -> int:
        """
        Мягко удаляет просроченные согласия (valid_until < now). Возвращает количество.
        """
        if asyncpg is None:
            raise RepositoryUnavailable("asyncpg is not installed")
        now = _utcnow()
        cutoff = older_than or now
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    """
                    UPDATE consents
                       SET soft_deleted=TRUE, updated_at=now(), version=version+1
                     WHERE tenant_id=$1
                       AND soft_deleted=FALSE
                       AND valid_until IS NOT NULL
                       AND valid_until < $2
                   RETURNING *;
                    """,
                    tenant_id, cutoff,
                )
                for r in rows[:limit]:
                    await conn.execute(
                        """
                        INSERT INTO consent_audit (consent_id, tenant_id, subject_id, purpose,
                                                   prev_status, new_status, change_kind, actor, reason, snapshot)
                        VALUES ($1,$2,$3,$4,$5,$6,'delete',NULL,'expired',$7)
                        """,
                        r["id"], r["tenant_id"], r["subject_id"], r["purpose"],
                        r["status"], r["status"],
                        json.dumps(dict(r), ensure_ascii=False),
                    )
                return min(len(rows), limit)
