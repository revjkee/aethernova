# -*- coding: utf-8 -*-
"""
Veilmind-core: Privacy Budget Repository (PostgreSQL, SQLAlchemy 2.x async)

Требования:
  - PostgreSQL 13+ (рекомендуется 14+), наличие схемы/таблиц из миграции 0002_privacy_budgets.sql
  - RLS по GUC: current_setting('app.tenant_id')
  - SQLAlchemy >= 2.0, asyncpg

Устанавливает tenant через `SET LOCAL app.tenant_id = :tenant_id` в каждой транзакции.
Поддерживает:
  * CRUD бюджета
  * keyset-пагинацию списка бюджетов
  * атомарное списание через privacy.consume_budget(...)
  * чтение леджера и витрины privacy.v_budget_usage
  * безопасные ретраи на serialization/deadlock

Пример инициализации:
    from sqlalchemy.ext.asyncio import create_async_engine
    engine = create_async_engine("postgresql+asyncpg://user:pass@host:5432/db", pool_size=10, max_overflow=20)
    repo = BudgetRepository(engine, default_tenant="tenant-1")

Автор: veilmind-core
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from ipaddress import ip_address
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

# -----------------------------
# Доменные типы/DTO/исключения
# -----------------------------

class SubjectKind(str, Enum):
    user = "user"
    dataset = "dataset"
    client = "client"
    service = "service"


ConsumeStatus = Literal["active", "exhausted", "paused", "not_found", "out_of_window"]


class BudgetError(Exception):
    """Базовая ошибка домена бюджетов."""


class BudgetNotFound(BudgetError):
    pass


class BudgetPaused(BudgetError):
    pass


class BudgetExhausted(BudgetError):
    pass


class BudgetOutOfWindow(BudgetError):
    pass


@dataclass(frozen=True)
class Budget:
    id: str
    tenant_id: str
    subject_kind: SubjectKind
    subject_id: str
    epsilon_total: float
    delta_total: float
    epsilon_spent: float
    delta_spent: float
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    rolling_window: Optional[str]  # interval -> текстовое представление, например "30 days"
    status: str
    soft_limit_ratio: float
    last_soft_alert_at: Optional[datetime]
    description: Optional[str]
    meta: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class LedgerEntry:
    id: str
    budget_id: str
    tenant_id: str
    ts: datetime
    epsilon_spent: float
    delta_spent: float
    purpose: str
    actor_id: Optional[str]
    request_id: Optional[str]
    trace_id: Optional[str]
    client_ip: Optional[str]
    meta: Dict[str, Any]


@dataclass(frozen=True)
class BudgetUsage:
    id: str
    tenant_id: str
    subject_kind: SubjectKind
    subject_id: str
    status: str
    epsilon_total: float
    epsilon_spent: float
    epsilon_remaining: float
    delta_total: float
    delta_spent: float
    delta_remaining: float
    eps_used_percent: float
    soft_limit_ratio: float
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    rolling_window: Optional[str]
    updated_at: datetime


@dataclass(frozen=True)
class ConsumeResult:
    ledger_id: Optional[str]
    status: ConsumeStatus


@dataclass(frozen=True)
class BudgetFilter:
    subject_kind: Optional[SubjectKind] = None
    subject_id: Optional[str] = None
    status: Optional[str] = None            # 'active' | 'paused' | 'exhausted'
    query: Optional[str] = None             # полнотекстовый фильтр по subject_id/description
    limit: int = 100
    page_token: Optional[str] = None        # keyset: base64url({"updated_at": iso, "id": uuid})


# -----------------------------
# Утилиты
# -----------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_budget(r: Any) -> Budget:
    return Budget(
        id=str(r.id),
        tenant_id=str(r.tenant_id),
        subject_kind=SubjectKind(str(r.subject_kind)),
        subject_id=str(r.subject_id),
        epsilon_total=float(r.epsilon_total),
        delta_total=float(r.delta_total),
        epsilon_spent=float(r.epsilon_spent),
        delta_spent=float(r.delta_spent),
        window_start=r.window_start,
        window_end=r.window_end,
        rolling_window=str(r.rolling_window) if r.rolling_window is not None else None,
        status=str(r.status),
        soft_limit_ratio=float(r.soft_limit_ratio),
        last_soft_alert_at=r.last_soft_alert_at,
        description=str(r.description) if r.description is not None else None,
        meta=dict(r.meta or {}),
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _row_to_ledger(r: Any) -> LedgerEntry:
    return LedgerEntry(
        id=str(r.id),
        budget_id=str(r.budget_id),
        tenant_id=str(r.tenant_id),
        ts=r.ts,
        epsilon_spent=float(r.epsilon_spent),
        delta_spent=float(r.delta_spent),
        purpose=str(r.purpose),
        actor_id=str(r.actor_id) if r.actor_id is not None else None,
        request_id=str(r.request_id) if r.request_id is not None else None,
        trace_id=str(r.trace_id) if r.trace_id is not None else None,
        client_ip=str(r.client_ip) if r.client_ip is not None else None,
        meta=dict(r.meta or {}),
    )


def _row_to_usage(r: Any) -> BudgetUsage:
    return BudgetUsage(
        id=str(r.id),
        tenant_id=str(r.tenant_id),
        subject_kind=SubjectKind(str(r.subject_kind)),
        subject_id=str(r.subject_id),
        status=str(r.status),
        epsilon_total=float(r.epsilon_total),
        epsilon_spent=float(r.epsilon_spent),
        epsilon_remaining=float(r.epsilon_remaining),
        delta_total=float(r.delta_total),
        delta_spent=float(r.delta_spent),
        delta_remaining=float(r.delta_remaining),
        eps_used_percent=float(r.eps_used_percent),
        soft_limit_ratio=float(r.soft_limit_ratio),
        window_start=r.window_start,
        window_end=r.window_end,
        rolling_window=str(r.rolling_window) if r.rolling_window is not None else None,
        updated_at=r.updated_at,
    )


def _encode_page(updated_at: datetime, id_: str) -> str:
    payload = {"updated_at": updated_at.isoformat(), "id": id_}
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def _decode_page(token: str) -> Tuple[datetime, str]:
    data = json.loads(base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8"))
    return datetime.fromisoformat(data["updated_at"]), str(data["id"])


# -----------------------------
# Репозиторий
# -----------------------------

class BudgetRepository:
    """
    Асинхронный репозиторий для privacy.budgets/ledger.

    Все методы требуют tenant_id: если не указан в вызове, берётся default_tenant.
    Для RLS используется `SET LOCAL app.tenant_id`.
    """

    def __init__(self, engine: AsyncEngine, default_tenant: Optional[str] = None) -> None:
        self.engine = engine
        self.default_tenant = default_tenant

    def bind_tenant(self, tenant_id: str) -> "BudgetRepository":
        """Возвращает новый репозиторий с предустановленным tenant_id."""
        return BudgetRepository(self.engine, tenant_id)

    # --------------------- CRUD бюджета ---------------------

    async def create_budget(
        self,
        *,
        tenant_id: Optional[str],
        subject_kind: SubjectKind,
        subject_id: str,
        epsilon_total: float,
        delta_total: float,
        rolling_window: Optional[str] = None,   # например "30 days"
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        soft_limit_ratio: float = 0.80,
        description: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Budget:
        tid = self._tenant_or_raise(tenant_id)
        q = text(
            """
            INSERT INTO privacy.budgets(
              tenant_id, subject_kind, subject_id,
              epsilon_total, delta_total,
              rolling_window, window_start, window_end,
              soft_limit_ratio, description, meta
            )
            VALUES (:tenant_id, :subject_kind, :subject_id,
                    :epsilon_total, :delta_total,
                    CAST(:rolling_window AS interval), :window_start, :window_end,
                    :soft_limit_ratio, :description, COALESCE(CAST(:meta AS jsonb), '{}'::jsonb))
            RETURNING *
            """
        )
        async with self.engine.begin() as conn:
            await self._set_tenant(conn, tid)
            r = await conn.execute(
                q,
                {
                    "tenant_id": tid,
                    "subject_kind": subject_kind.value,
                    "subject_id": subject_id,
                    "epsilon_total": epsilon_total,
                    "delta_total": delta_total,
                    "rolling_window": rolling_window,
                    "window_start": window_start,
                    "window_end": window_end,
                    "soft_limit_ratio": soft_limit_ratio,
                    "description": description,
                    "meta": json.dumps(meta or {}),
                },
            )
            row = r.fetchone()
            if not row:
                raise BudgetError("failed_to_create_budget")
            return _row_to_budget(row)

    async def get_budget(
        self,
        *,
        tenant_id: Optional[str],
        subject_kind: SubjectKind,
        subject_id: str,
    ) -> Budget:
        tid = self._tenant_or_raise(tenant_id)
        q = text(
            "SELECT * FROM privacy.budgets WHERE subject_kind=:sk AND subject_id=:sid LIMIT 1"
        )
        async with self.engine.begin() as conn:
            await self._set_tenant(conn, tid)
            r = await conn.execute(q, {"sk": subject_kind.value, "sid": subject_id})
            row = r.fetchone()
            if not row:
                raise BudgetNotFound(f"budget not found for {subject_kind.value}:{subject_id}")
            return _row_to_budget(row)

    async def update_budget(
        self,
        *,
        tenant_id: Optional[str],
        budget_id: str,
        status: Optional[str] = None,                 # 'active' | 'paused'
        soft_limit_ratio: Optional[float] = None,
        description: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        rolling_window: Optional[str] = None,
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
    ) -> Budget:
        tid = self._tenant_or_raise(tenant_id)
        # Строим динамический UPDATE
        sets = []
        params: Dict[str, Any] = {"id": budget_id}
        if status is not None:
            sets.append("status=:status")
            params["status"] = status
        if soft_limit_ratio is not None:
            sets.append("soft_limit_ratio=:soft_limit_ratio")
            params["soft_limit_ratio"] = soft_limit_ratio
        if description is not None:
            sets.append("description=:description")
            params["description"] = description
        if meta is not None:
            sets.append("meta=CAST(:meta AS jsonb)")
            params["meta"] = json.dumps(meta)
        if rolling_window is not None:
            sets.append("rolling_window=CAST(:rolling_window AS interval)")
            params["rolling_window"] = rolling_window
        if window_start is not None:
            sets.append("window_start=:window_start")
            params["window_start"] = window_start
        if window_end is not None:
            sets.append("window_end=:window_end")
            params["window_end"] = window_end

        if not sets:
            # Нечего обновлять — вернём как есть
            return await self.get_budget(tenant_id=tid, subject_kind=SubjectKind.user, subject_id="")  # unreachable

        q = text(f"UPDATE privacy.budgets SET {', '.join(sets)} WHERE id=:id RETURNING *")

        async with self.engine.begin() as conn:
            await self._set_tenant(conn, tid)
            r = await conn.execute(q, params)
            row = r.fetchone()
            if not row:
                raise BudgetNotFound(budget_id)
            return _row_to_budget(row)

    async def list_budgets(
        self,
        *,
        tenant_id: Optional[str],
        flt: Optional[BudgetFilter] = None,
    ) -> Tuple[List[Budget], Optional[str]]:
        tid = self._tenant_or_raise(tenant_id)
        flt = flt or BudgetFilter()
        where = ["TRUE"]
        params: Dict[str, Any] = {}
        if flt.subject_kind:
            where.append("subject_kind=:sk")
            params["sk"] = flt.subject_kind.value
        if flt.subject_id:
            where.append("subject_id=:sid")
            params["sid"] = flt.subject_id
        if flt.status:
            where.append("status=:st")
            params["st"] = flt.status
        if flt.query:
            where.append("(subject_id ILIKE :q OR description ILIKE :q)")
            params["q"] = f"%{flt.query}%"

        # keyset: updated_at DESC, id DESC
        after_sql = ""
        if flt.page_token:
            uat, bid = _decode_page(flt.page_token)
            after_sql = "AND (updated_at, id) < (:after_updated_at, :after_id)"
            params["after_updated_at"] = uat
            params["after_id"] = bid

        q = text(
            f"""
            SELECT * FROM privacy.budgets
            WHERE {' AND '.join(where)}
              {after_sql}
            ORDER BY updated_at DESC, id DESC
            LIMIT :lim
            """
        )
        params["lim"] = int(flt.limit)

        async with self.engine.begin() as conn:
            await self._set_tenant(conn, tid)
            r = await conn.execute(q, params)
            rows = r.fetchall()
            budgets = [_row_to_budget(x) for x in rows]
            next_token = None
            if budgets and len(budgets) == flt.limit:
                last = budgets[-1]
                next_token = _encode_page(last.updated_at, last.id)
            return budgets, next_token

    # --------------------- Леджер/витрина ---------------------

    async def list_ledger(
        self,
        *,
        tenant_id: Optional[str],
        budget_id: str,
        limit: int = 200,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        after_id: Optional[str] = None,  # для keyset (по (ts,id))
    ) -> List[LedgerEntry]:
        tid = self._tenant_or_raise(tenant_id)

        where = ["budget_id = :bid"]
        params: Dict[str, Any] = {"bid": budget_id}
        if since:
            where.append("ts >= :since")
            params["since"] = since
        if until:
            where.append("ts < :until")
            params["until"] = until
        if after_id:
            # Получим ts для after_id
            q_ts = text("SELECT ts FROM privacy.ledger WHERE id=:aid")
            async with self.engine.begin() as conn:
                await self._set_tenant(conn, tid)
                r = await conn.execute(q_ts, {"aid": after_id})
                row = r.fetchone()
                if row:
                    where.append("(ts, id) < (:ats, :aid)")
                    params["ats"] = row.ts
                    params["aid"] = after_id

        q = text(
            f"""
            SELECT * FROM privacy.ledger
            WHERE {' AND '.join(where)}
            ORDER BY ts DESC, id DESC
            LIMIT :lim
            """
        )
        params["lim"] = int(limit)

        async with self.engine.begin() as conn:
            await self._set_tenant(conn, tid)
            r = await conn.execute(q, params)
            return [_row_to_ledger(x) for x in r.fetchall()]

    async def get_usage(
        self,
        *,
        tenant_id: Optional[str],
        subject_kind: SubjectKind,
        subject_id: str,
    ) -> BudgetUsage:
        tid = self._tenant_or_raise(tenant_id)
        q = text(
            """
            SELECT * FROM privacy.v_budget_usage
            WHERE subject_kind=:sk AND subject_id=:sid
            LIMIT 1
            """
        )
        async with self.engine.begin() as conn:
            await self._set_tenant(conn, tid)
            r = await conn.execute(q, {"sk": subject_kind.value, "sid": subject_id})
            row = r.fetchone()
            if not row:
                raise BudgetNotFound(f"usage not found for {subject_kind.value}:{subject_id}")
            return _row_to_usage(row)

    # --------------------- Списание бюджета ---------------------

    async def consume(
        self,
        *,
        tenant_id: Optional[str],
        subject_kind: SubjectKind,
        subject_id: str,
        epsilon: float,
        delta: float,
        purpose: str,
        actor_id: Optional[str] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        raise_on_failure: bool = False,
        max_retries: int = 3,
        base_backoff: float = 0.05,
    ) -> ConsumeResult:
        """
        Атомарное списание через privacy.consume_budget(...).
        Возвращает статус и id записи леджера (если успешно).
        Опционально бросает исключения при статусах not_found/paused/exhausted/out_of_window.
        """
        tid = self._tenant_or_raise(tenant_id)

        # Валидация client_ip (если передан)
        if client_ip:
            try:
                ip_address(client_ip)
            except Exception:
                client_ip = None

        attempt = 0
        last_err: Optional[Exception] = None
        while attempt <= max_retries:
            try:
                async with self.engine.begin() as conn:
                    await self._set_tenant(conn, tid)
                    r = await conn.execute(
                        text(
                            """
                            SELECT * FROM privacy.consume_budget(
                              :tenant_id,
                              CAST(:subject_kind AS privacy.subject_kind),
                              :subject_id,
                              :epsilon, :delta,
                              :purpose, :actor_id, :request_id, :trace_id,
                              CAST(:client_ip AS inet),
                              CAST(:meta AS jsonb)
                            ) AS t(o_ledger_id uuid, o_status text)
                            """
                        ),
                        {
                            "tenant_id": tid,
                            "subject_kind": subject_kind.value,
                            "subject_id": subject_id,
                            "epsilon": epsilon,
                            "delta": delta,
                            "purpose": purpose,
                            "actor_id": actor_id,
                            "request_id": request_id,
                            "trace_id": trace_id,
                            "client_ip": client_ip,
                            "meta": json.dumps(meta or {}),
                        },
                    )
                    row = r.fetchone()
                    if not row:
                        # Неожиданно — функция должна вернуть запись всегда
                        return ConsumeResult(ledger_id=None, status="not_found")  # type: ignore

                    res = ConsumeResult(ledger_id=str(row.o_ledger_id) if row.o_ledger_id else None,
                                        status=str(row.o_status))  # type: ignore

                    if raise_on_failure:
                        self._raise_on_status(res)

                    return res
            except Exception as e:
                # Обработка транз. конфликтов: 40001 serialization failure / 40P01 deadlock_detected
                if _is_retryable_psql_error(e) and attempt < max_retries:
                    await asyncio.sleep(base_backoff * (2 ** attempt))
                    attempt += 1
                    last_err = e
                    continue
                raise
        # Если вышли по ретраям
        if last_err:
            raise last_err
        return ConsumeResult(ledger_id=None, status="not_found")  # type: ignore

    # --------------------- Вспомогательные ---------------------

    async def _set_tenant(self, conn: AsyncConnection, tenant_id: str) -> None:
        await conn.execute(text("SET LOCAL app.tenant_id = :tid"), {"tid": tenant_id})

    def _tenant_or_raise(self, tenant_id: Optional[str]) -> str:
        tid = tenant_id or self.default_tenant
        if not tid:
            raise BudgetError("tenant_id_required")
        return tid

    @staticmethod
    def _raise_on_status(res: ConsumeResult) -> None:
        st = res.status
        if st == "not_found":
            raise BudgetNotFound("budget not found")
        if st == "paused":
            raise BudgetPaused("budget paused")
        if st == "exhausted":
            raise BudgetExhausted("budget exhausted")
        if st == "out_of_window":
            raise BudgetOutOfWindow("outside of budget window")

# -----------------------------
# Диагностика retryable ошибок
# -----------------------------

def _is_retryable_psql_error(err: Exception) -> bool:
    """
    Пытается распознать retryable ошибки Postgres (по SQLSTATE в asyncpg/psycopg2).
    """
    # asyncpg.DatabaseError имеет атрибут .sqlstate
    code = getattr(err, "sqlstate", None) or getattr(getattr(err, "__cause__", None), "sqlstate", None)
    if code in ("40001", "40P01"):
        return True
    # SQLAlchemy DBAPIError -> .orig может нести sqlstate
    orig = getattr(err, "orig", None)
    if orig is not None:
        code = getattr(orig, "sqlstate", None) or getattr(getattr(orig, "__cause__", None), "sqlstate", None)
        if code in ("40001", "40P01"):
            return True
    # asyncpg может класть код в .code (str)
    code = getattr(err, "code", None)
    return code in ("40001", "40P01")

# -----------------------------
# (Необяз.) Пример использования
# -----------------------------

if __name__ == "__main__":
    # Демонстрация только для ручного запуска; в проде используйте DI/инициализацию приложения.
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine

    async def demo():
        engine = create_async_engine("postgresql+asyncpg://user:pass@localhost:5432/app", echo=False)
        repo = BudgetRepository(engine, default_tenant="demo-tenant")

        # Создание бюджета
        # budget = await repo.create_budget(
        #     tenant_id=None,
        #     subject_kind=SubjectKind.user,
        #     subject_id="alice",
        #     epsilon_total=10.0,
        #     delta_total=1e-6,
        #     rolling_window="30 days",
        #     description="Demo budget",
        # )
        # print(budget)

        # Списание
        # res = await repo.consume(
        #     tenant_id=None,
        #     subject_kind=SubjectKind.user,
        #     subject_id="alice",
        #     epsilon=0.1,
        #     delta=1e-7,
        #     purpose="analytics_query",
        #     request_id="req-123",
        #     raise_on_failure=True,
        # )
        # print(res)

    asyncio.run(demo())
