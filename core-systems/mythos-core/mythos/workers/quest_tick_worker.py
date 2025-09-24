# mythos-core/mythos/workers/quest_tick_worker.py
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import math
import os
import signal
import sys
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, AsyncIterator, Dict, List, Mapping, Optional, Sequence, Tuple

# ============================
# Конфигурация
# ============================

@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "")
    redis_url: Optional[str] = os.getenv("REDIS_URL")
    batch_size: int = int(os.getenv("WORKER_BATCH_SIZE", "500"))
    poll_interval_s: float = float(os.getenv("WORKER_POLL_INTERVAL", "1.0"))
    max_concurrency: int = int(os.getenv("WORKER_MAX_CONCURRENCY", "8"))
    backoff_min_s: float = float(os.getenv("WORKER_BACKOFF_MIN", "0.5"))
    backoff_max_s: float = float(os.getenv("WORKER_BACKOFF_MAX", "15"))
    skew_seconds: int = int(os.getenv("WORKER_EVENT_TIME_SKEW", "2"))
    metrics_enabled: bool = os.getenv("METRICS_ENABLED", "true").lower() == "true"
    offset_key: str = os.getenv("WORKER_OFFSET_KEY", "mythos:quest_tick_worker:offset")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")


# ============================
# Логирование
# ============================

def configure_logging(level: str) -> None:
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        stream=sys.stdout,
        format='{"ts":%(asctime)s,"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


logger = logging.getLogger("mythos.workers.quest_tick")


# ============================
# Метрики (опционально)
# ============================

class Metrics:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        try:
            if enabled:
                from prometheus_client import Counter, Histogram, Gauge  # type: ignore

                self.ev_processed = Counter("mythos_quest_worker_events_processed_total", "Events processed", ["kind", "result"])
                self.ev_latency = Histogram("mythos_quest_worker_event_latency_seconds", "Event age seconds")
                self.errors = Counter("mythos_quest_worker_errors_total", "Errors", ["where"])
                self.loop_sleep = Histogram("mythos_quest_worker_loop_sleep_seconds", "Loop sleep seconds")
                self.inflight = Gauge("mythos_quest_worker_inflight", "In-flight batches")
                self.batch_size = Histogram("mythos_quest_worker_batch_size", "Batch size", buckets=(1, 10, 50, 100, 250, 500, 1000, 2000))
            else:
                raise Exception("metrics disabled")
        except Exception:
            # no prometheus installed or disabled — no-op shims
            self.ev_processed = lambda *a, **k: type("X", (), {"inc": lambda *_: None})()  # type: ignore
            self.ev_latency = type("X", (), {"observe": lambda *_: None})()
            self.errors = lambda *a, **k: type("X", (), {"inc": lambda *_: None})()  # type: ignore
            self.loop_sleep = type("X", (), {"observe": lambda *_: None})()
            self.inflight = type("X", (), {"inc": lambda *_: None, "dec": lambda *_: None})()
            self.batch_size = type("X", (), {"observe": lambda *_: None})()


# ============================
# Смежные адаптеры: Redis offsets
# ============================

class OffsetStore:
    async def get(self) -> Optional[Tuple[str, int]]:
        """Вернет (event_date_iso, last_id) или None."""
        return None

    async def set(self, event_date_iso: str, last_id: int) -> None:
        pass

    async def is_processed_recently(self, event_date_iso: str, event_id: int) -> bool:
        return False

    async def mark_processed(self, event_date_iso: str, event_id: int, ttl_s: int = 3600) -> None:
        pass


class RedisOffsetStore(OffsetStore):
    def __init__(self, url: str, key: str) -> None:
        import redis.asyncio as redis  # type: ignore

        self._r = redis.from_url(url, decode_responses=True)
        self._key = key

    async def get(self) -> Optional[Tuple[str, int]]:
        data = await self._r.get(self._key)
        if not data:
            return None
        try:
            obj = json.loads(data)
            return (obj["date"], int(obj["id"]))
        except Exception:
            return None

    async def set(self, event_date_iso: str, last_id: int) -> None:
        payload = json.dumps({"date": event_date_iso, "id": last_id}, separators=(",", ":"))
        await self._r.set(self._key, payload)

    async def is_processed_recently(self, event_date_iso: str, event_id: int) -> bool:
        return bool(await self._r.sismember(f"{self._key}:dedup:{event_date_iso}", str(event_id)))

    async def mark_processed(self, event_date_iso: str, event_id: int, ttl_s: int = 3600) -> None:
        k = f"{self._key}:dedup:{event_date_iso}"
        await self._r.sadd(k, str(event_id))
        await self._r.expire(k, ttl_s)


class FileOffsetStore(OffsetStore):
    def __init__(self, path: str) -> None:
        self._path = path

    async def get(self) -> Optional[Tuple[str, int]]:
        if not os.path.exists(self._path):
            return None
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            return (obj["date"], int(obj["id"]))
        except Exception:
            return None

    async def set(self, event_date_iso: str, last_id: int) -> None:
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump({"date": event_date_iso, "id": last_id}, f, ensure_ascii=False)

    async def is_processed_recently(self, event_date_iso: str, event_id: int) -> bool:
        # файловый стор не хранит недавние id — считаем нет
        return False

    async def mark_processed(self, event_date_iso: str, event_id: int, ttl_s: int = 3600) -> None:
        return None


# ============================
# База данных: asyncpg (приоритет), fallback SQLAlchemy
# ============================

class DB:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._mode = "asyncpg"  # or "sqlalchemy"
        self._pool = None
        self._engine = None

    async def connect(self) -> None:
        try:
            import asyncpg  # type: ignore

            self._pool = await asyncpg.create_pool(dsn=self._dsn, min_size=1, max_size=10)
            self._mode = "asyncpg"
            logger.info("DB connected via asyncpg")
            return
        except Exception as e:
            logger.warning("asyncpg unavailable or failed: %s", e)

        try:
            from sqlalchemy.ext.asyncio import create_async_engine  # type: ignore

            self._engine = create_async_engine(self._dsn, pool_pre_ping=True)
            self._mode = "sqlalchemy"
            # probe
            async with self._engine.connect() as conn:
                await conn.execute("SELECT 1")  # type: ignore
            logger.info("DB connected via SQLAlchemy")
        except Exception as e:
            logger.error("DB connection failed: %s", e)
            raise

    async def close(self) -> None:
        if self._mode == "asyncpg" and self._pool:
            await self._pool.close()
        elif self._mode == "sqlalchemy" and self._engine:
            await self._engine.dispose()

    async def fetch_events_batch(
        self,
        after_date: Optional[str],
        after_id: Optional[int],
        limit: int,
        skew_seconds: int,
    ) -> List[Mapping[str, Any]]:
        """
        Возвращает упорядоченный батч событий, смещенный на skew_seconds в прошлое
        (чтобы исключить гонки часов).
        """
        skew_sql = f"(now() - interval '{int(skew_seconds)} seconds')"
        # Логика курсора: (event_date, id)
        cond = []
        params: List[Any] = []
        if after_date is not None and after_id is not None:
            cond.append("(event_date > $1 OR (event_date = $1 AND id > $2))")
            params.extend([after_date, after_id])
        else:
            cond.append("true")

        sql = f"""
        SELECT id, event_date, event_time, user_id, quest_key, quest_version_id, kind::text AS kind, payload
        FROM mythos.user_quest_events
        WHERE { ' AND '.join(cond) } AND event_time <= {skew_sql}
        ORDER BY event_date ASC, id ASC
        LIMIT {int(limit)}
        """

        if self._mode == "asyncpg":
            async with self._pool.acquire() as conn:  # type: ignore
                rows = await conn.fetch(sql, *params)
                return [dict(r) for r in rows]
        else:
            # SQLAlchemy text + bindparams
            from sqlalchemy import text  # type: ignore

            async with self._engine.connect() as conn:  # type: ignore
                res = await conn.execute(text(sql), params)
                cols = res.keys()
                return [dict(zip(cols, r)) for r in res.fetchall()]

    async def run_tx(self, fn) -> Any:
        if self._mode == "asyncpg":
            async with self._pool.acquire() as conn:  # type: ignore
                async with conn.transaction():
                    return await fn(AsyncPGConn(conn))
        else:
            from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
            from sqlalchemy.orm import sessionmaker  # type: ignore

            Session = sessionmaker(self._engine, expire_on_commit=False, class_=AsyncSession)  # type: ignore
            async with Session() as session:
                async with session.begin():
                    return await fn(SAConn(session))


class AsyncPGConn:
    def __init__(self, conn) -> None:
        self.conn = conn

    async def execute(self, sql: str, *args) -> None:
        await self.conn.execute(sql, *args)

    async def fetch(self, sql: str, *args) -> List[Mapping[str, Any]]:
        rows = await self.conn.fetch(sql, *args)
        return [dict(r) for r in rows]

    async def fetchrow(self, sql: str, *args) -> Optional[Mapping[str, Any]]:
        r = await self.conn.fetchrow(sql, *args)
        return dict(r) if r else None


class SAConn:
    def __init__(self, session) -> None:
        self.session = session

    async def execute(self, sql: str, *args) -> None:
        from sqlalchemy import text  # type: ignore

        await self.session.execute(text(sql), args)

    async def fetch(self, sql: str, *args) -> List[Mapping[str, Any]]:
        from sqlalchemy import text  # type: ignore

        res = await self.session.execute(text(sql), args)
        cols = res.keys()
        return [dict(zip(cols, r)) for r in res.fetchall()]

    async def fetchrow(self, sql: str, *args) -> Optional[Mapping[str, Any]]:
        rows = await self.fetch(sql, *args)
        return rows[0] if rows else None


# ============================
# Модель события (легкая)
# ============================

@dataclasses.dataclass
class Event:
    id: int
    event_date: str  # YYYY-MM-DD
    event_time: str
    user_id: str
    quest_key: str
    quest_version_id: str
    kind: str
    payload: Dict[str, Any]


# ============================
# Обработчик бизнес-логики
# ============================

class QuestEventProcessor:
    """
    Содержит чистую логику применения событий в рамках одной транзакции.
    """

    def __init__(self, db: DB, metrics: Metrics):
        self.db = db
        self.m = metrics

    async def process_batch(self, events: Sequence[Event]) -> None:
        if not events:
            return

        async def _tx(conn):
            # Группировка по пользователю для минимизации блокировок
            for ev in events:
                await self._apply_event(conn, ev)
        await self.db.run_tx(_tx)

    async def _apply_event(self, conn, ev: Event) -> None:
        # унифицированно обновляем last_event_at у user_quests при наличии записи
        await conn.execute(
            """
            UPDATE mythos.user_quests
               SET last_event_at = GREATEST(COALESCE(last_event_at, 'epoch'), $1)
             WHERE user_id = $2 AND quest_key = $3 AND quest_version_id = $4
            """,
            ev.event_time, ev.user_id, ev.quest_key, ev.quest_version_id,
        )

        kind = ev.kind
        age_s = max(0.0, time.time() - _parse_ts(ev.event_time))
        try:
            self.m.ev_latency.observe(age_s)  # type: ignore
        except Exception:
            pass

        if kind == "started":
            await self._on_started(conn, ev)
            self.m.ev_processed.labels(kind="started", result="ok").inc()  # type: ignore
        elif kind == "progressed":
            await self._on_progressed(conn, ev)
            self.m.ev_processed.labels(kind="progressed", result="ok").inc()  # type: ignore
        elif kind == "completed":
            await self._on_completed(conn, ev)
            self.m.ev_processed.labels(kind="completed", result="ok").inc()  # type: ignore
        elif kind == "failed":
            await self._on_failed(conn, ev)
            self.m.ev_processed.labels(kind="failed", result="ok").inc()  # type: ignore
        elif kind == "claimed":
            # Обычно выдача награды идет в completed; claimed — можно использовать как маркер UI.
            await self._on_claimed(conn, ev)
            self.m.ev_processed.labels(kind="claimed", result="ok").inc()  # type: ignore
        else:
            logger.debug("Unknown event kind: %s", kind)
            self.m.ev_processed.labels(kind="unknown", result="skip").inc()  # type: ignore

    async def _ensure_user_quest_row(self, conn, ev: Event) -> None:
        # Создать запись user_quests при необходимости
        await conn.execute(
            """
            INSERT INTO mythos.user_quests (user_id, quest_key, quest_version_id, state, started_at)
            VALUES ($1, $2, $3, 'active', $4)
            ON CONFLICT (user_id, quest_key, quest_version_id) DO NOTHING
            """,
            ev.user_id, ev.quest_key, ev.quest_version_id, ev.event_time,
        )

    async def _on_started(self, conn, ev: Event) -> None:
        await self._ensure_user_quest_row(conn, ev)

    async def _on_progressed(self, conn, ev: Event) -> None:
        await self._ensure_user_quest_row(conn, ev)
        # Ожидаем, что payload содержит objective_id и delta
        obj_id = (ev.payload or {}).get("objective_id")
        delta = (ev.payload or {}).get("delta", 0)
        try:
            delta = Decimal(str(delta))
        except Exception:
            delta = Decimal("0")
        if not obj_id or delta == 0:
            return

        # UPSERT прогресса
        await conn.execute(
            """
            INSERT INTO mythos.user_objective_progress (user_id, quest_key, quest_version_id, objective_id, progress_numeric, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, quest_version_id, objective_id)
            DO UPDATE SET progress_numeric = mythos.user_objective_progress.progress_numeric + EXCLUDED.progress_numeric,
                          updated_at = EXCLUDED.updated_at
            """,
            ev.user_id, ev.quest_key, ev.quest_version_id, obj_id, delta, ev.event_time,
        )

        # Проверка достижения целей этой версии
        await self._check_and_complete_if_ready(conn, ev)

    async def _on_completed(self, conn, ev: Event) -> None:
        await self._ensure_user_quest_row(conn, ev)
        await self._mark_completed_and_reward(conn, ev, idempotency_suffix=f"evt:{ev.event_date}:{ev.id}")

    async def _on_failed(self, conn, ev: Event) -> None:
        await self._ensure_user_quest_row(conn, ev)
        await conn.execute(
            """
            UPDATE mythos.user_quests
               SET state = 'failed'
             WHERE user_id = $1 AND quest_key = $2 AND quest_version_id = $3
            """,
            ev.user_id, ev.quest_key, ev.quest_version_id,
        )

    async def _on_claimed(self, conn, ev: Event) -> None:
        # помечаем как completed если еще не
        await self._on_completed(conn, ev)

    async def _check_and_complete_if_ready(self, conn, ev: Event) -> None:
        # Получить цели и сверить прогресс
        objs = await conn.fetch(
            """
            SELECT o.id, o.target_numeric
              FROM mythos.quest_objectives o
             WHERE o.quest_version_id = $1
            """,
            ev.quest_version_id,
        )
        if not objs:
            return

        # Прогресс пользователя по всем целям
        prog = await conn.fetch(
            """
            SELECT objective_id, progress_numeric
              FROM mythos.user_objective_progress
             WHERE user_id = $1 AND quest_version_id = $2
            """,
            ev.user_id, ev.quest_version_id,
        )
        prog_map = {p["objective_id"]: Decimal(str(p["progress_numeric"])) for p in prog}

        ready = True
        for o in objs:
            oid = o["id"]
            target = Decimal(str(o["target_numeric"] or 0))
            if prog_map.get(oid, Decimal("0")) < target:
                ready = False
                break

        if ready:
            await self._mark_completed_and_reward(conn, ev, idempotency_suffix=f"auto:{ev.event_date}:{ev.id}")

    async def _mark_completed_and_reward(self, conn, ev: Event, idempotency_suffix: str) -> None:
        # Обновить состояние
        await conn.execute(
            """
            UPDATE mythos.user_quests
               SET state = 'completed', completed_at = COALESCE(completed_at, $1)
             WHERE user_id = $2 AND quest_key = $3 AND quest_version_id = $4
            """,
            ev.event_time, ev.user_id, ev.quest_key, ev.quest_version_id,
        )

        # Выдать награды (если определены в версии)
        # Достаем rewards из quest_versions.rewards (jsonb) — структура произвольная, ожидаем поля: currency[], xp, items[]
        qv = await conn.fetchrow(
            "SELECT rewards FROM mythos.quest_versions WHERE id = $1",
            ev.quest_version_id,
        )
        if not qv or not qv.get("rewards"):
            return
        rewards = qv["rewards"] or {}

        # Формируем записи в reward_ledger с идемпотентностью
        idk_base = f"complete:{ev.quest_version_id}:{idempotency_suffix}"

        # Валюта
        for r in (rewards.get("currency") or []):
            code = str(r.get("code", "GOLD"))
            amt = Decimal(str(r.get("amount", 0)))
            if amt == 0:
                continue
            await self._insert_reward(
                conn,
                user_id=ev.user_id,
                quest_key=ev.quest_key,
                quest_version_id=ev.quest_version_id,
                kind="currency",
                currency_code=code,
                amount=amt,
                idempotency_key=f"{idk_base}:cur:{code}:{amt}",
                meta={"event_id": ev.id, "event_date": ev.event_date},
            )

        # XP
        xp = int(rewards.get("xp") or 0)
        if xp > 0:
            await self._insert_reward(
                conn,
                user_id=ev.user_id,
                quest_key=ev.quest_key,
                quest_version_id=ev.quest_version_id,
                kind="xp",
                xp_amount=xp,
                idempotency_key=f"{idk_base}:xp:{xp}",
                meta={"event_id": ev.id, "event_date": ev.event_date},
            )

        # Items
        for it in (rewards.get("items") or []):
            item_id = str(it.get("id"))
            qty = int(it.get("qty", 1))
            if not item_id or qty <= 0:
                continue
            await self._insert_reward(
                conn,
                user_id=ev.user_id,
                quest_key=ev.quest_key,
                quest_version_id=ev.quest_version_id,
                kind="item",
                item_id=item_id,
                item_qty=qty,
                idempotency_key=f"{idk_base}:item:{item_id}:{qty}",
                meta={"event_id": ev.id, "event_date": ev.event_date},
            )

        # Счетчики завершений
        await conn.execute(
            """
            UPDATE mythos.user_quests
               SET daily_count = daily_count + 1,
                   weekly_count = weekly_count + 1,
                   lifetime_count = lifetime_count + 1
             WHERE user_id = $1 AND quest_key = $2 AND quest_version_id = $3
            """,
            ev.user_id, ev.quest_key, ev.quest_version_id,
        )

    async def _insert_reward(
        self,
        conn,
        *,
        user_id: str,
        quest_key: str,
        quest_version_id: str,
        kind: str,
        currency_code: Optional[str] = None,
        amount: Optional[Decimal] = None,
        xp_amount: Optional[int] = None,
        item_id: Optional[str] = None,
        item_qty: Optional[int] = None,
        idempotency_key: str,
        meta: Optional[Mapping[str, Any]] = None,
    ) -> None:
        await conn.execute(
            """
            INSERT INTO mythos.reward_ledger
                (user_id, quest_key, quest_version_id, kind, currency_code, amount, xp_amount, item_id, item_qty, meta, idempotency_key)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            ON CONFLICT (user_id, idempotency_key) DO NOTHING
            """,
            user_id, quest_key, quest_version_id, kind, currency_code, amount, xp_amount, item_id, item_qty, json.dumps(meta or {}), idempotency_key,
        )


# ============================
# Утилита времени
# ============================

def _parse_ts(ts: str) -> float:
    # Простой парсер RFC3339 для оценки возраста события
    try:
        from datetime import datetime
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return time.time()


# ============================
# Воркер
# ============================

class QuestTickWorker:
    def __init__(self, settings: Settings):
        self.s = settings
        self.metrics = Metrics(settings.metrics_enabled)
        self.db = DB(settings.database_url)
        self.offsets: OffsetStore
        if self.s.redis_url:
            try:
                self.offsets = RedisOffsetStore(self.s.redis_url, self.s.offset_key)
            except Exception as e:
                logger.warning("RedisOffsetStore init failed: %s; fallback to file", e)
                self.offsets = FileOffsetStore(f"/tmp/{self.s.offset_key.replace(':','_')}.json")
        else:
            self.offsets = FileOffsetStore(f"/tmp/{self.s.offset_key.replace(':','_')}.json")
        self.proc = QuestEventProcessor(self.db, self.metrics)
        self._stop = asyncio.Event()

    async def start(self) -> None:
        await self.db.connect()
        # graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)
        await self._run_loop()

    async def _run_loop(self) -> None:
        backoff = self.s.backoff_min_s
        try:
            while not self._stop.is_set():
                processed = await self._tick_once()
                if processed == 0:
                    # нет новых событий — спим с backoff
                    self.metrics.loop_sleep.observe(backoff)  # type: ignore
                    await asyncio.wait([self._stop.wait()], timeout=backoff)
                    backoff = min(self.s.backoff_max_s, max(self.s.backoff_min_s, backoff * 1.5))
                else:
                    backoff = self.s.backoff_min_s
        finally:
            await self.db.close()

    async def _tick_once(self) -> int:
        # 1) Загрузить курсор
        cur = await self.offsets.get()
        after_date, after_id = (cur[0], cur[1]) if cur else (None, None)

        # 2) Прочитать батч событий
        rows = await self.db.fetch_events_batch(after_date, after_id, self.s.batch_size, self.s.skew_seconds)
        if not rows:
            return 0

        self.metrics.batch_size.observe(len(rows))  # type: ignore

        # 3) Преобразовать в Event и отфильтровать уже обработанные (быстрый дедуп)
        events: List[Event] = []
        for r in rows:
            ev = Event(
                id=int(r["id"]),
                event_date=str(r["event_date"]),
                event_time=r["event_time"].isoformat() if hasattr(r["event_time"], "isoformat") else str(r["event_time"]),
                user_id=str(r["user_id"]),
                quest_key=str(r["quest_key"]),
                quest_version_id=str(r["quest_version_id"]),
                kind=str(r["kind"]),
                payload=r.get("payload") or {},
            )
            # быстрый недавний дедуп (если Redis)
            if await self.offsets.is_processed_recently(ev.event_date, ev.id):
                continue
            events.append(ev)

        if not events:
            # сдвигаем курсор все равно (на последний raw)
            last = rows[-1]
            await self.offsets.set(str(last["event_date"]), int(last["id"]))
            return 0

        # 4) Обработка в транзакции (по месту — внутри процессора)
        try:
            self.metrics.inflight.inc()  # type: ignore
            await self.proc.process_batch(events)
        except Exception as e:
            logger.exception("Batch processing failed: %s", e)
            self.metrics.errors(where="process_batch").inc()  # type: ignore
            # частичный фейл — не двигаем курсор, дадим переиграть
            await asyncio.sleep(min(self.s.backoff_max_s, self.s.backoff_min_s * 2))
            return 0
        finally:
            self.metrics.inflight.dec()  # type: ignore

        # 5) Отметить обработанными и сдвинуть курсор
        last_ev = events[-1]
        await self.offsets.set(last_ev.event_date, last_ev.id)
        for ev in events:
            await self.offsets.mark_processed(ev.event_date, ev.id, ttl_s=3600)

        return len(events)


# ============================
# Точка входа
# ============================

async def _amain() -> None:
    s = Settings()
    if not s.database_url:
        logger.error("DATABASE_URL is required")
        sys.exit(2)
    configure_logging(s.log_level)
    worker = QuestTickWorker(s)
    await worker.start()


def main() -> None:
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
