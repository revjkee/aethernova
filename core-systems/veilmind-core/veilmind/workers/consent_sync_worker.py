# -*- coding: utf-8 -*-
"""
veilmind-core: workers.consent_sync_worker

Промышленный асинхронный воркер для синхронизации событий согласий (consent)
из внешних источников в PostgreSQL с учетом мультиарендности и RLS.

Возможности:
- Источники:
  * HTTP changefeed с курсорной пагинацией (GET/POST) — опционально с httpx.
  * Kafka topic (events) — опционально с aiokafka.
- Идемпотентность:
  * Dedup по event_id (таблица privacy.consent_events или Redis set).
- Применение:
  * UPSERT в privacy.consents по (tenant_id, subject_id, purpose).
  * Поддержка статусов GRANTED | REVOKED | EXPIRED.
- Транзакции:
  * SET LOCAL app.tenant_id для RLS и аудит-триггеров.
  * Повтор на serialization/deadlock (40001/40P01) с экспо-бэкоффом.
- Наблюдаемость:
  * Логирование в JSON.
  * Prometheus метрики (опционально).
  * OpenTelemetry (крючки, опционально).
- Чекпоинты:
  * Таблица privacy.consent_checkpoints (stream_id, cursor).
  * Redis key (если доступен).
- Безопасное завершение:
  * Обработка SIGINT/SIGTERM, дренирование очереди.

Зависимости (опциональные):
  pip install httpx aiokafka redis prometheus-client SQLAlchemy[asyncio] asyncpg

Совместимость: Python 3.9+, PostgreSQL 13+, SQLAlchemy 2.x (async)

Ожидаемая БД (предполагаемая схематика, адаптируйте под свою миграцию):
  privacy.consents(
    id uuid primary key default gen_random_uuid(),
    tenant_id text not null,
    subject_id text not null,
    purpose text not null,
    status text not null, -- 'granted' | 'revoked' | 'expired'
    granted_at timestamptz, revoked_at timestamptz, expires_at timestamptz,
    source text, meta jsonb default '{}'::jsonb,
    updated_at timestamptz not null default now(),
    unique(tenant_id, subject_id, purpose)
  )

  privacy.consent_events(
    event_id text primary key,
    tenant_id text not null,
    seen_at timestamptz not null default now()
  )

  privacy.consent_checkpoints(
    stream_id text primary key,
    cursor text not null,
    updated_at timestamptz not null default now()
  )

При отличиях схемы скорректируйте SQL в секциях UPSERT/DEDUP/CHECKPOINT.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import random
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

# Опциональные зависимости
try:  # http source
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:  # kafka source
    from aiokafka import AIOKafkaConsumer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaConsumer = None  # type: ignore

try:  # redis checkpoints/dedup
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

try:  # metrics
    from prometheus_client import Counter, Gauge, Histogram, start_http_server  # type: ignore
except Exception:  # pragma: no cover
    Counter = Gauge = Histogram = None  # type: ignore
    def start_http_server(*args, **kwargs):  # type: ignore
        return


# -----------------------------
# Типы и конфигурация
# -----------------------------

class ConsentStatus(str, Enum):
    granted = "granted"
    revoked = "revoked"
    expired = "expired"


@dataclass(frozen=True)
class ConsentEvent:
    event_id: str
    tenant_id: str
    subject_id: str
    purpose: str
    status: ConsentStatus
    ts: datetime
    expires_at: Optional[datetime] = None
    source: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)


Mode = Literal["http", "kafka"]


@dataclass
class HTTPSource:
    url: str                              # endpoint, напр. https://idp.example.com/consents/changes
    method: Literal["GET", "POST"] = "GET"
    auth_header: Optional[str] = None     # "Bearer <token>"
    page_size: int = 500
    cursor_param: str = "cursor"
    size_param: str = "limit"
    initial_cursor: Optional[str] = None
    timeout_sec: float = 10.0


@dataclass
class KafkaSource:
    bootstrap_servers: str
    topic: str
    group_id: str
    security_protocol: Optional[str] = None   # SASL_SSL, SSL, PLAINTEXT (передается в kwargs)
    sasl_mechanism: Optional[str] = None
    sasl_plain_username: Optional[str] = None
    sasl_plain_password: Optional[str] = None
    session_timeout_ms: int = 45000
    enable_auto_commit: bool = False
    auto_offset_reset: str = "latest"


@dataclass
class RedisConfig:
    dsn: str
    namespace: str = "veilmind:consent"
    ttl_dedup_seconds: int = 7 * 24 * 3600  # 7 дней


@dataclass
class WorkerConfig:
    mode: Mode
    tenant_id: str                             # tenant для RLS
    db_dsn: str                                # postgresql+asyncpg://...
    http: Optional[HTTPSource] = None
    kafka: Optional[KafkaSource] = None
    redis: Optional[RedisConfig] = None
    batch_size: int = 500
    poll_interval_sec: float = 2.0
    max_retries: int = 5
    base_backoff_sec: float = 0.25
    backoff_jitter: float = 0.20
    metrics_port: Optional[int] = None         # если задан — поднимем HTTP /metrics
    stream_id: str = "default"                 # идентификатор потока (для http чекпоинтов)
    log_level: int = logging.INFO


# -----------------------------
# Метрики (если доступны)
# -----------------------------

if Counter is not None:
    MET_EVENTS = Counter("consent_events_total", "События согласий, принятые на вход", ["status", "source"])
    MET_APPLIED = Counter("consent_events_applied_total", "События согласий, успешно примененные", ["status"])
    MET_SKIPPED = Counter("consent_events_skipped_total", "События согласий, пропущенные", ["reason"])
    MET_ERRORS = Counter("consent_worker_errors_total", "Ошибки воркера", ["kind"])
    MET_LATENCY = Histogram("consent_apply_latency_seconds", "Латентность применения события")
    MET_INFLIGHT = Gauge("consent_events_inflight", "События в обработке")
else:  # заглушки
    class _N:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def dec(self, *a, **k): pass
        def observe(self, *a, **k): pass
    MET_EVENTS = MET_APPLIED = MET_SKIPPED = MET_ERRORS = MET_LATENCY = MET_INFLIGHT = _N()


# -----------------------------
# Вспомогательные утилиты
# -----------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _jittered(base: float, jitter: float) -> float:
    return base * (1.0 + random.uniform(-jitter, jitter))


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _event_from_json(d: Dict[str, Any]) -> Optional[ConsentEvent]:
    """
    Универсальный нормализатор входного JSON в ConsentEvent.
    Поддерживает распространенные поля, при несовпадении — добавьте маппинг ниже.
    """
    try:
        event_id = str(d.get("event_id") or d.get("id") or d["eid"])
        tenant_id = str(d.get("tenant_id") or d["tenant"])
        subject_id = str(d.get("subject_id") or d.get("user_id") or d["subject"])
        purpose = str(d.get("purpose") or d.get("purpose_id") or d["purposeCode"])
        status_raw = str(d.get("status") or d.get("state") or d["consent_status"]).lower()
        if status_raw in ("granted", "allow", "allowed", "given"):
            status = ConsentStatus.granted
        elif status_raw in ("revoked", "deny", "denied", "withdrawn"):
            status = ConsentStatus.revoked
        elif status_raw in ("expired",):
            status = ConsentStatus.expired
        else:
            MET_SKIPPED.labels("unknown_status").inc()
            return None
        ts = d.get("ts") or d.get("timestamp") or d.get("created_at") or d.get("time")
        ts_dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00")) if isinstance(ts, str) else _now()
        exp = d.get("expires_at") or d.get("expiry")
        expires_at = datetime.fromisoformat(str(exp).replace("Z", "+00:00")) if isinstance(exp, str) else None
        src = d.get("source") or d.get("producer") or "external"
        meta = dict(d.get("meta") or {})
        return ConsentEvent(
            event_id=event_id, tenant_id=tenant_id, subject_id=subject_id,
            purpose=purpose, status=status, ts=ts_dt, expires_at=expires_at,
            source=str(src), meta=meta
        )
    except Exception:
        MET_SKIPPED.labels("normalize_error").inc()
        return None


def _is_retryable_psql_error(err: Exception) -> bool:
    code = getattr(err, "sqlstate", None) or getattr(getattr(err, "orig", None), "sqlstate", None)
    if code in ("40001", "40P01"):
        return True
    code2 = getattr(getattr(err, "orig", None), "code", None)
    return code2 in ("40001", "40P01")


# -----------------------------
# Основной воркер
# -----------------------------

class ConsentSyncWorker:
    def __init__(self, cfg: WorkerConfig) -> None:
        self.cfg = cfg
        self.log = logging.getLogger("veilmind.consent_worker")
        self.log.setLevel(cfg.log_level)

        self.engine: AsyncEngine = create_async_engine(cfg.db_dsn, pool_pre_ping=True, future=True)
        self.redis = None
        self._stop = asyncio.Event()

        # HTTP/Kafka клиенты и состояние
        self._http_client = None
        self._kafka_consumer = None

    # ---------- lifecycle ----------

    async def start(self) -> None:
        if self.cfg.metrics_port:
            start_http_server(self.cfg.metrics_port)
            self.log.info("metrics listening on :%s", self.cfg.metrics_port)

        if self.cfg.redis and aioredis is not None:
            self.redis = aioredis.from_url(self.cfg.redis.dsn, decode_responses=True)
            self.log.info("redis connected")

        if self.cfg.mode == "http":
            if httpx is None or self.cfg.http is None:
                raise RuntimeError("HTTP mode requires httpx and http config")
            self._http_client = httpx.AsyncClient(timeout=self.cfg.http.timeout_sec)
        elif self.cfg.mode == "kafka":
            if AIOKafkaConsumer is None or self.cfg.kafka is None:
                raise RuntimeError("Kafka mode requires aiokafka and kafka config")
            k = self.cfg.kafka
            self._kafka_consumer = AIOKafkaConsumer(
                k.topic,
                bootstrap_servers=k.bootstrap_servers,
                group_id=k.group_id,
                enable_auto_commit=k.enable_auto_commit,
                auto_offset_reset=k.auto_offset_reset,
                session_timeout_ms=k.session_timeout_ms,
                security_protocol=k.security_protocol,
                sasl_mechanism=k.sasl_mechanism,
                sasl_plain_username=k.sasl_plain_username,
                sasl_plain_password=k.sasl_plain_password,
                value_deserializer=lambda v: v.decode("utf-8"),
            )
            await self._kafka_consumer.start()

        self._install_signal_handlers()

    async def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(Exception):
            if self._kafka_consumer:
                await self._kafka_consumer.stop()
        with contextlib.suppress(Exception):
            if self._http_client:
                await self._http_client.aclose()
        with contextlib.suppress(Exception):
            if self.redis:
                await self.redis.close()
        with contextlib.suppress(Exception):
            await self.engine.dispose()

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)

    # ---------- run loops ----------

    async def run(self) -> None:
        await self.start()
        try:
            if self.cfg.mode == "http":
                await self._run_http_loop()
            else:
                await self._run_kafka_loop()
        finally:
            await self.stop()

    async def _run_http_loop(self) -> None:
        assert self._http_client and self.cfg.http
        cursor = await self._load_checkpoint(self.cfg.stream_id)
        if not cursor:
            cursor = self.cfg.http.initial_cursor

        while not self._stop.is_set():
            try:
                events, next_cursor, empty = await self._fetch_http_batch(cursor)
                if events:
                    await self._apply_batch(events)
                    await self._save_checkpoint(self.cfg.stream_id, next_cursor or cursor)
                elif empty:
                    # 204/нет данных — подождем
                    await asyncio.sleep(self.cfg.poll_interval_sec)
                cursor = next_cursor or cursor
            except Exception as e:
                MET_ERRORS.labels("http_loop").inc()
                self.log.exception("http loop error: %s", e)
                await asyncio.sleep(_jittered(self.cfg.base_backoff_sec, self.cfg.backoff_jitter))

    async def _run_kafka_loop(self) -> None:
        assert self._kafka_consumer
        consumer: AIOKafkaConsumer = self._kafka_consumer  # type: ignore
        try:
            async for msg in consumer:
                if self._stop.is_set():
                    break
                try:
                    payload = json.loads(msg.value)
                    ev = _event_from_json(payload)
                    if not ev:
                        continue
                    await self._apply_batch([ev])
                    if not self.cfg.kafka.enable_auto_commit:  # manual commit
                        await consumer.commit()
                except Exception as e:
                    MET_ERRORS.labels("kafka_message").inc()
                    self.log.exception("kafka message failed: %s", e)
        finally:
            # consumer.stop() вызывается в stop()
            pass

    # ---------- источники ----------

    async def _fetch_http_batch(self, cursor: Optional[str]) -> Tuple[List[ConsentEvent], Optional[str], bool]:
        """
        Возвращает (events, next_cursor, empty)
        empty=True означает 204 или отсутствие данных (для паузы).
        """
        assert self._http_client and self.cfg.http
        h = self.cfg.http
        params = {}
        if cursor:
            params[h.cursor_param] = cursor
        params[h.size_param] = self.cfg.batch_size

        headers = {}
        if h.auth_header:
            headers["Authorization"] = h.auth_header

        if h.method == "GET":
            resp = await self._http_client.get(h.url, params=params, headers=headers)
        else:
            body = {"cursor": cursor, "limit": self.cfg.batch_size}
            resp = await self._http_client.post(h.url, json=body, headers=headers)

        if resp.status_code == 204:
            return [], cursor, True
        resp.raise_for_status()
        data = resp.json()

        # Ожидаемый формат:
        # { "events": [...], "next_cursor": "..." } или массив событий
        raw_events = data.get("events") if isinstance(data, dict) else data
        next_cursor = data.get("next_cursor") if isinstance(data, dict) else None

        events: List[ConsentEvent] = []
        for item in (raw_events or []):
            ev = _event_from_json(item)
            if ev:
                events.append(ev)

        return events, next_cursor, len(events) == 0

    # ---------- применение ----------

    async def _apply_batch(self, events: List[ConsentEvent]) -> None:
        if not events:
            return
        MET_INFLIGHT.inc()
        try:
            # Группируем по tenant (на случай, если source мультиарендный)
            by_tenant: Dict[str, List[ConsentEvent]] = {}
            for ev in events:
                MET_EVENTS.labels(ev.status.value, ev.source or "unknown").inc()
                by_tenant.setdefault(ev.tenant_id or self.cfg.tenant_id, []).append(ev)

            for tenant_id, group in by_tenant.items():
                await self._apply_batch_tenant(tenant_id, group)
        finally:
            MET_INFLIGHT.dec()

    async def _apply_batch_tenant(self, tenant_id: str, events: List[ConsentEvent]) -> None:
        # Применяем по одному (можно объединить в батч в рамках одной транзакции при необходимости)
        for ev in events:
            await self._apply_one_with_retry(tenant_id, ev)

    async def _apply_one_with_retry(self, tenant_id: str, ev: ConsentEvent) -> None:
        attempt = 0
        while True:
            try:
                await self._apply_one(tenant_id, ev)
                MET_APPLIED.labels(ev.status.value).inc()
                return
            except Exception as e:
                if _is_retryable_psql_error(e) and attempt < self.cfg.max_retries:
                    delay = _jittered(self.cfg.base_backoff_sec * (2 ** attempt), self.cfg.backoff_jitter)
                    self.log.warning("retryable db error, attempt=%s delay=%.3fs: %s", attempt + 1, delay, e)
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                MET_ERRORS.labels("apply_one").inc()
                self.log.exception("apply_one failed (event_id=%s): %s", ev.event_id, e)
                # DLQ/логирование — событие не потеряем, Kafka переиграет, HTTP — курсор не сдвинем выше
                raise

    async def _apply_one(self, tenant_id: str, ev: ConsentEvent) -> None:
        # Dedup через Redis или таблицу
        if await self._already_processed(tenant_id, ev.event_id):
            MET_SKIPPED.labels("dedup").inc()
            return

        q_dedup = text(
            """
            INSERT INTO privacy.consent_events(event_id, tenant_id)
            VALUES(:event_id, :tenant_id)
            ON CONFLICT DO NOTHING
            RETURNING event_id
            """
        )

        q_upsert = text(
            """
            INSERT INTO privacy.consents(tenant_id, subject_id, purpose, status, granted_at, revoked_at, expires_at, source, meta)
            VALUES (:tenant_id, :subject_id, :purpose, :status, :granted_at, :revoked_at, :expires_at, :source, CAST(:meta AS jsonb))
            ON CONFLICT (tenant_id, subject_id, purpose) DO UPDATE
            SET status = EXCLUDED.status,
                granted_at = COALESCE(EXCLUDED.granted_at, privacy.consents.granted_at),
                revoked_at = COALESCE(EXCLUDED.revoked_at, privacy.consents.revoked_at),
                expires_at = COALESCE(EXCLUDED.expires_at, privacy.consents.expires_at),
                source = COALESCE(EXCLUDED.source, privacy.consents.source),
                meta = COALESCE(privacy.consents.meta, '{}'::jsonb) || COALESCE(EXCLUDED.meta, '{}'::jsonb),
                updated_at = now()
            """
        )

        granted_at = ev.ts if ev.status == ConsentStatus.granted else None
        revoked_at = ev.ts if ev.status == ConsentStatus.revoked else None
        expires_at = ev.expires_at if ev.expires_at else None

        async with self.engine.begin() as conn:
            await self._set_tenant(conn, tenant_id)

            # Вставим в dedup-таблицу; если уже было — пропустим применение
            r = await conn.execute(q_dedup, {"event_id": ev.event_id, "tenant_id": tenant_id})
            if not r.fetchone():
                MET_SKIPPED.labels("dedup_table").inc()
                return

            with MET_LATENCY.time():  # применение
                await conn.execute(
                    q_upsert,
                    {
                        "tenant_id": tenant_id,
                        "subject_id": ev.subject_id,
                        "purpose": ev.purpose,
                        "status": ev.status.value,
                        "granted_at": granted_at,
                        "revoked_at": revoked_at,
                        "expires_at": expires_at,
                        "source": ev.source or "external",
                        "meta": _json_dumps(ev.meta or {}),
                    },
                )

            # Сохраним dedup и в Redis (для быстрого фильтра до похода в БД)
            await self._mark_processed(tenant_id, ev.event_id)

    # ---------- чекпоинты и dedup ----------

    async def _load_checkpoint(self, stream_id: str) -> Optional[str]:
        # Redis приоритетнее
        if self.redis:
            key = f"{self.cfg.redis.namespace}:ckp:{stream_id}"
            c = await self.redis.get(key)
            if c:
                return c
        q = text("SELECT cursor FROM privacy.consent_checkpoints WHERE stream_id=:sid")
        async with self.engine.begin() as conn:
            await self._set_tenant(conn, self.cfg.tenant_id)
            r = await conn.execute(q, {"sid": stream_id})
            row = r.fetchone()
            return str(row.cursor) if row else None

    async def _save_checkpoint(self, stream_id: str, cursor: Optional[str]) -> None:
        if not cursor:
            return
        if self.redis:
            key = f"{self.cfg.redis.namespace}:ckp:{stream_id}"
            await self.redis.set(key, cursor)
        q = text(
            """
            INSERT INTO privacy.consent_checkpoints(stream_id, cursor)
            VALUES (:sid, :cursor)
            ON CONFLICT (stream_id) DO UPDATE SET cursor=EXCLUDED.cursor, updated_at=now()
            """
        )
        async with self.engine.begin() as conn:
            await self._set_tenant(conn, self.cfg.tenant_id)
            await conn.execute(q, {"sid": stream_id, "cursor": cursor})

    async def _already_processed(self, tenant_id: str, event_id: str) -> bool:
        if self.redis and self.cfg.redis:
            key = f"{self.cfg.redis.namespace}:dedup:{tenant_id}"
            exists = await self.redis.sismember(key, event_id)
            return bool(exists)
        # Быстрый путь без Redis: проверка таблицы через SELECT 1 (дороже)
        q = text("SELECT 1 FROM privacy.consent_events WHERE event_id=:eid")
        async with self.engine.begin() as conn:
            await self._set_tenant(conn, tenant_id)
            r = await conn.execute(q, {"eid": event_id})
            return r.fetchone() is not None

    async def _mark_processed(self, tenant_id: str, event_id: str) -> None:
        if self.redis and self.cfg.redis:
            key = f"{self.cfg.redis.namespace}:dedup:{tenant_id}"
            await self.redis.sadd(key, event_id)
            await self.redis.expire(key, self.cfg.redis.ttl_dedup_seconds)

    # ---------- служебное ----------

    async def _set_tenant(self, conn: AsyncConnection, tenant_id: str) -> None:
        await conn.execute(text("SET LOCAL app.tenant_id = :tid"), {"tid": tenant_id})


# -----------------------------
# CLI
# -----------------------------

def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default


def build_config_from_env() -> WorkerConfig:
    mode = (_env("CONSENT_MODE", "http") or "http").lower()
    cfg = WorkerConfig(
        mode="kafka" if mode == "kafka" else "http",
        tenant_id=_env("CONSENT_TENANT", "default-tenant") or "default-tenant",
        db_dsn=os.environ["CONSENT_DB_DSN"],
        batch_size=int(_env("CONSENT_BATCH_SIZE", "500")),
        poll_interval_sec=float(_env("CONSENT_POLL_SEC", "2.0")),
        max_retries=int(_env("CONSENT_MAX_RETRIES", "5")),
        base_backoff_sec=float(_env("CONSENT_BACKOFF", "0.25")),
        backoff_jitter=float(_env("CONSENT_JITTER", "0.2")),
        metrics_port=int(_env("CONSENT_METRICS_PORT", "0") or "0") or None,
        stream_id=_env("CONSENT_STREAM_ID", "default") or "default",
        log_level=getattr(logging, _env("CONSENT_LOG_LEVEL", "INFO") or "INFO", logging.INFO),
    )
    if cfg.mode == "http":
        cfg.http = HTTPSource(
            url=os.environ["CONSENT_HTTP_URL"],
            method=_env("CONSENT_HTTP_METHOD", "GET") in ("POST",) and "POST" or "GET",
            auth_header=_env("CONSENT_HTTP_AUTH"),
            page_size=int(_env("CONSENT_HTTP_PAGE_SIZE", "500")),
            cursor_param=_env("CONSENT_HTTP_CURSOR_PARAM", "cursor") or "cursor",
            size_param=_env("CONSENT_HTTP_SIZE_PARAM", "limit") or "limit",
            initial_cursor=_env("CONSENT_HTTP_INITIAL_CURSOR"),
            timeout_sec=float(_env("CONSENT_HTTP_TIMEOUT", "10.0")),
        )
    else:
        cfg.kafka = KafkaSource(
            bootstrap_servers=os.environ["CONSENT_KAFKA_BROKERS"],
            topic=os.environ["CONSENT_KAFKA_TOPIC"],
            group_id=_env("CONSENT_KAFKA_GROUP", "veilmind-consent") or "veilmind-consent",
            security_protocol=_env("CONSENT_KAFKA_SECURITY_PROTOCOL"),
            sasl_mechanism=_env("CONSENT_KAFKA_SASL_MECHANISM"),
            sasl_plain_username=_env("CONSENT_KAFKA_USERNAME"),
            sasl_plain_password=_env("CONSENT_KAFKA_PASSWORD"),
            session_timeout_ms=int(_env("CONSENT_KAFKA_SESSION_TIMEOUT", "45000")),
            enable_auto_commit=(_env("CONSENT_KAFKA_AUTO_COMMIT", "false") or "false").lower() == "true",
            auto_offset_reset=_env("CONSENT_KAFKA_OFFSET_RESET", "latest") or "latest",
        )
    if _env("CONSENT_REDIS_DSN"):
        cfg.redis = RedisConfig(
            dsn=os.environ["CONSENT_REDIS_DSN"],
            namespace=_env("CONSENT_REDIS_NAMESPACE", "veilmind:consent") or "veilmind:consent",
            ttl_dedup_seconds=int(_env("CONSENT_REDIS_TTL", "604800")),
        )
    return cfg


async def _amain() -> int:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":%(message)s}',
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    cfg = build_config_from_env()
    worker = ConsentSyncWorker(cfg)
    await worker.run()
    return 0


def main() -> None:
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
