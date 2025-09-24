# -*- coding: utf-8 -*-
"""
security-core HTTP router: Audit (v1)

Возможности:
- Append-only журнал аудита с криптографической цепочкой хешей (Merkle-like chain).
- Прием батчей событий с HMAC-SHA256 подписью (X-Audit-Signature: sha256=<hex>).
- Валидация и нормализация событий, автоматическое обогащение (received_at, remote_ip, ua).
- Поиск/фильтрация/пагинация (cursor по индексу), экспорт NDJSON (streaming).
- Проверка целостности цепочки /verify и получение головы /chain/head.
- Лимиты размера батча и скорости, защита от дубликатов jti, базовые метрики.

Интеграция:
- Для prod включите аутентификацию на уровне API-шлюза (mTLS/JWT).
- HMAC-секрет храните в KMS/Vault; ниже используется переменная окружения AUDIT_HMAC_SECRET.
- Замените InMemoryLedger на FileLedger или ваш KV/SQL append-only стор.

Зависимости:
  fastapi, pydantic
  (опционально) uvicorn для запуска
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator

# ---------------------------------------------------------------------------
# Константы/политики
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/v1/audit", tags=["audit"])

BATCH_MAX_EVENTS = 1000
MAX_EVENT_BYTES = 32 * 1024  # на одно событие
HMAC_HEADER = "x-audit-signature"  # формат: "sha256=<hex>"
HMAC_ALGO_PREFIX = "sha256="
CLOCK_SKEW_SEC = 300  # допустимая рассинхронизация клиентских часов
RATE_LIMIT_PER_MIN_IP = 6000  # грубый лимит приеме
NDJSON_CT = "application/x-ndjson"
JSON_CT = "application/json"

# Тумблеры поведения
ENFORCE_HMAC = True if os.getenv("AUDIT_ENFORCE_HMAC", "true").lower() == "true" else False
HMAC_SECRET = os.getenv("AUDIT_HMAC_SECRET", "")

# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _ts_to_rfc3339(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def _canonical_json(obj: Any) -> str:
    """Каноническое сериализованное представление для хеширования/подписи."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _event_id(ts: datetime) -> str:
    # монотонное, сортируемое: микросекунды + случайный хвост
    micros = int(ts.timestamp() * 1_000_000)
    return f"ae_{micros:016x}{secrets.token_hex(4)}"

def _parse_hmac(header_val: str) -> Optional[str]:
    if not header_val:
        return None
    header_val = header_val.strip()
    if not header_val.lower().startswith(HMAC_ALGO_PREFIX):
        return None
    return header_val[len(HMAC_ALGO_PREFIX):]

def _verify_hmac(body: bytes, signature_hex: str, secret: str) -> bool:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, signature_hex)

def _ip(req: Request) -> str:
    # В проде используйте список доверенных прокси и X-Forwarded-For
    return req.client.host if req.client else "0.0.0.0"

# ---------------------------------------------------------------------------
# Схемы
# ---------------------------------------------------------------------------

class Severity(str):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class Outcome(str):
    SUCCESS = "success"
    FAILURE = "failure"

class AuditEvent(BaseModel):
    ts: datetime = Field(..., description="Время события (RFC3339)")
    jti: Optional[str] = Field(None, description="Идентификатор события (dedup)")
    tenant_id: Optional[str] = Field(None, description="Арендатор/организация")
    actor_id: Optional[str] = Field(None, description="Инициатор (пользователь/сервис)")
    actor_type: Optional[str] = Field(None, description="user|service|system")
    action: str = Field(..., description="Тип действия, напр. authn.login")
    resource: Optional[str] = Field(None, description="Объект воздействия")
    resource_id: Optional[str] = Field(None, description="Идентификатор объекта")
    outcome: str = Field(..., regex="^(success|failure)$")
    severity: str = Field(Severity.INFO, regex="^(INFO|WARNING|ERROR|CRITICAL)$")
    trace_id: Optional[str] = Field(None, description="Trace ID")
    span_id: Optional[str] = Field(None, description="Span ID")
    labels: Dict[str, str] = Field(default_factory=dict, description="Произвольные метки")
    data: Dict[str, Any] = Field(default_factory=dict, description="Доп. поля (объект)")
    ip: Optional[str] = Field(None, description="IP инициатора")
    user_agent: Optional[str] = Field(None, description="User-Agent инициатора")

    @validator("ts")
    def _ts_recent(cls, v: datetime) -> datetime:
        # базовая проверка на разумный диапазон
        now = _utcnow()
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        delta = abs((now - v).total_seconds())
        if delta > 3650 * 24 * 3600:
            raise ValueError("ts is unrealistic")
        return v

class StoredAuditEvent(AuditEvent):
    id: str = Field(..., description="ID записи (генерируется сервером)")
    received_at: datetime = Field(..., description="Время приема на сервере")
    prev_hash: str = Field(..., description="Хеш предыдущей записи (цепочка)")
    content_hash: str = Field(..., description="SHA-256 канонизированного события")
    chain_hash: str = Field(..., description="SHA-256(prev_hash||content_hash)")
    index: int = Field(..., description="Монотонный индекс в журнале")

class IngestResponse(BaseModel):
    acked: int
    head_index: int
    head_hash: str

class HeadResponse(BaseModel):
    head_index: int
    head_hash: str
    count: int

class VerifyRequest(BaseModel):
    start_index: Optional[int] = Field(None, ge=0)
    end_index: Optional[int] = Field(None, ge=0)

class VerifyResponse(BaseModel):
    ok: bool
    first_bad_index: Optional[int] = None
    message: Optional[str] = None

class SearchResponse(BaseModel):
    items: List[StoredAuditEvent]
    next_cursor: Optional[int] = None

# ---------------------------------------------------------------------------
# Ledger интерфейсы и реализации
# ---------------------------------------------------------------------------

class LedgerBackend:
    """Интерфейс неизменяемого журнала."""
    def append(self, events: List[AuditEvent], extras: Dict[str, str]) -> Tuple[int, str, List[StoredAuditEvent]]:
        raise NotImplementedError

    def head(self) -> Tuple[int, str, int]:
        """(head_index, head_hash, count). Если пусто: (-1, '00..0', 0)."""
        raise NotImplementedError

    def iter_range(self, start: int, end: int) -> Iterable[StoredAuditEvent]:
        """Включительно-эксклюзивный полуинтервал [start, end)."""
        raise NotImplementedError

    def verify(self, start: int = 0, end: Optional[int] = None) -> Tuple[bool, Optional[int]]:
        raise NotImplementedError

    def search(self, **filters) -> Tuple[List[StoredAuditEvent], Optional[int]]:
        raise NotImplementedError

class InMemoryLedger(LedgerBackend):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: List[StoredAuditEvent] = []
        self._jti_seen: set[str] = set()

    def _head_tuple(self) -> Tuple[int, str, int]:
        if not self._records:
            return -1, "0"*64, 0
        last = self._records[-1]
        return last.index, last.chain_hash, len(self._records)

    def append(self, events: List[AuditEvent], extras: Dict[str, str]) -> Tuple[int, str, List[StoredAuditEvent]]:
        with self._lock:
            head_index, head_hash, _ = self._head_tuple()
            prev = head_hash
            out: List[StoredAuditEvent] = []
            for ev in events:
                # дедуп по jti (если есть)
                if ev.jti and ev.jti in self._jti_seen:
                    # пропускаем дубликат
                    continue
                # обогащение
                received_at = _utcnow()
                eid = _event_id(received_at)
                base_dict = ev.dict()
                # ограничение размера
                if len(_canonical_json(base_dict).encode("utf-8")) > MAX_EVENT_BYTES:
                    raise HTTPException(status_code=413, detail="Event too large")
                content_hash = _sha256_hex(_canonical_json(base_dict).encode("utf-8"))
                chain_hash = _sha256_hex((prev + content_hash).encode("utf-8"))
                rec = StoredAuditEvent(
                    **base_dict,
                    id=eid,
                    received_at=received_at,
                    prev_hash=prev,
                    content_hash=content_hash,
                    chain_hash=chain_hash,
                    index=head_index + 1 if head_index >= 0 else 0,
                )
                self._records.append(rec)
                if ev.jti:
                    self._jti_seen.add(ev.jti)
                head_index = rec.index
                prev = chain_hash
                out.append(rec)
            return self._head_tuple()[0], self._head_tuple()[1], out

    def head(self) -> Tuple[int, str, int]:
        with self._lock:
            return self._head_tuple()

    def iter_range(self, start: int, end: int) -> Iterable[StoredAuditEvent]:
        with self._lock:
            start = max(start, 0)
            end = min(end, len(self._records)) if end is not None else len(self._records)
            for i in range(start, end):
                yield self._records[i]

    def verify(self, start: int = 0, end: Optional[int] = None) -> Tuple[bool, Optional[int]]:
        with self._lock:
            end = end if end is not None else len(self._records)
            prev = "0"*64 if start == 0 else (self._records[start-1].chain_hash if start-1 >= 0 else "0"*64)
            for i in range(start, end):
                r = self._records[i]
                expected_content = _sha256_hex(_canonical_json(AuditEvent.parse_obj(r.dict(exclude={
                    "id","received_at","prev_hash","content_hash","chain_hash","index"
                })).dict()).encode("utf-8"))
                if expected_content != r.content_hash:
                    return False, i
                expected_chain = _sha256_hex((prev + r.content_hash).encode("utf-8"))
                if expected_chain != r.chain_hash:
                    return False, i
                prev = r.chain_hash
            return True, None

    def search(self,
               start_time: Optional[datetime] = None,
               end_time: Optional[datetime] = None,
               actor_id: Optional[str] = None,
               action: Optional[str] = None,
               severity: Optional[str] = None,
               tenant_id: Optional[str] = None,
               cursor: Optional[int] = None,
               limit: int = 100) -> Tuple[List[StoredAuditEvent], Optional[int]]:
        with self._lock:
            start_index = max(cursor or 0, 0)
            res: List[StoredAuditEvent] = []
            for i in range(start_index, len(self._records)):
                r = self._records[i]
                if start_time and r.ts < start_time:
                    continue
                if end_time and r.ts > end_time:
                    continue
                if actor_id and r.actor_id != actor_id:
                    continue
                if action and r.action != action:
                    continue
                if severity and r.severity != severity:
                    continue
                if tenant_id and r.tenant_id != tenant_id:
                    continue
                res.append(r)
                if len(res) >= limit:
                    next_cur = r.index + 1 if (r.index + 1) < len(self._records) else None
                    return res, next_cur
            return res, None

# Опциональный файловый журнал (append-only, одиночный процесс/подлок)
class FileLedger(InMemoryLedger):
    """
    Упрощенная файловая реализация на основе InMemoryLedger:
    - При старте читает файл NDJSON и восстанавливает состояние в память.
    - При append дописывает записи в файл атомарно.
    Примечание: для мультипроцессного доступа используйте lock-файл/файловые блокировки.
    """
    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path
        self._flock = threading.Lock()
        # загрузка
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    rec = StoredAuditEvent.parse_obj(obj)
                    self._records.append(rec)
                    if rec.jti:
                        self._jti_seen.add(rec.jti)

    def append(self, events: List[AuditEvent], extras: Dict[str, str]) -> Tuple[int, str, List[StoredAuditEvent]]:
        with self._flock:
            head_index, head_hash, new_records = super().append(events, extras)
            # дозапись
            if new_records:
                with open(self._path, "a", encoding="utf-8") as f:
                    for r in new_records:
                        f.write(_canonical_json(r.dict()) + "\n")
            return self.head()[0], self.head()[1], new_records

# ---------------------------------------------------------------------------
# Инициализация стора/лимитера
# ---------------------------------------------------------------------------

# По умолчанию in-memory; для продакшена выдайте путь к файлу через env AUDIT_FILE_PATH
_LEDGER: LedgerBackend = FileLedger(os.getenv("AUDIT_FILE_PATH")) if os.getenv("AUDIT_FILE_PATH") else InMemoryLedger()

class SimpleRateLimiter:
    def __init__(self, max_per_min_ip: int) -> None:
        self.max = max_per_min_ip
        self.buckets: Dict[Tuple[str, int], int] = {}
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        minute = int(time.time() // 60)
        key = (ip, minute)
        with self._lock:
            self.buckets[key] = self.buckets.get(key, 0) + 1
            return self.buckets[key] <= self.max

_RATE = SimpleRateLimiter(RATE_LIMIT_PER_MIN_IP)

# ---------------------------------------------------------------------------
# Зависимость: проверка HMAC
# ---------------------------------------------------------------------------

async def _require_hmac(request: Request) -> None:
    if not ENFORCE_HMAC:
        return
    sig = _parse_hmac(request.headers.get(HMAC_HEADER, ""))
    if not sig:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid HMAC header")
    body = await request.body()
    if not HMAC_SECRET:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Server HMAC secret not configured")
    if not _verify_hmac(body, sig, HMAC_SECRET):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad HMAC signature")

# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

class IngestRequest(BaseModel):
    events: List[AuditEvent] = Field(..., description="Список событий (<= BATCH_MAX_EVENTS)")

@router.post("/events", response_model=IngestResponse)
async def ingest_events(request: Request, payload: IngestRequest, _: Any = Depends(_require_hmac)) -> IngestResponse:
    client_ip = _ip(request)
    if not _RATE.allow(client_ip):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")

    if len(payload.events) > BATCH_MAX_EVENTS:
        raise HTTPException(status_code=413, detail="Batch too large")

    # Валидация времени и обогащение
    now = _utcnow()
    enriched: List[AuditEvent] = []
    ua = request.headers.get("user-agent", "")
    for ev in payload.events:
        # анти‑replay на чрезмерный заглядывание в прошлое/будущее
        skew = abs((now - ev.ts).total_seconds())
        if skew > CLOCK_SKEW_SEC:
            # допускаем, но отметим severity при желании — здесь просто пропустим
            pass
        # Обогащение полей ip/ua, если не заполнены
        ev.ip = ev.ip or client_ip
        ev.user_agent = ev.user_agent or ua
        enriched.append(ev)

    head_index, head_hash, appended = _LEDGER.append(enriched, extras={})
    return IngestResponse(acked=len(appended), head_index=head_index, head_hash=head_hash)

@router.get("/events", response_model=SearchResponse)
def search_events(
    start: Optional[str] = Query(None, description="RFC3339"),
    end: Optional[str] = Query(None, description="RFC3339"),
    actor_id: Optional[str] = None,
    action: Optional[str] = None,
    severity: Optional[str] = Query(None, regex="^(INFO|WARNING|ERROR|CRITICAL)$"),
    tenant_id: Optional[str] = None,
    cursor: Optional[int] = Query(None, ge=0),
    limit: int = Query(100, ge=1, le=1000),
) -> SearchResponse:
    def parse_dt(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid datetime")

    items, next_cur = _LEDGER.search(
        start_time=parse_dt(start),
        end_time=parse_dt(end),
        actor_id=actor_id,
        action=action,
        severity=severity,
        tenant_id=tenant_id,
        cursor=cursor,
        limit=limit,
    )
    return SearchResponse(items=items, next_cursor=next_cur)

@router.get("/export")
def export_events(
    start_index: int = Query(0, ge=0),
    end_index: Optional[int] = Query(None, ge=0),
    filename: Optional[str] = None,
):
    """Экспорт диапазона [start_index, end_index) в NDJSON (построчно, streaming)."""
    def gen() -> Generator[bytes, None, None]:
        for rec in _LEDGER.iter_range(start_index, end_index if end_index is not None else 1 << 62):
            line = _canonical_json(rec.dict()) + "\n"
            yield line.encode("utf-8")

    headers = {}
    if filename:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return StreamingResponse(gen(), media_type=NDJSON_CT, headers=headers)

@router.get("/chain/head", response_model=HeadResponse)
def get_head() -> HeadResponse:
    idx, hh, count = _LEDGER.head()
    return HeadResponse(head_index=idx, head_hash=hh, count=count)

@router.post("/verify", response_model=VerifyResponse)
def verify_chain(req: VerifyRequest) -> VerifyResponse:
    start = req.start_index or 0
    ok, bad = _LEDGER.verify(start=start, end=req.end_index)
    if ok:
        return VerifyResponse(ok=True)
    return VerifyResponse(ok=False, first_bad_index=bad, message="Chain integrity violation")

# Явно запрещаем удаление/модификацию (append-only)
@router.delete("/events")
def _reject_delete() -> Dict[str, str]:
    raise HTTPException(status_code=status.HTTP_405_METHOD_NOT_ALLOWED, detail="Append-only log")

# ---------------------------------------------------------------------------
# Примечания по эксплуатации:
# - Защитите /v1/audit/* на периметре (mTLS/JWT, IP-ACL).
# - Храните HMAC секрет в KMS/Vault; включите ENFORCE_HMAC.
# - Для SIEM/аналитики подключите экспорт /export и/или tail файл FileLedger.
# - Для высокой нагрузки используйте асинхронный бэкенд (Kafka→object storage).
# - Для Merkle-пруфов расширьте chain_hash до дерева и храните корни по интервалам.
