# ledger-core/ledger/telemetry/audit_log.py
# -*- coding: utf-8 -*-
"""
Промышленный аудит-лог с хэш-цепочкой, редактированием PII и многоканальной доставкой.

Требования:
  - Python 3.10+
  - pydantic>=2.5

Опционально:
  - aiofiles (для неблокирующей записи в файл; иначе синхронная запись выполняется в threadpool)
  - aiohttp (для HTTP sink)
  - opentelemetry-api (метрики/трейсы, если установлено)

Интеграция:
  from ledger.telemetry.audit_log import (
      AuditLogger, AuditConfig, ConsoleSink, RotatingFileSink, HttpSink,
      HmacSigner, Redactor, AuditEvent
  )
  logger = await AuditLogger.create(
      config=AuditConfig(env="prod", service="ledger-core", hmac_secret=os.environ.get("AUDIT_HMAC")),
      sinks=[ConsoleSink(), RotatingFileSink("/var/log/ledger/audit.jsonl")],
  )
  await logger.audit(
      action="transaction.create",
      resource="ledger/tx",
      subject="user:123",
      tenant="tenant-1",
      outcome="success",
      attrs={"amount":"100","currency":"USD","card":"4111111111111111"},  # будет отредактировано
      request_id="...", trace_id="...", span_id="..."
  )
  await logger.close()
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Protocol, Sequence, Tuple, Union

from pydantic import BaseModel, Field, ValidationError, computed_field, field_validator

# ------------------------------
# OpenTelemetry (опционально)
# ------------------------------
try:  # pragma: no cover
    from opentelemetry import trace, metrics
    _tracer = trace.get_tracer(__name__)
    _meter = metrics.get_meter(__name__)
    _m_events = _meter.create_counter("audit_events_total")
    _m_dropped = _meter.create_counter("audit_events_dropped_total")
    _m_failed = _meter.create_counter("audit_sink_failures_total")
except Exception:  # pragma: no cover
    class _N:
        def __getattr__(self, *_): return self
        def start_as_current_span(self, *_ , **__):
            class _S:
                def __enter__(self): return self
                def __exit__(self, *a): return False
                def set_attribute(self, *_, **__): pass
            return _S()
        def create_counter(self, *_ , **__):
            class _C: 
                def add(self, *_ , **__): pass
            return _C()
    _tracer = _N()
    _m_events = _N()
    _m_dropped = _N()
    _m_failed = _N()

LOG = logging.getLogger("ledger.audit")


# ------------------------------
# Константы и утилиты
# ------------------------------

DEFAULT_REDACT_FIELDS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "card", "card_number", "iban", "pan", "ssn", "cvv", "pin",
    "email", "phone", "authorization", "cookie", "set-cookie",
}

Outcome = Literal["success", "failure", "deny"]
Severity = Literal["info", "notice", "warning", "error", "critical"]

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _stable_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def _bool(v: Any) -> bool:
    return str(v).lower() in {"1","true","yes","on"}


# ------------------------------
# Схема события аудита
# ------------------------------

class AuditEvent(BaseModel):
    """
    Строгая схема события аудита. Все нестандартные поля — в attrs.
    """
    ts: str = Field(default_factory=_utcnow_iso)                 # RFC3339 UTC
    service: str
    env: str
    action: str                                                  # что делаем (domain.verb)
    resource: str                                                # объект (тип/id)
    subject: str                                                 # кто (user:<id>, svc:<name>, key:<id>)
    tenant: Optional[str] = None
    outcome: Outcome = "success"
    severity: Severity = "info"
    reason: Optional[str] = None                                 # для failure/deny
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    prev_hash_b64: Optional[str] = None                          # хэш предыдущего события (цепочка)
    event_hash_b64: Optional[str] = None                         # хэш текущего события (после вычисления)
    sig_b64: Optional[str] = None                                # подпись текущего события (если настроено)
    attrs: Dict[str, Any] = Field(default_factory=dict)          # произвольные атрибуты (редактируются)
    schema: int = 1

    @computed_field  # type: ignore[misc]
    @property
    def partition_key(self) -> str:
        # удобный ключ для шардирования/индексации
        return f"{self.env}:{self.service}:{(self.tenant or 'global')}"

    @field_validator("action")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or "/" in v or " " in v:
            raise ValueError("action must be a non-empty dot-separated token without spaces or slashes")
        return v

    @field_validator("outcome")
    @classmethod
    def _outcome_reason(cls, v: str, info):
        # reason обязателен при неуспехе
        return v


# ------------------------------
# Редактор PII/секретов
# ------------------------------

@dataclass(frozen=True)
class Redactor:
    fields: frozenset[str] = frozenset(DEFAULT_REDACT_FIELDS)
    mask: str = "***"
    max_string: int = 4096

    def redact(self, obj: Any) -> Any:
        try:
            return self._red(obj, 0)
        except Exception:
            return obj

    def _red(self, obj: Any, depth: int) -> Any:
        if depth > 64:
            return self.mask
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                out[k] = self.mask if k.lower() in self.fields else self._red(v, depth + 1)
            return out
        if isinstance(obj, list):
            return [self._red(x, depth + 1) for x in obj]
        if isinstance(obj, str):
            return obj if len(obj) <= self.max_string else obj[: self.max_string] + "...<truncated>"
        return obj


# ------------------------------
# Подписант (опционально)
# ------------------------------

class Signer(Protocol):
    async def sign(self, data: bytes) -> bytes: ...
    async def verify(self, data: bytes, signature: bytes) -> bool: ...

class HmacSigner:
    def __init__(self, secret: Union[str, bytes], algo: Literal["sha256","sha512"]="sha256") -> None:
        self._key = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._algo = algo

    async def sign(self, data: bytes) -> bytes:
        digestmod = hashlib.sha256 if self._algo == "sha256" else hashlib.sha512
        return hmac.new(self._key, data, digestmod).digest()

    async def verify(self, data: bytes, signature: bytes) -> bool:
        calc = await self.sign(data)
        return hmac.compare_digest(calc, signature)


# ------------------------------
# Синки (приёмники)
# ------------------------------

class AuditSink(Protocol):
    async def write_batch(self, records: Sequence[str]) -> None: ...
    async def close(self) -> None: ...

class ConsoleSink:
    """Структурированный вывод в stdout как JSONL."""
    def __init__(self, *, stream=None) -> None:
        self._stream = stream or sys.stdout

    async def write_batch(self, records: Sequence[str]) -> None:
        for r in records:
            self._stream.write(r + "\n")
        self._stream.flush()

    async def close(self) -> None:
        try:
            self._stream.flush()
        except Exception:
            pass

class RotatingFileSink:
    """
    Безопасная запись в файл (JSONL). Ротация по размеру.
    Для неблокирующей записи можно установить aiofiles; иначе писаем в threadpool.
    """
    def __init__(self, path: Union[str, Path], *, max_bytes: int = 128 * 1024 * 1024, backups: int = 5) -> None:
        self._path = Path(path)
        self._max = max_bytes
        self._backups = backups
        self._lock = asyncio.Lock()
        self._use_aiofiles = False
        try:  # pragma: no cover
            import aiofiles  # noqa
            self._use_aiofiles = True
        except Exception:
            self._use_aiofiles = False
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def write_batch(self, records: Sequence[str]) -> None:
        payload = "".join(r + "\n" for r in records)
        async with self._lock:
            await self._rotate_if_needed(len(payload))
            if self._use_aiofiles:  # pragma: no cover
                import aiofiles
                async with aiofiles.open(self._path, "a", encoding="utf-8") as f:
                    await f.write(payload)
            else:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self._append_sync, payload)

    def _append_sync(self, txt: str) -> None:
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(txt)

    async def _rotate_if_needed(self, incoming_bytes: int) -> None:
        size = self._path.stat().st_size if self._path.exists() else 0
        if size + incoming_bytes <= self._max:
            return
        # простая ротация .N
        for i in range(self._backups, 0, -1):
            src = self._path.with_suffix(self._path.suffix + f".{i}")
            dst = self._path.with_suffix(self._path.suffix + f".{i+1}")
            if src.exists():
                if i == self._backups and dst.exists():
                    dst.unlink(missing_ok=True)
                src.replace(dst)
        if self._path.exists():
            self._path.replace(self._path.with_suffix(self._path.suffix + ".1"))

    async def close(self) -> None:
        return

class HttpSink:
    """
    Отправка в удалённый приемник (SIEM/коллектор) по HTTP/HTTPS.
    Требует aiohttp. Пакетная отправка JSONL как application/x-ndjson.
    """
    def __init__(self, endpoint: str, *, headers: Optional[Mapping[str,str]]=None, timeout: float=5.0, verify_tls: bool=True) -> None:
        self._endpoint = endpoint
        self._headers = {"content-type":"application/x-ndjson", **(headers or {})}
        self._timeout = timeout
        self._verify = verify_tls
        self._session = None

    async def _ensure(self):
        if self._session:
            return
        try:
            import aiohttp  # pragma: no cover
        except Exception as e:
            raise RuntimeError("HttpSink requires aiohttp to be installed") from e
        import aiohttp  # type: ignore
        self._aiohttp = aiohttp  # cache
        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self._timeout))

    async def write_batch(self, records: Sequence[str]) -> None:
        await self._ensure()
        assert self._session is not None
        data = "".join(r + "\n" for r in records)
        async with self._session.post(self._endpoint, data=data, headers=self._headers, ssl=self._verify) as resp:  # type: ignore
            if resp.status >= 300:
                txt = await resp.text()
                raise RuntimeError(f"HttpSink error: {resp.status} {txt}")

    async def close(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None


# ------------------------------
# Конфигурация аудита
# ------------------------------

@dataclass(frozen=True)
class AuditConfig:
    service: str = "ledger-core"
    env: str = "dev"
    node: str = os.uname().nodename if hasattr(os, "uname") else "localhost"
    hmac_secret: Optional[str] = None                   # если задан — включаем подпись HMAC
    hash_algo: Literal["sha256","blake2b"] = "sha256"
    queue_capacity: int = 50_000
    batch_max: int = 256
    batch_max_delay_ms: int = 500
    drop_on_overflow: bool = False
    sample_rate: float = 1.0                            # INFO события; ошибки пишем всегда
    redact: Redactor = Redactor()
    # Поля контекста, которые следует всегда включать
    static_context: Dict[str, Any] = None  # type: ignore

    def __post_init__(self):
        object.__setattr__(self, "static_context", self.static_context or {})


# ------------------------------
# Основной логгер аудита
# ------------------------------

class AuditLogger:
    """
    Асинхронный аудит-логгер с хэш-цепочкой и многоканальной доставкой.
    """

    def __init__(self, config: AuditConfig, sinks: Sequence[AuditSink], signer: Optional[Signer]) -> None:
        self._cfg = config
        self._sinks = list(sinks)
        self._signer = signer
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(self._cfg.queue_capacity)
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._prev_hash: Optional[bytes] = None
        self._hash_fn = (lambda b: hashlib.sha256(b).digest()) if self._cfg.hash_algo == "sha256" else (lambda b: hashlib.blake2b(b, digest_size=32).digest())

    @classmethod
    async def create(cls, *, config: AuditConfig, sinks: Sequence[AuditSink]) -> "AuditLogger":
        signer = HmacSigner(config.hmac_secret) if config.hmac_secret else None
        self = cls(config, sinks, signer)
        self._task = asyncio.create_task(self._run(), name="audit-logger")
        return self

    async def close(self) -> None:
        self._stopping.set()
        if self._task:
            await self._task
        for s in self._sinks:
            try:
                await s.close()
            except Exception as e:
                LOG.error("audit sink close failed: %s", e)

    # -------- Публичный API --------

    async def audit(
        self,
        *,
        action: str,
        resource: str,
        subject: str,
        tenant: Optional[str] = None,
        outcome: Outcome = "success",
        severity: Severity = "info",
        reason: Optional[str] = None,
        attrs: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        force: bool = False,
    ) -> None:
        """
        Записать событие аудита (асинхронно).
        INFO‑события могут семплироваться; ошибки и deny пишутся всегда.
        """
        if not force and severity in ("info", "notice") and not self._sample():
            return
        ev = AuditEvent(
            service=self._cfg.service,
            env=self._cfg.env,
            action=action,
            resource=resource,
            subject=subject,
            tenant=tenant,
            outcome=outcome,
            severity=severity,
            reason=reason,
            request_id=request_id,
            trace_id=trace_id,
            span_id=span_id,
            ip=ip,
            user_agent=user_agent,
            attrs=self._cfg.redact.redact(attrs or {}),
        )
        ev.attrs.update(self._cfg.static_context)
        try:
            self._queue.put_nowait(ev)
            _m_events.add(1)  # type: ignore
        except asyncio.QueueFull:
            _m_dropped.add(1)  # type: ignore
            if self._cfg.drop_on_overflow:
                LOG.error("audit queue overflow: event dropped (action=%s resource=%s)", action, resource)
                return
            # Блокируемся до освобождения места
            await self._queue.put(ev)

    # -------- Основной цикл --------

    async def _run(self) -> None:
        try:
            while not self._stopping.is_set():
                batch = await self._dequeue_batch()
                if not batch:
                    continue
                records = []
                for ev in batch:
                    rec = await self._finalize_event(ev)
                    records.append(rec)
                await self._dispatch(records)
        except Exception as e:
            LOG.exception("audit logger loop error: %s", e)
        finally:
            # дренируем остатки
            remain = []
            while not self._queue.empty():
                try:
                    ev = self._queue.get_nowait()
                    remain.append(ev)
                except Exception:
                    break
            if remain:
                records = [await self._finalize_event(ev) for ev in remain]
                try:
                    await self._dispatch(records)
                except Exception as e:
                    LOG.error("audit drain dispatch failed: %s", e)

    async def _dequeue_batch(self) -> List[AuditEvent]:
        items: List[AuditEvent] = []
        try:
            first = await asyncio.wait_for(self._queue.get(), timeout=self._cfg.batch_max_delay_ms / 1000.0)
            items.append(first)
        except asyncio.TimeoutError:
            return items
        # собрать до лимита batch_max без ожидания
        for _ in range(self._cfg.batch_max - 1):
            try:
                items.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return items

    async def _finalize_event(self, ev: AuditEvent) -> str:
        # формируем хэш-цепочку
        prev_b64 = base64.b64encode(self._prev_hash).decode("ascii") if self._prev_hash else None
        body = {
            "ts": ev.ts,
            "service": ev.service,
            "env": ev.env,
            "node": self._cfg.node,
            "action": ev.action,
            "resource": ev.resource,
            "subject": ev.subject,
            "tenant": ev.tenant,
            "outcome": ev.outcome,
            "severity": ev.severity,
            "reason": ev.reason,
            "request_id": ev.request_id,
            "trace_id": ev.trace_id,
            "span_id": ev.span_id,
            "ip": ev.ip,
            "user_agent": ev.user_agent,
            "attrs": ev.attrs,
            "schema": ev.schema,
            "prev_hash_b64": prev_b64,
        }
        payload = _stable_json(body).encode("utf-8")
        ev_hash = self._hash_fn(b"\xAA" + (self._prev_hash or b"") + payload)
        self._prev_hash = ev_hash
        body["event_hash_b64"] = base64.b64encode(ev_hash).decode("ascii")
        # подпись (если есть)
        if self._signer:
            sig = await self._signer.sign(b"\xAB" + ev_hash)
            body["sig_b64"] = base64.b64encode(sig).decode("ascii")
        return _stable_json(body)

    async def _dispatch(self, records: Sequence[str]) -> None:
        # Отправляем во все синки; каждый sink не должен влиять на другие.
        tasks = []
        for s in self._sinks:
            tasks.append(asyncio.create_task(self._safe_sink_write(s, records)))
        if tasks:
            await asyncio.gather(*tasks)

    async def _safe_sink_write(self, sink: AuditSink, records: Sequence[str]) -> None:
        try:
            await sink.write_batch(records)
        except Exception as e:
            _m_failed.add(1)  # type: ignore
            LOG.error("audit sink failed: %s", e)

    # -------- Вспомогательное --------

    def _sample(self) -> bool:
        r = self._cfg.sample_rate
        if r >= 1.0:
            return True
        # детерминированная выборка по времени
        return (time.time_ns() % 10_000) / 10_000.0 < max(0.0, r)


# ------------------------------
# Верификация (offline)
# ------------------------------

class AuditVerifier:
    """
    Проверка целостности цепочки аудита, считанной из источника JSONL.
    """

    def __init__(self, *, hash_algo: Literal["sha256","blake2b"]="sha256", signer: Optional[Signer]=None) -> None:
        self._hash_fn = (lambda b: hashlib.sha256(b).digest()) if hash_algo == "sha256" else (lambda b: hashlib.blake2b(b, digest_size=32).digest())
        self._signer = signer

    async def verify_stream(self, lines: Iterable[str]) -> Tuple[int, Optional[str]]:
        """
        Возвращает (count, error_message_if_any).
        Останавливается на первом нарушении.
        """
        prev: Optional[bytes] = None
        count = 0
        for line in lines:
            count += 1
            try:
                ev = json.loads(line)
            except Exception as e:
                return count, f"invalid json at #{count}: {e}"
            payload = ev.copy()
            ev_hash_b64 = payload.pop("event_hash_b64", None)
            sig_b64 = payload.pop("sig_b64", None)
            prev_hash_b64 = payload.get("prev_hash_b64")
            if (prev is None and prev_hash_b64) or (prev is not None and base64.b64encode(prev).decode("ascii") != (prev_hash_b64 or "")):
                return count, f"prev_hash mismatch at #{count}"
            payload_str = _stable_json(payload)
            calc = self._hash_fn(b"\xAA" + (prev or b"") + payload_str.encode("utf-8"))
            if base64.b64encode(calc).decode("ascii") != ev_hash_b64:
                return count, f"event_hash mismatch at #{count}"
            if self._signer and sig_b64:
                ok = await self._signer.verify(b"\xAB" + calc, base64.b64decode(sig_b64))
                if not ok:
                    return count, f"invalid signature at #{count}"
            prev = calc
        return count, None


# ------------------------------
# Пример самостоятельного запуска (dev)
# ------------------------------

if __name__ == "__main__":  # pragma: no cover
    import asyncio
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)

    async def main():
        cfg = AuditConfig(
            env=os.getenv("ENV", "dev"),
            service="ledger-core",
            hmac_secret=os.getenv("AUDIT_HMAC"),
            sample_rate=float(os.getenv("AUDIT_SAMPLE","1.0")),
            drop_on_overflow=_bool(os.getenv("AUDIT_DROP","0")),
            static_context={"app_version": os.getenv("APP_VERSION","0.0.0")},
        )
        sinks = [ConsoleSink(), RotatingFileSink("./audit.jsonl", max_bytes=1024*1024, backups=3)]
        logger = await AuditLogger.create(config=cfg, sinks=sinks)

        # Примеры событий
        await logger.audit(
            action="auth.login",
            resource="iam/session",
            subject="user:42",
            outcome="success",
            attrs={"ip":"1.2.3.4","email":"a@example.com","password":"secret"},
            request_id="req-1", trace_id="t-1", span_id="s-1", user_agent="curl/8.4"
        )
        await logger.audit(
            action="transaction.create",
            resource="ledger/tx",
            subject="user:42",
            tenant="acme",
            outcome="failure",
            severity="warning",
            reason="insufficient_funds",
            attrs={"amount":"100","currency":"USD","card_number":"4111111111111111"},
            request_id="req-2", trace_id="t-2", span_id="s-2"
        )
        await logger.close()

        # Верификация файла
        verifier = AuditVerifier(hash_algo=cfg.hash_algo, signer=HmacSigner(cfg.hmac_secret) if cfg.hmac_secret else None)
        with open("./audit.jsonl", "r", encoding="utf-8") as f:
            count, err = await verifier.verify_stream(f)
            print("verified:", count, "error:", err)

    asyncio.run(main())
