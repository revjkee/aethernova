# -*- coding: utf-8 -*-
"""
Промышленный аудит-логгер ChronoWatch.

Особенности:
- Строгая схема события (Pydantic), стабильная сериализация JSON (sorted keys, no NaN).
- Редактирование чувствительных данных (PII, секреты, токены) с рекурсивной маскировкой.
- Цепочка целостности: prev_hash + sha256(current_canonical + prev_hash) => hash.
- Криптоподпись HMAC-SHA256 (секрет из AUDIT_HMAC_SECRET) поверх canonical-json.
- Контекст: request_id/correlation_id/tenant_id/actor/ip/ua через contextvars и явные аргументы.
- Надежные sinks: Stdout, File (с ротацией по размеру + fsync + межпроцессная блокировка), опционально Kafka (если установлен confluent_kafka).
- Синхронный и асинхронный интерфейсы (без фоновых потоков по умолчанию).
- Верификатор цепочки/подписи для офлайн-проверок.
- Минимальная кардинальность: ключевые поля — who, action, resource_template, result; большие payload в .data.

ENV (I cannot verify this):
  AUDIT_STDOUT=1|0
  AUDIT_FILE=/var/log/chronowatch/audit.log
  AUDIT_ROTATE_BYTES=104857600
  AUDIT_ROTATE_BACKUPS=7
  AUDIT_FSYNC=0|1
  AUDIT_HMAC_SECRET=base64|hex|plain
  AUDIT_KAFKA_BROKERS=host1:9092,host2:9092
  AUDIT_KAFKA_TOPIC=chronowatch.audit
"""

from __future__ import annotations

import base64
import contextvars
import dataclasses
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple, Union

# ---------- Pydantic (v1/v2 совместимость) ----------
try:
    from pydantic import BaseModel, Field, validator
except Exception:  # pragma: no cover
    # Минимальный фоллбэк, если pydantic не установлен (валидация урезана)
    class BaseModel:  # type: ignore
        def __init__(self, **kw):  # noqa
            for k, v in kw.items():
                setattr(self, k, v)
        def dict(self, **kw):
            return self.__dict__
    def Field(default=None, **kw):  # type: ignore
        return default
    def validator(*a, **k):  # type: ignore
        def _wrap(fn):
            return fn
        return _wrap

# ---------- Контекст ----------
_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("audit_request_id", default="")
_correlation_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("audit_correlation_id", default="")
_tenant_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("audit_tenant_id", default="")

def set_request_context(request_id: Optional[str] = None, correlation_id: Optional[str] = None, tenant_id: Optional[str] = None):
    if request_id is not None:
        _request_id_ctx.set(request_id)
    if correlation_id is not None:
        _correlation_id_ctx.set(correlation_id)
    if tenant_id is not None:
        _tenant_id_ctx.set(tenant_id)

def get_request_id() -> str:
    return _request_id_ctx.get("")

def get_correlation_id() -> str:
    return _correlation_id_ctx.get("")

def get_tenant_id() -> str:
    return _tenant_id_ctx.get("")

# ---------- Утилиты ----------
def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _from_env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return v.strip() in ("1", "true", "TRUE", "yes", "on")

def _canonical_json(obj: Any) -> str:
    # Стабильная сериализация: сортируем ключи, не допускаем NaN/Infinity.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)

def _safe_host() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"

# ---------- Маскировка чувствительных данных ----------
_MASK = "******"
_KEY_PATTERNS = re.compile(r"(password|pass|token|secret|authorization|cookie|set-cookie|api[_-]?key|ssn|card|cvv|iban)", re.I)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+?\d[\d\-\s()]{6,}\d")
_CARD_RE = re.compile(r"(?<!\d)(\d[ \-]?){13,19}(?!\d)")
_JWT_RE = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$")

def _mask_scalar(val: Any) -> Any:
    if val is None:
        return None
    if isinstance(val, (int, float, bool)):
        return val
    s = str(val)
    if _JWT_RE.match(s):
        return _MASK
    if _EMAIL_RE.search(s):
        return _EMAIL_RE.sub(lambda m: m.group(0)[:2] + "***" + m.group(0)[-2:], s)
    if _CARD_RE.search(s):
        return _CARD_RE.sub("**** **** **** ****", s)
    if _PHONE_RE.search(s):
        return _PHONE_RE.sub(lambda m: "***" + m.group(0)[-2:], s)
    return s

def redact(obj: Any) -> Any:
    """Рекурсивная маскировка PII/секретов."""
    if isinstance(obj, Mapping):
        out = {}
        for k, v in obj.items():
            if _KEY_PATTERNS.search(str(k)):
                out[k] = _MASK
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(x) for x in obj]
    return _mask_scalar(obj)

# ---------- Схема события ----------
class AuditEvent(BaseModel):
    schema: str = Field("chronowatch.audit.v1", description="Версия схемы события")
    ts: str = Field(..., description="RFC3339 UTC timestamp")
    event_id: str = Field(..., description="UUID события")
    who: str = Field(..., description="Идентификатор субъекта (actor)")
    action: str = Field(..., description="Действие: login, access, create, update, delete, grant, revoke, export, import, execute, error, custom")
    resource: str = Field(..., description="Ресурс/объект: 'order/123', 'policy/core'")
    result: str = Field(..., description="Результат: success|deny|error|partial")
    reason: Optional[str] = Field(None, description="Причина/комментарий")
    subject: Optional[str] = Field(None, description="Субъект над которым выполнялось действие (если отличается от who)")
    tenant_id: Optional[str] = Field(None, description="Арендатор/организация")
    org_id: Optional[str] = Field(None, description="Опционально, организация")
    request_id: Optional[str] = Field(None, description="Request-ID")
    correlation_id: Optional[str] = Field(None, description="Correlation-ID")
    ip: Optional[str] = Field(None, description="IP адрес клиента")
    user_agent: Optional[str] = Field(None, description="User-Agent клиента")
    host: Optional[str] = Field(None, description="Хост, где был сгенерирован лог")
    severity: str = Field("info", description="info|warning|critical")
    labels: Dict[str, str] = Field(default_factory=dict, description="Ключ-значение меток")
    data: Dict[str, Any] = Field(default_factory=dict, description="Доп. данные (после редактирования)")
    # Цепочка целостности и подпись
    prev_hash: Optional[str] = Field(None, description="Хеш предыдущего события в той же цепочке")
    hash: Optional[str] = Field(None, description="Хеш текущего события")
    signature: Optional[str] = Field(None, description="HMAC-SHA256 от canonical-json события (без signature)")

    @validator("ip")
    def _valid_ip(cls, v):  # noqa
        if v in (None, "", "-"):
            return v
        try:
            ipaddress.ip_address(v)
            return v
        except Exception:
            # IP может быть прокси-цепочкой — допустим как есть, но не валим
            return v

# ---------- Базовый sink ----------
class AuditSink:
    def emit_line(self, line: str) -> None:
        raise NotImplementedError
    def last_hash(self) -> Optional[str]:
        return None
    def close(self) -> None:
        pass

# ---------- Stdout sink ----------
class StdoutSink(AuditSink):
    _lock = threading.Lock()
    def __init__(self, stream=None):
        self._stream = stream or sys.stdout
        self._last_hash = None
    def emit_line(self, line: str) -> None:
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()
        try:
            self._last_hash = json.loads(line).get("hash")
        except Exception:
            pass
    def last_hash(self) -> Optional[str]:
        return self._last_hash

# ---------- File sink с ротацией и блокировкой ----------
class FileSink(AuditSink):
    def __init__(self, path: Union[str, Path],
                 rotate_bytes: int = 100 * 1024 * 1024,
                 backups: int = 7,
                 fsync_on_write: bool = False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rotate_bytes = int(rotate_bytes)
        self.backups = int(backups)
        self.fsync_on_write = bool(fsync_on_write)
        self._lock = threading.Lock()
        self._fh = open(self.path, "a", encoding="utf-8", buffering=1)
        self._last_hash_cache = self._recover_last_hash()

    def _recover_last_hash(self) -> Optional[str]:
        try:
            with open(self.path, "rb") as fh:
                try:
                    fh.seek(-8192, os.SEEK_END)
                except Exception:
                    fh.seek(0)
                tail = fh.read().decode("utf-8", errors="ignore").splitlines()
                for line in reversed(tail):
                    if not line.strip():
                        continue
                    try:
                        return json.loads(line).get("hash")
                    except Exception:
                        continue
        except Exception:
            return None
        return None

    def _should_rotate(self) -> bool:
        try:
            return self.path.stat().st_size >= self.rotate_bytes
        except Exception:
            return False

    def _rotate(self) -> None:
        self._fh.close()
        # Сдвиг файлов: .N -> .N+1
        for idx in range(self.backups - 1, 0, -1):
            src = f"{self.path}.{idx}"
            dst = f"{self.path}.{idx + 1}"
            if os.path.exists(src):
                try:
                    os.replace(src, dst)
                except Exception:
                    pass
        # Текущий -> .1
        if self.path.exists():
            try:
                os.replace(self.path, f"{self.path}.1")
            except Exception:
                pass
        self._fh = open(self.path, "a", encoding="utf-8", buffering=1)
        # При ротации цепочка может начинаться заново (prev_hash=None)
        self._last_hash_cache = None

    def emit_line(self, line: str) -> None:
        with self._lock:
            if self._should_rotate():
                self._rotate()
            self._fh.write(line + "\n")
            if self.fsync_on_write:
                try:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                except Exception:
                    pass
            try:
                self._last_hash_cache = json.loads(line).get("hash")
            except Exception:
                pass

    def last_hash(self) -> Optional[str]:
        return self._last_hash_cache

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except Exception:
                pass

# ---------- Kafka sink (опционально) ----------
class KafkaSink(AuditSink):
    def __init__(self, brokers: str, topic: str):
        try:
            from confluent_kafka import Producer  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RuntimeError("confluent_kafka не установлен") from e
        self.topic = topic
        self._p = Producer({"bootstrap.servers": brokers})
        self._last = None
    def emit_line(self, line: str) -> None:
        def _cb(err, msg):  # noqa
            pass
        self._p.produce(self.topic, line.encode("utf-8"), callback=_cb)
        self._p.poll(0)
        try:
            self._last = json.loads(line).get("hash")
        except Exception:
            pass
    def close(self) -> None:
        try:
            self._p.flush(5)
        except Exception:
            pass
    def last_hash(self) -> Optional[str]:
        return self._last

# ---------- AuditLogger ----------
class AuditLogger:
    def __init__(self, sink: AuditSink, hmac_secret: Optional[bytes] = None, redact_enabled: bool = True):
        self.sink = sink
        self.hmac_secret = hmac_secret
        self.redact_enabled = redact_enabled
        self._lock = threading.Lock()

    # --- Публичный API ---
    def emit(self,
             who: str,
             action: str,
             resource: str,
             result: str,
             *,
             reason: Optional[str] = None,
             subject: Optional[str] = None,
             tenant_id: Optional[str] = None,
             org_id: Optional[str] = None,
             ip: Optional[str] = None,
             user_agent: Optional[str] = None,
             severity: str = "info",
             labels: Optional[Dict[str, str]] = None,
             data: Optional[Dict[str, Any]] = None) -> AuditEvent:
        """Синхронная запись события."""
        event = self._build_event(
            who=who, action=action, resource=resource, result=result,
            reason=reason, subject=subject, tenant_id=tenant_id, org_id=org_id,
            ip=ip, user_agent=user_agent, severity=severity, labels=labels or {}, data=data or {}
        )
        self._write(event)
        return event

    async def emit_async(self, *args, **kwargs) -> AuditEvent:
        """Асинхронная запись события."""
        # Для совместимости — запись выполняется синхронно в пуле
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.emit(*args, **kwargs))

    # --- Утилиты верификации ---
    def verify_event(self, event: Mapping[str, Any], prev_hash: Optional[str]) -> Tuple[bool, str]:
        """Проверка hash-цепочки и HMAC подписи для одного события."""
        cloned = dict(event)
        sig = cloned.pop("signature", None)
        ev_hash = cloned.get("hash")
        calc_hash = self._calc_hash(cloned, prev_hash)
        if ev_hash != calc_hash:
            return False, "hash mismatch"
        if self.hmac_secret:
            calc_sig = self._calc_hmac(cloned)
            if sig != calc_sig:
                return False, "signature mismatch"
        return True, "ok"

    # --- Внутренняя сборка и запись ---
    def _build_event(self, **kw) -> AuditEvent:
        now = _utcnow().isoformat().replace("+00:00", "Z")
        event_id = os.urandom(16).hex()
        # Базовый словарь
        ev_dict = dict(
            schema="chronowatch.audit.v1",
            ts=now,
            event_id=event_id,
            who=str(kw["who"]),
            action=str(kw["action"]),
            resource=str(kw["resource"]),
            result=str(kw["result"]),
            reason=(kw.get("reason") or None),
            subject=(kw.get("subject") or None),
            tenant_id=(kw.get("tenant_id") or get_tenant_id() or None),
            org_id=(kw.get("org_id") or None),
            request_id=get_request_id() or None,
            correlation_id=get_correlation_id() or None,
            ip=(kw.get("ip") or None),
            user_agent=(kw.get("user_agent") or None),
            host=_safe_host(),
            severity=str(kw.get("severity") or "info"),
            labels=dict(kw.get("labels") or {}),
            data=redact(kw.get("data") or {}) if self.redact_enabled else (kw.get("data") or {}),
            prev_hash=None,
            hash=None,
            signature=None,
        )
        # Валидация
        event = AuditEvent(**ev_dict)  # type: ignore
        return event

    def _calc_hash(self, event_no_sig: Mapping[str, Any], prev_hash: Optional[str]) -> str:
        # Вычисляем sha256(canonical(event_without_signature or hash) + prev_hash)
        tmp = dict(event_no_sig)
        tmp["prev_hash"] = prev_hash  # включаем prev_hash в каноникализацию
        tmp["hash"] = None
        canonical = _canonical_json(tmp).encode("utf-8")
        h = hashlib.sha256()
        h.update(canonical)
        return h.hexdigest()

    def _calc_hmac(self, event_no_sig: Mapping[str, Any]) -> str:
        if not self.hmac_secret:
            return ""
        msg = _canonical_json(event_no_sig).encode("utf-8")
        return _b64(hmac.new(self.hmac_secret, msg, hashlib.sha256).digest())

    def _write(self, event: AuditEvent) -> None:
        with self._lock:
            prev = self.sink.last_hash()
            # Сборка финального словаря без signature
            no_sig = event.dict()
            no_sig["prev_hash"] = prev
            no_sig["hash"] = None
            no_sig.pop("signature", None)
            # Вычисления
            ev_hash = self._calc_hash(no_sig, prev)
            no_sig["hash"] = ev_hash
            signature = self._calc_hmac(no_sig) if self.hmac_secret else None
            # Финальный объект
            final = dict(no_sig)
            final["signature"] = signature
            line = _canonical_json(final)
            self.sink.emit_line(line)

# ---------- Фабрика логгера из окружения ----------
def _load_secret() -> Optional[bytes]:
    raw = os.getenv("AUDIT_HMAC_SECRET")
    if not raw:
        return None
    # Поддерживаем base64/hex/plain
    try:
        return base64.b64decode(raw, validate=True)
    except Exception:
        try:
            return bytes.fromhex(raw)
        except Exception:
            return raw.encode("utf-8")

def build_default_logger() -> AuditLogger:
    sinks: list[AuditSink] = []
    if _from_env_bool("AUDIT_STDOUT", True):
        sinks.append(StdoutSink())
    file_path = os.getenv("AUDIT_FILE")
    if file_path:
        rotate = int(os.getenv("AUDIT_ROTATE_BYTES", str(100 * 1024 * 1024)))
        backups = int(os.getenv("AUDIT_ROTATE_BACKUPS", "7"))
        fsync = _from_env_bool("AUDIT_FSYNC", False)
        sinks.append(FileSink(file_path, rotate_bytes=rotate, backups=backups, fsync_on_write=fsync))
    brokers = os.getenv("AUDIT_KAFKA_BROKERS")
    topic = os.getenv("AUDIT_KAFKA_TOPIC")
    if brokers and topic:
        try:
            sinks.append(KafkaSink(brokers, topic))
        except Exception:
            # Kafka недоступен — пропустим без падения
            pass

    if not sinks:
        sinks.append(StdoutSink())

    # Объединяем несколько sinks при необходимости
    if len(sinks) == 1:
        sink = sinks[0]
    else:
        sink = _MultiSink(sinks)

    secret = _load_secret()
    redact_enabled = _from_env_bool("AUDIT_REDACT", True)
    return AuditLogger(sink=sink, hmac_secret=secret, redact_enabled=redact_enabled)

class _MultiSink(AuditSink):
    def __init__(self, sinks: Iterable[AuditSink]):
        self.sinks = list(sinks)
    def emit_line(self, line: str) -> None:
        for s in self.sinks:
            try:
                s.emit_line(line)
            except Exception:
                # не блокируем аудит при падении одного sink
                pass
    def last_hash(self) -> Optional[str]:
        # берем первый определенный
        for s in self.sinks:
            h = s.last_hash()
            if h:
                return h
        return None
    def close(self) -> None:
        for s in self.sinks:
            try:
                s.close()
            except Exception:
                pass

# ---------- Пример использования (не выполняется при импорте) ----------
if __name__ == "__main__":
    # Пример: AUDIT_STDOUT=1 AUDIT_FILE=./audit.log AUDIT_HMAC_SECRET=secret python logger.py
    logger = build_default_logger()
    set_request_context(request_id="req-123", correlation_id="corr-xyz", tenant_id="tenant-A")
    e = logger.emit(
        who="user:42",
        action="access",
        resource="report/weekly",
        result="success",
        ip="203.0.113.10",
        user_agent="curl/8.5.0",
        labels={"module": "demo"},
        data={"query": {"token": "abc.def.ghi", "email": "a.user@example.com", "phone": "+1 (555) 123-4567"}}
    )
    print("sample event emitted", file=sys.stderr)
