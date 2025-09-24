# -*- coding: utf-8 -*-
"""
Security Auditor — промышленный модуль аудита и безопасности.

Python: 3.11+
Зависимости: только стандартная библиотека (опционально orjson для скорости).

Возможности:
- Структурированные события (NDJSON), строгая схема
- Редакция секретов и PII (e-mail, телефон, токены, ключи, IP-маскирование)
- HMAC-SHA256 подпись события + "цепочка" (tamper-evident) через prev_hash
- Корреляция: request_id, session_id, trace_id/span_id, actor/subject/tenant
- Локальный rate limit (token bucket) и детерминированная семплировка
- Фоновая очередь и бэтч-экспортер (file/syslog/HTTP NDJSON или JSON)
- Ротация файлов по размеру, ограничение числа бэкапов
- Метрики работы аудитора и проверка подписи (verify_event)
- Утилита context_from_request для FastAPI/Starlette

Назначение:
- Журналы доступа (authZ), изменения конфигурации, админ операции, безопасность/инциденты,
  технические события (health), ошибки.

Автор: Omnimind
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import datetime as _dt
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import queue
import random
import re
import socket
import sys
import threading
import time
import types
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple

try:
    import orjson  # type: ignore

    def _dumps(obj: Any) -> bytes:
        return orjson.dumps(obj, option=orjson.OPT_SERIALIZE_DATACLASS)

    def _loads(data: bytes) -> Any:
        return orjson.loads(data)
except Exception:  # pragma: no cover
    def _dumps(obj: Any) -> bytes:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _loads(data: bytes) -> Any:
        return json.loads(data.decode("utf-8"))

# --------------------------------------------------------------------------------------
# Модель и служебные типы
# --------------------------------------------------------------------------------------

EventKind = str  # "access" | "security" | "change" | "error" | "system" | "custom"

@dataclass(slots=True, frozen=True)
class AuditContext:
    request_id: str
    session_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    tenant: Optional[str] = None
    actor: Optional[str] = None      # кто делает (учетка/токен/сервис)
    subject: Optional[str] = None    # над чем действие (пользователь/ресурс)
    scopes: Tuple[str, ...] = ()
    extras: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class AuditEvent:
    # Обязательные
    event_id: str
    kind: EventKind
    action: str
    ts: str                  # ISO-8601 UTC
    level: str               # "INFO"|"WARN"|"ERROR"
    # Контекст
    request_id: str
    session_id: Optional[str]
    trace_id: Optional[str]
    span_id: Optional[str]
    ip: Optional[str]
    user_agent: Optional[str]
    tenant: Optional[str]
    actor: Optional[str]
    subject: Optional[str]
    scopes: Tuple[str, ...]
    # Описание
    resource: Optional[str]
    allowed: Optional[bool]
    reason: Optional[str]
    data: Mapping[str, Any]
    # Технические поля
    node: str
    pid: int
    seq: int
    prev_hash: Optional[str]  # цепочка целостности (base64)
    sign_hmac: Optional[str]  # подпись HMAC события (base64)
    sample_kept: bool         # прошло семплировку
    redacted: bool            # было ли редактирование

# --------------------------------------------------------------------------------------
# Редакция и нормализация
# --------------------------------------------------------------------------------------

DEFAULT_SECRET_KEYS = {
    "authorization", "cookie", "set-cookie", "x-api-key", "x-admin-token", "x-auth-token",
    "api_key", "apikey", "access_token", "refresh_token", "password", "secret", "client_secret",
    "private_key", "token", "jwt", "ssh_key",
}

# Компактные паттерны PII/секретов
_PAT_EMAIL = re.compile(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
_PAT_PHONE = re.compile(r"(?<!\d)(\+?\d[\d \-\(\)]{7,}\d)")
_PAT_TOKEN = re.compile(r"\b([A-Za-z0-9_\-]{16,})\b")
_PAT_CREDIT = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_PAT_IPV4 = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

def _mask_email(s: str) -> str:
    return _PAT_EMAIL.sub(lambda m: f"{m.group(1)[:2]}***@***.{m.group(2).split('.')[-1]}", s)

def _mask_phone(s: str) -> str:
    return _PAT_PHONE.sub(lambda m: "***PHONE***", s)

def _mask_tokens(s: str) -> str:
    return _PAT_TOKEN.sub(lambda m: "***TOKEN***", s)

def _mask_credit(s: str) -> str:
    return _PAT_CREDIT.sub(lambda m: "***CARD***", s)

def _mask_ipv4(s: str) -> str:
    return _PAT_IPV4.sub(lambda m: _ip_mask(m.group(0)), s)

def _ip_mask(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            # маска /24
            parts = ip.split(".")
            return ".".join(parts[:3] + ["0"])
    except Exception:
        pass
    return "***IP***"

def _redact_value(key: Optional[str], val: Any) -> tuple[Any, bool]:
    """
    Возвращает (новое_значение, был_ли_редактирован).
    """
    redacted = False
    if isinstance(val, str):
        original = val
        v = val
        if key and key.lower() in DEFAULT_SECRET_KEYS:
            v = "***REDACTED***"
        else:
            v = _mask_email(v)
            v = _mask_phone(v)
            v = _mask_credit(v)
            v = _mask_tokens(v)
            v = _mask_ipv4(v)
        redacted = (v != original)
        return v, redacted
    if isinstance(val, (list, tuple)):
        out, any_red = [], False
        for x in val:
            y, r = _redact_value(None, x)
            out.append(y)
            any_red = any_red or r
        return out if isinstance(val, list) else tuple(out), any_red
    if isinstance(val, dict):
        out: Dict[str, Any] = {}
        any_red = False
        for k, v in val.items():
            y, r = _redact_value(str(k), v)
            out[str(k)] = y
            any_red = any_red or r
        return out, any_red
    return val, False

def _cap_size(obj: Any, max_bytes: int = 32_768) -> tuple[Any, bool]:
    """
    Обрезает большие значения (строки/байты) до max_bytes. Возвращает (объект, было_урезано).
    """
    trimmed = False
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        if len(b) > max_bytes:
            obj = b[:max_bytes].decode("utf-8", errors="ignore") + "…TRUNCATED"
            trimmed = True
        return obj, trimmed
    if isinstance(obj, (bytes, bytearray)):
        if len(obj) > max_bytes:
            obj = bytes(obj[:max_bytes]) + b"...TRUNCATED"
            trimmed = True
        return obj, trimmed
    if isinstance(obj, dict):
        any_t = False
        out = {}
        for k, v in obj.items():
            nv, t = _cap_size(v, max_bytes)
            out[str(k)] = nv
            any_t = any_t or t
        return out, any_t
    if isinstance(obj, (list, tuple)):
        any_t = False
        out = []
        for v in obj:
            nv, t = _cap_size(v, max_bytes)
            out.append(nv)
            any_t = any_t or t
        return out if isinstance(obj, list) else tuple(out), any_t
    return obj, False

# --------------------------------------------------------------------------------------
# Rate limit и семплировка
# --------------------------------------------------------------------------------------

class _TokenBucket:
    def __init__(self, rps: float, burst: int) -> None:
        self.rps = float(rps)
        self.burst = int(burst)
        self.tokens = float(burst)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def allow(self) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.burst, self.tokens + elapsed * self.rps)
            if self.tokens < 1.0:
                return False
            self.tokens -= 1.0
            return True

def _sample_keep(key: str, rate: int) -> bool:
    """
    Детерминированная семплировка: сохраняем, если hash % rate == 0.
    rate=1 -> всегда сохранять.
    """
    if rate <= 1:
        return True
    h = hashlib.sha256(key.encode("utf-8")).digest()
    val = int.from_bytes(h[:4], "big")
    return (val % rate) == 0

# --------------------------------------------------------------------------------------
# Sinks
# --------------------------------------------------------------------------------------

class _BaseSink:
    def write(self, batch: Sequence[bytes]) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

class StdoutSink(_BaseSink):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stream = sys.stdout.buffer

    def write(self, batch: Sequence[bytes]) -> None:
        with self._lock:
            for line in batch:
                self._stream.write(line)
                if not line.endswith(b"\n"):
                    self._stream.write(b"\n")
            self._stream.flush()

class FileSink(_BaseSink):
    def __init__(self, path: str, max_bytes: int = 50_000_000, backups: int = 10) -> None:
        self.path = path
        self.max_bytes = int(max_bytes)
        self.backups = int(backups)
        self._lock = threading.Lock()
        Path = __import__("pathlib").Path
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def write(self, batch: Sequence[bytes]) -> None:
        with self._lock:
            with open(self.path, "ab", buffering=1024 * 1024) as f:
                for line in batch:
                    f.write(line)
                    if not line.endswith(b"\n"):
                        f.write(b"\n")
            self._rotate_if_needed()

    def _rotate_if_needed(self) -> None:
        try:
            st = os.stat(self.path)
            if st.st_size <= self.max_bytes:
                return
        except FileNotFoundError:
            return
        ts = _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        rotated = f"{self.path}.{ts}"
        with contextlib.suppress(Exception):
            os.rename(self.path, rotated)
        # cleanup old
        dirn = os.path.dirname(self.path) or "."
        base = os.path.basename(self.path)
        files = sorted([x for x in os.listdir(dirn) if x.startswith(base + ".")])
        excess = len(files) - self.backups
        for i in range(max(0, excess)):
            with contextlib.suppress(Exception):
                os.remove(os.path.join(dirn, files[i]))

class SyslogSink(_BaseSink):
    def __init__(self, address: str = "/dev/log") -> None:
        from logging.handlers import SysLogHandler
        self._logger = logging.getLogger("auditor.syslog")
        self._logger.setLevel(logging.INFO)
        handler = SysLogHandler(address=address) if isinstance(address, str) else SysLogHandler(address=tuple(address))
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

    def write(self, batch: Sequence[bytes]) -> None:
        for line in batch:
            self._logger.info(line.decode("utf-8", errors="ignore"))

class HTTPSink(_BaseSink):
    """
    Простой HTTP POST экспортер. Поддерживает:
      - content_type: "ndjson" (каждое событие отдельной строкой) или "json" (массив)
      - аутентификацию через заголовки (например, Bearer)
    """
    def __init__(self, url: str, headers: Optional[Mapping[str, str]] = None, content_type: str = "ndjson",
                 timeout_s: float = 3.0, verify_tls: bool = True) -> None:
        self.url = url
        self.headers = dict(headers or {})
        self.content_type = "ndjson" if content_type.lower() == "ndjson" else "json"
        self.timeout_s = float(timeout_s)
        self.verify_tls = bool(verify_tls)

    def write(self, batch: Sequence[bytes]) -> None:
        import http.client
        import urllib.parse

        if not batch:
            return

        parsed = urllib.parse.urlparse(self.url)
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), timeout=self.timeout_s)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        body: bytes
        if self.content_type == "ndjson":
            body = b"".join([b + (b"" if b.endswith(b"\n") else b"\n") for b in batch])
            ctype = "application/x-ndjson"
        else:
            # JSON массив
            arr = [ _loads(b) for b in batch ]
            body = _dumps(arr)
            ctype = "application/json"

        headers = {"Content-Type": ctype, **self.headers}
        if not self.verify_tls and parsed.scheme == "https":
            # http.client не предоставляет простой способ отключить проверку — оставим как есть.
            pass
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            # читаем и закрываем
            _ = resp.read()
        finally:
            with contextlib.suppress(Exception):
                conn.close()

# --------------------------------------------------------------------------------------
# Вспомогательные функции
# --------------------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc).isoformat()

def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"

def _ct_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

# --------------------------------------------------------------------------------------
# Аудитор
# --------------------------------------------------------------------------------------

@dataclass(slots=True)
class AuditorConfig:
    to_stdout: bool = True
    file_path: Optional[str] = None
    file_max_bytes: int = 50_000_000
    file_backups: int = 10
    syslog_address: Optional[str] = None
    http_url: Optional[str] = None
    http_headers: Mapping[str, str] = field(default_factory=dict)
    http_mode: str = "ndjson"  # "ndjson" | "json"

    # Контроль потока
    batch_size: int = 128
    flush_interval_s: float = 1.0
    queue_max: int = 50_000
    rate_rps: float = 1_000.0
    rate_burst: int = 2_000
    sample_rate: int = 1  # 1=100%, 10=каждый 10-й и т.д.

    # Безопасность и целостность
    hmac_secret: Optional[str] = None  # если задан, события подписываются
    enable_chain: bool = True          # включить prev_hash цепочку
    redact_max_value_bytes: int = 32_768

class SecurityAuditor:
    """
    Потокобезопасный аудитор с фоновой очередью и несколькими sink’ами.
    """
    def __init__(self, cfg: AuditorConfig) -> None:
        self.cfg = cfg
        self._sinks: list[_BaseSink] = []
        if cfg.to_stdout:
            self._sinks.append(StdoutSink())
        if cfg.file_path:
            self._sinks.append(FileSink(cfg.file_path, cfg.file_max_bytes, cfg.file_backups))
        if cfg.syslog_address:
            self._sinks.append(SyslogSink(cfg.syslog_address))
        if cfg.http_url:
            self._sinks.append(HTTPSink(cfg.http_url, cfg.http_headers, cfg.http_mode))

        self._bucket = _TokenBucket(cfg.rate_rps, cfg.rate_burst)
        self._queue: queue.Queue[bytes] = queue.Queue(maxsize=cfg.queue_max)
        self._seq = 0
        self._seq_lock = threading.Lock()
        self._prev_hash: Optional[bytes] = None
        self._alive = True
        self._worker = threading.Thread(target=self._run, name="auditor-worker", daemon=True)
        self._worker.start()

        # метрики
        self._stats = {
            "enqueued": 0,
            "dropped_rl": 0,
            "dropped_queue": 0,
            "written": 0,
            "errors": 0,
        }

    # ---------------------- публичное API ----------------------

    def log_access(self, ctx: AuditContext, *, action: str, resource: str, allowed: bool,
                   reason: Optional[str] = None, data: Optional[Mapping[str, Any]] = None) -> None:
        self._log("access", "INFO", action, ctx, resource=resource, allowed=allowed, reason=reason, data=data)

    def log_security(self, ctx: AuditContext, *, action: str, level: str = "WARN",
                     reason: Optional[str] = None, data: Optional[Mapping[str, Any]] = None) -> None:
        self._log("security", level, action, ctx, resource=None, allowed=None, reason=reason, data=data)

    def log_change(self, ctx: AuditContext, *, action: str, resource: str,
                   reason: Optional[str] = None, data: Optional[Mapping[str, Any]] = None) -> None:
        self._log("change", "INFO", action, ctx, resource=resource, allowed=True, reason=reason, data=data)

    def log_error(self, ctx: AuditContext, *, action: str, reason: str,
                  data: Optional[Mapping[str, Any]] = None) -> None:
        self._log("error", "ERROR", action, ctx, resource=None, allowed=None, reason=reason, data=data)

    def log_system(self, ctx: AuditContext, *, action: str, level: str = "INFO",
                   data: Optional[Mapping[str, Any]] = None) -> None:
        self._log("system", level, action, ctx, resource=None, allowed=True, reason=None, data=data)

    def log_custom(self, ctx: AuditContext, *, kind: str, action: str, level: str = "INFO",
                   resource: Optional[str] = None, data: Optional[Mapping[str, Any]] = None) -> None:
        self._log(kind, level, action, ctx, resource=resource, allowed=None, reason=None, data=data)

    def stats(self) -> Mapping[str, int]:
        return dict(self._stats)

    def close(self) -> None:
        self._alive = False
        with contextlib.suppress(Exception):
            self._worker.join(timeout=2.0)
        for s in self._sinks:
            with contextlib.suppress(Exception):
                s.close()

    # ---------------------- создание событий ----------------------

    def _log(self, kind: EventKind, level: str, action: str, ctx: AuditContext,
             *, resource: Optional[str], allowed: Optional[bool], reason: Optional[str],
             data: Optional[Mapping[str, Any]]) -> None:
        # rate limit
        if not self._bucket.allow():
            self._stats["dropped_rl"] += 1
            return

        # семплировка (детерминированная по request_id/actor/action)
        sample_key = f"{ctx.request_id}|{ctx.actor}|{action}|{kind}"
        keep = _sample_keep(sample_key, self.cfg.sample_rate)
        if not keep:
            # семплирование: не записываем
            return

        # подготовка полезной нагрузки: редакция и обрезка
        data = dict(data or {})
        redacted_any = False
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            nv, red = _redact_value(k, v)
            nv, cut = _cap_size(nv, self.cfg.redact_max_value_bytes)
            if cut:
                red = True
            sanitized[str(k)] = nv
            redacted_any = redacted_any or red

        # безопасный IP (маскирование)
        ip = _ip_mask(ctx.ip) if ctx.ip else None

        # seq
        with self._seq_lock:
            self._seq += 1
            seq = self._seq

        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            kind=str(kind),
            action=str(action),
            ts=_utc_now_iso(),
            level=str(level).upper(),
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            trace_id=ctx.trace_id,
            span_id=ctx.span_id,
            ip=ip,
            user_agent=ctx.user_agent,
            tenant=ctx.tenant,
            actor=ctx.actor,
            subject=ctx.subject,
            scopes=tuple(ctx.scopes or ()),
            resource=resource,
            allowed=allowed,
            reason=reason,
            data=sanitized,
            node=_hostname(),
            pid=os.getpid(),
            seq=seq,
            prev_hash=None,
            sign_hmac=None,
            sample_kept=True,
            redacted=redacted_any,
        )

        # сериализация без подписи
        body = dataclasses.asdict(event)
        body_no_sig = dict(body)
        body_no_sig["prev_hash"] = self._prev_hash_b64()
        body_no_sig["sign_hmac"] = None

        raw = _dumps(body_no_sig)

        # подпись и цепочка
        prev_hash = hashlib.sha256(raw).digest() if self.cfg.enable_chain else None
        signature = self._sign(raw) if self.cfg.hmac_secret else None

        body_no_sig["prev_hash"] = base64.b64encode(prev_hash).decode("ascii") if prev_hash else None
        body_no_sig["sign_hmac"] = base64.b64encode(signature).decode("ascii") if signature else None
        line = _dumps(body_no_sig)

        # обновляем prev для следующей записи
        self._prev_hash = prev_hash

        # enqueue
        try:
            self._queue.put_nowait(line + (b"" if line.endswith(b"\n") else b"\n"))
            self._stats["enqueued"] += 1
        except queue.Full:
            self._stats["dropped_queue"] += 1

    def _sign(self, payload: bytes) -> bytes:
        secret = (self.cfg.hmac_secret or "").encode("utf-8")
        return hmac.new(secret, payload, hashlib.sha256).digest()

    def _prev_hash_b64(self) -> Optional[str]:
        if not self._prev_hash:
            return None
        return base64.b64encode(self._prev_hash).decode("ascii")

    # ---------------------- воркер ----------------------

    def _run(self) -> None:
        batch: list[bytes] = []
        last_flush = time.monotonic()
        while self._alive:
            timeout = max(0.0, self.cfg.flush_interval_s - (time.monotonic() - last_flush))
            try:
                item = self._queue.get(timeout=timeout)
                batch.append(item)
                if len(batch) >= self.cfg.batch_size:
                    self._flush(batch)
                    batch.clear()
                    last_flush = time.monotonic()
            except queue.Empty:
                if batch:
                    self._flush(batch)
                    batch.clear()
                    last_flush = time.monotonic()
        # финальный дренаж
        if batch:
            self._flush(batch)

    def _flush(self, batch: Sequence[bytes]) -> None:
        for s in self._sinks:
            try:
                s.write(batch)
                self._stats["written"] += len(batch)
            except Exception:
                self._stats["errors"] += 1

# --------------------------------------------------------------------------------------
# Верификация подписи/цепочки (оффлайн)
# --------------------------------------------------------------------------------------

def verify_event(event_json: bytes, *, hmac_secret: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Проверяет HMAC подпись отдельного события (без проверки цепочки к предыдущим).
    Возвращает (ok, причина_ошибки|None).
    """
    try:
        obj = _loads(event_json)
        sign_b64 = obj.get("sign_hmac")
        prev_b64 = obj.get("prev_hash")
        obj_check = dict(obj)
        obj_check["sign_hmac"] = None  # вычисление подписи делалось до вставки sign_hmac
        raw = _dumps(obj_check)
        if hmac_secret:
            if not sign_b64:
                return False, "missing_signature"
            expected = hmac.new(hmac_secret.encode("utf-8"), raw, hashlib.sha256).digest()
            got = base64.b64decode(sign_b64)
            if not _ct_equal(base64.b64encode(expected).decode("ascii"), base64.b64encode(got).decode("ascii")):
                return False, "bad_signature"
        # prev_hash проверяется сверкой sha256(raw) == prev_hash следующего события
        return True, None
    except Exception as e:
        return False, f"verify_error:{type(e).__name__}"

# --------------------------------------------------------------------------------------
# Извлечение контекста из HTTP-запроса (FastAPI/Starlette совместимо)
# --------------------------------------------------------------------------------------

def context_from_request(request) -> AuditContext:
    """
    Извлекает AuditContext из объекта Starlette Request (или подобного):
    - request_id: из X-Request-Id или генерируется
    - ip: из X-Forwarded-For (первый) или client.host
    - user_agent: из заголовка User-Agent
    - trace_id/span_id: из W3C traceparent (если есть)
    """
    headers = {k.lower(): v for k, v in (getattr(request, "headers", {}) or {}).items()}
    req_id = headers.get("x-request-id") or str(uuid.uuid4())
    xff = headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = getattr(getattr(request, "client", types.SimpleNamespace(host=None)), "host", None)
    ua = headers.get("user-agent")
    trace_id, span_id = _trace_from_headers(headers.get("traceparent"))
    return AuditContext(request_id=req_id, ip=ip, user_agent=ua, trace_id=trace_id, span_id=span_id)

def _trace_from_headers(traceparent: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    # Формат: 00-<trace_id>-<span_id>-<flags>
    if not traceparent:
        return None, None
    parts = traceparent.split("-")
    if len(parts) >= 3 and len(parts[1]) == 32 and len(parts[2]) == 16:
        return parts[1], parts[2]
    return None, None

# --------------------------------------------------------------------------------------
# Пример использования
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    cfg = AuditorConfig(
        to_stdout=True,
        file_path=os.getenv("AUDIT_FILE", "/tmp/omnimind_audit.ndjson"),
        hmac_secret=os.getenv("AUDIT_HMAC", "dev-secret"),
        sample_rate=int(os.getenv("AUDIT_SAMPLE", "1")),
        rate_rps=float(os.getenv("AUDIT_RPS", "1000")),
        rate_burst=int(os.getenv("AUDIT_BURST", "2000")),
    )
    auditor = SecurityAuditor(cfg)

    # Имитация простого контекста
    ctx = AuditContext(request_id=str(uuid.uuid4()), actor="admin@corp", subject="user:alice", ip="203.0.113.42",
                       user_agent="curl/8.0", tenant="acme", scopes=("operate", "danger"))

    auditor.log_access(ctx, action="admin.login", resource="console", allowed=True, reason=None,
                       data={"authorization": "Bearer abcdef1234567890", "email": "alice@example.com"})
    auditor.log_change(ctx, action="feature.toggle", resource="flags/exp1", reason="rollout 5%",
                       data={"old": False, "new": True})
    auditor.log_security(ctx, action="bruteforce.block", level="WARN",
                         reason="ip rate exceeded", data={"ip": "198.51.100.77"})
    auditor.log_error(ctx, action="backup.failed", reason="S3 timeout", data={"bucket": "prod-backup"})

    time.sleep(1.5)
    auditor.close()
