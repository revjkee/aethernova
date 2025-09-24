"""
security-core.audit.logger — промышленный аудит-логгер.

Возможности:
- Структурированные события (JSON Lines), канонизация и ISO8601.
- Маскирование чувствительных полей (PII/SPII) и токенов.
- Контекст через contextvars: tenant/principal/ip/ua/request_id/correlation_id/trace_id.
- Очередь и фоновая батчевая запись с бэкпрешером.
- Синки: StdoutJSONLSink, JsonlFileSink (ротация + gzip), SQLiteSink.
- Криптографическая цепочка целостности: HMAC-SHA256, поля chain.prev/chain.sig/chain.kid/chain.alg/seq.
- Идемпотентность по event_id (опциональный кэш в памяти).
- Декоратор @audit_action для автологирования операций.
- Без внешних зависимостей (кроме sqlite3 из stdlib).

Примечание:
- Это модуль инфраструктуры; используйте его в API-роутерах/сервисах, подавая события через AuditLogger.emit().
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import io
import json
import os
import queue
import sqlite3
import sys
import threading
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Callable

# ============================ Константы/типы ============================

ISO_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"

class Outcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ERROR = "ERROR"

# Набор примеров действий — расширяйте под домен
class AuditAction(str, Enum):
    AUTH_LOGIN = "AUTH_LOGIN"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    SESSION_REVOKE = "SESSION_REVOKE"
    USER_CREATE = "USER_CREATE"
    USER_UPDATE = "USER_UPDATE"
    USER_DEACTIVATE = "USER_DEACTIVATE"
    ROLE_ASSIGN = "ROLE_ASSIGN"
    APIKEY_CREATE = "APIKEY_CREATE"
    APIKEY_REVOKE = "APIKEY_REVOKE"
    SECRET_PUT = "SECRET_PUT"
    SECRET_ROTATE = "SECRET_ROTATE"
    KEY_SIGN = "KEY_SIGN"
    CERT_ISSUE = "CERT_ISSUE"
    CERT_REVOKE = "CERT_REVOKE"
    ALERT_ACK = "ALERT_ACK"
    INCIDENT_CREATE = "INCIDENT_CREATE"

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# ============================ Контекст запроса ==========================

_ctx_tenant: ContextVar[Optional[str]] = ContextVar("audit_tenant", default=None)
_ctx_principal: ContextVar[Optional[str]] = ContextVar("audit_principal", default=None)
_ctx_ip: ContextVar[Optional[str]] = ContextVar("audit_ip", default=None)
_ctx_ua: ContextVar[Optional[str]] = ContextVar("audit_ua", default=None)
_ctx_reqid: ContextVar[Optional[str]] = ContextVar("audit_request_id", default=None)
_ctx_corr: ContextVar[Optional[str]] = ContextVar("audit_correlation_id", default=None)
_ctx_trace: ContextVar[Optional[str]] = ContextVar("audit_trace_id", default=None)
_ctx_span: ContextVar[Optional[str]] = ContextVar("audit_span_id", default=None)

def bind_context(
    *,
    tenant_id: Optional[str] = None,
    principal_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
) -> None:
    if tenant_id is not None: _ctx_tenant.set(tenant_id)
    if principal_id is not None: _ctx_principal.set(principal_id)
    if ip is not None: _ctx_ip.set(ip)
    if user_agent is not None: _ctx_ua.set(user_agent)
    if request_id is not None: _ctx_reqid.set(request_id)
    if correlation_id is not None: _ctx_corr.set(correlation_id)
    if trace_id is not None: _ctx_trace.set(trace_id)
    if span_id is not None: _ctx_span.set(span_id)

# ============================ Маскирование ==============================

_DEFAULT_MASK_KEYS = {
    "password", "secret", "token", "access_token", "refresh_token",
    "authorization", "api_key", "apikey", "key", "private_key",
    "ssn", "card", "pan", "email",
}

def _mask_value(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        # Email: a****@d****
        if "@" in v and "." in v.split("@")[-1]:
            name, dom = v.split("@", 1)
            return (name[:1] + "****" if name else "****") + "@" + (dom[:1] + "****")
        # Числа карточек/токены: оставим 4 хвостовых
        if any(ch.isdigit() for ch in v) and len(v) >= 6:
            return "***" + v[-4:]
        # По умолчанию
        return "****"
    if isinstance(v, (bytes, bytearray)):
        return b"****"
    if isinstance(v, (list, tuple)):
        return [ _mask_value(x) for x in v ]
    if isinstance(v, dict):
        return { k: _mask_value(x) for k, x in v.items() }
    return "****"

def redact(details: Optional[Dict[str, Any]], extra_secret_keys: Optional[Iterable[str]] = None) -> Optional[Dict[str, Any]]:
    if not details:
        return details
    secret_keys = set(_DEFAULT_MASK_KEYS)
    if extra_secret_keys:
        secret_keys |= set(map(str, extra_secret_keys))
    def _walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if str(k).lower() in secret_keys:
                    out[k] = _mask_value(v)
                else:
                    out[k] = _walk(v)
            return out
        if isinstance(obj, list):
            return [ _walk(x) for x in obj ]
        return obj
    return _walk(details)

# ============================ Подпись/цепочка ==========================

class KeyProvider(Protocol):
    def get_key(self) -> Tuple[str, bytes]: ...
    # Возвращает (kid, key_bytes)

@dataclass
class EnvHmacKeyProvider:
    env_var: str = "SECURITY_CORE_AUDIT_HMAC_KEY"
    def get_key(self) -> Tuple[str, bytes]:
        v = os.getenv(self.env_var)
        if not v:
            raise RuntimeError(f"Missing env {self.env_var}")
        key = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
        if len(key) < 16:
            raise RuntimeError("HMAC key is too short (min 16 bytes)")
        return (f"env:{self.env_var}", key)

@dataclass
class ChainState:
    seq: int = 0
    prev_sig: bytes = b""
    tail_path: Optional[Path] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def load_tail(self) -> None:
        if not self.tail_path or not self.tail_path.exists():
            return
        try:
            d = json.loads(self.tail_path.read_text("utf-8"))
            self.seq = int(d.get("seq", 0))
            self.prev_sig = base64.urlsafe_b64decode(d.get("prev", ""))
        except Exception:
            # Начинаем новую цепочку
            self.seq, self.prev_sig = 0, b""

    def store_tail(self) -> None:
        if not self.tail_path:
            return
        tmp = self.tail_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seq": self.seq, "prev": base64.urlsafe_b64encode(self.prev_sig).decode("ascii")}), "utf-8")
        os.replace(tmp, self.tail_path)

    def sign(self, key: bytes, event_hash: bytes) -> Tuple[int, bytes, bytes]:
        with self._lock:
            seq = self.seq + 1
            msg = self.prev_sig + event_hash
            sig = hmac.new(key, msg, "sha256").digest()
            # обновляем хвост
            self.seq = seq
            self.prev_sig = sig
            self.store_tail()
            return seq, self.prev_sig, sig  # prev_sig == current after update

# ============================ Событие/сериализация =====================

def _iso8601(ts: float) -> str:
    # Простой формат UTC
    return time.strftime(ISO_FMT, time.gmtime(ts))

@dataclass
class AuditEvent:
    id: str
    time: float
    ts: str
    action: str
    outcome: str
    severity: str
    tenant_id: Optional[str]
    actor_id: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip: Optional[str]
    user_agent: Optional[str]
    request_id: Optional[str]
    correlation_id: Optional[str]
    trace_id: Optional[str]
    span_id: Optional[str]
    details: Optional[Dict[str, Any]]
    seq: int
    chain: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

def _canonical_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

# ============================ Синки (вывод) ============================

class AuditSink(Protocol):
    def write_batch(self, batch: List[Dict[str, Any]]) -> None: ...
    def flush(self) -> None: ...
    def close(self) -> None: ...

class StdoutJSONLSink:
    def write_batch(self, batch: List[Dict[str, Any]]) -> None:
        out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", write_through=True)
        for item in batch:
            out.write(json.dumps(item, ensure_ascii=False) + "\n")
    def flush(self) -> None:
        sys.stdout.flush()
    def close(self) -> None:
        try:
            sys.stdout.flush()
        except Exception:
            pass

class JsonlFileSink:
    def __init__(self, path: str, max_bytes: int = 50 * 1024 * 1024, backups: int = 5, compress: bool = True):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self.compress = compress
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "ab", buffering=0)

    def _rotate(self) -> None:
        try:
            self._fh.flush()
        except Exception:
            pass
        self._fh.close()
        # сдвиг резервных
        for i in range(self.backups - 1, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{i}")
            dst = self.path.with_suffix(self.path.suffix + f".{i+1}")
            if src.exists():
                if dst.exists():
                    dst.unlink()
                src.rename(dst)
        # текущий -> .1 (с компрессией)
        rot = self.path.with_suffix(self.path.suffix + ".1")
        if rot.exists():
            rot.unlink()
        self.path.rename(rot)
        if self.compress:
            with open(rot, "rb") as f_in, gzip.open(str(rot) + ".gz", "wb") as f_out:
                f_out.writelines(f_in)
            rot.unlink()
        # открыть новый
        self._fh = open(self.path, "ab", buffering=0)

    def write_batch(self, batch: List[Dict[str, Any]]) -> None:
        b = ("\n".join(json.dumps(x, ensure_ascii=False) for x in batch) + "\n").encode("utf-8")
        with self._lock:
            if self._fh.tell() + len(b) > self.max_bytes:
                self._rotate()
            self._fh.write(b)

    def flush(self) -> None:
        with self._lock:
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
            finally:
                self._fh.close()

class SQLiteSink:
    """
    Простой sink в SQLite: таблица audit_events(id TEXT PRIMARY KEY, ts REAL, json TEXT).
    """
    def __init__(self, db_path: str):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=30.0)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, ts REAL NOT NULL, json TEXT NOT NULL)")
        self._lock = threading.Lock()

    def write_batch(self, batch: List[Dict[str, Any]]) -> None:
        rows = [(x["id"], x["time"], json.dumps(x, ensure_ascii=False)) for x in batch]
        with self._lock, self._conn:
            self._conn.executemany("INSERT OR REPLACE INTO audit_events(id, ts, json) VALUES(?,?,?)", rows)

    def flush(self) -> None:
        with self._lock:
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
            finally:
                self._conn.close()

# ============================ Основной логгер ===========================

@dataclass
class AuditLoggerConfig:
    sinks: List[AuditSink]
    key_provider: KeyProvider
    tail_file: Optional[str] = None           # хранит seq/prev для цепочки между рестартами
    queue_maxsize: int = 10000
    batch_size: int = 200
    flush_interval_sec: float = 1.0
    redact_extra_keys: Tuple[str, ...] = tuple()
    dedupe_seconds: int = 5                   # идемпотентность событий по id
    drop_on_overflow: bool = True             # True: дропаем старое при заполнении
    include_iso_ts: bool = True

class AuditLogger:
    def __init__(self, cfg: AuditLoggerConfig):
        self.cfg = cfg
        self._q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=cfg.queue_maxsize)
        self._worker = threading.Thread(target=self._run, name="audit-worker", daemon=True)
        self._stop = threading.Event()
        self._chain = ChainState(seq=0, prev_sig=b"", tail_path=Path(cfg.tail_file) if cfg.tail_file else None)
        self._chain.load_tail()
        self._dedupe: Dict[str, float] = {}
        self._dedupe_lock = threading.Lock()
        self._worker.start()

    # -------------------- Публичный API --------------------

    def emit(
        self,
        *,
        action: AuditAction | str,
        outcome: Outcome | str,
        severity: Severity | str = Severity.LOW,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        event_id: Optional[str] = None,
        extra_redact_keys: Optional[Iterable[str]] = None,
    ) -> str:
        """
        Создать и поставить событие в очередь. Возвращает event_id.
        """
        now = time.time()
        eid = event_id or ("evt-" + uuid.uuid4().hex)
        # идемпотентность (короткое окно)
        if self._is_duplicate(eid, now):
            return eid

        # Составим базовый словарь (без chain/seq)
        tenant = tenant_id if tenant_id is not None else _ctx_tenant.get()
        actor = actor_id if actor_id is not None else _ctx_principal.get()
        base = {
            "id": eid,
            "time": now,
            "ts": _iso8601(now) if self.cfg.include_iso_ts else None,
            "action": action.value if isinstance(action, AuditAction) else str(action),
            "outcome": outcome.value if isinstance(outcome, Outcome) else str(outcome),
            "severity": severity.value if isinstance(severity, Severity) else str(severity),
            "tenant_id": tenant,
            "actor_id": actor,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "ip": _ctx_ip.get(),
            "user_agent": _ctx_ua.get(),
            "request_id": _ctx_reqid.get(),
            "correlation_id": _ctx_corr.get(),
            "trace_id": _ctx_trace.get(),
            "span_id": _ctx_span.get(),
        }
        if base["ts"] is None:
            base.pop("ts")

        # Маскирование
        red_keys = set(self.cfg.redact_extra_keys)
        if extra_redact_keys:
            red_keys |= set(map(str, extra_redact_keys))
        base["details"] = redact(details, extra_secret_keys=red_keys)

        # Хэш + подпись + цепочка
        kid, key = self.cfg.key_provider.get_key()
        # Хэш по каноническому представлению без seq/chain
        event_core = _canonical_json(base)
        event_hash = hashlib.sha256(event_core).digest()
        seq, prev_sig, sig = self._chain.sign(key, event_hash)
        chain = {
            "alg": "HMAC-SHA256",
            "kid": kid,
            "prev": base64.urlsafe_b64encode(prev_sig).decode("ascii"),
            "sig": base64.urlsafe_b64encode(sig).decode("ascii"),
            "hash": hashlib.sha256(sig).hexdigest(),  # дополнительный контрольный отпечаток
        }

        full = dict(base)
        full["seq"] = seq
        full["chain"] = chain

        # Поставим в очередь с защитой от переполнения
        self._enqueue(full)
        return eid

    def flush(self) -> None:
        for s in self.cfg.sinks:
            try:
                s.flush()
            except Exception:
                pass

    def close(self) -> None:
        self._stop.set()
        self._worker.join(timeout=2.0)
        self.flush()
        for s in self.cfg.sinks:
            try:
                s.close()
            except Exception:
                pass

    # -------------------- Декоратор --------------------

    def audit_action(
        self,
        action: AuditAction | str,
        *,
        severity: Severity | str = Severity.LOW,
        resource_type: Optional[str] = None,
        resource_id_getter: Optional[Callable[..., Optional[str]]] = None,
        details_getter: Optional[Callable[..., Dict[str, Any]]] = None,
    ):
        """
        Декоратор для функций/эндпоинтов:
        @audit.audit_action(AuditAction.USER_UPDATE, resource_type="USER", resource_id_getter=lambda *a, **kw: kw.get("user_id"))
        """
        def _decor(fn: Callable[..., Any]) -> Callable[..., Any]:
            def _wrap(*args: Any, **kwargs: Any) -> Any:
                try:
                    res = fn(*args, **kwargs)
                    rid = resource_id_getter(*args, **kwargs) if resource_id_getter else None
                    det = details_getter(*args, **kwargs) if details_getter else None
                    self.emit(
                        action=action,
                        outcome=Outcome.ALLOW,
                        severity=severity,
                        resource_type=resource_type,
                        resource_id=rid,
                        details=det,
                    )
                    return res
                except Exception as e:
                    rid = resource_id_getter(*args, **kwargs) if resource_id_getter else None
                    det = (details_getter(*args, **kwargs) if details_getter else {}) or {}
                    det["error"] = str(e)
                    self.emit(
                        action=action,
                        outcome=Outcome.ERROR,
                        severity=Severity.HIGH,
                        resource_type=resource_type,
                        resource_id=rid,
                        details=det,
                    )
                    raise
            return _wrap
        return _decor

    # -------------------- Внутренние --------------------

    def _is_duplicate(self, eid: str, now: float) -> bool:
        if self.cfg.dedupe_seconds <= 0:
            return False
        with self._dedupe_lock:
            ts = self._dedupe.get(eid)
            if ts and (now - ts) <= self.cfg.dedupe_seconds:
                return True
            self._dedupe[eid] = now
            # лёгкая очистка
            if len(self._dedupe) > 100_000:
                cutoff = now - self.cfg.dedupe_seconds
                self._dedupe = {k: v for k, v in self._dedupe.items() if v >= cutoff}
            return False

    def _enqueue(self, event: Dict[str, Any]) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            if self.cfg.drop_on_overflow:
                # удалим один старый и положим новый
                try:
                    self._q.get_nowait()
                except Exception:
                    pass
                try:
                    self._q.put_nowait(event)
                except Exception:
                    pass
            else:
                self._q.put(event, timeout=1.0)

    def _run(self) -> None:
        batch: List[Dict[str, Any]] = []
        last_flush = time.time()
        while not self._stop.is_set():
            timeout = max(0.0, self.cfg.flush_interval_sec - (time.time() - last_flush))
            try:
                item = self._q.get(timeout=timeout)
                batch.append(item)
                if len(batch) >= self.cfg.batch_size:
                    self._write(batch)
                    batch.clear()
                    last_flush = time.time()
            except queue.Empty:
                if batch:
                    self._write(batch)
                    batch.clear()
                    last_flush = time.time()
        # финальный сброс
        if batch:
            self._write(batch)

    def _write(self, batch: List[Dict[str, Any]]) -> None:
        for s in self.cfg.sinks:
            try:
                s.write_batch(batch)
            except Exception as e:
                # без исключений наружу — аудит не должен валить приложение
                sys.stderr.write(f"[audit] sink error: {e}\n")
        for s in self.cfg.sinks:
            try:
                s.flush()
            except Exception:
                pass

# ============================ Проверка цепочки ==========================

def verify_chain(events: Iterable[Dict[str, Any]], key: bytes) -> bool:
    """
    Верифицировать непрерывность подписи: sig_i == HMAC(key, prev_{i-1} || hash(core_i)).
    Возвращает True/False.
    """
    prev = b""
    for ev in events:
        chain = ev.get("chain") or {}
        sig_b64 = chain.get("sig") or ""
        try:
            sig = base64.urlsafe_b64decode(sig_b64)
        except Exception:
            return False
        # вычислим hash(core) из события, исключая seq/chain
        core = dict(ev)
        core.pop("seq", None)
        core.pop("chain", None)
        event_core = _canonical_json(core)
        event_hash = hashlib.sha256(event_core).digest()
        expect = hmac.new(key, prev + event_hash, "sha256").digest()
        if not hmac.compare_digest(expect, sig):
            return False
        prev = sig
    return True

# ============================ Утилита сборки ============================

def build_default_logger(
    *,
    jsonl_path: Optional[str] = None,
    sqlite_path: Optional[str] = None,
    tail_file: Optional[str] = None,
    hmac_env: str = "SECURITY_CORE_AUDIT_HMAC_KEY",
) -> AuditLogger:
    """
    Быстрая сборка: Stdout + (опц.) файл + (опц.) SQLite.
    Ключ в env: base64url(секрет >=16 байт).
    """
    sinks: List[AuditSink] = [StdoutJSONLSink()]
    if jsonl_path:
        sinks.append(JsonlFileSink(jsonl_path))
    if sqlite_path:
        sinks.append(SQLiteSink(sqlite_path))
    kp = EnvHmacKeyProvider(hmac_env)
    cfg = AuditLoggerConfig(
        sinks=sinks,
        key_provider=kp,
        tail_file=tail_file,
    )
    return AuditLogger(cfg)

# ============================ Пример использования ======================

if __name__ == "__main__":
    # Демонстрация работы
    os.environ.setdefault("SECURITY_CORE_AUDIT_HMAC_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    logger = build_default_logger(jsonl_path="./audit.log", sqlite_path="./audit.db", tail_file="./audit.tail.json")
    bind_context(tenant_id="t-default", principal_id="u-admin", ip="203.0.113.10", user_agent="curl/8.5.0", request_id="req-123", correlation_id="corr-abc")

    eid = logger.emit(
        action=AuditAction.USER_CREATE,
        outcome=Outcome.ALLOW,
        severity=Severity.MEDIUM,
        resource_type="USER",
        resource_id="u-1",
        details={"email": "alice@example.org", "token": "xyz123", "note": "created via API"},
    )
    print("emitted:", eid)

    # Проверка цепочки для последних 3 событий из файла (если есть)
    try:
        lines = Path("./audit.log").read_text("utf-8").strip().splitlines()[-3:]
        events = [json.loads(l) for l in lines]
        _, key = EnvHmacKeyProvider().get_key()
        ok = verify_chain(events, key)
        print("chain verify(last3):", ok)
    except Exception:
        pass

    logger.close()
