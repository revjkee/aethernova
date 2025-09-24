# cybersecurity-core/cybersecurity/observability/logging.py
from __future__ import annotations

import contextlib
import contextvars
import datetime as _dt
import io
import json
import logging
import logging.handlers
import os
import queue
import re
import signal
import socket
import sys
import threading
import time
import traceback
import types
import uuid
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# ---------------------------
# Опциональные зависимости
# ---------------------------
try:
    import orjson  # type: ignore
except Exception:  # pragma: no cover
    orjson = None  # type: ignore

try:
    from opentelemetry.trace import get_current_span  # type: ignore
except Exception:  # pragma: no cover
    def get_current_span():  # type: ignore
        return None

__all__ = [
    "configure_logging",
    "reconfigure_from_env",
    "get_logger",
    "bind_context",
    "context",
    "correlation",
    "set_level",
    "audit",
    "security_event",
    "patch_uvicorn_access",
]

# =============================================================================
# Константы и глобальные контексты
# =============================================================================

_ECS_VERSION = "1.12.0"
_HOSTNAME = socket.gethostname()
_PROCESS_PID = os.getpid()

_LOG_CONTEXT: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("log_ctx", default={})
_CORR_ID: contextvars.ContextVar[str] = contextvars.ContextVar("corr_id", default="")

_DEFAULT_REDACT_KEYS = {
    "password", "passwd", "secret", "token", "auth", "authorization",
    "api_key", "apikey", "access_key", "refresh_token", "id_token", "set-cookie",
}
_DEFAULT_PII_PATTERNS = [
    # email
    (re.compile(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"), r"***@***"),
    # IPv4 (не маскируем приватные, но пример простой — универсальная маска)
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "***.***.***.***"),
    # простейшая маска для любых ключей похожих на GUID/UUID
    (re.compile(r"\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b"), "***UUID***"),
]

# =============================================================================
# JSON сериализация
# =============================================================================

def _json_dumps(obj: Any) -> bytes:
    if orjson is not None:
        return orjson.dumps(
            obj,
            option=orjson.OPT_APPEND_NEWLINE
                  | orjson.OPT_NON_STR_KEYS
                  | orjson.OPT_UTC_Z
                  | orjson.OPT_SERIALIZE_NUMPY
        )
    # Fallback
    class _Encoder(json.JSONEncoder):
        def default(self, o):  # type: ignore
            if isinstance(o, (_dt.datetime, _dt.date, _dt.time)):
                if isinstance(o, _dt.datetime):
                    if o.tzinfo is None:
                        o = o.replace(tzinfo=_dt.timezone.utc)
                    return o.astimezone(_dt.timezone.utc).isoformat()
                return o.isoformat()
            try:
                return str(o)
            except Exception:
                return repr(o)
    return (json.dumps(obj, ensure_ascii=False, cls=_Encoder) + "\n").encode("utf-8")

# =============================================================================
# Редакция секретов и PII
# =============================================================================

def _redact_string(s: str) -> str:
    out = s
    for patt, repl in _DEFAULT_PII_PATTERNS:
        out = patt.sub(repl, out)
    return out

def _redact_mapping(m: Mapping[str, Any], redact_keys: Iterable[str]) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    rk = {k.lower() for k in redact_keys}
    for k, v in m.items():
        lk = str(k).lower()
        if lk in rk or any(r in lk for r in rk):
            redacted[k] = "***REDACTED***"
            continue
        redacted[k] = _redact_value(v, redact_keys)
    return redacted

def _redact_sequence(seq: Iterable[Any], redact_keys: Iterable[str]) -> List[Any]:
    return [_redact_value(v, redact_keys) for v in seq]

def _redact_value(v: Any, redact_keys: Iterable[str]) -> Any:
    if isinstance(v, Mapping):
        return _redact_mapping(v, redact_keys)
    if isinstance(v, (list, tuple, set)):
        return _redact_sequence(list(v), redact_keys)
    if isinstance(v, str):
        return _redact_string(v)
    return v

# =============================================================================
# Фильтры: Sampling, RateLimit, Redact, DropHealthcheck
# =============================================================================

class ProbabilisticSamplingFilter(logging.Filter):
    def __init__(self, rate: float) -> None:
        super().__init__()
        self.rate = max(0.0, min(rate, 1.0))

    def filter(self, record: logging.LogRecord) -> bool:
        if self.rate >= 1.0:
            return True
        # быстрый XORShift псевдо-рандом на основе времени и pid
        t = int(time.time_ns())
        x = (t ^ _PROCESS_PID ^ hash(record.name) ^ hash(record.msg)) & 0xFFFFFFFF
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        val = (x & 0xFFFF) / 0xFFFF
        return val < self.rate

class RateLimitFilter(logging.Filter):
    """
    Простой лимит: N событий за интервал (по ключу = logger+level+msg шаблон).
    """
    def __init__(self, max_events: int = 1000, interval_sec: int = 60) -> None:
        super().__init__()
        self.max = max(1, max_events)
        self.win = max(1, interval_sec)
        self._bucket: Dict[str, Tuple[int, float]] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        key = f"{record.name}|{record.levelno}|{getattr(record, 'msg', '')}"
        cnt, start = self._bucket.get(key, (0, time.time()))
        now = time.time()
        if now - start >= self.win:
            cnt, start = 0, now
        cnt += 1
        self._bucket[key] = (cnt, start)
        return cnt <= self.max

class RedactFilter(logging.Filter):
    def __init__(self, redact_keys: Optional[Iterable[str]] = None) -> None:
        super().__init__()
        self.redact_keys = set(redact_keys or _DEFAULT_REDACT_KEYS)

    def filter(self, record: logging.LogRecord) -> bool:
        # Редактируем только extras, не трогаем core атрибуты logging
        extras = {k: v for k, v in record.__dict__.items() if k not in _RESERVED_LOGREC_ATTRS}
        if extras:
            for k, v in extras.items():
                record.__dict__[k] = _redact_value(v, self.redact_keys)
        # Маскируем и сам message (кроме форматных %), но деликатно
        try:
            msg = record.getMessage()
            record.msg = _redact_string(msg)
            record.args = ()
        except Exception:
            pass
        return True

class DropHealthcheckFilter(logging.Filter):
    def __init__(self, patterns: Optional[List[str]] = None) -> None:
        super().__init__()
        self._patts = [re.compile(p) for p in (patterns or [r"\b/healthz\b", r"\b/metrics\b"])]

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        for p in self._patts:
            if p.search(msg):
                return False
        return True

# =============================================================================
# ECS JSON Formatter
# =============================================================================

_RESERVED_LOGREC_ATTRS = set(vars(logging.makeLogRecord({})).keys()) | {
    "asctime", "message",
}

class ECSJsonFormatter(logging.Formatter):
    def __init__(self, service_name: str, service_version: Optional[str] = None, extra_static: Optional[Dict[str, Any]] = None) -> None:
        super().__init__()
        self.service_name = service_name
        self.service_version = service_version
        self.extra_static = extra_static or {}

    def format(self, record: logging.LogRecord) -> str:
        ts = _dt.datetime.utcfromtimestamp(record.created).replace(tzinfo=_dt.timezone.utc).isoformat()
        base: Dict[str, Any] = {
            "@timestamp": ts,
            "ecs": {"version": _ECS_VERSION},
            "log": {"level": record.levelname, "logger": record.name},
            "host": {"hostname": _HOSTNAME},
            "process": {"pid": _PROCESS_PID, "thread": {"name": record.threadName, "id": record.thread}},
            "service": {"name": self.service_name},
            "event": {"dataset": record.name},
            "message": record.getMessage(),
        }
        if self.service_version:
            base["service"]["version"] = self.service_version

        # OpenTelemetry correlation
        try:
            span = get_current_span()
            if span:
                ctx = span.get_span_context()
                if getattr(ctx, "is_valid", lambda: False)():
                    trace_id = format(ctx.trace_id, "032x")
                    span_id = format(ctx.span_id, "016x")
                    base["trace"] = {"id": trace_id}
                    base["span"] = {"id": span_id}
        except Exception:
            pass

        # Correlation ID
        corr = _CORR_ID.get("")
        if corr:
            base.setdefault("labels", {})["correlation.id"] = corr

        # ContextVars
        ctx = _LOG_CONTEXT.get({})
        if ctx:
            base.setdefault("labels", {}).update(ctx)

        # Merge extras from record (non-reserved)
        for k, v in record.__dict__.items():
            if k in _RESERVED_LOGREC_ATTRS:
                continue
            # системные поля для ECS
            if k in ("http", "url", "user", "client", "source", "destination"):
                base[k] = v
            else:
                base.setdefault("extra", {})[k] = v

        # Exception info -> ECS error.*
        if record.exc_info:
            exc_type, exc, tb = record.exc_info
            base["error"] = {
                "type": getattr(exc_type, "__name__", str(exc_type)),
                "message": str(exc),
                "stack_trace": "".join(traceback.format_exception(exc_type, exc, tb))[:100_000],
            }
        elif record.exc_text:
            base.setdefault("error", {})["stack_trace"] = record.exc_text

        # Статические лейблы
        if self.extra_static:
            base.setdefault("labels", {}).update(self.extra_static)

        return _json_dumps(base).decode("utf-8").rstrip("\n")

# =============================================================================
# Контекст и утилиты
# =============================================================================

class _ContextAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.get("extra") or {}
        # объединяем с текущим ContextVar
        ctx = _LOG_CONTEXT.get({})
        if ctx:
            extra = {**ctx, **extra}
        # корреляция
        corr = _CORR_ID.get("")
        if corr:
            extra.setdefault("correlation_id", corr)
        kwargs["extra"] = extra
        return msg, kwargs

def get_logger(name: Optional[str] = None) -> logging.Logger:
    base = logging.getLogger(name or "")
    return _ContextAdapter(base, {}).logger  # type: ignore

def bind_context(**kv: Any) -> None:
    cur = dict(_LOG_CONTEXT.get({}))
    cur.update(kv)
    _LOG_CONTEXT.set(cur)

@contextlib.contextmanager
def context(**kv: Any):
    prev = _LOG_CONTEXT.get({})
    try:
        cur = dict(prev)
        cur.update(kv)
        _LOG_CONTEXT.set(cur)
        yield
    finally:
        _LOG_CONTEXT.set(prev)

@contextlib.contextmanager
def correlation(correlation_id: Optional[str] = None):
    prev = _CORR_ID.get("")
    try:
        _CORR_ID.set(correlation_id or prev or str(uuid.uuid4()))
        yield
    finally:
        _CORR_ID.set(prev)

# =============================================================================
# Конфигурация логирования
# =============================================================================

_listener: Optional[logging.handlers.QueueListener] = None
_queue: Optional[queue.SimpleQueue] = None
_configured_flag = False
_config_lock = threading.Lock()

def _build_handler_stack(
    json_enabled: bool,
    service_name: str,
    service_version: Optional[str],
    to_stdout: bool,
    file_path: Optional[str],
    rotate_bytes: int,
    rotate_backup: int,
    syslog_addr: Optional[str],
    sampling: float,
    ratelimit_n: int,
    ratelimit_win: int,
    drop_healthchecks: bool,
    extra_labels: Dict[str, Any],
) -> List[logging.Handler]:
    fmt: logging.Formatter
    if json_enabled:
        fmt = ECSJsonFormatter(service_name, service_version, extra_static=extra_labels)
    else:
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")

    filters: List[logging.Filter] = []
    if sampling < 1.0:
        filters.append(ProbabilisticSamplingFilter(sampling))
    if ratelimit_n > 0:
        filters.append(RateLimitFilter(ratelimit_n, ratelimit_win))
    filters.append(RedactFilter())
    if drop_healthchecks:
        filters.append(DropHealthcheckFilter())

    handlers: List[logging.Handler] = []

    if to_stdout:
        sh = logging.StreamHandler(stream=sys.stdout)
        sh.setFormatter(fmt)
        for f in filters:
            sh.addFilter(f)
        handlers.append(sh)

    if file_path:
        fh = logging.handlers.RotatingFileHandler(file_path, maxBytes=rotate_bytes, backupCount=rotate_backup, encoding="utf-8")
        fh.setFormatter(fmt)
        for f in filters:
            fh.addFilter(f)
        handlers.append(fh)

    if syslog_addr:
        addr: Tuple[str, int]
        if ":" in syslog_addr:
            host, port = syslog_addr.rsplit(":", 1)
            addr = (host, int(port))
        else:
            # unix socket путь
            addr = syslog_addr  # type: ignore
        shdl = logging.handlers.SysLogHandler(address=addr)
        shdl.setFormatter(fmt)
        for f in filters:
            shdl.addFilter(f)
        handlers.append(shdl)

    return handlers

def configure_logging(
    level: Optional[str] = None,
    json_enabled: Optional[bool] = None,
    service_name: Optional[str] = None,
    service_version: Optional[str] = None,
    to_stdout: Optional[bool] = None,
    file_path: Optional[str] = None,
    rotate_bytes: Optional[int] = None,
    rotate_backup: Optional[int] = None,
    syslog_addr: Optional[str] = None,
    sampling: Optional[float] = None,
    ratelimit_n: Optional[int] = None,
    ratelimit_win: Optional[int] = None,
    drop_healthchecks: Optional[bool] = None,
    extra_labels: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Идемпотентная настройка root-логгера с асинхронной очередью и JSON-форматтером (ECS).
    Безопасно вызывать многократно.
    """
    global _listener, _queue, _configured_flag

    with _config_lock:
        # Прочитать ENV по умолчанию
        env = os.environ
        lvl = (level or env.get("LOG_LEVEL", "INFO")).upper()
        json_en = json_enabled if json_enabled is not None else env.get("LOG_FORMAT", "json").lower() == "json"
        svc = service_name or env.get("SERVICE_NAME", "cybersecurity-core")
        svc_ver = service_version or env.get("SERVICE_VERSION", None)
        out = to_stdout if to_stdout is not None else env.get("LOG_TO_STDOUT", "true").lower() == "true"
        fpath = file_path or env.get("LOG_FILE", "")
        rbytes = rotate_bytes if rotate_bytes is not None else int(env.get("LOG_ROTATE_BYTES", str(10 * 1024 * 1024)))
        rback = rotate_backup if rotate_backup is not None else int(env.get("LOG_BACKUP", "5"))
        sysl = syslog_addr or env.get("LOG_SYSLOG_ADDR", "")
        samp = sampling if sampling is not None else float(env.get("LOG_SAMPLING", "1.0"))
        rl_n = ratelimit_n if ratelimit_n is not None else int(env.get("LOG_RATELIMIT_N", "0"))
        rl_w = ratelimit_win if ratelimit_win is not None else int(env.get("LOG_RATELIMIT_WIN", "60"))
        drop_h = drop_healthchecks if drop_healthchecks is not None else env.get("LOG_DROP_HEALTHCHECKS", "true").lower() == "true"
        labels = extra_labels or {}
        # Подмешаем метки окружения
        for key in ("ENV", "REGION", "TENANT"):
            v = env.get(key)
            if v:
                labels[f"env.{key.lower()}"] = v

        # Закрыть прежний listener, если был
        root = logging.getLogger()
        root.setLevel(getattr(logging, lvl, logging.INFO))

        if _listener is not None:
            try:
                _listener.stop()
            except Exception:
                pass
            _listener = None

        # Снять все хендлеры с root
        for h in list(root.handlers):
            try:
                root.removeHandler(h)
                h.close()
            except Exception:
                pass

        # Построить целевые хендлеры
        handlers = _build_handler_stack(
            json_en, svc, svc_ver, out, fpath or None, rbytes, rback,
            sysl or None, samp, rl_n, rl_w, drop_h, labels
        )

        # Асинхронная очередь
        _queue = queue.SimpleQueue()
        qh = logging.handlers.QueueHandler(_queue)
        root.addHandler(qh)
        _listener = logging.handlers.QueueListener(_queue, *handlers, respect_handler_level=False)
        _listener.start()

        # Приведем популярные логгеры к уровню root
        for n in ("uvicorn", "uvicorn.error", "uvicorn.access", "asyncio", "sqlalchemy", "httpx", "aiohttp"):
            logging.getLogger(n).setLevel(root.level)

        _configured_flag = True

def reconfigure_from_env() -> None:
    """
    Перечитывает параметры из ENV и переинициализирует стек.
    """
    configure_logging()  # все значения читаются из ENV

def set_level(level: str) -> None:
    lvl = getattr(logging, level.upper(), None)
    if not isinstance(lvl, int):
        raise ValueError(f"Unknown log level: {level}")
    logging.getLogger().setLevel(lvl)

# Перезагрузка по SIGHUP (Unix)
def _install_sighup_reload() -> None:
    if hasattr(signal, "SIGHUP"):
        def _handler(signum, frame):
            try:
                reconfigure_from_env()
            except Exception as ex:
                logging.getLogger(__name__).exception("reconfigure failed: %s", ex)
        try:
            signal.signal(signal.SIGHUP, _handler)  # type: ignore[arg-type]
        except Exception:
            pass

_install_sighup_reload()

# =============================================================================
# Аудит и security-события
# =============================================================================

def audit(action: str, outcome: str = "success", subject: Optional[str] = None, target: Optional[str] = None, **extra: Any) -> None:
    """
    Каноническое ауди-событие (ECS-совместимое).
    """
    log = logging.getLogger("audit")
    payload = {
        "event": {"action": action, "outcome": outcome, "kind": "event", "category": ["authentication", "iam"]},
        "user": {"name": subject} if subject else None,
        "target": {"name": target} if target else None,
    }
    payload.update(extra or {})
    log.info("audit", extra=payload)

def security_event(category: str, action: str, severity: int = 5, outcome: str = "success", **extra: Any) -> None:
    """
    Каноническое security-событие, например detections/alerts.
    """
    log = logging.getLogger("security")
    payload = {
        "event": {"kind": "alert", "category": [category], "action": action, "outcome": outcome, "severity": severity},
    }
    payload.update(extra or {})
    log.warning("security", extra=payload)

# =============================================================================
# Интеграция с Uvicorn/FastAPI
# =============================================================================

class _UvicornAccessAdapter(logging.Filter):
    """
    Преобразует записи uvicorn.access в ECS-подобные поля http/request/response.
    Работает best-effort, не ломает оригинальные сообщения.
    """
    _agent_re = re.compile(r'"(?P<method>\S+)\s(?P<path>\S+)\sHTTP/(?P<http_version>[^"]+)"\s(?P<status>\d{3})\s(?P<size>\d+|-)\s"(?P<referer>[^"]*)"\s"(?P<ua>[^"]*)"')

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        http: Dict[str, Any] = {}
        m = self._agent_re.search(msg)
        if m:
            http = {
                "request": {
                    "method": m.group("method"),
                },
                "response": {
                    "status_code": int(m.group("status")),
                },
                "version": m.group("http_version"),
            }
            url = {"path": m.group("path")}
            client = {}
            # Попробуем извлечь IP из начала строки 'X.X.X.X:port - "GET ...'
            ipm = re.match(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})[:\d]*\s", msg)
            if ipm:
                client = {"address": ipm.group("ip")}
            record.__dict__.update({
                "http": http,
                "url": url,
                "client": client,
                "user_agent": {"original": m.group("ua")} if m.group("ua") else None,
            })
        return True

def patch_uvicorn_access() -> None:
    """
    Устанавливает фильтр и уровень для uvicorn.access, чтобы записи были структурированы.
    """
    lg = logging.getLogger("uvicorn.access")
    lg.addFilter(_UvicornAccessAdapter())

# =============================================================================
# Автоконфигурация при импорте (безопасно)
# =============================================================================

def _auto_configure() -> None:
    # Только если пользователь не конфигурировал логирование ранее
    root = logging.getLogger()
    if not root.handlers:
        configure_logging()

_auto_configure()
