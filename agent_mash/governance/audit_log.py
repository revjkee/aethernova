# agent_mash/governance/audit_log.py
from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import hashlib
import hmac
import json
import os
import queue
import secrets
import socket
import sys
import threading
import time
import typing as t
import urllib.request
import uuid

Json = t.Dict[str, t.Any]


class AuditError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True, slots=True)
class AuditConfig:
    enabled: bool = True

    app_name: str = "agent_mash"
    environment: str = "dev"  # dev|test|staging|prod

    # Output configuration
    sink: str = "stdout"  # stdout|file|http|multi
    file_path: str = "audit.log"
    file_fsync: bool = False

    http_url: str = ""
    http_timeout_s: float = 3.0
    http_headers: t.Mapping[str, str] = dataclasses.field(default_factory=dict)

    # Integrity configuration
    enable_hash_chain: bool = True
    chain_state_path: str = "audit.chain.state"  # stores last_hash
    chain_state_fsync: bool = False

    # Optional signing (HMAC)
    enable_hmac: bool = False
    hmac_secret: str = ""  # if empty, read from env AUDIT_HMAC_SECRET
    hmac_algo: str = "sha256"

    # Behavior
    max_queue_size: int = 10000
    drop_on_overflow: bool = True
    flush_interval_s: float = 0.0  # 0 means flush each event in sinks that buffer
    background_worker: bool = True
    strict_schema: bool = True
    redact_sensitive: bool = True

    # Redaction configuration
    redact_keys: t.FrozenSet[str] = frozenset(
        {
            "password",
            "pass",
            "pwd",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "authorization",
            "cookie",
            "set-cookie",
            "api_key",
            "apikey",
            "private_key",
            "seed",
            "mnemonic",
            "session",
        }
    )
    redact_value: str = "[REDACTED]"

    # Limits
    max_value_length: int = 8192
    max_blob_length: int = 32768


@dataclasses.dataclass(frozen=True, slots=True)
class AuditContext:
    correlation_id: str
    actor_id: str | None = None
    actor_type: str | None = None  # user|service|system
    tenant_id: str | None = None
    request_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    session_id: str | None = None

    def to_dict(self) -> Json:
        out: Json = {"correlation_id": self.correlation_id}
        if self.actor_id is not None:
            out["actor_id"] = self.actor_id
        if self.actor_type is not None:
            out["actor_type"] = self.actor_type
        if self.tenant_id is not None:
            out["tenant_id"] = self.tenant_id
        if self.request_id is not None:
            out["request_id"] = self.request_id
        if self.ip is not None:
            out["ip"] = self.ip
        if self.user_agent is not None:
            out["user_agent"] = self.user_agent
        if self.session_id is not None:
            out["session_id"] = self.session_id
        return out


_audit_ctx: contextvars.ContextVar[AuditContext | None] = contextvars.ContextVar(
    "agent_mash_audit_context", default=None
)


def set_audit_context(ctx: AuditContext | None) -> None:
    _audit_ctx.set(ctx)


def get_audit_context() -> AuditContext | None:
    return _audit_ctx.get()


class audit_context:
    def __init__(self, ctx: AuditContext | None) -> None:
        self._ctx = ctx
        self._token: contextvars.Token[AuditContext | None] | None = None

    def __enter__(self) -> None:
        self._token = _audit_ctx.set(self._ctx)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._token is not None:
            _audit_ctx.reset(self._token)


def _now_unix() -> float:
    return time.time()


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def _pid() -> int:
    return os.getpid()


def _safe_uuid() -> str:
    return str(uuid.uuid4())


def _stable_json_dumps(obj: t.Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac_hex(secret: bytes, msg: bytes, algo: str) -> str:
    try:
        digestmod = getattr(hashlib, algo)
    except AttributeError as e:
        raise AuditError(f"Unsupported HMAC algo: {algo}") from e
    return hmac.new(secret, msg, digestmod=digestmod).hexdigest()


def _truncate_str(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _is_sensitive_key(key: str, redact_keys: t.FrozenSet[str]) -> bool:
    k = key.strip().lower()
    return k in redact_keys


def _redact(obj: t.Any, cfg: AuditConfig) -> t.Any:
    if not cfg.redact_sensitive:
        return obj

    if isinstance(obj, dict):
        out: dict[str, t.Any] = {}
        for k, v in obj.items():
            ks = str(k)
            if _is_sensitive_key(ks, cfg.redact_keys):
                out[ks] = cfg.redact_value
            else:
                out[ks] = _redact(v, cfg)
        return out

    if isinstance(obj, (list, tuple)):
        return [_redact(x, cfg) for x in obj]

    if isinstance(obj, bytes):
        if len(obj) > cfg.max_blob_length:
            return f"[BYTES:{len(obj)}]"
        return obj.hex()

    if isinstance(obj, str):
        return _truncate_str(obj, cfg.max_value_length)

    return obj


def _ensure_str(s: t.Any, max_len: int) -> str:
    if s is None:
        return ""
    if isinstance(s, str):
        return _truncate_str(s, max_len)
    return _truncate_str(str(s), max_len)


@dataclasses.dataclass(frozen=True, slots=True)
class AuditEvent:
    ts: float
    event_id: str
    event_type: str
    severity: str  # INFO|WARN|ERROR|SECURITY
    message: str

    app: str
    env: str
    host: str
    pid: int

    context: Json
    data: Json

    prev_hash: str | None = None
    hash: str | None = None
    hmac: str | None = None

    def to_dict(self) -> Json:
        d: Json = {
            "ts": self.ts,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "app": self.app,
            "env": self.env,
            "host": self.host,
            "pid": self.pid,
            "context": self.context,
            "data": self.data,
        }
        if self.prev_hash is not None:
            d["prev_hash"] = self.prev_hash
        if self.hash is not None:
            d["hash"] = self.hash
        if self.hmac is not None:
            d["hmac"] = self.hmac
        return d


class AuditSink(t.Protocol):
    def write_line(self, line: str) -> None: ...
    def flush(self) -> None: ...
    def close(self) -> None: ...


class StdoutSink:
    def __init__(self) -> None:
        self._stream = sys.stdout
        self._lock = threading.RLock()

    def write_line(self, line: str) -> None:
        with self._lock:
            self._stream.write(line + "\n")

    def flush(self) -> None:
        with self._lock:
            try:
                self._stream.flush()
            except Exception:
                pass

    def close(self) -> None:
        self.flush()


class FileSink:
    def __init__(self, path: str, *, fsync: bool) -> None:
        self._path = path
        self._fsync = fsync
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8", buffering=1)

    def write_line(self, line: str) -> None:
        with self._lock:
            self._fh.write(line + "\n")
            if self._fsync:
                try:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                except Exception:
                    pass

    def flush(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
            except Exception:
                pass

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
            except Exception:
                pass
            try:
                self._fh.close()
            except Exception:
                pass


class HttpSink:
    def __init__(self, url: str, *, timeout_s: float, headers: t.Mapping[str, str]) -> None:
        self._url = url
        self._timeout_s = timeout_s
        self._headers = dict(headers)
        self._lock = threading.RLock()

    def write_line(self, line: str) -> None:
        if not self._url:
            return
        data = line.encode("utf-8")
        req = urllib.request.Request(self._url, data=data, method="POST")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        for k, v in self._headers.items():
            req.add_header(k, v)
        with self._lock:
            with urllib.request.urlopen(req, timeout=self._timeout_s) as resp:
                _ = resp.read(1)

    def flush(self) -> None:
        return

    def close(self) -> None:
        return


class MultiSink:
    def __init__(self, sinks: t.Sequence[AuditSink]) -> None:
        self._sinks = list(sinks)

    def write_line(self, line: str) -> None:
        errors: list[Exception] = []
        for s in self._sinks:
            try:
                s.write_line(line)
            except Exception as e:
                errors.append(e)
        if errors:
            raise AuditError(f"MultiSink write errors: {len(errors)}")

    def flush(self) -> None:
        for s in self._sinks:
            try:
                s.flush()
            except Exception:
                pass

    def close(self) -> None:
        for s in self._sinks:
            try:
                s.close()
            except Exception:
                pass


class _ChainState:
    def __init__(self, path: str, *, fsync: bool) -> None:
        self._path = path
        self._fsync = fsync
        self._lock = threading.RLock()
        self._last_hash: str | None = None
        self._load()

    def _load(self) -> None:
        with self._lock:
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    v = f.read().strip()
                self._last_hash = v if v else None
            except FileNotFoundError:
                self._last_hash = None
            except Exception:
                self._last_hash = None

    def get_last_hash(self) -> str | None:
        with self._lock:
            return self._last_hash

    def set_last_hash(self, h: str) -> None:
        with self._lock:
            self._last_hash = h
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                f.write(h)
                f.write("\n")
                if self._fsync:
                    try:
                        f.flush()
                        os.fsync(f.fileno())
                    except Exception:
                        pass


class AuditLogger:
    def __init__(self, cfg: AuditConfig) -> None:
        self._cfg = cfg
        self._sink = self._build_sink(cfg)
        self._chain = _ChainState(cfg.chain_state_path, fsync=cfg.chain_state_fsync) if cfg.enable_hash_chain else None
        self._hmac_secret = self._load_hmac_secret(cfg) if cfg.enable_hmac else b""
        self._queue: queue.Queue[str] | None = None
        self._worker_thread: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._lock = threading.RLock()

        if cfg.background_worker:
            self._queue = queue.Queue(maxsize=max(1, cfg.max_queue_size))
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="audit-writer",
                daemon=True,
            )
            self._worker_thread.start()

    @property
    def config(self) -> AuditConfig:
        return self._cfg

    def close(self) -> None:
        with self._lock:
            self._stop_evt.set()
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=max(0.1, self._cfg.graceful_shutdown_timeout_s))
        try:
            self._sink.flush()
        except Exception:
            pass
        try:
            self._sink.close()
        except Exception:
            pass

    def flush(self) -> None:
        try:
            self._sink.flush()
        except Exception:
            pass

    def _build_sink(self, cfg: AuditConfig) -> AuditSink:
        if cfg.sink == "stdout":
            return StdoutSink()
        if cfg.sink == "file":
            return FileSink(cfg.file_path, fsync=cfg.file_fsync)
        if cfg.sink == "http":
            return HttpSink(cfg.http_url, timeout_s=cfg.http_timeout_s, headers=cfg.http_headers)
        if cfg.sink == "multi":
            sinks: list[AuditSink] = [StdoutSink()]
            if cfg.file_path:
                sinks.append(FileSink(cfg.file_path, fsync=cfg.file_fsync))
            if cfg.http_url:
                sinks.append(HttpSink(cfg.http_url, timeout_s=cfg.http_timeout_s, headers=cfg.http_headers))
            return MultiSink(sinks)
        raise AuditError(f"Unknown sink: {cfg.sink}")

    def _load_hmac_secret(self, cfg: AuditConfig) -> bytes:
        secret = cfg.hmac_secret.strip() if cfg.hmac_secret else os.environ.get("AUDIT_HMAC_SECRET", "").strip()
        if not secret:
            raise AuditError("HMAC enabled but secret is empty (set hmac_secret or env AUDIT_HMAC_SECRET)")
        return secret.encode("utf-8")

    def _schema_validate(self, event_type: str, severity: str, message: str, data: Json) -> None:
        if not self._cfg.strict_schema:
            return
        if not event_type or not isinstance(event_type, str):
            raise AuditError("event_type must be non-empty string")
        if severity not in {"INFO", "WARN", "ERROR", "SECURITY"}:
            raise AuditError("severity must be one of INFO|WARN|ERROR|SECURITY")
        if not message or not isinstance(message, str):
            raise AuditError("message must be non-empty string")
        if not isinstance(data, dict):
            raise AuditError("data must be dict")

    def _make_event(
        self,
        event_type: str,
        *,
        severity: str,
        message: str,
        data: Json,
    ) -> AuditEvent:
        ctx = get_audit_context()
        ctx_dict = ctx.to_dict() if ctx is not None else {"correlation_id": self._infer_correlation_id()}

        base_data = _redact(data, self._cfg)
        self._schema_validate(event_type, severity, message, base_data)

        ev = AuditEvent(
            ts=_now_unix(),
            event_id=_safe_uuid(),
            event_type=_ensure_str(event_type, 256),
            severity=severity,
            message=_ensure_str(message, 2048),
            app=self._cfg.app_name,
            env=self._cfg.environment,
            host=_hostname(),
            pid=_pid(),
            context=ctx_dict,
            data=base_data,
            prev_hash=None,
            hash=None,
            hmac=None,
        )

        d = ev.to_dict()
        if self._cfg.enable_hash_chain and self._chain is not None:
            prev = self._chain.get_last_hash()
            d["prev_hash"] = prev
            payload = _stable_json_dumps(d).encode("utf-8")
            h = _sha256_hex(payload)
            d["hash"] = h
            ev = dataclasses.replace(ev, prev_hash=prev, hash=h)

        if self._cfg.enable_hmac and self._hmac_secret:
            payload = _stable_json_dumps(d).encode("utf-8")
            sig = _hmac_hex(self._hmac_secret, payload, self._cfg.hmac_algo)
            d["hmac"] = sig
            ev = dataclasses.replace(ev, hmac=sig)

        return ev

    def _infer_correlation_id(self) -> str:
        return secrets.token_hex(16)

    def _emit_line(self, line: str) -> None:
        if not self._cfg.enabled:
            return

        if self._queue is None:
            self._write_line_sync(line)
            return

        try:
            self._queue.put_nowait(line)
        except queue.Full:
            if self._cfg.drop_on_overflow:
                return
            self._queue.put(line)

    def _write_line_sync(self, line: str) -> None:
        self._sink.write_line(line)
        if self._cfg.flush_interval_s == 0.0:
            self._sink.flush()

    def _worker_loop(self) -> None:
        assert self._queue is not None
        last_flush = time.time()
        flush_every = float(self._cfg.flush_interval_s)
        while not self._stop_evt.is_set():
            try:
                line = self._queue.get(timeout=0.2)
            except queue.Empty:
                if flush_every > 0.0 and (time.time() - last_flush) >= flush_every:
                    try:
                        self._sink.flush()
                    except Exception:
                        pass
                    last_flush = time.time()
                continue

            try:
                self._sink.write_line(line)
            except Exception:
                pass

            if flush_every == 0.0:
                try:
                    self._sink.flush()
                except Exception:
                    pass
            else:
                if (time.time() - last_flush) >= flush_every:
                    try:
                        self._sink.flush()
                    except Exception:
                        pass
                    last_flush = time.time()

    def log(
        self,
        event_type: str,
        *,
        severity: str = "INFO",
        message: str,
        data: Json | None = None,
    ) -> str:
        """
        Returns event_id.
        """
        if not self._cfg.enabled:
            return ""

        ev = self._make_event(event_type, severity=severity, message=message, data=data or {})
        d = ev.to_dict()

        line = _stable_json_dumps(d)
        self._emit_line(line)

        if self._cfg.enable_hash_chain and self._chain is not None and ev.hash is not None:
            self._chain.set_last_hash(ev.hash)

        return ev.event_id

    async def log_async(
        self,
        event_type: str,
        *,
        severity: str = "INFO",
        message: str,
        data: Json | None = None,
    ) -> str:
        if self._queue is not None:
            return self.log(event_type, severity=severity, message=message, data=data)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.log(event_type, severity=severity, message=message, data=data)
        )


_singleton_lock = threading.RLock()
_singleton_logger: AuditLogger | None = None


def init_audit_logger(cfg: AuditConfig) -> AuditLogger:
    global _singleton_logger
    with _singleton_lock:
        if _singleton_logger is not None:
            return _singleton_logger
        _singleton_logger = AuditLogger(cfg)
        return _singleton_logger


def get_audit_logger() -> AuditLogger:
    with _singleton_lock:
        if _singleton_logger is None:
            raise AuditError("AuditLogger is not initialized. Call init_audit_logger first.")
        return _singleton_logger


def shutdown_audit_logger() -> None:
    global _singleton_logger
    with _singleton_lock:
        if _singleton_logger is None:
            return
        try:
            _singleton_logger.close()
        finally:
            _singleton_logger = None


__all__ = [
    "AuditConfig",
    "AuditContext",
    "AuditError",
    "AuditEvent",
    "AuditLogger",
    "audit_context",
    "get_audit_context",
    "get_audit_logger",
    "init_audit_logger",
    "set_audit_context",
    "shutdown_audit_logger",
]
