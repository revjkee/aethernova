# policy-core/policy_core/audit/logger.py
"""
Industrial-grade structured audit logger for policy-core.

Features:
- Structured JSON events (RFC3339 timestamps, stable keys)
- Sync and async modes with bounded queue
- Size-based file rotation with retention
- Context propagation via contextvars (request_id, span_id, tenant_id, subject_id, session_id)
- Redaction of sensitive fields (token/secret/password/etc.)
- Per-event sampling
- Optional HMAC signature for tamper detection
- Integrity chain (prev_hash -> hash) to detect record reordering/tampering
- Canonical JSON serialization for stable hashing/signatures
- Fail-safe logging: failures never crash the application

No third-party dependencies. Python 3.9+.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import hashlib
import hmac
import io
import json
import os
import random
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple, Union

# ---------------------------- Context ----------------------------

request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
span_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("span_id", default="")
tenant_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("tenant_id", default="")
subject_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("subject_id", default="")
session_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("session_id", default="")

def set_context(
    request_id: Optional[str] = None,
    span_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    subject_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> None:
    """Set audit context variables if provided."""
    if request_id is not None:
        request_id_ctx.set(request_id)
    if span_id is not None:
        span_id_ctx.set(span_id)
    if tenant_id is not None:
        tenant_id_ctx.set(tenant_id)
    if subject_id is not None:
        subject_id_ctx.set(subject_id)
    if session_id is not None:
        session_id_ctx.set(session_id)

def clear_context() -> None:
    """Clear audit context variables."""
    request_id_ctx.set("")
    span_id_ctx.set("")
    tenant_id_ctx.set("")
    subject_id_ctx.set("")
    session_id_ctx.set("")

# ---------------------------- Utilities ----------------------------

_DEFAULT_REDACT_KEYS: Tuple[str, ...] = (
    "password", "pass", "secret", "token", "authorization", "cookie",
    "api_key", "apikey", "private_key", "access_key", "refresh_token",
)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _canonical_json(obj: Any) -> bytes:
    """Stable JSON for hashing/signatures."""
    return json.dumps(_stable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _stable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _stable(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_stable(x) for x in obj]
    if isinstance(obj, tuple):
        return [_stable(x) for x in obj]
    if isinstance(obj, float):
        return float(f"{obj:.15g}")
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    return str(obj)

def _redact(obj: Any, keys: Tuple[str, ...]) -> Any:
    """Recursively redact sensitive keys."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in keys:
                out[k] = "***"
            else:
                out[k] = _redact(v, keys)
        return out
    if isinstance(obj, list):
        return [_redact(x, keys) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_redact(x, keys) for x in obj)
    return obj

def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"

# ---------------------------- Levels ----------------------------

class Level:
    DEBUG = 10
    INFO = 20
    NOTICE = 25  # custom
    WARN = 30
    ERROR = 40
    CRITICAL = 50

    _NAME_TO_NUM = {
        "debug": DEBUG,
        "info": INFO,
        "notice": NOTICE,
        "warn": WARN,
        "warning": WARN,
        "error": ERROR,
        "critical": CRITICAL,
    }

    @classmethod
    def parse(cls, level: Union[int, str]) -> int:
        if isinstance(level, int):
            return level
        return cls._NAME_TO_NUM.get(str(level).lower(), cls.INFO)

# ---------------------------- Config ----------------------------

@dataclass
class AuditConfig:
    # sink
    sink: str = "stdout"          # "stdout" | "stderr" | "file" | "noop"
    file_path: Optional[str] = None
    # rotation
    max_bytes: int = 50 * 1024 * 1024
    backup_count: int = 10
    rotate_on_start: bool = False
    # behavior
    level: int = Level.INFO
    flush_immediately: bool = True
    async_mode: bool = False
    queue_maxsize: int = 10000
    # security
    redact_keys: Tuple[str, ...] = _DEFAULT_REDACT_KEYS
    include_signature: bool = False
    hmac_secret: Optional[bytes] = None
    include_integrity_chain: bool = True
    # sampling (per event type, probability 0..1)
    sampling: Mapping[str, float] = field(default_factory=dict)
    # statics
    service: str = "policy-core"
    service_version: str = "1.0"
    include_pid: bool = True
    include_hostname: bool = True

    def validate(self) -> None:
        if self.sink not in ("stdout", "stderr", "file", "noop"):
            raise ValueError("invalid sink")
        if self.sink == "file" and not self.file_path:
            raise ValueError("file_path required for file sink")
        if self.include_signature and not self.hmac_secret:
            raise ValueError("hmac_secret required when include_signature=True")
        if self.max_bytes <= 0 or self.backup_count < 0:
            raise ValueError("invalid rotation settings")

# ---------------------------- Writer (Sync/File/Std) ----------------------------

class _Writer:
    """Sync writer with size-based rotation and retention."""
    def __init__(self, cfg: AuditConfig):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._stream = self._open_stream()

        if self.cfg.rotate_on_start and self.cfg.sink == "file":
            # rotate empty-to-new to start a fresh file per run
            with self._lock:
                self._rotate_if_needed(force=True)

    def _open_stream(self):
        if self.cfg.sink == "stdout":
            return sys.stdout
        if self.cfg.sink == "stderr":
            return sys.stderr
        if self.cfg.sink == "file":
            os.makedirs(os.path.dirname(self.cfg.file_path), exist_ok=True)
            return open(self.cfg.file_path, "a", buffering=1, encoding="utf-8")
        class _Noop:
            def write(self, *_a, **_k): pass
            def flush(self): pass
            def close(self): pass
        return _Noop()

    def write_line(self, line: str) -> None:
        # Fail-safe: never raise to caller
        try:
            with self._lock:
                if self.cfg.sink == "file":
                    self._rotate_if_needed()
                self._stream.write(line)
                if self.cfg.flush_immediately:
                    self._stream.flush()
        except Exception as e:
            try:
                sys.stderr.write(f'{{"event":"audit_logger_error","ts":"{_now_iso()}","err":"{e}"}}\n')
            except Exception:
                pass

    def _rotate_if_needed(self, force: bool = False) -> None:
        if self.cfg.sink != "file":
            return
        try:
            path = self.cfg.file_path
            if not force:
                try:
                    size = os.path.getsize(path)
                except FileNotFoundError:
                    size = 0
                if size < self.cfg.max_bytes:
                    return
            # close current
            try:
                self._stream.flush()
                self._stream.close()
            except Exception:
                pass
            # rotate: .{n} -> .{n+1}, ... -> .1
            for i in range(self.cfg.backup_count - 1, 0, -1):
                src = f"{path}.{i}"
                dst = f"{path}.{i+1}"
                if os.path.exists(src):
                    try:
                        if os.path.exists(dst):
                            os.remove(dst)
                        os.rename(src, dst)
                    except Exception:
                        pass
            if self.cfg.backup_count > 0:
                dst = f"{path}.1"
                try:
                    if os.path.exists(dst):
                        os.remove(dst)
                    if os.path.exists(path):
                        os.rename(path, dst)
                except Exception:
                    pass
            # reopen new active file
            self._stream = open(path, "a", buffering=1, encoding="utf-8")
        except Exception as e:
            try:
                sys.stderr.write(f'{{"event":"audit_rotation_error","ts":"{_now_iso()}","err":"{e}"}}\n')
            except Exception:
                pass

    def close(self) -> None:
        try:
            if self.cfg.sink == "file" and self._stream:
                self._stream.flush()
                self._stream.close()
        except Exception:
            pass

# ---------------------------- Async worker ----------------------------

class _AsyncWorker:
    def __init__(self, writer: _Writer, maxsize: int):
        self._writer = writer
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            try:
                await self._task
            except Exception:
                pass
            self._task = None

    async def _run(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    line = await asyncio.wait_for(self._queue.get(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue
                self._writer.write_line(line)
        finally:
            # drain
            try:
                while not self._queue.empty():
                    self._writer.write_line(self._queue.get_nowait())
            except Exception:
                pass

    async def enqueue(self, line: str) -> None:
        try:
            await self._queue.put(line)
        except Exception:
            # fallback to direct write if queue is full or closed
            self._writer.write_line(line)

# ---------------------------- Audit Logger ----------------------------

@dataclass
class AuditLogger:
    cfg: AuditConfig
    _writer: _Writer = field(init=False)
    _worker: Optional[_AsyncWorker] = field(init=False, default=None)
    _last_hash: str = field(init=False, default="")  # integrity chain state
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self):
        self.cfg.validate()
        self._writer = _Writer(self.cfg)
        if self.cfg.async_mode:
            # async worker will be started explicitly by user via `await start_async()`
            self._worker = _AsyncWorker(self._writer, self.cfg.queue_maxsize)

    # ---------- Lifecycle (only in async mode) ----------

    async def start_async(self) -> None:
        if not self.cfg.async_mode or not self._worker:
            return
        await self._worker.start()

    async def stop_async(self) -> None:
        if not self.cfg.async_mode or not self._worker:
            return
        await self._worker.stop()

    def close(self) -> None:
        self._writer.close()

    # ---------- Public API ----------

    def log(self, event: str, data: Mapping[str, Any], level: Union[int, str] = Level.INFO) -> None:
        """Log arbitrary structured event."""
        lvl = Level.parse(level)
        if lvl < self.cfg.level:
            return
        # sampling
        p = float(self.cfg.sampling.get(event, 1.0))
        if p < 1.0 and random.random() > p:
            return
        record = self._build_record(event, data, lvl)
        line = self._encode(record)
        self._dispatch(line)

    # Convenience methods

    def decision(self, data: Mapping[str, Any], level: Union[int, str] = Level.INFO) -> None:
        self.log("pdp_decision", data, level)

    def access(self, data: Mapping[str, Any], level: Union[int, str] = Level.INFO) -> None:
        self.log("access", data, level)

    def policy_update(self, data: Mapping[str, Any], level: Union[int, str] = Level.NOTICE) -> None:
        self.log("policy_update", data, level)

    def security_alert(self, data: Mapping[str, Any], level: Union[int, str] = Level.WARN) -> None:
        self.log("security_alert", data, level)

    def info(self, event: str, data: Mapping[str, Any]) -> None:
        self.log(event, data, Level.INFO)

    def error(self, event: str, data: Mapping[str, Any]) -> None:
        self.log(event, data, Level.ERROR)

    # ---------- Internals ----------

    def _build_record(self, event: str, data: Mapping[str, Any], level: int) -> Dict[str, Any]:
        ts = _now_iso()
        ctx = {
            "request_id": request_id_ctx.get(),
            "span_id": span_id_ctx.get(),
            "tenant_id": tenant_id_ctx.get(),
            "subject_id": subject_id_ctx.get(),
            "session_id": session_id_ctx.get(),
        }
        static = {
            "service": self.cfg.service,
            "service_version": self.cfg.service_version,
        }
        if self.cfg.include_pid:
            static["pid"] = os.getpid()
        if self.cfg.include_hostname:
            static["host"] = _hostname()

        payload = {
            "ts": ts,
            "level": level,
            "event": event,
            "ctx": {k: v for k, v in ctx.items() if v},
            "static": static,
            "data": _redact(dict(data), self.cfg.redact_keys),
        }

        # integrity chain
        if self.cfg.include_integrity_chain:
            with self._lock:
                prev = self._last_hash
                payload["prev_hash"] = prev or None
                payload["hash"] = self._hash_for_record(payload, include_signature=False)
                self._last_hash = payload["hash"]

        # signature
        if self.cfg.include_signature and self.cfg.hmac_secret:
            payload["signature"] = self._sign(payload)

        return payload

    def _hash_for_record(self, payload: Mapping[str, Any], include_signature: bool) -> str:
        body = {k: v for k, v in payload.items() if k not in ("" if include_signature else "signature",)}
        return hashlib.sha256(_canonical_json(body)).hexdigest()

    def _sign(self, payload: Mapping[str, Any]) -> str:
        body = {k: v for k, v in payload.items() if k != "signature"}
        mac = hmac.new(self.cfg.hmac_secret, _canonical_json(body), hashlib.sha256).hexdigest()
        return mac

    def _encode(self, record: Mapping[str, Any]) -> str:
        try:
            return json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        except Exception:
            # fallback (best-effort)
            try:
                return f'{{"ts":"{_now_iso()}","event":"encode_error"}}\n'
            except Exception:
                return "\n"

    def _dispatch(self, line: str) -> None:
        if self.cfg.async_mode and self._worker:
            # enqueue without blocking caller; fallback to sync write on failure
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                # no loop -> write sync
                self._writer.write_line(line)
                return
            try:
                # fire-and-forget
                loop.create_task(self._worker.enqueue(line))
            except Exception:
                self._writer.write_line(line)
        else:
            self._writer.write_line(line)

# ---------------------------- Example schemas (for reference in code) ----------------------------

def decision_event_schema() -> Dict[str, Any]:
    """JSON schema-like shape for pdp_decision events (documentation purpose)."""
    return {
        "ts": "RFC3339 timestamp",
        "level": "int (10..50)",
        "event": "pdp_decision",
        "ctx": {
            "request_id": "string",
            "span_id": "string",
            "tenant_id": "string",
            "subject_id": "string",
            "session_id": "string",
        },
        "static": {
            "service": "policy-core",
            "service_version": "string",
            "pid": "int",
            "host": "string",
        },
        "data": {
            "decision": "permit|deny|indeterminate|not_applicable",
            "policy_id": "string|null",
            "matched_rules": ["string", "..."],
            "latency_ms": "float",
            "reason": "string|null",
            "decision_id": "uuid",
        },
        "prev_hash": "hex|null",
        "hash": "hex",
        "signature": "hex (optional when enabled)",
    }

# ---------------------------- __all__ ----------------------------

__all__ = [
    "AuditConfig",
    "AuditLogger",
    "Level",
    "set_context",
    "clear_context",
    "decision_event_schema",
]
