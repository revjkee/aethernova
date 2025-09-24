# cybersecurity-core/cybersecurity/audit/logger.py
# Industrial Audit Logger (stdlib only)
# - JSON Lines, tamper-evident (HMAC-SHA256 chain prev->hash)
# - Multi-tenant fields, privacy redaction, file rotation with cross-process lock
# - Integrity verification tool
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

__all__ = [
    "AuditLoggerConfig",
    "AuditLogger",
    "AuditEvent",
    "verify_log",
]

# --------------------------------------------------------------------------------------
# Config / secret management
# --------------------------------------------------------------------------------------

def _b64decode(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return s.encode("utf-8")

def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _canonical_json(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

HOSTNAME = socket.gethostname()
PID = os.getpid()

# --------------------------------------------------------------------------------------
# File lock (cross-process, best-effort; fcntl if available, else lock file)
# --------------------------------------------------------------------------------------

class _FileLock:
    def __init__(self, path: str) -> None:
        self.path = path
        self._fh: Optional[Any] = None
        self._mtx = threading.Lock()

    def __enter__(self):
        self._mtx.acquire()
        try:
            self._fh = open(self.path, "a+")
            try:
                import fcntl  # type: ignore
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
                self._use_fcntl = True
            except Exception:
                # Fallback: naive lockfile by exclusive create
                self._use_fcntl = False
                self._fh.close()
                self._fh = None
                self._spin_lockfile()
        except Exception:
            self._mtx.release()
            raise
        return self

    def _spin_lockfile(self):
        # primitive lock file loop
        lockfile = self.path + ".lock"
        for _ in range(10_000):
            try:
                fd = os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                self._lockfile = lockfile
                return
            except FileExistsError:
                time.sleep(0.005)
        raise TimeoutError("lock timeout")

    def __exit__(self, exc_type, exc, tb):
        try:
            if getattr(self, "_use_fcntl", False) and self._fh:
                try:
                    import fcntl  # type: ignore
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                try:
                    self._fh.close()
                except Exception:
                    pass
            else:
                try:
                    os.unlink(self.path + ".lock")
                except Exception:
                    pass
        finally:
            self._mtx.release()

# --------------------------------------------------------------------------------------
# Redaction helpers (privacy and secret hygiene)
# --------------------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_AWS_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_GENERIC_SECRET_RE = re.compile(r"\b(?:gh[pousr]_|xox[baprs]-|ya29\.[A-Za-z0-9\-_]+|sk-[A-Za-z0-9]{20,})[A-Za-z0-9\-_]{10,}\b")

def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits[:-1]):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    checksum = (checksum * 9) % 10
    return checksum == digits[-1]

def _mask(s: str) -> str:
    if len(s) <= 8:
        return "***"
    return s[:4] + "***" + s[-4:]

def redact_value(val: Any, max_len: int = 2000) -> Any:
    if val is None:
        return None
    if isinstance(val, (int, float, bool)):
        return val
    if isinstance(val, str):
        s = val[:max_len]
        # emails
        s = _EMAIL_RE.sub(lambda m: _mask(m.group(0)), s)
        # AWS AKIA
        s = _AWS_AKIA_RE.sub(lambda m: _mask(m.group(0)), s)
        # generic secrets
        s = _GENERIC_SECRET_RE.sub(lambda m: _mask(m.group(0)), s)
        # PAN with Luhn
        def repl_pan(m):
            txt = m.group(0)
            return _mask(txt) if _luhn_ok(txt) else txt
        s = _PAN_RE.sub(repl_pan, s)
        return s
    if isinstance(val, dict):
        return {k: redact_value(v, max_len=max_len) for k, v in list(val.items())[:200]}
    if isinstance(val, (list, tuple)):
        return [redact_value(v, max_len=max_len) for v in val[:200]]
    return str(val)[:max_len]

def clamp_metadata(meta: Optional[Mapping[str, Any]], max_bytes: int = 4096) -> Dict[str, Any]:
    m = {} if meta is None else redact_value(dict(meta))  # redact recursively
    # ensure size budget
    raw = _canonical_json(m)
    if len(raw) <= max_bytes:
        return m
    # downgrade by dropping keys by size
    items = sorted(((k, m[k]) for k in m.keys()), key=lambda kv: len(_canonical_json({kv[0]: kv[1]})), reverse=True)
    out: Dict[str, Any] = {}
    for k, v in items:
        out[k] = v
        if len(_canonical_json(out)) > max_bytes:
            out.pop(k, None)
    out["_truncated"] = True
    return out

# --------------------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------------------

@dataclass
class AuditLoggerConfig:
    log_path: str
    state_path: Optional[str] = None
    tenant_id: Optional[str] = None
    rotate_max_bytes: int = 20 * 1024 * 1024
    rotate_backups: int = 5
    key_id: str = os.getenv("AUDIT_KEY_ID", "k1")
    # Secrets: base64 string in env AUDIT_HMAC_SECRET, fallback ephemeral
    secret_b64: Optional[str] = os.getenv("AUDIT_HMAC_SECRET") or None
    echo_stdout: bool = False  # optional duplicate to stdout

@dataclass
class AuditEvent:
    ts: str
    type: str
    ver: str
    tenant: Optional[str]
    actor: Dict[str, Any]
    action: str
    target: Dict[str, Any]
    result: str
    severity: str
    reason: Optional[str]
    request_id: Optional[str]
    correlation_id: Optional[str]
    labels: List[str]
    metadata: Dict[str, Any]
    # provenance
    host: str
    pid: int
    seq: int
    prev: str
    hash: str
    key_id: str
    event_id: str

# --------------------------------------------------------------------------------------
# Core logger
# --------------------------------------------------------------------------------------

class AuditLogger:
    def __init__(self, cfg: AuditLoggerConfig) -> None:
        self.cfg = cfg
        self._secret = _b64decode(cfg.secret_b64) if cfg.secret_b64 else os.urandom(32)
        self._has_ephemeral_secret = not bool(cfg.secret_b64)
        self._state_path = cfg.state_path or (cfg.log_path + ".state.json")
        self._lock = _FileLock(self._state_path)
        # ensure directories
        os.makedirs(os.path.dirname(os.path.abspath(cfg.log_path)) or ".", exist_ok=True)

    # ---------- public API ----------

    def log(
        self,
        *,
        action: str,
        result: str,
        severity: str = "low",
        actor_id: Optional[str] = None,
        actor_type: str = "user",
        actor_ip: Optional[str] = None,
        actor_ua: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        reason: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        labels: Optional[Iterable[str]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        extra_actor: Optional[Mapping[str, Any]] = None,
        extra_target: Optional[Mapping[str, Any]] = None,
    ) -> AuditEvent:
        """
        Пишет одно аудит-событие в JSON Lines с доказуемой целостностью.
        """
        actor = {
            "id": actor_id,
            "type": actor_type,
            "ip": actor_ip,
            "ua": redact_value(actor_ua),
        }
        if extra_actor:
            actor.update(redact_value(dict(extra_actor)))  # type: ignore

        target = {
            "type": target_type,
            "id": target_id,
        }
        if extra_target:
            target.update(redact_value(dict(extra_target)))  # type: ignore

        # redact reason and metadata
        reason = redact_value(reason) if reason is not None else None
        metadata_clamped = clamp_metadata(metadata)

        # build base (no seq/hash yet)
        base: Dict[str, Any] = {
            "ts": _now_rfc3339(),
            "type": "audit",
            "ver": "1.0",
            "tenant": tenant_id or self.cfg.tenant_id,
            "actor": actor,
            "action": action,
            "target": target,
            "result": result,
            "severity": severity,
            "reason": reason,
            "request_id": request_id,
            "correlation_id": correlation_id,
            "labels": list(labels or ()),
            "metadata": metadata_clamped,
            "host": HOSTNAME,
            "pid": PID,
            "key_id": self.cfg.key_id,
            "event_id": str(uuid.uuid4()),
        }

        # under lock: read state, update seq, compute hash, write
        with self._lock:
            state = self._read_state()
            seq = state.get("seq", 0) + 1
            prev = state.get("last_hash", "GENESIS")
            payload_for_hash = {**base, "seq": seq, "prev": prev}
            digest = hmac.new(self._secret, _canonical_json(payload_for_hash), hashlib.sha256).hexdigest()
            event = AuditEvent(
                seq=seq,
                prev=prev,
                hash=digest,
                **base,  # type: ignore
            )
            self._write_event(event)
            self._write_state({"seq": seq, "last_hash": digest, "key_id": self.cfg.key_id, "has_ephemeral_secret": self._has_ephemeral_secret})
        return event

    # ---------- integrity verification ----------

    def verify_file(self, log_path: Optional[str] = None, secrets: Optional[Mapping[str, bytes]] = None) -> Tuple[bool, Optional[int], str]:
        """
        Проверяет целостность файла лога.
        secrets: ключи вида {key_id: secret_bytes}; если не указаны — используется текущий секрет/ключ.
        Возвращает (ok, broken_line_no, message).
        """
        lp = log_path or self.cfg.log_path
        return verify_log(lp, secrets or {self.cfg.key_id: self._secret})

    # ---------- internals ----------

    def _read_state(self) -> Dict[str, Any]:
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except Exception:
            # state corrupted: do not lose logging, restart chain
            return {}

    def _write_state(self, state: Mapping[str, Any]) -> None:
        tmp = self._state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._state_path)

    def _write_event(self, ev: AuditEvent) -> None:
        line = json.dumps(asdict(ev), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        # rotate under same lock
        self._maybe_rotate_locked()
        fd = os.open(self.cfg.log_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o640)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
        finally:
            try:
                os.close(fd)
            except Exception:
                pass
        if self.cfg.echo_stdout:
            try:
                print(line, flush=True)
            except Exception:
                pass

    def _maybe_rotate_locked(self) -> None:
        try:
            st = os.stat(self.cfg.log_path)
            cur_size = st.st_size
        except FileNotFoundError:
            return
        if cur_size < self.cfg.rotate_max_bytes:
            return
        # rotate: .N -> .N+1, ..., .1 -> .2, base -> .1
        for i in range(self.cfg.rotate_backups, 0, -1):
            src = f"{self.cfg.log_path}.{i}" if i > 1 else self.cfg.log_path
            dst = f"{self.cfg.log_path}.{i+1}" if i > 0 else f"{self.cfg.log_path}.1"
            if i == self.cfg.rotate_backups:
                # remove oldest
                try:
                    os.remove(dst)
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
            try:
                os.replace(src, dst)
            except FileNotFoundError:
                continue
            except Exception:
                # best-effort rotation
                continue

# --------------------------------------------------------------------------------------
# Verification utility (standalone)
# --------------------------------------------------------------------------------------

def verify_log(log_path: str, secrets: Mapping[str, bytes]) -> Tuple[bool, Optional[int], str]:
    """
    Верифицирует целостность JSON Lines-аудита.
    Поддерживает несколько key_id->secret (для ротации ключей).
    Возвращает: (ok, broken_line_no, message)
    """
    prev = "GENESIS"
    key_cache: Dict[str, bytes] = dict(secrets)
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    return (False, i, "invalid json")
                # basic fields
                if "hash" not in ev or "prev" not in ev or "seq" not in ev or "key_id" not in ev:
                    return (False, i, "missing chain fields")
                if ev.get("prev") != prev:
                    return (False, i, "prev mismatch")
                # rebuild payload for HMAC
                payload = dict(ev)
                key_id = str(payload.get("key_id", ""))
                digest_expect = str(payload.pop("hash"))
                # compute
                secret = key_cache.get(key_id)
                if not secret:
                    return (False, i, f"unknown key_id {key_id}")
                digest = hmac.new(secret, _canonical_json(payload), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(digest, digest_expect):
                    return (False, i, "hash mismatch")
                prev = digest_expect
        return (True, None, "ok")
    except FileNotFoundError:
        return (False, None, "file not found")
    except Exception as e:
        return (False, None, f"error: {e!r}")

# --------------------------------------------------------------------------------------
# Example CLI (optional)
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    # Minimal demo: write two events and verify
    cfg = AuditLoggerConfig(
        log_path=os.environ.get("AUDIT_LOG_PATH", "./audit.log"),
        tenant_id=os.environ.get("AUDIT_TENANT_ID", "acme"),
        echo_stdout=True,
    )
    logger = AuditLogger(cfg)
    logger.log(
        action="auth.login",
        result="success",
        severity="low",
        actor_id="j.doe",
        actor_ip="198.51.100.10",
        actor_ua="curl/7.88.1",
        target_type="account",
        target_id="j.doe",
        request_id=str(uuid.uuid4()),
        correlation_id=str(uuid.uuid4()),
        labels=["auth", "login"],
        metadata={"note": "ok", "email": "john.doe@example.com", "pan": "4111 1111 1111 1111"},
    )
    logger.log(
        action="edr.isolate_host",
        result="deny",
        severity="high",
        actor_id="svc-edr",
        actor_type="service",
        target_type="host",
        target_id="host-123",
        reason="policy_violation",
        labels=["edr", "response"],
        metadata={"ak": "AKIA0000000000000000", "token": "ghp_aaaBBBBcccDDDeeeFFF111222333444555"},
    )
    ok, n, msg = logger.verify_file()
    print(json.dumps({"verify_ok": ok, "line": n, "msg": msg}, ensure_ascii=False))
