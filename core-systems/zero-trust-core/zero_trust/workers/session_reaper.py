# zero_trust/workers/session_reaper.py
from __future__ import annotations

import contextlib
import dataclasses
import errno
import json
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Union, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------- Optional deps: import gracefully --------
try:
    import redis  # type: ignore
except Exception:
    redis = None  # type: ignore

try:
    import psycopg2  # type: ignore
    import psycopg2.extras  # type: ignore
except Exception:
    psycopg2 = None  # type: ignore

try:
    from kubernetes import client as k8s_client, config as k8s_config
    from kubernetes.client import ApiClient
    from kubernetes.client.rest import ApiException
except Exception:
    k8s_client = None  # type: ignore
    k8s_config = None  # type: ignore
    ApiClient = None  # type: ignore
    ApiException = Exception  # type: ignore

# Cilium quarantining is optional
with contextlib.suppress(Exception):
    from zero_trust.adapters.cilium_adapter import CiliumAdapter, KubernetesConfig as KubeCfg  # type: ignore


# =========================
# Utility / Infra
# =========================

def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)

def to_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)

def sleep_seconds(sec: float) -> None:
    time.sleep(sec)

def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "y", "on")

class RateLimiter:
    """
    Simple token-bucket limiter for revocations per second.
    """
    def __init__(self, rate_per_sec: float, capacity: Optional[int] = None) -> None:
        self.rate = max(rate_per_sec, 0.0)
        self.capacity = capacity if capacity is not None else max(int(rate_per_sec), 1)
        self.tokens = self.capacity
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self, amount: int = 1) -> None:
        if self.rate <= 0:
            return
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens < amount:
                need = amount - self.tokens
                wait = need / self.rate
                time.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= amount

def retry(
    attempts: int = 3,
    base_delay: float = 0.5,
    factor: float = 2.0,
    retry_on: Tuple[type, ...] = (Exception,),
    logger: Optional[logging.Logger] = None,
) -> Callable:
    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            _logger = logger or logging.getLogger("session_reaper")
            d = base_delay
            for i in range(attempts):
                try:
                    return fn(*args, **kwargs)
                except retry_on as e:
                    if i == attempts - 1:
                        raise
                    _logger.warning("Retryable error: %s. Retry %d/%d in %.2fs",
                                    e.__class__.__name__, i + 1, attempts - 1, d)
                    time.sleep(d)
                    d *= factor
        return wrapper
    return decorator

class FileLock:
    """
    Best-effort file lock. For distributed lock prefer RedisLock.
    """
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self.fd: Optional[int] = None

    def acquire(self) -> bool:
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(self.fd, str(os.getpid()).encode("utf-8"))
            return True
        except OSError as e:
            if e.errno == errno.EEXIST:
                return False
            raise

    def release(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            finally:
                self.fd = None
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self.path)

class RedisLock:
    """
    Distributed lock using Redis SET NX PX.
    """
    def __init__(self, client: "redis.Redis", key: str, ttl_ms: int = 60000) -> None:
        self.client = client
        self.key = key
        self.ttl_ms = ttl_ms
        self.value = f"reaper-{os.getpid()}-{time.time_ns()}"

    def acquire(self) -> bool:
        return bool(self.client.set(self.key, self.value, nx=True, px=self.ttl_ms))

    def refresh(self) -> None:
        self.client.pexpire(self.key, self.ttl_ms)

    def release(self) -> None:
        # Best-effort release
        val = self.client.get(self.key)
        if val and val.decode("utf-8") == self.value:
            self.client.delete(self.key)


# =========================
# Domain: Sessions
# =========================

@dataclass
class SessionRecord:
    """
    Canonical session view used by the reaper.
    """
    session_id: str
    subject: str                 # user or service identity
    session_type: str            # e.g. "oidc", "k8s_sa", "ssh_cert", "vpn"
    issued_at: datetime
    expires_at: datetime
    last_seen_at: Optional[datetime] = None
    risk_flags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)  # provider-specific data

    def is_expired(self, now: Optional=datetime] = None) -> bool:  # type: ignore[syntax]
        now = now or utc_now()
        return self.expires_at <= now

    def is_idle(self, idle_timeout: Optional[timedelta], now: Optional=datetime] = None) -> bool:  # type: ignore[syntax]
        if not idle_timeout:
            return False
        ref = self.last_seen_at or self.issued_at
        now = now or utc_now()
        return ref + idle_timeout <= now

# Fix accidental bracket typo above for Python correctness
def _sr_is_expired(self, now: Optional[datetime] = None) -> bool:
    now = now or utc_now()
    return self.expires_at <= now
def _sr_is_idle(self, idle_timeout: Optional[timedelta], now: Optional[datetime] = None) -> bool:
    if not idle_timeout:
        return False
    ref = self.last_seen_at or self.issued_at
    now = now or utc_now()
    return ref + idle_timeout <= now
SessionRecord.is_expired = _sr_is_expired  # type: ignore
SessionRecord.is_idle = _sr_is_idle        # type: ignore

class SessionStore(Protocol):
    """
    Abstract storage of session records.
    """
    def fetch_candidates(self, now: datetime, limit: int) -> List[SessionRecord]:
        ...

    def delete(self, session_id: str) -> None:
        ...

class RedisSessionStore(SessionStore):
    """
    Redis layout (example):
      key: zt:sessions:index -> ZSET by expires_at_ms
      key: zt:sessions:<id>  -> JSON payload
    """
    def __init__(self, dsn: str, namespace: str = "zt:sessions") -> None:
        if redis is None:
            raise RuntimeError("redis is not installed. pip install redis")
        self.r = redis.Redis.from_url(dsn, decode_responses=True)
        self.ns = namespace

    def _k(self, *parts: str) -> str:
        return ":".join((self.ns, *parts))

    def fetch_candidates(self, now: datetime, limit: int) -> List[SessionRecord]:
        now_ms = to_ms(now)
        idx = self._k("index")
        ids = self.r.zrangebyscore(idx, min=0, max=now_ms, start=0, num=limit)
        out: List[SessionRecord] = []
        for sid in ids:
            raw = self.r.get(self._k(sid))
            if not raw:
                continue
            try:
                data = json.loads(raw)
                out.append(self._from_json(data))
            except Exception:
                continue
        return out

    def delete(self, session_id: str) -> None:
        pipe = self.r.pipeline()
        pipe.delete(self._k(session_id))
        pipe.zrem(self._k("index"), session_id)
        pipe.execute()

    @staticmethod
    def _from_json(d: Dict[str, Any]) -> SessionRecord:
        def parse_dt(x: Optional[str]) -> Optional[datetime]:
            return datetime.fromisoformat(x) if x else None
        return SessionRecord(
            session_id=d["session_id"],
            subject=d["subject"],
            session_type=d["session_type"],
            issued_at=parse_dt(d["issued_at"]) or utc_now(),
            expires_at=parse_dt(d["expires_at"]) or utc_now(),
            last_seen_at=parse_dt(d.get("last_seen_at")),
            risk_flags=d.get("risk_flags", []),
            attributes=d.get("attributes", {}),
        )

class PostgresSessionStore(SessionStore):
    """
    Example PostgreSQL schema:

    CREATE TABLE zt_sessions (
      session_id TEXT PRIMARY KEY,
      subject TEXT NOT NULL,
      session_type TEXT NOT NULL,
      issued_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      last_seen_at TIMESTAMPTZ,
      risk_flags TEXT[] NOT NULL DEFAULT '{}',
      attributes JSONB NOT NULL DEFAULT '{}'
    );
    CREATE INDEX ON zt_sessions (expires_at);
    """
    def __init__(self, dsn: str) -> None:
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is not installed. pip install psycopg2-binary")
        self.dsn = dsn

    def _conn(self):
        return psycopg2.connect(self.dsn)

    def fetch_candidates(self, now: datetime, limit: int) -> List[SessionRecord]:
        sql = """
        SELECT session_id, subject, session_type, issued_at, expires_at, last_seen_at, risk_flags, attributes
        FROM zt_sessions
        WHERE expires_at <= %(now)s
        ORDER BY expires_at ASC
        LIMIT %(limit)s
        """
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, {"now": now, "limit": limit})
                rows = cur.fetchall()
        out: List[SessionRecord] = []
        for r in rows:
            out.append(SessionRecord(
                session_id=r["session_id"],
                subject=r["subject"],
                session_type=r["session_type"],
                issued_at=r["issued_at"],
                expires_at=r["expires_at"],
                last_seen_at=r.get("last_seen_at"),
                risk_flags=r.get("risk_flags") or [],
                attributes=r.get("attributes") or {},
            ))
        return out

    def delete(self, session_id: str) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM zt_sessions WHERE session_id = %s", (session_id,))


# =========================
# Revokers
# =========================

class RevocationError(Exception):
    pass

class Revoker(Protocol):
    """
    Provider-specific session revocation.
    """
    def supports(self, rec: SessionRecord) -> bool: ...
    def revoke(self, rec: SessionRecord, timeout_sec: float) -> None: ...

class OIDCRevoker:
    """
    Revokes tokens via OAuth 2.0 Token Revocation RFC 7009.
    Attributes required in SessionRecord.attributes:
      {"revocation_endpoint": "...", "client_id": "...", "client_secret": "...",
       "token": "...", "token_type_hint": "access_token|refresh_token"}
    """
    def __init__(self, http_timeout: float = 5.0) -> None:
        self.http_timeout = http_timeout

    def supports(self, rec: SessionRecord) -> bool:
        return rec.session_type.lower() in ("oidc", "oauth2") and "revocation_endpoint" in rec.attributes

    def revoke(self, rec: SessionRecord, timeout_sec: float) -> None:
        import urllib.request
        import urllib.parse
        data = {
            "token": rec.attributes.get("token", ""),
            "token_type_hint": rec.attributes.get("token_type_hint", "access_token"),
            "client_id": rec.attributes.get("client_id", ""),
            "client_secret": rec.attributes.get("client_secret", ""),
        }
        body = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            rec.attributes["revocation_endpoint"],
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with contextlib.closing(urllib.request.urlopen(req, timeout=min(timeout_sec, self.http_timeout))) as resp:
                if resp.status not in (200, 201, 204):
                    raise RevocationError(f"OIDC revocation failed HTTP {resp.status}")
        except Exception as e:
            raise RevocationError(f"OIDC revoke error: {e}") from e

class KubernetesSARevoker:
    """
    Revokes legacy ServiceAccount token by deleting its Secret.
    SessionRecord.attributes should include:
      {"namespace": "...", "secret_name": "..."}  # legacy token secret
    """
    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None, in_cluster: bool = False) -> None:
        self.kubeconfig = kubeconfig
        self.context = context
        self.in_cluster = in_cluster
        self._core: Optional[Any] = None

    def _ensure_client(self) -> None:
        if k8s_client is None or k8s_config is None:
            raise RevocationError("kubernetes client not installed")
        try:
            if self.in_cluster:
                k8s_config.load_incluster_config()
            else:
                k8s_config.load_kube_config(config_file=self.kubeconfig, context=self.context)
            self._core = k8s_client.CoreV1Api()
        except Exception as e:
            raise RevocationError(f"Kubernetes client init failed: {e}") from e

    def supports(self, rec: SessionRecord) -> bool:
        return rec.session_type.lower() in ("k8s_sa", "kubernetes_sa") and \
               "namespace" in rec.attributes and "secret_name" in rec.attributes

    def revoke(self, rec: SessionRecord, timeout_sec: float) -> None:
        self._ensure_client()
        ns = rec.attributes["namespace"]
        secret = rec.attributes["secret_name"]
        try:
            self._core.delete_namespaced_secret(name=secret, namespace=ns, _request_timeout=timeout_sec)  # type: ignore
        except ApiException as e:  # type: ignore
            status = getattr(e, "status", None)
            if status == 404:
                return
            raise RevocationError(f"K8s delete secret failed: {getattr(e, 'body', str(e))}") from e
        except Exception as e:
            raise RevocationError(f"K8s revocation error: {e}") from e


# =========================
# Policy / Config
# =========================

@dataclass
class ReaperPolicy:
    batch_limit: int = 200
    idle_timeout: Optional[timedelta] = None
    grace_period: timedelta = timedelta(seconds=0)      # extra time after expiry
    revoke_timeout_sec: float = 5.0
    rate_limit_per_sec: float = 25.0
    quarantine_on_failure: bool = False
    dry_run: bool = False

@dataclass
class QuarantineConfig:
    enabled: bool = False
    namespace: Optional[str] = None
    cilium_context: Optional[str] = None
    kubeconfig: Optional[str] = None
    in_cluster: bool = False
    policy_name_prefix: str = "zt-quarantine-"
    http_allow_only_health: bool = True

@dataclass
class AuditEvent:
    ts: datetime
    session_id: str
    subject: str
    session_type: str
    action: str
    success: bool
    error: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        def enc(x: Any) -> Any:
            if isinstance(x, datetime):
                return x.isoformat()
            return x
        return json.dumps(dataclasses.asdict(self), default=enc, ensure_ascii=False)

class AuditLogger:
    def __init__(self, sink_path: Union[str, Path]) -> None:
        self.path = Path(sink_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def write(self, evt: AuditEvent) -> None:
        line = evt.to_json()
        with self.lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)
                f.write("\n")


# =========================
# Reaper Worker
# =========================

class SessionReaperWorker:
    """
    Production-grade session reaper:
     - fetches candidates
     - applies policy (expiry + idle)
     - revokes using pluggable revokers
     - audits results
     - optional quarantine when revocation fails
     - supports dry-run, rate-limit, retries, locking, graceful shutdown
    """

    def __init__(
        self,
        store: SessionStore,
        policy: ReaperPolicy,
        revokers: Iterable[Revoker],
        audit: AuditLogger,
        quarantine: Optional[QuarantineConfig] = None,
        logger: Optional[logging.Logger] = None,
        lock: Optional[Union[FileLock, RedisLock]] = None,
        metrics_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.store = store
        self.policy = policy
        self.revokers = list(revokers)
        self.audit = audit
        self.logger = logger or self._default_logger()
        self.quarantine_cfg = quarantine or QuarantineConfig()
        self.limiter = RateLimiter(rate_per_sec=policy.rate_limit_per_sec)
        self._lock = lock
        self._stop = threading.Event()
        self.metrics_sink = metrics_sink
        self._cilium_adapter: Optional["CiliumAdapter"] = None

    @staticmethod
    def _default_logger() -> logging.Logger:
        lg = logging.getLogger("session_reaper")
        if not lg.handlers:
            h = logging.StreamHandler(sys.stdout)
            h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            lg.addHandler(h)
        lg.setLevel(logging.INFO)
        return lg

    def _init_quarantine(self) -> None:
        if not self.quarantine_cfg.enabled:
            return
        try:
            # no type hints if absent
            self._cilium_adapter = CiliumAdapter(  # type: ignore[name-defined]
                k8s=KubeCfg(  # type: ignore[name-defined]
                    kubeconfig=self.quarantine_cfg.kubeconfig,
                    context=self.quarantine_cfg.cilium_context,
                    namespace=self.quarantine_cfg.namespace,
                    in_cluster=self.quarantine_cfg.in_cluster,
                ),
                logger=self.logger,
            )
            self._cilium_adapter.connect()  # type: ignore[union-attr]
        except Exception as e:
            self.logger.error("Quarantine init failed, disabling: %s", e)
            self.quarantine_cfg.enabled = False

    def request_stop(self) -> None:
        self._stop.set()

    def _should_reap(self, rec: SessionRecord, now: datetime) -> bool:
        if self.policy.grace_period.total_seconds() > 0:
            if rec.expires_at + self.policy.grace_period > now:
                return False
        if rec.is_expired(now):
            return True
        if rec.is_idle(self.policy.idle_timeout, now):
            return True
        return False

    def _pick_revoker(self, rec: SessionRecord) -> Optional[Revoker]:
        for r in self.revokers:
            with contextlib.suppress(Exception):
                if r.supports(rec):
                    return r
        return None

    def _audit(self, rec: SessionRecord, action: str, success: bool, error: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> None:
        evt = AuditEvent(
            ts=utc_now(),
            session_id=rec.session_id,
            subject=rec.subject,
            session_type=rec.session_type,
            action=action,
            success=success,
            error=error,
            extra=extra or {},
        )
        self.audit.write(evt)

    def _maybe_quarantine(self, rec: SessionRecord) -> None:
        if not (self.quarantine_cfg.enabled and self._cilium_adapter):
            return
        try:
            ns = self.quarantine_cfg.namespace or rec.attributes.get("namespace")
            name = f"{self.quarantine_cfg.policy_name_prefix}{rec.subject.replace(':', '-').replace('/', '-')}"
            if not ns:
                return
            # Very tight default-deny for the namespace/pod selector from attributes
            pod_selector = rec.attributes.get("pod_selector", {})
            pol = self._cilium_adapter.build_http_allowlist(  # type: ignore[union-attr]
                namespace=ns,
                name=name,
                pod_selector=pod_selector,
                http_rules=[{"method": "GET", "path": "/healthz"}] if self.quarantine_cfg.http_allow_only_health else [],
            )
            pol["metadata"]["labels"] = {"zt.quarantine": "true", "subject": rec.subject}
            if self.policy.dry_run:
                self.logger.info("[dry-run] Would apply quarantine policy: %s", name)
            else:
                self._cilium_adapter.apply_policy(pol, validate=True)  # type: ignore[union-attr]
                self.logger.warning("Applied quarantine policy '%s' for subject '%s'", name, rec.subject)
        except Exception as e:
            self.logger.error("Quarantine failed: %s", e)

    def _revoke_one(self, rec: SessionRecord) -> Tuple[str, bool, Optional[str]]:
        self.limiter.acquire(1)
        if self.policy.dry_run:
            self.logger.info("[dry-run] Would revoke session %s type=%s subject=%s",
                             rec.session_id, rec.session_type, rec.subject)
            return ("dry_run", True, None)

        rev = self._pick_revoker(rec)
        if not rev:
            return ("no_revoker", False, "no revoker supports this session type")

        try:
            # Retry revocation with backoff
            @retry(attempts=3, base_delay=0.5, factor=2.0, logger=self.logger)
            def _do():
                rev.revoke(rec, timeout_sec=self.policy.revoke_timeout_sec)
            _do()
            return ("revoked", True, None)
        except Exception as e:
            return ("revoke_error", False, str(e))

    def run_once(self) -> Dict[str, Any]:
        """
        Executes a single sweep cycle.
        """
        if self._lock:
            acquired = self._lock.acquire()
            if not acquired:
                self.logger.info("Another reaper instance holds the lock. Skipping run.")
                return {"skipped": True}
        try:
            self._init_quarantine()
            now = utc_now()
            candidates = self.store.fetch_candidates(now, limit=self.policy.batch_limit)
            self.logger.info("Fetched %d candidate sessions", len(candidates))

            to_reap: List[SessionRecord] = [r for r in candidates if self._should_reap(r, now)]
            self.logger.info("Selected %d sessions for revocation", len(to_reap))

            results = {"success": 0, "failed": 0, "total": len(to_reap)}
            errors: List[str] = []

            with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
                fut2rec = {pool.submit(self._revoke_one, rec): rec for rec in to_reap}
                for fut in as_completed(fut2rec):
                    rec = fut2rec[fut]
                    try:
                        action, ok, err = fut.result()
                        self._audit(rec, action=action, success=ok, error=err)
                        if ok:
                            results["success"] += 1
                            # remove from store only on real revoke success or dry-run?
                            if not self.policy.dry_run:
                                with contextlib.suppress(Exception):
                                    self.store.delete(rec.session_id)
                        else:
                            results["failed"] += 1
                            if self.policy.quarantine_on_failure:
                                self._maybe_quarantine(rec)
                            if err:
                                errors.append(f"{rec.session_id}:{err}")
                    except Exception as e:
                        results["failed"] += 1
                        msg = f"{rec.session_id}:{e}"
                        errors.append(msg)
                        self._audit(rec, action="internal_error", success=False, error=str(e))

            if self.metrics_sink:
                self.metrics_sink({"ts": utc_now().isoformat(), **results})

            if errors:
                self.logger.warning("Revocation finished with errors: %d", len(errors))
            else:
                self.logger.info("Revocation finished successfully")

            return {"skipped": False, **results, "errors": errors}
        finally:
            if self._lock:
                with contextlib.suppress(Exception):
                    self._lock.release()

    def run_forever(self, interval_sec: float = 30.0) -> None:
        """
        Periodic loop with graceful SIGTERM/SIGINT handling.
        """
        stop_msgs: List[str] = []

        def _handler(signum, frame):
            stop_msgs.append(f"signal {signum}")
            self.request_stop()

        with contextlib.suppress(Exception):
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)

        self.logger.info("SessionReaper started")
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as e:
                self.logger.error("Run error: %s", e)
            finally:
                for _ in range(int(interval_sec * 10)):
                    if self._stop.is_set():
                        break
                    time.sleep(0.1)
        self.logger.info("SessionReaper stopped: %s", ", ".join(stop_msgs) if stop_msgs else "requested")

# =========================
# Bootstrap helper
# =========================

def build_default_worker() -> SessionReaperWorker:
    """
    Convenience builder from environment variables.
    Useful for container entrypoint.
    """
    # Logging
    logger = logging.getLogger("session_reaper")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(h)
    logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

    # Store
    store_backend = os.getenv("STORE_BACKEND", "redis").lower()
    if store_backend == "redis":
        dsn = os.getenv("REDIS_DSN", "redis://localhost:6379/0")
        store: SessionStore = RedisSessionStore(dsn=dsn, namespace=os.getenv("REDIS_NS", "zt:sessions"))
    elif store_backend in ("postgres", "postgresql"):
        dsn = os.getenv("PG_DSN", "postgres://user:pass@localhost:5432/zt")
        store = PostgresSessionStore(dsn=dsn)
    else:
        raise RuntimeError(f"Unsupported STORE_BACKEND: {store_backend}")

    # Policy
    policy = ReaperPolicy(
        batch_limit=int(os.getenv("BATCH_LIMIT", "200")),
        idle_timeout=timedelta(seconds=int(os.getenv("IDLE_TIMEOUT_SEC", "0"))) if int(os.getenv("IDLE_TIMEOUT_SEC", "0")) > 0 else None,
        grace_period=timedelta(seconds=int(os.getenv("GRACE_PERIOD_SEC", "0"))),
        revoke_timeout_sec=float(os.getenv("REVOKE_TIMEOUT_SEC", "5")),
        rate_limit_per_sec=float(os.getenv("RATE_LIMIT_RPS", "25")),
        quarantine_on_failure=_env_bool("QUARANTINE_ON_FAILURE", False),
        dry_run=_env_bool("DRY_RUN", False),
    )

    # Revokers
    revokers: List[Revoker] = [OIDCRevoker(http_timeout=float(os.getenv("OIDC_HTTP_TIMEOUT", "5")))]
    if _env_bool("ENABLE_K8S_SA_REVOKER", True):
        revokers.append(KubernetesSARevoker(
            kubeconfig=os.getenv("KUBECONFIG"),
            context=os.getenv("K8S_CONTEXT"),
            in_cluster=_env_bool("K8S_IN_CLUSTER", False),
        ))

    # Audit
    audit_path = os.getenv("AUDIT_LOG_PATH", "/var/log/zt/session_reaper_audit.jsonl")
    audit = AuditLogger(audit_path)

    # Lock
    lock: Optional[Union[FileLock, RedisLock]] = None
    if _env_bool("ENABLE_REDIS_LOCK", False) and isinstance(store, RedisSessionStore) and redis is not None:
        rl_key = os.getenv("REDIS_LOCK_KEY", "zt:locks:session_reaper")
        lock = RedisLock(store.r, key=rl_key, ttl_ms=int(os.getenv("REDIS_LOCK_TTL_MS", "60000")))
    elif _env_bool("ENABLE_FILE_LOCK", True):
        lock = FileLock(os.getenv("FILE_LOCK_PATH", "/tmp/zt_session_reaper.lock"))

    # Quarantine
    quarantine = QuarantineConfig(
        enabled=_env_bool("QUARANTINE_ENABLED", False),
        namespace=os.getenv("QUARANTINE_NAMESPACE"),
        cilium_context=os.getenv("CILIUM_CONTEXT"),
        kubeconfig=os.getenv("KUBECONFIG"),
        in_cluster=_env_bool("K8S_IN_CLUSTER", False),
        http_allow_only_health=_env_bool("QUARANTINE_ALLOW_ONLY_HEALTH", True),
    )

    return SessionReaperWorker(
        store=store,
        policy=policy,
        revokers=revokers,
        audit=audit,
        quarantine=quarantine,
        logger=logger,
        lock=lock,
    )

if __name__ == "__main__":
    w = build_default_worker()
    mode = os.getenv("RUN_MODE", "loop")
    if mode == "once":
        res = w.run_once()
        print(json.dumps(res, ensure_ascii=False))
    else:
        w.run_forever(interval_sec=float(os.getenv("RUN_INTERVAL_SEC", "30")))
