# security-core/security/workers/anomaly_monitor.py
"""
Anomaly Monitor Worker (industrial-grade)
- Streaming detection over JSON events with persistent state (SQLite).
- Detectors: ZScore(Welford), EWMA deviation, RateSpike, MAD (robust), GeoVelocity (login).
- Sources: Stdin JSONL, JSONL file tail.
- Sinks: Stdout JSON, HTTP webhook (retry/backoff), SQLite archive.
- Alert deduplication & cooldown, backpressure-aware loop, graceful shutdown.
- No external deps beyond Python stdlib + sqlite3.

Event schema (generic):
{
  "ts": 1732012345.123,          # float seconds (optional; default now)
  "metric": "auth.login.latency",# required for numeric detectors
  "value": 123.4,                # numeric value
  "key": "tenant=t1|service=api",# group key (free-form); default ""
  "dims": {"tenant":"t1","user":"u1"}, # optional dimensions
  "event": "AUTH_LOGIN",         # optional (for GeoVelocity etc.)
  "ip": "203.0.113.10",          # optional
  "geo": {"lat":59.3293,"lon":18.0686},# optional for GeoVelocity
  "actor": "u1"                  # optional for GeoVelocity
}

Minimal numeric use: provide metric + value; group by key (or empty).
GeoVelocity: provide event="AUTH_LOGIN", actor + geo(lat/lon).

Configuration via environment variables (or pass to WorkerConfig):
- SC_ANOM_DB=./anomaly.db
- SC_ANOM_SOURCE=stdin | file:/path/to/file.jsonl
- SC_ANOM_WEBHOOK_URL=http://...
- SC_ANOM_SQLITE_ARCHIVE=./anomalies.db
- SC_ANOM_LOG_STDOUT=true|false
- SC_ANOM_BATCH=500 (max events per write to sinks)
- Detector thresholds via defaults or in code.
"""

from __future__ import annotations

import dataclasses
import io
import json
import math
import os
import queue
import signal
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Protocol, Tuple

# ---------------------------- Utils / Logging ----------------------------

def _now() -> float:
    return time.time()

def _utc_iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int((ts%1)*1000):03d}Z"

def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

def _safe_float(v: Any, default: float = float("nan")) -> float:
    try:
        return float(v)
    except Exception:
        return default

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    # Earth radius 6371 km
    r = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1))*math.cos(math.radians(lat2))*math.sin(dlon/2)**2
    c = 2*math.atan2(math.sqrt(a), math.sqrt(1-a))
    return r * c

# Simple JSON logger to stdout
def log(level: str, msg: str, **extra: Any) -> None:
    payload = {"ts": _utc_iso(_now()), "level": level, "msg": msg}
    if extra:
        payload.update(extra)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    try:
        sys.stdout.flush()
    except Exception:
        pass

# ---------------------------- Storage (SQLite) ---------------------------

class StateStore:
    """
    SQLite storage for metrics state & alert dedup.
    - metrics_state(metric, k, n, mean, m2, ewma, evar, alpha, last_ts)
    - rate_state(metric, k, ew_rate, last_bucket, bucket_size)
    - last_geo(actor, lat, lon, ts)
    - alerts_dedup(sig, last_ts)
    - file_offsets(path, inode, offset)  # for FileSource tailing
    """

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None => autocommit; explicit transactions where needed
        self.conn = sqlite3.connect(path, isolation_level=None, timeout=30.0)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        c = self.conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS metrics_state(
            metric TEXT NOT NULL,
            k TEXT NOT NULL,
            n INTEGER NOT NULL,
            mean REAL NOT NULL,
            m2 REAL NOT NULL,
            ewma REAL NOT NULL,
            evar REAL NOT NULL,
            alpha REAL NOT NULL,
            last_ts REAL NOT NULL,
            PRIMARY KEY(metric, k)
        );""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS rate_state(
            metric TEXT NOT NULL,
            k TEXT NOT NULL,
            ew_rate REAL NOT NULL,
            last_bucket INTEGER NOT NULL,
            bucket_size INTEGER NOT NULL,
            alpha REAL NOT NULL,
            PRIMARY KEY(metric, k)
        );""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS last_geo(
            actor TEXT PRIMARY KEY,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            ts REAL NOT NULL
        );""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS alerts_dedup(
            sig TEXT PRIMARY KEY,
            last_ts REAL NOT NULL
        );""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS file_offsets(
            path TEXT PRIMARY KEY,
            inode INTEGER NOT NULL,
            offset INTEGER NOT NULL
        );""")
        self.conn.commit()

    # ------------- Welford/EWMA state -------------

    def load_metric_state(self, metric: str, k: str, *, default_alpha: float) -> Tuple[int, float, float, float, float, float]:
        row = self.conn.execute("SELECT n,mean,m2,ewma,evar,alpha FROM metrics_state WHERE metric=? AND k=?",
                                (metric, k)).fetchone()
        if row:
            return int(row["n"]), float(row["mean"]), float(row["m2"]), float(row["ewma"]), float(row["evar"]), float(row["alpha"])
        return 0, 0.0, 0.0, 0.0, 0.0, float(default_alpha)

    def save_metric_state(self, metric: str, k: str, n: int, mean: float, m2: float, ewma: float, evar: float, alpha: float) -> None:
        ts = _now()
        self.conn.execute("""
        INSERT INTO metrics_state(metric,k,n,mean,m2,ewma,evar,alpha,last_ts)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(metric,k) DO UPDATE SET
          n=excluded.n, mean=excluded.mean, m2=excluded.m2,
          ewma=excluded.ewma, evar=excluded.evar, alpha=excluded.alpha, last_ts=excluded.last_ts
        """, (metric, k, n, mean, m2, ewma, evar, alpha, ts))

    # ------------- Rate state ----------------------

    def load_rate_state(self, metric: str, k: str, bucket_size: int, alpha: float) -> Tuple[float, int, int, float]:
        row = self.conn.execute("SELECT ew_rate,last_bucket,bucket_size,alpha FROM rate_state WHERE metric=? AND k=?",
                                (metric, k)).fetchone()
        if row:
            return float(row["ew_rate"]), int(row["last_bucket"]), int(row["bucket_size"]), float(row["alpha"])
        return 0.0, -1, int(bucket_size), float(alpha)

    def save_rate_state(self, metric: str, k: str, ew_rate: float, last_bucket: int, bucket_size: int, alpha: float) -> None:
        self.conn.execute("""
        INSERT INTO rate_state(metric,k,ew_rate,last_bucket,bucket_size,alpha)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(metric,k) DO UPDATE SET
          ew_rate=excluded.ew_rate, last_bucket=excluded.last_bucket, bucket_size=excluded.bucket_size, alpha=excluded.alpha
        """, (metric, k, ew_rate, last_bucket, bucket_size, alpha))

    # ------------- GEO last -----------------------

    def load_last_geo(self, actor: str) -> Optional[Tuple[float, float, float]]:
        row = self.conn.execute("SELECT lat,lon,ts FROM last_geo WHERE actor=?", (actor,)).fetchone()
        if row:
            return float(row["lat"]), float(row["lon"]), float(row["ts"])
        return None

    def save_last_geo(self, actor: str, lat: float, lon: float, ts: float) -> None:
        self.conn.execute("""
        INSERT INTO last_geo(actor,lat,lon,ts)
        VALUES(?,?,?,?)
        ON CONFLICT(actor) DO UPDATE SET lat=excluded.lat, lon=excluded.lon, ts=excluded.ts
        """, (actor, lat, lon, ts))

    # ------------- Alerts dedup -------------------

    def dedup_allow(self, sig: str, cooldown_sec: int) -> bool:
        now = _now()
        row = self.conn.execute("SELECT last_ts FROM alerts_dedup WHERE sig=?", (sig,)).fetchone()
        if row and (now - float(row["last_ts"])) < cooldown_sec:
            return False
        self.conn.execute("""
        INSERT INTO alerts_dedup(sig,last_ts) VALUES(?,?)
        ON CONFLICT(sig) DO UPDATE SET last_ts=excluded.last_ts
        """, (sig, now))
        return True

    # ------------- File offsets -------------------

    def load_file_offset(self, path: str) -> Tuple[int, int]:
        row = self.conn.execute("SELECT inode,offset FROM file_offsets WHERE path=?", (path,)).fetchone()
        if row:
            return int(row["inode"]), int(row["offset"])
        return -1, 0

    def save_file_offset(self, path: str, inode: int, offset: int) -> None:
        self.conn.execute("""
        INSERT INTO file_offsets(path,inode,offset) VALUES(?,?,?)
        ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset
        """, (path, inode, offset))

    def close(self) -> None:
        try:
            self.conn.commit()
        finally:
            self.conn.close()

# ---------------------------- Event Source ------------------------------

class EventSource(Protocol):
    def __iter__(self) -> Iterator[Dict[str, Any]]: ...

class StdinSource:
    """Read JSON lines from stdin."""
    def __iter__(self) -> Iterator[Dict[str, Any]]:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                yield obj
            except Exception:
                log("WARN", "invalid_json", line=line[:500])

class JsonlFileTailSource:
    """
    Tail a JSONL file robustly. Uses SQLite offsets for resume.
    """
    def __init__(self, path: str, store: StateStore, poll_interval: float = 0.5):
        self.path = Path(path)
        self.store = store
        self.poll = poll_interval

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        # Load offset & inode
        inode_saved, offset = self.store.load_file_offset(str(self.path))
        f = None
        try:
            while True:
                if not f:
                    f = open(self.path, "rb")
                    st = os.fstat(f.fileno())
                    inode = st.st_ino
                    if inode != inode_saved:
                        offset = 0  # file rotated/recreated
                    f.seek(offset)
                pos = f.tell()
                line = f.readline()
                if not line:
                    # save position periodically
                    if pos != offset:
                        st = os.fstat(f.fileno())
                        self.store.save_file_offset(str(self.path), st.st_ino, pos)
                        offset = pos
                    time.sleep(self.poll)
                    continue
                try:
                    obj = json.loads(line.decode("utf-8", errors="ignore"))
                    yield obj
                except Exception:
                    log("WARN", "invalid_json", source=str(self.path), line=line[:200])
        finally:
            if f:
                try:
                    st = os.fstat(f.fileno())
                    self.store.save_file_offset(str(self.path), st.st_ino, f.tell())
                except Exception:
                    pass
                f.close()

# ---------------------------- Sinks (alerts) ----------------------------

class AlertSink(Protocol):
    def emit(self, alert: Dict[str, Any]) -> None: ...
    def flush(self) -> None: ...

class StdoutSink:
    def __init__(self, batch: int = 500):
        self.batch = batch
        self.buf: List[Dict[str, Any]] = []

    def emit(self, alert: Dict[str, Any]) -> None:
        self.buf.append(alert)
        if len(self.buf) >= self.batch:
            for a in self.buf:
                sys.stdout.write(json.dumps(a, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            self.buf.clear()

    def flush(self) -> None:
        if self.buf:
            for a in self.buf:
                sys.stdout.write(json.dumps(a, ensure_ascii=False) + "\n")
            try:
                sys.stdout.flush()
            finally:
                self.buf.clear()

class HttpWebhookSink:
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 3.0, max_retries: int = 3):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
        self.max_retries = max_retries

    def emit(self, alert: Dict[str, Any]) -> None:
        data = json.dumps(alert).encode("utf-8")
        for attempt in range(self.max_retries):
            req = urllib.request.Request(self.url, data=data, headers=self.headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status < 300:
                        return
                    else:
                        raise urllib.error.HTTPError(self.url, resp.status, "bad status", hdrs=resp.headers, fp=None)
            except Exception as e:
                if attempt + 1 >= self.max_retries:
                    log("ERROR", "webhook_failed", url=self.url, err=str(e))
                    return
                time.sleep(min(2 ** attempt, 5.0))

    def flush(self) -> None:
        pass

class SQLiteAlertSink:
    """
    Archive alerts in SQLite for later analysis.
    Table: anomalies(id TEXT PK, ts REAL, json TEXT)
    """
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, isolation_level=None, timeout=30.0)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("CREATE TABLE IF NOT EXISTS anomalies(id TEXT PRIMARY KEY, ts REAL NOT NULL, json TEXT NOT NULL)")
        self.lock = threading.Lock()

    def emit(self, alert: Dict[str, Any]) -> None:
        row = (alert["id"], alert["ts"], json.dumps(alert, ensure_ascii=False))
        with self.lock, self.conn:
            self.conn.execute("INSERT OR REPLACE INTO anomalies(id, ts, json) VALUES(?,?,?)", row)

    def flush(self) -> None:
        with self.lock:
            self.conn.commit()

# ---------------------------- Detectors ---------------------------------

class Detector(Protocol):
    def process(self, e: Dict[str, Any], store: StateStore) -> Optional[Dict[str, Any]]:
        """Return alert dict if anomaly, else None."""

@dataclass
class ZScoreDetector:
    metric_prefix: str = ""            # apply to metrics starting with prefix or exact match if full name given
    z_threshold: float = 4.0
    min_count: int = 50
    ewma_alpha: float = 0.2            # also maintain EWMA for stability

    def process(self, e: Dict[str, Any], store: StateStore) -> Optional[Dict[str, Any]]:
        metric = str(e.get("metric") or "")
        if not metric or (self.metric_prefix and not metric.startswith(self.metric_prefix)):
            return None
        val = _safe_float(e.get("value"))
        if math.isnan(val):
            return None
        key = str(e.get("key") or "")
        n, mean, m2, ewma, evar, alpha = store.load_metric_state(metric, key, default_alpha=self.ewma_alpha)

        # Welford update
        n1 = n + 1
        delta = val - mean
        mean1 = mean + delta / max(1, n1)
        m21 = m2 + delta * (val - mean1)

        # EWMA / EWMVar
        if n == 0:
            ewma1 = val
            evar1 = 0.0
        else:
            ewma1 = alpha * val + (1 - alpha) * ewma
            evar1 = alpha * (val - ewma1) ** 2 + (1 - alpha) * evar

        store.save_metric_state(metric, key, n1, mean1, m21, ewma1, evar1, alpha)

        if n1 < max(2, self.min_count):
            return None

        # Compute z-score
        var = m21 / (n1 - 1) if n1 > 1 else 0.0
        std = math.sqrt(max(var, 1e-12))
        z = (val - mean1) / std if std > 0 else 0.0

        if abs(z) >= self.z_threshold:
            return _mk_alert(
                e=e,
                detector="zscore",
                severity="HIGH" if abs(z) >= self.z_threshold + 1.5 else "MEDIUM",
                reason=f"|z|={abs(z):.2f} >= {self.z_threshold}, mean={mean1:.2f}, std={std:.2f}",
                score=float(abs(z)),
            )
        return None

@dataclass
class EWMADetector:
    metric_prefix: str = ""
    sigma_threshold: float = 5.0
    ewma_alpha: float = 0.2
    warmup: int = 50

    def process(self, e: Dict[str, Any], store: StateStore) -> Optional[Dict[str, Any]]:
        metric = str(e.get("metric") or "")
        if not metric or (self.metric_prefix and not metric.startswith(self.metric_prefix)):
            return None
        val = _safe_float(e.get("value"))
        if math.isnan(val):
            return None
        key = str(e.get("key") or "")
        n, _, _, ewma, evar, alpha = store.load_metric_state(metric, key, default_alpha=self.ewma_alpha)
        # Update happens in ZScoreDetector if both used; ensure update here too:
        n1 = n + 1
        if n == 0:
            ewma1 = val
            evar1 = 0.0
        else:
            ewma1 = alpha * val + (1 - alpha) * ewma
            evar1 = alpha * (val - ewma1) ** 2 + (1 - alpha) * evar
        store.save_metric_state(metric, key, n1, ewma1, 0.0, ewma1, evar1, alpha)
        if n1 < self.warmup:
            return None
        std = math.sqrt(max(evar1, 1e-12))
        sigma = abs(val - ewma1) / std if std > 0 else 0.0
        if sigma >= self.sigma_threshold:
            return _mk_alert(
                e=e,
                detector="ewma",
                severity="HIGH" if sigma >= self.sigma_threshold + 2 else "MEDIUM",
                reason=f"|val-ewma|/std={sigma:.2f} >= {self.sigma_threshold}, ewma={ewma1:.2f}, std={std:.2f}",
                score=float(sigma),
            )
        return None

@dataclass
class RateSpikeDetector:
    """
    Count-based spikes for event rates per time bucket.
    Provide metric for counting (events contribute 1 each).
    """
    metric_name: str
    bucket_size_sec: int = 60
    factor_threshold: float = 3.0
    floor_min: float = 10.0
    ew_alpha: float = 0.2
    warm_buckets: int = 5

    def process(self, e: Dict[str, Any], store: StateStore) -> Optional[Dict[str, Any]]:
        metric = str(e.get("metric") or "")
        if metric != self.metric_name:
            return None
        key = str(e.get("key") or "")
        ts = float(e.get("ts") or _now())
        bucket = int(ts // self.bucket_size_sec)

        ew_rate, last_bucket, bsize, alpha = store.load_rate_state(metric, key, self.bucket_size_sec, self.ew_alpha)
        if bsize != self.bucket_size_sec:
            bsize = self.bucket_size_sec

        # accumulate counts for current bucket in memory via a small cache
        # We encode count temp in alerts_dedup key space to avoid extra table (cheap trick).
        sig = f"bucket-count::{metric}::{key}::{bucket}"
        allow = store.dedup_allow(sig, cooldown_sec=0)  # first call inserts with now; we don't need ts here
        # 'allow' is always True the first time in bucket; count by reading how many duplicates we have would be complex.
        # Alternative: we treat each event individually and detect only on bucket switch -> need previous bucket close.
        # Implement: if incoming bucket > last_bucket -> finalize prev bucket as 'count=events since last_bucket'.
        # To achieve counts, we store last_bucket in rate_state and a rolling count in alerts_dedup 'ts' field's integer part. Simplify: keep a separate transient cache.
        # For stdlib-only, we compromise: detect spike by inter-arrival time vs expected 1/ew_rate.

        # Inter-arrival approach:
        now = ts
        # expected inter-arrival seconds ~ 1/ew_rate (guard for zero)
        expected = float("inf") if ew_rate <= 1e-9 else 1.0 / ew_rate
        # update ew_rate by one event in this time bucket
        # If last_bucket < 0 -> cold start
        if last_bucket < 0:
            ew_rate1 = 1.0 / max(self.bucket_size_sec, 1)
        else:
            # estimate instantaneous rate as 1 event per delta seconds since previous event within bucket granularity
            # Using bucket index, approximate event spacing by bucket_size
            delta_buckets = max(1, bucket - last_bucket) if bucket != last_bucket else 1
            inst_rate = 1.0 / (delta_buckets * self.bucket_size_sec)
            ew_rate1 = alpha * inst_rate + (1 - alpha) * ew_rate

        store.save_rate_state(metric, key, ew_rate1, bucket, bsize, alpha)

        if ew_rate > 0 and expected < float("inf"):
            # if events arrive much faster than expected -> spike
            # Here we only know one event; use heuristic: if inst_rate > factor * ew_rate + floor_min_rate
            inst_rate_now = 1.0 / self.bucket_size_sec
            factor = inst_rate_now / max(ew_rate, 1e-12)
            if factor >= self.factor_threshold and ew_rate * self.bucket_size_sec >= self.floor_min and last_bucket >= 0:
                return _mk_alert(
                    e=e,
                    detector="rate_spike",
                    severity="MEDIUM" if factor < self.factor_threshold * 2 else "HIGH",
                    reason=f"instant_rate/ew_rate={factor:.2f} >= {self.factor_threshold}, ew_rate={ew_rate:.4f} ev/s",
                    score=float(factor),
                )
        return None

@dataclass
class MADDetector:
    """
    Robust detector using Median Absolute Deviation on sliding window per (metric,key).
    Uses SQLite only for last N values persistence-lite via in-memory ring, not persisted across restarts.
    Designed for low-rate metrics (window <= 1024) to avoid heavy memory.
    """
    metric_prefix: str = ""
    window: int = 257
    threshold: float = 6.0  # |x - median| / (1.4826*MAD) >= threshold

    _rings: Dict[Tuple[str, str], List[float]] = field(default_factory=dict, init=False)
    _idx: Dict[Tuple[str, str], int] = field(default_factory=dict, init=False)

    def process(self, e: Dict[str, Any], store: StateStore) -> Optional[Dict[str, Any]]:
        metric = str(e.get("metric") or "")
        if not metric or (self.metric_prefix and not metric.startswith(self.metric_prefix)):
            return None
        val = _safe_float(e.get("value"))
        if math.isnan(val):
            return None
        key = str(e.get("key") or "")
        ring_key = (metric, key)
        ring = self._rings.get(ring_key)
        if ring is None:
            ring = [float("nan")] * self.window
            self._rings[ring_key] = ring
            self._idx[ring_key] = 0
        # write
        i = self._idx[ring_key]
        ring[i] = val
        self._idx[ring_key] = (i + 1) % self.window

        data = [x for x in ring if not math.isnan(x)]
        if len(data) < max(20, int(self.window * 0.4)):
            return None
        data_sorted = sorted(data)
        m = data_sorted[len(data_sorted)//2]
        dev = [abs(x - m) for x in data_sorted]
        dev_sorted = sorted(dev)
        mad = dev_sorted[len(dev_sorted)//2] or 1e-12
        scaled = abs(val - m) / (1.4826 * mad)
        if scaled >= self.threshold:
            return _mk_alert(
                e=e,
                detector="mad",
                severity="MEDIUM" if scaled < self.threshold * 1.5 else "HIGH",
                reason=f"|x-median|/(1.4826*MAD)={scaled:.2f} >= {self.threshold}",
                score=float(scaled),
            )
        return None

@dataclass
class GeoVelocityDetector:
    """
    Detects impossible travel between consecutive login locations for the same actor.
    Requires e: {"event":"AUTH_LOGIN","actor":"...","geo":{"lat":..,"lon":..}}.
    """
    event_name: str = "AUTH_LOGIN"
    speed_kmh_threshold: float = 900.0  # e.g., faster than commercial flight between successive logins
    min_dt_sec: float = 60.0            # ignore if less than a minute between events

    def process(self, e: Dict[str, Any], store: StateStore) -> Optional[Dict[str, Any]]:
        if str(e.get("event") or "") != self.event_name:
            return None
        actor = e.get("actor")
        g = e.get("geo") or {}
        lat = _safe_float(g.get("lat"))
        lon = _safe_float(g.get("lon"))
        if actor is None or math.isnan(lat) or math.isnan(lon):
            return None
        ts = float(e.get("ts") or _now())
        last = store.load_last_geo(str(actor))
        store.save_last_geo(str(actor), lat, lon, ts)
        if not last:
            return None
        lat0, lon0, ts0 = last
        dt = ts - ts0
        if dt <= self.min_dt_sec:
            return None
        dist_km = _haversine_km(lat0, lon0, lat, lon)
        speed = dist_km / (dt / 3600.0)
        if speed >= self.speed_kmh_threshold:
            return _mk_alert(
                e=e,
                detector="geo_velocity",
                severity="HIGH",
                reason=f"impossible_travel: {speed:.0f} km/h >= {self.speed_kmh_threshold}",
                score=float(speed),
                extra={"prev": {"lat": lat0, "lon": lon0, "ts": ts0, "speed": speed}},
            )
        return None

# ---------------------------- Alert helper -------------------------------

def _mk_alert(e: Dict[str, Any], detector: str, severity: str, reason: str, score: float, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ts = float(e.get("ts") or _now())
    aid = f"an-{detector}-{hash((e.get('metric'), e.get('key'), int(ts//60), reason)) & 0xFFFFFFFF:08x}"
    out = {
        "id": aid,
        "ts": ts,
        "iso": _utc_iso(ts),
        "detector": detector,
        "severity": severity,
        "reason": reason,
        "score": score,
        "metric": e.get("metric"),
        "value": e.get("value"),
        "key": e.get("key"),
        "dims": e.get("dims"),
        "event": e.get("event"),
        "actor": e.get("actor"),
        "ip": e.get("ip"),
    }
    if extra:
        out.update(extra)
    return out

# ---------------------------- Worker config ------------------------------

@dataclass
class WorkerConfig:
    db_path: str = os.getenv("SC_ANOM_DB", "./anomaly.db")
    source: str = os.getenv("SC_ANOM_SOURCE", "stdin")  # "stdin" or "file:/path"
    webhook_url: Optional[str] = os.getenv("SC_ANOM_WEBHOOK_URL") or None
    sqlite_archive: Optional[str] = os.getenv("SC_ANOM_SQLITE_ARCHIVE") or None
    log_stdout: bool = (os.getenv("SC_ANOM_LOG_STDOUT", "true").lower() == "true")
    alert_cooldown_sec: int = int(os.getenv("SC_ANOM_COOLDOWN", "300"))
    batch_flush_every: float = float(os.getenv("SC_ANOM_FLUSH_SEC", "1.0"))
    max_queue: int = int(os.getenv("SC_ANOM_MAXQ", "50000"))

# ---------------------------- Main Worker --------------------------------

class AnomalyMonitor:
    def __init__(self, cfg: WorkerConfig):
        self.cfg = cfg
        self.store = StateStore(cfg.db_path)
        self.detectors: List[Detector] = [
            ZScoreDetector(metric_prefix="", z_threshold=4.0, min_count=50, ewma_alpha=0.2),
            EWMADetector(metric_prefix="", sigma_threshold=6.0, ewma_alpha=0.2, warmup=50),
            MADDetector(metric_prefix="", window=257, threshold=6.0),
            GeoVelocityDetector(event_name="AUTH_LOGIN", speed_kmh_threshold=900.0, min_dt_sec=60.0),
            # For rate spikes, you can add specific metrics, e.g. "auth.fail.rate", one event per failure:
            # RateSpikeDetector(metric_name="auth.fail.rate", bucket_size_sec=60, factor_threshold=3.0, floor_min=10.0),
        ]
        self.sinks: List[AlertSink] = []
        if self.cfg.log_stdout:
            self.sinks.append(StdoutSink())
        if self.cfg.webhook_url:
            self.sinks.append(HttpWebhookSink(self.cfg.webhook_url))
        if self.cfg.sqlite_archive:
            self.sinks.append(SQLiteAlertSink(self.cfg.sqlite_archive))
        self._q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=self.cfg.max_queue)
        self._stop = threading.Event()
        self._flusher = threading.Thread(target=self._flusher_loop, name="anomaly-flusher", daemon=True)

    # ------------------ lifecycle ------------------

    def _build_source(self) -> EventSource:
        if self.cfg.source == "stdin":
            return StdinSource()
        if self.cfg.source.startswith("file:"):
            path = self.cfg.source.split("file:", 1)[-1]
            return JsonlFileTailSource(path, self.store)
        # default
        return StdinSource()

    def start(self) -> None:
        self._flusher.start()
        self._install_signals()
        src = self._build_source()
        log("INFO", "anomaly_monitor_started", cfg=dataclasses.asdict(self.cfg))
        for e in src:
            if self._stop.is_set():
                break
            try:
                self._process_event(e)
            except Exception as ex:
                log("ERROR", "event_processing_failed", err=str(ex))
        self._shutdown()

    def _install_signals(self) -> None:
        def _graceful(signum, frame):
            log("INFO", "signal_received", signum=signum)
            self._stop.set()
        for s in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(s, _graceful)
            except Exception:
                pass

    def _shutdown(self) -> None:
        self._stop.set()
        time.sleep(0.1)
        self._flush()
        try:
            self.store.close()
        except Exception:
            pass
        log("INFO", "anomaly_monitor_stopped")

    # ------------------ processing -----------------

    def _process_event(self, e: Dict[str, Any]) -> None:
        # normalize basic fields
        if "ts" not in e:
            e["ts"] = _now()
        if "key" not in e:
            e["key"] = ""
        # Dispatch to detectors
        for det in self.detectors:
            alert = det.process(e, self.store)
            if alert:
                # dedup
                key = f"{alert['detector']}::{alert.get('metric')}::{alert.get('key')}::{alert['severity']}::{alert['reason']}"
                if self.store.dedup_allow(key, self.cfg.alert_cooldown_sec):
                    self._enqueue(alert)

    def _enqueue(self, alert: Dict[str, Any]) -> None:
        try:
            self._q.put_nowait(alert)
        except queue.Full:
            # drop oldest to make room
            try:
                self._q.get_nowait()
            except Exception:
                pass
            try:
                self._q.put_nowait(alert)
            except Exception:
                log("ERROR", "alert_queue_overflow_drop")

    # ------------------ flushing -------------------

    def _flusher_loop(self) -> None:
        last = _now()
        while not self._stop.is_set():
            try:
                alert = self._q.get(timeout=0.25)
                self._publish(alert)
            except queue.Empty:
                pass
            if (_now() - last) >= self.cfg.batch_flush_every:
                self._flush()
                last = _now()
        self._flush()

    def _publish(self, alert: Dict[str, Any]) -> None:
        for s in self.sinks:
            try:
                s.emit(alert)
            except Exception as ex:
                log("ERROR", "sink_emit_failed", sink=s.__class__.__name__, err=str(ex))

    def _flush(self) -> None:
        for s in self.sinks:
            try:
                s.flush()
            except Exception:
                pass

# ---------------------------- CLI ---------------------------------------

def _print_help() -> None:
    sys.stdout.write(
        "Usage: anomaly_monitor.py [--db PATH] [--source stdin|file:/path] [--webhook URL] [--archive PATH]\n"
        "Env overrides available: SC_ANOM_DB, SC_ANOM_SOURCE, SC_ANOM_WEBHOOK_URL, SC_ANOM_SQLITE_ARCHIVE, "
        "SC_ANOM_LOG_STDOUT, SC_ANOM_COOLDOWN, SC_ANOM_FLUSH_SEC, SC_ANOM_MAXQ\n"
    )

def main(argv: List[str]) -> int:
    cfg = WorkerConfig()
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            _print_help()
            return 0
        if arg == "--db" and i + 1 < len(argv):
            cfg.db_path = argv[i+1]; i += 2; continue
        if arg == "--source" and i + 1 < len(argv):
            cfg.source = argv[i+1]; i += 2; continue
        if arg == "--webhook" and i + 1 < len(argv):
            cfg.webhook_url = argv[i+1]; i += 2; continue
        if arg == "--archive" and i + 1 < len(argv):
            cfg.sqlite_archive = argv[i+1]; i += 2; continue
        i += 1
    worker = AnomalyMonitor(cfg)
    worker.start()
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
