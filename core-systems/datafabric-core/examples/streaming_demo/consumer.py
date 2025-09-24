#!/usr/bin/env python3
# examples/quickstart_local/streaming_demo/consumer.py
# Industrial-grade demo consumer for DataFabric EventBus (stdlib-only)

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

# -------- Stable exit codes (match cli/main.py style) --------
class Exit:
    OK = 0
    CONFIG = 10
    USAGE = 11
    NOT_FOUND = 12
    ACCESS = 13
    CONFLICT = 14
    BACKEND = 15
    TIMEOUT = 16
    INTERRUPTED = 17
    UNKNOWN = 19

# -------- Logging (human/JSON to stderr) --------
def _is_tty() -> bool:
    try:
        return sys.stderr.isatty()
    except Exception:
        return False

def _ansi(level: str) -> str:
    if not _is_tty():
        return ""
    colors = {"INFO": "\033[36m", "WARN": "\033[33m", "ERROR": "\033[31m", "RESET": "\033[0m"}
    return colors.get(level, "")

class _LogMode:
    json = False

def log(level: str, message: str, **kw) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level, "message": message}
    if kw:
        rec.update(kw)
    if _LogMode.json:
        sys.stderr.write(json.dumps(rec, ensure_ascii=False) + "\n")
    else:
        color, reset = _ansi(level), _ansi("RESET")
        extra = " ".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in kw.items())
        sys.stderr.write(f"{color}[{level}] {message}{reset}" + (f" {extra}" if extra else "") + "\n")
    sys.stderr.flush()

# -------- Idempotency store (SQLite) --------
class IdempotencyStore:
    """
    Простое персистентное хранилище обработанных ключей.
    Схема: table processed(key TEXT PRIMARY KEY, ts INTEGER)
    """
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(db_path), timeout=30, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("CREATE TABLE IF NOT EXISTS processed (key TEXT PRIMARY KEY, ts INTEGER NOT NULL)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON processed(ts)")
        self._conn.commit()

    def seen(self, key: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("SELECT 1 FROM processed WHERE key=? LIMIT 1", (key,))
            return cur.fetchone() is not None

    def mark(self, key: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("INSERT OR IGNORE INTO processed(key, ts) VALUES(?, ?)", (key, int(time.time())))

    def vacuum_old(self, older_than_seconds: int) -> int:
        cutoff = int(time.time()) - max(0, older_than_seconds)
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM processed WHERE ts < ?", (cutoff,))
            return cur.rowcount or 0

# -------- Safe writer for output (append JSONL) --------
class JsonlWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # open in append, line-buffered
        self._fh = open(self.path, "a", encoding="utf-8", buffering=1)

    def write(self, obj: Dict[str, Any]) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
            finally:
                self._fh.close()

# -------- Consumer implementation --------
@dataclass
class ConsumerConfig:
    topic: str
    group: str
    consumer: str
    output: Path
    state_db: Path
    filter_header_key: Optional[str] = None
    filter_header_value: Optional[str] = None
    log_json: bool = False
    metrics_interval: int = 10  # seconds
    vacuum_ttl: Optional[int] = 7 * 24 * 3600  # seconds (7 days)

# graceful shutdown flag
_STOP = {"value": False}

def _setup_signals() -> None:
    def handler(signum, frame):
        log("WARN", "Shutdown signal received", sig=signum)
        _STOP["value"] = True
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

def _idem_key(env) -> str:
    # Prefer explicit idempotency_key, else message.key, else message_id
    return env.idempotency_key or env.message.key or env.message_id

def run_consumer(cfg: ConsumerConfig) -> int:
    # defer import of EventBus to keep example self-contained
    try:
        from datafabric.io.bus import EventBus, Message, Ack, SubscriptionFilter
    except Exception as e:
        log("ERROR", "Failed to import EventBus", error=str(e))
        return Exit.BACKEND

    _LogMode.json = cfg.log_json
    _setup_signals()

    # Init subsystems
    idem = IdempotencyStore(cfg.state_db)
    writer = JsonlWriter(cfg.output)
    bus = EventBus()  # InMemory backend for local quickstart
    bus.set_acl(cfg.topic, producers={"*"}, consumers={"*"})

    # Build filter if requested
    flt = None
    if cfg.filter_header_key and cfg.filter_header_value:
        flt = SubscriptionFilter(header_equals={cfg.filter_header_key: cfg.filter_header_value})

    # Metrics reporter
    def metrics_loop():
        while not _STOP["value"]:
            m = bus.metrics()
            log("INFO", "metrics", **m)
            time.sleep(max(1, cfg.metrics_interval))

    reporter = threading.Thread(target=metrics_loop, name="metrics", daemon=True)
    reporter.start()

    # Optional periodic vacuum
    def vacuum_loop():
        if not cfg.vacuum_ttl:
            return
        while not _STOP["value"]:
            deleted = idem.vacuum_old(cfg.vacuum_ttl)
            if deleted:
                log("INFO", "idempotency_vacuum", deleted=deleted)
            for _ in range(60):
                if _STOP["value"]:
                    return
                time.sleep(1)

    vac = threading.Thread(target=vacuum_loop, name="idem-vacuum", daemon=True)
    vac.start()

    # Business handler
    def handler(env) -> Any:
        # type: (Envelope) -> Ack
        key = _idem_key(env)
        # header filter (extra guard if broker filter absent)
        if cfg.filter_header_key and cfg.filter_header_value:
            if env.message.headers.get(cfg.filter_header_key) != cfg.filter_header_value:
                return Ack.DROP

        # Idempotency
        if idem.seen(key):
            log("WARN", "duplicate_skip", message_id=env.message_id, key=key)
            return Ack.DROP

        # Simulate processing: write JSONL with trace metadata
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "message_id": env.message_id,
            "trace_id": env.trace_id,
            "topic": env.message.topic,
            "headers": env.message.headers,
            "payload": env.message.payload,
            "key": key,
        }

        try:
            writer.write(record)
            idem.mark(key)
            log("INFO", "processed", message_id=env.message_id, key=key)
            return Ack.ACK
        except Exception as e:
            # Do not mark as processed; ask for retry
            log("ERROR", "process_failed", message_id=env.message_id, error=str(e))
            return Ack.RETRY

    # Subscribe and run
    bus.subscribe(consumer=cfg.consumer, topic=cfg.topic, group=cfg.group, fn=handler, flt=flt)
    bus.start(workers_per_topic=1, poll_timeout_ms=500, max_batch=100)

    # Main loop: wait until stopped
    try:
        while not _STOP["value"]:
            time.sleep(0.25)
    except KeyboardInterrupt:
        _STOP["value"] = True
    finally:
        # Best-effort flush/close
        writer.close()
        log("INFO", "consumer_stopped")

    return Exit.OK

# -------- CLI --------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="df-consumer",
        description="DataFabric streaming demo consumer (stdlib-only)",
    )
    p.add_argument("--topic", required=True, help="Topic to consume, e.g. dq.events")
    p.add_argument("--group", required=True, help="Consumer group name, e.g. dq-workers")
    p.add_argument("--consumer", required=True, help="Consumer id, e.g. dq-service-1")
    p.add_argument("--output", required=True, help="Path to output JSONL (append)")
    p.add_argument("--state-db", default=str(Path(".state") / "consumer.sqlite"), help="SQLite file for idempotency store")
    p.add_argument("--filter-header-key", default=None, help="Optional header key to filter")
    p.add_argument("--filter-header-value", default=None, help="Optional header value to filter")
    p.add_argument("--log-json", action="store_true", help="Log in JSON to stderr")
    p.add_argument("--metrics-interval", type=int, default=int(os.getenv("DF_METRICS_INTERVAL", "10")), help="Metrics print interval (sec)")
    p.add_argument("--vacuum-ttl-seconds", type=int, default=int(os.getenv("DF_VACUUM_TTL", str(7 * 24 * 3600))), help="TTL in seconds to forget old idempotency keys")
    return p

def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    output = Path(args.output)
    state_db = Path(args.state_db)
    cfg = ConsumerConfig(
        topic=args.topic,
        group=args.group,
        consumer=args.consumer,
        output=output,
        state_db=state_db,
        filter_header_key=args.filter_header_key,
        filter_header_value=args.filter_header_value,
        log_json=bool(args.log_json),
        metrics_interval=int(args.metrics_interval),
        vacuum_ttl=int(args.vacuum_ttl_seconds) if args.vacuum_ttl_seconds >= 0 else None,
    )
    try:
        return run_consumer(cfg)
    except SystemExit as se:
        return int(se.code) if isinstance(se.code, int) else Exit.UNKNOWN
    except Exception as e:
        log("ERROR", "fatal", error=str(e))
        return Exit.UNKNOWN

if __name__ == "__main__":
    sys.exit(main())
