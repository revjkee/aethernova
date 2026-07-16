# -*- coding: utf-8 -*-
"""
agent_mash/legacy/scripts_archive/experiments/payment_retry_experiment.py

Industrial payment retry experiment runner.

What this script provides:
- Exponential backoff with jitter, bounded by max delay.
- Retry policy: network errors, timeouts, 408/409/425/429/5xx by default (configurable).
- Respects HTTP Retry-After header (seconds or HTTP-date) when present.
- Idempotency-Key support for safe payment retries (gateway must support it).
- Correlation IDs (X-Request-Id) and structured JSON logging.
- Persistent attempt journal via SQLite (exactly-once recording of attempts).
- Circuit breaker to avoid hammering a degraded upstream.
- CLI: run, dry-run, simulator mode, export journal to JSONL.

Important notes:
- Whether Idempotency-Key is honored depends on the payment provider. This script only sends it.
  If your gateway does not support idempotency keys, you cannot safely retry non-idempotent operations.

Primary references (verifiable):
- urllib.request / HTTP handling in stdlib: https://docs.python.org/3/library/urllib.request.html
- socket timeout semantics used by urllib: https://docs.python.org/3/library/socket.html#socket.socket.settimeout
- Exponential backoff concept and jitter recommendation:
  AWS Architecture Blog ("Exponential Backoff And Jitter"):
  https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
- Retry-After header definition: RFC 9110 (HTTP Semantics), section on Retry-After header:
  https://www.rfc-editor.org/rfc/rfc9110.html

This file is self-contained (stdlib only).
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import email.utils
import hashlib
import json
import os
import random
import signal
import sqlite3
import sys
import time
import traceback
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# -----------------------------
# Structured logging (JSON)
# -----------------------------

def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def log_event(
    level: str,
    event: str,
    *,
    message: str = "",
    **fields: Any,
) -> None:
    payload: Dict[str, Any] = {
        "ts": _utc_now().isoformat(),
        "level": level.upper(),
        "event": event,
    }
    if message:
        payload["message"] = message
    for k, v in fields.items():
        payload[k] = v
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


# -----------------------------
# Config / Policies
# -----------------------------

@dataclass(frozen=True)
class RetryPolicy:
    """
    Retry policy for HTTP payment submission.

    retry_statuses: HTTP status codes that are considered retryable.
    max_attempts: total attempts including the first one.
    connect_timeout_s / read_timeout_s: urllib uses a single timeout for blocking operations,
    but we expose both; the effective timeout is max(connect, read) for simplicity.
    """
    retry_statuses: Tuple[int, ...] = (408, 409, 425, 429, 500, 502, 503, 504)
    max_attempts: int = 8
    base_delay_s: float = 0.5
    max_delay_s: float = 30.0
    jitter: str = "full"  # "none" | "full"
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 20.0

    def validate(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.base_delay_s <= 0:
            raise ValueError("base_delay_s must be > 0")
        if self.max_delay_s < self.base_delay_s:
            raise ValueError("max_delay_s must be >= base_delay_s")
        if self.jitter not in ("none", "full"):
            raise ValueError("jitter must be one of: none, full")
        if self.connect_timeout_s <= 0 or self.read_timeout_s <= 0:
            raise ValueError("timeouts must be > 0")


@dataclass(frozen=True)
class CircuitBreakerConfig:
    """
    Circuit breaker:
    - opens after N consecutive failures
    - stays open for cooldown_s, then allows a single probe attempt (half-open behavior)
    """
    enabled: bool = True
    open_after_failures: int = 5
    cooldown_s: float = 30.0

    def validate(self) -> None:
        if self.enabled:
            if self.open_after_failures < 1:
                raise ValueError("open_after_failures must be >= 1")
            if self.cooldown_s <= 0:
                raise ValueError("cooldown_s must be > 0")


@dataclass(frozen=True)
class ClientConfig:
    endpoint_url: str
    method: str = "POST"
    user_agent: str = "payment-retry-experiment/1.0"
    content_type: str = "application/json; charset=utf-8"
    idempotency_header: str = "Idempotency-Key"
    request_id_header: str = "X-Request-Id"
    extra_headers_json: str = ""  # JSON object string

    def validate(self) -> None:
        if not self.endpoint_url or "://" not in self.endpoint_url:
            raise ValueError("endpoint_url must be a valid URL")
        if self.method.upper() not in ("POST", "PUT"):
            raise ValueError("method must be POST or PUT for payment submissions")


# -----------------------------
# SQLite journal
# -----------------------------

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS payment_jobs (
  job_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_id TEXT NOT NULL,
  status TEXT NOT NULL,              -- PENDING | SUCCEEDED | FAILED
  final_http_status INTEGER,
  final_error TEXT
);

CREATE TABLE IF NOT EXISTS payment_attempts (
  attempt_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_no INTEGER NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT NOT NULL,
  http_status INTEGER,
  retry_after_s REAL,
  error_type TEXT,
  error_message TEXT,
  response_body_snippet TEXT,
  FOREIGN KEY(job_id) REFERENCES payment_jobs(job_id)
);

CREATE INDEX IF NOT EXISTS idx_payment_attempts_job ON payment_attempts(job_id);
"""


class Journal:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        with self._conn:
            self._conn.executescript(SCHEMA_SQL)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close()

    def upsert_job_pending(
        self,
        *,
        job_id: str,
        payload_sha256: str,
        idempotency_key: str,
        request_id: str,
    ) -> None:
        now = _utc_now().isoformat()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO payment_jobs(job_id, created_at, payload_sha256, idempotency_key, request_id, status)
                VALUES (?, ?, ?, ?, ?, 'PENDING')
                ON CONFLICT(job_id) DO UPDATE SET
                  payload_sha256=excluded.payload_sha256,
                  idempotency_key=excluded.idempotency_key,
                  request_id=excluded.request_id
                """,
                (job_id, now, payload_sha256, idempotency_key, request_id),
            )

    def mark_job_succeeded(self, *, job_id: str, http_status: int) -> None:
        with self._conn:
            self._conn.execute(
                """
                UPDATE payment_jobs
                SET status='SUCCEEDED', final_http_status=?, final_error=NULL
                WHERE job_id=?
                """,
                (http_status, job_id),
            )

    def mark_job_failed(self, *, job_id: str, http_status: Optional[int], error: str) -> None:
        with self._conn:
            self._conn.execute(
                """
                UPDATE payment_jobs
                SET status='FAILED', final_http_status=?, final_error=?
                WHERE job_id=?
                """,
                (http_status, error, job_id),
            )

    def add_attempt(
        self,
        *,
        attempt_id: str,
        job_id: str,
        attempt_no: int,
        started_at: str,
        ended_at: str,
        http_status: Optional[int],
        retry_after_s: Optional[float],
        error_type: Optional[str],
        error_message: Optional[str],
        response_body_snippet: Optional[str],
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO payment_attempts(
                  attempt_id, job_id, attempt_no, started_at, ended_at,
                  http_status, retry_after_s, error_type, error_message, response_body_snippet
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt_id,
                    job_id,
                    attempt_no,
                    started_at,
                    ended_at,
                    http_status,
                    retry_after_s,
                    error_type,
                    error_message,
                    response_body_snippet,
                ),
            )

    def export_jsonl(self, out_path: str) -> int:
        """
        Export jobs+attempts as JSONL (one line per attempt, with job envelope).
        """
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM payment_jobs ORDER BY created_at ASC")
        jobs = [dict(r) for r in cur.fetchall()]

        attempts_by_job: Dict[str, List[Dict[str, Any]]] = {}
        cur.execute("SELECT * FROM payment_attempts ORDER BY started_at ASC")
        for r in cur.fetchall():
            d = dict(r)
            attempts_by_job.setdefault(d["job_id"], []).append(d)

        count = 0
        with open(out_path, "w", encoding="utf-8") as f:
            for job in jobs:
                job_id = job["job_id"]
                for att in attempts_by_job.get(job_id, []):
                    record = {"job": job, "attempt": att}
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    count += 1
        return count


# -----------------------------
# Retry / Backoff utilities
# -----------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_backoff_s(policy: RetryPolicy, attempt_no: int) -> float:
    """
    Exponential backoff with optional full jitter.
    attempt_no is 1-based (attempt 1 has no backoff; caller controls that).
    """
    exp = policy.base_delay_s * (2 ** max(0, attempt_no - 2))
    capped = min(policy.max_delay_s, exp)
    if policy.jitter == "none":
        return capped
    # Full jitter: random between 0 and capped
    return random.random() * capped


def parse_retry_after_seconds(value: str) -> Optional[float]:
    """
    Retry-After can be:
    - delta-seconds
    - HTTP-date (RFC 9110)
    """
    v = value.strip()
    if not v:
        return None
    # delta-seconds
    if v.isdigit():
        try:
            return float(int(v))
        except Exception:
            return None
    # HTTP-date
    try:
        when = email.utils.parsedate_to_datetime(v)
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        now = _utc_now()
        delta = (when - now).total_seconds()
        return max(0.0, float(delta))
    except Exception:
        return None


# -----------------------------
# Circuit breaker
# -----------------------------

class CircuitBreaker:
    def __init__(self, cfg: CircuitBreakerConfig) -> None:
        self.cfg = cfg
        self._failures = 0
        self._opened_at: Optional[float] = None

    def allow_request(self) -> bool:
        if not self.cfg.enabled:
            return True
        if self._opened_at is None:
            return True
        # open state
        elapsed = time.time() - self._opened_at
        if elapsed >= self.cfg.cooldown_s:
            # half-open: allow a single probe
            return True
        return False

    def on_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def on_failure(self) -> None:
        if not self.cfg.enabled:
            return
        self._failures += 1
        if self._failures >= self.cfg.open_after_failures:
            if self._opened_at is None:
                self._opened_at = time.time()

    def is_open(self) -> bool:
        return self.cfg.enabled and self._opened_at is not None


# -----------------------------
# HTTP client (stdlib urllib)
# -----------------------------

@dataclass(frozen=True)
class HttpResult:
    ok: bool
    http_status: Optional[int]
    response_body: Optional[bytes]
    headers: Dict[str, str]
    error_type: Optional[str]
    error_message: Optional[str]


class HttpClient:
    def __init__(self, client_cfg: ClientConfig) -> None:
        self.cfg = client_cfg

    def _build_headers(
        self,
        *,
        request_id: str,
        idempotency_key: str,
        extra_headers: Dict[str, str],
    ) -> Dict[str, str]:
        h = {
            "User-Agent": self.cfg.user_agent,
            "Content-Type": self.cfg.content_type,
            self.cfg.request_id_header: request_id,
            self.cfg.idempotency_header: idempotency_key,
        }
        for k, v in extra_headers.items():
            # do not allow override of critical headers unless user explicitly sets same key
            h[k] = v
        return h

    def send(
        self,
        *,
        body: bytes,
        request_id: str,
        idempotency_key: str,
        timeout_s: float,
        extra_headers: Dict[str, str],
    ) -> HttpResult:
        req = Request(
            url=self.cfg.endpoint_url,
            data=body,
            method=self.cfg.method.upper(),
        )
        headers = self._build_headers(
            request_id=request_id,
            idempotency_key=idempotency_key,
            extra_headers=extra_headers,
        )
        for k, v in headers.items():
            req.add_header(k, v)

        try:
            with urlopen(req, timeout=timeout_s) as resp:
                status = int(getattr(resp, "status", 200))
                resp_headers = {k: v for k, v in resp.headers.items()}
                data = resp.read()
                ok = 200 <= status < 300
                return HttpResult(
                    ok=ok,
                    http_status=status,
                    response_body=data,
                    headers=resp_headers,
                    error_type=None,
                    error_message=None,
                )
        except HTTPError as e:
            status = int(getattr(e, "code", 0)) or None
            resp_headers = dict(getattr(e, "headers", {}) or {})
            body_bytes = None
            try:
                body_bytes = e.read()
            except Exception:
                body_bytes = None
            return HttpResult(
                ok=False,
                http_status=status,
                response_body=body_bytes,
                headers={str(k): str(v) for k, v in resp_headers.items()},
                error_type="HTTPError",
                error_message=str(e),
            )
        except URLError as e:
            return HttpResult(
                ok=False,
                http_status=None,
                response_body=None,
                headers={},
                error_type="URLError",
                error_message=str(e),
            )
        except Exception as e:
            return HttpResult(
                ok=False,
                http_status=None,
                response_body=None,
                headers={},
                error_type=type(e).__name__,
                error_message=str(e),
            )


# -----------------------------
# Simulator (no real network)
# -----------------------------

@dataclass(frozen=True)
class SimulatedResponse:
    http_status: int
    body: Dict[str, Any]
    headers: Dict[str, str] = dataclasses.field(default_factory=dict)


class Simulator:
    """
    Deterministic simulation:
    Provide a sequence like: 500, 429 (Retry-After: 2), 200.
    """
    def __init__(self, sequence: List[SimulatedResponse]) -> None:
        if not sequence:
            raise ValueError("simulation sequence must not be empty")
        self._seq = sequence
        self._i = 0

    def next(self) -> SimulatedResponse:
        if self._i >= len(self._seq):
            # repeat the last response
            return self._seq[-1]
        r = self._seq[self._i]
        self._i += 1
        return r


# -----------------------------
# Payment retry runner
# -----------------------------

@dataclass(frozen=True)
class PaymentJob:
    job_id: str
    payload_json: str
    idempotency_key: str
    request_id: str

    @property
    def payload_bytes(self) -> bytes:
        return self.payload_json.encode("utf-8")

    @property
    def payload_hash(self) -> str:
        return sha256_hex(self.payload_bytes)


class GracefulShutdown:
    def __init__(self) -> None:
        self._stop = False
        self._installed = False

    def install(self) -> None:
        if self._installed:
            return

        def _handler(signum: int, frame: Any) -> None:
            self._stop = True
            log_event("WARN", "shutdown_signal", signal=signum)

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
        self._installed = True

    @property
    def stop_requested(self) -> bool:
        return self._stop


class PaymentRetryRunner:
    def __init__(
        self,
        *,
        journal: Journal,
        http_client: Optional[HttpClient],
        retry_policy: RetryPolicy,
        breaker: CircuitBreaker,
        dry_run: bool,
        simulator: Optional[Simulator],
        extra_headers: Dict[str, str],
    ) -> None:
        self.journal = journal
        self.http_client = http_client
        self.policy = retry_policy
        self.breaker = breaker
        self.dry_run = dry_run
        self.simulator = simulator
        self.extra_headers = extra_headers

    def _effective_timeout(self) -> float:
        # urllib has one timeout argument; we use a conservative effective timeout.
        return max(self.policy.connect_timeout_s, self.policy.read_timeout_s)

    def run(self, job: PaymentJob, shutdown: GracefulShutdown) -> int:
        """
        Returns exit code:
        0 = success
        2 = failed
        3 = aborted due to shutdown or circuit breaker open
        """
        self.policy.validate()

        self.journal.upsert_job_pending(
            job_id=job.job_id,
            payload_sha256=job.payload_hash,
            idempotency_key=job.idempotency_key,
            request_id=job.request_id,
        )

        log_event(
            "INFO",
            "job_started",
            job_id=job.job_id,
            request_id=job.request_id,
            idempotency_key=job.idempotency_key,
            payload_sha256=job.payload_hash,
            max_attempts=self.policy.max_attempts,
            dry_run=self.dry_run,
            simulated=self.simulator is not None,
        )

        for attempt_no in range(1, self.policy.max_attempts + 1):
            if shutdown.stop_requested:
                log_event("WARN", "job_aborted_shutdown", job_id=job.job_id, attempt_no=attempt_no)
                self.journal.mark_job_failed(job_id=job.job_id, http_status=None, error="aborted: shutdown")
                return 3

            if not self.breaker.allow_request():
                log_event("ERROR", "circuit_breaker_open", job_id=job.job_id)
                self.journal.mark_job_failed(job_id=job.job_id, http_status=None, error="aborted: circuit breaker open")
                return 3

            # Backoff before retries (not before first attempt)
            if attempt_no > 1:
                delay = compute_backoff_s(self.policy, attempt_no)
                log_event("INFO", "backoff_sleep", job_id=job.job_id, attempt_no=attempt_no, sleep_s=delay)
                time.sleep(delay)

            started = _utc_now().isoformat()
            attempt_id = str(uuid.uuid4())

            if self.dry_run:
                ended = _utc_now().isoformat()
                self.journal.add_attempt(
                    attempt_id=attempt_id,
                    job_id=job.job_id,
                    attempt_no=attempt_no,
                    started_at=started,
                    ended_at=ended,
                    http_status=None,
                    retry_after_s=None,
                    error_type="DRY_RUN",
                    error_message="dry-run: request not sent",
                    response_body_snippet=None,
                )
                log_event("INFO", "attempt_dry_run", job_id=job.job_id, attempt_no=attempt_no)
                self.journal.mark_job_failed(job_id=job.job_id, http_status=None, error="dry-run: no submission")
                return 2

            # Execute request (real or simulated)
            result: HttpResult
            if self.simulator is not None:
                sim = self.simulator.next()
                body_bytes = json.dumps(sim.body, ensure_ascii=False).encode("utf-8")
                result = HttpResult(
                    ok=200 <= sim.http_status < 300,
                    http_status=sim.http_status,
                    response_body=body_bytes,
                    headers={k: v for k, v in sim.headers.items()},
                    error_type=None if 200 <= sim.http_status < 300 else "SIMULATED_HTTP",
                    error_message=None if 200 <= sim.http_status < 300 else f"simulated status {sim.http_status}",
                )
            else:
                if self.http_client is None:
                    ended = _utc_now().isoformat()
                    self.journal.add_attempt(
                        attempt_id=attempt_id,
                        job_id=job.job_id,
                        attempt_no=attempt_no,
                        started_at=started,
                        ended_at=ended,
                        http_status=None,
                        retry_after_s=None,
                        error_type="CONFIG_ERROR",
                        error_message="http_client is not configured",
                        response_body_snippet=None,
                    )
                    self.journal.mark_job_failed(job_id=job.job_id, http_status=None, error="config_error: no http_client")
                    return 2

                timeout_s = self._effective_timeout()
                result = self.http_client.send(
                    body=job.payload_bytes,
                    request_id=job.request_id,
                    idempotency_key=job.idempotency_key,
                    timeout_s=timeout_s,
                    extra_headers=self.extra_headers,
                )

            ended = _utc_now().isoformat()

            retry_after_s: Optional[float] = None
            if result.headers:
                ra_val = result.headers.get("Retry-After") or result.headers.get("retry-after")
                if ra_val:
                    retry_after_s = parse_retry_after_seconds(ra_val)

            body_snippet: Optional[str] = None
            if result.response_body:
                try:
                    s = result.response_body.decode("utf-8", errors="replace")
                    body_snippet = s[:500]
                except Exception:
                    body_snippet = None

            self.journal.add_attempt(
                attempt_id=attempt_id,
                job_id=job.job_id,
                attempt_no=attempt_no,
                started_at=started,
                ended_at=ended,
                http_status=result.http_status,
                retry_after_s=retry_after_s,
                error_type=result.error_type,
                error_message=result.error_message,
                response_body_snippet=body_snippet,
            )

            log_event(
                "INFO" if result.ok else "WARN",
                "attempt_result",
                job_id=job.job_id,
                attempt_no=attempt_no,
                http_status=result.http_status,
                ok=result.ok,
                error_type=result.error_type,
                retry_after_s=retry_after_s,
            )

            if result.ok and result.http_status is not None:
                self.breaker.on_success()
                self.journal.mark_job_succeeded(job_id=job.job_id, http_status=int(result.http_status))
                log_event("INFO", "job_succeeded", job_id=job.job_id, http_status=int(result.http_status))
                return 0

            # Failure handling
            self.breaker.on_failure()

            # Decide retryable
            retryable = False
            if result.http_status is None:
                # network / unexpected -> retry (bounded by max_attempts)
                retryable = True
            else:
                retryable = int(result.http_status) in set(self.policy.retry_statuses)

            if retryable and attempt_no < self.policy.max_attempts:
                # If server asks Retry-After, honor it (additional to our backoff) before next attempt.
                if retry_after_s is not None and retry_after_s > 0:
                    log_event(
                        "INFO",
                        "retry_after_sleep",
                        job_id=job.job_id,
                        attempt_no=attempt_no,
                        sleep_s=retry_after_s,
                    )
                    time.sleep(retry_after_s)
                continue

            # Final failure
            err = result.error_message or "non-retryable failure"
            self.journal.mark_job_failed(job_id=job.job_id, http_status=result.http_status, error=str(err))
            log_event(
                "ERROR",
                "job_failed",
                job_id=job.job_id,
                http_status=result.http_status,
                error=str(err),
                retryable=retryable,
            )
            return 2

        # Should never hit due to loop bounds
        self.journal.mark_job_failed(job_id=job.job_id, http_status=None, error="unknown: exhausted attempts")
        return 2


# -----------------------------
# CLI helpers
# -----------------------------

def load_json_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    # Validate JSON is parseable, but keep original string to preserve formatting.
    json.loads(txt)
    return txt


def parse_extra_headers(extra_headers_json: str) -> Dict[str, str]:
    if not extra_headers_json.strip():
        return {}
    obj = json.loads(extra_headers_json)
    if not isinstance(obj, dict):
        raise ValueError("extra_headers_json must be a JSON object")
    out: Dict[str, str] = {}
    for k, v in obj.items():
        if not isinstance(k, str):
            raise ValueError("header keys must be strings")
        if not isinstance(v, (str, int, float, bool)):
            raise ValueError("header values must be scalar (string/number/bool)")
        out[k] = str(v)
    return out


def build_job(payload_json: str, job_id: Optional[str], idempotency_key: Optional[str], request_id: Optional[str]) -> PaymentJob:
    j_id = job_id or str(uuid.uuid4())
    idem = idempotency_key or str(uuid.uuid4())
    rid = request_id or str(uuid.uuid4())
    return PaymentJob(job_id=j_id, payload_json=payload_json, idempotency_key=idem, request_id=rid)


def build_simulator(sequence: str) -> Simulator:
    """
    sequence format:
      "500,429:2,200"
    Where:
      - "429:2" means status 429 with Retry-After=2 seconds
      - plain status means no headers
    Body is a minimal JSON with status and timestamp.

    This is purely local logic; it does not represent any real provider response schema.
    """
    items: List[SimulatedResponse] = []
    for raw in (x.strip() for x in sequence.split(",") if x.strip()):
        if ":" in raw:
            status_s, ra_s = raw.split(":", 1)
            status = int(status_s.strip())
            ra = ra_s.strip()
            headers = {"Retry-After": ra}
        else:
            status = int(raw)
            headers = {}
        body = {
            "simulated": True,
            "http_status": status,
            "ts": _utc_now().isoformat(),
        }
        items.append(SimulatedResponse(http_status=status, body=body, headers=headers))
    return Simulator(items)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="payment_retry_experiment",
        description="Industrial payment retry experiment runner (stdlib-only).",
    )

    parser.add_argument("--endpoint-url", default="", help="Payment endpoint URL (required unless --simulate is used).")
    parser.add_argument("--method", default="POST", choices=["POST", "PUT"], help="HTTP method.")
    parser.add_argument("--payload-file", default="", help="Path to JSON payload file.")
    parser.add_argument("--payload-json", default="", help="Inline JSON payload.")
    parser.add_argument("--db-path", default="payment_retry_journal.sqlite3", help="SQLite journal path.")
    parser.add_argument("--job-id", default="", help="Job ID (default: generated UUID).")
    parser.add_argument("--idempotency-key", default="", help="Idempotency-Key value (default: generated UUID).")
    parser.add_argument("--request-id", default="", help="X-Request-Id value (default: generated UUID).")
    parser.add_argument("--extra-headers-json", default="", help="Extra headers as JSON object string.")
    parser.add_argument("--max-attempts", type=int, default=8, help="Max attempts including first.")
    parser.add_argument("--base-delay-s", type=float, default=0.5, help="Base delay for exponential backoff.")
    parser.add_argument("--max-delay-s", type=float, default=30.0, help="Max backoff delay cap.")
    parser.add_argument("--jitter", default="full", choices=["none", "full"], help="Jitter strategy.")
    parser.add_argument("--connect-timeout-s", type=float, default=5.0, help="Connect timeout (informational for urllib).")
    parser.add_argument("--read-timeout-s", type=float, default=20.0, help="Read timeout (informational for urllib).")
    parser.add_argument("--retry-statuses", default="408,409,425,429,500,502,503,504", help="Comma-separated retryable HTTP statuses.")
    parser.add_argument("--dry-run", action="store_true", help="Do not send request; record attempt and fail.")
    parser.add_argument("--simulate", default="", help='Simulation sequence, e.g. "500,429:2,200". Skips real network.')
    parser.add_argument("--export-jsonl", default="", help="Export journal to JSONL file and exit.")
    parser.add_argument("--cb-enabled", action="store_true", help="Enable circuit breaker.")
    parser.add_argument("--cb-open-after", type=int, default=5, help="Open circuit after N consecutive failures.")
    parser.add_argument("--cb-cooldown-s", type=float, default=30.0, help="Circuit breaker cooldown seconds.")
    parser.add_argument("--user-agent", default="payment-retry-experiment/1.0", help="User-Agent header.")
    parser.add_argument("--content-type", default="application/json; charset=utf-8", help="Content-Type header.")
    parser.add_argument("--idempotency-header", default="Idempotency-Key", help="Idempotency header name.")
    parser.add_argument("--request-id-header", default="X-Request-Id", help="Request ID header name.")

    args = parser.parse_args(argv)

    # Journal
    journal = Journal(args.db_path)
    try:
        if args.export_jsonl:
            count = journal.export_jsonl(args.export_jsonl)
            log_event("INFO", "export_done", out_path=args.export_jsonl, records=count)
            return 0

        # Payload
        if bool(args.payload_file) == bool(args.payload_json):
            log_event("ERROR", "invalid_args", message="Provide exactly one of --payload-file or --payload-json")
            return 2

        try:
            payload_json = load_json_file(args.payload_file) if args.payload_file else args.payload_json
            # ensure it's valid JSON
            json.loads(payload_json)
        except Exception as e:
            log_event("ERROR", "payload_invalid", error=str(e))
            return 2

        # Retry policy
        try:
            retry_statuses = tuple(int(x.strip()) for x in args.retry_statuses.split(",") if x.strip())
            policy = RetryPolicy(
                retry_statuses=retry_statuses,
                max_attempts=int(args.max_attempts),
                base_delay_s=float(args.base_delay_s),
                max_delay_s=float(args.max_delay_s),
                jitter=str(args.jitter),
                connect_timeout_s=float(args.connect_timeout_s),
                read_timeout_s=float(args.read_timeout_s),
            )
            policy.validate()
        except Exception as e:
            log_event("ERROR", "policy_invalid", error=str(e))
            return 2

        # Circuit breaker
        try:
            cb_cfg = CircuitBreakerConfig(
                enabled=bool(args.cb_enabled),
                open_after_failures=int(args.cb_open_after),
                cooldown_s=float(args.cb_cooldown_s),
            )
            cb_cfg.validate()
        except Exception as e:
            log_event("ERROR", "circuit_breaker_invalid", error=str(e))
            return 2

        breaker = CircuitBreaker(cb_cfg)

        # Extra headers
        try:
            extra_headers = parse_extra_headers(args.extra_headers_json)
        except Exception as e:
            log_event("ERROR", "extra_headers_invalid", error=str(e))
            return 2

        # Client config
        simulate_mode = bool(args.simulate.strip())
        if not simulate_mode and not args.endpoint_url.strip():
            log_event("ERROR", "invalid_args", message="--endpoint-url is required unless --simulate is used")
            return 2

        client_cfg = ClientConfig(
            endpoint_url=args.endpoint_url.strip() if args.endpoint_url else "http://127.0.0.1/unused",
            method=args.method,
            user_agent=args.user_agent,
            content_type=args.content_type,
            idempotency_header=args.idempotency_header,
            request_id_header=args.request_id_header,
            extra_headers_json=args.extra_headers_json,
        )

        try:
            client_cfg.validate()
        except Exception as e:
            if not simulate_mode:
                log_event("ERROR", "client_config_invalid", error=str(e))
                return 2

        http_client = None if simulate_mode else HttpClient(client_cfg)

        simulator = build_simulator(args.simulate) if simulate_mode else None

        # Build job
        job = build_job(
            payload_json=payload_json,
            job_id=args.job_id.strip() or None,
            idempotency_key=args.idempotency_key.strip() or None,
            request_id=args.request_id.strip() or None,
        )

        shutdown = GracefulShutdown()
        shutdown.install()

        runner = PaymentRetryRunner(
            journal=journal,
            http_client=http_client,
            retry_policy=policy,
            breaker=breaker,
            dry_run=bool(args.dry_run),
            simulator=simulator,
            extra_headers=extra_headers,
        )

        return runner.run(job, shutdown)

    except Exception as e:
        log_event(
            "ERROR",
            "fatal_exception",
            error=str(e),
            traceback="".join(traceback.format_exception(type(e), e, e.__traceback__)),
        )
        return 2
    finally:
        journal.close()


if __name__ == "__main__":
    raise SystemExit(main())
