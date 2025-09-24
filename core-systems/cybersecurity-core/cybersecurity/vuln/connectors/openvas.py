# cybersecurity-core/cybersecurity/vuln/connectors/openvas.py
# Industrial-grade OpenVAS (Greenbone) connector using python-gvm (GMP).
# Python: 3.10+
# Dependencies:
#   - python-gvm >= 23.5.0  (pip install python-gvm)
#   - optional: prometheus_client (for metrics)
#
# Features:
# - TLS/mTLS (host:port) connection to GVM, configurable via env or params
# - Context manager with safe login/logout over GMP
# - Robust retries with exponential backoff for transient errors
# - Strict timeouts for connect and commands
# - Create/find Target, Config, Scanner, Task; start scan; wait for completion
# - Fetch report by format name (e.g., "XML", "HTML", "PDF", "CSV Results")
# - Structured JSON logging with request_id and redaction of secrets
# - Optional Prometheus metrics
# - Type hints, dataclasses, minimal coupling to app layer
#
# NOTE:
#   This file does not hardcode UUIDs (config/scanner/format). It resolves them by name at runtime
#   to remain portable across different GVM installations.

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import random
import socket
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

try:
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False

# python-gvm imports (lazy-checked for clearer error)
try:
    from gvm.connections import TLSConnection, UnixSocketConnection
    from gvm.errors import GvmError, GvmProtocolError
    from gvm.protocols.gmp import Gmp
except Exception as _e:  # pragma: no cover
    raise ImportError(
        "python-gvm is required for OpenVAS connector. Install: pip install python-gvm"
    ) from _e

import xml.etree.ElementTree as ET


# =========================
# Logging
# =========================

_REDACT_KEYS = {"password", "pass", "token", "authorization", "x-api-key", "cookie"}
_REDACT_MASK = "******"
_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(_redact(extra))
        try:
            return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return f'{payload["ts"]} {payload["level"]} {payload["logger"]} {payload["msg"]}'


def _get_logger(name: str = "cybersec.openvas") -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        lg.setLevel(logging.INFO)
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(_JsonFormatter())
        lg.addHandler(h)
        lg.propagate = False
    return lg


LOGGER = _get_logger()


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if str(k).lower() in _REDACT_KEYS:
                out[k] = _REDACT_MASK
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return type(obj)(_redact(v) for v in obj)
    return obj


def get_request_id() -> str:
    return _request_id_ctx.get()


# =========================
# Metrics (optional)
# =========================

if _PROM:
    GVM_CALLS = Counter("gvm_calls_total", "Total GMP calls", ["method", "status"])
    GVM_LAT = Histogram(
        "gvm_call_duration_seconds",
        "GMP call latency seconds",
        ["method", "status"],
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    )
else:  # pragma: no cover
    GVM_CALLS = None
    GVM_LAT = None


# =========================
# Config & Errors
# =========================

@dataclass(frozen=True)
class OpenVASConfig:
    host: str = field(default_factory=lambda: os.getenv("GVM_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("GVM_PORT", "9390")))
    username: str = field(default_factory=lambda: os.getenv("GVM_USERNAME", "admin"))
    password: str = field(default_factory=lambda: os.getenv("GVM_PASSWORD", "admin"))
    # TLS:
    cafile: Optional[str] = field(default_factory=lambda: os.getenv("GVM_TLS_CA") or None)
    certfile: Optional[str] = field(default_factory=lambda: os.getenv("GVM_TLS_CERT") or None)
    keyfile: Optional[str] = field(default_factory=lambda: os.getenv("GVM_TLS_KEY") or None)
    # Behavior:
    connect_timeout: float = float(os.getenv("GVM_CONNECT_TIMEOUT", "10"))     # TCP connect timeout
    command_timeout: float = float(os.getenv("GVM_COMMAND_TIMEOUT", "60"))     # Per-GMP call timeout
    max_retries: int = int(os.getenv("GVM_MAX_RETRIES", "4"))
    backoff_base: float = float(os.getenv("GVM_BACKOFF_BASE", "0.2"))
    backoff_max: float = float(os.getenv("GVM_BACKOFF_MAX", "3.0"))
    # Defaults lookup by name (not UUID-bound):
    default_scan_config_name: str = os.getenv("GVM_DEFAULT_CONFIG", "Full and fast")
    default_scanner_name: Optional[str] = os.getenv("GVM_DEFAULT_SCANNER") or None
    default_report_format_name: str = os.getenv("GVM_DEFAULT_REPORT_FORMAT", "XML")
    # Misc:
    request_id: Optional[str] = None  # for correlation


class OpenVASError(Exception):
    """Base connector error."""


class OpenVASTimeout(OpenVASError):
    """Command timeout."""


class OpenVASTransient(OpenVASError):
    """Transient error (retryable)."""


class OpenVASAuthError(OpenVASError):
    """Authentication error."""


# =========================
# Connector
# =========================

class OpenVASConnector(contextlib.AbstractContextManager):
    """
    Context-managed connector providing high-level operations:
      - login/logout
      - ensure_target, ensure_task, start_scan, wait_for_report, fetch_report
    """

    def __init__(self, cfg: OpenVASConfig) -> None:
        self.cfg = cfg
        self._gmp: Optional[Gmp] = None
        self._conn = None

    # ---------- Context manager ----------

    def __enter__(self) -> "OpenVASConnector":
        rid = self.cfg.request_id or f"req-{int(time.time()*1000)}-{random.randint(1000, 9999)}"
        self._rid_token = _request_id_ctx.set(rid)
        self.login()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.logout()
        finally:
            try:
                _request_id_ctx.reset(self._rid_token)  # type: ignore[attr-defined]
            except Exception:
                pass

    # ---------- Low-level session ----------

    def login(self) -> None:
        """Establish TLS connection and authenticate to GVM."""
        if self._gmp is not None:
            return

        rid = get_request_id()
        LOGGER.info("gvm.login.start", extra={"extra": {
            "request_id": rid,
            "host": self.cfg.host,
            "port": self.cfg.port,
            "tls": bool(self.cfg.cafile or self.cfg.certfile or self.cfg.keyfile),
        }})

        # TCP pre-check for clean timeouts
        self._tcp_ping(self.cfg.host, self.cfg.port, timeout=self.cfg.connect_timeout)

        # TLS or plain TLS-without-client-auth (GMP is TLS on 9390)
        if self.cfg.cafile or self.cfg.certfile or self.cfg.keyfile:
            self._conn = TLSConnection(
                host=self.cfg.host,
                port=self.cfg.port,
                cafile=self.cfg.cafile,
                certfile=self.cfg.certfile,
                keyfile=self.cfg.keyfile,
            )
        else:
            # Even без mTLS, GMP ожидает TLS — TLSConnection без CA/клиентского cert.
            self._conn = TLSConnection(host=self.cfg.host, port=self.cfg.port)

        try:
            gmp = Gmp(self._conn)  # type: ignore[arg-type]
            gmp.connect()
            gmp.authenticate(self.cfg.username, self.cfg.password)
            self._gmp = gmp
            LOGGER.info("gvm.login.ok", extra={"extra": {"request_id": rid, "user": self.cfg.username}})
        except GvmError as e:
            LOGGER.error("gvm.login.error", extra={"extra": {"request_id": rid, "error": repr(e)}})
            # Distinguish auth vs other
            raise OpenVASAuthError("Authentication failed") if "authentication" in str(e).lower() else OpenVASError(str(e))

    def logout(self) -> None:
        rid = get_request_id()
        if self._gmp is not None:
            try:
                self._gmp.disconnect()
            except Exception:
                pass
            self._gmp = None
            LOGGER.info("gvm.logout", extra={"extra": {"request_id": rid}})

    # ---------- High-level API ----------

    def ensure_target(
        self,
        name: str,
        hosts: str | Iterable[str],
        port_list_name: str | None = "All IANA assigned TCP and UDP",
        alive_tests: str = "Consider Alive",
    ) -> str:
        """
        Ensure a Target exists. Returns target_id.
        hosts: string "10.0.0.1,10.0.0.2" or iterable of hosts/CIDRs.
        """
        gmp = self._gmp_or_raise()
        rid = get_request_id()
        hosts_str = hosts if isinstance(hosts, str) else ",".join(hosts)

        # Find by name
        existing = self._find_entity_by_name(lambda: gmp.get_targets(details=True), "target", name)
        if existing:
            tid = existing
            LOGGER.info("gvm.target.exists", extra={"extra": {"request_id": rid, "name": name, "id": tid}})
            return tid

        # Resolve port list id by name if requested
        port_list_id = None
        if port_list_name:
            port_list_id = self._find_entity_by_name(lambda: gmp.get_port_lists(details=True), "port_list", port_list_name)
            if not port_list_id:
                LOGGER.info("gvm.portlist.not_found", extra={"extra": {"request_id": rid, "name": port_list_name}})

        LOGGER.info("gvm.target.create", extra={"extra": {
            "request_id": rid, "name": name, "hosts": hosts_str, "port_list_id": port_list_id, "alive_tests": alive_tests
        }})
        xml = self._call_gmp("create_target", lambda: gmp.create_target(
            name=name,
            hosts=hosts_str,
            port_list_id=port_list_id,
            alive_tests=alive_tests
        ))
        tid = _extract_id(xml, "create_target_response")
        if not tid:
            raise OpenVASError("Failed to create target")
        return tid

    def ensure_task(
        self,
        name: str,
        target_id: str,
        scan_config_name: Optional[str] = None,
        scanner_name: Optional[str] = None,
    ) -> str:
        """
        Ensure a Task exists. Returns task_id.
        """
        gmp = self._gmp_or_raise()
        rid = get_request_id()

        existing = self._find_entity_by_name(lambda: gmp.get_tasks(details=True), "task", name)
        if existing:
            LOGGER.info("gvm.task.exists", extra={"extra": {"request_id": rid, "name": name, "id": existing}})
            return existing

        cfg_name = scan_config_name or self.cfg.default_scan_config_name
        cfg_id = self._find_entity_by_name(lambda: gmp.get_scan_configs(details=True), "config", cfg_name)
        if not cfg_id:
            raise OpenVASError(f"Scan config '{cfg_name}' not found")

        scanner_id = None
        s_name = scanner_name or self.cfg.default_scanner_name
        if s_name:
            scanner_id = self._find_entity_by_name(lambda: gmp.get_scanners(details=True), "scanner", s_name)
            if not scanner_id:
                LOGGER.info("gvm.scanner.not_found", extra={"extra": {"request_id": rid, "name": s_name}})

        LOGGER.info("gvm.task.create", extra={"extra": {
            "request_id": rid, "name": name, "target_id": target_id, "config_id": cfg_id, "scanner_id": scanner_id
        }})
        xml = self._call_gmp("create_task", lambda: gmp.create_task(
            name=name,
            target_id=target_id,
            config_id=cfg_id,
            scanner_id=scanner_id
        ))
        task_id = _extract_id(xml, "create_task_response")
        if not task_id:
            raise OpenVASError("Failed to create task")
        return task_id

    def start_task(self, task_id: str) -> str:
        """Start a task and return report_id."""
        gmp = self._gmp_or_raise()
        rid = get_request_id()
        LOGGER.info("gvm.task.start", extra={"extra": {"request_id": rid, "task_id": task_id}})
        xml = self._call_gmp("start_task", lambda: gmp.start_task(task_id))
        report_id = _extract_id(xml, "start_task_response", child="report_id")
        if not report_id:
            # Some versions return <report id="...">
            report_id = _extract_id(xml, "start_task_response", attr="report_id") or _extract_any_id(xml)
        if not report_id:
            raise OpenVASError("Failed to start task or report_id not returned")
        return report_id

    def task_status(self, task_id: str) -> Tuple[str, int]:
        """
        Return (status, progress). Status examples: "Running", "Done", "Stopped", "Queued".
        """
        gmp = self._gmp_or_raise()
        xml = self._call_gmp("get_tasks", lambda: gmp.get_tasks(task_id=task_id, details=True))
        root = ET.fromstring(xml)
        task = root.find(".//task")
        if task is None:
            raise OpenVASError("Task not found")
        status = (task.findtext("./status") or "").strip()
        progress = int((task.findtext("./progress") or "0").strip())
        return status, progress

    def wait_for_report(
        self,
        task_id: str,
        *,
        poll_interval: float = 5.0,
        max_wait_seconds: Optional[int] = None,
        on_progress: Optional[Callable[[int, str], None]] = None,
    ) -> str:
        """
        Block until task is Done or error. Returns final report_id.
        """
        rid = get_request_id()
        start = time.monotonic()
        last_progress = -1

        while True:
            status, progress = self.task_status(task_id)
            if progress != last_progress:
                last_progress = progress
                if on_progress:
                    on_progress(progress, status)
                LOGGER.info("gvm.task.progress", extra={"extra": {
                    "request_id": rid, "task_id": task_id, "status": status, "progress": progress
                }})

            if status.lower() in {"done", "finished"}:
                # Fetch last report id from get_tasks
                gmp = self._gmp_or_raise()
                xml = self._call_gmp("get_tasks", lambda: gmp.get_tasks(task_id=task_id, details=True))
                root = ET.fromstring(xml)
                rep = root.find(".//task//last_report//report")
                if rep is None:
                    raise OpenVASError("Report not found after completion")
                rid_attr = rep.get("id")
                if not rid_attr:
                    raise OpenVASError("Report id missing")
                return rid_attr

            if status.lower() in {"stopped", "cancelled", "failed"}:
                raise OpenVASError(f"Task ended with status {status}")

            if max_wait_seconds is not None and (time.monotonic() - start) > max_wait_seconds:
                raise OpenVASTimeout("Wait for report timed out")

            time.sleep(poll_interval)

    def fetch_report(
        self,
        report_id: str,
        *,
        format_name: Optional[str] = None,
        as_bytes: bool = True,
        delta: Optional[str] = None,
        notes: bool = False,
        overrides: bool = False,
        result_filters: Optional[str] = None,
    ) -> bytes | str:
        """
        Download report in a given format.
        format_name: e.g., "XML", "HTML", "PDF", "CSV Results", "ITG".
        """
        gmp = self._gmp_or_raise()
        rid = get_request_id()
        fmt_name = format_name or self.cfg.default_report_format_name
        fmt_id = self._find_entity_by_name(lambda: gmp.get_report_formats(details=True), "report_format", fmt_name)
        if not fmt_id:
            raise OpenVASError(f"Report format '{fmt_name}' not found")

        LOGGER.info("gvm.report.fetch", extra={"extra": {
            "request_id": rid, "report_id": report_id, "format": fmt_name, "format_id": fmt_id
        }})

        # The newer GMP prefers get_report with format_id; may return base64 inside XML or raw content.
        xml = self._call_gmp("get_report", lambda: gmp.get_report(
            report_id=report_id,
            report_format_id=fmt_id,
            ignore_pagination=True,
            notes=notes,
            overrides=overrides,
            details=True,
            delta=delta,
            filter_string=result_filters
        ), timeout=self.cfg.command_timeout * 2)

        # Heuristics: try to extract <report><report> base64 or text content
        # For XML: return XML string
        # For binary (PDF/HTML zipped): python-gvm often returns raw body in <report><report> element with base64 attr
        root = ET.fromstring(xml)
        rnode = root.find(".//report/report")
        if rnode is not None:
            # If content is base64, python-gvm usually decodes already; but be defensive:
            text = rnode.text or ""
            # Best-effort: if it looks like XML, return text; else treat as bytes
            if text.strip().startswith("<"):
                return text if not as_bytes else text.encode("utf-8")
            try:
                import base64
                data = base64.b64decode(text, validate=False)
                return data if as_bytes else data.decode("utf-8", errors="replace")
            except Exception:
                return text if not as_bytes else text.encode("utf-8")

        # Fallback: return full XML
        return xml if not as_bytes else xml.encode("utf-8")

    # ---------- Internals ----------

    def _gmp_or_raise(self) -> Gmp:
        if self._gmp is None:
            raise OpenVASError("Not connected. Call login() or use context manager.")
        return self._gmp

    def _find_entity_by_name(self, getter: Callable[[], str], tag: str, name: str) -> Optional[str]:
        """
        Generic resolver: parse XML and find entity id by <name>.
        tag examples: "target", "task", "config", "scanner", "report_format", "port_list"
        """
        xml = self._call_gmp(f"get_{tag}s", getter)
        root = ET.fromstring(xml)
        path = f".//{tag}"
        for node in root.findall(path):
            n = node.findtext("name")
            if n and n.strip().lower() == name.strip().lower():
                _id = node.get("id")
                if _id:
                    return _id
        return None

    def _call_gmp(self, method: str, func: Callable[[], str], *, timeout: Optional[float] = None) -> str:
        """
        Call GMP function with retries and timeout. Returns XML string.
        """
        rid = get_request_id()
        retries = self.cfg.max_retries
        timeout = timeout or self.cfg.command_timeout
        attempt = 0
        while True:
            attempt += 1
            start = time.monotonic()
            status = "ok"
            try:
                # Enforce timeout by running in blocking mode with wall timer
                result = _run_with_timeout(func, timeout)
                return result
            except (GvmError, GvmProtocolError) as e:
                status = "gvm_error"
                if attempt <= retries and _is_transient(str(e)):
                    _sleep = _backoff(attempt, self.cfg.backoff_base, self.cfg.backoff_max)
                    LOGGER.warning("gvm.call.retry", extra={"extra": {
                        "request_id": rid, "method": method, "attempt": attempt, "error": repr(e), "sleep": round(_sleep, 3)
                    }})
                    time.sleep(_sleep)
                    continue
                LOGGER.error("gvm.call.error", extra={"extra": {
                    "request_id": rid, "method": method, "attempt": attempt, "error": repr(e)
                }})
                raise OpenVASTransient(str(e)) if _is_transient(str(e)) else OpenVASError(str(e))
            except OpenVASTimeout as e:
                status = "timeout"
                if attempt <= retries:
                    _sleep = _backoff(attempt, self.cfg.backoff_base, self.cfg.backoff_max)
                    LOGGER.warning("gvm.call.timeout_retry", extra={"extra": {
                        "request_id": rid, "method": method, "attempt": attempt, "sleep": round(_sleep, 3)
                    }})
                    time.sleep(_sleep)
                    continue
                LOGGER.error("gvm.call.timeout", extra={"extra": {
                    "request_id": rid, "method": method, "attempt": attempt
                }})
                raise
            finally:
                dur = time.monotonic() - start
                if _PROM and GVM_CALLS and GVM_LAT:
                    try:
                        GVM_CALLS.labels(method, status).inc()
                        GVM_LAT.labels(method, status).observe(dur)
                    except Exception:
                        pass

    @staticmethod
    def _tcp_ping(host: str, port: int, timeout: float) -> None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return
        except Exception as e:
            raise OpenVASError(f"TCP connect failed to {host}:{port}: {e}")


# =========================
# Helpers
# =========================

def _run_with_timeout(fn: Callable[[], str], timeout: float) -> str:
    """
    Run blocking function with wall-clock timeout.
    """
    start = time.monotonic()
    result: Optional[str] = None
    exc: Optional[BaseException] = None

    def _runner():
        nonlocal result, exc
        try:
            result = fn()
        except BaseException as e:  # capture to raise in main thread
            exc = e

    # Use a tiny thread to avoid blocking signals
    import threading
    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        # Best-effort: no cooperative cancel in GMP, just time out
        raise OpenVASTimeout(f"GMP call exceeded timeout {timeout}s")
    if exc:
        raise exc
    assert result is not None
    return result


def _is_transient(msg: str) -> bool:
    m = msg.lower()
    return any(s in m for s in (
        "temporarily", "timeout", "connection reset", "connection aborted", "broken pipe", "try again", "rate limit"
    ))


def _backoff(attempt: int, base: float, max_delay: float) -> float:
    # Exponential with jitter
    return min(max_delay, base * (2 ** (attempt - 1))) * (0.5 + random.random() / 2.0)


def _extract_id(xml: str, tag: str, *, child: Optional[str] = None, attr: str = "id") -> Optional[str]:
    root = ET.fromstring(xml)
    node = root if root.tag == tag else root.find(f".//{tag}")
    if node is None:
        return None
    if child:
        c = node.find(f".//{child}")
        if c is not None:
            return c.get(attr) or c.text
        return None
    return node.get(attr)


def _extract_any_id(xml: str) -> Optional[str]:
    root = ET.fromstring(xml)
    # Try common patterns
    for tag in ("report", "task", "create_task_response", "create_target_response"):
        node = root.find(f".//{tag}")
        if node is not None:
            _id = node.get("id")
            if _id:
                return _id
    return None


# =========================
# Minimal usage (example)
# =========================
# Example (not executed here):
#   cfg = OpenVASConfig(
#       host="gvm.local", port=9390, username="admin", password="secret",
#       default_scan_config_name="Full and fast", default_report_format_name="HTML"
#   )
#   with OpenVASConnector(cfg) as ov:
#       tid = ov.ensure_target("prod-web", ["10.0.1.15"])
#       task_id = ov.ensure_task("scan-prod-web", tid)
#       rep_id = ov.start_task(task_id)
#       final_rep = ov.wait_for_report(task_id, poll_interval=10, max_wait_seconds=3600)
#       data = ov.fetch_report(final_rep, format_name="HTML", as_bytes=True)
#       with open("report.html", "wb") as f:
#           f.write(data)
