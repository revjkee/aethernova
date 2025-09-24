# neuroforge-core/cli/tools/serve_local.py
# Industrial-grade local dev file server & artifact API for NeuroForge.
# Stdlib-only (optional TLS if cert/key provided).
# Endpoints (prefix /api/v1):
#   GET  /healthz
#   GET  /metrics
#   GET  /ls?path=rel/dir
#   HEAD /file?path=rel/file
#   GET  /file?path=rel/file            (supports Range/ETag/If-Modified-Since)
#   PUT  /file?path=rel/file            (raw body upload, atomic write)
#   POST /mkdir?path=rel/dir
#   DELETE /file?path=rel/file
#   GET  /events/tail?path=rel/file     (Server-Sent Events live tail)
#
# Auth:
#   - Optional Bearer token via --token or --token-file.
#
# CORS:
#   - --cors "*" or comma-separated origins; adds ACAO/ACAM/ACAH.
#
# TLS:
#   - --certfile --keyfile (PEM). Runs HTTPS on given host/port.
#
# Notes:
#   - Root jail: all paths are resolved under --root; traversal is denied.
#   - Atomic writes: data -> .tmp -> os.replace().
#   - Logs: JSON (stdout + rotating file).
#   - Simple token-bucket rate limiting per-IP.

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import email.utils
import http.server
import io
import json
import logging
import logging.handlers
import mimetypes
import os
import posixpath
import re
import signal
import socket
import ssl
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# ---------------------------
# Utils
# ---------------------------

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"


def utcnow() -> str:
    return dt.datetime.utcnow().strftime(ISO)


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------------------------
# Structured JSON logging
# ---------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": utcnow(),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            data.update(record.extra)
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json_dumps(data)


def setup_logging(log_dir: Path, level: str = "INFO") -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(JsonFormatter())
    root.addHandler(ch)
    fh = logging.handlers.RotatingFileHandler(
        log_dir / "serve_local.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    fh.setFormatter(JsonFormatter())
    root.addHandler(fh)


log = logging.getLogger("neuroforge.serve_local")

# ---------------------------
# Metrics (Prometheus text)
# ---------------------------

@dataclasses.dataclass
class Counter:
    name: str
    help: str
    value: float = 0.0
    def inc(self, v: float = 1.0) -> None:
        self.value += v


@dataclasses.dataclass
class Gauge:
    name: str
    help: str
    value: float = 0.0
    def set(self, v: float) -> None:
        self.value = v


class Metrics:
    def __init__(self) -> None:
        self.counters: Dict[str, Counter] = {}
        self.gauges: Dict[str, Gauge] = {}
        self._lock = threading.Lock()

    def counter(self, name: str, help: str) -> Counter:
        with self._lock:
            return self.counters.setdefault(name, Counter(name, help))

    def gauge(self, name: str, help: str) -> Gauge:
        with self._lock:
            return self.gauges.setdefault(name, Gauge(name, help))

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            for c in self.counters.values():
                lines.append(f"# HELP {c.name} {c.help}")
                lines.append(f"# TYPE {c.name} counter")
                lines.append(f"{c.name} {c.value}")
            for g in self.gauges.values():
                lines.append(f"# HELP {g.name} {g.help}")
                lines.append(f"# TYPE {g.name} gauge")
                lines.append(f"{g.name} {g.value}")
        return "\n".join(lines) + "\n"


METRICS = Metrics()
M_HTTP_TOTAL = METRICS.counter("serve_local_http_requests_total", "Total HTTP requests")
M_HTTP_ERRORS = METRICS.counter("serve_local_http_errors_total", "HTTP errors")
M_BYTES_OUT = METRICS.counter("serve_local_bytes_out_total", "Bytes sent")
M_BYTES_IN = METRICS.counter("serve_local_bytes_in_total", "Bytes received")
G_OPEN_CONNS = METRICS.gauge("serve_local_open_connections", "Open connections")


# ---------------------------
# Rate limiting (per IP)
# ---------------------------

class TokenBucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate = float(rate)
        self.burst = float(burst)
        self.tokens = burst
        self.last = time.time()
        self.lock = threading.Lock()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.time()
        with self.lock:
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False


# ---------------------------
# Server configuration
# ---------------------------

@dataclasses.dataclass
class ServerConfig:
    root: Path
    host: str = "127.0.0.1"
    port: int = 8081
    log_dir: Path = Path("./logs")
    log_level: str = "INFO"
    cors: Optional[str] = None  # "*" or "https://a,https://b"
    readonly: bool = False
    token: Optional[str] = None
    token_file: Optional[Path] = None
    max_upload_mb: int = 2048
    tls_certfile: Optional[Path] = None
    tls_keyfile: Optional[Path] = None
    rl_rate: float = 50.0  # tokens/sec per IP
    rl_burst: float = 200.0


CFG: ServerConfig  # will be set in main
RATE_LIMITERS: Dict[str, TokenBucket] = {}  # per-IP


def effective_token(cfg: ServerConfig) -> Optional[str]:
    if cfg.token:
        return cfg.token
    if cfg.token_file and cfg.token_file.exists():
        try:
            return cfg.token_file.read_text(encoding="utf-8").strip()
        except Exception:
            return None
    return None


# ---------------------------
# Path security (root jail)
# ---------------------------

def safe_join(root: Path, rel: str) -> Path:
    rel = rel.strip().lstrip("/\\")
    rel = rel.replace("\\", "/")
    # Normalize: remove // and ./, resolve .. safely
    p = (root / rel).resolve(strict=False)
    r = root.resolve(strict=False)
    if not str(p).startswith(str(r)):
        raise PermissionError("Path escapes root jail")
    return p


def etag_for(path: Path) -> str:
    st = path.stat()
    return f"W/\"{st.st_mtime_ns:x}-{st.st_size:x}\""


def http_date(ts: float) -> str:
    return email.utils.formatdate(ts, usegmt=True)


def parse_http_date(s: str) -> Optional[float]:
    try:
        dtp = email.utils.parsedate_to_datetime(s)
        return dtp.timestamp()
    except Exception:
        return None


def parse_range(h: Optional[str], size: int) -> Optional[Tuple[int, int]]:
    # Single range only; "bytes=start-end"
    if not h:
        return None
    m = re.match(r"bytes=(\d*)-(\d*)$", h.strip())
    if not m:
        return None
    start_s, end_s = m.groups()
    if start_s == "" and end_s == "":
        return None
    if start_s == "":
        # suffix length
        length = int(end_s)
        if length <= 0:
            return None
        start = max(0, size - length)
        end = size - 1
    else:
        start = int(start_s)
        end = size - 1 if end_s == "" else int(end_s)
    if start < 0 or end < start or start >= size:
        return None
    end = min(end, size - 1)
    return (start, end)


# ---------------------------
# HTTP Handler
# ---------------------------

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "NeuroForgeServeLocal/1.0"
    sys_version = ""

    # -------------- Helpers

    def _set_common_headers(self, code: int, ctype: str = "application/json", extra: Dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Server-Time", utcnow())
        if CFG.cors:
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type,Range,If-None-Match,If-Modified-Since")
            self.send_header("Access-Control-Allow-Methods", "GET,HEAD,PUT,POST,DELETE,OPTIONS")
            self.send_header("Access-Control-Max-Age", "600")
            for origin in (o.strip() for o in CFG.cors.split(",")):
                if origin == "*" or origin == self.headers.get("Origin"):
                    self.send_header("Access-Control-Allow-Origin", origin)
                    break
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)

    def _ip(self) -> str:
        return self.client_address[0] if self.client_address else "0.0.0.0"

    def _rate_limit(self, cost: float = 1.0) -> bool:
        ip = self._ip()
        tb = RATE_LIMITERS.get(ip)
        if tb is None:
            tb = RATE_LIMITERS[ip] = TokenBucket(CFG.rl_rate, CFG.rl_burst)
        return tb.allow(cost)

    def _auth_ok(self) -> bool:
        tok = effective_token(CFG)
        if tok is None:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            return h.split(" ", 1)[1].strip() == tok
        return False

    def _deny(self, code: int, msg: str) -> None:
        try:
            payload = {"error": msg, "code": code}
            body = json_dumps(payload).encode("utf-8")
            self._set_common_headers(code, extra={"Content-Length": str(len(body))})
            self.end_headers()
            self.wfile.write(body)
            M_HTTP_ERRORS.inc(1)
        except Exception:
            pass

    def _read_body(self, limit_bytes: int) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length > limit_bytes:
            raise ValueError("Request body too large")
        data = self.rfile.read(length) if length > 0 else b""
        M_BYTES_IN.inc(len(data))
        return data

    def _handle_options(self) -> None:
        self._set_common_headers(204)
        self.end_headers()

    # -------------- Methods

    def do_OPTIONS(self) -> None:
        self._handle_options()

    def do_GET(self) -> None:
        G_OPEN_CONNS.set(G_OPEN_CONNS.value + 1)
        M_HTTP_TOTAL.inc(1)
        try:
            if not self._rate_limit():
                self._deny(429, "Too Many Requests")
                return
            if self.path.startswith("/healthz"):
                self._send_healthz()
                return
            if self.path.startswith("/metrics"):
                self._send_metrics()
                return
            if not self._auth_ok():
                self._deny(401, "Unauthorized")
                return

            if self.path.startswith("/api/v1/ls"):
                self._api_ls()
                return
            if self.path.startswith("/api/v1/file"):
                self._api_file_get_or_head(method="GET")
                return
            if self.path.startswith("/api/v1/events/tail"):
                self._api_tail()
                return

            self._deny(404, "Not Found")
        except Exception:
            log.exception("GET_error", extra={"extra": {"path": self.path}})
            self._deny(500, "Internal Server Error")
        finally:
            G_OPEN_CONNS.set(max(0.0, G_OPEN_CONNS.value - 1))

    def do_HEAD(self) -> None:
        G_OPEN_CONNS.set(G_OPEN_CONNS.value + 1)
        M_HTTP_TOTAL.inc(1)
        try:
            if not self._rate_limit():
                self._deny(429, "Too Many Requests")
                return
            if not self._auth_ok():
                self._deny(401, "Unauthorized")
                return
            if self.path.startswith("/api/v1/file"):
                self._api_file_get_or_head(method="HEAD")
                return
            self._deny(404, "Not Found")
        except Exception:
            log.exception("HEAD_error", extra={"extra": {"path": self.path}})
            self._deny(500, "Internal Server Error")
        finally:
            G_OPEN_CONNS.set(max(0.0, G_OPEN_CONNS.value - 1))

    def do_POST(self) -> None:
        G_OPEN_CONNS.set(G_OPEN_CONNS.value + 1)
        M_HTTP_TOTAL.inc(1)
        try:
            if not self._rate_limit():
                self._deny(429, "Too Many Requests")
                return
            if not self._auth_ok():
                self._deny(401, "Unauthorized")
                return
            if CFG.readonly:
                self._deny(403, "Read-only mode")
                return
            if self.path.startswith("/api/v1/mkdir"):
                self._api_mkdir()
                return
            self._deny(404, "Not Found")
        except Exception:
            log.exception("POST_error", extra={"extra": {"path": self.path}})
            self._deny(500, "Internal Server Error")
        finally:
            G_OPEN_CONNS.set(max(0.0, G_OPEN_CONNS.value - 1))

    def do_PUT(self) -> None:
        G_OPEN_CONNS.set(G_OPEN_CONNS.value + 1)
        M_HTTP_TOTAL.inc(1)
        try:
            if not self._rate_limit(cost=2.0):
                self._deny(429, "Too Many Requests")
                return
            if not self._auth_ok():
                self._deny(401, "Unauthorized")
                return
            if CFG.readonly:
                self._deny(403, "Read-only mode")
                return
            if self.path.startswith("/api/v1/file"):
                self._api_file_put()
                return
            self._deny(404, "Not Found")
        except Exception:
            log.exception("PUT_error", extra={"extra": {"path": self.path}})
            self._deny(500, "Internal Server Error")
        finally:
            G_OPEN_CONNS.set(max(0.0, G_OPEN_CONNS.value - 1))

    def do_DELETE(self) -> None:
        G_OPEN_CONNS.set(G_OPEN_CONNS.value + 1)
        M_HTTP_TOTAL.inc(1)
        try:
            if not self._rate_limit():
                self._deny(429, "Too Many Requests")
                return
            if not self._auth_ok():
                self._deny(401, "Unauthorized")
                return
            if CFG.readonly:
                self._deny(403, "Read-only mode")
                return
            if self.path.startswith("/api/v1/file"):
                self._api_file_delete()
                return
            self._deny(404, "Not Found")
        except Exception:
            log.exception("DELETE_error", extra={"extra": {"path": self.path}})
            self._deny(500, "Internal Server Error")
        finally:
            G_OPEN_CONNS.set(max(0.0, G_OPEN_CONNS.value - 1))

    # -------------- Endpoint impls

    def _query_param(self, name: str) -> Optional[str]:
        # Very small parser to avoid urllib dependency explosion
        if "?" not in self.path:
            return None
        q = self.path.split("?", 1)[1]
        for pair in q.split("&"):
            if not pair:
                continue
            k, _, v = pair.partition("=")
            if k == name:
                # decode %2F and + minimally
                v = v.replace("+", " ")
                v = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: bytes.fromhex(m.group(1)).decode("utf-8", "ignore"), v)
                return v
        return None

    def _send_healthz(self) -> None:
        payload = {"status": "ok", "ts": utcnow()}
        body = json_dumps(payload).encode("utf-8")
        self._set_common_headers(200, extra={"Content-Length": str(len(body))})
        self.end_headers()
        self.wfile.write(body)

    def _send_metrics(self) -> None:
        text = METRICS.render().encode("utf-8")
        self._set_common_headers(200, "text/plain; version=0.0.4", extra={"Content-Length": str(len(text))})
        self.end_headers()
        self.wfile.write(text)

    def _api_ls(self) -> None:
        p = self._query_param("path") or ""
        try:
            base = safe_join(CFG.root, p)
            if not base.exists():
                self._deny(404, "Path not found")
                return
            if base.is_file():
                st = base.stat()
                item = {
                    "name": base.name, "type": "file", "size": st.st_size,
                    "mtime": st.st_mtime, "etag": etag_for(base)
                }
                payload = {"path": str(base.relative_to(CFG.root)), "items": [item]}
            else:
                items = []
                for child in sorted(base.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
                    try:
                        st = child.stat()
                        items.append({
                            "name": child.name,
                            "type": "file" if child.is_file() else "dir",
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                        })
                    except Exception:
                        continue
                payload = {"path": str(base.relative_to(CFG.root)), "items": items}
            body = json_dumps(payload).encode("utf-8")
            self._set_common_headers(200, extra={"Content-Length": str(len(body))})
            self.end_headers()
            self.wfile.write(body)
        except PermissionError:
            self._deny(403, "Forbidden")
        except Exception:
            log.exception("ls_error")
            self._deny(500, "Internal Server Error")

    def _api_file_get_or_head(self, method: str) -> None:
        rel = self._query_param("path")
        if not rel:
            self._deny(400, "Missing 'path'")
            return
        try:
            path = safe_join(CFG.root, rel)
            if not path.is_file():
                self._deny(404, "Not Found")
                return
            st = path.stat()
            ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            et = etag_for(path)
            last_mod = http_date(st.st_mtime)

            # Conditional requests
            inm = self.headers.get("If-None-Match")
            ims = self.headers.get("If-Modified-Since")
            if inm == et or (ims and parse_http_date(ims) and st.st_mtime <= parse_http_date(ims)):  # type: ignore[arg-type]
                self._set_common_headers(304, ctype, {
                    "ETag": et,
                    "Last-Modified": last_mod,
                    "Accept-Ranges": "bytes"
                })
                self.end_headers()
                return

            # Range
            rng = parse_range(self.headers.get("Range"), st.st_size)
            if rng:
                start, end = rng
                length = end - start + 1
                status = 206
                headers = {
                    "Content-Type": ctype,
                    "Content-Length": str(length),
                    "Content-Range": f"bytes {start}-{end}/{st.st_size}",
                    "ETag": et,
                    "Last-Modified": last_mod,
                    "Accept-Ranges": "bytes",
                }
            else:
                start, end = 0, st.st_size - 1
                length = st.st_size
                status = 200
                headers = {
                    "Content-Type": ctype,
                    "Content-Length": str(length),
                    "ETag": et,
                    "Last-Modified": last_mod,
                    "Accept-Ranges": "bytes",
                }

            self._set_common_headers(status, headers["Content-Type"], headers)
            self.end_headers()
            if method == "HEAD":
                return

            with path.open("rb") as f:
                f.seek(start)
                to_send = length
                buf = memoryview(bytearray(64 * 1024))
                while to_send > 0:
                    n = f.readinto(buf)
                    if not n:
                        break
                    if n > to_send:
                        n = to_send
                    self.wfile.write(buf[:n])
                    M_BYTES_OUT.inc(n)
                    to_send -= n
        except PermissionError:
            self._deny(403, "Forbidden")
        except Exception:
            log.exception("file_get_error")
            self._deny(500, "Internal Server Error")

    def _api_file_put(self) -> None:
        rel = self._query_param("path")
        if not rel:
            self._deny(400, "Missing 'path'")
            return
        limit = CFG.max_upload_mb * 1024 * 1024
        try:
            path = safe_join(CFG.root, rel)
            path.parent.mkdir(parents=True, exist_ok=True)

            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > limit:
                self._deny(413 if length > limit else 400, "Invalid Content-Length")
                return

            tmp = path.with_suffix(path.suffix + ".tmp")
            with tmp.open("wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(64 * 1024, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
                    M_BYTES_IN.inc(len(chunk))
            os.replace(tmp, path)

            st = path.stat()
            payload = {
                "status": "ok",
                "path": str(path.relative_to(CFG.root)),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "etag": etag_for(path),
            }
            body = json_dumps(payload).encode("utf-8")
            self._set_common_headers(200, extra={"Content-Length": str(len(body))})
            self.end_headers()
            self.wfile.write(body)
        except PermissionError:
            self._deny(403, "Forbidden")
        except Exception:
            log.exception("file_put_error")
            self._deny(500, "Internal Server Error")

    def _api_file_delete(self) -> None:
        rel = self._query_param("path")
        if not rel:
            self._deny(400, "Missing 'path'")
            return
        try:
            path = safe_join(CFG.root, rel)
            if not path.exists():
                self._deny(404, "Not Found")
                return
            if path.is_dir():
                self._deny(400, "Refuse to delete directory")
                return
            path.unlink()
            payload = {"status": "ok", "deleted": rel}
            body = json_dumps(payload).encode("utf-8")
            self._set_common_headers(200, extra={"Content-Length": str(len(body))})
            self.end_headers()
            self.wfile.write(body)
        except PermissionError:
            self._deny(403, "Forbidden")
        except Exception:
            log.exception("file_delete_error")
            self._deny(500, "Internal Server Error")

    def _api_mkdir(self) -> None:
        rel = self._query_param("path")
        if not rel:
            self._deny(400, "Missing 'path'")
            return
        try:
            path = safe_join(CFG.root, rel)
            path.mkdir(parents=True, exist_ok=True)
            payload = {"status": "ok", "path": str(path.relative_to(CFG.root))}
            body = json_dumps(payload).encode("utf-8")
            self._set_common_headers(200, extra={"Content-Length": str(len(body))})
            self.end_headers()
            self.wfile.write(body)
        except PermissionError:
            self._deny(403, "Forbidden")
        except Exception:
            log.exception("mkdir_error")
            self._deny(500, "Internal Server Error")

    def _api_tail(self) -> None:
        rel = self._query_param("path")
        if not rel:
            self._deny(400, "Missing 'path'")
            return
        try:
            path = safe_join(CFG.root, rel)
            if not path.is_file():
                self._deny(404, "Not Found")
                return
            # SSE headers
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            if CFG.cors:
                self.send_header("Access-Control-Allow-Credentials", "true")
                for origin in (o.strip() for o in CFG.cors.split(",")):
                    if origin == "*" or origin == self.headers.get("Origin"):
                        self.send_header("Access-Control-Allow-Origin", origin)
                        break
            self.end_headers()

            # Tail loop
            with path.open("rb") as f:
                # Start near the end
                try:
                    st = path.stat()
                    start = max(0, st.st_size - 8192)
                    f.seek(start)
                except Exception:
                    pass
                buf = b""
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.3)
                        continue
                    try:
                        data = line.decode("utf-8", "replace").rstrip("\n")
                        payload = f"data: {data}\n\n".encode("utf-8")
                        self.wfile.write(payload)
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break
        except Exception:
            # Can't reply with JSON at this point; just log
            log.exception("sse_tail_error")

    # Silence default noisy access log; we already log via JSON
    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("access", extra={"extra": {"client": self._ip(), "path": self.path}})


# ---------------------------
# Threaded HTTP server with TLS support
# ---------------------------

class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    # track open connections gauge
    def finish_request(self, request, client_address):
        try:
            super().finish_request(request, client_address)
        except Exception:
            log.exception("finish_request_error")


def build_server(cfg: ServerConfig) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((cfg.host, cfg.port), Handler)
    if cfg.tls_certfile and cfg.tls_keyfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cfg.tls_certfile), keyfile=str(cfg.tls_keyfile))
        srv.socket = context.wrap_socket(srv.socket, server_side=True)
    return srv


# ---------------------------
# Main
# ---------------------------

def parse_args(argv: Optional[list[str]] = None) -> ServerConfig:
    p = argparse.ArgumentParser(description="NeuroForge Local Artifact/API Server")
    p.add_argument("--root", type=Path, required=True, help="Root directory (jail)")
    p.add_argument("--host", type=str, default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--log-dir", type=Path, default=Path("./logs"))
    p.add_argument("--log-level", type=str, default="INFO")
    p.add_argument("--readonly", action="store_true")
    p.add_argument("--cors", type=str, default=None, help="CORS origins: * or comma-separated list")
    p.add_argument("--token", type=str, default=None, help="Static Bearer token")
    p.add_argument("--token-file", type=Path, default=None, help="File with token")
    p.add_argument("--max-upload-mb", type=int, default=2048)
    p.add_argument("--certfile", type=Path, default=None, help="TLS certificate (PEM)")
    p.add_argument("--keyfile", type=Path, default=None, help="TLS private key (PEM)")
    p.add_argument("--rl-rate", type=float, default=50.0, help="Rate limit tokens/sec per IP")
    p.add_argument("--rl-burst", type=float, default=200.0, help="Burst size per IP")
    ns = p.parse_args(argv)
    return ServerConfig(
        root=ns.root,
        host=ns.host,
        port=ns.port,
        log_dir=ns.log_dir,
        log_level=ns.log_level.upper(),
        cors=ns.cors,
        readonly=ns.readonly,
        token=ns.token,
        token_file=ns.token_file,
        max_upload_mb=ns.max_upload_mb,
        tls_certfile=ns.certfile,
        tls_keyfile=ns.keyfile,
        rl_rate=ns.rl_rate,
        rl_burst=ns.rl_burst,
    )


def main() -> None:
    global CFG
    CFG = parse_args()
    CFG.root.mkdir(parents=True, exist_ok=True)
    setup_logging(CFG.log_dir, CFG.log_level)
    token_present = "yes" if effective_token(CFG) else "no"
    log.info("serve_local_start", extra={"extra": {
        "host": CFG.host, "port": CFG.port, "root": str(CFG.root),
        "readonly": CFG.readonly, "cors": CFG.cors or "", "auth": token_present,
        "tls": bool(CFG.tls_certfile and CFG.tls_keyfile)
    }})
    srv = build_server(CFG)

    stop = threading.Event()

    def shutdown(signum=None, frame=None):
        log.info("serve_local_shutdown", extra={"extra": {"signal": signum}})
        stop.set()
        # Close the listener socket to break serve_forever()
        try:
            srv.shutdown()
        except Exception:
            pass

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, shutdown)
        except Exception:
            pass

    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        shutdown()
    finally:
        try:
            srv.server_close()
        except Exception:
            pass
        log.info("serve_local_stopped")

if __name__ == "__main__":
    main()
