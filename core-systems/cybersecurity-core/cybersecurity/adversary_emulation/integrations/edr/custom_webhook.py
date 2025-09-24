# -*- coding: utf-8 -*-
"""
custom_webhook.py — безопасный промышленный приёмник EDR-вебхуков без внешних зависимостей.

Назначение:
  - Принимать POST /v1/edr/webhook (application/json)
  - Проверять HMAC-SHA256 подпись (X-EDR-Signature: v1=<hex>)
  - Защищаться от повторов по nonce+timestamp с окном допустимого времени
  - Ограничивать размер тела запроса и частоту на IP
  - Поддерживать allowlist IP/CIDR
  - Вести NDJSON-аудит и структурированные JSON-логи
  - Health/Ready endpoints: GET /healthz, GET /readyz
  - Работать на ThreadingHTTPServer

Заметки:
  - Подпись рассчитывается как HMAC_SHA256(secret, f"{ts}.{nonce}.{sha256(body)}")
  - Секрет читается из переменной окружения EDR_WEBHOOK_SECRET (hex или base64)
  - Хранилище nonce — SQLite (по умолчанию ./audit/nonces.sqlite3)
  - Код не использует сторонних библиотек

Переменные окружения (со значениями по умолчанию):
  EDR_WEBHOOK_HOST="0.0.0.0"
  EDR_WEBHOOK_PORT="8080"
  EDR_WEBHOOK_MAX_BODY_BYTES="262144"            # 256 KiB
  EDR_WEBHOOK_ALLOWED_IPS=""                     # "203.0.113.5,198.51.100.0/24"
  EDR_WEBHOOK_SECRET="<REQUIRED>"                # hex или base64
  EDR_WEBHOOK_REPLAY_WINDOW_SECONDS="300"        # 5 минут
  EDR_WEBHOOK_AUDIT_DIR="./audit"
  EDR_WEBHOOK_RATE_LIMIT_RPS="5"                 # средняя для leaky bucket
  EDR_WEBHOOK_RATE_LIMIT_BURST="10"
  EDR_WEBHOOK_NONCE_DB_PATH="./audit/nonces.sqlite3"
  EDR_WEBHOOK_REQUIRE_TLS="0"                    # если "1", отклонять X-Forwarded-Proto != https

Внимание:
  - Для продакшена терминальная TLS-защита должна обеспечиваться обратным прокси/ингрессом.
  - Для доверия к заголовкам X-Forwarded-* требуется безопасная внутренняя сеть/прокси.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import queue
import signal
import sqlite3
import threading
import time
import uuid
from collections import deque, defaultdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple


# ------------------------------- Конфигурация --------------------------------

@dataclasses.dataclass(slots=True)
class WebhookConfig:
    host: str
    port: int
    max_body_bytes: int
    allowed_ips: List[ipaddress._BaseNetwork]  # type: ignore[name-defined]
    secret: bytes
    replay_window_seconds: int
    audit_dir: Path
    rate_limit_rps: float
    rate_limit_burst: int
    nonce_db_path: Path
    require_tls: bool

    @staticmethod
    def _parse_secret(raw: str) -> bytes:
        if not raw:
            raise ValueError("EDR_WEBHOOK_SECRET is required")
        # Пытаемся hex
        with contextlib.suppress(Exception):
            return bytes.fromhex(raw)
        # Пытаемся base64
        with contextlib.suppress(Exception):
            return base64.b64decode(raw, validate=True)
        raise ValueError("EDR_WEBHOOK_SECRET must be hex or base64")

    @staticmethod
    def _parse_allowed_ips(raw: str) -> List[ipaddress._BaseNetwork]:  # type: ignore[name-defined]
        nets: List[ipaddress._BaseNetwork] = []
        raw = (raw or "").strip()
        if not raw:
            return nets
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            # Если IP без маски — рассматриваем как /32 (IPv4) или /128 (IPv6)
            if "/" not in item:
                try:
                    ip = ipaddress.ip_address(item)
                    mask = "32" if isinstance(ip, ipaddress.IPv4Address) else "128"
                    item = f"{item}/{mask}"
                except ValueError:
                    raise
            nets.append(ipaddress.ip_network(item, strict=False))
        return nets

    @classmethod
    def from_env(cls) -> "WebhookConfig":
        host = os.environ.get("EDR_WEBHOOK_HOST", "0.0.0.0")
        port = int(os.environ.get("EDR_WEBHOOK_PORT", "8080"))
        max_body_bytes = int(os.environ.get("EDR_WEBHOOK_MAX_BODY_BYTES", "262144"))
        allowed_ips = cls._parse_allowed_ips(os.environ.get("EDR_WEBHOOK_ALLOWED_IPS", ""))
        secret = cls._parse_secret(os.environ.get("EDR_WEBHOOK_SECRET", ""))
        replay_window = int(os.environ.get("EDR_WEBHOOK_REPLAY_WINDOW_SECONDS", "300"))
        audit_dir = Path(os.environ.get("EDR_WEBHOOK_AUDIT_DIR", "./audit"))
        rate_limit_rps = float(os.environ.get("EDR_WEBHOOK_RATE_LIMIT_RPS", "5"))
        rate_limit_burst = int(os.environ.get("EDR_WEBHOOK_RATE_LIMIT_BURST", "10"))
        nonce_db_path = Path(os.environ.get("EDR_WEBHOOK_NONCE_DB_PATH", str(audit_dir / "nonces.sqlite3")))
        require_tls = os.environ.get("EDR_WEBHOOK_REQUIRE_TLS", "0") == "1"
        audit_dir.mkdir(parents=True, exist_ok=True)
        nonce_db_path.parent.mkdir(parents=True, exist_ok=True)
        return cls(
            host=host,
            port=port,
            max_body_bytes=max_body_bytes,
            allowed_ips=allowed_ips,
            secret=secret,
            replay_window_seconds=replay_window,
            audit_dir=audit_dir,
            rate_limit_rps=rate_limit_rps,
            rate_limit_burst=rate_limit_burst,
            nonce_db_path=nonce_db_path,
            require_tls=require_tls,
        )


# ------------------------------- Логирование ---------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k in ("remote_ip", "request_id", "path", "event", "extra"):
            v = getattr(record, k, None)
            if v is not None:
                payload[k] = v
        return json.dumps(payload, ensure_ascii=False)


def build_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(JsonFormatter())
        logger.addHandler(h)
    return logger


LOG = build_logger("edr.webhook")


# --------------------------------- Аудит -------------------------------------

class NdjsonAudit:
    def __init__(self, directory: Path):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path_for_today(self) -> Path:
        day = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
        return self.dir / f"edr_webhook_{day}.ndjson"

    def write(self, record: Dict[str, Any]) -> None:
        rec = dict(record)
        rec["ts"] = datetime.now(tz=timezone.utc).isoformat()
        data = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            with self._path_for_today().open("a", encoding="utf-8") as f:
                f.write(data + "\n")


# ------------------------------- Rate limiting --------------------------------

class LeakyBucket:
    """Простой ограничитель скорости по IP."""
    def __init__(self, rps: float, burst: int):
        self.rps = rps
        self.burst = burst
        self._state: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            tokens, last_ts = self._state.get(ip, (float(self.burst), now))
            # пополнение
            tokens = min(self.burst, tokens + (now - last_ts) * self.rps)
            if tokens >= 1.0:
                tokens -= 1.0
                self._state[ip] = (tokens, now)
                return True
            else:
                self._state[ip] = (tokens, now)
                return False


# ------------------------------- Nonce storage --------------------------------

class NonceDB:
    """SQLite-хранилище для защиты от повторов."""
    def __init__(self, path: Path):
        self.path = path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce TEXT PRIMARY KEY,
                    ts    INTEGER NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nonces_ts ON nonces(ts)")
            conn.commit()

    def is_replayed_and_store(self, nonce: str, ts_epoch: int, window: int) -> bool:
        """Возвращает True, если nonce уже видели в допустимом окне, иначе сохраняет и возвращает False."""
        now = int(time.time())
        min_ts = now - window
        with sqlite3.connect(self.path, timeout=5) as conn:
            conn.execute("DELETE FROM nonces WHERE ts < ?", (min_ts,))
            try:
                conn.execute("INSERT INTO nonces(nonce, ts) VALUES (?, ?)", (nonce, ts_epoch))
                conn.commit()
                return False
            except sqlite3.IntegrityError:
                # nonce уже существует
                return True


# ----------------------------- Очередь обработки -----------------------------

class Worker(threading.Thread):
    """Фоновая обработка валидных событий (пример: запись, маршрутизация и т.д.)."""
    daemon = True

    def __init__(self, audit: NdjsonAudit):
        super().__init__(name="webhook-worker")
        self.q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=10000)
        self.audit = audit
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            # Здесь может быть маршрутизация в шину/хранилище.
            self.audit.write({"event": "accepted_event", "payload_meta": item})
            self.q.task_done()

    def submit(self, item: Dict[str, Any]) -> None:
        self.q.put_nowait(item)

    def stop(self) -> None:
        self._stop.set()


# --------------------------- Утилиты подписи/безопасности --------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_signature(secret: bytes, ts: str, nonce: str, body: bytes, signature_header: str) -> bool:
    """Проверка X-EDR-Signature: v1=<hex> по строке f"{ts}.{nonce}.{sha256(body)}"."""
    if not signature_header or not signature_header.startswith("v1="):
        return False
    try:
        provided = bytes.fromhex(signature_header[3:].strip())
    except Exception:
        return False
    signing_str = f"{ts}.{nonce}.{sha256_hex(body)}".encode("utf-8")
    mac = hmac.new(secret, signing_str, hashlib.sha256).digest()
    return hmac.compare_digest(mac, provided)


def parse_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except Exception:
        return None


def client_ip_from_handler(h: BaseHTTPRequestHandler) -> str:
    # Предпочитаем direct socket IP. Если доверяете прокси — расширьте логикой X-Forwarded-For.
    return h.client_address[0]


def ip_allowed(ip: str, nets: List[ipaddress._BaseNetwork]) -> bool:  # type: ignore[name-defined]
    if not nets:
        return True
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in nets)


def read_body(handler: BaseHTTPRequestHandler, max_bytes: int) -> Tuple[int, bytes]:
    length = handler.headers.get("Content-Length")
    if length is None:
        return (413, b'{"error":"missing_content_length"}')
    try:
        n = int(length)
    except Exception:
        return (400, b'{"error":"bad_content_length"}')
    if n < 0 or n > max_bytes:
        return (413, b'{"error":"body_too_large"}')
    raw = handler.rfile.read(n)
    # Поддержка gzip
    if (handler.headers.get("Content-Encoding") or "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            return (400, b'{"error":"bad_gzip"}')
    return (0, raw)


# --------------------------------- HTTP handler ------------------------------

class EdrWebhookHandler(BaseHTTPRequestHandler):
    server_version = "EDRWebhook/1.0"
    sys_version = ""

    cfg: WebhookConfig = None  # type: ignore[assignment]
    audit: NdjsonAudit = None  # type: ignore[assignment]
    limiter: LeakyBucket = None  # type: ignore[assignment]
    nonces: NonceDB = None  # type: ignore[assignment]
    worker: Worker = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: Any) -> None:
        # Отключаем стандартный лог http.server
        return

    def _json_response(self, code: int, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response_only(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _health(self) -> None:
        self._json_response(200, {"status": "ok"})

    def _ready(self) -> None:
        # Пробный запрос к БД nonce
        try:
            self.nonces._init_db()
            self._json_response(200, {"status": "ready"})
        except Exception as e:
            self._json_response(503, {"status": "not_ready", "error": type(e).__name__})

    # ------------------------------ GET -------------------------------------

    def do_GET(self) -> None:
        ip = client_ip_from_handler(self)
        path = self.path.split("?")[0]
        request_id = uuid.uuid4().hex
        LOG.info("GET", extra={"remote_ip": ip, "request_id": request_id, "path": path, "event": "request_in"})
        if path == "/healthz":
            self._health()
            return
        if path == "/readyz":
            self._ready()
            return
        self._json_response(404, {"error": "not_found"})

    # ------------------------------ POST ------------------------------------

    def do_POST(self) -> None:
        cfg = self.cfg
        ip = client_ip_from_handler(self)
        path = self.path.split("?")[0]
        request_id = uuid.uuid4().hex

        LOG.info("POST", extra={"remote_ip": ip, "request_id": request_id, "path": path, "event": "request_in"})

        # IP allowlist
        if not ip_allowed(ip, cfg.allowed_ips):
            self.audit.write({"event": "deny_ip", "remote_ip": ip, "path": path, "request_id": request_id})
            self._json_response(403, {"error": "ip_not_allowed", "request_id": request_id})
            return

        # TLS требование (для доверенных прокси можно смотреть X-Forwarded-Proto)
        if cfg.require_tls:
            xfproto = (self.headers.get("X-Forwarded-Proto") or "").lower()
            if xfproto != "https":
                self.audit.write({"event": "deny_tls", "remote_ip": ip, "path": path, "request_id": request_id})
                self._json_response(400, {"error": "tls_required", "request_id": request_id})
                return

        if path != "/v1/edr/webhook":
            self._json_response(404, {"error": "not_found", "request_id": request_id})
            return

        # Rate limit
        if not self.limiter.allow(ip):
            self.audit.write({"event": "rate_limited", "remote_ip": ip, "request_id": request_id})
            self._json_response(429, {"error": "rate_limited", "request_id": request_id})
            return

        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._json_response(415, {"error": "unsupported_media_type", "request_id": request_id})
            return

        status, raw_body = read_body(self, cfg.max_body_bytes)
        if status != 0:
            self._json_response(status, {"error": "invalid_body", "request_id": request_id})
            return

        # Заголовки безопасности
        ts_str = (self.headers.get("X-EDR-Timestamp") or "").strip()
        nonce = (self.headers.get("X-EDR-Nonce") or "").strip()
        sig = (self.headers.get("X-EDR-Signature") or "").strip()

        ts_epoch = parse_int(ts_str)
        now = int(time.time())

        if not ts_epoch:
            self._json_response(400, {"error": "bad_timestamp", "request_id": request_id})
            return
        if abs(now - ts_epoch) > cfg.replay_window_seconds:
            self._json_response(401, {"error": "timestamp_out_of_window", "request_id": request_id})
            return
        # nonce должен быть UUIDv4 по формату
        try:
            _ = uuid.UUID(nonce)
        except Exception:
            self._json_response(400, {"error": "bad_nonce", "request_id": request_id})
            return

        # Проверка подписи
        if not verify_signature(cfg.secret, ts_str, nonce, raw_body, sig):
            self.audit.write({
                "event": "bad_signature",
                "remote_ip": ip,
                "request_id": request_id,
                "body_sha256": sha256_hex(raw_body)
            })
            self._json_response(401, {"error": "bad_signature", "request_id": request_id})
            return

        # Защита от повторов
        if self.nonces.is_replayed_and_store(nonce, ts_epoch, cfg.replay_window_seconds):
            self.audit.write({"event": "replay_detected", "remote_ip": ip, "request_id": request_id, "nonce": nonce})
            self._json_response(409, {"error": "replay", "request_id": request_id})
            return

        # Парсим JSON
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._json_response(400, {"error": "bad_json", "request_id": request_id})
            return

        # Минимальная валидация полезной нагрузки
        event_id = str(body.get("event_id") or "")
        event_type = str(body.get("event_type") or "")
        if not event_id or not event_type:
            self._json_response(422, {"error": "missing_fields", "request_id": request_id})
            return

        # Аудит и постановка в очередь
        meta = {
            "request_id": request_id,
            "remote_ip": ip,
            "event_id": event_id,
            "event_type": event_type,
            "ts": ts_epoch,
            "nonce": nonce,
            "body_sha256": sha256_hex(raw_body),
        }
        self.audit.write({"event": "accepted", **meta})

        try:
            self.worker.submit({"meta": meta, "body": body})
        except queue.Full:
            self.audit.write({"event": "queue_full", "request_id": request_id})
            self._json_response(503, {"error": "queue_full", "request_id": request_id})
            return

        # Принято к асинхронной обработке
        self._json_response(202, {"status": "accepted", "request_id": request_id})

    # ----------------------------- HEAD/others --------------------------------

    def do_HEAD(self) -> None:
        self.send_response_only(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self) -> None:
        self._json_response(405, {"error": "method_not_allowed"})

    def do_DELETE(self) -> None:
        self._json_response(405, {"error": "method_not_allowed"})


# --------------------------------- Сервер ------------------------------------

class EdrWebhookServer(ThreadingHTTPServer):
    def __init__(self, server_address: Tuple[str, int], RequestHandlerClass, cfg: WebhookConfig):
        super().__init__(server_address, RequestHandlerClass)
        self.cfg = cfg


def load_env_file(path: Path) -> None:
    """Примитивный парсер .env (KEY=VALUE), строки с # игнорируются."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)


def run_server() -> None:
    # Загрузим .env из текущего каталога при наличии
    load_env_file(Path(".env"))

    cfg = WebhookConfig.from_env()
    audit = NdjsonAudit(cfg.audit_dir)
    limiter = LeakyBucket(cfg.rate_limit_rps, cfg.rate_limit_burst)
    nonces = NonceDB(cfg.nonce_db_path)
    worker = Worker(audit)
    worker.start()

    EdrWebhookHandler.cfg = cfg
    EdrWebhookHandler.audit = audit
    EdrWebhookHandler.limiter = limiter
    EdrWebhookHandler.nonces = nonces
    EdrWebhookHandler.worker = worker

    httpd = EdrWebhookServer((cfg.host, cfg.port), EdrWebhookHandler, cfg)

    def _graceful_shutdown(signum, frame):
        LOG.info("shutdown_signal", extra={"event": "shutdown_signal"})
        worker.stop()
        httpd.shutdown()

    signal.signal(signal.SIGINT, _graceful_shutdown)
    signal.signal(signal.SIGTERM, _graceful_shutdown)

    LOG.info(
        "listening",
        extra={
            "event": "listening",
            "extra": {
                "host": cfg.host,
                "port": cfg.port,
                "audit_dir": str(cfg.audit_dir),
                "nonce_db": str(cfg.nonce_db_path),
                "allowlist": [str(n) for n in cfg.allowed_ips],
            },
        },
    )
    try:
        httpd.serve_forever()
    finally:
        worker.stop()


if __name__ == "__main__":
    run_server()
