# cybersecurity-core/cybersecurity/deception/honeypot.py
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# -----------------------------------------------------------------------------
# ЛОГИРОВАНИЕ
# -----------------------------------------------------------------------------
LOG = logging.getLogger("cybersecurity.deception.honeypot")
if not LOG.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

# -----------------------------------------------------------------------------
# УТИЛИТЫ / КОНФИГ
# -----------------------------------------------------------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def host_id() -> str:
    try:
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.exists(p):
                return Path(p).read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return socket.gethostname()

ENV = {
    # Общие
    "ENVIRONMENT": os.getenv("ENVIRONMENT", "prod"),
    "TENANT_ID": os.getenv("TENANT_ID"),  # UUID|None
    "HOSTNAME": socket.gethostname(),
    "SENSOR_ID": os.getenv("SENSOR_ID", host_id()),
    # Сетевые порты
    "HP_HTTP_PORT": int(os.getenv("HP_HTTP_PORT", "8080")),
    "HP_TELNET_PORT": int(os.getenv("HP_TELNET_PORT", "2323")),
    "HP_FTP_PORT": int(os.getenv("HP_FTP_PORT", "2121")),
    "HP_REDIS_PORT": int(os.getenv("HP_REDIS_PORT", "6380")),
    "HP_SSH_PORT": int(os.getenv("HP_SSH_PORT", "2222")),
    # Включение протоколов
    "HP_ENABLE_HTTP": os.getenv("HP_ENABLE_HTTP", "1") in {"1", "true", "yes"},
    "HP_ENABLE_TELNET": os.getenv("HP_ENABLE_TELNET", "1") in {"1", "true", "yes"},
    "HP_ENABLE_FTP": os.getenv("HP_ENABLE_FTP", "1") in {"1", "true", "yes"},
    "HP_ENABLE_REDIS": os.getenv("HP_ENABLE_REDIS", "1") in {"1", "true", "yes"},
    "HP_ENABLE_SSH_BANNER": os.getenv("HP_ENABLE_SSH_BANNER", "1") in {"1", "true", "yes"},
    # Ограничения и тарпитинг
    "HP_MAX_MESSAGE_BYTES": int(os.getenv("HP_MAX_MESSAGE_BYTES", "131072")),  # 128 KiB
    "HP_CONN_PER_IP": int(os.getenv("HP_CONN_PER_IP", "20")),
    "HP_RATE_LIMIT_RPS": int(os.getenv("HP_RATE_LIMIT_RPS", "20")),
    "HP_RATE_LIMIT_BURST": int(os.getenv("HP_RATE_LIMIT_BURST", "40")),
    "HP_TARPIT_DELAY_MS": int(os.getenv("HP_TARPIT_DELAY_MS", "150")),
    # Хранилище событий
    "HP_JSONL_PATH": os.getenv("HP_JSONL_PATH", "./logs/honeypot.jsonl"),
}

# -----------------------------------------------------------------------------
# СИНКИ ДЛЯ ВЫВОДА СОБЫТИЙ
# -----------------------------------------------------------------------------
class EventSink:
    async def emit(self, event: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError

class LoggingSink(EventSink):
    def __init__(self, level: int = logging.INFO) -> None:
        self.level = level
    async def emit(self, event: Dict[str, Any]) -> None:
        LOG.log(self.level, json.dumps(event, ensure_ascii=False))

class JsonlFileSink(EventSink):
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
    async def emit(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False) + "\n"
        async with self._lock:
            await asyncio.to_thread(self._path.open("a", encoding="utf-8").write, line)

class CallbackSink(EventSink):
    def __init__(self, cb: Callable[[Dict[str, Any]], asyncio.Future | None | Any]) -> None:
        self._cb = cb
    async def emit(self, event: Dict[str, Any]) -> None:
        res = self._cb(event)
        if asyncio.iscoroutine(res):
            await res  # type: ignore

# -----------------------------------------------------------------------------
# РЕЙТ-ЛИМИТЫ И КВОТЫ
# -----------------------------------------------------------------------------
class TokenBucket:
    def __init__(self, rps: int, burst: int) -> None:
        self.rate = float(rps)
        self.cap = float(burst)
        self.tokens = float(burst)
        self.ts = time.monotonic()
    def allow(self) -> bool:
        now = time.monotonic()
        dt = now - self.ts
        self.ts = now
        self.tokens = min(self.cap, self.tokens + dt * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

class Quotas:
    def __init__(self, per_ip: int) -> None:
        self.per_ip = per_ip
        self._c: Dict[str, int] = {}
        self._lock = asyncio.Lock()
    async def acquire(self, ip: str) -> bool:
        async with self._lock:
            n = self._c.get(ip, 0)
            if n >= self.per_ip:
                return False
            self._c[ip] = n + 1
            return True
    async def release(self, ip: str) -> None:
        async with self._lock:
            n = self._c.get(ip, 0)
            if n > 1:
                self._c[ip] = n - 1
            else:
                self._c.pop(ip, None)

# -----------------------------------------------------------------------------
# ОБЩИЙ БИЛДЕР СОБЫТИЙ (совместим с вашей IDS/EDR схемой)
# -----------------------------------------------------------------------------
def build_event(
    *,
    proto: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    severity: str,
    message: str,
    category: str,
    labels: List[str],
    http: Optional[Dict[str, Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "event": {
            "id": str(uuid.uuid4()),
            "occurred_at": iso(utcnow()),
            "timezone": "UTC",
        },
        "source": {
            "environment": ENV["ENVIRONMENT"],
            "tenant": ENV["TENANT_ID"] or "",
            "sensor": {
                "id": ENV["SENSOR_ID"],
                "hostname": ENV["HOSTNAME"],
                "ipv4": [],
                "mac": [],
                "location": "",
            },
            "engine": {
                "vendor": "Aethernova",
                "product": "Honeypot",
                "version": "1.0.0",
                "profile": "low-interaction",
                "rule_source": "builtin",
            },
        },
        "alert": {
            "signature": {
                "id": f"honeypot:{proto}",
                "name": f"{proto.upper()} honeypot interaction",
                "rev": 1,
                "gid": 2001,
                "sid": 600000 + (hash(proto) % 100000),
                "references": [],
            },
            "category": category,
            "action": "alert",
            "message": message,
            "labels": list(set(["honeypot", proto] + labels))[:10],
        },
        "severity": severity,
        "confidence": 75,
        "classification": {},
        "network": {
            "direction": "inbound",
            "protocol": proto if proto != "ssh_banner" else "tcp",
            "src": {"ip": src_ip, "port": src_port},
            "dst": {"ip": dst_ip, "port": dst_port},
            "http": http or None,
        },
        "enrichment": {
            "observables": [],
            "threat_intel": [],
        },
        "triage": {"status": "new"},
        "payload": payload or None,  # необязательный расширенный блок
        "labels": ["deception"],
    }

# -----------------------------------------------------------------------------
# БАЗОВЫЙ ОБРАБОТЧИК ПРОТОКОЛА
# -----------------------------------------------------------------------------
@dataclass
class ConnInfo:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

class ProtocolHandler:
    name = "base"
    def __init__(self, sinks: List[EventSink]) -> None:
        self.sinks = sinks
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ci: ConnInfo) -> None:
        raise NotImplementedError
    async def emit(self, event: Dict[str, Any]) -> None:
        for s in self.sinks:
            try:
                await s.emit(event)
            except Exception as e:  # noqa: BLE001
                LOG.warning("sink error: %s", e)

# -----------------------------------------------------------------------------
# HTTP HONEYPOT
# -----------------------------------------------------------------------------
class HTTPPot(ProtocolHandler):
    name = "http"
    BANNERS = {
        "server": os.getenv("HP_HTTP_SERVER_BANNER", "nginx/1.18.0"),
        "realm": os.getenv("HP_HTTP_BASIC_REALM", "Restricted Area"),
    }

    async def _read_request(self, reader: asyncio.StreamReader, max_bytes: int) -> Tuple[str, Dict[str, str], bytes]:
        data = b""
        # читаем заголовки
        while b"\r\n\r\n" not in data and len(data) < max_bytes:
            chunk = await asyncio.wait_for(reader.read(1024), timeout=10.0)
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        start_line, *header_lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        headers: Dict[str, str] = {}
        for h in header_lines:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        # тело (если есть content-length, дочитываем)
        body = rest
        if "content-length" in headers:
            try:
                need = int(headers["content-length"]) - len(rest)
                if 0 < need <= max_bytes:
                    body += await asyncio.wait_for(reader.readexactly(need), timeout=10.0)
            except Exception:
                pass
        return start_line, headers, body[:max_bytes]

    def _parse_http(self, start: str, headers: Dict[str, str], body: bytes) -> Tuple[Dict[str, Any], List[str]]:
        labels: List[str] = []
        # Строка запроса
        m = re.match(r"([A-Z]+)\s+(\S+)\s+HTTP/(\d\.\d)", start)
        method, path, httpver = (m.group(1), m.group(2), m.group(3)) if m else ("GET", "/", "1.1")
        # Basic creds
        creds = None
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                raw = base64.b64decode(auth.split(" ", 1)[1].strip()).decode("utf-8", errors="replace")
                if ":" in raw:
                    u, p = raw.split(":", 1)
                    creds = {"username": u, "password": p}
            except Exception:
                pass
        # Возможные логин-поля
        params = {}
        if body:
            try:
                # грубый парсинг application/x-www-form-urlencoded
                for kv in body.decode("utf-8", errors="replace").split("&"):
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        params[k] = v
            except Exception:
                pass
        for k in ("username", "user", "login", "email"):
            if k in params:
                labels.append("cred_attempt")
                break

        # эвристические метки по пути
        lower = path.lower()
        if "wp-login.php" in lower:
            labels.append("wordpress")
        if "boaform" in lower or "formlogin" in lower:
            labels.append("router")
        if "phpmyadmin" in lower:
            labels.append("phpmyadmin")

        http_block = {
            "method": method,
            "host": headers.get("host"),
            "url": path,
            "path": path.split("?", 1)[0],
            "user_agent": headers.get("user-agent"),
            "request_headers": {k: v for k, v in headers.items() if k in {"user-agent", "accept", "content-type", "authorization", "host"}},
            "status": 200,
        }
        payload = {
            "creds": creds,
            "form": params if params else None,
            "httpver": httpver,
        }
        return {"http": http_block, "payload": payload}, labels

    async def _respond(self, writer: asyncio.StreamWriter, path: str, headers: Dict[str, str]) -> None:
        # часть путей возвращаем 401 c BasicAuth, остальное — 200 с псевдо-страницей
        if path.startswith("/admin") or "wp-login.php" in path or "/login" in path:
            body = "<html><body><h1>401 Unauthorized</h1></body></html>"
            resp = (
                f"HTTP/1.1 401 Unauthorized\r\n"
                f"Server: {self.BANNERS['server']}\r\n"
                f"WWW-Authenticate: Basic realm=\"{self.BANNERS['realm']}\"\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n{body}"
            )
        else:
            body = "<html><body><h1>It works</h1></body></html>"
            resp = (
                f"HTTP/1.1 200 OK\r\n"
                f"Server: {self.BANNERS['server']}\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n{body}"
            )
        writer.write(resp.encode("utf-8"))
        await writer.drain()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ci: ConnInfo) -> None:
        start, headers, body = await self._read_request(reader, ENV["HP_MAX_MESSAGE_BYTES"])
        parsed, labels = self._parse_http(start, headers, body)
        http_block = parsed["http"]
        payload = parsed["payload"]
        event = build_event(
            proto="http",
            src_ip=ci.src_ip, src_port=ci.src_port,
            dst_ip=ci.dst_ip, dst_port=ci.dst_port,
            severity="low",
            message=f"HTTP {http_block['method']} {http_block['path']}",
            category="deception_interaction",
            labels=labels,
            http=http_block,
            payload=payload,
        )
        await self.emit(event)
        await asyncio.sleep(ENV["HP_TARPIT_DELAY_MS"] / 1000.0)
        await self._respond(writer, http_block["path"], headers)

# -----------------------------------------------------------------------------
# TELNET HONEYPOT
# -----------------------------------------------------------------------------
class TelnetPot(ProtocolHandler):
    name = "telnet"
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ci: ConnInfo) -> None:
        def w(s: str) -> None:
            writer.write(s.encode("utf-8", errors="ignore"))
        w("login: ")
        try:
            user = (await asyncio.wait_for(reader.readline(), timeout=20.0)).decode("utf-8", errors="replace").strip()
        except Exception:
            user = ""
        w("Password: ")
        try:
            pwd = (await asyncio.wait_for(reader.readline(), timeout=20.0)).decode("utf-8", errors="replace").strip()
        except Exception:
            pwd = ""
        message = "Telnet login attempt"
        payload = {"username": user, "password": pwd}
        event = build_event(
            proto="telnet",
            src_ip=ci.src_ip, src_port=ci.src_port, dst_ip=ci.dst_ip, dst_port=ci.dst_port,
            severity="medium",
            message=message,
            category="credential_attempt",
            labels=["cred_attempt"],
            payload=payload,
        )
        await self.emit(event)
        await asyncio.sleep(ENV["HP_TARPIT_DELAY_MS"] / 1000.0)
        w("\r\nLogin incorrect\r\n")
        await writer.drain()

# -----------------------------------------------------------------------------
# FTP HONEYPOT
# -----------------------------------------------------------------------------
class FTPPot(ProtocolHandler):
    name = "ftp"
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ci: ConnInfo) -> None:
        def w(line: str) -> None:
            writer.write((line + "\r\n").encode("utf-8"))
        w("220 ProFTPD 1.3.6 Server ready.")
        user = ""
        pwd = ""
        try:
            line = (await asyncio.wait_for(reader.readline(), timeout=20.0)).decode("utf-8", errors="replace").strip()
            m = re.match(r"USER\s+(.+)", line, re.I)
            if m: user = m.group(1)
            w("331 Password required for " + (user or "user") + ".")
            line = (await asyncio.wait_for(reader.readline(), timeout=20.0)).decode("utf-8", errors="replace").strip()
            m = re.match(r"PASS\s+(.+)", line, re.I)
            if m: pwd = m.group(1)
            w("230 Login successful.")
            # Считываем первую команду после логина для контекста
            cmd_line = (await asyncio.wait_for(reader.readline(), timeout=5.0)).decode("utf-8", errors="replace").strip()
        except Exception:
            cmd_line = ""
        event = build_event(
            proto="ftp",
            src_ip=ci.src_ip, src_port=ci.src_port, dst_ip=ci.dst_ip, dst_port=ci.dst_port,
            severity="medium",
            message="FTP credential submission",
            category="credential_attempt",
            labels=["cred_attempt"],
            payload={"username": user, "password": pwd, "cmd": cmd_line or None},
        )
        await self.emit(event)
        await asyncio.sleep(ENV["HP_TARPIT_DELAY_MS"] / 1000.0)
        w("221 Goodbye.")
        await writer.drain()

# -----------------------------------------------------------------------------
# REDIS HONEYPOT (RESP протокол, минимальный)
# -----------------------------------------------------------------------------
class RedisPot(ProtocolHandler):
    name = "redis"
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ci: ConnInfo) -> None:
        # читаем одну RESP-команду
        try:
            peek = await asyncio.wait_for(reader.read(1), timeout=10.0)
            if not peek:
                return
            data = peek + await asyncio.wait_for(reader.read(ENV["HP_MAX_MESSAGE_BYTES"] - 1), timeout=2.0)
        except Exception:
            data = b""
        cmd, args = self._parse_resp(data)
        labels = []
        payload: Dict[str, Any] = {"cmd": cmd, "args": args[:10]}
        if cmd and cmd.lower() == "auth" and args:
            labels.append("cred_attempt")
            payload["password"] = args[0]
        event = build_event(
            proto="redis",
            src_ip=ci.src_ip, src_port=ci.src_port, dst_ip=ci.dst_ip, dst_port=ci.dst_port,
            severity="low",
            message=f"Redis command: {cmd or 'unknown'}",
            category="deception_interaction",
            labels=labels,
            payload=payload,
        )
        await self.emit(event)
        await asyncio.sleep(ENV["HP_TARPIT_DELAY_MS"] / 1000.0)
        writer.write(b"-ERR unknown command\r\n")
        await writer.drain()

    def _parse_resp(self, data: bytes) -> Tuple[Optional[str], List[str]]:
        # Очень простой парсер массива: *N $len val ...
        try:
            if not data or data[0:1] != b"*":
                return None, []
            parts = []
            i = 0
            # пропускаем *N\r\n
            while i < len(data) and data[i:i+1] != b"\n":
                i += 1
            i += 1
            while i < len(data):
                if data[i:i+1] == b"$":
                    i += 1
                    # длина
                    ln = b""
                    while i < len(data) and data[i:i+1] != b"\n":
                        ln += data[i:i+1]
                        i += 1
                    i += 1
                    l = int(ln.decode("ascii").strip() or "0")
                    val = data[i:i+l]
                    parts.append(val.decode("utf-8", errors="replace"))
                    i += l + 2  # \r\n
                else:
                    break
            cmd = parts[0] if parts else None
            return cmd, parts[1:]
        except Exception:
            return None, []

# -----------------------------------------------------------------------------
# SSH BANNER (низкоуровневый баннер + закрытие)
# -----------------------------------------------------------------------------
class SSHBannerPot(ProtocolHandler):
    name = "ssh_banner"
    BANNER = os.getenv("HP_SSH_BANNER", "SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1")
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ci: ConnInfo) -> None:
        writer.write((self.BANNER + "\r\n").encode("ascii"))
        await writer.drain()
        # читаем немного и закрываем (имитация несовместимости ключей)
        try:
            data = await asyncio.wait_for(reader.read(64), timeout=2.0)
        except Exception:
            data = b""
        event = build_event(
            proto="ssh_banner",
            src_ip=ci.src_ip, src_port=ci.src_port, dst_ip=ci.dst_ip, dst_port=ci.dst_port,
            severity="low",
            message="SSH banner served",
            category="deception_interaction",
            labels=[],
            payload={"peek": data.hex() if data else None},
        )
        await self.emit(event)

# -----------------------------------------------------------------------------
# СЕРВЕР ОРКЕСТРАТОР
# -----------------------------------------------------------------------------
class HoneypotServer:
    def __init__(self, sinks: Optional[List[EventSink]] = None) -> None:
        self.sinks = sinks or [LoggingSink(), JsonlFileSink(ENV["HP_JSONL_PATH"])]
        self.servers: List[asyncio.base_events.Server] = []
        self.quotas = Quotas(ENV["HP_CONN_PER_IP"])
        self.rate: Dict[str, TokenBucket] = {}

    async def _wrap_handler(self, handler: ProtocolHandler, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # conn info
        try:
            src_ip, src_port = writer.get_extra_info("peername")[:2]
        except Exception:
            src_ip, src_port = ("0.0.0.0", 0)
        try:
            dst_ip, dst_port = writer.get_extra_info("sockname")[:2]
        except Exception:
            dst_ip, dst_port = ("0.0.0.0", 0)

        ci = ConnInfo(src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port)

        # квоты
        if not await self.quotas.acquire(src_ip):
            LOG.warning("too many connections from %s", src_ip)
            writer.close()
            await writer.wait_closed()
            return

        # rate limit
        bucket = self.rate.get(src_ip)
        if not bucket:
            bucket = self.rate[src_ip] = TokenBucket(ENV["HP_RATE_LIMIT_RPS"], ENV["HP_RATE_LIMIT_BURST"])
        if not bucket.allow():
            await asyncio.sleep(0.5)

        # тарпит небольшая задержка
        await asyncio.sleep(ENV["HP_TARPIT_DELAY_MS"] / 1000.0)

        try:
            await handler.handle(reader, writer, ci)
        except Exception as e:
            LOG.debug("handler error %s: %s", handler.name, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            await self.quotas.release(src_ip)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        # Создаем хендлеры
        handlers: List[Tuple[bool, int, ProtocolHandler]] = []
        if ENV["HP_ENABLE_HTTP"]:
            handlers.append((True, ENV["HP_HTTP_PORT"], HTTPPot(self.sinks)))
        if ENV["HP_ENABLE_TELNET"]:
            handlers.append((True, ENV["HP_TELNET_PORT"], TelnetPot(self.sinks)))
        if ENV["HP_ENABLE_FTP"]:
            handlers.append((True, ENV["HP_FTP_PORT"], FTPPot(self.sinks)))
        if ENV["HP_ENABLE_REDIS"]:
            handlers.append((True, ENV["HP_REDIS_PORT"], RedisPot(self.sinks)))
        if ENV["HP_ENABLE_SSH_BANNER"]:
            handlers.append((True, ENV["HP_SSH_PORT"], SSHBannerPot(self.sinks)))

        for enabled, port, h in handlers:
            if not enabled:
                continue
            srv = await asyncio.start_server(
                lambda r, w, hh=h: self._wrap_handler(hh, r, w),
                host="0.0.0.0",
                port=port,
                limit=ENV["HP_MAX_MESSAGE_BYTES"] + 1024,
                reuse_address=True,
            )
            self.servers.append(srv)
            sockets = ", ".join(str(s.getsockname()) for s in srv.sockets or [])
            LOG.info("Started %s on %s", h.name, sockets)

    async def stop(self) -> None:
        for srv in self.servers:
            srv.close()
        await asyncio.gather(*[srv.wait_closed() for srv in self.servers], return_exceptions=True)
        LOG.info("Honeypot stopped")

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
async def _amain() -> None:  # pragma: no cover
    hp = HoneypotServer()
    await hp.start()
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await hp.stop()

def main() -> None:  # pragma: no cover
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":  # pragma: no cover
    main()
