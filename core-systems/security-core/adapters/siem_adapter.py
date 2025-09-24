# -*- coding: utf-8 -*-
"""
security-core.adapters.siem_adapter — унифицированные адаптеры SIEM.

Возможности:
- Единый интерфейс отправки событий: send, send_many, flush, close.
- Нормализация события (ts/severity/action/actor/resource/labels/data) и редактирование PII.
- Батчирование по количеству и времени, потокобезопасная очередь.
- Экспоненциальный ретрай с джиттером и circuit breaker.
- Gzip-сжатие HTTP-пакетов, опциональная HMAC-подпись пользовательским секретом.
- TLS-настройки (verify/клиентские сертификаты).
- Метрики-хуки и диагностическое логирование (callbacks).
- Поддерживаемые цели:
  * Splunk HEC (services/collector, newline JSON)
  * Elasticsearch Bulk API
  * Azure Log Analytics Data Collector (для Microsoft Sentinel)
  * Syslog RFC 5424 (UDP/TCP/TLS)
  * Универсальный HTTP Webhook

Зависимости: только стандартная библиотека Python.
"""

from __future__ import annotations

import base64
import datetime as _dt
import gzip
import hmac
import io
import json
import os
import queue
import random
import socket
import ssl
import threading
import time
import typing as t
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field

# =============================================================================
# Утилиты нормализации/редакции
# =============================================================================

_PII_PATTERNS = [
    # базовые маркеры
    ("password", None),
    ("authorization", None),
    ("token", None),
    ("secret", None),
    ("set-cookie", None),
]

def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)

def _rfc3339(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")

def _epoch(dt: _dt.datetime) -> float:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.timestamp()

def _flatten(d: t.Mapping[str, t.Any], parent: str = "", sep: str = ".") -> t.Dict[str, t.Any]:
    out: t.Dict[str, t.Any] = {}
    for k, v in d.items():
        key = f"{parent}{sep}{k}" if parent else str(k)
        if isinstance(v, dict):
            out.update(_flatten(v, key, sep))
        else:
            out[key] = v
    return out

def _redact(obj: t.Any) -> t.Any:
    if obj is None:
        return None
    if isinstance(obj, str):
        if len(obj) <= 6:
            return "***"
        return obj[:3] + "***" + obj[-2:]
    if isinstance(obj, (list, tuple)):
        return type(obj)(_redact(x) for x in obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(lk == p or lk.endswith("_" + p) for p, _ in _PII_PATTERNS):
                out[k] = _redact(v)
            else:
                out[k] = _redact(v) if isinstance(v, (dict, list, tuple, str)) else v
        return out
    return "***"

def normalize_event(ev: t.Mapping[str, t.Any]) -> t.Dict[str, t.Any]:
    """
    Приводит событие к канонической форме.
    Поля: ts (RFC3339), ts_epoch, severity, action, actor_id, actor_type, resource, resource_id, tenant_id,
          labels (dict[str,str]), data (dict), trace_id/span_id, ip, user_agent.
    """
    out: t.Dict[str, t.Any] = dict(ev or {})
    # ts
    ts = out.get("ts")
    if isinstance(ts, str):
        try:
            dt = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            dt = _utcnow()
    elif isinstance(ts, (int, float)):
        dt = _dt.datetime.fromtimestamp(float(ts), tz=_dt.timezone.utc)
    elif isinstance(ts, _dt.datetime):
        dt = ts
    else:
        dt = _utcnow()
    out["ts"] = _rfc3339(dt)
    out["ts_epoch"] = _epoch(dt)
    # defaults
    out.setdefault("severity", "INFO")
    out.setdefault("labels", {})
    out.setdefault("data", {})
    # strings
    for k in ("action", "actor_id", "actor_type", "resource", "resource_id", "tenant_id", "trace_id", "span_id", "ip", "user_agent"):
        if k in out and out[k] is not None:
            out[k] = str(out[k])
    # labels as str:str
    labels = {}
    for k, v in (out.get("labels") or {}).items():
        labels[str(k)] = str(v)
    out["labels"] = labels
    # redact copy for systems, поддерживаем две формы: raw и redacted
    out["data_redacted"] = _redact(out.get("data") or {})
    return out

# =============================================================================
# Ретраи, backoff, circuit breaker
# =============================================================================

def _exp_backoff(base: float, factor: float, attempt: int, jitter: float, cap: float) -> float:
    d = base * (factor ** max(0, attempt - 1))
    d = d + random.uniform(0, jitter)
    return min(d, cap)

@dataclass
class CircuitBreaker:
    failures: int = 0
    threshold: int = 5
    reset_timeout: float = 30.0
    _state: str = field(default="closed")  # closed|open|half
    _opened_at: float = field(default=0.0)

    def on_success(self) -> None:
        self.failures = 0
        self._state = "closed"

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold and self._state != "open":
            self._state = "open"
            self._opened_at = time.time()

    def allow(self) -> bool:
        if self._state == "closed":
            return True
        if self._state == "open":
            if time.time() - self._opened_at >= self.reset_timeout:
                self._state = "half"
                return True
            return False
        # half-open: разрешаем единичные пробы
        return True

# =============================================================================
# Базовый адаптер
# =============================================================================

MetricsHook = t.Callable[[str, t.Mapping[str, t.Any]], None]

@dataclass
class AdapterConfig:
    batch_max: int = 500
    batch_max_bytes: int = 2 * 1024 * 1024
    flush_interval_sec: float = 2.0
    timeout_sec: float = 5.0
    retries: int = 5
    backoff_base: float = 0.3
    backoff_factor: float = 2.0
    backoff_jitter: float = 0.2
    backoff_cap: float = 10.0
    gzip_http: bool = True
    enable_hmac: bool = False
    hmac_secret: t.Optional[bytes] = None
    hmac_header: str = "x-siem-signature"
    tls_verify: bool = True
    tls_client_cert: t.Optional[str] = None
    tls_client_key: t.Optional[str] = None

class SIEMAdapter:
    """
    Базовый класс: реализует очередь, батчинг, ретраи и circuit breaker.
    Дочерние классы должны реализовать: _send_batch(self, batch: t.List[dict]) -> None.
    """
    def __init__(self, cfg: AdapterConfig, *, metrics_hook: t.Optional[MetricsHook] = None, name: str = "adapter"):
        self.cfg = cfg
        self._q: "queue.Queue[dict]" = queue.Queue()
        self._stop = threading.Event()
        self._flush_now = threading.Event()
        self._worker = threading.Thread(target=self._run, name=f"{name}-worker", daemon=True)
        self._metrics = metrics_hook
        self._cb = CircuitBreaker()

    # ---- Публичное API ----

    def start(self) -> None:
        self._worker.start()

    def close(self) -> None:
        self._stop.set()
        self._flush_now.set()
        self._worker.join(timeout=5)
        self.flush()

    def send(self, event: t.Mapping[str, t.Any]) -> None:
        self._q.put_nowait(normalize_event(event))

    def send_many(self, events: t.Iterable[t.Mapping[str, t.Any]]) -> None:
        for ev in events:
            self.send(ev)

    def flush(self) -> None:
        # вытягиваем все и отправляем синхронно
        batch: t.List[dict] = []
        size = 0
        while not self._q.empty():
            ev = self._q.get_nowait()
            x = json.dumps(ev, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if batch and (len(batch) >= self.cfg.batch_max or (size + len(x)) > self.cfg.batch_max_bytes):
                self._send_with_retry(batch)
                batch, size = [], 0
            batch.append(ev)
            size += len(x)
        if batch:
            self._send_with_retry(batch)

    # ---- Фоновая отправка ----

    def _run(self) -> None:
        buf: t.List[dict] = []
        size = 0
        last = time.time()
        while not self._stop.is_set():
            timeout = max(0.0, self.cfg.flush_interval_sec - (time.time() - last))
            try:
                ev = self._q.get(timeout=timeout)
                ev_bytes = json.dumps(ev, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                if buf and (len(buf) >= self.cfg.batch_max or (size + len(ev_bytes)) > self.cfg.batch_max_bytes):
                    self._send_with_retry(buf)
                    buf, size, last = [], 0, time.time()
                buf.append(ev)
                size += len(ev_bytes)
            except queue.Empty:
                pass
            if buf and (time.time() - last >= self.cfg.flush_interval_sec or self._flush_now.is_set()):
                self._send_with_retry(buf)
                buf, size, last = [], 0, time.time()
                self._flush_now.clear()

    # ---- Отправка с ретраями ----

    def _send_with_retry(self, batch: t.List[dict]) -> None:
        if not batch:
            return
        if not self._cb.allow():
            self._metric("drop.circuit_open", {"count": len(batch)})
            return
        attempt = 0
        while True:
            try:
                self._send_batch(batch)
                self._cb.on_success()
                self._metric("send.ok", {"count": len(batch), "attempt": attempt + 1})
                return
            except Exception as e:
                attempt += 1
                self._metric("send.err", {"attempt": attempt, "error": repr(e)})
                self._cb.on_failure()
                if attempt >= self.cfg.retries:
                    self._metric("drop.max_retries", {"count": len(batch)})
                    return
                time.sleep(_exp_backoff(self.cfg.backoff_base, self.cfg.backoff_factor, attempt, self.cfg.backoff_jitter, self.cfg.backoff_cap))

    def _metric(self, name: str, data: t.Mapping[str, t.Any]) -> None:
        if self._metrics:
            try:
                self._metrics(name, data)
            except Exception:
                pass

    # ---- Реализация в потомках ----
    def _send_batch(self, batch: t.List[dict]) -> None:
        raise NotImplementedError

# =============================================================================
# HTTP клиент (urllib) с gzip и HMAC
# =============================================================================

def _build_ssl_context(cfg: AdapterConfig) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not cfg.tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cfg.tls_client_cert:
        ctx.load_cert_chain(certfile=cfg.tls_client_cert, keyfile=cfg.tls_client_key)
    return ctx

def _http_post(url: str, body: bytes, headers: t.Dict[str, str], cfg: AdapterConfig) -> t.Tuple[int, bytes]:
    data = body
    req_headers = dict(headers or {})
    if cfg.gzip_http:
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(data)
        data = buf.getvalue()
        req_headers["Content-Encoding"] = "gzip"
    req = urllib.request.Request(url, data=data, method="POST")
    for k, v in req_headers.items():
        req.add_header(k, v)
    ctx = _build_ssl_context(cfg) if url.lower().startswith("https") else None
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)) if ctx else urllib.request.build_opener()
    with opener.open(req, timeout=cfg.timeout_sec) as resp:
        return resp.getcode(), resp.read()

def _maybe_hmac(headers: t.Dict[str, str], payload: bytes, cfg: AdapterConfig) -> None:
    if cfg.enable_hmac and cfg.hmac_secret:
        sig = hmac.new(cfg.hmac_secret, payload, digestmod="sha256").hexdigest()
        headers[cfg.hmac_header] = f"sha256={sig}"

# =============================================================================
# Splunk HEC
# =============================================================================

@dataclass
class SplunkHECConfig(AdapterConfig):
    url: str = ""  # https://splunk.example.com:8088/services/collector
    token: str = ""
    source: t.Optional[str] = None
    sourcetype: t.Optional[str] = "security-core:event"
    index: t.Optional[str] = None
    host: t.Optional[str] = os.uname().nodename if hasattr(os, "uname") else "host"

class SplunkHECAdapter(SIEMAdapter):
    def __init__(self, cfg: SplunkHECConfig, *, metrics_hook: t.Optional[MetricsHook] = None):
        super().__init__(cfg, metrics_hook=metrics_hook, name="splunk")
        self._cfg = cfg

    def _send_batch(self, batch: t.List[dict]) -> None:
        events = []
        for ev in batch:
            item = {
                "time": ev.get("ts_epoch", _epoch(_utcnow())),
                "host": self._cfg.host,
                "source": self._cfg.source,
                "sourcetype": self._cfg.sourcetype,
                "index": self._cfg.index,
                "event": ev,
                "fields": _flatten(ev.get("labels") or {}),
            }
            events.append(item)
        # Splunk допускает построчный JSON
        body_lines = [(json.dumps(e, separators=(",", ":"), ensure_ascii=False)) for e in events]
        body = ("\n".join(body_lines)).encode("utf-8")
        headers = {
            "Authorization": f"Splunk {self._cfg.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        _maybe_hmac(headers, body, self.cfg)
        code, resp = _http_post(self._cfg.url, body, headers, self.cfg)
        if code // 100 != 2:
            raise RuntimeError(f"Splunk HEC HTTP {code}: {resp[:256]!r}")
        # Специфический успех можно не парсить (200 с {"text":"Success"}).

# =============================================================================
# Elasticsearch Bulk API
# =============================================================================

@dataclass
class ElasticsearchConfig(AdapterConfig):
    url: str = ""         # https://es.example.com:9200/_bulk
    index: str = "security-core-events"
    pipeline: t.Optional[str] = None
    basic_user: t.Optional[str] = None
    basic_pass: t.Optional[str] = None
    api_key: t.Optional[str] = None  # base64(id:key) или уже готовый

class ElasticsearchBulkAdapter(SIEMAdapter):
    def __init__(self, cfg: ElasticsearchConfig, *, metrics_hook: t.Optional[MetricsHook] = None):
        super().__init__(cfg, metrics_hook=metrics_hook, name="elastic")
        self._cfg = cfg

    def _send_batch(self, batch: t.List[dict]) -> None:
        lines: t.List[str] = []
        for ev in batch:
            meta: t.Dict[str, t.Any] = {"index": {"_index": self._cfg.index}}
            if self._cfg.pipeline:
                meta["index"]["pipeline"] = self._cfg.pipeline
            lines.append(json.dumps(meta, separators=(",", ":"), ensure_ascii=False))
            doc = dict(ev)
            lines.append(json.dumps(doc, separators=(",", ":"), ensure_ascii=False))
        body = ("\n".join(lines) + "\n").encode("utf-8")
        headers = {"Content-Type": "application/x-ndjson", "Accept": "application/json"}
        if self._cfg.api_key:
            headers["Authorization"] = f"ApiKey {self._cfg.api_key}"
        elif self._cfg.basic_user and self._cfg.basic_pass:
            token = base64.b64encode(f"{self._cfg.basic_user}:{self._cfg.basic_pass}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        _maybe_hmac(headers, body, self.cfg)
        code, resp = _http_post(self._cfg.url, body, headers, self.cfg)
        if code // 100 != 2:
            raise RuntimeError(f"Elasticsearch HTTP {code}: {resp[:256]!r}")
        # Дополнительно можно проверить 'errors' в ответе, но для простоты оставим как есть.

# =============================================================================
# Azure Log Analytics (Sentinel)
# =============================================================================

@dataclass
class AzureLogConfig(AdapterConfig):
    workspace_id: str = ""
    shared_key_b64: str = ""  # base64(shared key)
    log_type: str = "SecurityCoreEvents"
    endpoint: str = ""        # если пусто — вычислим
    time_generated_field: t.Optional[str] = "ts"  # имя поля времени
    resource: str = "/api/logs"  # константа строки для подписи

    def resolve_endpoint(self) -> str:
        if self.endpoint:
            return self.endpoint
        # default публичная точка
        return f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

def _azure_build_signature(shared_key_b64: str, date_str: str, content_length: int, content_type: str, resource: str) -> str:
    key = base64.b64decode(shared_key_b64)
    x = f"POST\n{content_length}\n{content_type}\nx-ms-date:{date_str}\n{resource}"
    mac = hmac.new(key, x.encode("utf-8"), digestmod="sha256").digest()
    return base64.b64encode(mac).decode("ascii")

class AzureLogAnalyticsAdapter(SIEMAdapter):
    def __init__(self, cfg: AzureLogConfig, *, metrics_hook: t.Optional[MetricsHook] = None):
        super().__init__(cfg, metrics_hook=metrics_hook, name="azurelog")
        self._cfg = cfg

    def _send_batch(self, batch: t.List[dict]) -> None:
        body_json = json.dumps(batch, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        # Azure сигнатура должна строиться по несжатому контенту
        date_str = _utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_type = "application/json"
        sig = _azure_build_signature(self._cfg.shared_key_b64, date_str, len(body_json), content_type, self._cfg.resource)
        headers = {
            "Content-Type": content_type,
            "Log-Type": self._cfg.log_type,
            "x-ms-date": date_str,
            "Authorization": f"SharedKey {self._cfg.workspace_id}:{sig}",
        }
        if self._cfg.time_generated_field:
            headers["time-generated-field"] = self._cfg.time_generated_field
        # Публикуем несжатое тело (Azure Data Collector ожидает длину по несжатому контенту)
        code, resp = _http_post(self._cfg.resolve_endpoint(), body_json, headers, dataclass_replace(self.cfg, gzip_http=False))
        if code // 100 != 2:
            raise RuntimeError(f"Azure Log Analytics HTTP {code}: {resp[:256]!r}")

# =============================================================================
# Syslog RFC 5424 (UDP/TCP/TLS)
# =============================================================================

@dataclass
class SyslogConfig(AdapterConfig):
    host: str = "127.0.0.1"
    port: int = 514
    protocol: str = "udp"  # udp|tcp|tls
    facility: int = 1      # user-level messages
    app_name: str = "security-core"
    hostname: str = socket.gethostname()
    procid: str = "-"
    msgid: str = "AUDIT"
    sd_id: str = "sc@1"

def _syslog_pri(facility: int, severity: str) -> int:
    sev_map = {"DEBUG": 7, "INFO": 6, "NOTICE": 5, "WARNING": 4, "ERROR": 3, "CRITICAL": 2, "ALERT": 1, "EMERGENCY": 0}
    sev = sev_map.get(str(severity).upper(), 6)
    return facility * 8 + sev

def _syslog_sd(sd_id: str, kv: t.Mapping[str, t.Any]) -> str:
    def esc(v: str) -> str:
        return v.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
    parts = [f'{k}="{esc(str(v))}"' for k, v in kv.items()]
    return f"[{sd_id} " + " ".join(parts) + "]"

class SyslogAdapter(SIEMAdapter):
    def __init__(self, cfg: SyslogConfig, *, metrics_hook: t.Optional[MetricsHook] = None):
        # для syslog нет gzip/http, но базовые поля нужны для очереди
        super().__init__(cfg, metrics_hook=metrics_hook, name="syslog")
        self._cfg = cfg
        self._sock = None  # type: ignore
        self._sslctx: t.Optional[ssl.SSLContext] = None
        if self._cfg.protocol == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self._cfg.protocol in ("tcp", "tls"):
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self._cfg.protocol == "tls":
                self._sslctx = ssl.create_default_context()
                if not self.cfg.tls_verify:
                    self._sslctx.check_hostname = False
                    self._sslctx.verify_mode = ssl.CERT_NONE
            self._sock.settimeout(self.cfg.timeout_sec)
            self._sock.connect((self._cfg.host, self._cfg.port))
            if self._sslctx:
                self._sock = self._sslctx.wrap_socket(self._sock, server_hostname=self._cfg.host)
        else:
            raise ValueError("protocol must be udp|tcp|tls")

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        finally:
            super().close()

    def _send_batch(self, batch: t.List[dict]) -> None:
        # Формат RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG
        for ev in batch:
            pri = _syslog_pri(self._cfg.facility, ev.get("severity", "INFO"))
            ts = ev.get("ts") or _rfc3339(_utcnow())
            header = f"<{pri}>1 {self._cfg.hostname} {self._cfg.app_name} {self._cfg.procid} {self._cfg.msgid}"
            sd_fields = {
                "tenant": ev.get("tenant_id") or "-",
                "actor": ev.get("actor_id") or "-",
                "action": ev.get("action") or "-",
                "resource": ev.get("resource") or "-",
                "trace": ev.get("trace_id") or "-",
            }
            sd = _syslog_sd(self._cfg.sd_id, sd_fields)
            msg = json.dumps(ev, separators=(",", ":"), ensure_ascii=False)
            line = f"{header} {ts} {sd} {msg}".encode("utf-8")
            if self._cfg.protocol == "udp":
                self._sock.sendto(line, (self._cfg.host, self._cfg.port))
            else:
                # TCP/TLS — framer по переносу строки
                self._sock.sendall(line + b"\n")

# =============================================================================
# Универсальный HTTP Webhook
# =============================================================================

@dataclass
class WebhookConfig(AdapterConfig):
    url: str = ""
    headers: t.Dict[str, str] = field(default_factory=lambda: {"Content-Type": "application/json", "Accept": "application/json"})

class WebhookAdapter(SIEMAdapter):
    def __init__(self, cfg: WebhookConfig, *, metrics_hook: t.Optional[MetricsHook] = None):
        super().__init__(cfg, metrics_hook=metrics_hook, name="webhook")
        self._cfg = cfg

    def _send_batch(self, batch: t.List[dict]) -> None:
        body = json.dumps(batch, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = dict(self._cfg.headers or {})
        _maybe_hmac(headers, body, self.cfg)
        code, resp = _http_post(self._cfg.url, body, headers, self.cfg)
        if code // 100 != 2:
            raise RuntimeError(f"Webhook HTTP {code}: {resp[:256]!r}")

# =============================================================================
# Вспомогательные фабрики и утилиты
# =============================================================================

def dataclass_replace(cfg: AdapterConfig, **overrides: t.Any) -> AdapterConfig:
    d = cfg.__dict__.copy()
    d.update(overrides)
    return AdapterConfig(**d)

# Пример метрик-хука: интеграция с вашим логгером/экспортёром
def default_metrics_hook(name: str, data: t.Mapping[str, t.Any]) -> None:
    # оставлено пустым для интеграции
    pass

# =============================================================================
# Пример использования (документация в коде)
# =============================================================================
#
# from adapters.siem_adapter import (
#     AdapterConfig, SplunkHECConfig, SplunkHECAdapter,
#     ElasticsearchConfig, ElasticsearchBulkAdapter,
#     AzureLogConfig, AzureLogAnalyticsAdapter,
#     SyslogConfig, SyslogAdapter,
#     WebhookConfig, WebhookAdapter,
# )
#
# cfg = SplunkHECConfig(
#     url="https://splunk.example.com:8088/services/collector",
#     token="...hec-token...",
#     batch_max=500,
# )
# adapter = SplunkHECAdapter(cfg, metrics_hook=default_metrics_hook)
# adapter.start()
# adapter.send({"ts": _rfc3339(_utcnow()), "severity": "INFO", "action": "authn.login", "actor_id": "u1", "labels": {"env":"prod"}, "data": {"ip":"1.2.3.4"}})
# adapter.flush()
# adapter.close()
#
# Для Elasticsearch:
# es = ElasticsearchBulkAdapter(ElasticsearchConfig(url="https://es:9200/_bulk", index="sc-events", api_key="..."))
# es.start(); es.send_many([...]); es.close()
#
# Для Azure Sentinel:
# az = AzureLogAnalyticsAdapter(AzureLogConfig(workspace_id="xxx", shared_key_b64="base64key=="))
# az.send({...}); az.flush()
#
# Для Syslog:
# sl = SyslogAdapter(SyslogConfig(host="syslog.example", port=6514, protocol="tls"))
# sl.send({...}); sl.flush()
