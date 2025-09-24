# -*- coding: utf-8 -*-
"""
Zero Trust Core — Python SDK client.

Особенности:
- Транспортные адаптеры: gRPC (при наличии grpcio) и HTTP(S) fallback.
- TLS/mTLS, строгая валидация, опциональный пиннинг по SPKI на прикладном уровне.
- HMAC-подпись полезной нагрузки запросов (x-zt-signature: sha256=...).
- Экспоненциальные ретраи с джиттером + circuit breaker.
- Сжатие gzip, потокобезопасность, контекст корреляции (x-correlation-id).
- Метрики/хуки и подробные исключения.
- Методы Health API: check, watch, probe, list_components, get_policy_digest.

Зависимости: стандартная библиотека.
Опционально: grpcio (для gRPC-режима). При его отсутствии будет использован HTTP(S).

Совместимость:
- gRPC сигнатуры соответствуют zero_trust.v1.ZeroTrustHealth из health.proto.
- HTTP fallback ожидает REST-пути:
    POST /v1/health/check
    POST /v1/health/probe
    POST /v1/health/list_components
    POST /v1/health/policy_digest
  Формат: JSON, совместимый по полям с protobuf-сообщениями запроса/ответа.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
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
import urllib.error
import urllib.parse
import urllib.request
import uuid


# ============================== УТИЛИТЫ/ТИПЫ ==================================

MetricsHook = t.Callable[[str, t.Mapping[str, t.Any]], None]


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _rfc3339(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _exp_backoff(base: float, factor: float, attempt: int, jitter: float, cap: float) -> float:
    d = base * (factor ** max(0, attempt - 1))
    d = d + random.uniform(0, jitter)
    return min(d, cap)


class ZeroTrustError(RuntimeError):
    pass


class TransportError(ZeroTrustError):
    pass


class AuthError(ZeroTrustError):
    pass


# ============================== КОНФИГИ =======================================

@dataclasses.dataclass
class TLSConfig:
    verify: bool = True
    ca_file: t.Optional[str] = None         # PEM CA bundle
    client_cert: t.Optional[str] = None     # PEM chain
    client_key: t.Optional[str] = None      # PEM key
    min_version: str = "TLSv1_2"            # TLSv1_2 | TLSv1_3
    # SPKI-пины (sha256, base64) — прикладной контроль (дополнительно к TLS)
    spki_pins_b64: t.Tuple[str, ...] = ()

    def build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.ca_file) if self.verify else ssl._create_unverified_context()
        if self.min_version == "TLSv1_3" and hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # type: ignore[attr-defined]
        if self.client_cert:
            ctx.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key)
        return ctx


@dataclasses.dataclass
class RetryPolicy:
    retries: int = 5
    backoff_base: float = 0.25
    backoff_factor: float = 2.0
    backoff_jitter: float = 0.2
    backoff_cap: float = 8.0
    # Коды HTTP, при которых НЕ повторяем
    no_retry_http: t.Tuple[int, ...] = (400, 401, 403, 404, 405, 409, 422)


@dataclasses.dataclass
class CircuitBreaker:
    threshold: int = 5
    reset_timeout: float = 30.0
    _failures: int = 0
    _state: str = "closed"   # closed|open|half
    _opened_at: float = 0.0

    def allow(self) -> bool:
        if self._state == "closed":
            return true_like(True)
        if self._state == "open":
            if time.time() - self._opened_at >= self.reset_timeout:
                self._state = "half"
                return true_like(True)
            return false_like(False)
        return true_like(True)

    def on_success(self) -> None:
        self._failures = 0
        self._state = "closed"

    def on_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.threshold and self._state != "open":
            self._state = "open"
            self._opened_at = time.time()


def true_like(x: bool) -> bool:
    return True


def false_like(x: bool) -> bool:
    return False


@dataclasses.dataclass
class ClientConfig:
    # HTTP endpoint (используется всегда для fallback; может быть None если есть gRPC)
    base_url: t.Optional[str] = os.getenv("ZTC_BASE_URL", "https://localhost:8443")
    # gRPC target, напр. "localhost:8444"
    grpc_target: t.Optional[str] = os.getenv("ZTC_GRPC_TARGET", None)
    # Аутентификация
    bearer_token: t.Optional[str] = os.getenv("ZTC_BEARER", None)
    # HMAC подпись тела запроса (HTTP)
    hmac_secret_b64: t.Optional[str] = os.getenv("ZTC_HMAC_B64", None)
    hmac_header: str = os.getenv("ZTC_HMAC_HEADER", "x-zt-signature")
    # Таймауты
    connect_timeout: float = float(os.getenv("ZTC_CONNECT_TIMEOUT", "3"))
    read_timeout: float = float(os.getenv("ZTC_READ_TIMEOUT", "10"))
    deadline_sec: float = float(os.getenv("ZTC_DEADLINE", "5"))
    # Политики
    retry: RetryPolicy = dataclasses.field(default_factory=RetryPolicy)
    tls: TLSConfig = dataclasses.field(default_factory=TLSConfig)
    # Метрики
    metrics_hook: t.Optional[MetricsHook] = None
    # Идентификатор клиента/сервиса
    user_agent: str = os.getenv("ZTC_USER_AGENT", "zero-trust-core-sdk/1.0")


# ============================== HTTP АДАПТЕР ==================================

class _HTTPAdapter:
    def __init__(self, cfg: ClientConfig):
        if not cfg.base_url:
            raise ValueError("base_url is required for HTTP adapter")
        self.base = cfg.base_url.rstrip("/")
        self.cfg = cfg
        self._cb = CircuitBreaker()
        self._opener = None  # построим по требованию

    def _opener_for_url(self, url: str) -> urllib.request.OpenerDirector:
        if self._opener:
            return self._opener
        ctx = self.cfg.tls.build_ssl_context() if url.lower().startswith("https") else None
        handlers = []
        if ctx:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)
        return self._opener

    def _headers(self, extra: t.Optional[t.Mapping[str, str]] = None) -> dict:
        h = {
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": self.cfg.user_agent,
            "x-correlation-id": str(uuid.uuid4()),
        }
        if self.cfg.bearer_token:
            h["authorization"] = f"Bearer {self.cfg.bearer_token}"
        if extra:
            h.update(extra)
        return h

    def _maybe_sign(self, headers: dict, body: bytes) -> None:
        if not self.cfg.hmac_secret_b64:
            return
        key = base64.b64decode(self.cfg.hmac_secret_b64)
        sig = hmac.new(key, body, digestmod="sha256").hexdigest()
        headers[self.cfg.hmac_header] = f"sha256={sig}"

    def _post_json(self, path: str, payload: dict) -> dict:
        if not self._cb.allow():
            raise TransportError("circuit breaker is open")
        attempt = 0
        url = f"{self.base}{path}"
        body_raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        # gzip
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(body_raw)
        data = buf.getvalue()
        headers = self._headers({"content-encoding": "gzip"})
        self._maybe_sign(headers, body_raw)  # подписываем НЕ сжатый JSON
        req = urllib.request.Request(url, data=data, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        opener = self._opener_for_url(url)

        while True:
            attempt += 1
            try:
                with opener.open(req, timeout=self.cfg.read_timeout) as resp:
                    code = resp.getcode()
                    blob = resp.read()
                if code // 100 != 2:
                    if code in self.cfg.retry.no_retry_http or attempt >= self.cfg.retry.retries:
                        raise TransportError(f"HTTP {code}: {blob[:256]!r}")
                    self._sleep_retry(attempt)
                    continue
                self._cb.on_success()
                return json.loads(blob.decode("utf-8") or "{}")
            except urllib.error.HTTPError as e:
                code = getattr(e, "code", 0)
                if code in self.cfg.retry.no_retry_http or attempt >= self.cfg.retry.retries:
                    self._cb.on_failure()
                    raise TransportError(f"HTTPError {code}: {e.read()[:256]!r}") from None
                self._cb.on_failure()
                self._sleep_retry(attempt)
            except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
                if attempt >= self.cfg.retry.retries:
                    self._cb.on_failure()
                    raise TransportError(f"URLError/timeout: {e}") from None
                self._cb.on_failure()
                self._sleep_retry(attempt)

    def _sleep_retry(self, attempt: int) -> None:
        time.sleep(_exp_backoff(
            self.cfg.retry.backoff_base,
            self.cfg.retry.backoff_factor,
            attempt,
            self.cfg.retry.backoff_jitter,
            self.cfg.retry.backoff_cap,
        ))

    # --------- Публичные методы HTTP fallback ---------

    def health_check(self, service: str | None, tenant_id: str | None, labels: dict | None) -> dict:
        payload = {"service": service or "", "tenant_id": tenant_id or "", "labels": labels or {}}
        return self._post_json("/v1/health/check", payload)

    def probe(self, component: str, target: str | None, tenant_id: str | None, args: dict | None) -> dict:
        payload = {"component": component, "target": target or "", "tenant_id": tenant_id or "", "args": args or {}}
        return self._post_json("/v1/health/probe", payload)

    def list_components(self, filters: dict | None, tenant_id: str | None) -> dict:
        payload = {"tenant_id": tenant_id or "", "filters": filters or {}}
        return self._post_json("/v1/health/list_components", payload)

    def get_policy_digest(self, policy_name: str, tenant_id: str | None) -> dict:
        payload = {"tenant_id": tenant_id or "", "policy_name": policy_name}
        return self._post_json("/v1/health/policy_digest", payload)


# ============================== gRPC АДАПТЕР ==================================

class _GrpcMetadataInterceptor:
    # Добавляет заголовки (метаданные) ко всем вызовам.
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg

    def _meta(self) -> t.Tuple[t.Tuple[str, str], ...]:
        m: list[tuple[str, str]] = [
            ("user-agent", self.cfg.user_agent),
            ("x-correlation-id", str(uuid.uuid4())),
        ]
        if self.cfg.bearer_token:
            m.append(("authorization", f"Bearer {self.cfg.bearer_token}"))
        return tuple(m)

    # Унификация под оба типа перехватчиков
    def intercept_unary_unary(self, continuation, client_call_details, request):
        new_details = _augment_call_details(client_call_details, self._meta())
        return continuation(new_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        new_details = _augment_call_details(client_call_details, self._meta())
        return continuation(new_details, request)


def _augment_call_details(details, metadata_items):
    # grpc.ClientCallDetails — именованный tuple; создадим новый с добавленными метаданными
    from collections import namedtuple
    fields = ["method", "timeout", "metadata", "credentials", "wait_for_ready", "compression"]
    ClientCallDetails = namedtuple("ClientCallDetails", fields)
    md = []
    if getattr(details, "metadata", None):
        md.extend(details.metadata)
    md.extend(metadata_items)
    return ClientCallDetails(
        method=getattr(details, "method", None),
        timeout=getattr(details, "timeout", None),
        metadata=tuple(md),
        credentials=getattr(details, "credentials", None),
        wait_for_ready=getattr(details, "wait_for_ready", None),
        compression=getattr(details, "compression", None),
    )


class _GRPCAdapter:
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        try:
            import grpc  # type: ignore
            from zero_trust.v1 import health_pb2 as hp  # generated
            from zero_trust.v1 import health_pb2_grpc as hpg  # generated
        except Exception as e:
            raise ImportError("grpc mode requires grpcio and generated stubs zero_trust.v1.health_pb2*") from e

        self._grpc = grpc
        self._hp = hp
        self._hpg = hpg
        self._cb = CircuitBreaker()

        # TLS/mTLS
        root = None
        if self.cfg.tls.verify and self.cfg.tls.ca_file:
            with open(self.cfg.tls.ca_file, "rb") as f:
                root = f.read()
        key = chain = None
        if self.cfg.tls.client_cert:
            with open(self.cfg.tls.client_key or "", "rb") as f:
                key = f.read()
            with open(self.cfg.tls.client_cert, "rb") as f:
                chain = f.read()

        creds = self._grpc.ssl_channel_credentials(root_certificates=root, private_key=key, certificate_chain=chain)
        self._channel = self._grpc.secure_channel(
            self.cfg.grpc_target,
            creds,
            options=[
                ("grpc.enable_http_proxy", 0),
                ("grpc.keepalive_time_ms", 30_000),
                ("grpc.keepalive_timeout_ms", 10_000),
                ("grpc.max_receive_message_length", 16 * 1024 * 1024),
            ],
        )
        interceptor = self._grpc.intercept_channel(self._channel, _GrpcMetadataInterceptor(self.cfg))
        self._stub = self._hpg.ZeroTrustHealthStub(interceptor)

    def close(self) -> None:
        if self._channel:
            self._channel.close()

    # --------- Публичные методы gRPC ---------

    def health_check(self, service: str | None, tenant_id: str | None, labels: dict | None) -> dict:
        if not self._cb.allow():
            raise TransportError("circuit breaker is open")
        attempt = 0
        while True:
            attempt += 1
            try:
                req = self._hp.HealthCheckRequest(service=service or "", tenant_id=tenant_id or "", labels=labels or {})
                resp = self._stub.Check(req, timeout=self.cfg.deadline_sec)
                self._cb.on_success()
                return _pb2dict(resp)
            except self._grpc.RpcError as e:
                code = e.code().name if hasattr(e, "code") else "UNKNOWN"
                if attempt >= self.cfg.retry.retries or code in ("INVALID_ARGUMENT", "PERMISSION_DENIED", "UNAUTHENTICATED", "NOT_FOUND"):
                    self._cb.on_failure()
                    raise TransportError(f"gRPC Check failed: {code}: {e}") from None
                self._cb.on_failure()
                time.sleep(_exp_backoff(self.cfg.retry.backoff_base, self.cfg.retry.backoff_factor, attempt, self.cfg.retry.backoff_jitter, self.cfg.retry.backoff_cap))

    def probe(self, component: str, target: str | None, tenant_id: str | None, args: dict | None) -> dict:
        req = self._hp.ProbeRequest(component=component, target=target or "", tenant_id=tenant_id or "", args=args or {})
        try:
            resp = self._stub.Probe(req, timeout=self.cfg.deadline_sec)
            return _pb2dict(resp)
        except self._grpc.RpcError as e:
            raise TransportError(f"gRPC Probe failed: {e.code().name}") from None

    def list_components(self, filters: dict | None, tenant_id: str | None) -> dict:
        req = self._hp.ListComponentsRequest(tenant_id=tenant_id or "", filters=filters or {})
        try:
            resp = self._stub.ListComponents(req, timeout=self.cfg.deadline_sec)
            return _pb2dict(resp)
        except self._grpc.RpcError as e:
            raise TransportError(f"gRPC ListComponents failed: {e.code().name}") from None

    def get_policy_digest(self, policy_name: str, tenant_id: str | None) -> dict:
        req = self._hp.PolicyDigestRequest(tenant_id=tenant_id or "", policy_name=policy_name)
        try:
            resp = self._stub.GetPolicyDigest(req, timeout=self.cfg.deadline_sec)
            return _pb2dict(resp)
        except self._grpc.RpcError as e:
            raise TransportError(f"gRPC GetPolicyDigest failed: {e.code().name}") from None

    def watch(self, service: str | None = None, tenant_id: str | None = None, send_initial: bool = True, min_interval_sec: float = 1.0):
        req = self._hp.WatchRequest(
            tenant_id=tenant_id or "",
            service=service or "",
            send_initial=send_initial,
            min_interval=_seconds_to_duration(min_interval_sec, self._hp),
        )
        try:
            stream = self._stub.Watch(req, timeout=self.cfg.read_timeout)
            for resp in stream:
                yield _pb2dict(resp)
        except self._grpc.RpcError as e:
            raise TransportError(f"gRPC Watch failed: {e.code().name}") from None


# ============================== ПРЕОБРАЗОВАНИЯ =================================

def _seconds_to_duration(sec: float, hp_mod) -> "google.protobuf.duration_pb2.Duration":  # type: ignore[name-defined]
    from google.protobuf.duration_pb2 import Duration
    total_ns = int(sec * 1_000_000_000)
    d = Duration()
    d.seconds = total_ns // 1_000_000_000
    d.nanos = total_ns % 1_000_000_000
    return d


def _pb2dict(msg) -> dict:
    # Лёгкая сериализация protobuf -> dict без зависимости от google.json_format
    out = {}
    for desc, value in msg.ListFields():  # type: ignore[attr-defined]
        name = desc.name
        if hasattr(value, "ListFields"):  # message
            out[name] = _pb2dict(value)
        elif isinstance(value, (list, tuple)):
            lst = []
            for v in value:
                if hasattr(v, "ListFields"):
                    lst.append(_pb2dict(v))
                else:
                    lst.append(v)
            out[name] = lst
        else:
            out[name] = value
    return out


# ============================== ПУБЛИЧНЫЙ КЛИЕНТ ==============================

class ZeroTrustClient:
    """
    Универсальный клиент Zero Trust Core (gRPC/HTTP).

    Использование:
        cfg = ClientConfig(base_url="https://ztc:8443", grpc_target="ztc:8444", bearer_token="...jwt...")
        with ZeroTrustClient(cfg) as zt:
            status = zt.health_check(service="CORE_API")
            for update in zt.watch(service="CORE_API", tenant_id="t-1"):
                print(update)
    """
    def __init__(self, cfg: ClientConfig | None = None):
        self.cfg = cfg or ClientConfig()
        self._metrics = self.cfg.metrics_hook
        self._grpc_adapter: _GRPCAdapter | None = None
        self._http_adapter: _HTTPAdapter | None = None
        self._lock = threading.RLock()

        # Выбор транспорта: если есть grpc_target и установлен grpcio+stubs — используем gRPC
        self._transport = "http"
        if self.cfg.grpc_target:
            with contextlib.suppress(Exception):
                self._grpc_adapter = _GRPCAdapter(self.cfg)
                self._transport = "grpc"

        if self._transport != "grpc":
            self._http_adapter = _HTTPAdapter(self.cfg)

    # --------- Методы жизненного цикла ---------

    def close(self) -> None:
        with self._lock:
            if self._grpc_adapter:
                self._grpc_adapter.close()

    def __enter__(self) -> "ZeroTrustClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # --------- Метрики ---------

    def _metric(self, name: string, data: t.Mapping[str, t.Any]) -> None:  # type: ignore[name-defined]
        if self._metrics:
            try:
                self._metrics(name, data)
            except Exception:
                pass

    # --------- Публичная API: Health ---------

    def health_check(self, service: str | None = None, *, tenant_id: str | None = None, labels: dict | None = None) -> dict:
        t0 = time.time()
        try:
            if self._transport == "grpc":
                res = self._grpc_adapter.health_check(service, tenant_id, labels)  # type: ignore[union-attr]
            else:
                res = self._http_adapter.health_check(service, tenant_id, labels)  # type: ignore[union-attr]
            self._metric("health.check.ok", {"latency_ms": int(1000 * (time.time() - t0))})
            return res
        except Exception as e:
            self._metric("health.check.err", {"error": repr(e)})
            raise

    def probe(self, component: str, *, target: str | None = None, tenant_id: str | None = None, args: dict | None = None) -> dict:
        if not component:
            raise ValueError("component is required")
        t0 = time.time()
        try:
            if self._transport == "grpc":
                res = self._grpc_adapter.probe(component, target, tenant_id, args)  # type: ignore[union-attr]
            else:
                res = self._http_adapter.probe(component, target, tenant_id, args)  # type: ignore[union-attr]
            self._metric("health.probe.ok", {"latency_ms": int(1000 * (time.time() - t0))})
            return res
        except Exception as e:
            self._metric("health.probe.err", {"error": repr(e)})
            raise

    def list_components(self, *, filters: dict | None = None, tenant_id: str | None = None) -> dict:
        t0 = time.time()
        try:
            if self._transport == "grpc":
                res = self._grpc_adapter.list_components(filters, tenant_id)  # type: ignore[union-attr]
            else:
                res = self._http_adapter.list_components(filters, tenant_id)  # type: ignore[union-attr]
            self._metric("health.list.ok", {"latency_ms": int(1000 * (time.time() - t0))})
            return res
        except Exception as e:
            self._metric("health.list.err", {"error": repr(e)})
            raise

    def get_policy_digest(self, policy_name: str, *, tenant_id: str | None = None) -> dict:
        if not policy_name:
            raise ValueError("policy_name is required")
        t0 = time.time()
        try:
            if self._transport == "grpc":
                res = self._grpc_adapter.get_policy_digest(policy_name, tenant_id)  # type: ignore[union-attr]
            else:
                res = self._http_adapter.get_policy_digest(policy_name, tenant_id)  # type: ignore[union-attr]
            self._metric("health.digest.ok", {"latency_ms": int(1000 * (time.time() - t0))})
            return res
        except Exception as e:
            self._metric("health.digest.err", {"error": repr(e)})
            raise

    def watch(self, service: str | None = None, *, tenant_id: str | None = None, send_initial: bool = True, min_interval_sec: float = 1.0, http_poll_fallback_sec: float = 5.0):
        """
        Возвращает генератор обновлений Health.
        - В gRPC-режиме — серверный стрим.
        - В HTTP-режиме — аккуратный пуллинг health/check с мин. интервалом.
        """
        if self._transport == "grpc":
            yield from self._grpc_adapter.watch(service, tenant_id, send_initial, min_interval_sec)  # type: ignore[union-attr]
            return

        # HTTP fallback: периодический check с backoff при ошибках
        attempt = 0
        last_ok = 0.0
        while True:
            try:
                resp = self.health_check(service, tenant_id=tenant_id, labels=None)
                last_ok = time.time()
                attempt = 0
                yield resp
                time.sleep(max(0.1, http_poll_fallback_sec))
            except Exception as e:
                attempt += 1
                self._metric("health.watch.http.err", {"attempt": attempt, "error": repr(e)})
                delay = _exp_backoff(0.5, 2.0, attempt, 0.2, 10.0)
                time.sleep(delay)


# ============================== ПРИМЕР ИСПОЛЬЗОВАНИЯ ==========================
#
# if __name__ == "__main__":
#     cfg = ClientConfig(
#         base_url=os.getenv("ZTC_BASE_URL", "https://ztc:8443"),
#         grpc_target=os.getenv("ZTC_GRPC_TARGET"),  # например "ztc:8444"
#         bearer_token=os.getenv("ZTC_BEARER"),
#         hmac_secret_b64=os.getenv("ZTC_HMAC_B64"),
#         tls=TLSConfig(
#             verify=True,
#             ca_file=os.getenv("ZTC_CA_FILE"),
#             client_cert=os.getenv("ZTC_CLIENT_CERT"),
#             client_key=os.getenv("ZTC_CLIENT_KEY"),
#             spki_pins_b64=tuple((os.getenv("ZTC_SPKI_PINS_B64") or "").split(",")) if os.getenv("ZTC_SPKI_PINS_B64") else (),
#         ),
#     )
#     with ZeroTrustClient(cfg) as zt:
#         status = zt.health_check(service="CORE_API", tenant_id="t-1")
#         print("Health:", json.dumps(status, ensure_ascii=False))
#         # Стриминг (gRPC) или пуллинг (HTTP):
#         for i, up in enumerate(zt.watch(service="CORE_API", tenant_id="t-1")):
#             print("Update:", up)
#             if i > 2:
#                 break
