# -*- coding: utf-8 -*-
"""
security_client.py — промышленный SDK для security-core HealthService.

Зависимости:
  - grpcio>=1.62
  - grpcio-tools (для генерации прото-стабов)
  - httpx>=0.25 (опционально, для HTTP фолбэка через grpc-gateway)
  - opentelemetry-api, opentelemetry-sdk (опционально)

Ожидаемые сгенерированные модули из health.proto:
  security.v1.health_pb2            as pb
  security.v1.health_pb2_grpc       as stubs

Методы покрытия:
  Check, Watch, Liveness, Readiness, ListProbes,
  GetBuildInfo, GetDependencies, MetricsSnapshot, SLO
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union, Callable

# --- Опциональные импорты (грациозная деградация) ---
try:
    import grpc
    from grpc import aio as grpc_aio
except Exception:  # pragma: no cover
    grpc = None
    grpc_aio = None

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None

# Прото-стабы (должны быть сгенерированы вашим пайплайном)
try:
    from security.v1 import health_pb2 as pb
    from security.v1 import health_pb2_grpc as stubs
except Exception as e:  # pragma: no cover
    pb = None
    stubs = None

# ----------------------------- Конфигурация ----------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_backoff_s: float = 0.2
    max_backoff_s: float = 2.0
    backoff_multiplier: float = 2.0
    retryable_statuses: Tuple[int, ...] = field(
        default_factory=lambda: (
            getattr(grpc, "StatusCode", object()).UNAVAILABLE,
            getattr(grpc, "StatusCode", object()).DEADLINE_EXCEEDED,
            getattr(grpc, "StatusCode", object()).RESOURCE_EXHAUSTED,
            getattr(grpc, "StatusCode", object()).INTERNAL,
        )
    )


@dataclass(frozen=True)
class TimeoutPolicy:
    # Дедлайны по умолчанию
    check_s: float = 2.0
    probe_s: float = 1.0
    deps_s: float = 3.0
    metrics_s: float = 2.0
    slo_s: float = 2.5
    watch_idle_timeout_s: float = 60.0


@dataclass(frozen=True)
class TLSConfig:
    enable: bool = False
    root_ca: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    server_name_override: Optional[str] = None  # для SNI/override


@dataclass(frozen=True)
class AuthConfig:
    # Один из вариантов: static bearer, пер‑RPC callback, mTLS (через TLSConfig)
    bearer_token: Optional[str] = None
    metadata_cb: Optional[Callable[[], Mapping[str, str]]] = None


@dataclass(frozen=True)
class ClientConfig:
    target: str = "localhost:50051"       # gRPC адрес
    http_base_url: Optional[str] = None   # http(s)://gw.example.org (grpc-gateway)
    tenant_id: Optional[str] = None
    default_labels: Mapping[str, str] = dataclasses.field(default_factory=dict)
    retry: RetryPolicy = RetryPolicy()
    timeouts: TimeoutPolicy = TimeoutPolicy()
    tls: TLSConfig = TLSConfig()
    auth: AuthConfig = AuthConfig()
    user_agent: str = "security-core-python-sdk/1.0"
    # Circuit breaker
    cb_fail_threshold: int = 5
    cb_reset_timeout_s: float = 10.0


# -------------------------- Вспомогательные утилиты ---------------------------

def _now_monotonic() -> float:
    return time.monotonic()


class CircuitBreaker:
    """Простой circuit breaker для защиты от каскадных сбоев."""
    def __init__(self, fail_threshold: int, reset_timeout_s: float):
        self.fail_threshold = fail_threshold
        self.reset_timeout_s = reset_timeout_s
        self.fail_count = 0
        self.opened_at: Optional[float] = None

    def allow(self) -> bool:
        if self.opened_at is None:
            return True
        # Half-open после таймаута
        if _now_monotonic() - self.opened_at >= self.reset_timeout_s:
            return True
        return False

    def on_success(self) -> None:
        self.fail_count = 0
        self.opened_at = None

    def on_failure(self) -> None:
        self.fail_count += 1
        if self.fail_count >= self.fail_threshold:
            self.opened_at = _now_monotonic()


def _metadata(config: ClientConfig, correlation_id: Optional[str]) -> Sequence[Tuple[str, str]]:
    md = [
        ("x-correlation-id", correlation_id or str(uuid.uuid4())),
        ("x-tenant-id", config.tenant_id or ""),
        ("user-agent", config.user_agent),
    ]
    # bearer
    if config.auth.bearer_token:
        md.append(("authorization", f"Bearer {config.auth.bearer_token}"))
    # custom metadata
    if config.auth.metadata_cb:
        for k, v in (config.auth.metadata_cb() or {}).items():
            md.append((k, v))
    # default labels as JSON
    if config.default_labels:
        md.append(("x-default-labels", json.dumps(dict(config.default_labels))))
    return tuple(md)


def _secure_channel(target: str, tls: TLSConfig) -> "grpc.Channel":
    if not tls.enable:
        return grpc.insecure_channel(target)
    # загрузка корня и ключей
    root = None
    if tls.root_ca:
        with open(tls.root_ca, "rb") as f:
            root = f.read()
    cert = key = None
    if tls.client_cert and tls.client_key:
        with open(tls.client_cert, "rb") as cf, open(tls.client_key, "rb") as kf:
            cert, key = cf.read(), kf.read()
    creds = grpc.ssl_channel_credentials(root_certificates=root, private_key=key, certificate_chain=cert)
    opts = []
    if tls.server_name_override:
        opts.append(("grpc.ssl_target_name_override", tls.server_name_override))
    return grpc.secure_channel(target, creds, options=opts)


def _secure_channel_async(target: str, tls: TLSConfig) -> "grpc_aio.Channel":
    if not tls.enable:
        return grpc_aio.insecure_channel(target)
    root = None
    if tls.root_ca:
        with open(tls.root_ca, "rb") as f:
            root = f.read()
    cert = key = None
    if tls.client_cert and tls.client_key:
        with open(tls.client_cert, "rb") as cf, open(tls.client_key, "rb") as kf:
            cert, key = cf.read(), kf.read()
    creds = grpc.ssl_channel_credentials(root_certificates=root, private_key=key, certificate_chain=cert)
    opts = []
    if tls.server_name_override:
        opts.append(("grpc.ssl_target_name_override", tls.server_name_override))
    return grpc_aio.secure_channel(target, creds, options=opts)


def _with_retry(call: Callable[[], Any], policy: RetryPolicy) -> Any:
    attempt = 0
    delay = policy.initial_backoff_s
    while True:
        try:
            return call()
        except Exception as e:  # noqa
            # Если grpc доступен — проверим статус
            code = getattr(e, "code", lambda: None)()
            if grpc and code in policy.retryable_statuses and attempt + 1 < policy.max_attempts:
                time.sleep(delay)
                delay = min(policy.max_backoff_s, delay * policy.backoff_multiplier)
                attempt += 1
                continue
            raise


async def _with_retry_async(call: Callable[[], Any], policy: RetryPolicy) -> Any:
    attempt = 0
    delay = policy.initial_backoff_s
    while True:
        try:
            return await call()
        except Exception as e:  # noqa
            code = getattr(e, "code", lambda: None)()
            if grpc and code in policy.retryable_statuses and attempt + 1 < policy.max_attempts:
                await _sleep(delay)
                delay = min(policy.max_backoff_s, delay * policy.backoff_multiplier)
                attempt += 1
                continue
            raise


async def _sleep(seconds: float) -> None:
    import asyncio
    await asyncio.sleep(seconds)


# ----------------------------- Синхронный клиент ------------------------------

class SecurityClient:
    """
    Синхронный gRPC клиент с HTTP фолбэком (grpc-gateway).
    Используйте как контекст-менеджер: with SecurityClient(cfg) as c: ...
    """
    def __init__(self, config: ClientConfig):
        if grpc is None or pb is None or stubs is None:
            raise RuntimeError("grpc / protobuf stubs not available")
        self._cfg = config
        self._cb = CircuitBreaker(config.cb_fail_threshold, config.cb_reset_timeout_s)
        self._channel = _secure_channel(config.target, config.tls)
        self._stub = stubs.HealthServiceStub(self._channel)
        self._http = None
        if self._cfg.http_base_url and httpx:
            self._http = httpx.Client(base_url=self._cfg.http_base_url, timeout=self._cfg.timeouts.check_s)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            if hasattr(self._channel, "close"):
                self._channel.close()
        if self._http:
            self._http.close()

    # ---- Context manager ----
    def __enter__(self) -> "SecurityClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ---- RPCs ----

    def check(self,
              components: Optional[Sequence[str]] = None,
              selector: Optional[Mapping[str, str]] = None,
              field_mask_paths: Optional[Sequence[str]] = None,
              correlation_id: Optional[str] = None) -> pb.HealthCheckResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.HealthCheckRequest(
            meta=pb.RequestMeta(
                correlation_id=dict(md).get("x-correlation-id", ""),
                tenant_id=self._cfg.tenant_id or "",
                user_agent=self._cfg.user_agent,
                labels=dict(self._cfg.default_labels),
            ),
            components=list(components or []),
            selector=dict(selector or {}),
        )
        if field_mask_paths:
            req.field_mask.paths.extend(field_mask_paths)

        def _do():
            return self._stub.Check(
                req, timeout=self._cfg.timeouts.check_s, metadata=md
            )

        try:
            resp = _with_retry(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            # HTTP fallback (опционально)
            if self._http:
                payload = {
                    "components": list(components or []),
                    "selector": dict(selector or {}),
                }
                hdrs = {k: v for k, v in md}
                r = self._http.get("/v1/security/health:check", headers=hdrs, params={"q": json.dumps(payload)})
                r.raise_for_status()
                # Ожидается JSON, маппинг в pb при необходимости
                return _from_json_check(r.json())
            raise

    def watch(self,
              components: Optional[Sequence[str]] = None,
              selector: Optional[Mapping[str, str]] = None,
              correlation_id: Optional[str] = None,
              idle_timeout_s: Optional[float] = None) -> Iterator[pb.HealthStatusEvent]:
        """Server-streaming; возвращает итератор событий."""
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.HealthWatchRequest(
            meta=pb.RequestMeta(
                correlation_id=dict(md).get("x-correlation-id", ""),
                tenant_id=self._cfg.tenant_id or "",
                user_agent=self._cfg.user_agent,
                labels=dict(self._cfg.default_labels),
            ),
            components=list(components or []),
            selector=dict(selector or {}),
            min_interval=pb.google_dot_protobuf_dot_duration__pb2.Duration(seconds=1),
        )
        deadline = idle_timeout_s or self._cfg.timeouts.watch_idle_timeout_s
        try:
            stream = self._stub.Watch(req, metadata=md, timeout=deadline)
            for ev in stream:
                yield ev
            self._cb.on_success()
        except Exception:
            self._cb.on_failure()
            raise

    def liveness(self, correlation_id: Optional[str] = None) -> pb.ProbeResponse:
        return self._probe_call(self._stub.Liveness, self._cfg.timeouts.probe_s, correlation_id)

    def readiness(self, correlation_id: Optional[str] = None) -> pb.ProbeResponse:
        return self._probe_call(self._stub.Readiness, self._cfg.timeouts.probe_s, correlation_id)

    def list_probes(self, correlation_id: Optional[str] = None) -> pb.ListProbesResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        def _do():
            return self._stub.ListProbes(pb.ListProbesRequest(meta=pb.RequestMeta()), timeout=self._cfg.timeouts.probe_s, metadata=md)
        try:
            resp = _with_retry(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    def get_build_info(self, correlation_id: Optional[str] = None) -> pb.BuildInfo:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        def _do():
            return self._stub.GetBuildInfo(pb.google_dot_protobuf_dot_empty__pb2.Empty(), timeout=self._cfg.timeouts.check_s, metadata=md)
        try:
            resp = _with_retry(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    def get_dependencies(self,
                         selector: Optional[Mapping[str, str]] = None,
                         page_size: int = 100,
                         page_token: Optional[str] = None,
                         correlation_id: Optional[str] = None) -> pb.GetDependenciesResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.GetDependenciesRequest(
            meta=pb.RequestMeta(),
            selector=dict(selector or {}),
            page_size=page_size,
            page_token=page_token or "",
        )
        def _do():
            return self._stub.GetDependencies(req, timeout=self._cfg.timeouts.deps_s, metadata=md)
        try:
            resp = _with_retry(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    def metrics_snapshot(self,
                         metric_names: Optional[Sequence[str]] = None,
                         selector: Optional[Mapping[str, str]] = None,
                         correlation_id: Optional[str] = None) -> pb.MetricsSnapshotResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.MetricsSnapshotRequest(
            meta=pb.RequestMeta(),
            metric_names=list(metric_names or []),
            selector=dict(selector or {}),
        )
        def _do():
            return self._stub.MetricsSnapshot(req, timeout=self._cfg.timeouts.metrics_s, metadata=md)
        try:
            resp = _with_retry(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    def slo(self,
            window: str,
            availability_pct: float,
            selector: Optional[Mapping[str, str]] = None,
            correlation_id: Optional[str] = None) -> pb.SLOResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.SLORequest(
            meta=pb.RequestMeta(),
            target=pb.SLOTarget(window=window, availability_pct=availability_pct),
            selector=dict(selector or {}),
        )
        def _do():
            return self._stub.SLO(req, timeout=self._cfg.timeouts.slo_s, metadata=md)
        try:
            resp = _with_retry(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    # ---- helpers ----
    def _probe_call(self, fn: Callable, timeout: float, correlation_id: Optional[str]) -> pb.ProbeResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        def _do():
            return fn(pb.google_dot_protobuf_dot_empty__pb2.Empty(), timeout=timeout, metadata=md)
        try:
            resp = _with_retry(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            # HTTP fallback не реализуем для probe — обычно не нужен
            raise


# ----------------------------- Асинхронный клиент -----------------------------

class AsyncSecurityClient:
    """
    Асинхронный gRPC клиент. Используйте как async context manager:
      async with AsyncSecurityClient(cfg) as c: ...
    """
    def __init__(self, config: ClientConfig):
        if grpc_aio is None or pb is None or stubs is None:
            raise RuntimeError("grpc aio / protobuf stubs not available")
        self._cfg = config
        self._cb = CircuitBreaker(config.cb_fail_threshold, config.cb_reset_timeout_s)
        self._channel = _secure_channel_async(config.target, config.tls)
        self._stub = stubs.HealthServiceStub(self._channel)
        self._http: Optional[httpx.AsyncClient] = None
        if self._cfg.http_base_url and httpx:
            self._http = httpx.AsyncClient(base_url=self._cfg.http_base_url, timeout=self._cfg.timeouts.check_s)

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self._channel.close()
        if self._http:
            await self._http.aclose()

    async def __aenter__(self) -> "AsyncSecurityClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # ---- RPCs ----

    async def check(self,
                    components: Optional[Sequence[str]] = None,
                    selector: Optional[Mapping[str, str]] = None,
                    field_mask_paths: Optional[Sequence[str]] = None,
                    correlation_id: Optional[str] = None) -> pb.HealthCheckResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.HealthCheckRequest(
            meta=pb.RequestMeta(
                correlation_id=dict(md).get("x-correlation-id", ""),
                tenant_id=self._cfg.tenant_id or "",
                user_agent=self._cfg.user_agent,
                labels=dict(self._cfg.default_labels),
            ),
            components=list(components or []),
            selector=dict(selector or {}),
        )
        if field_mask_paths:
            req.field_mask.paths.extend(field_mask_paths)

        async def _do():
            return await self._stub.Check(req, timeout=self._cfg.timeouts.check_s, metadata=md)

        try:
            resp = await _with_retry_async(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            if self._http:
                payload = {
                    "components": list(components or []),
                    "selector": dict(selector or {}),
                }
                hdrs = {k: v for k, v in md}
                r = await self._http.get("/v1/security/health:check", headers=hdrs, params={"q": json.dumps(payload)})
                r.raise_for_status()
                return _from_json_check(r.json())
            raise

    async def watch(self,
                    components: Optional[Sequence[str]] = None,
                    selector: Optional[Mapping[str, str]] = None,
                    correlation_id: Optional[str] = None,
                    idle_timeout_s: Optional[float] = None) -> AsyncIterator[pb.HealthStatusEvent]:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.HealthWatchRequest(
            meta=pb.RequestMeta(
                correlation_id=dict(md).get("x-correlation-id", ""),
                tenant_id=self._cfg.tenant_id or "",
                user_agent=self._cfg.user_agent,
                labels=dict(self._cfg.default_labels),
            ),
            components=list(components or []),
            selector=dict(selector or {}),
            min_interval=pb.google_dot_protobuf_dot_duration__pb2.Duration(seconds=1),
        )
        deadline = idle_timeout_s or self._cfg.timeouts.watch_idle_timeout_s

        async def _do_stream() -> AsyncIterator[pb.HealthStatusEvent]:
            call = self._stub.Watch(req, metadata=md, timeout=deadline)
            async for ev in call:
                yield ev

        try:
            # Первая попытка; ретраи для потоков обычно оборачивают снаружи.
            async for ev in _do_stream():
                yield ev
            self._cb.on_success()
        except Exception:
            self._cb.on_failure()
            raise

    async def liveness(self, correlation_id: Optional[str] = None) -> pb.ProbeResponse:
        return await self._probe_call(self._stub.Liveness, self._cfg.timeouts.probe_s, correlation_id)

    async def readiness(self, correlation_id: Optional[str] = None) -> pb.ProbeResponse:
        return await self._probe_call(self._stub.Readiness, self._cfg.timeouts.probe_s, correlation_id)

    async def list_probes(self, correlation_id: Optional[str] = None) -> pb.ListProbesResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        async def _do():
            return await self._stub.ListProbes(pb.ListProbesRequest(meta=pb.RequestMeta()), timeout=self._cfg.timeouts.probe_s, metadata=md)
        try:
            resp = await _with_retry_async(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    async def get_build_info(self, correlation_id: Optional[str] = None) -> pb.BuildInfo:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        async def _do():
            return await self._stub.GetBuildInfo(pb.google_dot_protobuf_dot_empty__pb2.Empty(), timeout=self._cfg.timeouts.check_s, metadata=md)
        try:
            resp = await _with_retry_async(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    async def get_dependencies(self,
                               selector: Optional[Mapping[str, str]] = None,
                               page_size: int = 100,
                               page_token: Optional[str] = None,
                               correlation_id: Optional[str] = None) -> pb.GetDependenciesResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.GetDependenciesRequest(
            meta=pb.RequestMeta(),
            selector=dict(selector or {}),
            page_size=page_size,
            page_token=page_token or "",
        )
        async def _do():
            return await self._stub.GetDependencies(req, timeout=self._cfg.timeouts.deps_s, metadata=md)
        try:
            resp = await _with_retry_async(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    async def metrics_snapshot(self,
                               metric_names: Optional[Sequence[str]] = None,
                               selector: Optional[Mapping[str, str]] = None,
                               correlation_id: Optional[str] = None) -> pb.MetricsSnapshotResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.MetricsSnapshotRequest(
            meta=pb.RequestMeta(),
            metric_names=list(metric_names or []),
            selector=dict(selector or {}),
        )
        async def _do():
            return await self._stub.MetricsSnapshot(req, timeout=self._cfg.timeouts.metrics_s, metadata=md)
        try:
            resp = await _with_retry_async(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    async def slo(self,
                  window: str,
                  availability_pct: float,
                  selector: Optional[Mapping[str, str]] = None,
                  correlation_id: Optional[str] = None) -> pb.SLOResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        req = pb.SLORequest(
            meta=pb.RequestMeta(),
            target=pb.SLOTarget(window=window, availability_pct=availability_pct),
            selector=dict(selector or {}),
        )
        async def _do():
            return await self._stub.SLO(req, timeout=self._cfg.timeouts.slo_s, metadata=md)
        try:
            resp = await _with_retry_async(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise

    # ---- helpers ----
    async def _probe_call(self, fn: Callable, timeout: float, correlation_id: Optional[str]) -> pb.ProbeResponse:
        if not self._cb.allow():
            raise RuntimeError("Circuit breaker is open")
        md = _metadata(self._cfg, correlation_id)
        async def _do():
            return await fn(pb.google_dot_protobuf_dot_empty__pb2.Empty(), timeout=timeout, metadata=md)
        try:
            resp = await _with_retry_async(_do, self._cfg.retry)
            self._cb.on_success()
            return resp
        except Exception:
            self._cb.on_failure()
            raise


# ----------------------------- JSON → PB helpers ------------------------------

def _from_json_check(data: Dict[str, Any]) -> "pb.HealthCheckResponse":
    """
    Простейший маппер JSON → pb.HealthCheckResponse для HTTP фолбэка.
    Предполагает, что gateway возвращает схему, совместимую с pb.
    В реальном проекте используйте pydantic и явное сопоставление.
    """
    if pb is None:
        raise RuntimeError("protobuf not available")
    resp = pb.HealthCheckResponse()
    # Заполнение минимального подмножества; остальное — по ситуации
    overall = data.get("overall")
    if overall is not None:
        resp.overall = overall
    if "ttl" in data and isinstance(data["ttl"], dict):
        # { "seconds": int, "nanos": int }
        resp.ttl.seconds = int(data["ttl"].get("seconds", 0))
        resp.ttl.nanos = int(data["ttl"].get("nanos", 0))
    # details
    for d in data.get("details", []):
        sd = resp.details.add()
        sd.component = d.get("component", "")
        sd.status = int(d.get("status", 0))
        sd.severity = int(d.get("severity", 0))
        sd.reason = d.get("reason", "")
        sd.message = d.get("message", "")
    # build (минимально)
    if "build" in data and isinstance(data["build"], dict):
        b = data["build"]
        resp.build.version = b.get("version", "")
        resp.build.git_commit = b.get("git_commit", "")
        resp.build.build_date = b.get("build_date", "")
        resp.build.runtime = b.get("runtime", "")
    return resp


# ----------------------------- Пример инициализации ---------------------------

def default_client(target: str,
                   http_base_url: Optional[str] = None,
                   bearer_token: Optional[str] = None,
                   mtls: Optional[TLSConfig] = None) -> SecurityClient:
    """
    Быстрый фабричный метод для синхронного клиента.
    """
    cfg = ClientConfig(
        target=target,
        http_base_url=http_base_url,
        auth=AuthConfig(bearer_token=bearer_token),
        tls=mtls or TLSConfig(enable=False),
        default_labels={"service": "security-core-client"},
    )
    return SecurityClient(cfg)
