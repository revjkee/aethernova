# -*- coding: utf-8 -*-
"""
VeilMind Core — gRPC server (async, industrial-grade)

Требования:
  - Python 3.10+
  - grpcio>=1.56, grpcio-health-checking, grpcio-reflection
  - (опционально) PyJWT для JWT-проверки, opentelemetry-api для трассировки

Файл реализует сервер для protobuf: schemas/proto/v1/veilmind/synthetic.proto
Генерируемые модули принято располагать в: veilmind_core/gen/veilmind/v1/
и импортировать как synthetic_pb2 / synthetic_pb2_grpc.
Адаптируйте import-пути согласно вашей структуре.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import signal
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Tuple

import grpc
from grpc import aio
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection

# ---- Замените пути импорта под ваш генератор/пакет ---------------------------
# Предполагается, что вы сгенерировали код из synthetic.proto
try:
    from veilmind_core.gen.veilmind.v1 import synthetic_pb2 as pb
    from veilmind_core.gen.veilmind.v1 import synthetic_pb2_grpc as pbg
except Exception:  # fallback для демонстрации (адаптируйте!)
    from schemas.proto.v1.veilmind import synthetic_pb2 as pb  # type: ignore
    from schemas.proto.v1.veilmind import synthetic_pb2_grpc as pbg  # type: ignore

# ---- Опционально: PyJWT для проверки JWT ------------------------------------
try:
    import jwt  # type: ignore
except Exception:
    jwt = None  # type: ignore

# ---- Опционально: OpenTelemetry ---------------------------------------------
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer("veilmind.grpc.server")
except Exception:
    _tracer = None

LOGGER = logging.getLogger("veilmind.grpc")


# =============================================================================
# Конфигурация сервера
# =============================================================================
@dataclass(frozen=True)
class ServerConfig:
    host: str = os.getenv("GRPC_HOST", "0.0.0.0")
    port: int = int(os.getenv("GRPC_PORT", "50051"))

    # Сообщения и сжатие
    max_recv_mb: int = int(os.getenv("GRPC_MAX_RECV_MB", "64"))
    max_send_mb: int = int(os.getenv("GRPC_MAX_SEND_MB", "64"))
    compression: grpc.Compression = grpc.Compression.Gzip if os.getenv("GRPC_GZIP", "1") == "1" else grpc.Compression.NoCompression

    # TLS
    tls_enabled: bool = os.getenv("GRPC_TLS_ENABLED", "0") == "1"
    tls_cert_file: str = os.getenv("GRPC_TLS_CERT_FILE", "")
    tls_key_file: str = os.getenv("GRPC_TLS_KEY_FILE", "")
    tls_ca_file: str = os.getenv("GRPC_TLS_CA_FILE", "")  # опционально, для mTLS укажите и ca + client_auth

    # Keepalive/аргументы канала
    keepalive_time_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIME_MS", "20000"))          # отправлять ping каждые 20с
    keepalive_timeout_ms: int = int(os.getenv("GRPC_KEEPALIVE_TIMEOUT_MS", "20000"))    # ожидать ACK 20с
    keepalive_permit_without_calls: int = int(os.getenv("GRPC_KEEPALIVE_WITHOUT_CALLS", "1"))
    http2_max_pings_without_data: int = int(os.getenv("GRPC_MAX_PINGS_WITHOUT_DATA", "0"))
    http2_min_recv_ping_interval_ms: int = int(os.getenv("GRPC_MIN_RECV_PING_INTERVAL_MS", "5000"))

    # Аутентификация
    auth_enabled: bool = os.getenv("GRPC_AUTH_ENABLED", "0") == "1"
    auth_audience: str = os.getenv("GRPC_AUTH_AUD", "veilmind-core")
    auth_issuers: Tuple[str, ...] = tuple(os.getenv("GRPC_AUTH_ISSUERS", "").split(",")) if os.getenv("GRPC_AUTH_ISSUERS") else tuple()
    auth_jwks_json: str = os.getenv("GRPC_AUTH_JWKS_JSON", "")  # статический JWKS JSON (для демо) или оставьте пустым

    # Сервисное поведение
    drain_grace_seconds: int = int(os.getenv("GRPC_DRAIN_SECONDS", "15"))
    reflection_enabled: bool = os.getenv("GRPC_REFLECTION", "1") == "1"
    health_enabled: bool = os.getenv("GRPC_HEALTH", "1") == "1"


def _server_options(cfg: ServerConfig) -> List[Tuple[str, Any]]:
    return [
        ("grpc.max_receive_message_length", cfg.max_recv_mb * 1024 * 1024),
        ("grpc.max_send_message_length", cfg.max_send_mb * 1024 * 1024),
        ("grpc.keepalive_time_ms", cfg.keepalive_time_ms),
        ("grpc.keepalive_timeout_ms", cfg.keepalive_timeout_ms),
        ("grpc.keepalive_permit_without_calls", cfg.keepalive_permit_without_calls),
        ("grpc.http2.max_pings_without_data", cfg.http2_max_pings_without_data),
        ("grpc.http2.min_time_between_pings_ms", cfg.keepalive_time_ms),
        ("grpc.http2.min_ping_interval_without_data_ms", cfg.http2_min_recv_ping_interval_ms),
    ]


# =============================================================================
# Перехватчики: исключения, логирование, аутентификация
# =============================================================================
class ExceptionInterceptor(aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        try:
            return await continuation(handler_call_details)
        except grpc.RpcError:
            raise
        except asyncio.CancelledError:
            raise grpc.aio.AbortError()  # корректно завершаем
        except Exception as e:
            LOGGER.exception("Unhandled server error: %s", e)
            def error_handler(request, context):
                context.set_code(grpc.StatusCode.INTERNAL)
                context.set_details("internal server error")
                return None
            # Для streaming методов grpc ожидает разные сигнатуры; вернём generic error handler
            return grpc.unary_unary_rpc_method_handler(error_handler)


class LoggingInterceptor(aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        metadata = dict(handler_call_details.invocation_metadata or [])
        peer = handler_call_details.peer
        start_ns = time.perf_counter_ns()

        if _tracer is not None:
            span_name = f"grpc:{method}"
            with _tracer.start_as_current_span(span_name):
                handler = await continuation(handler_call_details)
        else:
            handler = await continuation(handler_call_details)

        async def _log_unary_unary(request, context, handler_fn):
            try:
                resp = await handler_fn(request, context)
                return resp
            finally:
                dur_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                LOGGER.info("grpc_call",
                            extra={"method": method, "duration_ms": round(dur_ms, 3),
                                   "peer": peer, "user_agent": metadata.get("user-agent", "")})

        async def _log_streaming(request_or_iterator, context, handler_fn, kind: str):
            try:
                return await handler_fn(request_or_iterator, context)
            finally:
                dur_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                LOGGER.info("grpc_call_stream",
                            extra={"method": method, "duration_ms": round(dur_ms, 3),
                                   "peer": peer, "kind": kind, "user_agent": metadata.get("user-agent", "")})

        # Оборачиваем выбранный handler
        if handler is None:
            return None

        if handler.unary_unary:
            fn = handler.unary_unary
            async def wrapper(request, context):
                return await _log_unary_unary(request, context, fn)
            return handler._replace(unary_unary=wrapper)
        if handler.unary_stream:
            fn = handler.unary_stream
            async def wrapper(request, context):
                return await _log_streaming(request, context, fn, "unary_stream")
            return handler._replace(unary_stream=wrapper)
        if handler.stream_unary:
            fn = handler.stream_unary
            async def wrapper(request_iterator, context):
                return await _log_streaming(request_iterator, context, fn, "stream_unary")
            return handler._replace(stream_unary=wrapper)
        if handler.stream_stream:
            fn = handler.stream_stream
            async def wrapper(request_iterator, context):
                return await _log_streaming(request_iterator, context, fn, "stream_stream")
            return handler._replace(stream_stream=wrapper)
        return handler


class AuthInterceptor(aio.ServerInterceptor):
    """
    Простой Bearer JWT перехватчик.
    - Если GRPC_AUTH_ENABLED=0, пропускаем без проверки.
    - Если включено и PyJWT недоступен, отклоняем с UNAUTHENTICATED.
    - Поддержка аудиторий и списка допустимых issuers.
    - Для демонстрации поддерживается статический JWKS_JSON из ENV.
      В проде используйте кэш JWKS по https://<issuer>/.well-known/jwks.json
    """

    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self._jwks: Dict[str, Any] = {}
        if cfg.auth_jwks_json:
            try:
                self._jwks = json.loads(cfg.auth_jwks_json)
            except Exception:
                LOGGER.warning("Invalid GRPC_AUTH_JWKS_JSON, ignoring")

    async def intercept_service(self, continuation, handler_call_details):
        if not self.cfg.auth_enabled:
            return await continuation(handler_call_details)

        if jwt is None:
            def unauthorized(request, context):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "authentication library not available")
            return grpc.unary_unary_rpc_method_handler(unauthorized)

        metadata = dict(handler_call_details.invocation_metadata or [])
        auth = metadata.get("authorization") or metadata.get("Authorization")
        token = None
        if auth and auth.lower().startswith("bearer "):
            token = auth[7:].strip()

        if not token:
            def unauthorized(request, context):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "missing bearer token")
            return grpc.unary_unary_rpc_method_handler(unauthorized)

        # Валидация токена (упрощённая): без сетевых JWKS-запросов
        try:
            options = {"verify_aud": bool(self.cfg.auth_audience)}
            decoded = jwt.decode(
                token,
                key=None if not self._jwks else jwt.PyJWKClient.from_jwks_data(self._jwks).get_signing_key_from_jwt(token).key,  # type: ignore
                algorithms=["RS256", "ES256", "EdDSA", "HS256"],
                audience=self.cfg.auth_audience if self.cfg.auth_audience else None,
                options=options,
            )
            iss = decoded.get("iss", "")
            if self.cfg.auth_issuers and iss not in self.cfg.auth_issuers:
                raise jwt.InvalidIssuerError(f"issuer not allowed: {iss}")
        except Exception as e:
            def unauthorized(request, context, err=str(e)):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, f"invalid token: {err}")
            return grpc.unary_unary_rpc_method_handler(unauthorized)

        # Если всё ок — передаём управление
        return await continuation(handler_call_details)


# =============================================================================
# Репозиторий (абстракция хранения). Для продакшна подключите БД.
# =============================================================================
class Repository:
    async def create_job(self, job: pb.SyntheticJob) -> pb.SyntheticJob: ...
    async def get_job(self, job_id: str) -> Optional[pb.SyntheticJob]: ...
    async def update_job(self, job: pb.SyntheticJob) -> pb.SyntheticJob: ...
    async def list_jobs(self, states: Iterable[pb.JobState], dataset_name: str, page: pb.PageRequest) -> Tuple[List[pb.SyntheticJob], pb.PageResponse]: ...
    async def cancel_job(self, job_id: str) -> Optional[pb.SyntheticJob]: ...


class InMemoryRepository(Repository):
    def __init__(self) -> None:
        self._jobs: Dict[str, pb.SyntheticJob] = {}

    async def create_job(self, job: pb.SyntheticJob) -> pb.SyntheticJob:
        self._jobs[job.id] = job
        return job

    async def get_job(self, job_id: str) -> Optional[pb.SyntheticJob]:
        return self._jobs.get(job_id)

    async def update_job(self, job: pb.SyntheticJob) -> pb.SyntheticJob:
        self._jobs[job.id] = job
        return job

    async def list_jobs(self, states: Iterable[pb.JobState], dataset_name: str, page: pb.PageRequest) -> Tuple[List[pb.SyntheticJob], pb.PageResponse]:
        filtered = list(self._jobs.values())
        if states:
            st = set(states)
            filtered = [j for j in filtered if j.state in st]
        if dataset_name:
            dn = dataset_name.lower()
            filtered = [j for j in filtered if j.dataset_name.lower() == dn]
        # простая пагинация index/size
        size = page.page_size or 20
        idx = page.page_index or 0
        start = idx * size
        end = start + size
        chunk = filtered[start:end]
        next_token = "" if end >= len(filtered) else str(idx + 1)
        resp = pb.PageResponse(page_size=len(chunk), next_page_token=next_token, page_index=idx, total_count=len(filtered))
        return chunk, resp

    async def cancel_job(self, job_id: str) -> Optional[pb.SyntheticJob]:
        job = self._jobs.get(job_id)
        if not job:
            return None
        if job.state in (pb.SUCCEEDED, pb.FAILED, pb.CANCELED):
            return job
        job.state = pb.CANCELED
        job.finished_at.GetCurrentTime()
        self._jobs[job_id] = job
        return job


# =============================================================================
# Реализация сервиса SyntheticService
# =============================================================================
class SyntheticService(pbg.SyntheticServiceServicer):
    def __init__(self, repo: Repository):
        self.repo = repo

    # --------------------------- Вспомогательные проверки ---------------------------
    @staticmethod
    def _validate_spec(spec: pb.SyntheticDatasetSpec) -> List[pb.ValidationError]:
        errors: List[pb.ValidationError] = []
        if not spec.dataset_name:
            errors.append(pb.ValidationError(code=pb.ValidationError.REQUIRED, path="$.dataset_name", message="dataset_name is required"))
        if spec.record_count <= 0:
            errors.append(pb.ValidationError(code=pb.ValidationError.OUT_OF_RANGE, path="$.record_count", message="record_count must be > 0"))
        if not spec.schema.fields:
            errors.append(pb.ValidationError(code=pb.ValidationError.REQUIRED, path="$.schema.fields", message="at least one field required"))
        # Пример доп. проверки ограничений
        for i, f in enumerate(spec.schema.fields):
            if f.type == pb.STRING and f.string.regex and f.constraints.pattern and f.string.regex != f.constraints.pattern:
                errors.append(pb.ValidationError(code=pb.ValidationError.CONFLICT,
                                                path=f"$.schema.fields[{i}]",
                                                message="string.regex conflicts with constraints.pattern"))
        return errors

    @staticmethod
    def _ts_now(ts) -> None:
        ts.GetCurrentTime()

    # --------------------------- RPC методы ---------------------------
    async def CreateGenerationJob(self, request: pb.GenerateDatasetRequest, context: aio.ServicerContext) -> pb.GenerateDatasetResponse:
        # Валидация
        errors = self._validate_spec(request.spec)
        if errors:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "spec validation failed")

        job_id = str(uuid.uuid4())
        job = pb.SyntheticJob(
            id=job_id,
            spec=request.spec,
            output=request.output or pb.OutputSpec(),
            streaming=request.streaming or pb.StreamingSpec(),
            schedule=request.schedule or pb.ScheduleSpec(),
            state=pb.PENDING,
            percent_complete=0.0,
            sink_uri="",
        )
        self._ts_now(job.created_at)
        self._ts_now(job.updated_at)

        await self.repo.create_job(job)

        # Демонстрация перевода в RUNNING (в реальном воркере/оркестраторе)
        job.state = pb.RUNNING
        self._ts_now(job.started_at)
        self._ts_now(job.updated_at)
        await self.repo.update_job(job)

        return pb.GenerateDatasetResponse(job=job)

    async def GetJob(self, request: pb.GetJobRequest, context: aio.ServicerContext) -> pb.GetJobResponse:
        job = await self.repo.get_job(request.id)
        if not job:
            context.abort(grpc.StatusCode.NOT_FOUND, "job not found")
        return pb.GetJobResponse(job=job)

    async def CancelJob(self, request: pb.CancelJobRequest, context: aio.ServicerContext) -> pb.CancelJobResponse:
        job = await self.repo.cancel_job(request.id)
        if not job:
            context.abort(grpc.StatusCode.NOT_FOUND, "job not found")
        return pb.CancelJobResponse(job=job)

    async def ListJobs(self, request: pb.ListJobsRequest, context: aio.ServicerContext) -> pb.ListJobsResponse:
        jobs, page = await self.repo.list_jobs(request.states, request.dataset_name, request.page or pb.PageRequest())
        return pb.ListJobsResponse(jobs=jobs, page=page)

    async def ValidateSpec(self, request: pb.ValidateSpecRequest, context: aio.ServicerContext) -> pb.ValidateSpecResponse:
        errs = self._validate_spec(request.spec)
        return pb.ValidateSpecResponse(valid=(len(errs) == 0), errors=errs)

    async def PreviewSchema(self, request: pb.PreviewSchemaRequest, context: aio.ServicerContext) -> pb.PreviewSchemaResponse:
        n = request.sample_records or 5
        samples = []
        rnd = random.Random(request.seed.seed if request.seed and request.seed.seed else None)
        for _ in range(n):
            data: Dict[str, Any] = {}
            for f in request.schema.fields:
                fname = f.name or "field"
                if f.type == pb.STRING:
                    data[fname] = f"default-{rnd.randint(1000, 9999)}"
                elif f.type == pb.INT64:
                    data[fname] = rnd.randint(0, 1000)
                elif f.type == pb.DOUBLE:
                    data[fname] = rnd.random()
                elif f.type == pb.BOOL:
                    data[fname] = rnd.choice([True, False])
                elif f.type == pb.TIMESTAMP:
                    # RFC3339 text — но в Struct кладём как строку
                    data[fname] = "2025-01-01T00:00:00Z"
                elif f.type == pb.CATEGORY:
                    data[fname] = "A"
                else:
                    data[fname] = None
            samples.append(pb.google_dot_protobuf_dot_struct__pb2.Struct(fields={k: pb.google_dot_protobuf_dot_struct__pb2.Value(string_value=str(v)) if not isinstance(v, (int, float, bool)) else (
                pb.google_dot_protobuf_dot_struct__pb2.Value(number_value=float(v)) if isinstance(v, (int, float))
                else pb.google_dot_protobuf_dot_struct__pb2.Value(bool_value=bool(v))
            ) for k, v in data.items()}))
        return pb.PreviewSchemaResponse(samples=samples)

    async def StreamRecords(self, request: pb.StreamRecordsRequest, context: aio.ServicerContext) -> AsyncIterator[pb.SyntheticRecord]:
        # Демонстрационный поток (настоящая генерация должна использовать ваш движок)
        min_rps = request.min_rps or 10
        max_duration = request.max_duration.seconds if request.max_duration.seconds else 5
        end_time = time.monotonic() + max_duration

        seq = 0
        while time.monotonic() < end_time:
            seq += 1
            # Простейший пример одной записи
            payload = pb.google_dot_protobuf_dot_struct__pb2.Struct(fields={
                "example": pb.google_dot_protobuf_dot_struct__pb2.Value(string_value=f"rec-{seq}")
            })
            rec = pb.SyntheticRecord(seq_no=seq, data=payload)
            rec.event_time.GetCurrentTime()
            rec.partition_key = str(uuid.uuid4())
            yield rec

            await asyncio.sleep(1.0 / max(1, min_rps))


# =============================================================================
# Инициализация и запуск сервера
# =============================================================================
async def serve(cfg: ServerConfig) -> None:
    interceptors: List[aio.ServerInterceptor] = [
        ExceptionInterceptor(),
        LoggingInterceptor(),
        AuthInterceptor(cfg),
    ]

    server = aio.server(
        interceptors=interceptors,
        options=_server_options(cfg),
        compression=cfg.compression,
    )

    # Регистрация сервисов
    repo = InMemoryRepository()
    pbg.add_SyntheticServiceServicer_to_server(SyntheticService(repo), server)

    # Health
    health_svc = None
    if cfg.health_enabled:
        health_svc = health.HealthServicer(experimental_non_blocking=True)
        health_pb2_grpc.add_HealthServicer_to_server(health_svc, server)
        # Изначально — SERVING после старта
        service_names = (
            pbg.SyntheticService.__name__,
            health.SERVICE_NAME,
        )
    else:
        service_names = (pbg.SyntheticService.__name__,)

    # Reflection
    if cfg.reflection_enabled:
        reflection.enable_server_reflection(service_names + (reflection.SERVICE_NAME,), server)

    # Адрес и креды
    bind_addr = f"{cfg.host}:{cfg.port}"
    if cfg.tls_enabled:
        if not (cfg.tls_cert_file and cfg.tls_key_file):
            raise RuntimeError("TLS enabled but cert/key not provided")
        with open(cfg.tls_cert_file, "rb") as f:
            cert = f.read()
        with open(cfg.tls_key_file, "rb") as f:
            key = f.read()
        if cfg.tls_ca_file:
            with open(cfg.tls_ca_file, "rb") as f:
                ca = f.read()
            creds = grpc.ssl_server_credentials(
                [(key, cert)],
                root_certificates=ca,
                require_client_auth=True,
            )
        else:
            creds = grpc.ssl_server_credentials([(key, cert)], require_client_auth=False)
        await server.add_secure_port(bind_addr, creds)
    else:
        await server.add_insecure_port(bind_addr)

    await server.start()
    LOGGER.info("gRPC server started on %s (tls=%s)", bind_addr, cfg.tls_enabled)

    if cfg.health_enabled and health_svc:
        # Отметить сервисы как SERVING
        await health_svc.set(service="", status=health_pb2.HealthCheckResponse.SERVING)
        await health_svc.set(pbg.SyntheticService.__name__, health_pb2.HealthCheckResponse.SERVING)

    # Грейсфул-шатдаун
    stop_event = asyncio.Event()

    def _signal_handler():
        LOGGER.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows
            pass

    await stop_event.wait()
    LOGGER.info("Shutting down gRPC server...")
    await server.stop(grace=cfg.drain_grace_seconds)
    LOGGER.info("gRPC server stopped")

# =============================================================================
# Entry point
# =============================================================================
def _setup_logging() -> None:
    level = os.getenv("GRPC_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")

def main() -> None:
    _setup_logging()
    cfg = ServerConfig()
    try:
        asyncio.run(serve(cfg))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
