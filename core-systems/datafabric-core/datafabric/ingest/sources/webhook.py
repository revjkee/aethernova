# datafabric-core/datafabric/ingest/sources/webhook.py
"""
Промышленный источник приёма событий через Webhook для конвейера ingestion.

Возможности:
- Безопасность: HMAC подпись (SHA256/512), обязательные заголовки, IP allowlist/denylist.
- Защита от дублей: Idempotency-Key (опционально Redis для хранения отпечатков).
- Ограничения: max body size, rate-limit per API key / per IP (токен‑бакет in‑memory).
- Наблюдаемость: структурированные логи, Prometheus‑метрики, OpenTelemetry‑трейсы.
- Валидация: pydantic v2 схема события, строгая нормализация заголовков.
- Очередь обработки: пользовательский async‑обработчик batch/single, с backpressure.
- Ответы: детерминированные JSON‑ответы, корректные коды статусов.
- Производство: изоляция зависимостей (все интеграции — опциональны).

Интеграция:
    from fastapi import FastAPI
    from datafabric.ingest.sources.webhook import WebhookIngest, webhook_router

    async def handle_records(records: list["WebhookRecord"]) -> None:
        # Пользовательская логика: запись в Kafka/NATS/БД и т.п.
        ...

    ingest = WebhookIngest(
        handler=handle_records,
        secret_provider=lambda key_id: b"super-secret",  # вернёт байтовый секрет по ключу
    )

    app = FastAPI()
    app.include_router(webhook_router(ingest), prefix="")

Заголовки:
- X-Webhook-Key-Id: идентификатор ключа (обязателен при HMAC)
- X-Webhook-Signature: hex подпись тела (HMAC SHA256|SHA512)
- X-Idempotency-Key: строка для защиты от повторов (опционально, рекомендуется)
- Content-Type: application/json

Формат подписи (по умолчанию):
    signature = hex(hmac.new(secret, body, hashlib.sha256).digest())
Можно сменить алгоритм на sha512 (см. конфиг).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

try:
    from pydantic import BaseModel, Field, ValidationError, field_validator
except Exception as ex:  # pragma: no cover
    raise RuntimeError("pydantic>=2 is required") from ex

# Опциональные зависимости
try:
    from prometheus_client import Counter, Histogram  # type: ignore
    PROM_ENABLED = True
except Exception:  # pragma: no cover
    PROM_ENABLED = False
    Counter = Histogram = None  # type: ignore

try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TRACER = None

# Redis (опционально) для идемпотентности
try:
    import redis.asyncio as redis  # type: ignore
    REDIS_AVAILABLE = True
except Exception:  # pragma: no cover
    REDIS_AVAILABLE = False
    redis = None  # type: ignore


# ============================
# Конфигурация
# ============================

class WebhookConfig(BaseModel):
    path: str = Field(default="/ingest/webhook")
    # Безопасность
    require_hmac: bool = Field(default=True)
    hmac_algo: str = Field(default="sha256")  # sha256|sha512
    # Поставщик секретов по ключу (см. WebhookIngest.secret_provider)
    key_id_header: str = Field(default="X-Webhook-Key-Id")
    sig_header: str = Field(default="X-Webhook-Signature")
    idemp_header: str = Field(default="X-Idempotency-Key")
    # Ограничения
    max_body_bytes: int = Field(default=1 * 1024 * 1024)   # 1 MiB
    max_headers_bytes: int = Field(default=16 * 1024)
    # Rate Limit
    rate_capacity: int = Field(default=20)   # burst
    rate_refill_per_sec: float = Field(default=10.0)
    # IP‑фильтры
    ip_allowlist: List[str] = Field(default_factory=list)  # CIDR или IP
    ip_denylist: List[str] = Field(default_factory=list)
    # Обработка
    batch_mode: bool = Field(default=False)  # если True, payload ожидается списком записей
    batch_max: int = Field(default=1000)
    # Идемпотентность
    idempotency_ttl_sec: int = Field(default=6 * 60 * 60)  # 6 часов
    # Ответ
    include_echo_hash: bool = Field(default=True)

    @field_validator("hmac_algo")
    @classmethod
    def _chk_algo(cls, v: str) -> str:
        v = v.lower()
        if v not in ("sha256", "sha512"):
            raise ValueError("hmac_algo must be sha256 or sha512")
        return v


# ============================
# Модели данных
# ============================

class WebhookRecord(BaseModel):
    # Минимальная универсальная схема записи
    source: str = Field(default="webhook")
    type: str = Field(min_length=1, max_length=128)
    ts: float = Field(default_factory=lambda: time.time())
    payload: Dict[str, Any] = Field(default_factory=dict)
    # Метаданные транспорта
    request_id: Optional[str] = None
    remote_ip: Optional[str] = None
    key_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class WebhookRequest(BaseModel):
    # Для batch_mode=False: единичная запись
    # Для batch_mode=True: массив записей
    record: Optional[WebhookRecord] = None
    records: Optional[List[WebhookRecord]] = None

    @field_validator("records")
    @classmethod
    def _non_empty(cls, v):
        if v is not None and len(v) == 0:
            raise ValueError("records must be non-empty when provided")
        return v


# ============================
# Метрики
# ============================

def _metrics():
    if not PROM_ENABLED:
        return {}
    labels = ("path",)
    return {
        "requests": Counter("datafabric_webhook_requests_total", "Принятые запросы", labels),
        "accepted": Counter("datafabric_webhook_accepted_total", "Принятые события", labels),
        "rejected": Counter("datafabric_webhook_rejected_total", "Отклонённые запросы", labels),
        "duplicates": Counter("datafabric_webhook_duplicates_total", "Дубликаты по идемпотентности", labels),
        "proc_time": Histogram("datafabric_webhook_processing_seconds", "Время обработки запроса"),
        "batch_size": Histogram("datafabric_webhook_batch_size", "Размер батча", buckets=(1, 10, 50, 100, 250, 500, 1000)),
        "body_size": Histogram("datafabric_webhook_body_bytes", "Размер тела запроса", buckets=(256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304)),
    }


# ============================
# Rate Limiter (token bucket)
# ============================

@dataclass
class _TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float = 0.0
    last_refill: float = field(default_factory=lambda: time.time())

    def consume(self, amount: float = 1.0) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


# ============================
# Утилиты безопасности
# ============================

def _client_ip(request: Request) -> str:
    # Учитываем X-Forwarded-For, если стоит за LB/ingress
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"

def _ip_in_cidrs(ip: str, cidrs: Sequence[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for cidr in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr, strict=False):
                return True
        except Exception:
            continue
    return False

def _hmac_hex(secret: bytes, body: bytes, algo: str) -> str:
    if algo == "sha512":
        digest = hmac.new(secret, body, hashlib.sha512).hexdigest()
    else:
        digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return digest


# ============================
# Основной класс
# ============================

HandlerFunc = Callable[[List[WebhookRecord]], Awaitable[None]]
SecretProvider = Callable[[str], Optional[bytes]]

@dataclass
class WebhookIngest:
    handler: HandlerFunc
    config: WebhookConfig = field(default_factory=WebhookConfig)
    secret_provider: Optional[SecretProvider] = None
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("datafabric.ingest.webhook"))
    redis_client: Optional["redis.Redis"] = None  # type: ignore

    # внутреннее
    _metrics: Dict[str, Any] = field(init=False, default_factory=dict)
    _rate_buckets: Dict[str, _TokenBucket] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.logger.setLevel(logging.INFO)
        if PROM_ENABLED:
            self._metrics = _metrics()

    # -------- Публичное API --------

    async def handle(self, request: Request, body: bytes,
                     x_key_id: Optional[str],
                     x_signature: Optional[str],
                     x_idempotency: Optional[str]) -> JSONResponse:
        path = self.config.path
        if PROM_ENABLED:
            try:
                self._metrics["requests"].labels(path).inc()
                self._metrics["body_size"].observe(len(body))
            except Exception:
                pass

        # 1) Ограничения размеров
        if len(body) > self.config.max_body_bytes:
            await self._reject(path, reason="body_too_large", code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="body too large")

        # 2) IP фильтры
        rip = _client_ip(request)
        if self.config.ip_denylist and _ip_in_cidrs(rip, self.config.ip_denylist):
            await self._reject(path, reason="ip_denied", code=status.HTTP_403_FORBIDDEN)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        if self.config.ip_allowlist and not _ip_in_cidrs(rip, self.config.ip_allowlist):
            await self._reject(path, reason="ip_not_allowed", code=status.HTTP_403_FORBIDDEN)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")

        # 3) Rate limit (per key/ip)
        bucket_key = f"{x_key_id or 'anon'}:{rip}"
        bucket = self._rate_buckets.get(bucket_key)
        if not bucket:
            bucket = self._rate_buckets[bucket_key] = _TokenBucket(
                capacity=self.config.rate_capacity,
                refill_per_sec=self.config.rate_refill_per_sec
            )
        if not bucket.consume(1.0):
            await self._reject(path, reason="rate_limited", code=status.HTTP_429_TOO_MANY_REQUESTS)
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limited")

        # 4) HMAC проверка
        if self.config.require_hmac:
            if not x_key_id or not x_signature:
                await self._reject(path, reason="missing_signature", code=status.HTTP_401_UNAUTHORIZED)
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="signature required")
            secret = await self._get_secret(x_key_id)
            if not secret:
                await self._reject(path, reason="unknown_key", code=status.HTTP_401_UNAUTHORIZED)
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unknown key")
            try:
                calc = _hmac_hex(secret, body, self.config.hmac_algo)
            except Exception:
                await self._reject(path, reason="signature_error", code=status.HTTP_401_UNAUTHORIZED)
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="signature error")
            if not hmac.compare_digest(calc, x_signature.strip().lower()):
                await self._reject(path, reason="invalid_signature", code=status.HTTP_401_UNAUTHORIZED)
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature")

        # 5) Идемпотентность
        if x_idempotency and await self._is_duplicate(x_idempotency):
            if PROM_ENABLED:
                try:
                    self._metrics["duplicates"].labels(path).inc()
                except Exception:
                    pass
            # детерминированный ответ при дублировании
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=self._ok_response(echo=body)
            )
        if x_idempotency:
            await self._remember_idempotency(x_idempotency)

        # 6) Парсинг/валидация
        try:
            obj = json.loads(body.decode("utf-8"))
        except Exception:
            await self._reject(path, reason="invalid_json", code=status.HTTP_400_BAD_REQUEST)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid json")

        # Разрешаем как сырой объект, так и обёртку WebhookRequest
        records: List[WebhookRecord]
        try:
            if self.config.batch_mode:
                # ожидаем список объектов
                if isinstance(obj, list):
                    records = [WebhookRecord(**r) if isinstance(r, dict) else WebhookRecord(payload={"raw": r}) for r in obj]
                else:
                    req = WebhookRequest.model_validate(obj)
                    if not req.records:
                        raise ValueError("records required in batch mode")
                    records = req.records
            else:
                if isinstance(obj, dict) and all(k in obj for k in ("type", "payload")):
                    records = [WebhookRecord(**obj)]
                else:
                    req = WebhookRequest.model_validate({"record": obj})
                    if not req.record:
                        raise ValueError("record required")
                    records = [req.record]
        except (ValidationError, ValueError) as ex:
            await self._reject(path, reason=f"validation_error:{ex}", code=status.HTTP_422_UNPROCESSABLE_ENTITY)
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="validation error")

        # 7) Нормализуем метаданные транспорта
        req_id = request.headers.get("x-request-id")
        for r in records:
            r.request_id = req_id
            r.remote_ip = rip
            r.key_id = x_key_id
            r.idempotency_key = x_idempotency

        # 8) Ограничения батча
        if self.config.batch_mode and len(records) > self.config.batch_max:
            await self._reject(path, reason="batch_too_large", code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="batch too large")

        if PROM_ENABLED:
            try:
                self._metrics["batch_size"].observe(len(records))
            except Exception:
                pass

        # 9) Обработка (асинхронный handler) с трейсом и метриками
        t0 = time.perf_counter()
        try:
            if _TRACER:
                with _TRACER.start_as_current_span("webhook.handle"):
                    await self.handler(records)
            else:
                await self.handler(records)
        except Exception as ex:
            await self._reject(path, reason=f"handler_failed:{ex}", code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="handler failed")
        finally:
            if PROM_ENABLED:
                try:
                    self._metrics["proc_time"].observe(time.perf_counter() - t0)
                except Exception:
                    pass

        # 10) Успех
        if PROM_ENABLED:
            try:
                self._metrics["accepted"].labels(path).inc(len(records))
            except Exception:
                pass
        return JSONResponse(status_code=status.HTTP_200_OK, content=self._ok_response(echo=body))

    # -------- Вспомогательные --------

    async def _get_secret(self, key_id: str) -> Optional[bytes]:
        if self.secret_provider:
            try:
                sec = self.secret_provider(key_id)
                return sec if isinstance(sec, (bytes, bytearray)) else (sec.encode("utf-8") if isinstance(sec, str) else None)
            except Exception:
                return None
        # fallback: из переменных окружения WEBHOOK_KEY_<KEYID>
        env_key = f"WEBHOOK_KEY_{key_id}"
        val = os.getenv(env_key)
        return val.encode("utf-8") if val else None

    async def _is_duplicate(self, key: str) -> bool:
        if self.redis_client and REDIS_AVAILABLE:
            try:
                # SETNX + TTL
                return not await self.redis_client.set(name=f"idemp:{key}", value=1, nx=True, ex=self.config.idempotency_ttl_sec)
            except Exception:
                # В случае ошибки Redis — не блокируем поток, допускаем потенциальный дубликат
                return False
        # In‑memory best‑effort LRU (упрощённо): не храним, чтобы не раздувать память — пропускаем
        return False

    async def _remember_idempotency(self, key: str) -> None:
        if self.redis_client and REDIS_AVAILABLE:
            try:
                await self.redis_client.set(name=f"idemp:{key}", value=1, ex=self.config.idempotency_ttl_sec)
            except Exception:
                pass

    async def _reject(self, path: str, reason: str, code: int) -> None:
        self.logger.warning("webhook_reject", extra={"path": path, "reason": reason, "code": code})
        if PROM_ENABLED:
            try:
                self._metrics["rejected"].labels(path).inc()
            except Exception:
                pass

    def _ok_response(self, echo: bytes) -> Dict[str, Any]:
        out: Dict[str, Any] = {"status": "ok"}
        if self.config.include_echo_hash:
            out["echo_sha256"] = hashlib.sha256(echo).hexdigest()
        return out


# ============================
# FastAPI router
# ============================

def webhook_router(ingest: WebhookIngest) -> APIRouter:
    router = APIRouter()

    @router.post(ingest.config.path)
    async def _webhook_endpoint(
        request: Request,
        response: Response,
        x_key_id: Optional[str] = Header(default=None, alias=ingest.config.key_id_header),
        x_signature: Optional[str] = Header(default=None, alias=ingest.config.sig_header),
        x_idempotency: Optional[str] = Header(default=None, alias=ingest.config.idemp_header),
    ):
        # Читаем тело один раз, контролируем max size в ingest.handle
        body = await request.body()
        return await ingest.handle(
            request=request,
            body=body,
            x_key_id=x_key_id,
            x_signature=(x_signature.lower() if isinstance(x_signature, str) else x_signature),
            x_idempotency=x_idempotency,
        )

    return router


# ============================
# Пример провайдера секрета (опционально)
# ============================

def env_secret_provider(key_id: str) -> Optional[bytes]:
    """
    Альтернативный SecretProvider: читает WEBHOOK_KEY_<KEYID> из окружения.
    """
    val = os.getenv(f"WEBHOOK_KEY_{key_id}")
    return val.encode("utf-8") if val else None
