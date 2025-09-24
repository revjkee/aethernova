# -*- coding: utf-8 -*-
"""
Домейн-сервис якорения (anchoring) для ledger-core.

Возможности:
- Идемпотентное создание анкера с локальным сохранением и вызовом внешнего Blockchain Gateway.
- Подтягивание статуса ончейн-транзакции до подтверждённого состояния (confirmations >= threshold).
- Верификация меркл-доказательств (простая проверка пути + алгоритма).
- Политики надёжности: тайм-ауты, экспоненциальные ретраи, джиттер, полуоткрытый circuit-breaker.
- Интеграция с аудитом/метриками через переданные хуки.
- Минимальные зависимости (httpx — как в остальном проекте).

Интеграция:
- Репозиторий предоставляет транзакции БД и CRUD для Anchor/Proof.
- HTTP-клиент к Blockchain Gateway из ops/terraform/modules/blockchain_gateway.
- Сервис асинхронный, совместим с FastAPI/BackgroundTasks или отдельным воркером.

© MIT
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Protocol, Tuple

import httpx
from pydantic import BaseModel, Field, validator


# ============================== Доменные модели ==============================

class Proof(BaseModel):
    type: str = Field(..., description="merkle|snark|stark")
    algorithm: str = Field(..., description="sha256|keccak256|... для merkle")
    data: bytes = Field(..., description="Сырые байты доказательства (формат зависит от типа)")
    path: List[bytes] = Field(default_factory=list, description="Меркл путь (если применимо)")

class Metadata(BaseModel):
    schema_version: str = Field(default="v1")
    created_by: str
    created_at: datetime
    updated_at: datetime
    tags: Dict[str, str] = Field(default_factory=dict)

class AnchorStatus(str):
    PENDING = "pending"
    BROADCASTED = "broadcasted"
    CONFIRMED = "confirmed"
    FAILED = "failed"

class Anchor(BaseModel):
    anchor_id: str
    root_hash: bytes
    block_height: Optional[int] = None
    chain_id: Optional[str] = None
    tx_id: Optional[str] = None
    status: str = Field(default=AnchorStatus.PENDING)
    confirmations: int = Field(default=0)
    metadata: Metadata

    @validator("metadata", pre=True)
    def _coerce_metadata(cls, v):
        if isinstance(v, dict):
            return Metadata(**v)
        return v


# ============================== Контракты порта/адаптеров ==============================

class Tx(Protocol):
    """Транзакция БД (Unit-of-Work)."""
    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...

class AnchorRepository(Protocol):
    """Репозиторий якорей (хранение в БД)."""
    async def begin(self) -> Tx: ...
    async def get_by_id(self, anchor_id: str) -> Optional[Anchor]: ...
    async def get_by_idempotency_key(self, idem_key: str) -> Optional[Anchor]: ...
    async def save_new(self, tx: Tx, anchor: Anchor, idempotency_key: Optional[str]) -> None: ...
    async def mark_broadcasted(self, tx: Tx, anchor_id: str, tx_id: str, block_height: Optional[int]) -> None: ...
    async def mark_confirmed(self, tx: Tx, anchor_id: str, confirmations: int, block_height: int) -> None: ...
    async def mark_failed(self, tx: Tx, anchor_id: str, reason: str) -> None: ...

class AuditHook(Protocol):
    def __call__(self, event: str, payload: Dict[str, Any]) -> None: ...

class MetricsHook(Protocol):
    def __call__(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None: ...

class AuthorizationProvider(Protocol):
    """Источник подписи/токенов для вызова шлюза."""
    async def get_headers(self) -> Dict[str, str]: ...


# ============================== Конфигурация и политика надёжности ==============================

@dataclass
class AnchoringConfig:
    gateway_base_url: str
    # Тайм-ауты и ретраи
    http_timeout_s: float = 3.5
    max_retries: int = 4
    backoff_base_ms: int = 100
    backoff_max_ms: int = 2000
    # Подтверждения сети
    confirm_threshold: int = 6
    # Circuit breaker
    cb_failure_threshold: int = 5          # столько подряд ошибок, чтобы "врубить" breaker
    cb_reset_timeout_s: int = 30           # через сколько секунд пробуем полузакрыть
    # Идемпотентность
    allow_idempotency: bool = True
    # Верификация хэша
    hash_algorithm: str = "sha256"         # алгоритм для локальной проверки меркл-веток
    # Фоновые задачи
    confirm_poll_interval_s: float = 5.0
    confirm_poll_jitter_s: float = 1.0


# ============================== Исключения ==============================

class AnchoringError(Exception): ...
class IdempotencyConflict(AnchoringError): ...
class GatewayError(AnchoringError): ...
class VerificationError(AnchoringError): ...


# ============================== Вспомогательные утилиты ==============================

def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)

def _jittered_backoff(attempt: int, base_ms: int, cap_ms: int) -> float:
    exp = min(cap_ms, base_ms * (2 ** attempt))
    return (exp / 1000.0) * (0.5 + random.random())  # 0.5..1.5 * exp

def _hex(b: Optional[bytes]) -> Optional[str]:
    return b.hex() if b is not None else None

def _short(s: Optional[str], n: int = 12) -> str:
    if not s:
        return ""
    return s[:n]


# ============================== Клиент шлюза ==============================

class BlockchainGatewayClient:
    """
    Тонкий клиент к нашему API Gateway:
      POST /v1/anchor        -> создает анкер, возвращает {anchor_id, tx_id, block_height?}
      GET  /v1/anchor/{id}   -> статус анкера {status, tx_id, block_height, confirmations}
    """
    def __init__(self, base_url: str, auth: AuthorizationProvider, timeout_s: float):
        self._base = base_url.rstrip("/")
        self._auth = auth
        self._timeout = timeout_s

    async def create_anchor(self, *, root_hash: bytes, chain_id: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        headers = {"content-type": "application/json"}
        headers.update(await self._auth.get_headers())
        payload = {
            "root_hash": _hex(root_hash),
            "chain_id": chain_id,
            "metadata": metadata,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.post(f"{self._base}/v1/anchor", json=payload, headers=headers)
            if r.status_code >= 500:
                raise GatewayError(f"gateway 5xx: {r.status_code}")
            if r.status_code not in (200, 201):
                # 409/400/403 и пр. транслируем как GatewayError с телом
                raise GatewayError(f"gateway error {r.status_code}: {r.text}")
            return r.json()

    async def get_anchor(self, *, anchor_id: str) -> Dict[str, Any]:
        headers = {}
        headers.update(await self._auth.get_headers())
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            r = await client.get(f"{self._base}/v1/anchor/{anchor_id}", headers=headers)
            if r.status_code >= 500:
                raise GatewayError(f"gateway 5xx: {r.status_code}")
            if r.status_code == 404:
                return {"status": "not_found"}
            if r.status_code != 200:
                raise GatewayError(f"gateway error {r.status_code}: {r.text}")
            return r.json()


# ============================== Circuit Breaker (простой) ==============================

class CircuitBreaker:
    def __init__(self, failure_threshold: int, reset_timeout_s: int):
        self._threshold = failure_threshold
        self._reset_s = reset_timeout_s
        self._fails = 0
        self._opened_at: Optional[float] = None

    def record_success(self) -> None:
        self._fails = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._fails += 1
        if self._fails >= self._threshold and self._opened_at is None:
            self._opened_at = time.time()

    def can_pass(self) -> bool:
        if self._opened_at is None:
            return True
        # полузакрываем через reset_timeout
        return (time.time() - self._opened_at) >= self._reset_s


# ============================== Сервис якорения ==============================

class AnchoringService:
    """
    Домейн-сервис. Не знает о фреймворке, работает через порты:
    - repo: AnchorRepository
    - gateway: BlockchainGatewayClient
    - audit/metrics: функции-хуки
    """
    def __init__(
        self,
        repo: AnchorRepository,
        gateway: BlockchainGatewayClient,
        cfg: AnchoringConfig,
        audit: Optional[AuditHook] = None,
        metrics: Optional[MetricsHook] = None,
    ):
        self._repo = repo
        self._gw = gateway
        self._cfg = cfg
        self._audit = audit or (lambda e, p: None)
        self._metrics = metrics or (lambda n, v, t=None: None)
        self._cb = CircuitBreaker(cfg.cb_failure_threshold, cfg.cb_reset_timeout_s)

    # ---------- Публичные операции ----------

    async def anchor_data(
        self,
        *,
        root_hash: bytes,
        chain_id: str,
        tags: Optional[Dict[str, str]] = None,
        created_by: str,
        idempotency_key: Optional[str] = None,
    ) -> Anchor:
        """
        Идемпотентно создаёт анкер локально и транслирует запрос во внешний шлюз.
        Возвращает агрегат Anchor с актуальным статусом (pending|broadcasted|confirmed).
        """
        if idempotency_key and self._cfg.allow_idempotency:
            existing = await self._repo.get_by_idempotency_key(idempotency_key)
            if existing:
                self._metrics("anchoring.idempotent_hit", 1.0, {"status": existing.status})
                return existing

        meta = Metadata(
            schema_version="v1",
            created_by=created_by,
            created_at=_utcnow(),
            updated_at=_utcnow(),
            tags=tags or {},
        )
        anchor = Anchor(
            anchor_id=self._derive_anchor_id(root_hash),
            root_hash=root_hash,
            chain_id=chain_id,
            status=AnchorStatus.PENDING,
            metadata=meta,
        )

        tx = await self._repo.begin()
        try:
            await self._repo.save_new(tx, anchor, idempotency_key if self._cfg.allow_idempotency else None)
            await tx.commit()
        except Exception as e:
            await tx.rollback()
            # возможен конфликт идемпотентности на БД-уровне
            raise IdempotencyConflict(str(e)) if idempotency_key else AnchoringError(str(e))

        self._audit("anchor.created", {"anchor_id": anchor.anchor_id, "chain_id": chain_id, "root_hash": _hex(root_hash)})

        # Вызов шлюза с ретраями/брейкером
        gw_resp = await self._with_retries(self._gw.create_anchor, root_hash=root_hash, chain_id=chain_id, metadata=meta.dict())
        tx = await self._repo.begin()
        try:
            await self._repo.mark_broadcasted(tx, anchor.anchor_id, gw_resp.get("tx_id"), gw_resp.get("block_height"))
            await tx.commit()
            anchor.tx_id = gw_resp.get("tx_id")
            anchor.block_height = gw_resp.get("block_height")
            anchor.status = AnchorStatus.BROADCASTED
            self._metrics("anchoring.broadcasted", 1.0, {"chain": chain_id})
        except Exception as e:
            await tx.rollback()
            raise AnchoringError(f"failed to mark broadcasted: {e}")

        # Фоновое подтверждение (не блокируем ответ)
        asyncio.create_task(self._poll_until_confirmed(anchor.anchor_id))

        return anchor

    async def get_anchor(self, anchor_id: str) -> Optional[Anchor]:
        return await self._repo.get_by_id(anchor_id)

    async def verify_proof(self, *, root_hash: bytes, proof: Proof) -> bool:
        """
        Минимальная локальная верификация: меркл-доказательство по алгоритму hash_algorithm.
        """
        if proof.type.lower() != "merkle":
            # Для SNARK/STARK предполагается внешняя проверка/верификатор
            raise VerificationError("unsupported proof type for local verification")

        algo = self._cfg.hash_algorithm.lower()
        if algo not in ("sha256", "keccak256"):
            raise VerificationError("unsupported hash algorithm")

        def _h(x: bytes) -> bytes:
            if algo == "sha256":
                return hashlib.sha256(x).digest()
            # Прим.: keccak256 доступен через external lib; упрощённая заглушка
            raise VerificationError("keccak256 not implemented in local verifier")

        # Верификация: сводим путь к корню и сравниваем
        h = proof.data  # лист
        for sibling in proof.path:
            # упорядочивание: лексикографически, если не храните флагов сторон
            pair = b"".join(sorted([h, sibling]))
            h = _h(pair)
        return h == root_hash

    # ---------- Внутренние операции ----------

    async def _poll_until_confirmed(self, anchor_id: str) -> None:
        """
        Пуллим шлюз до достижения порога подтверждений. Обновляем запись, аудируем.
        """
        try:
            while True:
                try:
                    data = await self._with_retries(self._gw.get_anchor, anchor_id=anchor_id)
                except GatewayError as e:
                    # логируем и продолжаем (breaker/ретраи уже были)
                    self._metrics("anchoring.poll.error", 1.0, {"reason": "gateway"})
                    await asyncio.sleep(self._cfg.confirm_poll_interval_s)
                    continue

                status = data.get("status")
                tx_id = data.get("tx_id")
                block_height = data.get("block_height")
                conf = int(data.get("confirmations", 0))

                if status == "not_found":
                    # Случай временной рассинхронизации шлюза
                    await asyncio.sleep(2.0)
                    continue

                if conf >= self._cfg.confirm_threshold:
                    tx = await self._repo.begin()
                    try:
                        await self._repo.mark_confirmed(tx, anchor_id, conf, block_height or 0)
                        await tx.commit()
                        self._audit("anchor.confirmed", {"anchor_id": anchor_id, "tx_id": tx_id, "confirmations": conf})
                        self._metrics("anchoring.confirmed", 1.0, {})
                    except Exception:
                        await tx.rollback()
                    break

                # Ещё не подтверждено — ждём
                delay = self._cfg.confirm_poll_interval_s + random.random() * self._cfg.confirm_poll_jitter_s
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            return
        except Exception:
            # не роняем процесс
            self._metrics("anchoring.poll.crash", 1.0, {})

    async def _with_retries(self, func: Callable[..., Awaitable[Dict[str, Any]]], **kwargs) -> Dict[str, Any]:
        """
        Унифицированные ретраи + circuit breaker.
        """
        attempt = 0
        while True:
            if not self._cb.can_pass():
                raise GatewayError("circuit breaker open")

            try:
                resp = await func(**kwargs)
                self._cb.record_success()
                return resp
            except (httpx.TimeoutException, httpx.NetworkError, GatewayError) as e:
                self._cb.record_failure()
                if attempt >= self._cfg.max_retries:
                    raise GatewayError(f"exceeded retries: {e}") from e
                attempt += 1
                sleep = _jittered_backoff(attempt, self._cfg.backoff_base_ms, self._cfg.backoff_max_ms)
                self._metrics("anchoring.retry", 1.0, {"attempt": str(attempt)})
                await asyncio.sleep(sleep)


    # ---------- Вспомогательное ----------

    def _derive_anchor_id(self, root_hash: bytes) -> str:
        """
        Генерация детерминированного идентификатора якоря (аналог UUIDv5).
        """
        ns = b"ledger-core.anchor.v1"
        h = hashlib.sha256(ns + root_hash).hexdigest()
        # компактный id с префиксом
        return f"anc_{h[:32]}"


# ============================== Базовый провайдер авторизации ==============================

class StaticBearerAuth(AuthorizationProvider):
    """
    Простой поставщик заголовков авторизации (например, сервисный токен).
    Для продакшена предпочтительно OIDC/JWT c ротацией.
    """
    def __init__(self, token: str):
        self._token = token

    async def get_headers(self) -> Dict[str, str]:
        return {"authorization": f"Bearer {self._token}"}


# ============================== Фабрика сервиса (удобство интеграции) ==============================

def make_anchoring_service(
    *,
    repo: AnchorRepository,
    gateway_url: str,
    auth_provider: AuthorizationProvider,
    config: Optional[AnchoringConfig] = None,
    audit_hook: Optional[AuditHook] = None,
    metrics_hook: Optional[MetricsHook] = None,
) -> AnchoringService:
    cfg = config or AnchoringConfig(gateway_base_url=gateway_url)
    gw = BlockchainGatewayClient(base_url=cfg.gateway_base_url, auth=auth_provider, timeout_s=cfg.http_timeout_s)
    return AnchoringService(repo=repo, gateway=gw, cfg=cffix(cfg), audit=audit_hook, metrics=metrics_hook)


def cffix(cfg: AnchoringConfig) -> AnchoringConfig:
    """Небольшая нормализация конфигурации (границы и т.п.)."""
    if cfg.max_retries < 0:
        cfg.max_retries = 0
    if cfg.cb_failure_threshold < 1:
        cfg.cb_failure_threshold = 1
    if cfg.backoff_base_ms < 10:
        cfg.backoff_base_ms = 10
    if cfg.backoff_max_ms < cfg.backoff_base_ms:
        cfg.backoff_max_ms = cfg.backoff_base_ms
    return cfg
