# ledger-core/ledger/anchoring/anchor_builder.py
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, runtime_checkable
from uuid import UUID, uuid4

try:
    # Pydantic v2
    from pydantic import BaseModel, Field, ConfigDict, field_validator
except Exception:  # pragma: no cover
    from pydantic import BaseModel, Field, validator as field_validator  # type: ignore
    class ConfigDict:  # type: ignore
        pass

logger = logging.getLogger("ledger.anchoring.anchor_builder")

# ======================================================================================
# Доменные модели
# ======================================================================================

class AnchorStatus(str, Enum):
    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    FINALIZED = "FINALIZED"
    FAILED = "FAILED"
    DUPLICATE = "DUPLICATE"


class AnchorNetwork(str, Enum):
    BTC = "BTC"
    ETH = "ETH"
    TON = "TON"
    FILECOIN = "FILECOIN"
    ARWEAVE = "ARWEAVE"
    OFFCHAIN = "OFFCHAIN"  # например, S3/MinIO с публичным отпечатком


@dataclass(frozen=True)
class MerkleNode:
    hash: bytes
    left: Optional["MerkleNode"] = None
    right: Optional["MerkleNode"] = None


class CanonicalEncoder:
    """
    Каноническая сериализация словарей/структур для детерминированного хэширования.
    """
    @staticmethod
    def dumps(data: Any) -> bytes:
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=CanonicalEncoder._default
        ).encode("utf-8")

    @staticmethod
    def _default(obj: Any):
        if isinstance(obj, (datetime,)):
            # RFC3339/ISO8601 в UTC с Z-суффиксом
            return obj.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        if isinstance(obj, UUID):
            return str(obj)
        return str(obj)


# ======================================================================================
# DTO
# ======================================================================================

class AnchorRequest(BaseModel):
    """
    Запрос на построение якоря за фиксированное окно времени/версию/снапшот.
    По одному из идентификаторов: snapshot_id или (period_start, period_end).
    """
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., min_length=1, max_length=200)
    network: AnchorNetwork
    snapshot_id: Optional[UUID] = None
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    # Опциональная соль для доменного разделения якорей разных инсталляций
    domain_salt_hex: Optional[str] = Field(default=None, min_length=0, max_length=128)
    # Пользовательские метаданные
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("period_start", "period_end")
    @classmethod
    def _to_utc(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is None:
            return v
        if v.tzinfo is None:
            # считаем, что время в UTC
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class AnchorRecord(BaseModel):
    """
    Итем якоря в нашей БД.
    """
    model_config = ConfigDict(extra="forbid")

    id: UUID
    request_id: str
    network: AnchorNetwork
    status: AnchorStatus
    anchor_key: str                      # уникальный ключ идемпотентности (см. AnchorKeyBuilder)
    merkle_root_hex: str
    leaf_count: int
    snapshot_id: Optional[UUID] = None
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    prev_anchor_hash_hex: Optional[str] = None
    anchor_payload_cid: Optional[str] = None  # например, CID/IPFS/Arweave-id
    submit_tx_id: Optional[str] = None
    submit_block_ref: Optional[str] = None
    created_at: datetime
    submitted_at: Optional[datetime] = None
    finalized_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    signature_hex: Optional[str] = None  # подпись на payload


class MerkleProof(BaseModel):
    """
    Данные для проверки включения.
    """
    model_config = ConfigDict(extra="forbid")

    root_hex: str
    leaf_hex: str
    path: List[str]  # список соседних узлов (hex) от листа к корню
    indexes: List[int]  # 0 - left, 1 - right


# ======================================================================================
# Контракты (интерфейсы/протоколы)
# ======================================================================================

@runtime_checkable
class AnchorUnitOfWork(Protocol):
    """
    UoW для атомарной записи якоря и взаимодействия с репозиториями.
    """
    async def __aenter__(self) -> "AnchorUnitOfWork": ...
    async def __aexit__(self, exc_type, exc, tb): ...
    async def commit(self): ...
    async def rollback(self): ...

    # Репозитории
    @property
    def anchors(self) -> "AnchorRepository": ...
    @property
    def snapshots(self) -> "SnapshotRepository": ...
    @property
    def outbox(self) -> "OutboxRepository": ...


@runtime_checkable
class AnchorRepository(Protocol):
    async def get_by_anchor_key(self, anchor_key: str) -> Optional[AnchorRecord]: ...
    async def insert(self, record: AnchorRecord) -> None: ...
    async def mark_submitted(self, anchor_id: UUID, tx_id: str, block_ref: Optional[str]) -> None: ...
    async def mark_finalized(self, anchor_id: UUID, block_ref: Optional[str]) -> None: ...
    async def mark_failed(self, anchor_id: UUID, reason: str) -> None: ...
    async def get_latest_for_network(self, network: AnchorNetwork) -> Optional[AnchorRecord]: ...


@runtime_checkable
class SnapshotRepository(Protocol):
    """
    Источник листьев для Merkle.
    Возвращает сериализованные (!) «листья» (байты или hex), устойчивые к переигрыванию.
    """
    async def get_leaves_for_snapshot(self, snapshot_id: UUID) -> List[bytes]: ...
    async def get_leaves_for_period(self, start: datetime, end: datetime) -> List[bytes]: ...


@runtime_checkable
class OutboxRepository(Protocol):
    async def enqueue(self, topic: str, payload: Dict[str, Any]) -> None: ...


@runtime_checkable
class AnchorNetworkClient(Protocol):
    """
    Клиент отправки якоря в конкретную сеть (адаптер).
    """
    async def submit_payload(self, network: AnchorNetwork, payload: bytes, *, memo: str | None = None) -> Tuple[str, Optional[str]]:
        """
        Отправка якоря. Возвращает (tx_id, block_ref|None).
        payload обычно компактный: merkle_root + метаданные, либо CID документа.
        """
        ...

    async def is_finalized(self, network: AnchorNetwork, tx_id: str) -> Tuple[bool, Optional[str]]:
        """
        Проверка финализации (например, достаточное подтверждение).
        Возвращает (finalized?, block_ref|None).
        """
        ...


@runtime_checkable
class Signer(Protocol):
    """
    Подписываем payload перед отправкой.
    """
    def sign(self, data: bytes) -> bytes: ...
    def public_key_hex(self) -> str: ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


# ======================================================================================
# Вспомогательные утилиты
# ======================================================================================

class AnchorKeyBuilder:
    """
    Строим стабильный ключ идемпотентности для якоря.
    """
    @staticmethod
    def build(
        *,
        network: AnchorNetwork,
        snapshot_id: Optional[UUID],
        period_start: Optional[datetime],
        period_end: Optional[datetime],
        domain_salt_hex: Optional[str],
    ) -> str:
        body = {
            "network": network.value,
            "snapshot_id": str(snapshot_id) if snapshot_id else None,
            "period_start": period_start.isoformat().replace("+00:00", "Z") if period_start else None,
            "period_end": period_end.isoformat().replace("+00:00", "Z") if period_end else None,
            "salt": domain_salt_hex or "",
        }
        return hashlib.sha256(CanonicalEncoder.dumps(body)).hexdigest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hex(b: bytes) -> str:
    return b.hex()


def _concat(a: bytes, b: bytes) -> bytes:
    return a + b


def _merkle_pair(h1: bytes, h2: bytes) -> bytes:
    # Упорядочиваем левый/правый детерминированно: лексикографически
    if h1 <= h2:
        left, right = h1, h2
    else:
        left, right = h2, h1
    return _sha256(_concat(left, right))


def build_merkle_root(leaves: Sequence[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    """
    Строим корень и уровни (для последующего построения доказательств).
    Если листьев нет — используем пустой корень от hash(b"").
    """
    if not leaves:
        empty = _sha256(b"")
        return empty, [[empty]]

    level: List[bytes] = [(_sha256(l) if len(l) != 32 else l) for l in leaves]
    levels: List[List[bytes]] = [level]

    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_merkle_pair(level[i], level[i+1]))
            else:
                # дубль последнего (common practice)
                nxt.append(_merkle_pair(level[i], level[i]))
        levels.append(nxt)
        level = nxt

    return level[0], levels


def build_merkle_proof(levels: List[List[bytes]], leaf_index: int) -> MerkleProof:
    """
    Строим путь доказательства для листа с индексом leaf_index.
    """
    if not levels:
        raise ValueError("Empty merkle levels")
    path: List[str] = []
    indexes: List[int] = []

    idx = leaf_index
    for level in levels[:-1]:
        if idx % 2 == 0:
            # правый сосед либо дубль
            neighbor = level[idx + 1] if idx + 1 < len(level) else level[idx]
            indexes.append(0)  # мы слева
        else:
            neighbor = level[idx - 1]
            indexes.append(1)  # мы справа
        path.append(_hex(neighbor))
        idx //= 2

    root_hex = _hex(levels[-1][0])
    leaf_hex = _hex(levels[0][leaf_index] if len(levels[0][leaf_index]) == 32 else _sha256(levels[0][leaf_index]))
    return MerkleProof(root_hex=root_hex, leaf_hex=leaf_hex, path=path, indexes=indexes)


def verify_merkle_proof(proof: MerkleProof) -> bool:
    cur = bytes.fromhex(proof.leaf_hex)
    for neigh_hex, side in zip(proof.path, proof.indexes):
        neigh = bytes.fromhex(neigh_hex)
        if side == 0:
            # leaf is left
            cur = _merkle_pair(cur, neigh)
        else:
            cur = _merkle_pair(neigh, cur)
    return _hex(cur) == proof.root_hex


def _retryable_async(fn, *, retries: int = 5, base_delay: float = 0.05, max_delay: float = 0.6, retriable=(AssertionError,)):
    async def runner():
        delay = base_delay
        for attempt in range(1, retries + 1):
            try:
                return await fn()
            except retriable as e:
                if attempt >= retries:
                    raise
                await asyncio.sleep(delay)
                delay = min(max_delay, delay * 2)
    return runner()


# ======================================================================================
# AnchorBuilder
# ======================================================================================

@dataclass
class AnchorBuilderSettings:
    min_leaves: int = 1
    max_bundle_bytes: int = 128 * 1024  # лимит полезной нагрузки перед отправкой
    memo_prefix: str = "ledger-anchor"
    finalize_confirmations: int = 3  # может использоваться клиентом
    signing_required: bool = True


class AnchorBuilder:
    """
    Промышленный строитель якорей:
    - батчинг листьев (snapshot/period)
    - Merkle корень и доказательства
    - prev_anchor_hash для связности
    - подпись payload
    - идемпотентность по anchor_key
    - отправка в сеть через AnchorNetworkClient
    - маркеры статусов в UoW и outbox события
    """

    def __init__(
        self,
        uow_factory: Protocol,  # callable -> AnchorUnitOfWork
        client: AnchorNetworkClient,
        *,
        signer: Optional[Signer],
        clock: Clock | None = None,
        settings: Optional[AnchorBuilderSettings] = None,
        tracer: Any = None,
        service_name: str = "ledger.anchoring.anchor_builder",
    ):
        self._uow_factory = uow_factory
        self._client = client
        self._signer = signer
        self._clock = clock or SystemClock()
        self._settings = settings or AnchorBuilderSettings()
        self._tracer = tracer
        self._service_name = service_name

    # ----------------------------------------------------------------------------------
    # Публичное API
    # ----------------------------------------------------------------------------------

    async def build_and_submit(self, req: AnchorRequest) -> AnchorRecord:
        """
        Полный цикл: построить якорь из листьев и отправить в сеть.
        Идемпотентно по anchor_key.
        """
        span = self._start_span("anchor.build_and_submit", {"request_id": req.request_id, "network": req.network.value})
        try:
            anchor_key = AnchorKeyBuilder.build(
                network=req.network,
                snapshot_id=req.snapshot_id,
                period_start=req.period_start,
                period_end=req.period_end,
                domain_salt_hex=req.domain_salt_hex,
            )

            # Быстрый путь: уже строили
            async with self._uow_factory() as uow:
                existing = await uow.anchors.get_by_anchor_key(anchor_key)
                if existing:
                    logger.info("anchor_idempotent_hit", extra={"anchor_id": str(existing.id), "anchor_key": anchor_key})
                    return existing

            # Собираем листья
            leaves = await self._collect_leaves(req)

            if len(leaves) < self._settings.min_leaves:
                raise ValueError(f"Not enough leaves to anchor: {len(leaves)} < {self._settings.min_leaves}")

            merkle_root, levels = build_merkle_root(leaves)

            # Достаём prev_anchor для связности
            async with self._uow_factory() as uow:
                latest = await uow.anchors.get_latest_for_network(req.network)
                prev_hash = latest.merkle_root_hex if latest else None

            # Строим payload
            now = self._clock.now()
            payload_doc = self._compose_payload_document(
                merkle_root=merkle_root,
                leaf_count=len(leaves),
                req=req,
                prev_root_hex=prev_hash,
                now=now,
            )
            payload_bytes = CanonicalEncoder.dumps(payload_doc)

            if self._settings.signing_required:
                if not self._signer:
                    raise ValueError("Signer is required but not configured")
                signature = self._signer.sign(payload_bytes)
                signature_hex = signature.hex()
                payload_doc["signature_hex"] = signature_hex
                payload_doc["signer_pubkey_hex"] = self._signer.public_key_hex()
                payload_bytes = CanonicalEncoder.dumps(payload_doc)
            else:
                signature_hex = None

            if len(payload_bytes) > self._settings.max_bundle_bytes:
                raise ValueError(f"Anchor payload too large: {len(payload_bytes)} bytes > {self._settings.max_bundle_bytes}")

            # Создаём AnchorRecord и фиксируем в БД (PENDING)
            record = AnchorRecord(
                id=uuid4(),
                request_id=req.request_id,
                network=req.network,
                status=AnchorStatus.PENDING,
                anchor_key=anchor_key,
                merkle_root_hex=_hex(merkle_root),
                leaf_count=len(leaves),
                snapshot_id=req.snapshot_id,
                period_start=req.period_start,
                period_end=req.period_end,
                prev_anchor_hash_hex=prev_hash,
                created_at=now,
                metadata=req.metadata,
                signature_hex=signature_hex,
            )

            async with self._uow_factory() as uow:
                # Идемпотентность при гонке
                existing = await uow.anchors.get_by_anchor_key(anchor_key)
                if existing:
                    logger.info("anchor_idempotent_race", extra={"anchor_id": str(existing.id), "anchor_key": anchor_key})
                    return existing

                await uow.anchors.insert(record)
                await uow.outbox.enqueue("anchor.built", {
                    "anchor_id": str(record.id),
                    "root": record.merkle_root_hex,
                    "network": record.network.value,
                    "leaf_count": record.leaf_count,
                    "prev_root": record.prev_anchor_hash_hex,
                    "request_id": record.request_id,
                })
                await uow.commit()

            # Отправка в сеть
            memo = f"{self._settings.memo_prefix}:{record.merkle_root_hex}"
            tx_id, block_ref = await _retryable_async(lambda: self._client.submit_payload(req.network, payload_bytes, memo=memo))

            async with self._uow_factory() as uow:
                await uow.anchors.mark_submitted(record.id, tx_id, block_ref)
                await uow.outbox.enqueue("anchor.submitted", {
                    "anchor_id": str(record.id),
                    "tx_id": tx_id,
                    "block_ref": block_ref,
                    "network": record.network.value,
                })
                await uow.commit()
                record.submit_tx_id = tx_id
                record.submit_block_ref = block_ref
                record.status = AnchorStatus.SUBMITTED
                record.submitted_at = self._clock.now()

            return record
        finally:
            self._end_span(span)

    async def finalize_if_confirmed(self, anchor_id: UUID, network: AnchorNetwork, tx_id: str) -> AnchorRecord:
        """
        Проверка финализации в сети и обновление статуса.
        """
        span = self._start_span("anchor.finalize", {"anchor_id": str(anchor_id), "tx_id": tx_id})
        try:
            finalized, block_ref = await _retryable_async(lambda: self._client.is_finalized(network, tx_id))
            if not finalized:
                raise AssertionError("Not finalized yet")

            async with self._uow_factory() as uow:
                # Загрузим текущий рекорд для возврата
                current = await uow.anchors.get_latest_for_network(network)
                # current может быть не тот якорь, поэтому не полагаемся на него
                await uow.anchors.mark_finalized(anchor_id, block_ref)
                await uow.outbox.enqueue("anchor.finalized", {
                    "anchor_id": str(anchor_id),
                    "tx_id": tx_id,
                    "block_ref": block_ref,
                    "network": network.value,
                })
                await uow.commit()

            # Для простоты рефрешим «текущий» снова (в проде — отдельный метод get_by_id)
            # Здесь допустимо вернуть компактный объект
            return AnchorRecord(
                id=anchor_id,
                request_id="",
                network=network,
                status=AnchorStatus.FINALIZED,
                anchor_key="",
                merkle_root_hex="",
                leaf_count=0,
                created_at=self._clock.now(),
            )
        finally:
            self._end_span(span)

    async def build_only(self, req: AnchorRequest) -> Tuple[AnchorRecord, Dict[str, Any], List[List[str]]]:
        """
        Построить Merkle и payload, не отправляя в сеть.
        Возвращает: (AnchorRecord(PENDING), payload_doc, levels_hex)
        """
        anchor_key = AnchorKeyBuilder.build(
            network=req.network,
            snapshot_id=req.snapshot_id,
            period_start=req.period_start,
            period_end=req.period_end,
            domain_salt_hex=req.domain_salt_hex,
        )

        async with self._uow_factory() as uow:
            existing = await uow.anchors.get_by_anchor_key(anchor_key)
            if existing:
                return existing, {}, []

        leaves = await self._collect_leaves(req)
        merkle_root, levels = build_merkle_root(leaves)
        now = self._clock.now()

        async with self._uow_factory() as uow:
            latest = await uow.anchors.get_latest_for_network(req.network)
            prev_hash = latest.merkle_root_hex if latest else None

        payload_doc = self._compose_payload_document(
            merkle_root=merkle_root,
            leaf_count=len(leaves),
            req=req,
            prev_root_hex=prev_hash,
            now=now,
        )
        payload_bytes = CanonicalEncoder.dumps(payload_doc)

        signature_hex = None
        if self._settings.signing_required and self._signer:
            sig = self._signer.sign(payload_bytes)
            signature_hex = sig.hex()
            payload_doc["signature_hex"] = signature_hex
            payload_doc["signer_pubkey_hex"] = self._signer.public_key_hex()

        record = AnchorRecord(
            id=uuid4(),
            request_id=req.request_id,
            network=req.network,
            status=AnchorStatus.PENDING,
            anchor_key=anchor_key,
            merkle_root_hex=_hex(merkle_root),
            leaf_count=len(leaves),
            snapshot_id=req.snapshot_id,
            period_start=req.period_start,
            period_end=req.period_end,
            prev_anchor_hash_hex=prev_hash,
            created_at=now,
            metadata=req.metadata,
            signature_hex=signature_hex,
        )

        levels_hex = [[_hex(x) for x in lvl] for lvl in levels]
        return record, payload_doc, levels_hex

    async def merkle_proof_for_leaf(
        self,
        req: AnchorRequest,
        leaf_index: int
    ) -> MerkleProof:
        """
        Построить proof для конкретного листа.
        """
        leaves = await self._collect_leaves(req)
        _, levels = build_merkle_root(leaves)
        return build_merkle_proof(levels, leaf_index)

    # ----------------------------------------------------------------------------------
    # Внутренние методы
    # ----------------------------------------------------------------------------------

    async def _collect_leaves(self, req: AnchorRequest) -> List[bytes]:
        if req.snapshot_id:
            async with self._uow_factory() as uow:
                leaves = await uow.snapshots.get_leaves_for_snapshot(req.snapshot_id)
            logger.debug("leaves_from_snapshot", extra={"count": len(leaves), "snapshot_id": str(req.snapshot_id)})
            return leaves

        if req.period_start and req.period_end:
            if req.period_start >= req.period_end:
                raise ValueError("period_start must be < period_end")
            async with self._uow_factory() as uow:
                leaves = await uow.snapshots.get_leaves_for_period(req.period_start, req.period_end)
            logger.debug("leaves_from_period", extra={
                "count": len(leaves),
                "start": req.period_start.isoformat(),
                "end": req.period_end.isoformat()
            })
            return leaves

        raise ValueError("Either snapshot_id or (period_start & period_end) must be provided")

    def _compose_payload_document(
        self,
        *,
        merkle_root: bytes,
        leaf_count: int,
        req: AnchorRequest,
        prev_root_hex: Optional[str],
        now: datetime,
    ) -> Dict[str, Any]:
        doc = {
            "schema": "ledger-anchor-v1",
            "network": req.network.value,
            "root_hex": _hex(merkle_root),
            "leaf_count": leaf_count,
            "snapshot_id": str(req.snapshot_id) if req.snapshot_id else None,
            "period": {
                "start": req.period_start.isoformat().replace("+00:00", "Z") if req.period_start else None,
                "end": req.period_end.isoformat().replace("+00:00", "Z") if req.period_end else None,
            },
            "prev_root_hex": prev_root_hex,
            "requested_at": now.isoformat().replace("+00:00", "Z"),
            "metadata": req.metadata,
            "domain_salt_hex": req.domain_salt_hex or "",
        }
        return doc

    def _start_span(self, name: str, attrs: Dict[str, Any]):
        if not self._tracer:
            return None
        span = self._tracer.start_as_current_span(name)
        if hasattr(span, "set_attributes"):
            span.set_attributes(attrs)
        return span

    def _end_span(self, span):
        if span is None:
            return
        with contextlib.suppress(Exception):
            span.__exit__(None, None, None)
