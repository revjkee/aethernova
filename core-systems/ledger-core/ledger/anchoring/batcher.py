# ledger-core/ledger/anchoring/batcher.py
# -*- coding: utf-8 -*-
"""
AnchorBatcher — промышленный батчер для анкоринга записей журнала (или их хешей)
во внешнюю доверенную среду (блокчейн/нотаризация/реестр).

Возможности:
  - Триггеры формирования пакета: по времени (max_wait), по числу элементов (max_items), по размеру (max_bytes)
  - Детерминированное формирование коммитмента (Merkle root + метаданные)
  - Идемпотентность: стабильный ключ анкоринга для повторов
  - Устойчивые ретраи: экспоненциальный бэкофф с джиттером, верхние пределы
  - Персистентность: сохранение/восстановление незавершённых батчей, квитанций и статусов элементов
  - Наблюдаемость: OpenTelemetry (если установлен), структурированные логи, счётчики/таймеры
  - Корректная остановка: флеш незакрытого пакета, ожидание завершения отправок
  - Плагины: абстракции AnchorClient и BatcherStore для вашей инфраструктуры
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterable, Awaitable, Dict, Iterable, List, Literal, Optional, Protocol, Sequence, Tuple

# ------------------------------
# OpenTelemetry (опционально)
# ------------------------------
try:  # pragma: no cover
    from opentelemetry import trace, metrics
    _tracer = trace.get_tracer(__name__)
    _meter = metrics.get_meter(__name__)
    _m_batches = _meter.create_counter("ledger_anchor_batches_total")
    _m_items = _meter.create_counter("ledger_anchor_items_total")
    _m_fail = _meter.create_counter("ledger_anchor_failures_total")
    _m_bytes = _meter.create_counter("ledger_anchor_bytes_total")
except Exception:  # pragma: no cover
    class _N:
        def __getattr__(self, *_): return self
        def start_as_current_span(self, *_ , **__):
            class _S:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def set_attribute(self, *_, **__): pass
            return _S()
        def create_counter(self, *_ , **__):
            class _C:
                def add(self, *_ , **__): pass
            return _C()
    _tracer = _N()
    _m_batches = _N()
    _m_items = _N()
    _m_fail = _N()
    _m_bytes = _N()

LOG = logging.getLogger("ledger.anchoring")


# ------------------------------
# Исключения
# ------------------------------

class AnchoringError(Exception): ...
class StoreError(AnchoringError): ...
class ClientError(AnchoringError): ...
class PermanentClientError(ClientError): ...
class TransientClientError(ClientError): ...


# ------------------------------
# Абстракции клиента и стораджа
# ------------------------------

class AnchorClient(Protocol):
    """
    Клиент внешнего анкора.
    Должен обеспечивать идемпотентность через ключ (idempotency_key).
    """

    async def submit_commitment(
        self,
        *,
        commitment: bytes,
        idempotency_key: str,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Отправить коммитмент, вернуть квитанцию (например, tx_id, anchor_ts, chain_height).
        Может бросать PermanentClientError или TransientClientError.
        """
        ...


class BatcherStore(Protocol):
    """
    Персистентное состояние батчера.
    """

    # Элементы
    async def mark_item_anchored(self, item_id: str, receipt: Dict[str, Any]) -> None: ...
    async def mark_item_failed(self, item_id: str, reason: str) -> None: ...

    # Батчи
    async def save_open_batch(self, batch_id: str, state: Dict[str, Any]) -> None: ...
    async def load_open_batch(self) -> Optional[Dict[str, Any]]: ...
    async def delete_open_batch(self, batch_id: str) -> None: ...

    # Квитанции
    async def save_receipt(self, batch_id: str, receipt: Dict[str, Any]) -> None: ...

    # Идемпотентность
    async def is_commitment_processed(self, idempotency_key: str) -> bool: ...


# ------------------------------
# Хэширование/мерклирование
# ------------------------------

HashName = Literal["sha256", "sha384", "sha512", "blake2b"]

def _hasher_by_name(name: HashName):
    if name == "sha256": return hashlib.sha256
    if name == "sha384": return hashlib.sha384
    if name == "sha512": return hashlib.sha512
    if name == "blake2b": return lambda: hashlib.blake2b(digest_size=32)
    raise ValueError(f"Unsupported hash: {name}")

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

def _encode_leaf(obj: Dict[str, Any]) -> bytes:
    # Стабильная сериализация без пробелов, сортировка ключей
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _hash_leaf(hf, leaf: bytes) -> bytes:
    h = hf()
    h.update(LEAF_PREFIX)
    h.update(leaf)
    return h.digest()

def _hash_node(hf, left: bytes, right: bytes) -> bytes:
    h = hf()
    h.update(NODE_PREFIX)
    h.update(left)
    h.update(right)
    return h.digest()

def _merkle_root(hf, leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        h = hf(); h.update(LEAF_PREFIX); return h.digest()
    level = [_hash_leaf(hf, l) for l in leaves]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_hash_node(hf, level[i], level[i+1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


# ------------------------------
# Модель элемента и батча
# ------------------------------

@dataclass(frozen=True)
class AnchorItem:
    """
    Элемент, добавляемый в батч. Должен быть компактным и однозначно сериализуемым.
    """
    id: str
    payload: Dict[str, Any]  # минимально: хеш записи (например, {"entry_id": "...", "hash": "hex"})
    size_bytes: int = field(default=0)  # если 0 — вычислим по сериализации

    def encoded(self) -> bytes:
        return _encode_leaf(self.payload)

    def effective_size(self) -> int:
        return self.size_bytes or len(self.encoded())


@dataclass
class OpenBatch:
    batch_id: str
    created_ts: float
    items: List[AnchorItem] = field(default_factory=list)
    bytes_total: int = 0

    def add(self, item: AnchorItem) -> None:
        self.items.append(item)
        self.bytes_total += item.effective_size()

    def size(self) -> int:
        return len(self.items)


# ------------------------------
# Конфиг и полиси ретраев
# ------------------------------

@dataclass(frozen=True)
class RetryPolicy:
    initial_delay_ms: int = 500
    max_delay_ms: int = 30_000
    multiplier: float = 2.0
    jitter_ratio: float = 0.2
    max_attempts: int = 10

    def next_delay(self, attempt: int) -> float:
        base = min(self.initial_delay_ms * (self.multiplier ** (attempt - 1)), self.max_delay_ms)
        jitter = base * self.jitter_ratio * (2 * random.random() - 1)  # [-j..+j]
        return max(0.0, (base + jitter) / 1000.0)


@dataclass(frozen=True)
class BatcherConfig:
    hash_name: HashName = "sha256"
    # Триггеры формирования
    max_items: int = 1000
    max_bytes: int = 512 * 1024
    max_wait_seconds: float = 5.0
    # Очередь
    in_memory_queue_capacity: int = 10_000
    # Идемпотентность
    idempotency_prefix: str = "ledger-anchor"
    # Ретраи
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    # Журналирование
    log_sample_rate: float = 1.0  # 1.0 — логировать все успешные батчи


# ------------------------------
# Основной сервис
# ------------------------------

class AnchorBatcher:
    """
    Асинхронный батчер анкоринга.
    Паттерн использования:
        batcher = AnchorBatcher(store, client, cfg)
        await batcher.start()
        await batcher.submit(item)  # из продюсеров
        ...
        await batcher.stop()
    """

    def __init__(self, store: BatcherStore, client: AnchorClient, cfg: Optional[BatcherConfig] = None) -> None:
        self._store = store
        self._client = client
        self._cfg = cfg or BatcherConfig()
        self._hf_factory = _hasher_by_name(self._cfg.hash_name)
        self._queue: asyncio.Queue[AnchorItem] = asyncio.Queue(self._cfg.in_memory_queue_capacity)
        self._open: Optional[OpenBatch] = None
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._flush_needed = asyncio.Event()
        self._lock = asyncio.Lock()

    # -------- Публичный API --------

    async def start(self) -> None:
        """Восстанавливает незавершённый батч (если есть) и запускает цикл сбора/отправки."""
        await self._restore_open_batch()
        self._stopping.clear()
        self._task = asyncio.create_task(self._run_loop(), name="anchor-batcher")

    async def stop(self) -> None:
        """Корректно останавливает батчер, отправляя финальный батч при необходимости."""
        self._stopping.set()
        if self._task:
            await self._task
        # После завершения цикла гарантируем финальный флеш
        async with self._lock:
            if self._open and self._open.size() > 0:
                await self._finalize_and_send(self._open)

    async def submit(self, item: AnchorItem, *, timeout: Optional[float] = None) -> None:
        """Положить элемент в очередь (с бэкпрешером)."""
        await asyncio.wait_for(self._queue.put(item), timeout=timeout)

    async def flush(self) -> None:
        """Принудительно закрыть текущий батч и отправить."""
        self._flush_needed.set()

    # -------- Внутреннее --------

    async def _run_loop(self) -> None:
        t_start = time.monotonic()
        max_wait = self._cfg.max_wait_seconds
        while not self._stopping.is_set():
            try:
                # Ждём событий: новый элемент или истечение таймера/принудительный флеш
                timeout = max(0.0, max_wait - (time.monotonic() - t_start)) if self._open else max_wait
                done, _ = await asyncio.wait(
                    {
                        asyncio.create_task(self._queue.get()),
                        asyncio.create_task(asyncio.sleep(timeout)),
                        asyncio.create_task(self._flush_needed.wait()),
                    },
                    return_when=asyncio.FIRST_COMPLETED,
                )
                # Обработка событий
                if any(t for t in done if isinstance(t.result(), AnchorItem)):  # тип: ignore
                    item_task = next(t for t in done if t is not None and t is not asyncio.Task.current_task())  # pragma: no cover
                # Поскольку выше сложно типизировать, просто извлечём неблокирующе:
                item = None
                while True:
                    try:
                        item = self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    else:
                        await self._add_to_open(item)
                        self._queue.task_done()

                # Триггеры закрытия батча
                if self._flush_needed.is_set():
                    self._flush_needed.clear()
                    await self._maybe_finalize(reason="flush")
                    t_start = time.monotonic()
                elif self._open and (
                    self._open.size() >= self._cfg.max_items
                    or self._open.bytes_total >= self._cfg.max_bytes
                    or (time.monotonic() - t_start) >= self._cfg.max_wait_seconds
                ):
                    await self._maybe_finalize(reason="timeout/size")
                    t_start = time.monotonic()

            except Exception as e:  # защитный контур
                LOG.exception("anchor batcher loop error: %s", e)
                await asyncio.sleep(0.5)

    async def _add_to_open(self, item: AnchorItem) -> None:
        async with self._lock:
            if self._open is None:
                self._open = OpenBatch(batch_id=_gen_batch_id(), created_ts=time.time())
            self._open.add(item)
            # Периодически сохраняем состояние (на случай падения)
            if self._open.size() % 50 == 1:
                await self._persist_open(self._open)

    async def _maybe_finalize(self, *, reason: str) -> None:
        async with self._lock:
            if not self._open or self._open.size() == 0:
                return
            ob = self._open
            self._open = None
        await self._finalize_and_send(ob, reason=reason)

    async def _finalize_and_send(self, ob: OpenBatch, *, reason: str = "unknown") -> None:
        # Формируем меркль‑коммитмент
        with _tracer.start_as_current_span("anchoring.finalize"):
            leaves = [it.encoded() for it in ob.items]
            root = _merkle_root(self._hf_factory, leaves)
            commitment = _build_commitment(root=root, items=ob.items, hash_name=self._cfg.hash_name)
            idem_key = _idempotency_key(self._cfg.idempotency_prefix, ob.batch_id, root)
            meta = {
                "batch_id": ob.batch_id,
                "created_ts": ob.created_ts,
                "items": ob.size(),
                "bytes": ob.bytes_total,
                "hash": self._cfg.hash_name,
                "reason": reason,
            }
            # Сохраняем "open batch" перед отправкой
            await self._persist_open(ob)
            # Отправляем с ретраями
            attempt = 0
            while True:
                attempt += 1
                try:
                    if await self._store.is_commitment_processed(idem_key):
                        receipt = {"status": "duplicate", "idempotency_key": idem_key}
                    else:
                        receipt = await self._client.submit_commitment(
                            commitment=commitment,
                            idempotency_key=idem_key,
                            metadata=meta,
                        )
                    await self._after_success(ob, receipt)
                    return
                except PermanentClientError as e:
                    _m_fail.add(1)  # type: ignore
                    LOG.error("anchor permanent failure batch=%s err=%s", ob.batch_id, str(e), extra={
                        "extra": {"batch_id": ob.batch_id, "attempt": attempt}
                    })
                    await self._after_failure(ob, str(e), permanent=True)
                    return
                except TransientClientError as e:
                    _m_fail.add(1)  # type: ignore
                    delay = self._cfg.retry_policy.next_delay(attempt)
                    LOG.warning("anchor transient failure batch=%s attempt=%d retry_in=%.3fs: %s",
                                ob.batch_id, attempt, delay, str(e), extra={"extra": {"batch_id": ob.batch_id}})
                    if attempt >= self._cfg.retry_policy.max_attempts or self._stopping.is_set():
                        await self._after_failure(ob, f"transient_exhausted: {e}", permanent=False)
                        return
                    await asyncio.sleep(delay)

    async def _after_success(self, ob: OpenBatch, receipt: Dict[str, Any]) -> None:
        with _tracer.start_as_current_span("anchoring.after_success") as sp:
            sp.set_attribute("batch.id", ob.batch_id)
            sp.set_attribute("items", ob.size())
            # Проставляем для каждого элемента статус
            for it in ob.items:
                try:
                    await self._store.mark_item_anchored(it.id, receipt)
                except Exception as e:
                    LOG.error("mark_item_anchored failed id=%s err=%s", it.id, e)
            # Квитанция и очистка open‑batch
            try:
                await self._store.save_receipt(ob.batch_id, receipt)
                await self._store.delete_open_batch(ob.batch_id)
            except Exception as e:
                LOG.error("save_receipt/delete_open_batch failed batch=%s err=%s", ob.batch_id, e)

            # Метрики/логи
            _m_batches.add(1)  # type: ignore
            _m_items.add(ob.size())  # type: ignore
            _m_bytes.add(ob.bytes_total)  # type: ignore
            if _should_log(self._cfg.log_sample_rate):
                LOG.info("anchored batch id=%s items=%d bytes=%d receipt=%s",
                         ob.batch_id, ob.size(), ob.bytes_total, _safe_json(receipt),
                         extra={"extra": {"batch_id": ob.batch_id, "items": ob.size(), "bytes": ob.bytes_total}})

    async def _after_failure(self, ob: OpenBatch, reason: str, *, permanent: bool) -> None:
        with _tracer.start_as_current_span("anchoring.after_failure") as sp:
            sp.set_attribute("batch.id", ob.batch_id)
            sp.set_attribute("permanent", permanent)
            for it in ob.items:
                try:
                    await self._store.mark_item_failed(it.id, reason)
                except Exception as e:
                    LOG.error("mark_item_failed failed id=%s err=%s", it.id, e)
            try:
                await self._store.delete_open_batch(ob.batch_id)
            except Exception as e:
                LOG.error("delete_open_batch failed batch=%s err=%s", ob.batch_id, e)

    async def _persist_open(self, ob: OpenBatch) -> None:
        state = {
            "batch_id": ob.batch_id,
            "created_ts": ob.created_ts,
            "items": [{"id": it.id, "payload": it.payload, "size_bytes": it.size_bytes} for it in ob.items],
            "bytes_total": ob.bytes_total,
            "hash": self._cfg.hash_name,
        }
        await self._store.save_open_batch(ob.batch_id, state)

    async def _restore_open_batch(self) -> None:
        try:
            state = await self._store.load_open_batch()
        except Exception as e:
            raise StoreError(f"failed to load open batch: {e}")
        if not state:
            return
        ob = OpenBatch(batch_id=state["batch_id"], created_ts=state["created_ts"], items=[], bytes_total=state["bytes_total"])
        for rec in state.get("items", []):
            ob.add(AnchorItem(id=rec["id"], payload=rec["payload"], size_bytes=rec.get("size_bytes", 0)))
        self._open = ob
        LOG.info("restored open batch id=%s items=%d bytes=%d", ob.batch_id, ob.size(), ob.bytes_total,
                 extra={"extra": {"batch_id": ob.batch_id}})


# ------------------------------
# Утилиты
# ------------------------------

def _gen_batch_id() -> str:
    # Монотонность не требуется; используем base32 от 64‑битного времени и случайности
    t = int(time.time() * 1e6)
    r = random.getrandbits(32)
    raw = t.to_bytes(8, "big") + r.to_bytes(4, "big")
    return base64.b32encode(raw).decode("ascii").rstrip("=")

def _idempotency_key(prefix: str, batch_id: str, root: bytes) -> str:
    h = hashlib.sha256()
    h.update(prefix.encode("utf-8"))
    h.update(b"|")
    h.update(batch_id.encode("utf-8"))
    h.update(b"|")
    h.update(root)
    return f"{prefix}/{batch_id}/{h.hexdigest()[:16]}"

def _build_commitment(*, root: bytes, items: Sequence[AnchorItem], hash_name: str) -> bytes:
    """
    Коммитмент — минимальный бинарный формат:
      {
        "hash": "<algo>",
        "root_b64": "<base64>",
        "leaf_count": N,
        "ts": epoch_ms,
        "schema": 1
      }
    """
    payload = {
        "schema": 1,
        "hash": hash_name,
        "root_b64": base64.b64encode(root).decode("ascii"),
        "leaf_count": len(items),
        "ts": int(time.time() * 1000),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _should_log(rate: float) -> bool:
    if rate >= 1.0:
        return True
    return (time.time_ns() % 10_000) / 10_000.0 < max(0.0, rate)

def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)


# ------------------------------
# Ин‑мемори адаптеры (для тестов/примера)
# ------------------------------

class InMemoryStore(BatcherStore):
    def __init__(self) -> None:
        self._open: Optional[Dict[str, Any]] = None
        self._receipts: Dict[str, Dict[str, Any]] = {}
        self._items_status: Dict[str, Dict[str, Any]] = {}
        self._idem: set[str] = set()

    async def mark_item_anchored(self, item_id: str, receipt: Dict[str, Any]) -> None:
        self._items_status[item_id] = {"status": "anchored", "receipt": receipt}

    async def mark_item_failed(self, item_id: str, reason: str) -> None:
        self._items_status[item_id] = {"status": "failed", "reason": reason}

    async def save_open_batch(self, batch_id: str, state: Dict[str, Any]) -> None:
        self._open = state

    async def load_open_batch(self) -> Optional[Dict[str, Any]]:
        return self._open

    async def delete_open_batch(self, batch_id: str) -> None:
        self._open = None

    async def save_receipt(self, batch_id: str, receipt: Dict[str, Any]) -> None:
        self._receipts[batch_id] = receipt
        key = receipt.get("idempotency_key")
        if key:
            self._idem.add(key)

    async def is_commitment_processed(self, idempotency_key: str) -> bool:
        return idempotency_key in self._idem


class InMemoryAnchorClient(AnchorClient):
    def __init__(self, fail_ratio: float = 0.0) -> None:
        self._fail_ratio = fail_ratio
        self._seen: Dict[str, Dict[str, Any]] = {}

    async def submit_commitment(self, *, commitment: bytes, idempotency_key: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        # Идемпотентность
        if idempotency_key in self._seen:
            return self._seen[idempotency_key]
        # Смоделируем временные сбои
        if random.random() < self._fail_ratio:
            raise TransientClientError("simulated transient error")
        receipt = {
            "status": "anchored",
            "tx_id": base64.urlsafe_b64encode(hashlib.sha256(commitment).digest()[:12]).decode("ascii").rstrip("="),
            "idempotency_key": idempotency_key,
            "anchor_ts": int(time.time() * 1000),
        }
        self._seen[idempotency_key] = receipt
        return receipt


# ------------------------------
# Пример использования (dev)
# ------------------------------

async def _demo() -> None:  # pragma: no cover
    store = InMemoryStore()
    client = InMemoryAnchorClient(fail_ratio=0.2)
    batcher = AnchorBatcher(store, client, BatcherConfig(max_items=5, max_wait_seconds=1.0))
    await batcher.start()
    for i in range(13):
        item = AnchorItem(id=f"e-{i}", payload={"id": f"tx-{i}", "hash": hashlib.sha256(str(i).encode()).hexdigest()})
        await batcher.submit(item)
        await asyncio.sleep(0.05)
    await batcher.flush()
    await batcher.stop()

if __name__ == "__main__":  # pragma: no cover
    import asyncio
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_demo())
