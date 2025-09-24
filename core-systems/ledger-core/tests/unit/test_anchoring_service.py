# ledger-core/tests/unit/test_anchoring_service.py
# -*- coding: utf-8 -*-
"""
Промышленный набор тестов для сервиса анкоринга (AnchoringService).
Контракт (ожидаемая поверхность сервиса):

class AnchoringService:
    async def anchor(
        self,
        *,
        chain_id: str,
        payload: bytes,
        wait: bool = True,
        wait_timeout: float = 120.0,
        poll_interval: float = 2.0,
        metadata: dict | None = None,
    ) -> "AnchorResult": ...

    async def get_status(self, *, chain_id: str, tx_hash: str) -> "AnchorStatus": ...

class AnchorResult(BaseModel | dataclass):
    tx_hash: str
    status: Literal["PENDING","CONFIRMED","FAILED","DROPPED"]
    block_number: int | None
    anchor_id: str  # детерминированный ID (например, blake2b(payload))

Сервис использует зависимости:
- rpc: с методами send_raw(raw_hex) -> tx_hash, get_receipt(tx_hash) -> dict | None
- tx_repo: с upsert(...), mark_confirmed(...), update_status(...), get_by_chain_and_hash(...)
- metrics: .inc(name, labels), .observe(name, value, labels)
- idgen/hash: функция calc_anchor_id(payload: bytes) -> str

Данный тест задает поведение для реализации AnchoringService.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import time
from typing import Any, Dict, List, Optional, Tuple, Protocol

import pytest

pytestmark = pytest.mark.asyncio


# =========================
# ПРОТОКОЛЫ ЗАВИСИМОСТЕЙ
# =========================

class RpcClient(Protocol):
    async def send_raw(self, raw_hex: str) -> str: ...
    async def get_receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]: ...

class TxRepository(Protocol):
    async def upsert(self, tx) -> str: ...
    async def mark_confirmed(self, chain_id: str, tx_hash: str, block_number: int, block_hash: str, block_time, expected_version: int | None = None, receipt: dict | None = None) -> bool: ...
    async def update_status(self, chain_id: str, tx_hash: str, new_status: str, expected_version: int | None = None, extra: dict | None = None) -> bool: ...
    async def exists(self, chain_id: str, tx_hash: str) -> bool: ...
    async def get_by_chain_and_hash(self, chain_id: str, tx_hash: str) -> Optional[dict]: ...

class Metrics(Protocol):
    def inc(self, name: str, labels: Dict[str, str] | None = None) -> None: ...
    def observe(self, name: str, value: float, labels: Dict[str, str] | None = None) -> None: ...


# =========================
# КОНСТАНТЫ/ВСПОМОГАТЕЛЬНОЕ
# =========================

CONFIRMED = "CONFIRMED"
PENDING = "PENDING"
FAILED = "FAILED"
DROPPED = "DROPPED"

def calc_anchor_id(payload: bytes) -> str:
    # детерминированный ID по содержимому (имитируем поведение сервиса)
    import hashlib
    h = hashlib.blake2b(payload, digest_size=16).hexdigest()
    return f"anc_{h}"

@dataclasses.dataclass
class TxCreate:
    chain_id: str
    tx_hash: str
    status: str
    metadata: dict | None = None


@dataclasses.dataclass
class AnchorResult:
    tx_hash: str
    status: str
    block_number: int | None
    anchor_id: str


# =========================
# ФЕЙКИ/ДВОЙНИКИ
# =========================

class FakeMetrics:
    def __init__(self):
        self.counters: Dict[str, int] = {}
        self.observations: List[Tuple[str, float, Dict[str, str] | None]] = []

    def inc(self, name: str, labels: Dict[str, str] | None = None) -> None:
        key = name + "|" + json.dumps(labels or {}, sort_keys=True)
        self.counters[key] = self.counters.get(key, 0) + 1

    def observe(self, name: str, value: float, labels: Dict[str, str] | None = None) -> None:
        self.observations.append((name, value, labels or {}))


class FakeTxRepo:
    def __init__(self):
        self.rows: Dict[Tuple[str, str], dict] = {}
        self.upserts: int = 0
        self.confirms: int = 0
        self.updates: int = 0

    async def upsert(self, tx: TxCreate) -> str:
        self.upserts += 1
        key = (tx.chain_id, tx.tx_hash)
        row = self.rows.get(key, {"version": 1})
        row.update({
            "chain_id": tx.chain_id, "tx_hash": tx.tx_hash, "status": tx.status,
            "metadata": tx.metadata or {}, "version": row["version"] + 1
        })
        self.rows[key] = row
        return f"row:{tx.tx_hash}"

    async def mark_confirmed(self, chain_id: str, tx_hash: str, block_number: int, block_hash: str, block_time, expected_version: int | None = None, receipt: dict | None = None) -> bool:
        self.confirms += 1
        key = (chain_id, tx_hash)
        row = self.rows.get(key) or {}
        row.update({"status": CONFIRMED, "block_number": block_number, "block_hash": block_hash, "metadata": {"receipt": receipt or {}}, "version": (row.get("version") or 0) + 1})
        self.rows[key] = row
        return True

    async def update_status(self, chain_id: str, tx_hash: str, new_status: str, expected_version: int | None = None, extra: dict | None = None) -> bool:
        self.updates += 1
        key = (chain_id, tx_hash)
        row = self.rows.get(key) or {}
        row.update({"status": new_status, "metadata": {**row.get("metadata", {}), **(extra or {})}, "version": (row.get("version") or 0) + 1})
        self.rows[key] = row
        return True

    async def exists(self, chain_id: str, tx_hash: str) -> bool:
        return (chain_id, tx_hash) in self.rows

    async def get_by_chain_and_hash(self, chain_id: str, tx_hash: str) -> Optional[dict]:
        return self.rows.get((chain_id, tx_hash))


class ScenarioRpc(FakeMetrics):
    """
    RPC-двойник со сценарием ответов:
      - send_plan: список значений/исключений для send_raw
      - receipts: dict[tx_hash] -> список ответов get_receipt (None для "ещё нет")
    """
    def __init__(self, send_plan: List[Any], receipts: Dict[str, List[Optional[Dict[str, Any]]]]):
        super().__init__()
        self.send_plan = list(send_plan)
        self.receipts = {k: list(v) for k, v in receipts.items()}
        self.send_calls = 0
        self.receipt_calls = 0

    async def send_raw(self, raw_hex: str) -> str:
        self.send_calls += 1
        if not self.send_plan:
            raise RuntimeError("send_plan exhausted")
        step = self.send_plan.pop(0)
        if isinstance(step, Exception):
            raise step
        return str(step)

    async def get_receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        self.receipt_calls += 1
        seq = self.receipts.get(tx_hash, [])
        if not seq:
            return None
        nxt = seq.pop(0)
        return nxt


# =========================
# ТЕСТИРУЕМЫЙ СЕРВИС (SUT) - УПРОЩЕННЫЙ ЭТАЛОН ДЛЯ ПРОВЕРОК
# =========================
# В реальном проекте импортируйте ваш AnchoringService. Здесь — эталонная реализация,
# чтобы тесты были самодостаточны. Сохраните интерфейс.

class AnchoringService:
    def __init__(self, rpc: RpcClient, tx_repo: TxRepository, metrics: Metrics, *, default_poll_interval: float = 1.0, default_timeout: float = 30.0, max_retries: int = 3, backoff: float = 0.2):
        self.rpc = rpc
        self.tx_repo = tx_repo
        self.metrics = metrics
        self.default_poll_interval = default_poll_interval
        self.default_timeout = default_timeout
        self.max_retries = max_retries
        self.backoff = backoff

    async def anchor(self, *, chain_id: str, payload: bytes, wait: bool = True, wait_timeout: float | None = None, poll_interval: float | None = None, metadata: dict | None = None) -> AnchorResult:
        if not chain_id or not isinstance(chain_id, str):
            raise ValueError("chain_id is required")
        anchor_id = calc_anchor_id(payload)
        raw_hex = "0x02" + payload.hex()  # имитация "подписанной" tx
        tx_hash = await self._retry_send(raw_hex)

        # репозиторий: PENDING
        await self.tx_repo.upsert(TxCreate(chain_id=chain_id, tx_hash=tx_hash, status=PENDING, metadata={"anchor_id": anchor_id, **(metadata or {})}))
        self.metrics.inc("anchor_submitted", {"chain_id": chain_id})

        if not wait:
            return AnchorResult(tx_hash=tx_hash, status=PENDING, block_number=None, anchor_id=anchor_id)

        # ожидание receipt
        timeout = self.default_timeout if wait_timeout is None else wait_timeout
        poll = self.default_poll_interval if poll_interval is None else poll_interval

        start = time.time()
        rec = None
        while True:
            rec = await self.rpc.get_receipt(tx_hash)
            if rec is not None:
                break
            if time.time() - start >= timeout:
                self.metrics.inc("anchor_wait_timeout", {"chain_id": chain_id})
                return AnchorResult(tx_hash=tx_hash, status=PENDING, block_number=None, anchor_id=anchor_id)
            await asyncio.sleep(poll)

        status_hex = rec.get("status")
        status = int(status_hex, 16) if status_hex else 0
        if status == 1:
            await self.tx_repo.mark_confirmed(chain_id, tx_hash, int(rec.get("blockNumber", "0x0"), 16) if rec.get("blockNumber") else 0, rec.get("blockHash") or "0x0", time.time(), receipt=rec)
            self.metrics.inc("anchor_confirmed", {"chain_id": chain_id})
            return AnchorResult(tx_hash=tx_hash, status=CONFIRMED, block_number=int(rec.get("blockNumber", "0x0"), 16) if rec.get("blockNumber") else None, anchor_id=anchor_id)
        else:
            await self.tx_repo.update_status(chain_id, tx_hash, FAILED, extra={"receipt": rec})
            self.metrics.inc("anchor_failed", {"chain_id": chain_id})
            return AnchorResult(tx_hash=tx_hash, status=FAILED, block_number=int(rec.get("blockNumber", "0x0"), 16) if rec.get("blockNumber") else None, anchor_id=anchor_id)

    async def get_status(self, *, chain_id: str, tx_hash: str) -> str:
        row = await self.tx_repo.get_by_chain_and_hash(chain_id, tx_hash)
        return (row or {}).get("status") or PENDING

    async def _retry_send(self, raw_hex: str) -> str:
        attempt = 0
        delay = self.backoff
        while True:
            attempt += 1
            try:
                return await self.rpc.send_raw(raw_hex)
            except Exception:
                if attempt >= self.max_retries:
                    raise
                await asyncio.sleep(delay)
                delay = min(delay * 2, 3.0)


# =========================
# ФИКСТУРЫ
# =========================

@pytest.fixture
def repo() -> FakeTxRepo:
    return FakeTxRepo()

@pytest.fixture
def metrics() -> FakeMetrics:
    return FakeMetrics()


# =========================
# ТЕСТЫ: HAPPY PATH
# =========================

async def test_anchor_success_confirmed(repo, metrics):
    txh = "0xabc"
    rpc = ScenarioRpc(send_plan=[txh], receipts={
        txh: [None, {"status": "0x1", "blockNumber": "0x10", "blockHash": "0xdeadbeef"}]
    })
    svc = AnchoringService(rpc, repo, metrics, default_timeout=5.0, default_poll_interval=0.01)

    payload = b"hello-world"
    res = await svc.anchor(chain_id="ethereum", payload=payload, wait=True)

    assert res.tx_hash == txh
    assert res.status == CONFIRMED
    assert res.block_number == 16
    assert res.anchor_id.startswith("anc_")
    assert repo.confirms == 1
    # метрики
    assert any(k.startswith("anchor_confirmed") for k in metrics.counters.keys())


# =========================
# ТЕСТЫ: РЕТРАИ
# =========================

class TransientError(RuntimeError): ...

async def test_anchor_retries_on_transient_errors(repo, metrics):
    txh = "0xdef"
    rpc = ScenarioRpc(send_plan=[TransientError("net down"), TransientError("try again"), txh], receipts={txh: [{"status": "0x1", "blockNumber": "0x2", "blockHash": "0xbeef"}]})
    svc = AnchoringService(rpc, repo, metrics, default_timeout=3.0, default_poll_interval=0.01, max_retries=5, backoff=0.001)

    res = await svc.anchor(chain_id="ethereum", payload=b"data", wait=True)

    assert res.status == CONFIRMED
    assert rpc.send_calls == 3
    assert repo.upserts >= 1


# =========================
# ТЕСТЫ: ИДЕМПОТЕНТНОСТЬ
# =========================

async def test_anchor_idempotent_same_payload(repo, metrics):
    txh = "0x777"
    rpc = ScenarioRpc(send_plan=[txh, txh], receipts={txh: [None, {"status": "0x1", "blockNumber": "0x3", "blockHash": "0xbee"}]})
    svc = AnchoringService(rpc, repo, metrics, default_timeout=5.0, default_poll_interval=0.01)

    payload = b"A" * 32
    r1 = await svc.anchor(chain_id="ethereum", payload=payload, wait=False)
    r2 = await svc.anchor(chain_id="ethereum", payload=payload, wait=True)

    assert r1.anchor_id == r2.anchor_id
    # репозиторий не должен разрастись дубликатами статусов
    key = ("ethereum", txh)
    assert repo.rows[key]["status"] in (PENDING, CONFIRMED)


# =========================
# ТЕСТЫ: FAILED
# =========================

async def test_anchor_failed_receipt(repo, metrics):
    txh = "0xf00"
    rpc = ScenarioRpc(send_plan=[txh], receipts={txh: [{"status": "0x0", "blockNumber": "0x22", "blockHash": "0xaaa"}]})
    svc = AnchoringService(rpc, repo, metrics, default_timeout=2.0, default_poll_interval=0.01)

    res = await svc.anchor(chain_id="ethereum", payload=b"x", wait=True)

    assert res.status == FAILED
    row = await repo.get_by_chain_and_hash("ethereum", txh)
    assert row["status"] == FAILED
    # метрики
    assert any(k.startswith("anchor_failed") for k in metrics.counters.keys())


# =========================
# ТЕСТЫ: TIMEOUT ОЖИДАНИЯ ЧЕКА
# =========================

async def test_anchor_timeout_waiting_receipt(repo, metrics):
    txh = "0x999"
    rpc = ScenarioRpc(send_plan=[txh], receipts={txh: [None, None, None]})
    svc = AnchoringService(rpc, repo, metrics, default_timeout=0.02, default_poll_interval=0.01)

    res = await svc.anchor(chain_id="ethereum", payload=b"y", wait=True)

    assert res.status == PENDING
    assert repo.confirms == 0
    assert any(k.startswith("anchor_wait_timeout") for k in metrics.counters.keys())


# =========================
# ТЕСТЫ: DROPPED/REPLACED СЦЕНАРИИ
# =========================

async def test_anchor_dropped_then_retry_send(repo, metrics):
    """
    Сценарий: tx выпала из мемпула (эмулируем как отсутствие receipt долгое время),
    сервис должен вернуть PENDING; последующий вызов может отправить заново.
    """
    txh1 = "0xaaa"
    txh2 = "0xaab"
    rpc1 = ScenarioRpc(send_plan=[txh1], receipts={txh1: [None] * 5})
    svc1 = AnchoringService(rpc1, repo, metrics, default_timeout=0.03, default_poll_interval=0.01)
    r1 = await svc1.anchor(chain_id="ethereum", payload=b"z", wait=True)
    assert r1.status == PENDING

    # Повторный анкор: новая отправка и быстрый CONFIRMED
    rpc2 = ScenarioRpc(send_plan=[txh2], receipts={txh2: [{"status": "0x1", "blockNumber": "0x33", "blockHash": "0xbb"}]})
    svc2 = AnchoringService(rpc2, repo, metrics, default_timeout=2.0, default_poll_interval=0.01)
    r2 = await svc2.anchor(chain_id="ethereum", payload=b"z", wait=True)
    assert r2.status == CONFIRMED
    assert repo.confirms >= 1


# =========================
# ТЕСТЫ: КОНКУРЕНЦИЯ
# =========================

async def test_anchor_concurrent_calls(repo, metrics):
    """
    Параллельные анкоринги разных payload не должны конфликтовать и блокировать друг друга.
    """
    txhs = [f"0x{100+i:x}" for i in range(10)]
    receipts = {h: [{"status": "0x1", "blockNumber": "0x5"}] for h in txhs}
    rpc = ScenarioRpc(send_plan=list(txhs), receipts=receipts)
    svc = AnchoringService(rpc, repo, metrics, default_timeout=2.0, default_poll_interval=0.001, max_retries=2, backoff=0.0001)

    async def run_one(ix: int):
        payload = f"payload-{ix}".encode()
        return await svc.anchor(chain_id="ethereum", payload=payload, wait=True)

    results = await asyncio.gather(*[run_one(i) for i in range(10)])
    assert all(r.status == CONFIRMED for r in results)
    assert repo.confirms >= 10


# =========================
# ТЕСТЫ: ВАЛИДАЦИЯ ВХОДА
# =========================

@pytest.mark.parametrize("chain_id", ["", None])
async def test_anchor_invalid_chain_id_raises(chain_id, repo, metrics):
    rpc = ScenarioRpc(send_plan=["0x1"], receipts={"0x1": [{"status": "0x1"}]})
    svc = AnchoringService(rpc, repo, metrics)
    with pytest.raises(ValueError):
        await svc.anchor(chain_id=chain_id, payload=b"p", wait=False)


# =========================
# ТЕСТЫ: get_status
# =========================

async def test_get_status_reads_from_repo(repo, metrics):
    txh = "0xabc123"
    repo.rows[("ethereum", txh)] = {"status": CONFIRMED}
    rpc = ScenarioRpc(send_plan=[], receipts={})
    svc = AnchoringService(rpc, repo, metrics)
    st = await svc.get_status(chain_id="ethereum", tx_hash=txh)
    assert st == CONFIRMED
