# ledger-core/ledger/adapters/chains/mock_chain.py
# -*- coding: utf-8 -*-
"""
MockChain — промышленный тестовый адаптер "блокчейна":
- Идемпотентная отправка коммитментов (idempotency_key)
- Асинхронное "майнинг"-событие с настраиваемым интервалом блоков
- Подтверждения (confirmations), ожидание с таймаутом
- Мнимые комиссии (fee), квазипул мемпула, квитанции (tx_id, block_height, anchor_ts)
- Инъекция отказов/задержек/перегрузки, реорганизации (reorg) заданной глубины
- Совместим с интерфейсом AnchorClient из ledger/anchoring/batcher.py
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from ..utils.idgen import monotonic_ulid  # опционально; если нет — замените на локальную реализацию
# Если у вас нет utils.idgen.monotonic_ulid, раскомментируйте заглушку ниже.
# def monotonic_ulid() -> str:
#     raw = hashlib.sha256(f"{time.time_ns()}-{os.getpid()}-{random.random()}".encode()).digest()[:10]
#     return base64.b32encode(raw).decode("ascii").rstrip("=")

LOG = logging.getLogger("ledger.adapters.mock_chain")


# Исключения совместимы с анкорингом
class ClientError(Exception): ...
class PermanentClientError(ClientError): ...
class TransientClientError(ClientError): ...


@dataclass(frozen=True)
class MockChainConfig:
    block_interval_sec: float = 1.0           # интервал майнинга блоков
    target_tx_per_block: int = 500            # вместимость блока
    base_fee: int = 1000                      # базовая комиссия в "микроединицах"
    fee_volatility: float = 0.1               # +-10% шума
    rps_limit: int = 200                      # ограничение запросов submit в секунду
    idem_ttl_sec: int = 24 * 3600             # TTL кэша идемпотентности
    failure_ratio_transient: float = 0.0      # вероятность временной ошибки
    failure_ratio_permanent: float = 0.0      # вероятность постоянной ошибки
    artificial_delay_ms: int = 0              # искусственная задержка на отправку, мс
    max_reorg_depth: int = 0                  # максимальная глубина реорганизации
    reorg_probability: float = 0.0            # вероятность реорганизации при добыче блока
    confirmations_required_default: int = 1   # базовое число подтверждений


@dataclass
class TxRecord:
    tx_id: str
    commitment_hash: str
    idempotency_key: str
    submitted_at_ms: int
    fee_paid: int
    status: str = "pending"                   # pending|mined|finalized|reorged|dropped
    block_height: Optional[int] = None
    anchor_ts: Optional[int] = None           # время включения в блок


class MockChain:
    """
    Эмулятор блокчейна с подтверждениями и реорганизациями.
    Публичный API совместим с AnchorClient: submit_commitment().
    Дополнительно: get_tx(), wait_confirmations(), start(), stop().
    """

    def __init__(self, cfg: Optional[MockChainConfig] = None) -> None:
        self._cfg = cfg or MockChainConfig()
        self._height = 0
        self._mempool: Dict[str, TxRecord] = {}
        self._by_txid: Dict[str, TxRecord] = {}
        self._by_idem: Dict[str, Tuple[int, str]] = {}  # idem_key -> (expires_at, tx_id)
        self._per_height: Dict[int, Dict[str, TxRecord]] = {}
        self._submit_times: Dict[int, int] = {}  # sec -> count (для RPS)
        self._loop_task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()

    # ---------------- Публичный API ----------------

    async def start(self) -> None:
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._mining_loop(), name="mock-chain-miner")

    async def stop(self) -> None:
        self._stop.set()
        if self._loop_task:
            await self._loop_task

    async def submit_commitment(self, *, commitment: bytes, idempotency_key: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Идемпотентная отправка коммитмента.
        Возвращает receipt: {status, tx_id, idempotency_key, anchor_ts?}
        Может бросить TransientClientError или PermanentClientError.
        """
        await self._apply_artificial_delay()
        async with self._lock:
            self._enforce_rps()

            # Идемпотентность
            now = int(time.time())
            self._gc_idem(now)
            cached = self._by_idem.get(idempotency_key)
            if cached:
                tx_id = cached[1]
                tx = self._by_txid.get(tx_id)
                if tx:
                    return self._to_receipt(tx)

            # Инъекция сбоев
            self._maybe_fail()

            # Создание транзакции
            tx_id = self._gen_tx_id(commitment)
            fee = self._simulate_fee()
            rec = TxRecord(
                tx_id=tx_id,
                commitment_hash=self._hash_hex(commitment),
                idempotency_key=idempotency_key,
                submitted_at_ms=self._now_ms(),
                fee_paid=fee,
            )
            self._mempool[tx_id] = rec
            self._by_txid[tx_id] = rec
            self._by_idem[idempotency_key] = (now + self._cfg.idem_ttl_sec, tx_id)

            LOG.debug("mock_chain: submit tx_id=%s idem=%s", tx_id, idempotency_key,
                      extra={"extra": {"tx_id": tx_id, "idempotency_key": idempotency_key}})

            return self._to_receipt(rec)

    async def get_tx(self, tx_id: str) -> Optional[Dict[str, Any]]:
        async with self._lock:
            tx = self._by_txid.get(tx_id)
            return self._to_receipt(tx) if tx else None

    async def wait_confirmations(
        self,
        tx_id: str,
        *,
        min_confirmations: Optional[int] = None,
        timeout_sec: Optional[float] = None,
        poll_interval_sec: float = 0.25,
    ) -> Dict[str, Any]:
        """
        Ожидает требуемое число подтверждений.
        Возвращает receipt последнего известного состояния.
        """
        min_conf = min_confirmations or self._cfg.confirmations_required_default
        deadline = time.time() + timeout_sec if timeout_sec else None
        while True:
            rcpt = await self.get_tx(tx_id)
            if not rcpt:
                raise PermanentClientError("tx not found")
            if rcpt["status"] in ("finalized", "reorged", "dropped"):
                return rcpt
            if rcpt["status"] == "mined" and rcpt.get("confirmations", 0) >= min_conf:
                return rcpt
            if deadline and time.time() >= deadline:
                return rcpt
            await asyncio.sleep(poll_interval_sec)

    # ---------------- Внутренняя логика ----------------

    async def _mining_loop(self) -> None:
        """
        Периодически формирует блоки из мемпула.
        С вероятностью reorg_probability может выполнить реорганизацию до max_reorg_depth.
        """
        try:
            while not self._stop.is_set():
                await asyncio.sleep(self._cfg.block_interval_sec)
                try:
                    async with self._lock:
                        # Редко симулируем реорганизацию
                        if self._cfg.max_reorg_depth > 0 and random.random() < self._cfg.reorg_probability:
                            depth = random.randint(1, min(self._cfg.max_reorg_depth, max(self._height, 1)))
                            self._do_reorg(depth)

                        # Формируем новый блок
                        if not self._mempool:
                            self._advance_empty_block()
                            continue
                        self._mine_block()
                except Exception as e:
                    LOG.exception("mock_chain: mining iteration error: %s", e)
        finally:
            LOG.info("mock_chain: miner stopped at height=%d", self._height)

    def _mine_block(self) -> None:
        capacity = max(1, self._cfg.target_tx_per_block)
        tx_ids = list(self._mempool.keys())[:capacity]
        self._height += 1
        blk = {}
        for tx_id in tx_ids:
            tx = self._mempool.pop(tx_id, None)
            if not tx:
                continue
            tx.block_height = self._height
            tx.anchor_ts = self._now_ms()
            tx.status = "mined"
            blk[tx_id] = tx
        self._per_height[self._height] = blk
        LOG.debug("mock_chain: mined block #%d, txs=%d", self._height, len(blk),
                  extra={"extra": {"height": self._height, "txs": len(blk)}})

        # Продвигаем финализацию: считаем finalized, если у блока >= 6 подтверждений
        self._update_confirmations()

    def _advance_empty_block(self) -> None:
        self._height += 1
        self._per_height[self._height] = {}
        self._update_confirmations()

    def _update_confirmations(self) -> None:
        tip = self._height
        for h in range(max(1, tip - 1024), tip + 1):
            blk = self._per_height.get(h)
            if not blk:
                continue
            conf = max(0, tip - h + 1)
            for tx in blk.values():
                # status остаётся "mined", но при conf >= 6 можно промаркировать finalized
                if conf >= 6 and tx.status == "mined":
                    tx.status = "finalized"

    def _do_reorg(self, depth: int) -> None:
        """
        Реорганизация на заданную глубину: переносим транзакции из меняемых блоков обратно в мемпул,
        уменьшаем высоту, затем пусть майнинг включит их повторно.
        """
        if depth <= 0 or self._height == 0:
            return
        reorg_from = max(1, self._height - depth + 1)
        LOG.warning("mock_chain: REORG depth=%d from_height=%d", depth, reorg_from,
                    extra={"extra": {"depth": depth, "from": reorg_from}})
        # Соберём tx обратно
        for h in range(reorg_from, self._height + 1):
            blk = self._per_height.get(h, {})
            for tx in blk.values():
                # пометим как reorged и вернём в мемпул для повторного включения
                tx.status = "reorged"
                tx.block_height = None
                self._mempool[tx.tx_id] = tx
        # Урежем цепь
        for h in range(reorg_from, self._height + 1):
            self._per_height.pop(h, None)
        self._height = reorg_from - 1

    # ---------------- Вспомогательные методы ----------------

    def _simulate_fee(self) -> int:
        base = self._cfg.base_fee
        if self._cfg.fee_volatility > 0:
            jitter = 1.0 + (2 * random.random() - 1.0) * self._cfg.fee_volatility
            return max(1, int(base * jitter))
        return base

    def _to_receipt(self, tx: TxRecord) -> Dict[str, Any]:
        if not tx:
            return {}
        tip = self._height
        confirmations = 0
        if tx.block_height:
            confirmations = max(0, tip - tx.block_height + 1)
        return {
            "status": tx.status,
            "tx_id": tx.tx_id,
            "idempotency_key": tx.idempotency_key,
            "anchor_ts": tx.anchor_ts,
            "block_height": tx.block_height,
            "confirmations": confirmations,
            "fee_paid": tx.fee_paid,
        }

    def _gen_tx_id(self, commitment: bytes) -> str:
        # Детерминируемый и короткий tx_id для удобства логов
        h = hashlib.sha256(commitment).digest()
        return base64.urlsafe_b64encode(h[:12]).decode("ascii").rstrip("=")

    def _hash_hex(self, b: bytes) -> str:
        return hashlib.sha256(b).hexdigest()

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def _gc_idem(self, now_sec: int) -> None:
        expired = [k for k, (exp, _) in self._by_idem.items() if exp <= now_sec]
        for k in expired:
            self._by_idem.pop(k, None)

    def _enforce_rps(self) -> None:
        sec = int(time.time())
        cnt = self._submit_times.get(sec, 0)
        if cnt >= self._cfg.rps_limit:
            raise TransientClientError("rate_limited")
        self._submit_times[sec] = cnt + 1

    def _maybe_fail(self) -> None:
        if self._cfg.failure_ratio_permanent > 0 and random.random() < self._cfg.failure_ratio_permanent:
            raise PermanentClientError("permanent_failure_injected")
        if self._cfg.failure_ratio_transient > 0 and random.random() < self._cfg.failure_ratio_transient:
            raise TransientClientError("transient_failure_injected")

    async def _apply_artificial_delay(self) -> None:
        if self._cfg.artificial_delay_ms > 0:
            await asyncio.sleep(self._cfg.artificial_delay_ms / 1000.0)


# Фабрика по умолчанию (удобно мокать в тестах)
def default_mock_chain() -> MockChain:
    return MockChain(MockChainConfig())


# Пример самостоятельного запуска (dev)
if __name__ == "__main__":  # pragma: no cover
    import asyncio
    logging.basicConfig(level=logging.INFO)

    async def main():
        chain = MockChain(MockChainConfig(block_interval_sec=0.5, reorg_probability=0.05, max_reorg_depth=2))
        await chain.start()
        try:
            # имитируем клиент анкоринга
            for i in range(5):
                payload = f'{{"schema":1,"root_b64":"{i}","leaf_count":1,"ts":{int(time.time()*1000)}}}'.encode()
                rcpt = await chain.submit_commitment(commitment=payload, idempotency_key=f"id-{i}", metadata={"i": i})
                print("submitted:", rcpt)
            # ждём подтверждений первой транзакции
            first_tx = rcpt["tx_id"]
            done = await chain.wait_confirmations(first_tx, min_confirmations=2, timeout_sec=10)
            print("confirmed:", done)
        finally:
            await chain.stop()

    asyncio.run(main())
