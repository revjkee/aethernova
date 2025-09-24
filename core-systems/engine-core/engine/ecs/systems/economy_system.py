# -*- coding: utf-8 -*-
"""
ECS Economy System (industrial-grade)

Назначение:
- Управление денежной экономикой в ECS на уровне систем.
- Единая точка приёма команд (deposit/withdraw/transfer/convert/hold/capture/release/batch).
- Идемпотентность по operation_id и пер-энтити rate-limit.
- Саги покупок (hold -> capture/auto-expire -> refund), дедлайны через AsyncEventLoop.
- Хранилище и индексы кошельков, снапшоты/восстановление состояния.
- Интеграция с engine.event_loop.AsyncEventLoop (планирование отложенных задач).
- Аудит и метрики-хуки.

Зависимости: стандартная библиотека + локальный компонент EconWallet.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Literal, Optional, Tuple, Callable

# Компонент кошелька
from engine.engine.ecs.components.econ_wallet import EconWallet, FXProvider, PolicyEngine, WalletError, InsufficientFunds, CurrencyNotSupported

# Опциональная интеграция с нашим супервайзером событий
try:
    from engine.engine.event_loop import AsyncEventLoop, RetryPolicy
    HAS_LOOP = True
except Exception:
    HAS_LOOP = False

# -----------------------------------------------------------------------------
# Утилиты/мета
# -----------------------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _uuid() -> str:
    return str(uuid.uuid4())

# -----------------------------------------------------------------------------
# Аудит/Метрики (заглушки)
# -----------------------------------------------------------------------------
class Audit:
    @staticmethod
    def emit(event: Dict[str, Any]) -> None:
        # В проде: шина событий/лог
        pass

class Metrics:
    @staticmethod
    def inc(name: str, **labels) -> None:
        pass

    @staticmethod
    def observe(name: str, value: float, **labels) -> None:
        pass

# -----------------------------------------------------------------------------
# Rate limit per-entity
# -----------------------------------------------------------------------------
class TokenBucket:
    def __init__(self, rate: int, per_seconds: int):
        self.capacity = max(1, rate)
        self.tokens = self.capacity
        self.per_seconds = max(1, per_seconds)
        self.updated_at = time.time()
        self._lock = threading.RLock()

    def try_consume(self, n: int = 1) -> bool:
        with self._lock:
            now = time.time()
            elapsed = now - self.updated_at
            refill = int((elapsed / self.per_seconds) * self.capacity)
            if refill > 0:
                self.tokens = min(self.capacity, self.tokens + refill)
                self.updated_at = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False

# -----------------------------------------------------------------------------
# Команды и события системы
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class Command:
    type: Literal[
        "deposit", "withdraw", "transfer", "convert",
        "hold_create", "hold_capture", "hold_release",
        "batch", "purchase_start", "purchase_capture", "purchase_cancel"
    ]
    operation_id: str
    payload: Dict[str, Any]

@dataclass(frozen=True)
class Event:
    type: Literal[
        "wallet_updated", "hold_created", "hold_captured", "hold_released",
        "purchase_started", "purchase_captured", "purchase_cancelled",
        "command_rejected", "command_duplicate"
    ]
    ts: datetime
    entity_id: str
    data: Dict[str, Any]

# -----------------------------------------------------------------------------
# Состояния саг покупок
# -----------------------------------------------------------------------------
@dataclass
class PurchaseSaga:
    purchase_id: str
    entity_id: str
    currency: str
    amount: Decimal
    hold_id: str
    status: Literal["started", "captured", "cancelled"] = "started"
    created_at: datetime = field(default_factory=now_utc)
    expires_at: Optional[datetime] = None
    meta: Dict[str, Any] = field(default_factory=dict)

# -----------------------------------------------------------------------------
# Экономическая система
# -----------------------------------------------------------------------------
class EconomySystem:
    """
    Центральная система экономики для ECS.
    """

    def __init__(
        self,
        *,
        fx_provider: Optional[FXProvider] = None,
        policy_factory: Optional[Callable[[], PolicyEngine]] = None,
        supported_currencies: Optional[List[str]] = None,
        loop: Optional["AsyncEventLoop"] = None,
        rate_limit_per_entity: Tuple[int, int] = (60, 60),  # 60 команд в 60с
    ):
        self.fx_provider = fx_provider or FXProvider()
        self.policy_factory = policy_factory or (lambda: PolicyEngine())
        self.supported_currencies = supported_currencies or ["USD"]
        self.loop = loop  # может быть None — таймеры саг тогда не активируются
        self._wallets: Dict[str, EconWallet] = {}
        self._idempotency: Dict[str, Any] = {}            # operation_id -> result
        self._idem_ttl: Dict[str, float] = {}             # operation_id -> ts
        self._idem_ttl_seconds = 900
        self._bucket_by_entity: Dict[str, TokenBucket] = {}
        self._bucket_config = rate_limit_per_entity
        self._sagas: Dict[str, PurchaseSaga] = {}
        self._cmd_lock = threading.RLock()

    # ---------------------- Wallet registry ---------------------- #

    def ensure_wallet(self, entity_id: str) -> EconWallet:
        w = self._wallets.get(entity_id)
        if w:
            return w
        with self._cmd_lock:
            w = self._wallets.get(entity_id)
            if w:
                return w
            w = EconWallet(
                entity_id=entity_id,
                supported_currencies=list(self.supported_currencies),
                fx=self.fx_provider,
                policy=self.policy_factory(),
            )
            self._wallets[entity_id] = w
        return w

    # ---------------------- Idempotency ---------------------- #

    def _idem_key(self, cmd: Command) -> str:
        return f"{cmd.type}:{cmd.operation_id}"

    def _idem_get_or_set(self, cmd: Command, compute: Callable[[], Any]) -> Tuple[bool, Any]:
        """
        Возвращает (is_duplicate, value). При дубле — True и предыдущее значение.
        """
        key = self._idem_key(cmd)
        now = time.time()
        with self._cmd_lock:
            # GC старых ключей
            for k, ts in list(self._idem_ttl.items()):
                if now - ts > self._idem_ttl_seconds:
                    self._idempotency.pop(k, None)
                    self._idem_ttl.pop(k, None)
            if key in self._idempotency:
                return True, self._idempotency[key]
            value = compute()
            self._idempotency[key] = value
            self._idem_ttl[key] = now
            return False, value

    # ---------------------- Rate limit ---------------------- #

    def _bucket(self, entity_id: str) -> TokenBucket:
        b = self._bucket_by_entity.get(entity_id)
        if b:
            return b
        rate, per_s = self._bucket_config
        b = TokenBucket(rate, per_s)
        self._bucket_by_entity[entity_id] = b
        return b

    # ---------------------- Public API: command handling ---------------------- #

    def handle(self, cmd: Command) -> List[Event]:
        """
        Синхронная обработка команды с идемпотентностью и rate-limit.
        Возвращает список событий.
        """
        # Базовые проверки
        if not cmd.operation_id:
            raise ValueError("operation_id required")

        # Определим адресата
        p = cmd.payload
        entity_id = p.get("entity_id") or p.get("from_entity_id") or p.get("to_entity_id")
        if not entity_id:
            raise ValueError("entity_id required")

        # rate-limit
        if not self._bucket(entity_id).try_consume(1):
            return [Event("command_rejected", now_utc(), entity_id, {"reason": "rate_limited"})]

        # идемпотентность
        def _apply() -> List[Event]:
            try:
                if cmd.type == "deposit":
                    return self._cmd_deposit(cmd)
                if cmd.type == "withdraw":
                    return self._cmd_withdraw(cmd)
                if cmd.type == "transfer":
                    return self._cmd_transfer(cmd)
                if cmd.type == "convert":
                    return self._cmd_convert(cmd)
                if cmd.type == "hold_create":
                    return self._cmd_hold_create(cmd)
                if cmd.type == "hold_capture":
                    return self._cmd_hold_capture(cmd)
                if cmd.type == "hold_release":
                    return self._cmd_hold_release(cmd)
                if cmd.type == "batch":
                    return self._cmd_batch(cmd)
                if cmd.type == "purchase_start":
                    return self._cmd_purchase_start(cmd)
                if cmd.type == "purchase_capture":
                    return self._cmd_purchase_capture(cmd)
                if cmd.type == "purchase_cancel":
                    return self._cmd_purchase_cancel(cmd)
                raise ValueError(f"unknown command type {cmd.type}")
            except (WalletError, CurrencyNotSupported, InsufficientFunds) as e:
                Metrics.inc("economy_command_fail", type=cmd.type, reason=type(e).__name__)
                return [Event("command_rejected", now_utc(), entity_id, {"reason": type(e).__name__, "message": str(e)})]

        is_dup, res = self._idem_get_or_set(cmd, _apply)
        if is_dup:
            return [Event("command_duplicate", now_utc(), entity_id, {"operation_id": cmd.operation_id})] + list(res)
        return list(res)

    # ---------------------- Command implementations ---------------------- #

    def _cmd_deposit(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        w = self.ensure_wallet(p["entity_id"])
        after = w.deposit(p["amount"], currency=p["currency"], operation_id=cmd.operation_id, meta=p.get("meta"))
        Metrics.inc("economy_deposit", currency=p["currency"])
        return [Event("wallet_updated", now_utc(), w.entity_id, {"currency": p["currency"], "balance": str(after)})]

    def _cmd_withdraw(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        w = self.ensure_wallet(p["entity_id"])
        after = w.withdraw(p["amount"], currency=p["currency"], operation_id=cmd.operation_id, meta=p.get("meta"))
        Metrics.inc("economy_withdraw", currency=p["currency"])
        return [Event("wallet_updated", now_utc(), w.entity_id, {"currency": p["currency"], "balance": str(after)})]

    def _cmd_transfer(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        src = self.ensure_wallet(p["from_entity_id"])
        dst = self.ensure_wallet(p["to_entity_id"])
        after_src, after_dst = src.transfer_to(dst, p["amount"], currency=p["currency"], operation_id=cmd.operation_id, meta=p.get("meta"))
        Metrics.inc("economy_transfer", currency=p["currency"])
        return [
            Event("wallet_updated", now_utc(), src.entity_id, {"currency": p["currency"], "balance": str(after_src)}),
            Event("wallet_updated", now_utc(), dst.entity_id, {"currency": p["currency"], "balance": str(after_dst)}),
        ]

    def _cmd_convert(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        w = self.ensure_wallet(p["entity_id"])
        after_src, after_dst = w.convert(p["amount"], from_ccy=p["from_currency"], to_ccy=p["to_currency"], operation_id=cmd.operation_id, meta=p.get("meta"))
        Metrics.inc("economy_convert", from_currency=p["from_currency"], to_currency=p["to_currency"])
        return [
            Event("wallet_updated", now_utc(), w.entity_id, {"currency": p["from_currency"], "balance": str(after_src)}),
            Event("wallet_updated", now_utc(), w.entity_id, {"currency": p["to_currency"], "balance": str(after_dst)}),
        ]

    def _cmd_hold_create(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        w = self.ensure_wallet(p["entity_id"])
        hid = w.create_hold(p["amount"], currency=p["currency"], hold_id=p.get("hold_id"), expires_at=p.get("expires_at"), operation_id=cmd.operation_id, meta=p.get("meta"))
        Metrics.inc("economy_hold_create", currency=p["currency"])
        return [
            Event("hold_created", now_utc(), w.entity_id, {"hold_id": hid, "currency": p["currency"], "amount": str(p["amount"])}),
            Event("wallet_updated", now_utc(), w.entity_id, {"currency": p["currency"], "balance": str(w.get_balance(p["currency"]))}),
        ]

    def _cmd_hold_capture(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        w = self.ensure_wallet(p["entity_id"])
        w.capture_hold(p["hold_id"], operation_id=cmd.operation_id, meta=p.get("meta"))
        Metrics.inc("economy_hold_capture")
        return [Event("hold_captured", now_utc(), w.entity_id, {"hold_id": p["hold_id"]})]

    def _cmd_hold_release(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        w = self.ensure_wallet(p["entity_id"])
        after = w.release_hold(p["hold_id"], operation_id=cmd.operation_id, meta=p.get("meta"))
        Metrics.inc("economy_hold_release")
        return [
            Event("hold_released", now_utc(), w.entity_id, {"hold_id": p["hold_id"]}),
            Event("wallet_updated", now_utc(), w.entity_id, {"currency": p.get("currency") or "", "balance": str(after)}),
        ]

    def _cmd_batch(self, cmd: Command) -> List[Event]:
        """
        Транзакционный батч: либо все операции применяются, либо ни одна.
        Для простоты: батч ограничивается одной сущностью.
        """
        p = cmd.payload
        entity_id = p["entity_id"]
        ops: List[Dict[str, Any]] = p["operations"]
        w = self.ensure_wallet(entity_id)

        # Снимем снапшот для отката
        snapshot = w.snapshot()
        events: List[Event] = []
        try:
            for i, op in enumerate(ops):
                sub_cmd = Command(type=op["type"], operation_id=f"{cmd.operation_id}:{i}", payload={**op, "entity_id": entity_id})
                evs = self.handle(sub_cmd)
                # если вернулся reject — инициируем откат
                for e in evs:
                    if e.type == "command_rejected":
                        raise WalletError(f"batch failed: op#{i} {e.data}")
                events.extend(evs)
        except Exception:
            # откат
            restored = self._restore_wallet(entity_id, snapshot)
            Metrics.inc("economy_batch_rollback")
            return [Event("command_rejected", now_utc(), entity_id, {"reason": "batch_rollback"})]
        Metrics.inc("economy_batch_commit")
        return events

    # ---------------------- Purchase Sagas ---------------------- #

    def _cmd_purchase_start(self, cmd: Command) -> List[Event]:
        """
        Начинает покупку: создаёт hold и планирует авто-истечение, если loop указан.
        payload: {entity_id, currency, amount, purchase_id?, expires_in_s?, meta?}
        """
        p = cmd.payload
        w = self.ensure_wallet(p["entity_id"])
        purchase_id = p.get("purchase_id") or _uuid()
        hold_id = p.get("hold_id") or f"hold:{purchase_id}"

        expires_at = None
        if p.get("expires_in_s"):
            expires_at = now_utc() + timedelta(seconds=int(p["expires_in_s"]))

        # Сама резервная операция идемпотентна по operation_id
        w.create_hold(p["amount"], currency=p["currency"], hold_id=hold_id, expires_at=expires_at, operation_id=cmd.operation_id, meta={"purchase_id": purchase_id, **(p.get("meta") or {})})

        saga = self._sagas.get(purchase_id)
        if not saga:
            saga = PurchaseSaga(
                purchase_id=purchase_id,
                entity_id=w.entity_id,
                currency=p["currency"],
                amount=Decimal(str(p["amount"])),
                hold_id=hold_id,
                expires_at=expires_at,
                meta=p.get("meta") or {},
            )
            self._sagas[purchase_id] = saga

        # Планируем авто-cancel при истечении (если не будет capture)
        if expires_at and self.loop and HAS_LOOP:
            delay = max(0, int((expires_at - now_utc()).total_seconds()))
            async def _auto_cancel():
                # если к моменту дедлайна транзакция не захвачена — отменяем
                s = self._sagas.get(purchase_id)
                if s and s.status == "started":
                    self.handle(Command(
                        type="purchase_cancel",
                        operation_id=f"auto_cancel:{purchase_id}",
                        payload={"entity_id": w.entity_id, "purchase_id": purchase_id, "hold_id": hold_id}
                    ))
            self.loop.register_delayed(f"purchase_deadline:{purchase_id}", lambda: _auto_task(_auto_cancel), delay_s=delay)

        Metrics.inc("economy_purchase_started", currency=p["currency"])
        return [
            Event("purchase_started", now_utc(), w.entity_id, {"purchase_id": purchase_id, "hold_id": hold_id, "amount": str(p["amount"]), "currency": p["currency"]})
        ]

    def _cmd_purchase_capture(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        purchase_id = p["purchase_id"]
        saga = self._sagas.get(purchase_id)
        if not saga:
            return [Event("command_rejected", now_utc(), p["entity_id"], {"reason": "saga_not_found"})]
        if saga.status != "started":
            return [Event("command_rejected", now_utc(), p["entity_id"], {"reason": f"invalid_state:{saga.status}"})]

        w = self.ensure_wallet(saga.entity_id)
        w.capture_hold(saga.hold_id, operation_id=cmd.operation_id, meta={"purchase_id": saga.purchase_id, **(p.get("meta") or {})})
        saga.status = "captured"
        Metrics.inc("economy_purchase_captured", currency=saga.currency)
        return [Event("purchase_captured", now_utc(), w.entity_id, {"purchase_id": purchase_id, "hold_id": saga.hold_id})]

    def _cmd_purchase_cancel(self, cmd: Command) -> List[Event]:
        p = cmd.payload
        purchase_id = p["purchase_id"]
        saga = self._sagas.get(purchase_id)
        if not saga:
            return [Event("command_rejected", now_utc(), p["entity_id"], {"reason": "saga_not_found"})]
        if saga.status != "started":
            return [Event("command_rejected", now_utc(), p["entity_id"], {"reason": f"invalid_state:{saga.status}"})]
        w = self.ensure_wallet(saga.entity_id)
        after = w.release_hold(saga.hold_id, operation_id=cmd.operation_id, meta={"purchase_id": saga.purchase_id, **(p.get("meta") or {})})
        saga.status = "cancelled"
        Metrics.inc("economy_purchase_cancelled", currency=saga.currency)
        return [
            Event("purchase_cancelled", now_utc(), w.entity_id, {"purchase_id": purchase_id, "hold_id": saga.hold_id}),
            Event("wallet_updated", now_utc(), w.entity_id, {"currency": saga.currency, "balance": str(after)}),
        ]

    # ---------------------- Snapshot / Restore ---------------------- #

    def snapshot(self) -> Dict[str, Any]:
        """
        Снимок всей системы (кошельки, саги, idem).
        """
        with self._cmd_lock:
            return {
                "time": now_utc().isoformat(),
                "wallets": {eid: w.snapshot() for eid, w in self._wallets.items()},
                "sagas": {
                    pid: {
                        "purchase_id": s.purchase_id,
                        "entity_id": s.entity_id,
                        "currency": s.currency,
                        "amount": str(s.amount),
                        "hold_id": s.hold_id,
                        "status": s.status,
                        "created_at": s.created_at.isoformat(),
                        "expires_at": s.expires_at.isoformat() if s.expires_at else None,
                        "meta": s.meta,
                    } for pid, s in self._sagas.items()
                },
                "idem": list(self._idempotency.keys()),
            }

    def restore(self, data: Dict[str, Any]) -> None:
        """
        Восстановление состояния системы. Идемпотентные ключи восстанавливаются пустыми.
        """
        wallets = data.get("wallets") or {}
        sagas = data.get("sagas") or {}
        with self._cmd_lock:
            self._wallets.clear()
            for eid, snap in wallets.items():
                self._wallets[eid] = EconWallet.restore(snap)
            self._sagas.clear()
            for pid, s in sagas.items():
                self._sagas[pid] = PurchaseSaga(
                    purchase_id=s["purchase_id"],
                    entity_id=s["entity_id"],
                    currency=s["currency"],
                    amount=Decimal(str(s["amount"])),
                    hold_id=s["hold_id"],
                    status=s["status"],
                    created_at=datetime.fromisoformat(s["created_at"]),
                    expires_at=datetime.fromisoformat(s["expires_at"]) if s.get("expires_at") else None,
                    meta=s.get("meta") or {},
                )
            # idem список — не переносим значения, только метки, чтобы не повторять действия
            self._idempotency = {k: [] for k in (data.get("idem") or [])}
            now = time.time()
            self._idem_ttl = {k: now for k in self._idempotency.keys()}

    # ---------------------- Internal helpers ---------------------- #

    def _restore_wallet(self, entity_id: str, snapshot: Dict[str, Any]) -> EconWallet:
        w = EconWallet.restore(snapshot)
        self._wallets[entity_id] = w
        return w

# -----------------------------------------------------------------------------
# Вспомогательное: обёртка для асинхронной ламбды в AsyncEventLoop
# -----------------------------------------------------------------------------
async def _auto_task(coro_factory: Callable[[], Any]) -> None:
    await coro_factory()

# -----------------------------------------------------------------------------
# Демонстрация локального использования
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    sys = EconomySystem(supported_currencies=["USD", "EUR"])

    def cmd(t, op_id, **payload):
        return Command(type=t, operation_id=op_id, payload=payload)

    # Пополнение и перевод
    evs = sys.handle(cmd("deposit", "op1", entity_id="p1", currency="USD", amount="100.00"))
    evs += sys.handle(cmd("transfer", "op2", from_entity_id="p1", to_entity_id="p2", currency="USD", amount="15.50"))
    for e in evs:
        print(e)

    # Покупка с резервом и захватом
    evs = sys.handle(cmd("purchase_start", "op3", entity_id="p1", currency="USD", amount="30.00", purchase_id="order-1", expires_in_s=10))
    evs += sys.handle(cmd("purchase_capture", "op4", entity_id="p1", purchase_id="order-1"))
    for e in evs:
        print(e)

    # Идемпотентность (повтор оп1)
    dup = sys.handle(cmd("deposit", "op1", entity_id="p1", currency="USD", amount="100.00"))
    for e in dup:
        print("dup:", e)

    # Снапшот/восстановление
    snap = sys.snapshot()
    sys2 = EconomySystem(supported_currencies=["USD", "EUR"])
    sys2.restore(snap)
    print("restored wallets:", list(sys2._wallets.keys()))
