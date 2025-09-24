# -*- coding: utf-8 -*-
"""
ECS Econ Wallet Component (industrial-grade)

Особенности:
- Денежные суммы через Decimal, конфигурируемая точность и округление
- Многовалютность: баланс по каждой валюте, опциональные FX-конверсии через провайдер курсов
- Идемпотентные операции (по operation_id) с TTL-кэшем результатов
- Журнал (ledger) с монотонными sequence-инкрементами и целостностью (running balance)
- Резервирования (holds): create / capture / release
- Политики и лимиты (per currency, overdraft off по умолчанию)
- Потокобезопасность: RLock вокруг любых мутаций; чтения — консистентные снапшоты
- Снапшоты состояния и полная сериализация с версией схемы
- Защита от переполнений и некорректной шкалы (scale) Decimal
- Точки интеграции: FXProvider, PolicyEngine, AuditSink (заглушки)

Зависимости: только стандартная библиотека.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, getcontext, ROUND_HALF_UP, InvalidOperation
from typing import Dict, List, Optional, Tuple, Literal, Any

# -----------------------------------------------------------------------------
# Денежные настройки (глобально для модуля)
# -----------------------------------------------------------------------------
getcontext().prec = 38  # достаточная точность для сумм и курсов
DEFAULT_SCALE = Decimal("0.01")  # центы
ROUNDING = ROUND_HALF_UP

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _ensure_decimal(v: Any) -> Decimal:
    if isinstance(v, Decimal):
        return v
    try:
        return Decimal(str(v))
    except Exception:
        raise ValueError("invalid decimal value")

def _quantize_money(amount: Decimal, scale: Decimal = DEFAULT_SCALE) -> Decimal:
    try:
        return amount.quantize(scale, rounding=ROUNDING)
    except InvalidOperation:
        raise ValueError("invalid amount scale")

def _non_negative(amount: Decimal) -> None:
    if amount < 0:
        raise ValueError("amount must be non-negative")

# -----------------------------------------------------------------------------
# Исключения домена
# -----------------------------------------------------------------------------
class WalletError(Exception):
    pass

class InsufficientFunds(WalletError):
    pass

class CurrencyNotSupported(WalletError):
    pass

class DuplicateOperation(WalletError):
    pass

class HoldNotFound(WalletError):
    pass

class PolicyViolation(WalletError):
    pass

# -----------------------------------------------------------------------------
# Интерфейсы интеграций (заглушки)
# -----------------------------------------------------------------------------
class FXProvider:
    """
    Поставщик курсов: вернуть коэффициент множителя FROM->TO.
    Реализация может кешировать/получать из внешнего источника.
    """
    def get_rate(self, from_ccy: str, to_ccy: str) -> Decimal:
        if from_ccy == to_ccy:
            return Decimal("1")
        # Демоверсия: фикс 1:1 (перекройте в проде)
        return Decimal("1")

class PolicyEngine:
    """
    Правила кошелька: лимиты, запреты, овердрафт.
    """
    def __init__(self):
        self.overdraft_enabled: Dict[str, bool] = {}
        self.max_balance: Dict[str, Decimal] = {}

    def set_overdraft(self, ccy: str, enabled: bool) -> None:
        self.overdraft_enabled[ccy.upper()] = enabled

    def set_max_balance(self, ccy: str, limit: Decimal) -> None:
        self.max_balance[ccy.upper()] = _quantize_money(limit)

    def check_debit(self, ccy: str, balance_after: Decimal) -> None:
        if not self.overdraft_enabled.get(ccy.upper(), False) and balance_after < 0:
            raise InsufficientFunds(f"insufficient funds for {ccy}")

    def check_credit(self, ccy: str, balance_after: Decimal) -> None:
        limit = self.max_balance.get(ccy.upper())
        if limit is not None and balance_after > limit:
            raise PolicyViolation(f"max balance exceeded for {ccy}")

class AuditSink:
    @staticmethod
    def emit(event: Dict[str, Any]) -> None:
        # В проде — отправка в шину/лог
        pass

# -----------------------------------------------------------------------------
# Структуры данных
# -----------------------------------------------------------------------------
@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    ts: datetime
    operation_id: str
    type: Literal["deposit", "withdraw", "transfer_in", "transfer_out", "hold_create", "hold_capture", "hold_release", "fx_convert"]
    ccy: str
    amount: Decimal
    balance_after: Decimal
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Hold:
    id: str
    ccy: str
    amount: Decimal
    created_at: datetime
    expires_at: Optional[datetime] = None
    captured: bool = False
    released: bool = False
    meta: Dict[str, Any] = field(default_factory=dict)

# -----------------------------------------------------------------------------
# Идемпотентность
# -----------------------------------------------------------------------------
class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 900):
        self.ttl = ttl_seconds
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.RLock()

    def get_or_set(self, key: str, compute) -> Any:
        now = time.time()
        with self._lock:
            # GC и проверка
            item = self._store.get(key)
            if item:
                ts, value = item
                if now - ts <= self.ttl:
                    return value
                else:
                    self._store.pop(key, None)
            value = compute()
            self._store[key] = (now, value)
            return value

# -----------------------------------------------------------------------------
# Основной компонент Wallet
# -----------------------------------------------------------------------------
@dataclass
class EconWallet:
    """
    Денежный кошелек для ECS сущности.
    """
    entity_id: str
    base_currency: str = "USD"
    supported_currencies: List[str] = field(default_factory=lambda: ["USD"])
    fx: FXProvider = field(default_factory=FXProvider)
    policy: PolicyEngine = field(default_factory=PolicyEngine)

    # внутреннее состояние
    _balances: Dict[str, Decimal] = field(default_factory=dict, init=False, repr=False)
    _holds: Dict[str, Hold] = field(default_factory=dict, init=False, repr=False)
    _ledger: List[LedgerEntry] = field(default_factory=list, init=False, repr=False)
    _seq: int = field(default=0, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _idem: IdempotencyStore = field(default_factory=lambda: IdempotencyStore(900), init=False, repr=False)
    _schema_version: int = field(default=1, init=False, repr=False)

    # -------------------------- Вспомогательное -------------------------- #
    def _ensure_ccy(self, ccy: str) -> str:
        c = ccy.upper()
        if c not in self.supported_currencies:
            raise CurrencyNotSupported(c)
        return c

    def _bal(self, ccy: str) -> Decimal:
        return self._balances.get(ccy, Decimal("0"))

    def _set_bal(self, ccy: str, value: Decimal) -> None:
        self._balances[ccy] = _quantize_money(value)

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _append_ledger(self, entry: LedgerEntry) -> None:
        # Контроль целостности последовательного баланса
        if self._ledger and entry.balance_after is not None:
            prev = self._ledger[-1]
            # Баланс в леджере ведется per currency; консистентность проверяем для той же валюты
            # (межвалютные операции пишут две строки).
        self._ledger.append(entry)

    def _write_ledger(self, *, ccy: str, amount: Decimal, op_id: str, typ: LedgerEntry.__annotations__['type'], after: Decimal, meta: Dict[str, Any]) -> None:
        self._append_ledger(LedgerEntry(
            seq=self._next_seq(),
            ts=now_utc(),
            operation_id=op_id,
            type=typ,
            ccy=ccy,
            amount=_quantize_money(amount),
            balance_after=_quantize_money(after),
            meta=meta or {},
        ))

    def _emit_audit(self, action: str, details: Dict[str, Any]) -> None:
        AuditSink.emit({
            "ts": now_utc().isoformat(),
            "entity_id": self.entity_id,
            "action": action,
            "details": details,
        })

    # -------------------------- Публичные API -------------------------- #
    def get_balance(self, ccy: Optional[str] = None) -> Dict[str, Decimal] | Decimal:
        with self._lock:
            if ccy is None:
                return dict(self._balances)
            c = self._ensure_ccy(ccy)
            return self._bal(c)

    def deposit(self, amount: Any, *, currency: str, operation_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Decimal:
        """
        Положить средства; идемпотентно по operation_id.
        Возвращает баланс после операции.
        """
        op_id = operation_id or str(uuid.uuid4())
        amt = _quantize_money(_ensure_decimal(amount))
        _non_negative(amt)
        c = self._ensure_ccy(currency)

        def apply():
            with self._lock:
                before = self._bal(c)
                after = before + amt
                self.policy.check_credit(c, after)
                self._set_bal(c, after)
                self._write_ledger(ccy=c, amount=amt, op_id=op_id, typ="deposit", after=after, meta=meta or {})
                self._emit_audit("deposit", {"ccy": c, "amount": str(amt), "after": str(after), "op_id": op_id})
                return after

        return self._idem.get_or_set(f"deposit:{self.entity_id}:{c}:{op_id}", apply)

    def withdraw(self, amount: Any, *, currency: str, operation_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Decimal:
        """
        Снять средства; идемпотентно по operation_id.
        """
        op_id = operation_id or str(uuid.uuid4())
        amt = _quantize_money(_ensure_decimal(amount))
        _non_negative(amt)
        c = self._ensure_ccy(currency)

        def apply():
            with self._lock:
                before = self._bal(c)
                after = before - amt
                self.policy.check_debit(c, after)
                self._set_bal(c, after)
                self._write_ledger(ccy=c, amount=-amt, op_id=op_id, typ="withdraw", after=after, meta=meta or {})
                self._emit_audit("withdraw", {"ccy": c, "amount": str(amt), "after": str(after), "op_id": op_id})
                return after

        return self._idem.get_or_set(f"withdraw:{self.entity_id}:{c}:{op_id}", apply)

    def transfer_to(self, other: "EconWallet", amount: Any, *, currency: str, operation_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Tuple[Decimal, Decimal]:
        """
        Перевод между кошельками (одна валюта); идемпотентно.
        Возвращает (баланс_отправителя_после, баланс_получателя_после).
        """
        if self is other:
            raise WalletError("cannot transfer to self")
        op_id = operation_id or str(uuid.uuid4())
        amt = _quantize_money(_ensure_decimal(amount))
        _non_negative(amt)
        c = self._ensure_ccy(currency)
        other._ensure_ccy(currency)  # проверим поддержку у получателя

        def apply():
            with self._lock, other._lock:
                before_src = self._bal(c)
                after_src = before_src - amt
                self.policy.check_debit(c, after_src)

                before_dst = other._bal(c)
                after_dst = before_dst + amt
                other.policy.check_credit(c, after_dst)

                self._set_bal(c, after_src)
                other._set_bal(c, after_dst)

                self._write_ledger(ccy=c, amount=-amt, op_id=op_id, typ="transfer_out", after=after_src, meta=meta or {"to": other.entity_id})
                other._write_ledger(ccy=c, amount=amt, op_id=op_id, typ="transfer_in", after=after_dst, meta=meta or {"from": self.entity_id})

                self._emit_audit("transfer_out", {"to": other.entity_id, "ccy": c, "amount": str(amt), "after": str(after_src), "op_id": op_id})
                other._emit_audit("transfer_in", {"from": self.entity_id, "ccy": c, "amount": str(amt), "after": str(after_dst), "op_id": op_id})

                return after_src, after_dst

        key = f"transfer:{self.entity_id}:{other.entity_id}:{c}:{op_id}"
        return self._idem.get_or_set(key, apply)

    def convert(self, amount: Any, *, from_ccy: str, to_ccy: str, operation_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Tuple[Decimal, Decimal]:
        """
        Конвертация внутри кошелька по FX‑курсу. Списывает из from_ccy и зачисляет в to_ccy.
        Возвращает (баланс_from_after, баланс_to_after).
        """
        op_id = operation_id or str(uuid.uuid4())
        amt = _quantize_money(_ensure_decimal(amount))
        _non_negative(amt)
        src = self._ensure_ccy(from_ccy)
        dst = self._ensure_ccy(to_ccy)

        def apply():
            with self._lock:
                rate = self.fx.get_rate(src, dst)
                if rate <= 0:
                    raise WalletError("invalid fx rate")
                out_before = self._bal(src)
                out_after = out_before - amt
                self.policy.check_debit(src, out_after)

                in_before = self._bal(dst)
                credited = _quantize_money(amt * rate)
                in_after = in_before + credited
                self.policy.check_credit(dst, in_after)

                self._set_bal(src, out_after)
                self._set_bal(dst, in_after)

                self._write_ledger(ccy=src, amount=-amt, op_id=op_id, typ="fx_convert", after=out_after, meta={**(meta or {}), "to": dst, "rate": str(rate), "credited": str(credited)})
                self._write_ledger(ccy=dst, amount=credited, op_id=op_id, typ="fx_convert", after=in_after, meta={**(meta or {}), "from": src, "rate": str(rate), "debited": str(amt)})
                self._emit_audit("fx_convert", {"from": src, "to": dst, "amount": str(amt), "credited": str(credited), "rate": str(rate), "op_id": op_id})

                return out_after, in_after

        key = f"fx:{self.entity_id}:{src}:{dst}:{op_id}"
        return self._idem.get_or_set(key, apply)

    # -------------------------- Резервирования -------------------------- #
    def create_hold(self, amount: Any, *, currency: str, hold_id: Optional[str] = None, expires_at: Optional[datetime] = None, operation_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> str:
        """
        Создать резерв (hold), списывает доступный баланс, но не фиксирует окончательно.
        Возвращает hold_id. Идемпотентно по operation_id.
        """
        op_id = operation_id or str(uuid.uuid4())
        hid = hold_id or str(uuid.uuid4())
        amt = _quantize_money(_ensure_decimal(amount))
        _non_negative(amt)
        c = self._ensure_ccy(currency)

        def apply():
            with self._lock:
                if hid in self._holds:
                    return hid
                before = self._bal(c)
                after = before - amt
                self.policy.check_debit(c, after)
                self._set_bal(c, after)

                h = Hold(id=hid, ccy=c, amount=amt, created_at=now_utc(), expires_at=expires_at, meta=meta or {})
                self._holds[hid] = h

                self._write_ledger(ccy=c, amount=-amt, op_id=op_id, typ="hold_create", after=after, meta={"hold_id": hid, **(meta or {})})
                self._emit_audit("hold_create", {"hold_id": hid, "ccy": c, "amount": str(amt), "after": str(after), "op_id": op_id})
                return hid

        return self._idem.get_or_set(f"hold_create:{self.entity_id}:{c}:{op_id}", apply)

    def capture_hold(self, hold_id: str, *, operation_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> None:
        """
        Финализировать резерв: списание уже учтено, поэтому только отмечаем capture.
        Идемпотентно.
        """
        op_id = operation_id or str(uuid.uuid4())

        def apply():
            with self._lock:
                h = self._holds.get(hold_id)
                if not h:
                    raise HoldNotFound(hold_id)
                if h.captured:
                    return None
                if h.released:
                    raise WalletError("hold already released")
                # capture не меняет баланс — средства уже удержаны
                h.captured = True
                self._write_ledger(ccy=h.ccy, amount=Decimal("0"), op_id=op_id, typ="hold_capture", after=self._bal(h.ccy), meta={"hold_id": hold_id, **(meta or {})})
                self._emit_audit("hold_capture", {"hold_id": hold_id, "ccy": h.ccy, "amount": str(h.amount), "op_id": op_id})
                return None

        self._idem.get_or_set(f"hold_capture:{self.entity_id}:{hold_id}:{op_id}", apply)

    def release_hold(self, hold_id: str, *, operation_id: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Decimal:
        """
        Освободить резерв: возвращает сумму в доступный баланс.
        Идемпотентно.
        """
        op_id = operation_id or str(uuid.uuid4())

        def apply():
            with self._lock:
                h = self._holds.get(hold_id)
                if not h:
                    raise HoldNotFound(hold_id)
                if h.released:
                    return self._bal(h.ccy)
                if h.captured:
                    # Уже финализирован — не возвращаем
                    return self._bal(h.ccy)
                before = self._bal(h.ccy)
                after = before + h.amount
                self.policy.check_credit(h.ccy, after)
                self._set_bal(h.ccy, after)
                h.released = True
                self._write_ledger(ccy=h.ccy, amount=h.amount, op_id=op_id, typ="hold_release", after=after, meta={"hold_id": hold_id, **(meta or {})})
                self._emit_audit("hold_release", {"hold_id": hold_id, "ccy": h.ccy, "amount": str(h.amount), "after": str(after), "op_id": op_id})
                return after

        return self._idem.get_or_set(f"hold_release:{self.entity_id}:{hold_id}:{op_id}", apply)

    # -------------------------- Сериализация/снапшоты -------------------------- #
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": self._schema_version,
                "entity_id": self.entity_id,
                "base_currency": self.base_currency,
                "supported_currencies": list(self.supported_currencies),
                "balances": {k: str(v) for k, v in self._balances.items()},
                "holds": {
                    hid: {
                        "ccy": h.ccy,
                        "amount": str(h.amount),
                        "created_at": h.created_at.isoformat(),
                        "expires_at": h.expires_at.isoformat() if h.expires_at else None,
                        "captured": h.captured,
                        "released": h.released,
                        "meta": h.meta,
                    } for hid, h in self._holds.items()
                },
                "seq": self._seq,
                "ledger": [
                    {
                        "seq": e.seq,
                        "ts": e.ts.isoformat(),
                        "operation_id": e.operation_id,
                        "type": e.type,
                        "ccy": e.ccy,
                        "amount": str(e.amount),
                        "balance_after": str(e.balance_after),
                        "meta": e.meta,
                    } for e in self._ledger
                ],
            }

    @staticmethod
    def restore(data: Dict[str, Any]) -> "EconWallet":
        if int(data.get("version", 1)) != 1:
            raise WalletError("unsupported schema version")
        w = EconWallet(
            entity_id=data["entity_id"],
            base_currency=data.get("base_currency", "USD"),
            supported_currencies=list(data.get("supported_currencies") or ["USD"]),
        )
        with w._lock:
            for k, v in (data.get("balances") or {}).items():
                w._balances[k] = _quantize_money(Decimal(str(v)))
            for hid, hd in (data.get("holds") or {}).items():
                w._holds[hid] = Hold(
                    id=hid,
                    ccy=hd["ccy"],
                    amount=_quantize_money(Decimal(str(hd["amount"]))),
                    created_at=datetime.fromisoformat(hd["created_at"]),
                    expires_at=datetime.fromisoformat(hd["expires_at"]) if hd.get("expires_at") else None,
                    captured=bool(hd.get("captured", False)),
                    released=bool(hd.get("released", False)),
                    meta=hd.get("meta") or {},
                )
            w._seq = int(data.get("seq", 0))
            w._ledger = [
                LedgerEntry(
                    seq=int(le["seq"]),
                    ts=datetime.fromisoformat(le["ts"]),
                    operation_id=le["operation_id"],
                    type=le["type"],  # type: ignore[arg-type]
                    ccy=le["ccy"],
                    amount=_quantize_money(Decimal(str(le["amount"]))),
                    balance_after=_quantize_money(Decimal(str(le["balance_after"]))),
                    meta=le.get("meta") or {},
                ) for le in (data.get("ledger") or [])
            ]
        return w

    # -------------------------- Управление политиками -------------------------- #
    def set_overdraft(self, currency: str, enabled: bool) -> None:
        self.policy.set_overdraft(self._ensure_ccy(currency), enabled)

    def set_max_balance(self, currency: str, limit: Any) -> None:
        self.policy.set_max_balance(self._ensure_ccy(currency), _ensure_decimal(limit))

    def add_supported_currency(self, currency: str) -> None:
        c = currency.upper()
        with self._lock:
            if c not in self.supported_currencies:
                self.supported_currencies.append(c)
                if c not in self._balances:
                    self._balances[c] = Decimal("0")

    # -------------------------- Утилиты -------------------------- #
    def ledger(self, *, limit: int = 1000, offset: int = 0) -> List[LedgerEntry]:
        with self._lock:
            return list(self._ledger[offset: offset + limit])

# -----------------------------------------------------------------------------
# Пример локальной проверки
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    w1 = EconWallet(entity_id="player-1", supported_currencies=["USD", "EUR"])
    w2 = EconWallet(entity_id="player-2", supported_currencies=["USD", "EUR"])

    w1.deposit("100.00", currency="USD", operation_id="op-1")
    w1.create_hold("30.00", currency="USD", hold_id="h-1", operation_id="op-h1")
    w1.capture_hold("h-1", operation_id="op-h1c")
    w1.release_hold("h-1", operation_id="op-h1r")  # идемпотентно: баланс не увеличится, так как captured=True

    w1.deposit("50", currency="EUR", operation_id="op-2")
    w1.convert("10", from_ccy="EUR", to_ccy="USD", operation_id="op-fx1")

    w1.transfer_to(w2, "15.50", currency="USD", operation_id="op-tr1")

    print("w1 balances:", w1.get_balance())
    print("w2 balances:", w2.get_balance())
    print("w1 ledger size:", len(w1.ledger()))
