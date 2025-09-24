# ledger-core/tests/fuzz/test_tx_fuzz.py
# -*- coding: utf-8 -*-
"""
Промышленный fuzz-набор для проверки транзакционной подсистемы ledger-core.

Ключевые свойства:
- Детерминированность сериализации и хеширования
- Корректность подписи и ее нарушение при любой мутации
- Инварианты комиссий и балансов (account-based)
- Защита от повтора транзакций (replay) и двойной траты
- Последовательная обработка батча случайных транзакций

Интеграция:
- По умолчанию используется встроенный DummyAdapter (без внешних зависимостей)
- Для подключения реального адаптера установите переменную окружения:
    LEDGER_CORE_ADAPTER="pkg.module:FactoryFunction"
  где FactoryFunction -> adapter с тем же интерфейсом.

Зависимости: pytest, hypothesis
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import random
import secrets
import string
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple, List, Protocol, Callable

import pytest

try:
    from hypothesis import given, settings, HealthCheck, strategies as st
except Exception as _e:  # pragma: no cover
    pytest.skip(f"Hypothesis required for fuzz tests: {_e}", allow_module_level=True)


# ===============================
# Adapter protocol and primitives
# ===============================

class LedgerAdapter(Protocol):
    """
    Протокол адаптера. Ваш реальный адаптер должен поддерживать эти методы.
    Все операции детерминированы для воспроизводимости тестов.
    """

    # --- ключи и адреса ---
    def new_wallet(self) -> Tuple[bytes, bytes, str]:
        """Создает новую пару ключей (priv, pub) и адрес."""
        ...

    # --- транзакция и подписи ---
    def build_tx(
        self,
        sender_pub: bytes,
        recipient_addr: str,
        amount: int,
        fee: int,
        nonce: int,
        memo: str,
        timestamp: int,
    ) -> "Tx":
        """Собирает транзакцию без подписи."""
        ...

    def sign_tx(self, tx: "Tx", sender_priv: bytes) -> "SignedTx":
        """Подписывает транзакцию ключом отправителя."""
        ...

    def verify_tx(self, stx: "SignedTx") -> bool:
        """Проверяет подпись транзакции."""
        ...

    def serialize_tx(self, stx: "SignedTx") -> bytes:
        """Каноническая детерминированная сериализация подписанной транзакции."""
        ...

    def deserialize_tx(self, raw: bytes) -> "SignedTx":
        """Обратная операция к serialize_tx, без потери информации."""
        ...

    def tx_hash(self, stx: "SignedTx") -> bytes:
        """Детерминированный хеш подписанной транзакции."""
        ...

    # --- состояние и применение ---
    def initial_state(self) -> "LedgerState":
        """Создает чистое состояние реестра."""
        ...

    def get_balance(self, state: "LedgerState", address: str) -> int:
        ...

    def min_fee(self) -> int:
        """Минимальная комиссия сети."""
        ...

    def apply_tx(self, state: "LedgerState", stx: "SignedTx") -> "LedgerState":
        """Применяет транзакцию к состоянию с проверками.
        Должна бросать исключение при нарушении правил."""
        ...

    def expected_nonce(self, state: "LedgerState", address: str) -> int:
        """Ожидаемый nonce для адреса в данном состоянии."""
        ...


# ============================
# DummyAdapter (самодостаточный)
# ============================

JSON_SEPARATORS = (",", ":")  # без пробелов для каноничности


@dataclass(frozen=True)
class Tx:
    sender_pub_b64: str
    sender_addr: str
    recipient_addr: str
    amount: int
    fee: int
    nonce: int
    memo: str
    timestamp: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender_pub_b64": self.sender_pub_b64,
            "sender_addr": self.sender_addr,
            "recipient_addr": self.recipient_addr,
            "amount": self.amount,
            "fee": self.fee,
            "nonce": self.nonce,
            "memo": self.memo,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class SignedTx:
    tx: Tx
    signature_b64: str  # детерминированная подпись

    def to_dict(self) -> Dict[str, Any]:
        return {"tx": self.tx.to_dict(), "signature_b64": self.signature_b64}


@dataclasses.dataclass
class LedgerState:
    # Простейшая account-based модель
    balances: Dict[str, int] = dataclasses.field(default_factory=dict)
    nonces: Dict[str, int] = dataclasses.field(default_factory=dict)
    fee_pot: int = 0  # "сжигаем" комиссию для инвариантов
    # Для Dummy проверки подписи
    _secrets_by_pub: Dict[str, bytes] = dataclasses.field(default_factory=dict)


class DummyAdapter(LedgerAdapter):
    """
    Детерминированный адаптер без внешних зависимостей:
    - Адрес: первые 20 байт SHA256(pubkey), hex
    - Подпись: HMAC-SHA256(priv, canonical_json(tx)), хранит карту pub->priv в состоянии
    - Сериализация: canonical JSON dict с сортировкой ключей
    - Хеш: SHA256(serialized_bytes)
    """

    def __init__(self, min_fee_value: int = 1000):
        self._min_fee = int(min_fee_value)

    # --- helpers ---

    @staticmethod
    def _addr_from_pub(pub: bytes) -> str:
        return hashlib.sha256(pub).hexdigest()[:40]  # 20 байт hex

    @staticmethod
    def _b64(b: bytes) -> str:
        return base64.b64encode(b).decode("ascii")

    @staticmethod
    def _b64dec(s: str) -> bytes:
        return base64.b64decode(s.encode("ascii"))

    @staticmethod
    def _canon_json(obj: Any) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=JSON_SEPARATORS, ensure_ascii=False).encode("utf-8")

    # --- keys and addresses ---

    def new_wallet(self) -> Tuple[bytes, bytes, str]:
        priv = secrets.token_bytes(32)
        pub = hashlib.sha256(priv).digest()  # псевдо-публичный ключ
        addr = self._addr_from_pub(pub)
        return priv, pub, addr

    # --- tx build/sign/verify ---

    def build_tx(
        self,
        sender_pub: bytes,
        recipient_addr: str,
        amount: int,
        fee: int,
        nonce: int,
        memo: str,
        timestamp: int,
    ) -> Tx:
        return Tx(
            sender_pub_b64=self._b64(sender_pub),
            sender_addr=self._addr_from_pub(sender_pub),
            recipient_addr=recipient_addr,
            amount=int(amount),
            fee=int(fee),
            nonce=int(nonce),
            memo=memo,
            timestamp=int(timestamp),
        )

    def sign_tx(self, tx: Tx, sender_priv: bytes) -> SignedTx:
        msg = self._canon_json(tx.to_dict())
        sig = hmac.new(sender_priv, msg, hashlib.sha256).digest()
        return SignedTx(tx=tx, signature_b64=self._b64(sig))

    def verify_tx(self, stx: SignedTx) -> bool:
        # В Dummy проверка основана на знании карты pub->priv из состояния.
        # Для валидации без состояния мы допускаем локальную проверку,
        # если в подписи используется priv = sha256(pub)[:32] XOR 0x00.. (невозможно восстановить).
        # Поэтому реальная проверка делается при apply_tx, где есть state с картой секретов.
        # Здесь проверяем только формат и базовые поля.
        try:
            _ = self._b64dec(stx.tx.sender_pub_b64)
            _ = self._b64dec(stx.signature_b64)
            return True
        except Exception:
            return False

    def serialize_tx(self, stx: SignedTx) -> bytes:
        return self._canon_json(stx.to_dict())

    def deserialize_tx(self, raw: bytes) -> SignedTx:
        obj = json.loads(raw.decode("utf-8"))
        txd = obj["tx"]
        tx = Tx(
            sender_pub_b64=txd["sender_pub_b64"],
            sender_addr=txd["sender_addr"],
            recipient_addr=txd["recipient_addr"],
            amount=int(txd["amount"]),
            fee=int(txd["fee"]),
            nonce=int(txd["nonce"]),
            memo=txd["memo"],
            timestamp=int(txd["timestamp"]),
        )
        return SignedTx(tx=tx, signature_b64=obj["signature_b64"])

    def tx_hash(self, stx: SignedTx) -> bytes:
        return hashlib.sha256(self.serialize_tx(stx)).digest()

    # --- state operations ---

    def initial_state(self) -> LedgerState:
        return LedgerState()

    def get_balance(self, state: LedgerState, address: str) -> int:
        return int(state.balances.get(address, 0))

    def min_fee(self) -> int:
        return self._min_fee

    def expected_nonce(self, state: LedgerState, address: str) -> int:
        return int(state.nonces.get(address, 0))

    def apply_tx(self, state: LedgerState, stx: SignedTx) -> LedgerState:
        # Проверки инвариантов
        sender_pub = self._b64dec(stx.tx.sender_pub_b64)
        sender_addr = stx.tx.sender_addr
        if self._addr_from_pub(sender_pub) != sender_addr:
            raise ValueError("Sender address does not match public key")

        # Подпись (в Dummy: HMAC(priv, json(tx))) где priv берем из state._secrets_by_pub
        pub_b64 = stx.tx.sender_pub_b64
        if pub_b64 not in state._secrets_by_pub:
            raise ValueError("Unknown sender key in state")

        priv = state._secrets_by_pub[pub_b64]
        expected_sig = hmac.new(priv, self._canon_json(stx.tx.to_dict()), hashlib.sha256).digest()
        if not hmac.compare_digest(expected_sig, self._b64dec(stx.signature_b64)):
            raise ValueError("Bad signature")

        if stx.tx.amount <= 0:
            raise ValueError("Amount must be > 0")
        if stx.tx.fee < self._min_fee:
            raise ValueError("Fee below network minimum")

        exp_nonce = self.expected_nonce(state, sender_addr)
        if stx.tx.nonce != exp_nonce:
            raise ValueError("Bad nonce")

        total = stx.tx.amount + stx.tx.fee
        if self.get_balance(state, sender_addr) < total:
            raise ValueError("Insufficient funds")

        # Применяем
        state.balances[sender_addr] = self.get_balance(state, sender_addr) - total
        state.balances[stx.tx.recipient_addr] = self.get_balance(state, stx.tx.recipient_addr) + stx.tx.amount
        state.fee_pot += stx.tx.fee
        state.nonces[sender_addr] = exp_nonce + 1
        return state


# ==========================
# Adapter loader (optional)
# ==========================

def _load_adapter() -> LedgerAdapter:
    path = os.getenv("LEDGER_CORE_ADAPTER", "").strip()
    if not path:
        return DummyAdapter()

    # Ожидается "pkg.module:factory"
    if ":" not in path:
        raise RuntimeError("LEDGER_CORE_ADAPTER must be 'pkg.module:factory'")

    mod_name, factory = path.split(":", 1)
    import importlib  # локальный импорт чтобы не мешать pytest --collect-only
    mod = importlib.import_module(mod_name)
    fn: Callable[[], LedgerAdapter] = getattr(mod, factory)
    return fn()


ADAPTER = _load_adapter()


# ===================
# Hypothesis strategies
# ===================

def _addr_chars() -> str:
    # hex адрес длиной 40 символов
    return string.hexdigits.lower()


@st.composite
def addr_strategy(draw) -> st.SearchStrategy[str]:
    # 20 байт hex
    return draw(st.text(alphabet="0123456789abcdef", min_size=40, max_size=40))


@st.composite
def memo_strategy(draw) -> st.SearchStrategy[str]:
    # ограниченный memo до 140 символов, без управляющих
    return draw(
        st.text(
            alphabet=st.characters(
                blacklist_categories=("Cc", "Cs"),
                min_codepoint=32,
                max_codepoint=0x10FFFF,
            ),
            min_size=0,
            max_size=140,
        )
    )


@st.composite
def wallet_strategy(draw) -> Tuple[bytes, bytes, str]:
    priv, pub, addr = ADAPTER.new_wallet()
    return priv, pub, addr


@st.composite
def tx_params_strategy(draw) -> Dict[str, Any]:
    # Таймстемпы в разумных рамках
    timestamp = draw(st.integers(min_value=1_700_000_000, max_value=2_000_000_000))
    amount = draw(st.integers(min_value=1, max_value=10**9))
    # fee не ниже минимальной и не выше amount для удобства применимости
    min_fee = ADAPTER.min_fee()
    fee = draw(st.integers(min_value=min_fee, max_value=min(amount, min_fee * 1000)))
    nonce = draw(st.integers(min_value=0, max_value=1_000_000))
    memo = draw(memo_strategy())
    return {"timestamp": timestamp, "amount": amount, "fee": fee, "nonce": nonce, "memo": memo}


# ===================
# Pytest fixtures
# ===================

@pytest.fixture
def clean_state() -> LedgerState:
    return ADAPTER.initial_state()


@pytest.fixture
def funded_sender_and_recipient(clean_state) -> Tuple[LedgerState, Tuple[bytes, bytes, str], str]:
    """
    Создаем отправителя c крупным балансом и получателя.
    Регистрируем секреты в состоянии для DummyAdapter.
    """
    state: LedgerState = clean_state
    priv_s, pub_s, addr_s = ADAPTER.new_wallet()
    _, pub_r, addr_r = ADAPTER.new_wallet()

    # пополняем отправителя
    state.balances[addr_s] = 10**12
    state.nonces[addr_s] = 0

    # регистрируем секрет для проверки HMAC в Dummy
    if isinstance(ADAPTER, DummyAdapter):
        state._secrets_by_pub[base64.b64encode(pub_s).decode("ascii")] = priv_s

    return state, (priv_s, pub_s, addr_s), addr_r


# ===================
# Tests
# ===================

DEFAULT_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


@pytest.mark.fuzz
@DEFAULT_SETTINGS
@given(wallet=wallet_strategy(), recipient=addr_strategy(), p=tx_params_strategy())
def test_serialize_roundtrip_and_hash_determinism(wallet, recipient, p):
    """
    Проверяем:
    - сериализация детерминирована
    - десериализация восстанавливает эквивалентный объект
    - хеш стабилен и соответствует сериализации
    """
    sender_priv, sender_pub, sender_addr = wallet
    tx = ADAPTER.build_tx(
        sender_pub=sender_pub,
        recipient_addr=recipient,
        amount=p["amount"],
        fee=max(p["fee"], ADAPTER.min_fee()),
        nonce=p["nonce"],
        memo=p["memo"],
        timestamp=p["timestamp"],
    )
    stx = ADAPTER.sign_tx(tx, sender_priv)

    raw1 = ADAPTER.serialize_tx(stx)
    raw2 = ADAPTER.serialize_tx(stx)
    assert raw1 == raw2, "Serialization must be deterministic"

    stx2 = ADAPTER.deserialize_tx(raw1)
    assert stx2 == stx, "Round-trip must preserve signed tx exactly"

    h1 = ADAPTER.tx_hash(stx)
    h2 = hashlib.sha256(raw1).digest()
    assert h1 == h2, "tx_hash must equal SHA256(serialized)"


@pytest.mark.fuzz
@DEFAULT_SETTINGS
@given(wallet=wallet_strategy(), recipient=addr_strategy(), p=tx_params_strategy())
def test_signature_verification_and_mutation(wallet, recipient, p):
    """
    Проверяем:
    - подпись валидна на исходной транзакции
    - любая мутация приводит к невалидной подписи при проверке на уровне apply
    """
    state = ADAPTER.initial_state()
    sender_priv, sender_pub, sender_addr = wallet

    if isinstance(ADAPTER, DummyAdapter):
        state._secrets_by_pub[base64.b64encode(sender_pub).decode("ascii")] = sender_priv
        state.balances[sender_addr] = 10**9
        state.nonces[sender_addr] = p["nonce"]

    tx = ADAPTER.build_tx(
        sender_pub=sender_pub,
        recipient_addr=recipient,
        amount=p["amount"],
        fee=max(p["fee"], ADAPTER.min_fee()),
        nonce=p["nonce"],
        memo=p["memo"],
        timestamp=p["timestamp"],
    )
    stx = ADAPTER.sign_tx(tx, sender_priv)
    assert ADAPTER.verify_tx(stx), "Signature format check failed"

    # Байт-мутация сериализованного представления
    raw = bytearray(ADAPTER.serialize_tx(stx))
    if len(raw) > 0:
        idx = random.randrange(0, len(raw))
        raw[idx] ^= 0x01  # минимальная мутация
    mutated = bytes(raw)

    # Восстановим объект; если JSON испорчен — это тоже ожидаемо
    try:
        stx_mut = ADAPTER.deserialize_tx(mutated)
    except Exception:
        # Любая невалидность формата — тоже фейл подписи
        return

    # На уровне apply подпись должна поломаться
    with pytest.raises(Exception):
        ADAPTER.apply_tx(state, stx_mut)


@pytest.mark.fuzz
@DEFAULT_SETTINGS
@given(p=tx_params_strategy())
def test_fee_balance_and_nonce_invariants(funded_sender_and_recipient, p):
    """
    Инварианты:
    - amount > 0
    - fee >= min_fee
    - баланс списывается на amount+fee, получатель получает amount, fee отправляется в fee_pot
    - nonce увеличивается ровно на 1
    """
    state, (priv_s, pub_s, addr_s), addr_r = funded_sender_and_recipient
    # подберем параметры, чтобы точно применилось
    amount = max(1, min(p["amount"], ADAPTER.get_balance(state, addr_s) // 2))
    fee = max(ADAPTER.min_fee(), min(p["fee"], amount))
    nonce = ADAPTER.expected_nonce(state, addr_s)

    tx = ADAPTER.build_tx(
        sender_pub=pub_s,
        recipient_addr=addr_r,
        amount=amount,
        fee=fee,
        nonce=nonce,
        memo=p["memo"],
        timestamp=p["timestamp"],
    )
    stx = ADAPTER.sign_tx(tx, priv_s)

    bal_s_before = ADAPTER.get_balance(state, addr_s)
    bal_r_before = ADAPTER.get_balance(state, addr_r)
    fee_before = state.fee_pot

    new_state = ADAPTER.apply_tx(state, stx)

    assert ADAPTER.get_balance(new_state, addr_s) == bal_s_before - amount - fee
    assert ADAPTER.get_balance(new_state, addr_r) == bal_r_before + amount
    assert new_state.fee_pot == fee_before + fee
    assert ADAPTER.expected_nonce(new_state, addr_s) == nonce + 1


@pytest.mark.fuzz
@DEFAULT_SETTINGS
@given(p=tx_params_strategy())
def test_replay_protection(funded_sender_and_recipient, p):
    """
    Одна и та же подписанная транзакция не может быть применена дважды.
    """
    state, (priv_s, pub_s, addr_s), addr_r = funded_sender_and_recipient
    amount = max(1, min(p["amount"], ADAPTER.get_balance(state, addr_s) // 2))
    fee = max(ADAPTER.min_fee(), min(p["fee"], amount))
    nonce = ADAPTER.expected_nonce(state, addr_s)

    tx = ADAPTER.build_tx(
        sender_pub=pub_s,
        recipient_addr=addr_r,
        amount=amount,
        fee=fee,
        nonce=nonce,
        memo=p["memo"],
        timestamp=p["timestamp"],
    )
    stx = ADAPTER.sign_tx(tx, priv_s)

    ADAPTER.apply_tx(state, stx)
    with pytest.raises(Exception):
        ADAPTER.apply_tx(state, stx)


@pytest.mark.fuzz
@DEFAULT_SETTINGS
@given(p=tx_params_strategy())
def test_double_spend_protection(funded_sender_and_recipient, p):
    """
    Две транзакции с одинаковым nonce от одного отправителя:
    - первая проходит
    - вторая отклоняется по nonce
    """
    state, (priv_s, pub_s, addr_s), addr_r = funded_sender_and_recipient
    amount = max(1, min(p["amount"], ADAPTER.get_balance(state, addr_s) // 4))
    fee = max(ADAPTER.min_fee(), min(p["fee"], amount))
    nonce = ADAPTER.expected_nonce(state, addr_s)

    tx1 = ADAPTER.build_tx(pub_s, addr_r, amount, fee, nonce, p["memo"], p["timestamp"])
    tx2 = ADAPTER.build_tx(pub_s, addr_r, amount, fee, nonce, p["memo"], p["timestamp"])
    stx1 = ADAPTER.sign_tx(tx1, priv_s)
    stx2 = ADAPTER.sign_tx(tx2, priv_s)

    ADAPTER.apply_tx(state, stx1)
    with pytest.raises(Exception):
        ADAPTER.apply_tx(state, stx2)


@pytest.mark.fuzz
@DEFAULT_SETTINGS
@given(
    batch=st.lists(
        tx_params_strategy(),
        min_size=1,
        max_size=25,
    )
)
def test_batch_conservation_and_nonce_monotonicity(funded_sender_and_recipient, batch):
    """
    Батч случайных транзакций:
    - общая сумма средств у аккаунтов уменьшается ровно на сумму комиссий (fee_pot увеличивается)
    - nonce отправителя строго монотонен
    """
    state, (priv_s, pub_s, addr_s), addr_r = funded_sender_and_recipient

    initial_supply = sum(state.balances.values())
    initial_fee_pot = state.fee_pot
    expected_nonce = ADAPTER.expected_nonce(state, addr_s)

    total_fees_applied = 0
    for p in batch:
        # выбираем безопасные параметры
        amount = max(1, min(p["amount"], max(1, ADAPTER.get_balance(state, addr_s) // 3)))
        fee = max(ADAPTER.min_fee(), min(p["fee"], amount))
        nonce = ADAPTER.expected_nonce(state, addr_s)

        tx = ADAPTER.build_tx(pub_s, addr_r, amount, fee, nonce, p["memo"], p["timestamp"])
        stx = ADAPTER.sign_tx(tx, priv_s)
        try:
            ADAPTER.apply_tx(state, stx)
            expected_nonce += 1
            total_fees_applied += fee
        except Exception:
            # Пропускаем примеры, которые нарушают балансные ограничения в процессе батча
            # Это корректно для fuzz: важны инварианты успешных применений.
            pass

        assert ADAPTER.expected_nonce(state, addr_s) == expected_nonce

    final_supply = sum(state.balances.values()) + state.fee_pot
    assert final_supply == initial_supply + initial_fee_pot, "Conservation with fee sink violated"
    assert state.fee_pot - initial_fee_pot == total_fees_applied
