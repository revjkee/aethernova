# ledger-core/tests/unit/test_tx_service.py
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from decimal import Decimal

import pytest

# Доменные модели и политики из проекта
from ledger.ledger.domain.models.tx import (
    PostedTransaction,
    TransactionEntry,
    AccountRef,
    EntryDirection,
    Currency,
    TxType,
    Money,
)
from ledger.ledger.domain.policies.signing_policy import (
    SigningPolicy,
    StaticKeyResolver,
    InMemoryNonceStore,
    make_ephemeral_ed25519_keys,
)

# =========================================================
# Вспомогательные фикстуры
# =========================================================

@pytest.fixture
def utc_now() -> datetime:
    return datetime(2025, 8, 15, 12, 0, 0, tzinfo=timezone.utc)

@pytest.fixture
def tx_transfer(utc_now) -> PostedTransaction:
    return PostedTransaction.transfer(
        transaction_id="tx-001",
        posted_at=utc_now,
        currency=Currency.SEK,
        from_account="SRC",
        to_account="DST",
        amount_minor=10_00,
        attributes={"purpose": "test"},
    )

@pytest.fixture(scope="module")
def signing_policy() -> SigningPolicy:
    # cryptography обязателен — если не установлен, этот набор тестов можно пропустить
    try:
        priv_pem, pub_pem = make_ephemeral_ed25519_keys()
    except Exception:
        pytest.skip("cryptography is required for signing tests")
    resolver = StaticKeyResolver(
        sign_keys={"k1": ("Ed25519", priv_pem)},
        verify_keys={"k1": ("Ed25519", pub_pem)},
    )
    return SigningPolicy(key_resolver=resolver, nonce_store=InMemoryNonceStore())

# =========================================================
# Тесты доменной модели
# =========================================================

def test_transfer_factory_balanced_and_valid(tx_transfer: PostedTransaction, utc_now: datetime):
    assert tx_transfer.tx_type == TxType.TRANSFER
    assert tx_transfer.posted_at == utc_now
    assert tx_transfer.currency == Currency.SEK
    # Две ноги, баланс и положительная сумма
    assert len(tx_transfer.entries) == 2
    assert tx_transfer.total_debit_minor == 10_00
    assert tx_transfer.total_credit_minor == 10_00
    assert tx_transfer.total_minor == 10_00
    # Денежное представление
    m = tx_transfer.total_money
    assert isinstance(m, Money)
    assert m.amount == Decimal("10.00")
    assert m.currency == Currency.SEK

def test_invariants_same_currency_and_positive_amounts(utc_now: datetime):
    # currency mismatch
    with pytest.raises(ValueError):
        PostedTransaction(
            transaction_id="bad-1",
            tx_type=TxType.PAYMENT,
            posted_at=utc_now,
            currency=Currency.USD,
            entries=[
                TransactionEntry(account=AccountRef(account_id="A"), direction=EntryDirection.DEBIT, amount_minor=100, currency=Currency.EUR),
                TransactionEntry(account=AccountRef(account_id="B"), direction=EntryDirection.CREDIT, amount_minor=100, currency=Currency.EUR),
            ],
            attributes={},
        )
    # non-positive amounts are rejected by Field(gt=0) at model build time
    with pytest.raises(ValueError):
        TransactionEntry(account=AccountRef(account_id="A"), direction=EntryDirection.DEBIT, amount_minor=0, currency=Currency.USD)

def test_idempotency_key_changes_on_entry_change(tx_transfer: PostedTransaction, utc_now: datetime):
    key1 = tx_transfer.idempotency_key
    # Поменяем счёт получателя — ключ должен измениться
    modified = PostedTransaction.transfer(
        transaction_id=tx_transfer.transaction_id,
        posted_at=utc_now,
        currency=tx_transfer.currency,
        from_account="SRC",
        to_account="ANOTHER",
        amount_minor=10_00,
        attributes=tx_transfer.attributes,
    )
    key2 = modified.idempotency_key
    assert key1 != key2

def test_money_arithmetic_precision():
    a = Money(amount=Decimal("0.10"), currency=Currency.USD)
    b = Money(amount=Decimal("0.20"), currency=Currency.USD)
    c = a + b
    assert c.amount == Decimal("0.30")
    # Минорные единицы согласованы
    assert c.minor == 30

# =========================================================
# Avro‑совместимость (round‑trip)
# =========================================================

def test_avro_round_trip(tx_transfer: PostedTransaction):
    payload = tx_transfer.to_avro_transaction_posted()
    restored = PostedTransaction.from_avro_transaction_posted(payload)
    assert restored.currency == tx_transfer.currency
    assert restored.total_minor == tx_transfer.total_minor
    # Баланс и состав ног сохраняется
    assert len(restored.entries) == len(tx_transfer.entries)
    assert {e.direction for e in restored.entries} == {EntryDirection.DEBIT, EntryDirection.CREDIT}

# =========================================================
# Подпись/верификация и защита от повторов
# =========================================================

def test_sign_and_verify_success(signing_policy: SigningPolicy, tx_transfer: PostedTransaction):
    # Подписываем сериализованный словарь транзакции (детерминированная структура pydantic)
    payload = {
        "transaction_id": tx_transfer.transaction_id,
        "tx_type": tx_transfer.tx_type.value,
        "posted_at": tx_transfer.posted_at.isoformat(),
        "currency": tx_transfer.currency.value,
        "entries": [
            {
                "account": {"account_id": e.account.account_id},
                "direction": e.direction.value,
                "amount_minor": e.amount_minor,
                "currency": e.currency.value,
            }
            for e in tx_transfer.entries
        ],
        "attributes": dict(tx_transfer.attributes),
    }
    sig = signing_policy.sign(payload, "k1")
    # Проверка проходит
    signing_policy.verify(payload, sig)

def test_replay_is_blocked(signing_policy: SigningPolicy, tx_transfer: PostedTransaction):
    payload = {
        "transaction_id": tx_transfer.transaction_id,
        "tx_type": tx_transfer.tx_type.value,
        "posted_at": tx_transfer.posted_at.isoformat(),
        "currency": tx_transfer.currency.value,
        "entries": [
            {
                "account": {"account_id": e.account.account_id},
                "direction": e.direction.value,
                "amount_minor": e.amount_minor,
                "currency": e.currency.value,
            }
            for e in tx_transfer.entries
        ],
        "attributes": dict(tx_transfer.attributes),
    }
    sig = signing_policy.sign(payload, "k1")
    # Первый раз — ок
    signing_policy.verify(payload, sig)
    # Повтор с тем же nonce — заблокирован (nonce-store помнит)
    with pytest.raises(ValueError):
        signing_policy.verify(payload, sig)

def test_signature_payload_tamper_detected(signing_policy: SigningPolicy, tx_transfer: PostedTransaction):
    payload = {
        "transaction_id": tx_transfer.transaction_id,
        "tx_type": tx_transfer.tx_type.value,
        "posted_at": tx_transfer.posted_at.isoformat(),
        "currency": tx_transfer.currency.value,
        "entries": [
            {
                "account": {"account_id": e.account.account_id},
                "direction": e.direction.value,
                "amount_minor": e.amount_minor,
                "currency": e.currency.value,
            }
            for e in tx_transfer.entries
        ],
        "attributes": dict(tx_transfer.attributes),
    }
    sig = signing_policy.sign(payload, "k1")
    # Изменим сумму — верификация должна упасть по несовпадению дайджеста
    payload_tampered = dict(payload)
    payload_tampered["entries"] = list(payload_tampered["entries"])
    payload_tampered["entries"][0] = dict(payload_tampered["entries"][0])
    payload_tampered["entries"][0]["amount_minor"] = payload_tampered["entries"][0]["amount_minor"] + 1
    with pytest.raises(ValueError):
        signing_policy.verify(payload_tampered, sig)

# =========================================================
# «Сервис транзакций» — минимальный каркас и тестирование поведения
# =========================================================

class FakeTxRepo:
    """Мини‑репозиторий для сервиса: хранит принятые транзакции в памяти."""
    def __init__(self):
        self._by_id: dict[str, PostedTransaction] = {}

    async def save_if_new(self, tx: PostedTransaction) -> bool:
        if tx.transaction_id in self._by_id:
            return False
        self._by_id[tx.transaction_id] = tx
        return True

    async def get(self, tx_id: str) -> PostedTransaction | None:
        return self._by_id.get(tx_id)

class TxService:
    """
    Пример сервиса: принимает транзакцию, проверяет инварианты модели (делает Pydantic),
    опционально проверяет подпись и сохраняет, обеспечивая идемпотентность по transaction_id.
    """
    def __init__(self, repo: FakeTxRepo, policy: SigningPolicy | None = None) -> None:
        self.repo = repo
        self.policy = policy

    async def process(self, tx: PostedTransaction, *, signature: dict | None = None) -> str:
        # Валидация подписи при необходимости
        if self.policy and signature is not None:
            payload = {
                "transaction_id": tx.transaction_id,
                "tx_type": tx.tx_type.value,
                "posted_at": tx.posted_at.isoformat(),
                "currency": tx.currency.value,
                "entries": [
                    {
                        "account": {"account_id": e.account.account_id},
                        "direction": e.direction.value,
                        "amount_minor": e.amount_minor,
                        "currency": e.currency.value,
                    }
                    for e in tx.entries
                ],
                "attributes": dict(tx.attributes or {}),
            }
            self.policy.verify(payload, signature)

        created = await self.repo.save_if_new(tx)
        return "created" if created else "duplicate"

@pytest.mark.asyncio
async def test_tx_service_accepts_valid_and_rejects_duplicates(tx_transfer: PostedTransaction, signing_policy: SigningPolicy):
    repo = FakeTxRepo()
    svc = TxService(repo, policy=signing_policy)

    # Подписываем полезную нагрузку
    payload = {
        "transaction_id": tx_transfer.transaction_id,
        "tx_type": tx_transfer.tx_type.value,
        "posted_at": tx_transfer.posted_at.isoformat(),
        "currency": tx_transfer.currency.value,
        "entries": [
            {
                "account": {"account_id": e.account.account_id},
                "direction": e.direction.value,
                "amount_minor": e.amount_minor,
                "currency": e.currency.value,
            }
            for e in tx_transfer.entries
        ],
        "attributes": dict(tx_transfer.attributes),
    }
    sig = signing_policy.sign(payload, "k1")

    # Первая обработка — created
    status1 = await svc.process(tx_transfer, signature=sig)
    assert status1 == "created"
    # Повтор — duplicate
    status2 = await svc.process(tx_transfer, signature=sig)
    assert status2 == "duplicate"

@pytest.mark.asyncio
async def test_tx_service_signature_required_if_policy_present(tx_transfer: PostedTransaction):
    repo = FakeTxRepo()
    # policy задан, но подпись не передана — считаем это ошибкой контракта
    svc = TxService(repo, policy=SigningPolicy(  # dummy неполная политика
        key_resolver=StaticKeyResolver(sign_keys={}, verify_keys={}),
        nonce_store=InMemoryNonceStore(),
    ))
    with pytest.raises(Exception):
        await svc.process(tx_transfer, signature=None)

# =========================================================
# Граничные случаи времени
# =========================================================

def test_posted_at_must_be_utc():
    # naive datetime — не допускается
    with pytest.raises(ValueError):
        PostedTransaction.transfer(
            transaction_id="tx-naive",
            posted_at=datetime(2025, 8, 15, 12, 0, 0),  # naive
            currency=Currency.EUR,
            from_account="A",
            to_account="B",
            amount_minor=100,
        )

def test_large_batch_entries_balance_ok(utc_now: datetime):
    # 100 пар ног — баланс сохраняется
    entries = []
    for i in range(1, 101):
        entries.append(TransactionEntry(account=AccountRef(account_id=f"A{i}"), direction=EntryDirection.DEBIT, amount_minor=1, currency=Currency.USD))
        entries.append(TransactionEntry(account=AccountRef(account_id=f"B{i}"), direction=EntryDirection.CREDIT, amount_minor=1, currency=Currency.USD))
    tx = PostedTransaction(
        transaction_id="tx-batch",
        tx_type=TxType.ADJUSTMENT,
        posted_at=utc_now,
        currency=Currency.USD,
        entries=entries,
        attributes={},
    )
    assert tx.total_debit_minor == tx.total_credit_minor == 100
    assert tx.total_money.amount == Decimal("1.00")
