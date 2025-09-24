# engine-core/engine/tests/unit/test_economy_hooks.py
# -*- coding: utf-8 -*-
"""
Контрактные тесты экономических хуков движка.

Покрывает:
- grant_reward: пополнение счёта игрока, идемпотентность, теги/мемо
- purchase: списание со счёта, атомарность и отказ при недостатке средств
- refund: возврат средств с обращением проводки вспять
- лимиты/антифрод: дневной кап и отказ без побочных эффектов
- конкурентная идемпотентность: гонка grant_reward с одинаковым idempotency_key
- целостность журнала: двойная запись и баланс после проводки

Ожидаемый API модуля хуков:
  engine.engine.economy.hooks:
    class EconomyHooks:
        def __init__(self, ledger): ...
        async def grant_reward(self, *, tenant: str, user_id: str, amount_minor: int, currency: str,
                               idempotency_key: str, tags: dict | None = None, memo: str = "") -> dict
        async def purchase(self, *, tenant: str, user_id: str, price_minor: int, currency: str, sku: str,
                           idempotency_key: str, tags: dict | None = None, memo: str = "") -> dict
        async def refund(self, *, tenant: str, posting_id: str, reason: str, idempotency_key: str) -> dict
        # опционально: лимиты/антифрод внедряются через колбэк:
        #    can_grant(tenant, user_id, amount_minor, currency) -> bool | awaitable

Если интерфейс отличается, адаптируйте реализацию под эти спецификации — тесты отражают требования к поведению.
"""

from __future__ import annotations

import asyncio
import math
import random
import string
from typing import Any, Dict, Tuple, List, Optional

import pytest

ledger_mod = pytest.importorskip(
    "engine.engine.mocks.ledger_mock",
    reason="LedgerMock отсутствует (требуется для тестов экономики)"
)
LedgerMock = getattr(ledger_mod, "LedgerMock", None)
assert LedgerMock is not None, "I cannot verify this."

hooks_mod = pytest.importorskip(
    "engine.engine.economy.hooks",
    reason="Модуль economy.hooks отсутствует — тесты выступают спецификацией API"
)
EconomyHooks = getattr(hooks_mod, "EconomyHooks", None)
assert EconomyHooks is not None, "I cannot verify this."

# ------------------------------------------------------------
# Вспомогательные утилиты
# ------------------------------------------------------------

def _rid(prefix: str = "tx") -> str:
    rnd = random.Random(42)
    return prefix + "-" + "".join(rnd.choice(string.ascii_lowercase + string.digits) for _ in range(10))

@pytest.fixture
def event_loop():
    # explicit loop to allow asyncio tests under pytest
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def ledger(event_loop):
    lg = LedgerMock(namespace="econ-tests", overdraft_check=True)
    await lg.open_account(account_id="treasury", currency="USD", meta={"type": "asset"})
    yield lg

@pytest.fixture
async def user_accounts(ledger: LedgerMock):
    # Каждому пользователю — отдельный счёт
    async def _open(user_id: str, currency: str = "USD") -> str:
        acc = f"user:{user_id}"
        try:
            await ledger.open_account(account_id=acc, currency=currency, meta={"type": "liability", "user": user_id})
        except Exception:
            # допускаем повторную инициализацию в отдельных тестах
            pass
        return acc
    return _open

@pytest.fixture
async def hooks(ledger: LedgerMock):
    # Экземпляр хуков c внедрённой книгой
    return EconomyHooks(ledger)

# ------------------------------------------------------------
# Тесты grant_reward
# ------------------------------------------------------------

@pytest.mark.asyncio
async def test_grant_reward_increases_balance_and_is_idempotent(hooks: Any, ledger: LedgerMock, user_accounts):
    user_id = "u1"
    acc = await user_accounts(user_id)
    tenant = "game"
    idem = "reward-001"

    # Стартовый баланс
    bal0, ver0 = await ledger.balance(account_id=acc)

    # Пополнение 10.00 USD
    res1 = await hooks.grant_reward(
        tenant=tenant, user_id=user_id, amount_minor=1000, currency="USD",
        idempotency_key=idem, tags={"reason": "quest"}, memo="Quest reward"
    )
    assert isinstance(res1, dict)
    assert "posting_id" in res1 and "balance_after" in res1

    bal1, _ = await ledger.balance(account_id=acc)
    assert bal1 - bal0 == 1000

    # Повтор тем же idempotency_key — не должен дублировать проводку
    res2 = await hooks.grant_reward(
        tenant=tenant, user_id=user_id, amount_minor=1000, currency="USD",
        idempotency_key=idem, tags={"reason": "quest"}, memo="Quest reward"
    )
    assert res1["posting_id"] == res2["posting_id"]
    bal2, _ = await ledger.balance(account_id=acc)
    assert bal2 == bal1

@pytest.mark.asyncio
async def test_grant_reward_concurrent_idempotency(hooks: Any, ledger: LedgerMock, user_accounts):
    user_id = "u2"
    await user_accounts(user_id)
    tenant = "game"
    idem = "reward-concurrent-01"

    async def worker():
        return await hooks.grant_reward(
            tenant=tenant, user_id=user_id, amount_minor=500, currency="USD",
            idempotency_key=idem, tags={"batch": "A"}
        )

    # Запускаем гонку из нескольких задач
    tasks = [asyncio.create_task(worker()) for _ in range(8)]
    results = await asyncio.gather(*tasks)
    pids = {r["posting_id"] for r in results}
    assert len(pids) == 1, "Идемпотентность должна удерживать один posting_id при гонке"
    bal, _ = await ledger.balance(account_id=f"user:{user_id}")
    assert bal == 500

# ------------------------------------------------------------
# Тесты purchase
# ------------------------------------------------------------

@pytest.mark.asyncio
async def test_purchase_decreases_balance_and_fails_on_insufficient(hooks: Any, ledger: LedgerMock, user_accounts):
    user_id = "u3"
    acc = await user_accounts(user_id)
    tenant = "game"

    # Пополняем 15.00, затем покупаем на 9.99
    await hooks.grant_reward(tenant=tenant, user_id=user_id, amount_minor=1500, currency="USD", idempotency_key="seed-u3")
    bal0, _ = await ledger.balance(account_id=acc)

    ok = await hooks.purchase(
        tenant=tenant, user_id=user_id, price_minor=999, currency="USD",
        sku="skin.red", idempotency_key="buy-1", tags={"store": "skins"}, memo="Red Skin"
    )
    assert isinstance(ok, dict) and ok["balance_after"] == bal0 - 999

    # Покупка на сумму больше баланса — отказ без побочных эффектов
    bal1, _ = await ledger.balance(account_id=acc)
    with pytest.raises(Exception):
        await hooks.purchase(
            tenant=tenant, user_id=user_id, price_minor=10_000, currency="USD",
            sku="bundle.pro", idempotency_key="buy-2"
        )
    bal2, _ = await ledger.balance(account_id=acc)
    assert bal2 == bal1, "Баланс не должен меняться при отказе"

@pytest.mark.asyncio
async def test_purchase_is_idempotent(hooks: Any, ledger: LedgerMock, user_accounts):
    user_id = "u4"
    acc = await user_accounts(user_id)
    tenant = "game"
    await hooks.grant_reward(tenant=tenant, user_id=user_id, amount_minor=2000, currency="USD", idempotency_key="seed-u4")
    idem = "buy-s1"

    r1 = await hooks.purchase(tenant=tenant, user_id=user_id, price_minor=1000, currency="USD", sku="s1", idempotency_key=idem)
    r2 = await hooks.purchase(tenant=tenant, user_id=user_id, price_minor=1000, currency="USD", sku="s1", idempotency_key=idem)
    assert r1["posting_id"] == r2["posting_id"]
    bal, _ = await ledger.balance(account_id=acc)
    assert bal == 1000

# ------------------------------------------------------------
# Тесты refund
# ------------------------------------------------------------

@pytest.mark.asyncio
async def test_refund_reverts_purchase_amount(hooks: Any, ledger: LedgerMock, user_accounts):
    user_id = "u5"
    acc = await user_accounts(user_id)
    tenant = "game"
    await hooks.grant_reward(tenant=tenant, user_id=user_id, amount_minor=1200, currency="USD", idempotency_key="seed-u5")

    buy = await hooks.purchase(tenant=tenant, user_id=user_id, price_minor=700, currency="USD", sku="consumable.x", idempotency_key="buy-u5")
    bal_after_buy, _ = await ledger.balance(account_id=acc)

    ref = await hooks.refund(tenant=tenant, posting_id=buy["posting_id"], reason="cs_ticket#42", idempotency_key="refund-u5")
    assert isinstance(ref, dict) and "posting_id" in ref

    bal_final, _ = await ledger.balance(account_id=acc)
    assert bal_final == bal_after_buy + 700, "Возврат должен восстановить баланс на сумму покупки"

# ------------------------------------------------------------
# Антифрод/лимиты
# ------------------------------------------------------------

@pytest.mark.asyncio
async def test_grant_respects_daily_cap(monkeypatch, hooks: Any, ledger: LedgerMock, user_accounts):
    user_id = "u6"
    await user_accounts(user_id)
    tenant = "game"

    # Внедрим колбэк лимитов, отклоняющий grant свыше 5.00
    def can_grant(tenant_: str, user_id_: str, amount_minor: int, currency: str) -> bool:
        return amount_minor <= 500

    # hooks.should_grant может отсутствовать — допускаем опциональный интерфейс
    if hasattr(hooks, "set_grant_checker"):
        hooks.set_grant_checker(can_grant)
    elif hasattr(hooks, "can_grant"):
        monkeypatch.setattr(hooks, "can_grant", can_grant, raising=True)
    else:
        pytest.xfail("Нет точки расширения для лимитов (can_grant)")

    # 5.00 — проходит
    await hooks.grant_reward(tenant=tenant, user_id=user_id, amount_minor=500, currency="USD", idempotency_key="cap-ok")
    bal1, _ = await ledger.balance(account_id=f"user:{user_id}")
    assert bal1 == 500

    # 5.01 — отклоняется без побочных эффектов
    with pytest.raises(Exception):
        await hooks.grant_reward(tenant=tenant, user_id=user_id, amount_minor=501, currency="USD", idempotency_key="cap-fail")
    bal2, _ = await ledger.balance(account_id=f"user:{user_id}")
    assert bal2 == bal1

# ------------------------------------------------------------
# Инварианты двойной записи и метаданные
# ------------------------------------------------------------

@pytest.mark.asyncio
async def test_journal_invariants_on_reward(hooks: Any, ledger: LedgerMock, user_accounts):
    user_id = "u7"
    acc_user = await user_accounts(user_id)
    tenant = "game"

    await hooks.grant_reward(tenant=tenant, user_id=user_id, amount_minor=900, currency="USD", idempotency_key="meta-1", tags={"reason":"daily"}, memo="Daily login")

    # Находим последнюю проводку по счёту пользователя
    lines, _ = await ledger.statement(account_id=acc_user, limit=10)
    assert lines, "Выписка не должна быть пустой"
    last = lines[-1]
    assert last.delta > 0 and last.balance_after >= last.delta
    # Проверка соответствия двойной записи: сумма дельт по posting_id == 0
    je = await ledger.find_posting(posting_id=last.posting_id)
    assert je is not None
    total = sum(ln.delta for ln in je.lines)
    assert total == 0, "Двойная запись нарушена (сумма дельт должна быть 0)"

# ------------------------------------------------------------
# Идемпотентность refund
# ------------------------------------------------------------

@pytest.mark.asyncio
async def test_refund_is_idempotent(hooks: Any, ledger: LedgerMock, user_accounts):
    user_id = "u8"
    await user_accounts(user_id)
    tenant = "game"
    await hooks.grant_reward(tenant=tenant, user_id=user_id, amount_minor=1000, currency="USD", idempotency_key="seed-u8")
    buy = await hooks.purchase(tenant=tenant, user_id=user_id, price_minor=400, currency="USD", sku="x", idempotency_key="buy-u8")

    r1 = await hooks.refund(tenant=tenant, posting_id=buy["posting_id"], reason="dup", idempotency_key="refund-u8")
    r2 = await hooks.refund(tenant=tenant, posting_id=buy["posting_id"], reason="dup", idempotency_key="refund-u8")
    assert r1["posting_id"] == r2["posting_id"]
