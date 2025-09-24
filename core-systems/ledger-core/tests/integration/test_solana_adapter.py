# ledger-core/tests/integration/test_solana_adapter.py
"""
Интеграционные тесты для Solana Adapter.

Назначение
---------
Промышленный набор проверок для адаптера Solana, устойчивый к сетевым задержкам
и rate limit devnet. Тесты исполняются ТОЛЬКО при SOLANA_LIVE_TESTS=1
и наличии рабочей RPC-точки (по умолчанию devnet).

Ожидаемый интерфейс адаптера (минимум)
--------------------------------------
Класс: SolanaAdapter (расположение: ledger_core.adapters.solana_adapter)
Методы (async):
    - get_latest_blockhash() -> dict | str | tuple
    - get_slot(commitment: str = "confirmed") -> int
    - get_balance(address: str) -> int
    - request_airdrop(address: str, lamports: int) -> str  # возвращает tx signature
    - confirm_transaction(signature: str, timeout: float = 30.0) -> None
    - transfer(sender: Any, recipient: str, lamports: int, skip_preflight: bool = False) -> str
    - aclose() -> None   # закрытие внутренних клиентов/сессий

Примечания
----------
1) Тесты используют независимый solana AsyncClient для валидации фактов.
2) Все с длительными сетевыми операциями обернуты в ретраи и таймауты.
3) Балансы проверяются с допуском по комиссиям: принимается, что получатель
   получает >= отправленной суммы (за минусом возможных особенностей),
   а отправитель тратит >= сумма + комиссия.
4) Для ускорения CI можно поднимать локальный validator (test validator)
   и указывать SOLANA_RPC_URL на него.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import os
import random
import string
import time
from typing import Any, Callable, Optional, Tuple

import pytest

# pytest-asyncio policy: тесты в этом модуле асинхронные
pytestmark = [
    pytest.mark.integration,
    pytest.mark.solana,
    pytest.mark.asyncio,
]

# ---------- Константы и конфиг через ENV ----------

ENV_LIVE_FLAG = os.getenv("SOLANA_LIVE_TESTS", "0")
RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.devnet.solana.com")
AIRDROP_LAMPORTS = int(os.getenv("TEST_AIRDROP_LAMPORTS", str(2_000_000)))  # 0.002 SOL
TRANSFER_LAMPORTS = int(os.getenv("TEST_TRANSFER_LAMPORTS", str(500_000)))   # 0.0005 SOL
MAX_RETRIES = int(os.getenv("TEST_MAX_RETRIES", "8"))
BASE_DELAY = float(os.getenv("TEST_BASE_DELAY", "0.75"))  # сек
OP_TIMEOUT = float(os.getenv("TEST_OP_TIMEOUT", "60.0"))  # сек на одну сетевую операцию

# ---------- Логирование ----------

logger = logging.getLogger("test_solana_adapter")
if not logger.handlers:
    handler = logging.StreamHandler()
    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    handler.setFormatter(fmt)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ---------- Утилиты ретраев и таймаутов ----------

async def _with_backoff(
    func: Callable[[], Any],
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    timeout: float = OP_TIMEOUT,
    retry_on: Tuple[type, ...] = (Exception,),
    op_name: str = "operation",
) -> Any:
    """
    Выполнить асинхронную операцию с экспоненциальным backoff и общим таймаутом.
    """
    start = time.monotonic()
    attempt = 0
    last_exc = None
    while attempt <= max_retries:
        try:
            return await asyncio.wait_for(func(), timeout=timeout)
        except retry_on as exc:
            last_exc = exc
            elapsed = time.monotonic() - start
            if attempt == max_retries or elapsed + base_delay * (2 ** attempt) > timeout:
                logger.error("Fail %s after %d attempts: %s", op_name, attempt + 1, exc)
                raise
            sleep_for = base_delay * (2 ** attempt)
            logger.warning("Retry %s in %.2fs (attempt %d/%d): %s",
                           op_name, sleep_for, attempt + 1, max_retries, exc)
            await asyncio.sleep(sleep_for)
            attempt += 1
    # На случай, если цикл завершился без return/raise:
    raise last_exc if last_exc else RuntimeError(f"{op_name} failed")


def _rand_memo(prefix: str = "it") -> str:
    sfx = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"{prefix}-{sfx}"


# ---------- Работа с solana-py для независимой валидации ----------

_SOLANA_IMPORT_ERROR = None
try:
    from solana.keypair import Keypair  # type: ignore
    from solana.publickey import PublicKey  # type: ignore
    from solana.rpc.async_api import AsyncClient  # type: ignore
    from solana.rpc.types import TxOpts  # type: ignore
except Exception as exc:  # noqa: BLE001
    _SOLANA_IMPORT_ERROR = exc
    Keypair = object  # type: ignore
    PublicKey = object  # type: ignore
    AsyncClient = object  # type: ignore
    TxOpts = object  # type: ignore


# ---------- Фикстуры ----------

def _require_live() -> None:
    if ENV_LIVE_FLAG != "1":
        pytest.skip("SOLANA_LIVE_TESTS != 1, пропускаем интеграционные live-тесты.")


def _require_solana_libs() -> None:
    if _SOLANA_IMPORT_ERROR is not None:
        pytest.skip(f"solana-py недоступна: {_SOLANA_IMPORT_ERROR}")


@pytest.fixture(scope="session")
def rpc_url() -> str:
    _require_live()
    return RPC_URL


@pytest.fixture(scope="session")
async def rpc_client(rpc_url: str):
    _require_solana_libs()
    client = AsyncClient(rpc_url)
    try:
        # Быстрая проверка доступности RPC
        await _with_backoff(lambda: client.get_version(), op_name="get_version")
    except Exception:
        await client.close()
        raise
    yield client
    await client.close()


def _load_adapter_class() -> Any:
    """
    Универсальная загрузка класса адаптера.
    При необходимости добавляйте альтернативные пути.
    """
    candidates = [
        ("ledger_core.adapters.solana_adapter", "SolanaAdapter"),
        ("ledger_core.adapter.solana_adapter", "SolanaAdapter"),
        ("ledger_core.solana.adapter", "SolanaAdapter"),
    ]
    errors = []
    for module_name, class_name in candidates:
        try:
            mod = importlib.import_module(module_name)
            cls = getattr(mod, class_name, None)
            if cls is not None:
                return cls
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{module_name}.{class_name}: {exc}")
    raise ImportError("Не найден SolanaAdapter. Пробовали: " + "; ".join(errors))


@pytest.fixture(scope="session")
def adapter_cls():
    _require_live()
    try:
        return _load_adapter_class()
    except ImportError as exc:
        pytest.skip(f"SolanaAdapter не найден: {exc}")


@pytest.fixture(scope="function")
async def adapter(adapter_cls):
    """
    Экземпляр адаптера на каждый тест.
    Предполагается, что конструктор принимает rpc_url=<...>.
    """
    try:
        inst = adapter_cls(rpc_url=RPC_URL)
    except TypeError:
        # fallback: без аргументов
        inst = adapter_cls()
    try:
        yield inst
    finally:
        # Корректно закрываем ресурсы, если метод доступен.
        close = getattr(inst, "aclose", None)
        if callable(close):
            try:
                await close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Ошибка при закрытии адаптера: %s", exc)


@pytest.fixture(scope="function")
def sender_keypair():
    _require_solana_libs()
    return Keypair.generate()


@pytest.fixture(scope="function")
def recipient_keypair():
    _require_solana_libs()
    return Keypair.generate()


# ---------- Вспомогательные операции ----------

async def _airdrop_and_confirm(
    adapter: Any,
    rpc_client: Any,
    address_str: str,
    lamports: int,
    op_label: str,
) -> str:
    """
    Аирдроп с подтверждением. Возвращает signature.
    """
    async def _req() -> str:
        sig = await adapter.request_airdrop(address_str, lamports)
        return sig

    signature = await _with_backoff(_req, op_name=f"{op_label}.request_airdrop")

    async def _confirm() -> None:
        await adapter.confirm_transaction(signature, timeout=OP_TIMEOUT)

    await _with_backoff(_confirm, op_name=f"{op_label}.confirm_airdrop")
    # Ждем фактического обновления баланса
    async def _wait_balance() -> int:
        bal = await adapter.get_balance(address_str)
        if bal < lamports:
            raise RuntimeError(f"Balance {bal} < expected airdrop {lamports}")
        return bal

    await _with_backoff(_wait_balance, op_name=f"{op_label}.wait_balance")
    return signature


async def _get_balance_via_client(rpc_client: Any, address_str: str) -> int:
    from solana.publickey import PublicKey  # local import to ensure availability
    resp = await rpc_client.get_balance(PublicKey(address_str))
    if "result" not in resp or "value" not in resp["result"]:
        raise RuntimeError(f"Malformed balance response: {resp}")
    return int(resp["result"]["value"])


def _ensure_method(obj: Any, name: str) -> None:
    if not hasattr(obj, name) or not callable(getattr(obj, name)):
        pytest.skip(f"Адаптер не реализует метод: {name}")


# ---------- Тесты ----------

@pytest.mark.slow
async def test_airdrop_increases_balance(adapter, rpc_client, sender_keypair):
    """
    Проверяем, что аирдроп через адаптер увеличивает баланс нового аккаунта.
    """
    _ensure_method(adapter, "request_airdrop")
    _ensure_method(adapter, "confirm_transaction")
    _ensure_method(adapter, "get_balance")

    sender_addr = str(sender_keypair.public_key)
    before = await adapter.get_balance(sender_addr)
    assert before == 0, "Для чистоты теста ожидаем 0 на новом аккаунте"

    await _airdrop_and_confirm(
        adapter=adapter,
        rpc_client=rpc_client,
        address_str=sender_addr,
        lamports=AIRDROP_LAMPORTS,
        op_label="airdrop_sender",
    )

    after_adapter = await adapter.get_balance(sender_addr)
    after_client = await _get_balance_via_client(rpc_client, sender_addr)

    assert after_adapter >= AIRDROP_LAMPORTS
    assert after_client >= AIRDROP_LAMPORTS


@pytest.mark.slow
async def test_transfer_lamports_adapter_to_new_recipient(adapter, rpc_client, sender_keypair, recipient_keypair):
    """
    Проверяем полный цикл: аирдроп -> перевод -> подтверждение -> проверка остатков.
    """
    for m in ("transfer", "request_airdrop", "confirm_transaction", "get_balance"):
        _ensure_method(adapter, m)

    sender_addr = str(sender_keypair.public_key)
    recipient_addr = str(recipient_keypair.public_key)

    # Аирдроп на отправителя
    await _airdrop_and_confirm(
        adapter=adapter,
        rpc_client=rpc_client,
        address_str=sender_addr,
        lamports=AIRDROP_LAMPORTS,
        op_label="airdrop_sender_for_transfer",
    )

    sender_before = await adapter.get_balance(sender_addr)
    recipient_before = await adapter.get_balance(recipient_addr)
    assert recipient_before == 0

    # Перевод
    async def _do_transfer() -> str:
        # Некоторые адаптеры ожидают Keypair, некоторые — свою обертку.
        # Передаем как есть Keypair из solana-py.
        sig = await adapter.transfer(sender_keypair, recipient_addr, TRANSFER_LAMPORTS, skip_preflight=False)
        return sig

    transfer_sig = await _with_backoff(_do_transfer, op_name="adapter.transfer")

    # Подтверждение
    async def _confirm() -> None:
        await adapter.confirm_transaction(transfer_sig, timeout=OP_TIMEOUT)

    await _with_backoff(_confirm, op_name="confirm.transfer")

    # Проверяем остатки с терпением к комиссиям
    async def _wait_recipient_received() -> int:
        bal = await adapter.get_balance(recipient_addr)
        if bal < TRANSFER_LAMPORTS:
            raise RuntimeError(f"Recipient balance {bal} < transferred {TRANSFER_LAMPORTS}")
        return bal

    recipient_after = await _with_backoff(_wait_recipient_received, op_name="wait.recipient.balance")
    sender_after = await adapter.get_balance(sender_addr)

    assert recipient_after >= TRANSFER_LAMPORTS
    assert sender_after <= sender_before - TRANSFER_LAMPORTS, "Отправитель должен потратить минимум сумму перевода"


async def test_latest_blockhash_changes_over_time(adapter):
    """
    Проверяем, что latest blockhash меняется (или растет высота блока).
    """
    _ensure_method(adapter, "get_latest_blockhash")

    first = await adapter.get_latest_blockhash()
    await asyncio.sleep(1.5)
    second = await adapter.get_latest_blockhash()

    # Универсальная проверка: либо разные блокхеши, либо есть высота/slot и она растет.
    def _normalize(x: Any) -> Tuple[Optional[str], Optional[int]]:
        if isinstance(x, dict):
            bh = x.get("blockhash") or x.get("value") or x.get("hash")
            height = x.get("lastValidBlockHeight") or x.get("height") or x.get("slot")
            return (str(bh) if bh is not None else None, int(height) if height is not None else None)
        if isinstance(x, (list, tuple)) and x:
            return (str(x[0]), None)
        return (str(x), None)

    b1, h1 = _normalize(first)
    b2, h2 = _normalize(second)

    if b1 is not None and b2 is not None:
        assert b1 != b2, "Ожидаем смену blockhash"
    elif h1 is not None and h2 is not None:
        assert h2 >= h1, "Ожидаем неубывающую высоту"
    else:
        pytest.skip("Формат get_latest_blockhash не распознан для надежной проверки")


async def test_slot_monotonic_increase(adapter):
    """
    Проверяем, что slot не убывает.
    """
    _ensure_method(adapter, "get_slot")
    s1 = await adapter.get_slot("confirmed")
    await asyncio.sleep(0.8)
    s2 = await adapter.get_slot("confirmed")
    assert isinstance(s1, int) and isinstance(s2, int)
    assert s2 >= s1


@pytest.mark.slow
async def test_account_info_presence_after_airdrop(adapter, rpc_client, recipient_keypair):
    """
    После аирдропа аккаунт должен существовать в сети.
    """
    for m in ("request_airdrop", "confirm_transaction", "get_balance"):
        _ensure_method(adapter, m)

    addr = str(recipient_keypair.public_key)

    await _airdrop_and_confirm(
        adapter=adapter,
        rpc_client=rpc_client,
        address_str=addr,
        lamports=AIRDROP_LAMPORTS,
        op_label="airdrop_recipient_account_info",
    )

    # Если у адаптера есть get_account_info — используем. Иначе проверяем балансом.
    if hasattr(adapter, "get_account_info") and callable(getattr(adapter, "get_account_info")):
        async def _wait_info() -> Any:
            info = await adapter.get_account_info(addr)
            if not info:
                raise RuntimeError("account info is empty")
            return info

        info = await _with_backoff(_wait_info, op_name="wait.account.info")
        assert info is not None
    else:
        bal = await adapter.get_balance(addr)
        assert bal >= AIRDROP_LAMPORTS


@pytest.mark.slow
async def test_confirm_rejects_invalid_signature(adapter):
    """
    Негативный сценарий: confirm_transaction должен падать на несуществующей подписи.
    """
    _ensure_method(adapter, "confirm_transaction")
    invalid_sig = "1" * 88  # строка-заглушка неподобной подписи
    with pytest.raises(Exception):
        await adapter.confirm_transaction(invalid_sig, timeout=5.0)


@pytest.mark.slow
async def test_adapter_closure_is_idempotent(adapter):
    """
    Проверяем, что aclose() можно безопасно вызывать повторно.
    """
    if not hasattr(adapter, "aclose") or not callable(getattr(adapter, "aclose")):
        pytest.skip("Адаптер не реализует aclose()")
    await adapter.aclose()
    await adapter.aclose()  # не должно падать


# ---------- Smoke-тест доступности RPC перед запуском остального ----------

async def test_rpc_health_precheck(rpc_client):
    """
    Smoke-тест доступности RPC: get_slot и get_latest_blockhash через независимый клиент.
    """
    slot_resp = await _with_backoff(lambda: rpc_client.get_slot(commitment="confirmed"), op_name="rpc.get_slot")
    assert "result" in slot_resp and isinstance(slot_resp["result"], int)

    # blockhash через raw RPC (в некоторых версиях — getLatestBlockhash)
    # оставляем smoke в виде get_block_commitment на текущем слоте как прокси.
    curr_slot = slot_resp["result"]
    bh_resp = await _with_backoff(lambda: rpc_client.get_block_commitment(curr_slot), op_name="rpc.get_block_commitment")
    assert "result" in bh_resp
