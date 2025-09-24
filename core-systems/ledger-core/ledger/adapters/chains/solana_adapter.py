# ledger-core/ledger/adapters/chains/solana_adapter.py
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

# --- Зависимости (solana-py, spl-memo) ---
# pip install "solana>=0.33" "solders>=0.18" "spl-token-cli==2.10.0" (для memo — spl.memo внутри solana-py)
try:
    from solana.rpc.api import Client
    from solana.rpc.types import TxOpts
    from solana.rpc.commitment import Confirmed, Processed, Finalized
    from solana.publickey import PublicKey
    from solana.keypair import Keypair
    from solana.transaction import Transaction
    from solana.system_program import SYS_PROGRAM_ID
    from solders.hash import Hash as SoldersHash
    from solders.message import MessageV0
    from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
    from solders.instruction import Instruction as SoldersInstruction
    from solders.transaction import VersionedTransaction
    from solders.pubkey import Pubkey as SoldersPubkey
    from solders.message import v0
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "solana_adapter requires packages: solana, solders. "
        "Install: pip install 'solana>=0.33' 'solders>=0.18'"
    ) from e

logger = logging.getLogger("ledger.adapters.solana")

# Memo program (v1)
MEMO_PROGRAM_ID = PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

# ======================================================================================
# Конфиг/настройки
# ======================================================================================

@dataclass(frozen=True)
class SolanaAdapterSettings:
    rpc_url: str
    # Коммитмент для отправки и статусов
    send_commitment: str = "confirmed"  # processed|confirmed|finalized
    status_commitment: str = "confirmed"
    min_confirmations: int = 1         # итоговая проверка is_finalized()
    # Ограничения/тайминги
    blockhash_ttl_seconds: int = 60
    request_timeout_sec: float = 12.0
    overall_send_timeout_sec: float = 45.0
    # Приоритет (Compute Budget), в микро-лампортах за CU (1e-6 lamports)
    priority_micro_lamports: Optional[int] = None
    compute_unit_limit: Optional[int] = None  # например, 200_000
    # Memo
    memo_prefix: str = "ledger-anchor"
    # Шардирование payload по нескольким Memo инструкциям
    max_memo_bytes_per_ix: int = 512  # безопасный лимит полезной нагрузки на одну инструкцию
    # Ретраи
    retries: int = 5
    base_delay_sec: float = 0.2
    max_delay_sec: float = 2.0


# ======================================================================================
# Утилиты загрузки ключей
# ======================================================================================

def _load_keypair_from_bytes(secret: bytes) -> Keypair:
    """
    Поддержка форматов:
    - 64-байтовый seed (ed25519 private+public)
    - JSON-список из solana-keygen (64 ints)
    - base64 (64 bytes)
    """
    try:
        # Попытка: JSON-список
        arr = json.loads(secret.decode("utf-8"))
        if isinstance(arr, list):
            return Keypair.from_secret_key(bytes(arr))
    except Exception:
        pass

    if len(secret) == 64:
        return Keypair.from_secret_key(secret)

    # Попытка: base64
    try:
        raw = base64.b64decode(secret, validate=True)
        if len(raw) == 64:
            return Keypair.from_secret_key(raw)
    except Exception:
        pass

    raise ValueError("Unsupported key material for Solana Keypair")


def load_keypair_from_env(env_var: str = "SOLANA_KEYPAIR") -> Keypair:
    """
    Загружает ключ из:
    - env SOLANA_KEYPAIR как путь к файлу с JSON-ключом (solana-keygen)
    - env SOLANA_KEYPAIR как base64/bytes (64 байта)
    """
    val = os.getenv(env_var)
    if not val:
        raise RuntimeError(f"{env_var} is not set")

    # Путь к файлу?
    if os.path.exists(val):
        with open(val, "rb") as f:
            data = f.read()
        return _load_keypair_from_bytes(data)

    # Иначе — напрямую
    return _load_keypair_from_bytes(val.encode("utf-8"))


# ======================================================================================
# Вспомогательные функции
# ======================================================================================

def _commitment_label(level: str):
    lvl = (level or "").lower()
    if lvl in ("processed",):
        return Processed
    if lvl in ("finalized", "finalised"):
        return Finalized
    return Confirmed  # по умолчанию


def _make_memo_ix(memo_bytes: bytes, signer_pubkey: PublicKey) -> SoldersInstruction:
    """
    Инструкция Memo v1: account metas — только подпись плательщика для удобства трассировки.
    """
    return SoldersInstruction(
        program_id=SoldersPubkey.from_string(str(MEMO_PROGRAM_ID)),
        accounts=[  # single signer meta
            v0.AccountMeta(pubkey=SoldersPubkey.from_string(str(signer_pubkey)), is_signer=True, is_writable=False)
        ],
        data=memo_bytes,
    )


def _chunk_payload(data: bytes, chunk: int) -> Sequence[bytes]:
    return [data[i : i + chunk] for i in range(0, len(data), chunk)] if data else [b""]


async def _async_retry(coro_fn, *, retries: int, base_delay: float, max_delay: float, exc_types=(Exception,)):
    delay = base_delay
    last_err: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            return await coro_fn()
        except exc_types as e:  # pragma: no cover
            last_err = e
            if attempt >= retries:
                break
            await asyncio.sleep(delay)
            delay = min(max_delay, delay * 2)
    if last_err:
        raise last_err
    raise RuntimeError("retry failed without exception")  # защита


# ======================================================================================
# SolanaAdapter
# ======================================================================================

class SolanaAdapter:
    """
    Адаптер для сети Solana, совместимый с контрактом AnchorNetworkClient:

    async def submit_payload(self, network, payload: bytes, memo: str|None) -> (tx_id, block_ref)
    async def is_finalized(self, network, tx_id: str) -> (bool, block_ref|None)

    Примечания:
    - payload шардируется на несколько Memo-инструкций, первая включает memo-prefix.
    - Подтверждение — по getSignatureStatuses с целевым числом confirmations.
    """

    def __init__(self, settings: SolanaAdapterSettings, keypair: Optional[Keypair] = None):
        self._cfg = settings
        self._client = Client(settings.rpc_url, timeout=settings.request_timeout_sec)
        self._kp = keypair or load_keypair_from_env()
        self._send_commitment = _commitment_label(settings.send_commitment)
        self._status_commitment = _commitment_label(settings.status_commitment)

    # ----------------------------------------------------------------------
    # AnchorNetworkClient: submit_payload
    # ----------------------------------------------------------------------
    async def submit_payload(self, network: Any, payload: bytes, *, memo: str | None = None) -> Tuple[str, Optional[str]]:
        """
        Отправка транзакции с одной или несколькими Memo-инструкциями.
        Возвращает (signature_base58, block_ref|None).
        """
        # Неблокирующий вызов через loop.run_in_executor для синхронного клиента
        loop = asyncio.get_running_loop()

        async def _send_once():
            # 1) Получить свежий blockhash
            latest = await loop.run_in_executor(
                None,
                lambda: self._client.get_latest_blockhash(self._send_commitment)
            )
            if latest.get("error"):
                raise RuntimeError(f"get_latest_blockhash error: {latest['error']}")
            value = latest["result"]["value"]
            blockhash = SoldersHash.from_string(value["blockhash"])

            # 2) Сконструировать инструкции
            ixs: list[SoldersInstruction] = []

            # Compute Budget (опционально)
            if self._cfg.compute_unit_limit:
                ixs.append(set_compute_unit_limit(self._cfg.compute_unit_limit))
            if self._cfg.priority_micro_lamports:
                ixs.append(set_compute_unit_price(self._cfg.priority_micro_lamports))

            # Первая Memo — префикс и, при наличии, memo-строка
            prefix = self._cfg.memo_prefix.encode("utf-8")
            header = prefix if memo is None else (prefix + b":" + memo.encode("utf-8"))
            ixs.append(_make_memo_ix(header, self._kp.public_key))

            # Шардировать payload
            for chunk in _chunk_payload(payload, self._cfg.max_memo_bytes_per_ix):
                if not chunk:
                    continue
                ixs.append(_make_memo_ix(chunk, self._kp.public_key))

            # 3) Собрать и подписать v0 transaction
            payer = SoldersPubkey.from_string(str(self._kp.public_key))
            msg = MessageV0.try_compile(
                payer=payer,
                instructions=ixs,
                address_lookup_tables=[],
                recent_blockhash=blockhash,
            )
            tx = VersionedTransaction(msg, [self._kp])

            # 4) Отправить
            raw_b64 = base64.b64encode(bytes(tx)).decode("ascii")
            resp = await loop.run_in_executor(
                None,
                lambda: self._client.send_raw_transaction(
                    raw_b64,
                    opts=TxOpts(skip_preflight=False, preflight_commitment=self._send_commitment),
                ),
            )
            if resp.get("error"):
                raise RuntimeError(f"send_raw_transaction error: {resp['error']}")

            sig = resp["result"]
            # 5) Опционально: дождаться commitment уровня send_commitment
            await self._confirm_signature(sig, desired_commitment=self._cfg.send_commitment, timeout=self._cfg.overall_send_timeout_sec)
            return sig, None  # block_ref можно дополнить слот/блоком при необходимости

        # Ретраи отправки
        sig, block_ref = await _async_retry(
            _send_once,
            retries=self._cfg.retries,
            base_delay=self._cfg.base_delay_sec,
            max_delay=self._cfg.max_delay_sec,
            exc_types=(Exception,),
        )
        logger.info("solana_submit_payload_ok", extra={"sig": sig})
        return sig, block_ref

    # ----------------------------------------------------------------------
    # AnchorNetworkClient: is_finalized
    # ----------------------------------------------------------------------
    async def is_finalized(self, network: Any, tx_id: str) -> Tuple[bool, Optional[str]]:
        """
        Проверка числа подтверждений для подписи и статуса финализации.
        Возвращает (finalized?, block_ref|None).
        """
        loop = asyncio.get_running_loop()

        def _status():
            return self._client.get_signature_statuses([tx_id], search_transaction_history=True)

        resp = await loop.run_in_executor(None, _status)
        if resp.get("error"):
            raise RuntimeError(f"get_signature_statuses error: {resp['error']}")
        statuses = resp["result"]["value"]
        st = statuses[0]
        if st is None:
            return False, None

        # confirmed/processed/finalized + confirmations
        confirmations = st.get("confirmations")
        confirmation_status = st.get("confirmationStatus")  # processed|confirmed|finalized
        slot = st.get("slot")

        # Логика финализации:
        # 1) если статус finalized — принято
        # 2) иначе — по числу подтверждений
        finalized = (confirmation_status == "finalized") or (
            isinstance(confirmations, int) and confirmations >= self._cfg.min_confirmations
        )
        block_ref = f"slot:{slot}" if slot is not None else None
        return finalized, block_ref

    # ----------------------------------------------------------------------
    # Внутреннее: ожидание подтверждения отправки
    # ----------------------------------------------------------------------
    async def _confirm_signature(self, sig: str, *, desired_commitment: str, timeout: float):
        """
        Ожидание достижения требуемого commitment в рамках тайм-аута.
        """
        commitment = (desired_commitment or "confirmed").lower()
        if commitment not in ("processed", "confirmed", "finalized"):
            commitment = "confirmed"

        async def _poll():
            ok, _ = await self.is_finalized(network=None, tx_id=sig)
            if commitment == "processed":
                return ok or True  # уже отправлено
            if commitment == "confirmed":
                return ok  # достаточность по min_confirmations
            if commitment == "finalized":
                # Для строгого finalized можно принудительно проверять равенство
                loop = asyncio.get_running_loop()
                resp = await loop.run_in_executor(
                    None, lambda: self._client.get_signature_statuses([sig], search_transaction_history=True)
                )
                st = resp["result"]["value"][0]
                return bool(st and st.get("confirmationStatus") == "finalized")
            return ok

        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            if await _poll():
                return
            if asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("Timeout waiting for desired commitment")
            await asyncio.sleep(0.5)


# ======================================================================================
# Фабрика для DI
# ======================================================================================

def make_solana_adapter_from_env() -> SolanaAdapter:
    """
    Удобная фабрика: читает настройки из ENV и возвращает готовый адаптер.
    Обязательные:
      - SOLANA_RPC_URL
      - SOLANA_KEYPAIR (путь к файлу JSON-ключа или base64/bytes)
    Необязательные:
      - SOLANA_COMMIT_SEND (processed|confirmed|finalized)
      - SOLANA_COMMIT_STATUS (processed|confirmed|finalized)
      - SOLANA_MIN_CONFIRMATIONS (int)
      - SOLANA_PRIORITY_MICRO_LAMPORTS (int)
      - SOLANA_CU_LIMIT (int)
      - SOLANA_MEMO_PREFIX (str)
      - SOLANA_MAX_MEMO_BYTES (int)
    """
    rpc = os.getenv("SOLANA_RPC_URL")
    if not rpc:
        raise RuntimeError("SOLANA_RPC_URL is not set")

    cfg = SolanaAdapterSettings(
        rpc_url=rpc,
        send_commitment=os.getenv("SOLANA_COMMIT_SEND", "confirmed"),
        status_commitment=os.getenv("SOLANA_COMMIT_STATUS", "confirmed"),
        min_confirmations=int(os.getenv("SOLANA_MIN_CONFIRMATIONS", "1")),
        priority_micro_lamports=int(os.getenv("SOLANA_PRIORITY_MICRO_LAMPORTS", "0")) or None,
        compute_unit_limit=int(os.getenv("SOLANA_CU_LIMIT", "0")) or None,
        memo_prefix=os.getenv("SOLANA_MEMO_PREFIX", "ledger-anchor"),
        max_memo_bytes_per_ix=int(os.getenv("SOLANA_MAX_MEMO_BYTES", "512")),
    )
    kp = load_keypair_from_env("SOLANA_KEYPAIR")
    return SolanaAdapter(cfg, kp)


# ======================================================================================
# Совместимость с AnchorNetworkClient (duck typing)
# ======================================================================================

class AnchorNetworkClientCompat:
    """
    Обёртка-адаптер, если требуется строго соответствовать интерфейсу AnchorNetworkClient.
    """

    def __init__(self, sol: SolanaAdapter):
        self._sol = sol

    async def submit_payload(self, network: Any, payload: bytes, *, memo: str | None = None) -> Tuple[str, Optional[str]]:
        # network: ожидается AnchorNetwork, но для Solana игнорируем.
        return await self._sol.submit_payload(network, payload, memo=memo)

    async def is_finalized(self, network: Any, tx_id: str) -> Tuple[bool, Optional[str]]:
        return await self._sol.is_finalized(network, tx_id)
