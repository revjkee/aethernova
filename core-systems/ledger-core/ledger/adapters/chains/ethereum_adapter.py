# ledger/adapters/chains/ethereum_adapter.py
# Industrial-grade async Ethereum adapter for ledger-core.
# Dependencies (typical project requirements):
#   web3>=6.0.0
#   pydantic>=2.0
#   tenacity>=8.2
#   eth-account>=0.9
#
# Notes:
# - Uses AsyncWeb3 for non-blocking I/O.
# - EIP-1559 fee handling with sane defaults and multipliers.
# - Robust retries with jitter and idempotent read ops.
# - Local signing with eth-account; private key never leaves process.
# - Minimal in-file ABI snippets for ERC-20; extend as needed.
# - Avoids global state; safe for DI and testing.

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from functools import lru_cache, wraps
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union, Callable, Awaitable

from pydantic import BaseModel, Field, HttpUrl, ValidationError, SecretStr
from tenacity import retry, stop_after_attempt, wait_exponential_jitter, retry_if_exception_type, before_sleep_log

from web3 import AsyncWeb3
from web3.providers.async_rpc import AsyncHTTPProvider
from web3.exceptions import TransactionNotFound, ContractLogicError
from web3.types import TxParams, TxReceipt, LogReceipt, BlockData

from eth_account import Account
from eth_account.messages import encode_structured_data
from eth_account.signers.local import LocalAccount

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

logger = logging.getLogger("ledger.adapters.ethereum")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class EthereumAdapterError(Exception):
    """Base adapter error."""

class EthereumConfigError(EthereumAdapterError):
    """Configuration invalid or inconsistent."""

class EthereumSigningError(EthereumAdapterError):
    """Signing failures."""

class EthereumRPCError(EthereumAdapterError):
    """RPC invocation failures."""

class EthereumTimeoutError(EthereumAdapterError):
    """Timeout waiting for confirmations or receipts."""

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------

class EthereumAdapterConfig(BaseModel):
    rpc_url: HttpUrl = Field(..., description="Async HTTP RPC endpoint")
    chain_id: Optional[int] = Field(None, description="Explicit chain id; auto-detected if None")
    request_timeout_sec: float = Field(30.0, ge=1.0, description="Per-RPC call timeout")
    max_retries: int = Field(5, ge=0, description="Max retry attempts for transient RPC errors")
    confirmation_blocks: int = Field(2, ge=0, description="Blocks to wait after inclusion")
    gas_multiplier: float = Field(1.10, ge=1.0, description="Safety multiplier for gas limit")
    priority_fee_wei: Optional[int] = Field(None, description="Override tip; if None use node suggestion")
    max_fee_cap_multiplier: float = Field(2.0, ge=1.0, description="MaxFeePerGas cap vs baseFee")
    rate_limit_concurrency: int = Field(8, ge=1, description="Concurrent RPC calls semaphore")
    private_key: Optional[SecretStr] = Field(None, description="Private key hex for local signing")
    default_sender: Optional[str] = Field(None, description="0x address used as default from")
    # Optional: explicit sleep between blocks while waiting confirmations
    confirmation_poll_interval_sec: float = Field(2.0, ge=0.2, description="Polling interval for tx confirmation")

    model_config = {
        "extra": "ignore",
        "frozen": True,
    }

# -----------------------------------------------------------------------------
# Utilities and ABI
# -----------------------------------------------------------------------------

def to_checksum(address: str) -> str:
    return AsyncWeb3.to_checksum_address(address)

# Minimal ERC-20 ABI subset
_ERC20_ABI: List[Dict[str, Any]] = [
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [{"name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
        "name": "transfer",
        "outputs": [{"name": "ok", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]

def _with_timeout(coro: Awaitable[Any], timeout: float, what: str) -> Awaitable[Any]:
    return asyncio.wait_for(coro, timeout=timeout)

def _is_transient_rpc_error(exc: Exception) -> bool:
    # Heuristic classification for retryable errors
    retriable = (
        "timeout" in str(exc).lower()
        or "temporarily unavailable" in str(exc).lower()
        or "429" in str(exc)
        or "503" in str(exc)
        or "reset" in str(exc).lower()
        or "connection" in str(exc).lower()
    )
    return retriable

def rpc_retry(max_attempts: int) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    def decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @retry(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential_jitter(initial=0.2, max=3.0),
            retry=retry_if_exception_type(EthereumRPCError),
            before_sleep=before_sleep_log(logger, logging.WARNING),
            reraise=True,
        )
        @wraps(fn)
        async def wrapper(self: "EthereumAdapter", *args, **kwargs):
            try:
                return await fn(self, *args, **kwargs)
            except asyncio.TimeoutError as e:
                raise EthereumRPCError(f"RPC timeout in {fn.__name__}: {e}") from e
            except Exception as e:
                # Re-wrap only transient errors for retry; others bubble up
                if _is_transient_rpc_error(e):
                    raise EthereumRPCError(f"Transient RPC error in {fn.__name__}: {e}") from e
                raise
        return wrapper
    return decorator

# -----------------------------------------------------------------------------
# Core Adapter
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class FeeSuggestion:
    max_fee_per_gas: int
    max_priority_fee_per_gas: int

class EthereumAdapter:
    """
    Async Ethereum adapter for ledger-core.

    Thread-safety: use one instance per event loop; internal semaphore limits concurrency.
    """
    def __init__(self, config: EthereumAdapterConfig):
        try:
            object.__setattr__(self, "_config", config)
        except Exception as e:
            raise EthereumConfigError(f"Invalid config: {e}") from e

        self._w3: Optional[AsyncWeb3] = None
        self._sem = asyncio.Semaphore(config.rate_limit_concurrency)

        # Local signer (optional)
        self._account: Optional[LocalAccount] = None
        if config.private_key:
            try:
                acct = Account.from_key(config.private_key.get_secret_value())
                object.__setattr__(self, "_account", acct)
                if config.default_sender and to_checksum(config.default_sender) != to_checksum(acct.address):
                    logger.warning("default_sender differs from private key address; using private key address for signing ops.")
            except Exception as e:
                raise EthereumConfigError(f"Failed to load private key: {e}") from e

    async def connect(self) -> None:
        if self._w3 is not None:
            return
        provider = AsyncHTTPProvider(str(self._config.rpc_url), request_kwargs={"timeout": self._config.request_timeout_sec})
        self._w3 = AsyncWeb3(provider)
        # Pre-flight check: chainId
        cid = await self.get_chain_id()
        if self._config.chain_id and cid != self._config.chain_id:
            raise EthereumConfigError(f"Configured chain_id={self._config.chain_id} but node reports {cid}")
        logger.info(f"Connected to Ethereum chain_id={cid}")

    async def close(self) -> None:
        # AsyncHTTPProvider doesn't require an explicit close; placeholder for future providers.
        self._w3 = None

    # -------------------------
    # Basic chain queries
    # -------------------------

    @rpc_retry(max_attempts=5)
    async def get_chain_id(self) -> int:
        async with self._sem:
            assert self._w3 is not None, "Adapter not connected"
            return await _with_timeout(self._w3.eth.chain_id, self._config.request_timeout_sec, "chain_id")

    @rpc_retry(max_attempts=5)
    async def get_block_number(self) -> int:
        async with self._sem:
            assert self._w3 is not None
            return await _with_timeout(self._w3.eth.block_number, self._config.request_timeout_sec, "block_number")

    @rpc_retry(max_attempts=5)
    async def get_block(self, block_identifier: Union[int, str] = "latest") -> BlockData:
        async with self._sem:
            assert self._w3 is not None
            return await _with_timeout(self._w3.eth.get_block(block_identifier), self._config.request_timeout_sec, "get_block")

    @rpc_retry(max_attempts=5)
    async def get_balance(self, address: str, block_identifier: Union[int, str] = "latest") -> int:
        async with self._sem:
            assert self._w3 is not None
            return await _with_timeout(self._w3.eth.get_balance(to_checksum(address), block_identifier), self._config.request_timeout_sec, "get_balance")

    @rpc_retry(max_attempts=5)
    async def get_transaction(self, tx_hash: str) -> Dict[str, Any]:
        async with self._sem:
            assert self._w3 is not None
            return await _with_timeout(self._w3.eth.get_transaction(tx_hash), self._config.request_timeout_sec, "get_transaction")

    @rpc_retry(max_attempts=5)
    async def get_transaction_receipt(self, tx_hash: str) -> TxReceipt:
        async with self._sem:
            assert self._w3 is not None
            return await _with_timeout(self._w3.eth.get_transaction_receipt(tx_hash), self._config.request_timeout_sec, "get_transaction_receipt")

    @rpc_retry(max_attempts=5)
    async def get_nonce(self, address: str, pending: bool = True) -> int:
        async with self._sem:
            assert self._w3 is not None
            state = "pending" if pending else "latest"
            return await _with_timeout(self._w3.eth.get_transaction_count(to_checksum(address), state), self._config.request_timeout_sec, "get_transaction_count")

    # -------------------------
    # Fees and tx building
    # -------------------------

    @rpc_retry(max_attempts=5)
    async def suggest_fees(self) -> FeeSuggestion:
        """
        EIP-1559 fee suggestion.
        maxFeePerGas ~= baseFee * max_fee_cap_multiplier + maxPriorityFee
        """
        async with self._sem:
            assert self._w3 is not None
            # Get pending block base fee
            pending_block = await _with_timeout(self._w3.eth.get_block("pending"), self._config.request_timeout_sec, "get_block_pending")
            base_fee: Optional[int] = pending_block.get("baseFeePerGas")
            if base_fee is None:
                # Fall back to legacy gas_price if base fee not available (pre-London or L2s that omit it)
                legacy_gas_price = await _with_timeout(self._w3.eth.gas_price, self._config.request_timeout_sec, "gas_price")
                priority_fee = self._config.priority_fee_wei or int(legacy_gas_price * 0.15)
                return FeeSuggestion(max_fee_per_gas=int(legacy_gas_price * self._config.max_fee_cap_multiplier), max_priority_fee_per_gas=priority_fee)

            if self._config.priority_fee_wei is not None:
                priority_fee = self._config.priority_fee_wei
            else:
                try:
                    priority_fee = await _with_timeout(self._w3.eth.max_priority_fee, self._config.request_timeout_sec, "max_priority_fee")
                except Exception:
                    # Conservative default if node can't suggest
                    priority_fee = 2_000_000_000  # 2 gwei

            max_fee = int(base_fee * self._config.max_fee_cap_multiplier) + int(priority_fee)
            return FeeSuggestion(max_fee_per_gas=max_fee, max_priority_fee_per_gas=int(priority_fee))

    @rpc_retry(max_attempts=5)
    async def estimate_gas(self, tx: TxParams) -> int:
        async with self._sem:
            assert self._w3 is not None
            gas = await _with_timeout(self._w3.eth.estimate_gas(tx), self._config.request_timeout_sec, "estimate_gas")
            gas = int(gas * self._config.gas_multiplier)
            return gas

    async def build_eip1559_tx(
        self,
        tx: TxParams,
        from_addr: Optional[str] = None,
        override_fees: Optional[FeeSuggestion] = None,
        set_nonce: bool = True,
        set_gas: bool = True,
    ) -> TxParams:
        assert self._w3 is not None, "Adapter not connected"

        # Determine sender
        sender = (
            to_checksum(from_addr)
            if from_addr
            else (
                to_checksum(self._config.default_sender)
                if self._config.default_sender
                else (to_checksum(self._account.address) if self._account else None)
            )
        )
        if sender is None:
            raise EthereumAdapterError("Sender address is required but not provided")

        chain_id = self._config.chain_id or await self.get_chain_id()
        # Attach mandatory fields
        tx_built: TxParams = {
            "chainId": chain_id,
            "type": 2,  # EIP-1559
            "from": sender,
            **tx,
        }

        # Fees
        fees = override_fees or await self.suggest_fees()
        tx_built["maxFeePerGas"] = fees.max_fee_per_gas
        tx_built["maxPriorityFeePerGas"] = fees.max_priority_fee_per_gas

        # Nonce
        if set_nonce and "nonce" not in tx_built:
            tx_built["nonce"] = await self.get_nonce(sender, pending=True)

        # Gas
        if set_gas and "gas" not in tx_built:
            # For estimate, remove gas fields to avoid node rejection
            est_ctx = dict(tx_built)
            est_ctx.pop("gas", None)
            gas_est = await self.estimate_gas(est_ctx)
            tx_built["gas"] = gas_est

        return tx_built

    # -------------------------
    # Signing and sending
    # -------------------------

    async def sign_and_send(self, tx: TxParams, from_addr: Optional[str] = None) -> str:
        assert self._w3 is not None, "Adapter not connected"
        if not self._account:
            raise EthereumSigningError("Private key not configured; cannot sign transaction")

        sender = to_checksum(from_addr) if from_addr else to_checksum(self._account.address)
        if "from" in tx and to_checksum(tx["from"]) != sender:
            raise EthereumSigningError("Mismatch between tx.from and signer address")

        # Ensure built tx has all fields
        built = await self.build_eip1559_tx(tx, from_addr=sender)
        try:
            signed = self._account.sign_transaction(built)
        except Exception as e:
            raise EthereumSigningError(f"Failed to sign transaction: {e}") from e

        # Send raw
        async with self._sem:
            try:
                tx_hash = await _with_timeout(self._w3.eth.send_raw_transaction(signed.rawTransaction), self._config.request_timeout_sec, "send_raw_transaction")
            except Exception as e:
                raise EthereumRPCError(f"send_raw_transaction failed: {e}") from e

        hex_hash = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
        logger.info(f"Broadcasted tx {hex_hash}")
        return hex_hash

    async def wait_for_confirmations(self, tx_hash: str, confirmations: Optional[int] = None, timeout_sec: Optional[float] = None) -> TxReceipt:
        """
        Waits until the tx is mined and then for N confirmation blocks.
        """
        assert self._w3 is not None, "Adapter not connected"

        confirmations = confirmations if confirmations is not None else self._config.confirmation_blocks
        timeout_sec = timeout_sec if timeout_sec is not None else max(60.0, self._config.request_timeout_sec * 4)

        start = time.monotonic()
        # First wait for receipt
        receipt: Optional[TxReceipt] = None
        while True:
            try:
                receipt = await self.get_transaction_receipt(tx_hash)
                break
            except EthereumRPCError as e:
                # Retryable path handled in decorator
                await asyncio.sleep(self._config.confirmation_poll_interval_sec)
            except TransactionNotFound:
                await asyncio.sleep(self._config.confirmation_poll_interval_sec)

            if time.monotonic() - start > timeout_sec:
                raise EthereumTimeoutError(f"Timeout waiting for receipt of {tx_hash}")

        # Now wait for confirmations (if any)
        if confirmations > 0:
            target_block = receipt["blockNumber"] + confirmations
            while True:
                head = await self.get_block_number()
                if head >= target_block:
                    break
                await asyncio.sleep(self._config.confirmation_poll_interval_sec)
                if time.monotonic() - start > timeout_sec:
                    raise EthereumTimeoutError(f"Timeout waiting for {confirmations} confirmations for {tx_hash}")

        logger.info(f"Tx {tx_hash} confirmed in block {receipt['blockNumber']} with {confirmations} confirmations")
        return receipt

    # -------------------------
    # High-level helpers
    # -------------------------

    async def transfer_eth(self, to: str, value_wei: int, from_addr: Optional[str] = None) -> str:
        tx: TxParams = {
            "to": to_checksum(to),
            "value": int(value_wei),
            # data omitted
        }
        return await self.sign_and_send(tx, from_addr=from_addr)

    async def call_contract_view(self, address: str, abi: List[Dict[str, Any]], fn_name: str, *args: Any, block_identifier: Union[int, str] = "latest") -> Any:
        assert self._w3 is not None
        async with self._sem:
            contract = self._w3.eth.contract(address=to_checksum(address), abi=abi)
            func = getattr(contract.functions, fn_name)(*args)
            try:
                return await _with_timeout(func.call(block_identifier=block_identifier), self._config.request_timeout_sec, f"contract_view_{fn_name}")
            except ContractLogicError as e:
                raise EthereumRPCError(f"Contract view reverted: {e}") from e

    async def send_contract_tx(self, address: str, abi: List[Dict[str, Any]], fn_name: str, *args: Any, value_wei: int = 0, from_addr: Optional[str] = None) -> str:
        assert self._w3 is not None
        contract = self._w3.eth.contract(address=to_checksum(address), abi=abi)
        tx: TxParams = getattr(contract.functions, fn_name)(*args).build_transaction({
            "from": to_checksum(from_addr) if from_addr else None,
            "value": int(value_wei),
        })
        # Remove None fields introduced by build_transaction defaults
        tx = {k: v for k, v in tx.items() if v is not None}
        return await self.sign_and_send(tx, from_addr=from_addr)

    # -------------------------
    # ERC-20 convenience
    # -------------------------

    @lru_cache(maxsize=2048)
    def _erc20_contract(self, token_addr: str):
        assert self._w3 is not None
        return self._w3.eth.contract(address=to_checksum(token_addr), abi=_ERC20_ABI)

    async def erc20_symbol(self, token_addr: str) -> str:
        assert self._w3 is not None
        async with self._sem:
            return await _with_timeout(self._erc20_contract(token_addr).functions.symbol().call(), self._config.request_timeout_sec, "erc20_symbol")

    async def erc20_decimals(self, token_addr: str) -> int:
        assert self._w3 is not None
        async with self._sem:
            return await _with_timeout(self._erc20_contract(token_addr).functions.decimals().call(), self._config.request_timeout_sec, "erc20_decimals")

    async def erc20_balance_of(self, token_addr: str, owner: str, block_identifier: Union[int, str] = "latest") -> int:
        assert self._w3 is not None
        async with self._sem:
            return await _with_timeout(
                self._erc20_contract(token_addr).functions.balanceOf(to_checksum(owner)).call(block_identifier=block_identifier),
                self._config.request_timeout_sec,
                "erc20_balance_of",
            )

    async def erc20_transfer(self, token_addr: str, to: str, amount_wei: int, from_addr: Optional[str] = None) -> str:
        return await self.send_contract_tx(token_addr, _ERC20_ABI, "transfer", to_checksum(to), int(amount_wei), value_wei=0, from_addr=from_addr)

    # -------------------------
    # Logs and filters
    # -------------------------

    @rpc_retry(max_attempts=5)
    async def get_logs(
        self,
        address: Optional[str],
        from_block: Union[int, str],
        to_block: Union[int, str],
        topics: Optional[List[Optional[Union[str, List[str]]]]] = None,
    ) -> List[LogReceipt]:
        async with self._sem:
            assert self._w3 is not None
            params: Dict[str, Any] = {
                "fromBlock": from_block,
                "toBlock": to_block,
            }
            if address:
                params["address"] = to_checksum(address)
            if topics is not None:
                params["topics"] = topics
            return await _with_timeout(self._w3.eth.get_logs(params), self._config.request_timeout_sec, "get_logs")

    # -------------------------
    # EIP-712 signing
    # -------------------------

    def sign_eip712(self, typed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign EIP-712 typed data with the configured private key.
        Returns dict with 'signature' and 'address'.
        """
        if not self._account:
            raise EthereumSigningError("Private key not configured; cannot sign EIP-712")
        try:
            message = encode_structured_data(primitive=typed_data)
            signed = self._account.sign_message(message)
            return {"signature": signed.signature.hex(), "address": self._account.address}
        except Exception as e:
            raise EthereumSigningError(f"EIP-712 signing failed: {e}") from e

    # -------------------------
    # Health / diagnostics
    # -------------------------

    async def healthcheck(self) -> Dict[str, Any]:
        """
        Lightweight health probe for monitoring.
        """
        try:
            cid = await self.get_chain_id()
            head = await self.get_block_number()
            return {"ok": True, "chain_id": cid, "head": head}
        except Exception as e:
            return {"ok": False, "error": str(e)}

# -----------------------------------------------------------------------------
# Factory
# -----------------------------------------------------------------------------

def build_ethereum_adapter(config_dict: Dict[str, Any]) -> EthereumAdapter:
    """
    Helper to construct adapter from dict (e.g., loaded from env/JSON).
    """
    try:
        cfg = EthereumAdapterConfig(**config_dict)
    except ValidationError as e:
        raise EthereumConfigError(f"Config validation failed: {e}") from e
    return EthereumAdapter(cfg)

# -----------------------------------------------------------------------------
# Example (for documentation/testing; not executed on import)
# -----------------------------------------------------------------------------
# async def _example():
#     adapter = build_ethereum_adapter({
#         "rpc_url": "https://mainnet.infura.io/v3/<key>",
#         "confirmation_blocks": 2,
#         "private_key": "<hex>",
#         "default_sender": "0xYourAddress",
#     })
#     await adapter.connect()
#     print(await adapter.healthcheck())
#     bal = await adapter.get_balance("0xYourAddress")
#     print("Balance:", bal)
#     tx_hash = await adapter.transfer_eth("0xRecipient", 10_000_000_000_000_000)  # 0.01 ETH
#     receipt = await adapter.wait_for_confirmations(tx_hash, confirmations=2)
#     print("Receipt:", receipt)
#     await adapter.close()
