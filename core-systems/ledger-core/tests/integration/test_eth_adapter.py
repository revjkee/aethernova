# tests/integration/test_eth_adapter.py
# Integration tests for ledger.adapters.chains.ethereum_adapter.EthereumAdapter
#
# Requirements:
#   pytest>=7, pytest-asyncio>=0.23, web3>=6, eth-account>=0.9, pydantic>=2
#
# Env variables:
#   ETH_RPC_URL              - required (e.g., http://127.0.0.1:8545 or anvil/hardhat/ganache)
#   ETH_TEST_PRIVATE_KEY     - required for tx/signing (hex without 0x or with 0x)
#   ETH_CHAIN_ID             - optional override (int)
#   ETH_DEFAULT_SENDER       - optional (0x...), defaults to derived from private key
#   ETH_CONFIRMATIONS        - optional (int, default 1)
#   ETH_TEST_ERC20           - optional ERC-20 token address for ERC-20 tests
#
# Safety:
#   - Tests that spend gas are SKIPPED on well-known mainnets (1, 56, 137, 10, 42161, 43114, 8453).
#   - Designed for local dev chains or testnets.
#
from __future__ import annotations

import asyncio
import os
import time
from typing import Optional

import pytest

# Mark entire module as integration
pytestmark = pytest.mark.integration

# Optional: set event loop policy explicitly for Windows if needed
try:  # pragma: no cover
    import sys
    if sys.platform.startswith("win"):
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore
except Exception:
    pass

# Import the adapter under test
from ledger.adapters.chains.ethereum_adapter import build_ethereum_adapter, EthereumAdapter

REQUIRED_ENV = ("ETH_RPC_URL", "ETH_TEST_PRIVATE_KEY")

MAINNET_LIKE_CHAIN_IDS = {1, 56, 137, 10, 42161, 43114, 8453}  # ETH, BSC, Polygon, OP, Arbitrum, Avalanche, Base


def _require_env():
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        pytest.skip(f"Missing env vars for integration test: {missing}")


def _confirmations() -> int:
    try:
        return int(os.getenv("ETH_CONFIRMATIONS", "1"))
    except Exception:
        return 1


@pytest.fixture(scope="session")
def eth_cfg_dict():
    _require_env()
    cfg = {
        "rpc_url": os.environ["ETH_RPC_URL"],
        "private_key": os.environ["ETH_TEST_PRIVATE_KEY"],
        "default_sender": os.getenv("ETH_DEFAULT_SENDER"),
        "confirmation_blocks": _confirmations(),
    }
    chain_id_env = os.getenv("ETH_CHAIN_ID")
    if chain_id_env:
        try:
            cfg["chain_id"] = int(chain_id_env)
        except ValueError:
            pass
    return cfg


@pytest.fixture(scope="session")
async def adapter(eth_cfg_dict) -> EthereumAdapter:
    ad = build_ethereum_adapter(eth_cfg_dict)
    await ad.connect()
    yield ad
    await ad.close()


@pytest.fixture(scope="session")
async def sender_address(adapter: EthereumAdapter) -> str:
    # Uses adapter's configured signer
    # The adapter enforces default_sender or key address internally.
    # We fetch nonce to confirm address is valid.
    if adapter._account is None:  # type: ignore[attr-defined]
        pytest.skip("Adapter has no local signer (private key not configured)")
    addr = adapter._account.address  # type: ignore[attr-defined]
    _ = await adapter.get_nonce(addr, pending=True)
    return addr


@pytest.fixture(scope="session")
async def safe_chain(adapter: EthereumAdapter) -> bool:
    cid = await adapter.get_chain_id()
    return cid not in MAINNET_LIKE_CHAIN_IDS


@pytest.mark.asyncio
async def test_connect_and_chain_info(adapter: EthereumAdapter):
    cid = await adapter.get_chain_id()
    head = await adapter.get_block_number()
    assert isinstance(cid, int) and cid > 0
    assert isinstance(head, int) and head >= 0

    hc = await adapter.healthcheck()
    assert hc.get("ok") is True
    assert hc.get("chain_id") == cid
    assert isinstance(hc.get("head"), int)


@pytest.mark.asyncio
async def test_fee_suggestion(adapter: EthereumAdapter):
    fees = await adapter.suggest_fees()
    assert isinstance(fees.max_fee_per_gas, int) and fees.max_fee_per_gas > 0
    assert isinstance(fees.max_priority_fee_per_gas, int) and fees.max_priority_fee_per_gas >= 0


@pytest.mark.asyncio
async def test_build_and_send_zero_value_tx(adapter: EthereumAdapter, sender_address: str, safe_chain: bool):
    if not safe_chain:
        pytest.skip("Skipping value-spending test on mainnet-like chain")

    # Baseline nonce
    nonce_before = await adapter.get_nonce(sender_address, pending=True)

    # Self-transfer of 0 wei (costs only gas), EIP-1559 tx
    tx_hash = await adapter.transfer_eth(to=sender_address, value_wei=0, from_addr=sender_address)
    assert isinstance(tx_hash, str) and tx_hash.startswith("0x")

    # Wait for confirmations
    rcpt = await adapter.wait_for_confirmations(tx_hash, confirmations=_confirmations(), timeout_sec=180.0)
    assert int(rcpt.get("status", 0)) in (1, True)
    assert rcpt.get("transactionHash").hex() == tx_hash if hasattr(rcpt.get("transactionHash"), "hex") else True

    # Nonce should have increased
    nonce_after = await adapter.get_nonce(sender_address, pending=True)
    assert nonce_after >= nonce_before + 1


@pytest.mark.asyncio
async def test_get_transaction_and_logs(adapter: EthereumAdapter, safe_chain: bool, sender_address: str):
    if not safe_chain:
        pytest.skip("Skipping log-range test on mainnet-like chain (non-deterministic)")

    # Send a tiny tx to self again (0 wei)
    tx_hash = await adapter.transfer_eth(to=sender_address, value_wei=0, from_addr=sender_address)
    rcpt = await adapter.wait_for_confirmations(tx_hash, confirmations=_confirmations(), timeout_sec=180.0)

    # Fetch tx and receipt explicitly
    tx = await adapter.get_transaction(tx_hash)
    got_rcpt = await adapter.get_transaction_receipt(tx_hash)
    assert tx.get("hash").hex() == tx_hash if hasattr(tx.get("hash"), "hex") else True
    assert got_rcpt.get("blockNumber") == rcpt.get("blockNumber")

    # Logs query across a small window around the block
    blk = rcpt.get("blockNumber")
    from_blk = max(0, blk - 5) if isinstance(blk, int) else "latest"
    logs = await adapter.get_logs(address=None, from_block=from_blk, to_block=blk)
    # We do not assert non-empty (tx may have no logs), but the API should return a list
    assert isinstance(logs, list)


@pytest.mark.asyncio
async def test_eip712_sign_and_recover(adapter: EthereumAdapter, sender_address: str):
    # Prepare typed data (simple domain and struct)
    typed = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "PermitTest": [
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        },
        "domain": {"name": "LedgerCore", "version": "1", "chainId": await adapter.get_chain_id()},
        "primaryType": "PermitTest",
        "message": {"nonce": 1, "deadline": int(time.time()) + 3600},
    }

    sig = adapter.sign_eip712(typed)
    assert sig["address"].lower() == sender_address.lower()
    assert isinstance(sig["signature"], str) and sig["signature"].startswith("0x")

    # Verify by recovering the signer
    from eth_account.messages import encode_structured_data
    from eth_account import Account

    msg = encode_structured_data(primitive=typed)
    rec = Account.recover_message(msg, signature=sig["signature"])
    assert rec.lower() == sender_address.lower()


@pytest.mark.asyncio
async def test_optional_erc20_helpers(adapter: EthereumAdapter):
    token = os.getenv("ETH_TEST_ERC20")
    if not token:
        pytest.skip("ETH_TEST_ERC20 not set; skipping ERC-20 tests")

    # Basic metadata
    sym = await adapter.erc20_symbol(token)
    dec = await adapter.erc20_decimals(token)
    assert isinstance(sym, str) and len(sym) > 0
    assert isinstance(dec, int) and 0 <= dec <= 36

    # Balance for default sender may be zero; just assert call works
    # If default_sender is not set, adapter uses signer address
    sender = adapter._account.address if adapter._account else os.getenv("ETH_DEFAULT_SENDER")  # type: ignore[attr-defined]
    bal = await adapter.erc20_balance_of(token, sender)
    assert isinstance(bal, int) and bal >= 0
