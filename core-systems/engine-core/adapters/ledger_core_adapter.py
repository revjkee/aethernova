# engine-core/engine/adapters/ledger_core_adapter.py
# Industrial-grade unified ledger adapter for multiple chains (EVM, TON, UTXO-like).
# Features:
# - Strongly-typed models (Pydantic)
# - Async operations with timeouts, retries (exp backoff + jitter), and circuit breaker
# - Idempotency keys + deterministic request hashing
# - Nonce cache for EVM-like chains
# - Address validation stubs (extensible)
# - Fee estimation abstraction
# - Transaction lifecycle: build -> sign -> submit -> wait
# - Pluggable signer interface (HSM/KMS ready) + safe in-memory reference signer
# - Structured logging and lightweight metrics
# - Pagination for transaction listings
# - Health checks per backend
#
# External integrations (web3, ton, bitcoin) are optional and injected by user code.
# This module is dependency-light and safe to import without chain SDKs.

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import random
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Tuple, Union, Iterable

# Pydantic v1/v2 compatibility shim
try:
    from pydantic import BaseModel, Field, validator  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("ledger_core_adapter requires 'pydantic'") from e


# ----------------------------
# Logging (structured)
# ----------------------------
LOG = logging.getLogger("engine.adapters.ledger")
if not LOG.handlers:
    handler = logging.StreamHandler()
    fmt = '{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s","mod":"%(name)s"}'
    handler.setFormatter(logging.Formatter(fmt=fmt))
    LOG.addHandler(handler)
LOG.setLevel(os.environ.get("LEDGER_ADAPTER_LOG_LEVEL", "INFO").upper())


# ----------------------------
# Errors
# ----------------------------
class LedgerError(Exception):
    """Base class for ledger related errors."""


class ConfigError(LedgerError):
    pass


class SigningError(LedgerError):
    pass


class SubmissionError(LedgerError):
    pass


class TimeoutError(LedgerError):
    pass


class NotSupportedError(LedgerError):
    pass


class ValidationError(LedgerError):
    pass


# ----------------------------
# Enums / basic types
# ----------------------------
class LedgerType(str, Enum):
    EVM = "evm"
    TON = "ton"
    UTXO = "utxo"  # e.g., Bitcoin-like


class TxStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    UNKNOWN = "unknown"


# ----------------------------
# Data models
# ----------------------------
class NetworkInfo(BaseModel):
    ledger: LedgerType
    chain_id: str = Field(..., description="EVM chain id / TON workchain / network id")
    name: Optional[str] = None
    native_symbol: str = Field(..., description="e.g., ETH, TON, BTC")
    decimals: int = 18


class AccountRef(BaseModel):
    ledger: LedgerType
    address: str
    chain_id: Optional[str] = None


class AssetRef(BaseModel):
    ledger: LedgerType
    symbol: str
    address: Optional[str] = Field(
        None, description="Token contract addr for EVM, jetton for TON, None for native"
    )
    decimals: int = 18


class Amount(BaseModel):
    value: int = Field(..., ge=0, description="Amount in minimal units (wei/tonnano/sat)")
    decimals: int = 18

    def human(self) -> str:
        if self.decimals <= 0:
            return str(self.value)
        fmt = f"{{:.{self.decimals}f}}"
        return fmt.format(self.value / (10 ** self.decimals))


